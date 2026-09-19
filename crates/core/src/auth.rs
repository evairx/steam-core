//! High-level developer facade (`SteamAuth`) for native Steam authentication integrations.

use qrcode::render::unicode;
use qrcode::QrCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, sync::RwLock};
use tokio::sync::Mutex;

use crate::client::{SteamApiClient, SteamWebCookies};
use crate::enums::{EAuthSessionGuardType, EAuthTokenPlatformType, ESessionPersistence};
use crate::error::{Result, SteamError};
use crate::keeper::{AutoKeeper, AutoKeeperHandle};
use crate::session::{AuthTokens, LoginSession, PollStatus};
use crate::vault::{SavedSession, SessionStore, SessionVault};

/// Events emitted during the authentication flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEvent {
    /// Steam sent a push notification to the user's mobile app.
    NeedMobileConfirmation,
    /// A Steam Guard TOTP code from the mobile app is required.
    NeedDeviceCode,
    /// A Steam Guard code was emailed to the user.
    NeedEmailCode,
    /// Awaiting user confirmation or approval.
    Polling,
    /// Authentication successfully confirmed.
    Authenticated { account_name: String },
}

/// Authentication configuration shared by credentials, QR, token restoration, and persistence.
///
/// `WebBrowser` finalizes web cookies from a refresh token. `MobileApp` can refresh its access
/// token, rotate its refresh token, and derive web cookies locally. `SteamClient` requires CM and
/// is rejected until a real CM transport and verified protocol definitions exist.
#[derive(Clone)]
pub struct LoginOptions {
    /// Target platform encoded in the Steam authentication request.
    pub platform_type: EAuthTokenPlatformType,
    /// Requested Steam token persistence.
    pub persistence: ESessionPersistence,
    /// Device name reported to Steam during authentication.
    pub device_name: String,
    /// Optional Steam website identifier. Browser sessions default to `Community`; MobileApp
    /// sessions default to `Mobile`.
    pub website_id: Option<String>,
    client: Option<SteamApiClient>,
}

impl fmt::Debug for LoginOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginOptions")
            .field("platform_type", &self.platform_type)
            .field("persistence", &self.persistence)
            .field("has_device_name", &!self.device_name.is_empty())
            .field("has_website_id", &self.website_id.is_some())
            .field("has_http_transport", &self.client.is_some())
            .finish()
    }
}

impl Default for LoginOptions {
    fn default() -> Self {
        Self::web_browser()
    }
}

impl LoginOptions {
    /// Returns options for Steam's browser authentication flow.
    pub fn web_browser() -> Self {
        Self::new(EAuthTokenPlatformType::WebBrowser)
    }

    /// Returns options for a Steam Mobile App authentication challenge.
    pub fn mobile_app() -> Self {
        Self::new(EAuthTokenPlatformType::MobileApp)
    }

    /// Returns options for a Steam Client authentication challenge.
    pub fn steam_client() -> Self {
        Self::new(EAuthTokenPlatformType::SteamClient)
    }

    /// Returns options for the requested target platform.
    pub fn new(platform_type: EAuthTokenPlatformType) -> Self {
        Self {
            platform_type,
            persistence: ESessionPersistence::Persistent,
            device_name: "steam-core".to_string(),
            website_id: match platform_type {
                EAuthTokenPlatformType::WebBrowser => Some("Community".to_string()),
                EAuthTokenPlatformType::MobileApp => Some("Mobile".to_string()),
                EAuthTokenPlatformType::SteamClient | EAuthTokenPlatformType::Unknown => None,
            },
            client: None,
        }
    }

    /// Uses a custom device name for the authentication request.
    pub fn with_device_name(mut self, device_name: impl Into<String>) -> Self {
        self.device_name = device_name.into();
        self
    }

    /// Sets the requested persistence level.
    pub fn with_persistence(mut self, persistence: ESessionPersistence) -> Self {
        self.persistence = persistence;
        self
    }

    /// Overrides the optional Steam website identifier for this authentication request.
    pub fn with_website_id(mut self, website_id: Option<String>) -> Self {
        self.website_id = website_id;
        self
    }

    /// Uses a host-provided HTTP client and transport for all authentication calls.
    pub fn with_http_client(mut self, client: SteamApiClient) -> Self {
        self.client = Some(client);
        self
    }

    fn build_session(&self) -> Result<LoginSession> {
        if self.platform_type == EAuthTokenPlatformType::Unknown {
            return Err(SteamError::UnsupportedPlatform(
                "Unknown authentication platform",
            ));
        }
        if self.platform_type == EAuthTokenPlatformType::SteamClient {
            return Err(SteamError::CmNotImplemented);
        }
        if self.device_name.trim().is_empty()
            || self.device_name.len() > 256
            || self.device_name.chars().any(char::is_control)
        {
            return Err(SteamError::InvalidResponse(
                "Invalid authentication device name",
            ));
        }
        let session = LoginSession::new(self.platform_type)
            .with_persistence(self.persistence)
            .with_device_name(self.device_name.clone())
            .with_website_id(self.website_id.clone());
        Ok(match &self.client {
            Some(client) => session.with_client(client.clone()),
            None => session,
        })
    }
}

/// The mutable state shared by an authenticated session and its background keeper.
#[derive(Clone)]
pub(crate) struct SessionState {
    pub(crate) account_name: String,
    pub(crate) steam_id: u64,
    pub(crate) refresh_token: String,
    pub(crate) access_token: String,
    pub(crate) cookies: SteamWebCookies,
    pub(crate) guard_data: Option<String>,
    pub(crate) platform_type: EAuthTokenPlatformType,
    pub(crate) generation: u64,
    pub(crate) revoked: bool,
}

/// An authenticated session with ready-to-use tokens and web cookies.
#[derive(Clone)]
pub struct AuthenticatedSession {
    /// The authenticated Steam account name.
    state: Arc<RwLock<SessionState>>,
    /// The resolved SteamID64.
    session: Arc<Mutex<LoginSession>>,
    store: Arc<dyn SessionStore>,
    keeper_active: Arc<AtomicBool>,
}

impl fmt::Debug for AuthenticatedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.snapshot();
        f.debug_struct("AuthenticatedSession")
            .field("account_name", &state.account_name)
            .field("steam_id", &state.steam_id)
            .field("has_refresh_token", &!state.refresh_token.is_empty())
            .field("has_access_token", &!state.access_token.is_empty())
            .field("cookie_count", &state.cookies.all_cookies.len())
            .field("has_guard_data", &state.guard_data.is_some())
            .finish()
    }
}

impl AuthenticatedSession {
    /// Creates a new `AuthenticatedSession` wrapping the inner `LoginSession`.
    pub(crate) fn new(
        account_name: String,
        steam_id: u64,
        refresh_token: String,
        access_token: String,
        cookies: SteamWebCookies,
        session: LoginSession,
    ) -> Self {
        Self::new_with_store(
            account_name,
            steam_id,
            refresh_token,
            access_token,
            cookies,
            session,
            Arc::new(SessionVault),
        )
    }

    fn new_with_store(
        account_name: String,
        steam_id: u64,
        refresh_token: String,
        access_token: String,
        cookies: SteamWebCookies,
        session: LoginSession,
        store: Arc<dyn SessionStore>,
    ) -> Self {
        let guard_data = session.guard_data.clone();
        Self {
            state: Arc::new(RwLock::new(SessionState {
                account_name,
                steam_id,
                refresh_token,
                access_token,
                cookies,
                guard_data,
                platform_type: session.platform_type(),
                generation: 0,
                revoked: false,
            })),
            session: Arc::new(Mutex::new(session)),
            store,
            keeper_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Uses a host-provided store for future persistence and background renewals.
    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = store;
        self
    }

    fn snapshot(&self) -> SessionState {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn replace_state(&self, state: SessionState) {
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = state;
    }

    /// Refreshes the web cookies on demand.
    pub async fn get_cookies(&self) -> Result<SteamWebCookies> {
        let mut session = self.session.lock().await;
        let cookies = session.get_web_cookies().await?;

        let mut state = self.snapshot();
        if state.revoked {
            return Err(SteamError::InvalidToken("Session has been revoked".into()));
        }
        state.cookies = cookies.clone();
        state.refresh_token = session.refresh_token.clone().unwrap_or_default();
        state.access_token = session.access_token.clone().unwrap_or_default();
        state.steam_id = session.steam_id.unwrap_or_default();
        state.guard_data = session.guard_data.clone();
        drop(session);
        self.replace_state(state);
        Ok(cookies)
    }

    /// Renews the access token and web cookies immediately via the Steam API.
    pub async fn renew(&self) -> Result<()> {
        let mut session = self.session.lock().await;
        let (tokens, cookies) = session.renew().await?;
        let mut state = self.snapshot();
        if state.revoked {
            return Err(SteamError::InvalidToken("Session has been revoked".into()));
        }
        state.refresh_token = tokens.export_refresh_token().to_string();
        state.access_token = tokens.export_access_token().to_string();
        state.cookies = cookies;
        state.guard_data = session.guard_data.clone();
        if state.steam_id == 0 {
            state.steam_id = session.steam_id.unwrap_or_default();
        }
        if state.account_name.is_empty() {
            state.account_name = session.account_name.clone().unwrap_or_default();
        }
        drop(session);
        self.replace_state(state);
        Ok(())
    }

    /// Explicitly rotates the MobileApp refresh token. Hosts should persist the session after a
    /// successful rotation; local state is updated before a storage retry can occur.
    pub async fn renew_refresh_token(&self) -> Result<bool> {
        let mut session = self.session.lock().await;
        let changed = session.renew_refresh_token().await?;
        if !changed {
            return Ok(false);
        }
        let mut state = self.snapshot();
        if state.revoked {
            return Err(SteamError::InvalidToken("Session has been revoked".into()));
        }
        state.refresh_token = session.refresh_token.clone().unwrap_or_default();
        state.steam_id = session.steam_id.unwrap_or_default();
        drop(session);
        self.replace_state(state);
        Ok(true)
    }

    /// Saves the current session through the configured [`SessionStore`].
    ///
    /// [`SessionVault`] requires the optional `keyring-store` feature. Portable targets should
    /// inject their own platform-secure store with [`Self::with_session_store`].
    pub fn save_to_vault(&self) -> Result<()> {
        let state = self.snapshot();
        if state.revoked {
            return Err(SteamError::InvalidToken("Session has been revoked".into()));
        }
        let saved = SavedSession {
            account_name: state.account_name,
            steam_id: state.steam_id,
            refresh_token: state.refresh_token,
            access_token: state.access_token,
            cookies: state.cookies,
            guard_data: state.guard_data,
            platform_type: state.platform_type,
            saved_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        self.store.save(&saved)
    }

    /// Deletes this session from the OS credential store.
    pub fn delete_from_vault(&self) -> Result<()> {
        let account_name = self.snapshot().account_name;
        if account_name.is_empty() {
            return Err(SteamError::InvalidResponse(
                "Cannot delete a session without an account name",
            ));
        }
        self.store.delete(&account_name)
    }

    /// Revokes the refresh token with Steam, removes persisted state, and clears local secrets.
    pub async fn revoke_and_delete(&self) -> Result<()> {
        let existing = self.snapshot();
        if existing.revoked {
            return self.store.delete(&existing.account_name);
        }
        let mut session = self.session.lock().await;
        session.revoke_refresh_token().await?;
        drop(session);

        let mut cleared = self.snapshot();
        let account_name = cleared.account_name.clone();
        cleared.steam_id = 0;
        cleared.refresh_token.clear();
        cleared.access_token.clear();
        cleared.cookies = SteamWebCookies {
            session_id: String::new(),
            steam_login_secure: None,
            all_cookies: Vec::new(),
        };
        cleared.guard_data = None;
        cleared.generation = cleared.generation.wrapping_add(1);
        cleared.revoked = true;
        self.replace_state(cleared);

        // Local invalidation is guaranteed even when secure storage is temporarily unavailable.
        self.store.delete(&account_name)?;
        Ok(())
    }

    /// Starts a background auto-renewal daemon (`AutoKeeper`) that monitors token expiration
    /// and silently refreshes tokens and web cookies before they expire.
    pub fn spawn_keeper(&self, interval: Option<Duration>) -> AutoKeeperHandle {
        AutoKeeper::spawn(
            Arc::clone(&self.session),
            Arc::clone(&self.state),
            Arc::clone(&self.store),
            Arc::clone(&self.keeper_active),
            interval,
        )
    }

    /// Starts one background auto-renewal task, returning an error for invalid intervals or a
    /// second keeper on the same authenticated session.
    pub fn try_spawn_keeper(&self, interval: Option<Duration>) -> Result<AutoKeeperHandle> {
        AutoKeeper::try_spawn(
            Arc::clone(&self.session),
            Arc::clone(&self.state),
            Arc::clone(&self.store),
            Arc::clone(&self.keeper_active),
            interval,
        )
    }

    /// Reports the token platform selected for this authenticated session.
    pub fn platform_type(&self) -> EAuthTokenPlatformType {
        self.snapshot().platform_type
    }

    /// Returns the short-lived access token only when the caller explicitly needs to export it.
    pub fn export_access_token(&self) -> String {
        self.snapshot().access_token
    }

    /// Returns the long-lived refresh token only when the caller explicitly needs to export it.
    pub fn export_refresh_token(&self) -> String {
        self.snapshot().refresh_token
    }

    /// Returns the 64-bit SteamID of the authenticated user.
    pub fn steam_id(&self) -> u64 {
        self.snapshot().steam_id
    }

    /// Returns the account login name.
    pub fn account_name(&self) -> String {
        self.snapshot().account_name
    }

    /// Returns the `steamLoginSecure` cookie value if present.
    pub fn export_steam_login_secure(&self) -> Option<String> {
        self.snapshot().cookies.steam_login_secure
    }

    /// Returns the active web session ID (`sessionid` cookie).
    pub fn export_session_id(&self) -> String {
        self.snapshot().cookies.session_id
    }

    /// Returns device guard data only when the caller explicitly needs to export it.
    pub fn export_guard_data(&self) -> Option<String> {
        self.snapshot().guard_data
    }

    /// Returns a pre-formatted HTTP `Cookie` header string containing `steamLoginSecure` and `sessionid`.
    ///
    /// Ready to be attached directly to requests to `steamcommunity.com` or `store.steampowered.com`.
    pub fn cookie_header(&self) -> String {
        let cookies = self.snapshot().cookies;
        match &cookies.steam_login_secure {
            Some(login_secure) => {
                if login_secure.starts_with("steamLoginSecure=") {
                    format!("sessionid={}; {}", cookies.session_id, login_secure)
                } else {
                    format!(
                        "sessionid={}; steamLoginSecure={}",
                        cookies.session_id, login_secure
                    )
                }
            }
            None => format!("sessionid={}", cookies.session_id),
        }
    }

    /// Returns a pre-formatted `Authorization: Bearer <access_token>` header value.
    pub fn bearer_auth_header(&self) -> String {
        format!("Bearer {}", self.snapshot().access_token)
    }
}

fn validate_challenge_tokens(
    session: &LoginSession,
    tokens: &AuthTokens,
    expected_attempt: u64,
) -> Result<()> {
    if tokens.attempt_id != expected_attempt
        || session.refresh_token.as_deref() != Some(tokens.export_refresh_token())
        || session.access_token.as_deref() != Some(tokens.export_access_token())
        || session.account_name.as_deref() != Some(tokens.account_name.as_str())
    {
        return Err(SteamError::InvalidResponse(
            "Authentication tokens do not belong to this challenge",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    use crate::proto::CAuthenticationTokenRevokeResponse;
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportFuture};

    struct FakeTransport {
        responses: StdMutex<VecDeque<HttpResponse>>,
    }

    impl FakeTransport {
        fn new(response: HttpResponse) -> Self {
            Self {
                responses: StdMutex::new(VecDeque::from([response])),
            }
        }
    }

    impl HttpTransport for FakeTransport {
        fn execute(&self, _request: HttpRequest) -> TransportFuture<'_, HttpResponse> {
            let response = self
                .responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .ok_or(SteamError::InvalidResponse("Unexpected request"));
            Box::pin(async move { response })
        }
    }

    #[derive(Default)]
    struct RetryDeleteStore {
        remaining_failures: AtomicUsize,
    }

    impl RetryDeleteStore {
        fn fail_once() -> Self {
            Self {
                remaining_failures: AtomicUsize::new(1),
            }
        }
    }

    impl SessionStore for RetryDeleteStore {
        fn save(&self, _session: &SavedSession) -> Result<()> {
            Ok(())
        }

        fn load(&self, _account_name: &str) -> Result<Option<SavedSession>> {
            Ok(None)
        }

        fn delete(&self, _account_name: &str) -> Result<()> {
            if self
                .remaining_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |failures| {
                    failures.checked_sub(1)
                })
                .is_ok()
            {
                Err(SteamError::Internal("store failure".into()))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn platform_options_are_explicit_and_do_not_synthesize_mobile_web_settings() {
        let browser = LoginOptions::web_browser();
        assert_eq!(browser.platform_type, EAuthTokenPlatformType::WebBrowser);
        assert_eq!(browser.website_id.as_deref(), Some("Community"));
        assert_eq!(
            browser.build_session().unwrap().platform_type(),
            EAuthTokenPlatformType::WebBrowser
        );

        let mobile = LoginOptions::mobile_app();
        assert_eq!(mobile.website_id.as_deref(), Some("Mobile"));
        assert_eq!(
            mobile.build_session().unwrap().platform_type(),
            EAuthTokenPlatformType::MobileApp
        );
        assert!(matches!(
            LoginOptions::steam_client().build_session(),
            Err(SteamError::CmNotImplemented)
        ));
        assert!(matches!(
            LoginOptions::new(EAuthTokenPlatformType::Unknown).build_session(),
            Err(SteamError::UnsupportedPlatform(_))
        ));
    }

    #[tokio::test]
    async fn revocation_clears_local_secrets_before_retrying_storage_deletion() {
        let response = HttpResponse {
            status: 200,
            headers: vec![("x-eresult".into(), "1".into())],
            body: CAuthenticationTokenRevokeResponse::default().encode_to_vec(),
        };
        let client = SteamApiClient::with_transport(Arc::new(FakeTransport::new(response)));
        let session = LoginSession::new(EAuthTokenPlatformType::WebBrowser)
            .with_client(client)
            .with_refresh_token("refresh-secret")
            .with_guard_data("guard-secret");
        let authenticated = AuthenticatedSession::new(
            "account".into(),
            42,
            "refresh-secret".into(),
            "access-secret".into(),
            SteamWebCookies {
                session_id: "session-secret".into(),
                steam_login_secure: Some("steamLoginSecure=cookie-secret".into()),
                all_cookies: vec!["steamLoginSecure=cookie-secret".into()],
            },
            session,
        )
        .with_session_store(Arc::new(RetryDeleteStore::fail_once()));

        assert!(authenticated.revoke_and_delete().await.is_err());
        assert!(authenticated.export_refresh_token().is_empty());
        assert!(authenticated.export_access_token().is_empty());
        assert!(authenticated.export_guard_data().is_none());
        assert!(authenticated.export_steam_login_secure().is_none());
        assert!(!format!("{authenticated:?}").contains("secret"));

        authenticated
            .revoke_and_delete()
            .await
            .expect("retry only deletes the already-revoked local record");
    }
}

/// A pending QR code authentication challenge.
pub struct QrChallenge {
    /// The challenge URL to be encoded in a QR code (e.g. `https://s.team/q/1/...`).
    pub url: String,
    /// The unique Steam client identifier for this attempt.
    pub client_id: u64,
    interval: f32,
    session: LoginSession,
    attempt_id: u64,
}

/// A credential login that may require a Steam Guard code before it can complete.
pub struct CredentialsChallenge {
    start_info: crate::session::CredentialsAuthSession,
    session: LoginSession,
}

impl CredentialsChallenge {
    /// Returns the confirmation methods accepted by Steam for this login.
    pub fn allowed_confirmations(&self) -> &[EAuthSessionGuardType] {
        &self.start_info.allowed_confirmations
    }

    /// Returns Steam's recommended polling interval for this login.
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs_f32(self.start_info.interval)
    }

    /// Submits an email or mobile authenticator Steam Guard code.
    pub async fn submit_steam_guard_code(
        &self,
        code: &str,
        code_type: EAuthSessionGuardType,
    ) -> Result<()> {
        self.session.submit_steam_guard_code(code, code_type).await
    }

    /// Performs one non-blocking poll of the Steam authentication state.
    pub async fn poll_status(&mut self) -> Result<PollStatus> {
        self.session.poll_status().await
    }

    /// Completes a login after a previous poll returned confirmed tokens.
    pub async fn finish(mut self, tokens: AuthTokens) -> Result<AuthenticatedSession> {
        validate_challenge_tokens(&self.session, &tokens, self.start_info.attempt_id)?;
        let cookies = self.session.get_web_cookies().await?;
        let steam_id = self.session.steam_id.unwrap_or_default();
        let refresh_token = self.session.refresh_token.clone().unwrap_or_default();
        let access_token = self.session.access_token.clone().unwrap_or_default();

        Ok(AuthenticatedSession::new(
            tokens.account_name.clone(),
            steam_id,
            refresh_token,
            access_token,
            cookies,
            self.session,
        ))
    }

    /// Waits until the login is approved or the timeout expires.
    pub async fn wait_for_confirmation(
        mut self,
        timeout: Duration,
    ) -> Result<AuthenticatedSession> {
        let tokens = self
            .session
            .poll_until_confirmed(self.start_info.interval, timeout)
            .await?;
        self.finish(tokens).await
    }

    /// Cancels this local authentication attempt without guessing at an undocumented remote API.
    pub fn cancel(mut self) {
        self.session.cancel_authentication();
    }
}

impl QrChallenge {
    /// Renders the QR challenge as an ASCII string formatted for console displays.
    pub fn render_ascii(&self) -> Result<String> {
        let code =
            QrCode::new(self.url.as_bytes()).map_err(|e| SteamError::QrCode(e.to_string()))?;
        let image = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build();
        Ok(image)
    }

    /// Performs one non-blocking poll of the Steam authentication state.
    pub async fn poll_status(&mut self) -> Result<PollStatus> {
        let status = self.session.poll_status().await?;
        if let PollStatus::RemoteInteraction {
            new_challenge_url: Some(new_challenge_url),
        } = &status
        {
            self.url = new_challenge_url.clone();
        }
        Ok(status)
    }

    /// Completes a QR login after a previous poll returned confirmed tokens.
    pub async fn finish(mut self, tokens: AuthTokens) -> Result<AuthenticatedSession> {
        validate_challenge_tokens(&self.session, &tokens, self.attempt_id)?;
        let cookies = self.session.get_web_cookies().await?;
        let steam_id = self.session.steam_id.unwrap_or_default();
        let refresh_token = self.session.refresh_token.clone().unwrap_or_default();
        let access_token = self.session.access_token.clone().unwrap_or_default();

        Ok(AuthenticatedSession::new(
            tokens.account_name.clone(),
            steam_id,
            refresh_token,
            access_token,
            cookies,
            self.session,
        ))
    }

    /// Awaits until the user scans the QR code in their Steam Mobile app and approves the login.
    pub async fn wait_for_scan(mut self, timeout: Duration) -> Result<AuthenticatedSession> {
        let tokens = self
            .session
            .poll_until_confirmed(self.interval, timeout)
            .await?;
        self.finish(tokens).await
    }

    /// Cancels this local authentication attempt without guessing at an undocumented remote API.
    pub fn cancel(mut self) {
        self.session.cancel_authentication();
    }
}

/// The primary developer facade for Steam authentication.
pub struct SteamAuth;

impl SteamAuth {
    /// Starts a credential login and returns an interactive challenge when Steam Guard is needed.
    pub async fn begin_login(account_name: &str, password: &str) -> Result<CredentialsChallenge> {
        Self::begin_login_with_options(account_name, password, LoginOptions::web_browser()).await
    }

    /// Starts a credential login for an explicitly selected Steam token platform.
    pub async fn begin_login_with_options(
        account_name: &str,
        password: &str,
        options: LoginOptions,
    ) -> Result<CredentialsChallenge> {
        let mut session = options.build_session()?;
        let start_info = session
            .start_with_credentials(account_name, password)
            .await?;

        Ok(CredentialsChallenge {
            start_info,
            session,
        })
    }

    /// Initiates a credential login that can complete through mobile approval.
    ///
    /// Use [`SteamAuth::begin_login`] when the host application must submit an email or
    /// authenticator Steam Guard code.
    ///
    /// # Example
    /// ```no_run
    /// # async fn run() -> steam_core::Result<()> {
    /// use steam_core::{SteamAuth, AuthEvent};
    ///
    /// let session = SteamAuth::login("username", "password", |event| {
    ///     match event {
    ///         AuthEvent::NeedMobileConfirmation => println!("Approve on your phone!"),
    ///         _ => {}
    ///     }
    /// }).await?;
    ///
    /// println!("Session cookie available: {}", session.export_steam_login_secure().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login<F>(
        account_name: &str,
        password: &str,
        on_event: F,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        Self::login_with_options(
            account_name,
            password,
            on_event,
            LoginOptions::web_browser(),
        )
        .await
    }

    /// Initiates a credential login for an explicitly selected token platform.
    pub async fn login_with_options<F>(
        account_name: &str,
        password: &str,
        mut on_event: F,
        options: LoginOptions,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        let challenge = Self::begin_login_with_options(account_name, password, options).await?;
        let start_info = challenge.start_info.clone();

        if start_info
            .allowed_confirmations
            .contains(&EAuthSessionGuardType::DeviceConfirmation)
        {
            on_event(AuthEvent::NeedMobileConfirmation);
        } else if start_info
            .allowed_confirmations
            .contains(&EAuthSessionGuardType::DeviceCode)
        {
            on_event(AuthEvent::NeedDeviceCode);
            return Err(SteamError::SteamGuardCodeRequired);
        } else if start_info
            .allowed_confirmations
            .contains(&EAuthSessionGuardType::EmailCode)
        {
            on_event(AuthEvent::NeedEmailCode);
            return Err(SteamError::SteamGuardCodeRequired);
        }

        on_event(AuthEvent::Polling);
        let authenticated = challenge
            .wait_for_confirmation(Duration::from_secs(120))
            .await?;
        on_event(AuthEvent::Authenticated {
            account_name: authenticated.account_name(),
        });
        Ok(authenticated)
    }

    /// Performs credential-based login and immediately persists the session securely into the OS credential store.
    pub async fn login_and_store<F>(
        account_name: &str,
        password: &str,
        on_event: F,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        Self::login_and_store_with(account_name, password, on_event, Arc::new(SessionVault)).await
    }

    /// Performs credential login and persists the resulting session through a host-provided store.
    pub async fn login_and_store_with<F>(
        account_name: &str,
        password: &str,
        on_event: F,
        store: Arc<dyn SessionStore>,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        Self::login_and_store_with_options(
            account_name,
            password,
            on_event,
            store,
            LoginOptions::web_browser(),
        )
        .await
    }

    /// Performs credential login with explicit platform options and persists it through a
    /// host-provided store.
    pub async fn login_and_store_with_options<F>(
        account_name: &str,
        password: &str,
        on_event: F,
        store: Arc<dyn SessionStore>,
        options: LoginOptions,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        let session = Self::login_with_options(account_name, password, on_event, options)
            .await?
            .with_session_store(store);
        session.save_to_vault()?;
        Ok(session)
    }

    /// Loads an authenticated session metadata record directly from the OS credential store without network calls.
    pub fn load_from_vault(account_name: &str) -> Result<Option<SavedSession>> {
        SessionVault::load(account_name)
    }

    /// Loads session metadata from a host-provided store without network calls.
    pub fn load_from_store(
        account_name: &str,
        store: &dyn SessionStore,
    ) -> Result<Option<SavedSession>> {
        store.load(account_name)
    }

    /// Restores an authenticated session from the OS credential store.
    ///
    /// If the access token is expired or close to expiring, it silently contacts the Steam API,
    /// renews the tokens and cookies, updates the OS vault, and returns the restored session.
    pub async fn restore_from_vault(account_name: &str) -> Result<Option<AuthenticatedSession>> {
        Self::restore_from_store(account_name, Arc::new(SessionVault)).await
    }

    /// Restores an authenticated session through a host-provided store.
    pub async fn restore_from_store(
        account_name: &str,
        store: Arc<dyn SessionStore>,
    ) -> Result<Option<AuthenticatedSession>> {
        let saved = match store.load(account_name)? {
            Some(s) => s,
            None => return Ok(None),
        };

        let options = LoginOptions::new(saved.platform_type());
        Self::restore_saved(account_name, saved, store, options).await
    }

    /// Restores an authenticated session with an explicit HTTP transport and platform policy.
    pub async fn restore_from_store_with_options(
        account_name: &str,
        store: Arc<dyn SessionStore>,
        options: LoginOptions,
    ) -> Result<Option<AuthenticatedSession>> {
        let saved = match store.load(account_name)? {
            Some(s) => s,
            None => return Ok(None),
        };
        Self::restore_saved(account_name, saved, store, options).await
    }

    async fn restore_saved(
        account_name: &str,
        saved: SavedSession,
        store: Arc<dyn SessionStore>,
        options: LoginOptions,
    ) -> Result<Option<AuthenticatedSession>> {
        saved.validate()?;
        if saved.account_name != account_name {
            return Err(SteamError::InvalidResponse(
                "Saved session account does not match requested account",
            ));
        }
        if saved.platform_type() != options.platform_type {
            return Err(SteamError::UnsupportedPlatform(
                "Saved session platform does not match LoginOptions",
            ));
        }

        let mut session = options.build_session()?;
        if let Some(guard_data) = saved.guard_data.clone() {
            session = session.with_guard_data(guard_data);
        }
        session.steam_id = Some(saved.steam_id);
        session.account_name = Some(saved.account_name.clone());
        session.set_refresh_token(saved.refresh_token.clone())?;
        session.set_access_token(saved.access_token.clone())?;

        // MobileApp has a supported access-token refresh flow. Browser access-token refresh is
        // intentionally not attempted; callers can still use its refresh token for web cookies.
        let needs_refresh = crate::tokens::is_token_expired(&saved.access_token, 900);

        if needs_refresh {
            if saved.platform_type() == EAuthTokenPlatformType::WebBrowser {
                return Err(SteamError::SessionExpired);
            }
            let (tokens, cookies) = session.renew().await?;
            let updated = AuthenticatedSession::new(
                saved.account_name,
                session.steam_id.unwrap_or(saved.steam_id),
                tokens.export_refresh_token().to_string(),
                tokens.export_access_token().to_string(),
                cookies,
                session,
            )
            .with_session_store(store);
            updated.save_to_vault()?;
            Ok(Some(updated))
        } else {
            Ok(Some(
                AuthenticatedSession::new(
                    saved.account_name,
                    saved.steam_id,
                    saved.refresh_token,
                    saved.access_token,
                    saved.cookies,
                    session,
                )
                .with_session_store(store),
            ))
        }
    }

    /// One-line login with automatic vault restoration:
    ///
    /// Attempts to restore an existing valid session from the OS credential store first.
    /// If no session is saved or its token is invalid, it performs a new login and saves the result.
    /// Credential-store and network failures are returned to the caller rather than being hidden.
    pub async fn load_or_login<F>(
        account_name: &str,
        password: &str,
        on_event: F,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        Self::load_or_login_with(account_name, password, on_event, Arc::new(SessionVault)).await
    }

    /// Restores or creates a session using a host-provided store.
    pub async fn load_or_login_with<F>(
        account_name: &str,
        password: &str,
        on_event: F,
        store: Arc<dyn SessionStore>,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        match Self::restore_from_store(account_name, Arc::clone(&store)).await {
            Ok(Some(restored)) => return Ok(restored),
            Ok(None)
            | Err(SteamError::InvalidToken(_))
            | Err(SteamError::SessionExpired)
            | Err(SteamError::SteamApi { eresult: 27, .. }) => {}
            Err(error) => return Err(error),
        }

        Self::login_and_store_with(account_name, password, on_event, store).await
    }

    /// Starts a QR code login challenge.
    ///
    /// # Example
    /// ```no_run
    /// # async fn run() -> steam_core::Result<()> {
    /// use steam_core::SteamAuth;
    /// use std::time::Duration;
    ///
    /// let qr = SteamAuth::get_qr().await?;
    /// println!("{}", qr.render_ascii()?); // Prints QR code directly in the terminal!
    ///
    /// let session = qr.wait_for_scan(Duration::from_secs(60)).await?;
    /// println!("Authenticated: {}", session.account_name());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_qr() -> Result<QrChallenge> {
        Self::get_qr_with_options(LoginOptions::web_browser()).await
    }

    /// Starts a QR challenge for an explicitly selected Steam token platform.
    pub async fn get_qr_with_options(options: LoginOptions) -> Result<QrChallenge> {
        let mut session = options.build_session()?;
        let qr_session = session.start_with_qr().await?;

        Ok(QrChallenge {
            url: qr_session.challenge_url,
            client_id: qr_session.client_id,
            interval: qr_session.interval,
            session,
            attempt_id: qr_session.attempt_id,
        })
    }

    /// Produces an error because a WebBrowser refresh token cannot safely mint an access token.
    ///
    /// Use [`Self::web_cookies_from_refresh_token`] to obtain browser cookies, or
    /// [`Self::from_mobile_refresh_token_for_account`] for a complete MobileApp session.
    ///
    /// # Example
    /// ```no_run
    /// # async fn run() -> steam_core::Result<()> {
    /// use steam_core::SteamAuth;
    ///
    /// let cookies = SteamAuth::web_cookies_from_refresh_token("saved_refresh_token_here").await?;
    /// println!("Cookies available: {}", cookies.export_steam_login_secure().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_token(_refresh_token: impl Into<String>) -> Result<AuthenticatedSession> {
        Err(SteamError::UnsupportedPlatform(
            "WebBrowser refresh tokens only derive web cookies; use web_cookies_from_refresh_token",
        ))
    }

    /// Produces an error for the same reason as [`Self::from_token`].
    pub async fn from_token_for_account(
        _account_name: impl Into<String>,
        _refresh_token: impl Into<String>,
    ) -> Result<AuthenticatedSession> {
        Err(SteamError::UnsupportedPlatform(
            "WebBrowser refresh tokens only derive web cookies; use web_cookies_from_refresh_token",
        ))
    }

    /// Derives WebBrowser cookies from a valid browser refresh token without minting an access
    /// token or fabricating an authenticated application session.
    pub async fn web_cookies_from_refresh_token(
        refresh_token: impl Into<String>,
    ) -> Result<SteamWebCookies> {
        let refresh_token = refresh_token.into();
        let steam_id = crate::tokens::validate_steam_token(
            &refresh_token,
            crate::tokens::SteamTokenKind::Refresh,
            EAuthTokenPlatformType::WebBrowser,
            None,
        )?;
        let mut session =
            LoginSession::new(EAuthTokenPlatformType::WebBrowser).with_refresh_token(refresh_token);
        session.steam_id = Some(steam_id);
        session.get_web_cookies().await
    }

    /// Restores a complete MobileApp session from a refresh token and a host-supplied account
    /// name suitable for persistence.
    pub async fn from_mobile_refresh_token_for_account(
        account_name: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> Result<AuthenticatedSession> {
        let account_name = account_name.into();
        if account_name.trim().is_empty() || account_name.chars().any(char::is_control) {
            return Err(SteamError::InvalidResponse("Invalid account name"));
        }
        let refresh_token = refresh_token.into();
        let steam_id = crate::tokens::validate_steam_token(
            &refresh_token,
            crate::tokens::SteamTokenKind::Refresh,
            EAuthTokenPlatformType::MobileApp,
            None,
        )?;
        let mut session = LoginOptions::mobile_app()
            .build_session()?
            .with_refresh_token(refresh_token);
        session.account_name = Some(account_name.clone());
        session.steam_id = Some(steam_id);
        let (tokens, cookies) = session.renew().await?;
        Ok(AuthenticatedSession::new(
            account_name,
            steam_id,
            tokens.export_refresh_token().to_string(),
            tokens.export_access_token().to_string(),
            cookies,
            session,
        ))
    }
}
