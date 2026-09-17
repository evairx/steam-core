//! Ergonomic, high-level developer facade (`SteamAuth`) for zero-friction integration.

use std::sync::Arc;
use std::time::Duration;
use qrcode::render::unicode;
use qrcode::QrCode;
use tokio::sync::Mutex;

use crate::client::SteamWebCookies;
use crate::enums::{EAuthSessionGuardType, EAuthTokenPlatformType};
use crate::error::{Result, SteamError};
use crate::keeper::{AutoKeeper, AutoKeeperHandle};
use crate::session::{AuthTokens, LoginSession, PollStatus};
use crate::vault::{SavedSession, SessionVault};

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

/// An authenticated session with ready-to-use tokens and web cookies.
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    /// The authenticated Steam account name.
    pub account_name: String,
    /// The resolved SteamID64.
    pub steam_id: u64,
    /// The long-lived refresh token.
    pub refresh_token: String,
    /// The short-lived access token.
    pub access_token: String,
    /// Web cookies (`steamLoginSecure`, `sessionid`, etc.).
    pub cookies: SteamWebCookies,
    session: Arc<Mutex<LoginSession>>,
}

impl AuthenticatedSession {
    /// Creates a new `AuthenticatedSession` wrapping the inner `LoginSession`.
    pub fn new(
        account_name: String,
        steam_id: u64,
        refresh_token: String,
        access_token: String,
        cookies: SteamWebCookies,
        session: LoginSession,
    ) -> Self {
        Self {
            account_name,
            steam_id,
            refresh_token,
            access_token,
            cookies,
            session: Arc::new(Mutex::new(session)),
        }
    }

    /// Refreshes the web cookies on demand.
    pub async fn get_cookies(&self) -> Result<SteamWebCookies> {
        let session = self.session.lock().await;
        session.get_web_cookies().await
    }

    /// Renews the access token and web cookies immediately via the Steam API.
    pub async fn renew(&mut self) -> Result<()> {
        let mut session = self.session.lock().await;
        let (tokens, cookies) = session.renew().await?;
        self.refresh_token = tokens.refresh_token;
        self.access_token = tokens.access_token;
        self.cookies = cookies;
        if self.steam_id == 0 {
            self.steam_id = session.steam_id.unwrap_or_default();
        }
        if self.account_name.is_empty() {
            self.account_name = session.account_name.clone().unwrap_or_default();
        }
        Ok(())
    }

    /// Saves the current session securely into the OS credential store
    /// (Windows Credential Manager / macOS Keychain / Linux Secret Service).
    pub fn save_to_vault(&self) -> Result<()> {
        let saved = SavedSession {
            account_name: self.account_name.clone(),
            steam_id: self.steam_id,
            refresh_token: self.refresh_token.clone(),
            access_token: self.access_token.clone(),
            cookies: self.cookies.clone(),
            saved_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        SessionVault::save(&saved)
    }

    /// Deletes this session from the OS credential store.
    pub fn delete_from_vault(&self) -> Result<()> {
        SessionVault::delete(&self.account_name)
    }

    /// Starts a background auto-renewal daemon (`AutoKeeper`) that monitors token expiration
    /// and silently refreshes tokens and web cookies before they expire.
    pub fn spawn_keeper(&self, interval: Option<Duration>) -> AutoKeeperHandle {
        AutoKeeper::spawn(Arc::clone(&self.session), self.cookies.clone(), interval)
    }

    /// Returns the short-lived access token, specifically used for the Steam CM Client Logon
    /// (`CMsgClientLogon.access_token`) and WebAPI calls.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the long-lived refresh token used for session persistence and renewal.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Returns the 64-bit SteamID of the authenticated user.
    pub fn steam_id(&self) -> u64 {
        self.steam_id
    }

    /// Returns the account login name.
    pub fn account_name(&self) -> &str {
        &self.account_name
    }

    /// Returns the `steamLoginSecure` cookie value if present.
    pub fn steam_login_secure(&self) -> Option<&str> {
        self.cookies.steam_login_secure.as_deref()
    }

    /// Returns the active web session ID (`sessionid` cookie).
    pub fn session_id(&self) -> &str {
        &self.cookies.session_id
    }

    /// Returns a pre-formatted HTTP `Cookie` header string containing `steamLoginSecure` and `sessionid`.
    ///
    /// Ready to be attached directly to requests to `steamcommunity.com` or `store.steampowered.com`.
    pub fn cookie_header(&self) -> String {
        match &self.cookies.steam_login_secure {
            Some(login_secure) => {
                if login_secure.starts_with("steamLoginSecure=") {
                    format!("sessionid={}; {}", self.cookies.session_id, login_secure)
                } else {
                    format!(
                        "sessionid={}; steamLoginSecure={}",
                        self.cookies.session_id, login_secure
                    )
                }
            }
            None => format!("sessionid={}", self.cookies.session_id),
        }
    }

    /// Returns a pre-formatted `Authorization: Bearer <access_token>` header value.
    pub fn bearer_auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
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
}

impl QrChallenge {
    /// Renders the QR challenge as an ASCII string formatted for console displays.
    pub fn render_ascii(&self) -> Result<String> {
        let code = QrCode::new(self.url.as_bytes())
            .map_err(|e| SteamError::QrCode(e.to_string()))?;
        let image = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build();
        Ok(image)
    }

    /// Awaits until the user scans the QR code in their Steam Mobile app and approves the login.
    pub async fn wait_for_scan(mut self, timeout: Duration) -> Result<AuthenticatedSession> {
        let tokens = self.session.poll_until_confirmed(self.interval, timeout).await?;
        let cookies = self.session.get_web_cookies().await?;
        let steam_id = self.session.steam_id.unwrap_or_default();

        Ok(AuthenticatedSession::new(
            tokens.account_name,
            steam_id,
            tokens.refresh_token,
            tokens.access_token,
            cookies,
            self.session,
        ))
    }
}

/// The primary developer facade for Steam authentication.
pub struct SteamAuth;

impl SteamAuth {
    /// Initiates a credential login, invokes the `on_event` callback when confirmation is needed,
    /// and waits for confirmation before returning an [`AuthenticatedSession`].
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
    /// println!("Session cookie: {:?}", session.cookies.steam_login_secure);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login<F>(
        account_name: &str,
        password: &str,
        mut on_event: F,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser);
        let start_info = session.start_with_credentials(account_name, password).await?;

        if start_info.allowed_confirmations.contains(&EAuthSessionGuardType::DeviceConfirmation) {
            on_event(AuthEvent::NeedMobileConfirmation);
        } else if start_info.allowed_confirmations.contains(&EAuthSessionGuardType::DeviceCode) {
            on_event(AuthEvent::NeedDeviceCode);
        } else if start_info.allowed_confirmations.contains(&EAuthSessionGuardType::EmailCode) {
            on_event(AuthEvent::NeedEmailCode);
        }

        let timeout = Duration::from_secs(120);
        let start = std::time::Instant::now();
        let interval = if start_info.interval < 1.0 { 3.0 } else { start_info.interval };
        let sleep_duration = Duration::from_secs_f32(interval);

        let tokens: AuthTokens;
        loop {
            if start.elapsed() > timeout {
                return Err(SteamError::SessionExpired);
            }

            on_event(AuthEvent::Polling);
            match session.poll_status().await? {
                PollStatus::Confirmed(t) => {
                    on_event(AuthEvent::Authenticated {
                        account_name: t.account_name.clone(),
                    });
                    tokens = t;
                    break;
                }
                PollStatus::Waiting => {
                    tokio::time::sleep(sleep_duration).await;
                }
            }
        }

        let cookies = session.get_web_cookies().await?;
        let steam_id = session.steam_id.unwrap_or_default();

        Ok(AuthenticatedSession::new(
            tokens.account_name,
            steam_id,
            tokens.refresh_token,
            tokens.access_token,
            cookies,
            session,
        ))
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
        let session = Self::login(account_name, password, on_event).await?;
        session.save_to_vault()?;
        Ok(session)
    }

    /// Loads an authenticated session metadata record directly from the OS credential store without network calls.
    pub fn load_from_vault(account_name: &str) -> Result<Option<SavedSession>> {
        SessionVault::load(account_name)
    }

    /// Restores an authenticated session from the OS credential store.
    ///
    /// If the access token is expired or close to expiring, it silently contacts the Steam API,
    /// renews the tokens and cookies, updates the OS vault, and returns the restored session.
    pub async fn restore_from_vault(account_name: &str) -> Result<Option<AuthenticatedSession>> {
        let saved = match SessionVault::load(account_name)? {
            Some(s) => s,
            None => return Ok(None),
        };

        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser)
            .with_refresh_token(saved.refresh_token.clone());
        session.steam_id = Some(saved.steam_id);
        session.account_name = Some(saved.account_name.clone());

        // Check if access token is expired or close to expiring (15 min safety window)
        let needs_refresh = crate::tokens::is_token_expired(&saved.access_token, 900);

        if needs_refresh {
            match session.renew().await {
                Ok((tokens, cookies)) => {
                    let updated = AuthenticatedSession::new(
                        saved.account_name,
                        saved.steam_id,
                        tokens.refresh_token,
                        tokens.access_token,
                        cookies,
                        session,
                    );
                    let _ = updated.save_to_vault();
                    Ok(Some(updated))
                }
                Err(e) => {
                    // Session refresh failed (e.g. revoked or expired)
                    Err(e)
                }
            }
        } else {
            session.access_token = Some(saved.access_token.clone());
            Ok(Some(AuthenticatedSession::new(
                saved.account_name,
                saved.steam_id,
                saved.refresh_token,
                saved.access_token,
                saved.cookies,
                session,
            )))
        }
    }

    /// One-line login with automatic vault restoration:
    ///
    /// Attempts to restore an existing valid session from the OS credential store first.
    /// If no session is saved or restoration fails, prompts for login credentials, completes 2FA,
    /// and securely saves the new session to the OS vault.
    pub async fn load_or_login<F>(
        account_name: &str,
        password: &str,
        on_event: F,
    ) -> Result<AuthenticatedSession>
    where
        F: FnMut(AuthEvent) + Send,
    {
        if let Ok(Some(restored)) = Self::restore_from_vault(account_name).await {
            return Ok(restored);
        }

        Self::login_and_store(account_name, password, on_event).await
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
    /// println!("Authenticated: {}", session.account_name);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_qr() -> Result<QrChallenge> {
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser);
        let qr_session = session.start_with_qr().await?;

        Ok(QrChallenge {
            url: qr_session.challenge_url,
            client_id: qr_session.client_id,
            interval: qr_session.interval,
            session,
        })
    }

    /// Restores an existing session from a previously saved refresh token.
    ///
    /// # Example
    /// ```no_run
    /// # async fn run() -> steam_core::Result<()> {
    /// use steam_core::SteamAuth;
    ///
    /// let session = SteamAuth::from_token("saved_refresh_token_here").await?;
    /// let cookies = session.get_cookies().await?;
    /// println!("Cookies refreshed without entering credentials!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_token(refresh_token: impl Into<String>) -> Result<AuthenticatedSession> {
        let token_str = refresh_token.into();
        let mut steam_id = 0;
        if let Ok(claims) = crate::tokens::decode_jwt(&token_str) {
            if let Some(sub) = claims.sub {
                steam_id = sub.parse::<u64>().unwrap_or_default();
            }
        }

        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser)
            .with_refresh_token(token_str.clone());
        if steam_id != 0 {
            session.steam_id = Some(steam_id);
        }

        let (tokens, cookies) = session.renew().await?;
        let sid = session.steam_id.unwrap_or(steam_id);

        Ok(AuthenticatedSession::new(
            tokens.account_name,
            sid,
            tokens.refresh_token,
            tokens.access_token,
            cookies,
            session,
        ))
    }
}
