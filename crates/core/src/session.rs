//! State machine and lifecycle manager for Steam authentication sessions.

use std::fmt;
use std::time::Duration;
use tokio::time::{sleep, timeout, Instant};

use crate::client::{SteamApiClient, SteamApiClientBuilder, SteamRsaKey, SteamWebCookies};
use crate::crypto::{self, EncryptedPassword};
use crate::enums::{EAuthSessionGuardType, EAuthTokenPlatformType, ESessionPersistence};
use crate::error::{Result, SteamError};
use crate::proto::{
    CAuthenticationAccessTokenGenerateForAppRequest,
    CAuthenticationBeginAuthSessionViaCredentialsRequest,
    CAuthenticationBeginAuthSessionViaQrRequest, CAuthenticationDeviceDetails,
    CAuthenticationPollAuthSessionStatusRequest,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest,
};
use crate::tokens::{validate_steam_token, SteamTokenKind};

/// Result of starting a credentials-based authentication session.
#[derive(Clone, PartialEq)]
pub struct CredentialsAuthSession {
    /// Unique identifier for this authentication attempt.
    pub client_id: u64,
    /// Cryptographic challenge / request identifier.
    pub request_id: Vec<u8>,
    /// Recommended interval in seconds between poll attempts.
    pub interval: f32,
    /// List of 2FA guard mechanisms permitted to approve this session.
    pub allowed_confirmations: Vec<EAuthSessionGuardType>,
    /// SteamID of the user, if resolved.
    pub steam_id: u64,
    /// Weak token placeholder, if any.
    weak_token: Option<String>,
    pub(crate) attempt_id: u64,
}

impl fmt::Debug for CredentialsAuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialsAuthSession")
            .field("client_id", &self.client_id)
            .field("request_id_len", &self.request_id.len())
            .field("interval", &self.interval)
            .field("allowed_confirmations", &self.allowed_confirmations)
            .field("steam_id", &self.steam_id)
            .field("has_weak_token", &self.weak_token.is_some())
            .finish()
    }
}

impl CredentialsAuthSession {
    /// Returns the machine-auth token only when the caller explicitly needs to persist it.
    pub fn export_weak_token(&self) -> Option<&str> {
        self.weak_token.as_deref()
    }
}

/// Result of starting a QR-code authentication session.
#[derive(Debug, Clone, PartialEq)]
pub struct QrAuthSession {
    /// Unique identifier for this QR authentication attempt.
    pub client_id: u64,
    /// URL challenge string (e.g. `https://s.team/q/1/...`) to be encoded in a QR code.
    pub challenge_url: String,
    /// Cryptographic challenge identifier.
    pub request_id: Vec<u8>,
    /// Recommended interval in seconds between poll attempts.
    pub interval: f32,
    pub(crate) attempt_id: u64,
}

/// Final authentication tokens returned once an authentication attempt is confirmed.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthTokens {
    /// The long-lived refresh token used to generate web cookies or re-authenticate.
    refresh_token: String,
    /// The short-lived access token used for direct WebAPI calls.
    access_token: String,
    /// The account name for which authentication was confirmed.
    pub account_name: String,
    pub(crate) attempt_id: u64,
}

impl fmt::Debug for AuthTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthTokens")
            .field("has_refresh_token", &!self.refresh_token.is_empty())
            .field("has_access_token", &!self.access_token.is_empty())
            .field("account_name", &self.account_name)
            .finish()
    }
}

impl AuthTokens {
    /// Returns the refresh token only when the caller explicitly needs to export it.
    pub fn export_refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Returns the access token only when the caller explicitly needs to export it.
    pub fn export_access_token(&self) -> &str {
        &self.access_token
    }
}

/// Lifecycle status returned by a single poll operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollStatus {
    /// The user has not yet approved or entered their 2FA code.
    Waiting,
    /// Steam observed an interaction from an approving device; tokens are not issued yet.
    RemoteInteraction {
        /// Replacement QR challenge URL, when Steam rotates it.
        new_challenge_url: Option<String>,
    },
    /// Authentication was approved and tokens have been issued.
    Confirmed(AuthTokens),
}

/// Session manager coordinating the login lifecycle.
#[derive(Clone)]
pub struct LoginSession {
    client: SteamApiClient,
    pub platform_type: EAuthTokenPlatformType,
    pub persistence: ESessionPersistence,
    pub device_name: String,
    website_id: Option<String>,
    pub active_client_id: Option<u64>,
    pub active_request_id: Option<Vec<u8>>,
    pub account_name: Option<String>,
    pub steam_id: Option<u64>,
    pub(crate) refresh_token: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) guard_data: Option<String>,
    allowed_confirmations: Vec<EAuthSessionGuardType>,
    active_attempt: u64,
    cancelled: bool,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("platform_type", &self.platform_type)
            .field("persistence", &self.persistence)
            .field("device_name", &self.device_name)
            .field("active_client_id", &self.active_client_id)
            .field(
                "has_active_request_id",
                &self
                    .active_request_id
                    .as_ref()
                    .is_some_and(|id| !id.is_empty()),
            )
            .field("account_name", &self.account_name)
            .field("steam_id", &self.steam_id)
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("has_access_token", &self.access_token.is_some())
            .field("has_guard_data", &self.guard_data.is_some())
            .finish()
    }
}

impl LoginSession {
    /// Creates a new `LoginSession` for the specified platform type.
    pub fn new(platform_type: EAuthTokenPlatformType) -> Self {
        Self {
            client: SteamApiClient::new().with_auth_platform(platform_type),
            platform_type,
            persistence: ESessionPersistence::Persistent,
            device_name: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            website_id: default_website_id(platform_type),
            active_client_id: None,
            active_request_id: None,
            account_name: None,
            steam_id: None,
            refresh_token: None,
            access_token: None,
            guard_data: None,
            allowed_confirmations: Vec::new(),
            active_attempt: 0,
            cancelled: false,
        }
    }

    /// Sets a custom device friendly name.
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = name.into();
        self
    }

    /// Sets the session persistence level (ephemeral vs persistent).
    pub fn with_persistence(mut self, persistence: ESessionPersistence) -> Self {
        self.persistence = persistence;
        self
    }

    /// Sets an optional Steam website identifier for the authentication request.
    pub fn with_website_id(mut self, website_id: Option<String>) -> Self {
        self.website_id = website_id;
        self
    }

    /// Pre-configures an existing refresh token to restore an active session without entering credentials.
    pub fn with_refresh_token(mut self, token: impl Into<String>) -> Self {
        self.refresh_token = Some(token.into());
        self
    }

    /// Validates and installs a refresh token for this session's platform.
    pub fn set_refresh_token(&mut self, token: impl Into<String>) -> Result<()> {
        let token = token.into();
        let steam_id = validate_steam_token(
            &token,
            SteamTokenKind::Refresh,
            self.platform_type,
            self.steam_id,
        )?;
        self.refresh_token = Some(token);
        self.steam_id = Some(steam_id);
        Ok(())
    }

    /// Validates and installs an access token for this session's platform.
    pub fn set_access_token(&mut self, token: impl Into<String>) -> Result<()> {
        let token = token.into();
        let steam_id = validate_steam_token(
            &token,
            SteamTokenKind::Access,
            self.platform_type,
            self.steam_id,
        )?;
        self.access_token = Some(token);
        self.steam_id = Some(steam_id);
        Ok(())
    }

    /// Pre-configures device guard data returned by a prior successful authentication.
    pub fn with_guard_data(mut self, guard_data: impl Into<String>) -> Self {
        self.guard_data = Some(guard_data.into());
        self
    }

    /// Configures a proxy for the internal HTTP client.
    pub fn with_proxy(mut self, proxy_url: impl Into<String>) -> Result<Self> {
        self.client = SteamApiClientBuilder::default()
            .proxy(proxy_url)
            .build()?
            .with_auth_platform(self.platform_type);
        Ok(self)
    }

    /// Replaces the HTTP transport used by this login session.
    ///
    /// This is primarily intended for host integrations and deterministic contract tests.
    pub fn with_client(mut self, client: SteamApiClient) -> Self {
        self.client = client.with_auth_platform(self.platform_type);
        self
    }

    /// Returns the platform for which this session requests tokens.
    pub fn platform_type(&self) -> EAuthTokenPlatformType {
        self.platform_type
    }

    /// Cancels this local authentication attempt.
    ///
    /// Steam's authentication protobuf in this core does not document a separate cancel endpoint,
    /// so this never guesses at a remote revocation request. A cancelled session cannot be polled
    /// or updated again; start a new challenge instead.
    pub fn cancel_authentication(&mut self) {
        self.cancelled = true;
        self.active_client_id = None;
        self.active_request_id = None;
        self.allowed_confirmations.clear();
    }

    fn clear_for_new_attempt(&mut self) {
        self.active_client_id = None;
        self.active_request_id = None;
        self.account_name = None;
        self.steam_id = None;
        self.refresh_token = None;
        self.access_token = None;
        self.allowed_confirmations.clear();
        self.cancelled = false;
        self.active_attempt = self.active_attempt.wrapping_add(1);
    }

    /// Fetches the RSA public key and encrypts the plaintext password.
    pub async fn get_encrypted_password(
        &self,
        account_name: &str,
        password: &str,
    ) -> Result<(EncryptedPassword, SteamRsaKey)> {
        self.ensure_webapi_auth_platform()?;
        let rsa_key = self
            .client
            .get_password_rsa_public_key(account_name)
            .await?;
        let encrypted = crypto::encrypt_password(
            password,
            &rsa_key.publickey_mod,
            &rsa_key.publickey_exp,
            rsa_key.timestamp,
        )?;
        Ok((encrypted, rsa_key))
    }

    /// Initiates a credential-based login attempt (username and password).
    pub async fn start_with_credentials(
        &mut self,
        account_name: &str,
        password: &str,
    ) -> Result<CredentialsAuthSession> {
        self.ensure_webapi_auth_platform()?;
        let clean_account = account_name.trim().to_string();
        if clean_account.is_empty() || password.is_empty() {
            return Err(SteamError::InvalidCredentials);
        }
        self.clear_for_new_attempt();

        let (encrypted, _) = self
            .get_encrypted_password(&clean_account, password)
            .await?;

        let request = CAuthenticationBeginAuthSessionViaCredentialsRequest {
            device_friendly_name: Some(self.device_name.clone()),
            account_name: Some(clean_account.clone()),
            encrypted_password: Some(encrypted.encrypted_password),
            encryption_timestamp: Some(encrypted.timestamp),
            remember_login: Some(self.persistence == ESessionPersistence::Persistent),
            platform_type: Some(self.platform_type as i32),
            persistence: Some(self.persistence as i32),
            website_id: self.website_id.clone(),
            device_details: Some(CAuthenticationDeviceDetails {
                device_friendly_name: Some(self.device_name.clone()),
                platform_type: Some(self.platform_type as i32),
                os_type: Some(0),
                gaming_device_type: Some(0),
                ..Default::default()
            }),
            guard_data: self.guard_data.clone(),
            ..Default::default()
        };

        let response = self
            .client
            .begin_auth_session_via_credentials(&request)
            .await?;

        let client_id = response.client_id.filter(|id| *id != 0).ok_or_else(|| {
            SteamError::Internal("Steam returned an empty authentication client ID".into())
        })?;
        let request_id = response
            .request_id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                SteamError::Internal("Steam returned an empty authentication request ID".into())
            })?;
        let interval = validate_poll_interval(response.interval.unwrap_or(5.0))?;
        let steam_id = response.steamid.unwrap_or(0);

        self.active_client_id = Some(client_id);
        self.active_request_id = Some(request_id.clone());
        self.account_name = Some(clean_account.clone());
        self.steam_id = Some(steam_id);

        let allowed_confirmations = response
            .allowed_confirmations
            .into_iter()
            .map(|c| EAuthSessionGuardType::from(c.confirmation_type.unwrap_or(0)))
            .collect::<Vec<_>>();
        self.allowed_confirmations = allowed_confirmations.clone();

        Ok(CredentialsAuthSession {
            client_id,
            request_id,
            interval,
            allowed_confirmations,
            steam_id,
            weak_token: response.weak_token,
            attempt_id: self.active_attempt,
        })
    }

    /// Initiates a QR code authentication session.
    pub async fn start_with_qr(&mut self) -> Result<QrAuthSession> {
        self.ensure_webapi_auth_platform()?;
        self.clear_for_new_attempt();
        let request = CAuthenticationBeginAuthSessionViaQrRequest {
            device_friendly_name: Some(self.device_name.clone()),
            platform_type: Some(self.platform_type as i32),
            website_id: self.website_id.clone(),
            device_details: Some(CAuthenticationDeviceDetails {
                device_friendly_name: Some(self.device_name.clone()),
                platform_type: Some(self.platform_type as i32),
                os_type: Some(0),
                gaming_device_type: Some(0),
                ..Default::default()
            }),
        };

        let response = self.client.begin_auth_session_via_qr(&request).await?;

        let client_id = response.client_id.filter(|id| *id != 0).ok_or_else(|| {
            SteamError::Internal("Steam returned an empty QR authentication client ID".into())
        })?;
        let request_id = response
            .request_id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                SteamError::Internal("Steam returned an empty QR authentication request ID".into())
            })?;
        let challenge_url = response
            .challenge_url
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| {
                SteamError::Internal("Steam returned an empty QR challenge URL".into())
            })?;
        let interval = validate_poll_interval(response.interval.unwrap_or(5.0))?;

        self.active_client_id = Some(client_id);
        self.active_request_id = Some(request_id.clone());

        Ok(QrAuthSession {
            client_id,
            challenge_url,
            request_id,
            interval,
            attempt_id: self.active_attempt,
        })
    }

    /// Submits a Steam Guard code (email or mobile TOTP code).
    pub async fn submit_steam_guard_code(
        &self,
        code: &str,
        code_type: EAuthSessionGuardType,
    ) -> Result<()> {
        if self.cancelled {
            return Err(SteamError::AuthCancelled);
        }
        if code.trim().is_empty() {
            return Err(SteamError::InvalidToken(
                "Steam Guard code cannot be empty".into(),
            ));
        }
        if !matches!(
            code_type,
            EAuthSessionGuardType::DeviceCode | EAuthSessionGuardType::EmailCode
        ) {
            return Err(SteamError::Internal(
                "Steam Guard code type must be DeviceCode or EmailCode".into(),
            ));
        }
        if !self.allowed_confirmations.contains(&code_type) {
            return Err(SteamError::Internal(
                "Steam Guard code type was not offered for this authentication session".into(),
            ));
        }
        let client_id = self.active_client_id.ok_or_else(|| {
            SteamError::Internal("No active authentication session to update".into())
        })?;

        let request = CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest {
            client_id: Some(client_id),
            steamid: self.steam_id,
            code: Some(code.trim().to_uppercase()),
            code_type: Some(code_type as i32),
        };

        self.client
            .update_auth_session_with_steam_guard_code(&request)
            .await?;

        Ok(())
    }

    /// Performs a single poll operation to check the session status.
    pub async fn poll_status(&mut self) -> Result<PollStatus> {
        if self.cancelled {
            return Err(SteamError::AuthCancelled);
        }
        let client_id = self.active_client_id.ok_or_else(|| {
            SteamError::Internal("No active authentication session to poll".into())
        })?;
        let request_id = self
            .active_request_id
            .clone()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                SteamError::Internal("No active authentication request ID to poll".into())
            })?;

        let request = CAuthenticationPollAuthSessionStatusRequest {
            client_id: Some(client_id),
            request_id: Some(request_id),
            token_to_revoke: None,
        };

        let res = self.client.poll_auth_session_status(&request).await?;

        if let Some(new_client_id) = res.new_client_id.filter(|client_id| *client_id != 0) {
            self.active_client_id = Some(new_client_id);
        }

        if let Some(new_guard_data) = res
            .new_guard_data
            .as_deref()
            .filter(|data| !data.is_empty())
        {
            self.guard_data = Some(new_guard_data.to_string());
        }

        if res.had_remote_interaction.unwrap_or(false) {
            return Ok(PollStatus::RemoteInteraction {
                new_challenge_url: res
                    .new_challenge_url
                    .filter(|challenge_url| !challenge_url.trim().is_empty()),
            });
        }

        match (res.refresh_token, res.access_token) {
            (None, None) => Ok(PollStatus::Waiting),
            (Some(refresh_token), Some(access_token))
                if !refresh_token.is_empty() && !access_token.is_empty() =>
            {
                let account_name = res
                    .account_name
                    .filter(|account| is_valid_account_name(account))
                    .or_else(|| {
                        self.account_name
                            .clone()
                            .filter(|account| is_valid_account_name(account))
                    })
                    .ok_or(SteamError::InvalidResponse(
                        "Missing account name in confirmed authentication",
                    ))?;

                let expected_steam_id = self.steam_id.filter(|steam_id| *steam_id != 0);
                let refresh_steam_id = validate_steam_token(
                    &refresh_token,
                    SteamTokenKind::Refresh,
                    self.platform_type,
                    expected_steam_id,
                )?;
                let steam_id = validate_steam_token(
                    &access_token,
                    SteamTokenKind::Access,
                    self.platform_type,
                    Some(refresh_steam_id),
                )?;

                self.refresh_token = Some(refresh_token.clone());
                self.access_token = Some(access_token.clone());
                self.account_name = Some(account_name.clone());
                self.steam_id = Some(steam_id);

                Ok(PollStatus::Confirmed(AuthTokens {
                    refresh_token,
                    access_token,
                    account_name,
                    attempt_id: self.active_attempt,
                }))
            }
            _ => Err(SteamError::InvalidResponse(
                "Incomplete authentication token response",
            )),
        }
    }

    /// Polls periodically until the session is confirmed or the timeout duration expires.
    pub async fn poll_until_confirmed(
        &mut self,
        interval_secs: f32,
        timeout_duration: Duration,
    ) -> Result<AuthTokens> {
        let sleep_duration = Duration::from_secs_f32(validate_poll_interval(interval_secs)?);
        let deadline =
            Instant::now()
                .checked_add(timeout_duration)
                .ok_or(SteamError::InvalidResponse(
                    "Authentication timeout is too large",
                ))?;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SteamError::SessionExpired);
            }
            match timeout(remaining, self.poll_status()).await {
                Err(_) => return Err(SteamError::SessionExpired),
                Ok(Err(error)) => return Err(error),
                Ok(Ok(PollStatus::Confirmed(tokens))) => return Ok(tokens),
                Ok(Ok(PollStatus::Waiting | PollStatus::RemoteInteraction { .. })) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SteamError::SessionExpired);
            }
            sleep(sleep_duration.min(remaining)).await;
        }
    }

    /// Retrieves `steamLoginSecure` and `sessionid` cookies for the selected Web-capable platform.
    pub async fn get_web_cookies(&mut self) -> Result<SteamWebCookies> {
        match self.platform_type {
            EAuthTokenPlatformType::WebBrowser => {
                let refresh_token = self.refresh_token.as_ref().ok_or_else(|| {
                    SteamError::InvalidToken(
                        "A valid refresh token is required to get web cookies".into(),
                    )
                })?;
                self.client
                    .finalize_login(refresh_token, self.steam_id)
                    .await
            }
            EAuthTokenPlatformType::MobileApp => self.mobile_web_cookies().await,
            EAuthTokenPlatformType::SteamClient => Err(SteamError::CmNotImplemented),
            EAuthTokenPlatformType::Unknown => Err(SteamError::UnsupportedPlatform(
                "Unknown authentication platform",
            )),
        }
    }

    /// Refreshes the access token for a MobileApp session without rotating its refresh token.
    pub async fn refresh_access_token(&mut self) -> Result<AuthTokens> {
        self.require_mobile_platform("Access-token refresh is only supported for MobileApp")?;
        let refresh_token = self.refresh_token.clone().ok_or_else(|| {
            SteamError::InvalidToken("Cannot refresh access token without a refresh token".into())
        })?;
        let expected_steam_id = self.steam_id;
        validate_steam_token(
            &refresh_token,
            SteamTokenKind::Refresh,
            self.platform_type,
            expected_steam_id,
        )?;
        let request = CAuthenticationAccessTokenGenerateForAppRequest {
            refresh_token: Some(refresh_token.clone()),
            steamid: self.steam_id,
            renewal_type: None,
        };
        let response = self.client.generate_access_token_for_app(&request).await?;
        let access_token = response
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                SteamError::InvalidToken("Steam did not return a refreshed access token".into())
            })?;
        let steam_id = validate_steam_token(
            &access_token,
            SteamTokenKind::Access,
            self.platform_type,
            expected_steam_id,
        )?;
        self.access_token = Some(access_token.clone());
        self.steam_id = Some(steam_id);
        Ok(AuthTokens {
            refresh_token,
            access_token,
            account_name: self.account_name.clone().unwrap_or_default(),
            attempt_id: self.active_attempt,
        })
    }

    /// Requests refresh-token rotation for a MobileApp session.
    ///
    /// Returns `Ok(false)` when Steam keeps the existing refresh token.
    pub async fn renew_refresh_token(&mut self) -> Result<bool> {
        self.require_mobile_platform("Refresh-token rotation is only supported for MobileApp")?;
        let refresh_token = self.refresh_token.clone().ok_or_else(|| {
            SteamError::InvalidToken("Cannot renew a missing refresh token".into())
        })?;
        let expected_steam_id = self.steam_id;
        validate_steam_token(
            &refresh_token,
            SteamTokenKind::Refresh,
            self.platform_type,
            expected_steam_id,
        )?;
        let request = CAuthenticationAccessTokenGenerateForAppRequest {
            refresh_token: Some(refresh_token.clone()),
            steamid: self.steam_id,
            renewal_type: Some(1),
        };
        let response = self.client.generate_access_token_for_app(&request).await?;
        let Some(new_refresh_token) = response.refresh_token.filter(|token| !token.is_empty())
        else {
            return Ok(false);
        };
        let steam_id = validate_steam_token(
            &new_refresh_token,
            SteamTokenKind::Refresh,
            self.platform_type,
            expected_steam_id,
        )?;
        let changed = new_refresh_token != refresh_token;
        self.refresh_token = Some(new_refresh_token);
        self.steam_id = Some(steam_id);
        Ok(changed)
    }

    /// Refreshes a MobileApp access token and derives fresh web cookies without rotating the
    /// refresh token. Rotation remains an explicit operation so a host can persist it immediately.
    pub async fn renew(&mut self) -> Result<(AuthTokens, SteamWebCookies)> {
        self.require_mobile_platform("Full token renewal is only supported for MobileApp")?;
        let tokens = self.refresh_access_token().await?;
        let cookies = self.get_web_cookies().await?;
        Ok((tokens, cookies))
    }

    fn ensure_webapi_auth_platform(&self) -> Result<()> {
        match self.platform_type {
            EAuthTokenPlatformType::WebBrowser | EAuthTokenPlatformType::MobileApp => Ok(()),
            EAuthTokenPlatformType::SteamClient => Err(SteamError::CmNotImplemented),
            EAuthTokenPlatformType::Unknown => Err(SteamError::UnsupportedPlatform(
                "Unknown authentication platform",
            )),
        }
    }

    fn require_mobile_platform(&self, reason: &'static str) -> Result<()> {
        if self.platform_type == EAuthTokenPlatformType::MobileApp {
            Ok(())
        } else {
            Err(SteamError::UnsupportedPlatform(reason))
        }
    }

    async fn mobile_web_cookies(&mut self) -> Result<SteamWebCookies> {
        if self
            .access_token
            .as_deref()
            .map(|token| crate::tokens::is_token_expired(token, 600))
            .unwrap_or(true)
        {
            self.refresh_access_token().await?;
        }
        let access_token = self.access_token.as_deref().ok_or_else(|| {
            SteamError::InvalidToken(
                "A valid access token is required for MobileApp cookies".into(),
            )
        })?;
        let steam_id = validate_steam_token(
            access_token,
            SteamTokenKind::Access,
            self.platform_type,
            self.steam_id,
        )?;
        self.steam_id = Some(steam_id);
        let session_id = hex::encode(rand::random::<[u8; 12]>());
        let login_value: String =
            url::form_urlencoded::byte_serialize(format!("{steam_id}||{access_token}").as_bytes())
                .collect();
        let steam_login_secure = format!("steamLoginSecure={login_value}");
        Ok(SteamWebCookies {
            session_id: session_id.clone(),
            steam_login_secure: Some(steam_login_secure.clone()),
            all_cookies: vec![steam_login_secure, format!("sessionid={session_id}")],
        })
    }

    /// Revokes the current refresh token and clears local authentication state.
    pub async fn revoke_refresh_token(&mut self) -> Result<()> {
        let refresh_token = self.refresh_token.clone().ok_or_else(|| {
            SteamError::InvalidToken("Cannot revoke a session without a refresh token".into())
        })?;

        self.client.revoke_token(&refresh_token).await?;
        self.refresh_token = None;
        self.access_token = None;
        self.guard_data = None;
        Ok(())
    }
}

fn default_website_id(platform: EAuthTokenPlatformType) -> Option<String> {
    match platform {
        EAuthTokenPlatformType::WebBrowser => Some("Community".to_string()),
        EAuthTokenPlatformType::MobileApp => Some("Mobile".to_string()),
        EAuthTokenPlatformType::SteamClient | EAuthTokenPlatformType::Unknown => None,
    }
}

const MIN_POLL_INTERVAL_SECS: f32 = 0.1;
const MAX_POLL_INTERVAL_SECS: f32 = 60.0;

fn validate_poll_interval(interval: f32) -> Result<f32> {
    if !interval.is_finite()
        || !(MIN_POLL_INTERVAL_SECS..=MAX_POLL_INTERVAL_SECS).contains(&interval)
    {
        return Err(SteamError::InvalidResponse(
            "Authentication poll interval is outside the supported range",
        ));
    }
    Ok(interval)
}

fn is_valid_account_name(account_name: &str) -> bool {
    !account_name.trim().is_empty()
        && account_name.len() <= 256
        && !account_name.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use prost::Message;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::proto::{
        CAuthenticationBeginAuthSessionViaCredentialsResponse,
        CAuthenticationBeginAuthSessionViaQrResponse, CAuthenticationPollAuthSessionStatusResponse,
        CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse,
    };
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportFuture};

    struct FakeTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    impl HttpTransport for FakeTransport {
        fn execute(&self, request: HttpRequest) -> TransportFuture<'_, HttpResponse> {
            self.requests.lock().expect("requests lock").push(request);
            let response = self
                .responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .ok_or(SteamError::InvalidResponse("Unexpected request"));
            Box::pin(async move { response })
        }
    }

    fn protobuf_response<M: Message>(message: M) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("x-eresult".into(), "1".into())],
            body: message.encode_to_vec(),
        }
    }

    #[tokio::test]
    async fn cancellation_prevents_polling_and_guard_submission() {
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser);
        session.active_client_id = Some(1);
        session.active_request_id = Some(vec![1]);
        session.cancel_authentication();

        assert!(matches!(
            session.poll_status().await,
            Err(SteamError::AuthCancelled)
        ));
        assert!(matches!(
            session
                .submit_steam_guard_code("12345", EAuthSessionGuardType::DeviceCode)
                .await,
            Err(SteamError::AuthCancelled)
        ));
    }

    #[tokio::test]
    async fn credentials_qr_and_guard_requests_use_the_injected_transport() {
        use rand::{rngs::StdRng, SeedableRng};
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = StdRng::seed_from_u64(0x0041_5554_4846);
        let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("RSA fixture");
        let public_key = RsaPublicKey::from(&private_key);
        let rsa_body = serde_json::json!({
            "response": {
                "publickey_mod": hex::encode(public_key.n().to_bytes_be()),
                "publickey_exp": hex::encode(public_key.e().to_bytes_be()),
                "timestamp": "1"
            }
        })
        .to_string()
        .into_bytes();
        let credentials = CAuthenticationBeginAuthSessionViaCredentialsResponse {
            client_id: Some(42),
            request_id: Some(vec![1, 2, 3]),
            interval: Some(1.0),
            steamid: Some(42),
            ..Default::default()
        };
        let qr = CAuthenticationBeginAuthSessionViaQrResponse {
            client_id: Some(43),
            request_id: Some(vec![4, 5, 6]),
            challenge_url: Some("https://s.team/q/1/fixture".into()),
            interval: Some(1.0),
            ..Default::default()
        };
        let transport = Arc::new(FakeTransport::new([
            HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: rsa_body,
            },
            protobuf_response(credentials),
            protobuf_response(qr),
            protobuf_response(
                CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse::default(),
            ),
        ]));
        let client =
            SteamApiClient::with_transport(Arc::clone(&transport) as Arc<dyn HttpTransport>);
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser).with_client(client);

        let started = session
            .start_with_credentials("account", "password-secret")
            .await
            .expect("credential start");
        assert_eq!(started.client_id, 42);
        let qr = session.start_with_qr().await.expect("QR start");
        assert_eq!(qr.client_id, 43);
        session.allowed_confirmations = vec![EAuthSessionGuardType::DeviceCode];
        session
            .submit_steam_guard_code("12345", EAuthSessionGuardType::DeviceCode)
            .await
            .expect("guard submission");

        let requests = transport.requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].method, crate::HttpMethod::Get);
        for request in &requests[1..] {
            assert!(request
                .form
                .iter()
                .any(|(name, _)| name == "input_protobuf_encoded"));
        }
        assert!(!format!("{:?}", requests[1]).contains("password-secret"));
    }

    #[tokio::test]
    async fn poll_rejects_partial_tokens_but_keeps_new_guard_data() {
        let response = CAuthenticationPollAuthSessionStatusResponse {
            refresh_token: Some("refresh-secret".into()),
            new_guard_data: Some("guard-secret".into()),
            ..Default::default()
        };
        let transport = Arc::new(FakeTransport::new([protobuf_response(response)]));
        let client = SteamApiClient::with_transport(transport as Arc<dyn HttpTransport>);
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser).with_client(client);
        session.active_client_id = Some(1);
        session.active_request_id = Some(vec![1]);
        session.account_name = Some("account".into());
        session.steam_id = Some(42);

        assert!(matches!(
            session.poll_status().await,
            Err(SteamError::InvalidResponse(
                "Incomplete authentication token response"
            ))
        ));
        assert_eq!(session.guard_data.as_deref(), Some("guard-secret"));
        assert!(!format!("{session:?}").contains("guard-secret"));
    }

    #[tokio::test]
    async fn polling_reports_remote_interaction_and_rotates_client_id() {
        let response = CAuthenticationPollAuthSessionStatusResponse {
            new_client_id: Some(2),
            new_challenge_url: Some("https://s.team/q/1/rotated".into()),
            had_remote_interaction: Some(true),
            ..Default::default()
        };
        let transport = Arc::new(FakeTransport::new([protobuf_response(response)]));
        let client = SteamApiClient::with_transport(transport as Arc<dyn HttpTransport>);
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser).with_client(client);
        session.active_client_id = Some(1);
        session.active_request_id = Some(vec![1]);

        assert!(matches!(
            session.poll_status().await,
            Ok(PollStatus::RemoteInteraction {
                new_challenge_url: Some(new_challenge_url),
            }) if new_challenge_url == "https://s.team/q/1/rotated"
        ));
        assert_eq!(session.active_client_id, Some(2));
    }

    #[tokio::test]
    async fn poll_deadline_and_interval_validation_are_bounded() {
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser);
        assert!(matches!(
            session
                .poll_until_confirmed(f32::NAN, Duration::from_secs(1))
                .await,
            Err(SteamError::InvalidResponse(_))
        ));
        assert!(matches!(
            session.poll_until_confirmed(0.1, Duration::ZERO).await,
            Err(SteamError::SessionExpired)
        ));
    }

    #[tokio::test]
    async fn browser_sessions_do_not_claim_access_token_renewal() {
        let client = SteamApiClient::with_transport(Arc::new(FakeTransport::new([])));
        let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser)
            .with_client(client)
            .with_refresh_token("old-refresh");
        session.access_token = Some("old-access".into());
        session.steam_id = Some(42);
        session.account_name = Some("account".into());

        assert!(matches!(
            session.renew().await,
            Err(SteamError::UnsupportedPlatform(_))
        ));
        assert_eq!(session.refresh_token.as_deref(), Some("old-refresh"));
        assert_eq!(session.access_token.as_deref(), Some("old-access"));
    }

    #[tokio::test]
    async fn steam_client_sessions_do_not_claim_http_authentication_support() {
        let mut session = LoginSession::new(EAuthTokenPlatformType::SteamClient)
            .with_refresh_token("refresh-secret");
        assert!(matches!(
            session.get_web_cookies().await,
            Err(SteamError::CmNotImplemented)
        ));
        assert!(matches!(
            session.renew().await,
            Err(SteamError::UnsupportedPlatform(_))
        ));
    }

    #[tokio::test]
    async fn mobile_cookies_are_derived_from_a_valid_mobile_access_token() {
        let future_exp = 1_893_456_000_u64;
        let payload = format!(r#"{{"sub":"42","exp":{future_exp},"aud":["web","mobile"]}}"#);
        let access_token = format!(
            "header.{}.signature",
            base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload)
        );
        let mut session = LoginSession::new(EAuthTokenPlatformType::MobileApp);
        session.steam_id = Some(42);
        session.access_token = Some(access_token.clone());

        let cookies = session.get_web_cookies().await.expect("mobile cookies");
        let login = cookies.export_steam_login_secure().expect("login cookie");
        assert!(login.starts_with("steamLoginSecure=42%7C%7C"));
        assert!(login.contains("header."));
        assert_eq!(cookies.export_all_cookies().len(), 2);
    }
}
