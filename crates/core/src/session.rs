//! State machine and lifecycle manager for Steam authentication sessions.

use std::time::Duration;
use tokio::time::sleep;

use crate::client::{SteamApiClient, SteamApiClientBuilder, SteamRsaKey, SteamWebCookies};
use crate::crypto::{self, EncryptedPassword};
use crate::enums::{EAuthSessionGuardType, EAuthTokenPlatformType, ESessionPersistence};
use crate::error::{Result, SteamError};
use crate::proto::{
    CAuthenticationAccessTokenGenerateForAppRequest,
    CAuthenticationBeginAuthSessionViaCredentialsRequest,
    CAuthenticationBeginAuthSessionViaQrRequest,
    CAuthenticationDeviceDetails,
    CAuthenticationPollAuthSessionStatusRequest,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest,
};

/// Result of starting a credentials-based authentication session.
#[derive(Debug, Clone, PartialEq)]
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
    pub weak_token: Option<String>,
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
}

/// Final authentication tokens returned once an authentication attempt is confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTokens {
    /// The long-lived refresh token used to generate web cookies or re-authenticate.
    pub refresh_token: String,
    /// The short-lived access token used for direct WebAPI calls.
    pub access_token: String,
    /// The account name for which authentication was confirmed.
    pub account_name: String,
}

/// Lifecycle status returned by a single poll operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollStatus {
    /// The user has not yet approved or entered their 2FA code.
    Waiting,
    /// Authentication was approved and tokens have been issued.
    Confirmed(AuthTokens),
}

/// Session manager coordinating the login lifecycle.
#[derive(Debug, Clone)]
pub struct LoginSession {
    client: SteamApiClient,
    pub platform_type: EAuthTokenPlatformType,
    pub persistence: ESessionPersistence,
    pub device_name: String,
    pub active_client_id: Option<u64>,
    pub active_request_id: Option<Vec<u8>>,
    pub account_name: Option<String>,
    pub steam_id: Option<u64>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
}

impl LoginSession {
    /// Creates a new `LoginSession` for the specified platform type.
    pub fn new(platform_type: EAuthTokenPlatformType) -> Self {
        Self {
            client: SteamApiClient::new(),
            platform_type,
            persistence: ESessionPersistence::Persistent,
            device_name: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            active_client_id: None,
            active_request_id: None,
            account_name: None,
            steam_id: None,
            refresh_token: None,
            access_token: None,
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

    /// Pre-configures an existing refresh token to restore an active session without entering credentials.
    pub fn with_refresh_token(mut self, token: impl Into<String>) -> Self {
        self.refresh_token = Some(token.into());
        self
    }

    /// Configures a proxy for the internal HTTP client.
    pub fn with_proxy(mut self, proxy_url: impl Into<String>) -> Result<Self> {
        self.client = SteamApiClientBuilder::default().proxy(proxy_url).build()?;
        Ok(self)
    }

    /// Fetches the RSA public key and encrypts the plaintext password.
    pub async fn get_encrypted_password(
        &self,
        account_name: &str,
        password: &str,
    ) -> Result<(EncryptedPassword, SteamRsaKey)> {
        let rsa_key = self.client.get_password_rsa_public_key(account_name).await?;
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
        let clean_account = account_name.trim().to_string();
        self.account_name = Some(clean_account.clone());

        let (encrypted, _) = self.get_encrypted_password(&clean_account, password).await?;

        let request = CAuthenticationBeginAuthSessionViaCredentialsRequest {
            device_friendly_name: Some(self.device_name.clone()),
            account_name: Some(clean_account),
            encrypted_password: Some(encrypted.encrypted_password),
            encryption_timestamp: Some(encrypted.timestamp),
            remember_login: Some(self.persistence == ESessionPersistence::Persistent),
            platform_type: Some(self.platform_type as i32),
            persistence: Some(self.persistence as i32),
            website_id: Some("Community".to_string()),
            device_details: Some(CAuthenticationDeviceDetails {
                device_friendly_name: Some(self.device_name.clone()),
                platform_type: Some(self.platform_type as i32),
                os_type: Some(0),
                gaming_device_type: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let response = self.client.begin_auth_session_via_credentials(&request).await?;

        let client_id = response.client_id.unwrap_or(0);
        let request_id = response.request_id.unwrap_or_default();
        let interval = response.interval.unwrap_or(5.0);
        let steam_id = response.steamid.unwrap_or(0);

        self.active_client_id = Some(client_id);
        self.active_request_id = Some(request_id.clone());
        self.steam_id = Some(steam_id);

        let allowed_confirmations = response
            .allowed_confirmations
            .into_iter()
            .map(|c| EAuthSessionGuardType::from(c.confirmation_type.unwrap_or(0)))
            .collect();

        Ok(CredentialsAuthSession {
            client_id,
            request_id,
            interval,
            allowed_confirmations,
            steam_id,
            weak_token: response.weak_token,
        })
    }

    /// Initiates a QR code authentication session.
    pub async fn start_with_qr(&mut self) -> Result<QrAuthSession> {
        let request = CAuthenticationBeginAuthSessionViaQrRequest {
            device_friendly_name: Some(self.device_name.clone()),
            platform_type: Some(self.platform_type as i32),
            website_id: Some("Community".to_string()),
            device_details: Some(CAuthenticationDeviceDetails {
                device_friendly_name: Some(self.device_name.clone()),
                platform_type: Some(self.platform_type as i32),
                os_type: Some(0),
                gaming_device_type: Some(0),
                ..Default::default()
            }),
        };

        let response = self.client.begin_auth_session_via_qr(&request).await?;

        let client_id = response.client_id.unwrap_or(0);
        let request_id = response.request_id.unwrap_or_default();
        let challenge_url = response.challenge_url.unwrap_or_default();
        let interval = response.interval.unwrap_or(5.0);

        self.active_client_id = Some(client_id);
        self.active_request_id = Some(request_id.clone());

        Ok(QrAuthSession {
            client_id,
            challenge_url,
            request_id,
            interval,
        })
    }

    /// Submits a Steam Guard code (email or mobile TOTP code).
    pub async fn submit_steam_guard_code(
        &self,
        code: &str,
        code_type: EAuthSessionGuardType,
    ) -> Result<()> {
        let client_id = self
            .active_client_id
            .ok_or_else(|| SteamError::Internal("No active authentication session to update".into()))?;

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
        let client_id = self
            .active_client_id
            .ok_or_else(|| SteamError::Internal("No active authentication session to poll".into()))?;
        let request_id = self.active_request_id.clone().unwrap_or_default();

        let request = CAuthenticationPollAuthSessionStatusRequest {
            client_id: Some(client_id),
            request_id: Some(request_id),
            token_to_revoke: None,
        };

        let res = self.client.poll_auth_session_status(&request).await?;

        if let (Some(refresh_token), Some(access_token)) = (res.refresh_token, res.access_token) {
            if !refresh_token.is_empty() {
                self.refresh_token = Some(refresh_token.clone());
                self.access_token = Some(access_token.clone());

                if self.steam_id.is_none() || self.steam_id == Some(0) {
                    if let Ok(claims) = crate::tokens::decode_jwt(&access_token) {
                        if let Some(sub) = claims.sub {
                            self.steam_id = sub.parse::<u64>().ok();
                        }
                    }
                }

                if let Some(ref acc) = res.account_name {
                    if !acc.is_empty() {
                        self.account_name = Some(acc.clone());
                    }
                }

                let account_name = self.account_name.clone().unwrap_or_default();
                return Ok(PollStatus::Confirmed(AuthTokens {
                    refresh_token,
                    access_token,
                    account_name,
                }));
            }
        }

        Ok(PollStatus::Waiting)
    }

    /// Polls periodically until the session is confirmed or the timeout duration expires.
    pub async fn poll_until_confirmed(
        &mut self,
        interval_secs: f32,
        timeout_duration: Duration,
    ) -> Result<AuthTokens> {
        let start = std::time::Instant::now();
        let sleep_duration = Duration::from_secs_f32(if interval_secs < 1.0 { 3.0 } else { interval_secs });

        while start.elapsed() < timeout_duration {
            match self.poll_status().await? {
                PollStatus::Confirmed(tokens) => return Ok(tokens),
                PollStatus::Waiting => {
                    sleep(sleep_duration).await;
                }
            }
        }

        Err(SteamError::SessionExpired)
    }

    /// Retrieves web authentication cookies (`steamLoginSecure`, `sessionid`) using the session's refresh token.
    pub async fn get_web_cookies(&self) -> Result<SteamWebCookies> {
        let refresh_token = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| SteamError::InvalidToken("A valid refresh token is required to get web cookies".into()))?;

        self.client.finalize_login(refresh_token, self.steam_id).await
    }

    /// Renews the access token (and rotates refresh token if applicable) using the current refresh token,
    /// and retrieves fresh web cookies.
    pub async fn renew(&mut self) -> Result<(AuthTokens, SteamWebCookies)> {
        let current_refresh = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| SteamError::InvalidToken("Cannot renew session without an existing refresh token".into()))?;

        let request = CAuthenticationAccessTokenGenerateForAppRequest {
            refresh_token: Some(current_refresh.clone()),
            steamid: self.steam_id,
            renewal_type: Some(1), // k_ETokenRenewalType_Allow
        };

        let response = self.client.generate_access_token_for_app(&request).await?;

        let new_access_token = response
            .access_token
            .ok_or_else(|| SteamError::InvalidToken("Steam API did not return an access token upon renewal".into()))?;

        if let Some(new_refresh) = response.refresh_token {
            if !new_refresh.is_empty() {
                self.refresh_token = Some(new_refresh);
            }
        }

        self.access_token = Some(new_access_token.clone());

        if self.steam_id.is_none() || self.steam_id == Some(0) {
            if let Ok(claims) = crate::tokens::decode_jwt(&new_access_token) {
                if let Some(sub) = claims.sub {
                    self.steam_id = sub.parse::<u64>().ok();
                }
            }
        }

        let cookies = self.get_web_cookies().await?;
        let final_refresh = self.refresh_token.clone().unwrap_or_default();
        let account = self.account_name.clone().unwrap_or_default();

        Ok((
            AuthTokens {
                refresh_token: final_refresh,
                access_token: new_access_token,
                account_name: account,
            },
            cookies,
        ))
    }
}
