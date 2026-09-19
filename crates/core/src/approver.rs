//! Steam Mobile App approval of pending QR and credential authentication sessions.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fmt;

use crate::client::SteamApiClient;
use crate::enums::{EAuthTokenPlatformType, ESessionPersistence};
use crate::error::{Result, SteamError};
use crate::proto::{
    CAuthenticationGetAuthSessionInfoRequest,
    CAuthenticationUpdateAuthSessionWithMobileConfirmationRequest,
};
use crate::tokens::{validate_steam_token, SteamTokenKind};

type HmacSha1 = Hmac<Sha1>;

/// Non-secret details describing a pending Steam authentication session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSessionInfo {
    /// Device name supplied by the login client.
    pub device_name: String,
    /// Platform requested by the login client.
    pub platform_type: EAuthTokenPlatformType,
    /// Source IP supplied by Steam, if available.
    pub ip: String,
    /// Approximate login location supplied by Steam, if available.
    pub geoloc: String,
    /// City supplied by Steam, if available.
    pub city: String,
    /// State supplied by Steam, if available.
    pub state: String,
    /// Country supplied by Steam, if available.
    pub country: String,
    /// Session version required for approval.
    pub version: i32,
    /// Raw Steam login-security history value. No public enum is exposed until it is verified.
    pub login_history: i32,
    /// Whether Steam detected a location mismatch for the requesting client.
    pub requestor_location_mismatch: bool,
    /// Whether Steam marked the requester as a high-usage login.
    pub high_usage_login: bool,
    /// Persistency requested by the pending session, if Steam supplied a recognized value.
    pub requested_persistence: Option<ESessionPersistence>,
    /// Raw Steam device-trust value.
    pub device_trust: i32,
    /// Raw Steam application-type value.
    pub app_type: i32,
}

/// Mobile authenticator capable of inspecting and approving a pending login request.
///
/// The access token and shared secret are redacted from `Debug`. The shared secret is decoded from
/// standard Base64 and remains in memory only for this instance.
#[derive(Clone)]
pub struct LoginApprover {
    client: SteamApiClient,
    access_token: String,
    steam_id: u64,
    shared_secret: Vec<u8>,
    persistence: ESessionPersistence,
}

impl fmt::Debug for LoginApprover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginApprover")
            .field("has_access_token", &!self.access_token.is_empty())
            .field("has_shared_secret", &!self.shared_secret.is_empty())
            .field("persistence", &self.persistence)
            .finish()
    }
}

impl LoginApprover {
    /// Creates a MobileApp approver from a mobile access token and authenticator shared secret.
    pub fn new(access_token: impl Into<String>, shared_secret: impl AsRef<str>) -> Result<Self> {
        let access_token = access_token.into();
        let steam_id = validate_steam_token(
            &access_token,
            SteamTokenKind::Access,
            EAuthTokenPlatformType::MobileApp,
            None,
        )?;
        let shared_secret = base64::prelude::BASE64_STANDARD
            .decode(shared_secret.as_ref())
            .map_err(|_| {
                SteamError::InvalidToken("Invalid mobile authenticator shared secret".into())
            })?;
        if shared_secret.is_empty() {
            return Err(SteamError::InvalidToken(
                "Mobile authenticator shared secret is empty".into(),
            ));
        }
        Ok(Self {
            client: SteamApiClient::new().with_auth_platform(EAuthTokenPlatformType::MobileApp),
            access_token,
            steam_id,
            shared_secret,
            persistence: ESessionPersistence::Persistent,
        })
    }

    /// Replaces the HTTP client used for Steam authentication requests.
    pub fn with_client(mut self, client: SteamApiClient) -> Self {
        self.client = client.with_auth_platform(EAuthTokenPlatformType::MobileApp);
        self
    }

    /// Sets the requested persistence for an approved session.
    pub fn with_persistence(mut self, persistence: ESessionPersistence) -> Self {
        self.persistence = persistence;
        self
    }

    /// Retrieves Steam's details for a pending authentication session.
    pub async fn get_auth_session_info(&self, client_id: u64) -> Result<AuthSessionInfo> {
        if client_id == 0 {
            return Err(SteamError::InvalidResponse(
                "A pending session client ID is required",
            ));
        }
        let response = self
            .client
            .get_auth_session_info(
                &self.access_token,
                &CAuthenticationGetAuthSessionInfoRequest {
                    client_id: Some(client_id),
                },
            )
            .await?;
        Ok(AuthSessionInfo {
            device_name: response.device_friendly_name.unwrap_or_default(),
            platform_type: EAuthTokenPlatformType::from(response.platform_type.unwrap_or_default()),
            ip: response.ip.unwrap_or_default(),
            geoloc: response.geoloc.unwrap_or_default(),
            city: response.city.unwrap_or_default(),
            state: response.state.unwrap_or_default(),
            country: response.country.unwrap_or_default(),
            version: response.version.unwrap_or_default(),
            login_history: response.login_history.unwrap_or_default(),
            requestor_location_mismatch: response.requestor_location_mismatch.unwrap_or(false),
            high_usage_login: response.high_usage_login.unwrap_or(false),
            requested_persistence: session_persistence(response.requested_persistence),
            device_trust: response.device_trust.unwrap_or_default(),
            app_type: response.app_type.unwrap_or_default(),
        })
    }

    /// Approves a pending session using the current Unix timestamp.
    pub async fn approve_auth_session(&self, client_id: u64, version: i32) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.approve_auth_session_at(client_id, version, timestamp)
            .await
    }

    /// Approves a pending session at a supplied Unix timestamp for deterministic host tests.
    pub async fn approve_auth_session_at(
        &self,
        client_id: u64,
        version: i32,
        timestamp: u64,
    ) -> Result<()> {
        if client_id == 0 || version <= 0 {
            return Err(SteamError::InvalidResponse(
                "A pending session client ID and version are required",
            ));
        }
        let signature = self.confirmation_signature(timestamp)?;
        let request = CAuthenticationUpdateAuthSessionWithMobileConfirmationRequest {
            version: Some(version),
            client_id: Some(client_id),
            steamid: Some(self.steam_id),
            signature: Some(signature),
            confirm: Some(true),
            persistence: Some(self.persistence as i32),
        };
        self.client
            .update_auth_session_with_mobile_confirmation(&self.access_token, &request)
            .await?;
        Ok(())
    }

    fn confirmation_signature(&self, timestamp: u64) -> Result<Vec<u8>> {
        let mut mac = HmacSha1::new_from_slice(&self.shared_secret)
            .map_err(|_| SteamError::Internal("Invalid mobile authenticator key".into()))?;
        mac.update(&timestamp.to_be_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn session_persistence(value: Option<i32>) -> Option<ESessionPersistence> {
    match value {
        Some(0) => Some(ESessionPersistence::Ephemeral),
        Some(1) => Some(ESessionPersistence::Persistent),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::proto::{
        CAuthenticationGetAuthSessionInfoResponse,
        CAuthenticationUpdateAuthSessionWithMobileConfirmationRequest,
        CAuthenticationUpdateAuthSessionWithMobileConfirmationResponse,
    };
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportFuture};

    struct FakeTransport {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into_iter().collect()),
            }
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

    fn mobile_access_token() -> String {
        let payload = r#"{"sub":"42","exp":1893456000,"aud":["web","mobile"]}"#;
        format!(
            "header.{}.signature",
            base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[tokio::test]
    async fn approval_signs_the_timestamp_and_redacts_secrets_from_requests() {
        let transport = Arc::new(FakeTransport::new([protobuf_response(
            CAuthenticationUpdateAuthSessionWithMobileConfirmationResponse::default(),
        )]));
        let secret = base64::prelude::BASE64_STANDARD.encode([7_u8; 20]);
        let approver = LoginApprover::new(mobile_access_token(), &secret)
            .expect("approver")
            .with_client(SteamApiClient::with_transport(
                Arc::clone(&transport) as Arc<dyn HttpTransport>
            ));

        approver
            .approve_auth_session_at(99, 4, 1_700_000_000)
            .await
            .expect("approval request");
        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 1);
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value.starts_with("Bearer ")));
        assert!(!format!("{:?}", requests[0]).contains(&secret));
        let encoded = requests[0]
            .form
            .iter()
            .find(|(name, _)| name == "input_protobuf_encoded")
            .expect("protobuf field")
            .1
            .clone();
        let bytes = base64::prelude::BASE64_STANDARD
            .decode(encoded)
            .expect("protobuf base64");
        let request =
            CAuthenticationUpdateAuthSessionWithMobileConfirmationRequest::decode(bytes.as_slice())
                .expect("protobuf request");
        assert_eq!(request.client_id, Some(99));
        assert_eq!(request.steamid, Some(42));
        assert_eq!(request.version, Some(4));
        assert_eq!(request.confirm, Some(true));
        assert_eq!(request.signature.as_deref().map(<[u8]>::len), Some(20));
    }

    #[tokio::test]
    async fn session_info_maps_supported_response_fields() {
        let response = CAuthenticationGetAuthSessionInfoResponse {
            ip: Some("203.0.113.1".into()),
            geoloc: Some("Example".into()),
            city: Some("City".into()),
            state: Some("State".into()),
            country: Some("Country".into()),
            platform_type: Some(EAuthTokenPlatformType::WebBrowser as i32),
            device_friendly_name: Some("Other device".into()),
            version: Some(4),
            requested_persistence: Some(ESessionPersistence::Persistent as i32),
            ..Default::default()
        };
        let transport = Arc::new(FakeTransport::new([protobuf_response(response)]));
        let secret = base64::prelude::BASE64_STANDARD.encode([7_u8; 20]);
        let approver = LoginApprover::new(mobile_access_token(), &secret)
            .expect("approver")
            .with_client(SteamApiClient::with_transport(
                Arc::clone(&transport) as Arc<dyn HttpTransport>
            ));

        let info = approver
            .get_auth_session_info(99)
            .await
            .expect("session info");
        assert_eq!(info.ip, "203.0.113.1");
        assert_eq!(info.platform_type, EAuthTokenPlatformType::WebBrowser);
        assert_eq!(
            info.requested_persistence,
            Some(ESessionPersistence::Persistent)
        );
    }
}
