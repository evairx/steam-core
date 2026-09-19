//! Low-level HTTP and Protobuf transport for Steam WebAPI (`IAuthenticationService`).

use base64::Engine;
use prost::Message;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use crate::enums::EAuthTokenPlatformType;
use crate::error::{Result, SteamError};
use crate::proto::{
    CAuthenticationAccessTokenGenerateForAppRequest,
    CAuthenticationAccessTokenGenerateForAppResponse,
    CAuthenticationBeginAuthSessionViaCredentialsRequest,
    CAuthenticationBeginAuthSessionViaCredentialsResponse,
    CAuthenticationBeginAuthSessionViaQrRequest, CAuthenticationBeginAuthSessionViaQrResponse,
    CAuthenticationGetAuthSessionInfoRequest, CAuthenticationGetAuthSessionInfoResponse,
    CAuthenticationPollAuthSessionStatusRequest, CAuthenticationPollAuthSessionStatusResponse,
    CAuthenticationTokenRevokeRequest, CAuthenticationTokenRevokeResponse,
    CAuthenticationUpdateAuthSessionWithMobileConfirmationRequest,
    CAuthenticationUpdateAuthSessionWithMobileConfirmationResponse,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse,
};
use crate::transport::{
    HttpMethod, HttpRequest, HttpResponse, HttpTransport, ReqwestTransport, TransportFuture,
    DEFAULT_REQUEST_TIMEOUT, MAX_RESPONSE_BYTES,
};

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
const STEAM_API_BASE: &str = "https://api.steampowered.com";
const STEAM_LOGIN_BASE: &str = "https://login.steampowered.com";

#[derive(Deserialize, Debug)]
struct RsaKeyWrapper {
    response: Option<RsaKeyInner>,
}

#[derive(Deserialize, Debug, Clone)]
struct RsaKeyInner {
    publickey_mod: Option<String>,
    publickey_exp: Option<String>,
    timestamp: Option<serde_json::Value>,
}

/// Steam RSA Public Key components used to encrypt user passwords.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteamRsaKey {
    /// Modulus `n` in hexadecimal.
    pub publickey_mod: String,
    /// Public exponent `e` in hexadecimal.
    pub publickey_exp: String,
    /// Unix timestamp associated with this key version.
    pub timestamp: u64,
}

#[derive(Deserialize)]
struct FinalizeLoginResponse {
    #[serde(rename = "steamID")]
    steam_id: Option<String>,
    transfer_info: Option<Vec<TransferInfo>>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Clone)]
struct TransferInfo {
    url: String,
    params: HashMap<String, String>,
}

/// Web authentication cookies returned after finalizing a Steam login session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamWebCookies {
    /// The active session ID.
    pub(crate) session_id: String,
    /// The primary authentication cookie `steamLoginSecure`.
    pub(crate) steam_login_secure: Option<String>,
    /// All raw `Set-Cookie` strings returned by Steam's domains.
    pub(crate) all_cookies: Vec<String>,
}

impl fmt::Debug for SteamWebCookies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SteamWebCookies")
            .field("has_session_id", &!self.session_id.is_empty())
            .field("has_steam_login_secure", &self.steam_login_secure.is_some())
            .field("cookie_count", &self.all_cookies.len())
            .finish()
    }
}

impl SteamWebCookies {
    /// Returns the session ID for callers that explicitly need to export it.
    pub fn export_session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the Steam login cookie for callers that explicitly need to export it.
    pub fn export_steam_login_secure(&self) -> Option<&str> {
        self.steam_login_secure.as_deref()
    }

    /// Returns all cookie values for callers that explicitly need to export them.
    pub fn export_all_cookies(&self) -> &[String] {
        &self.all_cookies
    }
}

/// Low-level HTTP client for communicating with Steam API services.
#[derive(Clone)]
pub struct SteamApiClient {
    transport: Arc<dyn HttpTransport>,
    user_agent: String,
    platform_headers: Vec<(String, String)>,
}

impl fmt::Debug for SteamApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SteamApiClient").finish_non_exhaustive()
    }
}

// Preserve the infallible constructor without silently dropping timeout/security settings.
struct UnavailableTransport;

impl HttpTransport for UnavailableTransport {
    fn execute(&self, _request: HttpRequest) -> TransportFuture<'_, HttpResponse> {
        Box::pin(async { Err(SteamError::Transport) })
    }
}

impl Default for SteamApiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SteamApiClient {
    /// Constructs a new `SteamApiClient` with sensible browser defaults.
    ///
    /// If initialization fails, operations return `SteamError::Transport`.
    /// Use the builder to handle initialization errors immediately.
    pub fn new() -> Self {
        Self::builder()
            .build()
            .unwrap_or_else(|_| Self::with_transport(Arc::new(UnavailableTransport)))
    }

    /// Uses the supplied transport for every endpoint, including login transfers.
    ///
    /// The transport must not follow redirects; it owns TLS, timeouts, and cookies.
    pub fn with_transport(transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            transport,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            platform_headers: Vec::new(),
        }
    }

    /// Applies request headers required by Steam's selected authentication platform.
    ///
    /// This only configures WebAPI authentication requests. `SteamClient` still requires the CM
    /// transport and is rejected by the high-level login facade until that transport exists.
    pub fn with_auth_platform(mut self, platform: EAuthTokenPlatformType) -> Self {
        self.platform_headers = match platform {
            EAuthTokenPlatformType::MobileApp => vec![(
                "Cookie".into(),
                "mobileClientVersion=0 (2.10.2); mobileClient=android; Steam_Language=english; dob="
                    .into(),
            )],
            EAuthTokenPlatformType::WebBrowser
            | EAuthTokenPlatformType::SteamClient
            | EAuthTokenPlatformType::Unknown => Vec::new(),
        };
        self
    }

    /// Creates a builder for fine-grained configuration of the HTTP client.
    pub fn builder() -> SteamApiClientBuilder {
        SteamApiClientBuilder::default()
    }

    /// Fetches the RSA public key and timestamp for a given account name.
    pub async fn get_password_rsa_public_key(&self, account_name: &str) -> Result<SteamRsaKey> {
        let mut request = self.request(
            HttpMethod::Get,
            format!("{STEAM_API_BASE}/IAuthenticationService/GetPasswordRSAPublicKey/v1/"),
        );
        request
            .query
            .push(("account_name".into(), account_name.into()));
        let res = self.execute(request, false).await?;

        let wrapper: RsaKeyWrapper = serde_json::from_slice(&res.body)
            .map_err(|_| SteamError::InvalidResponse("Invalid RSA response JSON"))?;
        let inner = wrapper.response.ok_or(SteamError::InvalidResponse(
            "Empty response from Steam RSA key endpoint",
        ))?;

        let publickey_mod = inner
            .publickey_mod
            .ok_or(SteamError::InvalidResponse("Missing RSA modulus"))?;
        let publickey_exp = inner
            .publickey_exp
            .ok_or(SteamError::InvalidResponse("Missing RSA exponent"))?;

        for value in [&publickey_mod, &publickey_exp] {
            let bytes = hex::decode(value)
                .map_err(|_| SteamError::InvalidResponse("Invalid RSA key hexadecimal"))?;
            if !bytes.iter().any(|byte| *byte != 0) {
                return Err(SteamError::InvalidResponse(
                    "Empty or zero RSA key component",
                ));
            }
        }

        let timestamp = match inner.timestamp {
            Some(serde_json::Value::Number(n)) => n.as_u64().filter(|value| *value != 0),
            Some(serde_json::Value::String(s)) => parse_positive_u64(&s),
            _ => None,
        }
        .ok_or(SteamError::InvalidResponse(
            "Invalid or missing RSA timestamp",
        ))?;

        Ok(SteamRsaKey {
            publickey_mod,
            publickey_exp,
            timestamp,
        })
    }

    /// Initiates a credential-based login session via Protobuf over HTTP.
    pub async fn begin_auth_session_via_credentials(
        &self,
        request: &CAuthenticationBeginAuthSessionViaCredentialsRequest,
    ) -> Result<CAuthenticationBeginAuthSessionViaCredentialsResponse> {
        self.send_protobuf_request(
            "IAuthenticationService",
            "BeginAuthSessionViaCredentials",
            1,
            request,
        )
        .await
    }

    /// Initiates a QR code login session via Protobuf over HTTP.
    pub async fn begin_auth_session_via_qr(
        &self,
        request: &CAuthenticationBeginAuthSessionViaQrRequest,
    ) -> Result<CAuthenticationBeginAuthSessionViaQrResponse> {
        self.send_protobuf_request(
            "IAuthenticationService",
            "BeginAuthSessionViaQR",
            1,
            request,
        )
        .await
    }

    /// Submits a 2FA Steam Guard code (email code or mobile authenticator code).
    pub async fn update_auth_session_with_steam_guard_code(
        &self,
        request: &CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest,
    ) -> Result<CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse> {
        self.send_protobuf_request(
            "IAuthenticationService",
            "UpdateAuthSessionWithSteamGuardCode",
            1,
            request,
        )
        .await
    }

    /// Retrieves details for a pending session that a Steam Mobile App user may approve.
    pub async fn get_auth_session_info(
        &self,
        access_token: &str,
        request: &CAuthenticationGetAuthSessionInfoRequest,
    ) -> Result<CAuthenticationGetAuthSessionInfoResponse> {
        self.send_protobuf_request_with_access_token(
            "IAuthenticationService",
            "GetAuthSessionInfo",
            1,
            request,
            access_token,
        )
        .await
    }

    /// Approves a pending session through a Steam Mobile App authenticator proof.
    pub async fn update_auth_session_with_mobile_confirmation(
        &self,
        access_token: &str,
        request: &CAuthenticationUpdateAuthSessionWithMobileConfirmationRequest,
    ) -> Result<CAuthenticationUpdateAuthSessionWithMobileConfirmationResponse> {
        self.send_protobuf_request_with_access_token(
            "IAuthenticationService",
            "UpdateAuthSessionWithMobileConfirmation",
            1,
            request,
            access_token,
        )
        .await
    }

    /// Polls the status of an ongoing authentication session.
    pub async fn poll_auth_session_status(
        &self,
        request: &CAuthenticationPollAuthSessionStatusRequest,
    ) -> Result<CAuthenticationPollAuthSessionStatusResponse> {
        self.send_protobuf_request(
            "IAuthenticationService",
            "PollAuthSessionStatus",
            1,
            request,
        )
        .await
    }

    /// Generates a new access token and optionally renews the refresh token using an existing refresh token.
    pub async fn generate_access_token_for_app(
        &self,
        request: &CAuthenticationAccessTokenGenerateForAppRequest,
    ) -> Result<CAuthenticationAccessTokenGenerateForAppResponse> {
        self.send_protobuf_request(
            "IAuthenticationService",
            "GenerateAccessTokenForApp",
            1,
            request,
        )
        .await
    }

    /// Revokes a token through Steam's authentication service.
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        if token.is_empty() {
            return Err(SteamError::InvalidToken(
                "Cannot revoke an empty Steam token".into(),
            ));
        }

        let request = CAuthenticationTokenRevokeRequest {
            token: Some(token.to_string()),
            revoke_action: None,
        };
        let _: CAuthenticationTokenRevokeResponse = self
            .send_protobuf_request("IAuthenticationService", "RevokeToken", 1, &request)
            .await?;
        Ok(())
    }

    /// Finalizes the web login session using the refresh token, retrieving `steamLoginSecure` and other cookies.
    pub async fn finalize_login(
        &self,
        refresh_token: &str,
        steam_id: Option<u64>,
    ) -> Result<SteamWebCookies> {
        if refresh_token.trim().is_empty() || steam_id == Some(0) {
            return Err(SteamError::InvalidToken(
                "Invalid login finalization input".into(),
            ));
        }
        let random_bytes: [u8; 12] = rand::random();
        let session_id = hex::encode(random_bytes);

        let mut request = self.request(
            HttpMethod::Post,
            format!("{STEAM_LOGIN_BASE}/jwt/finalizelogin"),
        );
        request.form = vec![
            ("nonce".into(), refresh_token.into()),
            ("sessionid".into(), session_id.clone()),
            (
                "redir".into(),
                "https://steamcommunity.com/login/home/?goto=".into(),
            ),
        ];
        let res = self.execute(request, false).await?;
        let finalize_data: FinalizeLoginResponse = serde_json::from_slice(&res.body)
            .map_err(|_| SteamError::InvalidResponse("Invalid finalize login JSON"))?;
        if finalize_data.error.is_some() {
            return Err(SteamError::InvalidResponse(
                "Steam rejected login finalization",
            ));
        }

        let returned_id = finalize_data
            .steam_id
            .as_deref()
            .map(|id| {
                parse_positive_u64(id)
                    .ok_or(SteamError::InvalidResponse("Invalid finalize SteamID"))
            })
            .transpose()?;
        if let (Some(expected), Some(actual)) = (steam_id, returned_id) {
            if expected != actual {
                return Err(SteamError::InvalidResponse(
                    "Finalize SteamID does not match requested identity",
                ));
            }
        }
        let sid = returned_id
            .or(steam_id)
            .ok_or(SteamError::InvalidResponse("Missing finalize SteamID"))?
            .to_string();

        // Validate the entire transfer list before sending any credentials to it.
        let mut transfers = finalize_data.transfer_info.unwrap_or_default();
        for transfer in &mut transfers {
            let url = Url::parse(&transfer.url)
                .map_err(|_| SteamError::InvalidResponse("Invalid login transfer URL"))?;
            if !is_allowed_transfer_url(&url) {
                return Err(SteamError::InvalidResponse("Untrusted login transfer URL"));
            }
            transfer.url = url.to_string();
            if transfer
                .params
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("steamID") && value != &sid)
            {
                return Err(SteamError::InvalidResponse(
                    "Transfer SteamID does not match requested identity",
                ));
            }
            transfer
                .params
                .retain(|name, _| !name.eq_ignore_ascii_case("steamID"));
            transfer.params.insert("steamID".into(), sid.clone());
        }

        let mut all_cookies: Vec<String> = res
            .headers
            .into_iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value)
            .collect();
        for transfer in transfers {
            let mut request = self.request(HttpMethod::Post, transfer.url);
            request.form = transfer.params.into_iter().collect();
            let res = self.execute(request, false).await?;
            all_cookies.extend(
                res.headers
                    .into_iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
                    .map(|(_, value)| value),
            );
        }

        let steam_login_secure = all_cookies
            .iter()
            .find_map(|cookie| {
                let pair = cookie.split(';').next()?.trim();
                let value = pair.strip_prefix("steamLoginSecure=")?;
                (!value.trim_matches('"').trim().is_empty()
                    && !value.bytes().any(|byte| byte.is_ascii_control()))
                .then(|| pair.to_string())
            })
            .ok_or(SteamError::InvalidResponse(
                "Missing or empty steamLoginSecure cookie",
            ))?;
        all_cookies.push(format!("sessionid={session_id}"));

        Ok(SteamWebCookies {
            session_id,
            steam_login_secure: Some(steam_login_secure),
            all_cookies,
        })
    }

    /// Generic helper to send Protobuf requests to Steam WebAPI.
    async fn send_protobuf_request<Req: Message, Res: Message + Default>(
        &self,
        service: &str,
        method: &str,
        version: u32,
        request: &Req,
    ) -> Result<Res> {
        self.send_protobuf_request_internal(service, method, version, request, None)
            .await
    }

    async fn send_protobuf_request_with_access_token<Req: Message, Res: Message + Default>(
        &self,
        service: &str,
        method: &str,
        version: u32,
        request: &Req,
        access_token: &str,
    ) -> Result<Res> {
        if access_token.is_empty() {
            return Err(SteamError::InvalidToken(
                "A non-empty access token is required".into(),
            ));
        }
        self.send_protobuf_request_internal(service, method, version, request, Some(access_token))
            .await
    }

    async fn send_protobuf_request_internal<Req: Message, Res: Message + Default>(
        &self,
        service: &str,
        method: &str,
        version: u32,
        request: &Req,
        access_token: Option<&str>,
    ) -> Result<Res> {
        let url = format!("{STEAM_API_BASE}/{service}/{method}/v{version}/");

        let proto_bytes = request.encode_to_vec();
        let encoded_b64 = base64::prelude::BASE64_STANDARD.encode(&proto_bytes);

        let mut request = self.request(HttpMethod::Post, url);
        if let Some(access_token) = access_token {
            request
                .headers
                .push(("Authorization".into(), format!("Bearer {access_token}")));
        }
        request
            .form
            .push(("input_protobuf_encoded".into(), encoded_b64));
        let res = self.execute(request, true).await?;
        Res::decode(res.body.as_slice())
            .map_err(|_| SteamError::InvalidResponse("Invalid protobuf response"))
    }

    fn request(&self, method: HttpMethod, url: String) -> HttpRequest {
        let mut headers: Vec<(String, String)> = [
            ("User-Agent", self.user_agent.as_str()),
            ("Accept", "application/json, text/plain, */*"),
            ("Origin", "https://steamcommunity.com"),
            ("Referer", "https://steamcommunity.com/"),
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect();
        headers.extend(self.platform_headers.iter().cloned());
        if method == HttpMethod::Post {
            headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
        }
        HttpRequest {
            method,
            url,
            headers,
            form: Vec::new(),
            query: Vec::new(),
        }
    }

    async fn execute(&self, request: HttpRequest, require_eresult: bool) -> Result<HttpResponse> {
        let res = self
            .transport
            .execute(request)
            .await
            .map_err(|error| match error {
                SteamError::InvalidResponse(_) | SteamError::HttpStatus(_) => error,
                _ => SteamError::Transport,
            })?;
        if res.body.len() > MAX_RESPONSE_BYTES {
            return Err(SteamError::InvalidResponse("HTTP response exceeds 2 MiB"));
        }
        if !(200..300).contains(&res.status) {
            return Err(SteamError::HttpStatus(res.status));
        }
        let mut headers = res
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-eresult"));
        let Some((_, value)) = headers.next() else {
            return if require_eresult {
                Err(SteamError::InvalidResponse("Missing EResult header"))
            } else {
                Ok(res)
            };
        };
        if headers.next().is_some()
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(SteamError::InvalidResponse("Malformed EResult header"));
        }
        let eresult = value
            .parse::<i32>()
            .map_err(|_| SteamError::InvalidResponse("Malformed EResult header"))?;
        if eresult != 1 {
            let message = match eresult {
                5 => "Invalid credentials (k_EResultInvalidPassword)",
                84 => "Rate limit exceeded (k_EResultRateLimitExceeded)",
                _ => "Steam API rejected the request",
            };
            return Err(SteamError::SteamApi {
                eresult,
                message: message.into(),
            });
        }
        Ok(res)
    }
}

/// Builder for constructing a configured [`SteamApiClient`].
#[derive(Default)]
pub struct SteamApiClientBuilder {
    user_agent: Option<String>,
    proxy_url: Option<String>,
    timeout: Option<Duration>,
}

impl fmt::Debug for SteamApiClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SteamApiClientBuilder")
            .field("has_user_agent", &self.user_agent.is_some())
            .field("has_proxy", &self.proxy_url.is_some())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SteamApiClientBuilder {
    /// Sets a custom User-Agent string.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Sets an HTTP or SOCKS5 proxy URL for all requests.
    pub fn proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy_url = Some(proxy_url.into());
        self
    }

    /// Sets a timeout for HTTP requests.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Builds the `SteamApiClient`.
    pub fn build(self) -> Result<SteamApiClient> {
        let user_agent = self.user_agent.unwrap_or_else(|| DEFAULT_USER_AGENT.into());
        HeaderValue::from_str(&user_agent).map_err(|_| SteamError::Transport)?;
        let transport = ReqwestTransport::configured(
            self.timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            self.proxy_url.as_deref(),
        )?;
        Ok(SteamApiClient {
            transport: Arc::new(transport),
            user_agent,
            platform_headers: Vec::new(),
        })
    }
}

fn is_allowed_transfer_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.fragment().is_none()
        && matches!(
            url.host_str(),
            Some("steamcommunity.com" | "store.steampowered.com" | "help.steampowered.com")
        )
}

fn parse_positive_u64(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().filter(|value| *value != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeTransport {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    impl FakeTransport {
        fn with_responses(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into_iter().collect()),
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
                .ok_or(SteamError::InvalidResponse("Unexpected HTTP request"));
            Box::pin(async move { response })
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: impl Into<Vec<u8>>) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            body: body.into(),
        }
    }

    #[test]
    fn cookie_debug_output_redacts_secret_values() {
        let cookies = SteamWebCookies {
            session_id: "session-secret".into(),
            steam_login_secure: Some("login-secret".into()),
            all_cookies: vec!["cookie-secret".into()],
        };

        let output = format!("{cookies:?}");
        assert!(!output.contains("session-secret"));
        assert!(!output.contains("login-secret"));
        assert!(!output.contains("cookie-secret"));
    }

    #[test]
    fn login_transfers_are_restricted_to_https_steam_hosts() {
        assert!(is_allowed_transfer_url(
            &Url::parse("https://steamcommunity.com/login/transfer").unwrap()
        ));
        assert!(is_allowed_transfer_url(
            &Url::parse("https://store.steampowered.com/login/transfer").unwrap()
        ));
        assert!(!is_allowed_transfer_url(
            &Url::parse("http://steamcommunity.com/login/transfer").unwrap()
        ));
        assert!(!is_allowed_transfer_url(
            &Url::parse("https://steamcommunity.example/login/transfer").unwrap()
        ));
        assert!(!is_allowed_transfer_url(
            &Url::parse("https://user:secret@steamcommunity.com/login/transfer").unwrap()
        ));
        assert!(!is_allowed_transfer_url(
            &Url::parse("https://steamcommunity.com:8443/login/transfer").unwrap()
        ));
    }

    #[tokio::test]
    async fn protobuf_contract_requires_explicit_success_eresult() {
        let fake = Arc::new(FakeTransport::with_responses([response(
            200,
            &[],
            Vec::new(),
        )]));
        let client = SteamApiClient::with_transport(Arc::clone(&fake) as Arc<dyn HttpTransport>);
        let request = CAuthenticationPollAuthSessionStatusRequest {
            client_id: Some(42),
            request_id: Some(vec![1, 2, 3]),
            token_to_revoke: None,
        };

        assert!(matches!(
            client.poll_auth_session_status(&request).await,
            Err(SteamError::InvalidResponse("Missing EResult header"))
        ));
        let recorded = fake.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, HttpMethod::Post);
        assert!(recorded[0]
            .form
            .iter()
            .any(|(name, _)| name == "input_protobuf_encoded"));
        let encoded = recorded[0]
            .form
            .iter()
            .find(|(name, _)| name == "input_protobuf_encoded")
            .expect("protobuf form field")
            .1
            .clone();
        assert!(!format!("{:?}", recorded[0]).contains(&encoded));
    }

    #[tokio::test]
    async fn protobuf_rejections_and_bad_bodies_are_typed_and_redacted() {
        let fake = Arc::new(FakeTransport::with_responses([
            response(
                200,
                &[
                    ("x-eresult", "84"),
                    ("x-error-message", "secret remote reason"),
                ],
                Vec::new(),
            ),
            response(200, &[("x-eresult", "1")], [0xff, 0xff]),
        ]));
        let client = SteamApiClient::with_transport(Arc::clone(&fake) as Arc<dyn HttpTransport>);
        let request = CAuthenticationPollAuthSessionStatusRequest::default();

        let rejection = client.poll_auth_session_status(&request).await.unwrap_err();
        assert!(matches!(
            rejection,
            SteamError::SteamApi { eresult: 84, .. }
        ));
        assert!(!format!("{rejection} {rejection:?}").contains("secret remote reason"));
        assert!(matches!(
            client.poll_auth_session_status(&request).await,
            Err(SteamError::InvalidResponse("Invalid protobuf response"))
        ));
    }

    #[tokio::test]
    async fn mobile_platform_requests_include_mobile_authentication_cookie() {
        let fake = Arc::new(FakeTransport::with_responses([response(
            200,
            &[("x-eresult", "1")],
            Vec::new(),
        )]));
        let client = SteamApiClient::with_transport(Arc::clone(&fake) as Arc<dyn HttpTransport>)
            .with_auth_platform(crate::EAuthTokenPlatformType::MobileApp);
        client
            .poll_auth_session_status(&CAuthenticationPollAuthSessionStatusRequest::default())
            .await
            .expect("mobile poll request");
        let request = fake.requests().pop().expect("recorded request");
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| { name == "Cookie" && value.contains("mobileClient=android") }));
        assert!(!format!("{request:?}").contains("mobileClient=android"));
    }

    #[tokio::test]
    async fn rsa_and_finalize_contracts_reject_incomplete_or_inconsistent_responses() {
        let fake = Arc::new(FakeTransport::with_responses([response(
            200,
            &[],
            br#"{"response":{"publickey_mod":"00","publickey_exp":"010001","timestamp":"0"}}"#
                .to_vec(),
        )]));
        let client = SteamApiClient::with_transport(Arc::clone(&fake) as Arc<dyn HttpTransport>);
        assert!(matches!(
            client.get_password_rsa_public_key("account").await,
            Err(SteamError::InvalidResponse(_))
        ));

        let fake = Arc::new(FakeTransport::with_responses([response(
            200,
            &[],
            br#"{"steamID":"43"}"#.to_vec(),
        )]));
        let client = SteamApiClient::with_transport(fake as Arc<dyn HttpTransport>);
        assert!(matches!(
            client.finalize_login("refresh-secret", Some(42)).await,
            Err(SteamError::InvalidResponse(
                "Finalize SteamID does not match requested identity"
            ))
        ));
    }

    #[tokio::test]
    async fn login_transfer_keeps_the_validated_steam_identity() {
        let fake = Arc::new(FakeTransport::with_responses([
            response(
                200,
                &[("Set-Cookie", "steamLoginSecure=first-cookie; Secure")],
                br#"{"steamID":"42","transfer_info":[{"url":"https://steamcommunity.com/login/transfer","params":{"steamID":"42","token":"secret-transfer"}}]}"#.to_vec(),
            ),
            response(200, &[("Set-Cookie", "another=value; Secure")], Vec::new()),
        ]));
        let client = SteamApiClient::with_transport(Arc::clone(&fake) as Arc<dyn HttpTransport>);
        let cookies = client
            .finalize_login("refresh-secret", Some(42))
            .await
            .expect("valid finalization");
        assert!(cookies.export_steam_login_secure().is_some());
        let requests = fake.requests();
        assert_eq!(requests.len(), 2);
        let transfer = &requests[1];
        assert_eq!(
            transfer
                .form
                .iter()
                .filter(|(name, _)| name == "steamID")
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["42"]
        );
        assert!(!format!("{transfer:?}").contains("secret-transfer"));
        let proto = CAuthenticationPollAuthSessionStatusResponse::default();
        assert_eq!(proto.encode_to_vec(), Vec::<u8>::new());
    }
}
