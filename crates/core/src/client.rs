//! Low-level HTTP and Protobuf transport for Steam WebAPI (`IAuthenticationService`).

use std::collections::HashMap;
use std::time::Duration;
use base64::Engine;
use prost::Message;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SteamError};
use crate::proto::{
    CAuthenticationAccessTokenGenerateForAppRequest,
    CAuthenticationAccessTokenGenerateForAppResponse,
    CAuthenticationBeginAuthSessionViaCredentialsRequest,
    CAuthenticationBeginAuthSessionViaCredentialsResponse,
    CAuthenticationBeginAuthSessionViaQrRequest,
    CAuthenticationBeginAuthSessionViaQrResponse,
    CAuthenticationPollAuthSessionStatusRequest,
    CAuthenticationPollAuthSessionStatusResponse,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse,
};

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
const STEAM_API_BASE: &str = "https://api.steampowered.com";
const STEAM_LOGIN_BASE: &str = "https://login.steampowered.com";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

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

#[derive(Deserialize, Debug)]
struct FinalizeLoginResponse {
    #[serde(rename = "steamID")]
    steam_id: Option<String>,
    transfer_info: Option<Vec<TransferInfo>>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
struct TransferInfo {
    url: String,
    params: HashMap<String, String>,
}

/// Web authentication cookies returned after finalizing a Steam login session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamWebCookies {
    /// The active session ID.
    pub session_id: String,
    /// The primary authentication cookie `steamLoginSecure`.
    pub steam_login_secure: Option<String>,
    /// All raw `Set-Cookie` strings returned by Steam's domains.
    pub all_cookies: Vec<String>,
}

/// Low-level HTTP client for communicating with Steam API services.
#[derive(Clone, Debug)]
pub struct SteamApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl Default for SteamApiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SteamApiClient {
    /// Constructs a new `SteamApiClient` with sensible browser defaults.
    pub fn new() -> Self {
        Self::builder().build().unwrap_or_else(|_| {
            // Fallback to basic client if custom build fails
            Self {
                http: reqwest::Client::new(),
                base_url: STEAM_API_BASE.to_string(),
            }
        })
    }

    /// Creates a builder for fine-grained configuration of the HTTP client.
    pub fn builder() -> SteamApiClientBuilder {
        SteamApiClientBuilder::default()
    }

    /// Fetches the RSA public key and timestamp for a given account name.
    pub async fn get_password_rsa_public_key(&self, account_name: &str) -> Result<SteamRsaKey> {
        let url = format!(
            "{}/IAuthenticationService/GetPasswordRSAPublicKey/v1/",
            self.base_url
        );

        let res = self
            .http
            .get(&url)
            .query(&[("account_name", account_name)])
            .send()
            .await?;

        self.check_eresult_header(&res)?;

        let wrapper: RsaKeyWrapper = res.json().await?;
        let inner = wrapper
            .response
            .ok_or_else(|| SteamError::Internal("Empty response from Steam RSA key endpoint".into()))?;

        let publickey_mod = inner
            .publickey_mod
            .ok_or_else(|| SteamError::Internal("Missing publickey_mod in RSA response".into()))?;
        let publickey_exp = inner
            .publickey_exp
            .ok_or_else(|| SteamError::Internal("Missing publickey_exp in RSA response".into()))?;

        let timestamp = match inner.timestamp {
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(serde_json::Value::String(s)) => s.parse::<u64>().unwrap_or(0),
            _ => {
                return Err(SteamError::Internal(
                    "Invalid or missing timestamp in RSA response".into(),
                ))
            }
        };

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

    /// Finalizes the web login session using the refresh token, retrieving `steamLoginSecure` and other cookies.
    pub async fn finalize_login(&self, refresh_token: &str, steam_id: Option<u64>) -> Result<SteamWebCookies> {
        let random_bytes: [u8; 12] = rand::random();
        let session_id = hex::encode(random_bytes);

        let finalize_url = format!("{}/jwt/finalizelogin", STEAM_LOGIN_BASE);
        let mut form = HashMap::new();
        form.insert("nonce", refresh_token);
        form.insert("sessionid", &session_id);
        form.insert("redir", "https://steamcommunity.com/login/home/?goto=");

        let res = self
            .http
            .post(&finalize_url)
            .header("Origin", "https://steamcommunity.com")
            .header("Referer", "https://steamcommunity.com/")
            .form(&form)
            .send()
            .await?;

        let mut all_cookies = Vec::new();
        for cookie_header in res.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                all_cookies.push(cookie_str.to_string());
            }
        }

        let finalize_data: FinalizeLoginResponse = res.json().await.map_err(|e| {
            SteamError::Internal(format!("Failed to parse finalize login response: {e}"))
        })?;

        if let Some(err) = finalize_data.error {
            return Err(SteamError::Internal(format!("Finalize login rejected: {err}")));
        }

        let sid = finalize_data
            .steam_id
            .or_else(|| steam_id.map(|id| id.to_string()))
            .unwrap_or_default();

        // Perform token transfers to steamcommunity.com and store.steampowered.com
        if let Some(transfers) = finalize_data.transfer_info {
            for transfer in transfers {
                let mut transfer_form = HashMap::new();
                transfer_form.insert("steamID".to_string(), sid.clone());
                for (k, v) in transfer.params {
                    transfer_form.insert(k, v);
                }

                if let Ok(t_res) = self
                    .http
                    .post(&transfer.url)
                    .form(&transfer_form)
                    .send()
                    .await
                {
                    for cookie_header in t_res.headers().get_all(reqwest::header::SET_COOKIE) {
                        if let Ok(cookie_str) = cookie_header.to_str() {
                            all_cookies.push(cookie_str.to_string());
                        }
                    }
                }
            }
        }

        // Find steamLoginSecure cookie
        let mut steam_login_secure = None;
        for c in &all_cookies {
            if c.starts_with("steamLoginSecure=") {
                let val = c.split(';').next().unwrap_or(c);
                steam_login_secure = Some(val.to_string());
                break;
            }
        }

        all_cookies.push(format!("sessionid={session_id}"));

        Ok(SteamWebCookies {
            session_id,
            steam_login_secure,
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
        let url = format!("{}/{}/{}/v{}/", self.base_url, service, method, version);

        let proto_bytes = request.encode_to_vec();
        let encoded_b64 = base64::prelude::BASE64_STANDARD.encode(&proto_bytes);

        let res = self
            .http
            .post(&url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("Origin", "https://steamcommunity.com")
            .header("Referer", "https://steamcommunity.com/")
            .form(&[("input_protobuf_encoded", &encoded_b64)])
            .send()
            .await?;

        let eresult = res
            .headers()
            .get("x-eresult")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(1);

        let error_msg = res
            .headers()
            .get("x-error-message")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let bytes = res.bytes().await?;

        if eresult != 1 {
            let detail = error_msg.unwrap_or_else(|| match eresult {
                5 => "Invalid credentials (k_EResultInvalidPassword)".to_string(),
                84 => "Rate limit exceeded (k_EResultRateLimitExceeded)".to_string(),
                other => format!("Steam API EResult {other}"),
            });

            return Err(SteamError::SteamApi {
                eresult,
                message: detail,
            });
        }

        let response_proto = Res::decode(bytes.as_ref())?;
        Ok(response_proto)
    }

    fn check_eresult_header(&self, res: &reqwest::Response) -> Result<()> {
        if let Some(eresult_header) = res.headers().get("x-eresult") {
            if let Ok(val_str) = eresult_header.to_str() {
                if let Ok(eresult_code) = val_str.parse::<i32>() {
                    if eresult_code != 1 {
                        let error_msg = res
                            .headers()
                            .get("x-error-message")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("Steam API returned EResult {eresult_code}"));

                        return Err(SteamError::SteamApi {
                            eresult: eresult_code,
                            message: error_msg,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// Builder for constructing a configured [`SteamApiClient`].
#[derive(Default, Debug)]
pub struct SteamApiClientBuilder {
    user_agent: Option<String>,
    proxy_url: Option<String>,
    timeout: Option<Duration>,
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
        let mut headers = HeaderMap::new();
        let ua = self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT);
        headers.insert(USER_AGENT, HeaderValue::from_str(ua).map_err(|e| SteamError::Internal(e.to_string()))?);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json, text/plain, */*"));
        headers.insert("Origin", HeaderValue::from_static("https://steamcommunity.com"));
        headers.insert("Referer", HeaderValue::from_static("https://steamcommunity.com/"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("cross-site"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(self.timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT));

        if let Some(proxy_url) = self.proxy_url {
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|e| SteamError::Internal(format!("Invalid proxy configuration: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let http = builder.build()?;
        Ok(SteamApiClient {
            http,
            base_url: STEAM_API_BASE.to_string(),
        })
    }
}
