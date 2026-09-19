//! Injectable HTTP transport boundary for Steam WebAPI authentication requests.
//!
//! The core owns protocol validation. Hosts may provide a transport for tests or for a target
//! runtime, while `ReqwestTransport` remains the portable default implementation.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::cookie::Jar;

use crate::error::{Result, SteamError};

/// Default per-request timeout for the bundled HTTP transport.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum response body accepted by the authentication protocol.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// HTTP request method supported by the authentication transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

/// A protocol request passed to an [`HttpTransport`].
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute endpoint URL.
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// URL-encoded form fields.
    pub form: Vec<(String, String)>,
    /// URL query pairs.
    pub query: Vec<(String, String)>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field(
                "form_field_names",
                &self.form.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .field(
                "query_field_names",
                &self.query.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// A complete HTTP response returned by an [`HttpTransport`].
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric HTTP status.
    pub status: u16,
    /// Response headers. Repeated headers, including `Set-Cookie`, are retained.
    pub headers: Vec<(String, String)>,
    /// Response body, capped at [`MAX_RESPONSE_BYTES`] by the bundled transport.
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Boxed transport result used to keep the trait independent of a particular async runtime.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Host-provided HTTP execution boundary.
///
/// Implementations must not follow redirects for authentication requests. The caller validates
/// every explicitly supplied Steam endpoint before sending credentials or transfer parameters.
pub trait HttpTransport: Send + Sync {
    /// Executes one protocol request.
    fn execute(&self, request: HttpRequest) -> TransportFuture<'_, HttpResponse>;
}

/// Portable Reqwest-backed [`HttpTransport`] used by [`crate::SteamApiClient`].
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestTransport").finish_non_exhaustive()
    }
}

impl ReqwestTransport {
    /// Builds a transport with cookies, a bounded response size, and redirects disabled.
    pub fn configured(timeout: Duration, proxy_url: Option<&str>) -> Result<Self> {
        if timeout.is_zero() {
            return Err(SteamError::InvalidResponse("HTTP timeout must be non-zero"));
        }

        let mut builder = reqwest::Client::builder()
            .cookie_provider(Arc::new(Jar::default()))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout);
        if let Some(proxy_url) = proxy_url {
            builder =
                builder.proxy(reqwest::Proxy::all(proxy_url).map_err(|_| SteamError::Transport)?);
        }

        let client = builder.build().map_err(|_| SteamError::Transport)?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn execute(&self, request: HttpRequest) -> TransportFuture<'_, HttpResponse> {
        Box::pin(async move {
            let url = reqwest::Url::parse(&request.url)
                .map_err(|_| SteamError::InvalidResponse("Invalid request URL"))?;
            let mut builder = match request.method {
                HttpMethod::Get => self.client.get(url),
                HttpMethod::Post => self.client.post(url),
            };
            if !request.headers.is_empty() {
                let mut headers = reqwest::header::HeaderMap::new();
                for (name, value) in request.headers {
                    let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| SteamError::InvalidResponse("Invalid request header name"))?;
                    let value = reqwest::header::HeaderValue::from_str(&value)
                        .map_err(|_| SteamError::InvalidResponse("Invalid request header value"))?;
                    headers.append(name, value);
                }
                builder = builder.headers(headers);
            }
            if !request.query.is_empty() {
                builder = builder.query(&request.query);
            }
            if request.method == HttpMethod::Post && !request.form.is_empty() {
                builder = builder.form(&request.form);
            }

            let mut response = builder.send().await.map_err(|_| SteamError::Transport)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.to_string(), value.to_string()))
                })
                .collect();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| SteamError::Transport)? {
                if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(SteamError::InvalidResponse("HTTP response exceeds 2 MiB"));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_debug_does_not_render_request_or_response_values() {
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: "https://example.invalid/?access_token=secret".into(),
            headers: vec![("Authorization".into(), "Bearer secret".into())],
            form: vec![("password".into(), "secret".into())],
            query: vec![("guard_data".into(), "secret".into())],
        };
        let response = HttpResponse {
            status: 200,
            headers: vec![("Set-Cookie".into(), "steamLoginSecure=secret".into())],
            body: b"secret".to_vec(),
        };
        let debug = format!("{request:?} {response:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("example.invalid"));
    }
}
