//! Strongly-typed error definitions for Steam authentication.

use std::fmt;

/// The primary error type for all operations within `steam-auth`.
pub enum SteamError {
    /// An error occurred during an HTTP request or network transport.
    /// Retained for explicit callers; formatting and `source()` hide the inner error.
    Http(reqwest::Error),

    /// A network failure without retaining URLs, credentials, or response bodies.
    Transport,

    /// An unsuccessful HTTP response, retaining only its numeric status.
    HttpStatus(u16),

    /// An invalid protocol response. The reason must be a local, non-sensitive label.
    InvalidResponse(&'static str),

    /// Failed to encode a Protobuf message.
    ProtobufEncode(prost::EncodeError),

    /// Failed to decode a Protobuf message from Steam.
    ProtobufDecode(prost::DecodeError),

    /// An error occurred during RSA cryptographic operations.
    Crypto(String),

    /// Steam API responded with a non-success `EResult`.
    SteamApi {
        /// The numeric Steam EResult code.
        eresult: i32,
        /// Untrusted descriptive message, never included in error formatting.
        message: String,
    },

    /// The authentication credentials provided were invalid or rejected by Steam.
    InvalidCredentials,

    /// The authentication session timed out waiting for approval or confirmation.
    SessionExpired,

    /// The caller cancelled the authentication attempt.
    AuthCancelled,

    /// The platform cannot perform this operation; use a local, non-sensitive label.
    UnsupportedPlatform(&'static str),

    /// Connection Manager transport is not implemented.
    CmNotImplemented,

    /// Steam Guard requires a code through an interactive login challenge.
    SteamGuardCodeRequired,

    /// A required refresh token was not present or is malformed.
    InvalidToken(String),

    /// Generating or rendering a QR code failed.
    QrCode(String),

    /// General internal or protocol parsing error.
    Internal(String),
}

impl fmt::Display for SteamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(_) | Self::Transport => f.write_str("Network transport error"),
            Self::HttpStatus(status) => write!(f, "HTTP status {status}"),
            Self::InvalidResponse(reason) => write!(f, "Invalid Steam response: {reason}"),
            Self::ProtobufEncode(_) => f.write_str("Protobuf encoding failure"),
            Self::ProtobufDecode(_) => f.write_str("Protobuf decoding failure"),
            Self::Crypto(_) => f.write_str("Cryptographic operation failed: [REDACTED]"),
            Self::SteamApi { eresult, .. } => {
                write!(f, "Steam API error (EResult {eresult}): [REDACTED]")
            }
            Self::InvalidCredentials => {
                f.write_str("Invalid Steam credentials (account name or password incorrect)")
            }
            Self::SessionExpired => {
                f.write_str("Steam authentication session expired or timed out")
            }
            Self::AuthCancelled => f.write_str("Steam authentication cancelled"),
            Self::UnsupportedPlatform(reason) => write!(f, "Unsupported platform: {reason}"),
            Self::CmNotImplemented => f.write_str("Steam CM transport is not implemented"),
            Self::SteamGuardCodeRequired => f.write_str(
                "Steam Guard code required; start the login with SteamAuth::begin_login",
            ),
            Self::InvalidToken(_) => f.write_str("Missing or invalid token: [REDACTED]"),
            Self::QrCode(_) => f.write_str("QR code generation failure: [REDACTED]"),
            Self::Internal(_) => f.write_str("Internal error: [REDACTED]"),
        }
    }
}

impl fmt::Debug for SteamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Do not expose inner error chains: they can contain URLs or remote payloads.
impl std::error::Error for SteamError {}

impl From<reqwest::Error> for SteamError {
    fn from(_: reqwest::Error) -> Self {
        Self::Transport
    }
}

impl From<prost::EncodeError> for SteamError {
    fn from(error: prost::EncodeError) -> Self {
        Self::ProtobufEncode(error)
    }
}

impl From<prost::DecodeError> for SteamError {
    fn from(error: prost::DecodeError) -> Self {
        Self::ProtobufDecode(error)
    }
}

/// Convenience alias for `std::result::Result<T, SteamError>`.
pub type Result<T> = std::result::Result<T, SteamError>;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
    use std::error::Error;

    #[test]
    fn test_error_display() {
        let err = SteamError::SteamApi {
            eresult: 5,
            message: "Invalid password".into(),
        };
        assert_eq!(err.to_string(), "Steam API error (EResult 5): [REDACTED]");

        let cred_err = SteamError::InvalidCredentials;
        assert!(cred_err.to_string().contains("Invalid Steam credentials"));
    }

    #[test]
    fn sensitive_errors_are_redacted() {
        let secret = "secret-token-password\nremote-message";
        let errors = [
            SteamError::Crypto(secret.into()),
            SteamError::InvalidToken(secret.into()),
            SteamError::QrCode(secret.into()),
            SteamError::Internal(secret.into()),
            SteamError::SteamApi {
                eresult: 84,
                message: secret.into(),
            },
            prost::DecodeError::new(secret).into(),
        ];
        for error in errors {
            for formatted in [
                error.to_string(),
                format!("{error:?}"),
                format!("{error:#?}"),
            ] {
                assert!(!formatted.contains("secret-token-password"));
                assert!(!formatted.contains("remote-message"));
            }
            assert!(error.source().is_none());
        }
        let error = SteamError::SteamApi {
            eresult: 84,
            message: secret.into(),
        };
        assert!(format!("{error:?}").contains("EResult 84"));
        assert!(error.to_string().contains("EResult 84"));
    }

    #[test]
    fn http_errors_do_not_expose_urls_or_sources() {
        let url = "https://example.invalid/private?access_token=secret-query-token";
        let error = reqwest::Client::new()
            .get(url)
            .header("invalid\nheader", "value")
            .build()
            .expect_err("invalid header")
            .with_url(url.parse().unwrap());
        let error = SteamError::Http(error);
        assert!(!format!("{error} {error:?} {error:#?}").contains("secret-query-token"));
        assert!(error.source().is_none());
        if let SteamError::Http(inner) = error {
            assert!(matches!(SteamError::from(inner), SteamError::Transport));
        }
    }

    #[test]
    fn typed_errors_keep_safe_diagnostics() {
        let errors = [
            (SteamError::HttpStatus(503), "HTTP status 503"),
            (
                SteamError::InvalidResponse("missing client ID"),
                "missing client ID",
            ),
            (
                SteamError::UnsupportedPlatform("web renewal"),
                "web renewal",
            ),
            (SteamError::Transport, "Network transport error"),
            (SteamError::AuthCancelled, "cancelled"),
            (
                SteamError::CmNotImplemented,
                "CM transport is not implemented",
            ),
        ];
        for (error, diagnostic) in errors {
            assert!(error.to_string().contains(diagnostic));
            assert!(format!("{error:?}").contains(diagnostic));
            assert!(error.source().is_none());
        }
    }

    fn check_protobuf<M: Message + Default + PartialEq>(bytes: &[u8]) {
        match M::decode(bytes) {
            Ok(message) => {
                let encoded = message.encode_to_vec();
                assert_eq!(encoded.len(), message.encoded_len());
                assert_eq!(M::decode(encoded.as_slice()).unwrap(), message);
            }
            Err(error) => {
                let error = SteamError::from(error);
                assert_eq!(error.to_string(), "Protobuf decoding failure");
                assert_eq!(format!("{error:?}"), "Protobuf decoding failure");
                assert!(error.source().is_none());
            }
        }
    }

    #[test]
    fn arbitrary_protobuf_inputs_are_safe() {
        use crate::proto::{
            CAuthenticationBeginAuthSessionViaCredentialsRequest,
            CAuthenticationPollAuthSessionStatusResponse,
            CAuthenticationRefreshTokenEnumerateResponse,
        };

        let mut rng = StdRng::seed_from_u64(0x0050_524f_544f);
        for _ in 0..1024 {
            let mut bytes = vec![0; rng.gen_range(0..=1024)];
            rng.fill_bytes(&mut bytes);
            check_protobuf::<CAuthenticationBeginAuthSessionViaCredentialsRequest>(&bytes);
            check_protobuf::<CAuthenticationPollAuthSessionStatusResponse>(&bytes);
            check_protobuf::<CAuthenticationRefreshTokenEnumerateResponse>(&bytes);
        }
        for bytes in [
            vec![0xff; 128],
            vec![0x1a, 0xff, 0xff, 0xff, 0xff, 0x0f],
            vec![0x1a, 1, 0xff],
            vec![0x0b; 256],
            vec![0x0c],
        ] {
            check_protobuf::<CAuthenticationPollAuthSessionStatusResponse>(&bytes);
        }
    }

    #[test]
    fn generated_messages_redact_secrets_and_still_roundtrip() {
        use crate::proto::{
            CAuthenticationBeginAuthSessionViaCredentialsRequest,
            CAuthenticationPollAuthSessionStatusResponse,
        };

        let request = CAuthenticationBeginAuthSessionViaCredentialsRequest {
            encrypted_password: Some("secret-encrypted-password".into()),
            guard_data: Some("secret-guard-data".into()),
            ..Default::default()
        };
        let response = CAuthenticationPollAuthSessionStatusResponse {
            access_token: Some("secret-access-token".into()),
            refresh_token: Some("secret-refresh-token".into()),
            new_guard_data: Some("secret-guard-data".into()),
            ..Default::default()
        };
        for debug in [
            format!("{request:?}"),
            format!("{request:#?}"),
            format!("{response:?}"),
            format!("{response:#?}"),
        ] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("secret-"));
        }
        check_protobuf::<CAuthenticationBeginAuthSessionViaCredentialsRequest>(
            &request.encode_to_vec(),
        );
        check_protobuf::<CAuthenticationPollAuthSessionStatusResponse>(&response.encode_to_vec());
        let mut output = [0_u8; 0];
        let error = SteamError::from(response.encode(&mut &mut output[..]).unwrap_err());
        assert_eq!(error.to_string(), "Protobuf encoding failure");
        assert!(error.source().is_none());
    }
}
