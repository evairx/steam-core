//! Strongly-typed error definitions for Steam authentication.

use thiserror::Error;

/// The primary error type for all operations within `steam-auth`.
#[derive(Error, Debug)]
pub enum SteamError {
    /// An error occurred during an HTTP request or network transport.
    #[error("Network transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// Failed to encode a Protobuf message.
    #[error("Protobuf encoding failure: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),

    /// Failed to decode a Protobuf message from Steam.
    #[error("Protobuf decoding failure: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    /// An error occurred during RSA cryptographic operations.
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    /// Steam API responded with a non-success `EResult`.
    #[error("Steam API error (EResult {eresult}): {message}")]
    SteamApi {
        /// The numeric Steam EResult code.
        eresult: i32,
        /// Descriptive message from Steam or the error catalog.
        message: String,
    },

    /// The authentication credentials provided were invalid or rejected by Steam.
    #[error("Invalid Steam credentials (account name or password incorrect)")]
    InvalidCredentials,

    /// The authentication session timed out waiting for approval or confirmation.
    #[error("Steam authentication session expired or timed out")]
    SessionExpired,

    /// A required refresh token was not present or is malformed.
    #[error("Missing or invalid token: {0}")]
    InvalidToken(String),

    /// Generating or rendering a QR code failed.
    #[error("QR code generation failure: {0}")]
    QrCode(String),

    /// General internal or protocol parsing error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenience alias for `std::result::Result<T, SteamError>`.
pub type Result<T> = std::result::Result<T, SteamError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SteamError::SteamApi {
            eresult: 5,
            message: "Invalid password".into(),
        };
        assert_eq!(err.to_string(), "Steam API error (EResult 5): Invalid password");

        let cred_err = SteamError::InvalidCredentials;
        assert!(cred_err.to_string().contains("Invalid Steam credentials"));
    }
}
