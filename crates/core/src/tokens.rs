//! JWT token inspection and expiration utilities for Steam tokens.

use base64::Engine;
use serde::Deserialize;

use crate::error::{Result, SteamError};

/// Standard claims extracted from a Steam JWT access or refresh token.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SteamJwtClaims {
    /// Subject: SteamID64 as string.
    pub sub: Option<String>,
    /// Expiration timestamp in seconds since Unix epoch.
    pub exp: Option<u64>,
    /// Issuer (typically "steam").
    pub iss: Option<String>,
    /// Audiences for which this token was issued (e.g. `["web", "client"]`).
    pub aud: Option<Vec<String>>,
}

/// Decodes the payload of a Steam JWT token without requiring external cryptography.
pub fn decode_jwt(token: &str) -> Result<SteamJwtClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SteamError::InvalidToken("Malformed JWT token (expected 3 parts)".into()));
    }

    let mut payload = parts[1].replace('-', "+").replace('_', "/");
    while !payload.len().is_multiple_of(4) {
        payload.push('=');
    }

    let bytes = base64::prelude::BASE64_STANDARD
        .decode(&payload)
        .map_err(|e| SteamError::InvalidToken(format!("Base64 decoding failed for JWT: {e}")))?;

    let claims: SteamJwtClaims = serde_json::from_slice(&bytes)
        .map_err(|e| SteamError::InvalidToken(format!("JSON parsing failed for JWT claims: {e}")))?;

    Ok(claims)
}

/// Checks whether a JWT token is expired or will expire within the given safety margin in seconds.
pub fn is_token_expired(token: &str, margin_seconds: u64) -> bool {
    let claims = match decode_jwt(token) {
        Ok(c) => c,
        Err(_) => return true,
    };

    let exp = match claims.exp {
        Some(exp) => exp,
        None => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    now + margin_seconds >= exp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_decode() {
        // Minimal mock JWT header.payload.signature
        // Payload: {"sub":"76561198000000000","exp":1893456000,"iss":"steam"}
        let mock_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI3NjU2MTE5ODAwMDAwMDAwMCIsImV4cCI6MTg5MzQ1NjAwMCwiaXNzIjoic3RlYW0ifQ.mockSignature";

        let claims = decode_jwt(mock_token).expect("decode mock jwt");
        assert_eq!(claims.sub.as_deref(), Some("76561198000000000"));
        assert_eq!(claims.exp, Some(1893456000));
        assert_eq!(claims.iss.as_deref(), Some("steam"));

        assert!(!is_token_expired(mock_token, 60));
    }
}
