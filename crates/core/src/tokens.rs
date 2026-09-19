//! JWT token inspection and expiration utilities for Steam tokens.

use base64::Engine;
use serde::Deserialize;
use std::fmt;

use crate::error::{Result, SteamError};
use crate::EAuthTokenPlatformType;

/// Standard claims extracted from a Steam JWT access or refresh token.
#[derive(Deserialize, Clone, PartialEq, Eq)]
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

impl fmt::Debug for SteamJwtClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SteamJwtClaims")
            .field("has_subject", &self.sub.is_some())
            .field("has_expiration", &self.exp.is_some())
            .field("has_issuer", &self.iss.is_some())
            .field("audience_count", &self.aud.as_ref().map_or(0, Vec::len))
            .finish()
    }
}

const MAX_JWT_BYTES: usize = 16 * 1024;
const MAX_JWT_PAYLOAD_BYTES: usize = 8 * 1024;

/// Distinguishes a short-lived application access token from a derivable refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteamTokenKind {
    /// An access token used for WebAPI or platform-specific authenticated calls.
    Access,
    /// A refresh token that can derive access tokens or web cookies for its platform.
    Refresh,
}

/// Decodes the payload of a Steam JWT token without requiring external cryptography.
pub fn decode_jwt(token: &str) -> Result<SteamJwtClaims> {
    if token.is_empty() || token.len() > MAX_JWT_BYTES {
        return Err(SteamError::InvalidToken(
            "JWT token is empty or too large".into(),
        ));
    }
    let mut parts = token.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let (Some(header), Some(payload), Some(signature)) = (header, payload, signature) else {
        return Err(SteamError::InvalidToken(
            "Malformed JWT token (expected 3 parts)".into(),
        ));
    };
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(SteamError::InvalidToken(
            "Malformed JWT token (expected 3 parts)".into(),
        ));
    }

    let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| SteamError::InvalidToken("Invalid JWT payload encoding".into()))?;
    if bytes.len() > MAX_JWT_PAYLOAD_BYTES {
        return Err(SteamError::InvalidToken("JWT payload is too large".into()));
    }
    let claims: SteamJwtClaims = serde_json::from_slice(&bytes)
        .map_err(|_| SteamError::InvalidToken("Invalid JWT claims JSON".into()))?;

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
        None => return true,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    now.saturating_add(margin_seconds) >= exp
}

/// Validates non-cryptographic Steam JWT claims required to keep token categories and platform
/// audiences separate.
///
/// This function does not verify a JWT signature and must not be used as an authorization
/// boundary. Steam validates the token remotely; this only rejects locally inconsistent state.
pub fn validate_steam_token(
    token: &str,
    kind: SteamTokenKind,
    platform: EAuthTokenPlatformType,
    expected_steam_id: Option<u64>,
) -> Result<u64> {
    let claims = decode_jwt(token)?;
    let steam_id = claims
        .sub
        .as_deref()
        .and_then(|subject| subject.parse::<u64>().ok())
        .filter(|steam_id| *steam_id != 0)
        .ok_or_else(|| SteamError::InvalidToken("Steam JWT has no valid subject".into()))?;
    if let Some(expected_steam_id) = expected_steam_id.filter(|steam_id| *steam_id != 0) {
        if steam_id != expected_steam_id {
            return Err(SteamError::InvalidToken(
                "Steam JWT subject does not match the session".into(),
            ));
        }
    }

    let audiences = claims
        .aud
        .as_deref()
        .ok_or_else(|| SteamError::InvalidToken("Steam JWT has no audience list".into()))?;
    let derives = audiences.iter().any(|audience| audience == "derive");
    if matches!(kind, SteamTokenKind::Refresh) != derives {
        return Err(SteamError::InvalidToken(
            "Steam JWT token kind does not match its audience".into(),
        ));
    }
    if !audiences.iter().any(|audience| audience == "web") {
        return Err(SteamError::InvalidToken(
            "Steam JWT is missing the web audience".into(),
        ));
    }
    let platform_audience = match platform {
        EAuthTokenPlatformType::WebBrowser => None,
        EAuthTokenPlatformType::MobileApp => Some("mobile"),
        EAuthTokenPlatformType::SteamClient => Some("client"),
        EAuthTokenPlatformType::Unknown => {
            return Err(SteamError::UnsupportedPlatform(
                "Unknown Steam token platform",
            ));
        }
    };
    if platform_audience.is_some_and(|audience| !audiences.iter().any(|item| item == audience)) {
        return Err(SteamError::InvalidToken(
            "Steam JWT audience does not match the session platform".into(),
        ));
    }
    Ok(steam_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

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

    #[test]
    fn token_debug_and_parse_failures_do_not_expose_token_material() {
        let token = "secret-header.secret-payload.secret-signature";
        let error = decode_jwt(token).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("secret-"));

        let claims = SteamJwtClaims {
            sub: Some("76561198000000000".into()),
            exp: Some(1),
            iss: Some("secret-issuer".into()),
            aud: Some(vec!["secret-audience".into()]),
        };
        let debug = format!("{claims:?}");
        assert!(!debug.contains("secret-"));
        assert!(debug.contains("has_subject"));
    }

    #[test]
    fn arbitrary_jwt_inputs_are_bounded_and_safe() {
        let mut rng = StdRng::seed_from_u64(0x4a57_5400);
        for _ in 0..1024 {
            let mut bytes = vec![0; rng.gen_range(0..=MAX_JWT_BYTES + 128)];
            rng.fill_bytes(&mut bytes);
            let input = String::from_utf8_lossy(&bytes);
            let _ = decode_jwt(&input);
            assert!(is_token_expired(&input, u64::MAX));
        }
    }

    #[test]
    fn token_kind_and_platform_audiences_are_checked_without_signature_claims() {
        let future_exp = 1_893_456_000_u64;
        let make_token = |audiences: &str| {
            let payload = format!(r#"{{"sub":"42","exp":{future_exp},"aud":{audiences}}}"#);
            format!(
                "header.{}.signature",
                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload)
            )
        };
        let mobile_refresh = make_token(r#"["web","mobile","derive"]"#);
        let mobile_access = make_token(r#"["web","mobile"]"#);
        assert_eq!(
            validate_steam_token(
                &mobile_refresh,
                SteamTokenKind::Refresh,
                EAuthTokenPlatformType::MobileApp,
                Some(42),
            )
            .unwrap(),
            42
        );
        assert!(validate_steam_token(
            &mobile_access,
            SteamTokenKind::Refresh,
            EAuthTokenPlatformType::MobileApp,
            Some(42),
        )
        .is_err());
        assert!(validate_steam_token(
            &mobile_access,
            SteamTokenKind::Access,
            EAuthTokenPlatformType::SteamClient,
            Some(42),
        )
        .is_err());
    }
}
