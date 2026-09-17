//! Secure session persistence using the operating system's native credential store.
//!
//! On Windows, this utilizes the **Windows Credential Manager**.
//! On macOS, it uses the **Keychain**.
//! On Linux, it interfaces with the **Secret Service** / DBus daemon.
//!
//! Tokens and web cookies are encrypted by the OS hardware/system keystore and are never stored in plain-text files.

use keyring::Entry;
use serde::{Deserialize, Serialize};

use crate::client::SteamWebCookies;
use crate::error::{Result, SteamError};

const SERVICE_NAME: &str = "steam-auth";

/// Stored session data containing credentials, tokens, and web cookies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedSession {
    /// The Steam account login name.
    pub account_name: String,
    /// The resolved SteamID64.
    pub steam_id: u64,
    /// The long-lived refresh token.
    pub refresh_token: String,
    /// The short-lived access token.
    pub access_token: String,
    /// The web session cookies.
    pub cookies: SteamWebCookies,
    /// Unix timestamp in seconds when this session was stored.
    pub saved_at: u64,
}

/// Secure session vault for storing and retrieving authenticated Steam sessions.
pub struct SessionVault;

impl SessionVault {
    /// Saves an authenticated session securely in the OS credential store.
    pub fn save(session: &SavedSession) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, &session.account_name)
            .map_err(|e| SteamError::Internal(format!("Failed to access OS keyring: {e}")))?;

        let serialized = serde_json::to_string(session)
            .map_err(|e| SteamError::Internal(format!("Failed to serialize session data: {e}")))?;

        entry
            .set_password(&serialized)
            .map_err(|e| SteamError::Internal(format!("Failed to write to OS keyring: {e}")))?;

        Ok(())
    }

    /// Loads a previously stored session for the given account name from the OS credential store.
    pub fn load(account_name: &str) -> Result<Option<SavedSession>> {
        let entry = Entry::new(SERVICE_NAME, account_name)
            .map_err(|e| SteamError::Internal(format!("Failed to access OS keyring: {e}")))?;

        match entry.get_password() {
            Ok(json_str) => {
                let session: SavedSession = serde_json::from_str(&json_str).map_err(|e| {
                    SteamError::Internal(format!("Corrupted session data in keyring: {e}"))
                })?;
                Ok(Some(session))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SteamError::Internal(format!(
                "Failed to read from OS keyring: {e}"
            ))),
        }
    }

    /// Deletes a stored session from the OS credential store.
    pub fn delete(account_name: &str) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, account_name)
            .map_err(|e| SteamError::Internal(format!("Failed to access OS keyring: {e}")))?;

        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SteamError::Internal(format!(
                "Failed to delete from OS keyring: {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saved_session_serde() {
        let session = SavedSession {
            account_name: "test_user".into(),
            steam_id: 76561198000000000,
            refresh_token: "eyMockRefresh".into(),
            access_token: "eyMockAccess".into(),
            cookies: SteamWebCookies {
                session_id: "abc123session".into(),
                steam_login_secure: Some("76561198000000000||eyMockAccess".into()),
                all_cookies: vec!["sessionid=abc123session".into()],
            },
            saved_at: 1700000000,
        };

        let json = serde_json::to_string(&session).expect("serialize session");
        let deserialized: SavedSession = serde_json::from_str(&json).expect("deserialize session");
        assert_eq!(session, deserialized);
    }
}
