//! Secure session persistence using the operating system's native credential store.
//!
//! On Windows, this utilizes the **Windows Credential Manager**.
//! On macOS, it uses the **Keychain**.
//! On Linux, it interfaces with the **Secret Service** / DBus daemon.
//!
//! The active platform credential provider protects the serialized session. Callers can choose
//! in-memory sessions instead when no secure provider is appropriate for their target.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

#[cfg(feature = "keyring-store")]
use keyring::Entry;
use serde::{Deserialize, Serialize};

use crate::client::SteamWebCookies;
use crate::enums::EAuthTokenPlatformType;
use crate::error::{Result, SteamError};

#[cfg(feature = "keyring-store")]
const SERVICE_NAME: &str = "steam-core";

/// Persistent storage for authenticated session material.
///
/// Platform integrations provide this boundary rather than forcing the core to depend on a
/// particular keychain, database, or runtime. Implementations must never silently fall back to
/// plaintext storage when secure persistence is required by the host application.
pub trait SessionStore: Send + Sync {
    /// Persists a session for its account name.
    fn save(&self, session: &SavedSession) -> Result<()>;

    /// Retrieves a persisted session for an account name.
    fn load(&self, account_name: &str) -> Result<Option<SavedSession>>;

    /// Removes a persisted session for an account name.
    fn delete(&self, account_name: &str) -> Result<()>;
}

/// Stored session data containing credentials, tokens, and web cookies.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedSession {
    /// The Steam account login name.
    pub(crate) account_name: String,
    /// The resolved SteamID64.
    pub(crate) steam_id: u64,
    /// The long-lived refresh token.
    pub(crate) refresh_token: String,
    /// The short-lived access token.
    pub(crate) access_token: String,
    /// The web session cookies.
    pub(crate) cookies: SteamWebCookies,
    /// Steam Guard device data returned after a successful authentication.
    #[serde(default)]
    pub(crate) guard_data: Option<String>,
    /// Platform for which the refresh and access tokens were issued.
    #[serde(default = "default_platform_type")]
    pub(crate) platform_type: EAuthTokenPlatformType,
    /// Unix timestamp in seconds when this session was stored.
    pub(crate) saved_at: u64,
}

impl fmt::Debug for SavedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavedSession")
            .field("account_name", &self.account_name)
            .field("steam_id", &self.steam_id)
            .field("has_refresh_token", &!self.refresh_token.is_empty())
            .field("has_access_token", &!self.access_token.is_empty())
            .field("cookie_count", &self.cookies.all_cookies.len())
            .field("has_guard_data", &self.guard_data.is_some())
            .field("platform_type", &self.platform_type)
            .field("saved_at", &self.saved_at)
            .finish()
    }
}

impl SavedSession {
    /// Returns the account login name associated with this saved session.
    pub fn account_name(&self) -> &str {
        &self.account_name
    }

    /// Returns the SteamID64 associated with this saved session.
    pub fn steam_id(&self) -> u64 {
        self.steam_id
    }

    /// Returns the save timestamp as Unix seconds.
    pub fn saved_at(&self) -> u64 {
        self.saved_at
    }

    /// Returns the refresh token only when the caller explicitly needs to export it.
    pub fn export_refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Returns the access token only when the caller explicitly needs to export it.
    pub fn export_access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns web cookies only when the caller explicitly needs to export them.
    pub fn export_cookies(&self) -> &SteamWebCookies {
        &self.cookies
    }

    /// Returns device guard data only when the caller explicitly needs to export it.
    pub fn export_guard_data(&self) -> Option<&str> {
        self.guard_data.as_deref()
    }

    /// Returns the token platform selected when this session was saved.
    pub fn platform_type(&self) -> EAuthTokenPlatformType {
        self.platform_type
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.account_name.trim().is_empty()
            || self.account_name.len() > 256
            || self.account_name.chars().any(char::is_control)
        {
            return Err(SteamError::InvalidResponse(
                "Saved session has no valid account name",
            ));
        }
        if self.steam_id == 0
            || self.refresh_token.trim().is_empty()
            || self.access_token.trim().is_empty()
        {
            return Err(SteamError::InvalidResponse("Saved session is incomplete"));
        }
        if self.platform_type == EAuthTokenPlatformType::Unknown {
            return Err(SteamError::InvalidResponse(
                "Saved session has an unknown platform",
            ));
        }
        if self.platform_type == EAuthTokenPlatformType::WebBrowser
            && self
                .cookies
                .steam_login_secure
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true)
        {
            return Err(SteamError::InvalidResponse(
                "Saved web session has no login cookie",
            ));
        }
        Ok(())
    }
}

fn default_platform_type() -> EAuthTokenPlatformType {
    // Records created before platform metadata existed were browser sessions.
    EAuthTokenPlatformType::WebBrowser
}

/// Secure session vault for storing and retrieving authenticated Steam sessions.
#[derive(Debug, Default)]
pub struct SessionVault;

impl SessionVault {
    /// Saves an authenticated session securely in the OS credential store.
    pub fn save(session: &SavedSession) -> Result<()> {
        session.validate()?;
        #[cfg(feature = "keyring-store")]
        {
            let entry = Entry::new(SERVICE_NAME, &session.account_name)
                .map_err(|e| SteamError::Internal(format!("Failed to access OS keyring: {e}")))?;

            let serialized = serde_json::to_string(session).map_err(|e| {
                SteamError::Internal(format!("Failed to serialize session data: {e}"))
            })?;

            entry
                .set_password(&serialized)
                .map_err(|e| SteamError::Internal(format!("Failed to write to OS keyring: {e}")))?;

            Ok(())
        }

        #[cfg(not(feature = "keyring-store"))]
        {
            let _ = session;
            Err(SteamError::Internal(
                "The keyring-store feature is disabled; inject a platform SessionStore instead"
                    .into(),
            ))
        }
    }

    /// Loads a previously stored session for the given account name from the OS credential store.
    pub fn load(account_name: &str) -> Result<Option<SavedSession>> {
        #[cfg(feature = "keyring-store")]
        {
            let entry = Entry::new(SERVICE_NAME, account_name)
                .map_err(|e| SteamError::Internal(format!("Failed to access OS keyring: {e}")))?;

            match entry.get_password() {
                Ok(json_str) => {
                    let session: SavedSession = serde_json::from_str(&json_str).map_err(|e| {
                        SteamError::Internal(format!("Corrupted session data in keyring: {e}"))
                    })?;
                    session.validate()?;
                    Ok(Some(session))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(SteamError::Internal(format!(
                    "Failed to read from OS keyring: {e}"
                ))),
            }
        }

        #[cfg(not(feature = "keyring-store"))]
        {
            let _ = account_name;
            Err(SteamError::Internal(
                "The keyring-store feature is disabled; inject a platform SessionStore instead"
                    .into(),
            ))
        }
    }

    /// Deletes a stored session from the OS credential store.
    pub fn delete(account_name: &str) -> Result<()> {
        #[cfg(feature = "keyring-store")]
        {
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

        #[cfg(not(feature = "keyring-store"))]
        {
            let _ = account_name;
            Err(SteamError::Internal(
                "The keyring-store feature is disabled; inject a platform SessionStore instead"
                    .into(),
            ))
        }
    }
}

impl SessionStore for SessionVault {
    fn save(&self, session: &SavedSession) -> Result<()> {
        session.validate()?;
        Self::save(session)
    }

    fn load(&self, account_name: &str) -> Result<Option<SavedSession>> {
        Self::load(account_name)
    }

    fn delete(&self, account_name: &str) -> Result<()> {
        Self::delete(account_name)
    }
}

/// In-memory session storage for ephemeral targets and tests.
///
/// This store intentionally does not persist across process restarts. Applications that require
/// persistent storage must inject a platform-specific secure implementation instead.
#[derive(Clone, Default)]
pub struct MemorySessionStore {
    sessions: Arc<Mutex<HashMap<String, SavedSession>>>,
}

impl MemorySessionStore {
    /// Creates an empty ephemeral session store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn save(&self, session: &SavedSession) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SteamError::Internal("Memory session store lock was poisoned".into()))?;
        sessions.insert(session.account_name.clone(), session.clone());
        Ok(())
    }

    fn load(&self, account_name: &str) -> Result<Option<SavedSession>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| SteamError::Internal("Memory session store lock was poisoned".into()))?;
        let session = sessions.get(account_name).cloned();
        if let Some(session) = &session {
            session.validate()?;
            if session.account_name != account_name {
                return Err(SteamError::InvalidResponse(
                    "Saved session account does not match requested account",
                ));
            }
        }
        Ok(session)
    }

    fn delete(&self, account_name: &str) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SteamError::Internal("Memory session store lock was poisoned".into()))?;
        sessions.remove(account_name);
        Ok(())
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
            guard_data: Some("guard-data".into()),
            platform_type: EAuthTokenPlatformType::WebBrowser,
            saved_at: 1700000000,
        };

        let json = serde_json::to_string(&session).expect("serialize session");
        let deserialized: SavedSession = serde_json::from_str(&json).expect("deserialize session");
        assert_eq!(session, deserialized);
    }

    #[test]
    fn saved_session_debug_output_redacts_secrets() {
        let session = SavedSession {
            account_name: "test_user".into(),
            steam_id: 76561198000000000,
            refresh_token: "refresh-secret".into(),
            access_token: "access-secret".into(),
            cookies: SteamWebCookies {
                session_id: "session-secret".into(),
                steam_login_secure: Some("cookie-secret".into()),
                all_cookies: vec!["raw-cookie-secret".into()],
            },
            guard_data: Some("guard-data-secret".into()),
            platform_type: EAuthTokenPlatformType::WebBrowser,
            saved_at: 1700000000,
        };

        let output = format!("{session:?}");
        assert!(!output.contains("refresh-secret"));
        assert!(!output.contains("access-secret"));
        assert!(!output.contains("session-secret"));
        assert!(!output.contains("cookie-secret"));
        assert!(!output.contains("raw-cookie-secret"));
        assert!(!output.contains("guard-data-secret"));
    }

    #[test]
    fn memory_session_store_is_ephemeral_and_account_scoped() {
        let store = MemorySessionStore::new();
        let session = SavedSession {
            account_name: "test_user".into(),
            steam_id: 76561198000000000,
            refresh_token: "refresh-secret".into(),
            access_token: "access-secret".into(),
            cookies: SteamWebCookies {
                session_id: "session-secret".into(),
                steam_login_secure: Some("cookie-secret".into()),
                all_cookies: vec!["raw-cookie-secret".into()],
            },
            guard_data: None,
            platform_type: EAuthTokenPlatformType::WebBrowser,
            saved_at: 1700000000,
        };

        store.save(&session).expect("save memory session");
        assert_eq!(
            store
                .load("test_user")
                .expect("load memory session")
                .expect("stored session")
                .account_name(),
            "test_user"
        );
        store.delete("test_user").expect("delete memory session");
        assert!(store
            .load("test_user")
            .expect("load deleted session")
            .is_none());
    }
}
