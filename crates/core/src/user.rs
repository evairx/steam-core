//! Steam user client foundations.
//!
//! CM transport and protocol support are not implemented. Connection and presence operations
//! return errors rather than presenting local state changes as remote success.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::auth::AuthenticatedSession;
use crate::error::{Result, SteamError};

/// Persona online state in the Steam Community.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i32)]
pub enum EPersonaState {
    #[default]
    Offline = 0,
    Online = 1,
    Busy = 2,
    Away = 3,
    Snooze = 4,
    LookingToTrade = 5,
    LookingToPlay = 6,
    Invisible = 7,
}

/// Transport protocol for connecting to Steam Connection Manager (CM) servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ECmProtocol {
    #[default]
    WebSocket,
    Tcp,
}

/// Configuration options for [`SteamUser`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamUserOptions {
    /// Transport protocol (WebSocket or TCP). Defaults to WebSocket.
    pub protocol: ECmProtocol,
    /// Whether to automatically reconnect upon connection loss.
    pub auto_reconnect: bool,
    /// Heartbeat ping interval in seconds.
    pub heartbeat_interval: Duration,
    /// Initial persona state after logon.
    pub initial_persona_state: EPersonaState,
}

impl Default for SteamUserOptions {
    fn default() -> Self {
        Self {
            protocol: ECmProtocol::WebSocket,
            auto_reconnect: true,
            heartbeat_interval: Duration::from_secs(30),
            initial_persona_state: EPersonaState::Online,
        }
    }
}

/// Lifecycle and network events emitted by [`SteamUser`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SteamUserEvent {
    /// Successfully connected to a Steam CM server.
    Connected { cm_server: String },
    /// Successfully logged on to the Steam network with confirmed SteamID.
    LoggedOn { steam_id: u64, account_name: String },
    /// Disconnected from the Steam network.
    Disconnected { reason: String },
    /// Persona state changed.
    PersonaStateUpdated { state: EPersonaState },
    /// Currently played game IDs changed.
    GamesPlayingUpdated { app_ids: Vec<u32> },
}

/// Connection Manager endpoint description returned by Steam Directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmServerEndpoint {
    pub endpoint: String,
    pub legacy_endpoint: Option<String>,
    pub r#type: String,
    pub dc: Option<String>,
}

/// Reserved client API for interacting with the Steam network as a logged-in user.
///
/// An [`AuthenticatedSession`] does not establish a CM connection. Until CM transport and
/// logon are implemented, [`Self::connect`] cannot return a connected client.
pub struct SteamUser {
    steam_id: u64,
    account_name: String,
    current_persona_state: EPersonaState,
    currently_playing: Vec<u32>,
    options: SteamUserOptions,
    is_connected: bool,
}

impl SteamUser {
    /// Attempts to connect using an authenticated session.
    ///
    /// Returns [`SteamError::InvalidToken`] for an empty access token, otherwise
    /// [`SteamError::CmNotImplemented`]. No transport is opened or CM logon performed.
    pub async fn connect(
        session: &AuthenticatedSession,
        _options: SteamUserOptions,
    ) -> Result<Self> {
        let access_token = session.export_access_token();

        if access_token.is_empty() {
            return Err(SteamError::InvalidToken(
                "Cannot connect SteamUser without a valid access_token".into(),
            ));
        }

        Err(SteamError::CmNotImplemented)
    }

    /// Returns the 64-bit SteamID of the connected user.
    pub fn steam_id(&self) -> u64 {
        self.steam_id
    }

    /// Returns the account login name.
    pub fn account_name(&self) -> &str {
        &self.account_name
    }

    /// Returns the active configuration options.
    pub fn options(&self) -> &SteamUserOptions {
        &self.options
    }

    /// Returns whether the client is currently connected and logged on to the CM network.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Requests a persona state change on Steam.
    ///
    /// Returns [`SteamError::CmNotImplemented`] without changing local or remote state.
    pub async fn set_persona_state(&mut self, _state: EPersonaState) -> Result<()> {
        Err(SteamError::CmNotImplemented)
    }

    /// Requests a change to the Steam AppIDs currently being played.
    ///
    /// Returns [`SteamError::CmNotImplemented`] without changing local or remote state.
    pub async fn set_games_played(&mut self, _app_ids: &[u32]) -> Result<()> {
        Err(SteamError::CmNotImplemented)
    }

    /// Returns the locally stored AppIDs, not a query of remote Steam presence.
    pub fn games_played(&self) -> &[u32] {
        &self.currently_playing
    }

    /// Returns the locally stored persona state, not a query of remote Steam presence.
    pub fn persona_state(&self) -> EPersonaState {
        self.current_persona_state
    }

    /// Clears local connection and presence state. No CM logoff message is sent.
    pub async fn disconnect(&mut self) -> Result<()> {
        self.is_connected = false;
        self.currently_playing.clear();
        self.current_persona_state = EPersonaState::Offline;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SteamWebCookies;
    use crate::enums::EAuthTokenPlatformType;
    use crate::session::LoginSession;

    #[tokio::test]
    async fn connect_never_succeeds_without_cm_transport() {
        for access_token in ["", "not-a-real-access-token"] {
            // Local fixture only: no login, token validation, or network request.
            let session = AuthenticatedSession::new(
                "test-account".into(),
                0,
                String::new(),
                access_token.into(),
                SteamWebCookies {
                    session_id: String::new(),
                    steam_login_secure: None,
                    all_cookies: Vec::new(),
                },
                LoginSession::new(EAuthTokenPlatformType::WebBrowser),
            );

            for protocol in [ECmProtocol::WebSocket, ECmProtocol::Tcp] {
                let result = SteamUser::connect(
                    &session,
                    SteamUserOptions {
                        protocol,
                        ..SteamUserOptions::default()
                    },
                )
                .await;

                if access_token.is_empty() {
                    assert!(matches!(result, Err(SteamError::InvalidToken(_))));
                } else {
                    assert!(matches!(result, Err(SteamError::CmNotImplemented)));
                }
            }
        }
    }

    #[tokio::test]
    async fn presence_operations_never_report_remote_success() {
        for is_connected in [false, true] {
            // Even a fabricated local connected flag must not permit false success.
            let mut user = SteamUser {
                steam_id: 0,
                account_name: "test-account".into(),
                current_persona_state: EPersonaState::Offline,
                currently_playing: vec![440],
                options: SteamUserOptions::default(),
                is_connected,
            };

            assert!(matches!(
                user.set_persona_state(EPersonaState::Online).await,
                Err(SteamError::CmNotImplemented)
            ));
            assert_eq!(user.persona_state(), EPersonaState::Offline);

            for app_ids in [&[730][..], &[][..]] {
                assert!(matches!(
                    user.set_games_played(app_ids).await,
                    Err(SteamError::CmNotImplemented)
                ));
                assert_eq!(user.games_played(), &[440]);
            }
            assert_eq!(user.is_connected(), is_connected);
        }
    }
}
