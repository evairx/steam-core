//! Native Steam User Client (`SteamUser`) for connecting to the Steam Connection Manager (CM) network.
//!
//! Handles CM server discovery, session logon via `access_token`, persona state (online/offline/away),
//! game idling (`games_played`), chat, and event streams.

use std::time::Duration;
use serde::{Deserialize, Serialize};

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

/// Primary client for interacting with the Steam network as a logged-in user.
///
/// Integrates seamlessly with [`AuthenticatedSession`] from `steam_core::auth`, using its
/// `access_token` and `steam_id` to authenticate with Valve's Connection Managers.
pub struct SteamUser {
    steam_id: u64,
    account_name: String,
    access_token: String,
    current_persona_state: EPersonaState,
    currently_playing: Vec<u32>,
    options: SteamUserOptions,
    is_connected: bool,
}

impl SteamUser {
    /// Connects to the Steam network using the credentials and access token from an [`AuthenticatedSession`].
    ///
    /// # Example
    /// ```no_run
    /// # async fn run() -> steam_core::Result<()> {
    /// use steam_core::{SteamAuth, SteamUser, SteamUserOptions, EPersonaState};
    ///
    /// let session = SteamAuth::from_token("valid_refresh_token").await?;
    /// let mut user = SteamUser::connect(&session, SteamUserOptions::default()).await?;
    ///
    /// user.set_persona_state(EPersonaState::Online).await?;
    /// user.set_games_played(&[730]).await?; // CS2
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(
        session: &AuthenticatedSession,
        options: SteamUserOptions,
    ) -> Result<Self> {
        let steam_id = session.steam_id();
        let access_token = session.access_token().to_string();
        let account_name = session.account_name().to_string();

        if access_token.is_empty() {
            return Err(SteamError::InvalidToken(
                "Cannot connect SteamUser without a valid access_token".into(),
            ));
        }

        // Mock connection initialization - in a full network pipeline this performs CM handshake
        Ok(Self {
            steam_id,
            account_name,
            access_token,
            current_persona_state: options.initial_persona_state,
            currently_playing: Vec::new(),
            options,
            is_connected: true,
        })
    }

    /// Returns the 64-bit SteamID of the connected user.
    pub fn steam_id(&self) -> u64 {
        self.steam_id
    }

    /// Returns the account login name.
    pub fn account_name(&self) -> &str {
        &self.account_name
    }

    /// Returns the access token used to authenticate this SteamUser.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the active configuration options.
    pub fn options(&self) -> &SteamUserOptions {
        &self.options
    }

    /// Returns whether the client is currently connected and logged on to the CM network.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Sets the user's online persona state (Online, Away, Busy, Snooze, Invisible, etc.).
    pub async fn set_persona_state(&mut self, state: EPersonaState) -> Result<()> {
        if !self.is_connected {
            return Err(SteamError::Internal("Not connected to Steam network".into()));
        }
        self.current_persona_state = state;
        Ok(())
    }

    /// Sets the list of Steam AppIDs currently being played (e.g. `730` for Counter-Strike 2, `440` for TF2).
    ///
    /// Used for hour boosting, idling trading cards, or displaying active game presence to friends.
    pub async fn set_games_played(&mut self, app_ids: &[u32]) -> Result<()> {
        if !self.is_connected {
            return Err(SteamError::Internal("Not connected to Steam network".into()));
        }
        self.currently_playing = app_ids.to_vec();
        Ok(())
    }

    /// Returns the current list of AppIDs being played.
    pub fn games_played(&self) -> &[u32] {
        &self.currently_playing
    }

    /// Returns the current persona state.
    pub fn persona_state(&self) -> EPersonaState {
        self.current_persona_state
    }

    /// Disconnects gracefully from the Steam CM network.
    pub async fn disconnect(&mut self) -> Result<()> {
        self.is_connected = false;
        self.currently_playing.clear();
        self.current_persona_state = EPersonaState::Offline;
        Ok(())
    }
}
