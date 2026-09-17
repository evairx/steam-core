//! # steam-core
//!
//! All-in-one high-performance Steam client and authentication library in Rust,
//! unifying authentication (`steam-session`) and Steam network client interactions (`steam-user`).
//!
//! ## Key Capabilities
//! - **Unified Architecture:** Seamlessly connects authentication (`SteamAuth`) with the client (`SteamUser`).
//! - **Credentials & QR Auth:** RSA PKCS#1 v1.5 encryption, Steam Guard push notifications, TOTP codes, QR generation.
//! - **Hardware-Backed OS Vault:** Stores tokens & cookies safely in Windows Credential Manager, macOS Keychain, or Linux Secret Service.
//! - **Background Auto-Keeper:** Silently watches JWT token expiration and automatically rotates access tokens and web cookies before they expire.
//! - **Steam Network Integration:** Connects to Valve's Connection Manager (CM) servers using validated `access_token` JWTs.
//!
//! ## Quick Start
//!
//! ```no_run
//! use steam_core::{SteamAuth, SteamUser, SteamUserOptions, EPersonaState, AuthEvent};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. One-line Login with automatic OS vault storage & restoration
//!     let session = SteamAuth::load_or_login("username", "password", |event| {
//!         if event == AuthEvent::NeedMobileConfirmation {
//!             println!("Approve the notification on your phone!");
//!         }
//!     }).await?;
//!
//!     // 2. Start background auto-renewal (never let cookies or tokens expire)
//!     let _keeper = session.spawn_keeper(None);
//!
//!     // 3. Connect to the Steam network using the authenticated session
//!     let mut user = SteamUser::connect(&session, SteamUserOptions::default()).await?;
//!     user.set_persona_state(EPersonaState::Online).await?;
//!     user.set_games_played(&[730]).await?; // Idle Counter-Strike 2
//!
//!     println!("Successfully logged on as: {}", user.account_name());
//!     Ok(())
//! }
//! ```

pub mod auth;
pub mod client;
pub mod crypto;
pub mod enums;
pub mod error;
pub mod keeper;
pub mod session;
pub mod tokens;
pub mod user;
pub mod vault;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

// Re-export primary types for ergonomics
pub use auth::{AuthEvent, AuthenticatedSession, QrChallenge, SteamAuth};
pub use client::{SteamApiClient, SteamApiClientBuilder, SteamRsaKey, SteamWebCookies};
pub use crypto::{encrypt_password, EncryptedPassword};
pub use enums::{EAuthSessionGuardType, EAuthTokenPlatformType, EResult, ESessionPersistence};
pub use error::{Result, SteamError};
pub use keeper::{AutoKeeper, AutoKeeperHandle};
pub use session::{AuthTokens, CredentialsAuthSession, LoginSession, PollStatus, QrAuthSession};
pub use tokens::{decode_jwt, is_token_expired, SteamJwtClaims};
pub use user::{ECmProtocol, EPersonaState, SteamUser, SteamUserEvent, SteamUserOptions};
pub use vault::{SavedSession, SessionVault};
