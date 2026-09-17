//! # steam-auth
//!
//! High-performance, native Rust library for Steam authentication and session management.
//!
//! Provides zero-friction, cross-platform capabilities:
//! - Credentials login with RSA PKCS#1 v1.5 dynamic encryption.
//! - Steam Guard 2FA support (Mobile Authenticator Push, TOTP codes, Email codes).
//! - QR Code generation and scanning flows (with built-in terminal and graphical QR rendering).
//! - Automatic web cookie acquisition (`steamLoginSecure`, `sessionid`).
//! - Hardware-backed secure persistence via OS credential stores (Windows Credential Manager, macOS Keychain, Linux Secret Service).
//! - Background Auto-Keeper daemon for silent automatic token & cookie renewals.
//! - Direct restoration and refresh token lifecycle management.
//!
//! ## Quick Start
//!
//! ```no_run
//! use steam_auth::{SteamAuth, AuthEvent};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. One-line Login with automatic OS vault storage & restoration:
//!     let mut session = SteamAuth::load_or_login("username", "password", |event| {
//!         if event == AuthEvent::NeedMobileConfirmation {
//!             println!("Approve the notification on your phone!");
//!         }
//!     }).await?;
//!
//!     // 2. Start background auto-renewal (never let cookies expire):
//!     let _keeper = session.spawn_keeper(None);
//!
//!     // 3. Ready-to-use cookies:
//!     println!("Session cookie: {:?}", session.cookies.steam_login_secure);
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
pub use vault::{SavedSession, SessionVault};
