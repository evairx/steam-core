//! # steam-core
//!
//! Native Rust core for Steam authentication and session management.
//!
//! ## Key Capabilities
//! - **Credentials and QR Auth:** RSA PKCS#1 v1.5 encryption, Steam Guard approval and QR generation.
//! - **Explicit Secrets:** Tokens and cookies are redacted from `Debug` output and exported only by named methods.
//! - **Session Store Boundary:** Hosts inject secure persistence; the optional keyring adapter is
//!   not required for portable builds.
//! - **Background Keeper:** Watches token expiration and publishes refreshed cookies when renewal succeeds.
//! - **Client Foundations:** `SteamUser` currently models state; CM transport is not implemented yet.
//!
//! ## Quick Start
//!
//! ```no_run
//! use steam_core::{AuthEvent, SteamAuth};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Start a login that uses mobile approval rather than a Steam Guard code.
//!     let session = SteamAuth::load_or_login("username", "password", |event| {
//!         if event == AuthEvent::NeedMobileConfirmation {
//!             println!("Approve the notification on your phone!");
//!         }
//!     }).await?;
//!
//!     // Start background renewal when the target platform supports it.
//!     let _keeper = session.spawn_keeper(None);
//!     println!("Successfully logged on as: {}", session.account_name());
//!     Ok(())
//! }
//! ```

pub mod approver;
pub mod auth;
pub mod client;
pub mod crypto;
pub mod enums;
pub mod error;
pub mod keeper;
pub mod runtime;
pub mod session;
pub mod tokens;
pub mod transport;
pub mod user;
pub mod vault;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

// Re-export primary types for ergonomics
pub use approver::{AuthSessionInfo, LoginApprover};
pub use auth::{
    AuthEvent, AuthenticatedSession, CredentialsChallenge, LoginOptions, QrChallenge, SteamAuth,
};
pub use client::{SteamApiClient, SteamApiClientBuilder, SteamRsaKey, SteamWebCookies};
pub use crypto::{encrypt_password, EncryptedPassword};
pub use enums::{EAuthSessionGuardType, EAuthTokenPlatformType, EResult, ESessionPersistence};
pub use error::{Result, SteamError};
pub use keeper::{AutoKeeper, AutoKeeperHandle};
pub use runtime::{
    Clock, CmConnection, CmTransport, CoreFuture, OsRandom, RandomSource, Runtime, SystemClock,
    TokioRuntime,
};
pub use session::{AuthTokens, CredentialsAuthSession, LoginSession, PollStatus, QrAuthSession};
pub use tokens::{decode_jwt, is_token_expired, SteamJwtClaims};
pub use transport::{HttpMethod, HttpRequest, HttpResponse, HttpTransport, ReqwestTransport};
pub use user::{ECmProtocol, EPersonaState, SteamUser, SteamUserEvent, SteamUserOptions};
pub use vault::{MemorySessionStore, SavedSession, SessionStore, SessionVault};
