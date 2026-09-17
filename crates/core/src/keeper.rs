//! Background session watcher and automatic token renewal daemon ("Auto-Keeper").
//!
//! Automatically monitors Steam JWT expiration and silently refreshes tokens and web cookies
//! before they expire, keeping sessions permanently alive and saving updates to the OS vault.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::client::SteamWebCookies;
use crate::session::LoginSession;
use crate::tokens::is_token_expired;
use crate::vault::{SavedSession, SessionVault};

const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const EXPIRY_SAFETY_MARGIN_SECS: u64 = 900; // 15 minutes before expiration

/// Handle to an active background session renewal task.
pub struct AutoKeeperHandle {
    handle: JoinHandle<()>,
    cookie_rx: watch::Receiver<SteamWebCookies>,
}

impl AutoKeeperHandle {
    /// Returns a reference to the latest valid web cookies.
    pub fn latest_cookies(&self) -> SteamWebCookies {
        self.cookie_rx.borrow().clone()
    }

    /// Obtains a reactive watch receiver that notifies whenever cookies are refreshed.
    pub fn watch_cookies(&self) -> watch::Receiver<SteamWebCookies> {
        self.cookie_rx.clone()
    }

    /// Stops the background renewal task.
    pub fn stop(self) {
        self.handle.abort();
    }
}

/// Daemon responsible for automatic token maintenance.
pub struct AutoKeeper;

impl AutoKeeper {
    /// Spawns a background task that keeps the session alive permanently.
    pub fn spawn(
        session: Arc<Mutex<LoginSession>>,
        initial_cookies: SteamWebCookies,
        check_interval: Option<Duration>,
    ) -> AutoKeeperHandle {
        let (cookie_tx, cookie_rx) = watch::channel(initial_cookies);
        let interval = check_interval.unwrap_or(DEFAULT_CHECK_INTERVAL);

        let session_clone = Arc::clone(&session);

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                let (needs_renewal, steam_id, account) = {
                    let s = session_clone.lock().await;
                    let expired = s
                        .access_token
                        .as_deref()
                        .map(|tok| is_token_expired(tok, EXPIRY_SAFETY_MARGIN_SECS))
                        .unwrap_or(true);
                    (expired, s.steam_id.unwrap_or_default(), s.account_name.clone().unwrap_or_default())
                };

                if needs_renewal {
                    tracing::info!("AutoKeeper: Renewing session for account '{}'...", account);
                    let mut s = session_clone.lock().await;

                    match s.renew().await {
                        Ok((tokens, new_cookies)) => {
                            tracing::info!("AutoKeeper: Successfully renewed session for '{}'!", account);

                            // Update OS Credential Manager
                            let saved = SavedSession {
                                account_name: account.clone(),
                                steam_id,
                                refresh_token: tokens.refresh_token,
                                access_token: tokens.access_token,
                                cookies: new_cookies.clone(),
                                saved_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            };

                            let _ = SessionVault::save(&saved);
                            let _ = cookie_tx.send(new_cookies);
                        }
                        Err(e) => {
                            tracing::warn!("AutoKeeper: Failed to renew session for '{}': {}", account, e);
                        }
                    }
                }
            }
        });

        AutoKeeperHandle { handle, cookie_rx }
    }
}
