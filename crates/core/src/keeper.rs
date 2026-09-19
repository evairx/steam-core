//! Background session watcher and automatic token renewal daemon ("Auto-Keeper").
//!
//! Automatically monitors Steam JWT expiration and silently refreshes tokens and web cookies
//! before they expire and persisting updates through the host session store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::auth::SessionState;
use crate::client::SteamWebCookies;
use crate::session::LoginSession;
use crate::tokens::is_token_expired;
use crate::vault::{SavedSession, SessionStore};

const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const EXPIRY_SAFETY_MARGIN_SECS: u64 = 900; // 15 minutes before expiration

/// Handle to an active background session renewal task.
pub struct AutoKeeperHandle {
    handle: JoinHandle<()>,
    cookie_rx: watch::Receiver<SteamWebCookies>,
    stop_tx: watch::Sender<bool>,
    active: Arc<AtomicBool>,
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
        let _ = self.stop_tx.send(true);
        self.handle.abort();
        self.active.store(false, Ordering::Release);
    }
}

impl Drop for AutoKeeperHandle {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);
        self.handle.abort();
        self.active.store(false, Ordering::Release);
    }
}

/// Daemon responsible for automatic token maintenance.
pub struct AutoKeeper;

impl AutoKeeper {
    /// Spawns a background task that keeps the session alive permanently.
    pub(crate) fn spawn(
        session: Arc<Mutex<LoginSession>>,
        state: Arc<RwLock<SessionState>>,
        store: Arc<dyn SessionStore>,
        active: Arc<AtomicBool>,
        check_interval: Option<Duration>,
    ) -> AutoKeeperHandle {
        match Self::try_spawn(session, state, store, active, check_interval) {
            Ok(handle) => handle,
            Err(_) => Self::inactive_handle(),
        }
    }

    /// Starts one renewal task. Prefer this fallible API when configuration errors must be shown
    /// to the host application.
    pub(crate) fn try_spawn(
        session: Arc<Mutex<LoginSession>>,
        state: Arc<RwLock<SessionState>>,
        store: Arc<dyn SessionStore>,
        active: Arc<AtomicBool>,
        check_interval: Option<Duration>,
    ) -> crate::Result<AutoKeeperHandle> {
        let interval = check_interval.unwrap_or(DEFAULT_CHECK_INTERVAL);
        if interval.is_zero() {
            return Err(crate::SteamError::InvalidResponse(
                "AutoKeeper interval must be non-zero",
            ));
        }
        if active.swap(true, Ordering::AcqRel) {
            return Err(crate::SteamError::InvalidResponse(
                "An AutoKeeper is already active for this session",
            ));
        }
        let initial_state = state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if initial_state.platform_type != crate::EAuthTokenPlatformType::MobileApp {
            active.store(false, Ordering::Release);
            return Err(crate::SteamError::UnsupportedPlatform(
                "AutoKeeper access-token renewal is only supported for MobileApp",
            ));
        }
        let initial_cookies = initial_state.cookies;
        let (cookie_tx, cookie_rx) = watch::channel(initial_cookies);
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let session_clone = Arc::clone(&session);
        let state_clone = Arc::clone(&state);
        let store_clone = Arc::clone(&store);
        let active_clone = Arc::clone(&active);

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut pending_save: Option<SavedSession> = None;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                }

                let snapshot = state_clone
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if snapshot.revoked {
                    break;
                }
                if cookie_tx.borrow().ne(&snapshot.cookies) {
                    let _ = cookie_tx.send(snapshot.cookies.clone());
                }

                if let Some(saved) = pending_save.take() {
                    if store_clone.save(&saved).is_err() {
                        pending_save = Some(saved);
                    }
                }

                let needs_renewal =
                    is_token_expired(&snapshot.access_token, EXPIRY_SAFETY_MARGIN_SECS);

                if needs_renewal {
                    let mut s = session_clone.lock().await;

                    match s.renew().await {
                        Ok((tokens, new_cookies)) => {
                            let steam_id = s.steam_id.unwrap_or_default();
                            let refreshed_account = s.account_name.clone().unwrap_or_default();
                            let guard_data = s.guard_data.clone();
                            drop(s);

                            let saved = {
                                let mut current = state_clone
                                    .write()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                if current.revoked || current.generation != snapshot.generation {
                                    continue;
                                }
                                current.account_name = refreshed_account;
                                current.steam_id = steam_id;
                                current.refresh_token = tokens.export_refresh_token().to_string();
                                current.access_token = tokens.export_access_token().to_string();
                                current.cookies = new_cookies.clone();
                                current.guard_data = guard_data;
                                current.generation = current.generation.wrapping_add(1);

                                SavedSession {
                                    account_name: current.account_name.clone(),
                                    steam_id: current.steam_id,
                                    refresh_token: current.refresh_token.clone(),
                                    access_token: current.access_token.clone(),
                                    cookies: current.cookies.clone(),
                                    guard_data: current.guard_data.clone(),
                                    platform_type: current.platform_type,
                                    saved_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                }
                            };

                            if store_clone.save(&saved).is_err() {
                                pending_save = Some(saved);
                            }

                            let _ = cookie_tx.send(new_cookies);
                        }
                        Err(_) => {
                            // The host chooses retry cadence by configuring the keeper interval.
                        }
                    }
                }
            }
            active_clone.store(false, Ordering::Release);
        });

        Ok(AutoKeeperHandle {
            handle,
            cookie_rx,
            stop_tx,
            active,
        })
    }

    fn inactive_handle() -> AutoKeeperHandle {
        let (cookie_tx, cookie_rx) = watch::channel(SteamWebCookies {
            session_id: String::new(),
            steam_login_secure: None,
            all_cookies: Vec::new(),
        });
        let (stop_tx, _) = watch::channel(true);
        AutoKeeperHandle {
            handle: tokio::spawn(async {}),
            cookie_rx,
            stop_tx: {
                drop(cookie_tx);
                stop_tx
            },
            active: Arc::new(AtomicBool::new(false)),
        }
    }
}
