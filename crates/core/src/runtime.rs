//! Portable host boundaries for time, randomness, task scheduling, and future CM transports.
//!
//! These traits deliberately do not implement CM. They let integrations provide Android, desktop,
//! browser, or test-specific facilities without making this crate depend on a desktop keyring or
//! a particular WebSocket implementation.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::error::Result;

/// Boxed future used by host boundaries without an async-trait dependency.
pub type CoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Monotonic and wall-clock source supplied by an embedding host when deterministic time matters.
pub trait Clock: Send + Sync {
    /// Returns Unix seconds for expiry and persistence metadata.
    fn unix_seconds(&self) -> u64;
}

/// Secure random-byte source supplied by an embedding host when deterministic testing matters.
pub trait RandomSource: Send + Sync {
    /// Fills the supplied buffer with random bytes.
    fn fill(&self, output: &mut [u8]);
}

/// Async timing boundary for host runtimes.
pub trait Runtime: Send + Sync {
    /// Completes after the requested duration.
    fn sleep(&self, duration: Duration) -> CoreFuture<'_, ()>;
}

/// Future CM connection boundary. No CM protocol messages are sent by this crate yet.
pub trait CmTransport: Send + Sync {
    /// Opens a validated CM endpoint chosen by future CM directory support.
    fn connect(&self, endpoint: &str) -> CoreFuture<'_, Box<dyn CmConnection>>;
}

/// Byte-oriented CM connection boundary for future framing and protobuf headers.
pub trait CmConnection: Send + Sync {
    /// Sends one already-framed CM payload.
    fn send(&self, frame: Vec<u8>) -> CoreFuture<'_, ()>;
    /// Receives one already-framed CM payload.
    fn receive(&self) -> CoreFuture<'_, Vec<u8>>;
    /// Closes the connection without implying a CM logoff was sent.
    fn close(&self) -> CoreFuture<'_, ()>;
}

/// Default wall clock for native Rust targets.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Default operating-system random source for native Rust targets.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, output: &mut [u8]) {
        use rand::RngCore;

        rand::thread_rng().fill_bytes(output);
    }
}

/// Tokio-backed runtime adapter used by the bundled native implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn sleep(&self, duration: Duration) -> CoreFuture<'_, ()> {
        Box::pin(async move {
            tokio::time::sleep(duration).await;
            Ok(())
        })
    }
}
