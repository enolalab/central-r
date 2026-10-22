//! The process-wide transfer limiter (upstream `TransferLimiter`).
//!
//! A counting semaphore bounding concurrent object-store byte transfers.
//! `acquire` waits until a permit is free; cancellation is delivered by
//! dropping the returned future. The permit is an RAII guard — dropping it
//! returns the permit exactly once, which is what makes the upstream
//! "release is idempotent" contract structural in Rust.

use std::sync::Arc;

use central_artifact::port::{MAX_CONCURRENT_TRANSFERS, TransferPermit};
use central_foundation::failure::Failure as PortFailure;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{FailureClass, Reason, fail};

/// One held permit (upstream's returned `release func()`, made RAII).
/// Dropping the guard returns the permit to the semaphore; the port's
/// default `TransferPermit::release` is that drop.
#[derive(Debug)]
struct HeldPermit {
    _inner: OwnedSemaphorePermit,
}

impl TransferPermit for HeldPermit {}

/// Bounds the process-wide count of concurrent object-store transfers to
/// `permits` (the store installs [`MAX_CONCURRENT_TRANSFERS`] `= 2`).
pub struct TransferLimiter {
    semaphore: Arc<Semaphore>,
    capacity: usize,
}

impl TransferLimiter {
    /// A limiter admitting at most `permits` concurrent transfers; a bound
    /// below one is treated as one (upstream `NewTransferLimiter`).
    #[must_use]
    pub fn new(permits: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(permits.max(1))),
            capacity: permits.max(1),
        }
    }

    /// The bounded capacity this limiter admits.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Acquires one permit at the raw `OwnedSemaphorePermit` level — the
    /// store's internal hold — without boxing into the port trait object.
    ///
    /// The wait resolves when a permit frees or the caller's future is
    /// dropped (upstream's `ctx.Done()` branch). A closed semaphore cannot
    /// occur in this adapter; it is still classified rather than unwrapped.
    pub(crate) async fn acquire_owned(
        &self,
    ) -> Result<OwnedSemaphorePermit, crate::error::Failure> {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| fail("acquire", FailureClass::Unavailable, Reason::Canceled))
    }
}

impl Default for TransferLimiter {
    fn default() -> Self {
        Self::new(MAX_CONCURRENT_TRANSFERS)
    }
}

impl central_artifact::port::TransferLimiter for TransferLimiter {
    async fn acquire(&self) -> Result<Box<dyn TransferPermit>, PortFailure> {
        self.acquire_owned()
            .await
            .map(|permit| Box::new(HeldPermit { _inner: permit }) as Box<dyn TransferPermit>)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_artifact::port::TransferLimiter as _;
    use std::time::Duration;

    /// Upstream `TestTransferLimiterAllowsAtMostTwoConcurrentTransfers`:
    /// two permits admit, a third blocks until one is freed.
    #[tokio::test]
    async fn allows_at_most_two_concurrent_transfers() {
        let limiter = TransferLimiter::new(MAX_CONCURRENT_TRANSFERS);

        let a = limiter.acquire().await;
        assert!(a.is_ok());
        let b = limiter.acquire().await;
        assert!(b.is_ok());

        // A third concurrent transfer must block.
        let third = tokio::time::timeout(Duration::from_millis(100), limiter.acquire()).await;
        assert!(third.is_err(), "a third concurrent transfer was admitted");

        // Freeing a permit admits it.
        drop(a);
        let third = tokio::time::timeout(Duration::from_secs(3), limiter.acquire()).await;
        assert!(third.is_ok(), "third transfer not admitted after release");
        drop(b);
        drop(third);
    }

    /// Upstream `TestTransferLimiterReleaseIsIdempotent`: a double release
    /// cannot corrupt the semaphore — here by construction, because the
    /// RAII guard returns the permit exactly once.
    #[tokio::test]
    async fn release_is_idempotent() {
        let limiter = TransferLimiter::new(1);
        let permit = limiter.acquire().await;
        assert!(permit.is_ok());
        drop(permit); // the explicit `release()` on the trait is this drop
        let regained = tokio::time::timeout(Duration::from_secs(1), limiter.acquire()).await;
        assert!(regained.is_ok(), "release corrupted the semaphore");
    }

    /// Dropping a pending `acquire` future is the caller-cancellation path
    /// (upstream `ctx.Done()`): it must not consume a permit.
    #[tokio::test]
    async fn dropped_acquire_does_not_hold_a_permit() {
        let limiter = TransferLimiter::new(1);
        let held = limiter.acquire().await;
        assert!(held.is_ok());
        let wait = tokio::time::timeout(Duration::from_secs(3600), limiter.acquire());
        drop(wait);
        drop(held);
        let regained = limiter.acquire().await;
        assert!(regained.is_ok());
    }
}
