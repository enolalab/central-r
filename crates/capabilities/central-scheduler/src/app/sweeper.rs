//! The Central-internal lease monitor — port of
//! `central/internal/scheduler/app/sweeper.go` (spec-2 decisions 5 and
//! 6 — the missed-beat ladder is its job, never the worker's). Every
//! `tick_interval` the supervisor calls [`Sweeper::sweep_once`], which
//! runs one sequential pass: `expire_leases(now)` closes every lease
//! whose TTL lapsed, then `sweep_suspects(now)` walks the worker
//! ladder — suspect at `MISSED_BEATS_SUSPECT` missed beats (observable
//! only), lost at `MISSED_BEATS_LOST` (all of the worker's leases
//! expire in one transaction). The default cadence is the heartbeat
//! interval itself: beats are evaluated at the same rate they are
//! expected.

use std::sync::Arc;

use time::Duration;

use crate::domain;
use crate::port::{Clock, Store, SystemClock};

/// The Central-internal lease monitor (upstream `app.Sweeper`).
/// Passes are sequential and never overlap by construction (one
/// `&self` call); a failed pass retries on the next tick because an
/// unexpired lease or an unmarked lost worker must not kill the serve
/// process.
pub struct Sweeper<S: Store> {
    /// The durable scheduler substrate.
    pub store: S,
    /// Supplies the evaluation timestamp; `None` uses UTC wall time.
    /// PostgreSQL remains authoritative inside the store's own
    /// commits.
    pub clock: Option<Arc<dyn Clock>>,
    /// The pass cadence the supervisor ticks on; `<= ZERO` uses
    /// [`domain::heartbeat_interval`].
    pub interval: Duration,
}

impl<S: Store> Sweeper<S> {
    /// Builds a sweeper over `store` with the wall clock and the
    /// default cadence.
    pub fn new(store: S) -> Self {
        Self {
            store,
            clock: None,
            interval: Duration::ZERO,
        }
    }

    /// The pass cadence the supervisor ticks [`sweep_once`] on;
    /// resolves `interval <= ZERO` to the locked
    /// [`domain::heartbeat_interval`].
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        if self.interval <= Duration::ZERO {
            domain::heartbeat_interval()
        } else {
            self.interval
        }
    }

    /// Runs one expiry pass then one ladder pass at a single timestamp
    /// (upstream `sweepOnce`). The two are independent: a sweep still
    /// runs when the expiry pass failed part-way, and both retry on
    /// the next tick. Pass errors are deliberately dropped — a failed
    /// pass must not kill the serve process.
    pub async fn sweep_once(&self) {
        let now = self
            .clock
            .as_deref()
            .map_or_else(|| SystemClock.now(), Clock::now);
        let _ = self.store.expire_leases(now).await;
        let _ = self.store.sweep_suspects(now).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::fakes::RecordingStore;
    use crate::testkit::block_on;

    // -- upstream components_test.go: TestSweeperExpiresThenSweepsEachTick

    /// Each tick runs `expire` then `sweep` at the injected clock —
    /// the order is the contract (expiry precedes the ladder so a lost
    /// worker's leases close inside the same sweep the ladder marks).
    #[test]
    fn sweeper_expires_then_sweeps_each_tick() {
        let store = RecordingStore::default();
        let fixed = time::macros::datetime!(2026-10-07 12:00:00 UTC);
        let mut sweeper = Sweeper::new(store);
        sweeper.clock = Some(Arc::new(move || fixed));
        sweeper.interval = Duration::milliseconds(5);

        for _ in 0..3 {
            block_on(sweeper.sweep_once());
        }

        let (expire, sweep) = sweeper.store.sweep_stats();
        assert_eq!(expire, 3);
        assert_eq!(sweep, 3, "every tick must run both passes");
        let seq = sweeper.store.sequence();
        let (pairs, rest) = seq.as_chunks::<2>();
        assert!(rest.is_empty(), "each tick records an expire+sweep pair");
        for [expire, sweep] in pairs {
            assert_eq!(expire, "expire");
            assert_eq!(sweep, "sweep", "ExpireLeases must precede SweepSuspects");
        }
        assert_eq!(sweeper.store.expire_now(), Some(fixed));
        assert_eq!(sweeper.tick_interval(), Duration::milliseconds(5));
    }

    /// The default cadence resolves to the locked heartbeat interval.
    #[test]
    fn sweeper_default_interval_is_heartbeat() {
        let sweeper = Sweeper::new(RecordingStore::default());
        assert_eq!(sweeper.tick_interval(), domain::heartbeat_interval());
    }

    // -- upstream components_test.go: TestSweeperUnconfiguredFails ---
    // Unconfigured is unrepresentable: `Sweeper::new` requires the
    // store (the eventjournal `Publisher::new` precedent).
}
