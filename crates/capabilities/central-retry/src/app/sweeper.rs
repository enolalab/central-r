//! The Central-internal deadline monitor — port of
//! `central/internal/retry/app/sweeper.go` (spec-4 decision 5 — the
//! three-level timeout hierarchy is the store's job; this component
//! only supplies cadence). The supervisor calls
//! [`RetrySweeper::sweep_once`] once at component start and again
//! every `tick_interval` (upstream `Run`'s `sweepOnce` before the
//! ticker, sweeper.go:58). Each call runs one sequential pass:
//! `sweep_timeouts(now)` commits the session-ceiling kills, the
//! node-timeout landings, and the workflow-timeout cascade inside the
//! store's own transactions — a node or run carrying an unresolved
//! ambiguous descendant is skipped because timers never fire across
//! it (locked input 3).
//!
//! The default cadence is [`DEFAULT_INTERVAL`] (upstream
//! `DefaultInterval` = 1 s): short enough that a node or workflow
//! bound reads as prompt, long enough that an idle pass is a handful
//! of indexed reads. Callers may tighten it under test via
//! `interval`.

use std::sync::Arc;

use time::Duration;

use crate::port::{Clock, Store, SystemClock};

/// The timeout-sweep cadence when the component's `interval` is unset
/// (upstream `app.DefaultInterval` = `time.Second`).
pub const DEFAULT_INTERVAL: Duration = Duration::seconds(1);

/// The Central-internal deadline monitor (upstream
/// `app.TimeoutSweeper`). Passes are sequential and never overlap by
/// construction (one `&self` call); a failed pass retries on the next
/// tick because an unfired bound must not kill the serve process, and
/// every candidate re-verifies under the run-row lock so a repeat
/// pass is safe.
pub struct RetrySweeper<S: Store> {
    /// The durable retry substrate.
    pub store: S,
    /// Supplies the evaluation timestamp; `None` uses UTC wall time.
    /// PostgreSQL remains authoritative inside the store's own
    /// commits.
    pub clock: Option<Arc<dyn Clock>>,
    /// The pass cadence the supervisor ticks on; `<= ZERO` uses
    /// [`DEFAULT_INTERVAL`].
    pub interval: Duration,
}

impl<S: Store> RetrySweeper<S> {
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
    /// resolves `interval <= ZERO` to [`DEFAULT_INTERVAL`].
    ///
    /// TICK CONTRACT (upstream `Run`, sweeper.go:58): the supervisor
    /// runs one [`sweep_once`] pass at component start BEFORE the
    /// ticker begins, then ticks every `tick_interval`. A naive
    /// interval-only loop delays the first deadline pass by a full
    /// interval.
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        if self.interval <= Duration::ZERO {
            DEFAULT_INTERVAL
        } else {
            self.interval
        }
    }

    /// Runs one timeout pass at a single timestamp (upstream
    /// `sweepOnce`). This is the run-once pass: the supervisor calls
    /// it once at component start, then again on every
    /// [`tick_interval`](Self::tick_interval) tick. The committed
    /// summary is advisory — a partial pass still committed its own
    /// landings, and the next tick re-evaluates whatever was skipped —
    /// so the result is deliberately dropped: a failed pass must not
    /// kill the serve process.
    pub async fn sweep_once(&self) {
        let now = self
            .clock
            .as_deref()
            .map_or_else(|| SystemClock.now(), Clock::now);
        let _ = self.store.sweep_timeouts(now).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use central_foundation::failure::Failure;
    use central_foundation::identity::{RunId, WorkflowNodeId};
    use time::OffsetDateTime;

    use crate::domain::AttemptCounts;
    use crate::port::{Outcome, OutcomeResult, SkippedScope, SweepSummary};
    use crate::testkit::block_on;

    /// `fakeStore` — the in-memory [`Store`] the sweeper tests drive
    /// (upstream `fakeStore`): passes are counted, the injected
    /// failure proves the loop survives it, and the instants the
    /// store saw pin the injected clock.
    #[derive(Default)]
    struct FakeStore {
        calls: Mutex<u64>,
        last_now: Mutex<Option<OffsetDateTime>>,
        sweep_err: Mutex<Option<Failure>>,
    }

    impl FakeStore {
        fn calls(&self) -> u64 {
            *self.calls.lock().unwrap()
        }

        fn last_now(&self) -> Option<OffsetDateTime> {
            *self.last_now.lock().unwrap()
        }

        fn set_err(&self, err: Failure) {
            *self.sweep_err.lock().unwrap() = Some(err);
        }
    }

    impl Store for FakeStore {
        async fn record_outcome(&self, _outcome: Outcome) -> Result<OutcomeResult, Failure> {
            Ok(OutcomeResult {
                deduped: false,
                class: crate::domain::FailureClass::Transient,
                node_status: "ready".to_string(),
                retry_at: None,
            })
        }

        async fn attempt_counts(&self, _node_id: WorkflowNodeId) -> Result<AttemptCounts, Failure> {
            Ok(AttemptCounts::default())
        }

        async fn first_dispatch_at(
            &self,
            _node_id: WorkflowNodeId,
        ) -> Result<Option<OffsetDateTime>, Failure> {
            Ok(None)
        }

        async fn sweep_timeouts(&self, now: OffsetDateTime) -> Result<SweepSummary, Failure> {
            *self.calls.lock().unwrap() += 1;
            *self.last_now.lock().unwrap() = Some(now);
            match &*self.sweep_err.lock().unwrap() {
                Some(err) => Err(err.clone()),
                None => Ok(SweepSummary {
                    node_timeouts: vec![],
                    workflow_timeouts: vec![],
                    skipped_ambiguous: vec![SkippedScope::Run(RunId::new())],
                }),
            }
        }

        async fn run_compensation(&self, _node_id: WorkflowNodeId) -> Result<(), Failure> {
            Ok(())
        }
    }

    // -- upstream sweeper_test.go: TestTimeoutSweeperRunsPasses ---

    /// Each pass drives `sweep_timeouts` at the injected clock — the
    /// cadence contract is "one pass at start, then one per tick",
    /// which the supervisor reproduces by calling `sweep_once`.
    #[test]
    fn timeout_sweeper_runs_passes() {
        let store = FakeStore::default();
        let instant = time::macros::datetime!(2026-10-07 12:00:00 UTC);
        let mut sweeper = RetrySweeper::new(store);
        sweeper.clock = Some(Arc::new(move || instant));
        sweeper.interval = Duration::milliseconds(5);

        for _ in 0..3 {
            block_on(sweeper.sweep_once());
        }

        assert_eq!(sweeper.store.calls(), 3, "every pass must sweep");
        assert_eq!(
            sweeper.store.last_now(),
            Some(instant),
            "sweep instant must be the injected clock"
        );
        assert_eq!(sweeper.tick_interval(), Duration::milliseconds(5));
    }

    // -- upstream sweeper_test.go: TestTimeoutSweeperSurvivesFailures ---

    /// A store failure does not kill the loop — the pass error is
    /// dropped and the pass retries on the next tick.
    #[test]
    fn timeout_sweeper_survives_failures() {
        let store = FakeStore::default();
        store.set_err(Failure::internal("test_sweep", "boom"));
        let sweeper = RetrySweeper::new(store);

        for _ in 0..2 {
            block_on(sweeper.sweep_once());
        }

        assert_eq!(
            sweeper.store.calls(),
            2,
            "passes must keep arriving despite scripted failures"
        );
    }

    /// The default cadence resolves to the locked one-second
    /// interval (upstream `DefaultInterval`).
    #[test]
    fn timeout_sweeper_default_interval_is_one_second() {
        let sweeper = RetrySweeper::new(FakeStore::default());
        assert_eq!(sweeper.tick_interval(), Duration::seconds(1));
    }

    // -- upstream sweeper_test.go: TestTimeoutSweeperUnconfigured ---
    // Unconfigured is unrepresentable: `RetrySweeper::new` requires
    // the store (the scheduler `Sweeper::new` precedent).
}
