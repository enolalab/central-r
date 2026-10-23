//! The scheduled checkpoint GC component — port of
//! `central/internal/checkpoint/app/janitor.go` (spec D5 + OQ-2). The
//! janitor sweeps `central.resume_checkpoints` on a fixed cadence
//! inside `central serve`, next to the scheduler's
//! [`central-scheduler`](crate) Sweeper.
//!
//! Every [`tick_interval`](Janitor::tick_interval) the supervisor calls
//! [`Janitor::collect_once`], which runs ONE
//! [`CollectStore::collect`] pass at a single evaluation timestamp.
//! Passes are sequential and never overlap by construction (one `&self`
//! call); a failed or partial pass logs and retries on the next tick —
//! spec-3 makes partial GC harmless (deletions are independent per
//! anchor) and a janitor error must never kill the serve process.
//!
//! TICK CONTRACT (upstream `Run`, janitor.go:60): the supervisor runs
//! one [`collect_once`](Janitor::collect_once) pass at component start
//! BEFORE the ticker begins, then ticks every `tick_interval` — a
//! serve boot must not wait a whole interval before expired rows go.
//! Upstream's `Shutdown` done-wait is a kernel settlement concern; a
//! pass abandoned mid-await commits only what the store already
//! committed, and the store's statement timeouts bound the wait.
//!
//! OWNING PACKET: P2C05. SLICE: 2C (issue #94).

use std::sync::Arc;

use time::Duration;

use crate::port::{Clock, CollectStore, SystemClock};

/// The GC pass cadence when the janitor's `interval` is unset — spec
/// OQ-2's scheduled-janitor default (upstream
/// `DefaultJanitorInterval`): frequent enough that a superseded or
/// expired checkpoint does not linger, slow enough that a pass is a
/// handful of small per-anchor transactions.
pub const DEFAULT_JANITOR_INTERVAL: Duration = Duration::minutes(15);

/// The scheduled checkpoint GC component (upstream `app.Janitor`).
/// `Run`'s ticker loop stays a kernel concern; this carries the passes
/// themselves and the cadence contract, the [`crate`]-internal mirror
/// of the scheduler's `Sweeper`.
pub struct Janitor<S: CollectStore> {
    /// The durable GC substrate.
    pub store: S,
    /// Supplies the evaluation timestamp; `None` uses UTC wall time.
    /// PostgreSQL remains authoritative inside the store's own
    /// commits.
    pub clock: Option<Arc<dyn Clock>>,
    /// The pass cadence; `<= ZERO` uses [`DEFAULT_JANITOR_INTERVAL`].
    pub interval: Duration,
}

impl<S: CollectStore> Janitor<S> {
    /// Builds a janitor over `store` with the wall clock and the
    /// default cadence.
    pub fn new(store: S) -> Self {
        Self {
            store,
            clock: None,
            interval: Duration::ZERO,
        }
    }

    /// The pass cadence the supervisor ticks
    /// [`collect_once`](Self::collect_once) on; resolves
    /// `interval <= ZERO` to [`DEFAULT_JANITOR_INTERVAL`] (upstream
    /// `Run`'s `interval <= 0` fallback).
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        if self.interval <= Duration::ZERO {
            DEFAULT_JANITOR_INTERVAL
        } else {
            self.interval
        }
    }

    /// Runs one GC pass at a single timestamp (upstream
    /// `collectOnce`). The store owns per-anchor atomicity; a
    /// per-tick failure — or a partial pass whose `CollectOutcome`
    /// carried per-anchor failures — is logged and left for the next
    /// tick, never propagated.
    pub async fn collect_once(&self) {
        let now = self
            .clock
            .as_deref()
            .map_or_else(|| SystemClock.now(), Clock::now);
        match self.store.collect(now).await {
            Ok(outcome) if outcome.has_failures() => {
                for failure in &outcome.failures {
                    tracing::warn!(
                        code = failure.code(),
                        "checkpoint janitor: anchor collect pass failed"
                    );
                }
            }
            Ok(_) => {}
            Err(failure) => {
                tracing::warn!(
                    code = failure.code(),
                    "checkpoint janitor: collect pass failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use central_foundation::failure::Failure;
    use time::OffsetDateTime;

    use crate::port::CollectOutcome;

    /// The port of upstream `fakeCollectStore`: records each `collect`
    /// call's timestamp and can script per-call failures.
    #[derive(Default)]
    struct FakeCollectStore {
        calls: Mutex<Vec<OffsetDateTime>>,
        failures: Mutex<Vec<Result<CollectOutcome, Failure>>>,
    }

    impl FakeCollectStore {
        fn script(&self, result: Result<CollectOutcome, Failure>) {
            self.failures.lock().unwrap().push(result);
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl CollectStore for FakeCollectStore {
        async fn collect(&self, now: OffsetDateTime) -> Result<CollectOutcome, Failure> {
            self.calls.lock().unwrap().push(now);
            let mut scripted = self.failures.lock().unwrap();
            if scripted.is_empty() {
                Ok(CollectOutcome {
                    collected: self.calls.lock().unwrap().len() - 1,
                    failures: Vec::new(),
                })
            } else {
                scripted.remove(0)
            }
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        // A single-threaded park/unpark executor — the same pattern
        // central-scheduler's testkit uses — so janitor tests stay
        // runtime-free.
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }

        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut f = std::pin::pin!(f);
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    // -- upstream janitor_test.go: TestJanitorTicksCollect -----------------

    /// Each tick runs exactly one `collect` at the injected clock; a
    /// start pass plus two ticks is three sequential, non-overlapping
    /// passes.
    #[test]
    fn janitor_collects_each_tick() {
        let store = FakeCollectStore::default();
        let fixed = time::macros::datetime!(2026-10-07 12:00:00 UTC);
        let mut janitor = Janitor::new(store);
        janitor.clock = Some(Arc::new(move || fixed));
        janitor.interval = Duration::milliseconds(5);

        for _ in 0..3 {
            block_on(janitor.collect_once());
        }

        assert_eq!(janitor.store.call_count(), 3);
        for seen in janitor.store.calls.lock().unwrap().iter() {
            assert_eq!(*seen, fixed);
        }
        assert_eq!(janitor.tick_interval(), Duration::milliseconds(5));
    }

    /// The default cadence resolves to spec OQ-2's 15 minutes
    /// (upstream `DefaultJanitorInterval`).
    #[test]
    fn janitor_default_interval_is_fifteen_minutes() {
        let janitor = Janitor::new(FakeCollectStore::default());
        assert_eq!(janitor.tick_interval(), Duration::minutes(15));
    }

    // -- upstream janitor_test.go: TestJanitorLogsErrorAndKeepsTicking -----

    /// A failed pass is dropped inside `collect_once` — the next tick
    /// still runs. (Upstream asserts the `log.Printf` line too; Rust
    /// logs through `tracing` — best-effort observability the
    /// supervisor's subscriber owns — so the behavioral contract the
    /// test locks is "an error must never kill the component".)
    #[test]
    fn janitor_error_does_not_kill_the_component() {
        let store = FakeCollectStore::default();
        store.script(Err(Failure::unavailable(
            "checkpoint_store_error",
            "collect boom",
        )));
        let mut janitor = Janitor::new(store);
        janitor.interval = Duration::milliseconds(5);

        // Tick 1 fails; tick 2 must still run.
        block_on(janitor.collect_once());
        block_on(janitor.collect_once());
        assert_eq!(janitor.store.call_count(), 2);
    }

    /// A partial pass (per-anchor failures inside the outcome) is
    /// likewise logged-and-continued, never propagated.
    #[test]
    fn janitor_partial_pass_keeps_ticking() {
        let store = FakeCollectStore::default();
        store.script(Ok(CollectOutcome {
            collected: 1,
            failures: vec![Failure::unavailable(
                "checkpoint_store_error",
                "anchor boom",
            )],
        }));
        let janitor = Janitor::new(store);

        block_on(janitor.collect_once());
        block_on(janitor.collect_once());
        assert_eq!(janitor.store.call_count(), 2);
    }

    // -- upstream janitor_test.go: TestJanitorUnconfigured ------------------
    // Unconfigured is unrepresentable: `Janitor::new` requires the
    // store (the `Sweeper::new` precedent). `Shutdown` on a
    // never-started janitor is a kernel settlement concern.
}
