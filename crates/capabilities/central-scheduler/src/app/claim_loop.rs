//! The worker's ready-queue poller — port of
//! `central/internal/scheduler/app/claim_loop.go` (spec-2). Every tick
//! the supervisor calls [`ClaimLoop::claim_once`]: it asks the store to
//! atomically claim up to `limit` ready nodes for its worker id, then
//! hands each claimed attempt to the [`Dispatcher`].
//!
//! In-flight dispatches stay bounded without a local cap:
//! `claim_ready` never returns more attempts than the worker's
//! live-lease headroom under `max_concurrent_attempts`, and every
//! claimed attempt holds a live lease — so `dispatch` calls cannot
//! exceed the registered ceiling.
//!
//! Upstream hands each claim to `Dispatcher.Dispatch` on its own
//! goroutine; this port awaits them SEQUENTIALLY inside
//! `claim_once`. The observable contract is unchanged — every
//! `Dispatch` error is dropped (the dispatcher's fenced writes already
//! committed the outcome, a fence rejection means the sweeper owns the
//! attempt, and an abandoned dispatch leaves the lease to the expiry
//! ladder) — and the claim-side concurrency ceiling lives in the
//! store's lease headroom, not in the spawn shape. The sequential form
//! is what makes the upstream `Shutdown`-waits-for-in-flight invariant
//! structural: a supervisor awaiting `claim_once` to completion is
//! drained by construction, and dropping the future mid-dispatch is
//! upstream's `dispatchCtx` cancel — the attempt stays `claimed` until
//! the lease ladder closes it (`LEASE_EXPIRED_NOT_STARTED` requeues the
//! node).

use std::sync::Arc;

use central_foundation::identity::WorkerId;
use time::Duration;

use crate::app::dispatch::Dispatcher;
use crate::port::{NodeLauncher, Provisioner, Store};

/// The ready-queue poll cadence when the loop carries no explicit
/// interval (upstream `DefaultClaimLoopInterval`). It is the CLAIM
/// poll, not the heartbeat: lease renewal runs on the [`super::worker`]
/// component at [`crate::domain::heartbeat_interval`].
pub const DEFAULT_CLAIM_LOOP_INTERVAL: Duration = Duration::seconds(2);
/// Bounds one poll's take when the loop carries no explicit limit
/// (upstream `DefaultClaimLimit`). The store additionally caps every
/// claim at the worker's `max_concurrent_attempts` minus its live
/// leases, so this is a per-tick bound, not the concurrency ceiling.
pub const DEFAULT_CLAIM_LIMIT: u32 = 4;

/// The ready-queue poller component (upstream `app.ClaimLoop`). It
/// shares its `Arc` store handle with the dispatcher — upstream wires
/// the same `*Store` into both.
pub struct ClaimLoop<S: Store + ?Sized, P: Provisioner, L: NodeLauncher> {
    /// The durable scheduler substrate — the `Arc` clone the
    /// dispatcher also holds.
    pub store: Arc<S>,
    /// The dispatcher each claimed attempt hands to.
    pub dispatcher: Dispatcher<Arc<S>, P, L>,
    /// The registration this loop claims for — the same id the
    /// sibling [`super::worker::Worker`] registered under.
    pub worker_id: WorkerId,
    /// Bounds claims per poll; `0` uses [`DEFAULT_CLAIM_LIMIT`].
    pub limit: u32,
    /// The poll cadence the supervisor ticks on; `<= ZERO` uses
    /// [`DEFAULT_CLAIM_LOOP_INTERVAL`].
    pub interval: Duration,
}

impl<S: Store + ?Sized, P: Provisioner, L: NodeLauncher> ClaimLoop<S, P, L> {
    /// Builds a claim loop over `store` + `dispatcher` claiming for
    /// `worker_id`.
    pub fn new(store: Arc<S>, dispatcher: Dispatcher<Arc<S>, P, L>, worker_id: WorkerId) -> Self {
        Self {
            store,
            dispatcher,
            worker_id,
            limit: 0,
            interval: Duration::ZERO,
        }
    }

    /// The resolved per-poll claim bound.
    #[must_use]
    pub fn claim_limit(&self) -> u32 {
        if self.limit == 0 {
            DEFAULT_CLAIM_LIMIT
        } else {
            self.limit
        }
    }

    /// The poll cadence the supervisor ticks [`claim_once`] on.
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        if self.interval <= Duration::ZERO {
            DEFAULT_CLAIM_LOOP_INTERVAL
        } else {
            self.interval
        }
    }

    /// Runs one poll (upstream `claimOnce`): claim up to the limit,
    /// then dispatch each claimed attempt in claim order. A failed
    /// poll is retried on the next tick: a transient store error must
    /// not kill the component, and a permanently refused worker is
    /// fenced out of every durable write by the store regardless.
    /// Each dispatch error is dropped deliberately — see the module
    /// docs for the sequential-dispatch rationale.
    pub async fn claim_once(&self) {
        let Ok(claimed) = self
            .store
            .claim_ready(self.worker_id, self.claim_limit())
            .await
        else {
            return;
        };
        for claim in claimed {
            let _ = self.dispatcher.dispatch(claim).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use central_foundation::failure::Failure;

    use super::*;
    use crate::app::dispatch::Dispatcher;
    use crate::app::fakes::{FakeLauncher, FakeProvisioner, RecordingStore, test_claim};
    use crate::port::LaunchVerdict;
    use crate::testkit::block_on;

    fn dispatcher(
        store: Arc<RecordingStore>,
        verdict: LaunchVerdict,
    ) -> Dispatcher<Arc<RecordingStore>, FakeProvisioner, FakeLauncher> {
        Dispatcher::new(
            store,
            FakeProvisioner::new("/w"),
            FakeLauncher::new(verdict),
        )
    }

    // -- upstream components_test.go: TestClaimLoopClaimsAndDispatches

    /// One poll claims the scripted batch and dispatches each attempt
    /// through the launcher to `mark_started`; the worker id and the
    /// configured limit reach the store verbatim.
    #[test]
    fn claim_loop_claims_and_dispatches() {
        let store = Arc::new(RecordingStore::default());
        let claim_a = test_claim();
        let claim_b = test_claim();
        store.set_claim_results(vec![vec![claim_a, claim_b]]);
        let launcher = FakeLauncher::new(LaunchVerdict::Started("sess".to_string()));
        let launched = launcher.calls_handle();
        let worker_id = WorkerId::new();
        let d = Dispatcher::new(store.clone(), FakeProvisioner::new("/w"), launcher);
        let mut l = ClaimLoop::new(store.clone(), d, worker_id);
        l.limit = 3;

        block_on(l.claim_once());

        assert_eq!(launched.lock().unwrap().len(), 2, "2 dispatched attempts");
        assert_eq!(store.claim_worker(), Some(worker_id));
        assert_eq!(store.claim_limit(), 3);
        assert_eq!(store.count("mark_started"), 2, "seq={:?}", store.sequence());
        // A second poll returns the empty rest page — claims are
        // consumed per call.
        block_on(l.claim_once());
        assert_eq!(store.count("mark_started"), 2);
    }

    // -- upstream components_test.go: TestClaimLoopClaimErrorKeepsTicking

    /// A claim-store failure is a silent pass: the loop stays alive
    /// and retries on the next tick.
    #[test]
    fn claim_loop_claim_error_keeps_ticking() {
        let store = Arc::new(RecordingStore::default());
        store.set_claim_err(Failure::unavailable("STORE_UNAVAILABLE", "pg down"));
        let d = dispatcher(store.clone(), LaunchVerdict::Started("sess".to_string()));
        let l = ClaimLoop::new(store.clone(), d, WorkerId::new());

        for _ in 0..3 {
            block_on(l.claim_once());
        }
        assert!(store.claims() >= 3, "claim polls retried after errors");
        assert_eq!(store.count("mark_started"), 0);
    }

    // -- upstream components_test.go:
    // TestClaimLoopShutdownWaitsInflightDispatch — the sequential
    // dispatch makes "shutdown waits for in-flight" structural:
    // claim_once returns only after the last dispatch's store writes
    // commit. The blocking-provisioner shape has no analogue in a
    // block_on world (a pending future would spin forever), so this
    // pins the equivalent: a claim_once that returned observed all its
    // dispatches' outcome writes.
    #[test]
    fn claim_loop_pass_drains_dispatches_before_returning() {
        let store = Arc::new(RecordingStore::default());
        store.set_claim_results(vec![vec![test_claim(), test_claim()]]);
        let d = dispatcher(store.clone(), LaunchVerdict::Started("s".to_string()));
        let l = ClaimLoop::new(store.clone(), d, WorkerId::new());

        block_on(l.claim_once());
        // When claim_once returned, every dispatch's persist already
        // committed — that IS the drain the supervisor's shutdown
        // relies on.
        assert_eq!(store.count("mark_started"), 2);
        assert_eq!(store.sequence().iter().filter(|s| *s == "claim").count(), 1);
    }

    // -- upstream components_test.go: TestClaimLoopUnconfiguredFails --
    // Unconfigured is unrepresentable: `ClaimLoop::new` requires the
    // store, dispatcher, and worker id.

    /// The zero-value `limit`/`interval` resolve to the locked
    /// defaults — upstream's `<= 0` fallback.
    #[test]
    fn claim_loop_defaults_resolve() {
        let store = Arc::new(RecordingStore::default());
        let d = dispatcher(store.clone(), LaunchVerdict::Started("s".to_string()));
        let l = ClaimLoop::new(store, d, WorkerId::new());
        assert_eq!(l.claim_limit(), DEFAULT_CLAIM_LIMIT);
        assert_eq!(l.tick_interval(), DEFAULT_CLAIM_LOOP_INTERVAL);
    }
}
