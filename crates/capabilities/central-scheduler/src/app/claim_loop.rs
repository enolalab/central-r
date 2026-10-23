//! The worker's ready-queue poller — port of
//! `central/internal/scheduler/app/claim_loop.go` (spec-2). One poll
//! splits into two halves: [`ClaimLoop::claims`] runs upstream
//! `claimOnce`'s store call — atomically claiming up to `limit` ready
//! nodes for the worker id — and returns the batch, and
//! [`ClaimLoop::dispatch`] runs one claimed attempt through the
//! [`Dispatcher`]. [`ClaimLoop::claim_once`] composes the pair into
//! the pass-shaped sequential driver.
//!
//! TICK CONTRACT (upstream `Run`, claim_loop.go:79): the supervisor
//! runs one poll at component start BEFORE the ticker begins, then
//! ticks every [`ClaimLoop::tick_interval`] — a naive interval-only
//! loop delays the first claim by a full 2 s cadence.
//!
//! In-flight dispatches stay bounded without a local cap:
//! `claim_ready` never returns more attempts than the worker's
//! live-lease headroom under `max_concurrent_attempts`, and every
//! claimed attempt holds a live lease — so `dispatch` calls cannot
//! exceed the registered ceiling.
//!
//! Upstream hands each claim to `Dispatcher.Dispatch` on its own
//! goroutine (claim_loop.go:110-117). The capability crate owns no
//! executor, so the fan-out is the KERNEL's: poll
//! [`ClaimLoop::claims`], then spawn one task per claim running
//! [`ClaimLoop::dispatch`]. That seam — not
//! [`ClaimLoop::claim_once`] — is the recommended driver under tokio:
//! sequential dispatch delays the next poll by the summed dispatch
//! latency, and one permanently stuck invoke would wedge the whole
//! claim path, where upstream degrades to headroom−1 (a stuck
//! invoke's claim is a durable lease, not a borrow — while the worker
//! heartbeats, the lease stays live and occupies its slot; the
//! sweeper's lease TTL is the bound once the worker dies, and
//! `LEASE_EXPIRED_NOT_STARTED` requeues the node). To reproduce
//! upstream's `wg`-backed `Shutdown` drain, the spawned dispatches
//! must be tracked (e.g. a `JoinSet`); cancellation is still
//! future-drop, upstream's `dispatchCtx` cancel.
//!
//! Every `dispatch` error may be dropped — the dispatcher's fenced
//! writes already committed the outcome, a fence rejection means the
//! sweeper owns the attempt, and an abandoned dispatch leaves the
//! lease to the expiry ladder. [`ClaimLoop::dispatch`] returns the
//! `Result` only so a fan-out driver may log it.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_foundation::identity::WorkerId;
use time::Duration;

use crate::app::dispatch::Dispatcher;
use crate::domain::ClaimedAttempt;
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

    /// The poll cadence the supervisor ticks on; resolves `interval
    /// <= ZERO` to [`DEFAULT_CLAIM_LOOP_INTERVAL`]. Per the module's
    /// TICK CONTRACT the supervisor runs one poll at component start
    /// before the first tick, then every `tick_interval`.
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        if self.interval <= Duration::ZERO {
            DEFAULT_CLAIM_LOOP_INTERVAL
        } else {
            self.interval
        }
    }

    /// The claim half of one poll (upstream `claimOnce`'s store call)
    /// — the FAN-OUT SEAM and the recommended driver. Claims up to
    /// [`claim_limit`](Self::claim_limit) ready attempts for
    /// `worker_id` and returns the batch for the caller to dispatch.
    /// A failed poll returns an empty batch and is retried on the
    /// next tick: a transient store error must not kill the
    /// component, and a permanently refused worker is fenced out of
    /// every durable write by the store regardless.
    ///
    /// Under tokio the kernel calls `claims()` per tick — plus once
    /// at component start, per the module's TICK CONTRACT — and
    /// spawns one task per returned claim running
    /// [`dispatch`](Self::dispatch) (upstream's goroutine-per-claim,
    /// claim_loop.go:110-117), keeping the poll on cadence and a
    /// stuck invoke's blast radius at one headroom slot.
    pub async fn claims(&self) -> Vec<ClaimedAttempt> {
        self.store
            .claim_ready(self.worker_id, self.claim_limit())
            .await
            .unwrap_or_default()
    }

    /// Dispatches one claimed attempt — the body of upstream's
    /// per-claim goroutine (claim_loop.go:113-116). The `Result` is
    /// returned only so a fan-out driver may log it; dropping it is
    /// the correct default — the dispatcher's fenced writes already
    /// committed the outcome, a fence rejection means the sweeper
    /// owns the attempt, and an abandoned dispatch leaves the lease
    /// to the expiry ladder.
    ///
    /// Stuck-invoke bound: the claim is a durable lease, not a
    /// borrow. An invoke that never returns leaves the attempt
    /// `claimed` under a live lease — the sibling worker's heartbeat
    /// keeps renewing it, so while the worker lives the bound is one
    /// headroom slot under `max_concurrent_attempts` (upstream's
    /// degrade-to-headroom−1); once the worker dies the sweeper's
    /// lease TTL closes it (`LEASE_EXPIRED_NOT_STARTED` requeues the
    /// node). Nothing else bounds a permanently stuck invoke — that
    /// is upstream's contract.
    pub async fn dispatch(&self, claim: ClaimedAttempt) -> Result<(), Failure> {
        self.dispatcher.dispatch(claim).await
    }

    /// Runs one poll end to end, dispatching each claim SEQUENTIALLY
    /// in claim order — the pass-shaped simple driver for supervisors
    /// without spawn (upstream `claimOnce` minus the fan-out). Prefer
    /// the [`claims`](Self::claims) + spawned-[`dispatch`](Self::dispatch)
    /// seam under tokio: sequential dispatch delays the next poll by
    /// the summed dispatch latency, and one permanently stuck invoke
    /// wedges the claim path entirely where upstream degrades to
    /// headroom−1. This driver remains the drain-by-construction
    /// shape: a returned `claim_once` has observed all its
    /// dispatches' outcome writes, which is what a blocking
    /// supervisor's shutdown relies on.
    pub async fn claim_once(&self) {
        for claim in self.claims().await {
            let _ = self.dispatch(claim).await;
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

    // -- fix-round-1 seam pin: `claims` + `dispatch` split the poll so
    // the kernel can fan dispatch out onto spawned tasks (upstream's
    // goroutine-per-claim, claim_loop.go:110-117).

    /// `claims` polls the store but never dispatches; `dispatch`
    /// drives one claim through the launcher to `mark_started`. A
    /// claim-store failure yields an empty batch, not a poisoned
    /// component.
    #[test]
    fn claims_and_dispatch_split_the_poll() {
        let store = Arc::new(RecordingStore::default());
        store.set_claim_results(vec![vec![test_claim(), test_claim()]]);
        let launcher = FakeLauncher::new(LaunchVerdict::Started("sess".to_string()));
        let launched = launcher.calls_handle();
        let d = Dispatcher::new(store.clone(), FakeProvisioner::new("/w"), launcher);
        let l = ClaimLoop::new(store.clone(), d, WorkerId::new());

        let claimed = block_on(l.claims());
        assert_eq!(claimed.len(), 2, "claims returns the claimed batch");
        assert!(
            launched.lock().unwrap().is_empty(),
            "claims must not dispatch — fan-out is the caller's"
        );
        for claim in claimed {
            block_on(l.dispatch(claim)).unwrap();
        }
        assert_eq!(launched.lock().unwrap().len(), 2);
        assert_eq!(store.count("mark_started"), 2);

        store.set_claim_err(Failure::unavailable("STORE_UNAVAILABLE", "pg down"));
        assert!(block_on(l.claims()).is_empty(), "claim error = empty batch");
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
