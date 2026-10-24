//! The supervised periodic Artifact reconciliation pass — the port of
//! upstream `cmd/central/serve_monitors.go`'s
//! `serveArtifactReconcilePass` merged with
//! `serve_artifact_composition.go`'s `serveArtifactPassStarter`.
//!
//! [`ArtifactReconcilerComponent`] drives
//! [`central_artifact::reconciler::Reconciler::reconcile`] on a bounded
//! `tokio::time::Interval` ticker under the B08 `recovery_coordinator`
//! lease's artifact-work fence — the pass introduces no second lease
//! and no second scheduler. Each tick first re-acquires (claim) or
//! renews that fence through [`ArtifactFenceSource`], then runs exactly
//! one pass; sequential `.await` makes overlapping passes impossible by
//! construction, so upstream's `running`/`skipped` defensive pair has
//! no Rust counterpart.
//!
//! The starter half survives as the `epoch_source` consulted once at
//! `run` start: upstream components are registered before the startup
//! gate opens the recovery epoch, so a component constructed without
//! one idles — never returns — until the supervisor drops its future
//! (upstream `idleUntilShutdown`; any return at all is a terminal
//! profile event under [`crate::lifecycle::Profile`]).
//!
//! Cancellation is delivered by future drop, never by a
//! capability-imported kernel type and never by observing the profile
//! token inside the loop: a component future that resolved early on
//! `CancellationToken` could win the supervisor's first-completion
//! race against the profile's own `cancelled()` branch and convert a
//! clean stop into a terminal exit. Dropping this future mid-pass stops
//! the pass at the next port call — the reconciler is
//! cancellation-safe at every `.await`. Settlement is upstream's no-op
//! `Shutdown`: the durable claim is left fenced and resumable, so the
//! same coordinator generation resumes the work.

use std::sync::Arc;
use std::time::{Duration, Instant};

use central_artifact::app::ResumeLifecycle;
use central_artifact::port::{ObjectStore, ReconciliationStore, Store};
use central_artifact::reconciler::{Fence, PassReport, Reconciler};
use central_execution::app::RecoveryCoordinatorService;
use central_execution::port::{ArtifactWorkClaim, Clock, RecoveryStore};
use central_execution::resume::RecoveryEpoch;
use central_foundation::failure::{Failure, FailureKind};
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, interval_at};

use crate::BoxFuture;
use crate::lifecycle::Component;

/// Upstream `serveArtifactReconcileInterval` (60 seconds): one bounded
/// reconciliation pass per tick.
pub const ARTIFACT_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// The narrow reconcile surface the supervised component drives —
/// upstream `artifactReconciler` (`*artifactapp.Reconciler`, narrowed
/// so the component never depends on the interactive entry points).
/// The blanket impl below covers the real
/// [`central_artifact::reconciler::Reconciler`]; tests substitute a
/// counting double.
pub trait ArtifactPass: Send + Sync + 'static {
    /// Runs one bounded fenced pass (upstream `Reconcile`).
    fn reconcile<'a>(&'a self, fence: &'a Fence) -> BoxFuture<'a, Result<PassReport, Failure>>;
}

impl<C, R, O, L> ArtifactPass for Reconciler<C, R, O, L>
where
    C: ReconciliationStore,
    R: Store,
    O: ObjectStore,
    L: ResumeLifecycle,
{
    fn reconcile<'a>(&'a self, fence: &'a Fence) -> BoxFuture<'a, Result<PassReport, Failure>> {
        Box::pin(Reconciler::reconcile(self, fence))
    }
}

/// `Arc<T>` shares one reconciler between the startup gate (which
/// needs the same instance's `reconcile` for the one-shot recovery
/// pass) and the supervised component — upstream passes the same
/// `*Reconciler` to both.
impl<T: ArtifactPass + ?Sized> ArtifactPass for Arc<T> {
    fn reconcile<'a>(&'a self, fence: &'a Fence) -> BoxFuture<'a, Result<PassReport, Failure>> {
        (**self).reconcile(fence)
    }
}

/// The artifact-work fence source — upstream `artifactFenceSource`,
/// normally B08's recovery coordinator. It yields and renews the
/// single artifact-reconciliation claim derived from the coordinator
/// lease this instance already holds; it creates no lease, row, or
/// scheduler of its own.
pub trait ArtifactFenceSource: Send + Sync + 'static {
    /// `ClaimArtifactWork` — re-acquires the coordinator lease under
    /// `epoch` and yields the derived artifact work claim.
    fn claim_artifact_work<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>>;

    /// `RenewArtifactWork` — re-validates the held claim and
    /// re-acquires the same lease. A superseded coordinator fails
    /// closed with `Conflict`: the caller drops the held claim and
    /// re-attempts acquisition next tick.
    fn renew_artifact_work<'a>(
        &'a self,
        held: &'a ArtifactWorkClaim,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>>;
}

/// `Arc<T>` shares one coordinator between the startup gate (the
/// artifact-recovery pass needs the same lease authority) and the
/// component — upstream passes the same `*RecoveryCoordinator` to
/// both.
impl<T: ArtifactFenceSource + ?Sized> ArtifactFenceSource for Arc<T> {
    fn claim_artifact_work<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
        (**self).claim_artifact_work(epoch)
    }

    fn renew_artifact_work<'a>(
        &'a self,
        held: &'a ArtifactWorkClaim,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
        (**self).renew_artifact_work(held)
    }
}

impl<R, C> ArtifactFenceSource for RecoveryCoordinatorService<R, C>
where
    R: RecoveryStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    fn claim_artifact_work<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
        Box::pin(self.claim_artifact_work(epoch))
    }

    fn renew_artifact_work<'a>(
        &'a self,
        held: &'a ArtifactWorkClaim,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
        Box::pin(self.renew_artifact_work(held))
    }
}

/// Kernel-owned supervised component running the periodic B10
/// reconciliation pass (upstream `serveArtifactReconcilePass` +
/// `serveArtifactPassStarter`).
///
/// `T` is the [`ArtifactPass`] surface — the real
/// [`Reconciler`] in production. `F` is the [`ArtifactFenceSource`] —
/// the composed `RecoveryCoordinatorService` in production.
pub struct ArtifactReconcilerComponent<T, F> {
    reconciler: T,
    fences: F,
    /// Deferred epoch lookup — upstream `serveArtifactPassStarter`'s
    /// `epochs` seam. Components register before the startup gate opens
    /// the recovery epoch, so the value is consulted at `run` start,
    /// not at registration.
    epoch_source: Box<dyn Fn() -> Option<RecoveryEpoch> + Send + Sync>,
    interval: Duration,
    /// Passes attempted (upstream `passes`) — counted before each pass
    /// so the number is honest even when the pass fails.
    passes: u64,
    /// Claim/acquire and pass failures contained by the retry ladder
    /// (upstream's `RecordDependencyFailure` counter half).
    dependency_failures: u64,
    /// Seeded at construction and stamped on every successful pass —
    /// the base of [`Self::no_progress_for`] (upstream
    /// `lastProgressUnixNano`).
    last_progress: Instant,
}

impl<T, F> ArtifactReconcilerComponent<T, F> {
    /// Production constructor: the recovery epoch is already known.
    /// Installs [`ARTIFACT_RECONCILE_INTERVAL`].
    pub fn new(reconciler: T, fences: F, epoch: RecoveryEpoch) -> Self {
        Self::with_epoch_source(reconciler, fences, move || Some(epoch.clone()))
    }

    /// Deferred-epoch constructor (upstream `serveArtifactPassStarter`):
    /// `epoch_source` is consulted once when `run` starts — after the
    /// startup gate has opened the epoch — and a `None` answer idles
    /// the component until the supervisor drops its future.
    pub fn with_epoch_source(
        reconciler: T,
        fences: F,
        epoch_source: impl Fn() -> Option<RecoveryEpoch> + Send + Sync + 'static,
    ) -> Self {
        Self {
            reconciler,
            fences,
            epoch_source: Box::new(epoch_source),
            interval: ARTIFACT_RECONCILE_INTERVAL,
            passes: 0,
            dependency_failures: 0,
            last_progress: Instant::now(),
        }
    }

    /// Installs a custom tick interval; a zero value keeps the
    /// installed default (the `Reconciler::with_staging_lifetime`
    /// convention — never a panic path).
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        if !interval.is_zero() {
            self.interval = interval;
        }
        self
    }

    /// Passes attempted since construction (upstream `passes`).
    #[must_use]
    pub const fn passes(&self) -> u64 {
        self.passes
    }

    /// Fence-acquisition and pass failures contained by the retry
    /// ladder (upstream's dependency-failure counter).
    #[must_use]
    pub const fn dependency_failures(&self) -> u64 {
        self.dependency_failures
    }

    /// How long this instance has gone without a successful pass —
    /// the accumulating counter the health monitor's no-progress
    /// thresholds evaluate (upstream `noProgressFor`). Seeded at
    /// construction so consecutive failing ticks grow it rather than
    /// pinning it below the thresholds.
    #[must_use]
    pub fn no_progress_for(&self) -> Duration {
        self.last_progress.elapsed()
    }
}

impl<T, F> ArtifactReconcilerComponent<T, F>
where
    T: ArtifactPass,
    F: ArtifactFenceSource,
{
    /// The supervised loop (upstream `serveArtifactReconcilePass.Run`):
    /// idle when no epoch was opened; otherwise claim/renew the fence
    /// then run one pass per tick.
    async fn drive(&mut self) -> Result<(), Failure> {
        let Some(epoch) = (self.epoch_source)() else {
            // No epoch was opened, so there is no fence to reconcile
            // under: idle — never return — until the supervisor drops
            // this future (upstream `idleUntilShutdown`).
            std::future::pending::<()>().await;
            return Ok(());
        };

        // `interval_at` keeps upstream `time.NewTicker` semantics: the
        // first tick fires after `interval`, not immediately the way
        // `tokio::time::interval`'s first tick does.
        let mut ticker = interval_at(TokioInstant::now() + self.interval, self.interval);
        // A pass that outruns the interval skips missed ticks rather
        // than bursting through them — upstream's unbuffered ticker
        // drops them the same way.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut held: Option<ArtifactWorkClaim> = None;
        loop {
            ticker.tick().await;
            match held.take() {
                // A claim that could not be acquired is retried on the
                // next tick: a single transient failure must never
                // disable reconciliation for the rest of the process's
                // life.
                None => match self.fences.claim_artifact_work(&epoch).await {
                    Ok(claim) => held = Some(claim),
                    Err(cause) => {
                        self.record_dependency_failure(&cause);
                        continue;
                    }
                },
                // A lost fence is not a dependency failure and must not
                // mutate durable state, so this instance stops passing —
                // but re-attempts acquisition on the next tick, because
                // the fence may be this instance's own again by then.
                Some(claim) => match self.fences.renew_artifact_work(&claim).await {
                    Ok(renewed) => held = Some(renewed),
                    Err(cause) => {
                        tracing::warn!(
                            code = cause.code(),
                            "kernel: artifact work fence lost; re-claiming next tick"
                        );
                        continue;
                    }
                },
            }
            if let Some(claim) = held.as_ref() {
                self.once(claim).await;
            }
        }
    }

    /// One non-overlapping pass (upstream `once`). Passes are
    /// sequential `.await`s inside [`Self::drive`], so upstream's
    /// `running` guard can never trip here — the `skipped` counter it
    /// fed is dropped rather than carried dead.
    async fn once(&mut self, claim: &ArtifactWorkClaim) {
        self.passes += 1;
        let fence = Fence {
            generation: claim.fence.generation,
            epoch_generation: claim.epoch_generation,
            claim_token: claim.claim_token.clone(),
        };
        match self.reconciler.reconcile(&fence).await {
            Ok(report) => {
                // The pass's own measured observations, not constants —
                // the backlog/stall signal a later health monitor
                // publishes (upstream `RecordProgress`).
                self.last_progress = Instant::now();
                tracing::debug!(
                    processed = report.processed,
                    deferred = report.deferred,
                    item_failures = report.item_failures,
                    oldest_backlog_age = ?report.oldest_backlog_age,
                    required_output_blocked_for = ?report.required_output_blocked_for,
                    skipped_workspaces = report.skipped_workspaces,
                    resolver_budget_exhausted = report.resolver_budget_exhausted,
                    "kernel: artifact reconciliation pass complete"
                );
            }
            // A cancelled pass is a clean stop, never a dependency
            // failure (upstream's `context.Canceled` arm); the
            // supervisor's future drop ends the loop itself.
            Err(cause) if matches!(cause.kind(), FailureKind::Cancelled) => {}
            Err(cause) => self.record_dependency_failure(&cause),
        }
    }

    /// Contained-failure bookkeeping (upstream
    /// `monitor.RecordDependencyFailure(noProgressFor, interval)`): the
    /// accumulating duration and the tick cadence are the two inputs a
    /// health monitor needs to tell a stalled pass from a quiet one.
    fn record_dependency_failure(&mut self, cause: &Failure) {
        self.dependency_failures += 1;
        tracing::warn!(
            code = cause.code(),
            no_progress_for = ?self.no_progress_for(),
            interval = ?self.interval,
            "kernel: artifact reconciliation dependency failure"
        );
    }
}

impl<T, F> Component for ArtifactReconcilerComponent<T, F>
where
    T: ArtifactPass,
    F: ArtifactFenceSource,
{
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(self.drive())
    }

    /// Upstream `Shutdown` is a no-op: cancellation leaves the artifact
    /// work claim fenced and resumable — nothing is released, so the
    /// same coordinator generation resumes it.
    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use central_execution::domain::ZERO_TIME;
    use central_execution::resume::{RecoveryCoordinatorFence, RecoveryEpochState};
    use central_foundation::identity::WorkspaceId;

    use crate::lifecycle::{Profile, ProfileConfig};
    use crate::readiness::Readiness;

    fn test_epoch() -> RecoveryEpoch {
        RecoveryEpoch {
            generation: 7,
            coordinator_fence: RecoveryCoordinatorFence { generation: 3 },
            state: RecoveryEpochState::default(),
            scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
            workspace_count: 0,
            processed_count: 0,
            claim_cycle: 0,
            retry_attempt: 0,
            snapshot_at: ZERO_TIME,
        }
    }

    fn test_claim() -> ArtifactWorkClaim {
        ArtifactWorkClaim {
            fence: RecoveryCoordinatorFence { generation: 3 },
            epoch_generation: 7,
            claim_token: vec![0xAB; 32],
            expires_at: ZERO_TIME,
            claimed: true,
        }
    }

    /// A pass double that counts `reconcile` invocations and returns a
    /// scriptable result.
    struct CountingPass {
        calls: Arc<AtomicUsize>,
        failures: Arc<StdMutex<Vec<Failure>>>,
    }

    impl ArtifactPass for CountingPass {
        fn reconcile<'a>(
            &'a self,
            _fence: &'a Fence,
        ) -> BoxFuture<'a, Result<PassReport, Failure>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let failure = self.failures.lock().unwrap().pop();
            Box::pin(async move {
                match failure {
                    Some(cause) => Err(cause),
                    None => Ok(PassReport::default()),
                }
            })
        }
    }

    /// A fence-source double: `claim` pops scripted failures then
    /// yields `test_claim`; `renew` echoes the held claim back.
    struct ScriptedFenceSource {
        claims: Arc<AtomicUsize>,
        renews: Arc<AtomicUsize>,
        claim_failures: StdMutex<Vec<Failure>>,
    }

    impl ArtifactFenceSource for ScriptedFenceSource {
        fn claim_artifact_work<'a>(
            &'a self,
            _epoch: &'a RecoveryEpoch,
        ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
            self.claims.fetch_add(1, Ordering::SeqCst);
            let failure = self.claim_failures.lock().unwrap().pop();
            Box::pin(async move {
                match failure {
                    Some(cause) => Err(cause),
                    None => Ok(test_claim()),
                }
            })
        }

        fn renew_artifact_work<'a>(
            &'a self,
            held: &'a ArtifactWorkClaim,
        ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
            self.renews.fetch_add(1, Ordering::SeqCst);
            let claim = held.clone();
            Box::pin(async move { Ok(claim) })
        }
    }

    fn test_config() -> ProfileConfig {
        ProfileConfig {
            startup_limit: Duration::from_secs(5),
            settlement: Duration::from_millis(50),
            shutdown: Duration::from_millis(200),
            proof_ttl: Duration::from_secs(300),
        }
    }

    /// Waits — bounded — until `condition` holds on the supervised
    /// component the driver task owns. Returns `false` on timeout so a
    /// wedged loop fails the test instead of hanging the suite.
    async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = TokioInstant::now() + Duration::from_secs(10);
        while TokioInstant::now() < deadline {
            if condition() {
                return true;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        condition()
    }

    /// The component starts under the profile, claims the fence on the
    /// first tick, renews and reconciles on later ticks, and the
    /// profile settles it cleanly on cancellation.
    #[tokio::test(flavor = "current_thread")]
    async fn component_claims_renews_and_settles_under_profile() {
        let calls = Arc::new(AtomicUsize::new(0));
        let claims = Arc::new(AtomicUsize::new(0));
        let renews = Arc::new(AtomicUsize::new(0));
        let component = ArtifactReconcilerComponent::new(
            CountingPass {
                calls: calls.clone(),
                failures: Arc::new(StdMutex::new(Vec::new())),
            },
            ScriptedFenceSource {
                claims: claims.clone(),
                renews: renews.clone(),
                claim_failures: StdMutex::new(Vec::new()),
            },
            test_epoch(),
        )
        .with_interval(Duration::from_millis(10));

        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_component(component);
        let token = profile.cancellation_token();
        let driver = tokio::spawn(async move { profile.run(std::future::pending()).await });

        // 10 ms ticks: first tick claims, every later tick renews then
        // passes — three passes prove the claim→renew→pass ladder ran.
        assert!(
            wait_until(|| calls.load(Ordering::SeqCst) >= 3).await,
            "the component must execute reconciliation passes under the profile"
        );
        assert_eq!(claims.load(Ordering::SeqCst), 1, "one acquire, then renews");
        assert!(
            renews.load(Ordering::SeqCst) >= 2,
            "held claims renew each tick"
        );

        token.cancel();
        let result = driver.await.unwrap();
        assert!(result.is_ok(), "intentional stop must settle cleanly");
    }

    /// A transient claim failure is contained and retried on the next
    /// tick — it must never disable reconciliation for the process's
    /// remaining life.
    #[tokio::test(flavor = "current_thread")]
    async fn claim_failure_retries_on_next_tick() {
        let calls = Arc::new(AtomicUsize::new(0));
        let claims = Arc::new(AtomicUsize::new(0));
        let component = ArtifactReconcilerComponent::new(
            CountingPass {
                calls: calls.clone(),
                failures: Arc::new(StdMutex::new(Vec::new())),
            },
            ScriptedFenceSource {
                claims: claims.clone(),
                renews: Arc::new(AtomicUsize::new(0)),
                claim_failures: StdMutex::new(vec![Failure::unavailable(
                    "claim_store_down",
                    "coordinator store unreachable",
                )]),
            },
            test_epoch(),
        )
        .with_interval(Duration::from_millis(10));

        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_component(component);
        let token = profile.cancellation_token();
        let driver = tokio::spawn(async move { profile.run(std::future::pending()).await });

        // First tick's claim fails; the next tick re-claims and passes.
        assert!(
            wait_until(|| calls.load(Ordering::SeqCst) >= 1).await,
            "a contained claim failure must not disable later passes"
        );
        assert!(
            claims.load(Ordering::SeqCst) >= 2,
            "the failed claim is retried on a later tick"
        );

        token.cancel();
        let result = driver.await.unwrap();
        assert!(result.is_ok(), "intentional stop must settle cleanly");
    }

    /// A missing epoch idles the component: it never returns (a return
    /// would be a terminal profile event) and never reconciles, and the
    /// profile still settles it cleanly.
    #[tokio::test(flavor = "current_thread")]
    async fn missing_epoch_idles_until_shutdown() {
        let calls = Arc::new(AtomicUsize::new(0));
        let component = ArtifactReconcilerComponent::with_epoch_source(
            CountingPass {
                calls: calls.clone(),
                failures: Arc::new(StdMutex::new(Vec::new())),
            },
            ScriptedFenceSource {
                claims: Arc::new(AtomicUsize::new(0)),
                renews: Arc::new(AtomicUsize::new(0)),
                claim_failures: StdMutex::new(Vec::new()),
            },
            || None,
        )
        .with_interval(Duration::from_millis(10));

        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_component(component);
        let token = profile.cancellation_token();
        let driver = tokio::spawn(async move { profile.run(std::future::pending()).await });

        // Give the idle arm several tick intervals to misbehave: any
        // premature return would end the profile as a terminal exit.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !driver.is_finished(),
            "an epoch-less component must idle, never return"
        );
        token.cancel();
        let result = driver.await.unwrap();
        assert!(result.is_ok(), "the idle component settles cleanly");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
