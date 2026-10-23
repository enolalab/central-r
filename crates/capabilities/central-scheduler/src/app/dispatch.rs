//! The claim-loop dispatcher — port of
//! `central/internal/scheduler/app/dispatch.go`: it turns a claimed
//! node into one live harness session attempt through spec-1's
//! dispatch shape — prepare (workspace provisioning) → invoke the
//! launcher outside any transaction → persist the outcome under the
//! lease fence. Each port call commits independently; the dispatcher
//! never holds a transaction open across the launcher invoke.
//!
//! Also carries the interim [`StubLauncher`] — the development-gate
//! [`NodeLauncher`] the kernel composes until the real harness wiring
//! lands (upstream `launcher_stub.go`).

use std::sync::Mutex;

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::SessionAttemptId;
use time::OffsetDateTime;

use crate::domain::ClaimedAttempt;
use crate::port::{LaunchSpec, LaunchVerdict, NodeLauncher, Provisioner, Store};

// Dispatch-class reason codes (upstream's app-package constants). The
// first two are spec-4's dispatch_infra taxonomy (retryable,
// classified by the 2D policy); the third is the dispatch-scope
// ambiguous code this slice introduces: spec-2's `ATTEMPT_AMBIGUOUS_*`
// set covers lease expiry and worker loss, while an invoke returning
// without a confirmed outcome is neither, so it carries
// `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN`.

/// `WORKSPACE_PROVISION_FAILED` — a definite workspace-prepare
/// failure before the launch invoke.
pub const REASON_WORKSPACE_PROVISION_FAILED: &str = "WORKSPACE_PROVISION_FAILED";
/// `LAUNCHER_REFUSED` — a confirmed launcher refusal; nothing ran.
pub const REASON_LAUNCHER_REFUSED: &str = "LAUNCHER_REFUSED";
/// `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN` — the invoke returned without a
/// confirmed outcome; the attempt parks for an operator decision.
pub const REASON_ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN: &str = "ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN";

/// Names the variable through which the dispatcher hands
/// `central artifact read` (`internal/command/artifact_read.go`) its
/// attempt scope — the name is pinned by that command.
const ATTEMPT_SCOPE_ENV_VAR: &str = "CENTRAL_ATTEMPT_SCOPE";

/// The `CENTRAL_ATTEMPT_SCOPE=<run_id>:<node_id>:<attempt_id>` env
/// entry injected into one attempt's launch (upstream
/// `AttemptScopeEnv`).
#[must_use]
pub fn attempt_scope_env(claim: &ClaimedAttempt) -> String {
    format!(
        "{ATTEMPT_SCOPE_ENV_VAR}={}:{}:{}",
        claim.attempt.run_id, claim.attempt.node_id, claim.attempt.id
    )
}

/// Runs one claimed attempt through spec-1's dispatch shape (upstream
/// `app.Dispatcher`): prepare → invoke → persist.
pub struct Dispatcher<S: Store, P: Provisioner, L: NodeLauncher> {
    /// Persists dispatch outcomes through the fenced P2B02 methods.
    pub store: S,
    /// Provisions the per-node isolated workspace in prepare.
    pub provisioner: P,
    /// Invokes the harness launch machinery outside transactions.
    pub launcher: L,
    /// Supplies app-side timestamps where dispatch needs them;
    /// `None` uses UTC wall time. PostgreSQL remains authoritative
    /// for committed timestamps.
    pub now: Option<Box<dyn Fn() -> OffsetDateTime + Send + Sync>>,
    /// The git ref worktree workspaces are checked out at — the run's
    /// recorded base ref once the run record carries it through the
    /// claim. Empty means `HEAD`.
    pub base_ref: String,
}

impl<S: Store, P: Provisioner, L: NodeLauncher> Dispatcher<S, P, L> {
    /// Builds a dispatcher over its three ports; `now` unset and
    /// `base_ref` empty (`HEAD`).
    pub fn new(store: S, provisioner: P, launcher: L) -> Self {
        Self {
            store,
            provisioner,
            launcher,
            now: None,
            base_ref: String::new(),
        }
    }

    /// Executes prepare → invoke → persist for one claim (upstream
    /// `Dispatch`):
    ///
    /// 1. prepare — [`Provisioner::provision`] isolates the workspace;
    ///    a definite failure closes the attempt via
    ///    `fail_dispatch(WORKSPACE_PROVISION_FAILED)`. A
    ///    `FailureKind::Cancelled` failure reports an interrupted
    ///    prepare (upstream's `ctx.Err()` branch): it returns without
    ///    a durable write — the attempt stays `claimed` and the
    ///    lease-expiry ladder closes it as never-started.
    /// 2. tx1 — [`Store::mark_provisioning`] fences and records
    ///    `provisioning` + `workspace_path` in one commit.
    /// 3. invoke — [`NodeLauncher::launch`] runs with no transaction
    ///    open.
    /// 4. tx2 — a confirmed invoke persists via
    ///    [`Store::mark_started`] (attempt `started`, node `running`,
    ///    `attempt_started`); a confirmed refusal via
    ///    `fail_dispatch(LAUNCHER_REFUSED)` (attempt `failed`, node
    ///    `ready`); an unknown outcome via
    ///    [`Store::ambiguate_dispatch`] (attempt `ambiguous`, node
    ///    `attempt_ambiguous`, operator decision only).
    ///
    /// A store write rejected by the lease fence (the lease expired or
    /// was released mid-dispatch) propagates as the dispatch error —
    /// the sweeper already owns that attempt's outcome. Dropping the
    /// returned future during prepare is upstream's ctx cancellation:
    /// no durable write, the lease ladder owns the attempt.
    pub async fn dispatch(&self, claim: ClaimedAttempt) -> Result<(), Failure> {
        let attempt = &claim.attempt;
        let path = match self
            .provisioner
            .provision(
                attempt.run_id,
                attempt.node_id,
                attempt.id,
                &attempt.workspace_kind,
                &self.base_ref,
            )
            .await
        {
            Ok(path) => path,
            Err(failure) => {
                if failure.kind() == FailureKind::Cancelled {
                    // Upstream `ctx.Err() != nil → return ctxErr`: an
                    // interrupted prepare writes nothing durable.
                    return Err(failure);
                }
                return Err(self
                    .fail_dispatch(attempt.id, REASON_WORKSPACE_PROVISION_FAILED, failure)
                    .await);
            }
        };
        self.store.mark_provisioning(attempt.id, &path).await?;
        // Invoke happens here — no transaction open, per spec-1's
        // prepare → invoke → persist discipline.
        let verdict = self
            .launcher
            .launch(LaunchSpec {
                attempt: claim.clone(),
                workspace_path: path,
                env: vec![attempt_scope_env(&claim)],
            })
            .await;
        match verdict {
            LaunchVerdict::Started(session_id) if !session_id.is_empty() => {
                self.store.mark_started(attempt.id, &session_id).await
            }
            LaunchVerdict::Refused(cause) => Err(self
                .fail_dispatch(attempt.id, REASON_LAUNCHER_REFUSED, cause)
                .await),
            // `Unknown`, or a contract-breach empty session id on
            // `Started`: the outcome is unknowable — park ambiguous
            // for the operator.
            _ => {
                self.store
                    .ambiguate_dispatch(attempt.id, REASON_ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN)
                    .await
            }
        }
    }

    /// Records a definite pre-start failure durably, then reports the
    /// original cause to the caller (upstream `failDispatch`). When
    /// the failure write itself is fenced (lease already gone), the
    /// fence error is what propagates — the sweeper's expiry path
    /// already owns the attempt. The write's machine code survives
    /// verbatim: upstream's `fmt.Errorf("… record %s: %w")` keeps
    /// `errors.Is`, so the port keeps `code` and rewrites only the
    /// redacted message.
    async fn fail_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &'static str,
        cause: Failure,
    ) -> Failure {
        match self.store.fail_dispatch(attempt_id, reason_code).await {
            Ok(()) => cause,
            Err(write) => Failure::new(
                write.kind(),
                write.code(),
                format!(
                    "scheduler dispatch: record {reason_code}: {}",
                    write.message()
                ),
            ),
        }
    }
}

/// The interim [`NodeLauncher`] for Slice 2B (upstream
/// `StubLauncher`). It records every [`LaunchSpec`] it is asked to
/// invoke and confirms a deterministic session id
/// (`stub-session-<attempt-id>`), standing in for the real harness
/// launch wiring until the scheduler→harness path binds to
/// `harness_attempt` rows in serve composition (the B09 lineage /
/// R4 Task 12). It exists so dispatch's invoke step is exercised end
/// to end through the port; it MUST NOT be presented as real harness
/// execution — no harness process runs and no real session id exists
/// behind the returned value.
///
/// KNOWN LIMITATION (flagged for the slice evidence): a dispatch
/// confirmed through `StubLauncher` journals `attempt_started` for a
/// session nothing is actually running. That is acceptable only while
/// the scheduler workers slice is composed behind a development gate;
/// the serve wiring replaces it before any real run path is
/// reachable. Upstream installs it only behind the explicit
/// `CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB=1` dev gate (issue #120).
#[derive(Default)]
pub struct StubLauncher {
    specs: Mutex<Vec<LaunchSpec>>,
}

impl StubLauncher {
    /// A stub that confirms every launch (upstream `NewStubLauncher`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of every recorded launch spec, in invoke order
    /// (upstream `Specs`).
    #[must_use]
    pub fn specs(&self) -> Vec<LaunchSpec> {
        self.specs.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl NodeLauncher for StubLauncher {
    /// Records the spec and confirms a deterministic session id
    /// (upstream `Launch`). Upstream's cancelled-context branch — an
    /// unconfirmed outcome — maps onto future-drop here: a dropped
    /// `launch` future never reaches the record, which IS the honest
    /// "invoke interrupted before anything was decided" answer.
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
        let session_id = format!("stub-session-{}", spec.attempt.attempt.id);
        self.specs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(spec);
        LaunchVerdict::Started(session_id)
    }
}

#[cfg(test)]
mod tests {
    use central_foundation::identity::{NodeLeaseId, WorkerId, WorkflowNodeId};

    use super::*;
    use crate::app::fakes::{
        FakeLauncher, FakeProvisioner, RecordingStore, SharedLog, shared_log, test_claim,
    };
    use crate::domain::{self, ExpiryResult, Lease};
    use crate::testkit::block_on;

    /// Wraps a [`RecordingStore`] so the four dispatch writes also
    /// join the shared order log (upstream `orderStore`); every other
    /// method forwards unlogged.
    struct OrderStore(SharedLog, RecordingStore);

    fn order_store(log: &SharedLog, store: RecordingStore) -> OrderStore {
        OrderStore(log.clone(), store)
    }

    impl OrderStore {
        fn log(&self, name: &str) {
            self.0.lock().unwrap().push(name.to_string());
        }
    }

    impl Store for OrderStore {
        async fn register_worker(&self, worker: domain::Worker) -> Result<WorkerId, Failure> {
            self.1.register_worker(worker).await
        }

        async fn deregister_worker(&self, worker_id: WorkerId, actor: &str) -> Result<(), Failure> {
            self.1.deregister_worker(worker_id, actor).await
        }

        async fn claim_ready(
            &self,
            worker_id: WorkerId,
            limit: u32,
        ) -> Result<Vec<ClaimedAttempt>, Failure> {
            self.1.claim_ready(worker_id, limit).await
        }

        async fn renew_lease(
            &self,
            lease_id: NodeLeaseId,
            worker_id: WorkerId,
        ) -> Result<(), Failure> {
            self.1.renew_lease(lease_id, worker_id).await
        }

        async fn worker_leases(&self, worker_id: WorkerId) -> Result<Vec<Lease>, Failure> {
            self.1.worker_leases(worker_id).await
        }

        async fn fence(
            &self,
            node_id: WorkflowNodeId,
            attempt_id: SessionAttemptId,
            lease_id: NodeLeaseId,
        ) -> Result<(), Failure> {
            self.1.fence(node_id, attempt_id, lease_id).await
        }

        async fn expire_leases(&self, now: OffsetDateTime) -> Result<Vec<ExpiryResult>, Failure> {
            self.1.expire_leases(now).await
        }

        async fn reconcile(&self, actor: &str) -> Result<(), Failure> {
            self.1.reconcile(actor).await
        }

        async fn sweep_suspects(&self, now: OffsetDateTime) -> Result<(), Failure> {
            self.1.sweep_suspects(now).await
        }

        async fn mark_provisioning(
            &self,
            attempt_id: SessionAttemptId,
            workspace_path: &str,
        ) -> Result<(), Failure> {
            self.log("mark_provisioning");
            self.1.mark_provisioning(attempt_id, workspace_path).await
        }

        async fn mark_started(
            &self,
            attempt_id: SessionAttemptId,
            harness_session_id: &str,
        ) -> Result<(), Failure> {
            self.log("mark_started");
            self.1.mark_started(attempt_id, harness_session_id).await
        }

        async fn fail_dispatch(
            &self,
            attempt_id: SessionAttemptId,
            reason_code: &str,
        ) -> Result<(), Failure> {
            self.log("fail_dispatch");
            self.1.fail_dispatch(attempt_id, reason_code).await
        }

        async fn ambiguate_dispatch(
            &self,
            attempt_id: SessionAttemptId,
            reason_code: &str,
        ) -> Result<(), Failure> {
            self.log("ambiguate_dispatch");
            self.1.ambiguate_dispatch(attempt_id, reason_code).await
        }

        async fn list_wall_clock_breaches(
            &self,
            now: OffsetDateTime,
        ) -> Result<Vec<domain::SessionAttempt>, Failure> {
            self.1.list_wall_clock_breaches(now).await
        }

        async fn record_ceiling_breach(
            &self,
            attempt_id: SessionAttemptId,
            reason_code: &str,
        ) -> Result<(), Failure> {
            self.1.record_ceiling_breach(attempt_id, reason_code).await
        }
    }

    // -- upstream dispatch_test.go: TestDispatchHappyPathOrdersProvisionInvokePersist

    /// Prepare → provisioning mark → invoke → started persist, in that
    /// order, with the scope env injected and the provisioned path
    /// carried through.
    #[test]
    fn dispatch_happy_path_orders_provision_invoke_persist() {
        let claim = test_claim();
        let log = shared_log();
        let store = RecordingStore::default();
        let mut prov = FakeProvisioner::new("/scratch/workspaces/run/node");
        prov.log = Some(log.clone());
        let mut launch = FakeLauncher::new(LaunchVerdict::Started("sess-1".to_string()));
        launch.log = Some(log.clone());
        let launches = launch.calls_handle();

        // The store joins the shared order log through the wrapper.
        let d = Dispatcher::new(order_store(&log, store), prov, launch);

        block_on(d.dispatch(claim.clone())).unwrap();

        assert_eq!(
            log.lock().unwrap().as_slice(),
            ["provision", "mark_provisioning", "launch", "mark_started"]
        );
        assert_eq!(
            d.store.1.provisioning_path(),
            "/scratch/workspaces/run/node"
        );
        // The provision call carried run, node, kind, and base ref.
        assert_eq!(d.provisioner.calls(), ["provision"]);
        assert_eq!(
            d.provisioner.got(),
            Some((
                claim.attempt.run_id,
                claim.attempt.node_id,
                "directory".to_string(),
                String::new()
            ))
        );
        let spec = &launches.lock().unwrap()[0];
        assert_eq!(spec.workspace_path, "/scratch/workspaces/run/node");
        let want_scope = format!(
            "CENTRAL_ATTEMPT_SCOPE={}:{}:{}",
            claim.attempt.run_id, claim.attempt.node_id, claim.attempt.id
        );
        assert_eq!(spec.env, [want_scope]);
        assert_eq!(d.store.1.started_session_id(), "sess-1");
    }

    // -- upstream dispatch_test.go: TestDispatchProvisionFailureFailsAttemptAndRequeues

    /// A definite prepare failure closes the attempt
    /// (`WORKSPACE_PROVISION_FAILED`), never invokes the launcher, and
    /// the cause propagates to the caller.
    #[test]
    fn dispatch_provision_failure_fails_attempt_and_requeues() {
        let claim = test_claim();
        let cause = Failure::unavailable("DISK_FULL", "disk full");
        let store = RecordingStore::default();
        let mut prov = FakeProvisioner::new("");
        prov.provision_err = Some(cause.clone());
        let launch = FakeLauncher::new(LaunchVerdict::Started("s".to_string()));
        let launches = launch.calls_handle();
        let d = Dispatcher::new(store, prov, launch);

        let err = block_on(d.dispatch(claim)).unwrap_err();
        assert_eq!(err, cause);
        assert_eq!(d.provisioner.calls(), ["provision"]);
        assert_eq!(d.store.fail_reason(), REASON_WORKSPACE_PROVISION_FAILED);
        assert!(launches.lock().unwrap().is_empty());
        assert_eq!(d.store.sequence(), ["fail_dispatch"]);
    }

    // -- upstream dispatch_test.go: TestDispatchLauncherRefusalFailsAttempt

    /// A confirmed launcher refusal closes `failed` with
    /// `LAUNCHER_REFUSED` after the provisioning mark committed.
    #[test]
    fn dispatch_launcher_refusal_fails_attempt() {
        let store = RecordingStore::default();
        let refused = Failure::invalid("ARGV_REFUSED", "argv refused");
        let launch = FakeLauncher::new(LaunchVerdict::Refused(refused.clone()));
        let d = Dispatcher::new(store, FakeProvisioner::new("/w"), launch);

        let err = block_on(d.dispatch(test_claim())).unwrap_err();
        assert_eq!(err, refused);
        assert_eq!(d.store.fail_reason(), REASON_LAUNCHER_REFUSED);
        assert_eq!(d.store.sequence(), ["mark_provisioning", "fail_dispatch"]);
    }

    // -- upstream dispatch_test.go: TestDispatchUnconfirmedLaunchParksAmbiguous

    /// An unconfirmed invoke parks `ambiguous` — never auto-relaunched.
    #[test]
    fn dispatch_unconfirmed_launch_parks_ambiguous() {
        let store = RecordingStore::default();
        let d = Dispatcher::new(
            store,
            FakeProvisioner::new("/w"),
            FakeLauncher::new(LaunchVerdict::Unknown),
        );

        block_on(d.dispatch(test_claim())).unwrap();
        assert_eq!(
            d.store.ambiguous_reason(),
            REASON_ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN
        );
        assert_eq!(
            d.store.sequence(),
            ["mark_provisioning", "ambiguate_dispatch"]
        );
    }

    // -- upstream dispatch_test.go: TestDispatchEmptySessionIDIsAmbiguous

    /// A confirmed success with an empty session id is a contract
    /// breach treated as unknown outcome.
    #[test]
    fn dispatch_empty_session_id_is_ambiguous() {
        let store = RecordingStore::default();
        let d = Dispatcher::new(
            store,
            FakeProvisioner::new("/w"),
            FakeLauncher::new(LaunchVerdict::Started(String::new())),
        );

        block_on(d.dispatch(test_claim())).unwrap();
        assert_eq!(
            d.store.ambiguous_reason(),
            REASON_ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN
        );
    }

    // -- upstream dispatch_test.go: TestDispatchFenceRejectionStopsBeforeLaunch

    /// A fenced `mark_provisioning` propagates and the launcher is
    /// never invoked — the sweeper owns the attempt now.
    #[test]
    fn dispatch_fence_rejection_stops_before_launch() {
        let fence = domain::Failure::new(
            domain::FailureClass::Denied,
            domain::REASON_LEASE_FENCE_STALE,
        );
        let fence_failure: Failure = fence.into();
        let store = RecordingStore::default();
        store.set_mark_provisioning_err(fence_failure.clone());
        let launch = FakeLauncher::new(LaunchVerdict::Started("s".to_string()));
        let launches = launch.calls_handle();
        let d = Dispatcher::new(store, FakeProvisioner::new("/w"), launch);

        let err = block_on(d.dispatch(test_claim())).unwrap_err();
        assert_eq!(err, fence_failure);
        assert!(launches.lock().unwrap().is_empty());
    }

    // -- upstream dispatch_test.go:
    // TestDispatchCancelledContextSkipsDurableWrite — the Rust port has
    // no context: a `FailureKind::Cancelled` provision result is the
    // cancelled-prepare surface (the provisioner's `ctx.Err()` branch),
    // and dropping the `dispatch` future mid-prepare writes nothing.
    // Both map to "no durable write".
    #[test]
    fn dispatch_cancelled_prepare_skips_durable_write() {
        let store = RecordingStore::default();
        let mut prov = FakeProvisioner::new("");
        prov.provision_err = Some(Failure::cancelled("CANCELLED", "interrupted"));
        let d = Dispatcher::new(store, prov, FakeLauncher::new(LaunchVerdict::Unknown));

        let err = block_on(d.dispatch(test_claim())).unwrap_err();
        assert_eq!(err.kind(), FailureKind::Cancelled);
        assert!(
            d.store.sequence().is_empty(),
            "store writes under a cancelled prepare: {:?}",
            d.store.sequence()
        );
    }

    // -- upstream dispatch_test.go: TestDispatchUnconfiguredFails -----
    // Unconfigured is unrepresentable: `Dispatcher::new` requires all
    // three ports.

    // -- upstream dispatch_test.go: TestDispatchWithStubLauncher ------

    /// The stub confirms `stub-session-<attempt-id>` and records the
    /// spec verbatim — env scope included.
    #[test]
    fn dispatch_with_stub_launcher() {
        let claim = test_claim();
        let store = RecordingStore::default();
        let stub = StubLauncher::new();
        let d = Dispatcher::new(store, FakeProvisioner::new("/w"), stub);

        block_on(d.dispatch(claim.clone())).unwrap();
        let want_sid = format!("stub-session-{}", claim.attempt.id);
        assert_eq!(d.store.started_session_id(), want_sid);
        let specs = d.launcher.specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].attempt.attempt.id, claim.attempt.id);
        assert!(specs[0].env[0].starts_with("CENTRAL_ATTEMPT_SCOPE="));
    }
}
