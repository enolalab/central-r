//! The Slice-2B scheduler application services — the port of
//! `central/internal/scheduler/app`: the in-process [`worker::Worker`]
//! registration/heartbeat component, the ready-queue
//! [`claim_loop::ClaimLoop`], the [`dispatch::Dispatcher`] that turns a
//! claimed node into one live harness session attempt, the
//! [`sweeper::Sweeper`] lease monitor, and the startup
//! [`reconciler::Reconciler`] preflight.
//!
//! The package depends only on the scheduler domain and its ports —
//! durable state lives behind [`crate::port::Store`], workspace
//! isolation behind [`crate::port::Provisioner`], harness launch behind
//! [`crate::port::NodeLauncher`].
//!
//! Upstream's `Run`/`Shutdown` loop bodies (the `time.Ticker` loops and
//! done-channel waits) are kernel `Component`/`Preflight` concerns —
//! this crate carries the passes themselves
//! ([`worker::Worker::heartbeat_once`],
//! [`claim_loop::ClaimLoop::claim_once`],
//! [`sweeper::Sweeper::sweep_once`], [`reconciler::Reconciler::run`])
//! plus each component's `tick_interval` cadence contract the
//! supervisor ticks on.
//!
//! SHARED TICK CONTRACT — every ticked component runs its pass ONCE
//! at component start, then again on every `tick_interval` tick:
//! upstream `Run` calls `heartbeat()`/`claimOnce()`/`sweepOnce()`
//! before creating the ticker (worker.go:102, claim_loop.go:79,
//! sweeper.go:51). The run-once pass is the same `*_once` method —
//! a supervisor that only sleeps on `tick_interval` delays the first
//! heartbeat/sweep by 15 s and the first claim by 2 s. The claim
//! loop additionally splits its poll into
//! [`claim_loop::ClaimLoop::claims`] and
//! [`claim_loop::ClaimLoop::dispatch`] so the kernel can fan
//! dispatch out onto spawned tasks — the recommended driver;
//! `claim_once` remains the sequential simple driver.
//! [`reconciler::Reconciler::run`] is not ticked at all: it is the
//! one-shot preflight gate.
//!
//! Passes never overlap by
//! construction (one `&self`/`&mut self` call), and cancellation is
//! future-drop: a pass abandoned mid-await is the upstream `ctx.Done`
//! case — no durable write beyond what already committed, and the
//! lease-expiry ladder closes whatever it leaves.
//!
//! OWNING PACKET: P2B01–P2B06. SLICE: 2B (issue #93).

pub mod claim_loop;
pub mod dispatch;
pub mod reconciler;
pub mod sweeper;
pub mod worker;

#[cfg(test)]
pub(crate) mod fakes {
    //! Shared test doubles — the port of upstream's `recordingStore`,
    //! `countLauncher`, and the scripted provisioners from
    //! `components_test.go`/`dispatch_test.go`. Every fake is
    //! `Mutex`-backed (single-pass `block_on` drives them) and records
    //! into `seq` in arrival order.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use central_foundation::failure::Failure;
    use central_foundation::identity::{
        NodeLeaseId, RunId, SessionAttemptId, WorkerId, WorkflowNodeId, WorkspaceId,
    };
    use time::OffsetDateTime;

    use crate::domain::{
        AttemptState, ClaimedAttempt, ExpiryResult, Lease, SessionAttempt, Worker,
    };
    use crate::port::{LaunchSpec, LaunchVerdict, NodeLauncher, Provisioner, Store};

    /// A shared call-order log — when several fakes must interleave
    /// into one ordering assertion (the dispatch happy path) they all
    /// record into the same `log`.
    pub(crate) type SharedLog = std::sync::Arc<Mutex<Vec<String>>>;

    pub(crate) fn shared_log() -> SharedLog {
        std::sync::Arc::new(Mutex::new(Vec::new()))
    }

    /// Logs every call in arrival order and returns scripted results
    /// (upstream `recordingStore`). The dispatch-outcome writes record
    /// and succeed unless an error is scripted; the worker and sweep
    /// surfaces are scripted per test.
    #[derive(Default)]
    pub(crate) struct RecordingStore {
        inner: Mutex<RecordingInner>,
    }

    #[derive(Default)]
    struct RecordingInner {
        seq: Vec<String>,

        claim_results: std::collections::VecDeque<Vec<ClaimedAttempt>>,
        claim_rest: Vec<ClaimedAttempt>,
        claim_err: Option<Failure>,
        claims: u32,
        claim_worker: Option<WorkerId>,
        claim_limit: u32,

        leases: Vec<Lease>,
        leases_err: Option<Failure>,
        worker_leases_calls: u32,

        renew_errs: HashMap<NodeLeaseId, Failure>,
        renew_counts: HashMap<NodeLeaseId, u32>,

        expire_calls: u32,
        expire_now: Option<OffsetDateTime>,
        expire_err: Option<Failure>,
        sweep_calls: u32,
        sweep_err: Option<Failure>,

        reconcile_calls: u32,
        reconcile_actor: String,
        reconcile_err: Option<Failure>,

        registered_w: Option<Worker>,
        register_err: Option<Failure>,
        register_return: Option<WorkerId>,
        deregister_calls: u32,
        deregistered_id: Option<WorkerId>,
        deregistered_actor: String,
        deregister_err: Option<Failure>,

        provisioning_path: String,
        started_session_id: String,
        fail_reason: String,
        ambiguous_reason: String,
        mark_provisioning_err: Option<Failure>,
        mark_started_err: Option<Failure>,
        fail_dispatch_err: Option<Failure>,
        ambiguate_err: Option<Failure>,
    }

    impl RecordingStore {
        fn record(&self, name: &str) {
            self.inner.lock().unwrap().seq.push(name.to_string());
        }

        pub(crate) fn sequence(&self) -> Vec<String> {
            self.inner.lock().unwrap().seq.clone()
        }

        pub(crate) fn count(&self, want: &str) -> usize {
            self.inner
                .lock()
                .unwrap()
                .seq
                .iter()
                .filter(|s| s.as_str() == want)
                .count()
        }

        pub(crate) fn set_claim_results(&self, results: Vec<Vec<ClaimedAttempt>>) {
            self.inner.lock().unwrap().claim_results = results.into();
        }

        pub(crate) fn set_claim_err(&self, err: Failure) {
            self.inner.lock().unwrap().claim_err = Some(err);
        }

        pub(crate) fn claims(&self) -> u32 {
            self.inner.lock().unwrap().claims
        }

        pub(crate) fn claim_worker(&self) -> Option<WorkerId> {
            self.inner.lock().unwrap().claim_worker
        }

        pub(crate) fn claim_limit(&self) -> u32 {
            self.inner.lock().unwrap().claim_limit
        }

        pub(crate) fn set_leases(&self, leases: Vec<Lease>) {
            self.inner.lock().unwrap().leases = leases;
        }

        pub(crate) fn set_renew_err(&self, lease_id: NodeLeaseId, err: Failure) {
            self.inner.lock().unwrap().renew_errs.insert(lease_id, err);
        }

        pub(crate) fn renew_count(&self, lease_id: NodeLeaseId) -> u32 {
            self.inner
                .lock()
                .unwrap()
                .renew_counts
                .get(&lease_id)
                .copied()
                .unwrap_or(0)
        }

        pub(crate) fn set_reconcile_err(&self, err: Failure) {
            self.inner.lock().unwrap().reconcile_err = Some(err);
        }

        pub(crate) fn reconcile_calls(&self) -> u32 {
            self.inner.lock().unwrap().reconcile_calls
        }

        pub(crate) fn reconcile_actor(&self) -> String {
            self.inner.lock().unwrap().reconcile_actor.clone()
        }

        pub(crate) fn set_register_err(&self, err: Failure) {
            self.inner.lock().unwrap().register_err = Some(err);
        }

        pub(crate) fn registered(&self) -> Option<Worker> {
            self.inner.lock().unwrap().registered_w.clone()
        }

        pub(crate) fn deregister_calls(&self) -> u32 {
            self.inner.lock().unwrap().deregister_calls
        }

        pub(crate) fn deregistered(&self) -> (Option<WorkerId>, String) {
            let inner = self.inner.lock().unwrap();
            (inner.deregistered_id, inner.deregistered_actor.clone())
        }

        pub(crate) fn sweep_stats(&self) -> (u32, u32) {
            let inner = self.inner.lock().unwrap();
            (inner.expire_calls, inner.sweep_calls)
        }

        pub(crate) fn expire_now(&self) -> Option<OffsetDateTime> {
            self.inner.lock().unwrap().expire_now
        }

        pub(crate) fn provisioning_path(&self) -> String {
            self.inner.lock().unwrap().provisioning_path.clone()
        }

        pub(crate) fn started_session_id(&self) -> String {
            self.inner.lock().unwrap().started_session_id.clone()
        }

        pub(crate) fn fail_reason(&self) -> String {
            self.inner.lock().unwrap().fail_reason.clone()
        }

        pub(crate) fn ambiguous_reason(&self) -> String {
            self.inner.lock().unwrap().ambiguous_reason.clone()
        }

        pub(crate) fn set_mark_provisioning_err(&self, err: Failure) {
            self.inner.lock().unwrap().mark_provisioning_err = Some(err);
        }
    }

    impl Store for RecordingStore {
        async fn register_worker(&self, worker: Worker) -> Result<WorkerId, Failure> {
            self.record("register");
            let mut inner = self.inner.lock().unwrap();
            inner.registered_w = Some(worker.clone());
            if let Some(err) = &inner.register_err {
                return Err(err.clone());
            }
            Ok(inner.register_return.unwrap_or(worker.id))
        }

        async fn deregister_worker(&self, worker_id: WorkerId, actor: &str) -> Result<(), Failure> {
            self.record("deregister");
            let mut inner = self.inner.lock().unwrap();
            inner.deregister_calls += 1;
            inner.deregistered_id = Some(worker_id);
            inner.deregistered_actor = actor.to_string();
            match &inner.deregister_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn claim_ready(
            &self,
            worker_id: WorkerId,
            limit: u32,
        ) -> Result<Vec<ClaimedAttempt>, Failure> {
            self.record("claim");
            let mut inner = self.inner.lock().unwrap();
            inner.claims += 1;
            inner.claim_worker = Some(worker_id);
            inner.claim_limit = limit;
            if let Some(err) = &inner.claim_err {
                return Err(err.clone());
            }
            if let Some(batch) = inner.claim_results.pop_front() {
                return Ok(batch);
            }
            Ok(inner.claim_rest.clone())
        }

        async fn renew_lease(
            &self,
            lease_id: NodeLeaseId,
            _worker_id: WorkerId,
        ) -> Result<(), Failure> {
            self.record("renew");
            let mut inner = self.inner.lock().unwrap();
            *inner.renew_counts.entry(lease_id).or_default() += 1;
            match inner.renew_errs.get(&lease_id) {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn worker_leases(&self, _worker_id: WorkerId) -> Result<Vec<Lease>, Failure> {
            self.record("worker_leases");
            let mut inner = self.inner.lock().unwrap();
            inner.worker_leases_calls += 1;
            if let Some(err) = &inner.leases_err {
                return Err(err.clone());
            }
            Ok(inner.leases.clone())
        }

        async fn fence(
            &self,
            _node_id: WorkflowNodeId,
            _attempt_id: SessionAttemptId,
            _lease_id: NodeLeaseId,
        ) -> Result<(), Failure> {
            self.record("fence");
            Ok(())
        }

        async fn expire_leases(&self, now: OffsetDateTime) -> Result<Vec<ExpiryResult>, Failure> {
            self.record("expire");
            let mut inner = self.inner.lock().unwrap();
            inner.expire_calls += 1;
            inner.expire_now = Some(now);
            match &inner.expire_err {
                Some(err) => Err(err.clone()),
                None => Ok(vec![]),
            }
        }

        async fn reconcile(&self, actor: &str) -> Result<(), Failure> {
            self.record("reconcile");
            let mut inner = self.inner.lock().unwrap();
            inner.reconcile_calls += 1;
            inner.reconcile_actor = actor.to_string();
            match &inner.reconcile_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn sweep_suspects(&self, _now: OffsetDateTime) -> Result<(), Failure> {
            self.record("sweep");
            let mut inner = self.inner.lock().unwrap();
            inner.sweep_calls += 1;
            match &inner.sweep_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn mark_provisioning(
            &self,
            _attempt_id: SessionAttemptId,
            workspace_path: &str,
        ) -> Result<(), Failure> {
            self.record("mark_provisioning");
            let mut inner = self.inner.lock().unwrap();
            inner.provisioning_path = workspace_path.to_string();
            match &inner.mark_provisioning_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn mark_started(
            &self,
            _attempt_id: SessionAttemptId,
            harness_session_id: &str,
        ) -> Result<(), Failure> {
            self.record("mark_started");
            let mut inner = self.inner.lock().unwrap();
            inner.started_session_id = harness_session_id.to_string();
            match &inner.mark_started_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn fail_dispatch(
            &self,
            _attempt_id: SessionAttemptId,
            reason_code: &str,
        ) -> Result<(), Failure> {
            self.record("fail_dispatch");
            let mut inner = self.inner.lock().unwrap();
            inner.fail_reason = reason_code.to_string();
            match &inner.fail_dispatch_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn ambiguate_dispatch(
            &self,
            _attempt_id: SessionAttemptId,
            reason_code: &str,
        ) -> Result<(), Failure> {
            self.record("ambiguate_dispatch");
            let mut inner = self.inner.lock().unwrap();
            inner.ambiguous_reason = reason_code.to_string();
            match &inner.ambiguate_err {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn list_wall_clock_breaches(
            &self,
            _now: OffsetDateTime,
        ) -> Result<Vec<SessionAttempt>, Failure> {
            self.record("list_wall_clock_breaches");
            Ok(vec![])
        }

        async fn record_ceiling_breach(
            &self,
            _attempt_id: SessionAttemptId,
            _reason_code: &str,
        ) -> Result<(), Failure> {
            self.record("record_ceiling_breach");
            Ok(())
        }
    }

    /// Records `Provision` args and returns a scripted result
    /// (upstream `fakeProvisioner`); when `log` is set it also joins
    /// the shared call-order log.
    pub(crate) struct FakeProvisioner {
        pub(crate) log: Option<SharedLog>,
        pub(crate) path: String,
        pub(crate) provision_err: Option<Failure>,
        calls: Mutex<Vec<String>>,
        got: Mutex<Option<(RunId, WorkflowNodeId, String, String)>>,
    }

    impl FakeProvisioner {
        pub(crate) fn new(path: &str) -> Self {
            Self {
                log: None,
                path: path.to_string(),
                provision_err: None,
                calls: Mutex::new(vec![]),
                got: Mutex::new(None),
            }
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// The last `(run_id, node_id, kind, base_ref)` provision call.
        pub(crate) fn got(&self) -> Option<(RunId, WorkflowNodeId, String, String)> {
            self.got.lock().unwrap().clone()
        }
    }

    impl Provisioner for FakeProvisioner {
        async fn provision(
            &self,
            run_id: RunId,
            node_id: WorkflowNodeId,
            _attempt_id: SessionAttemptId,
            kind: &str,
            base_ref: &str,
        ) -> Result<String, Failure> {
            if let Some(log) = &self.log {
                log.lock().unwrap().push("provision".to_string());
            }
            self.calls.lock().unwrap().push("provision".to_string());
            *self.got.lock().unwrap() =
                Some((run_id, node_id, kind.to_string(), base_ref.to_string()));
            match &self.provision_err {
                Some(err) => Err(err.clone()),
                None => Ok(self.path.clone()),
            }
        }

        fn free(&self, path: &str) -> Result<(), Failure> {
            self.calls.lock().unwrap().push(format!("free:{path}"));
            Ok(())
        }
    }

    /// Records the spec it was invoked with and returns a scripted
    /// verdict (upstream `fakeLauncher`/`countLauncher`). `calls`
    /// sits behind an `Arc` so a handle survives the launcher's move
    /// into the dispatcher.
    pub(crate) struct FakeLauncher {
        pub(crate) log: Option<SharedLog>,
        pub(crate) verdict: LaunchVerdict,
        calls: std::sync::Arc<Mutex<Vec<LaunchSpec>>>,
    }

    impl FakeLauncher {
        pub(crate) fn new(verdict: LaunchVerdict) -> Self {
            Self {
                log: None,
                verdict,
                calls: std::sync::Arc::new(Mutex::new(vec![])),
            }
        }

        /// The shared invoke log — clones survive the move into a
        /// [`crate::app::dispatch::Dispatcher`].
        pub(crate) fn calls_handle(&self) -> std::sync::Arc<Mutex<Vec<LaunchSpec>>> {
            self.calls.clone()
        }
    }

    impl NodeLauncher for FakeLauncher {
        async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
            if let Some(log) = &self.log {
                log.lock().unwrap().push("launch".to_string());
            }
            self.calls.lock().unwrap().push(spec);
            self.verdict.clone()
        }
    }

    /// Builds one claimed attempt fixture (upstream `testClaim`).
    pub(crate) fn test_claim() -> ClaimedAttempt {
        let node_id = WorkflowNodeId::new();
        let attempt_id = SessionAttemptId::new();
        ClaimedAttempt {
            attempt: SessionAttempt {
                id: attempt_id,
                workspace_id: WorkspaceId::new(),
                run_id: RunId::new(),
                node_id,
                attempt_seq: 1,
                worker_id: None,
                harness_attempt_id: None,
                workspace_path: None,
                workspace_kind: "directory".to_string(),
                state: AttemptState::Claimed,
                dispatch_reason_code: None,
                reservation_id: None,
                harness_session_id: None,
                claimed_at: OffsetDateTime::now_utc(),
                started_at: None,
                ended_at: None,
            },
            lease: Lease {
                id: NodeLeaseId::new(),
                node_id,
                attempt_id,
                worker_id: WorkerId::new(),
                issued_at: OffsetDateTime::now_utc(),
                last_heartbeat_at: OffsetDateTime::now_utc(),
                expires_at: OffsetDateTime::now_utc() + crate::domain::lease_ttl(),
                heartbeat_interval_sec: 15,
                released_at: None,
            },
            harness: "claude-code".to_string(),
        }
    }

    /// A lease fixture for worker tests (upstream builds bare
    /// `Lease{ID, NodeID, WorkerID}` rows).
    pub(crate) fn test_lease(worker_id: WorkerId) -> Lease {
        Lease {
            id: NodeLeaseId::new(),
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
            worker_id,
            issued_at: OffsetDateTime::now_utc(),
            last_heartbeat_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + crate::domain::lease_ttl(),
            heartbeat_interval_sec: 15,
            released_at: None,
        }
    }
}
