//! Shared test scaffolding — in-memory fakes for the transport's
//! narrow service seams and request builders that install the
//! `ConnectInfo` extension the admission layer requires.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use central_foundation::identity::{SessionId, WorkspaceId};
use central_session::contract::{Failure, FailureClass, PreAuthCSRF, RequestIdentity};
use central_session::domain::{ActivationRequest, Session, SessionState, ValidationRequest};
use central_transport_http::ports::{DeliveryPrecommit, PreAuthCsrf, SessionValidator};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

/// The test service implementing all three transport seams on one
/// fake — mirrors production where `Service<S, B>` satisfies all of
/// them.
pub struct FakeSessions {
    /// token_hash → Session rows.
    pub sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// activate_delivery calls, in order.
    pub activations: Mutex<Vec<ActivationRequest>>,
    /// revoke calls, in order.
    pub revocations: Mutex<Vec<SessionId>>,
    /// When true, `activate_delivery` fails (authority/store error).
    pub activate_fails: std::sync::atomic::AtomicBool,
    /// Count of `issue_pre_auth_csrf` calls.
    pub issued: AtomicUsize,
    /// `exchange_bootstrap` calls, in order.
    pub exchanges: Mutex<Vec<ExchangeRequest>>,
    /// One-shot exchange failure.
    pub exchange_failure: Mutex<Option<Failure>>,
    /// One-shot `prepare_delivery` failure.
    pub delivery_fails: AtomicBool,
    /// `prepare_delivery` sessions, in order.
    pub deliveries: Mutex<Vec<Session>>,
}

impl FakeSessions {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            activations: Mutex::new(Vec::new()),
            revocations: Mutex::new(Vec::new()),
            activate_fails: std::sync::atomic::AtomicBool::new(false),
            issued: AtomicUsize::new(0),
            exchanges: Mutex::new(Vec::new()),
            exchange_failure: Mutex::new(None),
            delivery_fails: AtomicBool::new(false),
            deliveries: Mutex::new(Vec::new()),
        }
    }

    /// Registers an Active session keyed by `token_hash` so `validate`
    /// succeeds for the matching `central_session` cookie value.
    pub fn insert_active(&self, token_value: [u8; 32]) -> Session {
        let now = OffsetDateTime::now_utc();
        let session = Session {
            id: SessionId::new(),
            workspace_id: WorkspaceId::sentinel(),
            state: SessionState::Active,
            principal_identity: "test".to_string(),
            security_epoch: central_session::domain::SecurityEpoch(0),
            token_hash: Sha256::digest(token_value).into(),
            csrf_hash: [7u8; 32],
            idle_expiry: now + time::Duration::minutes(30),
            absolute_expiry: now + time::Duration::hours(12),
            first_use_deadline: None,
            first_used_at: Some(now),
            created_at: now,
            last_seen_at: now,
            revoked_at: None,
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.token_hash, session.clone());
        session
    }
}

impl Default for FakeSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl PreAuthCsrf for FakeSessions {
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        self.issued.fetch_add(1, Ordering::SeqCst);
        let value: [u8; 32] = rand::random();
        let hash: [u8; 32] = Sha256::digest(value).into();
        PreAuthCSRF::new(value, hash)
    }

    fn validate_pre_auth_csrf(&self, p: &PreAuthCSRF) -> Result<(), Failure> {
        // Mirror `Service::validate_pre_auth_csrf`: reject the zero
        // pair and a value/hash mismatch.
        if p.is_zero() {
            return Err(Failure::new(FailureClass::CsrfInvalid, "zero", ""));
        }
        let got: [u8; 32] = Sha256::digest(p.value()).into();
        if got != p.hash() {
            return Err(Failure::new(FailureClass::CsrfInvalid, "mismatch", ""));
        }
        Ok(())
    }
}

impl SessionValidator for FakeSessions {
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
        let invalidated = || Failure::new(FailureClass::SessionInvalidated, "not found", "");
        if req.token_hash == [0u8; 32] {
            return Err(invalidated());
        }
        let sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get(&req.token_hash) else {
            return Err(invalidated());
        };
        // Mirror the real store's WHERE clause (`Store::validate`):
        // lifecycle Active, security-epoch equality, and — when the
        // route presented a CSRF hash — `csrf_hash` equality. The
        // `Some([0;32])` sentinel means "route did not require CSRF",
        // exactly like the store's `checkCSRF` flag. This is the real
        // session-CSRF enforcement path upstream's
        // `activeSessionWithCSRF` relies on.
        let check_csrf = matches!(req.presented_csrf_hash, Some(h) if h != [0u8; 32]);
        if session.state != SessionState::Active
            || session.security_epoch != req.epoch
            || (check_csrf && req.presented_csrf_hash != Some(session.csrf_hash))
        {
            return Err(invalidated());
        }
        Ok(session.clone())
    }
}

impl DeliveryPrecommit for FakeSessions {
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
        self.activations.lock().unwrap().push(req.clone());
        if self.activate_fails.load(Ordering::SeqCst) {
            return Err(Failure::new(FailureClass::AuthorityDenied, "denied", ""));
        }
        let now = OffsetDateTime::now_utc();
        Ok(Session {
            id: req.delivery_id.as_session_id(),
            workspace_id: WorkspaceId::sentinel(),
            state: SessionState::Active,
            principal_identity: "test".to_string(),
            security_epoch: req.epoch,
            token_hash: req.token_hash,
            csrf_hash: req.csrf_hash,
            idle_expiry: now + time::Duration::minutes(30),
            absolute_expiry: now + time::Duration::hours(12),
            first_use_deadline: None,
            first_used_at: None,
            created_at: now,
            last_seen_at: now,
            revoked_at: None,
        })
    }

    async fn revoke(&self, id: SessionId) -> Result<(), Failure> {
        self.revocations.lock().unwrap().push(id);
        Ok(())
    }
}

/// The `ConnectInfo<SocketAddr>` loopback extension admission requires.
pub fn loopback_req(builder: axum::http::request::Builder) -> Request<Body> {
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        49_001,
    )));
    req
}

/// Same, carrying a body.
pub fn loopback_req_body(
    builder: axum::http::request::Builder,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut req = loopback_req(builder);
    *req.body_mut() = body.into();
    req
}

/// A request carrying a synthetic non-loopback peer.
pub fn remote_req(builder: axum::http::request::Builder) -> Request<Body> {
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        49_001,
    )));
    req
}

pub const HOST: &str = "127.0.0.1:8080";
pub const ORIGIN: &str = "https://127.0.0.1:8080";

/// The expected-host request builder: `GET path` with exact Host.
pub fn get(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("host", HOST)
}

/// `POST path` with exact Host and the expected Origin.
pub fn post_origin(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("host", HOST)
        .header("origin", ORIGIN)
}

/// `RequestIdentity` for precommit arms.
pub fn test_identity() -> RequestIdentity {
    RequestIdentity {
        peer_uid: 1000,
        peer_pid: 42,
        origin: ORIGIN.to_string(),
    }
}

/// A body of exactly `n` bytes.
pub fn body_bytes(n: usize) -> Vec<u8> {
    vec![b'x'; n]
}

/// Waits up to `dur` for `f` to become true.
pub async fn wait_for(dur: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + dur;
    while std::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// Task 12 — web/api fakes: SessionService, TaskService, ArtifactDelivery,
// RecoveryClaimability, HarnessOperator, ReadinessProbe, and the full
// `/app` + `/api/v1` router builder.
// ---------------------------------------------------------------------------

use std::sync::atomic::AtomicBool;

use central_artifact::app::{DeliverArtifactOutcome, DeliverReadyArtifactRequest};
use central_artifact::port::ByteStream;
use central_execution::domain::TrustedScope;
use central_foundation::identity::{ArtifactId, RunId, TaskId};
use central_session::contract::CandidateBinding;
use central_session::domain::{
    DeliveryId, DeliveryRequest, DeliveryResult, ExchangeRequest, ExchangeResult, SecurityEpoch,
};
use central_task::app::CommandMeta;
use central_task::domain::{
    Budget, CancelUnclaimedTaskRequest, CommitResult, PermissionPolicy, RequestCancellationRequest,
    RerunCancelledTaskRequest, RetryFailedTaskRequest, Run, RunStatus, SubmitTaskRequest, Task,
    TaskAggregate, TaskStatus,
};
use central_task::port::LoadedAggregate;
use central_task::query::{
    TaskDetail, TaskDetailProjection, TaskEventLogProjection, TaskListProjection, TaskSummary,
};
use central_transport_http::health::{ProbeSnapshot, ProbeState, ReadinessProbe};
use central_transport_http::ports::{
    ArtifactDelivery, BoxFuture, RecoveryClaimability, SessionService, TaskService,
};
use central_transport_http::web::harness::{
    HarnessBanner, HarnessBudgetDefaults, HarnessOperator, HarnessPermissionDecision,
    HarnessPermissionPanel, HarnessPermissionRecord, HarnessResolveRequest, HarnessResumeBlock,
    HarnessResumeState, HarnessRetryState, HarnessRunBudget,
};

/// A probe always reporting one fixed state.
pub struct StaticProbe(pub ProbeState);

impl ReadinessProbe for StaticProbe {
    fn health(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            state: self.0,
            reason: String::new(),
            remediation: String::new(),
            failure_class: 0,
        }
    }
}

impl SessionService for FakeSessions {
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        PreAuthCsrf::issue_pre_auth_csrf(self)
    }

    fn validate(&self, req: ValidationRequest) -> BoxFuture<'_, Result<Session, Failure>> {
        Box::pin(async move { SessionValidator::validate(self, req).await })
    }

    fn logout(&self, id: SessionId) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.revocations.lock().unwrap().push(id);
            self.sessions
                .lock()
                .unwrap()
                .values_mut()
                .filter(|s| s.id == id)
                .for_each(|s| s.state = SessionState::Revoked);
            Ok(())
        })
    }

    fn exchange_bootstrap(
        &self,
        req: ExchangeRequest,
    ) -> BoxFuture<'_, Result<ExchangeResult, Failure>> {
        Box::pin(async move {
            self.exchanges.lock().unwrap().push(req.clone());
            if let Some(f) = self.exchange_failure.lock().unwrap().take() {
                return Err(f);
            }
            let now = OffsetDateTime::now_utc();
            let session = Session {
                id: SessionId::new(),
                workspace_id: req.workspace_id.unwrap_or_else(WorkspaceId::sentinel),
                state: SessionState::PendingBootstrap,
                principal_identity: "test".to_string(),
                security_epoch: req.epoch,
                token_hash: req.pre_auth_csrf_hash,
                csrf_hash: [0u8; 32],
                idle_expiry: now + req.idle_expiry,
                absolute_expiry: now + req.absolute_expiry,
                first_use_deadline: None,
                first_used_at: None,
                created_at: now,
                last_seen_at: now,
                revoked_at: None,
            };
            Ok(ExchangeResult {
                session,
                replacement: CandidateBinding {
                    candidate_id: SessionId::new().to_string(),
                    generation: 1,
                    digest: [3u8; 32].into(),
                },
            })
        })
    }

    fn prepare_delivery(
        &self,
        req: DeliveryRequest,
    ) -> BoxFuture<'_, Result<DeliveryResult, Failure>> {
        Box::pin(async move {
            if self.delivery_fails.swap(false, Ordering::SeqCst) {
                return Err(Failure::new(FailureClass::AuthorityDenied, "denied", ""));
            }
            let session = Session {
                state: SessionState::DeliveryPending,
                ..exchange_session_placeholder(req.session_id)
            };
            self.deliveries.lock().unwrap().push(session.clone());
            Ok(DeliveryResult {
                delivery_id: DeliveryId::from_session_id(req.session_id),
                session,
            })
        })
    }
}

fn exchange_session_placeholder(id: SessionId) -> Session {
    let now = OffsetDateTime::now_utc();
    Session {
        id,
        workspace_id: WorkspaceId::sentinel(),
        state: SessionState::PendingBootstrap,
        principal_identity: "test".to_string(),
        security_epoch: SecurityEpoch(0),
        token_hash: [0u8; 32],
        csrf_hash: [0u8; 32],
        idle_expiry: now + time::Duration::minutes(30),
        absolute_expiry: now + time::Duration::hours(12),
        first_use_deadline: None,
        first_used_at: None,
        created_at: now,
        last_seen_at: now,
        revoked_at: None,
    }
}

/// In-memory task surface: aggregates keyed by id, mutation calls
/// recorded, failures injectable per method.
pub struct FakeTasks {
    /// `(workspace_id, task_id)` → aggregate.
    pub aggregates: Mutex<HashMap<(WorkspaceId, TaskId), LoadedAggregate>>,
    /// Upstream `reloadAggregate`: when set, every `load_aggregate` call
    /// after the first returns this snapshot — the "meanwhile" re-read
    /// the cancel refusal-notice path performs.
    pub reload_aggregate: Mutex<Option<LoadedAggregate>>,
    /// `load_aggregate` call count (calls ≥ 2 read the reload snapshot).
    pub load_calls: AtomicUsize,
    /// submitted requests, in order.
    pub submit_calls: Mutex<Vec<SubmitTaskRequest>>,
    /// cancel paths taken: "unclaimed" | "request".
    pub cancel_calls: Mutex<Vec<&'static str>>,
    /// retry calls.
    pub retry_calls: Mutex<Vec<TaskId>>,
    /// rerun calls.
    pub rerun_calls: Mutex<Vec<TaskId>>,
    /// `CommandMeta` presented to each mutation entry point, in order.
    pub metas: Mutex<Vec<CommandMeta>>,
    /// injected failures (one-shot each).
    pub submit_fail: Mutex<Option<central_foundation::failure::Failure>>,
    /// injected failures (one-shot each).
    pub mutation_fail: Mutex<Option<central_foundation::failure::Failure>>,
    /// activity events returned by `list_task_events`.
    pub events: Mutex<Vec<central_task::query::TaskEvent>>,
}

impl FakeTasks {
    pub fn new() -> Self {
        Self {
            aggregates: Mutex::new(HashMap::new()),
            reload_aggregate: Mutex::new(None),
            load_calls: AtomicUsize::new(0),
            submit_calls: Mutex::new(Vec::new()),
            cancel_calls: Mutex::new(Vec::new()),
            retry_calls: Mutex::new(Vec::new()),
            rerun_calls: Mutex::new(Vec::new()),
            metas: Mutex::new(Vec::new()),
            submit_fail: Mutex::new(None),
            mutation_fail: Mutex::new(None),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Registers an aggregate (workspace default = sentinel).
    pub fn insert(&self, task: Task, run: Option<Run>) -> LoadedAggregate {
        let loaded = LoadedAggregate {
            aggregate: TaskAggregate {
                task,
                current_run: run,
            },
            task_version: 1,
            run_version: Some(1),
        };
        let ws = loaded.aggregate.task.workspace_id;
        let id = loaded.aggregate.task.id;
        self.aggregates
            .lock()
            .unwrap()
            .insert((ws, id), loaded.clone());
        loaded
    }

    /// A task row with sensible defaults; `status` is the only axis
    /// most tests vary.
    pub fn task(status: TaskStatus) -> Task {
        let now = OffsetDateTime::now_utc();
        let id = TaskId::new();
        Task {
            id,
            workspace_id: WorkspaceId::sentinel(),
            version: 1,
            status,
            current_run_id: None,
            parent_task_id: None,
            last_run_index: 1,
            retry_count: 0,
            retry_eligible_at: None,
            waiting_reason: None,
            failure_reason: String::new(),
            input: r#"{"schema_version":"repository_analysis/v1","instruction":"do it","workspace_root_id":"root"}"#
                .to_string(),
            title: format!("task-{id}"),
            permission_policy: PermissionPolicy::Deny,
            budget: Budget::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// A run bound to `task`.
    pub fn run(task: &Task, status: RunStatus) -> Run {
        let now = OffsetDateTime::now_utc();
        Run {
            id: RunId::new(),
            task_id: task.id,
            workspace_id: task.workspace_id,
            version: 1,
            status,
            index: 1,
            waiting_reason: None,
            failure_reason: String::new(),
            ownership_token: String::new(),
            run_key: None,
            request_fingerprint: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn not_found() -> central_foundation::failure::Failure {
        central_foundation::failure::Failure::not_found("TASK_NOT_FOUND", "not found")
    }
}

impl Default for FakeTasks {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskService for FakeTasks {
    fn list_tasks(
        &self,
        req: central_task::query::TaskListRequest,
    ) -> BoxFuture<'_, Result<TaskListProjection, central_foundation::failure::Failure>> {
        Box::pin(async move {
            let rows = self
                .aggregates
                .lock()
                .unwrap()
                .values()
                .filter(|l| l.aggregate.task.workspace_id == req.workspace_id)
                .map(|l| {
                    let t = &l.aggregate.task;
                    TaskSummary {
                        task_id: t.id,
                        workspace_id: t.workspace_id,
                        status: t.status,
                        current_run_id: t.current_run_id,
                        waiting_reason: t.waiting_reason,
                        retry_count: t.retry_count,
                        title: t.title.clone(),
                        failure_reason: t.failure_reason.clone(),
                        retry_eligible_at: t.retry_eligible_at,
                        updated_at: t.updated_at,
                        created_at: t.created_at,
                    }
                })
                .collect();
            Ok(TaskListProjection {
                tasks: rows,
                next_cursor: None,
            })
        })
    }

    fn task_detail(
        &self,
        req: central_task::query::TaskDetailRequest,
    ) -> BoxFuture<'_, Result<TaskDetailProjection, central_foundation::failure::Failure>> {
        Box::pin(async move {
            let map = self.aggregates.lock().unwrap();
            let Some(l) = map.get(&(req.workspace_id, req.task_id)) else {
                return Err(Self::not_found());
            };
            let t = &l.aggregate.task;
            Ok(TaskDetailProjection {
                task: TaskDetail {
                    task_id: t.id,
                    workspace_id: t.workspace_id,
                    status: t.status,
                    title: t.title.clone(),
                    input: t.input.clone(),
                    current_run_id: t.current_run_id,
                    retry_count: t.retry_count,
                    failure_reason: t.failure_reason.clone(),
                    waiting_reason: t.waiting_reason,
                    updated_at: t.updated_at,
                    created_at: t.created_at,
                    parent_task_id: t.parent_task_id,
                    permission_policy: t.permission_policy,
                    budget: t.budget,
                    required_artifact_id: None,
                    artifacts: Vec::new(),
                    projection_revision: 1,
                    event_revision: 0,
                },
                runs: l
                    .aggregate
                    .current_run
                    .iter()
                    .map(|r| central_task::query::RunSummary {
                        run_id: r.id,
                        task_id: r.task_id,
                        workspace_id: r.workspace_id,
                        status: r.status,
                        index: r.index,
                        waiting_reason: r.waiting_reason,
                        failure_reason: r.failure_reason.clone(),
                        updated_at: r.updated_at,
                        created_at: r.created_at,
                    })
                    .collect(),
                next_run_cursor: None,
            })
        })
    }

    fn list_task_events(
        &self,
        _req: central_task::query::TaskEventLogRequest,
    ) -> BoxFuture<'_, Result<TaskEventLogProjection, central_foundation::failure::Failure>> {
        Box::pin(async move {
            Ok(TaskEventLogProjection {
                events: self.events.lock().unwrap().clone(),
                next_cursor: None,
            })
        })
    }

    fn submit_task(
        &self,
        req: SubmitTaskRequest,
        meta: CommandMeta,
    ) -> BoxFuture<'_, Result<CommitResult, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.metas.lock().unwrap().push(meta);
            self.submit_calls.lock().unwrap().push(req.clone());
            if let Some(f) = self.submit_fail.lock().unwrap().take() {
                return Err(f);
            }
            let mut t = Self::task(TaskStatus::Queued);
            t.workspace_id = req.workspace_id;
            t.title = req.title;
            t.input = req.input;
            Ok(CommitResult {
                task: t,
                runs: Vec::new(),
                events: Vec::new(),
            })
        })
    }

    fn request_cancellation(
        &self,
        _req: RequestCancellationRequest,
        meta: CommandMeta,
    ) -> BoxFuture<'_, Result<CommitResult, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.metas.lock().unwrap().push(meta);
            self.cancel_calls.lock().unwrap().push("request");
            if let Some(f) = self.mutation_fail.lock().unwrap().take() {
                return Err(f);
            }
            Ok(CommitResult {
                task: Self::task(TaskStatus::Cancelling),
                runs: Vec::new(),
                events: Vec::new(),
            })
        })
    }

    fn cancel_unclaimed_task(
        &self,
        _req: CancelUnclaimedTaskRequest,
        meta: CommandMeta,
    ) -> BoxFuture<'_, Result<CommitResult, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.metas.lock().unwrap().push(meta);
            self.cancel_calls.lock().unwrap().push("unclaimed");
            if let Some(f) = self.mutation_fail.lock().unwrap().take() {
                return Err(f);
            }
            Ok(CommitResult {
                task: Self::task(TaskStatus::Cancelled),
                runs: Vec::new(),
                events: Vec::new(),
            })
        })
    }

    fn retry_failed_task(
        &self,
        req: RetryFailedTaskRequest,
        meta: CommandMeta,
    ) -> BoxFuture<'_, Result<CommitResult, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.metas.lock().unwrap().push(meta);
            self.retry_calls
                .lock()
                .unwrap()
                .push(req.input.aggregate.task.id);
            if let Some(f) = self.mutation_fail.lock().unwrap().take() {
                return Err(f);
            }
            Ok(CommitResult {
                task: req.input.aggregate.task,
                runs: Vec::new(),
                events: Vec::new(),
            })
        })
    }

    fn rerun_cancelled_task(
        &self,
        req: RerunCancelledTaskRequest,
        meta: CommandMeta,
    ) -> BoxFuture<'_, Result<CommitResult, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.metas.lock().unwrap().push(meta);
            self.rerun_calls.lock().unwrap().push(req.source.task.id);
            if let Some(f) = self.mutation_fail.lock().unwrap().take() {
                return Err(f);
            }
            Ok(CommitResult {
                task: Self::task(TaskStatus::Queued),
                runs: Vec::new(),
                events: Vec::new(),
            })
        })
    }

    fn load_aggregate(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'_, Result<LoadedAggregate, central_foundation::failure::Failure>> {
        Box::pin(async move {
            // Upstream `fakeTaskService.LoadAggregate`: calls after the
            // first return the `reload_aggregate` snapshot verbatim —
            // the durable "meanwhile" state the refusal-notice re-read
            // observes.
            let n = self.load_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n > 1
                && let Some(reload) = self.reload_aggregate.lock().unwrap().as_ref()
            {
                return Ok(reload.clone());
            }
            self.aggregates
                .lock()
                .unwrap()
                .get(&(workspace_id, task_id))
                .cloned()
                .ok_or_else(Self::not_found)
        })
    }
}

/// A `ByteStream` over a fixed byte body.
pub struct SliceStream {
    data: std::io::Cursor<Vec<u8>>,
}

impl SliceStream {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: std::io::Cursor::new(data.to_vec()),
        }
    }
}

impl ByteStream for SliceStream {
    fn read_chunk<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> central_artifact::port::ByteStreamFuture<
        'a,
        Result<usize, central_foundation::failure::Failure>,
    > {
        Box::pin(async move { std::io::Read::read(&mut self.data, buf).map_err(|_| Self::err()) })
    }

    fn close<'a>(
        &'a mut self,
    ) -> central_artifact::port::ByteStreamFuture<
        'a,
        Result<(), central_foundation::failure::Failure>,
    > {
        Box::pin(async move { Ok(()) })
    }
}

impl SliceStream {
    fn err() -> central_foundation::failure::Failure {
        central_foundation::failure::Failure::invalid("IO", "read failed")
    }
}

/// An artifact delivery gate returning one canned outcome.
pub struct FakeArtifacts {
    /// bytes served on `Allowed`; `None` → `Denied`.
    pub body: Mutex<Option<Vec<u8>>>,
    /// requests received.
    pub calls: Mutex<Vec<DeliverReadyArtifactRequest>>,
    /// artifact id reported on `Allowed`.
    pub artifact_id: ArtifactId,
}

impl FakeArtifacts {
    pub fn new() -> Self {
        Self {
            body: Mutex::new(Some(b"# report\n".to_vec())),
            calls: Mutex::new(Vec::new()),
            artifact_id: ArtifactId::new(),
        }
    }
}

impl Default for FakeArtifacts {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactDelivery for FakeArtifacts {
    fn deliver_ready_artifact(
        &self,
        request: DeliverReadyArtifactRequest,
    ) -> BoxFuture<'_, Result<DeliverArtifactOutcome, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(request);
            let body = self.body.lock().unwrap().clone();
            match body {
                Some(b) => Ok(DeliverArtifactOutcome::Allowed {
                    body: Box::new(SliceStream::new(&b)),
                    info: central_artifact::port::ObjectInfo {
                        size: b.len() as i64,
                        etag: String::new(),
                        version: String::new(),
                    },
                    artifact: Box::new(canned_artifact(self.artifact_id, &request)),
                }),
                None => Ok(DeliverArtifactOutcome::Denied {
                    reason: "not found",
                }),
            }
        })
    }
}

fn canned_artifact(
    id: ArtifactId,
    req: &DeliverReadyArtifactRequest,
) -> central_artifact::domain::Artifact {
    central_artifact::domain::Artifact {
        workspace_id: req.workspace_id,
        artifact_id: id,
        state: central_artifact::domain::State::Ready,
        version: 1,
        staging_generation: central_foundation::identity::StagingGeneration::new(),
        staging_key: String::new(),
        content_generation: None,
        ready_key: "v1/ready/x".to_string(),
        limits: central_artifact::domain::Limits::default(),
        verified_size: 9,
        verified_checksum: [0u8; 32],
        ready_object_version: String::new(),
        task_id: TaskId::new(),
        run_id: RunId::new(),
        step_id: central_foundation::identity::StepId::new(),
        step_attempt_id: central_foundation::identity::StepAttemptId::new(),
        tool_call_attempt_id: None,
        producer_id: "p".to_string(),
        required_role: "report".to_string(),
        sensitivity: central_artifact::domain::Sensitivity::Restricted,
        disposition: central_artifact::domain::Disposition::Attachment,
        delete_intent_at: None,
        deleted_at: None,
    }
}

/// A claimability gate with a single switch.
pub struct FakeClaim {
    /// the answer; `false` = restart barrier active.
    pub claimable: AtomicBool,
    /// call count.
    pub calls: AtomicUsize,
}

impl FakeClaim {
    pub fn yes() -> Self {
        Self {
            claimable: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        }
    }
}

impl RecoveryClaimability for FakeClaim {
    fn recovery_claimability(
        &self,
        _scope: TrustedScope,
        _task_id: TaskId,
        _run_id: RunId,
    ) -> BoxFuture<
        '_,
        Result<central_execution::domain::Claimability, central_foundation::failure::Failure>,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(central_execution::domain::Claimability {
                claimable: self.claimable.load(Ordering::SeqCst),
                epoch_generation: 1,
                reason: "RECOVERY_RESTART_BARRIER".to_string(),
            })
        })
    }
}

/// A minimal harness operator — all reads answer with configured
/// values; decisions/resolves record calls.
pub struct FakeHarness {
    /// `resolvable` answer.
    pub resolvable: AtomicBool,
    /// `prepared_settleable` answer.
    pub prepared_settleable: AtomicBool,
    /// resolve calls.
    pub resolves: Mutex<Vec<HarnessResolveRequest>>,
    /// decisions received.
    pub decisions: Mutex<Vec<HarnessPermissionDecision>>,
    /// injected failure on the next resolve/resume/decide.
    pub op_fail: Mutex<Option<central_foundation::failure::Failure>>,
    /// `retry_state` call count — a gate that must not run for a
    /// non-retry-eligible Task proves itself here.
    pub retry_state_calls: AtomicUsize,
    /// `retry_state` returns an infrastructure failure when set.
    pub retry_state_fails: AtomicBool,
    /// `retry_state` reports the cost cap reached when set.
    pub retry_blocked: AtomicBool,
}

impl FakeHarness {
    pub fn new() -> Self {
        Self {
            resolvable: AtomicBool::new(true),
            prepared_settleable: AtomicBool::new(false),
            resolves: Mutex::new(Vec::new()),
            decisions: Mutex::new(Vec::new()),
            op_fail: Mutex::new(None),
            retry_state_calls: AtomicUsize::new(0),
            retry_state_fails: AtomicBool::new(false),
            retry_blocked: AtomicBool::new(false),
        }
    }

    fn take_fail(&self) -> Option<central_foundation::failure::Failure> {
        self.op_fail.lock().unwrap().take()
    }

    fn infra_err() -> central_foundation::failure::Failure {
        central_foundation::failure::Failure::invalid("HARNESS", "operator error")
    }
}

impl Default for FakeHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl HarnessOperator for FakeHarness {
    fn banner(&self, _w: WorkspaceId) -> BoxFuture<'_, HarnessBanner> {
        Box::pin(async move { HarnessBanner::default() })
    }
    fn resolvable(
        &self,
        _w: WorkspaceId,
        _t: TaskId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<bool, central_foundation::failure::Failure>> {
        Box::pin(async move { Ok(self.resolvable.load(Ordering::SeqCst)) })
    }
    fn resolve_failed(
        &self,
        req: HarnessResolveRequest,
    ) -> BoxFuture<'_, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.resolves.lock().unwrap().push(req);
            self.take_fail().map_or(Ok(()), Err)
        })
    }
    fn resolve_cancelled(
        &self,
        req: HarnessResolveRequest,
    ) -> BoxFuture<'_, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.resolves.lock().unwrap().push(req);
            self.take_fail().map_or(Ok(()), Err)
        })
    }
    fn prepared_settleable(
        &self,
        _w: WorkspaceId,
        _t: TaskId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<bool, central_foundation::failure::Failure>> {
        Box::pin(async move { Ok(self.prepared_settleable.load(Ordering::SeqCst)) })
    }
    fn settle_prepared(
        &self,
        req: HarnessResolveRequest,
    ) -> BoxFuture<'_, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.resolves.lock().unwrap().push(req);
            self.take_fail().map_or(Ok(()), Err)
        })
    }
    fn resume_state(
        &self,
        _w: WorkspaceId,
        _t: TaskId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<HarnessResumeState, central_foundation::failure::Failure>> {
        Box::pin(async move {
            Ok(HarnessResumeState {
                eligible: true,
                blocked: HarnessResumeBlock::None,
            })
        })
    }
    fn resume(
        &self,
        req: HarnessResolveRequest,
    ) -> BoxFuture<'_, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.resolves.lock().unwrap().push(req);
            self.take_fail().map_or(Ok(()), Err)
        })
    }
    fn rerun_offered(
        &self,
        _w: WorkspaceId,
        _t: TaskId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<bool, central_foundation::failure::Failure>> {
        Box::pin(async move { Ok(true) })
    }
    fn resolve_rerun(
        &self,
        req: HarnessResolveRequest,
    ) -> BoxFuture<'_, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.resolves.lock().unwrap().push(req);
            self.take_fail().map_or(Ok(()), Err)
        })
    }
    fn permission_panel(
        &self,
        _w: WorkspaceId,
        _t: TaskId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<Option<HarnessPermissionPanel>, central_foundation::failure::Failure>>
    {
        Box::pin(async move { Ok(None) })
    }
    fn permission_history(
        &self,
        _w: WorkspaceId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<Vec<HarnessPermissionRecord>, central_foundation::failure::Failure>>
    {
        Box::pin(async move { Ok(Vec::new()) })
    }
    fn decide_permission(
        &self,
        req: HarnessPermissionDecision,
    ) -> BoxFuture<'_, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.decisions.lock().unwrap().push(req);
            self.take_fail().map_or(Ok(()), Err)
        })
    }
    fn retry_state(
        &self,
        _w: WorkspaceId,
        _t: TaskId,
    ) -> BoxFuture<'_, Result<HarnessRetryState, central_foundation::failure::Failure>> {
        Box::pin(async move {
            self.retry_state_calls.fetch_add(1, Ordering::SeqCst);
            if self.retry_state_fails.load(Ordering::SeqCst) {
                return Err(Self::infra_err());
            }
            Ok(HarnessRetryState {
                blocked: self.retry_blocked.load(Ordering::SeqCst),
                ..HarnessRetryState::default()
            })
        })
    }
    fn run_budget(
        &self,
        _w: WorkspaceId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<Option<HarnessRunBudget>, central_foundation::failure::Failure>> {
        Box::pin(async move { Ok(None) })
    }
    fn permission_policies_enabled(&self) -> bool {
        false
    }
    fn harness_backend(&self) -> &'static str {
        "claude"
    }
    fn budget_defaults(&self) -> HarnessBudgetDefaults {
        HarnessBudgetDefaults::default()
    }
}
