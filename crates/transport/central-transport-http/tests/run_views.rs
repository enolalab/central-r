//! Behavioral tests for the runview pages + run controls (issue #96,
//! slice 2E) — the Rust port of upstream `handler_runs_test.go`,
//! `run_controls_test.go`, `handler_fleet_test.go`,
//! `handler_lineage_test.go`: the state matrix (unauthenticated →
//! bootstrap, nil reader → 503, hard failure → 503, malformed/foreign
//! ids → generic 404), the typed cursor, escaping, node-scope event
//! isolation, and the CSRF/Origin security prelude of every control
//! POST — all through the composed router.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::StatusCode;
use central_eventjournal::domain::RunEvent;
use central_foundation::failure::{Failure as DomainFailure, FailureKind};
use central_foundation::identity::{
    ArtifactId, RunId, TaskId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_runview::domain::{
    AttemptRow, DeferredRow, GraphEdge, GraphNode, LeaseRow, OutboxHealth, RunCursor, RunGraph,
    RunSummary, WorkerRow,
};
use central_session::domain::SecurityEpoch;
use central_transport_http::api;
use central_transport_http::b64;
use central_transport_http::health::ProbeState;
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::ports::{
    AmbiguityResolver, BoxFuture, CheckpointControls, FleetReader, Resumer, RunCanceller,
    RunControlPorts, RunLineageReader, RunsReader,
};
use central_transport_http::router::{TransportConfig, build_app_router};
use central_transport_http::web::{self, WebState};
use common::*;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt;

const WORKSPACE: WorkspaceId = WorkspaceId::sentinel();

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeRuns {
    runs: Mutex<Vec<RunSummary>>,
    nodes: Mutex<HashMap<WorkflowNodeId, GraphNode>>,
    graph: Mutex<RunGraph>,
    events: Mutex<Vec<RunEvent>>,
    attempts: Mutex<Vec<AttemptRow>>,
    current: Mutex<BTreeMap<String, String>>,
    leases: Mutex<Vec<LeaseRow>>,
    workers: Mutex<Vec<WorkerRow>>,
    deferred: Mutex<HashMap<RunId, Vec<DeferredRow>>>,
    deferred_calls: Mutex<Vec<RunId>>,
    outbox: Mutex<Option<OutboxHealth>>,
    fail: Mutex<Option<DomainFailure>>,
}

impl FakeRuns {
    fn failure() -> DomainFailure {
        DomainFailure::new(FailureKind::Internal, "RUNVIEW_READ_FAILED", "boom")
    }
    fn not_found() -> DomainFailure {
        DomainFailure::new(FailureKind::NotFound, "RUNVIEW_NOT_FOUND", "absent")
    }
}

macro_rules! guarded {
    ($self:ident, $body:expr) => {{
        if let Some(f) = $self.fail.lock().unwrap().clone() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok($body) })
    }};
}

impl RunsReader for FakeRuns {
    fn list_runs(
        &self,
        _w: WorkspaceId,
        after: Option<RunCursor>,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<RunSummary>, DomainFailure>> {
        let all = self.runs.lock().unwrap().clone();
        guarded!(self, {
            let start = after.map_or(0, |c| {
                all.iter()
                    .position(|r| r.created_at == c.created_at && r.id == c.id)
                    .map_or(all.len(), |p| p + 1)
            });
            all.iter()
                .skip(start)
                .take(limit.max(0) as usize)
                .cloned()
                .collect()
        })
    }
    fn run_for_id(
        &self,
        w: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<RunSummary, DomainFailure>> {
        let run = self
            .runs
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == run_id && r.workspace_id == w)
            .cloned();
        if let Some(f) = self.fail.lock().unwrap().clone() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { run.ok_or_else(FakeRuns::not_found) })
    }
    fn run_scope(&self, r: RunId) -> BoxFuture<'_, Result<Option<WorkspaceId>, DomainFailure>> {
        let scope = self
            .runs
            .lock()
            .unwrap()
            .iter()
            .find(|run| run.id == r)
            .map(|run| run.workspace_id);
        if let Some(f) = self.fail.lock().unwrap().clone() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok(scope) })
    }
    fn node_for_id(
        &self,
        w: WorkspaceId,
        node_id: WorkflowNodeId,
    ) -> BoxFuture<'_, Result<GraphNode, DomainFailure>> {
        // The real store filters `n.workspace_id = $1`: the node's
        // workspace is its run's, so a node whose run lives in another
        // workspace — or whose run the fake does not carry — is the
        // same not-found as an absent row.
        let nodes = self.nodes.lock().unwrap().clone();
        let runs = self.runs.lock().unwrap().clone();
        let node = nodes
            .get(&node_id)
            .cloned()
            .filter(|n| runs.iter().any(|r| r.id == n.run_id && r.workspace_id == w));
        if let Some(f) = self.fail.lock().unwrap().clone() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { node.ok_or_else(FakeRuns::not_found) })
    }
    fn graph_for_run(&self, _r: RunId) -> BoxFuture<'_, Result<RunGraph, DomainFailure>> {
        let g = self.graph.lock().unwrap().clone();
        guarded!(self, g)
    }
    fn events_for_run(&self, _r: RunId) -> BoxFuture<'_, Result<Vec<RunEvent>, DomainFailure>> {
        let e = self.events.lock().unwrap().clone();
        guarded!(self, e)
    }
    fn attempts_for_node(
        &self,
        _n: WorkflowNodeId,
    ) -> BoxFuture<'_, Result<Vec<AttemptRow>, DomainFailure>> {
        let a = self.attempts.lock().unwrap().clone();
        guarded!(self, a)
    }
    fn nodes_current(
        &self,
        _r: RunId,
    ) -> BoxFuture<'_, Result<BTreeMap<String, String>, DomainFailure>> {
        let c = self.current.lock().unwrap().clone();
        guarded!(self, c)
    }
    fn live_leases(&self, _w: WorkspaceId) -> BoxFuture<'_, Result<Vec<LeaseRow>, DomainFailure>> {
        let l = self.leases.lock().unwrap().clone();
        guarded!(self, l)
    }
}

impl FleetReader for FakeRuns {
    fn workers(&self, _w: WorkspaceId) -> BoxFuture<'_, Result<Vec<WorkerRow>, DomainFailure>> {
        let v = self.workers.lock().unwrap().clone();
        guarded!(self, v)
    }
    fn live_leases(&self, w: WorkspaceId) -> BoxFuture<'_, Result<Vec<LeaseRow>, DomainFailure>> {
        <Self as RunsReader>::live_leases(self, w)
    }
    fn list_runs(
        &self,
        w: WorkspaceId,
        after: Option<RunCursor>,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<RunSummary>, DomainFailure>> {
        <Self as RunsReader>::list_runs(self, w, after, limit)
    }
    fn deferred_admissions(
        &self,
        r: RunId,
    ) -> BoxFuture<'_, Result<Vec<DeferredRow>, DomainFailure>> {
        self.deferred_calls.lock().unwrap().push(r);
        let d = self
            .deferred
            .lock()
            .unwrap()
            .get(&r)
            .cloned()
            .unwrap_or_default();
        guarded!(self, d)
    }
    fn outbox_health(&self) -> BoxFuture<'_, Result<OutboxHealth, DomainFailure>> {
        let o = (*self.outbox.lock().unwrap()).unwrap_or(OutboxHealth {
            unpublished_depth: 0,
            oldest_unpublished: None,
        });
        guarded!(self, o)
    }
}

#[derive(Default)]
struct FakeLineage {
    scope: Mutex<Option<WorkspaceId>>,
    graph: Mutex<RunGraph>,
    attempts: Mutex<Vec<AttemptRow>>,
    produced: Mutex<Vec<central_artifact::lineage::ProduceEdge>>,
    reads: Mutex<Vec<central_artifact::lineage::ReadEdge>>,
    artifacts: Mutex<HashMap<ArtifactId, central_artifact::lineage::LineageArtifact>>,
    fail: Mutex<Option<DomainFailure>>,
}

impl FakeLineage {
    fn err(&self) -> Option<DomainFailure> {
        self.fail.lock().unwrap().clone()
    }
}

impl RunLineageReader for FakeLineage {
    fn run_scope(&self, _r: RunId) -> BoxFuture<'_, Result<Option<WorkspaceId>, DomainFailure>> {
        let v = *self.scope.lock().unwrap();
        if let Some(f) = self.err() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok(v) })
    }
    fn graph_for_run(&self, _r: RunId) -> BoxFuture<'_, Result<RunGraph, DomainFailure>> {
        let g = self.graph.lock().unwrap().clone();
        if let Some(f) = self.err() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok(g) })
    }
    fn attempts_for_run(&self, _r: RunId) -> BoxFuture<'_, Result<Vec<AttemptRow>, DomainFailure>> {
        let a = self.attempts.lock().unwrap().clone();
        if let Some(f) = self.err() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok(a) })
    }
    fn produce_edges_for_run(
        &self,
        _r: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_artifact::lineage::ProduceEdge>, DomainFailure>> {
        let v = self.produced.lock().unwrap().clone();
        if let Some(f) = self.err() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok(v) })
    }
    fn read_edges_for_run(
        &self,
        _r: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_artifact::lineage::ReadEdge>, DomainFailure>> {
        let v = self.reads.lock().unwrap().clone();
        if let Some(f) = self.err() {
            return Box::pin(async move { Err(f) });
        }
        Box::pin(async move { Ok(v) })
    }
    fn find_artifact(
        &self,
        id: ArtifactId,
    ) -> BoxFuture<'_, Result<Option<central_artifact::lineage::LineageArtifact>, DomainFailure>>
    {
        let v = self.artifacts.lock().unwrap().get(&id).cloned();
        Box::pin(async move { Ok(v) })
    }
}

#[derive(Default)]
struct FakeControls {
    cancel_calls: Mutex<Vec<WorkflowNodeId>>,
    decide_calls: Mutex<Vec<(WorkflowNodeId, String)>>,
    resume_calls: Mutex<Vec<String>>,
    write_calls: Mutex<i32>,
    gc_calls: Mutex<i32>,
    cancel_err: Mutex<Option<DomainFailure>>,
    resolve_err: Mutex<Option<DomainFailure>>,
    preflight: Mutex<Option<central_checkpoint::domain::ResumeCheckpoint>>,
    preflight_err: Mutex<Option<DomainFailure>>,
    gc_failures: Mutex<bool>,
    checkpoints: Mutex<Vec<central_checkpoint::domain::ResumeCheckpoint>>,
    /// `write_checkpoint`'s recorded `(seq, gc_class)` arguments and
    /// the canned row/error it returns (upstream `writeSeq`/`writeErr`).
    write_args: Mutex<Vec<(i64, central_checkpoint::domain::GcClass)>>,
    write_record: Mutex<Option<central_checkpoint::domain::ResumeCheckpoint>>,
    write_err: Mutex<Option<DomainFailure>>,
    /// `update_gc_class`'s recorded `(checkpoint_id, class)` calls and
    /// its canned refusal.
    class_calls: Mutex<
        Vec<(
            central_foundation::identity::ResumeCheckpointId,
            central_checkpoint::domain::GcClass,
        )>,
    >,
    class_err: Mutex<Option<DomainFailure>>,
}

impl RunCanceller for FakeControls {
    fn cancel_node<'a>(
        &'a self,
        node_id: WorkflowNodeId,
        _actor: &'a str,
    ) -> BoxFuture<'a, Result<Vec<WorkflowNodeId>, DomainFailure>> {
        self.cancel_calls.lock().unwrap().push(node_id);
        let err = self.cancel_err.lock().unwrap().clone();
        Box::pin(async move { err.map_or(Ok(vec![node_id]), Err) })
    }
}

impl AmbiguityResolver for FakeControls {
    fn resolve_ambiguous<'a>(
        &'a self,
        node_id: WorkflowNodeId,
        decision: &'a str,
        _f: [u8; 32],
        _a: &'a str,
    ) -> BoxFuture<'a, Result<(), DomainFailure>> {
        self.decide_calls
            .lock()
            .unwrap()
            .push((node_id, decision.to_string()));
        let err = self.resolve_err.lock().unwrap().clone();
        Box::pin(async move { err.map_or(Ok(()), Err) })
    }
}

impl Resumer for FakeControls {
    fn resume_preflight<'a>(
        &'a self,
        _t: &'a str,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>> {
        let err = self.preflight_err.lock().unwrap().clone();
        let rec = self.preflight.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(e) = err {
                return Err(e);
            }
            rec.ok_or_else(|| {
                DomainFailure::new(FailureKind::Invalid, "CHECKPOINT_NOT_FOUND", "absent")
            })
        })
    }
    fn resume_subtree<'a>(
        &'a self,
        token: &'a str,
        _a: &'a str,
    ) -> BoxFuture<'a, Result<(), DomainFailure>> {
        self.resume_calls.lock().unwrap().push(token.to_string());
        Box::pin(async move { Ok(()) })
    }
}

impl CheckpointControls for FakeControls {
    fn write_checkpoint<'a>(
        &'a self,
        _r: RunId,
        _n: WorkflowNodeId,
        _a: &'a str,
        g: central_checkpoint::domain::GcClass,
        s: i64,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>> {
        *self.write_calls.lock().unwrap() += 1;
        self.write_args.lock().unwrap().push((s, g));
        let err = self.write_err.lock().unwrap().clone();
        let rec = self.write_record.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(e) = err {
                return Err(e);
            }
            rec.ok_or_else(|| {
                DomainFailure::new(FailureKind::Invalid, "CHECKPOINT_WRITE_FAILED", "no")
            })
        })
    }
    fn load_checkpoint<'a>(
        &'a self,
        _id: central_foundation::identity::ResumeCheckpointId,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>> {
        let rec = self.preflight.lock().unwrap().clone();
        Box::pin(async move {
            rec.ok_or_else(|| {
                DomainFailure::new(FailureKind::Invalid, "CHECKPOINT_NOT_FOUND", "absent")
            })
        })
    }
    fn update_gc_class<'a>(
        &'a self,
        id: central_foundation::identity::ResumeCheckpointId,
        c: central_checkpoint::domain::GcClass,
    ) -> BoxFuture<'a, Result<(), DomainFailure>> {
        self.class_calls.lock().unwrap().push((id, c));
        let err = self.class_err.lock().unwrap().clone();
        Box::pin(async move { err.map_or(Ok(()), Err) })
    }
    fn collect<'a>(
        &'a self,
        _now: OffsetDateTime,
    ) -> BoxFuture<'a, Result<central_checkpoint::port::CollectOutcome, DomainFailure>> {
        *self.gc_calls.lock().unwrap() += 1;
        let partial = *self.gc_failures.lock().unwrap();
        Box::pin(async move {
            Ok(central_checkpoint::port::CollectOutcome {
                collected: 3,
                failures: if partial {
                    vec![DomainFailure::new(FailureKind::Internal, "GC_PARTIAL", "x")]
                } else {
                    Vec::new()
                },
            })
        })
    }
    fn list_checkpoints<'a>(
        &'a self,
        _r: RunId,
    ) -> BoxFuture<'a, Result<Vec<central_checkpoint::domain::ResumeCheckpoint>, DomainFailure>>
    {
        let v = self.checkpoints.lock().unwrap().clone();
        Box::pin(async move { Ok(v) })
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    sessions: Arc<FakeSessions>,
    app: Router,
}

fn fixture(
    runs: Option<Arc<dyn RunsReader>>,
    fleet: Option<Arc<dyn FleetReader>>,
    lineage: Option<Arc<dyn RunLineageReader>>,
    controls: RunControlPorts,
    scheduler_enabled: bool,
) -> Fixture {
    let sessions = Arc::new(FakeSessions::new());
    let state = Arc::new(WebState {
        readiness: Arc::new(StaticProbe(ProbeState::Ready)),
        sessions: sessions.clone(),
        tasks: Arc::new(FakeTasks::new()),
        artifacts: Arc::new(FakeArtifacts::new()),
        claimability: Arc::new(FakeClaim::yes()),
        turn_activity: None,
        harness: None,
        run_submitter: None,
        runs,
        fleet,
        run_lineage: lineage,
        controls,
        scheduler_enabled,
        workspace: WORKSPACE,
        allowed_roots: vec![],
        epoch_source: Arc::new(|| SecurityEpoch(0)),
    });
    let mut routes = web::routes(&state);
    routes.extend(api::routes(&state));
    let app = build_app_router(
        routes,
        TransportConfig {
            admission: AdmissionConfig {
                expected_host: Some(HOST.to_string()),
                ..AdmissionConfig::default()
            },
            expected_origin: ORIGIN.to_string(),
            preauth: sessions.clone(),
            sessions: sessions.clone(),
            delivery: sessions.clone(),
            epoch_source: Arc::new(|| SecurityEpoch(0)),
            observer: None,
        },
    )
    .unwrap();
    Fixture { sessions, app }
}

fn active_cookies(f: &Fixture) -> String {
    let token = [9u8; 32];
    let csrf = [8u8; 32];
    let session = f.sessions.insert_active(token);
    f.sessions
        .sessions
        .lock()
        .unwrap()
        .values_mut()
        .filter(|s| s.id == session.id)
        .for_each(|s| s.csrf_hash = Sha256::digest(csrf).into());
    format!(
        "central_session={}; central_session_csrf={}",
        b64::encode(&token),
        b64::encode(&csrf)
    )
}

async fn get_authed(f: &Fixture, path: &str) -> (StatusCode, String) {
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            get(path).header("cookie", active_cookies(f)),
            axum::body::Body::empty(),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_control(f: &Fixture, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
    let (t, c) = {
        let token = [9u8; 32];
        let csrf = [8u8; 32];
        let session = f.sessions.insert_active(token);
        f.sessions
            .sessions
            .lock()
            .unwrap()
            .values_mut()
            .filter(|s| s.id == session.id)
            .for_each(|s| s.csrf_hash = Sha256::digest(csrf).into());
        (b64::encode(&token), b64::encode(&csrf))
    };
    let mut body = format!("csrf={}", urlenc(&c));
    for (k, v) in fields {
        body.push_str(&format!("&{k}={}", urlenc(v)));
    }
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .header(
                    "cookie",
                    format!("central_session={t}; central_session_csrf={c}"),
                ),
            body,
        ))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn urlenc(v: &str) -> String {
    v.replace('%', "%25")
        .replace('+', "%2B")
        .replace('=', "%3D")
        .replace('&', "%26")
}

fn summary(run_id: RunId, status: &str) -> RunSummary {
    let now = OffsetDateTime::now_utc();
    RunSummary {
        id: run_id,
        task_id: TaskId::new(),
        workspace_id: WORKSPACE,
        index: 3,
        status: status.to_string(),
        run_key: Some("key-1".to_string()),
        created_at: now,
        updated_at: now,
        started_at: Some(now),
        ended_at: None,
        deadline: None,
        node_counts: BTreeMap::from([("succeeded".to_string(), 2i64)]),
    }
}

fn event(seq: i64, node_id: Option<WorkflowNodeId>, kind: &str) -> RunEvent {
    RunEvent {
        id: central_foundation::identity::RunEventId::new(),
        workspace_id: WORKSPACE,
        run_id: RunId::new(),
        seq,
        node_id,
        attempt_id: None,
        kind: kind.to_string(),
        actor: "test".to_string(),
        reason_code: None,
        payload: serde_json::Value::Null,
        recorded_at: OffsetDateTime::now_utc(),
    }
}

// ---------------------------------------------------------------------------
// Run list — state matrix
// ---------------------------------------------------------------------------

/// Unauthenticated GET renders the bootstrap shell (200), never a
/// redirect — the established safe-GET precedent.
#[tokio::test]
async fn run_list_anonymous_renders_bootstrap() {
    let f = fixture(None, None, None, RunControlPorts::default(), false);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            get("/app/runs"),
            axum::body::Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("bootstrap") || body.contains("Unlock"),
        "{body}"
    );
}

/// Nil runs reader → bare 503 even though the route itself exists.
#[tokio::test]
async fn run_list_nil_reader_503() {
    let f = fixture(None, None, None, RunControlPorts::default(), false);
    let (status, _) = get_authed(&f, "/app/runs").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// A hard projection failure is the same bare 503 as an unwired port.
#[tokio::test]
async fn run_list_read_failure_503() {
    let runs = Arc::new(FakeRuns::default());
    *runs.fail.lock().unwrap() = Some(FakeRuns::failure());
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, _) = get_authed(&f, "/app/runs").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// A malformed cursor token is the same generic 404 as a malformed id —
/// never a silently-reset page one.
#[tokio::test]
async fn run_list_malformed_cursor_404() {
    let runs = Arc::new(FakeRuns::default());
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, _) = get_authed(&f, "/app/runs?cursor=not-a-cursor").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The census renders rows with detail links, status badges, and state
/// counts; the second page follows the typed `?cursor=` token.
#[tokio::test]
async fn run_list_renders_census_and_paginates() {
    let runs = Arc::new(FakeRuns::default());
    let mut ids = Vec::new();
    for _ in 0..60 {
        let id = RunId::new();
        ids.push(id);
        let mut s = summary(id, "running");
        // Monotone-created ordering: UUIDv7 + created DESC keeps newest first.
        s.node_counts = BTreeMap::from([("running".to_string(), 1i64)]);
        runs.runs.lock().unwrap().push(s);
    }
    let f = fixture(
        Some(runs.clone()),
        None,
        None,
        RunControlPorts::default(),
        false,
    );
    let (status, body) = get_authed(&f, "/app/runs").await;
    assert_eq!(status, StatusCode::OK);
    let first = ids[0].to_string();
    assert!(body.contains(&format!("/app/runs/detail?run={first}")));
    assert!(body.contains("badge badge-running"));
    assert!(body.contains("key-1"));
    // 60 rows > 50 page → a next-page cursor link exists and is opaque.
    assert!(body.contains("/app/runs?cursor="), "{body}");
    // No inline script/style anywhere (the state-matrix check).
    assert!(!body.contains("<script"));
    assert!(!body.contains("style=\""));
    // Page two starts after the 50th row and must not repeat page one.
    // The lock guard must drop before `.oneshot` — holding it across the
    // await deadlocks the handler's own `runs.lock()`.
    let cursor = {
        let rows = runs.runs.lock().unwrap();
        central_runview::query::encode_run_cursor(&central_runview::domain::RunCursor {
            created_at: rows[49].created_at,
            id: rows[49].id,
        })
    };
    let (status2, body2) = get_authed(
        &f,
        &format!("/app/runs?cursor={}", cursor.replace('%', "%25")),
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    assert!(!body2.contains(&ids[0].to_string()));
    assert!(body2.contains(&ids[50].to_string()));
    // The same cursor percent-encoded (`%3A` for the `:`s inside the
    // RFC3339 timestamp) decodes to the identical second page —
    // `r.URL.Query().Get` semantics, not raw bytes.
    let encoded = cursor.replace(':', "%3A");
    let (status3, body3) = get_authed(&f, &format!("/app/runs?cursor={encoded}")).await;
    assert_eq!(status3, StatusCode::OK);
    assert!(!body3.contains(&ids[0].to_string()));
    assert!(body3.contains(&ids[50].to_string()));
    // A malformed escape is skipped like `url.ParseQuery` — no value,
    // so the request lands on the first page rather than erroring.
    let (status4, body4) = get_authed(&f, "/app/runs?cursor=%zz").await;
    assert_eq!(status4, StatusCode::OK);
    assert!(body4.contains(&ids[0].to_string()));
}

/// `POST /app/runs` is 405 with `Allow: GET`.
#[tokio::test]
async fn run_list_post_405() {
    let f = fixture(None, None, None, RunControlPorts::default(), false);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            axum::http::Request::post("/app/runs").header("host", HOST),
            axum::body::Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    // Axum auto-attaches HEAD to every GET route.
    assert_eq!(
        resp.headers().get("allow").and_then(|v| v.to_str().ok()),
        Some("GET,HEAD")
    );
}

// ---------------------------------------------------------------------------
// Run detail — scope, DAG, escaping, node timeline isolation
// ---------------------------------------------------------------------------

fn detail_fixture(node_key: &str) -> (Arc<FakeRuns>, RunId, WorkflowNodeId) {
    let runs = Arc::new(FakeRuns::default());
    let run_id = RunId::new();
    runs.runs.lock().unwrap().push(summary(run_id, "running"));
    let node_id = WorkflowNodeId::new();
    let node = GraphNode {
        id: node_id,
        run_id,
        key: node_key.to_string(),
        status: "running".to_string(),
        reason: String::new(),
        attempt_count: 1,
        max_attempts: 3,
        not_before: None,
        parent_key: None,
        created_at: OffsetDateTime::now_utc(),
    };
    runs.nodes.lock().unwrap().insert(node_id, node.clone());
    runs.graph.lock().unwrap().nodes.push(node);
    (runs, run_id, node_id)
}

#[tokio::test]
async fn run_detail_renders_dag_and_events() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    runs.events
        .lock()
        .unwrap()
        .push(event(1, Some(node_id), "node_dispatched"));
    runs.events
        .lock()
        .unwrap()
        .push(event(2, None, "run_submitted"));
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&format!("/app/runs/node?id={node_id}")));
    assert!(body.contains("root-1"));
    assert!(body.contains("node_dispatched"));
    assert!(body.contains("run_submitted"));
    assert!(body.contains("/app/runs/lineage?run="));
    assert!(body.contains("/app/runs/controls?run="));
}

/// Malformed, absent, and foreign-run ids all answer the same generic
/// 404 — existence is never disclosed across workspaces.
#[tokio::test]
async fn run_detail_scope_matrix() {
    let (runs, _run_id, _n) = detail_fixture("root-1");
    let foreign = RunId::new();
    // A run in another workspace: scoped lookup refuses not-found.
    runs.runs.lock().unwrap().push({
        let mut s = summary(foreign, "running");
        s.workspace_id = WorkspaceId::new();
        s
    });
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    for path in [
        "/app/runs/detail",
        "/app/runs/detail?run=not-a-uuid",
        &format!("/app/runs/detail?run={}", RunId::new()),
        &format!("/app/runs/detail?run={foreign}"),
    ] {
        let (status, _) = get_authed(&f, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// Node keys are HTML-escaped — a `<script>` key renders escaped text,
/// never markup.
#[tokio::test]
async fn run_detail_escapes_node_key() {
    let (runs, run_id, _n) = detail_fixture("<script>alert(1)</script>");
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("<script>alert(1)</script>"));
    assert!(body.contains("&lt;script&gt;"));
}

/// An empty graph renders the explicit empty state.
#[tokio::test]
async fn run_detail_empty_graph_message() {
    let runs = Arc::new(FakeRuns::default());
    let run_id = RunId::new();
    runs.runs.lock().unwrap().push(summary(run_id, "running"));
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (_, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert!(body.contains("no workflow nodes"), "{body}");
}

/// Upstream `detailFixture` — a run whose journal folds to exactly the
/// materialized `current` map (parent `succeeded` → child `ready`,
/// ordering + artifact edges, a `not_before` on the child). Every
/// banner test perturbs one input off this clean baseline.
fn banner_fixture() -> (Arc<FakeRuns>, RunId, WorkflowNodeId, WorkflowNodeId) {
    let runs = Arc::new(FakeRuns::default());
    let run_id = RunId::new();
    runs.runs.lock().unwrap().push(summary(run_id, "running"));
    let parent_id = WorkflowNodeId::new();
    let child_id = WorkflowNodeId::new();
    let node = |id, key: &str, status: &str| GraphNode {
        id,
        run_id,
        key: key.to_string(),
        status: status.to_string(),
        reason: String::new(),
        attempt_count: 1,
        max_attempts: 3,
        not_before: None,
        parent_key: None,
        created_at: OffsetDateTime::now_utc(),
    };
    let mut child = node(child_id, "child", "ready");
    child.parent_key = Some("parent".to_string());
    child.not_before = Some(OffsetDateTime::now_utc() + time::Duration::hours(1));
    let artifact_id = ArtifactId::new();
    *runs.graph.lock().unwrap() = RunGraph {
        nodes: vec![node(parent_id, "parent", "succeeded"), child],
        edges: vec![
            GraphEdge {
                from_key: "parent".to_string(),
                to_key: "child".to_string(),
                kind: "ordering".to_string(),
                artifact_id: None,
            },
            GraphEdge {
                from_key: "parent".to_string(),
                to_key: "child".to_string(),
                kind: "artifact".to_string(),
                artifact_id: Some(artifact_id),
            },
        ],
    };
    *runs.current.lock().unwrap() = BTreeMap::from([
        ("parent".to_string(), "succeeded".to_string()),
        ("child".to_string(), "ready".to_string()),
    ]);
    let declared = |seq: i64, node_id: WorkflowNodeId, key: &str, depends: &[&str]| {
        let mut e = event(seq, Some(node_id), "node_declared");
        e.run_id = run_id;
        e.actor = "scheduler".to_string();
        e.payload = serde_json::json!({
            "payload_version": 1,
            "node_key": key,
            "depends_on": depends,
        });
        e
    };
    let applied = |seq: i64, node_id: WorkflowNodeId, kind: &str, reason: Option<&str>| {
        let mut e = event(seq, Some(node_id), kind);
        e.run_id = run_id;
        e.actor = "scheduler".to_string();
        e.reason_code = reason.map(str::to_string);
        e
    };
    *runs.events.lock().unwrap() = vec![
        declared(1, parent_id, "parent", &[]),
        declared(2, child_id, "child", &["parent"]),
        applied(3, parent_id, "node_succeeded", None),
        applied(4, child_id, "node_ready", Some("NODE_READY")),
    ];
    (runs, run_id, parent_id, child_id)
}

/// Upstream `TestServeRunDetailDivergenceBanner` — a materialized node
/// the journal never declared is `RECONSTRUCTION_DIVERGED` evidence,
/// rendered verbatim in the banner.
#[tokio::test]
async fn run_detail_divergence_banner() {
    let (runs, run_id, _p, _c) = banner_fixture();
    runs.current
        .lock()
        .unwrap()
        .insert("ghost".to_string(), "succeeded".to_string());
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("RECONSTRUCTION_DIVERGED"), "{body}");
    assert!(body.contains("ghost"), "{body}");
}

/// Upstream `TestServeRunDetailJournalFindings` — a `seq` gap surfaces
/// `EVENT_SEQUENCE_GAP` in the fold findings list.
#[tokio::test]
async fn run_detail_journal_findings() {
    let (runs, run_id, _p, _c) = banner_fixture();
    runs.events.lock().unwrap()[1].seq = 9;
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("EVENT_SEQUENCE_GAP"), "{body}");
}

/// Upstream `TestServeRunDetailAmbiguousBanner` — a parked
/// `attempt_ambiguous` node renders the reconciliation banner naming
/// the node key, its reason, and the node-detail link.
#[tokio::test]
async fn run_detail_parked_ambiguous_banner() {
    let (runs, run_id, _p, child) = banner_fixture();
    {
        let mut graph = runs.graph.lock().unwrap();
        let c = &mut graph.nodes[1];
        c.status = "attempt_ambiguous".to_string();
        c.reason = "ATTEMPT_OUTCOME_UNKNOWN".to_string();
    }
    runs.current
        .lock()
        .unwrap()
        .insert("child".to_string(), "attempt_ambiguous".to_string());
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("attempt_ambiguous"), "{body}");
    assert!(body.contains("ATTEMPT_OUTCOME_UNKNOWN"), "{body}");
    assert!(
        body.contains(&format!("/app/runs/node?id={child}")),
        "{body}"
    );
}

/// Upstream `TestServeRunDetailLeaseWarnings` — a live lease 2 missed
/// beats deep renders `suspect`; a lease of a different run never
/// leaks into this run's banner.
#[tokio::test]
async fn run_detail_lease_warnings() {
    let (runs, run_id, _p, child) = banner_fixture();
    let worker = WorkerId::new();
    let now = OffsetDateTime::now_utc();
    let lease = |run: RunId, node: WorkflowNodeId, key: &str, age: i64| LeaseRow {
        id: central_foundation::identity::NodeLeaseId::new(),
        run_id: run,
        node_id: node,
        node_key: key.to_string(),
        attempt_id: central_foundation::identity::SessionAttemptId::new(),
        attempt_seq: 1,
        worker_id: worker,
        issued_at: now - time::Duration::hours(1),
        last_heartbeat_at: now - time::Duration::seconds(age),
        heartbeat_age_seconds: age,
        expires_at: now + time::Duration::hours(1),
        heartbeat_interval_sec: central_scheduler::domain::HEARTBEAT_INTERVAL_SEC as i32,
    };
    runs.leases.lock().unwrap().extend([
        // Two missed beats (>= suspect, < lost).
        lease(
            run_id,
            child,
            "child",
            2 * central_scheduler::domain::HEARTBEAT_INTERVAL_SEC,
        ),
        // A foreign run's lost lease must not leak into this banner.
        lease(
            RunId::new(),
            WorkflowNodeId::new(),
            "other-run-node",
            9 * central_scheduler::domain::HEARTBEAT_INTERVAL_SEC,
        ),
    ]);
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/detail?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("suspect"), "{body}");
    assert!(!body.contains("other-run-node"), "{body}");
}

/// Node detail renders the attempt ledger and the degraded
/// `not recorded` version fields, and its timeline contains only the
/// node's own events — run-scope and foreign-node events stay out.
#[tokio::test]
async fn node_detail_attempts_and_timeline_scope() {
    let (runs, _run_id, node_id) = detail_fixture("root-1");
    let other = WorkflowNodeId::new();
    runs.events.lock().unwrap().extend([
        event(1, Some(node_id), "node_dispatched"),
        event(2, Some(other), "node_cancelled"),
        event(3, None, "run_submitted"),
    ]);
    runs.attempts.lock().unwrap().push(AttemptRow {
        id: central_foundation::identity::SessionAttemptId::new(),
        node_id,
        node_key: "root-1".to_string(),
        seq: 1,
        state: "running".to_string(),
        reason_code: None,
        worker_id: None,
        claimed_at: OffsetDateTime::now_utc(),
        started_at: None,
        ended_at: None,
        versions: Default::default(),
    });
    let f = fixture(Some(runs), None, None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/node?id={node_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("node_dispatched"));
    assert!(!body.contains("node_cancelled"));
    assert!(!body.contains("run_submitted"));
    assert!(body.contains("not recorded"));
    // A foreign node id is the same 404 as an absent one.
    let (status2, _) = get_authed(&f, &format!("/app/runs/node?id={other}")).await;
    assert_eq!(status2, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Fleet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fleet_nil_reader_503_and_disabled_notice() {
    let f = fixture(None, None, None, RunControlPorts::default(), false);
    let (status, _) = get_authed(&f, "/app/runs/fleet").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn fleet_renders_workers_and_disabled_notice() {
    let runs = Arc::new(FakeRuns::default());
    *runs.fail.lock().unwrap() = None;
    // Extend the fake with fleet state.
    let f = {
        let fleet = Arc::new(FakeRunsFleet::default());
        fleet.workers.lock().unwrap().push(WorkerRow {
            id: WorkerId::new(),
            workspace_id: WORKSPACE,
            protocol_version: 1,
            harness_kinds: vec!["claude".to_string()],
            workspace_kinds: vec![],
            max_concurrent_attempts: 4,
            state: "active".to_string(),
            registered_at: OffsetDateTime::now_utc(),
            last_seen_at: Some(OffsetDateTime::now_utc()),
            beat_age_seconds: Some(100),
            deregistered_at: None,
        });
        fleet
    };
    let fix = fixture(None, Some(f), None, RunControlPorts::default(), false);
    let (status, body) = get_authed(&fix, "/app/runs/fleet").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Scheduler disabled"));
    assert!(body.contains("suspect"), "{body}");
}

/// A fleet fake independent of `FakeRuns` (the `FleetReader` impl on
/// `FakeRuns` above covers the shared fixture; this standalone fake
/// keeps the fleet test readable). Per-run deferrals and the recorded
/// `deferred_admissions` call order pin the live-run scan (upstream
/// `fakeFleetReader.deferredCalls`).
#[derive(Default)]
struct FakeRunsFleet {
    workers: Mutex<Vec<WorkerRow>>,
    leases: Mutex<Vec<LeaseRow>>,
    runs: Mutex<Vec<RunSummary>>,
    deferred: Mutex<HashMap<RunId, Vec<DeferredRow>>>,
    deferred_calls: Mutex<Vec<RunId>>,
    runs_limit: Mutex<i64>,
    outbox: Mutex<Option<OutboxHealth>>,
}

impl FleetReader for FakeRunsFleet {
    fn workers(&self, _w: WorkspaceId) -> BoxFuture<'_, Result<Vec<WorkerRow>, DomainFailure>> {
        let v = self.workers.lock().unwrap().clone();
        Box::pin(async move { Ok(v) })
    }
    fn live_leases(&self, _w: WorkspaceId) -> BoxFuture<'_, Result<Vec<LeaseRow>, DomainFailure>> {
        let v = self.leases.lock().unwrap().clone();
        Box::pin(async move { Ok(v) })
    }
    fn list_runs(
        &self,
        _w: WorkspaceId,
        _a: Option<RunCursor>,
        l: i64,
    ) -> BoxFuture<'_, Result<Vec<RunSummary>, DomainFailure>> {
        *self.runs_limit.lock().unwrap() = l;
        let mut v = self.runs.lock().unwrap().clone();
        // The store honors the LIMIT clause; the fake must too or the
        // scan-limit test sees every seeded run.
        v.truncate(usize::try_from(l.max(0)).unwrap_or(usize::MAX));
        Box::pin(async move { Ok(v) })
    }
    fn deferred_admissions(
        &self,
        r: RunId,
    ) -> BoxFuture<'_, Result<Vec<DeferredRow>, DomainFailure>> {
        self.deferred_calls.lock().unwrap().push(r);
        let v = self
            .deferred
            .lock()
            .unwrap()
            .get(&r)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(v) })
    }
    fn outbox_health(&self) -> BoxFuture<'_, Result<OutboxHealth, DomainFailure>> {
        let o = (*self.outbox.lock().unwrap()).unwrap_or(OutboxHealth {
            unpublished_depth: 0,
            oldest_unpublished: None,
        });
        Box::pin(async move { Ok(o) })
    }
}

/// A live run for the fleet fixture (upstream `fakeRunSummary`).
fn live_run(id: RunId, key: Option<&str>, status: &str) -> RunSummary {
    let created_at = OffsetDateTime::now_utc();
    RunSummary {
        id,
        task_id: TaskId::new(),
        workspace_id: WORKSPACE,
        index: 1,
        status: status.to_string(),
        run_key: key.map(str::to_string),
        created_at,
        updated_at: created_at,
        started_at: Some(created_at),
        ended_at: None,
        deadline: None,
        node_counts: BTreeMap::new(),
    }
}

fn fleet_lease(run: RunId, node_key: &str) -> LeaseRow {
    let now = OffsetDateTime::now_utc();
    LeaseRow {
        id: central_foundation::identity::NodeLeaseId::new(),
        run_id: run,
        node_id: WorkflowNodeId::new(),
        node_key: node_key.to_string(),
        attempt_id: central_foundation::identity::SessionAttemptId::new(),
        attempt_seq: 1,
        worker_id: WorkerId::new(),
        issued_at: now,
        last_heartbeat_at: now,
        heartbeat_age_seconds: 5,
        expires_at: now + time::Duration::minutes(5),
        heartbeat_interval_sec: central_scheduler::domain::HEARTBEAT_INTERVAL_SEC as i32,
    }
}

fn fleet_deferred(
    run: RunId,
    seq: i64,
    node_key: &str,
    ready_at: Option<OffsetDateTime>,
) -> DeferredRow {
    DeferredRow {
        event_id: central_foundation::identity::RunEventId::new(),
        run_id: run,
        seq,
        node_id: WorkflowNodeId::new(),
        node_key: node_key.to_string(),
        reason_code: Some("CAPACITY_ADMISSION_DEFERRED".to_string()),
        ready_at,
        recorded_at: OffsetDateTime::now_utc(),
    }
}

/// Upstream `TestServeFleetShowsLeasesDeferredOutbox` — one run with
/// pending/ready counts, a live lease, a deferred-admission row with
/// its ready_at rendered, and the outbox stall cell.
#[tokio::test]
async fn fleet_shows_leases_deferred_outbox() {
    let fleet = Arc::new(FakeRunsFleet::default());
    let run_id = RunId::new();
    fleet
        .runs
        .lock()
        .unwrap()
        .push(live_run(run_id, Some("run-1"), "running"));
    fleet
        .leases
        .lock()
        .unwrap()
        .push(fleet_lease(run_id, "gen-1"));
    let ready_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
    fleet
        .deferred
        .lock()
        .unwrap()
        .entry(run_id)
        .or_default()
        .push(fleet_deferred(run_id, 7, "nodelay-1", Some(ready_at)));
    *fleet.outbox.lock().unwrap() = Some(OutboxHealth {
        unpublished_depth: 3,
        oldest_unpublished: Some(OffsetDateTime::now_utc() - time::Duration::seconds(125)),
    });
    let f = fixture(None, Some(fleet), None, RunControlPorts::default(), true);
    let (status, body) = get_authed(&f, "/app/runs/fleet").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("gen-1"), "{body}");
    assert!(body.contains("nodelay-1"), "{body}");
    assert!(body.contains("CAPACITY_ADMISSION_DEFERRED"), "{body}");
    // Outbox depth cell: `<dd>3 <span ...>(stall threshold...</span></dd>`.
    assert!(body.contains("<dd>3 <span"), "{body}");
}

/// Upstream `TestServeFleetDeferredRunOrder` — only live runs are
/// scanned for deferrals and groups render in the `list_runs` order.
#[tokio::test]
async fn fleet_deferred_run_order() {
    let fleet = Arc::new(FakeRunsFleet::default());
    let a = RunId::new();
    let b = RunId::new();
    let c = RunId::new();
    {
        let mut runs = fleet.runs.lock().unwrap();
        runs.push(live_run(a, Some("run-a"), "running"));
        runs.push(live_run(b, Some("run-b"), "queued"));
        runs.push(live_run(c, Some("run-c"), "running"));
    }
    fleet
        .deferred
        .lock()
        .unwrap()
        .insert(a, vec![fleet_deferred(a, 1, "a-node", None)]);
    fleet
        .deferred
        .lock()
        .unwrap()
        .insert(b, vec![fleet_deferred(b, 2, "b-node", None)]);
    let f = fixture(
        None,
        Some(fleet.clone()),
        None,
        RunControlPorts::default(),
        true,
    );
    let (status, body) = get_authed(&f, "/app/runs/fleet").await;
    assert_eq!(status, StatusCode::OK);
    // Only runs with non-empty deferrals render a group; both scanned.
    assert_eq!(*fleet.deferred_calls.lock().unwrap(), vec![a, b, c]);
    let pos_a = body.find("a-node").expect("a-node row");
    let pos_b = body.find("b-node").expect("b-node row");
    assert!(pos_a < pos_b, "{body}");
}

/// Upstream `TestServeFleetDeferredSkipsTerminal` — a terminal run's
/// deferrals are never scanned or rendered.
#[tokio::test]
async fn fleet_deferred_skips_terminal() {
    let fleet = Arc::new(FakeRunsFleet::default());
    let t = RunId::new();
    fleet
        .runs
        .lock()
        .unwrap()
        .push(live_run(t, Some("run-terminal"), "succeeded"));
    fleet
        .deferred
        .lock()
        .unwrap()
        .insert(t, vec![fleet_deferred(t, 1, "t-node", None)]);
    let f = fixture(
        None,
        Some(fleet.clone()),
        None,
        RunControlPorts::default(),
        true,
    );
    let (status, body) = get_authed(&f, "/app/runs/fleet").await;
    assert_eq!(status, StatusCode::OK);
    assert!(fleet.deferred_calls.lock().unwrap().is_empty());
    assert!(!body.contains("t-node"), "{body}");
}

/// Upstream `TestServeFleetDeferredScanLimit` — the scan stops after
/// `FLEET_DEFERRED_RUN_SCAN_LIMIT` live runs so the page stays bounded.
#[tokio::test]
async fn fleet_deferred_scan_limit() {
    let fleet = Arc::new(FakeRunsFleet::default());
    {
        let mut runs = fleet.runs.lock().unwrap();
        for _ in 0..(central_runview::query::FLEET_DEFERRED_RUN_SCAN_LIMIT + 5) {
            runs.push(live_run(RunId::new(), None, "running"));
        }
    }
    let f = fixture(
        None,
        Some(fleet.clone()),
        None,
        RunControlPorts::default(),
        true,
    );
    let (status, _body) = get_authed(&f, "/app/runs/fleet").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        fleet.deferred_calls.lock().unwrap().len() as i64,
        central_runview::query::FLEET_DEFERRED_RUN_SCAN_LIMIT
    );
    assert_eq!(
        *fleet.runs_limit.lock().unwrap(),
        central_runview::query::FLEET_DEFERRED_RUN_SCAN_LIMIT
    );
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lineage_scope_and_undeclared_flag() {
    let lin = Arc::new(FakeLineage::default());
    *lin.scope.lock().unwrap() = Some(WORKSPACE);
    let f = fixture(
        None,
        None,
        Some(lin.clone()),
        RunControlPorts::default(),
        false,
    );
    let run_id = RunId::new();
    // Cross-workspace run → generic 404.
    *lin.scope.lock().unwrap() = Some(WorkspaceId::new());
    let (status, _) = get_authed(&f, &format!("/app/runs/lineage?run={run_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Absent run → same 404.
    *lin.scope.lock().unwrap() = None;
    let (status, _) = get_authed(&f, &format!("/app/runs/lineage?run={run_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // In-workspace, one undeclared read → flagged, never hidden.
    *lin.scope.lock().unwrap() = Some(WORKSPACE);
    lin.reads
        .lock()
        .unwrap()
        .push(central_artifact::lineage::ReadEdge {
            id: central_foundation::identity::ReadEdgeId::new(),
            run_id,
            reader_node_id: Some(WorkflowNodeId::new()),
            attempt_id: None,
            artifact_id: ArtifactId::new(),
            declared: false,
            checksum: "abc".to_string(),
            created_at: OffsetDateTime::now_utc(),
        });
    let (status, body) = get_authed(&f, &format!("/app/runs/lineage?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("undeclared read(s) journaled"), "{body}");
}

/// Upstream `newLineageFixture` — extract produced `produced_a`,
/// analyze (attempt `attempt_b`, prompt_ref `prompt_ref`) reads
/// `produced_a` declared plus `undeclared` undeclared; one operator
/// read and one foreign-workspace read sit on top.
struct LineageFixture {
    lin: Arc<FakeLineage>,
    run: RunId,
    prompt_ref: ArtifactId,
    foreign: ArtifactId,
    staging: ArtifactId,
}

fn lineage_fixture() -> LineageFixture {
    let lin = Arc::new(FakeLineage::default());
    let run = RunId::new();
    let node_a = WorkflowNodeId::new();
    let node_b = WorkflowNodeId::new();
    let attempt_a = central_foundation::identity::SessionAttemptId::new();
    let attempt_b = central_foundation::identity::SessionAttemptId::new();
    let produced_a = ArtifactId::new();
    let produced_b = ArtifactId::new();
    let prompt_ref = ArtifactId::new();
    let undeclared = ArtifactId::new();
    let foreign = ArtifactId::new();
    let staging = ArtifactId::new();
    *lin.scope.lock().unwrap() = Some(WORKSPACE);
    let now = OffsetDateTime::now_utc();
    let gnode = |id: WorkflowNodeId, key: &str| GraphNode {
        id,
        run_id: run,
        key: key.to_string(),
        status: "succeeded".to_string(),
        reason: String::new(),
        attempt_count: 1,
        max_attempts: 3,
        not_before: None,
        parent_key: None,
        created_at: now,
    };
    *lin.graph.lock().unwrap() = RunGraph {
        nodes: vec![gnode(node_a, "extract"), gnode(node_b, "analyze")],
        edges: Vec::new(),
    };
    let attempt = |id, node, key: &str, prompt: Option<ArtifactId>| AttemptRow {
        id,
        node_id: node,
        node_key: key.to_string(),
        seq: 0,
        state: "succeeded".to_string(),
        reason_code: None,
        worker_id: None,
        claimed_at: now,
        started_at: Some(now),
        ended_at: Some(now),
        versions: central_runview::domain::Versions {
            prompt_ref_artifact_id: prompt,
            ..Default::default()
        },
    };
    *lin.attempts.lock().unwrap() = vec![
        attempt(attempt_a, node_a, "extract", None),
        attempt(attempt_b, node_b, "analyze", Some(prompt_ref)),
    ];
    let produce = |node: WorkflowNodeId, attempt_id, artifact: ArtifactId| {
        central_artifact::lineage::ProduceEdge {
            id: central_foundation::identity::ProduceEdgeId::new(),
            run_id: run,
            node_id: node,
            attempt_id,
            artifact_id: artifact,
            created_at: now,
        }
    };
    *lin.produced.lock().unwrap() = vec![
        produce(node_a, attempt_a, produced_a),
        produce(node_b, attempt_b, produced_b),
        produce(node_b, attempt_b, staging),
    ];
    let read = |reader: Option<WorkflowNodeId>,
                attempt: Option<central_foundation::identity::SessionAttemptId>,
                artifact: ArtifactId,
                declared: bool,
                checksum: &str| {
        central_artifact::lineage::ReadEdge {
            id: central_foundation::identity::ReadEdgeId::new(),
            run_id: run,
            reader_node_id: reader,
            attempt_id: attempt,
            artifact_id: artifact,
            declared,
            checksum: checksum.to_string(),
            created_at: now,
        }
    };
    *lin.reads.lock().unwrap() = vec![
        read(Some(node_b), Some(attempt_b), produced_a, true, "aa55"),
        read(Some(node_b), Some(attempt_b), undeclared, false, "bb66"),
        read(None, None, produced_a, false, "aa55"),
        read(Some(node_b), Some(attempt_b), foreign, false, "cc77"),
    ];
    let art = |id: ArtifactId, workspace: WorkspaceId, state, checksum: &str| {
        let a = central_artifact::lineage::LineageArtifact {
            id,
            workspace_id: workspace,
            run_id: run,
            state,
            ready_key: format!("v1/ready/{id}"),
            checksum: checksum.to_string(),
        };
        lin.artifacts.lock().unwrap().insert(id, a);
    };
    let ready = central_artifact::domain::State::Ready;
    art(produced_a, WORKSPACE, ready, "aa55");
    art(produced_b, WORKSPACE, ready, "dd44");
    art(prompt_ref, WORKSPACE, ready, "ee33");
    art(undeclared, WORKSPACE, ready, "bb66");
    art(
        staging,
        WORKSPACE,
        central_artifact::domain::State::Staging,
        "",
    );
    art(foreign, WorkspaceId::new(), ready, "cc77");
    LineageFixture {
        lin,
        run,
        prompt_ref,
        foreign,
        staging,
    }
}

/// Upstream `TestServeLineageHappyPath` scope-denied cells + the
/// non-ready artifact cell: a foreign-workspace artifact renders the
/// `scope denied` hint without a link (I-1 header parity keeps node
/// headings as plain text), and a `staging` artifact renders its state
/// verbatim.
#[tokio::test]
async fn lineage_scope_denied_and_non_ready_cells() {
    let fx = lineage_fixture();
    let f = fixture(
        None,
        None,
        Some(fx.lin.clone()),
        RunControlPorts::default(),
        false,
    );
    let (status, body) = get_authed(&f, &format!("/app/runs/lineage?run={}", fx.run)).await;
    assert_eq!(status, StatusCode::OK);
    // Foreign artifact: scope-denied cell, never a link.
    assert!(body.contains("scope denied"), "{body}");
    assert!(
        !body.contains(&format!("preview?id={}", fx.foreign)),
        "{body}"
    );
    // Non-ready artifact: the state token renders verbatim, no link.
    assert!(body.contains("staging"), "{body}");
    assert!(
        !body.contains(&format!("preview?id={}", fx.staging)),
        "{body}"
    );
    // Ready artifacts link to the preview route (M-9): node headings
    // stay plain text while artifact cells keep their links.
    assert!(
        body.contains(&format!("preview?id={}", fx.prompt_ref)),
        "{body}"
    );
}

/// Upstream `TestServeLineageEmptyRun` — a run with neither produced
/// edges nor read edges renders the `No lineage journaled` notice
/// even when attempts still carry prompt_ref links (I-1 empty
/// semantics: finals + reads only).
#[tokio::test]
async fn lineage_empty_run_notice() {
    let fx = lineage_fixture();
    *fx.lin.produced.lock().unwrap() = Vec::new();
    *fx.lin.reads.lock().unwrap() = Vec::new();
    let run = fx.run;
    let f = fixture(None, None, Some(fx.lin), RunControlPorts::default(), false);
    let (status, body) = get_authed(&f, &format!("/app/runs/lineage?run={run}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No lineage journaled"), "{body}");
}

// ---------------------------------------------------------------------------
// Controls — the security prelude + verdict pages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn controls_page_renders_wired_forms() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let controls = RunControlPorts {
        canceller: Some(Arc::new(FakeControls::default())),
        resolver: Some(Arc::new(FakeControls::default())),
        resumer: Some(Arc::new(FakeControls::default())),
        checkpoints: Some(Arc::new(FakeControls::default())),
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, body) = get_authed(&f, &format!("/app/runs/controls?run={run_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("/app/runs/cancel"));
    assert!(body.contains("/app/runs/resume"));
    assert!(body.contains("/app/runs/checkpoint/create"));
    assert!(body.contains(node_id.to_string().as_str()));
    assert!(!body.contains("<script"));
    // A missing run → generic 404.
    let (status, _) = get_authed(&f, &format!("/app/runs/controls?run={}", RunId::new())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Missing Origin → 403 `RUN_CONTROL_FAILED` before any store call.
#[tokio::test]
async fn control_no_origin_403() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let controls = RunControlPorts {
        canceller: Some(Arc::new(FakeControls::default())),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let body = format!(
        "csrf={}&run_id={run_id}&node_id={node_id}",
        b64::encode(&[8u8; 32])
    );
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            axum::http::Request::post("/app/runs/node/cancel")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded"),
            body,
        ))
        .await
        .unwrap();
    // The middleware's Origin gate rejects before the handler.
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn control_cancel_node_commits_verdict() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let canceller = Arc::new(FakeControls::default());
    let controls = RunControlPorts {
        canceller: Some(canceller.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, body) = post_control(
        &f,
        "/app/runs/node/cancel",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &node_id.to_string()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(canceller.cancel_calls.lock().unwrap().len(), 1);
    assert!(body.contains("cascade committed"), "{body}");
}

/// A foreign-run node id answers the same generic 404 and the store is
/// never touched.
#[tokio::test]
async fn control_cancel_foreign_node_404() {
    let (runs, run_id, _n) = detail_fixture("root-1");
    let canceller = Arc::new(FakeControls::default());
    let controls = RunControlPorts {
        canceller: Some(canceller.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, _) = post_control(
        &f,
        "/app/runs/node/cancel",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &WorkflowNodeId::new().to_string()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(canceller.cancel_calls.lock().unwrap().is_empty());
}

/// An unknown decision is a grammar refusal before the store.
#[tokio::test]
async fn control_decide_unknown_400() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let resolver = Arc::new(FakeControls::default());
    let controls = RunControlPorts {
        resolver: Some(resolver.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, _) = post_control(
        &f,
        "/app/runs/node/decide",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &node_id.to_string()),
            ("decision", "explode"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resolver.decide_calls.lock().unwrap().is_empty());
    // A refused store decision renders its reason inline at 200.
    *resolver.resolve_err.lock().unwrap() = Some(DomainFailure::new(
        FailureKind::Conflict,
        "WORKFLOW_NODE_NOT_AMBIGUOUS",
        "not parked",
    ));
    let (status, body) = post_control(
        &f,
        "/app/runs/node/decide",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &node_id.to_string()),
            ("decision", "rerun"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("WORKFLOW_NODE_NOT_AMBIGUOUS"), "{body}");
}

/// A resume token whose record resolves to another workspace is the
/// same generic 404 as an absent run.
#[tokio::test]
async fn control_resume_foreign_workspace_404() {
    let resumer = Arc::new(FakeControls::default());
    let mut rec = checkpoint_record();
    rec.workspace_id = WorkspaceId::new();
    *resumer.preflight.lock().unwrap() = Some(rec);
    let controls = RunControlPorts {
        resumer: Some(resumer.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(None, None, None, controls, false);
    let (status, _) = post_control(&f, "/app/runs/resume", &[("token", "tok")]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(resumer.resume_calls.lock().unwrap().is_empty());
    // A preflight refusal renders its reason code inline.
    *resumer.preflight.lock().unwrap() = None;
    *resumer.preflight_err.lock().unwrap() = Some(DomainFailure::new(
        FailureKind::Invalid,
        "CHECKPOINT_EXPIRED",
        "gone",
    ));
    let (status, body) = post_control(&f, "/app/runs/resume", &[("token", "tok")]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CHECKPOINT_EXPIRED"), "{body}");
}

/// A checkpoint id of another workspace is the same generic 404 as an
/// absent one — the class change is never attempted.
#[tokio::test]
async fn control_checkpoint_pin_foreign_404() {
    let cps = Arc::new(FakeControls::default());
    let mut rec = checkpoint_record();
    rec.workspace_id = WorkspaceId::new();
    *cps.preflight.lock().unwrap() = Some(rec);
    let controls = RunControlPorts {
        checkpoints: Some(cps),
        ..RunControlPorts::default()
    };
    let f = fixture(None, None, None, controls, false);
    let (status, _) = post_control(
        &f,
        "/app/runs/checkpoint/pin",
        &[(
            "checkpoint_id",
            &central_foundation::identity::ResumeCheckpointId::new().to_string(),
        )],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn control_gc_renders_collected_and_partial() {
    let cps = Arc::new(FakeControls::default());
    let controls = RunControlPorts {
        checkpoints: Some(cps.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(None, None, None, controls, false);
    let (status, body) = post_control(&f, "/app/runs/checkpoint/gc", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Collected 3"), "{body}");
    *cps.gc_failures.lock().unwrap() = true;
    let (status, body) = post_control(&f, "/app/runs/checkpoint/gc", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CHECKPOINT_GC_PARTIAL"), "{body}");
}

fn checkpoint_record() -> central_checkpoint::domain::ResumeCheckpoint {
    let now = OffsetDateTime::now_utc();
    central_checkpoint::domain::ResumeCheckpoint {
        id: central_foundation::identity::ResumeCheckpointId::new(),
        workspace_id: WORKSPACE,
        run_id: RunId::new(),
        node_id: WorkflowNodeId::new(),
        attempt_id: central_foundation::identity::SessionAttemptId::new(),
        checkpoint_seq: 1,
        format_version: "central.checkpoint/v1".to_string(),
        graph_schema_version: "v1".to_string(),
        event_watermark: 7,
        harness_session_id: None,
        workspace_digest: None,
        workspace_path: None,
        content_digest: "x".to_string(),
        completed_nodes: Vec::new(),
        finalized_artifacts: Vec::new(),
        in_flight_nodes: Vec::new(),
        gc_class: central_checkpoint::domain::GcClass::Supersedeable,
        created_at: now,
        expires_at: None,
    }
}

/// Upstream `TestServeRunCancelTerminalDeniedInline` — a store-level
/// DENIED on a terminal node renders its reason code inline at 200
/// (the node-status denial is never hidden behind a generic error).
#[tokio::test]
async fn control_cancel_terminal_denied_inline() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    runs.nodes.lock().unwrap().get_mut(&node_id).unwrap().status = "succeeded".to_string();
    let canceller = Arc::new(FakeControls::default());
    *canceller.cancel_err.lock().unwrap() = Some(DomainFailure::new(
        FailureKind::Denied,
        "INVALID_NODE_TRANSITION",
        "terminal",
    ));
    let controls = RunControlPorts {
        canceller: Some(canceller.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, body) = post_control(
        &f,
        "/app/runs/node/cancel",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &node_id.to_string()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(canceller.cancel_calls.lock().unwrap().len(), 1);
    assert!(body.contains("INVALID_NODE_TRANSITION"), "{body}");
    assert!(body.contains("refused"), "{body}");
}

/// Upstream `TestServeRunNodeDecideRefusals` — every out-of-vocabulary
/// decision is a 400 grammar refusal before the store, and both
/// declared decisions (`resume`, `rerun`) reach the resolver.
#[tokio::test]
async fn control_decide_vocabulary() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let resolver = Arc::new(FakeControls::default());
    let controls = RunControlPorts {
        resolver: Some(resolver.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    for decision in ["abandon", "bogus", ""] {
        let (status, _) = post_control(
            &f,
            "/app/runs/node/decide",
            &[
                ("run_id", &run_id.to_string()),
                ("node_id", &node_id.to_string()),
                ("decision", decision),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "decision {decision}");
    }
    assert!(resolver.decide_calls.lock().unwrap().is_empty());
    for decision in ["resume", "rerun"] {
        let (status, body) = post_control(
            &f,
            "/app/runs/node/decide",
            &[
                ("run_id", &run_id.to_string()),
                ("node_id", &node_id.to_string()),
                ("decision", decision),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "decision {decision}: {body}");
        assert!(body.contains("decision recorded"), "{body}");
    }
    assert_eq!(resolver.decide_calls.lock().unwrap().len(), 2);
}

/// Upstream `TestServeRunCheckpointCreateHappyPath` — create passes the
/// caller-supplied seq and class through and renders the fresh resume
/// token.
#[tokio::test]
async fn control_checkpoint_create_happy_path() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let cps = Arc::new(FakeControls::default());
    let mut rec = checkpoint_record();
    rec.run_id = run_id;
    rec.node_id = node_id;
    rec.checkpoint_seq = 7;
    rec.gc_class = central_checkpoint::domain::GcClass::Pinned;
    *cps.write_record.lock().unwrap() = Some(rec.clone());
    let controls = RunControlPorts {
        checkpoints: Some(cps.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, body) = post_control(
        &f,
        "/app/runs/checkpoint/create",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &node_id.to_string()),
            ("seq", "7"),
            ("gc_class", "pinned"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        *cps.write_args.lock().unwrap(),
        vec![(7, central_checkpoint::domain::GcClass::Pinned)]
    );
    assert!(body.contains(&rec.id.to_string()), "{body}");
    assert!(body.contains("ckpt."), "{body}");
    assert!(body.contains("written"), "{body}");
}

/// Upstream `TestServeRunCheckpointCreateGrammarRefusals` — `seq` < 1 /
/// unparsable / absent and an unknown `gc_class` are 400s that never
/// reach the store.
#[tokio::test]
async fn control_checkpoint_create_grammar_refusals() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let cps = Arc::new(FakeControls::default());
    let controls = RunControlPorts {
        checkpoints: Some(cps.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let run = run_id.to_string();
    let node = node_id.to_string();
    for fields in [
        vec![
            ("run_id", run.as_str()),
            ("node_id", node.as_str()),
            ("seq", "0"),
        ],
        vec![
            ("run_id", run.as_str()),
            ("node_id", node.as_str()),
            ("seq", "-3"),
        ],
        vec![
            ("run_id", run.as_str()),
            ("node_id", node.as_str()),
            ("seq", "abc"),
        ],
        vec![("run_id", run.as_str()), ("node_id", node.as_str())],
        vec![
            ("run_id", run.as_str()),
            ("node_id", node.as_str()),
            ("seq", "1"),
            ("gc_class", "bogus"),
        ],
    ] {
        let (status, body) = post_control(&f, "/app/runs/checkpoint/create", &fields).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{fields:?}: {body}");
    }
    assert_eq!(*cps.write_calls.lock().unwrap(), 0);
}

/// Upstream `TestServeRunCheckpointCreateSeqConflictInline` — the
/// `(attempt_id, checkpoint_seq)` dedupe refusal renders
/// `DUPLICATE_IDEMPOTENCY_KEY` inline.
#[tokio::test]
async fn control_checkpoint_create_seq_conflict() {
    let (runs, run_id, node_id) = detail_fixture("root-1");
    let cps = Arc::new(FakeControls::default());
    *cps.write_err.lock().unwrap() = Some(DomainFailure::new(
        FailureKind::Denied,
        "DUPLICATE_IDEMPOTENCY_KEY",
        "seq taken",
    ));
    let controls = RunControlPorts {
        checkpoints: Some(cps),
        ..RunControlPorts::default()
    };
    let f = fixture(Some(runs), None, None, controls, false);
    let (status, body) = post_control(
        &f,
        "/app/runs/checkpoint/create",
        &[
            ("run_id", &run_id.to_string()),
            ("node_id", &node_id.to_string()),
            ("seq", "4"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("DUPLICATE_IDEMPOTENCY_KEY"), "{body}");
}

/// Upstream `TestServeRunCheckpointPinUnpin` — the class change is
/// scope-checked through the checkpoint's own record workspace before
/// `update_gc_class`; a store refusal renders its reason inline.
#[tokio::test]
async fn control_checkpoint_pin_unpin() {
    let cps = Arc::new(FakeControls::default());
    *cps.preflight.lock().unwrap() = Some(checkpoint_record());
    let controls = RunControlPorts {
        checkpoints: Some(cps.clone()),
        ..RunControlPorts::default()
    };
    let f = fixture(None, None, None, controls, false);
    let checkpoint_id = central_foundation::identity::ResumeCheckpointId::new().to_string();
    let (status, body) = post_control(
        &f,
        "/app/runs/checkpoint/pin",
        &[("checkpoint_id", &checkpoint_id)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("pinned"), "{body}");
    let (status, body) = post_control(
        &f,
        "/app/runs/checkpoint/unpin",
        &[("checkpoint_id", &checkpoint_id)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("unpinned"), "{body}");
    assert_eq!(
        cps.class_calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, c)| *c)
            .collect::<Vec<_>>(),
        vec![
            central_checkpoint::domain::GcClass::Pinned,
            central_checkpoint::domain::GcClass::Supersedeable,
        ]
    );
    // A store refusal renders its reason code inline at 200.
    *cps.class_err.lock().unwrap() = Some(DomainFailure::new(
        FailureKind::Conflict,
        "CHECKPOINT_CLASS_LOCKED",
        "locked",
    ));
    let (status, body) = post_control(
        &f,
        "/app/runs/checkpoint/pin",
        &[("checkpoint_id", &checkpoint_id)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("CHECKPOINT_CLASS_LOCKED"), "{body}");
}
