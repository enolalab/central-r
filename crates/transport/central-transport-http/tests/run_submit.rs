//! Behavioral tests for `POST /app/runs/submit` and the `/app/runs`
//! submit form (issue #122) — the Rust port of upstream
//! `web/run_submit_test.go`: the success PRG, the run-control
//! security prelude, worker-parse 400s, the ValidationError→400 /
//! other→503 mapping, the unwired 503 + hidden form, and the wired
//! form render — all through the composed router so the session/CSRF
//! middleware contract is what ships.

// Test bodies unwrap liberally — a failed unwrap is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::StatusCode;
use central_foundation::failure::Failure as DomainFailure;
use central_foundation::identity::{RunId, TaskId, WorkspaceId};
use central_runsubmit::domain::{SubmitRequest, SubmitResult, SubmittedNode, codes};
use central_session::domain::SecurityEpoch;
use central_transport_http::api;
use central_transport_http::b64;
use central_transport_http::health::ProbeState;
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::ports::{BoxFuture, RunSubmitter, RunsReader};
use central_transport_http::router::{TransportConfig, build_app_router};
use central_transport_http::web::{self, WebState};
use central_workflow::domain::NodeStatus;
use common::*;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Fakes + fixture
// ---------------------------------------------------------------------------

struct FakeSubmitter {
    requests: Mutex<Vec<SubmitRequest>>,
    result: Mutex<Result<SubmitResult, DomainFailure>>,
}

impl FakeSubmitter {
    fn ok() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            result: Mutex::new(Ok(SubmitResult {
                task_id: TaskId::new(),
                run_id: RunId::new(),
                nodes: vec![
                    SubmittedNode {
                        node_id: central_foundation::identity::WorkflowNodeId::new(),
                        node_key: "leader".to_string(),
                        state: NodeStatus::Ready,
                    },
                    SubmittedNode {
                        node_id: central_foundation::identity::WorkflowNodeId::new(),
                        node_key: "worker-1".to_string(),
                        state: NodeStatus::Ready,
                    },
                ],
                deduped: false,
            })),
        }
    }
}

impl RunSubmitter for FakeSubmitter {
    fn submit(&self, req: SubmitRequest) -> BoxFuture<'_, Result<SubmitResult, DomainFailure>> {
        self.requests.lock().unwrap().push(req);
        let res = self.result.lock().unwrap().clone();
        Box::pin(async move { res })
    }
}

struct Fixture {
    sessions: Arc<FakeSessions>,
    #[allow(dead_code)]
    submitter: Option<Arc<FakeSubmitter>>,
    app: Router,
}

/// A runs projection wired but always empty/not-found — the submit
/// tests care about the form, not the census rows.
struct EmptyRuns;

macro_rules! runs_ok {
    ($v:expr) => {
        Box::pin(async move { Ok($v) })
    };
}

impl RunsReader for EmptyRuns {
    fn list_runs(
        &self,
        _w: WorkspaceId,
        _a: Option<central_runview::domain::RunCursor>,
        _l: i64,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::RunSummary>, DomainFailure>> {
        runs_ok!(Vec::new())
    }
    fn run_for_id(
        &self,
        _w: WorkspaceId,
        _r: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunSummary, DomainFailure>> {
        Box::pin(async move {
            Err(DomainFailure::new(
                central_foundation::failure::FailureKind::NotFound,
                "RUNVIEW_NOT_FOUND",
                "absent",
            ))
        })
    }
    fn node_for_id(
        &self,
        _w: WorkspaceId,
        _n: central_foundation::identity::WorkflowNodeId,
    ) -> BoxFuture<'_, Result<central_runview::domain::GraphNode, DomainFailure>> {
        Box::pin(async move {
            Err(DomainFailure::new(
                central_foundation::failure::FailureKind::NotFound,
                "RUNVIEW_NOT_FOUND",
                "absent",
            ))
        })
    }
    fn graph_for_run(
        &self,
        _r: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunGraph, DomainFailure>> {
        runs_ok!(Default::default())
    }
    fn events_for_run(
        &self,
        _r: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_eventjournal::domain::RunEvent>, DomainFailure>> {
        runs_ok!(Vec::new())
    }
    fn attempts_for_node(
        &self,
        _n: central_foundation::identity::WorkflowNodeId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::AttemptRow>, DomainFailure>> {
        runs_ok!(Vec::new())
    }
    fn nodes_current(
        &self,
        _r: RunId,
    ) -> BoxFuture<'_, Result<std::collections::BTreeMap<String, String>, DomainFailure>> {
        runs_ok!(Default::default())
    }
    fn live_leases(
        &self,
        _w: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::LeaseRow>, DomainFailure>> {
        runs_ok!(Vec::new())
    }
}

fn fixture(submitter: Option<Arc<FakeSubmitter>>) -> Fixture {
    fixture_with_runs(submitter, None)
}

fn fixture_with_runs(
    submitter: Option<Arc<FakeSubmitter>>,
    runs: Option<Arc<dyn RunsReader>>,
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
        run_submitter: submitter.clone().map(|s| s as Arc<dyn RunSubmitter>),
        runs,
        fleet: None,
        run_lineage: None,
        controls: Default::default(),
        scheduler_enabled: false,
        workspace: WorkspaceId::sentinel(),
        allowed_roots: vec!["root".to_string()],
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
    Fixture {
        sessions,
        submitter,
        app,
    }
}

fn active_cookies(f: &Fixture) -> (String, String) {
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
}

fn cookie_header(token_b64: &str, csrf_b64: &str) -> String {
    format!("central_session={token_b64}; central_session_csrf={csrf_b64}")
}

async fn post_form(
    f: &Fixture,
    fields: &[(&str, &str)],
    with_session: bool,
) -> axum::response::Response {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let builder =
        post_origin("/app/runs/submit").header("content-type", "application/x-www-form-urlencoded");
    let builder = if with_session {
        let (t, c) = active_cookies(f);
        builder.header("cookie", cookie_header(&t, &c))
    } else {
        builder
    };
    f.app
        .clone()
        .oneshot(loopback_req_body(builder, body))
        .await
        .unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Upstream ports
// ---------------------------------------------------------------------------

/// `TestServeRunSubmitSuccessRedirects` — 303 to the fresh run's
/// detail page; the submitter receives the session workspace and the
/// form fields verbatim.
#[tokio::test]
async fn submit_success_redirects() {
    let sub = Arc::new(FakeSubmitter::ok());
    let f = fixture(Some(sub.clone()));
    let resp = post_form(
        &f,
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("idempotency_key", "ik1"),
            ("title", "demo"),
            ("workers", "2"),
            ("run_key", "k1"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let reqs = sub.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert!(location.starts_with("/app/runs/detail?run="));
    assert_eq!(reqs[0].workspace_id, WorkspaceId::sentinel());
    assert_eq!(reqs[0].title, "demo");
    assert_eq!(reqs[0].workers, 2);
    assert_eq!(reqs[0].run_key.as_deref(), Some("k1"));
    assert_eq!(reqs[0].idempotency_key.as_deref(), Some("ik1"));
}

/// `TestServeRunSubmitPrelude` — the run-control security prelude:
/// non-POST 405s with Allow; a missing session or CSRF field is 403
/// and the submitter is never called.
#[tokio::test]
async fn submit_prelude_refusals() {
    let sub = Arc::new(FakeSubmitter::ok());
    let f = fixture(Some(sub.clone()));

    // GET is rejected with Allow: POST.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(get("/app/runs/submit")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        resp.headers().get("allow").unwrap().to_str().unwrap(),
        "POST"
    );

    // Missing session → 403.
    let resp = post_form(
        &f,
        &[("csrf", "x"), ("title", "t"), ("workers", "2")],
        false,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Session but no csrf field → 403.
    let (t, c) = active_cookies(&f);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/app/runs/submit")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", cookie_header(&t, &c)),
            "title=t&workers=2",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    assert!(sub.requests.lock().unwrap().is_empty());
}

/// `TestServeRunSubmitValidationIs400` — `workers=abc` never reaches
/// the port (400); the service's request-validation marker is 400;
/// every other error is a bare 503.
#[tokio::test]
async fn submit_validation_is_400_other_errors_503() {
    let sub = Arc::new(FakeSubmitter::ok());
    let f = fixture(Some(sub.clone()));

    let resp = post_form(
        &f,
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("workers", "abc"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(resp).await.contains("RUN_CONTROL_FAILED"));
    assert!(sub.requests.lock().unwrap().is_empty());

    *sub.result.lock().unwrap() = Err(DomainFailure::invalid(
        codes::REQUEST_VALIDATION,
        "runsubmit: invalid workers",
    ));
    let resp = post_form(
        &f,
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("workers", "99"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(sub.requests.lock().unwrap().len(), 1);

    *sub.result.lock().unwrap() = Err(DomainFailure::internal("pg_boom", "boom"));
    let resp = post_form(
        &f,
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("workers", "2"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body_text(resp).await.contains("RUN_CONTROL_FAILED"));
}

/// `TestServeRunSubmitUnwiredIs503` — an unwired submitter answers
/// the POST a bare 503 and the list renders no form.
#[tokio::test]
async fn submit_unwired_is_503_and_list_hides_form() {
    let f = fixture_with_runs(None, Some(Arc::new(EmptyRuns)));
    let resp = post_form(
        &f,
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("workers", "2"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let (t, c) = active_cookies(&f);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get("/app/runs").header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        !body_text(resp)
            .await
            .contains(r#"action="/app/runs/submit""#)
    );
}

/// `TestServeRunListRendersSubmitForm` — the wired list renders the
/// form with the hidden csrf + per-render idempotency fields.
#[tokio::test]
async fn list_renders_submit_form_when_wired() {
    let f = fixture_with_runs(
        Some(Arc::new(FakeSubmitter::ok())),
        Some(Arc::new(EmptyRuns)),
    );
    let (t, c) = active_cookies(&f);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get("/app/runs").header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains(r#"action="/app/runs/submit""#));
    assert!(body.contains(r#"name="csrf""#));
    assert!(body.contains(r#"name="idempotency_key""#));
    assert!(body.contains(r#"name="workers""#));
    assert!(body.contains(r#"name="run_key""#));
}

/// Anonymous `/app/runs` renders the same bootstrap shell every safe
/// `/app` GET renders.
#[tokio::test]
async fn anonymous_runs_renders_bootstrap() {
    let f = fixture(Some(Arc::new(FakeSubmitter::ok())));
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(get("/app/runs")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_text(resp).await.contains("Bootstrap"));
}
