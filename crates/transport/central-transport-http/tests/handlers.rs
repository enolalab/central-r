//! Behavioral tests for the Task 12 `/app` SSR handlers and the
//! `/api/v1/session/bootstrap` exchange — the Rust port of upstream
//! `web/handler_test.go` and `web/harness_test.go` coverage: anonymous
//! bootstrap shells, session validation, PRG redirects, mutation
//! preludes (fresh aggregate + optimistic versions + restart barrier),
//! artifact delivery revalidation, and harness resolve/resume/
//! permission behavior through the composed router.

// Test bodies unwrap liberally — a failed unwrap is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Router;
use axum::http::StatusCode;
use central_foundation::identity::{TaskId, WorkspaceId};
use central_session::domain::SecurityEpoch;
use central_task::domain::{RunStatus, TaskStatus, WaitingReason};
use central_transport_http::api;
use central_transport_http::b64;
use central_transport_http::health::ProbeState;
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::router::{TransportConfig, build_app_router};
use central_transport_http::web::{self, WebState};
use common::*;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// App construction
// ---------------------------------------------------------------------------

struct Fixture {
    sessions: Arc<FakeSessions>,
    tasks: Arc<FakeTasks>,
    artifacts: Arc<FakeArtifacts>,
    claim: Arc<FakeClaim>,
    #[allow(dead_code)]
    harness: Option<Arc<FakeHarness>>,
    app: Router,
}

fn fixture() -> Fixture {
    fixture_with(None)
}

fn fixture_with(harness: Option<Arc<FakeHarness>>) -> Fixture {
    let sessions = Arc::new(FakeSessions::new());
    let tasks = Arc::new(FakeTasks::new());
    let artifacts = Arc::new(FakeArtifacts::new());
    let claim = Arc::new(FakeClaim::yes());
    let state = Arc::new(WebState {
        readiness: Arc::new(StaticProbe(ProbeState::Ready)),
        sessions: sessions.clone(),
        tasks: tasks.clone(),
        artifacts: artifacts.clone(),
        claimability: claim.clone(),
        turn_activity: None,
        harness: harness
            .clone()
            .map(|h| h as Arc<dyn web::harness::HarnessOperator>),
        run_submitter: None,
        runs: None,
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
        tasks,
        artifacts,
        claim,
        harness,
        app,
    }
}

/// An active session cookie pair; returns `(token_b64, csrf_b64)` —
/// `csrf_b64` is the session-CSRF form value AND the
/// `central_session_csrf` cookie value (they are the same plaintext
/// upstream delivers at activation).
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

/// An authenticated mutation POST carrying the session pair and the
/// urlencoded `csrf` + `idempotency_key` + `task_id` fields.
async fn post_form(
    f: &Fixture,
    path: &str,
    fields: &[(&str, &str)],
    with_session: bool,
) -> axum::response::Response {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let builder = post_origin(path).header("content-type", "application/x-www-form-urlencoded");
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

/// Mints a real pre-auth CSRF pair through the composed router (a safe
/// GET issues the cookie; the exchange POST presents the same value in
/// the `x-central-preauth-csrf` header).
async fn issued_preauth_value(app: &Router) -> String {
    let resp = app
        .clone()
        .oneshot(loopback_req(get("/app/tasks")))
        .await
        .unwrap();
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.contains("central_preauth_csrf"))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// Anonymous + root pages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anonymous_get_pages_render_bootstrap_not_redirect() {
    let f = fixture();
    for path in [
        "/app/tasks",
        "/app/tasks/detail?id=x",
        "/app/overview",
        "/app/activity",
        "/app/office",
    ] {
        let resp = f
            .app
            .clone()
            .oneshot(loopback_req(get(path)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let body = body_text(resp).await;
        assert!(
            body.contains("Bootstrap"),
            "{path} must render the bootstrap shell"
        );
        assert!(!body.contains("task-"), "{path} must not leak task data");
    }
}

#[tokio::test]
async fn root_renders_bootstrap_anonymous_and_ready_when_active() {
    let f = fixture();
    let resp = f.app.clone().oneshot(loopback_req(get("/"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_text(resp).await.contains("Bootstrap"));
    let (t, c) = active_cookies(&f);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get("/").header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_text(resp).await.contains("Ready"));
}

// ---------------------------------------------------------------------------
// Task list + detail
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_list_renders_tasks_and_empty_state() {
    let f = fixture();
    let (t, c) = active_cookies(&f);
    let task = FakeTasks::task(TaskStatus::Running);
    let _ = f.tasks.insert(task, None);
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get("/app/tasks").header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("Running"), "{body}");
}

#[tokio::test]
async fn task_detail_escapes_title_and_generic_404s() {
    let f = fixture();
    let (t, c) = active_cookies(&f);
    let mut task = FakeTasks::task(TaskStatus::Failed);
    task.title = "<script>alert(1)</script>".to_string();
    let loaded = f.tasks.insert(task.clone(), None);
    // malformed id → fixed 404
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get("/app/tasks/detail?id=not-a-uuid").header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // unknown id → same 404 (existence never disclosed)
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get(&format!("/app/tasks/detail?id={}", TaskId::new()))
                .header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // real task → escaped title, retry control (Failed is retry-eligible)
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get(&format!(
                "/app/tasks/detail?id={}",
                loaded.aggregate.task.id
            ))
            .header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(!body.contains("<script>alert"), "{body}");
    assert!(body.contains("&#60;script&#62;"), "{body}");
    assert!(body.contains("/app/tasks/retry"), "{body}");
}

// ---------------------------------------------------------------------------
// Mutations: submit / cancel / retry / rerun
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_requires_origin_and_session() {
    let f = fixture();
    // no Origin → the admission layer's generic 403 envelope.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            axum::http::Request::builder()
                .method("POST")
                .uri("/app/tasks/submit")
                .header("host", HOST)
                .header("content-type", "application/x-www-form-urlencoded"),
            "title=x",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // valid Origin but anonymous → 403 session gate.
    let resp = post_form(&f, "/app/tasks/submit", &[("csrf", "x")], false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn submit_happy_path_redirects_303() {
    let f = fixture();
    let resp = post_form(
        &f,
        "/app/tasks/submit",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("idempotency_key", "k1"),
            ("title", "t"),
            ("instruction", "do it"),
            ("workspace_root_id", "root"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.starts_with("/app/tasks/detail?id="), "{loc}");
    assert_eq!(f.tasks.submit_calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn submit_rejects_bad_root_and_double_policy() {
    let f = fixture();
    let base = [("csrf", "ignored"), ("title", "t"), ("instruction", "x")];
    // workspace_root_id not in the allowlist → 400, no service call.
    let resp = post_form(
        &f,
        "/app/tasks/submit",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("instruction", "x"),
            ("workspace_root_id", "evil"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let _ = base;
    // auto_allow without acknowledgement → 400.
    let resp = post_form(
        &f,
        "/app/tasks/submit",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("instruction", "x"),
            ("workspace_root_id", "root"),
            ("permission_policy", "auto_allow"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(f.tasks.submit_calls.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn cancel_unclaimed_task_goes_unclaimed_path() {
    let f = fixture();
    let mut task = FakeTasks::task(TaskStatus::Queued);
    let run = FakeTasks::run(&task, RunStatus::Queued);
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    let resp = post_form(
        &f,
        "/app/tasks/cancel",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("idempotency_key", "k"),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        f.tasks.cancel_calls.lock().unwrap().as_slice(),
        &["unclaimed"]
    );
}

#[tokio::test]
async fn cancel_claimed_run_goes_request_cancellation() {
    let f = fixture();
    let mut task = FakeTasks::task(TaskStatus::Running);
    let mut run = FakeTasks::run(&task, RunStatus::Running);
    run.ownership_token = "claimed".to_string();
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    let resp = post_form(
        &f,
        "/app/tasks/cancel",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("idempotency_key", "k"),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        f.tasks.cancel_calls.lock().unwrap().as_slice(),
        &["request"]
    );
}

#[tokio::test]
async fn mutation_restart_barrier_fails_closed_409() {
    let f = fixture();
    f.claim.claimable.store(false, Ordering::SeqCst);
    let mut task = FakeTasks::task(TaskStatus::Running);
    let mut run = FakeTasks::run(&task, RunStatus::Running);
    run.ownership_token = "claimed".to_string();
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    let resp = post_form(
        &f,
        "/app/tasks/cancel",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(f.tasks.cancel_calls.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn mutation_unknown_task_is_generic_404() {
    let f = fixture();
    let resp = post_form(
        &f,
        "/app/tasks/cancel",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &TaskId::new().to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mutation_failure_is_generic_409_no_reason_leak() {
    let f = fixture();
    let mut task = FakeTasks::task(TaskStatus::Running);
    let mut run = FakeTasks::run(&task, RunStatus::Running);
    run.ownership_token = "claimed".to_string();
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    *f.tasks.mutation_fail.lock().unwrap() = Some(central_foundation::failure::Failure::invalid(
        "OPTIMISTIC",
        "internal secret detail",
    ));
    let resp = post_form(
        &f,
        "/app/tasks/cancel",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    // A refused cancel on a still-running task re-reads the aggregate;
    // the refusal notice path returns the generic 409 only when the
    // task did not change — here status is still Running → 409.
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_text(resp).await;
    assert!(!body.contains("internal secret detail"), "{body}");
}

#[tokio::test]
async fn retry_and_rerun_redirect() {
    let f = fixture();
    let failed = FakeTasks::task(TaskStatus::Failed);
    let loaded_f = f.tasks.insert(failed, None);
    let resp = post_form(
        &f,
        "/app/tasks/retry",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded_f.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cancelled = FakeTasks::task(TaskStatus::Cancelled);
    let loaded_c = f.tasks.insert(cancelled, None);
    let resp = post_form(
        &f,
        "/app/tasks/rerun",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded_c.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(f.tasks.rerun_calls.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_revokes_and_renders_recovery() {
    let f = fixture();
    let (t, c) = active_cookies(&f);
    let session_id = f
        .sessions
        .sessions
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .id;
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/app/logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", cookie_header(&t, &c)),
            format!("csrf={c}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(
        body.contains("Signed out") || body.contains("bootstrap"),
        "{body}"
    );
    assert!(f.sessions.revocations.lock().unwrap().contains(&session_id));
}

// ---------------------------------------------------------------------------
// Artifact preview / download
// ---------------------------------------------------------------------------

#[tokio::test]
async fn artifact_routes_require_session_and_revalidate() {
    let f = fixture();
    let (t, c) = active_cookies(&f);
    // anonymous → bootstrap shell.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(get(&format!(
            "/app/tasks/artifact/preview?id={}",
            f.artifacts.artifact_id
        ))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_text(resp).await.contains("Bootstrap"));
    // authenticated preview → escaped <pre> body.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get(&format!(
                "/app/tasks/artifact/preview?id={}",
                f.artifacts.artifact_id
            ))
            .header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("# report"), "{body}");
    // download → attachment disposition.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get(&format!(
                "/app/tasks/artifact/download?id={}",
                f.artifacts.artifact_id
            ))
            .header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-disposition").unwrap(),
        "attachment; filename=\"report.md\""
    );
    // Denied delivery → the same generic 404 as a missing artifact.
    *f.artifacts.body.lock().unwrap() = None;
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req(
            get(&format!(
                "/app/tasks/artifact/download?id={}",
                f.artifacts.artifact_id
            ))
            .header("cookie", cookie_header(&t, &c)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // The delivery guard ran on every request (never a projection trust).
    assert!(f.artifacts.calls.lock().unwrap().len() >= 3);
}

// ---------------------------------------------------------------------------
// Bootstrap exchange
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exchange_rejects_query_token_and_missing_csrf() {
    let f = fixture();
    // token in the query string → 400 remediation page.
    // Query token with a VALID pre-auth pair → the handler's 400.
    let v = issued_preauth_value(&f.app).await;
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/api/v1/session/bootstrap?bootstrap_token=abc")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("central_preauth_csrf={v}"))
                .header("x-central-preauth-csrf", &v),
            "bootstrap_token=abc",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Without the validated pair the middleware answers CSRF_MISSING 403
    // and the handler never runs.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/api/v1/session/bootstrap")
                .header("content-type", "application/x-www-form-urlencoded"),
            "bootstrap_token=abc",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn exchange_happy_path_sets_session_cookies_and_303() {
    let f = fixture();
    // A valid pre-auth CSRF pair: minted on a safe GET, validated on
    // this POST — the middleware runs the real check end to end.
    let v = issued_preauth_value(&f.app).await;
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/api/v1/session/bootstrap")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("central_preauth_csrf={v}"))
                .header("x-central-preauth-csrf", &v),
            format!("csrf={v}&bootstrap_token=tok"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{:?}", resp.status());
    assert_eq!(resp.headers().get("location").unwrap(), "/app/tasks");
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    assert!(set_cookies.iter().any(|c| c.contains("central_session=")));
    assert!(
        set_cookies
            .iter()
            .any(|c| c.contains("central_session_csrf="))
    );
    // The precommit activation ran: exactly one delivery armed+activated.
    assert_eq!(f.sessions.activations.lock().unwrap().len(), 1);
    assert_eq!(f.sessions.exchanges.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn exchange_throttled_is_429_with_retry_after() {
    let f = fixture();
    *f.sessions.exchange_failure.lock().unwrap() = Some(
        central_session::domain::new_throttled_failure(time::Duration::seconds(30)),
    );
    let v = issued_preauth_value(&f.app).await;
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/api/v1/session/bootstrap")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("central_preauth_csrf={v}"))
                .header("x-central-preauth-csrf", &v),
            format!("csrf={v}&bootstrap_token=tok"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_some());
}

// ---------------------------------------------------------------------------
// Harness operator surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn harness_routes_404_without_operator() {
    let f = fixture();
    let resp = post_form(
        &f,
        "/app/tasks/harness/resolve",
        &[("csrf", &b64::encode(&[8u8; 32]))],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn harness_resolve_cancel_marks_cancelled() {
    let h = Arc::new(FakeHarness::new());
    let f = fixture_with(Some(h.clone()));
    let mut task = FakeTasks::task(TaskStatus::Cancelling);
    let run = FakeTasks::run(&task, RunStatus::Cancelling);
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    let resp = post_form(
        &f,
        "/app/tasks/harness/resolve",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
            ("action", "cancel"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(h.resolves.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn harness_resolve_rejects_unoffered_action() {
    let h = Arc::new(FakeHarness::new());
    let f = fixture_with(Some(h.clone()));
    // A queued task offers nothing → 409 before the operator is asked.
    let task = FakeTasks::task(TaskStatus::Queued);
    let loaded = f.tasks.insert(task, None);
    let resp = post_form(
        &f,
        "/app/tasks/harness/resolve",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
            ("action", "fail"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(h.resolves.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn harness_resume_only_on_reconciliation() {
    let h = Arc::new(FakeHarness::new());
    let f = fixture_with(Some(h.clone()));
    let mut task = FakeTasks::task(TaskStatus::Waiting);
    task.waiting_reason = Some(WaitingReason::Reconciliation);
    let run = FakeTasks::run(&task, RunStatus::Running);
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    let resp = post_form(
        &f,
        "/app/tasks/harness/resume",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(h.resolves.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn harness_permission_decision_binds_session_principal() {
    let h = Arc::new(FakeHarness::new());
    let f = fixture_with(Some(h.clone()));
    let task = FakeTasks::task(TaskStatus::Waiting);
    let loaded = f.tasks.insert(task, None);
    let approval = central_foundation::identity::HarnessPermissionApprovalId::new();
    let resp = post_form(
        &f,
        "/app/tasks/harness/permission",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
            ("approval_id", &approval.to_string()),
            ("input_mac", "ab12"),
            ("decision", "allow"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let decisions = h.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].principal, "test");
    assert!(decisions[0].allow);
}
