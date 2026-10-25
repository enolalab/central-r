//! Review-round-1 regression tests — one block per finding (C1, I1,
//! I2, I3, M1, M3, M7), each pinning the upstream contract the fix
//! restores (upstream `handler.go`, `repository_analysis_input.go`,
//! `budget_view.go`, `serve_composition.go`).

// Test bodies unwrap liberally — a failed unwrap is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Router;
use axum::http::{Method, StatusCode};
use central_foundation::identity::{RunId, WorkspaceId};
use central_session::domain::SecurityEpoch;
use central_task::domain::{RunStatus, TaskStatus};
use central_task::port::LoadedAggregate;
use central_transport_http::api;
use central_transport_http::b64;
use central_transport_http::health::ProbeState;
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::policy;
use central_transport_http::router::{TransportConfig, build_app_router};
use central_transport_http::web::budget_view::format_budget_duration;
use central_transport_http::web::repository_analysis;
use central_transport_http::web::{self, WebState};
use common::*;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// App construction (same shape as tests/handlers.rs)
// ---------------------------------------------------------------------------

struct Fixture {
    sessions: Arc<FakeSessions>,
    tasks: Arc<FakeTasks>,
    state: Arc<WebState>,
    app: Router,
}

fn fixture() -> Fixture {
    fixture_with(None)
}

fn fixture_with(harness: Option<Arc<FakeHarness>>) -> Fixture {
    let sessions = Arc::new(FakeSessions::new());
    let tasks = Arc::new(FakeTasks::new());
    let state = Arc::new(WebState {
        readiness: Arc::new(StaticProbe(ProbeState::Ready)),
        sessions: sessions.clone(),
        tasks: tasks.clone(),
        artifacts: Arc::new(FakeArtifacts::new()),
        claimability: Arc::new(FakeClaim::yes()),
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
        state,
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
// C1 — the repository-analysis parser must decode JSON escapes
// ---------------------------------------------------------------------------

#[test]
fn c1_parse_decodes_escaped_member_names_and_values() {
    let roots = vec!["root".to_string()];
    // `instru\u0063tion` decodes to `instruction`, `\u0072oot` to
    // `root`, and `\"`/`\n`/`\\` inside the instruction — upstream's
    // `json.Unmarshal` decodes escapes before every check, so the
    // decoded text is what the predicates (and the allowlist) see.
    let raw = br#"{"schema_version":"repository_analysis/v1","instru\u0063tion":"say \"hi\"\nthen C:\\tmp","workspace_root_id":"\u0072oot"}"#;
    let parsed = repository_analysis::parse_repository_analysis_input(raw, &roots).unwrap();
    assert_eq!(parsed.instruction, "say \"hi\"\nthen C:\\tmp");
    assert_eq!(parsed.workspace_root_id, "root");
    // A member repeated only through an escape is still a duplicate.
    let dup = br#"{"schema_version":"repository_analysis/v1","instruction":"a","instru\u0063tion":"b","workspace_root_id":"root"}"#;
    assert!(
        repository_analysis::parse_repository_analysis_input(dup, &roots).is_err(),
        "a decoded duplicate member name must refuse"
    );
}

#[tokio::test]
async fn c1_submit_accepts_instruction_with_escapes_303() {
    let f = fixture();
    // The form field decodes to `say "hi" then\split` + a real newline
    // + `second line`; the canonical JSON the server serializes
    // escapes every one — the borrowed-&str parse rejected exactly
    // this submission with a 400 where upstream issues the 303.
    let resp = post_form(
        &f,
        "/app/tasks/submit",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("instruction", "say+%22hi%22+then%5Csplit%0Asecond+line"),
            ("workspace_root_id", "root"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let calls = f.tasks.submit_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    // The escaped canonical JSON persists verbatim as the Task input.
    let stored = &calls[0].input;
    assert!(stored.contains("\\n"), "{stored}");
    assert!(stored.contains("\\\"hi\\\""), "{stored}");
    assert!(stored.contains("\\\\split"), "{stored}");
}

#[tokio::test]
async fn c1_detail_renders_stored_input_with_escapes() {
    let f = fixture();
    let (t, c) = active_cookies(&f);
    let mut task = FakeTasks::task(TaskStatus::Queued);
    // A stored input the submit path itself produced — escapes and
    // all. The display parse used to fail on it and drop the section.
    task.input = r#"{"schema_version":"repository_analysis/v1","instruction":"line one\nline \"two\"","workspace_root_id":"root"}"#
        .to_string();
    let loaded = f.tasks.insert(task, None);
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
    assert!(body.contains("line one"), "{body}");
    assert!(body.contains("two"), "{body}");
    assert!(body.contains("Repository root"), "{body}");
}

// ---------------------------------------------------------------------------
// I1 — the cancel refusal notice is exactly upstream's five conjuncts
// ---------------------------------------------------------------------------

/// An aggregate whose `Unclaimed()` is true: a never-claimed run on a
/// queued or cancelling task.
fn unclaimed_loaded(f: &Fixture, status: TaskStatus, run_status: RunStatus) -> LoadedAggregate {
    let mut task = FakeTasks::task(status);
    let run = FakeTasks::run(&task, run_status);
    task.current_run_id = Some(run.id);
    f.tasks.insert(task, Some(run))
}

/// The loaded aggregate as it re-reads after the dispatcher claimed
/// the SAME run (the lost-race shape upstream's notice names).
fn claimed_same_run(
    loaded: &LoadedAggregate,
    task_status: TaskStatus,
    run_status: RunStatus,
) -> LoadedAggregate {
    let mut reload = loaded.clone();
    reload.aggregate.task.status = task_status;
    let run = reload.aggregate.current_run.as_mut().unwrap();
    run.status = run_status;
    run.ownership_token = "dispatcher".to_string();
    reload
}

fn inject_conflict(f: &Fixture) {
    *f.tasks.mutation_fail.lock().unwrap() = Some(central_foundation::failure::Failure::invalid(
        "OPTIMISTIC",
        "task version mismatch",
    ));
}

async fn cancel(
    f: &Fixture,
    task_id: central_foundation::identity::TaskId,
) -> axum::response::Response {
    post_form(
        f,
        "/app/tasks/cancel",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &task_id.to_string()),
        ],
        true,
    )
    .await
}

#[tokio::test]
async fn i1_cancel_lost_claim_notice_needs_all_five_conjuncts() {
    // All five: loaded Queued, re-read not terminal, re-read has a
    // current Run, the SAME run, now claimed → 303 + cancel_started.
    let f = fixture();
    let loaded = unclaimed_loaded(&f, TaskStatus::Queued, RunStatus::Queued);
    *f.tasks.reload_aggregate.lock().unwrap() = Some(claimed_same_run(
        &loaded,
        TaskStatus::Running,
        RunStatus::Running,
    ));
    inject_conflict(&f);
    let resp = cancel(&f, loaded.aggregate.task.id).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        loc,
        &format!(
            "/app/tasks/detail?id={}&notice=cancel_started",
            loaded.aggregate.task.id
        ),
        "{loc}"
    );
}

#[tokio::test]
async fn i1_cancel_refusal_otherwise_stays_generic_409() {
    for (name, loaded_status, loaded_run, mutate) in [
        // The loaded task was Cancelling, not Queued — a claimed
        // re-read alone never earned the notice upstream.
        (
            "cancelling loaded task",
            TaskStatus::Cancelling,
            RunStatus::Cancelling,
            0u8,
        ),
        // The re-read is terminal — no claim race to explain.
        (
            "re-read now failed",
            TaskStatus::Queued,
            RunStatus::Queued,
            1u8,
        ),
        // A DIFFERENT run carries the claim — not this run's race.
        (
            "different run claimed",
            TaskStatus::Queued,
            RunStatus::Queued,
            2u8,
        ),
        // The re-read run still has no ownership token.
        (
            "reload still unclaimed",
            TaskStatus::Queued,
            RunStatus::Queued,
            3u8,
        ),
    ] {
        let f = fixture();
        let loaded = unclaimed_loaded(&f, loaded_status, loaded_run);
        let mut reload = claimed_same_run(&loaded, TaskStatus::Running, RunStatus::Running);
        match mutate {
            1 => {
                reload.aggregate.task.status = TaskStatus::Failed;
                reload.aggregate.current_run.as_mut().unwrap().status = RunStatus::Failed;
            }
            2 => {
                let run = reload.aggregate.current_run.as_mut().unwrap();
                run.id = RunId::new();
                reload.aggregate.task.current_run_id = Some(run.id);
            }
            3 => {
                reload
                    .aggregate
                    .current_run
                    .as_mut()
                    .unwrap()
                    .ownership_token = String::new();
            }
            _ => {}
        }
        *f.tasks.reload_aggregate.lock().unwrap() = Some(reload);
        inject_conflict(&f);
        let resp = cancel(&f, loaded.aggregate.task.id).await;
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "{name}: a re-read outside the five conjuncts is the generic 409"
        );
    }
}

#[tokio::test]
async fn i1_cancel_of_task_cancelled_meanwhile_notices_already_cancelled() {
    let f = fixture();
    let loaded = unclaimed_loaded(&f, TaskStatus::Queued, RunStatus::Queued);
    let mut reload = loaded.clone();
    reload.aggregate.task.status = TaskStatus::Cancelled;
    reload.aggregate.current_run.as_mut().unwrap().status = RunStatus::Cancelled;
    *f.tasks.reload_aggregate.lock().unwrap() = Some(reload);
    inject_conflict(&f);
    let resp = cancel(&f, loaded.aggregate.task.id).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.ends_with("&notice=already_cancelled"), "{loc}");
}

// ---------------------------------------------------------------------------
// I2 — the seven /app/tasks/* mutations cap at 1 MiB, not 2 MiB
// ---------------------------------------------------------------------------

#[test]
fn i2_every_task_mutation_route_carries_the_1mib_body_limit() {
    let f = fixture();
    let mut seen = 0;
    for r in web::routes(&f.state) {
        if r.spec.method == Method::POST && r.spec.path.starts_with("/app/tasks") {
            assert_eq!(
                r.spec.policy.body_limit,
                policy::DEFAULT_BOOTSTRAP_BODY_LIMIT,
                "{} must cap at upstream's DefaultBootstrapBodyLimit",
                r.spec.path
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 7, "submit/cancel/retry/rerun + 3 harness mutations");
}

#[tokio::test]
async fn i2_mutation_body_over_1mib_refused_before_the_handler() {
    let f = fixture();
    let (t, c) = active_cookies(&f);
    // A form body just over 1 MiB: the session-CSRF body read fails
    // inside the route's own RequestBodyLimit → the fixed 403 outcome
    // upstream's unreadable `parseBodyForm` produces.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/app/tasks/submit")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", cookie_header(&t, &c)),
            format!("csrf={c}&pad={}", "x".repeat(1 << 20)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.tasks.submit_calls.lock().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// I3 — the retry harness gate: Failed-only and a 500 on read failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i3_retry_state_never_runs_for_a_non_failed_task() {
    let h = Arc::new(FakeHarness::new());
    h.retry_state_fails.store(true, Ordering::SeqCst);
    let f = fixture_with(Some(h.clone()));
    // A Running task is not retry-eligible: upstream proceeds straight
    // to the domain call, so a retry_state failure cannot mask it with
    // a 503 (the pre-fix behavior).
    let mut task = FakeTasks::task(TaskStatus::Running);
    let mut run = FakeTasks::run(&task, RunStatus::Running);
    run.ownership_token = "claimed".to_string();
    task.current_run_id = Some(run.id);
    let loaded = f.tasks.insert(task, Some(run));
    let resp = post_form(
        &f,
        "/app/tasks/retry",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(
        h.retry_state_calls.load(Ordering::SeqCst),
        0,
        "retry_state must not run outside taskRetryEligible"
    );
    // The fake's domain succeeds — the pinned contract is "never the
    // retry_state failure status".
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn i3_retry_state_read_failure_is_500_not_503() {
    let h = Arc::new(FakeHarness::new());
    h.retry_state_fails.store(true, Ordering::SeqCst);
    let f = fixture_with(Some(h));
    let task = FakeTasks::task(TaskStatus::Failed);
    let loaded = f.tasks.insert(task, None);
    let resp = post_form(
        &f,
        "/app/tasks/retry",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(f.tasks.retry_calls.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn i3_retry_blocked_by_cost_cap_is_409() {
    let h = Arc::new(FakeHarness::new());
    h.retry_blocked.store(true, Ordering::SeqCst);
    let f = fixture_with(Some(h));
    let task = FakeTasks::task(TaskStatus::Failed);
    let loaded = f.tasks.insert(task, None);
    let resp = post_form(
        &f,
        "/app/tasks/retry",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("task_id", &loaded.aggregate.task.id.to_string()),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(f.tasks.retry_calls.lock().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// M1 — the exchange checks the DECODED query after the body parse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m1_exchange_refuses_percent_encoded_bootstrap_token_key() {
    let f = fixture();
    let v = issued_preauth_value(&f.app).await;
    // `?bootstrap%5Ftoken=x` decodes to `bootstrap_token` — Go's
    // `r.URL.Query()` refuses it exactly like the literal spelling.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/api/v1/session/bootstrap?bootstrap%5Ftoken=x")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("central_preauth_csrf={v}"))
                .header("x-central-preauth-csrf", &v),
            format!("csrf={v}&bootstrap_token=tok"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_text(resp).await;
    assert!(
        body.contains("must be submitted in the form body"),
        "{body}"
    );
    assert_eq!(f.sessions.exchanges.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn m1_unreadable_body_takes_precedence_over_query_token() {
    let f = fixture();
    let v = issued_preauth_value(&f.app).await;
    // Upstream parses the body FIRST: a body over the route's own
    // 1 MiB cap yields FORM_UNREADABLE even though the query token is
    // present — the two remediations are distinguishable page text.
    let resp = f
        .app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/api/v1/session/bootstrap?bootstrap_token=x")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("central_preauth_csrf={v}"))
                .header("x-central-preauth-csrf", &v),
            format!("csrf={v}&pad={}", "x".repeat(1 << 20)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_text(resp).await;
    assert!(body.contains("could not be read"), "{body}");
}

// ---------------------------------------------------------------------------
// M3 — format_budget_duration matches Go time.Duration.String()
// ---------------------------------------------------------------------------

#[test]
fn m3_budget_duration_matches_go_duration_shape() {
    for (secs, want) in [
        (60i64, "1 minute"),
        (120, "2 minutes"),
        (600, "10 minutes"),
        // Whole minutes take the "N minutes" branch even past an hour
        // (upstream `d % time.Minute == 0` wins over `d.String()`).
        (3600, "60 minutes"),
        (3660, "61 minutes"),
        // Non-whole-minute values render Go's Duration.String():
        // seconds always, minutes while nonzero, hours the top unit.
        (90, "1m30s"),
        (3599, "59m59s"),
        (3601, "1h0m1s"),
        (3661, "1h1m1s"),
        (90_061, "25h1m1s"),
        (30, "30s"),
        (0, "0s"),
        (-90, "-1m30s"),
    ] {
        assert_eq!(format_budget_duration(secs), want, "{secs}s");
    }
}

// ---------------------------------------------------------------------------
// M7 — an empty idempotency_key maps to `None` (upstream `""` ≡ no
// receipt either way: both stores gate the dedup row on non-empty)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m7_absent_or_empty_idempotency_key_maps_to_none() {
    let f = fixture();
    // Field absent entirely.
    let resp = post_form(
        &f,
        "/app/tasks/submit",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("title", "t"),
            ("instruction", "do it"),
            ("workspace_root_id", "root"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Field present but empty — upstream's verbatim `""`.
    let resp = post_form(
        &f,
        "/app/tasks/submit",
        &[
            ("csrf", &b64::encode(&[8u8; 32])),
            ("idempotency_key", ""),
            ("title", "t"),
            ("instruction", "do it again"),
            ("workspace_root_id", "root"),
        ],
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let metas = f.tasks.metas.lock().unwrap();
    assert_eq!(metas.len(), 2);
    for (i, m) in metas.iter().enumerate() {
        assert!(
            m.idempotency_key.is_none(),
            "meta {i}: an absent/empty key must be None, got {:?}",
            m.idempotency_key
        );
    }
}
