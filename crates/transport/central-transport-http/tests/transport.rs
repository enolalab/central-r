//! Behavioral tests for the §4 transport contract — admission bounds,
//! security headers, Origin/CSRF guards, session gate, buffered
//! precommit, health and metrics. Mirrors the upstream
//! `middleware_test.go`/`handler_test.go` coverage through
//! `tower::ServiceExt` calls on the composed router.

// Test bodies unwrap liberally — a failed unwrap is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{MethodRouter, get as rget, post as rpost};
use central_foundation::identity::SessionId;
use central_session::domain::{DeliveryId, SecurityEpoch};
use central_transport_http::b64;
use central_transport_http::health::{ProbeSnapshot, ProbeState, ReadinessProbe};
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::middleware::buffer::Precommit;
use central_transport_http::policy::{self, RouteClass, RoutePolicy, RouteSpec};
use central_transport_http::ports::PreAuthCsrf;
use central_transport_http::router::{
    RoutedSpec, TransportConfig, build_app_router, build_ops_router,
};
use common::*;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test app construction
// ---------------------------------------------------------------------------

fn policy_app() -> RoutePolicy {
    RoutePolicy::safe_get(RouteClass::App)
}

fn session_get_policy() -> RoutePolicy {
    let mut p = RoutePolicy::safe_get(RouteClass::App);
    p.session_required = true;
    p
}

fn session_api_get_policy() -> RoutePolicy {
    let mut p = RoutePolicy::safe_get(RouteClass::Api);
    p.session_required = true;
    p
}

fn mutation_policy(class: RouteClass) -> RoutePolicy {
    let mut p = RoutePolicy::safe_get(class);
    p.origin_required = true;
    p.state_changing = true;
    p.session_required = true;
    p.session_csrf_required = true;
    p.csrf_required = true;
    p.body_limit = policy::DEFAULT_BOOTSTRAP_BODY_LIMIT;
    p.restart_barrier = true;
    p
}

fn spec(method: axum::http::Method, path: &'static str, policy: RoutePolicy) -> RouteSpec {
    RouteSpec {
        method,
        path,
        policy,
    }
}

fn routed(
    method: axum::http::Method,
    path: &'static str,
    policy: RoutePolicy,
    handler: MethodRouter,
) -> RoutedSpec {
    RoutedSpec {
        spec: spec(method, path, policy),
        handler,
    }
}

fn test_app(sessions: Arc<FakeSessions>) -> Router {
    test_app_with(routes_default(), sessions, AdmissionConfig::default())
}

fn routes_default() -> Vec<RoutedSpec> {
    vec![
        routed(
            axum::http::Method::GET,
            "/",
            policy_app(),
            rget(|| async { "root" }),
        ),
        routed(
            axum::http::Method::GET,
            "/app/bootstrap",
            {
                let mut p = policy_app();
                p.issue_pre_auth_csrf = true;
                p
            },
            rget(|| async { "bootstrap" }),
        ),
        routed(
            axum::http::Method::POST,
            "/api/v1/session/bootstrap",
            {
                let mut p = RoutePolicy::safe_get(RouteClass::Api);
                p.origin_required = true;
                p.state_changing = true;
                p.csrf_required = true;
                p.body_limit = policy::DEFAULT_BOOTSTRAP_BODY_LIMIT;
                p
            },
            rpost(|| async { "exchanged" }),
        ),
        routed(
            axum::http::Method::GET,
            "/app/tasks",
            session_get_policy(),
            rget(|| async { "tasks" }),
        ),
        routed(
            axum::http::Method::GET,
            "/api/v1/tasks",
            session_api_get_policy(),
            rget(|| async { "tasks api" }),
        ),
        routed(
            axum::http::Method::POST,
            "/app/logout",
            mutation_policy(RouteClass::App),
            rpost(|| async { "logged out" }),
        ),
        routed(
            axum::http::Method::POST,
            "/app/tasks/{task_id}/cancel",
            mutation_policy(RouteClass::App),
            rpost(|| async { "cancelled" }),
        ),
        routed(
            axum::http::Method::POST,
            "/api/v1/tasks/cancel",
            mutation_policy(RouteClass::Api),
            rpost(|| async { "api cancelled" }),
        ),
        routed(
            axum::http::Method::GET,
            "/assets/{name}",
            RoutePolicy::safe_get(RouteClass::Asset),
            rget(
                |axum::extract::Path(name): axum::extract::Path<String>| async move {
                    central_transport_http::assets::response(&name)
                        .unwrap_or_else(|| central_transport_http::error::not_found(""))
                },
            ),
        ),
        routed(
            axum::http::Method::GET,
            "/app/big",
            {
                let mut p = policy_app();
                p.response_cap = 16;
                p
            },
            rget(|| async { "this body is far larger than sixteen bytes" }),
        ),
        routed(
            axum::http::Method::POST,
            "/echo",
            {
                let mut p = RoutePolicy::safe_get(RouteClass::Api);
                p.body_limit = 16;
                p.state_changing = true;
                p.origin_required = true;
                p
            },
            rpost(|body: Bytes| async move { body }),
        ),
        routed(
            axum::http::Method::GET,
            "/app/panic",
            policy_app(),
            rget(panics),
        ),
    ]
}

/// The one deliberate panic site — recovery-path coverage; the
/// workspace `clippy::panic` deny is lifted only here.
#[allow(clippy::panic)]
async fn panics() -> &'static str {
    panic!("boom")
}

fn test_app_with(
    routes: Vec<RoutedSpec>,
    sessions: Arc<FakeSessions>,
    admission: AdmissionConfig,
) -> Router {
    build_app_router(
        routes,
        TransportConfig {
            admission: AdmissionConfig {
                expected_host: Some(HOST.to_string()),
                ..admission
            },
            expected_origin: ORIGIN.to_string(),
            preauth: sessions.clone(),
            sessions: sessions.clone(),
            delivery: sessions,
            epoch_source: Arc::new(|| SecurityEpoch(0)),
            observer: None,
        },
    )
    .unwrap()
}

async fn body_string(resp: Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn assert_security_headers(h: &HeaderMap) {
    assert_eq!(
        h.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'"
    );
    assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
    assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "same-origin");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
}

// ---------------------------------------------------------------------------
// §4.4 — security headers on every outcome
// ---------------------------------------------------------------------------

#[tokio::test]
async fn security_headers_on_every_response() {
    let app = test_app(Arc::new(FakeSessions::new()));
    for req in [
        loopback_req(get("/nope")),
        loopback_req(post_origin("/api/v1/session/bootstrap")),
        loopback_req(get("/app/bootstrap")),
        loopback_req(get("/app/panic")),
    ] {
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_security_headers(resp.headers());
    }
}

// ---------------------------------------------------------------------------
// Admission — peer, host, OPTIONS, allowlist, headers, cookies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn loopback_peer_required() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app
        .oneshot(remote_req(get("/app/bootstrap")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "PEER_NOT_LOOPBACK");
}

#[tokio::test]
async fn exact_host_enforced() {
    let app = test_app(Arc::new(FakeSessions::new()));
    // loopback peer, wrong Host
    let req = loopback_req(
        Request::builder()
            .method("GET")
            .uri("/app/bootstrap")
            .header("host", "127.0.0.1:9999"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "HOST_MISMATCH");
}

#[tokio::test]
async fn options_is_cors_disabled() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let req = loopback_req(
        Request::builder()
            .method("OPTIONS")
            .uri("/app/bootstrap")
            .header("host", HOST)
            .header("origin", ORIGIN),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let has_cors = resp
        .headers()
        .keys()
        .any(|k| k.as_str().starts_with("access-control-"));
    assert_eq!(body_string(resp).await.trim(), "CORS_DISABLED");
    assert!(!has_cors);
}

#[tokio::test]
async fn unmatched_path_fixed_404() {
    let app = test_app(Arc::new(FakeSessions::new()));
    // unclassified path → JSON envelope
    let resp = app
        .clone()
        .oneshot(loopback_req(get("/does/not/exist")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        body_string(resp).await,
        "{\"error\":{\"code\":\"NOT_FOUND\"}}"
    );
    // /app/... → HTML page
    let resp = app
        .oneshot(loopback_req(get("/app/missing")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(ct.starts_with("text/html"));
    let body = body_string(resp).await;
    assert!(body.contains("Page not found"));
    assert!(!body.contains("/app/missing"));
}

#[tokio::test]
async fn matched_path_wrong_method_405() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let req = loopback_req(
        Request::builder()
            .method("DELETE")
            .uri("/app/bootstrap")
            .header("host", HOST),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(resp.headers().get(header::ALLOW).unwrap(), "GET,HEAD");
}

#[tokio::test]
async fn trailing_slash_does_not_redirect() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app
        .oneshot(loopback_req(get("/app/bootstrap/")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn header_and_cookie_bounds() {
    let app = test_app(Arc::new(FakeSessions::new()));
    // single header > 4 KiB → 431
    let big = "v".repeat(5000);
    let resp = app
        .clone()
        .oneshot(loopback_req(get("/app/bootstrap").header("x-big", big)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    assert_eq!(body_string(resp).await.trim(), "HEADER_TOO_LARGE");
    // total headers > 32 KiB → 431
    let mut builder = get("/app/bootstrap");
    for i in 0..70 {
        builder = builder.header(format!("x-pad-{i}"), "v".repeat(512));
    }
    let resp = app.clone().oneshot(loopback_req(builder)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    assert_eq!(body_string(resp).await.trim(), "HEADERS_TOO_LARGE");
    // duplicate cookie name → 400
    let resp = app
        .oneshot(loopback_req(
            get("/app/bootstrap").header("cookie", "a=1; a=2"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_string(resp).await.trim(), "DUPLICATE_COOKIE");
}

// ---------------------------------------------------------------------------
// Origin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn origin_enforcement() {
    let app = test_app(Arc::new(FakeSessions::new()));
    // mutation route, missing Origin → 403 ORIGIN_REQUIRED
    let resp = app
        .clone()
        .oneshot(loopback_req(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/bootstrap")
                .header("host", HOST),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "ORIGIN_REQUIRED");
    // mismatch → 403 ORIGIN_MISMATCH (single, wrong Origin)
    let resp = app
        .clone()
        .oneshot(loopback_req(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/bootstrap")
                .header("host", HOST)
                .header("origin", "https://evil.example"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "ORIGIN_MISMATCH");
    // literal null → 403 NULL_ORIGIN
    let resp = app
        .clone()
        .oneshot(loopback_req(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/bootstrap")
                .header("host", HOST)
                .header("origin", "null"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "NULL_ORIGIN");
    // duplicate Origin → 400
    let resp = app
        .clone()
        .oneshot(loopback_req(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session/bootstrap")
                .header("host", HOST)
                .header("origin", ORIGIN)
                .header("origin", ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_string(resp).await.trim(), "DUPLICATE_ORIGIN");
    // present-but-bad Origin is rejected even on a safe GET
    let resp = app
        .oneshot(loopback_req(
            get("/app/bootstrap").header("origin", "https://evil.example"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "ORIGIN_MISMATCH");
}

// ---------------------------------------------------------------------------
// Pre-auth CSRF
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preauth_issue_sets_cookie() {
    let sessions = Arc::new(FakeSessions::new());
    let app = test_app(sessions.clone());
    let resp = app
        .oneshot(loopback_req(get("/app/bootstrap")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("central_preauth_csrf="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Secure"));
    assert_eq!(sessions.issued.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn preauth_csrf_validation() {
    let sessions = Arc::new(FakeSessions::new());
    let app = test_app(sessions.clone());
    let uri = "/api/v1/session/bootstrap";
    // missing cookie → CSRF_MISSING
    let resp = app
        .clone()
        .oneshot(loopback_req(post_origin(uri)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await.trim(), "CSRF_MISSING");
    // missing header → CSRF_DUPLICATE
    let pair = sessions.issue_pre_auth_csrf();
    let value = b64::encode(&pair.value());
    let cookie = format!("central_preauth_csrf={value}");
    let resp = app
        .clone()
        .oneshot(loopback_req(post_origin(uri).header("cookie", &cookie)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await.trim(), "CSRF_DUPLICATE");
    // cookie != header → CSRF_MISMATCH
    let resp = app
        .clone()
        .oneshot(loopback_req(
            post_origin(uri).header("cookie", &cookie).header(
                "x-central-preauth-csrf",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        ))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await.trim(), "CSRF_MISMATCH");
    // malformed (not 32-byte b64url) → CSRF_MALFORMED
    let resp = app
        .clone()
        .oneshot(loopback_req(
            post_origin(uri)
                .header("cookie", "central_preauth_csrf=abc")
                .header("x-central-preauth-csrf", "abc"),
        ))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await.trim(), "CSRF_MALFORMED");
    // valid pair → handler runs
    let resp = app
        .oneshot(loopback_req(
            post_origin(uri)
                .header("cookie", &cookie)
                .header("x-central-preauth-csrf", &value),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "exchanged");
}

// ---------------------------------------------------------------------------
// Session gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_session_redirects_app_get_303() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app.oneshot(loopback_req(get("/app/tasks"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/app/bootstrap"
    );
    assert_security_headers(resp.headers());
}

#[tokio::test]
async fn missing_session_api_get_401() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app
        .oneshot(loopback_req(get("/api/v1/tasks")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(resp).await,
        "{\"error\":{\"code\":\"UNAUTHORIZED\"}}"
    );
}

#[tokio::test]
async fn missing_session_app_mutation_task_action_failed() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app
        .oneshot(loopback_req(post_origin("/app/logout")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(resp).await.trim(), "TASK_ACTION_FAILED");
}

#[tokio::test]
async fn session_csrf_form_flow() {
    let sessions = Arc::new(FakeSessions::new());
    let token = [9u8; 32];
    sessions.insert_active(token);
    let token_b64 = b64::encode(&token);
    let csrf_value = [8u8; 32];
    let csrf_b64 = b64::encode(&csrf_value);
    // The fake compares sha256(presented) to the session row's csrf_hash —
    // register the row's hash as sha256(csrf_value).
    sessions
        .sessions
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|s| s.csrf_hash = Sha256::digest(csrf_value).into());
    let app = test_app(sessions);
    // valid: session cookie + csrf cookie + form csrf field match → 200
    let body = format!("csrf={csrf_b64}");
    let resp = app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/app/logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .header(
                    "cookie",
                    format!("central_session={token_b64}; central_session_csrf={csrf_b64}"),
                ),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // missing csrf cookie → CSRF_MISSING
    let resp = app
        .clone()
        .oneshot(loopback_req_body(
            post_origin("/app/logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("central_session={token_b64}")),
            format!("csrf={csrf_b64}"),
        ))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await.trim(), "CSRF_MISSING");
    // cookie/form mismatch → CSRF_MISMATCH
    let other = b64::encode(&[4u8; 32]);
    let resp = app
        .oneshot(loopback_req_body(
            post_origin("/app/logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .header(
                    "cookie",
                    format!("central_session={token_b64}; central_session_csrf={csrf_b64}"),
                ),
            format!("csrf={other}"),
        ))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await.trim(), "CSRF_MISMATCH");
}

// ---------------------------------------------------------------------------
// Buffered precommit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffered_precommit_activates_before_flush() {
    let sessions = Arc::new(FakeSessions::new());
    let routes = vec![routed(
        axum::http::Method::GET,
        "/app/deliver",
        policy_app(),
        rget(
            |axum::extract::Extension(slot): axum::extract::Extension<
                central_transport_http::middleware::buffer::ArmedSlot,
            >| async move {
                slot.0
                    .arm(Precommit {
                        delivery_id: DeliveryId::from_session_id(SessionId::new()),
                        token_hash: [1u8; 32],
                        csrf_hash: [2u8; 32],
                        identity: test_identity(),
                        epoch: SecurityEpoch(0),
                        session_id: SessionId::new(),
                    })
                    .await;
                "delivered"
            },
        ),
    )];
    let app = test_app_with(routes, sessions.clone(), AdmissionConfig::default());
    let resp = app
        .oneshot(loopback_req(get("/app/deliver")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "delivered");
    assert_eq!(sessions.activations.lock().unwrap().len(), 1);
    assert!(sessions.revocations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn buffered_precommit_activation_failure_revokes_and_500s() {
    let sessions = Arc::new(FakeSessions::new());
    sessions.activate_fails.store(true, Ordering::SeqCst);
    let routes = vec![routed(
        axum::http::Method::GET,
        "/app/deliver",
        policy_app(),
        rget(
            |axum::extract::Extension(slot): axum::extract::Extension<
                central_transport_http::middleware::buffer::ArmedSlot,
            >| async move {
                slot.0
                    .arm(Precommit {
                        delivery_id: DeliveryId::from_session_id(SessionId::new()),
                        token_hash: [1u8; 32],
                        csrf_hash: [2u8; 32],
                        identity: test_identity(),
                        epoch: SecurityEpoch(0),
                        session_id: SessionId::new(),
                    })
                    .await;
                "delivered"
            },
        ),
    )];
    let app = test_app_with(routes, sessions.clone(), AdmissionConfig::default());
    let resp = app
        .oneshot(loopback_req(get("/app/deliver")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        axum::body::to_bytes(resp.into_body(), 1 << 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(sessions.activations.lock().unwrap().len(), 1);
    assert_eq!(sessions.revocations.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Resource caps
// ---------------------------------------------------------------------------

#[tokio::test]
async fn response_cap_overflow_is_bare_500() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app.oneshot(loopback_req(get("/app/big"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        axum::body::to_bytes(resp.into_body(), 1 << 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn request_body_limit_413() {
    let app = test_app(Arc::new(FakeSessions::new()));
    // /echo caps at 16 bytes per-route
    let resp = app
        .clone()
        .oneshot(loopback_req_body(post_origin("/echo"), body_bytes(17)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // at the cap it succeeds
    let resp = app
        .oneshot(loopback_req_body(post_origin("/echo"), body_bytes(16)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn section46_installed_values() {
    assert_eq!(policy::DEFAULT_ACTIVE_LIMIT, 32);
    assert_eq!(policy::MAX_ACTIVE_LIMIT, 32);
    assert_eq!(policy::DEFAULT_WAITER_LIMIT, 64);
    assert_eq!(policy::MAX_WAITER_LIMIT, 64);
    assert_eq!(policy::DEFAULT_WAIT_TIMEOUT, Duration::from_secs(5));
    assert_eq!(policy::MAX_WAIT_TIMEOUT, Duration::from_secs(5));
    assert_eq!(policy::MAX_BODY_BUFFER, 2 << 20);
    assert_eq!(policy::MAX_RESPONSE_BUFFER, 2 << 20);
    assert_eq!(policy::MAX_PER_HEADER_BYTES, 4 << 10);
    // cross-field: 32 × 2 MiB = 64 MiB
    assert_eq!(
        (policy::MAX_ACTIVE_LIMIT as u64) * (policy::MAX_RESPONSE_BUFFER as u64),
        policy::MAX_AGGREGATE_BUFFER
    );
}

#[tokio::test]
async fn admission_queueing_and_full_rejection() {
    // Scaled-down shape of the 32/64 contract: with active=2,
    // waiters=2 — the 3rd request queues (does not reject), the 5th
    // is rejected with 503.
    let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let entered = Arc::new(AtomicUsize::new(0));
    let gate2 = gate.clone();
    let entered2 = entered.clone();
    let routes = vec![routed(
        axum::http::Method::GET,
        "/block",
        policy_app(),
        rget(move || {
            let gate = gate2.clone();
            let entered = entered2.clone();
            async move {
                entered.fetch_add(1, Ordering::SeqCst);
                while !gate.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                "done"
            }
        }),
    )];
    let app = test_app_with(
        routes,
        Arc::new(FakeSessions::new()),
        AdmissionConfig {
            expected_host: Some(HOST.to_string()),
            active_limit: 2,
            waiter_limit: 2,
            wait_timeout: policy::MAX_WAIT_TIMEOUT,
            ..AdmissionConfig::default()
        },
    );
    // 2 active requests hold the slots.
    let r1 = tokio::spawn({
        let app = app.clone();
        async move { app.oneshot(loopback_req(get("/block"))).await.unwrap() }
    });
    let r2 = tokio::spawn({
        let app = app.clone();
        async move { app.oneshot(loopback_req(get("/block"))).await.unwrap() }
    });
    assert!(
        wait_for(Duration::from_secs(2), || {
            entered.load(Ordering::SeqCst) == 2
        })
        .await
    );
    // 3rd and 4th queue as waiters; the 5th sees waiters == limit → 503.
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let app = app.clone();
            tokio::spawn(async move { app.oneshot(loopback_req(get("/block"))).await.unwrap() })
        })
        .collect();
    // Give the waiters a moment to register.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let resp = app.oneshot(loopback_req(get("/block"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_string(resp).await.trim(), "ADMISSION_FULL");
    // Release the handlers; queued waiters complete.
    gate.store(true, Ordering::SeqCst);
    for r in [r1, r2] {
        assert_eq!(r.await.unwrap().status(), StatusCode::OK);
    }
    for r in waiters {
        assert_eq!(r.await.unwrap().status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn admission_waiter_timeout_503() {
    // active=1, waiters=2, timeout=60ms — queued waiters expire → 503.
    let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gate2 = gate.clone();
    let routes = vec![routed(
        axum::http::Method::GET,
        "/block",
        policy_app(),
        rget(move || {
            let gate = gate2.clone();
            async move {
                while !gate.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                "done"
            }
        }),
    )];
    let app = test_app_with(
        routes,
        Arc::new(FakeSessions::new()),
        AdmissionConfig {
            expected_host: Some(HOST.to_string()),
            active_limit: 1,
            waiter_limit: 2,
            wait_timeout: Duration::from_millis(60),
            ..AdmissionConfig::default()
        },
    );
    let hold = tokio::spawn({
        let app = app.clone();
        async move { app.oneshot(loopback_req(get("/block"))).await.unwrap() }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let resp = app.oneshot(loopback_req(get("/block"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_string(resp).await.trim(), "ADMISSION_FULL");
    gate.store(true, Ordering::SeqCst);
    assert_eq!(hold.await.unwrap().status(), StatusCode::OK);
}

#[test]
fn admission_config_hard_caps() {
    use central_transport_http::middleware::admission::Admission;
    let over = Admission::new(
        AdmissionConfig {
            active_limit: 33,
            ..AdmissionConfig::default()
        },
        &[],
    );
    assert!(over.is_err());
    let over = Admission::new(
        AdmissionConfig {
            waiter_limit: 65,
            ..AdmissionConfig::default()
        },
        &[],
    );
    assert!(over.is_err());
    let over = Admission::new(
        AdmissionConfig {
            wait_timeout: Duration::from_secs(6),
            ..AdmissionConfig::default()
        },
        &[],
    );
    assert!(over.is_err());
    let over = Admission::new(
        AdmissionConfig {
            max_header_bytes: 65 * 1024,
            ..AdmissionConfig::default()
        },
        &[],
    );
    assert!(over.is_err());
}

// ---------------------------------------------------------------------------
// Fixed outcomes
// ---------------------------------------------------------------------------

#[test]
fn task_action_failure_shape() {
    let resp = central_transport_http::error::task_action_failure(StatusCode::CONFLICT);
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
}

#[tokio::test]
async fn panic_recovers_to_fixed_500() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app.oneshot(loopback_req(get("/app/panic"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_security_headers(resp.headers());
    assert_eq!(
        body_string(resp).await,
        "{\"error\":{\"code\":\"INTERNAL\"}}"
    );
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn embedded_assets_served() {
    let app = test_app(Arc::new(FakeSessions::new()));
    let resp = app
        .clone()
        .oneshot(loopback_req(get("/assets/central.css")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(ct.starts_with("text/css"));
    let resp = app
        .oneshot(loopback_req(get("/assets/evil.sh")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Health + metrics (operations listener)
// ---------------------------------------------------------------------------

struct Probe(ProbeState, &'static str);
impl ReadinessProbe for Probe {
    fn health(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            state: self.0,
            reason: self.1.to_string(),
        }
    }
}

#[tokio::test]
async fn health_live_always_200_ready_profile_aware() {
    let registry = Arc::new(prometheus_client::registry::Registry::default());
    let app = build_ops_router(
        Arc::new(Probe(ProbeState::NotReady, "POSTGRES_UNAVAILABLE")),
        registry.clone(),
        None,
    );
    let resp = app
        .clone()
        .oneshot(loopback_req(get("/health/live")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("\"status\":\"not_ready\""));
    assert!(body.contains("POSTGRES_UNAVAILABLE"));
    let resp = app
        .oneshot(loopback_req(get("/health/ready")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let ready = build_ops_router(
        Arc::new(Probe(ProbeState::Ready, "")),
        registry.clone(),
        None,
    );
    let resp = ready
        .clone()
        .oneshot(loopback_req(get("/health/ready")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_string(resp).await,
        "{\"status\":\"ready\",\"reason\":\"\"}"
    );
    let resp = ready.oneshot(loopback_req(get("/metrics"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // unbounded reasons collapse
    let leaked = build_ops_router(
        Arc::new(Probe(ProbeState::Failed, "db password: hunter2")),
        registry,
        None,
    );
    let resp = leaked
        .oneshot(loopback_req(get("/health/ready")))
        .await
        .unwrap();
    let body = body_string(resp).await;
    assert!(body.contains("UNAVAILABLE"));
    assert!(!body.contains("hunter2"));
}
