//! `/app/...` server-rendered web surface — the Task 12 port of upstream
//! `internal/transport/http/gintransport/web`.
//!
//! Every handler consumes the middleware seams (validated pre-auth CSRF
//! pair, authenticated session, parsed form, armed precommit slot) via
//! request extensions — Origin, CSRF, and session checks are never
//! reimplemented here. Safe `/app` GET routes carry `session_required:
//! false` deliberately: an anonymous page request renders the bootstrap
//! shell in place (upstream's precedent), never a redirect, so the handler
//! validates the session itself via [`ports::SessionService::validate`].
//!
//! R4 surfaces (runs, fleet, lineage, run controls, run submission) are
//! intentionally absent.

pub mod activity_view;
pub mod budget_view;
pub mod handler;
pub mod harness;
pub mod office_view;
pub mod overview_view;
pub mod permission_form;
pub mod permission_view;
pub mod repository_analysis;
pub mod task_view;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::{MethodRouter, get, post};
use central_foundation::identity::WorkspaceId;
use central_session::contract::RequestIdentity;
use central_session::domain::{SecurityEpoch, Session, SessionState, ValidationRequest};
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::cookies;
use crate::error;
use crate::health::ReadinessProbe;
use crate::middleware::preauth::IssuedPreAuthCsrf;
use crate::middleware::session_auth::{self, AuthenticatedSession, ParsedForm};
use crate::policy::{self, RouteClass, RoutePolicy, RouteSpec};
use crate::ports;
use crate::router::RoutedSpec;

/// The collaborator set every `/app` handler shares — upstream
/// `web.Config`. `readiness`, `sessions`, `tasks`, `artifacts`, and
/// `claimability` are mandatory (upstream `New` panics on nil); the
/// optional surfaces render nothing when absent.
pub struct WebState {
    /// Kernel readiness for the root entry and the overview/office
    /// health cards.
    pub readiness: Arc<dyn ReadinessProbe>,
    /// Session exchange/validation/logout.
    pub sessions: Arc<dyn ports::SessionService>,
    /// Task reads and mutations.
    pub tasks: Arc<dyn ports::TaskService>,
    /// Ready-artifact delivery guard.
    pub artifacts: Arc<dyn ports::ArtifactDelivery>,
    /// Durable restart-barrier gate; wired to the same instance the
    /// read path decorates with.
    pub claimability: Arc<dyn ports::RecoveryClaimability>,
    /// OPTIONAL per-run provider-turn timeline (ADR 0021).
    pub turn_activity: Option<Arc<dyn ports::RunTurnActivityRead>>,
    /// OPTIONAL harness operator surface; `None` renders no banner and
    /// the resolve/resume/permission routes answer 404.
    pub harness: Option<Arc<dyn harness::HarnessOperator>>,
    /// The fixed workspace the bootstrap exchange mints sessions for.
    pub workspace: WorkspaceId,
    /// The operator-configured `workspace_root_id` allowlist a
    /// repository-analysis submission may select. An empty list fails
    /// every submission closed.
    pub allowed_roots: Vec<String>,
    /// The workspace security epoch asserted on every validation —
    /// the same source [`crate::router::TransportConfig::epoch_source`]
    /// feeds the session middleware.
    pub epoch_source: Arc<dyn Fn() -> SecurityEpoch + Send + Sync>,
}

/// Registers the whole `/app` surface plus `/`, `/app/logout`, and the
/// embedded `/assets/{name}` allowlist. The bootstrap exchange lives in
/// [`crate::api`].
#[must_use]
pub fn routes(state: &Arc<WebState>) -> Vec<RoutedSpec> {
    let mut out: Vec<RoutedSpec> = Vec::new();

    let mut push =
        |method: Method, path: &'static str, policy: RoutePolicy, handler: MethodRouter| {
            out.push(RoutedSpec {
                spec: RouteSpec {
                    method,
                    path,
                    policy,
                },
                handler,
            });
        };

    let safe_page = |response_cap: usize| RoutePolicy {
        class: RouteClass::App,
        response_cap,
        body_limit: 0,
        origin_required: false,
        state_changing: false,
        csrf_required: false,
        session_csrf_required: false,
        issue_pre_auth_csrf: true,
        session_required: false,
        restart_barrier: false,
    };

    let mutation = |restart_barrier: bool| RoutePolicy {
        class: RouteClass::App,
        response_cap: policy::HTML_RESPONSE_CAP,
        // Upstream `serve_composition.go` puts
        // `middleware.DefaultBootstrapBodyLimit` (1 MiB) on every
        // `/app/tasks/*` mutation route — submit, cancel, retry,
        // rerun, and the three harness operator routes.
        body_limit: policy::DEFAULT_BOOTSTRAP_BODY_LIMIT,
        origin_required: true,
        state_changing: true,
        csrf_required: false,
        session_csrf_required: true,
        issue_pre_auth_csrf: false,
        session_required: true,
        restart_barrier,
    };

    macro_rules! page {
        ($path:literal, $cap:expr, $f:ident) => {
            push(
                Method::GET,
                $path,
                safe_page($cap),
                get({
                    let st = Arc::clone(state);
                    move |req: Request| handler::$f(Arc::clone(&st), req)
                }),
            );
        };
    }
    macro_rules! mutate {
        ($path:literal, $f:ident, $barrier:literal) => {
            push(
                Method::POST,
                $path,
                mutation($barrier),
                post({
                    let st = Arc::clone(state);
                    move |req: Request| handler::$f(Arc::clone(&st), req)
                }),
            );
        };
    }

    push(
        Method::GET,
        "/",
        safe_page(policy::HTML_RESPONSE_CAP),
        get({
            let st = Arc::clone(state);
            move |req: Request| handler::serve_root(Arc::clone(&st), req)
        }),
    );
    page!("/app/bootstrap", policy::HTML_RESPONSE_CAP, serve_bootstrap);
    push(
        Method::POST,
        "/app/logout",
        RoutePolicy {
            class: RouteClass::App,
            response_cap: policy::HTML_RESPONSE_CAP,
            body_limit: policy::MAX_BODY_BUFFER,
            origin_required: true,
            state_changing: true,
            csrf_required: false,
            session_csrf_required: false,
            issue_pre_auth_csrf: false,
            // The handler validates the session itself: upstream's logout
            // failures render the recovery shell (cookies cleared, fresh
            // pre-auth CSRF reissued), never `TASK_ACTION_FAILED`, so the
            // session middleware must stay out of this route.
            session_required: false,
            restart_barrier: false,
        },
        post({
            let st = Arc::clone(state);
            move |req: Request| handler::serve_logout(Arc::clone(&st), req)
        }),
    );
    page!("/app/overview", policy::HTML_RESPONSE_CAP, serve_overview);
    page!("/app/activity", policy::HTML_RESPONSE_CAP, serve_activity);
    page!("/app/office", policy::HTML_RESPONSE_CAP, serve_office);
    page!("/app/tasks", policy::HTML_RESPONSE_CAP, serve_task_list);
    // Upstream `TaskDetailResponseCap` (32 × the 256 KiB bridged-input
    // bound = 8 MiB) exceeds the §4.6 hard buffered cap, so the effective
    // cap is the 2 MiB ceiling — same clamp the policy table applies.
    page!(
        "/app/tasks/detail",
        policy::MAX_RESPONSE_BUFFER,
        serve_task_detail
    );
    mutate!("/app/tasks/submit", serve_task_submit, false);
    mutate!("/app/tasks/cancel", serve_task_cancel, true);
    mutate!("/app/tasks/retry", serve_task_retry, true);
    mutate!("/app/tasks/rerun", serve_task_rerun, true);
    mutate!("/app/tasks/harness/resolve", serve_harness_resolve, true);
    mutate!("/app/tasks/harness/resume", serve_harness_resume, true);
    mutate!(
        "/app/tasks/harness/permission",
        serve_harness_permission,
        true
    );
    page!(
        "/app/tasks/artifact/preview",
        policy::HTML_RESPONSE_CAP,
        serve_artifact_preview
    );
    page!(
        "/app/tasks/artifact/download",
        policy::API_RESPONSE_CAP,
        serve_artifact_download
    );

    // `/assets/{name}` — the embedded allowlist; outside names produce the
    // same fixed 404 as any unmatched path.
    push(
        Method::GET,
        "/assets/{name}",
        RoutePolicy::safe_get(RouteClass::Asset),
        get(handler::serve_asset),
    );

    out
}

// ---------------------------------------------------------------------------
// Shared helpers (upstream handler.go's session/render prelude).
// ---------------------------------------------------------------------------

/// `activeSession` — validates the presented session cookie for a safe
/// `/app` GET. Missing, malformed, or invalid yields `None`; the typed
/// failure is never surfaced. Takes `&HeaderMap` (not `&Request`): an
/// `axum` request body is `UnsyncBoxBody`, so `&Request` held across an
/// `.await` would make every handler future `!Send`.
pub(crate) async fn active_session(state: &WebState, headers: &HeaderMap) -> Option<Session> {
    let token_value = presented_session_token(headers)?;
    let token_hash: [u8; 32] = Sha256::digest(token_value).into();
    let session = state
        .sessions
        .validate(ValidationRequest {
            token_hash,
            presented_csrf_hash: None,
            epoch: (state.epoch_source)(),
        })
        .await
        .ok()?;
    (session.state == SessionState::Active).then_some(session)
}

/// Exactly one non-empty `central_session` cookie value decoded to the
/// 32-byte opaque token (upstream `activeSession`'s cookie half).
fn presented_session_token(headers: &HeaderMap) -> Option<[u8; 32]> {
    let values = cookies::cookie_values(headers, cookies::SESSION_COOKIE);
    match values.as_slice() {
        [one] if !one.is_empty() => b64::decode(one),
        _ => None,
    }
}

/// `sessionCSRFValue` — the `central_session_csrf` cookie's raw value
/// rendered into hidden `csrf` form fields. Already delivered to the
/// browser at activation; echoing it introduces no new exposure.
pub(crate) fn session_csrf_value(req: &Request) -> String {
    cookies::cookie_values(req.headers(), cookies::SESSION_CSRF_COOKIE)
        .into_iter()
        .next()
        .unwrap_or_default()
}

/// `issuedCSRFValue` — the pre-auth CSRF value the middleware stashed on
/// a safe route, rendered into the bootstrap form's hidden field. Empty
/// when the middleware did not run.
pub(crate) fn issued_csrf_value(req: &Request) -> String {
    req.extensions()
        .get::<IssuedPreAuthCsrf>()
        .map(|p| b64::encode(&p.0.value()))
        .unwrap_or_default()
}

/// The middleware-validated session plus parsed form for a
/// `session_required + session_csrf_required` mutation route. `None`
/// fails closed — a missing stash means the middleware did not run.
pub(crate) fn authenticated(req: &Request) -> Option<(Session, HashMap<String, Vec<String>>)> {
    let session = req.extensions().get::<AuthenticatedSession>()?.0.clone();
    let form = req.extensions().get::<ParsedForm>()?.0.clone();
    Some((session, form))
}

/// `parseBodyForm` — the tolerant urlencoded body read upstream's
/// logout/exchange handlers perform themselves (the session middleware
/// is deliberately absent on those routes). The admission
/// `RequestBodyLimitLayer` already bounds the read; `to_bytes` re-bounds
/// at `DefaultBootstrapBodyLimit` — the self-cap upstream's
/// `parseBodyForm` applies on every caller (handler.go:1681). Takes
/// `&mut` so request extensions (validated pre-auth pair, armed
/// precommit slot) survive the read.
pub(crate) async fn parse_body_form(
    req: &mut Request,
) -> Result<HashMap<String, Vec<String>>, Box<Response>> {
    let is_form = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
    let body = std::mem::replace(req.body_mut(), Body::empty());
    if !is_form {
        // Upstream `r.ParseForm()` consumes a non-form body but yields
        // an empty PostForm — mirror that with an empty map so the
        // caller's field checks produce the same "could not be read"
        // outcome instead of a second failure shape.
        let _ = axum::body::to_bytes(body, policy::DEFAULT_BOOTSTRAP_BODY_LIMIT).await;
        return Ok(HashMap::new());
    }
    let bytes = axum::body::to_bytes(body, policy::DEFAULT_BOOTSTRAP_BODY_LIMIT)
        .await
        .map_err(|_| Box::new(error::task_action_failure(StatusCode::FORBIDDEN)))?;
    Ok(session_auth::parse_urlencoded(&bytes))
}

/// `formValue` — `form[key][0]` when present, else `""`.
#[must_use]
pub(crate) fn form_value<'a>(form: &'a HashMap<String, Vec<String>>, key: &str) -> &'a str {
    form.get(key)
        .and_then(|v| v.first())
        .map_or("", String::as_str)
}

/// `requestIdentity` — the request-scoped caller identity bound into the
/// bootstrap exchange: the serve process's loopback peer uid/pid and the
/// exact validated `Origin` (upstream's `os.Getuid`/`os.Getpid`).
pub(crate) fn request_identity(req: &Request) -> RequestIdentity {
    RequestIdentity {
        peer_uid: process_uid(),
        peer_pid: std::process::id() as i32,
        origin: req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
    }
}

/// `os.Getuid` — the first uid on `/proc/self/status`'s `Uid:` line;
/// `0` when unreadable (the exchange binds whatever the kernel reports).
fn process_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

/// `renderBootstrap` — the bootstrap shell with the issued pre-auth CSRF
/// and an optional error message.
pub(crate) fn render_bootstrap(req: &Request, status: StatusCode, err: &str) -> Response {
    render_bootstrap_issued(&issued_csrf_value(req), status, err)
}

/// `renderBootstrap` with the already-extracted pre-auth CSRF value —
/// the form async helpers pass once `&Request` can no longer be held
/// across their `.await`s.
pub(crate) fn render_bootstrap_issued(csrf_field: &str, status: StatusCode, err: &str) -> Response {
    html_response(
        status,
        &BootstrapTemplate {
            csrf_field: csrf_field.to_string(),
            error: err.to_string(),
            autofocus: false,
        }
        .render(),
    )
}

/// `rejectCSRFMissing` — the fail-closed 403 when no validated pre-auth
/// CSRF pair is in extensions. Identical to the middleware's
/// `CSRF_MISSING` outcome whether the chain ran or not.
#[must_use]
pub(crate) fn reject_csrf_missing() -> Response {
    error::reject(StatusCode::FORBIDDEN, "CSRF_MISSING")
}

/// `renderTaskActionFailure` — the fixed mutation rejection: same body
/// for every refusal, never a domain reason or task existence.
#[must_use]
pub(crate) fn task_action_failure(status: StatusCode) -> Response {
    error::task_action_failure(status)
}

/// `renderHarnessStarting` — the retryable refusal of "Finish
/// cancelling" while a live lease holds the never-invoked attempt.
#[must_use]
pub(crate) fn render_harness_starting() -> Response {
    error::reject(StatusCode::CONFLICT, harness::HARNESS_STARTING_MSG)
}

/// `renderNotFound` — the generic `404 NOT_FOUND` text page (upstream's
/// plain-text body, deliberately distinct from the HTML fixed-404 so a
/// task/artifact existence probe learns nothing either way).
#[must_use]
pub(crate) fn render_not_found() -> Response {
    error::reject(StatusCode::NOT_FOUND, "NOT_FOUND")
}

/// A `303 See Other` redirect with a dynamically built location (task
/// ids embedded in the detail redirect are opaque UUID text — never
/// attacker input, but still emitted through `HeaderValue` validation).
#[must_use]
pub(crate) fn redirect_303(location: &str) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// An HTML page response at `status`.
#[must_use]
pub(crate) fn html_response(status: StatusCode, body: &str) -> Response {
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// `formatTimestamp` — absolute RFC3339 UTC; a zero time yields `""` so
/// the template renders nothing rather than a misleading epoch. Seconds
/// precision, exactly like Go's `time.RFC3339` (no fractional part).
#[must_use]
pub(crate) fn format_timestamp(ts: time::OffsetDateTime) -> String {
    let y = ts.year();
    let m = ts.month() as u8;
    let d = ts.day();
    let (h, mi, s) = ts.to_hms();
    if y == 0 {
        // `OffsetDateTime` has no Go-style zero value, but a
        // year-0 timestamp is the defensive equivalent.
        return String::new();
    }
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// The bootstrap shell template — a standalone document like upstream
/// (it does not extend the app layout because it carries its own CSP-tight
/// script tag and no nav).
#[derive(askama::Template)]
#[template(path = "bootstrap.html")]
pub struct BootstrapTemplate {
    /// The issued pre-auth CSRF value for the hidden `csrf` field.
    pub csrf_field: String,
    /// Safe remediation text, empty on a clean render.
    pub error: String,
    /// Whether the token field takes focus (the dedicated page only).
    pub autofocus: bool,
}

impl BootstrapTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Bootstrap", "Unavailable"))
    }
}

/// The signed-in root shell.
#[derive(askama::Template)]
#[template(path = "ready.html")]
pub struct ReadyTemplate {
    /// The session CSRF cookie value for the sign-out form.
    pub csrf_field: String,
}

impl ReadyTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Central", "Unavailable"))
    }
}

/// The artifact preview page — the bounded, escaped body plus the
/// truncation notice.
#[derive(askama::Template)]
#[template(path = "artifact_preview.html")]
pub struct ArtifactPreviewTemplate {
    /// The artifact id the preview renders.
    pub artifact_id: String,
    /// The bounded raw body (Askama escapes it in the template).
    pub content: String,
    /// Whether the body exceeded the preview budget and was cut.
    pub truncated: bool,
}

impl ArtifactPreviewTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Artifact", "Unavailable"))
    }
}

/// The post-logout recovery shell.
#[derive(askama::Template)]
#[template(path = "recovery.html")]
pub struct RecoveryTemplate {
    /// A fresh pre-auth CSRF value for the re-bootstrap form.
    pub csrf_field: String,
    /// Safe status text; empty renders the default message.
    pub error: String,
}

impl RecoveryTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Recovery", "Unavailable"))
    }
}

/// `issueFreshPreAuthCSRF` — mints and sets a fresh pre-auth cookie on
/// the response, returning the encoded value for the form. `None` when
/// the service cannot mint (the caller renders the degraded shell).
pub(crate) fn issue_fresh_preauth(state: &WebState, headers: &mut HeaderMap) -> Option<String> {
    let pair = state.sessions.issue_pre_auth_csrf();
    if pair.is_zero() {
        return None;
    }
    let encoded = b64::encode(&pair.value());
    let cookie = cookies::preauth_csrf_set_cookie(&encoded);
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, v);
    }
    Some(encoded)
}

/// Clears the session pair cookies onto `headers` (upstream
/// `clearSessionCookies`).
pub(crate) fn clear_session_cookies(headers: &mut HeaderMap) {
    for c in cookies::clear_session_cookies() {
        if let Ok(v) = HeaderValue::from_str(&c) {
            headers.append(header::SET_COOKIE, v);
        }
    }
}

/// Whether a named cookie appears more than once on the request
/// (upstream `duplicateCookieName`).
pub(crate) fn duplicate_cookie_name(req: &Request, name: &str) -> bool {
    cookies::cookie_values(req.headers(), name).len() > 1
}
