//! Fixed outcomes and rejection helpers — the safe, non-enumerating
//! responses every transport guard shares.
//!
//! Two families:
//!
//! - [`reject`]: the upstream `rejectText` port — `text/plain` body
//!   carrying a short stable reason token (`PEER_NOT_LOOPBACK`,
//!   `HOST_MISMATCH`, `CORS_DISABLED`, `ORIGIN_MISMATCH`, `CSRF_*`,
//!   `ADMISSION_FULL`, ...). Route existence is never leaked; no
//!   `Access-Control-*` header is ever emitted (no CORS layer exists to
//!   set one).
//! - Fixed §4.1.1 outcomes ([`not_found`], [`method_not_allowed`],
//!   [`unauthorized`], [`recovered_internal`],
//!   [`task_action_failure`]): HTML pages for `/app/...` paths, the
//!   canonical `{"error":{"code":"..."}}` envelope everywhere else.
//!
//! Every response produced here gets the full §4.4 security profile
//! from the outer [`crate::middleware::security_headers`] layer; the
//! panic-recovery outcome applies it directly because it is produced
//! outside that layer.

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;

use crate::middleware::security_headers::apply_security_headers;

/// `rejectText` — a minimal text response whose body is one short,
/// stable, safe diagnostic token. Route existence and request content
/// are never reflected.
#[must_use]
pub fn reject(status: StatusCode, reason: &'static str) -> Response {
    let mut resp = Response::new(Body::from(format!("{reason}\n")));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// Whether a path belongs to the HTML response family (`/app/...`).
/// Everything else — `/api/...` and unclassified paths — takes the JSON
/// envelope (§4.1.1 content-type rule).
#[must_use]
pub fn is_app_path(path: &str) -> bool {
    path.starts_with("/app/")
}

/// The canonical API v1 error envelope reduced to its fixed-outcome
/// core: `{"error":{"code":"<CODE>"}}` — no additional fields (§4.1.1).
fn json_error(code: &'static str) -> Body {
    Body::from(format!("{{\"error\":{{\"code\":\"{code}\"}}}}"))
}

fn json_response(status: StatusCode, code: &'static str) -> Response {
    let mut resp = Response::new(json_error(code));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

fn html_response(status: StatusCode, title: &str, message: &str) -> Response {
    let body = crate::rendering::render_error_page(title, message);
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// Fixed `404` — HTML "Page not found" for `/app/...`, JSON
/// `NOT_FOUND` envelope elsewhere. No route suggestions, no path echo,
/// no header reflection.
#[must_use]
pub fn not_found(path: &str) -> Response {
    if is_app_path(path) {
        html_response(
            StatusCode::NOT_FOUND,
            "Page not found",
            "The page you requested does not exist.",
        )
    } else {
        json_response(StatusCode::NOT_FOUND, "NOT_FOUND")
    }
}

/// Fixed `405` — same content rules as [`not_found`] plus the matched
/// route's `Allow` header. No route inventory beyond that header.
#[must_use]
pub fn method_not_allowed(path: &str, allow: &str) -> Response {
    let mut resp = if is_app_path(path) {
        html_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed",
            "The request method is not allowed for this page.",
        )
    } else {
        json_response(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED")
    };
    if let Ok(v) = HeaderValue::from_str(allow) {
        resp.headers_mut().insert(header::ALLOW, v);
    }
    resp
}

/// Fixed `401` for a missing, expired, or revoked session on a
/// non-`/app` route — the v1 `unauthorized` outcome, non-enumerating.
#[must_use]
pub fn unauthorized() -> Response {
    json_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED")
}

/// `renderTaskActionFailure` — the generic mutation-failure outcome
/// used by `/app/...` handlers for every rejection (bad form, denied
/// session/CSRF, and the §4.3 restart barrier). Upstream emits
/// `http.StatusConflict` for the barrier path; the caller picks the
/// status. The body is always the same fixed `text/plain` token — it
/// never discloses the specific reason or task existence.
#[must_use]
pub fn task_action_failure(status: StatusCode) -> Response {
    reject(status, "TASK_ACTION_FAILED")
}

/// Fixed `303` redirect used for Post/Redirect/Get and for
/// unauthenticated `/app/...` page requests (`/app/bootstrap`).
#[must_use]
pub fn redirect_303(location: &'static str) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    resp
}

/// Fixed `500` produced by the panic-recovery layer — the only fixed
/// outcome generated outside the security-headers layer, so it applies
/// the §4.4 profile itself. Body is the minimal JSON envelope: the
/// panic payload and request path are never reachable here.
#[must_use]
pub fn recovered_internal() -> Response {
    let mut resp = json_response(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL");
    apply_security_headers(resp.headers_mut());
    resp
}

/// Fixed `500` for the buffered layer's fail-closed outcomes (response
/// overflow, activation failure, double-armed precommit). No body, no
/// handler-set body headers — only the §4.4 profile applied outside.
#[must_use]
pub fn buffered_failure() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}
