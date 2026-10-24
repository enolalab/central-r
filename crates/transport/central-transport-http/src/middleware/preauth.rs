//! Pre-auth CSRF — port of upstream `middleware/session.go`'s
//! `PreAuthCSRF` middleware.
//!
//! Policy-driven, exactly like upstream:
//!
//! - `session_csrf_required` → pass through; the session gate owns CSRF.
//! - `csrf_required` → validate the double-submit pair: exactly one
//!   non-empty `central_preauth_csrf` cookie, exactly one
//!   `X-Central-Preauth-CSRF` header, cookie value == header value
//!   (constant-time), value decodes to 32 bytes; then the service
//!   validates `PreAuthCSRF{value, sha256(value)}`. Every failure is a
//!   `403` with a stable reason token; the handler never runs.
//! - `issue_pre_auth_csrf` → mint a fresh pair via the service, set the
//!   cookie (`HttpOnly; Secure; SameSite=Strict; Path=/`), stash the
//!   pair in extensions so the handler can render the value into the
//!   bootstrap form's hidden field.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use central_session::contract::PreAuthCSRF;
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::cookies;
use crate::error;
use crate::policy::MatchedRoute;
use crate::ports::PreAuthCsrf;

/// The layer's collaborator set.
pub struct PreAuthCsrfState<S: PreAuthCsrf> {
    /// The session service (any `Service<S, B>` satisfies
    /// [`PreAuthCsrf`]).
    pub service: Arc<S>,
}

impl<S: PreAuthCsrf> Clone for PreAuthCsrfState<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

/// The middleware entry point (`from_fn_with_state`).
pub async fn layer<S: PreAuthCsrf>(
    axum::extract::State(state): axum::extract::State<PreAuthCsrfState<S>>,
    mut req: Request,
    next: Next,
) -> Response {
    let (csrf_required, session_csrf_required, issue) = req
        .extensions()
        .get::<MatchedRoute>()
        .map_or((false, false, false), |m| {
            (
                m.policy.csrf_required,
                m.policy.session_csrf_required,
                m.policy.issue_pre_auth_csrf,
            )
        });
    if session_csrf_required {
        return next.run(req).await;
    }
    if csrf_required {
        return validate(state, req, next).await;
    }
    if issue {
        let pair = state.service.issue_pre_auth_csrf();
        req.extensions_mut().insert(IssuedPreAuthCsrf(pair.clone()));
        let mut resp = next.run(req).await;
        set_preauth_cookie(resp.headers_mut(), &pair);
        return resp;
    }
    next.run(req).await
}

async fn validate<S: PreAuthCsrf>(
    state: PreAuthCsrfState<S>,
    mut req: Request,
    next: Next,
) -> Response {
    let cookie_values = cookies::cookie_values(req.headers(), cookies::PREAUTH_CSRF_COOKIE);
    // Upstream `pickCSRFCookie` — the first value under the name; a
    // missing or empty first value is CSRF_MISSING regardless of
    // whether later duplicates exist (the duplicate check runs later).
    let Some(cookie_value) = cookie_values.first().filter(|v| !v.is_empty()).cloned() else {
        return error::reject(StatusCode::FORBIDDEN, "CSRF_MISSING");
    };
    let header_values: Vec<&str> = req
        .headers()
        .get_all(cookies::PREAUTH_CSRF_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    // Missing header or duplicate header (replay attempt) — reject.
    if header_values.len() != 1 {
        return error::reject(StatusCode::FORBIDDEN, "CSRF_DUPLICATE");
    }
    // Upstream `hasDuplicateCookieValue` — the named cookie appearing
    // more than once is ambiguous (replay signal) — reject.
    if cookie_values.len() > 1 {
        return error::reject(StatusCode::FORBIDDEN, "CSRF_DUPLICATE");
    }
    // Constant-time match between cookie and header value. A mismatch
    // is a tampering signal — reject before hashing or service
    // validation.
    if !crate::ct_eq_str(&cookie_value, header_values[0]) {
        return error::reject(StatusCode::FORBIDDEN, "CSRF_MISMATCH");
    }
    let Some(value) = b64::decode(&cookie_value) else {
        return error::reject(StatusCode::FORBIDDEN, "CSRF_MALFORMED");
    };
    let hash: [u8; 32] = Sha256::digest(value).into();
    let pair = PreAuthCSRF::new(value, hash);
    if state.service.validate_pre_auth_csrf(&pair).is_err() {
        return error::reject(StatusCode::FORBIDDEN, "CSRF_INVALID");
    }
    req.extensions_mut().insert(ValidatedPreAuthCsrf(pair));
    next.run(req).await
}

fn set_preauth_cookie(headers: &mut HeaderMap, pair: &PreAuthCSRF) {
    // Upstream sets `Secure` unconditionally — the application listener
    // is TLS-only, so `preauth_csrf_set_cookie` already emits it.
    let cookie = cookies::preauth_csrf_set_cookie(&b64::encode(&pair.value()));
    if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
        headers.append(axum::http::header::SET_COOKIE, v);
    }
}

/// `PreAuthCSRFFromContext` — the freshly issued pair stashed on a safe
/// route so the handler can render `value` into a hidden form field.
#[derive(Debug, Clone)]
pub struct IssuedPreAuthCsrf(pub PreAuthCSRF);

/// `ValidatedPreAuthCSRFFromContext` — the validated pair stashed for
/// the request-scoped exchange handler. Never serialized or persisted
/// in this form.
#[derive(Debug, Clone)]
pub struct ValidatedPreAuthCsrf(pub PreAuthCSRF);
