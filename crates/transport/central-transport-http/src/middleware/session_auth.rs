//! Session gate — the §4.2 layers 8–9 ("session authentication" +
//! "header or form CSRF validation, when route policy requires them"),
//! porting the enforcement upstream spreads across `web.Handler`'s
//! `activeSession`/`activeSessionWithCSRF` helpers.
//!
//! For a route whose policy sets `session_required`:
//!
//! 1. The `central_session` cookie must decode to 32 bytes; its
//!    `token_hash = SHA-256(value)` is the lookup key.
//! 2. When `session_csrf_required` also holds (every state-changing
//!    session route), the presented CSRF evidence is exactly one
//!    `X-CSRF-Token` header on `Api` routes or exactly one `csrf` field
//!    of the `application/x-www-form-urlencoded` body on `App` routes.
//!    The enforcement is the persisted-hash comparison: the decoded
//!    value's `SHA-256` flows to `ValidationRequest.presented_csrf_hash`
//!    and the store requires it to equal the session row's `csrf_hash`
//!    (upstream `activeSessionWithCSRF`). The `central_session_csrf`
//!    cookie is issued script-readable for the form helper but is not
//!    consulted here — upstream compares cookie↔form only inside
//!    `ServeLogout`.
//! 3. `Service::validate` must return an `Active` session.
//!
//! Outcomes follow §4.3: a missing/expired session on an `App` safe
//! route → `303` to `/app/bootstrap`; on an `Api` route → `401`; on a
//! mutation → the fixed `renderTaskActionFailure`-shaped outcome
//! (`403 TASK_ACTION_FAILED`) for `App`, `401` JSON for `Api`. The
//! validated `Session` and the parsed form are stashed in request
//! extensions for the handler.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use central_session::domain::{SecurityEpoch, Session, SessionState, ValidationRequest};
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::cookies;
use crate::error;
use crate::policy::{MatchedRoute, RouteClass};
use crate::ports::SessionValidator;

/// `X-CSRF-Token` — the §4.3 session-CSRF header for `/api/v1`
/// mutations (canonical name lives in [`crate::cookies`]).
pub use crate::cookies::SESSION_CSRF_HEADER;

/// The layer's collaborator set.
pub struct SessionAuthState<S: SessionValidator> {
    /// The session service (any `Service<S, B>`).
    pub service: Arc<S>,
    /// The workspace security epoch to assert on every validation —
    /// upstream's `Config.EpochSource`.
    pub epoch_source: Arc<dyn Fn() -> SecurityEpoch + Send + Sync>,
}

impl<S: SessionValidator> Clone for SessionAuthState<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            epoch_source: self.epoch_source.clone(),
        }
    }
}

/// The session gate (`from_fn_with_state`).
pub async fn layer<S: SessionValidator>(
    axum::extract::State(state): axum::extract::State<SessionAuthState<S>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(matched) = req.extensions().get::<MatchedRoute>().cloned() else {
        return next.run(req).await;
    };
    if !matched.policy.session_required {
        return next.run(req).await;
    }
    let class = matched.policy.class;
    let safe = matches!(req.method(), &Method::GET | &Method::HEAD);
    let missing = || missing_session(class, safe);

    // 1. Session cookie — decode to the 32-byte opaque token.
    let cookie_values = cookies::cookie_values(req.headers(), cookies::SESSION_COOKIE);
    let Some(token_value) = (match cookie_values.as_slice() {
        [one] if !one.is_empty() => b64::decode(one),
        _ => None,
    }) else {
        return missing();
    };

    // 2. Session-CSRF evidence on state-changing routes. The presented
    //    value's hash is the only credential compared — upstream
    //    `activeSessionWithCSRF` delegates the check to the store via
    //    `PresentedCSRFHash`; the `central_session_csrf` cookie is not
    //    consulted on this path.
    let mut presented_csrf_hash: Option<[u8; 32]> = None;
    if matched.policy.session_csrf_required && !safe {
        let presented = match class {
            RouteClass::App => {
                match presented_form_csrf(&mut req, matched.policy.effective_body_limit()).await {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                }
            }
            _ => match presented_header_csrf(&req) {
                Some(v) => v,
                None => {
                    return error::reject(StatusCode::FORBIDDEN, "CSRF_DUPLICATE");
                }
            },
        };
        let Some(csrf_value) = b64::decode(&presented) else {
            return error::reject(StatusCode::FORBIDDEN, "CSRF_MALFORMED");
        };
        presented_csrf_hash = Some(Sha256::digest(csrf_value).into());
    }

    // 3. Validate — token-hash comparison and epoch assertion are the
    // store's; a `delivery_pending`/`revoked` row never passes.
    let token_hash: [u8; 32] = Sha256::digest(token_value).into();
    let session = state
        .service
        .validate(ValidationRequest {
            token_hash,
            presented_csrf_hash,
            epoch: (state.epoch_source)(),
        })
        .await;
    match session {
        Ok(session) if session.state == SessionState::Active => {
            req.extensions_mut()
                .insert(ValidatedSessionToken(token_value));
            req.extensions_mut().insert(AuthenticatedSession(session));
            next.run(req).await
        }
        _ => missing(),
    }
}

/// The outcome for a missing, malformed, or invalid session: `303`
/// to `/app/bootstrap` on `App` safe routes (§4.3), `401` JSON on `Api`
/// safe routes, the fixed `TASK_ACTION_FAILED` outcome on `App`
/// mutations, `401` on `Api` mutations.
fn missing_session(class: RouteClass, safe: bool) -> Response {
    match (class, safe) {
        (RouteClass::App, true) => error::redirect_303("/app/bootstrap"),
        (RouteClass::App, false) => error::task_action_failure(StatusCode::FORBIDDEN),
        (_, true) => error::unauthorized(),
        (_, false) => error::unauthorized(),
    }
}

/// Exactly one `X-CSRF-Token` header (a missing header and a duplicated
/// header are the same ambiguity class upstream calls `CSRF_DUPLICATE`).
fn presented_header_csrf(req: &Request) -> Option<String> {
    let mut iter = req.headers().get_all(SESSION_CSRF_HEADER).iter();
    let first = iter.next()?.to_str().ok()?;
    if iter.next().is_some() || first.is_empty() {
        return None;
    }
    Some(first.to_string())
}

/// Reads the bounded urlencoded body, extracts exactly one `csrf`
/// field, and re-installs the body bytes so the handler can parse the
/// same form again. This middleware is the FIRST body reader — the
/// route-level `RequestBodyLimit` only wraps what the handler sees —
/// so the bound must be the matched route's own
/// `effective_body_limit` (upstream's `MaxBytesReader` wraps `r.Body`
/// at admission, before any read).
async fn presented_form_csrf(req: &mut Request, limit: usize) -> Result<String, Box<Response>> {
    let is_form = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return Err(Box::new(error::task_action_failure(StatusCode::FORBIDDEN)));
    }
    let parts = std::mem::take(req);
    let (mut parts, body) = parts.into_parts();
    let bytes = match axum::body::to_bytes(body, limit).await {
        Ok(b) => b,
        Err(_) => {
            return Err(Box::new(error::task_action_failure(StatusCode::FORBIDDEN)));
        }
    };
    let form = parse_urlencoded(&bytes);
    parts.extensions.insert(ParsedForm(form.clone()));
    let values = form
        .get(cookies::SESSION_CSRF_FORM_FIELD)
        .cloned()
        .unwrap_or_default();
    let presented = match values.as_slice() {
        [one] if !one.is_empty() => one.clone(),
        _ => return Err(Box::new(error::task_action_failure(StatusCode::FORBIDDEN))),
    };
    *req = Request::from_parts(parts, Body::from(bytes));
    Ok(presented)
}

/// `url.ParseQuery` — `application/x-www-form-urlencoded` into a
/// multi-map; malformed percent escapes are dropped like upstream's
/// tolerant parser (a bad `csrf` value simply fails the compare).
/// `pub(crate)` for the `/app/logout` and `/api/v1/session/bootstrap`
/// handlers, which parse their own bodies upstream-style.
pub(crate) fn parse_urlencoded(body: &[u8]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for pair in std::str::from_utf8(body).unwrap_or("").split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Some(k), Some(v)) = (percent_decode(name), percent_decode(value)) {
            map.entry(k).or_default().push(v);
        }
    }
    map
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let v = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..=i + 2]).ok()?, 16)
                    .ok()?;
                out.push(v);
                i += 3;
            }
            b'%' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The parsed urlencoded form, stashed for the handler (upstream's
/// `parseBodyForm` result threaded through `loadAggregateForMutation`).
#[derive(Debug, Clone)]
pub struct ParsedForm(pub HashMap<String, Vec<String>>);

/// The decoded 32-byte session token plaintext, request-scoped — the
/// value the handler needs when it must echo the presented token
/// (e.g. the logout path clearing cookies). Never logged.
#[derive(Debug, Clone)]
pub struct ValidatedSessionToken(pub [u8; 32]);

/// The validated `Active` session, stashed for the handler.
#[derive(Debug, Clone)]
pub struct AuthenticatedSession(pub Session);
