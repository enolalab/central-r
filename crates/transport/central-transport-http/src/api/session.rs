//! `POST /api/v1/session/bootstrap` — the atomic bootstrap exchange
//! (upstream `ServeExchange`). The request-scoped plaintext token never
//! leaves this function; only its SHA-256 verifier digest crosses the
//! service boundary. On success the delivery is prepared and the armed
//! precommit slot activates it immediately before the buffered layer
//! flushes the `303`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use central_session::contract::BootstrapVerifier;
use central_session::domain::{DEFAULT_FIRST_USE_FENCE, retry_after_from_failure};
use central_session::domain::{DeliveryRequest, ExchangeRequest};
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::cookies;
use crate::middleware::buffer::{ArmedSlot, Precommit};
use crate::middleware::preauth::ValidatedPreAuthCsrf;
use crate::web::{self, WebState};

/// The fixed safe remediation for a form the transport cannot read.
const FORM_UNREADABLE: &str =
    "The submitted form could not be read. Reload the page and try again.";
/// A token in the query string is refused — it must be posted in the
/// body.
const TOKEN_IN_QUERY: &str =
    "The bootstrap token must be submitted in the form body. Reload the page and try again.";
/// Exactly one non-empty `bootstrap_token` is required.
const TOKEN_UNREADABLE: &str =
    "The submitted bootstrap token could not be read. Reload the page and try again.";
/// The generic exchange failure — never reveals whether a token existed.
const TOKEN_REJECTED: &str = "The bootstrap token could not be accepted. Request a fresh token with \u{201c}central bootstrap show\u{201d} and try again.";
/// The throttled retry remediation.
const THROTTLED: &str =
    "Too many bootstrap attempts. Wait for the retry window, then request a fresh token.";
/// The session cookie lifetime posture upstream commits.
const IDLE_EXPIRY: time::Duration = time::Duration::minutes(30);
const ABSOLUTE_EXPIRY: time::Duration = time::Duration::hours(12);

/// `ServeExchange` — see the module doc.
pub(crate) async fn serve_exchange(state: Arc<WebState>, req: Request) -> Response {
    // The token must not arrive in the query string — it would land in
    // access logs. Checked before the body parse just like upstream.
    if req.uri().query().is_some_and(|q| {
        q.split('&')
            .any(|p| p.split('=').next() == Some("bootstrap_token"))
    }) {
        return web::render_bootstrap(&req, StatusCode::BAD_REQUEST, TOKEN_IN_QUERY);
    }
    let mut req = req;
    let form = match web::parse_body_form(&mut req).await {
        Ok(f) => f,
        Err(_) => {
            return web::render_bootstrap(&req, StatusCode::BAD_REQUEST, FORM_UNREADABLE);
        }
    };
    let tokens = form.get("bootstrap_token").map_or(&[][..], Vec::as_slice);
    if tokens.len() != 1 || tokens[0].is_empty() {
        return web::render_bootstrap(&req, StatusCode::BAD_REQUEST, TOKEN_UNREADABLE);
    }
    // Fail closed: the pre-auth CSRF pair must have been validated by
    // the middleware and stashed in extensions. A missing pair means
    // the middleware did not run — never derive a pair from the form.
    let Some(pair) = req
        .extensions()
        .get::<ValidatedPreAuthCsrf>()
        .map(|p| p.0.clone())
    else {
        return web::reject_csrf_missing();
    };
    let identity = web::request_identity(&req);
    let epoch = (state.epoch_source)();
    let exchange = match state
        .sessions
        .exchange_bootstrap(ExchangeRequest {
            workspace_id: Some(state.workspace),
            verifier: derive_verifier(&tokens[0]),
            identity: identity.clone(),
            pre_auth_csrf_hash: pair.hash(),
            epoch,
            idle_expiry: IDLE_EXPIRY,
            absolute_expiry: ABSOLUTE_EXPIRY,
            first_use_fence: DEFAULT_FIRST_USE_FENCE,
        })
        .await
    {
        Ok(e) => e,
        Err(f) => return exchange_error(&req, &f),
    };
    let delivery = match state
        .sessions
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: exchange.replacement,
        })
        .await
    {
        Ok(d) => d,
        Err(f) => return exchange_error(&req, &f),
    };
    let (token_value, csrf_value) = cookies::mint_session_values();
    // The buffered layer arms one slot per request; a missing slot
    // means a misconfigured chain — revoke the pending session rather
    // than deliver a session that can never activate.
    let Some(slot) = req.extensions().get::<ArmedSlot>() else {
        let _ = state.sessions.logout(exchange.session.id).await;
        return exchange_error(&req, &unavailable_failure());
    };
    slot.0
        .arm(Precommit {
            delivery_id: delivery.delivery_id,
            token_hash: Sha256::digest(token_value).into(),
            csrf_hash: Sha256::digest(csrf_value).into(),
            identity,
            epoch,
            session_id: exchange.session.id,
        })
        .await;
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    for c in cookies::session_set_cookies(&b64::encode(&token_value), &b64::encode(&csrf_value)) {
        if let Ok(v) = HeaderValue::from_str(&c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/app/tasks"));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// `handleExchangeError` — a throttle is `429` with the bounded
/// `Retry-After`; every other failure re-renders the bootstrap shell
/// with the safe remediation.
fn exchange_error(req: &Request, f: &central_session::contract::Failure) -> Response {
    if let Some(retry) = retry_after_from_failure(f) {
        let mut resp = web::render_bootstrap(req, StatusCode::TOO_MANY_REQUESTS, THROTTLED);
        if let Ok(v) = HeaderValue::from_str(&retry.seconds().to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
    }
    web::render_bootstrap(req, StatusCode::BAD_REQUEST, TOKEN_REJECTED)
}

/// The untyped failure standing in for "session credentials
/// unavailable"/"session precommit unavailable" — upstream passes a
/// plain `errors.New`, which maps to the generic remediation.
fn unavailable_failure() -> central_session::contract::Failure {
    central_session::contract::Failure::untyped("session delivery unavailable")
}

/// `deriveVerifier` — the opaque versioned bootstrap verifier from the
/// request-scoped plaintext token. Only the digest crosses the service
/// boundary.
fn derive_verifier(plaintext: &str) -> BootstrapVerifier {
    BootstrapVerifier::new(
        central_session::contract::BOOTSTRAP_VERIFIER_V1,
        Sha256::digest(plaintext.as_bytes()).into(),
    )
}
