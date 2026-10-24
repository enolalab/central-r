//! Buffered — port of upstream `middleware/buffer.go`.
//!
//! The innermost transport layer. It installs a [`PrecommitSlot`] on the
//! request, runs the handler, collects the response body up to the
//! route's `response_cap` (default [`HTML_RESPONSE_CAP`], hard-bounded
//! by [`MAX_RESPONSE_BUFFER`]), then commits:
//!
//! - **Overflow** — the collected body exceeded the cap: the response is
//!   a bare `500` with every handler-set body header dropped. Tainted
//!   output never reaches the wire.
//! - **Precommit armed** — the handler signaled a successful bootstrap
//!   exchange by calling [`PrecommitSlot::arm`]: `activate_delivery`
//!   runs exactly once *before* any byte reaches the wire. Activation
//!   failure revokes the pending session and emits the bare `500`. On
//!   success the buffered response is returned for flush. Known gap vs
//!   upstream: upstream could still observe a mid-flush write failure
//!   and revoke the now-active session (partial credentials may have
//!   reached the client). Here the flush happens in hyper after the
//!   layer has returned the `Response`, so a post-activation write
//!   failure is unobservable and cannot trigger the revoke — activation
//!   before return remains the enforcement.
//! - **Otherwise** — the buffered response is returned unchanged;
//!   `activate_delivery` is never called.
//!
//! Response-body size accounting uses the collected body only —
//! `active_limit × MAX_RESPONSE_BUFFER ≤ 64 MiB` is enforced at
//! admission construction (§4.6), so no additional runtime reservation
//! counter is needed.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use central_foundation::identity::SessionId;
use central_session::contract::RequestIdentity;
use central_session::domain::{ActivationRequest, DeliveryId, SecurityEpoch};
use tokio::sync::Mutex;

use crate::policy::{HTML_RESPONSE_CAP, MatchedRoute};
use crate::ports::DeliveryPrecommit;

/// `Precommit` — the inputs the buffered layer needs to call
/// `ActivateDelivery` before flush. The handler mints the opaque
/// session identifier and session-bound CSRF value request-scoped,
/// hashes them, and supplies only the hashes here — plaintext never
/// crosses this boundary.
#[derive(Debug, Clone)]
pub struct Precommit {
    /// Ties the activation to the exact `delivery_pending` row.
    pub delivery_id: DeliveryId,
    /// `SHA-256` of the freshly minted opaque session identifier.
    pub token_hash: [u8; 32],
    /// `SHA-256` of the freshly minted session-bound CSRF value.
    pub csrf_hash: [u8; 32],
    /// Request-scoped caller identity re-asserted at activation.
    pub identity: RequestIdentity,
    /// The current workspace security epoch.
    pub epoch: SecurityEpoch,
    /// The pending session row, revoked when activation fails. (A
    /// post-return write failure is unobservable here — see the module
    /// doc.)
    pub session_id: SessionId,
}

/// `PrecommitSlot` — a once-per-request holder the handler arms to
/// signal "flush and activate". The layer inserts one fresh slot per
/// request before the handler runs; `arm` more than once per request
/// panics exactly like upstream's `PrecommitSlot.Set`.
#[derive(Debug, Default)]
pub struct PrecommitSlot {
    inner: Mutex<Option<Precommit>>,
}

impl PrecommitSlot {
    /// Records the precommit inputs. Calling `arm` twice in one request
    /// panics — a handler cannot accidentally re-arm a slot.
    pub async fn arm(&self, pc: Precommit) {
        let mut guard = self.inner.lock().await;
        assert!(
            guard.is_none(),
            "middleware: PrecommitSlot::arm called more than once per request"
        );
        *guard = Some(pc);
    }

    async fn take(&self) -> Option<Precommit> {
        self.inner.lock().await.take()
    }
}

/// The layer's collaborator set.
pub struct BufferedState<S: DeliveryPrecommit> {
    /// The session service (any `Service<S, B>` satisfies
    /// [`DeliveryPrecommit`]).
    pub service: Arc<S>,
}

impl<S: DeliveryPrecommit> Clone for BufferedState<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

/// The buffered entry point (`from_fn_with_state`).
pub async fn layer<S: DeliveryPrecommit>(
    axum::extract::State(state): axum::extract::State<BufferedState<S>>,
    mut req: Request,
    next: Next,
) -> Response {
    let cap = req
        .extensions()
        .get::<MatchedRoute>()
        .map_or(HTML_RESPONSE_CAP, |m| m.policy.effective_response_cap());
    let slot = Arc::new(PrecommitSlot::default());
    req.extensions_mut().insert(ArmedSlot(slot.clone()));
    let resp = next.run(req).await;
    let (mut parts, body) = resp.into_parts();
    let collected = collect_capped(body, cap).await;
    let bytes = match collected {
        Ok(b) => b,
        Err(()) => {
            // Overflow — fail closed: never activate, emit the bare 500
            // with handler-set body headers dropped.
            return buffered_failure(&mut parts);
        }
    };
    if let Some(pc) = slot.take().await {
        // Precommit path — activate before flush.
        if state
            .service
            .activate_delivery(ActivationRequest {
                delivery_id: pc.delivery_id,
                token_hash: pc.token_hash,
                csrf_hash: pc.csrf_hash,
                identity: pc.identity,
                epoch: pc.epoch,
            })
            .await
            .is_err()
        {
            let _ = state.service.revoke(pc.session_id).await;
            return buffered_failure(&mut parts);
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// The armed slot, stashed in request extensions. Handlers (Task 12)
/// fetch it to arm a bootstrap-exchange precommit.
#[derive(Debug, Clone)]
pub struct ArmedSlot(pub Arc<PrecommitSlot>);

/// Collects the body up to `cap` bytes; `Err(())` when the body
/// exceeds the cap or a body read fails (both are fail-closed).
async fn collect_capped(body: Body, cap: usize) -> Result<axum::body::Bytes, ()> {
    axum::body::to_bytes(body, cap).await.map_err(|_| ())
}

/// `writeStatus` — the bare `500` outcome: keep only non-body headers
/// (the §4.4 profile is applied outside by the security-headers layer).
fn buffered_failure(parts: &mut axum::http::response::Parts) -> Response {
    let kept: Vec<(axum::http::HeaderName, axum::http::HeaderValue)> = parts
        .headers
        .iter()
        .filter(|(name, _)| !is_body_header(name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    parts.headers.clear();
    for (name, value) in kept {
        parts.headers.append(name, value);
    }
    parts.status = StatusCode::INTERNAL_SERVER_ERROR;
    let taken = std::mem::replace(parts, Response::new(Body::empty()).into_parts().0);
    Response::from_parts(taken, Body::empty())
}

/// `isBodyHeader` — headers governing the body, dropped on the bare
/// `500` outcome.
fn is_body_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-encoding")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("content-language")
        || name.eq_ignore_ascii_case("content-location")
        || name.eq_ignore_ascii_case("set-cookie")
}
