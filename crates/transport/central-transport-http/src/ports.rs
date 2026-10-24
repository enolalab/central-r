//! Narrow capability ports the transport layers consume — the Rust
//! port of upstream's `middleware.CSRFService`, `middleware.SessionService`,
//! and `web.SessionService` seams.
//!
//! Each trait is satisfied by `central_session::app::Service<S, B>` for
//! any `S: SessionStore`, `B: ProtectedBootstrap`, mirroring upstream's
//! composition adapters (`bufferedSessionAdapter`, `csrfSessionAdapter`)
//! without the transport depending on a concrete store. The kernel wires
//! the concrete `Service` in Task 13; tests use in-memory fakes.

use central_foundation::identity::SessionId;
use central_session::app::Service;
use central_session::contract::{Failure, PreAuthCSRF};
use central_session::domain::{ActivationRequest, Session, ValidationRequest};
use central_session::port::{ProtectedBootstrap, SessionStore};

/// `CSRFService` — the pre-auth CSRF seam the [`crate::middleware::preauth`]
/// layer needs: mint a fresh pair on safe routes, validate a presented
/// pair on the bootstrap-exchange route.
pub trait PreAuthCsrf: Send + Sync + 'static {
    /// `IssuePreAuthCSRF` — infallible in the Rust port (`rand::random`
    /// cannot fail where upstream's `crypto/rand.Read` could).
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF;

    /// `ValidatePreAuthCSRF` — rejects a zero, mismatched, or replayed
    /// pair; a `Failure` here means the request is rejected before any
    /// mutation.
    fn validate_pre_auth_csrf(&self, pair: &PreAuthCSRF) -> Result<(), Failure>;
}

impl<S, B> PreAuthCsrf for Service<S, B>
where
    S: SessionStore,
    B: ProtectedBootstrap,
{
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        Service::issue_pre_auth_csrf(self)
    }

    fn validate_pre_auth_csrf(&self, pair: &PreAuthCSRF) -> Result<(), Failure> {
        Service::validate_pre_auth_csrf(self, pair)
    }
}

/// `SessionService` — the buffered precommit seam (upstream
/// `bufferedSessionAdapter`): the buffered layer calls
/// `activate_delivery` exactly once per request immediately before
/// flushing a successful response, and `revoke` on post-activation
/// failure. Upstream maps `Revoke` onto `Service::Logout`.
#[trait_variant::make(Send)]
pub trait DeliveryPrecommit: Send + Sync + 'static {
    /// `ActivateDelivery` — atomically transitions the `delivery_pending`
    /// session to `active`, persisting the freshly minted hashes.
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure>;

    /// `Revoke` — upstream's `svc.Revoke` → `Service::Logout` mapping.
    async fn revoke(&self, id: SessionId) -> Result<(), Failure>;
}

impl<S, B> DeliveryPrecommit for Service<S, B>
where
    S: SessionStore,
    B: ProtectedBootstrap,
{
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
        Service::activate_delivery(self, req).await
    }

    async fn revoke(&self, id: SessionId) -> Result<(), Failure> {
        Service::logout(self, id).await
    }
}

/// `SessionService` — the request-time session-validation seam
/// (upstream `web.Handler.sessions.Validate`).
#[trait_variant::make(Send)]
pub trait SessionValidator: Send + Sync + 'static {
    /// `Validate` — token-hash comparison, epoch assertion, expiry
    /// check. `presented_csrf_hash` carries the session-CSRF comparison
    /// for mutation routes.
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure>;
}

impl<S, B> SessionValidator for Service<S, B>
where
    S: SessionStore,
    B: ProtectedBootstrap,
{
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
        Service::validate(self, req).await
    }
}
