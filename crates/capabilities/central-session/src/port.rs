//! Persistence and authority ports for `central-session` — the port of
//! upstream `internal/session/port/session_port.go`.
//!
//! [`SessionStore`] is the durable session persistence port. It owns
//! hash-only verifier registration/comparison, generation consumption,
//! throttle state, session transaction linearization, and the staged
//! precommit activation. Every method executes atomically with database
//! time; no method accepts or returns plaintext bootstrap, token, or
//! CSRF material.
//!
//! The legal state progression produced by this port is exactly:
//!
//! ```text
//! exchange          -> pending_bootstrap
//! prepare_delivery  -> delivery_pending
//! activate_delivery -> active        (precommit only)
//! revoke            -> revoked
//! ```
//!
//! [`ProtectedBootstrap`] is the broker-facing candidate activation
//! port (open decision D1): the service asks the broker to activate
//! only the exact registered candidate/generation/digest before
//! recording `delivery_pending`; the broker never receives the
//! bootstrap verifier or plaintext. R3 ships the dev-gated
//! `DevFileProtectedBootstrap` in `central-adapter-linux::dev_bootstrap`;
//! the broker-backed implementation lands in R5.

use central_foundation::identity::SessionId;

use crate::contract::{CandidateBinding, Failure};
use crate::domain::{
    ActivationRequest, DeliveryRequest, DeliveryResult, ExchangeRequest, ExchangeResult,
    PresentationLease, ReconcileCandidate, Session, ValidationRequest,
};

/// `SessionStore` — upstream `port.Store`. Every method executes
/// atomically with database time; no method accepts or returns
/// plaintext bootstrap, token, or CSRF material.
#[trait_variant::make(Send)]
pub trait SessionStore: Send + Sync + 'static {
    /// `DiscoverBootstrapCandidates` — durable `delivery_pending`
    /// sessions left by an interrupted bootstrap delivery (plus
    /// orphaned `pending_bootstrap` rows and first-use-overdue active
    /// rows). The returned candidates are PostgreSQL-backed recovery
    /// input; callers must still reconcile them through the session
    /// service.
    async fn discover_bootstrap_candidates(&self) -> Result<Vec<ReconcileCandidate>, Failure>;

    /// `Exchange` — conditionally accepts the current presented,
    /// unconsumed, unexpired bootstrap generation in one database-time
    /// transaction, increments/resets the per-generation
    /// five-failures-per-60-seconds throttle, and creates exactly one
    /// `pending_bootstrap` session plus the replacement candidate
    /// registration. On throttle it returns a typed `Failure`
    /// (`FailureClass::BootstrapThrottled`) carrying a bounded
    /// `Retry-After`; a losing concurrent exchange returns the
    /// indistinguishable invalid/consumed outcome and creates no
    /// session.
    async fn exchange(&self, req: ExchangeRequest) -> Result<ExchangeResult, Failure>;

    /// `PrepareDelivery` — records `delivery_pending` for the session
    /// after the broker has activated the exact registered candidate
    /// binding. It requires an exact candidate/generation/digest match
    /// and returns the `DeliveryId` that ties the buffered transport
    /// response to the pending row for the precommit hook.
    async fn prepare_delivery(&self, req: DeliveryRequest) -> Result<DeliveryResult, Failure>;

    /// `ActivateDelivery` — atomically transitions the
    /// `delivery_pending` session to `active` in the transport
    /// precommit hook immediately before flush. It re-asserts the
    /// request identity and current epoch and persists the freshly
    /// minted token and CSRF hashes. A response-write failure after
    /// this point conditionally revokes the session.
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure>;

    /// `Validate` — validates the session presented by a state-changing
    /// request: it compares the token hash, asserts the current
    /// security epoch, and returns the active, non-expired session. An
    /// expired, restarted, or epoch-invalidated session returns a typed
    /// `Failure`.
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure>;

    /// `Revoke` — transitions a `pending_bootstrap`, `delivery_pending`
    /// or `active` session to the `revoked` terminal state. Used by
    /// logout, response-write failure recovery, and reconciliation.
    async fn revoke(&self, id: SessionId) -> Result<(), Failure>;
}

/// `ProtectedBootstrap` — the broker-facing candidate activation port
/// (open decision D1). The service asks the broker to activate only the
/// exact registered candidate/generation/digest before recording
/// `delivery_pending`; the broker never receives the bootstrap verifier
/// or plaintext. A typed `Failure` (`FailureClass::AuthorityDenied`)
/// reports refusal.
#[trait_variant::make(Send)]
pub trait ProtectedBootstrap: Send + Sync + 'static {
    /// `Register` — records exact candidate evidence in the protected
    /// broker before the session row can advance to `delivery_pending`.
    async fn register(&self, binding: CandidateBinding) -> Result<(), Failure>;

    /// `Activate` — asks the broker to confirm activation of the exact
    /// registered candidate binding. It returns a typed `Failure`
    /// (`FailureClass::AuthorityDenied`) on refusal; it never compares
    /// or receives the bootstrap verifier.
    async fn activate(&self, binding: CandidateBinding) -> Result<(), Failure>;
}

/// `PresentationStore` — upstream's `presentationStore` sub-interface:
/// the store may additionally lease the current bootstrap generation
/// for presentation. In Go the service discovers it by interface
/// assertion; in Rust the [`crate::app::Service`] exposes the
/// presentation methods only when the store type implements this port.
#[trait_variant::make(Send)]
pub trait PresentationStore: Send + Sync + 'static {
    /// `BeginPresentation` — leases the current active bootstrap
    /// generation using the PostgreSQL clock. The lease is durable and
    /// replaces any prior presentation deadline for that generation.
    async fn begin_presentation(&self) -> Result<PresentationLease, Failure>;

    /// `ValidatePresentation` — checks the currently leased generation
    /// against the PostgreSQL clock. It intentionally returns no token
    /// or verifier material.
    async fn validate_presentation(&self) -> Result<(), Failure>;
}
