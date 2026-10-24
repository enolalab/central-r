//! `central-session` application layer — the `Service` that orchestrates
//! the B06 bootstrap exchange, staged delivery, precommit activation,
//! validation, logout, and crash-cutpoint reconciliation. Port of
//! upstream `internal/session/app/service.go`.
//!
//! The service depends only on the session domain types and the
//! `port.rs` traits; it never imports a concrete `sqlx`, broker,
//! helper, or HTTP type. It owns no plaintext: the transport derives
//! the opaque verifier and mints the session token and CSRF plaintext
//! request-scoped, passing only hashes across the service boundary.
//!
//! Upstream divergence notes:
//!
//! - `New` panics on nil ports in Go; Rust generics make the nil case
//!   unconstructible, so [`Service::new`] simply stores its arguments.
//! - `IssuePreAuthCSRF` cannot fail: `rand::random` is infallible where
//!   `crypto/rand.Read` is not, so the method returns the pair
//!   directly.
//! - `BeginPresentation`/`ValidatePresentation` upstream discover the
//!   `presentationStore` sub-interface by type assertion and return a
//!   `ClassAuthorityDenied` `Failure` when the store lacks it. Rust
//!   resolves the same contract at compile time: the methods exist only
//!   on `Service<S, B>` where `S: PresentationStore`.

use central_foundation::identity::SessionId;
use sha2::{Digest as _, Sha256};

use crate::contract::{Failure, FailureClass, Joined, PreAuthCSRF, Sentinel};
use crate::domain::{
    ActivationRequest, DeliveryRequest, DeliveryResult, ExchangeRequest, ExchangeResult,
    PresentationLease, ReconcileRequest, ReconcileResult, Session, ValidationRequest,
};
use crate::port::{PresentationStore, ProtectedBootstrap, SessionStore};

/// `Service` — orchestrates the B06 session lifecycle. It is safe to
/// construct with an in-memory `SessionStore` for tests; the production
/// PostgreSQL store is wired by the composition root.
pub struct Service<S, B> {
    store: S,
    bootstrap: B,
}

impl<S: SessionStore, B: ProtectedBootstrap> Service<S, B> {
    /// `New` — a `Service` wired to the supplied persistence and broker
    /// activation ports.
    pub const fn new(store: S, bootstrap: B) -> Self {
        Self { store, bootstrap }
    }

    /// `IssuePreAuthCSRF` — mints a fresh unauthenticated double-submit
    /// CSRF pair for the bootstrap page. The value is the cookie/header
    /// value presented by the browser (transport-scoped); the hash is
    /// `SHA-256(value)`, the form persisted on the pending session row
    /// after a successful exchange. The plaintext never leaves the
    /// request scope.
    #[must_use]
    pub fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        let value: [u8; 32] = rand::random();
        let hash: [u8; 32] = Sha256::digest(value).into();
        PreAuthCSRF::new(value, hash)
    }

    /// `ValidatePreAuthCSRF` — validates a presented pre-auth CSRF pair
    /// before the bootstrap exchange is attempted. A zero or mismatched
    /// pair (value does not hash to the presented hash) returns a typed
    /// `Failure` wrapping [`Sentinel::CsrfInvalid`]; the transport must
    /// reject the request without mutation and must never call
    /// [`Service::exchange_bootstrap`] afterwards. This is the gate
    /// that guarantees a CSRF failure never reaches the store.
    pub fn validate_pre_auth_csrf(&self, p: &PreAuthCSRF) -> Result<(), Failure> {
        if p.equal(&PreAuthCSRF::zero()) {
            return Err(Failure::new(
                FailureClass::CsrfInvalid,
                "pre-auth csrf missing",
                "reload the bootstrap page for a fresh form",
            )
            .with_cause(Sentinel::CsrfInvalid));
        }
        let got: [u8; 32] = Sha256::digest(p.value()).into();
        if got != p.hash() {
            return Err(Failure::new(
                FailureClass::CsrfInvalid,
                "pre-auth csrf mismatch",
                "reload the bootstrap page for a fresh form",
            )
            .with_cause(Sentinel::CsrfInvalid));
        }
        Ok(())
    }

    /// `ExchangeBootstrap` — performs the bootstrap exchange. It
    /// delegates the atomic generation consumption, throttle update,
    /// pending session creation, and replacement candidate registration
    /// to the `SessionStore`. On throttle it returns the typed `Failure`
    /// carrying a bounded `Retry-After`. The transport must have already
    /// validated the pre-auth CSRF; this method does not re-validate it.
    pub async fn exchange_bootstrap(
        &self,
        req: ExchangeRequest,
    ) -> Result<ExchangeResult, Failure> {
        self.store.exchange(req).await
    }

    /// `PrepareDelivery` — records `delivery_pending` for the session
    /// after asking the broker to activate the exact registered
    /// candidate binding. The broker is contacted before the store so an
    /// authority denial never leaves an orphaned `delivery_pending` row.
    /// On broker denial the typed `Failure`
    /// (`FailureClass::AuthorityDenied`) is returned and the store is
    /// untouched.
    pub async fn prepare_delivery(&self, req: DeliveryRequest) -> Result<DeliveryResult, Failure> {
        if let Err(e) = self.bootstrap.register(req.candidate.clone()).await {
            let _ = self.store.revoke(req.session_id).await;
            return Err(as_authority_failure(e));
        }
        if let Err(e) = self.bootstrap.activate(req.candidate.clone()).await {
            let _ = self.store.revoke(req.session_id).await;
            return Err(as_authority_failure(e));
        }
        match self.store.prepare_delivery(req.clone()).await {
            Err(e) => {
                let _ = self.store.revoke(req.session_id).await;
                Err(e)
            }
            ok => ok,
        }
    }

    /// `ActivateDelivery` — the precommit hook invoked by the transport
    /// immediately before flushing the buffered successful-delivery
    /// response. It atomically transitions the `delivery_pending`
    /// session to `active`, persisting the freshly minted token and
    /// CSRF hashes. A failure here must cause the transport to withhold
    /// the response and conditionally revoke the session.
    pub async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
        self.store.activate_delivery(req).await
    }

    /// `Validate` — validates the session presented by a state-changing
    /// request. It delegates token-hash comparison and epoch assertion
    /// to the `SessionStore` and returns the active, non-expired
    /// session. An expired, restarted, or epoch-invalidated session
    /// returns a typed `Failure`.
    pub async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
        self.store.validate(req).await
    }

    /// `Logout` — revokes the session and clears server-side state. It
    /// delegates to the `SessionStore`; the transport is responsible
    /// for clearing the browser cookies.
    pub async fn logout(&self, id: SessionId) -> Result<(), Failure> {
        self.store.revoke(id).await
    }

    /// `ReconcileBootstrap` — drives crash-cutpoint recovery before
    /// kernel readiness. For each discovered `delivery_pending` session
    /// it revokes the row when the broker did not activate the
    /// candidate. An acknowledged delivery is also revoked and reported
    /// as a typed failure because reconciliation has no request-scoped
    /// hashes with which to safely complete activation. This is the
    /// sole path by which a session left pending by a crash reaches a
    /// terminal outcome; it never re-reveals plaintext and never
    /// re-derives the bootstrap verifier.
    pub async fn reconcile_bootstrap(
        &self,
        req: ReconcileRequest,
    ) -> Result<ReconcileResult, Failure> {
        let mut res = ReconcileResult::default();
        let mut first_err = None;
        let mut acknowledged = false;
        for c in &req.candidates {
            match self.store.revoke(c.delivery_id.as_session_id()).await {
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Ok(()) => {
                    res.revoked += 1;
                    if c.activated && !c.pending_bootstrap && !c.first_use_overdue {
                        // Reconciliation has no request-scoped plaintext
                        // and therefore no safe way to reconstruct the
                        // hashes minted during delivery. Fail closed
                        // instead of promoting a row with unusable
                        // credentials.
                        acknowledged = true;
                    }
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        if acknowledged {
            return Err(Failure::new(
                FailureClass::SessionInvalidated,
                "acknowledged delivery cannot be recovered safely",
                "request a fresh bootstrap token",
            )
            .with_cause(Sentinel::SessionInvalidated));
        }
        Ok(res)
    }
}

impl<S: SessionStore + PresentationStore, B: ProtectedBootstrap> Service<S, B> {
    /// `BeginPresentation` — upstream's `presentationStore` method:
    /// callable only when the store implements [`PresentationStore`]
    /// (upstream's `ClassAuthorityDenied` "presentation authority
    /// unavailable" branch is the compile-time absence of this method).
    pub async fn begin_presentation(&self) -> Result<PresentationLease, Failure> {
        self.store.begin_presentation().await
    }

    /// `ValidatePresentation` — see [`Service::begin_presentation`].
    pub async fn validate_presentation(&self) -> Result<(), Failure> {
        self.store.validate_presentation().await
    }
}

/// `asAuthorityFailure` — normalizes a broker activation error into a
/// typed session `Failure`. If the error is already typed or wraps the
/// authority-denied sentinel it is returned unchanged; otherwise it is
/// classified as `FailureClass::AuthorityDenied` so the transport can
/// map it to a safe diagnostic without leaking the underlying broker
/// detail. The original error is joined with
/// [`Sentinel::AuthorityDenied`] as the cause so `is_sentinel` reaches
/// both.
fn as_authority_failure(err: Failure) -> Failure {
    if err.class.is_some() || err.is_sentinel(Sentinel::AuthorityDenied) {
        return err;
    }
    Failure::new(
        FailureClass::AuthorityDenied,
        "broker refused candidate activation",
        "request a fresh bootstrap token",
    )
    .with_cause(Joined(vec![
        Box::new(Sentinel::AuthorityDenied),
        Box::new(err),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        BOOTSTRAP_VERIFIER_V1, BootstrapVerifier, CandidateBinding, RequestIdentity,
    };
    use crate::domain::{
        DeliveryId, ReconcileCandidate, SecurityEpoch, SessionState, clamp_retry_after,
        new_throttled_failure, retry_after_from_failure,
    };
    use central_foundation::identity::WorkspaceId;
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};

    fn must_verifier() -> BootstrapVerifier {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        BootstrapVerifier::new(BOOTSTRAP_VERIFIER_V1, d)
    }

    fn must_identity() -> RequestIdentity {
        RequestIdentity {
            peer_uid: 1000,
            peer_pid: 4242,
            origin: "https://127.0.0.1:8080".to_string(),
        }
    }

    fn must_binding() -> CandidateBinding {
        CandidateBinding {
            candidate_id: "7a2f0d60-3c30-4f6d-8f90-1e2b3c4d5e6f".to_string(),
            generation: 7,
            digest: zeroize::Zeroizing::new([9u8; 32]),
        }
    }

    fn fake_session(state: SessionState) -> Session {
        Session {
            id: SessionId::new(),
            workspace_id: WorkspaceId::sentinel(),
            state,
            principal_identity: "p".to_string(),
            security_epoch: SecurityEpoch(1),
            token_hash: [0u8; 32],
            csrf_hash: [0u8; 32],
            idle_expiry: OffsetDateTime::UNIX_EPOCH,
            absolute_expiry: OffsetDateTime::UNIX_EPOCH,
            first_use_deadline: None,
            first_used_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_seen_at: OffsetDateTime::UNIX_EPOCH,
            revoked_at: None,
        }
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Runs an immediately-ready future to completion (the fakes never
    /// yield). `Waker::noop` keeps this unsafe-free — the same pattern
    /// `central-execution`/`central-artifact` test suites use.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut context) {
                core::task::Poll::Ready(output) => return output,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    // -----------------------------------------------------------------
    // local fakes — Arc-shared so the test keeps handles after the
    // service takes ownership
    // -----------------------------------------------------------------

    #[derive(Default)]
    struct StoreShared {
        discovered: Vec<ReconcileCandidate>,
        discover_calls: Mutex<usize>,
        exchange_calls: Mutex<usize>,
        prepare_calls: Mutex<usize>,
        activate_calls: Mutex<usize>,
        validate_calls: Mutex<usize>,
        revoke_calls: Mutex<usize>,
        begin_presentation_calls: Mutex<usize>,
        validate_presentation_calls: Mutex<usize>,
        last_req: Mutex<Option<ExchangeRequest>>,
        last_delivery_req: Mutex<Option<DeliveryRequest>>,
        last_activation_req: Mutex<Option<ActivationRequest>>,
        last_validation_req: Mutex<Option<ValidationRequest>>,
        revoked_ids: Mutex<Vec<SessionId>>,

        exchange_err: Mutex<Option<Failure>>,
        prepare_err: Mutex<Option<Failure>>,
        activate_err: Mutex<Option<Failure>>,
        validate_err: Mutex<Option<Failure>>,
        revoke_err: Mutex<Option<Failure>>,
        presentation_lease: Mutex<PresentationLease>,
        presentation_err: Mutex<Option<Failure>>,

        pending_session: Mutex<Option<Session>>,
        delivery_session: Mutex<Option<Session>>,
        active_session: Mutex<Option<Session>>,
        valid_session: Mutex<Option<Session>>,
    }

    #[derive(Clone, Default)]
    struct FakeStore(Arc<StoreShared>);

    impl SessionStore for FakeStore {
        async fn discover_bootstrap_candidates(&self) -> Result<Vec<ReconcileCandidate>, Failure> {
            *lock(&self.0.discover_calls) += 1;
            Ok(self.0.discovered.clone())
        }

        async fn exchange(&self, req: ExchangeRequest) -> Result<ExchangeResult, Failure> {
            *lock(&self.0.exchange_calls) += 1;
            *lock(&self.0.last_req) = Some(req);
            if let Some(e) = lock(&self.0.exchange_err).take() {
                return Err(e);
            }
            Ok(ExchangeResult {
                session: lock(&self.0.pending_session)
                    .clone()
                    .unwrap_or_else(|| fake_session(SessionState::PendingBootstrap)),
                replacement: must_binding(),
            })
        }

        async fn prepare_delivery(&self, req: DeliveryRequest) -> Result<DeliveryResult, Failure> {
            *lock(&self.0.prepare_calls) += 1;
            *lock(&self.0.last_delivery_req) = Some(req.clone());
            if let Some(e) = lock(&self.0.prepare_err).take() {
                return Err(e);
            }
            Ok(DeliveryResult {
                session: lock(&self.0.delivery_session)
                    .clone()
                    .unwrap_or_else(|| fake_session(SessionState::DeliveryPending)),
                delivery_id: DeliveryId::from_session_id(req.session_id),
            })
        }

        async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
            *lock(&self.0.activate_calls) += 1;
            *lock(&self.0.last_activation_req) = Some(req);
            if let Some(e) = lock(&self.0.activate_err).take() {
                return Err(e);
            }
            Ok(lock(&self.0.active_session)
                .clone()
                .unwrap_or_else(|| fake_session(SessionState::Active)))
        }

        async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
            *lock(&self.0.validate_calls) += 1;
            *lock(&self.0.last_validation_req) = Some(req);
            if let Some(e) = lock(&self.0.validate_err).take() {
                return Err(e);
            }
            Ok(lock(&self.0.valid_session)
                .clone()
                .unwrap_or_else(|| fake_session(SessionState::Active)))
        }

        async fn revoke(&self, id: SessionId) -> Result<(), Failure> {
            *lock(&self.0.revoke_calls) += 1;
            lock(&self.0.revoked_ids).push(id);
            match lock(&self.0.revoke_err).take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    impl PresentationStore for FakeStore {
        async fn begin_presentation(&self) -> Result<PresentationLease, Failure> {
            *lock(&self.0.begin_presentation_calls) += 1;
            if let Some(e) = lock(&self.0.presentation_err).take() {
                return Err(e);
            }
            Ok(*lock(&self.0.presentation_lease))
        }

        async fn validate_presentation(&self) -> Result<(), Failure> {
            *lock(&self.0.validate_presentation_calls) += 1;
            match lock(&self.0.presentation_err).take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    #[derive(Default)]
    struct BrokerShared {
        register_calls: Mutex<usize>,
        activate_calls: Mutex<usize>,
        registered: Mutex<Option<CandidateBinding>>,
        activated: Mutex<Option<CandidateBinding>>,
        register_err: Mutex<Option<Failure>>,
        activate_err: Mutex<Option<Failure>>,
    }

    #[derive(Clone, Default)]
    struct FakeBootstrap(Arc<BrokerShared>);

    impl ProtectedBootstrap for FakeBootstrap {
        async fn register(&self, binding: CandidateBinding) -> Result<(), Failure> {
            *lock(&self.0.register_calls) += 1;
            *lock(&self.0.registered) = Some(binding);
            match lock(&self.0.register_err).take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }

        async fn activate(&self, binding: CandidateBinding) -> Result<(), Failure> {
            *lock(&self.0.activate_calls) += 1;
            *lock(&self.0.activated) = Some(binding);
            match lock(&self.0.activate_err).take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    fn fixture() -> (Service<FakeStore, FakeBootstrap>, FakeStore, FakeBootstrap) {
        let store = FakeStore::default();
        *lock(&store.0.pending_session) = Some(fake_session(SessionState::PendingBootstrap));
        *lock(&store.0.delivery_session) = Some(fake_session(SessionState::DeliveryPending));
        *lock(&store.0.active_session) = Some(fake_session(SessionState::Active));
        *lock(&store.0.valid_session) = Some(fake_session(SessionState::Active));
        let bootstrap = FakeBootstrap::default();
        (
            Service::new(store.clone(), bootstrap.clone()),
            store,
            bootstrap,
        )
    }

    fn exchange_req() -> ExchangeRequest {
        ExchangeRequest {
            workspace_id: None,
            verifier: must_verifier(),
            identity: must_identity(),
            pre_auth_csrf_hash: [7u8; 32],
            epoch: SecurityEpoch(1),
            idle_expiry: Duration::minutes(30),
            absolute_expiry: Duration::hours(12),
            first_use_fence: crate::domain::DEFAULT_FIRST_USE_FENCE,
        }
    }

    // -----------------------------------------------------------------
    // tests
    // -----------------------------------------------------------------

    /// `IssuePreAuthCSRF` — the minted pair must satisfy its own
    /// validation gate and must never collide on consecutive issues.
    #[test]
    fn issue_pre_auth_csrf_mints_valid_pairs() {
        let (svc, _, _) = fixture();
        let a = svc.issue_pre_auth_csrf();
        let b = svc.issue_pre_auth_csrf();
        assert!(!a.is_zero());
        assert!(!b.is_zero());
        assert!(!a.equal(&b));
        svc.validate_pre_auth_csrf(&a)
            .expect("fresh pair rejected: {e}");
    }

    /// `ValidatePreAuthCSRF` — zero pairs and value/hash mismatches are
    /// typed `CSRF_INVALID` and never reach the store.
    #[test]
    fn validate_pre_auth_csrf_rejects_zero_and_mismatch() {
        let (svc, store, _) = fixture();
        let zero = PreAuthCSRF::zero();
        let e = svc.validate_pre_auth_csrf(&zero).unwrap_err();
        assert_eq!(e.class, Some(FailureClass::CsrfInvalid));
        assert!(e.is_sentinel(Sentinel::CsrfInvalid));

        let good = svc.issue_pre_auth_csrf();
        let mismatched = PreAuthCSRF::new(good.value(), [0xabu8; 32]);
        let e = svc.validate_pre_auth_csrf(&mismatched).unwrap_err();
        assert_eq!(e.class, Some(FailureClass::CsrfInvalid));
        assert!(e.is_sentinel(Sentinel::CsrfInvalid));

        assert_eq!(*lock(&store.0.exchange_calls), 0);
        assert_eq!(*lock(&store.0.discover_calls), 0);
    }

    /// `ExchangeBootstrap` — the service forwards the request untouched
    /// and returns the pending session plus replacement binding.
    #[test]
    fn exchange_bootstrap_delegates() {
        let (svc, store, _) = fixture();
        let res = block_on(svc.exchange_bootstrap(exchange_req())).expect("exchange: {e}");
        assert_eq!(res.session.state, SessionState::PendingBootstrap);
        assert_eq!(res.replacement.candidate_id, must_binding().candidate_id);
        assert_eq!(*lock(&store.0.exchange_calls), 1);
        let req = lock(&store.0.last_req);
        let req = req.as_ref().unwrap();
        assert!(req.verifier.equal(&must_verifier()));
        assert_eq!(req.identity, must_identity());
        assert_eq!(req.pre_auth_csrf_hash, [7u8; 32]);
    }

    /// `ExchangeBootstrap` — a store throttle propagates verbatim with
    /// its bounded retry-after.
    #[test]
    fn exchange_bootstrap_propagates_throttle() {
        let (svc, store, _) = fixture();
        *lock(&store.0.exchange_err) = Some(new_throttled_failure(Duration::seconds(30)));
        let e = block_on(svc.exchange_bootstrap(exchange_req())).unwrap_err();
        assert_eq!(e.class, Some(FailureClass::BootstrapThrottled));
        assert_eq!(retry_after_from_failure(&e).map(|r| r.seconds()), Some(30));
    }

    /// `PrepareDelivery` — the broker is registered then activated
    /// BEFORE the store is touched, with the exact candidate binding.
    #[test]
    fn prepare_delivery_registers_then_activates_before_store() {
        let (svc, store, broker) = fixture();
        let sid = SessionId::new();
        let binding = must_binding();
        let res = block_on(svc.prepare_delivery(DeliveryRequest {
            session_id: sid,
            candidate: binding.clone(),
        }))
        .expect("prepare: {e}");
        assert_eq!(res.session.state, SessionState::DeliveryPending);
        assert_eq!(res.delivery_id.as_session_id(), sid);

        assert_eq!(*lock(&broker.0.register_calls), 1);
        assert_eq!(*lock(&broker.0.activate_calls), 1);
        assert_eq!(*lock(&store.0.prepare_calls), 1);
        let reg = lock(&broker.0.registered);
        let act = lock(&broker.0.activated);
        assert!(reg.as_ref().unwrap().equal(&binding));
        assert!(act.as_ref().unwrap().equal(&binding));
        let req = lock(&store.0.last_delivery_req);
        assert!(req.as_ref().unwrap().candidate.equal(&binding));
        assert_eq!(*lock(&store.0.revoke_calls), 0);
    }

    /// `PrepareDelivery` — a broker register failure is normalized to
    /// `AUTHORITY_DENIED`, the pending session is revoked, and the
    /// store's prepare path is never touched.
    #[test]
    fn prepare_delivery_register_denial_revokes_and_skips_store() {
        let (svc, store, broker) = fixture();
        *lock(&broker.0.register_err) = Some(Failure::untyped("broker unreachable"));
        let sid = SessionId::new();
        let e = block_on(svc.prepare_delivery(DeliveryRequest {
            session_id: sid,
            candidate: must_binding(),
        }))
        .unwrap_err();
        assert_eq!(e.class, Some(FailureClass::AuthorityDenied));
        assert!(e.is_sentinel(Sentinel::AuthorityDenied));
        assert_eq!(*lock(&store.0.prepare_calls), 0);
        assert_eq!(*lock(&store.0.revoke_calls), 1);
        assert_eq!(lock(&store.0.revoked_ids)[0], sid);
    }

    /// `PrepareDelivery` — an activate denial behaves identically.
    #[test]
    fn prepare_delivery_activate_denial_revokes() {
        let (svc, store, broker) = fixture();
        *lock(&broker.0.activate_err) = Some(Failure::untyped("refused"));
        let sid = SessionId::new();
        let e = block_on(svc.prepare_delivery(DeliveryRequest {
            session_id: sid,
            candidate: must_binding(),
        }))
        .unwrap_err();
        assert_eq!(e.class, Some(FailureClass::AuthorityDenied));
        assert_eq!(*lock(&store.0.prepare_calls), 0);
        assert_eq!(lock(&store.0.revoked_ids)[0], sid);
    }

    /// `PrepareDelivery` — a store prepare failure still revokes the
    /// orphaned pending row (upstream crash-safety shape).
    #[test]
    fn prepare_delivery_store_failure_revokes() {
        let (svc, store, _) = fixture();
        *lock(&store.0.prepare_err) = Some(Failure::untyped("session store: prepare"));
        let sid = SessionId::new();
        let e = block_on(svc.prepare_delivery(DeliveryRequest {
            session_id: sid,
            candidate: must_binding(),
        }))
        .unwrap_err();
        assert_eq!(e.class, None);
        assert_eq!(lock(&store.0.revoked_ids)[0], sid);
    }

    /// `PrepareDelivery` — a typed broker failure (already a
    /// `session.Failure` or wrapping the denied sentinel) is NOT
    /// re-wrapped.
    #[test]
    fn prepare_delivery_preserves_typed_broker_failures() {
        let (svc, _, broker) = fixture();
        *lock(&broker.0.register_err) = Some(
            Failure::new(
                FailureClass::AuthorityDenied,
                "denied",
                "request fresh token",
            )
            .with_cause(Sentinel::AuthorityDenied),
        );
        let e = block_on(svc.prepare_delivery(DeliveryRequest {
            session_id: SessionId::new(),
            candidate: must_binding(),
        }))
        .unwrap_err();
        assert_eq!(e.reason, "denied");
        assert_eq!(e.remediation, "request fresh token");
    }

    /// `ActivateDelivery` — forwarded verbatim.
    #[test]
    fn activate_delivery_delegates() {
        let (svc, store, _) = fixture();
        let sid = SessionId::new();
        let req = ActivationRequest {
            delivery_id: DeliveryId::from_session_id(sid),
            token_hash: [1u8; 32],
            csrf_hash: [2u8; 32],
            identity: must_identity(),
            epoch: SecurityEpoch(9),
        };
        let s = block_on(svc.activate_delivery(req)).expect("activate: {e}");
        assert_eq!(s.state, SessionState::Active);
        let got = lock(&store.0.last_activation_req);
        let got = got.as_ref().unwrap();
        assert_eq!(got.delivery_id.as_session_id(), sid);
        assert_eq!(got.token_hash, [1u8; 32]);
        assert_eq!(got.csrf_hash, [2u8; 32]);
    }

    /// `Validate` / `Logout` — forwarded verbatim.
    #[test]
    fn validate_and_logout_delegate() {
        let (svc, store, _) = fixture();
        let s = block_on(svc.validate(ValidationRequest {
            token_hash: [3u8; 32],
            presented_csrf_hash: Some([4u8; 32]),
            epoch: SecurityEpoch(1),
        }))
        .expect("validate: {e}");
        assert_eq!(s.state, SessionState::Active);
        assert_eq!(*lock(&store.0.validate_calls), 1);
        let sid = SessionId::new();
        block_on(svc.logout(sid)).expect("logout: {e}");
        assert_eq!(lock(&store.0.revoked_ids)[0], sid);
    }

    /// `ReconcileBootstrap` — orphaned candidates are revoked; an
    /// activated-but-unrecoverable candidate is revoked AND reported as
    /// the typed fail-closed failure.
    #[test]
    fn reconcile_revokes_orphans_and_fails_closed_on_acknowledged() {
        let (svc, store, _) = fixture();
        let a = SessionId::new();
        let b = SessionId::new();
        let res = block_on(svc.reconcile_bootstrap(ReconcileRequest {
            epoch: SecurityEpoch(1),
            candidates: vec![
                ReconcileCandidate {
                    delivery_id: DeliveryId::from_session_id(a),
                    activated: false,
                    pending_bootstrap: false,
                    first_use_overdue: false,
                },
                ReconcileCandidate {
                    delivery_id: DeliveryId::from_session_id(b),
                    activated: false,
                    pending_bootstrap: true,
                    first_use_overdue: false,
                },
            ],
        }))
        .expect("reconcile: {e}");
        assert_eq!(res.revoked, 2);
        assert_eq!(res.activated, 0);
        assert_eq!(lock(&store.0.revoked_ids).len(), 2);

        let c = SessionId::new();
        let e = block_on(svc.reconcile_bootstrap(ReconcileRequest {
            epoch: SecurityEpoch(1),
            candidates: vec![ReconcileCandidate {
                delivery_id: DeliveryId::from_session_id(c),
                activated: true,
                pending_bootstrap: false,
                first_use_overdue: false,
            }],
        }))
        .unwrap_err();
        assert_eq!(e.class, Some(FailureClass::SessionInvalidated));
        assert!(e.is_sentinel(Sentinel::SessionInvalidated));
        // The row was still revoked — fail closed never leaves a
        // durable delivery_pending behind.
        assert!(lock(&store.0.revoked_ids).contains(&c));
    }

    /// `ReconcileBootstrap` — a revoke error surfaces (first error wins)
    /// but reconciliation keeps draining the rest of the census.
    #[test]
    fn reconcile_surfaces_revoke_errors_and_keeps_draining() {
        let (svc, store, _) = fixture();
        *lock(&store.0.revoke_err) = Some(Failure::untyped("session store: revoke"));
        let a = SessionId::new();
        let b = SessionId::new();
        let e = block_on(svc.reconcile_bootstrap(ReconcileRequest {
            epoch: SecurityEpoch(1),
            candidates: vec![
                ReconcileCandidate {
                    delivery_id: DeliveryId::from_session_id(a),
                    activated: false,
                    pending_bootstrap: false,
                    first_use_overdue: false,
                },
                ReconcileCandidate {
                    delivery_id: DeliveryId::from_session_id(b),
                    activated: false,
                    pending_bootstrap: false,
                    first_use_overdue: false,
                },
            ],
        }))
        .unwrap_err();
        assert_eq!(e.reason, "session store: revoke");
        assert_eq!(*lock(&store.0.revoke_calls), 2);
    }

    /// `BeginPresentation`/`ValidatePresentation` — available only when
    /// the store implements `PresentationStore`; forwarded verbatim.
    #[test]
    fn presentation_delegates() {
        let (svc, store, _) = fixture();
        *lock(&store.0.presentation_lease) = PresentationLease {
            generation: 3,
            deadline: Some(OffsetDateTime::UNIX_EPOCH + Duration::minutes(3)),
        };
        let lease = block_on(svc.begin_presentation()).expect("begin: {e}");
        assert_eq!(lease.generation, 3);
        block_on(svc.validate_presentation()).expect("validate presentation: {e}");
        assert_eq!(*lock(&store.0.begin_presentation_calls), 1);
        assert_eq!(*lock(&store.0.validate_presentation_calls), 1);
    }

    /// `clamp_retry_after` exercised from app (the transport path uses
    /// the extracted value for the HTTP 429 header).
    #[test]
    fn retry_after_extraction_from_app_surface() {
        let f = new_throttled_failure(Duration::seconds(90));
        let ra = retry_after_from_failure(&f).unwrap();
        assert_eq!(ra.seconds(), 60);
        assert_eq!(clamp_retry_after(Duration::seconds(5)).seconds(), 5);
    }
}
