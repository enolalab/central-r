//! `central-session` domain — the B06 session capability: the typed
//! session lifecycle state machine, the durable `Session` entity, and
//! every request/result type that crosses the session `Store` and
//! `ProtectedBootstrap` ports. Port of upstream
//! `internal/session/domain.go`.
//!
//! Domain code sees no `sqlx`, broker, helper, or HTTP type; plaintext
//! bootstrap and CSRF material remains request-scoped transport-only
//! and is reachable from this package only through the opaque hashes
//! and verifiers declared in `contract.rs`.
//!
//! Upstream divergence notes:
//!
//! - `SessionID`/`DeliveryID` upstream are canonical-UUID strings. The
//!   port uses `central_foundation::identity::SessionId` (UUIDv7) and a
//!   [`DeliveryId`] newtype wrapping it — the store mints UUIDv7
//!   session ids where upstream minted v4 (both are opaque `uuid`
//!   column values; canonical-form validation is by construction, so
//!   upstream's `sessionIDFromString` boundary check has no runtime
//!   counterpart).
//! - Go `time.Time` zero values ("unset") map to `Option<OffsetDateTime>`.

use std::fmt;

use central_foundation::identity::{SessionId, WorkspaceId};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::contract::{
    BootstrapVerifier, CandidateBinding, Failure, FailureClass, RequestIdentity, Sentinel, ct_eq,
};

// ---------------------------------------------------------------------------
// SessionState — typed lifecycle state machine
// ---------------------------------------------------------------------------

/// `SessionState` — the typed, precommit-protected session lifecycle
/// state. The legal forward path is exactly:
///
/// ```text
/// PendingBootstrap -> DeliveryPending -> Active -> Revoked
/// ```
///
/// No state may skip the `DeliveryPending` precommit stage. A
/// `pending_bootstrap` or `delivery_pending` row left behind by a crash
/// is reconciled by the service before kernel readiness; it is never
/// silently promoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// `PendingBootstrap` — the state of a session row created by a
    /// successful bootstrap exchange but whose buffered delivery
    /// response has not yet been prepared. The row exists; the opaque
    /// session identifier has not yet been minted.
    PendingBootstrap,
    /// `DeliveryPending` — the state of a session whose registered
    /// candidate has been activated by the broker and whose buffered
    /// response is awaiting the transport precommit hook. Only the
    /// precommit activation transitions this state to `Active`.
    DeliveryPending,
    /// `Active` — the state of a precommit-activated session bearing a
    /// minted opaque session identifier and session-bound CSRF. It is
    /// the only state that authorizes state-changing requests.
    Active,
    /// `Revoked` — the sole terminal state reachable from `Active`
    /// (logout, response-write failure, epoch invalidation, or
    /// reconciliation).
    Revoked,
    /// `Expired` — a database-level reaping outcome the adapter can
    /// observe in a stored row (`lifecycle_state` CHECK includes it);
    /// it is reachable only from `Active` and never skips the
    /// precommit-activated `Active` state. It is not a legal typed
    /// transition target.
    Expired,
}

impl SessionState {
    /// Upstream `SessionState` text — the persisted `lifecycle_state`
    /// value, a wire contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingBootstrap => "pending_bootstrap",
            Self::DeliveryPending => "delivery_pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    /// Parses a persisted `lifecycle_state`; `None` on an unknown value
    /// (the adapter maps `None` to a corrupt-row failure, never to a
    /// state).
    #[must_use]
    pub const fn from_db_str(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"pending_bootstrap" => Some(Self::PendingBootstrap),
            b"delivery_pending" => Some(Self::DeliveryPending),
            b"active" => Some(Self::Active),
            b"revoked" => Some(Self::Revoked),
            b"expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// `IsTerminal` — whether the state admits no further forward
    /// transition. Only `Revoked` is terminal (upstream's literal
    /// `s == Revoked` check: an `Expired` row is non-terminal but
    /// transitionless, exactly as in Go).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// `ValidTransitions` — the legal forward states reachable from
    /// `self` in a single typed transition. The list is intentionally
    /// exhaustive so adapters and tests can assert the precommit
    /// contract without re-deriving it.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [SessionState] {
        match self {
            Self::PendingBootstrap => &[Self::DeliveryPending],
            Self::DeliveryPending => &[Self::Active, Self::Revoked],
            Self::Active => &[Self::Revoked],
            Self::Revoked | Self::Expired => &[],
        }
    }

    /// `CanTransition` — whether `to` is a legal forward transition.
    #[must_use]
    pub fn can_transition(self, to: SessionState) -> bool {
        self.valid_transitions().contains(&to)
    }
}

impl fmt::Display for SessionState {
    /// The stable state string. It carries no secret material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Opaque identifiers and scalar policy types
// ---------------------------------------------------------------------------

/// `DeliveryID` — identifies the buffered delivery precommit slot tied
/// to a `delivery_pending` session. The transport buffers the
/// successful response keyed by this value and, immediately before
/// flush, calls `activate_delivery` with it so the adapter activates
/// exactly that pending row.
///
/// B05 has no delivery table: the `DeliveryId` is deliberately the
/// canonical session id (upstream `deliveryIDForSession`), so the only
/// constructor is [`SessionId`]-to-[`DeliveryId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryId(SessionId);

impl DeliveryId {
    /// `deliveryIDForSession` — the canonical session id becomes the
    /// delivery slot identity.
    #[must_use]
    pub const fn from_session_id(id: SessionId) -> Self {
        Self(id)
    }

    /// `sessionIDFromDeliveryID` — the delivery slot names exactly one
    /// session row.
    #[must_use]
    pub const fn as_session_id(self) -> SessionId {
        self.0
    }

    /// Whether the underlying id is the nil UUID (only reachable
    /// through a corrupted `from_trusted_db_bytes` row).
    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.0.is_nil()
    }
}

impl fmt::Display for DeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// `SecurityEpoch` — the workspace security epoch a session is bound
/// to. A session is rejected on every request whose current epoch
/// differs from the epoch recorded at activation. The epoch is safe to
/// expose in diagnostics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityEpoch(pub u64);

impl fmt::Display for SecurityEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Retry-After and first-use fence
// ---------------------------------------------------------------------------

/// `MaxRetryAfter` — the hard upper bound on the `Retry-After` the
/// transport may advertise on a throttled bootstrap exchange. The B06
/// throttle window is five failures per 60 seconds, so the advertised
/// wait never exceeds that window.
pub const MAX_RETRY_AFTER: Duration = Duration::seconds(60);

/// `RetryAfter` — the bounded duration the transport surfaces as the
/// HTTP 429 `Retry-After` header on a throttled bootstrap exchange. It
/// is always non-negative and never exceeds [`MAX_RETRY_AFTER`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetryAfter(Duration);

impl RetryAfter {
    /// The integer seconds form used in the HTTP `Retry-After` header.
    #[must_use]
    pub fn seconds(self) -> i64 {
        self.0.whole_seconds()
    }

    /// The underlying duration.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// `ClampRetryAfter` — clamps an arbitrary duration into a legal
/// [`RetryAfter`]: a negative or zero input yields zero, and any value
/// above [`MAX_RETRY_AFTER`] is reduced to the cap. This is the sole
/// constructor callers should use when the source duration is
/// untrusted.
#[must_use]
pub fn clamp_retry_after(d: Duration) -> RetryAfter {
    if d <= Duration::ZERO {
        return RetryAfter(Duration::ZERO);
    }
    RetryAfter(d.min(MAX_RETRY_AFTER))
}

/// `DefaultFirstUseFence` — the installed one-minute window after
/// activation within which the session must be first-used, or it is
/// invalidated by reconciliation. It bounds the uncertainty window of
/// a response-write failure.
pub const DEFAULT_FIRST_USE_FENCE: Duration = Duration::minutes(1);

/// `PresentationWindow` — the PostgreSQL-authoritative period for which
/// a bootstrap generation may be presented after the helper shows it.
pub const PRESENTATION_WINDOW: Duration = Duration::minutes(3);

/// `PresentationLease` — identifies the generation whose bootstrap
/// presentation is currently authorized. The deadline is read from
/// PostgreSQL, not a process clock or an in-memory helper state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PresentationLease {
    /// The generation whose presentation is authorized.
    pub generation: u64,
    /// The database-time deadline (`None` = Go's zero `time.Time`).
    pub deadline: Option<OffsetDateTime>,
}

impl PresentationLease {
    /// `Active` — whether the lease is unexpired at `now`.
    #[must_use]
    pub fn active(&self, now: OffsetDateTime) -> bool {
        self.deadline.is_some_and(|d| d > now)
    }
}

/// `retry_after_detail_key` — the `safe_details` key under which a
/// bounded `Retry-After` is carried inside a throttled `Failure`. It is
/// private to keep the extraction path single-channeled through
/// [`retry_after_from_failure`].
const RETRY_AFTER_DETAIL_KEY: &str = "retry_after_seconds";

/// `NewThrottledFailure` — builds the typed throttle `Failure` carrying
/// a bounded `Retry-After`. The `Retry-After` is clamped before storage
/// so an adapter can never leak an unbounded wait.
#[must_use]
pub fn new_throttled_failure(retry_after: Duration) -> Failure {
    let clamped = clamp_retry_after(retry_after);
    let mut f = Failure::new(
        FailureClass::BootstrapThrottled,
        "bootstrap throttle exceeded",
        "wait for the advertised retry window, then run central bootstrap show again",
    );
    f.safe_details.insert(
        RETRY_AFTER_DETAIL_KEY.to_string(),
        clamped.seconds().to_string(),
    );
    f.with_cause(Sentinel::BootstrapThrottled)
}

/// `RetryAfterFromFailure` — extracts the bounded `Retry-After` from a
/// throttled `Failure`. Returns `None` for any non-throttle `Failure`
/// or a `Failure` missing the detail.
#[must_use]
pub fn retry_after_from_failure(f: &Failure) -> Option<RetryAfter> {
    if f.class != Some(FailureClass::BootstrapThrottled) {
        return None;
    }
    let secs: i64 = f.safe_details.get(RETRY_AFTER_DETAIL_KEY)?.parse().ok()?;
    if secs < 0 {
        return None;
    }
    Some(clamp_retry_after(Duration::seconds(secs)))
}

// ---------------------------------------------------------------------------
// SessionCSRF — session-bound CSRF pair minted at activation
// ---------------------------------------------------------------------------

/// `SessionCSRF` — the session-bound double-submit CSRF pair minted at
/// activation. `value` is the cookie/header value presented by the
/// browser (transport-scoped, never persisted); `hash` is
/// `SHA-256(value)`, the form persisted in the session row and compared
/// on subsequent state-changing requests. Both are redacted in every
/// formatted representation, mirroring [`crate::contract::PreAuthCSRF`],
/// and `value` is zeroized on drop.
#[derive(Clone)]
pub struct SessionCSRF {
    value: Zeroizing<[u8; 32]>,
    hash: [u8; 32],
}

impl SessionCSRF {
    /// `NewSessionCSRF` — constructs a session CSRF pair from the
    /// presented value and its persisted hash.
    #[must_use]
    pub fn new(value: [u8; 32], hash: [u8; 32]) -> Self {
        Self {
            value: Zeroizing::new(value),
            hash,
        }
    }

    /// The presented value. Reachable only by code that already owns
    /// the pair (the narrow transport path). Never appears in logs or
    /// database errors.
    #[must_use]
    pub fn value(&self) -> [u8; 32] {
        *self.value
    }

    /// The persisted hash form. Reachable by the session store for row
    /// comparison; never formatted.
    #[must_use]
    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Whether the pair is the zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self.value == [0u8; 32] && self.hash == [0u8; 32]
    }

    /// `Equal` — whether two pairs share the same value and hash using
    /// constant-time comparisons.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        ct_eq(&self.value[..], &other.value[..]) && ct_eq(&self.hash[..], &other.hash[..])
    }
}

impl fmt::Display for SessionCSRF {
    /// Redacted representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("session_csrf:redacted")
    }
}

impl fmt::Debug for SessionCSRF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Session — durable session entity (hashes only)
// ---------------------------------------------------------------------------

/// `Session` — the durable session entity. It carries only hashes,
/// opaque identifiers, expiry deadlines, and lifecycle state; it never
/// carries plaintext bootstrap, token, or CSRF material. `Option` time
/// fields denote "unset" (Go's `time.Time` zero value).
#[derive(Clone, PartialEq)]
pub struct Session {
    /// The opaque internal row identifier.
    pub id: SessionId,
    /// The sentinel B05 workspace the session row is scoped to.
    pub workspace_id: WorkspaceId,
    /// The typed lifecycle state.
    pub state: SessionState,
    /// The broker-validated caller identity string persisted in the
    /// session row.
    pub principal_identity: String,
    /// The workspace epoch the session is bound to.
    pub security_epoch: SecurityEpoch,
    /// The persisted hash of the opaque session identifier presented by
    /// the browser cookie. Compared by the store on validation.
    pub token_hash: [u8; 32],
    /// The persisted hash of the session-bound CSRF value.
    pub csrf_hash: [u8; 32],
    /// The absolute time after which the session is idle-expired.
    pub idle_expiry: OffsetDateTime,
    /// The absolute time after which the session is expired regardless
    /// of activity.
    pub absolute_expiry: OffsetDateTime,
    /// The deadline by which the session must be first-used after
    /// activation (one-minute fence). `None` when not applicable.
    pub first_use_deadline: Option<OffsetDateTime>,
    /// Records the first validated use after activation. `None` until
    /// first use.
    pub first_used_at: Option<OffsetDateTime>,
    /// The row creation time (database clock).
    pub created_at: OffsetDateTime,
    /// The last validated request time.
    pub last_seen_at: OffsetDateTime,
    /// The time the session entered the `Revoked` terminal state.
    /// `None` until revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

impl Session {
    /// `IsExpired` — whether the session is past its idle or absolute
    /// expiry at the given `now`.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now > self.absolute_expiry || now > self.idle_expiry
    }

    /// `IsFirstUseOverdue` — whether an active session has not been
    /// first-used within its first-use fence. Used by reconciliation.
    #[must_use]
    pub fn is_first_use_overdue(&self, now: OffsetDateTime) -> bool {
        if self.first_use_deadline.is_none() || self.first_used_at.is_some() {
            return false;
        }
        self.first_use_deadline.is_some_and(|d| now > d)
    }
}

impl fmt::Debug for Session {
    /// Debug never formats the persisted credential hashes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("workspace_id", &self.workspace_id)
            .field("state", &self.state)
            .field("principal_identity", &self.principal_identity)
            .field("security_epoch", &self.security_epoch)
            .field("token_hash", &"<redacted>")
            .field("csrf_hash", &"<redacted>")
            .field("idle_expiry", &self.idle_expiry)
            .field("absolute_expiry", &self.absolute_expiry)
            .field("first_use_deadline", &self.first_use_deadline)
            .field("first_used_at", &self.first_used_at)
            .field("created_at", &self.created_at)
            .field("last_seen_at", &self.last_seen_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Exchange — bootstrap exchange request/result
// ---------------------------------------------------------------------------

/// `ExchangeRequest` — the opaque inputs to a bootstrap exchange. The
/// transport derives the `BootstrapVerifier` from the presented
/// plaintext (request-scoped) and supplies the pre-auth CSRF hash and
/// the caller identity validated by the admission guard. No plaintext
/// crosses this boundary.
#[derive(Clone)]
pub struct ExchangeRequest {
    /// The sentinel B05 workspace scope — `None` mirrors upstream's
    /// empty `WorkspaceID`, which the store treats as the sentinel.
    pub workspace_id: Option<WorkspaceId>,
    /// The opaque, versioned bootstrap verifier derived from the
    /// presented token.
    pub verifier: BootstrapVerifier,
    /// The request-scoped caller identity bound to the exchange.
    pub identity: RequestIdentity,
    /// The persisted hash of the validated pre-auth CSRF value, stored
    /// on the pending session row.
    pub pre_auth_csrf_hash: [u8; 32],
    /// The current workspace security epoch.
    pub epoch: SecurityEpoch,
    /// The session idle lifetime policy.
    pub idle_expiry: Duration,
    /// The session absolute lifetime policy.
    pub absolute_expiry: Duration,
    /// The one-minute activation fence policy.
    pub first_use_fence: Duration,
}

/// `ExchangeResult` — the outcome of a successful bootstrap exchange.
/// It carries the newly created `pending_bootstrap` session and the
/// replacement candidate binding registered for the next bootstrap.
#[derive(Debug, Clone)]
pub struct ExchangeResult {
    /// The `pending_bootstrap` session row.
    pub session: Session,
    /// The broker-issued candidate binding registered to replace the
    /// consumed generation.
    pub replacement: CandidateBinding,
}

// ---------------------------------------------------------------------------
// Delivery — broker activation + delivery_pending recording
// ---------------------------------------------------------------------------

/// `DeliveryRequest` — the inputs to delivery preparation: the session
/// to advance and the exact registered candidate binding the broker
/// must activate.
#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    /// The `pending_bootstrap` session to advance.
    pub session_id: SessionId,
    /// The exact registered candidate/generation/digest the broker
    /// activates.
    pub candidate: CandidateBinding,
}

/// `DeliveryResult` — the outcome of a successful delivery preparation.
/// The session is now `delivery_pending` and the `DeliveryId` ties the
/// buffered transport response to the exact pending row for the
/// precommit hook.
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    /// The `delivery_pending` session.
    pub session: Session,
    /// Identifies the buffered delivery precommit slot.
    pub delivery_id: DeliveryId,
}

// ---------------------------------------------------------------------------
// Activation — precommit hook
// ---------------------------------------------------------------------------

/// `ActivationRequest` — the inputs to the precommit activation invoked
/// immediately before the buffered response is flushed. The transport
/// mints the opaque session identifier and session-bound CSRF
/// (request-scoped plaintext), hashes them, and supplies only the
/// hashes here.
#[derive(Debug, Clone)]
pub struct ActivationRequest {
    /// Ties the activation to the exact `delivery_pending` row.
    pub delivery_id: DeliveryId,
    /// The persisted hash of the freshly minted opaque session
    /// identifier.
    pub token_hash: [u8; 32],
    /// The persisted hash of the freshly minted session-bound CSRF.
    pub csrf_hash: [u8; 32],
    /// The request-scoped caller identity, re-asserted at activation.
    pub identity: RequestIdentity,
    /// The current workspace security epoch, re-asserted at activation.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Validation — request-time session validation
// ---------------------------------------------------------------------------

/// `ValidationRequest` — the inputs to request-time session validation.
/// The transport supplies the hash of the presented session token (and,
/// where the route requires it, the presented session CSRF hash for
/// comparison).
#[derive(Debug, Clone)]
pub struct ValidationRequest {
    /// The hash of the session token presented by the browser.
    pub token_hash: [u8; 32],
    /// The hash of the session CSRF value presented by the browser
    /// double-submit. `None` when the route does not require a CSRF
    /// comparison (upstream's zero-hash sentinel).
    pub presented_csrf_hash: Option<[u8; 32]>,
    /// The current workspace security epoch to validate against.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Reconcile — crash-cutpoint recovery
// ---------------------------------------------------------------------------

/// `ReconcileCandidate` — one `delivery_pending` session discovered
/// after a crash and whether the protected broker confirms its
/// candidate was activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileCandidate {
    /// Identifies the `delivery_pending` session to reconcile.
    pub delivery_id: DeliveryId,
    /// Whether the broker confirms the registered candidate was
    /// activated. If true, the reconciler attempts to complete
    /// activation; if false, it revokes the orphaned pending row.
    pub activated: bool,
    /// Marks a session that never reached `delivery_pending`. It is
    /// revoked during startup reconciliation rather than left durable.
    pub pending_bootstrap: bool,
    /// Marks an active session that crossed its one-minute first-use
    /// fence without a validated request.
    pub first_use_overdue: bool,
}

/// `ReconcileRequest` — the discovered `delivery_pending` sessions and
/// the current epoch. The kernel gathers the candidates (from the
/// broker's registered evidence and the adapter's pending-session
/// census) and the service drives each to a terminal outcome before
/// readiness.
#[derive(Debug, Default, Clone)]
pub struct ReconcileRequest {
    /// The current workspace security epoch.
    pub epoch: SecurityEpoch,
    /// The `delivery_pending` sessions to reconcile.
    pub candidates: Vec<ReconcileCandidate>,
}

/// `ReconcileResult` — the reconciliation outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileResult {
    /// The number of sessions completed to `Active`.
    pub activated: usize,
    /// The number of sessions revoked (orphaned or overdue).
    pub revoked: usize,
}

impl fmt::Display for ReconcileResult {
    /// A safe summary. It carries no secret material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "reconcile:activated={}:revoked={}",
            self.activated, self.revoked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn hex_encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len() * 2);
        for b in input {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// `TestPresentationLeaseUsesThreeMinuteDeadline`.
    #[test]
    fn presentation_lease_uses_three_minute_deadline() {
        let now = datetime!(2026-10-24 12:00:00 UTC);
        let lease = PresentationLease {
            generation: 0,
            deadline: Some(now + PRESENTATION_WINDOW),
        };
        assert!(lease.active(now));
        assert!(!lease.active(now + PRESENTATION_WINDOW + Duration::nanoseconds(1)));
        assert!(!PresentationLease::default().active(now));
    }

    /// `TestSessionStateLifecycleAssertsPrecommitContract` — the
    /// canonical B06 state-machine assertion.
    #[test]
    fn session_state_lifecycle_asserts_precommit_contract() {
        for from in [
            SessionState::PendingBootstrap,
            SessionState::DeliveryPending,
        ] {
            assert!(!from.is_terminal(), "{from} must not be terminal");
            assert!(
                from.can_transition(SessionState::DeliveryPending)
                    || from.can_transition(SessionState::Active)
                    || from.can_transition(SessionState::Revoked),
                "{from} has no legal forward transition"
            );
        }
        assert!(SessionState::PendingBootstrap.can_transition(SessionState::DeliveryPending));
        assert!(SessionState::DeliveryPending.can_transition(SessionState::Active));
        assert!(SessionState::Active.can_transition(SessionState::Revoked));
    }

    /// `TestSessionStateTerminalAndForbiddenTransitions` — `Revoked` is
    /// the sole terminal state; the lifecycle never allows skipping the
    /// `delivery_pending` precommit stage.
    #[test]
    fn session_state_terminal_and_forbidden_transitions() {
        assert!(SessionState::Revoked.is_terminal());
        assert!(!SessionState::PendingBootstrap.is_terminal());
        assert!(!SessionState::DeliveryPending.is_terminal());
        assert!(!SessionState::Active.is_terminal());
        assert!(!SessionState::PendingBootstrap.can_transition(SessionState::Active));
        // A pending_bootstrap row may be reaped by the adapter, but the
        // typed domain transition pending_bootstrap -> revoked is not a
        // legal forward lifecycle step; only delivery_pending/active
        // sessions are revoked through the service.
        assert!(!SessionState::PendingBootstrap.can_transition(SessionState::Revoked));
    }

    /// `TestSessionStateValidTransitionsAreComplete` — every
    /// non-terminal state declares at least one forward transition and
    /// `Active`'s only forward transition is `Revoked`.
    #[test]
    fn session_state_valid_transitions_are_complete() {
        for s in [
            SessionState::PendingBootstrap,
            SessionState::DeliveryPending,
            SessionState::Active,
        ] {
            assert!(!s.valid_transitions().is_empty(), "{s} declares none");
        }
        assert_eq!(
            SessionState::Active.valid_transitions(),
            &[SessionState::Revoked]
        );
    }

    /// `as_str`/`from_db_str` cover the persisted vocabulary, including
    /// the adapter-observed `expired` reaping outcome.
    #[test]
    fn session_state_db_vocabulary() {
        for (s, text) in [
            (SessionState::PendingBootstrap, "pending_bootstrap"),
            (SessionState::DeliveryPending, "delivery_pending"),
            (SessionState::Active, "active"),
            (SessionState::Revoked, "revoked"),
            (SessionState::Expired, "expired"),
        ] {
            assert_eq!(s.as_str(), text);
            assert_eq!(SessionState::from_db_str(text), Some(s));
        }
        assert_eq!(SessionState::from_db_str("bogus"), None);
        assert!(SessionState::Expired.valid_transitions().is_empty());
    }

    /// `TestRetryAfterIsBounded` — the safe `Retry-After` is clamped to
    /// the B06 hard cap.
    #[test]
    fn retry_after_is_bounded() {
        assert!(MAX_RETRY_AFTER > Duration::ZERO);
        assert!(clamp_retry_after(Duration::hours(2)).duration() <= MAX_RETRY_AFTER);
        assert_eq!(
            clamp_retry_after(Duration::seconds(5)).duration(),
            Duration::seconds(5)
        );
        assert_eq!(
            clamp_retry_after(Duration::seconds(-1)).duration(),
            Duration::ZERO
        );
    }

    /// `TestThrottledFailureCarriesBoundedRetryAfter` — the typed
    /// throttle `Failure` carries an extractable, bounded `Retry-After`.
    #[test]
    fn throttled_failure_carries_bounded_retry_after() {
        let f = new_throttled_failure(Duration::seconds(42));
        let ra = retry_after_from_failure(&f).expect("must extract from a throttled failure");
        assert_eq!(ra.duration(), Duration::seconds(42));
        assert!(ra.duration() <= MAX_RETRY_AFTER);
        assert!(f.is_sentinel(Sentinel::BootstrapThrottled));

        let plain = Failure::new(FailureClass::BootstrapInvalid, "r", "");
        assert!(retry_after_from_failure(&plain).is_none());

        let over = new_throttled_failure(Duration::hours(1));
        let ra = retry_after_from_failure(&over).expect("clamped retry-after");
        assert_eq!(ra.duration(), MAX_RETRY_AFTER);
    }

    /// `TestSessionCSRFRedactsValueAndHash` — the session-bound CSRF
    /// pair never formats its value or hash, mirroring `PreAuthCSRF`.
    #[test]
    fn session_csrf_redacts_value_and_hash() {
        let mut value = [0u8; 32];
        for (i, b) in value.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = 0xd0u8.wrapping_add(i as u8);
        }
        let value_leak = hex_encode(&value);
        let hash_leak = hex_encode(&hash);

        let c = SessionCSRF::new(value, hash);
        assert_eq!(c.value(), value);
        assert_eq!(c.hash(), hash);
        for out in [c.to_string(), format!("{c:?}")] {
            assert!(!out.contains(&value_leak), "leaked value in {out:?}");
            assert!(!out.contains(&hash_leak), "leaked hash in {out:?}");
        }
    }

    /// `Session::is_expired` / `is_first_use_overdue` — the domain
    /// predicates consumed by reconciliation.
    #[test]
    fn session_expiry_predicates() {
        let now = datetime!(2026-10-24 12:00:00 UTC);
        let mut s = Session {
            id: SessionId::new(),
            workspace_id: WorkspaceId::sentinel(),
            state: SessionState::Active,
            principal_identity: "p".to_string(),
            security_epoch: SecurityEpoch(0),
            token_hash: [0u8; 32],
            csrf_hash: [0u8; 32],
            idle_expiry: now + Duration::minutes(30),
            absolute_expiry: now + Duration::hours(12),
            first_use_deadline: Some(now + Duration::minutes(1)),
            first_used_at: None,
            created_at: now,
            last_seen_at: now,
            revoked_at: None,
        };
        assert!(!s.is_expired(now));
        assert!(s.is_expired(now + Duration::minutes(31)));
        assert!(s.is_expired(now + Duration::hours(13)));

        assert!(!s.is_first_use_overdue(now));
        assert!(s.is_first_use_overdue(now + Duration::minutes(2)));
        s.first_used_at = Some(now);
        assert!(!s.is_first_use_overdue(now + Duration::minutes(2)));
        s.first_used_at = None;
        s.first_use_deadline = None;
        assert!(!s.is_first_use_overdue(now + Duration::hours(2)));
    }

    /// `DeliveryId` — the B05 no-delivery-table convention: it is the
    /// canonical session id and converts only through it.
    #[test]
    fn delivery_id_is_canonical_session_id() {
        let id = SessionId::new();
        let d = DeliveryId::from_session_id(id);
        assert_eq!(d.as_session_id(), id);
        assert!(!d.is_nil());
        assert_eq!(d.to_string(), id.to_string());
    }

    /// `ReconcileResult` — the safe summary carries no secret material.
    #[test]
    fn reconcile_result_display() {
        assert_eq!(
            ReconcileResult {
                activated: 1,
                revoked: 2
            }
            .to_string(),
            "reconcile:activated=1:revoked=2"
        );
    }
}
