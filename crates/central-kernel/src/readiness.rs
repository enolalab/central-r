//! Profile-aware readiness — ports `internal/kernel/readiness.go`.
//!
//! [`Readiness`] owns the single readiness transition of a serve profile
//! and the currently valid [`ReadyProof`]. The proof is never returned
//! after revocation, even if a caller kept a copy of an earlier value.
//! [`marshal_health`] is the default redacted health representation: it
//! excludes internal failure text and all proof material.

use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use time::OffsetDateTime;

use crate::readyproof::ReadyProof;

/// The externally observable lifecycle state of a serve profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Startup admission is in progress.
    Starting,
    /// The profile is admitted and serving.
    Ready,
    /// The profile is alive but not admitted (or its proof expired).
    NotReady,
    /// An intentional stop is settling.
    ShuttingDown,
    /// A terminal failure cancelled the profile.
    Failed,
}

impl State {
    /// Stable wire name (matches upstream `State` values).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
            Self::ShuttingDown => "shutting_down",
            Self::Failed => "failed",
        }
    }
}

/// Bounded, non-sensitive operational state for health rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// Current lifecycle state.
    pub state: State,
    /// Safe reason code (already passed through [`safe_reason`]).
    pub reason: String,
    /// Bounded remediation copy (already passed through
    /// [`safe_remediation`]).
    pub remediation: String,
    /// Exit class associated with the failure, when one is classified.
    pub failure_class: u8,
}

#[derive(Debug)]
struct Inner {
    state: State,
    reason: String,
    remediation: String,
    failure_class: u8,
    security_epoch: u64,
    proof: Option<ReadyProof>,
}

/// Shared readiness handle. Cheap to clone; every clone observes the same
/// profile transition exactly like the upstream `*Readiness`.
#[derive(Debug, Clone)]
pub struct Readiness {
    inner: Arc<Mutex<Inner>>,
    now: fn() -> OffsetDateTime,
}

impl Default for Readiness {
    fn default() -> Self {
        Self::new()
    }
}

impl Readiness {
    /// A fresh profile in [`State::Starting`], reading the UTC clock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_now(OffsetDateTime::now_utc)
    }

    /// Same as [`Self::new`] but reads `now` for expiry checks — the test
    /// seam upstream provides through `Config.Now`.
    #[must_use]
    pub fn with_now(now: fn() -> OffsetDateTime) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                state: State::Starting,
                reason: String::new(),
                remediation: String::new(),
                failure_class: 0,
                security_epoch: 0,
                proof: None,
            })),
            now,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned readiness mutex means a profile transition panicked
        // mid-write; the fail-closed answer is to keep serving the last
        // durable state rather than expose a half-written transition.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expire_locked(&self, inner: &mut Inner) {
        let Some(proof) = &inner.proof else {
            return;
        };
        if inner.state != State::Ready || !proof.is_expired((self.now)()) {
            return;
        }
        inner.state = State::NotReady;
        inner.reason = "READY_EXPIRED".to_string();
        inner.remediation = String::new();
        inner.failure_class = 0;
        inner.proof = None;
    }

    /// The current state, applying proof expiry first.
    #[must_use]
    pub fn state(&self) -> State {
        let mut inner = self.lock();
        self.expire_locked(&mut inner);
        inner.state
    }

    /// A bounded, non-sensitive health snapshot.
    #[must_use]
    pub fn health(&self) -> HealthSnapshot {
        let mut inner = self.lock();
        self.expire_locked(&mut inner);
        HealthSnapshot {
            state: inner.state,
            reason: inner.reason.clone(),
            remediation: inner.remediation.clone(),
            failure_class: inner.failure_class,
        }
    }

    /// The opaque proof only while this profile is ready.
    #[must_use]
    pub fn proof(&self) -> Option<ReadyProof> {
        let mut inner = self.lock();
        self.expire_locked(&mut inner);
        if inner.state != State::Ready {
            return None;
        }
        inner.proof.clone()
    }

    /// Records the authoritative epoch used to admit this profile. It is
    /// kept on readiness so every startup consumer observes the same
    /// preflight result without exposing the value through health
    /// responses.
    pub fn set_security_epoch(&self, epoch: u64) {
        self.lock().security_epoch = epoch;
    }

    /// The epoch recorded by [`Self::set_security_epoch`].
    #[must_use]
    pub fn security_epoch(&self) -> u64 {
        self.lock().security_epoch
    }

    /// Transitions to [`State::Ready`] holding `proof`.
    pub fn mark_ready(&self, proof: ReadyProof) {
        let mut inner = self.lock();
        inner.state = State::Ready;
        inner.reason = String::new();
        inner.remediation = String::new();
        inner.failure_class = 0;
        inner.proof = Some(proof);
    }

    /// Transitions to [`State::NotReady`] with a safe reason.
    pub fn mark_not_ready(&self, reason: &str) {
        self.mark_not_ready_diagnostic(0, reason, "");
    }

    /// Transitions to [`State::NotReady`] carrying the classified exit
    /// class plus bounded remediation (upstream `markNotReadyDiagnostic`).
    pub fn mark_not_ready_diagnostic(&self, failure_class: u8, reason: &str, remediation: &str) {
        let mut inner = self.lock();
        inner.state = State::NotReady;
        inner.reason = safe_reason(reason).to_string();
        inner.remediation = safe_remediation(remediation).to_string();
        inner.failure_class = failure_class;
        inner.proof = None;
    }

    /// Transitions to [`State::ShuttingDown`].
    pub fn mark_shutting_down(&self) {
        let mut inner = self.lock();
        inner.state = State::ShuttingDown;
        inner.reason = "SHUTTING_DOWN".to_string();
        inner.remediation = String::new();
        inner.failure_class = 0;
        inner.proof = None;
    }

    /// Transitions to [`State::Failed`] with a safe reason.
    pub fn mark_failed(&self, reason: &str) {
        let mut inner = self.lock();
        inner.state = State::Failed;
        inner.reason = safe_reason(reason).to_string();
        inner.remediation = String::new();
        inner.failure_class = 0;
        inner.proof = None;
    }
}

/// The default redacted health representation. Excludes internal failure
/// text and all proof material; `status` is exactly `ready` or
/// `not_ready` (matches upstream `MarshalHealth`).
#[must_use]
pub fn marshal_health(snapshot: &HealthSnapshot) -> Vec<u8> {
    #[derive(Serialize)]
    struct Rendered<'a> {
        status: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        reason: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        remediation: &'a str,
        #[serde(skip_serializing_if = "is_zero")]
        failure_class: u8,
    }
    fn is_zero(v: &u8) -> bool {
        *v == 0
    }
    let status = if snapshot.state == State::Ready {
        "ready"
    } else {
        "not_ready"
    };
    serde_json::to_vec(&Rendered {
        status,
        reason: safe_reason(&snapshot.reason),
        remediation: safe_remediation(&snapshot.remediation),
        failure_class: snapshot.failure_class,
    })
    // serde_json::to_vec on a flat struct of scalars cannot fail.
    .unwrap_or_default()
}

/// The safe-reason allowlist — every other input collapses to
/// `UNAVAILABLE`, and an empty reason also maps to `UNAVAILABLE`.
#[must_use]
pub fn safe_reason(reason: &str) -> &'static str {
    match reason {
        "CONFIG_INVALID" => "CONFIG_INVALID",
        "POSTGRES_UNAVAILABLE" => "POSTGRES_UNAVAILABLE",
        "POSTGRES_INCOMPATIBLE" => "POSTGRES_INCOMPATIBLE",
        "MIGRATION_REQUIRED" => "MIGRATION_REQUIRED",
        "LEASE_LOST" => "LEASE_LOST",
        "BACKGROUND_LOOP_FAILED" => "BACKGROUND_LOOP_FAILED",
        "SHUTTING_DOWN" => "SHUTTING_DOWN",
        "PORT_IN_USE" => "PORT_IN_USE",
        "TLS_INVALID" => "TLS_INVALID",
        "BOOTSTRAP_RECONCILIATION_FAILED" => "BOOTSTRAP_RECONCILIATION_FAILED",
        "EPOCH_MISMATCH" => "EPOCH_MISMATCH",
        "READY_EXPIRED" => "READY_EXPIRED",
        "PROVISION_REQUIRED" => "PROVISION_REQUIRED",
        "RESUME_REQUIRED" => "RESUME_REQUIRED",
        "REPAIR_REQUIRED" => "REPAIR_REQUIRED",
        _ => "UNAVAILABLE",
    }
}

/// Bounded remediation copy: over 256 bytes or containing control
/// characters collapses to empty.
#[must_use]
pub fn safe_remediation(remediation: &str) -> &str {
    if remediation.len() > 256 {
        return "";
    }
    if remediation
        .chars()
        .any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f)
    {
        return "";
    }
    remediation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readyproof::ReadyProof;
    use std::sync::atomic::{AtomicI64, Ordering};
    use time::macros::datetime;

    fn proof_expiring(at: OffsetDateTime) -> ReadyProof {
        ReadyProof {
            launch_id: "launch-1".into(),
            runtime_generation: "launch-1".into(),
            nonce: [7u8; 32],
            expires_at: at,
        }
    }

    #[test]
    fn readiness_starts_and_transitions() {
        let r = Readiness::new();
        assert_eq!(r.state(), State::Starting);
        assert!(r.proof().is_none());

        r.mark_ready(proof_expiring(datetime!(2099-01-01 0:00:00 UTC)));
        assert_eq!(r.state(), State::Ready);
        let proof = r.proof().unwrap();
        assert_eq!(proof.launch_id, "launch-1");

        r.mark_not_ready("POSTGRES_UNAVAILABLE");
        assert_eq!(r.state(), State::NotReady);
        assert!(r.proof().is_none(), "proof must never survive revocation");
        assert_eq!(r.health().reason, "POSTGRES_UNAVAILABLE");

        r.mark_shutting_down();
        assert_eq!(r.state(), State::ShuttingDown);
        assert_eq!(r.health().reason, "SHUTTING_DOWN");

        r.mark_failed("BACKGROUND_LOOP_FAILED");
        assert_eq!(r.state(), State::Failed);
        assert_eq!(r.health().reason, "BACKGROUND_LOOP_FAILED");
    }

    #[test]
    fn proof_expiry_drops_state_and_proof() {
        // Injectable clock: first now is before expiry, then past it.
        static TICK: AtomicI64 = AtomicI64::new(0);
        fn fake_now() -> OffsetDateTime {
            datetime!(2026-01-01 0:00:00 UTC) + time::Duration::seconds(TICK.load(Ordering::SeqCst))
        }
        let r = Readiness::with_now(fake_now);
        r.mark_ready(proof_expiring(datetime!(2026-01-01 0:00:10 UTC)));
        assert_eq!(r.state(), State::Ready);
        assert!(r.proof().is_some());

        TICK.store(11, Ordering::SeqCst);
        assert_eq!(r.state(), State::NotReady);
        assert_eq!(r.health().reason, "READY_EXPIRED");
        assert!(r.proof().is_none());
    }

    #[test]
    fn proof_is_never_returned_after_revocation() {
        let r = Readiness::new();
        r.mark_ready(proof_expiring(datetime!(2099-01-01 0:00:00 UTC)));
        let held = r.proof().unwrap();
        r.mark_failed("LEASE_LOST");
        assert!(r.proof().is_none());
        // The earlier copy still exists for the caller but the profile
        // will never hand it out again.
        assert_eq!(held.launch_id, "launch-1");
    }

    #[test]
    fn security_epoch_is_recorded_not_exposed_in_health() {
        let r = Readiness::new();
        r.set_security_epoch(42);
        assert_eq!(r.security_epoch(), 42);
        let health = String::from_utf8(marshal_health(&r.health())).unwrap();
        assert!(!health.contains("42"));
    }

    #[test]
    fn marshal_health_is_redacted() {
        let r = Readiness::new();
        r.mark_not_ready_diagnostic(5, "POSTGRES_INCOMPATIBLE", "run central migrate status");
        let json = String::from_utf8(marshal_health(&r.health())).unwrap();
        assert_eq!(
            json,
            "{\"status\":\"not_ready\",\"reason\":\"POSTGRES_INCOMPATIBLE\",\"remediation\":\"run central migrate status\",\"failure_class\":5}"
        );

        r.mark_ready(proof_expiring(datetime!(2099-01-01 0:00:00 UTC)));
        let json = String::from_utf8(marshal_health(&r.health())).unwrap();
        // Upstream `MarshalHealth` runs the reason through `safeReason`
        // even when ready; "" collapses to "UNAVAILABLE" rather than
        // being omitted (omitempty drops only empty strings).
        assert_eq!(json, "{\"status\":\"ready\",\"reason\":\"UNAVAILABLE\"}");
    }

    #[test]
    fn safe_reason_allowlist_collapses_unknown() {
        assert_eq!(safe_reason(""), "UNAVAILABLE");
        assert_eq!(safe_reason("some raw error text"), "UNAVAILABLE");
        assert_eq!(safe_reason("LEASE_LOST"), "LEASE_LOST");
        assert_eq!(safe_reason("READY_EXPIRED"), "READY_EXPIRED");
    }

    #[test]
    fn safe_remediation_bounds() {
        assert_eq!(safe_remediation("ok"), "ok");
        let long = "x".repeat(257);
        assert_eq!(safe_remediation(&long), "");
        assert_eq!(safe_remediation("has\nnewline"), "");
        assert_eq!(safe_remediation("has\x7fdelete"), "");
        let boundary = "x".repeat(256);
        assert_eq!(safe_remediation(&boundary), boundary);
    }

    #[test]
    fn clones_share_one_transition() {
        let a = Readiness::new();
        let b = a.clone();
        a.mark_ready(proof_expiring(datetime!(2099-01-01 0:00:00 UTC)));
        assert_eq!(b.state(), State::Ready);
        b.mark_shutting_down();
        assert_eq!(a.state(), State::ShuttingDown);
    }
}
