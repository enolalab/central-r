//! `internal/backup/restore_refusal.go` — the closed, locator-free
//! C03/C04 operator-facing refusal vocabulary. An adapter error's own
//! text — which may carry a path, device name, or other locator —
//! can never enter a refusal; classification accepts only these
//! values.

use central_foundation::failure::{Failure, FailureKind};

/// `RestoreRefusalReason` — the closed vocabulary. Any other value —
/// in particular one built by formatting or concatenation — is
/// rejected, which keeps the type locator-free by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreRefusalReason {
    /// `RESTORE_STATE_INVALID` — protected operation, ticket,
    /// authorization, or credential-release precondition does not
    /// currently permit this action.
    StateInvalid,
    /// `RESTORE_MEDIA_INVALID` — the sealed recovery evidence could
    /// not be opened or verified. Points at the media, never the
    /// target.
    MediaInvalid,
    /// `RESTORE_CAPACITY_INSUFFICIENT` — a bounded resource (time
    /// budget today, device headroom under the reserve gate) is not
    /// enough to proceed safely.
    CapacityInsufficient,
    /// `RESTORE_ENGINE_UNAVAILABLE` — a real failure not yet
    /// classified more finely: transport unreachable, destructive
    /// process not started or not cleanly exited, incomplete
    /// composition precondition.
    EngineUnavailable,
    /// `RESTORE_TARGET_ADMISSION_STALE` — the live target's re-derived
    /// identity no longer matches what this backup was sealed against.
    /// Dominant cause: a completed restore advanced the target's
    /// restore/security epochs (the anti-rollback property they exist
    /// for), permanently invalidating earlier backups.
    TargetAdmissionStale,
}

impl RestoreRefusalReason {
    /// The wire value (`RestoreRefusalReason` constant text).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateInvalid => "RESTORE_STATE_INVALID",
            Self::MediaInvalid => "RESTORE_MEDIA_INVALID",
            Self::CapacityInsufficient => "RESTORE_CAPACITY_INSUFFICIENT",
            Self::EngineUnavailable => "RESTORE_ENGINE_UNAVAILABLE",
            Self::TargetAdmissionStale => "RESTORE_TARGET_ADMISSION_STALE",
        }
    }

    /// `Valid` — parse a wire/decoded value strictly.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "RESTORE_STATE_INVALID" => Self::StateInvalid,
            "RESTORE_MEDIA_INVALID" => Self::MediaInvalid,
            "RESTORE_CAPACITY_INSUFFICIENT" => Self::CapacityInsufficient,
            "RESTORE_ENGINE_UNAVAILABLE" => Self::EngineUnavailable,
            "RESTORE_TARGET_ADMISSION_STALE" => Self::TargetAdmissionStale,
            _ => return None,
        })
    }

    /// Renders the reason as the layer's [`Failure`] — `Denied`, with
    /// the closed wire reason as BOTH the stable machine code and the
    /// (locator-free) message, so classification keys on `code()` and
    /// never inspects free text.
    #[must_use]
    pub fn into_failure(self) -> Failure {
        Failure::new(FailureKind::Denied, self.as_str(), self.as_str())
    }
}

/// `ClassifyRestoreRefusal` — extracts a known reason from a
/// [`Failure`]'s stable machine code (never its message), or returns
/// `fallback` when no recognized reason is present.
#[must_use]
pub fn classify_restore_refusal(
    failure: Option<&Failure>,
    fallback: RestoreRefusalReason,
) -> RestoreRefusalReason {
    // Only the stable machine code is trusted — an adapter error's
    // own text may carry a path, device name, or other locator and can
    // never enter a refusal.
    failure
        .and_then(|f| RestoreRefusalReason::from_wire(f.code()))
        .unwrap_or(fallback)
}

/// `SanitizeRestoreRefusalCause` — returns the reason only when the
/// failure already carries a known, locator-free refusal; otherwise
/// `None`. This boundary stops a raw adapter error's locator-bearing
/// text from ever reaching a refusal.
#[must_use]
pub fn sanitize_restore_refusal_cause(failure: &Failure) -> Option<RestoreRefusalReason> {
    RestoreRefusalReason::from_wire(failure.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_vocabulary() {
        for reason in [
            RestoreRefusalReason::StateInvalid,
            RestoreRefusalReason::MediaInvalid,
            RestoreRefusalReason::CapacityInsufficient,
            RestoreRefusalReason::EngineUnavailable,
            RestoreRefusalReason::TargetAdmissionStale,
        ] {
            assert_eq!(
                RestoreRefusalReason::from_wire(reason.as_str()),
                Some(reason)
            );
        }
        assert_eq!(RestoreRefusalReason::from_wire("something failed"), None);
        assert_eq!(RestoreRefusalReason::from_wire(""), None);
    }

    #[test]
    fn classification_never_reads_messages() {
        let refusal = RestoreRefusalReason::CapacityInsufficient.into_failure();
        assert_eq!(
            classify_restore_refusal(Some(&refusal), RestoreRefusalReason::StateInvalid),
            RestoreRefusalReason::CapacityInsufficient
        );
        // A locator-bearing adapter message falls back, never leaks.
        let raw = Failure::invalid("adapter", "cannot stat /var/lib/central/x");
        assert_eq!(
            classify_restore_refusal(Some(&raw), RestoreRefusalReason::StateInvalid),
            RestoreRefusalReason::StateInvalid
        );
        assert!(sanitize_restore_refusal_cause(&raw).is_none());
        assert_eq!(
            sanitize_restore_refusal_cause(&refusal),
            Some(RestoreRefusalReason::CapacityInsufficient)
        );
        assert_eq!(
            classify_restore_refusal(None, RestoreRefusalReason::EngineUnavailable),
            RestoreRefusalReason::EngineUnavailable
        );
    }
}
