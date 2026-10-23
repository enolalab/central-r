//! Startup-recovery helpers — the port of `internal/harness/recovery.go`
//! (harness phase 3a): [`attempt_id_for_step_attempt`], the shared-UUID
//! link between a harness attempt and its execution StepAttempt, and
//! [`Attempt::fail_unlaunched`], the reconciler's prepared → failed path.
//!
//! `codes::RECOVERY_NOT_AUTHORIZED` stands in for
//! `ErrRecoveryNotAuthorized`: a recovery-authorized write is refused
//! when the attempt's linked execution StepAttempt may still be driven
//! under a live lease, so recovery has no authority over the harness
//! attempt row.

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, StepAttemptId};
use time::OffsetDateTime;

use crate::attempt::Attempt;
use crate::domain::{Fence, State, Terminal, TerminalStatus, codes};

/// `harness.ReasonNotLaunched` — the `Terminal::reason` Central records
/// for an attempt that reached prepared but was never launched: the
/// harness process never started (harness phase 3a plan check 4). It is
/// a Central code, not part of an adapter's vocabulary.
pub const REASON_NOT_LAUNCHED: &str = "harness_not_launched";

/// `harness.AttemptIDForStepAttempt`: the harness attempt id that links
/// a harness attempt to its execution StepAttempt (phase 3a decision 2:
/// one harness attempt is one execution StepAttempt). The two ids are
/// the same UUID; the stores join on it, so no link column is needed.
pub fn attempt_id_for_step_attempt(id: StepAttemptId) -> Result<HarnessAttemptId, Failure> {
    if id.is_nil() {
        return Err(Failure::invalid(
            codes::INVALID_ATTEMPT,
            "zero step attempt id",
        ));
    }
    HarnessAttemptId::parse(&id.to_string()).map_err(|_| {
        Failure::invalid(
            codes::INVALID_ATTEMPT,
            "step attempt id is not a harness attempt id",
        )
    })
}

impl Attempt {
    /// `harness.Attempt.FailUnlaunched`: records that a prepared attempt
    /// was never launched — prepared → failed with
    /// `Terminal{failed, REASON_NOT_LAUNCHED}`. It is the existing
    /// prepared → failed transition, named for the phase 3a reconciler.
    pub fn fail_unlaunched(&self, fence: Fence, at: OffsetDateTime) -> Result<Self, Failure> {
        if self.state != State::Prepared {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!(
                    "only a prepared attempt can fail unlaunched, not {}",
                    self.state.as_str()
                ),
            ));
        }
        self.terminate(
            fence,
            Terminal {
                status: TerminalStatus::Failed,
                reason: REASON_NOT_LAUNCHED.to_string(),
                exit_code: None,
            },
            at,
        )
    }
}

#[cfg(test)]
mod tests {
    use central_foundation::identity::{HarnessAttemptId, RunId, StepAttemptId, WorkspaceId};
    use time::Duration;
    use time::macros::datetime;

    use super::*;
    use crate::attempt::{Attempt, PrepareInput};
    use crate::budget::Budget;
    use crate::domain::{Fence, Kind, PermissionPolicy, State, TerminalStatus, Workspace, codes};
    use crate::testkit::{is_code, nil_step_attempt_id, ok};

    // Ports upstream `preparedForRecovery`.
    fn prepared_for_recovery() -> Attempt {
        let at = datetime!(2026-09-28 12:00:00 UTC);
        ok(Attempt::prepare(PrepareInput {
            id: HarnessAttemptId::new(),
            workspace_id: WorkspaceId::new(),
            run_id: RunId::new(),
            kind: Kind::new("claude-code"),
            adapter_version: "2a".to_string(),
            permission: PermissionPolicy::Deny,
            workspace: Workspace {
                path: "/var/lib/central-harness/worktrees/runs/r/repo".to_string(),
                base_sha: "abc123".to_string(),
            },
            fence: Fence { generation: 1 },
            budget: Budget {
                cost_micro_usd: 5_000_000,
                wall_clock: Duration::minutes(30),
                ..Budget::default()
            },
            at,
        }))
    }

    // Ports upstream `TestPreparedAttemptFailsUnlaunched` — plan check 4:
    // the state machine already allows prepared -> failed, which needs no
    // launch facts.
    #[test]
    fn prepared_attempt_fails_unlaunched() {
        let a = prepared_for_recovery();
        assert!(State::Prepared.can_transition(State::Failed));
        let at = a.updated_at + Duration::seconds(1);
        let failed = a.fail_unlaunched(a.fence, at).unwrap();
        assert_eq!(failed.state, State::Failed);
        assert_eq!(failed.terminal.status, TerminalStatus::Failed);
        assert_eq!(failed.terminal.reason, REASON_NOT_LAUNCHED);
        assert_eq!(failed.ended_at, Some(at));
        assert_eq!(failed.sandbox_scope_id, "");
        assert_eq!(failed.harness_version, "");
        assert!(
            failed.validate().is_ok(),
            "failed attempt does not validate"
        );
        let err = a.fail_unlaunched(Fence { generation: 2 }, at).unwrap_err();
        assert!(is_code(&err, codes::FENCE_MISMATCH), "stale fence: {err}");
        let launched = ok(a.launch(a.fence, "scope-1", "2.1.283", at));
        let err = launched.fail_unlaunched(a.fence, at).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "launched attempt failed unlaunched: {err}"
        );
    }

    // Ports upstream `TestAttemptIDForStepAttemptSharesTheUUID`.
    #[test]
    fn attempt_id_for_step_attempt_shares_the_uuid() {
        let step = StepAttemptId::new();
        let id = attempt_id_for_step_attempt(step).unwrap();
        assert_eq!(id.to_string(), step.to_string());
        let err = attempt_id_for_step_attempt(nil_step_attempt_id()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "zero id: {err}");
    }
}
