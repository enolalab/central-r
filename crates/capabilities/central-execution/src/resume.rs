//! Recovery epochs, recovery claimability, and resume evaluators —
//! the pure port of `central/internal/execution/resume.go`.
//!
//! A recovery epoch is a fenced coordinator pass over failed runs: it
//! scans per-workspace work rows, expires stale ownership, mints
//! prepared successors for never-invoked attempts, settles provable
//! outcomes from completion receipts, and can *resume* a reconciled
//! step by minting a successor step+attempt while keeping the run.

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{RunId, StepAttemptId, StepId, WorkspaceId};
use central_task::domain as task;
use central_task::execution_facade::{self, ExecutionTransition};
use sha2::Digest;
use time::OffsetDateTime;

use crate::domain::{
    self, AttemptState, Capability, Claimability, CommandEnvelope, EvaluationMetadata,
    ExecutionChangeSet, InvocationId, LogicalOperationId, PhysicalAttemptId,
    ReconciliationDisposition, ReconciliationEvidence, RequestFingerprint, Step, StepAttempt,
    StepState, TrustedScope, ZERO_TIME,
};
use crate::domain::{EVENT_ATTEMPT_RESUMED, OUTBOX_ATTEMPT_SETTLED};

fn failure(kind: FailureKind, reason: &'static str) -> Failure {
    Failure::new(kind, reason, "execution evaluation refused")
}

// ---------------------------------------------------------------------------
// Recovery epoch vocabulary (upstream RecoveryEpochState /
// RecoveryWorkspaceState / RecoveryCoordinatorFence).
// ---------------------------------------------------------------------------

/// `RecoveryEpochState` — one coordinator pass over a recovery epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecoveryEpochState {
    /// Minted, no coordinator has claimed it yet.
    #[default]
    RecoveryEpochOpen,
    /// A coordinator holds the fence and is scanning.
    RecoveryEpochRunning,
    /// Scan found (or inherited) degraded work — resumable, never
    /// auto-cleared without an explicit resume.
    RecoveryEpochDegraded,
    /// The epoch failed; a later epoch supersedes it.
    RecoveryEpochFailed,
    /// All workspace work completed; epoch is sealed.
    RecoveryEpochCompleted,
}

impl RecoveryEpochState {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryEpochOpen => "open",
            Self::RecoveryEpochRunning => "running",
            Self::RecoveryEpochDegraded => "degraded",
            Self::RecoveryEpochFailed => "failed",
            Self::RecoveryEpochCompleted => "completed",
        }
    }
    /// Completed/failed epochs accept no further mutation.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::RecoveryEpochFailed | Self::RecoveryEpochCompleted
        )
    }
}

/// `RecoveryWorkspaceState` — one workspace's row inside an epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecoveryWorkspaceState {
    /// Pending scan.
    #[default]
    RecoveryWorkspacePending,
    /// Claimed by the coordinator.
    RecoveryWorkspaceClaimed,
    /// Recovery actions committed.
    RecoveryWorkspaceCompleted,
    /// The workspace could not be recovered; work is parked until an
    /// operator resumes or cancels it.
    RecoveryWorkspaceFailed,
}

impl RecoveryWorkspaceState {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryWorkspacePending => "pending",
            Self::RecoveryWorkspaceClaimed => "claimed",
            Self::RecoveryWorkspaceCompleted => "completed",
            Self::RecoveryWorkspaceFailed => "failed",
        }
    }
}

/// `RecoveryCoordinatorFence` — the generation granted to the one
/// deployment-wide coordinator lease. The verifier is never retained by
/// the application; the adapter stores its hash and rechecks this
/// generation atomically.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryCoordinatorFence {
    /// Fenced generation; 0 means "no coordinator".
    pub generation: i64,
}

impl RecoveryCoordinatorFence {
    /// Upstream `RecoveryCoordinatorFence.Valid`.
    #[must_use]
    pub const fn valid(self) -> bool {
        self.generation > 0
    }
}

/// `RecoveryEpoch` — the durable epoch row.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryEpoch {
    /// Epoch identity — monotonically increasing.
    pub generation: i64,
    /// The coordinator's fence on this epoch.
    pub coordinator_fence: RecoveryCoordinatorFence,
    pub state: RecoveryEpochState,
    /// Scan cursor over the workspace keyspace.
    pub scheduler_cursor: WorkspaceId,
    /// Total workspace work rows in the epoch.
    pub workspace_count: i64,
    /// Workspace work rows already scanned.
    pub processed_count: i64,
    /// Advances durably after every workspace claim; backed by the
    /// epoch's processed counter so a takeover resumes fair ordering.
    pub claim_cycle: i64,
    /// Remaining scan budget in attempts.
    pub retry_attempt: i64,
    /// When the epoch snapshotted the failed-run watermark.
    pub snapshot_at: OffsetDateTime,
}

/// `RecoveryWorkspaceWork` — one workspace's recovery unit inside an
/// epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryWorkspaceWork {
    /// The epoch this work row belongs to.
    pub epoch_generation: i64,
    /// The workspace being recovered.
    pub workspace_id: WorkspaceId,
    pub state: RecoveryWorkspaceState,
    /// Watermark: runs failed *at or before* this point are covered.
    pub watermark_created_at: OffsetDateTime,
    /// The watermark's run-id tiebreak.
    pub watermark_run_id: RunId,
    /// Resume cursor: the last failed run's creation time.
    pub cursor_created_at: OffsetDateTime,
    /// Resume cursor: the last failed run's identity.
    pub cursor_run_id: RunId,
    /// Runs scanned by this work row.
    pub scanned_count: i64,
    /// Runs reconciled by this work row.
    pub reconciled_count: i64,
    /// Bounded recovery attempts spent on this row.
    pub retry_attempt: i64,
    /// Coarse failure bucket persisted on a failed row.
    pub failure_class: String,
    /// Operator-visible failure detail persisted on a failed row.
    pub failure_reason: String,
}

// ---------------------------------------------------------------------------
// Recovery claimability (upstream RecoveryClaimability).
// ---------------------------------------------------------------------------

/// `RecoveryClaimability` — a run created before a failed epoch's
/// watermark is quarantined until a reconciliation resolution at or
/// after the epoch's generation marks it reconciled.
#[must_use]
pub fn recovery_claimability(
    epoch: &RecoveryEpoch,
    work: &RecoveryWorkspaceWork,
    run_created_at: OffsetDateTime,
    run_id: RunId,
    reconciled_epoch_generation: i64,
) -> Claimability {
    let claimable = || Claimability {
        claimable: true,
        epoch_generation: epoch.generation,
        reason: String::new(),
    };
    if work.epoch_generation != epoch.generation
        || work.state == RecoveryWorkspaceState::RecoveryWorkspaceCompleted
        || reconciled_epoch_generation >= epoch.generation
    {
        return claimable();
    }
    let pre_watermark = run_created_at < work.watermark_created_at
        || (run_created_at == work.watermark_created_at
            && run_id.to_string() <= work.watermark_run_id.to_string());
    // Once serving continues in a degraded state, an operator may resume
    // the same epoch while listeners remain live. Therefore open/running
    // work is quarantined by the same durable watermark rule as
    // degraded/failed work; only a completed Workspace or reconciled Run
    // proves admission.
    if pre_watermark && epoch.state != RecoveryEpochState::RecoveryEpochCompleted {
        return Claimability {
            claimable: false,
            epoch_generation: epoch.generation,
            reason: "RECOVERY_QUARANTINE".to_string(),
        };
    }
    claimable()
}

/// `RecoveryCompletionState` — monotonic with respect to degradation.
/// A later successful workspace scan cannot erase an earlier
/// quarantine; only the explicitly authorized `ResumeEpoch` path may
/// move a degraded epoch back to running.
#[must_use]
pub fn recovery_completion_state(
    current: RecoveryEpochState,
    scan_failed: bool,
    no_incomplete_work: bool,
) -> (RecoveryEpochState, bool) {
    if current == RecoveryEpochState::RecoveryEpochDegraded
        || current == RecoveryEpochState::RecoveryEpochFailed
        || scan_failed
    {
        return (RecoveryEpochState::RecoveryEpochDegraded, false);
    }
    if no_incomplete_work {
        return (RecoveryEpochState::RecoveryEpochCompleted, true);
    }
    (RecoveryEpochState::RecoveryEpochRunning, false)
}

// ---------------------------------------------------------------------------
// `execution.resume_reconciled_attempt` — the B08 resume evaluator.
// ---------------------------------------------------------------------------

/// Floor for `remaining_cost_micro_usd` — mirrors the task budget
/// minimum; resuming below it can never afford a turn.
pub const MIN_RESUME_COST_MICRO_USD: i64 = task::MIN_BUDGET_COST_MICRO_USD;

/// `ResumeReconciledAttemptCommand` — mints a successor step+attempt
/// for a reconciled attempt while keeping the run.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeReconciledAttemptCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub new_step_id: StepId,
    pub new_attempt_id: StepAttemptId,
    /// The successor's logical operation — must differ from the
    /// reconciled attempt's.
    pub new_logical_operation: LogicalOperationId,
    pub physical_attempt_id: PhysicalAttemptId,
    /// Operator evidence for the resume decision.
    pub evidence: Vec<ReconciliationEvidence>,
    /// Upper bound on the successor step sequence.
    pub max_step_sequence: i64,
    /// Remaining budget the resume may consume.
    pub remaining_cost_micro_usd: i64,
}
impl std::ops::Deref for ResumeReconciledAttemptCommand {
    type Target = CommandEnvelope;
    fn deref(&self) -> &CommandEnvelope {
        &self.envelope
    }
}
impl std::ops::DerefMut for ResumeReconciledAttemptCommand {
    fn deref_mut(&mut self) -> &mut CommandEnvelope {
        &mut self.envelope
    }
}

/// `evaluateResumeReconciledAttempt` — fails the old step+attempt
/// (disposition resume), inserts a new running step (sequence+1) with a
/// new prepared attempt whose predecessor is the old one, and moves the
/// task/run back to running. It grants no lease: it only asserts that
/// none is active.
pub(crate) fn evaluate_resume_reconciled_attempt(
    cmd: &ResumeReconciledAttemptCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    domain::validate_evaluation(
        &cmd.envelope,
        meta,
        Capability::WorkspaceOperator,
        true,
        false,
    )?;
    let evidence = domain::clone_and_validate_evidence(&cmd.evidence)?;
    if cmd.max_step_sequence < 1 {
        return Err(failure(FailureKind::Invalid, "INVALID_RESUME_LIMIT"));
    }
    if cmd.new_step_id.is_nil()
        || cmd.new_attempt_id.is_nil()
        || cmd.new_logical_operation.is_nil()
        || cmd.physical_attempt_id.is_nil()
        || cmd.new_step_id == cmd.step_id
        || cmd.new_attempt_id == cmd.attempt_id
        || cmd.new_logical_operation == cmd.logical_operation
    {
        return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
    }
    if !cmd.state.tool_calls.is_empty() || !cmd.state.tool_attempts.is_empty() {
        return Err(failure(FailureKind::Denied, "RESUME_TOOL_CALLS_PRESENT"));
    }
    let step_src = cmd
        .state
        .step
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let attempt_src = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if step_src.sequence + 1 > cmd.max_step_sequence {
        return Err(failure(FailureKind::Denied, "RESUME_ATTEMPT_LIMIT_REACHED"));
    }
    if cmd.remaining_cost_micro_usd < MIN_RESUME_COST_MICRO_USD {
        return Err(failure(FailureKind::Denied, "RESUME_BUDGET_EXHAUSTED"));
    }
    let mut attempt = domain::resolve_attempt_reconciliation(
        attempt_src.clone(),
        ReconciliationDisposition::ReconciliationResume,
    )?;
    attempt.updated_at = meta.now;
    let mut step = domain::resolve_step_reconciliation(
        step_src.clone(),
        ReconciliationDisposition::ReconciliationResume,
    )?;
    step.updated_at = meta.now;
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::ResumeReconciled(execution_facade::ExecutionResumeReconciledRequest {
            aggregate: cmd.state.task.clone(),
            now: meta.now,
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    // Resume is a no-lease command: it asserts lease absence and must
    // not mint or fence a credential.
    let assertion = domain::no_active_lease_assertion(&cmd.envelope, meta.now)?;
    let new_step = Step {
        id: cmd.new_step_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        version: 1,
        sequence: step_src.sequence + 1,
        state: StepState::StepRunning,
        created_at: meta.now,
        updated_at: meta.now,
    };
    let new_attempt = StepAttempt {
        id: cmd.new_attempt_id,
        step_id: new_step.id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        logical_operation_id: cmd.new_logical_operation,
        physical_attempt_id: cmd.physical_attempt_id,
        invocation_id: InvocationId::default(),
        predecessor_id: attempt_src.id,
        version: 1,
        sequence: 1,
        state: AttemptState::AttemptPrepared,
        created_at: meta.now,
        updated_at: meta.now,
    };
    // The old rows come first: the store updates them before it inserts
    // the new ones (the one-active-run index is not deferrable).
    let change = ExecutionChangeSet {
        steps: vec![step, new_step],
        attempts: vec![attempt, new_attempt],
        reconciliations: vec![domain::Reconciliation {
            workspace_id: cmd.workspace_id,
            task_id: cmd.task_id,
            run_id: cmd.run_id,
            step_id: cmd.step_id,
            attempt_id: cmd.attempt_id,
            disposition: ReconciliationDisposition::ReconciliationResume,
            evidence,
            resolved_at: meta.now,
        }],
        lease_assertions: vec![assertion],
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    domain::with_evidence(
        &cmd.envelope,
        meta,
        change,
        EVENT_ATTEMPT_RESUMED,
        OUTBOX_ATTEMPT_SETTLED,
        AttemptState::AttemptFailed.as_str(),
        "resume",
    )
}

// ---------------------------------------------------------------------------
// Recovery-epoch coordinator commands + resume-epoch evaluator.
// ---------------------------------------------------------------------------

/// `ResumeRecoveryEpochCommand` — the operator resume that moves a
/// degraded epoch back to running under a new coordinator fence.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeRecoveryEpochCommand {
    /// Recovery-coordinator scope (principal + capabilities).
    pub scope: TrustedScope,
    /// The epoch being resumed.
    pub epoch_generation: i64,
    /// The new fence the resuming coordinator will hold.
    pub coordinator_fence: RecoveryCoordinatorFence,
    /// Optimistic guards on the durable epoch row.
    pub expected_state: RecoveryEpochState,
    /// Optimistic guards on the durable epoch row.
    pub expected_cursor: WorkspaceId,
    /// Optimistic guards on the durable epoch row.
    pub expected_retry_attempt: i64,
    /// Bounded operator acknowledgement; required and ≤512 bytes.
    pub acknowledgement_reason: String,
    /// Idempotency binding.
    pub idempotency_key: String,
    /// Required capability (recovery coordinator).
    pub capability: Capability,
    /// Canonical request fingerprint — see
    /// [`recovery_resume_fingerprint`].
    pub fingerprint: RequestFingerprint,
}

/// `recoveryResumeFingerprint` — binds an acknowledgement to the exact
/// durable epoch facts it may reopen. Any actor, capability, fence,
/// cursor, state, retry, or reason change creates a distinct command.
#[must_use]
pub fn recovery_resume_fingerprint(cmd: &ResumeRecoveryEpochCommand) -> RequestFingerprint {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        principal_id: &'a str,
        workspace_id: &'a str,
        capability: &'a str,
        epoch_generation: i64,
        coordinator_fence: i64,
        expected_state: &'a str,
        expected_cursor: &'a str,
        expected_retry: i64,
        acknowledgement: &'a str,
    }
    let workspace_text = cmd.scope.workspace_id.to_string();
    let cursor_text = cmd.expected_cursor.to_string();
    let acknowledgement = cmd.acknowledgement_reason.trim().to_string();
    let body = Body {
        principal_id: &cmd.scope.principal_id,
        workspace_id: &workspace_text,
        capability: cmd.capability.as_str(),
        epoch_generation: cmd.epoch_generation,
        coordinator_fence: cmd.coordinator_fence.generation,
        expected_state: cmd.expected_state.as_str(),
        expected_cursor: &cursor_text,
        expected_retry: cmd.expected_retry_attempt,
        acknowledgement: &acknowledgement,
    };
    let payload = serde_json::to_vec(&body).unwrap_or_default();
    let sum = sha2::Sha256::digest(domain::go_json_escapes(&payload));
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&sum);
    fp
}

impl ResumeRecoveryEpochCommand {
    /// `ResumeRecoveryEpochCommand.Validate` — the scope-shape and
    /// request-fact checks that run before any store mutation.
    pub fn validate(&self) -> Result<(), Failure> {
        if !self.scope.allows(Capability::WorkspaceOperator)
            || !self.scope.allows(Capability::RecoveryCoordinator)
            || self.scope.allows(Capability::Executor)
            || self.scope.allows(Capability::Approver)
            || self.capability != Capability::RecoveryCoordinator
        {
            return Err(failure(FailureKind::Denied, "RECOVERY_RESUME_DENIED"));
        }
        if self.epoch_generation <= 0
            || !self.coordinator_fence.valid()
            || !matches!(
                self.expected_state,
                RecoveryEpochState::RecoveryEpochDegraded | RecoveryEpochState::RecoveryEpochFailed
            )
            || self.expected_retry_attempt < 0
            || self.acknowledgement_reason.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || !domain::fingerprint_valid(&self.fingerprint)
            || self.fingerprint != recovery_resume_fingerprint(self)
        {
            return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_RESUME"));
        }
        Ok(())
    }
}

/// `EvaluateResumeRecoveryEpoch` — the domain-side half of the epoch
/// resume: validates the operator command (upstream `cmd.Validate()`)
/// then asserts the persisted epoch still matches the optimistic
/// guards; the coordinator and adapter own lease acquisition and the
/// atomic mutation. Returns the next epoch row under the new fence.
pub fn evaluate_resume_recovery_epoch(
    cmd: &ResumeRecoveryEpochCommand,
    epoch: &RecoveryEpoch,
) -> Result<RecoveryEpoch, Failure> {
    cmd.validate()?;
    if epoch.generation != cmd.epoch_generation
        || epoch.state != cmd.expected_state
        || epoch.scheduler_cursor != cmd.expected_cursor
        || epoch.retry_attempt != cmd.expected_retry_attempt
    {
        return Err(failure(FailureKind::Conflict, "RECOVERY_EPOCH_CONFLICT"));
    }
    Ok(RecoveryEpoch {
        coordinator_fence: cmd.coordinator_fence,
        state: RecoveryEpochState::RecoveryEpochRunning,
        ..epoch.clone()
    })
}

/// `EvaluateRecoveryWorkspaceComplete` — marks a claimed work row
/// completed or failed under the same fence.
pub fn evaluate_recovery_workspace_complete(
    epoch: &RecoveryEpoch,
    work: &RecoveryWorkspaceWork,
    fence: RecoveryCoordinatorFence,
    failed: bool,
    now: OffsetDateTime,
) -> Result<RecoveryWorkspaceWork, Failure> {
    if now == ZERO_TIME
        || epoch.generation <= 0
        || work.epoch_generation != epoch.generation
        || epoch.state != RecoveryEpochState::RecoveryEpochRunning
        || fence.generation <= 0
        || fence != epoch.coordinator_fence
        || work.state != RecoveryWorkspaceState::RecoveryWorkspaceClaimed
    {
        return Err(failure(FailureKind::Conflict, "RECOVERY_WORK_CONFLICT"));
    }
    let mut next = work.clone();
    next.state = if failed {
        RecoveryWorkspaceState::RecoveryWorkspaceFailed
    } else {
        RecoveryWorkspaceState::RecoveryWorkspaceCompleted
    };
    Ok(next)
}

// Re-export for command surface completeness.
pub use crate::harness_run::{
    CompletionReceipt, evaluate_recovery, evaluate_recovery_cancellation,
    evaluate_recovery_completion,
};
