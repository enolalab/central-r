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
            Self::RecoveryEpochOpen => "recovery_epoch_open",
            Self::RecoveryEpochRunning => "recovery_epoch_running",
            Self::RecoveryEpochDegraded => "recovery_epoch_degraded",
            Self::RecoveryEpochFailed => "recovery_epoch_failed",
            Self::RecoveryEpochCompleted => "recovery_epoch_completed",
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
            Self::RecoveryWorkspacePending => "recovery_workspace_pending",
            Self::RecoveryWorkspaceClaimed => "recovery_workspace_claimed",
            Self::RecoveryWorkspaceCompleted => "recovery_workspace_completed",
            Self::RecoveryWorkspaceFailed => "recovery_workspace_failed",
        }
    }
}

/// `RecoveryCoordinatorFence` — optimistic fence on the epoch row; the
/// coordinator holds generation `N` and every mutation asserts `N`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryCoordinatorFence {
    /// Fenced generation; 0 means "no coordinator".
    pub generation: i64,
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
        reason: None,
    };
    if work.epoch_generation != epoch.generation
        || epoch.state.is_terminal()
        || work.state != RecoveryWorkspaceState::RecoveryWorkspaceFailed
    {
        return claimable();
    }
    let before_watermark = run_created_at < work.watermark_created_at
        || (run_created_at == work.watermark_created_at && run_id <= work.watermark_run_id);
    if !before_watermark || reconciled_epoch_generation >= epoch.generation {
        return claimable();
    }
    Claimability {
        claimable: false,
        reason: Some("RECOVERY_QUARANTINED".to_string()),
    }
}

/// `RecoveryCompletionState` — resolves an epoch's terminal state after
/// a coordinator scan. `degraded` means the scan found work it could
/// not recover; `clean` means every work row completed.
#[must_use]
pub fn recovery_completion_state(
    current: RecoveryEpochState,
    degraded: bool,
    clean: bool,
) -> (RecoveryEpochState, bool) {
    if degraded || current == RecoveryEpochState::RecoveryEpochDegraded {
        return (RecoveryEpochState::RecoveryEpochDegraded, false);
    }
    if clean {
        return (RecoveryEpochState::RecoveryEpochCompleted, true);
    }
    (current, false)
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
    // Resume is a no-lease command: it asserts lease absence and must
    // not mint or fence a credential.
    let assertion = domain::no_active_lease_assertion(&cmd.envelope, meta.now)?;
    let attempt_src = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if attempt_src.state != AttemptState::AttemptReconciliation {
        return Err(failure(FailureKind::Denied, "RECONCILIATION_NOT_REQUIRED"));
    }
    let step_src = cmd
        .state
        .step
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if step_src.state != StepState::StepReconciliation {
        return Err(failure(FailureKind::Denied, "RECONCILIATION_NOT_REQUIRED"));
    }
    if !cmd.state.tool_calls.is_empty() || !cmd.state.tool_attempts.is_empty() {
        return Err(failure(FailureKind::Denied, "RESUME_TOOL_CALLS_PRESENT"));
    }
    if cmd.new_step_id.is_nil()
        || cmd.new_attempt_id.is_nil()
        || cmd.new_logical_operation.is_nil()
        || cmd.physical_attempt_id.is_nil()
        || cmd.new_step_id == step_src.id
        || cmd.new_attempt_id == attempt_src.id
        || cmd.new_logical_operation == attempt_src.logical_operation_id
        || cmd.physical_attempt_id == attempt_src.physical_attempt_id
    {
        return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
    }
    if cmd.max_step_sequence <= 0 {
        return Err(failure(FailureKind::Invalid, "INVALID_RESUME_LIMIT"));
    }
    if step_src.sequence + 1 > cmd.max_step_sequence {
        return Err(failure(FailureKind::Denied, "RESUME_ATTEMPT_LIMIT_REACHED"));
    }
    if cmd.remaining_cost_micro_usd < MIN_RESUME_COST_MICRO_USD {
        return Err(failure(FailureKind::Denied, "RESUME_BUDGET_EXHAUSTED"));
    }
    let evidence = domain::clone_and_validate_evidence(&cmd.evidence)?;
    // Close the reconciled pair.
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
    // Mint the successor pair.
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
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::ResumeReconciled(execution_facade::ExecutionResumeReconciledRequest {
            aggregate: cmd.state.task.clone(),
            now: meta.now,
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    let change = ExecutionChangeSet {
        steps: vec![step, new_step],
        attempts: vec![attempt, new_attempt],
        reconciliations: vec![domain::Reconciliation {
            workspace_id: cmd.workspace_id,
            task_id: cmd.task_id,
            run_id: cmd.run_id,
            step_id: cmd.step_id,
            attempt_id: cmd.attempt_id,
            tool_call_id: domain::NIL_TOOL_CALL_ID,
            tool_attempt_id: domain::NIL_TOOL_CALL_ATTEMPT_ID,
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
        AttemptState::AttemptPrepared.as_str(),
        "resume_reconciled_attempt",
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

/// `recoveryResumeFingerprint` — sha256 over the canonical resume
/// request; the coordinator must reproduce it byte-exactly.
#[must_use]
pub fn recovery_resume_fingerprint(cmd: &ResumeRecoveryEpochCommand) -> RequestFingerprint {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        workspace_id: &'a str,
        epoch_generation: i64,
        coordinator_fence_generation: i64,
        expected_state: &'a str,
        expected_cursor: &'a str,
        expected_retry_attempt: i64,
        acknowledgement_reason: &'a str,
        idempotency_key: &'a str,
        capability: &'a str,
        principal_id: &'a str,
    }
    let workspace_text = cmd.scope.workspace_id.to_string();
    let cursor_text = cmd.expected_cursor.to_string();
    let body = Body {
        workspace_id: &workspace_text,
        epoch_generation: cmd.epoch_generation,
        coordinator_fence_generation: cmd.coordinator_fence.generation,
        expected_state: cmd.expected_state.as_str(),
        expected_cursor: &cursor_text,
        expected_retry_attempt: cmd.expected_retry_attempt,
        acknowledgement_reason: &cmd.acknowledgement_reason,
        idempotency_key: &cmd.idempotency_key,
        capability: cmd.capability.as_str(),
        principal_id: &cmd.scope.principal_id,
    };
    let payload = serde_json::to_vec(&body).unwrap_or_default();
    let sum = sha2::Sha256::digest(domain::go_json_escapes(&payload));
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&sum);
    fp
}

/// `EvaluateResumeRecoveryEpoch` — validates the operator resume and
/// returns the next epoch row (open → running under the new fence).
/// A degraded epoch never silently completes; the coordinator must
/// re-scan remaining work.
pub fn evaluate_resume_recovery_epoch(
    cmd: &ResumeRecoveryEpochCommand,
    epoch: &RecoveryEpoch,
    now: OffsetDateTime,
) -> Result<RecoveryEpoch, Failure> {
    if now == ZERO_TIME
        || cmd.epoch_generation <= 0
        || epoch.generation != cmd.epoch_generation
        || cmd.coordinator_fence.generation <= 0
        || cmd.coordinator_fence.generation == epoch.coordinator_fence.generation
        || cmd.idempotency_key.trim().is_empty()
        || !domain::fingerprint_valid(&cmd.fingerprint)
        || cmd.fingerprint != recovery_resume_fingerprint(cmd)
        || cmd.capability != Capability::RecoveryCoordinator
        || !cmd.scope.allows(Capability::RecoveryCoordinator)
        || cmd.scope.principal_id.trim().is_empty()
        || cmd.acknowledgement_reason.trim().is_empty()
        || cmd.acknowledgement_reason.len() > 512
    {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_RESUME"));
    }
    if !matches!(
        epoch.state,
        RecoveryEpochState::RecoveryEpochDegraded | RecoveryEpochState::RecoveryEpochFailed
    ) || epoch.state != cmd.expected_state
        || epoch.scheduler_cursor != cmd.expected_cursor
        || epoch.retry_attempt != cmd.expected_retry_attempt
    {
        return Err(failure(FailureKind::Conflict, "RECOVERY_EPOCH_CONFLICT"));
    }
    Ok(RecoveryEpoch {
        generation: epoch.generation,
        coordinator_fence: cmd.coordinator_fence,
        state: RecoveryEpochState::RecoveryEpochRunning,
        scheduler_cursor: epoch.scheduler_cursor,
        retry_attempt: epoch.retry_attempt,
        snapshot_at: epoch.snapshot_at,
    })
}

/// `EvaluateRecoveryWorkspaceClaim` — the coordinator claims one
/// workspace row inside the epoch under its fence.
pub fn evaluate_recovery_workspace_claim(
    epoch: &RecoveryEpoch,
    work: &RecoveryWorkspaceWork,
    fence: RecoveryCoordinatorFence,
    now: OffsetDateTime,
) -> Result<RecoveryWorkspaceWork, Failure> {
    if now == ZERO_TIME
        || epoch.generation <= 0
        || work.epoch_generation != epoch.generation
        || epoch.state != RecoveryEpochState::RecoveryEpochRunning
        || fence.generation <= 0
        || fence != epoch.coordinator_fence
        || work.state != RecoveryWorkspaceState::RecoveryWorkspacePending
    {
        return Err(failure(FailureKind::Conflict, "RECOVERY_WORK_CONFLICT"));
    }
    let mut next = work.clone();
    next.state = RecoveryWorkspaceState::RecoveryWorkspaceClaimed;
    Ok(next)
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
