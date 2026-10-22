//! Harness-run transitions + B08 recovery evaluators — the pure port of
//! `central/internal/execution/harness_run.go` (and the recovery
//! evaluators that live in `domain.go` upstream but gate the same
//! invariants).

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{RunId, StepAttemptId, StepId, TaskId, WorkspaceId};
use central_task::domain as task;
use central_task::execution_facade::{self, ExecutionTransition};
use time::OffsetDateTime;

use crate::domain::{
    self, AttemptState, Capability, CommandEnvelope, EvaluationMetadata, ExecutionChangeSet,
    ExecutionState, FailureReason, InvocationId, Lease, LeaseCredential, LogicalOperationId,
    NIL_STEP_ATTEMPT_ID, PhysicalAttemptId, ProviderTurnId, ReconciliationDisposition,
    RequestFingerprint, StepAttempt, StepState, ZERO_TIME,
};
use crate::domain::{
    EVENT_ATTEMPT_ABANDONED, EVENT_ATTEMPT_CANCELLED, EVENT_ATTEMPT_RECOVERED,
    EVENT_HARNESS_RUN_STARTED, OUTBOX_ATTEMPT_CLAIMED, OUTBOX_ATTEMPT_SETTLED,
};

fn failure(kind: FailureKind, reason: &'static str) -> Failure {
    Failure::new(kind, reason, "execution evaluation refused")
}

/// `execution.start_harness_run` — fuses task claim, step+attempt
/// creation, and lease issuance in one atomic change set.
#[derive(Debug, Clone, PartialEq)]
pub struct StartHarnessRunCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub physical_attempt_id: PhysicalAttemptId,
    pub step_sequence: i64,
    pub attempt_sequence: i64,
}
impl std::ops::Deref for StartHarnessRunCommand {
    type Target = CommandEnvelope;
    fn deref(&self) -> &CommandEnvelope {
        &self.envelope
    }
}
impl std::ops::DerefMut for StartHarnessRunCommand {
    fn deref_mut(&mut self) -> &mut CommandEnvelope {
        &mut self.envelope
    }
}

/// `execution.abandon_prepared` — abandons a never-invoked prepared
/// attempt and fails the task without retry.
#[derive(Debug, Clone, PartialEq)]
pub struct AbandonPreparedCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// A known bounded failure reason (never empty).
    pub reason_code: FailureReason,
}
impl std::ops::Deref for AbandonPreparedCommand {
    type Target = CommandEnvelope;
    fn deref(&self) -> &CommandEnvelope {
        &self.envelope
    }
}
impl std::ops::DerefMut for AbandonPreparedCommand {
    fn deref_mut(&mut self) -> &mut CommandEnvelope {
        &mut self.envelope
    }
}

/// `execution.settle_cancellation` — the lease-holding executor settles
/// a requested cancellation.
#[derive(Debug, Clone, PartialEq)]
pub struct SettleCancellationCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// Executor attestation that the invoked effect stopped.
    pub executor_stopped: bool,
}
impl std::ops::Deref for SettleCancellationCommand {
    type Target = CommandEnvelope;
    fn deref(&self) -> &CommandEnvelope {
        &self.envelope
    }
}
impl std::ops::DerefMut for SettleCancellationCommand {
    fn deref_mut(&mut self) -> &mut CommandEnvelope {
        &mut self.envelope
    }
}

pub(crate) fn evaluate_start_harness_run(
    cmd: &StartHarnessRunCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    domain::validate_evaluation(&cmd.envelope, meta, Capability::Executor, false, true)?;
    if cmd.state.step.is_some() || cmd.state.attempt.is_some() {
        return Err(failure(FailureKind::Conflict, "ACTIVE_ATTEMPT_CONFLICT"));
    }
    if cmd.envelope.attempt_id.is_nil()
        || cmd.physical_attempt_id.is_nil()
        || cmd.step_sequence <= 0
        || cmd.attempt_sequence <= 0
    {
        return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
    }
    let mut next_generation = 1i64;
    if let Some(current) = &cmd.state.lease {
        if current.expires_at > meta.now {
            return Err(failure(FailureKind::Conflict, "ACTIVE_LEASE_CONFLICT"));
        }
        next_generation = current.generation + 1;
    }
    if !cmd.lease_credential.valid() || cmd.lease_generation != next_generation {
        return Err(failure(FailureKind::Conflict, "STALE_LEASE_FENCE"));
    }
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::Claim(execution_facade::ExecutionClaimRequest {
            aggregate: cmd.state.task.clone(),
            owner: meta.principal_id.clone(),
            now: meta.now,
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    let step = domain::Step {
        id: cmd.step_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        version: 1,
        sequence: cmd.step_sequence,
        state: StepState::StepRunning,
        created_at: meta.now,
        updated_at: meta.now,
    };
    let attempt = StepAttempt {
        id: cmd.attempt_id,
        step_id: cmd.step_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        logical_operation_id: cmd.logical_operation,
        physical_attempt_id: cmd.physical_attempt_id,
        invocation_id: InvocationId::default(),
        predecessor_id: NIL_STEP_ATTEMPT_ID,
        version: 1,
        sequence: cmd.attempt_sequence,
        state: AttemptState::AttemptPrepared,
        created_at: meta.now,
        updated_at: meta.now,
    };
    let lease = Lease {
        workspace_id: cmd.workspace_id,
        run_id: cmd.run_id,
        credential: cmd.lease_credential,
        generation: cmd.lease_generation,
        expires_at: meta.now + domain::DEFAULT_LEASE_DURATION,
        updated_at: meta.now,
    };
    domain::with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            steps: vec![step],
            attempts: vec![attempt],
            leases: vec![lease],
            task_transition: Some(task_transition),
            ..ExecutionChangeSet::default()
        },
        EVENT_HARNESS_RUN_STARTED,
        OUTBOX_ATTEMPT_CLAIMED,
        AttemptState::AttemptPrepared.as_str(),
        "",
    )
}

pub(crate) fn evaluate_abandon_prepared(
    cmd: &AbandonPreparedCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    domain::validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    if cmd.reason_code.is_empty() || !failure_reason_known(cmd.reason_code) {
        return Err(failure(FailureKind::Invalid, "INVALID_FAILURE_REASON"));
    }
    let lease = domain::active_fenced_lease(&cmd.envelope, meta.now)?;
    let attempt = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if attempt.state != AttemptState::AttemptPrepared {
        if matches!(
            attempt.state,
            AttemptState::AttemptInvoked
                | AttemptState::AttemptSettling
                | AttemptState::AttemptReconciliation
        ) {
            return Err(failure(FailureKind::Denied, "RECONCILIATION_REQUIRED"));
        }
        return Err(failure(FailureKind::Denied, "IMMUTABLE_ATTEMPT"));
    }
    let mut attempt = domain::transition_attempt(attempt, AttemptState::AttemptCancelled)?;
    attempt.updated_at = meta.now;
    let mut step = domain::transition_step_to(
        cmd.state
            .step
            .clone()
            .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
        StepState::StepCancelled,
    )?;
    step.updated_at = meta.now;
    let (tool_calls, tool_attempts) = domain::terminalize_tool_hierarchy(
        &cmd.state.tool_calls,
        &cmd.state.tool_attempts,
        AttemptState::AttemptCancelled,
        meta.now,
    )?;
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::Fail(execution_facade::ExecutionFailRequest {
            aggregate: cmd.state.task.clone(),
            reason: cmd.reason_code.to_string(),
            now: meta.now,
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    domain::with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            steps: vec![step],
            attempts: vec![attempt],
            tool_calls,
            tool_attempts,
            lease_releases: vec![domain::release_for(&lease)],
            task_transition: Some(task_transition),
            ..ExecutionChangeSet::default()
        },
        EVENT_ATTEMPT_ABANDONED,
        OUTBOX_ATTEMPT_SETTLED,
        AttemptState::AttemptCancelled.as_str(),
        cmd.reason_code,
    )
}

pub(crate) fn evaluate_settle_cancellation(
    cmd: &SettleCancellationCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    domain::validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    if cmd.state.task.task.status != task::TaskStatus::Cancelling {
        return Err(failure(FailureKind::Denied, "CANCELLATION_NOT_REQUESTED"));
    }
    let attempt = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut attempt = match attempt.state {
        AttemptState::AttemptPrepared => {
            domain::transition_attempt(attempt, AttemptState::AttemptCancelled)?
        }
        AttemptState::AttemptInvoked | AttemptState::AttemptSettling => {
            if !cmd.executor_stopped || cmd.state.lease.is_none() {
                return Err(failure(FailureKind::Denied, "RECONCILIATION_REQUIRED"));
            }
            let reconciled =
                domain::transition_attempt(attempt, AttemptState::AttemptReconciliation)?;
            domain::resolve_attempt_reconciliation(
                reconciled,
                ReconciliationDisposition::ReconciliationCancel,
            )?
        }
        _ => {
            return Err(failure(
                FailureKind::Conflict,
                "CANCELLATION_NOT_SETTLEABLE",
            ));
        }
    };
    let mut step = domain::transition_step_to(
        cmd.state
            .step
            .clone()
            .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
        StepState::StepCancelled,
    )?;
    let (tool_calls, tool_attempts) = domain::terminalize_tool_hierarchy(
        &cmd.state.tool_calls,
        &cmd.state.tool_attempts,
        AttemptState::AttemptCancelled,
        meta.now,
    )?;
    let task_transition =
        domain::cancellation_task_transition(cmd.state.task.clone(), cmd.expected, meta.now)?;
    attempt.updated_at = meta.now;
    step.updated_at = meta.now;
    let mut change = ExecutionChangeSet {
        steps: vec![step.clone()],
        attempts: vec![attempt.clone()],
        tool_calls,
        tool_attempts,
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    if cmd.state.lease.is_some() {
        let lease = domain::active_fenced_lease(&cmd.envelope, meta.now)?;
        change.lease_releases = vec![domain::release_for(&lease)];
    } else {
        change.lease_assertions = vec![domain::no_active_lease_assertion(&cmd.envelope, meta.now)?];
    }
    let reason = if cmd
        .state
        .attempt
        .as_ref()
        .is_some_and(|a| a.state == AttemptState::AttemptPrepared)
    {
        "executor_cancellation"
    } else {
        "executor_stopped_cancellation"
    };
    domain::with_evidence(
        &cmd.envelope,
        meta,
        change,
        EVENT_ATTEMPT_CANCELLED,
        OUTBOX_ATTEMPT_SETTLED,
        AttemptState::AttemptCancelled.as_str(),
        reason,
    )
}

// ---------------------------------------------------------------------------
// Bounded failure-reason vocabulary (upstream FailureReason).
// ---------------------------------------------------------------------------

/// The closed `FailureReason` vocabulary — a `&'static str` newtype
/// alias for ergonomic command fields; `""` is the absent marker.
pub const FAILURE_REASON_EXECUTION_FAILED: &str = "execution_failed";
pub const FAILURE_REASON_HARNESS_NOT_AUTHENTICATED: &str = "harness_not_authenticated";
pub const FAILURE_REASON_HARNESS_API_ERROR: &str = "harness_api_error";
pub const FAILURE_REASON_HARNESS_ABORTED: &str = "harness_aborted";
pub const FAILURE_REASON_HARNESS_EXITED_WITHOUT_RESULT: &str = "harness_exited_without_result";
pub const FAILURE_REASON_HARNESS_SESSION_MISMATCH: &str = "harness_session_mismatch";
pub const FAILURE_REASON_HARNESS_PROTOCOL_ERROR: &str = "harness_protocol_error";
pub const FAILURE_REASON_HARNESS_MAX_TURNS: &str = "harness_max_turns";
pub const FAILURE_REASON_HARNESS_BUDGET: &str = "harness_budget";
pub const FAILURE_REASON_HARNESS_POLICY_MISMATCH: &str = "harness_policy_mismatch";
pub const FAILURE_REASON_HARNESS_UNTRUSTED_PROJECT_CONFIG: &str =
    "harness_untrusted_project_config";
pub const FAILURE_REASON_WORKSPACE_UNAVAILABLE: &str = "workspace_unavailable";
pub const FAILURE_REASON_HARNESS_LAUNCH_FAILED: &str = "harness_launch_failed";
pub const FAILURE_REASON_HARNESS_LEASE_LOST: &str = "harness_lease_lost";
pub const FAILURE_REASON_OPERATOR_RESOLVED: &str = "operator_resolved";
pub const FAILURE_REASON_ARTIFACT_CAPTURE_FAILED: &str = "artifact_capture_failed";
pub const FAILURE_REASON_ARTIFACT_REJECTED: &str = "artifact_rejected";
pub const FAILURE_REASON_ARTIFACT_TOO_LARGE: &str = "artifact_too_large";
pub const FAILURE_REASON_ARTIFACT_QUOTA_EXCEEDED: &str = "artifact_quota_exceeded";
pub const FAILURE_REASON_HARNESS_REPORT_MISSING: &str = "harness_report_missing";
pub const FAILURE_REASON_PERMISSION_BRIDGE_UNAVAILABLE: &str = "permission_bridge_unavailable";
pub const FAILURE_REASON_BUDGET_COST: &str = "budget_cost";
pub const FAILURE_REASON_BUDGET_WALL_CLOCK: &str = "budget_wall_clock";
pub const FAILURE_REASON_BUDGET_TOKENS: &str = "budget_tokens";

/// All known reasons, upstream `FailureReasons()` order.
pub const FAILURE_REASONS: &[FailureReason] = &[
    FAILURE_REASON_EXECUTION_FAILED,
    FAILURE_REASON_HARNESS_NOT_AUTHENTICATED,
    FAILURE_REASON_HARNESS_API_ERROR,
    FAILURE_REASON_HARNESS_ABORTED,
    FAILURE_REASON_HARNESS_EXITED_WITHOUT_RESULT,
    FAILURE_REASON_HARNESS_SESSION_MISMATCH,
    FAILURE_REASON_HARNESS_PROTOCOL_ERROR,
    FAILURE_REASON_HARNESS_MAX_TURNS,
    FAILURE_REASON_HARNESS_BUDGET,
    FAILURE_REASON_HARNESS_POLICY_MISMATCH,
    FAILURE_REASON_HARNESS_UNTRUSTED_PROJECT_CONFIG,
    FAILURE_REASON_WORKSPACE_UNAVAILABLE,
    FAILURE_REASON_HARNESS_LAUNCH_FAILED,
    FAILURE_REASON_HARNESS_LEASE_LOST,
    FAILURE_REASON_OPERATOR_RESOLVED,
    FAILURE_REASON_ARTIFACT_CAPTURE_FAILED,
    FAILURE_REASON_ARTIFACT_REJECTED,
    FAILURE_REASON_ARTIFACT_TOO_LARGE,
    FAILURE_REASON_ARTIFACT_QUOTA_EXCEEDED,
    FAILURE_REASON_HARNESS_REPORT_MISSING,
    FAILURE_REASON_PERMISSION_BRIDGE_UNAVAILABLE,
    FAILURE_REASON_BUDGET_COST,
    FAILURE_REASON_BUDGET_WALL_CLOCK,
    FAILURE_REASON_BUDGET_TOKENS,
];

/// `FailureReason.Known()`.
#[must_use]
pub fn failure_reason_known(reason: &str) -> bool {
    FAILURE_REASONS.contains(&reason)
}

/// `settlementFailureReason` — the reason a settlement carries.
pub(crate) fn settlement_failure_reason(
    final_state: AttemptState,
    code: FailureReason,
) -> Result<FailureReason, Failure> {
    match final_state {
        AttemptState::AttemptFailed => {
            if code.is_empty() {
                return Ok(FAILURE_REASON_EXECUTION_FAILED);
            }
            if !failure_reason_known(code) {
                return Err(failure(FailureKind::Invalid, "INVALID_FAILURE_REASON"));
            }
            Ok(code)
        }
        AttemptState::AttemptSucceeded => {
            if !code.is_empty() {
                return Err(failure(FailureKind::Invalid, "INVALID_FAILURE_REASON"));
            }
            Ok("")
        }
        _ => Err(failure(FailureKind::Invalid, "INVALID_SETTLEMENT")),
    }
}

/// `NewSettlementOutcome` — the canonical settlement outcome payload.
pub fn new_settlement_outcome(
    final_state: AttemptState,
    code: FailureReason,
) -> Result<Vec<u8>, Failure> {
    let reason = settlement_failure_reason(final_state, code)?;
    let mut map = serde_json::Map::new();
    map.insert("schema_version".to_string(), serde_json::json!(1));
    map.insert(
        "status".to_string(),
        serde_json::json!(final_state.as_str()),
    );
    if !reason.is_empty() {
        map.insert("reason_code".to_string(), serde_json::json!(reason));
    }
    Ok(domain::must_json(map))
}

// ---------------------------------------------------------------------------
// CompletionReceipt — the immutable B10 handoff record (upstream
// `CompletionReceipt`); consumed again by the artifact completion guard.
// ---------------------------------------------------------------------------

/// The immutable settlement handoff a completing pass persists first.
#[derive(Debug, Clone, PartialEq)]
pub struct CompletionReceipt {
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    pub logical_operation_id: LogicalOperationId,
    pub physical_attempt_id: PhysicalAttemptId,
    pub invocation_id: InvocationId,
    /// Always `1` — the only accepted generation.
    pub invocation_generation: i64,
    pub final_state: AttemptState,
    pub outcome: Vec<u8>,
    pub context: Vec<u8>,
    /// Bounded producer evidence references (B09 lanes only).
    pub b09_references: B09References,
    pub producer_id: String,
}

/// The allowlisted B09 evidence reference kinds a receipt may carry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct B09References {
    /// `provider_turn` evidence ids.
    pub provider_turn_ids: Vec<ProviderTurnId>,
    /// `filesystem_page` evidence hashes.
    pub filesystem_page_hashes: Vec<[u8; 32]>,
}

impl CompletionReceipt {
    /// `CompletionReceipt.Validate()`.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.task_id.is_nil()
            || self.run_id.is_nil()
            || self.step_id.is_nil()
            || self.attempt_id.is_nil()
            || self.logical_operation_id.is_nil()
            || self.physical_attempt_id.is_nil()
            || self.invocation_id.is_nil()
            || self.invocation_generation != 1
            || !matches!(
                self.final_state,
                AttemptState::AttemptSucceeded | AttemptState::AttemptFailed
            )
            || self.producer_id.trim().is_empty()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_COMPLETION_RECEIPT"));
        }
        if self.outcome.is_empty() {
            return Err(failure(FailureKind::Invalid, "INVALID_COMPLETION_RECEIPT"));
        }
        Ok(())
    }
    /// `CompletionReceipt.FailureReason()` — the bounded reason of the
    /// outcome; unknown/absent collapses to `execution_failed`.
    #[must_use]
    pub fn failure_reason(&self) -> FailureReason {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&self.outcome) else {
            return FAILURE_REASON_EXECUTION_FAILED;
        };
        let Some(reason) = value.get("reason_code").and_then(|v| v.as_str()) else {
            return FAILURE_REASON_EXECUTION_FAILED;
        };
        if failure_reason_known(reason) {
            return FAILURE_REASONS
                .iter()
                .copied()
                .find(|r| *r == reason)
                .unwrap_or(FAILURE_REASON_EXECUTION_FAILED);
        }
        FAILURE_REASON_EXECUTION_FAILED
    }
}

// ---------------------------------------------------------------------------
// Recovery evaluators (upstream EvaluateRecoveryCompletion /
// EvaluateRecoveryCancellation in domain.go — co-located here because
// they gate the harness lifecycle's recovery half).
// ---------------------------------------------------------------------------

/// `EvaluateRecoveryCompletion` — settles an interrupted attempt from an
/// immutable completion receipt only.
pub fn evaluate_recovery_completion(
    state: &ExecutionState,
    receipt: &CompletionReceipt,
    now: OffsetDateTime,
) -> Result<ExecutionChangeSet, Failure> {
    receipt.validate()?;
    if now == ZERO_TIME
        || state.step.is_none()
        || state.attempt.is_none()
        || state.task.current_run.is_none()
    {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_STATE"));
    }
    let (Some(mut step), Some(mut attempt), Some(run)) = (
        state.step.clone(),
        state.attempt.clone(),
        state.task.current_run.clone(),
    ) else {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_STATE"));
    };
    if state.task.task.workspace_id != receipt.workspace_id
        || state.task.task.id != receipt.task_id
        || run.workspace_id != receipt.workspace_id
        || run.task_id != receipt.task_id
        || run.id != receipt.run_id
        || step.workspace_id != receipt.workspace_id
        || step.task_id != receipt.task_id
        || step.run_id != receipt.run_id
        || step.id != receipt.step_id
        || attempt.workspace_id != receipt.workspace_id
        || attempt.task_id != receipt.task_id
        || attempt.run_id != receipt.run_id
        || attempt.step_id != receipt.step_id
        || attempt.id != receipt.attempt_id
        || attempt.logical_operation_id != receipt.logical_operation_id
        || attempt.physical_attempt_id != receipt.physical_attempt_id
        || attempt.invocation_id != receipt.invocation_id
        || receipt.invocation_generation != 1
    {
        return Err(failure(
            FailureKind::Conflict,
            "COMPLETION_RECEIPT_MISMATCH",
        ));
    }
    match attempt.state {
        AttemptState::AttemptInvoked => {
            attempt = domain::transition_attempt(attempt, AttemptState::AttemptSettling)?;
        }
        AttemptState::AttemptSettling => {}
        _ => {
            return Err(failure(
                FailureKind::Conflict,
                "COMPLETION_RECEIPT_MISMATCH",
            ));
        }
    }
    attempt = domain::transition_attempt(attempt, receipt.final_state)?;
    attempt.updated_at = now;
    match step.state {
        StepState::StepRunning => {
            step = domain::transition_step(step, StepState::StepSettling)?;
        }
        StepState::StepSettling => {}
        _ => {
            return Err(failure(
                FailureKind::Conflict,
                "COMPLETION_RECEIPT_MISMATCH",
            ));
        }
    }
    let step_final = if receipt.final_state == AttemptState::AttemptFailed {
        StepState::StepFailed
    } else {
        StepState::StepSucceeded
    };
    step = domain::transition_step(step, step_final)?;
    step.updated_at = now;
    let expected = domain::ExpectedVersions {
        task: state.task.task.version,
        run: run.version,
        step: state.step.as_ref().map_or(0, |s| s.version),
        attempt: state.attempt.as_ref().map_or(0, |a| a.version),
        ..domain::ExpectedVersions::default()
    };
    let task_transition = domain::settlement_task_transition(
        state.task.clone(),
        expected,
        receipt.final_state,
        receipt.failure_reason(),
        now,
    )?;
    let (tool_calls, tool_attempts) = domain::terminalize_tool_hierarchy(
        &state.tool_calls,
        &state.tool_attempts,
        receipt.final_state,
        now,
    )?;
    let change = ExecutionChangeSet {
        steps: vec![step],
        attempts: vec![attempt.clone()],
        tool_calls,
        tool_attempts,
        settlements: vec![domain::Settlement {
            workspace_id: receipt.workspace_id,
            task_id: receipt.task_id,
            run_id: receipt.run_id,
            step_id: receipt.step_id,
            attempt_id: receipt.attempt_id,
            invocation_id: receipt.invocation_id,
            final_state: receipt.final_state,
            outcome: receipt.outcome.clone(),
            context: receipt.context.clone(),
            settled_at: now,
        }],
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    domain::build_execution_change_set(change)
}

/// `EvaluateRecoveryCancellation` — settles a cancellation that beat
/// `MarkInvoked` during B08 recovery.
pub fn evaluate_recovery_cancellation(
    state: &ExecutionState,
    now: OffsetDateTime,
) -> Result<ExecutionChangeSet, Failure> {
    if now == ZERO_TIME
        || state.step.is_none()
        || state.attempt.is_none()
        || state.task.current_run.is_none()
    {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_STATE"));
    }
    let (Some(mut step), Some(mut attempt), Some(run)) = (
        state.step.clone(),
        state.attempt.clone(),
        state.task.current_run.clone(),
    ) else {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_STATE"));
    };
    if state.task.task.status != task::TaskStatus::Cancelling
        || run.status != task::RunStatus::Cancelling
    {
        return Err(failure(FailureKind::Denied, "CANCELLATION_NOT_REQUESTED"));
    }
    if state.task.task.current_run_id != Some(run.id)
        || state.task.task.workspace_id != run.workspace_id
        || state.task.task.id != run.task_id
        || step.workspace_id != run.workspace_id
        || step.task_id != run.task_id
        || step.run_id != run.id
        || attempt.workspace_id != run.workspace_id
        || attempt.task_id != run.task_id
        || attempt.run_id != run.id
        || attempt.step_id != step.id
    {
        return Err(failure(FailureKind::Conflict, "RECOVERY_SCOPE_MISMATCH"));
    }
    if attempt.state != AttemptState::AttemptPrepared {
        return Err(failure(
            FailureKind::Conflict,
            "CANCELLATION_NOT_SETTLEABLE",
        ));
    }
    if state.lease.as_ref().is_some_and(|l| l.expires_at > now) {
        return Err(failure(FailureKind::Conflict, "ACTIVE_LEASE_CONFLICT"));
    }
    attempt = domain::transition_attempt(attempt, AttemptState::AttemptCancelled)?;
    attempt.updated_at = now;
    step = domain::transition_step_to(step, StepState::StepCancelled)?;
    step.updated_at = now;
    let (tool_calls, tool_attempts) = domain::terminalize_tool_hierarchy(
        &state.tool_calls,
        &state.tool_attempts,
        AttemptState::AttemptCancelled,
        now,
    )?;
    let task_transition =
        execution_facade::evaluate_execution_transition(ExecutionTransition::SettleCancellation(
            execution_facade::ExecutionSettleCancellationRequest {
                aggregate: state.task.clone(),
                now,
                expected_task_version: state.task.task.version,
                expected_run_version: run.version,
            },
        ))
        .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    domain::build_execution_change_set(ExecutionChangeSet {
        steps: vec![step],
        attempts: vec![attempt],
        tool_calls,
        tool_attempts,
        lease_assertions: vec![domain::LeaseAssertion {
            workspace_id: run.workspace_id,
            run_id: run.id,
            no_active: true,
        }],
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    })
}

#[allow(clippy::too_many_arguments)]
/// `EvaluateRecovery` — mints the prepared successor of a prepared,
/// never-invoked attempt whose lease B08 expired. The predecessor ends
/// cancelled; the successor keeps the logical operation and bumps the
/// sequence. Requires `attempt_reconciliation` evidence kind on the
/// event; the caller persists under its own recovery fence.
pub fn evaluate_recovery(
    state: &ExecutionState,
    now: OffsetDateTime,
    successor_id: StepAttemptId,
    physical_attempt_id: PhysicalAttemptId,
    event_id: central_foundation::identity::ExecutionEventId,
    outbox_id: central_foundation::identity::OutboxId,
    producer_id: &str,
    idempotency_key: &str,
) -> Result<ExecutionChangeSet, Failure> {
    if now == ZERO_TIME
        || state.step.is_none()
        || state.attempt.is_none()
        || state.task.current_run.is_none()
    {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_STATE"));
    }
    let (Some(step), Some(attempt), Some(run)) = (
        state.step.clone(),
        state.attempt.clone(),
        state.task.current_run.clone(),
    ) else {
        return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_STATE"));
    };
    if state.task.task.current_run_id != Some(run.id)
        || state.task.task.workspace_id != run.workspace_id
        || state.task.task.id != run.task_id
        || step.workspace_id != run.workspace_id
        || step.task_id != run.task_id
        || step.run_id != run.id
        || attempt.workspace_id != run.workspace_id
        || attempt.task_id != run.task_id
        || attempt.run_id != run.id
        || attempt.step_id != step.id
    {
        return Err(failure(FailureKind::Conflict, "RECOVERY_SCOPE_MISMATCH"));
    }
    if attempt.state != AttemptState::AttemptPrepared {
        return Err(failure(FailureKind::Conflict, "RECOVERY_NOT_REQUIRED"));
    }
    if state.lease.as_ref().is_some_and(|l| l.expires_at > now) {
        return Err(failure(FailureKind::Conflict, "ACTIVE_LEASE_CONFLICT"));
    }
    if successor_id.is_nil() || physical_attempt_id.is_nil() {
        return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
    }
    let mut predecessor = attempt.clone();
    predecessor = domain::transition_attempt(predecessor, AttemptState::AttemptCancelled)?;
    predecessor.updated_at = now;
    let successor = StepAttempt {
        id: successor_id,
        step_id: step.id,
        workspace_id: run.workspace_id,
        task_id: run.task_id,
        run_id: run.id,
        logical_operation_id: attempt.logical_operation_id,
        physical_attempt_id,
        invocation_id: InvocationId::default(),
        predecessor_id: attempt.id,
        version: 1,
        sequence: attempt.sequence + 1,
        state: AttemptState::AttemptPrepared,
        created_at: now,
        updated_at: now,
    };
    let meta = EvaluationMetadata {
        principal_id: producer_id.to_string(),
        capability: Capability::RecoveryCoordinator,
        idempotency_key: idempotency_key.to_string(),
        fingerprint: RequestFingerprint::default(),
        now,
        event_id,
        outbox_id,
        producer_id: producer_id.to_string(),
    };
    let envelope = CommandEnvelope {
        scope: domain::TrustedScope {
            principal_id: producer_id.to_string(),
            workspace_id: run.workspace_id,
            capabilities: std::collections::BTreeSet::from([Capability::RecoveryCoordinator]),
        },
        workspace_id: run.workspace_id,
        task_id: run.task_id,
        run_id: run.id,
        step_id: step.id,
        attempt_id: successor.id,
        logical_operation: attempt.logical_operation_id,
        expected: domain::ExpectedVersions::default(),
        operation_digest: RequestFingerprint::default(),
        lease_credential: LeaseCredential::default(),
        lease_generation: 0,
        assert_no_active_lease: false,
        state: ExecutionState {
            task: state.task.clone(),
            step: None,
            attempt: None,
            tool_calls: Vec::new(),
            tool_attempts: Vec::new(),
            lease: None,
            approval: None,
        },
        approval_subject_version: 0,
        approval_expected_step_version: 0,
    };
    let change = ExecutionChangeSet {
        attempts: vec![predecessor, successor],
        lease_assertions: vec![domain::LeaseAssertion {
            workspace_id: run.workspace_id,
            run_id: run.id,
            no_active: true,
        }],
        ..ExecutionChangeSet::default()
    };
    domain::build_execution_change_set(domain::with_evidence(
        &envelope,
        &meta,
        change,
        EVENT_ATTEMPT_RECOVERED,
        domain::OUTBOX_ATTEMPT_RECOVERED,
        AttemptState::AttemptPrepared.as_str(),
        "recovery_successor",
    )?)
}
