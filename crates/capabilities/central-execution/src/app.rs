//! Application service — the orchestration port of
//! `central/internal/execution/app/service.go` (+ `recovery.go`).
//!
//! Every command flows through the same pipeline:
//!   1. trusted-command validation (capability binding, fingerprint,
//!      idempotency key, scope);
//!   2. receipt lookup (a hit replays the durable result — no state
//!      read, no commit, no new lease credential);
//!   3. authoritative state read — a failure aborts before evaluation;
//!   4. domain evaluation against the loaded snapshot;
//!   5. one composite commit carrying the task transition with the
//!      execution rows, fenced by the *evaluator-proven* lease facts.
//!
//! The service never duplicates task lifecycle rules — the evaluators
//! already routed them through `central_task::execution_facade`.

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::InstanceId;
use central_task::execution_facade::{self, ExecutionTransition};
use time::OffsetDateTime;

use central_foundation::identity::WorkspaceId;

use crate::domain::{
    self, ApprovalSuccessorActionDescriptor, AttemptState, Capability, Command, CommandEnvelope,
    EvaluationMetadata, ExecutionChangeSet, ExecutionState, ExpectedVersions, LeaseCredential,
    ReconciliationActionDescriptor, TrustedScope, ZERO_TIME, describe_approval_successor_action,
    describe_reconciliation_actions, fingerprint_valid,
};
use crate::harness_run::CompletionReceipt;
use crate::port::{
    B09EvidenceStore, ClaimRecoveryWorkspaceRequest, Clock, CommitRequest, CommitResult,
    CompleteRecoveryWorkspaceRequest, CompositeExecutionStore, DurableResult, ExecutionReadRequest,
    LeaseCredentialValidator, LeaseValidationRequest, ReceiptBinding, ReceiptLookupRequest,
    RecoveryCoordinatorAcquireRequest, RecoveryCoordinatorLease, RecoveryStore,
    RecoveryWorkspaceClaim, ResumeRecoveryEpochRequest, StartRecoveryEpochRequest,
};
use crate::resume::{RecoveryEpoch, RecoveryEpochState, ResumeRecoveryEpochCommand};

/// The one deployment-wide coordinator domain (upstream
/// `recoveryDomain`).
const RECOVERY_DOMAIN: &str = "central.execution.recovery.v1";
/// Coordinator batch size (upstream `batchSize: 100`).
const RECOVERY_BATCH_SIZE: u32 = 100;

fn failure(kind: FailureKind, reason: &'static str) -> Failure {
    Failure::new(kind, reason, "execution service refused")
}

/// `ApprovalSuccessorResult` pairs the durable receipt result with the
/// B11 descriptor for the newly created pending approval.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalSuccessorResult {
    pub commit: CommitResult,
    pub action: ApprovalSuccessorActionDescriptor,
}

/// `ClaimResult` returns the newly issued raw lease bearer exactly
/// once. Receipt replay retains the durable correlation but
/// deliberately returns a zero credential because plaintext lease
/// material is never persisted.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimResult {
    pub commit: CommitResult,
    pub lease_credential: LeaseCredential,
}

/// `StartHarnessRunResult` returns the newly issued raw lease bearer
/// exactly once, with the fencing generation the harness attempt uses
/// as its fence. A receipt replay returns a zero credential.
#[derive(Debug, Clone, PartialEq)]
pub struct StartHarnessRunResult {
    pub commit: CommitResult,
    pub lease_credential: LeaseCredential,
    pub lease_generation: i64,
}

/// `Service` — the command entry point. `S` is the composite store,
/// `V` the lease-credential validator (fails closed when it errors),
/// `C` the clock, `B` the optional typed B09 evidence store.
pub struct Service<S, V, C, B = ()> {
    store: S,
    lease_validator: V,
    clock: C,
    b09: B,
}

/// Marker: a service built without a B09 evidence store.
pub struct NoB09;

impl<S, V, C> Service<S, V, C, NoB09>
where
    S: CompositeExecutionStore,
    V: LeaseCredentialValidator,
    C: Clock,
{
    /// Builds a service without a B09 evidence lane.
    pub const fn new(store: S, lease_validator: V, clock: C) -> Self {
        Self {
            store,
            lease_validator,
            clock,
            b09: NoB09,
        }
    }
}

impl<S, V, C, B> Service<S, V, C, B>
where
    S: CompositeExecutionStore,
    V: LeaseCredentialValidator,
    C: Clock,
{
    fn envelope_of(command: &Command) -> &CommandEnvelope {
        match command {
            Command::Prepare(c) => &c.envelope,
            Command::Claim(c) => &c.envelope,
            Command::Heartbeat(c) => &c.envelope,
            Command::MarkInvoked(c) => &c.envelope,
            Command::ScheduleRetry(c) => &c.envelope,
            Command::EnterReconciliation(c) => &c.envelope,
            Command::SettleCancellation(c) => &c.envelope,
            Command::PrepareToolCall(c) => &c.envelope,
            Command::MarkToolCallInvoked(c) => &c.envelope,
            Command::SettleToolCall(c) => &c.envelope,
            Command::Settle(c) => &c.envelope,
            Command::Cancel(c) => &c.envelope,
            Command::RecordCheckpoint(c) => &c.envelope,
            Command::RecordApproval(c) => &c.envelope,
            Command::ResolveApproval(c) => &c.envelope,
            Command::ExpireApproval(c) => &c.envelope,
            Command::CreateApprovalSuccessor(c) => &c.envelope,
            Command::ResolveReconciliation(c) => &c.envelope,
            Command::StartHarnessRun(c) => &c.envelope,
            Command::AbandonPrepared(c) => &c.envelope,
            Command::ResumeReconciledAttempt(c) => &c.envelope,
        }
    }

    fn envelope_of_mut(command: &mut Command) -> &mut CommandEnvelope {
        match command {
            Command::Prepare(c) => &mut c.envelope,
            Command::Claim(c) => &mut c.envelope,
            Command::Heartbeat(c) => &mut c.envelope,
            Command::MarkInvoked(c) => &mut c.envelope,
            Command::ScheduleRetry(c) => &mut c.envelope,
            Command::EnterReconciliation(c) => &mut c.envelope,
            Command::SettleCancellation(c) => &mut c.envelope,
            Command::PrepareToolCall(c) => &mut c.envelope,
            Command::MarkToolCallInvoked(c) => &mut c.envelope,
            Command::SettleToolCall(c) => &mut c.envelope,
            Command::Settle(c) => &mut c.envelope,
            Command::Cancel(c) => &mut c.envelope,
            Command::RecordCheckpoint(c) => &mut c.envelope,
            Command::RecordApproval(c) => &mut c.envelope,
            Command::ResolveApproval(c) => &mut c.envelope,
            Command::ExpireApproval(c) => &mut c.envelope,
            Command::CreateApprovalSuccessor(c) => &mut c.envelope,
            Command::ResolveReconciliation(c) => &mut c.envelope,
            Command::StartHarnessRun(c) => &mut c.envelope,
            Command::AbandonPrepared(c) => &mut c.envelope,
            Command::ResumeReconciledAttempt(c) => &mut c.envelope,
        }
    }

    /// The command's durable scope (`execution.<verb>`).
    fn command_scope_of(command: &Command) -> &'static str {
        match command {
            Command::Prepare(_) => "execution.prepare",
            Command::Claim(_) => "execution.claim",
            Command::Heartbeat(_) => "execution.heartbeat",
            Command::MarkInvoked(_) => "execution.mark_invoked",
            Command::ScheduleRetry(_) => "execution.schedule_retry",
            Command::EnterReconciliation(_) => "execution.enter_reconciliation",
            Command::SettleCancellation(_) => "execution.settle_cancellation",
            Command::PrepareToolCall(_) => "execution.prepare_tool_call",
            Command::MarkToolCallInvoked(_) => "execution.mark_tool_call_invoked",
            Command::SettleToolCall(_) => "execution.settle_tool_call",
            Command::Settle(_) => "execution.settle",
            Command::Cancel(_) => "execution.cancel",
            Command::RecordCheckpoint(_) => "execution.record_checkpoint",
            Command::RecordApproval(_) => "execution.record_approval",
            Command::ResolveApproval(_) => "execution.resolve_approval",
            Command::ExpireApproval(_) => "execution.expire_approval",
            Command::CreateApprovalSuccessor(_) => "execution.create_approval_successor",
            Command::ResolveReconciliation(_) => "execution.resolve_reconciliation",
            Command::StartHarnessRun(_) => "execution.start_harness_run",
            Command::AbandonPrepared(_) => "execution.abandon_prepared",
            Command::ResumeReconciledAttempt(_) => "execution.resume_reconciled_attempt",
        }
    }

    /// The capability each command verb requires (upstream per-method
    /// `required` arguments).
    fn required_capability_of(command: &Command) -> Capability {
        match command {
            Command::Cancel(_)
            | Command::CreateApprovalSuccessor(_)
            | Command::ResolveReconciliation(_)
            | Command::ResumeReconciledAttempt(_) => Capability::WorkspaceOperator,
            Command::RecordApproval(_)
            | Command::ResolveApproval(_)
            | Command::ExpireApproval(_) => Capability::Approver,
            _ => Capability::Executor,
        }
    }

    /// `requiresRecoveryClaimAdmission` — only the lease-granting
    /// commands pass the B08 recovery-claim admission gate.
    fn requires_recovery_claim_admission(command_scope: &str) -> bool {
        command_scope == "execution.claim" || command_scope == "execution.start_harness_run"
    }

    /// `receiptBinding` — the immutable target a receipt replays.
    fn receipt_binding(envelope: &CommandEnvelope) -> ReceiptBinding {
        ReceiptBinding {
            task_id: envelope.task_id,
            run_id: envelope.run_id,
            step_id: envelope.step_id,
            attempt_id: envelope.attempt_id,
            logical_operation: envelope.logical_operation,
        }
    }

    /// `validateTrustedCommand` — rejects authority and receipt
    /// defects before pure evaluation.
    fn validate_trusted_command(
        envelope: &CommandEnvelope,
        meta: &EvaluationMetadata,
        required: Capability,
    ) -> Result<(), Failure> {
        if meta.principal_id.trim().is_empty()
            || meta.principal_id != envelope.scope.principal_id
            || meta.capability != required
            || !envelope.scope.allows(required)
            || meta.idempotency_key.trim().is_empty()
            || !fingerprint_valid(&meta.fingerprint)
            || meta.event_id.is_nil()
            || meta.outbox_id.is_nil()
            || meta.producer_id.trim().is_empty()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_COMMAND_METADATA"));
        }
        if envelope.scope.workspace_id.is_nil()
            || envelope.scope.workspace_id != envelope.workspace_id
            || envelope.workspace_id.is_nil()
        {
            return Err(failure(FailureKind::Denied, "SCOPE_MISMATCH"));
        }
        Ok(())
    }

    /// `evaluatedLeaseFence` exports an active fence only when
    /// evaluator-produced evidence proves that the command required
    /// and passed `activeFencedLease`. Caller envelope equality never
    /// confers fence provenance. A claim's proposed lease is an
    /// evaluated mutation, not an already-active fence.
    fn evaluated_lease_fence(
        envelope: &CommandEnvelope,
        state: &ExecutionState,
        change_set: &ExecutionChangeSet,
        now: OffsetDateTime,
    ) -> (LeaseCredential, i64, bool) {
        let assert_no_active_lease = change_set.lease_assertions.iter().any(|assertion| {
            assertion.workspace_id == envelope.workspace_id
                && assertion.run_id == envelope.run_id
                && assertion.no_active
        });
        if assert_no_active_lease {
            return (LeaseCredential::default(), 0, true);
        }
        let Some(lease) = &state.lease else {
            return (LeaseCredential::default(), 0, false);
        };
        if lease.workspace_id != envelope.workspace_id
            || lease.run_id != envelope.run_id
            || lease.generation <= 0
            || lease.expires_at <= now
            || !Self::evaluation_proves_active_lease(lease, change_set)
        {
            return (LeaseCredential::default(), 0, false);
        }
        (envelope.lease_credential, lease.generation, false)
    }

    /// `evaluationProvesActiveLease` recognizes only closed evaluator
    /// outputs whose domain paths call `activeFencedLease`. Lease
    /// releases additionally bind the exact verifier and generation
    /// that evaluation proved.
    fn evaluation_proves_active_lease(
        lease: &crate::domain::Lease,
        change_set: &ExecutionChangeSet,
    ) -> bool {
        for release in &change_set.lease_releases {
            if release.workspace_id == lease.workspace_id
                && release.run_id == lease.run_id
                && release.credential.valid()
                && release.generation == lease.generation
            {
                return true;
            }
        }
        if change_set.events.len() != 1 {
            return false;
        }
        matches!(
            change_set.events[0].kind,
            k if k == domain::EVENT_ATTEMPT_HEARTBEAT
                || k == domain::EVENT_ATTEMPT_INVOKED
                || k == domain::EVENT_TOOL_CALL_PREPARED
                || k == domain::EVENT_TOOL_CALL_INVOKED
                || k == domain::EVENT_TOOL_CALL_SETTLED
                || k == domain::EVENT_CHECKPOINT_RECORDED
        )
    }

    /// `durableResult` derives the receipt result only from
    /// evaluator-produced immutable evidence. Callers cannot supply an
    /// arbitrary state or result.
    fn durable_result(
        scope: &TrustedScope,
        state: &ExecutionState,
        change_set: &ExecutionChangeSet,
    ) -> Result<DurableResult, Failure> {
        if change_set.events.len() != 1 || change_set.outbox.len() != 1 {
            return Err(failure(FailureKind::Invalid, "INVALID_DURABLE_RESULT"));
        }
        let event = &change_set.events[0];
        let outbox = &change_set.outbox[0];
        if event.id.is_nil()
            || event.workspace_id.is_nil()
            || event.task_id.is_nil()
            || event.run_id.is_nil()
            || event.step_id.is_nil()
            || event.attempt_id.is_nil()
            || outbox.id.is_nil()
            || outbox.workspace_id != event.workspace_id
            || outbox.event_id != event.id
        {
            return Err(failure(FailureKind::Invalid, "INVALID_DURABLE_RESULT"));
        }
        let mut result = DurableResult {
            workspace_id: event.workspace_id,
            task_id: event.task_id,
            run_id: event.run_id,
            step_id: event.step_id,
            attempt_id: event.attempt_id,
            event_id: event.id,
            event_kind: event.kind.to_string(),
            approval_action: None,
        };
        if event.kind == domain::EVENT_APPROVAL_SUCCESSOR {
            if change_set.steps.len() != 1 || change_set.approvals.len() != 1 {
                return Err(failure(FailureKind::Invalid, "INVALID_DURABLE_RESULT"));
            }
            let mut successor_state = state.clone();
            successor_state.step = Some(change_set.steps[0].clone());
            successor_state.approval = Some(change_set.approvals[0].clone());
            result.approval_action = Some(describe_approval_successor_action(
                scope,
                &successor_state,
                &change_set.steps[0],
                &change_set.approvals[0],
            ));
        }
        Ok(result)
    }

    /// `commit` — the shared pipeline every command runs (upstream
    /// `Service.commit`). Returns the full [`CommitResult`] so callers
    /// can observe receipt replays.
    async fn commit(
        &self,
        mut command: Command,
        mut meta: EvaluationMetadata,
    ) -> Result<CommitResult, Failure> {
        meta.now = self.clock.now();
        let scope = Self::command_scope_of(&command);
        // 1. trusted-command validation — authority and receipt facts,
        //    plus the command's required capability.
        let required = Self::required_capability_of(&command);
        Self::validate_trusted_command(Self::envelope_of(&command), &meta, required)?;
        let envelope = Self::envelope_of(&command);
        // 2. receipt lookup — replay short-circuits before any state
        //    read.
        let receipt = self
            .store
            .lookup_receipt(ReceiptLookupRequest {
                scope: envelope.scope.clone(),
                command_scope: scope.to_string(),
                idempotency_key: meta.idempotency_key.clone(),
                fingerprint: meta.fingerprint,
                principal_id: meta.principal_id.clone(),
                capability: meta.capability,
                binding: Self::receipt_binding(envelope),
                expected_versions: envelope.expected,
            })
            .await?;
        if receipt.found {
            return Ok(CommitResult {
                result: receipt
                    .result
                    .ok_or_else(|| failure(FailureKind::Internal, "RECEIPT_WITHOUT_RESULT"))?,
                replayed: true,
            });
        }
        // 3. authoritative state read — abort before evaluation on any
        //    failure. Caller-provided snapshots are discarded.
        let read = self
            .store
            .read_execution(ExecutionReadRequest {
                scope: envelope.scope.clone(),
                workspace_id: envelope.workspace_id,
                task_id: envelope.task_id,
                run_id: envelope.run_id,
                step_id: envelope.step_id,
                attempt_id: envelope.attempt_id,
            })
            .await?;
        Self::envelope_of_mut(&mut command).state = read.state.clone();
        // 4. evaluate against the loaded snapshot (the evaluator routes
        //    task transitions through the task facade).
        let change_set = domain::evaluate_command(command.clone(), &meta)?;
        let envelope = Self::envelope_of(&command).clone();
        let result = Self::durable_result(&envelope.scope, &read.state, &change_set)?;
        let (lease_credential, lease_generation, assert_no_active_lease) =
            Self::evaluated_lease_fence(&envelope, &read.state, &change_set, meta.now);
        // 5. one composite commit — rows + task transition + events +
        //    outbox + lease + receipt, atomically.
        self.store
            .commit(CommitRequest {
                scope: envelope.scope.clone(),
                command_scope: scope.to_string(),
                idempotency_key: meta.idempotency_key.clone(),
                fingerprint: meta.fingerprint,
                principal_id: meta.principal_id.clone(),
                capability: meta.capability,
                receipt_binding: Self::receipt_binding(&envelope),
                expected_versions: envelope.expected,
                require_recovery_claimable: Self::requires_recovery_claim_admission(scope),
                lease_credential,
                lease_generation,
                assert_no_active_lease,
                result,
                change_set,
            })
            .await
    }

    /// `execute` — the generic command entry point; shares the
    /// upstream `commit` pipeline and surfaces `CommitResult.replayed`.
    pub async fn execute(
        &self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> Result<CommitResult, Failure> {
        self.commit(command, meta).await
    }

    /// `Claim` — issues the raw lease bearer once, then runs the
    /// shared pipeline. Replay returns a zero credential.
    pub async fn claim(
        &self,
        mut command: Command,
        meta: EvaluationMetadata,
    ) -> Result<ClaimResult, Failure> {
        let credential = self.store.issue_lease_credential()?;
        Self::envelope_of_mut(&mut command).lease_credential = credential;
        let result = self.commit(command, meta).await?;
        let lease_credential = if result.replayed {
            LeaseCredential::default()
        } else {
            credential
        };
        Ok(ClaimResult {
            commit: result,
            lease_credential,
        })
    }

    /// `StartHarnessRun` — claims a queued task+run, prepares its
    /// first step+attempt, and grants the run's lease in one composite
    /// commit. Replay returns a zero credential and generation.
    pub async fn start_harness_run(
        &self,
        mut command: Command,
        meta: EvaluationMetadata,
    ) -> Result<StartHarnessRunResult, Failure> {
        let credential = self.store.issue_lease_credential()?;
        Self::envelope_of_mut(&mut command).lease_credential = credential;
        let envelope_generation = Self::envelope_of(&command).lease_generation;
        let result = self.commit(command, meta).await?;
        if result.replayed {
            return Ok(StartHarnessRunResult {
                commit: result,
                lease_credential: LeaseCredential::default(),
                lease_generation: 0,
            });
        }
        Ok(StartHarnessRunResult {
            commit: result,
            lease_credential: credential,
            lease_generation: envelope_generation,
        })
    }

    /// `CreateApprovalSuccessor` — the B11 successor lane; returns the
    /// persisted descriptor (or the replayed one) alongside the
    /// commit result.
    pub async fn create_approval_successor(
        &self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> Result<ApprovalSuccessorResult, Failure> {
        let result = self.commit(command, meta).await?;
        let action =
            result.result.approval_action.clone().ok_or_else(|| {
                failure(FailureKind::Conflict, "SUCCESSOR_DESCRIPTOR_UNAVAILABLE")
            })?;
        Ok(ApprovalSuccessorResult {
            commit: result,
            action,
        })
    }

    /// `ValidateLease` verifies a transient lease against an
    /// authoritative adapter. A durable execution projection is not
    /// sufficient to validate a bearer; if the adapter cannot perform
    /// the comparison, lease-bearing commands fail closed.
    pub async fn validate_lease(&self, req: LeaseValidationRequest) -> Result<(), Failure> {
        if req.scope.workspace_id.is_nil()
            || req.scope.workspace_id != req.workspace_id
            || req.run_id.is_nil()
            || req.step_id.is_nil()
            || req.attempt_id.is_nil()
            || !req.lease_credential.valid()
            || req.lease_generation <= 0
        {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE_VALIDATION"));
        }
        self.lease_validator
            .validate_lease(req)
            .await
            .map_err(|_| failure(FailureKind::Denied, "LEASE_VALIDATOR_UNAVAILABLE"))
    }

    /// `ReconciliationActions` reads the authoritative aggregate and
    /// returns the domain-owned B11 policy projection. It performs no
    /// mutation or receipt lookup.
    pub async fn reconciliation_actions(
        &self,
        request: ExecutionReadRequest,
    ) -> Result<ReconciliationActionDescriptor, Failure> {
        if request.scope.workspace_id.is_nil()
            || request.scope.workspace_id != request.workspace_id
            || request.task_id.is_nil()
            || request.run_id.is_nil()
        {
            return Err(failure(FailureKind::Denied, "SCOPE_MISMATCH"));
        }
        let read = self.store.read_execution(request.clone()).await?;
        Ok(describe_reconciliation_actions(
            &request.scope,
            &read.state,
            self.clock.now(),
        ))
    }

    /// `ValidateCompletionChangeSet` — the narrow B08 handoff used
    /// before a report artifact is materialized. It reloads the
    /// authoritative execution snapshot, validates the
    /// evaluator-produced set, and returns an owned copy. It never
    /// commits or mutates task/run/step/attempt state.
    pub async fn validate_completion_change_set(
        &self,
        request: crate::port::CompletionChangeSetRequest,
    ) -> Result<ExecutionChangeSet, Failure> {
        request.validate()?;
        if !request.scope.allows(Capability::Executor) {
            return Err(failure(FailureKind::Denied, "COMPLETION_VALIDATION_DENIED"));
        }
        let authoritative = self
            .store
            .read_execution(ExecutionReadRequest {
                scope: request.scope.clone(),
                workspace_id: request.workspace_id,
                task_id: request.task_id,
                run_id: request.run_id,
                step_id: request.step_id,
                attempt_id: request.attempt_id,
            })
            .await?;
        let state = &authoritative.state;
        if state.task.task.id != request.task_id
            || state.task.task.workspace_id != request.workspace_id
            || state.task.task.current_run_id != Some(request.run_id)
            || state.step.as_ref().is_none_or(|s| s.id != request.step_id)
            || state
                .attempt
                .as_ref()
                .is_none_or(|a| a.id != request.attempt_id)
        {
            return Err(failure(FailureKind::Conflict, "COMPLETION_SCOPE_MISMATCH"));
        }
        if request.change_set.settlements.len() != 1 {
            return Err(failure(
                FailureKind::Invalid,
                "COMPLETION_SETTLEMENT_REQUIRED",
            ));
        }
        let settlement = &request.change_set.settlements[0];
        if settlement.workspace_id != request.workspace_id
            || settlement.task_id != request.task_id
            || settlement.run_id != request.run_id
            || settlement.step_id != request.step_id
            || settlement.attempt_id != request.attempt_id
            || settlement.final_state != AttemptState::AttemptSucceeded
        {
            return Err(failure(FailureKind::Denied, "COMPLETION_SCOPE_MISMATCH"));
        }
        let Some(current_run) = &state.task.current_run else {
            return Err(failure(FailureKind::Conflict, "COMPLETION_RUN_UNAVAILABLE"));
        };
        // Re-derive the only legitimate transition from authoritative
        // state — a supplied transition with a wrong status would be
        // persisted verbatim downstream.
        let derived = execution_facade::evaluate_execution_transition(
            ExecutionTransition::Complete(execution_facade::ExecutionCompleteRequest {
                aggregate: state.task.clone(),
                now: self.clock.now(),
                expected_task_version: state.task.task.version,
                expected_run_version: current_run.version,
            }),
        )
        .map_err(|_| failure(FailureKind::Denied, "COMPLETION_TASK_TRANSITION_DENIED"))?;
        require_derived_task_transition(request.change_set.task_transition.as_ref(), &derived)?;
        // The completion candidate must also carry the B08 lease fence
        // it will be applied under: exactly one release naming this
        // run at the authoritative generation.
        if request.change_set.lease_releases.len() != 1 {
            return Err(failure(
                FailureKind::Invalid,
                "COMPLETION_LEASE_FENCE_REQUIRED",
            ));
        }
        let release = &request.change_set.lease_releases[0];
        if release.workspace_id != request.workspace_id || release.run_id != request.run_id {
            return Err(failure(FailureKind::Denied, "COMPLETION_SCOPE_MISMATCH"));
        }
        if state
            .lease
            .as_ref()
            .is_none_or(|l| l.generation != release.generation)
        {
            return Err(failure(FailureKind::Conflict, "STALE_LEASE_FENCE"));
        }
        domain::build_execution_change_set(request.change_set)
    }
}

/// `requireDerivedTaskTransition` refuses any supplied task transition
/// that does not match the one re-derived from authoritative state.
/// Every field the downstream commit takes from the supplied set is
/// compared; only the freshly-minted `updated_at`/`occurred_at`
/// stamps are excluded.
fn require_derived_task_transition(
    supplied: Option<&central_task::execution_facade::ExecutionTransitionResult>,
    derived: &central_task::execution_facade::ExecutionTransitionResult,
) -> Result<(), Failure> {
    let mismatch = || failure(FailureKind::Denied, "COMPLETION_TASK_TRANSITION_MISMATCH");
    let got = &supplied.ok_or_else(mismatch)?.change_set;
    let want = &derived.change_set;
    if got.expected_task_version != want.expected_task_version
        || got.task.id != want.task.id
        || got.task.workspace_id != want.task.workspace_id
        || got.task.version != want.task.version
        || got.task.status != want.task.status
        || got.task.current_run_id != want.task.current_run_id
        || got.task.last_run_index != want.task.last_run_index
        || got.task.retry_count != want.task.retry_count
        || got.task.retry_eligible_at != want.task.retry_eligible_at
        || got.task.failure_reason != want.task.failure_reason
        || got.task.waiting_reason != want.task.waiting_reason
        || got.runs.len() != want.runs.len()
        || got.run_expected_versions != want.run_expected_versions
        || got.events.len() != want.events.len()
    {
        return Err(mismatch());
    }
    for (got_run, want_run) in got.runs.iter().zip(want.runs.iter()) {
        if got_run.id != want_run.id
            || got_run.task_id != want_run.task_id
            || got_run.workspace_id != want_run.workspace_id
            || got_run.version != want_run.version
            || got_run.status != want_run.status
            || got_run.index != want_run.index
            || got_run.failure_reason != want_run.failure_reason
            || got_run.ownership_token != want_run.ownership_token
            || got_run.waiting_reason != want_run.waiting_reason
        {
            return Err(mismatch());
        }
    }
    for (got_event, want_event) in got.events.iter().zip(want.events.iter()) {
        if got_event.kind != want_event.kind
            || got_event.task_id != want_event.task_id
            || got_event.run_id != want_event.run_id
            || got_event.reason != want_event.reason
            || got_event.detail != want_event.detail
        {
            return Err(mismatch());
        }
    }
    Ok(())
}

impl<S, V, C, B> Service<S, V, C, B>
where
    S: CompositeExecutionStore,
    V: LeaseCredentialValidator,
    C: Clock,
    B: B09EvidenceStore,
{
    /// `CompleteWithReceipt` — the B10 completing pass: validates the
    /// immutable receipt, evaluates the recovery-completion change set,
    /// routes typed B09 evidence through its dedicated store, then
    /// commits once.
    pub async fn complete_with_receipt(
        &self,
        scope: TrustedScope,
        receipt: &CompletionReceipt,
        request: ExecutionReadRequest,
    ) -> Result<DurableResult, Failure>
    where
        B: B09EvidenceStore,
    {
        receipt.validate()?;
        let read = self.store.read_execution(request).await?;
        let change = crate::harness_run::evaluate_recovery_completion(
            &read.state,
            receipt,
            self.clock.now(),
        )?;
        if !receipt.b09_references.is_empty() {
            self.b09
                .commit_b09_evidence(
                    scope.clone(),
                    receipt.attempt_id,
                    receipt.b09_references.clone(),
                )
                .await?;
        }
        let envelope = CommandEnvelope {
            scope: scope.clone(),
            workspace_id: receipt.workspace_id,
            task_id: receipt.task_id,
            run_id: receipt.run_id,
            step_id: receipt.step_id,
            attempt_id: receipt.attempt_id,
            logical_operation: receipt.logical_operation_id,
            expected: ExpectedVersions::default(),
            operation_digest: domain::RequestFingerprint::default(),
            lease_credential: domain::LeaseCredential::default(),
            lease_generation: 0,
            assert_no_active_lease: false,
            state: read.state.clone(),
        };
        let result = Self::durable_result(&scope, &read.state, &change)?;
        let (lease_credential, lease_generation, assert_no_active_lease) =
            Self::evaluated_lease_fence(&envelope, &read.state, &change, self.clock.now());
        let commit = self
            .store
            .commit(CommitRequest {
                scope,
                command_scope: "execution.complete_with_receipt".to_string(),
                idempotency_key: format!("completion:{}", receipt.invocation_id),
                fingerprint: domain::new_request_fingerprint(&receipt.outcome),
                principal_id: receipt.producer_id.clone(),
                capability: Capability::Executor,
                receipt_binding: ReceiptBinding {
                    task_id: receipt.task_id,
                    run_id: receipt.run_id,
                    step_id: receipt.step_id,
                    attempt_id: receipt.attempt_id,
                    logical_operation: receipt.logical_operation_id,
                },
                expected_versions: envelope.expected,
                require_recovery_claimable: false,
                lease_credential,
                lease_generation,
                assert_no_active_lease,
                result,
                change_set: change,
            })
            .await?;
        Ok(commit.result)
    }
}

// ---------------------------------------------------------------------------
// Recovery coordinator service (upstream app/recovery.go).
// ---------------------------------------------------------------------------

/// `RecoveryCoordinator` — owns no provider or tool execution. It only
/// fences and schedules durable recovery evidence through the
/// adapter-owned transaction boundary.
pub struct RecoveryCoordinatorService<R: RecoveryStore, C: Clock> {
    store: R,
    /// Kept for parity with the upstream coordinator (the store owns
    /// database time); reserved for lease-expiry-aware scheduling.
    #[allow(dead_code)]
    clock: C,
    instance_id: InstanceId,
    batch_size: u32,
}

impl<R: RecoveryStore, C: Clock> RecoveryCoordinatorService<R, C> {
    /// Builds the coordinator service (upstream `NewRecoveryCoordinator`;
    /// `instance_id` binds every lease acquisition to this process).
    pub const fn new(store: R, clock: C, instance_id: InstanceId) -> Self {
        Self {
            store,
            clock,
            instance_id,
            batch_size: RECOVERY_BATCH_SIZE,
        }
    }

    /// `RunEpoch` takes the global fenced lease then opens (or resumes)
    /// its durable epoch. The store owns database time, repeatable-read
    /// snapshotting, and the exact persisted cursor.
    pub async fn run_epoch(&self) -> Result<RecoveryEpoch, Failure> {
        let lease = self.acquire_lease().await?;
        self.store
            .start_recovery_epoch(StartRecoveryEpochRequest {
                lease,
                batch_size: self.batch_size,
            })
            .await
    }

    /// `ClaimNext` — one workspace at a time; the persisted cursor and
    /// claim cycle are the fairness authority.
    pub async fn claim_next(
        &self,
        epoch: &RecoveryEpoch,
    ) -> Result<RecoveryWorkspaceClaim, Failure> {
        let claims = self.claim_batch(epoch, 1).await?;
        claims
            .into_iter()
            .next()
            .ok_or_else(|| failure(FailureKind::Internal, "RECOVERY_CLAIM_UNAVAILABLE"))
    }

    /// `ClaimBatch` — bounded by the coordinator's 100-row default.
    pub async fn claim_batch(
        &self,
        epoch: &RecoveryEpoch,
        batch_size: u32,
    ) -> Result<Vec<RecoveryWorkspaceClaim>, Failure> {
        let lease = self.acquire_lease().await?;
        if lease.fence.generation != epoch.coordinator_fence.generation {
            return Err(failure(FailureKind::Conflict, "STALE_RECOVERY_FENCE"));
        }
        let mut claims = self
            .store
            .claim_recovery_workspaces(ClaimRecoveryWorkspaceRequest {
                lease: lease.clone(),
                epoch_generation: epoch.generation,
                batch_size,
            })
            .await?;
        for claim in &mut claims {
            claim.coordinator_lease = lease.clone();
        }
        Ok(claims)
    }

    /// `CompleteWorkspace` — closes a claimed work row under the same
    /// lease; the 32-byte claim token binds the completion to the exact
    /// claim.
    pub async fn complete_workspace(
        &self,
        claim: &RecoveryWorkspaceClaim,
        degraded: bool,
        failure_class: &str,
        failure_reason: &str,
    ) -> Result<(), Failure> {
        let lease = &claim.coordinator_lease;
        let (epoch, work) = (&claim.epoch, &claim.work);
        if lease.fence.generation != epoch.coordinator_fence.generation
            || work.epoch_generation != epoch.generation
        {
            return Err(failure(FailureKind::Conflict, "STALE_RECOVERY_FENCE"));
        }
        if !claim.claimed || claim.claim_token.len() != domain::LEASE_CREDENTIAL_BYTES {
            return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_CLAIM"));
        }
        self.store
            .complete_recovery_workspace(CompleteRecoveryWorkspaceRequest {
                lease: lease.clone(),
                epoch_generation: epoch.generation,
                workspace_id: work.workspace_id,
                claim_token: claim.claim_token.clone(),
                degraded,
                failure_class: failure_class.trim().to_string(),
                failure_reason: failure_reason.trim().to_string(),
            })
            .await
    }

    /// `ClaimArtifactWork` derives the one B10 artifact-reconciliation
    /// work claim from the coordinator lease this instance already
    /// holds. It deliberately creates no new lease, row, or scheduler.
    pub async fn claim_artifact_work(
        &self,
        epoch: &RecoveryEpoch,
    ) -> Result<crate::port::ArtifactWorkClaim, Failure> {
        let lease = self.acquire_lease().await?;
        if lease.fence.generation != epoch.coordinator_fence.generation {
            return Err(failure(FailureKind::Conflict, "STALE_RECOVERY_FENCE"));
        }
        if lease.claim_token.len() != domain::LEASE_CREDENTIAL_BYTES {
            return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_CLAIM"));
        }
        Ok(crate::port::ArtifactWorkClaim {
            fence: lease.fence,
            epoch_generation: epoch.generation,
            claim_token: lease.claim_token,
            expires_at: lease.expires_at,
            claimed: true,
        })
    }

    /// `RenewArtifactWork` refreshes the artifact work claim for as
    /// long as the process serves: exactly one re-acquisition of the
    /// same lease.
    pub async fn renew_artifact_work(
        &self,
        claim: &crate::port::ArtifactWorkClaim,
    ) -> Result<crate::port::ArtifactWorkClaim, Failure> {
        if !claim.claimed
            || claim.claim_token.len() != domain::LEASE_CREDENTIAL_BYTES
            || claim.fence.generation <= 0
        {
            return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_CLAIM"));
        }
        self.claim_artifact_work(&RecoveryEpoch {
            generation: claim.epoch_generation,
            coordinator_fence: claim.fence,
            state: RecoveryEpochState::default(),
            scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
            workspace_count: 0,
            processed_count: 0,
            claim_cycle: 0,
            retry_attempt: 0,
            snapshot_at: ZERO_TIME,
        })
        .await
    }

    /// `ResumeEpoch` — operator-only, no implicit fallback to executor
    /// or approver authority. The store rejects a stale coordinator
    /// generation and retains the exact cursor.
    pub async fn resume_epoch(
        &self,
        command: ResumeRecoveryEpochCommand,
    ) -> Result<RecoveryEpoch, Failure> {
        command.validate()?;
        let lease = self.acquire_lease().await?;
        if command.coordinator_fence.generation != lease.fence.generation {
            return Err(failure(FailureKind::Conflict, "STALE_RECOVERY_FENCE"));
        }
        self.store
            .resume_recovery_epoch(ResumeRecoveryEpochRequest { command, lease })
            .await
    }

    /// `ListFailedRecoveryWorkspaces` — the operator's resume
    /// acknowledgement names the failed rows. Read-only: no lease, no
    /// mutation.
    pub async fn list_failed_workspaces(
        &self,
        epoch_generation: i64,
        limit: u32,
    ) -> Result<crate::port::FailedRecoveryWorkspaces, Failure> {
        self.store
            .list_failed_recovery_workspaces(epoch_generation, limit)
            .await
    }

    async fn acquire_lease(&self) -> Result<RecoveryCoordinatorLease, Failure> {
        self.store
            .acquire_recovery_coordinator(RecoveryCoordinatorAcquireRequest {
                recovery_domain: RECOVERY_DOMAIN.to_string(),
                instance_id: self.instance_id,
            })
            .await
    }
}

/// Alias used by signatures that want the coordinator fence type
/// without importing `resume` directly.
pub type CoordinatorFence = crate::resume::RecoveryCoordinatorFence;
