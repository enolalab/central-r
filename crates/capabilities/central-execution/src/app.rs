//! Application service — the orchestration port of
//! `central/internal/execution/app/service.go` (+ `recovery.go`).
//!
//! Every command flows through the same pipeline:
//!   1. metadata validation;
//!   2. receipt lookup (a hit replays the durable result — no state
//!      read, no commit, no new lease credential);
//!   3. authoritative state read — a failure aborts before evaluation;
//!   4. domain evaluation against the loaded snapshot;
//!   5. one composite commit carrying the task transition with the
//!      execution rows.
//!
//! The service never duplicates task lifecycle rules — the evaluators
//! already routed them through `central_task::execution_facade`.

use central_foundation::failure::{Failure, FailureKind};
use central_task::domain as task;

use crate::domain::{
    self, ApprovalAction, Capability, Command, CommandEnvelope, EvaluationMetadata,
    ExpectedVersions, ReconciliationActionDescriptor, TrustedScope,
    describe_reconciliation_actions, fingerprint_valid,
};
use crate::harness_run::CompletionReceipt;
use crate::port::{
    B09EvidenceStore, Clock, CommitRequest, CompositeExecutionStore, DurableResult,
    ExecutionReadRequest, LeaseCredentialValidator, LeaseValidationRequest, ReceiptBinding,
    ReceiptLookupRequest, RecoveryStore,
};
use crate::resume::{
    self, RecoveryCoordinatorFence, RecoveryEpoch, RecoveryWorkspaceWork,
    ResumeRecoveryEpochCommand, evaluate_resume_recovery_epoch,
};

fn failure(kind: FailureKind, reason: &'static str) -> Failure {
    Failure::new(kind, reason, "execution service refused")
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

    /// `execute` — the shared pipeline every command runs.
    ///
    /// Metadata is caller-supplied *except* `now`, which the service
    /// always stamps from its clock (callers never set time).
    pub async fn execute(
        &self,
        mut command: Command,
        mut meta: EvaluationMetadata,
    ) -> Result<DurableResult, Failure> {
        meta.now = self.clock.now();
        let scope = Self::command_scope_of(&command);
        // 1. metadata validation (capability binding, fingerprint,
        //    idempotency key, evidence ids — mirrors the upstream gate).
        let envelope = Self::envelope_of(&command);
        if meta.principal_id.trim().is_empty()
            || meta.principal_id != envelope.scope.principal_id
            || meta.idempotency_key.trim().is_empty()
            || !fingerprint_valid(&meta.fingerprint)
            || meta.event_id.is_nil()
            || meta.outbox_id.is_nil()
            || meta.producer_id.trim().is_empty()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_COMMAND_METADATA"));
        }
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
                binding: ReceiptBinding {
                    task_id: Some(envelope.task_id),
                    run_id: Some(envelope.run_id),
                    step_id: Some(envelope.step_id),
                    attempt_id: Some(envelope.attempt_id),
                    logical_operation: Some(envelope.logical_operation),
                },
                expected_versions: envelope.expected,
            })
            .await?;
        if receipt.found {
            return receipt
                .result
                .ok_or_else(|| failure(FailureKind::Internal, "RECEIPT_WITHOUT_RESULT"));
        }
        // 3. authoritative state read — abort before evaluation on any
        //    failure.
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
        Self::envelope_of_mut(&mut command).state = read.state;
        // 4. lease-credential fencing where the command presents one —
        //    fail closed when the validator is unreachable.
        let envelope = Self::envelope_of(&command);
        if envelope.lease_credential.valid() {
            let valid = self
                .lease_validator
                .validate_lease_credential(LeaseValidationRequest {
                    scope: envelope.scope.clone(),
                    workspace_id: envelope.workspace_id,
                    run_id: envelope.run_id,
                    credential: envelope.lease_credential,
                    generation: envelope.lease_generation,
                    now: meta.now,
                })
                .await
                .map_err(|_| failure(FailureKind::Unavailable, "LEASE_VALIDATION_UNAVAILABLE"))?;
            if !valid {
                return Err(failure(FailureKind::Conflict, "STALE_LEASE_FENCE"));
            }
        }
        // 5. evaluate against the loaded snapshot (the evaluator routes
        //    task transitions through the task facade).
        let change_set = domain::evaluate_command(command.clone(), &meta)?;
        let envelope = Self::envelope_of(&command);
        // 6. one composite commit — rows + task transition + events +
        //    outbox + lease + receipt, atomically.
        let result = DurableResult {
            workspace_id: envelope.workspace_id,
            task_id: envelope.task_id,
            run_id: envelope.run_id,
            step_id: envelope.step_id,
            attempt_id: envelope.attempt_id,
            event_id: meta.event_id,
            event_kind: change_set
                .events
                .first()
                .map_or_else(String::new, |e| e.kind.to_string()),
            approval_action: change_set.events.first().and(None::<ApprovalAction>),
        };
        let commit = self
            .store
            .commit(CommitRequest {
                scope: envelope.scope.clone(),
                command_scope: scope.to_string(),
                idempotency_key: meta.idempotency_key.clone(),
                fingerprint: meta.fingerprint,
                principal_id: meta.principal_id.clone(),
                capability: meta.capability,
                envelope: envelope.clone(),
                change_set,
                lease_credential: envelope.lease_credential,
                lease_generation: envelope.lease_generation,
                assert_no_active_lease: envelope.assert_no_active_lease,
                require_recovery_claimable: matches!(
                    command,
                    Command::Prepare(_) | Command::Claim(_) | Command::StartHarnessRun(_)
                ),
                result: result.clone(),
            })
            .await?;
        Ok(commit.result)
    }

    /// `DescribeReconciliationActions` — read-only descriptor an
    /// operator surface renders; performs the authoritative read then
    /// delegates to the domain.
    pub async fn reconciliation_actions(
        &self,
        request: ExecutionReadRequest,
    ) -> Result<ReconciliationActionDescriptor, Failure> {
        let read = self.store.read_execution(request.clone()).await?;
        Ok(describe_reconciliation_actions(
            &request.scope,
            &read.state,
            self.clock.now(),
        ))
    }
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
        if !receipt.b09_references.provider_turn_ids.is_empty()
            || !receipt.b09_references.filesystem_page_hashes.is_empty()
        {
            self.b09
                .commit_b09_evidence(
                    scope.clone(),
                    receipt.attempt_id,
                    receipt.b09_references.clone(),
                )
                .await?;
        }
        let envelope = CommandEnvelope {
            scope,
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
            approval_subject_version: 0,
            approval_expected_step_version: 0,
        };
        let commit = self
            .store
            .commit(CommitRequest {
                scope: envelope.scope.clone(),
                command_scope: "execution.complete_with_receipt".to_string(),
                idempotency_key: format!("completion:{}", receipt.invocation_id),
                fingerprint: domain::new_request_fingerprint(&receipt.outcome),
                principal_id: receipt.producer_id.clone(),
                capability: Capability::Executor,
                envelope,
                change_set: change,
                lease_credential: domain::LeaseCredential::default(),
                lease_generation: 0,
                assert_no_active_lease: false,
                require_recovery_claimable: false,
                result: DurableResult {
                    workspace_id: receipt.workspace_id,
                    task_id: receipt.task_id,
                    run_id: receipt.run_id,
                    step_id: receipt.step_id,
                    attempt_id: receipt.attempt_id,
                    ..DurableResult::default()
                },
            })
            .await?;
        Ok(commit.result)
    }
}

// ---------------------------------------------------------------------------
// Recovery coordinator service (upstream app/recovery.go).
// ---------------------------------------------------------------------------

/// `RecoveryCoordinator` — the fenced epoch-driving service.
pub struct RecoveryCoordinatorService<R: RecoveryStore, C: Clock> {
    store: R,
    clock: C,
}

impl<R: RecoveryStore, C: Clock> RecoveryCoordinatorService<R, C> {
    /// Builds the coordinator service.
    pub const fn new(store: R, clock: C) -> Self {
        Self { store, clock }
    }

    /// `StartEpoch` — opens a recovery epoch snapshotting the failed-run
    /// watermark.
    pub async fn start_epoch(&self, scope: TrustedScope) -> Result<RecoveryEpoch, Failure> {
        self.store
            .start_recovery_epoch(crate::port::StartRecoveryEpochRequest {
                scope,
                generation: 0,
                now: self.clock.now(),
            })
            .await
    }

    /// `Acquire` — takes or renews the coordinator fence on an epoch.
    pub async fn acquire(
        &self,
        scope: TrustedScope,
        epoch_generation: i64,
        fence_generation: i64,
    ) -> Result<crate::port::RecoveryCoordinatorLease, Failure> {
        self.store
            .acquire_recovery_coordinator(crate::port::RecoveryCoordinatorAcquireRequest {
                scope,
                epoch_generation,
                fence_generation,
                now: self.clock.now(),
                ttl: domain::DEFAULT_LEASE_DURATION,
            })
            .await
    }

    /// `ClaimWorkspaces` — claims pending per-workspace rows under the
    /// held fence.
    pub async fn claim_workspaces(
        &self,
        scope: TrustedScope,
        epoch: &RecoveryEpoch,
        limit: u32,
    ) -> Result<Vec<RecoveryWorkspaceWork>, Failure> {
        let claims = self
            .store
            .claim_recovery_workspaces(crate::port::ClaimRecoveryWorkspaceRequest {
                scope,
                epoch_generation: epoch.generation,
                fence_generation: epoch.coordinator_fence.generation,
                now: self.clock.now(),
                limit,
            })
            .await?;
        let mut out = Vec::with_capacity(claims.len());
        for claim in claims {
            out.push(resume::evaluate_recovery_workspace_claim(
                &claim.epoch,
                &claim.work,
                claim.epoch.coordinator_fence,
                self.clock.now(),
            )?);
        }
        Ok(out)
    }

    /// `CompleteWorkspace` — closes a claimed work row under the fence.
    pub async fn complete_workspace(
        &self,
        scope: TrustedScope,
        epoch: &RecoveryEpoch,
        work: &RecoveryWorkspaceWork,
        failed: bool,
    ) -> Result<(), Failure> {
        let now = self.clock.now();
        resume::evaluate_recovery_workspace_complete(
            epoch,
            work,
            epoch.coordinator_fence,
            failed,
            now,
        )?;
        self.store
            .complete_recovery_workspace(crate::port::CompleteRecoveryWorkspaceRequest {
                scope,
                epoch_generation: epoch.generation,
                fence_generation: epoch.coordinator_fence.generation,
                workspace_id: work.workspace_id,
                failed,
                now,
            })
            .await
    }

    /// `ResumeEpoch` — the operator resume path: validates the command
    /// and fingerprint *before* the store is touched, then commits the
    /// resumed epoch under the new fence.
    pub async fn resume_epoch(
        &self,
        command: ResumeRecoveryEpochCommand,
    ) -> Result<RecoveryEpoch, Failure> {
        // Fingerprint drift is rejected before any store access —
        // upstream tests pin this ordering.
        if command.fingerprint != resume::recovery_resume_fingerprint(&command) {
            return Err(failure(FailureKind::Invalid, "INVALID_RECOVERY_RESUME"));
        }
        let epoch = self
            .store
            .load_recovery_epoch(command.scope.clone(), command.epoch_generation)
            .await?;
        let next = evaluate_resume_recovery_epoch(&command, &epoch, self.clock.now())?;
        self.store
            .resume_recovery_epoch(crate::port::ResumeRecoveryEpochRequest {
                scope: command.scope.clone(),
                command,
                now: self.clock.now(),
            })
            .await?;
        Ok(next)
    }

    /// `FailedWorkspaces` — the operator-facing failed-work listing.
    pub async fn failed_workspaces(
        &self,
        scope: TrustedScope,
        epoch_generation: i64,
        cursor: &str,
        limit: u32,
    ) -> Result<crate::port::FailedRecoveryWorkspaces, Failure> {
        self.store
            .list_failed_recovery_workspaces(scope, epoch_generation, cursor, limit)
            .await
    }

    /// `ClaimArtifactWork` — claims artifact-producing recovery work
    /// for B11/B12 follow-up under the held fence.
    pub async fn claim_artifact_work(
        &self,
        scope: TrustedScope,
        epoch: &RecoveryEpoch,
        limit: u32,
    ) -> Result<Vec<crate::port::ArtifactWorkClaim>, Failure> {
        self.store
            .claim_artifact_work(
                scope,
                epoch.generation,
                epoch.coordinator_fence.generation,
                self.clock.now(),
                limit,
            )
            .await
    }
}

/// Alias used by signatures that want the coordinator fence type
/// without importing `resume` directly.
pub type CoordinatorFence = RecoveryCoordinatorFence;

#[allow(unused_imports)]
use task::TaskStatus as _;
