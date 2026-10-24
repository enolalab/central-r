//! `ServeHarnessOperator` — the kernel's port of upstream
//! `cmd/central`'s `harnessOperator` (the parts of
//! `harness_composition.go` from `operatorPrincipal` on, plus
//! `harness_resume.go`, `harness_rerun.go`, `harness_retry_gate.go`
//! and `harness_task_cost.go`).
//!
//! The type implements the transport surface
//! [`central_transport_http::web::harness::HarnessOperator`]: the `/app`
//! banner and page predicates, the operator-resolved reconciliation
//! exits ("Mark failed", "Mark cancelled", "Finish cancelling",
//! "Resume", "Mark failed and rerun"), and the permission decision
//! service.
//!
//! Every mutation re-reads authoritative execution state under the
//! operator authority derived from the validated session
//! (`operator-session:<principal>`,
//! [`Capability::WorkspaceOperator`]), carries the caller's
//! `expected_run_version` as the stale-page guard, asserts no active
//! lease, and commits through the execution command pipeline under a
//! per-attempt idempotency key — exactly like upstream. The harness
//! attempt-row writes are best-effort mirrors: after the execution
//! side commits durably, a lost row write is completed by the next
//! start's reconciler (harness phase 3a/3e/3g/3k decisions).

use std::sync::Arc;

use central_execution::app as exec_app;
use central_execution::domain as exec;
use central_execution::domain::{
    Capability, Command, CommandEnvelope, EvaluationMetadata, ExecutionState, ExpectedVersions,
    ReconciliationDisposition, ReconciliationEvidence, ReconciliationEvidenceKind, TrustedScope,
};
use central_execution::port::{
    CommitResult, ExecutionRead, ExecutionReadRequest, ExecutionReadResult,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, StepAttemptId, StepId, TaskId,
    WorkspaceId,
};
use central_harness::app::bridge::PendingRequest;
use central_harness::app::dispatcher;
use central_harness::app::ports::Clock;
use central_harness::app::reconciler::Resolver;
use central_harness::approval::{self, ApprovalState, InputMac, PermissionApproval};
use central_harness::attempt::Attempt;
use central_harness::budget::ChainCost;
use central_harness::domain::State;
use central_harness::domain::codes as hcodes;
use central_harness::port::PortFuture;
use central_harness::port::{
    ApprovalStore, AttemptStore, DecidePermissionRequest, PendingApprovalSummary,
};
use central_harness::query::{AttemptSummaryRead, BudgetUsageRead};
use central_harness::recovery::attempt_id_for_step_attempt;
use central_task::app as task_app;
use central_task::domain as task;
use central_transport_http::ports::{self, BoxFuture};
use central_transport_http::web::harness::{
    ERR_HARNESS_NOT_RESOLVABLE, ERR_HARNESS_PERMISSION_NOT_PENDING, ERR_HARNESS_STARTING,
    HarnessBanner, HarnessBudgetDefaults, HarnessOperator, HarnessPermissionDecision,
    HarnessPermissionPanel, HarnessPermissionRecord, HarnessResolveRequest, HarnessResumeBlock,
    HarnessResumeState, HarnessRetryState, HarnessRunBudget,
};
use time::OffsetDateTime;

use crate::serve_lifecycle::task_eligible;

// ---------------------------------------------------------------------------
// Sentinel failures — upstream's web.ErrHarness* as typed codes.
// ---------------------------------------------------------------------------

fn not_resolvable() -> Failure {
    Failure::conflict(
        ERR_HARNESS_NOT_RESOLVABLE,
        "the task no longer waits on the operator",
    )
}

fn starting() -> Failure {
    Failure::conflict(ERR_HARNESS_STARTING, "the harness is still starting")
}

fn permission_not_pending() -> Failure {
    Failure::conflict(
        ERR_HARNESS_PERMISSION_NOT_PENDING,
        "the permission request is no longer pending",
    )
}

/// `operatorPrincipal` — the operator authority derived from a
/// validated web session (harness phase 3a decision 15).
fn operator_principal(session_principal: &str) -> String {
    format!("operator-session:{session_principal}")
}

// ---------------------------------------------------------------------------
// The narrow composed surfaces — upstream's interface fields.
// ---------------------------------------------------------------------------

/// `harnessOperatorReads` — the execution read surface of the resolve
/// action; `central_adapter_postgres::execution::Store` implements it.
/// A workspace-scoped read needs no capability; the store checks the
/// workspace scope only.
pub trait HarnessOperatorReads: Send + Sync + 'static {
    /// `executionport.ExecutionRead.ReadExecution`.
    fn read_execution<'a>(
        &'a self,
        req: ExecutionReadRequest,
    ) -> PortFuture<'a, Result<ExecutionReadResult, Failure>>;

    /// `ReconciliationAttempt` — the Step and StepAttempt waiting in
    /// reconciliation, if any.
    fn reconciliation_attempt<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<(StepId, StepAttemptId)>, Failure>>;

    /// `PreparedAttempt` — the Run's never-invoked StepAttempt
    /// (harness phase 3f decision 10).
    fn prepared_attempt<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<(StepId, StepAttemptId)>, Failure>>;
}

impl HarnessOperatorReads for central_adapter_postgres::execution::Store {
    fn read_execution<'a>(
        &'a self,
        req: ExecutionReadRequest,
    ) -> PortFuture<'a, Result<ExecutionReadResult, Failure>> {
        Box::pin(async move { ExecutionRead::read_execution(self, req).await })
    }

    fn reconciliation_attempt<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<(StepId, StepAttemptId)>, Failure>> {
        Box::pin(async move { self.reconciliation_attempt(ws, run).await })
    }

    fn prepared_attempt<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<(StepId, StepAttemptId)>, Failure>> {
        Box::pin(async move { self.prepared_attempt(ws, run).await })
    }
}

/// `harnessOperatorCommands` — the execution command surface of the
/// resolve/settle/resume actions; `exec_app::Service` implements it.
/// All three upstream methods (`ResolveReconciliation`, `Cancel`,
/// `ResumeReconciledAttempt`) are the Rust [`Command`] enum through
/// `execute`.
pub trait HarnessOperatorCommands: Send + Sync + 'static {
    /// The durable command pipeline.
    fn execute<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<CommitResult, Failure>>;
}

impl<S, V, C, B> HarnessOperatorCommands for exec_app::Service<S, V, C, B>
where
    S: central_execution::port::CompositeExecutionStore + Send + Sync + 'static,
    V: central_execution::port::LeaseCredentialValidator + Send + Sync + 'static,
    C: central_execution::port::Clock + Send + Sync + 'static,
    B: Send + Sync + 'static,
{
    fn execute<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<CommitResult, Failure>> {
        Box::pin(async move { self.execute(command, meta).await })
    }
}

/// `approvalBridge` — the in-memory side of the permission bridge the
/// decision service needs (harness phase 3c decisions 8 and 13);
/// `Orchestrator` implements it.
pub trait ApprovalBridge: Send + Sync + 'static {
    /// `PendingRequest` — the bridged request this process holds.
    fn pending_request(
        &self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Option<PendingRequest>;

    /// `SignalDecision` — wakes the waiting orchestration.
    fn signal_decision(&self, ws: WorkspaceId, id: HarnessPermissionApprovalId) -> bool;
}

impl ApprovalBridge for central_harness::app::Orchestrator {
    fn pending_request(
        &self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Option<PendingRequest> {
        self.pending_request(ws, id)
    }

    fn signal_decision(&self, ws: WorkspaceId, id: HarnessPermissionApprovalId) -> bool {
        self.signal_decision(ws, id)
    }
}

/// `harnessAttemptStore` — the operator's harness row surface:
/// the resolve/resume/rerun reads plus the approval store's
/// decision and page reads. `PgHarnessStore` implements every
/// constituent port; the blanket impl joins them.
pub trait HarnessOperatorStore: Send + Sync + 'static {
    /// `Load` — the stored attempt or `ATTEMPT_NOT_FOUND`.
    fn load<'a>(
        &'a self,
        ws: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<Attempt, Failure>>;
    /// `AttemptsForRun` — every attempt of the Run, oldest first.
    fn attempts_for_run<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Vec<Attempt>, Failure>>;
    /// `CostForTask` — the recorded cost of the Task's attempts.
    fn cost_for_task<'a>(
        &'a self,
        ws: WorkspaceId,
        task: TaskId,
    ) -> PortFuture<'a, Result<i64, Failure>>;
    /// `DecidePermission` — the compare-and-set decision.
    fn decide_permission<'a>(
        &'a self,
        req: DecidePermissionRequest,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>>;
    /// `LoadApproval` — one approval or `NO_PENDING_APPROVAL`.
    fn load_approval<'a>(
        &'a self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>>;
    /// `PendingApprovalForRun`.
    fn pending_approval_for_run<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<PermissionApproval>, Failure>>;
    /// `PendingApprovals` — the banner summary.
    fn pending_approvals<'a>(
        &'a self,
        ws: WorkspaceId,
    ) -> PortFuture<'a, Result<PendingApprovalSummary, Failure>>;
    /// `ApprovalHistory` — newest first, bounded.
    fn approval_history<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<PermissionApproval>, Failure>>;
}

impl<T> HarnessOperatorStore for T
where
    T: AttemptStore + ApprovalStore + AttemptSummaryRead + BudgetUsageRead,
{
    fn load<'a>(
        &'a self,
        ws: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        AttemptStore::load(self, ws, id)
    }

    fn attempts_for_run<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Vec<Attempt>, Failure>> {
        Box::pin(async move { AttemptSummaryRead::attempts_for_run(self, ws, run).await })
    }

    fn cost_for_task<'a>(
        &'a self,
        ws: WorkspaceId,
        task: TaskId,
    ) -> PortFuture<'a, Result<i64, Failure>> {
        Box::pin(async move { BudgetUsageRead::cost_for_task(self, ws, task).await })
    }

    fn decide_permission<'a>(
        &'a self,
        req: DecidePermissionRequest,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
        ApprovalStore::decide_permission(self, req)
    }

    fn load_approval<'a>(
        &'a self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
        ApprovalStore::load_approval(self, ws, id)
    }

    fn pending_approval_for_run<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<PermissionApproval>, Failure>> {
        ApprovalStore::pending_approval_for_run(self, ws, run)
    }

    fn pending_approvals<'a>(
        &'a self,
        ws: WorkspaceId,
    ) -> PortFuture<'a, Result<PendingApprovalSummary, Failure>> {
        ApprovalStore::pending_approvals(self, ws)
    }

    fn approval_history<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<PermissionApproval>, Failure>> {
        ApprovalStore::approval_history(self, ws, run, limit)
    }
}

// ---------------------------------------------------------------------------
// ServeHarnessOperator
// ---------------------------------------------------------------------------

/// Upstream `harnessOperator` — the `web.HarnessOperator` serve
/// composes.
pub struct ServeHarnessOperator {
    /// `status` — the dispatcher's state, or disabled (upstream's
    /// `c.Status` closure).
    status: Arc<dyn Fn() -> dispatcher::Status + Send + Sync>,
    /// `reads` — the operator read surface.
    reads: Arc<dyn HarnessOperatorReads>,
    /// `commands` — the execution command surface.
    commands: Arc<dyn HarnessOperatorCommands>,
    /// `tasks` — "Mark cancelled"'s task surface (3e decision 12);
    /// `None` disables only that combined action.
    tasks: Option<Arc<dyn ports::TaskService>>,
    /// `rerunTasks` — "Mark failed and rerun"'s task surface (3k
    /// decision 5); composed only while execution is enabled.
    rerun_tasks: Option<Arc<dyn ports::TaskService>>,
    /// `attempts`/`approvals` — the harness row store.
    attempts: Arc<dyn HarnessOperatorStore>,
    /// `bridge` — the orchestrator's in-memory approval registry;
    /// `None` while execution is disabled, when no request can be
    /// allowed.
    bridge: Option<Arc<dyn ApprovalBridge>>,
    /// `policiesEnabled` — whether a Task may carry a non-deny policy.
    policies_enabled: bool,
    /// `backend` — the configured backend id, reported even while
    /// disabled.
    backend: &'static str,
    /// `budgetDefaults` — serve's default Run budget bounds.
    budget_defaults: HarnessBudgetDefaults,
    /// `maxAttempts` — `CENTRAL_HARNESS_MAX_ATTEMPTS` while enabled,
    /// else 0: Resume is off (3g decision 8).
    max_attempts: i64,
    /// `eligibleAfter` — `CENTRAL_HARNESS_ELIGIBLE_AFTER` while
    /// enabled, else the zero time: Resume is not offered for an
    /// older Task (3h).
    eligible_after: OffsetDateTime,
    /// `taskCostCapMicroUSD` — `CENTRAL_HARNESS_TASK_COST_CAP_USD`
    /// while enabled, else 0: Retry is not gated (3j decision 3).
    task_cost_cap_micro_usd: i64,
    resolver: Arc<Resolver>,
    clock: Arc<dyn Clock>,
}

/// `ServeHarnessOperatorDeps` — the composition seam; mirrors
/// upstream `harnessCapability.operator`'s wiring inputs.
pub struct ServeHarnessOperatorDeps {
    /// The dispatcher status closure (`HarnessCapability::status`).
    pub status: Arc<dyn Fn() -> dispatcher::Status + Send + Sync>,
    /// The execution read surface.
    pub reads: Arc<dyn HarnessOperatorReads>,
    /// The execution command surface.
    pub commands: Arc<dyn HarnessOperatorCommands>,
    /// "Mark cancelled"'s task surface; `None` disables it.
    pub tasks: Option<Arc<dyn ports::TaskService>>,
    /// "Mark failed and rerun"'s task surface; `None` disables it.
    pub rerun_tasks: Option<Arc<dyn ports::TaskService>>,
    /// The harness attempt + approval store.
    pub attempts: Arc<dyn HarnessOperatorStore>,
    /// The orchestrator's registry; `None` while disabled.
    pub bridge: Option<Arc<dyn ApprovalBridge>>,
    /// Whether permission policies are offered.
    pub policies_enabled: bool,
    /// The configured backend id (`Backend::as_str()`).
    pub backend: &'static str,
    /// Serve's default Run budget bounds.
    pub budget_defaults: HarnessBudgetDefaults,
    /// The attempt ceiling; 0 while disabled.
    pub max_attempts: i64,
    /// The eligibility floor; the zero time while disabled.
    pub eligible_after: OffsetDateTime,
    /// The Task cost cap; 0 while disabled.
    pub task_cost_cap_micro_usd: i64,
    /// The recovery-authority resolver.
    pub resolver: Arc<Resolver>,
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
}

impl ServeHarnessOperator {
    /// `composeHarness`'s operator block — always built, so ambiguous
    /// Tasks stay resolvable even when execution is disabled
    /// (harness phase 3a decision 9).
    #[must_use]
    pub fn new(deps: ServeHarnessOperatorDeps) -> Self {
        Self {
            status: deps.status,
            reads: deps.reads,
            commands: deps.commands,
            tasks: deps.tasks,
            rerun_tasks: deps.rerun_tasks,
            attempts: deps.attempts,
            bridge: deps.bridge,
            policies_enabled: deps.policies_enabled,
            backend: deps.backend,
            budget_defaults: deps.budget_defaults,
            max_attempts: deps.max_attempts,
            eligible_after: deps.eligible_after,
            task_cost_cap_micro_usd: deps.task_cost_cap_micro_usd,
            resolver: deps.resolver,
            clock: deps.clock,
        }
    }

    /// `notice` — the /app banner text of a paused dispatcher
    /// (decision 11) and of any Run waiting on the next restart's
    /// reconciliation (decision 10): a lost lease or a failed
    /// settlement. Both can show at once.
    fn notice(&self) -> String {
        let s = (self.status)();
        let mut lines: Vec<String> = Vec::new();
        if s.paused() {
            const RETRY: &str =
                " Central re-checks every 30 seconds; queued tasks wait and nothing fails.";
            match s.pause {
                dispatcher::PauseReason::NotLoggedIn => lines.push(format!(
                    "Harness execution is paused: Claude Code is not logged in for the operator. \
                     Log in with claude as the operator.{RETRY}"
                )),
                dispatcher::PauseReason::LauncherUnreachable => lines.push(format!(
                    "Harness execution is paused: the harness launcher is unreachable. \
                     Check central-harness-launcher.socket.{RETRY}"
                )),
                dispatcher::PauseReason::LowDisk => lines.push(format!(
                    "Harness execution is paused: free space under the harness data root is below \
                     CENTRAL_HARNESS_MIN_FREE. Remove terminal Run clones (see the harness \
                     runbook).{RETRY}"
                )),
                _ => lines.push(format!("Harness execution is paused.{RETRY}")),
            }
        }
        if s.needs_restart() {
            let n = s.lost.len() + s.settle_failed.len();
            lines.push(format!(
                "{n} harness run(s) need a serve restart to be reconciled."
            ));
        }
        lines.join(" ")
    }

    /// `reconciliationTarget` — the Run's StepAttempt in
    /// reconciliation and its harness attempt, if the harness
    /// attempt waits on the operator.
    async fn reconciliation_target(
        &self,
        ws: WorkspaceId,
        run: RunId,
    ) -> Result<Option<(StepId, StepAttemptId)>, Failure> {
        let found = self.reconciliation_row(ws, run).await?;
        Ok(found.map(|(step, attempt, _)| (step, attempt)))
    }

    /// `reconciliationRow` — `reconciliationTarget` with the harness
    /// attempt row it found.
    async fn reconciliation_row(
        &self,
        ws: WorkspaceId,
        run: RunId,
    ) -> Result<Option<(StepId, StepAttemptId, Attempt)>, Failure> {
        let Some((step, attempt)) = self.reads.reconciliation_attempt(ws, run).await? else {
            return Ok(None);
        };
        let id = attempt_id_for_step_attempt(attempt)?;
        let a = match self.attempts.load(ws, id).await {
            Err(e) if e.code() == hcodes::ATTEMPT_NOT_FOUND => return Ok(None), // not a harness Run
            r => r?,
        };
        // Ambiguous is the normal case. A terminal row whose
        // StepAttempt still waits (the lease was lost between
        // persisting the terminal and the receipt) needs the same
        // exit.
        if a.state != State::Ambiguous && !a.state.is_terminal() {
            return Ok(None);
        }
        Ok(Some((step, attempt, a)))
    }

    /// `resolveTarget` reads, under the session's operator authority,
    /// the Run's StepAttempt waiting on the operator and refuses
    /// anything else: no harness attempt waiting on the operator, a
    /// Run that moved on since the caller's own load
    /// (`expected_run_version`, when `check_run_version`; only the
    /// second step of "Mark cancelled", which re-reads its own
    /// commit, skips it), or a live lease.
    async fn resolve_target(
        &self,
        req: &HarnessResolveRequest,
        check_run_version: bool,
    ) -> Result<ResolveTarget, Failure> {
        if req.principal.is_empty() {
            return Err(not_resolvable());
        }
        let Some((step, attempt)) = self
            .reconciliation_target(req.workspace_id, req.run_id)
            .await?
        else {
            return Err(not_resolvable());
        };
        let principal = operator_principal(&req.principal);
        let scope = TrustedScope::new(
            &principal,
            req.workspace_id,
            &[Capability::WorkspaceOperator],
        )?;
        let state = self
            .reads
            .read_execution(ExecutionReadRequest {
                scope: scope.clone(),
                workspace_id: req.workspace_id,
                task_id: req.task_id,
                run_id: req.run_id,
                step_id: step,
                attempt_id: attempt,
            })
            .await?
            .state;
        let (Some(st), Some(at), Some(_)) = (&state.step, &state.attempt, &state.task.current_run)
        else {
            return Err(not_resolvable());
        };
        let _ = (st, at);
        if state.attempt.as_ref().map(|a| a.state)
            != Some(exec::AttemptState::AttemptReconciliation)
        {
            return Err(not_resolvable());
        }
        // The Run must still be the one the caller's own load saw
        // (harness phase 3a review fix): a stale page load can never
        // resolve a Run that has since moved on.
        if check_run_version
            && req.expected_run_version
                != state
                    .task
                    .current_run
                    .as_ref()
                    .map(|r| r.version)
                    .unwrap_or_default()
        {
            return Err(not_resolvable());
        }
        if self.lease_live(&state) {
            return Err(not_resolvable()); // something still holds the Run
        }
        Ok(ResolveTarget {
            req: req.clone(),
            principal,
            scope,
            step,
            attempt,
            state,
        })
    }

    /// `resolve` runs `ResolveReconciliation(disposition)` under the
    /// operator authority with the operator's attestation and a
    /// no-active-lease assertion, then makes the harness attempt
    /// `resolved(abandon)`. If the harness write fails after the
    /// execution commit, the startup reconciler completes it, so
    /// that failure is logged and not reported to the caller
    /// (decision 9).
    async fn resolve(
        &self,
        target: &ResolveTarget,
        disposition: ReconciliationDisposition,
        key: String,
    ) -> Result<(), Failure> {
        self.resolve_reconciliation(target, disposition, key)
            .await?;
        if let Err(err) = self
            .resolver
            .resolve_abandon(target.req.workspace_id, target.attempt, &target.principal)
            .await
        {
            tracing::warn!(
                target: "central.harness.operator",
                attempt = %target.attempt, error = %err,
                "harness resolve: the execution side committed but the harness attempt row \
                 was not updated; it is reconciled at the next start"
            );
        }
        Ok(())
    }

    /// `resolveReconciliation` — the execution commit of resolve:
    /// `ResolveReconciliation(disposition)` under the operator
    /// authority with the operator's attestation, a no-active-lease
    /// assertion and the full expected versions, under the
    /// idempotency key `key` (also its fingerprint source). "Mark
    /// failed and rerun" runs it as its step (a) (3k decision 2).
    async fn resolve_reconciliation(
        &self,
        target: &ResolveTarget,
        disposition: ReconciliationDisposition,
        key: String,
    ) -> Result<(), Failure> {
        let req = &target.req;
        let state = &target.state;
        let Some(attempt) = &state.attempt else {
            return Err(not_resolvable());
        };
        let (Some(step), Some(run)) = (&state.step, &state.task.current_run) else {
            return Err(not_resolvable());
        };
        self.commands
            .execute(
                Command::ResolveReconciliation(exec::ResolveReconciliationCommand {
                    envelope: CommandEnvelope {
                        scope: target.scope.clone(),
                        workspace_id: req.workspace_id,
                        task_id: req.task_id,
                        run_id: req.run_id,
                        step_id: target.step,
                        attempt_id: target.attempt,
                        logical_operation: attempt.logical_operation_id,
                        expected: ExpectedVersions {
                            task: state.task.task.version,
                            run: run.version,
                            step: step.version,
                            attempt: attempt.version,
                            ..ExpectedVersions::default()
                        },
                        operation_digest: exec::RequestFingerprint::default(),
                        lease_credential: exec::LeaseCredential::default(),
                        lease_generation: 0,
                        assert_no_active_lease: true,
                        state: state.clone(),
                    },
                    disposition,
                    evidence: vec![ReconciliationEvidence {
                        kind: ReconciliationEvidenceKind::ReconciliationEvidenceOperatorAttestation,
                        reference: target.principal.clone(),
                    }],
                }),
                operator_meta(&target.principal, &key),
            )
            .await?;
        Ok(())
    }

    /// `readPreparedTarget` reads, under `scope`, the Run's prepared
    /// StepAttempt, and reports `Some` only for a cancelling Task
    /// whose current, cancelling Run has it. It keys on execution
    /// state only, never on a harness row (decision 10): a successor
    /// cancelled before any re-claim has none.
    async fn read_prepared_target(
        &self,
        scope: &TrustedScope,
        ws: WorkspaceId,
        task_id: TaskId,
        run: RunId,
    ) -> Result<Option<PreparedTarget>, Failure> {
        let Some((step, attempt)) = self.reads.prepared_attempt(ws, run).await? else {
            return Ok(None);
        };
        let s = self
            .reads
            .read_execution(ExecutionReadRequest {
                scope: scope.clone(),
                workspace_id: ws,
                task_id,
                run_id: run,
                step_id: step,
                attempt_id: attempt,
            })
            .await?
            .state;
        let (Some(st), Some(at), Some(current_run)) = (&s.step, &s.attempt, &s.task.current_run)
        else {
            return Ok(None);
        };
        if s.task.task.current_run_id != Some(run)
            || current_run.id != run
            || at.state != exec::AttemptState::AttemptPrepared
            || s.task.task.status != task::TaskStatus::Cancelling
            || current_run.status != task::RunStatus::Cancelling
        {
            return Ok(None);
        }
        let _ = st;
        Ok(Some(PreparedTarget {
            step,
            attempt,
            state: s,
        }))
    }

    /// `leaseLive` — whether an unexpired lease holds the Run: the
    /// dispatcher may be claiming the attempt (decision 9).
    fn lease_live(&self, s: &ExecutionState) -> bool {
        s.lease
            .as_ref()
            .is_some_and(|l| l.expires_at > self.clock.now())
    }

    /// `readResumeTarget` reads, under `scope`, the Run's StepAttempt
    /// in reconciliation and reports `Some` when everything of
    /// decision 11 holds except the lease, the eligibility floor,
    /// the ceiling and the budget, which the callers judge.
    async fn read_resume_target(
        &self,
        scope: &TrustedScope,
        ws: WorkspaceId,
        task_id: TaskId,
        run: RunId,
    ) -> Result<Option<ResumeTarget>, Failure> {
        if self.max_attempts <= 0 || ws.is_nil() || run.is_nil() {
            return Ok(None);
        }
        let Some((step, attempt, row)) = self.reconciliation_row(ws, run).await? else {
            return Ok(None);
        };
        if row.state != State::Ambiguous || row.harness_session_id.is_empty() {
            return Ok(None);
        }
        let s = self
            .reads
            .read_execution(ExecutionReadRequest {
                scope: scope.clone(),
                workspace_id: ws,
                task_id,
                run_id: run,
                step_id: step,
                attempt_id: attempt,
            })
            .await?
            .state;
        let (Some(_st), Some(at), Some(current_run)) = (&s.step, &s.attempt, &s.task.current_run)
        else {
            return Ok(None);
        };
        if current_run.id != run
            || at.state != exec::AttemptState::AttemptReconciliation
            || !waiting_on_reconciliation(&s.task.task)
        {
            return Ok(None);
        }
        let attempts = self.attempts.attempts_for_run(ws, run).await?;
        let Some(chain) = central_harness::budget::sum_chain(&attempts) else {
            return Ok(None);
        };
        Ok(Some(ResumeTarget {
            step,
            attempt,
            state: s,
            chain,
        }))
    }

    /// `readRerunTarget` reads, under `scope`, the Run's StepAttempt
    /// in reconciliation and reports `Some` when every gate of
    /// harness phase 3k decision 3 except the lease holds.
    async fn read_rerun_target(
        &self,
        scope: &TrustedScope,
        ws: WorkspaceId,
        task_id: TaskId,
        run: RunId,
    ) -> Result<Option<RerunTarget>, Failure> {
        if self.rerun_tasks.is_none() || ws.is_nil() || task_id.is_nil() || run.is_nil() {
            return Ok(None);
        }
        let Some((step, attempt, row)) = self.reconciliation_row(ws, run).await? else {
            return Ok(None);
        };
        // The harness row must be ambiguous: a terminal row is not
        // eligible.
        if row.state != State::Ambiguous {
            return Ok(None);
        }
        let s = self
            .reads
            .read_execution(ExecutionReadRequest {
                scope: scope.clone(),
                workspace_id: ws,
                task_id,
                run_id: run,
                step_id: step,
                attempt_id: attempt,
            })
            .await?
            .state;
        let (Some(_st), Some(at), Some(current_run)) = (&s.step, &s.attempt, &s.task.current_run)
        else {
            return Ok(None);
        };
        if current_run.id != run
            || at.state != exec::AttemptState::AttemptReconciliation
            || !waiting_on_reconciliation(&s.task.task)
        {
            return Ok(None);
        }
        if !task_eligible(s.task.task.created_at, self.eligible_after) {
            return Ok(None);
        }
        let retry = self.retry_state_inner(ws, task_id).await?;
        if retry.blocked {
            return Ok(None);
        }
        Ok(Some(RerunTarget {
            step,
            attempt,
            state: s,
        }))
    }

    /// `RetryState`'s body — shared by the trait method and
    /// `read_rerun_target`.
    async fn retry_state_inner(
        &self,
        ws: WorkspaceId,
        task_id: TaskId,
    ) -> Result<HarnessRetryState, Failure> {
        if self.task_cost_cap_micro_usd <= 0 {
            return Ok(HarnessRetryState::default());
        }
        let used = self.attempts.cost_for_task(ws, task_id).await?;
        Ok(HarnessRetryState {
            used_micro_usd: used,
            cap_micro_usd: self.task_cost_cap_micro_usd,
            blocked: self.task_cost_cap_micro_usd - used
                < central_harness::budget::MIN_RESUME_COST_MICRO_USD,
        })
    }

    /// `rerunRetry` — step (b) of `ResolveRerun`: the Retry of the
    /// Task that step (a) failed, fed by a re-read of the Task.
    async fn rerun_retry(
        &self,
        req: &HarnessResolveRequest,
        attempt: StepAttemptId,
    ) -> Result<(), Failure> {
        let Some(tasks) = &self.rerun_tasks else {
            return Err(not_resolvable());
        };
        let loaded = tasks.load_aggregate(req.workspace_id, req.task_id).await?;
        if retried_past(&loaded, req.run_id) {
            return Ok(());
        }
        let t = &loaded.aggregate.task;
        if t.status != task::TaskStatus::Failed
            || t.current_run_id != Some(req.run_id)
            || loaded.aggregate.current_run.is_none()
        {
            return Err(not_resolvable());
        }
        // The key cannot replay against the real task store: its
        // receipt fingerprint includes the new Run's random id, so a
        // second commit under the same key is a fingerprint
        // mismatch, not a replay. What makes a replay work is the
        // re-read below after a refused Retry: a Task already on a
        // later Run means (b) is done.
        let key = format!("harness:rerun-retry:{attempt}");
        let run_version = loaded.run_version.unwrap_or_default();
        if let Err(err) = tasks
            .retry_failed_task(
                task::RetryFailedTaskRequest {
                    input: task::MutationInput {
                        aggregate: loaded.aggregate.clone(),
                        expected_task_version: loaded.task_version,
                        expected_run_version: run_version,
                        now: self.clock.now(),
                    },
                },
                task_app::CommandMeta {
                    idempotency_key: Some(key),
                    ..task_app::CommandMeta::default()
                },
            )
            .await
        {
            if let Ok(now) = tasks.load_aggregate(req.workspace_id, req.task_id).await
                && retried_past(&now, req.run_id)
            {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    /// `resumeError` — `resume_refusal` plus a log line for the one
    /// outcome the page cannot explain: an infrastructure failure.
    fn resume_error(&self, err: Failure) -> Failure {
        let mapped = resume_refusal(err);
        if mapped.code() != ERR_HARNESS_STARTING && mapped.code() != ERR_HARNESS_NOT_RESOLVABLE {
            tracing::warn!(
                target: "central.harness.operator",
                error = %mapped,
                "harness resume: infrastructure failure"
            );
        }
        mapped
    }
}

/// `resolveTarget` — the durable state a resolve action applies to.
struct ResolveTarget {
    req: HarnessResolveRequest,
    principal: String,
    scope: TrustedScope,
    step: StepId,
    attempt: StepAttemptId,
    state: ExecutionState,
}

/// `preparedTarget` — the durable state "Finish cancelling" settles
/// on a never-invoked attempt (3f decisions 8 to 10).
struct PreparedTarget {
    step: StepId,
    attempt: StepAttemptId,
    state: ExecutionState,
}

/// `resumeTarget` — the durable state Resume applies to (3g
/// decision 11).
struct ResumeTarget {
    step: StepId,
    attempt: StepAttemptId,
    state: ExecutionState,
    chain: ChainCost,
}

impl ResumeTarget {
    /// `blocked` — the one obstacle the page names: the eligibility
    /// floor, then the ceiling, then the budget (less than US$0.01
    /// left).
    fn blocked(&self, max_attempts: i64, eligible_after: OffsetDateTime) -> HarnessResumeBlock {
        if !task_eligible(self.state.task.task.created_at, eligible_after) {
            return HarnessResumeBlock::NotEligible;
        }
        let Some(step) = &self.state.step else {
            return HarnessResumeBlock::None;
        };
        if step.sequence + 1 > max_attempts {
            return HarnessResumeBlock::AttemptLimit;
        }
        if self.chain.remaining() < central_harness::budget::MIN_RESUME_COST_MICRO_USD {
            return HarnessResumeBlock::BudgetUsedUp;
        }
        HarnessResumeBlock::None
    }
}

/// `rerunTarget` — the durable state "Mark failed and rerun"
/// applies to.
struct RerunTarget {
    step: StepId,
    attempt: StepAttemptId,
    state: ExecutionState,
}

/// `waitingOnReconciliation` — whether `t` waits on the
/// reconciliation of its attempt.
fn waiting_on_reconciliation(t: &task::Task) -> bool {
    t.status == task::TaskStatus::Waiting
        && t.waiting_reason == Some(task::WaitingReason::Reconciliation)
}

/// `reReadIsCommitted` — whether the re-read aggregate is exactly
/// the Task and current Run versions the cancel request committed.
fn re_read_is_committed(committed: &task::CommitResult, reread: &task::TaskAggregate) -> bool {
    let Some(current) = &reread.current_run else {
        return false;
    };
    if committed.task.id != reread.task.id || committed.task.version != reread.task.version {
        return false;
    }
    committed
        .runs
        .iter()
        .any(|r| r.id == current.id && r.version == current.version)
}

/// `retriedPast` — whether the Task has moved on from `run` to a
/// newer current Run. From `failed`, only a Retry moves a Task's
/// current Run.
fn retried_past(loaded: &central_task::port::LoadedAggregate, run: RunId) -> bool {
    loaded
        .aggregate
        .task
        .current_run_id
        .is_some_and(|current| current != run)
}

/// `operatorMeta` — the operator authority's evaluation metadata:
/// principal `operator-session:<p>`, `WorkspaceOperator`
/// capability, the idempotency key and its fingerprint.
fn operator_meta(principal: &str, key: &str) -> EvaluationMetadata {
    EvaluationMetadata {
        principal_id: principal.to_string(),
        capability: Capability::WorkspaceOperator,
        idempotency_key: key.to_string(),
        fingerprint: exec::new_request_fingerprint(key.as_bytes()),
        now: exec::ZERO_TIME,
        event_id: central_foundation::identity::ExecutionEventId::new(),
        outbox_id: central_foundation::identity::OutboxId::new(),
        producer_id: principal.to_string(),
    }
}

/// A capability-free read scope — upstream `TrustedScope{WorkspaceID:
/// ws}`; the store checks the Workspace scope only.
fn read_scope(ws: WorkspaceId) -> TrustedScope {
    TrustedScope {
        principal_id: String::new(),
        workspace_id: ws,
        capabilities: Default::default(),
    }
}

/// `approvalRefusal` — whether `err` is the approval store refusing a
/// decision rather than failing: every refusal is shown as "no
/// longer pending", never as a server error.
fn approval_refusal(err: &Failure) -> bool {
    matches!(
        err.code(),
        hcodes::NO_PENDING_APPROVAL
            | hcodes::APPROVAL_NOT_PENDING
            | hcodes::INVALID_APPROVAL
            | hcodes::INPUT_MAC_MISMATCH
    )
}

/// `settlePreparedRefusal` maps the command refusals SettlePrepared
/// explains (decision 9 and the plan's spec conflict 1); any other
/// error is returned unchanged.
fn settle_prepared_refusal(err: Failure) -> Failure {
    match err.code() {
        "STALE_LEASE_FENCE" | "ACTIVE_LEASE_CONFLICT" => starting(),
        "RECONCILIATION_REQUIRED" => not_resolvable(),
        _ => err,
    }
}

/// `resumeRefusal` classifies an error of Resume's read or command
/// (harness phase 3i decision 8). A lease refusal is
/// `ERR_HARNESS_STARTING` (retry). Every other typed refusal is
/// `ERR_HARNESS_NOT_RESOLVABLE`. Anything else — a store/database
/// failure — is returned as is: an infrastructure failure, which the
/// page answers with 500.
fn resume_refusal(err: Failure) -> Failure {
    match err.code() {
        "STALE_LEASE_FENCE" | "ACTIVE_LEASE_CONFLICT" | "LEASE_STATE_ASSERTION_REQUIRED" => {
            starting()
        }
        _ if is_typed_refusal(&err) => not_resolvable(),
        _ => err,
    }
}

/// Whether `err` is a typed domain refusal rather than an
/// infrastructure failure: upstream classifies every
/// `execution.Failure` (any class). The Rust Failure carries the same
/// contract — domain refusals are `Invalid`/`Denied`/`Conflict`/
/// `NotFound`; infrastructure failures are `Internal`/`Unavailable`.
fn is_typed_refusal(err: &Failure) -> bool {
    use central_foundation::failure::FailureKind;
    matches!(
        err.kind(),
        FailureKind::Invalid | FailureKind::Denied | FailureKind::Conflict | FailureKind::NotFound
    )
}

/// `saturatingAdd` — two non-negative counters without wrapping.
fn saturating_add(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

// ---------------------------------------------------------------------------
// HarnessOperator impl
// ---------------------------------------------------------------------------

impl HarnessOperator for ServeHarnessOperator {
    /// `Banner` — the notice plus pending-permission facts every
    /// `/app` page of `ws` shows (3c decision 13). A failed approval
    /// read hides only the count.
    fn banner(&self, workspace_id: WorkspaceId) -> BoxFuture<'_, HarnessBanner> {
        Box::pin(async move {
            let mut b = HarnessBanner {
                notice: self.notice(),
                ..HarnessBanner::default()
            };
            if workspace_id.is_nil() {
                return b;
            }
            match self.attempts.pending_approvals(workspace_id).await {
                Ok(summary) => {
                    b.pending_permissions = summary.count as i32;
                    b.oldest_permission_task_id = summary.oldest_task_id;
                }
                Err(err) => {
                    tracing::warn!(
                        target: "central.harness.operator",
                        error = %err,
                        "harness banner: pending approvals not read"
                    );
                }
            }
            b
        })
    }

    /// `Resolvable` — whether the run's harness attempt waits on the
    /// operator.
    fn resolvable(
        &self,
        workspace_id: WorkspaceId,
        _task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<bool, Failure>> {
        Box::pin(async move {
            Ok(self
                .reconciliation_target(workspace_id, run_id)
                .await?
                .is_some())
        })
    }

    /// `ResolveFailed` — "Mark failed (operator resolved)".
    fn resolve_failed(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let target = self.resolve_target(&req, true).await?;
            if !waiting_on_reconciliation(&target.state.task.task) {
                return Err(not_resolvable());
            }
            self.resolve(
                &target,
                ReconciliationDisposition::ReconciliationConfirmFailed,
                format!("harness:resolve:{}", target.attempt),
            )
            .await
        })
    }

    /// `ResolveCancelled` — "Mark cancelled (operator resolved)"
    /// (3e decisions 6 and 12). For a Task still waiting on
    /// reconciliation it first requests the cancellation through
    /// the task domain: two durable commits.
    fn resolve_cancelled(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let mut target = self.resolve_target(&req, true).await?;
            let t = &target.state.task.task;
            match t.status {
                task::TaskStatus::Cancelling => {}
                _ if waiting_on_reconciliation(t) => {
                    let Some(tasks) = &self.tasks else {
                        return Err(not_resolvable());
                    };
                    let Some(run) = &target.state.task.current_run else {
                        return Err(not_resolvable());
                    };
                    let key = format!("harness:request-cancel:{}", target.attempt);
                    let committed = tasks
                        .request_cancellation(
                            task::RequestCancellationRequest {
                                input: task::MutationInput {
                                    aggregate: target.state.task.clone(),
                                    expected_task_version: t.version,
                                    expected_run_version: run.version,
                                    now: self.clock.now(),
                                },
                            },
                            task_app::CommandMeta {
                                idempotency_key: Some(key),
                                ..task_app::CommandMeta::default()
                            },
                        )
                        .await?;
                    // The cancel request moved the Task and Run
                    // versions on: resolve over the state it
                    // committed, and only that state.
                    target = self.resolve_target(&req, false).await?;
                    if !re_read_is_committed(&committed, &target.state.task)
                        || target.state.task.task.status != task::TaskStatus::Cancelling
                    {
                        return Err(not_resolvable());
                    }
                }
                _ => return Err(not_resolvable()),
            }
            self.resolve(
                &target,
                ReconciliationDisposition::ReconciliationCancel,
                format!("harness:resolve-cancel:{}", target.attempt),
            )
            .await
        })
    }

    /// `PreparedSettleable` — the page predicate of "Finish
    /// cancelling" on a never-invoked attempt (3f decisions 8 and
    /// 10): UX gating only.
    fn prepared_settleable(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<bool, Failure>> {
        Box::pin(async move {
            if workspace_id.is_nil() || task_id.is_nil() || run_id.is_nil() {
                return Ok(false);
            }
            let Some(target) = self
                .read_prepared_target(&read_scope(workspace_id), workspace_id, task_id, run_id)
                .await?
            else {
                return Ok(false);
            };
            Ok(!self.lease_live(&target.state))
        })
    }

    /// `SettlePrepared` — "Finish cancelling" on a never-invoked
    /// attempt (3f decisions 8 to 10). Under the operator authority,
    /// execution `Cancel` with a no-active-lease assertion ends the
    /// attempt, Step, Task and Run cancelled in one commit; then the
    /// harness row, if one exists, becomes
    /// `failed(harness_not_launched)` — logged, not reported, on
    /// failure.
    fn settle_prepared(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if req.principal.is_empty() {
                return Err(not_resolvable());
            }
            let principal = operator_principal(&req.principal);
            let scope = TrustedScope::new(
                &principal,
                req.workspace_id,
                &[Capability::WorkspaceOperator],
            )?;
            let Some(target) = self
                .read_prepared_target(&scope, req.workspace_id, req.task_id, req.run_id)
                .await?
            else {
                return Err(not_resolvable());
            };
            let Some(current_run) = &target.state.task.current_run else {
                return Err(not_resolvable());
            };
            if req.expected_run_version != current_run.version {
                return Err(not_resolvable());
            }
            if self.lease_live(&target.state) {
                return Err(starting());
            }
            let s = &target.state;
            let (Some(step), Some(attempt)) = (&s.step, &s.attempt) else {
                return Err(not_resolvable());
            };
            let key = format!("harness:settle-prepared:{}", target.attempt);
            self.commands
                .execute(
                    Command::Cancel(exec::CancelCommand {
                        envelope: CommandEnvelope {
                            scope: scope.clone(),
                            workspace_id: req.workspace_id,
                            task_id: req.task_id,
                            run_id: req.run_id,
                            step_id: target.step,
                            attempt_id: target.attempt,
                            logical_operation: attempt.logical_operation_id,
                            expected: ExpectedVersions {
                                task: s.task.task.version,
                                run: current_run.version,
                                step: step.version,
                                attempt: attempt.version,
                                ..ExpectedVersions::default()
                            },
                            operation_digest: exec::RequestFingerprint::default(),
                            lease_credential: exec::LeaseCredential::default(),
                            lease_generation: 0,
                            assert_no_active_lease: true,
                            state: s.clone(),
                        },
                        reason_code: "operator_request".to_string(),
                    }),
                    operator_meta(&principal, &key),
                )
                .await
                .map_err(settle_prepared_refusal)?;
            if let Err(err) = self
                .resolver
                .fail_unlaunched(req.workspace_id, target.attempt)
                .await
            {
                tracing::warn!(
                    target: "central.harness.operator",
                    attempt = %target.attempt, error = %err,
                    "finish cancelling: the execution side committed but the harness attempt row \
                     was not updated; it is reconciled at the next start"
                );
            }
            Ok(())
        })
    }

    /// `ResumeState` — the page predicate of Resume (3g decision
    /// 11); UX gating only.
    fn resume_state(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<HarnessResumeState, Failure>> {
        Box::pin(async move {
            let Some(target) = self
                .read_resume_target(&read_scope(workspace_id), workspace_id, task_id, run_id)
                .await?
            else {
                return Ok(HarnessResumeState::default());
            };
            if self.lease_live(&target.state) {
                return Ok(HarnessResumeState::default());
            }
            let blocked = target.blocked(self.max_attempts, self.eligible_after);
            if blocked != HarnessResumeBlock::None {
                return Ok(HarnessResumeState {
                    eligible: false,
                    blocked,
                });
            }
            Ok(HarnessResumeState {
                eligible: true,
                blocked: HarnessResumeBlock::None,
            })
        })
    }

    /// `Resume` — "Resume" on an ambiguous harness attempt (3g
    /// decisions 2, 6, 11 and 12). `ResumeReconciledAttempt` fails
    /// the old Step and StepAttempt and inserts a new Step with a
    /// prepared StepAttempt whose predecessor is the old one; then
    /// the old harness row becomes `resolved(resume)`.
    fn resume(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if req.principal.is_empty() {
                return Err(not_resolvable());
            }
            let principal = operator_principal(&req.principal);
            let scope = match TrustedScope::new(
                &principal,
                req.workspace_id,
                &[Capability::WorkspaceOperator],
            ) {
                Ok(s) => s,
                Err(e) => return Err(self.resume_error(e)),
            };
            let target = match self
                .read_resume_target(&scope, req.workspace_id, req.task_id, req.run_id)
                .await
            {
                Ok(t) => t,
                Err(e) => return Err(self.resume_error(e)),
            };
            let Some(target) = target else {
                return Err(not_resolvable());
            };
            let Some(current_run) = &target.state.task.current_run else {
                return Err(not_resolvable());
            };
            if req.expected_run_version != current_run.version {
                return Err(not_resolvable());
            }
            if self.lease_live(&target.state) {
                return Err(starting());
            }
            if target.blocked(self.max_attempts, self.eligible_after) != HarnessResumeBlock::None {
                return Err(not_resolvable());
            }
            let s = &target.state;
            let (Some(step), Some(attempt)) = (&s.step, &s.attempt) else {
                return Err(not_resolvable());
            };
            let key = format!("harness:resume:{}", target.attempt);
            let cmd = Command::ResumeReconciledAttempt(
                central_execution::resume::ResumeReconciledAttemptCommand {
                    envelope: CommandEnvelope {
                        scope: scope.clone(),
                        workspace_id: req.workspace_id,
                        task_id: req.task_id,
                        run_id: req.run_id,
                        step_id: target.step,
                        attempt_id: target.attempt,
                        logical_operation: attempt.logical_operation_id,
                        expected: ExpectedVersions {
                            task: s.task.task.version,
                            run: current_run.version,
                            step: step.version,
                            attempt: attempt.version,
                            ..ExpectedVersions::default()
                        },
                        operation_digest: exec::RequestFingerprint::default(),
                        lease_credential: exec::LeaseCredential::default(),
                        lease_generation: 0,
                        assert_no_active_lease: true,
                        state: s.clone(),
                    },
                    new_step_id: StepId::new(),
                    new_attempt_id: StepAttemptId::new(),
                    new_logical_operation: exec::LogicalOperationId::new(),
                    physical_attempt_id: exec::PhysicalAttemptId::new(),
                    evidence: vec![ReconciliationEvidence {
                        kind: ReconciliationEvidenceKind::ReconciliationEvidenceOperatorAttestation,
                        reference: principal.clone(),
                    }],
                    max_step_sequence: self.max_attempts,
                    remaining_cost_micro_usd: target.chain.remaining(),
                },
            );
            if let Err(e) = self
                .commands
                .execute(cmd, operator_meta(&principal, &key))
                .await
            {
                return Err(self.resume_error(e));
            }
            if let Err(err) = self
                .resolver
                .complete_resume(req.workspace_id, target.attempt, &principal)
                .await
            {
                tracing::warn!(
                    target: "central.harness.operator",
                    attempt = %target.attempt, error = %err,
                    "harness resume: the execution side committed but the harness attempt row \
                     was not recorded resolved(resume); the claim of the new attempt or the \
                     next start completes it"
                );
            }
            Ok(())
        })
    }

    /// `RerunOffered` — the page predicate of "Mark failed and
    /// rerun" (3k decisions 3 and 5).
    fn rerun_offered(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<bool, Failure>> {
        Box::pin(async move {
            let Some(target) = self
                .read_rerun_target(&read_scope(workspace_id), workspace_id, task_id, run_id)
                .await?
            else {
                return Ok(false);
            };
            Ok(!self.lease_live(&target.state))
        })
    }

    /// `ResolveRerun` — "Mark failed and rerun (operator resolved)"
    /// (3k decision 2): one operator attestation, three steps in
    /// this order — (a) `ResolveReconciliation(ConfirmFailed)`, (b)
    /// `RetryFailedTask` over a re-read, (c) the harness row to
    /// `resolved(rerun)`. Once (a) has committed, (b) and (c) must
    /// still run: the operator surface has no caller-context to
    /// detach, so they run inline — a failure of (b) is returned
    /// (the Task is then failed and the plain Retry applies); a
    /// failure of (c) is logged, not returned.
    fn resolve_rerun(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if req.principal.is_empty() {
                return Err(not_resolvable());
            }
            let principal = operator_principal(&req.principal);
            let scope = TrustedScope::new(
                &principal,
                req.workspace_id,
                &[Capability::WorkspaceOperator],
            )?;
            let Some(target) = self
                .read_rerun_target(&scope, req.workspace_id, req.task_id, req.run_id)
                .await?
            else {
                return Err(not_resolvable());
            };
            let Some(current_run) = &target.state.task.current_run else {
                return Err(not_resolvable());
            };
            if req.expected_run_version != current_run.version || self.lease_live(&target.state) {
                return Err(not_resolvable());
            }
            let resolve_target = ResolveTarget {
                req: req.clone(),
                principal: principal.clone(),
                scope,
                step: target.step,
                attempt: target.attempt,
                state: target.state,
            };
            self.resolve_reconciliation(
                &resolve_target,
                ReconciliationDisposition::ReconciliationConfirmFailed,
                format!("harness:rerun:{}", target.attempt),
            )
            .await?;
            self.rerun_retry(&req, target.attempt).await?;
            if let Err(err) = self
                .resolver
                .resolve_rerun(req.workspace_id, target.attempt, &principal)
                .await
            {
                tracing::warn!(
                    target: "central.harness.operator",
                    attempt = %target.attempt, error = %err,
                    "harness rerun: the Task was retried but the harness attempt row was not \
                     recorded resolved(rerun); the next start's reconciliation records it abandon"
                );
            }
            Ok(())
        })
    }

    /// `PermissionPanel` — the Run's pending permission request of
    /// `task_id`, or `None`. Its input and resources come only from
    /// this process's registry.
    fn permission_panel(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Option<HarnessPermissionPanel>, Failure>> {
        Box::pin(async move {
            if run_id.is_nil() {
                return Ok(None);
            }
            let Some(a) = self
                .attempts
                .pending_approval_for_run(workspace_id, run_id)
                .await?
            else {
                return Ok(None);
            };
            if a.task_id != task_id {
                return Ok(None);
            }
            let mut panel = HarnessPermissionPanel {
                approval_id: a.id,
                tool_name: a.tool_name,
                tool_call_id: a.tool_call_id,
                resources: Vec::new(),
                input: Vec::new(),
                input_size: a.input_size,
                input_mac: a.input_mac.to_string(),
                requested_at: a.requested_at,
                expires_at: a.expires_at,
                allowable: false,
            };
            if let Some(bridge) = &self.bridge
                && let Some(pending) = bridge.pending_request(workspace_id, a.id)
            {
                panel.input = pending.input;
                panel.resources = pending.resources;
                panel.allowable = true;
            }
            Ok(Some(panel))
        })
    }

    /// `PermissionHistory` — the Run's requests, newest first, ≤20.
    fn permission_history(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<HarnessPermissionRecord>, Failure>> {
        Box::pin(async move {
            if run_id.is_nil() {
                return Ok(Vec::new());
            }
            let history = self
                .attempts
                .approval_history(
                    workspace_id,
                    run_id,
                    central_harness::port::MAX_APPROVAL_HISTORY,
                )
                .await?;
            Ok(history
                .into_iter()
                .map(|a| HarnessPermissionRecord {
                    tool_name: a.tool_name,
                    outcome: a.state.as_str().to_string(),
                    decided_by: a.decided_by,
                    requested_at: a.requested_at,
                    decided_at: a.decided_at.unwrap_or(OffsetDateTime::UNIX_EPOCH),
                })
                .collect())
        })
    }

    /// `DecidePermission` — the decision service (3c decision 8):
    /// the durable compare-and-set first, then the registry signal.
    /// Allow and deny alike are refused unless this process's
    /// registry holds the request — a decision is never recorded
    /// that the harness would not receive.
    fn decide_permission(
        &self,
        req: HarnessPermissionDecision,
    ) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let Ok(decided_by) = approval::operator_decider(&req.principal) else {
                return Err(permission_not_pending());
            };
            let Ok(mac) = approval::parse_input_mac(&req.input_mac) else {
                return Err(permission_not_pending());
            };
            if mac == InputMac([0; 32]) {
                return Err(permission_not_pending());
            }
            let a = match self
                .attempts
                .load_approval(req.workspace_id, req.approval_id)
                .await
            {
                Err(e) if approval_refusal(&e) => return Err(permission_not_pending()),
                r => r?,
            };
            if a.task_id != req.task_id || a.state != ApprovalState::Pending {
                return Err(permission_not_pending());
            }
            let Some(bridge) = &self.bridge else {
                return Err(permission_not_pending());
            };
            if bridge
                .pending_request(req.workspace_id, req.approval_id)
                .is_none()
            {
                return Err(permission_not_pending());
            }
            self.attempts
                .decide_permission(DecidePermissionRequest {
                    workspace_id: req.workspace_id,
                    approval_id: req.approval_id,
                    allow: req.allow,
                    input_mac: mac,
                    decided_by,
                })
                .await
                .map_err(|e| {
                    if approval_refusal(&e) {
                        permission_not_pending()
                    } else {
                        e
                    }
                })?;
            bridge.signal_decision(req.workspace_id, req.approval_id);
            Ok(())
        })
    }

    /// `RetryState` — the Retry gate of the Task cost cap (3j
    /// decisions 3 and 6).
    fn retry_state(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'_, Result<HarnessRetryState, Failure>> {
        Box::pin(async move { self.retry_state_inner(workspace_id, task_id).await })
    }

    /// `RunBudget` — the Run's chain budget within `ws`, or `None`
    /// when the Run has no harness attempt (3d decision 9, 3g
    /// decision 9).
    fn run_budget(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Option<HarnessRunBudget>, Failure>> {
        Box::pin(async move {
            if workspace_id.is_nil() || run_id.is_nil() {
                return Ok(None);
            }
            let attempts = self.attempts.attempts_for_run(workspace_id, run_id).await?;
            let Some(chain) = central_harness::budget::sum_chain(&attempts) else {
                return Ok(None);
            };
            let mut b = HarnessRunBudget {
                cost_micro_usd: chain.root.cost_micro_usd,
                wall_clock_seconds: chain.root.wall_clock.whole_seconds(),
                cost_defaulted: chain.root.cost_defaulted,
                wall_clock_defaulted: chain.root.wall_clock_defaulted,
                cost_used_micro_usd: chain.used_cost,
                attempts: chain.attempts as i32,
                ..HarnessRunBudget::default()
            };
            let mut latest = &attempts[0];
            for a in &attempts {
                if a.usage != central_harness::event::Usage::default() {
                    b.usage_reported = true;
                }
                // A live report carries cost 0 and cache read 0; a
                // result carries them, so either above 0 proves a
                // result arrived on some attempt of the chain (3m
                // decision 1).
                if a.usage.cost_micro_usd > 0 || a.usage.cache_read > 0 {
                    b.cost_reported = true;
                }
                b.tokens_in = saturating_add(b.tokens_in, a.usage.tokens_in);
                b.tokens_out = saturating_add(b.tokens_out, a.usage.tokens_out);
                b.cache_read = saturating_add(b.cache_read, a.usage.cache_read);
                b.cache_write = saturating_add(b.cache_write, a.usage.cache_write);
                b.estimated = b.estimated || a.usage.estimated;
                if a.prepared_at > latest.prepared_at
                    || (a.prepared_at == latest.prepared_at
                        && a.id.to_string() > latest.id.to_string())
                {
                    latest = a;
                }
            }
            b.succeeded = latest.state == State::Succeeded;
            b.cost_reported = b.cost_reported || b.succeeded;
            // IsTerminal excludes ambiguous, but an ambiguous attempt
            // has no session left to report through: it counts as
            // ended (decision 2).
            b.ended = latest.state.is_terminal() || latest.state == State::Ambiguous;
            Ok(Some(b))
        })
    }

    /// `PermissionPoliciesEnabled` — whether a Task may be submitted
    /// with a policy other than deny.
    fn permission_policies_enabled(&self) -> bool {
        self.policies_enabled
    }

    /// `HarnessBackend` — the configured backend id; always set.
    fn harness_backend(&self) -> &'static str {
        self.backend
    }

    /// `BudgetDefaults` — serve's default Run budget bounds.
    fn budget_defaults(&self) -> HarnessBudgetDefaults {
        self.budget_defaults.clone()
    }
}
