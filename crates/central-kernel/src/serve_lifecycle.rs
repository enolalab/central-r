//! Serve-side harness lifecycle adapters — the kernel port of upstream
//! `cmd/central/harness_lifecycle.go`, the Artifact half of
//! `harness_artifacts.go`, `harness_resume.go`'s `harnessResumeSource`
//! plus the `taskEligible`/`clampToTaskCostCap` helpers, and the
//! `app.ResolveStore` delegation.
//!
//! [`ServeRunLifecycle`] implements
//! [`central_harness::app::ports::RunLifecycle`] over the execution
//! application service: every Run, Step, StepAttempt and Task
//! transition is evaluated by the execution and task domains. It keeps
//! no state between calls: each command reads the authoritative
//! execution state first for its expected versions and identities.
//!
//! Upstream divergences:
//!
//! - `errors.As(err, &execution.Failure)` distinguishes domain
//!   refusals from infrastructure errors. Here both are [`Failure`];
//!   the adapter marks its infrastructure errors with `pg_*` codes, so
//!   the domain check is `!code.starts_with("pg_")`.
//! - `permanentFailure` marks every domain refusal "not worth
//!   retrying". The flat [`Failure`] has no permanent marker, but the
//!   orchestrator's `transient` refuses [`FailureKind::Invalid`]; a
//!   domain refusal is therefore re-wrapped as `Invalid` under its own
//!   code — same code, same permanence, upstream parity.
//! - The fresh read `CompleteWithReport` performs is not separately
//!   time-bounded: `begin_tx`'s `statement_timeout`/`lock_timeout`
//!   already bound every read.

use std::sync::Arc;

use central_artifact::app::MaterializeRequest;
use central_artifact::domain as artifact;
use central_execution::app::{ClaimResult, StartHarnessRunResult};
use central_execution::domain::{
    self as exec, Capability, Command, CommandEnvelope, EvaluationMetadata, ExecutionState,
    ExpectedVersions, LeaseCredential, TrustedScope,
};
use central_execution::harness_run as exec_run;
use central_execution::port::{
    CommitResult, CompletionChangeSetRequest, ExecutionReadRequest, ExecutionReadResult,
    RecordCompletionReceiptRequest,
};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{StepAttemptId, StepId};
use central_harness::app::ports::{
    self as ports, ArtifactOutcome, ArtifactOutcomeKind, ArtifactRole, ClaimedRun, DispatchableRun,
    FailureCode, RunLifecycle, Settlement, codes,
};
use central_harness::budget::Budget;
use central_harness::domain::PermissionPolicy;
use central_harness::port::PortFuture;
use central_task::domain as task;
use central_task::execution_facade::{self, ExecutionTransition};
use time::{Duration, OffsetDateTime};

/// `harnessPrincipal` — the executor principal of every command the
/// harness dispatcher issues.
pub const HARNESS_PRINCIPAL: &str = "harness-dispatcher";

/// `harnessResumePrompt` — the one continuation text a resumed session
/// receives (harness phase 3g decision 4).
const HARNESS_RESUME_PROMPT: &str =
    "Continue the task from where the previous run stopped. When finished, give the final report.";

/// `errSettleSucceededNotAllowed`'s code.
const SETTLE_SUCCEEDED_NOT_ALLOWED: &str = "harness_lifecycle_settle_succeeded_not_allowed";

/// `FailureCode::ARTIFACT_CAPTURE_FAILED`'s text, in `&'static str`
/// code positions of the [`Failure`]s this adapter itself produces.
const ARTIFACT_CAPTURE_FAILED: &str = "artifact_capture_failed";

// ---------------------------------------------------------------------------
// Failure classification (upstream classify / permanentFailure /
// notStartable / commandOutcome / cancelAware).
// ---------------------------------------------------------------------------

/// `leaseReasons` — the execution refusals that mean this process no
/// longer holds the Run's lease.
fn is_lease_reason(code: &str) -> bool {
    matches!(
        code,
        "STALE_LEASE_FENCE"
            | "LEASE_NOT_CURRENT"
            | "ACTIVE_LEASE_CONFLICT"
            | "LEASE_FENCE_REQUIRED"
            | "RECONCILIATION_REQUIRED"
    )
}

/// `errors.As(err, &execution.Failure)` — a domain refusal, not a
/// PostgreSQL adapter infrastructure failure (`pg_*` codes).
fn is_domain_failure(e: &Failure) -> bool {
    !e.code().starts_with("pg_")
}

/// `permanentFailure{err}` — the same code, marked permanent for the
/// orchestrator's `transient` by its `Invalid` kind.
fn permanent(e: Failure) -> Failure {
    Failure::invalid(e.code(), e.message().to_string())
}

/// `classify` maps an execution error of a lease-holding command.
fn classify(err: Failure) -> Failure {
    if is_domain_failure(&err) {
        if is_lease_reason(err.code()) {
            return Failure::conflict(
                codes::LEASE_LOST,
                format!("the lease was lost: {}", err.code()),
            );
        }
        return permanent(err);
    }
    err
}

/// `notStartable` — a domain refusal means another state won.
fn not_startable(err: Failure) -> Failure {
    if is_domain_failure(&err) {
        return Failure::new(
            FailureKind::Internal,
            codes::NOT_STARTABLE,
            format!("the run is not startable: {}", err.code()),
        );
    }
    err
}

/// `commandOutcome` maps the error of the claiming command itself: a
/// domain refusal wrote nothing; any other error may have committed.
fn command_outcome(err: Failure) -> Failure {
    if is_domain_failure(&err) {
        return not_startable(err);
    }
    Failure::internal(
        codes::START_OUTCOME_UNKNOWN,
        format!("the claim may have committed: {}", err.code()),
    )
}

/// `errCancelling`.
fn err_cancelling() -> Failure {
    Failure::cancelled(codes::CANCEL_REQUESTED, "the task is cancelling")
}

/// `errSettleSucceededNotAllowed` — a permanent refusal.
fn err_settle_succeeded() -> Failure {
    Failure::invalid(
        SETTLE_SUCCEEDED_NOT_ALLOWED,
        "harness lifecycle: a Run may settle succeeded only through CompleteWithReport",
    )
}

/// `cancelling` reports whether state's Task is cancelling.
fn cancelling(state: &ExecutionState) -> bool {
    state.task.task.status == task::TaskStatus::Cancelling
}

/// `nextGeneration`.
fn next_generation(state: &ExecutionState) -> i64 {
    state.lease.as_ref().map_or(1, |l| l.generation + 1)
}

/// `failureReason` maps an orchestrator code onto the bounded
/// execution vocabulary; an unknown code falls back to
/// `execution_failed`.
fn failure_reason(code: &FailureCode) -> exec::FailureReason {
    exec_run::FAILURE_REASONS
        .iter()
        .copied()
        .find(|r| *r == code.as_str())
        .unwrap_or(exec_run::FAILURE_REASON_EXECUTION_FAILED)
}

/// `settlementOutcome`.
fn settlement_outcome(
    s: &Settlement,
) -> Result<(exec::AttemptState, exec::FailureReason, Vec<u8>), Failure> {
    let (final_state, reason) = if s.succeeded {
        (exec::AttemptState::AttemptSucceeded, "")
    } else {
        (exec::AttemptState::AttemptFailed, failure_reason(&s.reason))
    };
    let outcome = exec_run::new_settlement_outcome(final_state, reason)?;
    Ok((final_state, reason, outcome))
}

/// `taskInstruction` — the `instruction` of the submitted
/// `repository_analysis/v1` input; "" when absent.
fn task_instruction(t: &task::Task) -> String {
    #[derive(serde::Deserialize)]
    struct Input {
        #[serde(default)]
        instruction: String,
    }
    serde_json::from_str::<Input>(&t.input)
        .map(|i| i.instruction)
        .unwrap_or_default()
}

/// `harnessPolicy` maps the Task's recorded permission policy onto the
/// harness policy the attempt runs under; anything else fails safe to
/// Deny.
fn harness_policy(p: task::PermissionPolicy) -> PermissionPolicy {
    match p {
        task::PermissionPolicy::Bridge => PermissionPolicy::Bridge,
        task::PermissionPolicy::AutoAllow => PermissionPolicy::AutoAllow,
        _ => PermissionPolicy::Deny,
    }
}

/// `clampToTaskCostCap` (harness phase 3j decision 4):
/// `min(perRun, max(cap - used, MIN_RESUME_COST))`.
#[must_use]
pub fn clamp_to_task_cost_cap(per_run: i64, cap_micro_usd: i64, used: i64) -> i64 {
    let used = used.max(0);
    per_run.min((cap_micro_usd - used).max(central_harness::budget::MIN_RESUME_COST_MICRO_USD))
}

/// `taskEligible` — the complement of the dispatcher's eligibility
/// filter (`task.created_at >= floor`, microsecond precision). A zero
/// floor is no guard.
#[must_use]
pub fn task_eligible(created: OffsetDateTime, floor: OffsetDateTime) -> bool {
    if floor == exec::ZERO_TIME {
        return true;
    }
    truncate_micros(created) >= truncate_micros(floor)
}

fn truncate_micros(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_nanosecond(t.nanosecond() / 1_000 * 1_000)
        .unwrap_or(t)
}

/// `harnessMeta` — the evaluation metadata of one lifecycle command.
/// `now`, the event id and the outbox id are freshly minted here; the
/// service stamps `meta.now` from its own clock.
fn harness_meta(key: String) -> EvaluationMetadata {
    EvaluationMetadata {
        principal_id: HARNESS_PRINCIPAL.to_string(),
        capability: Capability::Executor,
        idempotency_key: key.clone(),
        fingerprint: exec::new_request_fingerprint(key.as_bytes()),
        now: exec::ZERO_TIME,
        event_id: central_foundation::identity::ExecutionEventId::new(),
        outbox_id: central_foundation::identity::OutboxId::new(),
        producer_id: HARNESS_PRINCIPAL.to_string(),
    }
}

/// `harnessArtifactOperationID` — the stable operation identity of one
/// role's Artifact of one harness attempt:
/// `harness:<attempt-id>:<role>` (3b decision 12).
fn artifact_operation_id(attempt: StepAttemptId, role: ArtifactRole) -> Result<String, Failure> {
    let spec = artifact_spec(role)?;
    if attempt.is_nil() {
        return Err(Failure::invalid(
            ARTIFACT_CAPTURE_FAILED,
            "harness artifacts: no operation identity for a nil attempt",
        ));
    }
    let id = central_harness::recovery::attempt_id_for_step_attempt(attempt)?;
    Ok(format!("harness:{id}:{}", spec.short))
}

/// `harnessArtifactSpec` — one role's declared media type and size
/// limit (3b decisions 3 and 14).
struct ArtifactSpec {
    short: &'static str,
    media_type: &'static str,
    max_bytes: i64,
}

fn artifact_spec(role: ArtifactRole) -> Result<ArtifactSpec, Failure> {
    Ok(match role {
        ArtifactRole::Report => ArtifactSpec {
            short: "report",
            media_type: "text/markdown",
            max_bytes: artifact::DEFAULT_REQUIRED_REPORT_MAX_BYTES,
        },
        ArtifactRole::Patch => ArtifactSpec {
            short: "patch",
            media_type: "text/plain",
            max_bytes: artifact::HARD_REQUIRED_REPORT_MAX_BYTES,
        },
        ArtifactRole::Commits => ArtifactSpec {
            short: "commits",
            media_type: "text/plain",
            max_bytes: artifact::DEFAULT_REQUIRED_REPORT_MAX_BYTES,
        },
        _ => {
            return Err(Failure::invalid(
                ARTIFACT_CAPTURE_FAILED,
                format!(
                    "harness artifacts: no artifact spec for role {}",
                    role.as_str()
                ),
            ));
        }
    })
}

// ---------------------------------------------------------------------------
// The narrow surfaces the adapter drives (upstream's local interfaces:
// harnessExecutionCommands, harnessExecutionReads,
// harnessArtifactService, taskCostReader). Production impls are the
// execution `Service`, the postgres execution `Store`, the artifact
// `Service` and `PgHarnessStore`; tests substitute fakes.
// ---------------------------------------------------------------------------

/// `harnessExecutionCommands` — the execution application surface the
/// lifecycle drives.
pub trait HarnessExecutionCommands: Send + Sync + 'static {
    /// `Service::start_harness_run`.
    fn start_harness_run<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<StartHarnessRunResult, Failure>>;

    /// `Service::claim`.
    fn claim<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<ClaimResult, Failure>>;

    /// `Service::execute` — the shared commit pipeline for the
    /// envelope-only and settled commands.
    fn execute<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<CommitResult, Failure>>;

    /// `Service::validate_completion_change_set`.
    fn validate_completion_change_set<'a>(
        &'a self,
        request: CompletionChangeSetRequest,
    ) -> PortFuture<'a, Result<exec::ExecutionChangeSet, Failure>>;
}

impl<S, V, C, B> HarnessExecutionCommands for central_execution::app::Service<S, V, C, B>
where
    S: central_execution::port::CompositeExecutionStore + Sync + 'static,
    V: central_execution::port::LeaseCredentialValidator + Sync + 'static,
    C: central_execution::port::Clock + Sync + 'static,
    B: Send + Sync + 'static,
{
    fn start_harness_run<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<StartHarnessRunResult, Failure>> {
        Box::pin(async move { self.start_harness_run(command, meta).await })
    }

    fn claim<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<ClaimResult, Failure>> {
        Box::pin(async move { self.claim(command, meta).await })
    }

    fn execute<'a>(
        &'a self,
        command: Command,
        meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<CommitResult, Failure>> {
        Box::pin(async move { self.execute(command, meta).await })
    }

    fn validate_completion_change_set<'a>(
        &'a self,
        request: CompletionChangeSetRequest,
    ) -> PortFuture<'a, Result<exec::ExecutionChangeSet, Failure>> {
        Box::pin(async move { self.validate_completion_change_set(request).await })
    }
}

/// `harnessExecutionReads` — the execution read surface.
pub trait HarnessExecutionReads: Send + Sync + 'static {
    /// `DispatchableRunReader::list_dispatchable_runs`.
    fn list_dispatchable_runs<'a>(
        &'a self,
        request: exec_run::ListDispatchableRunsRequest,
    ) -> PortFuture<'a, Result<Vec<exec_run::DispatchableRun>, Failure>>;

    /// `ExecutionRead::read_execution`.
    fn read_execution<'a>(
        &'a self,
        request: ExecutionReadRequest,
    ) -> PortFuture<'a, Result<ExecutionReadResult, Failure>>;

    /// `CompletionReceiptStore::record_completion_receipt`.
    fn record_completion_receipt<'a>(
        &'a self,
        request: RecordCompletionReceiptRequest,
    ) -> PortFuture<'a, Result<(), Failure>>;
}

impl<T> HarnessExecutionReads for T
where
    T: central_execution::port::DispatchableRunReader
        + central_execution::port::ExecutionRead
        + central_execution::port::CompletionReceiptStore
        + Send
        + Sync
        + 'static,
{
    fn list_dispatchable_runs<'a>(
        &'a self,
        request: exec_run::ListDispatchableRunsRequest,
    ) -> PortFuture<'a, Result<Vec<exec_run::DispatchableRun>, Failure>> {
        Box::pin(async move {
            central_execution::port::DispatchableRunReader::list_dispatchable_runs(self, request)
                .await
        })
    }

    fn read_execution<'a>(
        &'a self,
        request: ExecutionReadRequest,
    ) -> PortFuture<'a, Result<ExecutionReadResult, Failure>> {
        Box::pin(async move {
            central_execution::port::ExecutionRead::read_execution(self, request).await
        })
    }

    fn record_completion_receipt<'a>(
        &'a self,
        request: RecordCompletionReceiptRequest,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            central_execution::port::CompletionReceiptStore::record_completion_receipt(
                self, request,
            )
            .await
        })
    }
}

/// `harnessArtifactService` — the B10 lifecycle surface the harness
/// uses; `artifact::app::Service` implements it.
pub trait HarnessArtifactService: Send + Sync + 'static {
    /// `Service::materialize_required_report`.
    fn materialize_required_report<'a>(
        &'a self,
        request: MaterializeRequest,
    ) -> PortFuture<'a, Result<artifact::Outcome, Failure>>;
}

impl<S, O, C, P, F> HarnessArtifactService for central_artifact::app::Service<S, O, C, P, F>
where
    S: central_artifact::port::Store,
    O: central_artifact::port::ObjectStore,
    C: central_artifact::port::Classifier,
    P: central_artifact::port::CompletionContributor,
    F: central_artifact::app::ObjectFailureClassifier,
{
    fn materialize_required_report<'a>(
        &'a self,
        request: MaterializeRequest,
    ) -> PortFuture<'a, Result<artifact::Outcome, Failure>> {
        Box::pin(async move { self.materialize_required_report(request).await })
    }
}

/// `taskCostReader` — the Task-wide recorded-cost read of the claim
/// clamp (harness phase 3j decision 4); `PgHarnessStore` implements it
/// through [`central_harness::query::BudgetUsageRead`].
pub trait TaskCostReader: Send + Sync + 'static {
    /// `CostForTask`.
    fn cost_for_task<'a>(
        &'a self,
        ws: central_foundation::identity::WorkspaceId,
        task: central_foundation::identity::TaskId,
    ) -> PortFuture<'a, Result<i64, Failure>>;
}

impl<T: central_harness::query::BudgetUsageRead> TaskCostReader for T {
    fn cost_for_task<'a>(
        &'a self,
        ws: central_foundation::identity::WorkspaceId,
        task: central_foundation::identity::TaskId,
    ) -> PortFuture<'a, Result<i64, Failure>> {
        Box::pin(async move {
            central_harness::query::BudgetUsageRead::cost_for_task(self, ws, task).await
        })
    }
}

/// `harnessAttemptStore`'s `AttemptsForRun` half — the chain-cost read
/// of `ResumeFrom` (harness phase 3d decision 9). `AttemptSummaryRead`
/// is not dyn compatible, so the kernel narrows it; `PgHarnessStore`
/// implements it.
pub trait RunChainRead: Send + Sync + 'static {
    /// `AttemptsForRun`.
    fn attempts_for_run<'a>(
        &'a self,
        workspace_id: central_foundation::identity::WorkspaceId,
        run: central_foundation::identity::RunId,
    ) -> PortFuture<'a, Result<Vec<central_harness::attempt::Attempt>, Failure>>;
}

impl<T: central_harness::query::AttemptSummaryRead> RunChainRead for T {
    fn attempts_for_run<'a>(
        &'a self,
        workspace_id: central_foundation::identity::WorkspaceId,
        run: central_foundation::identity::RunId,
    ) -> PortFuture<'a, Result<Vec<central_harness::attempt::Attempt>, Failure>> {
        Box::pin(async move {
            central_harness::query::AttemptSummaryRead::attempts_for_run(self, workspace_id, run)
                .await
        })
    }
}

/// `harnessBudgetDefaults` — serve's default Run budget bounds
/// (`CENTRAL_HARNESS_MAX_COST_USD` and `CENTRAL_HARNESS_WALL_CLOCK`).
/// A zero default leaves the bound to the orchestrator's own default.
#[derive(Debug, Clone, Copy, Default)]
pub struct HarnessBudgetDefaults {
    /// `CENTRAL_HARNESS_MAX_COST_USD` in micro-USD.
    pub cost_micro_usd: i64,
    /// `CENTRAL_HARNESS_WALL_CLOCK`.
    pub wall_clock: Duration,
}

// ---------------------------------------------------------------------------
// ServeRunLifecycle — upstream `harnessLifecycle`.
// ---------------------------------------------------------------------------

/// `harnessLifecycle` — the kernel-side [`RunLifecycle`] over the
/// execution application service, the execution read surface and the
/// B10 artifact service.
pub struct ServeRunLifecycle {
    commands: Arc<dyn HarnessExecutionCommands>,
    reads: Arc<dyn HarnessExecutionReads>,
    artifacts: Arc<dyn HarnessArtifactService>,
    eligible_after: OffsetDateTime,
    budget_defaults: HarnessBudgetDefaults,
    /// The Task cost cap (harness phase 3j decision 4): a `None` reader
    /// or a non-positive cap reads nothing and clamps nothing.
    task_costs: Option<Arc<dyn TaskCostReader>>,
    task_cost_cap_micro_usd: i64,
}

impl ServeRunLifecycle {
    /// `newHarnessLifecycle`.
    pub fn new(
        commands: Arc<dyn HarnessExecutionCommands>,
        reads: Arc<dyn HarnessExecutionReads>,
        artifacts: Arc<dyn HarnessArtifactService>,
        eligible_after: OffsetDateTime,
    ) -> Self {
        Self {
            commands,
            reads,
            artifacts,
            eligible_after,
            budget_defaults: HarnessBudgetDefaults::default(),
            task_costs: None,
            task_cost_cap_micro_usd: 0,
        }
    }

    /// Installs the serve budget defaults and the Task cost cap the
    /// claim clamp reads (upstream's struct fields set by composition).
    #[must_use]
    pub fn with_budget(
        mut self,
        defaults: HarnessBudgetDefaults,
        task_costs: Option<Arc<dyn TaskCostReader>>,
        task_cost_cap_micro_usd: i64,
    ) -> Self {
        self.budget_defaults = defaults;
        self.task_costs = task_costs;
        self.task_cost_cap_micro_usd = task_cost_cap_micro_usd;
        self
    }

    /// `l.scope(ws)`.
    fn scope(ws: central_foundation::identity::WorkspaceId) -> Result<TrustedScope, Failure> {
        TrustedScope::new(HARNESS_PRINCIPAL, ws, &[Capability::Executor])
    }

    /// `l.read` — the authoritative state load every command performs
    /// first.
    async fn read(
        &self,
        ws: central_foundation::identity::WorkspaceId,
        task_id: central_foundation::identity::TaskId,
        run: central_foundation::identity::RunId,
        step: StepId,
        attempt: StepAttemptId,
    ) -> Result<(TrustedScope, ExecutionState), Failure> {
        let scope = Self::scope(ws)?;
        let got = self
            .reads
            .read_execution(ExecutionReadRequest {
                scope: scope.clone(),
                workspace_id: ws,
                task_id,
                run_id: run,
                step_id: step,
                attempt_id: attempt,
            })
            .await?;
        Ok((scope, got.state))
    }

    /// `l.taskCostUsed` — a zero cap or a `None` reader reads nothing.
    /// A read error is returned as is: it is neither `NOT_STARTABLE`
    /// nor `START_OUTCOME_UNKNOWN`, so the dispatcher cools the Run
    /// down and tries again later.
    async fn task_cost_used(
        &self,
        ws: central_foundation::identity::WorkspaceId,
        task_id: central_foundation::identity::TaskId,
    ) -> Result<i64, Failure> {
        match &self.task_costs {
            None => Ok(0),
            Some(costs) if self.task_cost_cap_micro_usd > 0 => {
                costs.cost_for_task(ws, task_id).await.map_err(|e| {
                    Failure::unavailable(
                        "harness_task_cost_read",
                        format!("harness claim: read the task's recorded cost: {}", e.code()),
                    )
                })
            }
            Some(_) => Ok(0),
        }
    }

    /// `l.harnessBudget` resolves a claimed Run's effective budget
    /// (harness phase 3d decision 4 + 3j decision 4).
    fn harness_budget(&self, requested: task::Budget, used: i64) -> Budget {
        let mut b = Budget {
            cost_micro_usd: requested.cost_micro_usd,
            wall_clock: Duration::seconds(i64::from(requested.wall_clock_seconds)),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        };
        if b.cost_micro_usd == 0 {
            b.cost_micro_usd = self.budget_defaults.cost_micro_usd;
            b.cost_defaulted = true;
        }
        if b.wall_clock == Duration::ZERO {
            b.wall_clock = Duration::seconds(self.budget_defaults.wall_clock.whole_seconds());
            b.wall_clock_defaulted = true;
        }
        // A zero cost is left to the orchestrator's own default.
        if self.task_cost_cap_micro_usd > 0 && b.cost_micro_usd > 0 {
            b.cost_micro_usd =
                clamp_to_task_cost_cap(b.cost_micro_usd, self.task_cost_cap_micro_usd, used);
        }
        b
    }

    /// `l.envelope` — the fenced executor envelope from the current
    /// authoritative state.
    async fn envelope(
        &self,
        run: &ClaimedRun,
    ) -> Result<(CommandEnvelope, ExecutionState), Failure> {
        let (scope, state) = self
            .read(
                run.workspace_id,
                run.task_id,
                run.run_id,
                run.step_id,
                run.step_attempt_id,
            )
            .await
            .map_err(classify)?;
        let (Some(step), Some(attempt), Some(current_run)) =
            (&state.step, &state.attempt, &state.task.current_run)
        else {
            return Err(Failure::conflict(codes::LEASE_LOST, "attempt is gone"));
        };
        let envelope = CommandEnvelope {
            scope,
            workspace_id: run.workspace_id,
            task_id: run.task_id,
            run_id: run.run_id,
            step_id: run.step_id,
            attempt_id: run.step_attempt_id,
            logical_operation: attempt.logical_operation_id,
            expected: ExpectedVersions {
                task: state.task.task.version,
                run: current_run.version,
                step: step.version,
                attempt: attempt.version,
                ..ExpectedVersions::default()
            },
            operation_digest: exec::RequestFingerprint::default(),
            lease_credential: LeaseCredential(run.lease.credential),
            lease_generation: run.lease.generation,
            assert_no_active_lease: false,
            // Caller-side hint — `commit` replaces it with the
            // authoritative read before evaluation.
            state: state.clone(),
        };
        Ok((envelope, state))
    }

    /// `l.cancelAware` maps a refused command to `CANCEL_REQUESTED`
    /// when the Task became cancelling meanwhile; any other error is
    /// classified as usual.
    async fn cancel_aware(&self, run: &ClaimedRun, err: Option<Failure>) -> Result<(), Failure> {
        let Some(err) = err else { return Ok(()) };
        if !is_domain_failure(&err) || is_lease_reason(err.code()) {
            return Err(classify(err));
        }
        if let Ok((_, state)) = self
            .read(
                run.workspace_id,
                run.task_id,
                run.run_id,
                run.step_id,
                run.step_attempt_id,
            )
            .await
            && cancelling(&state)
        {
            return Err(err_cancelling());
        }
        Err(classify(err))
    }

    /// `startQueued` — the fused `StartHarnessRun` claim.
    async fn start_queued(&self, run: &DispatchableRun) -> Result<ClaimedRun, Failure> {
        let (scope, state) = self
            .read(
                run.workspace_id,
                run.task_id,
                run.run_id,
                StepId::from_trusted_db_bytes([0u8; 16]),
                StepAttemptId::from_trusted_db_bytes([0u8; 16]),
            )
            .await
            .map_err(not_startable)?;
        let Some(current_run) = &state.task.current_run else {
            return Err(Failure::internal(
                codes::NOT_STARTABLE,
                "run is not the task's current run",
            ));
        };
        if current_run.id != run.run_id {
            return Err(Failure::internal(
                codes::NOT_STARTABLE,
                "run is not the task's current run",
            ));
        }
        // Before the command, which commits the lease (harness phase
        // 3j decision 4): a failed read leaves the Run queued and
        // untouched.
        let used = self.task_cost_used(run.workspace_id, run.task_id).await?;
        let (step, attempt) = (StepId::new(), StepAttemptId::new());
        let command = Command::StartHarnessRun(exec_run::StartHarnessRunCommand {
            envelope: CommandEnvelope {
                scope,
                workspace_id: run.workspace_id,
                task_id: run.task_id,
                run_id: run.run_id,
                step_id: step,
                attempt_id: attempt,
                logical_operation: exec::LogicalOperationId::new(),
                expected: ExpectedVersions {
                    task: state.task.task.version,
                    run: current_run.version,
                    ..ExpectedVersions::default()
                },
                operation_digest: exec::RequestFingerprint::default(),
                lease_credential: LeaseCredential::default(),
                lease_generation: next_generation(&state),
                assert_no_active_lease: false,
                state: state.clone(),
            },
            physical_attempt_id: exec::PhysicalAttemptId::new(),
            step_sequence: 1,
            attempt_sequence: 1,
        });
        let res = self
            .commands
            .start_harness_run(command, harness_meta(format!("harness:start:{attempt}")))
            .await
            .map_err(command_outcome)?;
        if !res.lease_credential.valid() {
            return Err(Failure::internal(
                codes::NOT_STARTABLE,
                "start replayed without a lease",
            ));
        }
        Ok(ClaimedRun {
            workspace_id: run.workspace_id,
            task_id: run.task_id,
            run_id: run.run_id,
            step_id: step,
            step_attempt_id: attempt,
            prompt: task_instruction(&state.task.task),
            permission: harness_policy(state.task.task.permission_policy),
            budget: self.harness_budget(state.task.task.budget, used),
            lease: central_harness::port::ExecutionLease {
                generation: res.lease_generation,
                credential: res.lease_credential.0,
            },
        })
    }

    /// `claimSuccessor` — the `Claim` of a B08 prepared successor.
    async fn claim_successor(&self, run: &DispatchableRun) -> Result<ClaimedRun, Failure> {
        let (scope, state) = self
            .read(
                run.workspace_id,
                run.task_id,
                run.run_id,
                run.step_id,
                run.step_attempt_id,
            )
            .await
            .map_err(not_startable)?;
        let (Some(step), Some(attempt), Some(current_run)) =
            (&state.step, &state.attempt, &state.task.current_run)
        else {
            return Err(Failure::internal(
                codes::NOT_STARTABLE,
                "the prepared successor moved on",
            ));
        };
        if attempt.id != run.step_attempt_id || attempt.state != exec::AttemptState::AttemptPrepared
        {
            return Err(Failure::internal(
                codes::NOT_STARTABLE,
                "the prepared successor moved on",
            ));
        }
        // Before the Claim command, as in start_queued (3j decision
        // 4). A successor prepared fresh after a crash (sequence 1)
        // records this clamped budget; a resumed attempt (sequence >
        // 1) ignores it and keeps its chain's budget, so it reads no
        // cost and a read failure cannot fail its claim.
        let mut used = 0;
        if step.sequence <= 1 {
            used = self.task_cost_used(run.workspace_id, run.task_id).await?;
        }
        let generation = next_generation(&state);
        let command = Command::Claim(exec::ClaimCommand {
            envelope: CommandEnvelope {
                scope,
                workspace_id: run.workspace_id,
                task_id: run.task_id,
                run_id: run.run_id,
                step_id: run.step_id,
                attempt_id: run.step_attempt_id,
                logical_operation: attempt.logical_operation_id,
                expected: ExpectedVersions {
                    task: state.task.task.version,
                    run: current_run.version,
                    step: step.version,
                    attempt: attempt.version,
                    ..ExpectedVersions::default()
                },
                operation_digest: exec::RequestFingerprint::default(),
                lease_credential: LeaseCredential::default(),
                lease_generation: generation,
                assert_no_active_lease: false,
                state: state.clone(),
            },
        });
        let res = self
            .commands
            .claim(
                command,
                harness_meta(format!(
                    "harness:claim:{}:{generation}",
                    run.step_attempt_id
                )),
            )
            .await
            .map_err(command_outcome)?;
        if !res.lease_credential.valid() {
            return Err(Failure::internal(
                codes::NOT_STARTABLE,
                "claim replayed without a lease",
            ));
        }
        Ok(ClaimedRun {
            workspace_id: run.workspace_id,
            task_id: run.task_id,
            run_id: run.run_id,
            step_id: run.step_id,
            step_attempt_id: run.step_attempt_id,
            prompt: task_instruction(&state.task.task),
            permission: harness_policy(state.task.task.permission_policy),
            budget: self.harness_budget(state.task.task.budget, used),
            lease: central_harness::port::ExecutionLease {
                generation,
                credential: res.lease_credential.0,
            },
        })
    }
}

/// `completedBy` — the fresh-read proof that the completing commit
/// landed.
fn completed_by(state: &ExecutionState, run: &ClaimedRun) -> bool {
    state.attempt.as_ref().is_some_and(|a| {
        a.id == run.step_attempt_id && a.state == exec::AttemptState::AttemptSucceeded
    }) && state
        .task
        .current_run
        .as_ref()
        .is_some_and(|r| r.id == run.run_id)
        && state.task.task.status == task::TaskStatus::Completed
}

/// `harnessCompletionCandidate` — the success settle candidate of the
/// invoked attempt, built as B09's `CompletionChangeSet` builds it.
fn completion_candidate(
    envelope: &CommandEnvelope,
    state: &ExecutionState,
    now: OffsetDateTime,
) -> Result<exec::ExecutionChangeSet, Failure> {
    let (Some(step), Some(attempt), Some(current_run)) =
        (&state.step, &state.attempt, &state.task.current_run)
    else {
        return Err(Failure::invalid(
            ARTIFACT_CAPTURE_FAILED,
            "harness completion: the invoked attempt is unavailable",
        ));
    };
    if attempt.invocation_id.is_nil() {
        return Err(Failure::invalid(
            ARTIFACT_CAPTURE_FAILED,
            "harness completion: the invoked attempt is unavailable",
        ));
    }
    let mut next_attempt = attempt.clone();
    next_attempt.state = exec::AttemptState::AttemptSucceeded;
    next_attempt.version += 1;
    let mut next_step = step.clone();
    next_step.state = exec::StepState::StepSucceeded;
    next_step.version += 1;
    let outcome = exec_run::new_settlement_outcome(exec::AttemptState::AttemptSucceeded, "")?;
    let transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::Complete(execution_facade::ExecutionCompleteRequest {
            aggregate: state.task.clone(),
            now,
            expected_task_version: state.task.task.version,
            expected_run_version: current_run.version,
        }),
    )
    .map_err(|e| {
        Failure::invalid(
            ARTIFACT_CAPTURE_FAILED,
            format!("harness completion Task transition: {}", e.code()),
        )
    })?;
    exec::build_execution_change_set(exec::ExecutionChangeSet {
        steps: vec![next_step],
        attempts: vec![next_attempt.clone()],
        settlements: vec![exec::Settlement {
            workspace_id: next_attempt.workspace_id,
            task_id: next_attempt.task_id,
            run_id: next_attempt.run_id,
            step_id: next_attempt.step_id,
            attempt_id: next_attempt.id,
            invocation_id: next_attempt.invocation_id,
            final_state: exec::AttemptState::AttemptSucceeded,
            outcome,
            context: Vec::new(),
            settled_at: now,
        }],
        lease_releases: vec![exec::LeaseRelease {
            workspace_id: next_attempt.workspace_id,
            run_id: next_attempt.run_id,
            credential: envelope.lease_credential,
            generation: envelope.lease_generation,
        }],
        task_transition: Some(transition),
        ..exec::ExecutionChangeSet::new()
    })
}

impl RunLifecycle for ServeRunLifecycle {
    /// `ListDispatchable` — up to `limit` dispatchable Runs, oldest
    /// Task first.
    fn list_dispatchable<'a>(
        &'a self,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<DispatchableRun>, Failure>> {
        Box::pin(async move {
            let limit = (limit as u32).min(exec_run::MAX_DISPATCHABLE_RUNS_LIMIT);
            let runs = self
                .reads
                .list_dispatchable_runs(exec_run::ListDispatchableRunsRequest {
                    limit,
                    eligible_after: self.eligible_after,
                })
                .await?;
            Ok(runs
                .into_iter()
                .map(|r| DispatchableRun {
                    case: match r.case {
                        exec_run::DispatchCase::DispatchQueued => ports::DispatchCase::Queued,
                        _ => ports::DispatchCase::PreparedSuccessor,
                    },
                    workspace_id: r.workspace_id,
                    task_id: r.task_id,
                    run_id: r.run_id,
                    step_id: r.step_id,
                    step_attempt_id: r.attempt_id,
                })
                .collect())
        })
    }

    /// `Start` — the fused claim of a dispatchable Run.
    fn start<'a>(&'a self, run: DispatchableRun) -> PortFuture<'a, Result<ClaimedRun, Failure>> {
        Box::pin(async move {
            match run.case {
                ports::DispatchCase::Queued => self.start_queued(&run).await,
                ports::DispatchCase::PreparedSuccessor => self.claim_successor(&run).await,
                _ => Err(Failure::internal(
                    codes::NOT_STARTABLE,
                    format!("unknown dispatch case {}", run.case.as_str()),
                )),
            }
        })
    }

    /// `Heartbeat` — extends the lease and reports whether the Task is
    /// cancelling (review T-I1): the lease is kept alive until the
    /// cancellation is settled.
    fn heartbeat<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            let (envelope, state) = self.envelope(&run).await?;
            let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
            let err = self
                .commands
                .execute(
                    Command::Heartbeat(exec::HeartbeatCommand { envelope }),
                    harness_meta(format!("harness:heartbeat:{}:{nanos}", run.step_attempt_id)),
                )
                .await
                .err();
            match err {
                Some(e) => Err(classify(e)),
                None => Ok(state.task.task.status == task::TaskStatus::Cancelling),
            }
        })
    }

    /// `MarkInvoked`.
    fn mark_invoked<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let (envelope, state) = self.envelope(&run).await?;
            if cancelling(&state) {
                return Err(err_cancelling());
            }
            let err = self
                .commands
                .execute(
                    Command::MarkInvoked(exec::MarkInvokedCommand {
                        envelope,
                        invocation_id: exec::InvocationId::new(),
                        approval_subject_version: 0,
                        approval_expected_step_version: 0,
                    }),
                    harness_meta(format!("harness:invoke:{}", run.step_attempt_id)),
                )
                .await
                .err();
            self.cancel_aware(&run, err).await
        })
    }

    /// `AbandonPrepared`.
    fn abandon_prepared<'a>(
        &'a self,
        run: ClaimedRun,
        reason: FailureCode,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let (envelope, state) = self.envelope(&run).await?;
            if cancelling(&state) {
                return Err(err_cancelling());
            }
            let err = self
                .commands
                .execute(
                    Command::AbandonPrepared(exec_run::AbandonPreparedCommand {
                        envelope,
                        reason_code: failure_reason(&reason),
                    }),
                    harness_meta(format!("harness:abandon:{}", run.step_attempt_id)),
                )
                .await
                .err();
            self.cancel_aware(&run, err).await
        })
    }

    /// `RecordCompletion` — the execution completion receipt for a
    /// failed settlement; success is refused outright (3b decision 2).
    fn record_completion<'a>(
        &'a self,
        run: ClaimedRun,
        outcome: Settlement,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if outcome.succeeded {
                return Err(err_settle_succeeded());
            }
            let (final_state, _reason, outcome_payload) =
                settlement_outcome(&outcome).map_err(permanent)?;
            let (envelope, state) = self.envelope(&run).await?;
            if cancelling(&state) {
                return Err(err_cancelling());
            }
            let Some(attempt) = state.attempt.as_ref() else {
                return Err(Failure::conflict(codes::LEASE_LOST, "attempt is gone"));
            };
            self.reads
                .record_completion_receipt(RecordCompletionReceiptRequest {
                    scope: envelope.scope,
                    receipt: exec_run::CompletionReceipt {
                        workspace_id: run.workspace_id,
                        task_id: run.task_id,
                        run_id: run.run_id,
                        step_id: run.step_id,
                        attempt_id: run.step_attempt_id,
                        logical_operation_id: attempt.logical_operation_id,
                        physical_attempt_id: attempt.physical_attempt_id,
                        invocation_id: attempt.invocation_id,
                        invocation_generation: 1,
                        final_state,
                        outcome: outcome_payload,
                        context: Vec::new(),
                        b09_references: Vec::new(),
                        producer_id: HARNESS_PRINCIPAL.to_string(),
                    },
                    lease_credential: envelope.lease_credential,
                    lease_generation: envelope.lease_generation,
                })
                .await
                .map_err(classify)
        })
    }

    /// `Settle` — settles the invoked attempt and ends the Run and
    /// Task. Success is refused outright.
    fn settle<'a>(
        &'a self,
        run: ClaimedRun,
        outcome: Settlement,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if outcome.succeeded {
                return Err(err_settle_succeeded());
            }
            let (final_state, reason, outcome_payload) =
                settlement_outcome(&outcome).map_err(permanent)?;
            let (envelope, state) = self.envelope(&run).await?;
            if cancelling(&state) {
                return Err(err_cancelling());
            }
            let err = self
                .commands
                .execute(
                    Command::Settle(exec::SettleCommand {
                        envelope,
                        final_state,
                        outcome: outcome_payload,
                        context: Vec::new(),
                        reason_code: reason,
                    }),
                    harness_meta(format!("harness:settle:{}", run.step_attempt_id)),
                )
                .await
                .err();
            self.cancel_aware(&run, err).await
        })
    }

    /// `SettleCancellation` — ends the cancelling Task and its Run
    /// cancelled and releases the lease.
    fn settle_cancellation<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let (envelope, state) = self.envelope(&run).await?;
            let Some(attempt) = state.attempt.as_ref() else {
                return Err(Failure::conflict(codes::LEASE_LOST, "attempt is gone"));
            };
            self.commands
                .execute(
                    Command::SettleCancellation(exec_run::SettleCancellationCommand {
                        envelope,
                        executor_stopped: attempt.state != exec::AttemptState::AttemptPrepared,
                    }),
                    harness_meta(format!("harness:cancel:{}", run.step_attempt_id)),
                )
                .await
                .map_err(classify)?;
            Ok(())
        })
    }

    /// `CompleteWithReport` — the only way a harness Run succeeds
    /// (3b decisions 2 and 8). No completion receipt is written. After
    /// an error or a not-ready outcome, a fresh read that finds the
    /// StepAttempt succeeded and the Task completed proves the
    /// completing commit landed.
    fn complete_with_report<'a>(
        &'a self,
        run: ClaimedRun,
        report: Vec<u8>,
    ) -> PortFuture<'a, Result<ArtifactOutcome, Failure>> {
        Box::pin(async move {
            let (envelope, state) = self.envelope(&run).await?;
            if cancelling(&state) {
                return Err(err_cancelling());
            }
            let candidate = completion_candidate(&envelope, &state, OffsetDateTime::now_utc())
                .map_err(permanent)?;
            let validated = match self
                .commands
                .validate_completion_change_set(CompletionChangeSetRequest {
                    scope: envelope.scope.clone(),
                    workspace_id: run.workspace_id,
                    task_id: run.task_id,
                    run_id: run.run_id,
                    step_id: run.step_id,
                    attempt_id: run.step_attempt_id,
                    change_set: candidate,
                })
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return self
                        .cancel_aware(&run, Some(e))
                        .await
                        .map(|_| ArtifactOutcome::default());
                }
            };
            let (outcome, err) = match self
                .materialize(&run, ArtifactRole::Report, report, validated)
                .await
            {
                Ok(outcome) => (outcome, None),
                Err(e) => (ArtifactOutcome::default(), Some(e)),
            };
            if err.is_none() && outcome.kind == ArtifactOutcomeKind::Ready {
                return Ok(outcome);
            }
            // A fresh read: an attempt that succeeded and a Task that
            // completed prove the completing commit landed (the commit
            // is the only path that completes a harness Run).
            if let Ok((_, fresh)) = self
                .read(
                    run.workspace_id,
                    run.task_id,
                    run.run_id,
                    run.step_id,
                    run.step_attempt_id,
                )
                .await
            {
                if cancelling(&fresh) {
                    return Err(err_cancelling());
                }
                if completed_by(&fresh, &run) {
                    return Ok(ArtifactOutcome {
                        kind: ArtifactOutcomeKind::Ready,
                        reason: FailureCode::default(),
                    });
                }
            }
            match err {
                Some(e) => Err(e),
                None => Ok(outcome),
            }
        })
    }

    /// `Reconcile` — moves the invoked attempt into B08 reconciliation
    /// and releases the lease.
    fn reconcile<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let (envelope, state) = self.envelope(&run).await?;
            if cancelling(&state) {
                return Err(err_cancelling());
            }
            let err = self
                .commands
                .execute(
                    Command::EnterReconciliation(exec::EnterReconciliationCommand {
                        envelope,
                        reason_code: exec::ProviderReconciliationReason::HandoffFailed,
                    }),
                    harness_meta(format!("harness:reconcile:{}", run.step_attempt_id)),
                )
                .await
                .err();
            self.cancel_aware(&run, err).await
        })
    }
}

impl ServeRunLifecycle {
    /// `harnessArtifacts{service: l.artifacts}.materialize` — the
    /// report's materialization on the same B10 surface.
    async fn materialize(
        &self,
        run: &ClaimedRun,
        role: ArtifactRole,
        body: Vec<u8>,
        completion: exec::ExecutionChangeSet,
    ) -> Result<ArtifactOutcome, Failure> {
        materialize(&*self.artifacts, run, role, body, completion).await
    }
}

// ---------------------------------------------------------------------------
// ServeArtifactSink — upstream `harnessArtifacts`.
// ---------------------------------------------------------------------------

/// `harnessArtifacts` — the orchestrator's [`ports::ArtifactSink`]
/// over B10.
pub struct ServeArtifactSink {
    service: Arc<dyn HarnessArtifactService>,
}

impl ServeArtifactSink {
    /// Binds the sink to the composed artifact service.
    pub fn new(service: Arc<dyn HarnessArtifactService>) -> Self {
        Self { service }
    }
}

/// `materialize` drives one role's Artifact through the B10 lifecycle
/// under its stable operation identity, with the role's limit and
/// declared media type, and maps the outcome onto the orchestrator's
/// bounded vocabulary.
async fn materialize(
    service: &dyn HarnessArtifactService,
    run: &ClaimedRun,
    role: ArtifactRole,
    body: Vec<u8>,
    completion: exec::ExecutionChangeSet,
) -> Result<ArtifactOutcome, Failure> {
    let spec = artifact_spec(role)?;
    let op = artifact_operation_id(run.step_attempt_id, role)?;
    let (artifact_id, staging) = artifact::derive_reservation_identity(&op)?;
    let outcome = match service
        .materialize_required_report(MaterializeRequest {
            workspace_id: run.workspace_id,
            task_id: run.task_id,
            run_id: run.run_id,
            step_id: run.step_id,
            step_attempt_id: run.step_attempt_id,
            tool_call_attempt_id: None,
            producer_id: HARNESS_PRINCIPAL.to_string(),
            required_role: role.as_str().to_string(),
            limits: artifact::Limits {
                max_bytes: spec.max_bytes,
            },
            declared_media_type: spec.media_type.to_string(),
            body: Some(Box::new(std::io::Cursor::new(body))),
            operation_id: op,
            artifact_id: Some(artifact_id),
            staging_generation: Some(staging),
            completion,
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => match artifact_error(e) {
            ArtifactOrOutcome::Outcome(o) => return Ok(o),
            ArtifactOrOutcome::Err(e) => return Err(e),
        },
    };
    Ok(artifact_outcome(outcome))
}

/// `harnessArtifactError` classifies a B10 error. A quota refusal is a
/// certain, bounded failure: the store refused it inside the
/// transaction, so nothing was reserved or committed — it surfaces as
/// a `Terminal` outcome, not an error. A lease-fence refusal means
/// another holder owns the Run: the lease is lost. Every other error
/// is unclassified and the orchestrator reconciles.
fn artifact_error(err: Failure) -> ArtifactOrOutcome {
    if is_domain_failure(&err) {
        if err.code() == "QUOTA_EXCEEDED" {
            return ArtifactOrOutcome::Outcome(ArtifactOutcome {
                kind: ArtifactOutcomeKind::Terminal,
                reason: FailureCode::ARTIFACT_QUOTA_EXCEEDED,
            });
        }
        if is_lease_reason(err.code()) {
            return ArtifactOrOutcome::Err(Failure::conflict(
                codes::LEASE_LOST,
                format!("the lease was lost: {}", err.code()),
            ));
        }
    }
    ArtifactOrOutcome::Err(err)
}

/// Internal either for [`materialize`]'s error classification.
enum ArtifactOrOutcome {
    Outcome(ArtifactOutcome),
    Err(Failure),
}

/// `harnessArtifactOutcome` maps a B10 outcome (3b decision 8): ready
/// and reconciliation carry over; a terminal or retryable outcome
/// fails the Run with the reason its closed failure code names.
fn artifact_outcome(o: artifact::Outcome) -> ArtifactOutcome {
    match o.kind {
        artifact::OutcomeKind::Ready => ArtifactOutcome {
            kind: ArtifactOutcomeKind::Ready,
            reason: FailureCode::default(),
        },
        artifact::OutcomeKind::Reconciliation => ArtifactOutcome {
            kind: ArtifactOutcomeKind::Reconciliation,
            reason: FailureCode::default(),
        },
        artifact::OutcomeKind::Terminal | artifact::OutcomeKind::Retryable => {
            let kind = if o.kind == artifact::OutcomeKind::Retryable {
                ArtifactOutcomeKind::Retryable
            } else {
                ArtifactOutcomeKind::Terminal
            };
            ArtifactOutcome {
                kind,
                reason: artifact_reason(&o.failure_code),
            }
        }
    }
}

/// `harnessArtifactReason`.
fn artifact_reason(code: &str) -> FailureCode {
    match code {
        artifact::FAILURE_CODE_SECRET_DISCLOSURE
        | artifact::FAILURE_CODE_CONTENT_POLICY
        | artifact::FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE => FailureCode::ARTIFACT_REJECTED,
        artifact::FAILURE_CODE_SIZE_LIMIT_EXCEEDED => FailureCode::ARTIFACT_TOO_LARGE,
        "QUOTA_EXCEEDED" => FailureCode::ARTIFACT_QUOTA_EXCEEDED,
        _ => FailureCode::ARTIFACT_CAPTURE_FAILED,
    }
}

impl ports::ArtifactSink for ServeArtifactSink {
    /// `Store` — materializes one supporting Artifact (the patch or
    /// the commits) from its capture temp file, ready in its own
    /// commit with an empty execution change set: no Task transition
    /// (decision 2).
    fn store<'a>(
        &'a self,
        run: ClaimedRun,
        role: ArtifactRole,
        body: String,
    ) -> PortFuture<'a, Result<ArtifactOutcome, Failure>> {
        Box::pin(async move {
            if role != ArtifactRole::Patch && role != ArtifactRole::Commits {
                return Err(Failure::invalid(
                    ARTIFACT_CAPTURE_FAILED,
                    format!(
                        "harness artifacts: {} is not a supporting role",
                        role.as_str()
                    ),
                ));
            }
            let bytes = match std::fs::read(&body) {
                Ok(b) => b,
                Err(_) => {
                    // Nothing was reserved: the capture file is gone
                    // or unreadable.
                    return Ok(ArtifactOutcome {
                        kind: ArtifactOutcomeKind::Terminal,
                        reason: FailureCode::ARTIFACT_CAPTURE_FAILED,
                    });
                }
            };
            materialize(
                &*self.service,
                &run,
                role,
                bytes,
                exec::ExecutionChangeSet::new(),
            )
            .await
        })
    }
}

// ---------------------------------------------------------------------------
// ServeResumeSource — upstream `harnessResumeSource` (3g decision 5).
// ---------------------------------------------------------------------------

/// `harnessResumeSource` — the orchestrator's [`ports::ResumeSource`]
/// keyed on the CLAIMED StepAttempt, never the Run's latest harness
/// row.
pub struct ServeResumeSource {
    reads: Arc<dyn HarnessExecutionReads>,
    attempts: Arc<dyn central_harness::port::AttemptStore>,
    summaries: Arc<dyn RunChainRead>,
    resolver: Arc<central_harness::app::reconciler::Resolver>,
}

impl ServeResumeSource {
    /// Binds the source to its stores and the recovery authority.
    pub fn new(
        reads: Arc<dyn HarnessExecutionReads>,
        attempts: Arc<dyn central_harness::port::AttemptStore>,
        summaries: Arc<dyn RunChainRead>,
        resolver: Arc<central_harness::app::reconciler::Resolver>,
    ) -> Self {
        Self {
            reads,
            attempts,
            summaries,
            resolver,
        }
    }

    /// `heal` completes the predecessor row's lost resolved(resume)
    /// write (3g decision 6) and reloads it. `None` when the row does
    /// not exist (any more). A row another writer moved on meanwhile
    /// (`RESUME_NOT_ALLOWED`) is reloaded and judged as it now is; any
    /// other failure, a refusal of the recovery authority included, is
    /// an error.
    async fn heal(
        &self,
        ws: central_foundation::identity::WorkspaceId,
        pred: StepAttemptId,
        pred_id: central_foundation::identity::HarnessAttemptId,
    ) -> Result<Option<central_harness::attempt::Attempt>, Failure> {
        use central_harness::domain::codes as hcodes;
        match self
            .resolver
            .complete_resume(
                ws,
                pred,
                central_harness::app::reconciler::DECIDED_BY_OPERATOR_RESUME,
            )
            .await
        {
            Err(e) if e.code() == hcodes::ATTEMPT_NOT_FOUND => return Ok(None),
            Err(e) if e.code() == hcodes::RESUME_NOT_ALLOWED => {}
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        match self.attempts.load(ws, pred_id).await {
            Err(e) if e.code() == hcodes::ATTEMPT_NOT_FOUND => Ok(None),
            r => r.map(Some),
        }
    }

    /// `from` — the resume of `source`: its session, the chain budget
    /// (decision 9) and the fixed prompt.
    async fn from(
        &self,
        run: &ClaimedRun,
        source: central_harness::attempt::Attempt,
    ) -> Result<Option<ports::ResumeFrom>, Failure> {
        if source.run_id != run.run_id || source.harness_session_id.is_empty() {
            return Err(resume_unavailable(format!(
                "harness attempt {} is not a session of this Run",
                source.id
            )));
        }
        let attempts = self
            .summaries
            .attempts_for_run(run.workspace_id, run.run_id)
            .await?;
        let Some(chain) = central_harness::budget::sum_chain(&attempts) else {
            return Err(resume_unavailable("the Run has no harness attempts"));
        };
        let budget = chain.next()?;
        Ok(Some(ports::ResumeFrom {
            source,
            budget,
            prompt: HARNESS_RESUME_PROMPT.to_string(),
        }))
    }
}

fn resume_unavailable(why: impl Into<String>) -> Failure {
    Failure::internal(codes::RESUME_UNAVAILABLE, why.into())
}

/// `resolvedForResume` — the only state a resume continues.
fn resolved_for_resume(a: &central_harness::attempt::Attempt) -> bool {
    a.state == central_harness::domain::State::Resolved
        && a.resolution.kind == central_harness::domain::ResolutionKind::Resume
}

impl ports::ResumeSource for ServeResumeSource {
    /// `ResumeFrom` — whether a claimed attempt continues an earlier
    /// session.
    fn resume_from<'a>(
        &'a self,
        run: ClaimedRun,
    ) -> PortFuture<'a, Result<Option<ports::ResumeFrom>, Failure>> {
        Box::pin(async move {
            use central_harness::domain::codes as hcodes;
            let ws = run.workspace_id;
            // A read needs no capability: the store checks the
            // Workspace scope only.
            let scope = TrustedScope {
                principal_id: String::new(),
                workspace_id: ws,
                capabilities: Default::default(),
            };
            let state = self
                .reads
                .read_execution(ExecutionReadRequest {
                    scope,
                    workspace_id: ws,
                    task_id: run.task_id,
                    run_id: run.run_id,
                    step_id: run.step_id,
                    attempt_id: run.step_attempt_id,
                })
                .await?
                .state;
            let (Some(step), Some(attempt)) = (&state.step, &state.attempt) else {
                return Err(resume_unavailable(format!(
                    "step attempt {} was not read",
                    run.step_attempt_id
                )));
            };
            if attempt.id != run.step_attempt_id {
                return Err(resume_unavailable(format!(
                    "step attempt {} was not read",
                    run.step_attempt_id
                )));
            }
            let sequence = step.sequence;
            let no_source = |why: String| -> Result<Option<ports::ResumeFrom>, Failure> {
                if sequence > 1 {
                    return Err(resume_unavailable(format!(
                        "step attempt {} in step sequence {sequence}: {why}",
                        run.step_attempt_id
                    )));
                }
                Ok(None)
            };

            let own_id =
                central_harness::recovery::attempt_id_for_step_attempt(run.step_attempt_id)?;
            match self.attempts.load(ws, own_id).await {
                Ok(own) => {
                    // An earlier claim of this attempt created its
                    // row: adopt its kind.
                    let Some(resume_of) = own.resume_of else {
                        return no_source("its harness attempt starts a fresh session".to_string());
                    };
                    let source = match self.attempts.load(ws, resume_of).await {
                        Err(e) if e.code() == hcodes::ATTEMPT_NOT_FOUND => {
                            return Err(resume_unavailable(format!(
                                "the resumed harness attempt {resume_of} does not exist"
                            )));
                        }
                        r => r?,
                    };
                    if !resolved_for_resume(&source) {
                        return Err(resume_unavailable(format!(
                            "the resumed harness attempt {} is {}",
                            source.id,
                            source.state.as_str()
                        )));
                    }
                    return self.from(&run, source).await;
                }
                Err(e) if e.code() == hcodes::ATTEMPT_NOT_FOUND => {}
                Err(e) => return Err(e),
            }

            // No own row: the predecessor's. A nil id is every first
            // attempt, and never reaches the store.
            let pred = attempt.predecessor_id;
            if pred.is_nil() {
                return no_source("it has no predecessor".to_string());
            }
            let pred_id = central_harness::recovery::attempt_id_for_step_attempt(pred)?;
            let mut source = match self.attempts.load(ws, pred_id).await {
                Err(e) if e.code() == hcodes::ATTEMPT_NOT_FOUND => {
                    return no_source("its predecessor has no harness attempt".to_string());
                }
                r => r?,
            };
            if source.state == central_harness::domain::State::Ambiguous {
                let Some(healed) = self.heal(ws, pred, pred_id).await? else {
                    return no_source("its predecessor has no harness attempt".to_string());
                };
                source = healed;
            }
            if !resolved_for_resume(&source) {
                return no_source(format!(
                    "its predecessor's harness attempt is {}",
                    source.state.as_str()
                ));
            }
            self.from(&run, source).await
        })
    }
}

// ---------------------------------------------------------------------------
// ServeResolveStore — the `app.ResolveStore` delegation over the
// capability-owned AttemptStore + RecoveryStore pair.
// ---------------------------------------------------------------------------

/// The store surface the operator resolve action needs — upstream
/// `harnessAttemptStore`'s `Load` + `RecoverAttempt` half.
pub struct ServeResolveStore {
    attempts: Arc<dyn central_harness::port::AttemptStore>,
    recovery: Arc<dyn central_harness::port::RecoveryStore>,
}

impl ServeResolveStore {
    /// Binds the store pair.
    pub fn new(
        attempts: Arc<dyn central_harness::port::AttemptStore>,
        recovery: Arc<dyn central_harness::port::RecoveryStore>,
    ) -> Self {
        Self { attempts, recovery }
    }
}

impl ports::ResolveStore for ServeResolveStore {
    /// `Load`.
    fn load<'a>(
        &'a self,
        ws: central_foundation::identity::WorkspaceId,
        id: central_foundation::identity::HarnessAttemptId,
    ) -> PortFuture<'a, Result<central_harness::attempt::Attempt, Failure>> {
        Box::pin(async move { self.attempts.load(ws, id).await })
    }

    /// `RecoverAttempt` — writes the resolution under the recovery
    /// authority.
    fn recover_attempt<'a>(
        &'a self,
        expected: &'a central_harness::attempt::Attempt,
        next: &'a central_harness::attempt::Attempt,
    ) -> PortFuture<'a, Result<central_harness::attempt::Attempt, Failure>> {
        Box::pin(async move { self.recovery.recover_attempt(expected, next).await })
    }
}

#[cfg(test)]
mod tests;
