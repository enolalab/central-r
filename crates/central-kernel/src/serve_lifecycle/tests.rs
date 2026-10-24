//! Tests for the serve-side lifecycle adapters — the mirror of
//! upstream `cmd/central/harness_artifacts_test.go`'s mapping tests,
//! `harness_resume_test.go`'s `taskEligible`/source tests, plus the
//! lifecycle semantics the upstream postgres tests pin (permanent
//! refusals, cancel-awareness, the succeeded-settle refusal).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use central_artifact::domain as artifact;
use central_execution::app::{ClaimResult, StartHarnessRunResult};
use central_execution::domain::{self as exec, Command, EvaluationMetadata, LeaseCredential};
use central_execution::harness_run as exec_run;
use central_execution::port::{
    CommitResult, CompletionChangeSetRequest, DurableResult, ExecutionReadRequest,
    ExecutionReadResult, RecordCompletionReceiptRequest,
};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    HarnessAttemptId, RunId, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use central_harness::app::ports::{
    self as ports, ArtifactOutcomeKind, ArtifactRole, ClaimedRun, DispatchableRun, FailureCode,
    RunLifecycle, Settlement, codes,
};
use central_harness::budget::Budget;
use central_harness::domain::{self as hdomain, PermissionPolicy};
use central_harness::port::{self as hport, PortFuture};
use central_task::domain as task;
use time::{Duration, OffsetDateTime};

use super::*;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn ws() -> WorkspaceId {
    WorkspaceId::new()
}
fn task_id() -> TaskId {
    TaskId::new()
}
fn run_id() -> RunId {
    RunId::new()
}

fn task_fixture(ws_id: WorkspaceId, t: TaskId, r: RunId, status: task::TaskStatus) -> task::Task {
    task::Task {
        id: t,
        workspace_id: ws_id,
        version: 1,
        status,
        current_run_id: Some(r),
        parent_task_id: None,
        last_run_index: 1,
        retry_count: 0,
        retry_eligible_at: None,
        waiting_reason: None,
        failure_reason: String::new(),
        input: r#"{"instruction":"fix the flake"}"#.to_string(),
        title: "fix".to_string(),
        permission_policy: task::PermissionPolicy::AutoAllow,
        budget: task::Budget {
            cost_micro_usd: 5_000_000,
            wall_clock_seconds: 3_600,
        },
        created_at: NOW,
        updated_at: NOW,
    }
}

fn run_fixture(ws_id: WorkspaceId, t: TaskId, r: RunId) -> task::Run {
    task::Run {
        id: r,
        task_id: t,
        workspace_id: ws_id,
        version: 1,
        status: task::RunStatus::Running,
        index: 1,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn step_fixture(ws_id: WorkspaceId, t: TaskId, r: RunId, s: StepId, sequence: i64) -> exec::Step {
    exec::Step {
        id: s,
        workspace_id: ws_id,
        task_id: t,
        run_id: r,
        version: 1,
        sequence,
        state: exec::StepState::StepRunning,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn attempt_fixture(
    ws_id: WorkspaceId,
    t: TaskId,
    r: RunId,
    s: StepId,
    a: StepAttemptId,
    state: exec::AttemptState,
) -> exec::StepAttempt {
    exec::StepAttempt {
        id: a,
        step_id: s,
        workspace_id: ws_id,
        task_id: t,
        run_id: r,
        logical_operation_id: exec::LogicalOperationId::new(),
        physical_attempt_id: exec::PhysicalAttemptId::new(),
        invocation_id: exec::InvocationId::new(),
        predecessor_id: StepAttemptId::from_trusted_db_bytes([0u8; 16]),
        version: 1,
        sequence: 1,
        state,
        created_at: NOW,
        updated_at: NOW,
    }
}

/// An authoritative state with a running task/run and an invoked
/// attempt — `envelope()`'s required trio.
fn invoked_state() -> (
    WorkspaceId,
    TaskId,
    RunId,
    StepId,
    StepAttemptId,
    ExecutionState,
) {
    let (w, t, r, s, a) = (
        ws(),
        task_id(),
        run_id(),
        StepId::new(),
        StepAttemptId::new(),
    );
    let state = ExecutionState {
        task: task::TaskAggregate {
            task: task_fixture(w, t, r, task::TaskStatus::Running),
            current_run: Some(run_fixture(w, t, r)),
        },
        step: Some(step_fixture(w, t, r, s, 1)),
        attempt: Some(attempt_fixture(
            w,
            t,
            r,
            s,
            a,
            exec::AttemptState::AttemptInvoked,
        )),
        tool_calls: Vec::new(),
        tool_attempts: Vec::new(),
        lease: Some(exec::Lease {
            workspace_id: w,
            run_id: r,
            credential: LeaseCredential::new(&[7u8; 32]).unwrap(),
            generation: 1,
            expires_at: NOW + Duration::minutes(5),
            updated_at: NOW,
        }),
        approval: None,
    };
    (w, t, r, s, a, state)
}

fn claimed(w: WorkspaceId, t: TaskId, r: RunId, s: StepId, a: StepAttemptId) -> ClaimedRun {
    ClaimedRun {
        workspace_id: w,
        task_id: t,
        run_id: r,
        step_id: s,
        step_attempt_id: a,
        prompt: "fix the flake".to_string(),
        permission: PermissionPolicy::AutoAllow,
        budget: Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: Duration::hours(1),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
        lease: hport::ExecutionLease {
            generation: 1,
            credential: [7u8; 32],
        },
    }
}

// ---------------------------------------------------------------------------
// Fakes.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeReads {
    states: Mutex<VecDeque<Result<ExecutionState, Failure>>>,
    runs: Mutex<Option<Result<Vec<exec_run::DispatchableRun>, Failure>>>,
    receipts: Mutex<Vec<RecordCompletionReceiptRequest>>,
    receipt_error: Mutex<Option<Failure>>,
}

impl FakeReads {
    fn push_state(&self, state: ExecutionState) {
        self.states.lock().unwrap().push_back(Ok(state));
    }
}

impl HarnessExecutionReads for FakeReads {
    fn list_dispatchable_runs<'a>(
        &'a self,
        _request: exec_run::ListDispatchableRunsRequest,
    ) -> PortFuture<'a, Result<Vec<exec_run::DispatchableRun>, Failure>> {
        let res = self
            .runs
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| Ok(Vec::new()));
        Box::pin(async move { res })
    }

    fn read_execution<'a>(
        &'a self,
        _request: ExecutionReadRequest,
    ) -> PortFuture<'a, Result<ExecutionReadResult, Failure>> {
        let next = self
            .states
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted read ran out");
        Box::pin(async move { next.map(|state| ExecutionReadResult { state }) })
    }

    fn record_completion_receipt<'a>(
        &'a self,
        request: RecordCompletionReceiptRequest,
    ) -> PortFuture<'a, Result<(), Failure>> {
        self.receipts.lock().unwrap().push(request);
        let err = self.receipt_error.lock().unwrap().take();
        Box::pin(async move {
            match err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        })
    }
}

#[derive(Default)]
struct FakeCommands {
    recorded: Mutex<Vec<Command>>,
    start_results: Mutex<VecDeque<Result<StartHarnessRunResult, Failure>>>,
    claim_results: Mutex<VecDeque<Result<ClaimResult, Failure>>>,
    execute_results: Mutex<VecDeque<Result<CommitResult, Failure>>>,
    validate_results: Mutex<VecDeque<Result<exec::ExecutionChangeSet, Failure>>>,
}

fn commit_result() -> CommitResult {
    CommitResult {
        result: DurableResult {
            workspace_id: WorkspaceId::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            attempt_id: StepAttemptId::new(),
            event_id: central_foundation::identity::ExecutionEventId::new(),
            event_kind: "test".to_string(),
            approval_action: None,
        },
        replayed: false,
    }
}

impl FakeCommands {
    fn ok_commit(&self) {
        self.execute_results
            .lock()
            .unwrap()
            .push_back(Ok(commit_result()));
    }
}

impl HarnessExecutionCommands for FakeCommands {
    fn start_harness_run<'a>(
        &'a self,
        command: Command,
        _meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<StartHarnessRunResult, Failure>> {
        self.recorded.lock().unwrap().push(command);
        let next = self
            .start_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted start ran out");
        Box::pin(async move { next })
    }

    fn claim<'a>(
        &'a self,
        command: Command,
        _meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<ClaimResult, Failure>> {
        self.recorded.lock().unwrap().push(command);
        let next = self
            .claim_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted claim ran out");
        Box::pin(async move { next })
    }

    fn execute<'a>(
        &'a self,
        command: Command,
        _meta: EvaluationMetadata,
    ) -> PortFuture<'a, Result<CommitResult, Failure>> {
        self.recorded.lock().unwrap().push(command);
        let next = self
            .execute_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(commit_result()));
        Box::pin(async move { next })
    }

    fn validate_completion_change_set<'a>(
        &'a self,
        request: CompletionChangeSetRequest,
    ) -> PortFuture<'a, Result<exec::ExecutionChangeSet, Failure>> {
        let next = self
            .validate_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(request.change_set));
        Box::pin(async move { next })
    }
}

#[derive(Default)]
struct FakeArtifacts {
    outcomes: Mutex<VecDeque<Result<artifact::Outcome, Failure>>>,
    seen: Mutex<Vec<(String, String, i64)>>,
}

impl HarnessArtifactService for FakeArtifacts {
    fn materialize_required_report<'a>(
        &'a self,
        request: MaterializeRequest,
    ) -> PortFuture<'a, Result<artifact::Outcome, Failure>> {
        let mut body = Vec::new();
        let _ = request.body.expect("a body").read_to_end(&mut body);
        self.seen.lock().unwrap().push((
            request.operation_id.clone(),
            request.required_role.clone(),
            body.len() as i64,
        ));
        let next = self
            .outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                Ok(artifact::Outcome {
                    kind: artifact::OutcomeKind::Ready,
                    failure_code: String::new(),
                })
            });
        Box::pin(async move { next })
    }
}

struct FakeCosts(i64);
impl TaskCostReader for FakeCosts {
    fn cost_for_task<'a>(
        &'a self,
        _ws: WorkspaceId,
        _task: TaskId,
    ) -> PortFuture<'a, Result<i64, Failure>> {
        let v = self.0;
        Box::pin(async move { Ok(v) })
    }
}

fn lifecycle(
    commands: std::sync::Arc<FakeCommands>,
    reads: std::sync::Arc<FakeReads>,
    artifacts: std::sync::Arc<FakeArtifacts>,
) -> ServeRunLifecycle {
    ServeRunLifecycle::new(commands, reads, artifacts, NOW)
}

// ---------------------------------------------------------------------------
// Upstream `TestTaskEligibleMatchesTheDispatcherFilter` +
// `TestResumeCostFloorsAgree`-adjacent helper coverage.
// ---------------------------------------------------------------------------

#[test]
fn task_eligible_matches_the_dispatcher_filter() {
    let floor = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    assert!(task_eligible(exec::ZERO_TIME, exec::ZERO_TIME));
    assert!(task_eligible(floor, exec::ZERO_TIME));
    assert!(task_eligible(floor, floor));
    assert!(task_eligible(floor + Duration::microseconds(1), floor));
    assert!(task_eligible(floor + Duration::nanoseconds(999), floor));
    assert!(!task_eligible(floor - Duration::microseconds(1), floor));
    assert!(!task_eligible(floor - Duration::days(1), floor));
}

#[test]
fn clamp_to_task_cost_cap_is_min_per_run_max_cap_minus_used() {
    // min(perRun, max(cap - used, MIN_RESUME_COST)) — the MIN floor
    // only matters when perRun itself exceeds it.
    let min = central_harness::budget::MIN_RESUME_COST_MICRO_USD;
    assert_eq!(clamp_to_task_cost_cap(1_000, 5_000, 0), 1_000);
    // cap - used < MIN ⇒ max(..., MIN) = MIN ⇒ min(perRun, MIN).
    assert_eq!(clamp_to_task_cost_cap(1_000, 5_000, 4_500), 1_000.min(min));
    assert_eq!(clamp_to_task_cost_cap(50_000, 5_000, 4_500), min);
    // cap - used > MIN ⇒ the Task cap bites.
    assert_eq!(clamp_to_task_cost_cap(50_000, 50_000, 30_000), 20_000);
    assert_eq!(clamp_to_task_cost_cap(50_000, 50_000, 10_000), 40_000);
    // Negative used is clamped to 0.
    assert_eq!(clamp_to_task_cost_cap(1_000, 5_000, -3), 1_000);
}

#[test]
fn artifact_operation_ids_are_stable_per_attempt_and_role() {
    let attempt = StepAttemptId::new();
    let a = artifact_operation_id(attempt, ArtifactRole::Report).unwrap();
    let b = artifact_operation_id(attempt, ArtifactRole::Report).unwrap();
    let c = artifact_operation_id(attempt, ArtifactRole::Patch).unwrap();
    let d = artifact_operation_id(StepAttemptId::new(), ArtifactRole::Report).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert!(a.starts_with("harness:") && a.ends_with(":report"));
    assert!(c.ends_with(":patch"));
    assert!(
        artifact_operation_id(
            StepAttemptId::from_trusted_db_bytes([0u8; 16]),
            ArtifactRole::Report
        )
        .is_err()
    );
}

#[test]
fn artifact_outcome_mapping() {
    let mk = |kind, code: &str| artifact::Outcome {
        kind,
        failure_code: code.to_string(),
    };
    assert_eq!(
        artifact_outcome(mk(artifact::OutcomeKind::Ready, "")).kind,
        ArtifactOutcomeKind::Ready
    );
    assert_eq!(
        artifact_outcome(mk(artifact::OutcomeKind::Reconciliation, "")).kind,
        ArtifactOutcomeKind::Reconciliation
    );
    for (code, want) in [
        (
            artifact::FAILURE_CODE_SECRET_DISCLOSURE,
            FailureCode::ARTIFACT_REJECTED,
        ),
        (
            artifact::FAILURE_CODE_CONTENT_POLICY,
            FailureCode::ARTIFACT_REJECTED,
        ),
        (
            artifact::FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE,
            FailureCode::ARTIFACT_REJECTED,
        ),
        (
            artifact::FAILURE_CODE_SIZE_LIMIT_EXCEEDED,
            FailureCode::ARTIFACT_TOO_LARGE,
        ),
        ("QUOTA_EXCEEDED", FailureCode::ARTIFACT_QUOTA_EXCEEDED),
        ("ANYTHING_ELSE", FailureCode::ARTIFACT_CAPTURE_FAILED),
    ] {
        let got = artifact_outcome(mk(artifact::OutcomeKind::Terminal, code));
        assert_eq!(got.kind, ArtifactOutcomeKind::Terminal, "{code}");
        assert_eq!(got.reason, want, "{code}");
        let got = artifact_outcome(mk(artifact::OutcomeKind::Retryable, code));
        assert_eq!(got.kind, ArtifactOutcomeKind::Retryable, "{code}");
        assert_eq!(got.reason, want, "{code}");
    }
}

#[test]
fn artifact_error_classifies_quota_lease_and_other() {
    // A quota refusal is a certain bounded failure — an outcome, not
    // an error.
    match artifact_error(Failure::invalid("QUOTA_EXCEEDED", "quota")) {
        ArtifactOrOutcome::Outcome(o) => {
            assert_eq!(o.kind, ArtifactOutcomeKind::Terminal);
            assert_eq!(o.reason, FailureCode::ARTIFACT_QUOTA_EXCEEDED);
        }
        _ => unreachable!("quota must be an outcome"),
    }
    // A lease-fence refusal means the lease is lost.
    match artifact_error(Failure::conflict("STALE_LEASE_FENCE", "stale")) {
        ArtifactOrOutcome::Err(e) => assert_eq!(e.code(), codes::LEASE_LOST),
        _ => unreachable!("a lease refusal must be an error"),
    }
    // Every other error is unclassified.
    match artifact_error(Failure::internal("pg_broken", "db")) {
        ArtifactOrOutcome::Err(e) => assert_eq!(e.code(), "pg_broken"),
        _ => unreachable!("an unclassified error passes through"),
    }
}

// ---------------------------------------------------------------------------
// ServeRunLifecycle.
// ---------------------------------------------------------------------------

#[test]
fn list_dispatchable_maps_cases() {
    let reads = std::sync::Arc::new(FakeReads::default());
    *reads.runs.lock().unwrap() = Some(Ok(vec![
        exec_run::DispatchableRun {
            case: exec_run::DispatchCase::DispatchQueued,
            workspace_id: ws(),
            task_id: task_id(),
            run_id: run_id(),
            step_id: StepId::from_trusted_db_bytes([0u8; 16]),
            attempt_id: StepAttemptId::from_trusted_db_bytes([0u8; 16]),
            logical_operation: exec::LogicalOperationId::new(),
            task_created_at: NOW,
        },
        exec_run::DispatchableRun {
            case: exec_run::DispatchCase::DispatchPreparedSuccessor,
            workspace_id: ws(),
            task_id: task_id(),
            run_id: run_id(),
            step_id: StepId::new(),
            attempt_id: StepAttemptId::new(),
            logical_operation: exec::LogicalOperationId::new(),
            task_created_at: NOW,
        },
    ]));
    let l = lifecycle(
        std::sync::Arc::new(FakeCommands::default()),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let got = block_on(l.list_dispatchable(50)).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].case, ports::DispatchCase::Queued);
    assert_eq!(got[1].case, ports::DispatchCase::PreparedSuccessor);
}

#[test]
fn start_queued_claims_and_resolves_budget() {
    let (w, t, r, _s, _a, state) = invoked_state();
    // Queued dispatchable: current_run must match.
    let mut queued_state = state.clone();
    queued_state.step = None;
    queued_state.attempt = None;
    queued_state.task.task.status = task::TaskStatus::Queued;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(queued_state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands
        .start_results
        .lock()
        .unwrap()
        .push_back(Ok(StartHarnessRunResult {
            commit: commit_result(),
            lease_credential: LeaseCredential::new(&[9u8; 32]).unwrap(),
            lease_generation: 2,
        }));
    let l = lifecycle(
        commands.clone(),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    )
    .with_budget(
        HarnessBudgetDefaults {
            cost_micro_usd: 2_000_000,
            wall_clock: Duration::minutes(10),
        },
        Some(std::sync::Arc::new(FakeCosts(4_000_000))),
        5_000_000,
    );
    let run = DispatchableRun {
        case: ports::DispatchCase::Queued,
        workspace_id: w,
        task_id: t,
        run_id: r,
        step_id: StepId::from_trusted_db_bytes([0u8; 16]),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes([0u8; 16]),
    };
    let got = block_on(l.start(run)).unwrap();
    assert_eq!(got.task_id, t);
    assert_eq!(got.prompt, "fix the flake");
    assert_eq!(got.permission, PermissionPolicy::AutoAllow);
    assert_eq!(got.lease.generation, 2);
    assert_eq!(got.lease.credential, [9u8; 32]);
    // requested 5_000_000 clamped to cap(5_000_000) - used(4_000_000) = 1_000_000.
    assert_eq!(got.budget.cost_micro_usd, 1_000_000);
    assert_eq!(got.budget.wall_clock, Duration::hours(1));
    assert!(!got.budget.cost_defaulted);
    assert!(!got.budget.wall_clock_defaulted);
}

#[test]
fn start_queued_refuses_a_run_that_is_not_current() {
    let (w, t, _r, _s, _a, state) = invoked_state();
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let l = lifecycle(
        std::sync::Arc::new(FakeCommands::default()),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let run = DispatchableRun {
        case: ports::DispatchCase::Queued,
        workspace_id: w,
        task_id: t,
        run_id: RunId::new(), // not the current run
        step_id: StepId::from_trusted_db_bytes([0u8; 16]),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes([0u8; 16]),
    };
    let err = block_on(l.start(run)).unwrap_err();
    assert_eq!(err.code(), codes::NOT_STARTABLE);
}

#[test]
fn start_queued_marks_an_ambiguous_claim_outcome() {
    let (w, t, r, _s, _a, state) = invoked_state();
    let mut queued_state = state;
    queued_state.step = None;
    queued_state.attempt = None;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(queued_state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands
        .start_results
        .lock()
        .unwrap()
        .push_back(Err(Failure::internal("pg_broken", "db down")));
    let l = lifecycle(
        commands,
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let run = DispatchableRun {
        case: ports::DispatchCase::Queued,
        workspace_id: w,
        task_id: t,
        run_id: r,
        step_id: StepId::from_trusted_db_bytes([0u8; 16]),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes([0u8; 16]),
    };
    let err = block_on(l.start(run)).unwrap_err();
    assert_eq!(err.code(), codes::START_OUTCOME_UNKNOWN);
}

#[test]
fn claim_successor_claims_the_prepared_attempt() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptPrepared;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands
        .claim_results
        .lock()
        .unwrap()
        .push_back(Ok(ClaimResult {
            commit: commit_result(),
            lease_credential: LeaseCredential::new(&[3u8; 32]).unwrap(),
        }));
    let l = lifecycle(
        commands.clone(),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let run = DispatchableRun {
        case: ports::DispatchCase::PreparedSuccessor,
        workspace_id: w,
        task_id: t,
        run_id: r,
        step_id: s,
        step_attempt_id: a,
    };
    let got = block_on(l.start(run)).unwrap();
    assert_eq!(got.step_attempt_id, a);
    assert_eq!(got.lease.generation, 2); // existing lease gen 1 + 1
    assert_eq!(got.lease.credential, [3u8; 32]);
    // The recorded Claim command names the prepared attempt.
    let recorded = commands.recorded.lock().unwrap();
    assert!(matches!(recorded.as_slice(), [Command::Claim(_)]));
}

#[test]
fn heartbeat_reports_cancelling_and_maps_lease_loss() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.task.task.status = task::TaskStatus::Cancelling;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands.ok_commit();
    let l = lifecycle(
        commands,
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let run = claimed(w, t, r, s, a);
    assert!(block_on(l.heartbeat(run)).unwrap());

    // A lease refusal of the heartbeat maps to LEASE_LOST.
    let (w, t, r, s, a, state) = invoked_state();
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands
        .execute_results
        .lock()
        .unwrap()
        .push_back(Err(Failure::conflict("STALE_LEASE_FENCE", "stale")));
    let l = lifecycle(
        commands,
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let err = block_on(l.heartbeat(claimed(w, t, r, s, a))).unwrap_err();
    assert_eq!(err.code(), codes::LEASE_LOST);
}

#[test]
fn mark_invoked_refuses_a_cancelling_task() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.task.task.status = task::TaskStatus::Cancelling;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    let l = lifecycle(
        commands.clone(),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let err = block_on(l.mark_invoked(claimed(w, t, r, s, a))).unwrap_err();
    assert_eq!(err.code(), codes::CANCEL_REQUESTED);
    assert!(commands.recorded.lock().unwrap().is_empty());
}

#[test]
fn a_concurrent_cancellation_maps_the_refusal_to_cancel_requested() {
    // The command fails EXPECTED_VERSION_CONFLICT; the fresh read shows
    // the Task cancelling.
    let (w, t, r, s, a, state) = invoked_state();
    let mut cancelled = state.clone();
    cancelled.task.task.status = task::TaskStatus::Cancelling;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state); // envelope's read
    reads.push_state(cancelled); // cancel_aware's re-read
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands
        .execute_results
        .lock()
        .unwrap()
        .push_back(Err(Failure::conflict("EXPECTED_VERSION_CONFLICT", "moved")));
    let l = lifecycle(
        commands,
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let err = block_on(l.mark_invoked(claimed(w, t, r, s, a))).unwrap_err();
    assert_eq!(err.code(), codes::CANCEL_REQUESTED);
}

#[test]
fn settle_and_record_completion_refuse_success() {
    let (w, t, r, s, a, state) = invoked_state();
    for call in ["settle", "record_completion"] {
        let reads = std::sync::Arc::new(FakeReads::default());
        reads.push_state(state.clone());
        let l = lifecycle(
            std::sync::Arc::new(FakeCommands::default()),
            reads,
            std::sync::Arc::new(FakeArtifacts::default()),
        );
        let outcome = Settlement {
            succeeded: true,
            reason: FailureCode::default(),
        };
        let err = if call == "settle" {
            block_on(l.settle(claimed(w, t, r, s, a), outcome)).unwrap_err()
        } else {
            block_on(l.record_completion(claimed(w, t, r, s, a), outcome)).unwrap_err()
        };
        assert_eq!(err.code(), SETTLE_SUCCEEDED_NOT_ALLOWED, "{call}");
        // permanentFailure parity: the refusal is not retryable.
        assert_eq!(err.kind(), FailureKind::Invalid, "{call}");
    }
}

#[test]
fn settle_commits_the_failed_settlement() {
    let (w, t, r, s, a, state) = invoked_state();
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands.ok_commit();
    let l = lifecycle(
        commands.clone(),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    block_on(l.settle(
        claimed(w, t, r, s, a),
        Settlement {
            succeeded: false,
            reason: FailureCode::BUDGET,
        },
    ))
    .unwrap();
    let recorded = commands.recorded.lock().unwrap();
    match &recorded[..] {
        [Command::Settle(c)] => {
            assert_eq!(c.final_state, exec::AttemptState::AttemptFailed);
            assert_eq!(c.reason_code, exec_run::FAILURE_REASON_HARNESS_BUDGET);
            assert_eq!(c.envelope.lease_generation, 1);
        }
        other => unreachable!("expected Settle, got {other:?}"),
    }
}

#[test]
fn record_completion_records_the_fenced_receipt() {
    let (w, t, r, s, a, state) = invoked_state();
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state.clone());
    let l = lifecycle(
        std::sync::Arc::new(FakeCommands::default()),
        reads.clone(),
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    block_on(l.record_completion(
        claimed(w, t, r, s, a),
        Settlement {
            succeeded: false,
            reason: FailureCode::EXECUTION_FAILED,
        },
    ))
    .unwrap();
    let receipts = reads.receipts.lock().unwrap();
    let req = &receipts[0];
    let attempt = state.attempt.as_ref().unwrap();
    assert_eq!(req.receipt.attempt_id, a);
    assert_eq!(
        req.receipt.logical_operation_id,
        attempt.logical_operation_id
    );
    assert_eq!(req.receipt.physical_attempt_id, attempt.physical_attempt_id);
    assert_eq!(req.receipt.invocation_id, attempt.invocation_id);
    assert_eq!(req.receipt.invocation_generation, 1);
    assert_eq!(req.receipt.final_state, exec::AttemptState::AttemptFailed);
    assert_eq!(req.receipt.producer_id, HARNESS_PRINCIPAL);
    assert_eq!(req.lease_generation, 1);
    assert_eq!(req.lease_credential.0, [7u8; 32]);
}

#[test]
fn settle_cancellation_attests_the_executor_stopped() {
    for (state_kind, want) in [
        (exec::AttemptState::AttemptInvoked, true),
        (exec::AttemptState::AttemptPrepared, false),
    ] {
        let (w, t, r, s, a, mut state) = invoked_state();
        state.attempt.as_mut().unwrap().state = state_kind;
        state.task.task.status = task::TaskStatus::Cancelling;
        let reads = std::sync::Arc::new(FakeReads::default());
        reads.push_state(state);
        let commands = std::sync::Arc::new(FakeCommands::default());
        commands.ok_commit();
        let l = lifecycle(
            commands.clone(),
            reads,
            std::sync::Arc::new(FakeArtifacts::default()),
        );
        block_on(l.settle_cancellation(claimed(w, t, r, s, a))).unwrap();
        let recorded = commands.recorded.lock().unwrap();
        match &recorded[..] {
            [Command::SettleCancellation(c)] => {
                assert_eq!(c.executor_stopped, want, "{state_kind:?}")
            }
            other => unreachable!("expected SettleCancellation, got {other:?}"),
        }
    }
}

#[test]
fn complete_with_report_materializes_the_report_with_the_candidate() {
    let (w, t, r, s, a, state) = invoked_state();
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    let artifacts = std::sync::Arc::new(FakeArtifacts::default());
    let l = lifecycle(commands, reads, artifacts.clone());
    let outcome =
        block_on(l.complete_with_report(claimed(w, t, r, s, a), b"# done".to_vec())).unwrap();
    assert_eq!(outcome.kind, ArtifactOutcomeKind::Ready);
    let seen = artifacts.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (op, role, bytes) = &seen[0];
    assert_eq!(role, "harness.report");
    assert_eq!(op, &format!("harness:{a}:report"));
    assert_eq!(*bytes, 6);
}

#[test]
fn complete_with_report_recognizes_a_landed_commit() {
    // The materialize call errors ambiguously; the fresh read finds the
    // StepAttempt succeeded and the Task completed → Ready.
    let (w, t, r, s, a, state) = invoked_state();
    let mut landed = state.clone();
    landed.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptSucceeded;
    landed.task.task.status = task::TaskStatus::Completed;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    reads.push_state(landed);
    let artifacts = std::sync::Arc::new(FakeArtifacts::default());
    artifacts
        .outcomes
        .lock()
        .unwrap()
        .push_back(Err(Failure::internal("pg_broken", "db flickered")));
    let l = lifecycle(
        std::sync::Arc::new(FakeCommands::default()),
        reads,
        artifacts,
    );
    let outcome =
        block_on(l.complete_with_report(claimed(w, t, r, s, a), b"# done".to_vec())).unwrap();
    assert_eq!(outcome.kind, ArtifactOutcomeKind::Ready);
}

#[test]
fn complete_with_report_refuses_a_cancelling_task() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.task.task.status = task::TaskStatus::Cancelling;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let l = lifecycle(
        std::sync::Arc::new(FakeCommands::default()),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    let err = block_on(l.complete_with_report(claimed(w, t, r, s, a), Vec::new())).unwrap_err();
    assert_eq!(err.code(), codes::CANCEL_REQUESTED);
}

#[test]
fn reconcile_moves_the_attempt_into_reconciliation() {
    let (w, t, r, s, a, state) = invoked_state();
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands.ok_commit();
    let l = lifecycle(
        commands.clone(),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    block_on(l.reconcile(claimed(w, t, r, s, a))).unwrap();
    let recorded = commands.recorded.lock().unwrap();
    match &recorded[..] {
        [Command::EnterReconciliation(c)] => {
            assert_eq!(
                c.reason_code,
                exec::ProviderReconciliationReason::HandoffFailed
            );
        }
        other => unreachable!("expected EnterReconciliation, got {other:?}"),
    }
}

#[test]
fn abandon_prepared_fails_with_the_bounded_reason() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptPrepared;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let commands = std::sync::Arc::new(FakeCommands::default());
    commands.ok_commit();
    let l = lifecycle(
        commands.clone(),
        reads,
        std::sync::Arc::new(FakeArtifacts::default()),
    );
    block_on(l.abandon_prepared(claimed(w, t, r, s, a), FailureCode::WORKSPACE_UNAVAILABLE))
        .unwrap();
    let recorded = commands.recorded.lock().unwrap();
    match &recorded[..] {
        [Command::AbandonPrepared(c)] => {
            assert_eq!(
                c.reason_code,
                exec_run::FAILURE_REASON_WORKSPACE_UNAVAILABLE
            );
        }
        other => unreachable!("expected AbandonPrepared, got {other:?}"),
    }
}

#[test]
fn a_domain_refusal_is_permanent() {
    // Upstream permanentFailure: a domain refusal keeps its code and is
    // not retryable.
    let e = classify(Failure::conflict("EXPECTED_VERSION_CONFLICT", "moved"));
    assert_eq!(e.code(), "EXPECTED_VERSION_CONFLICT");
    assert_eq!(e.kind(), FailureKind::Invalid);
    // ... while an infrastructure error passes through.
    let e = classify(Failure::internal("pg_broken", "db"));
    assert_eq!(e.code(), "pg_broken");
    // ... and a lease refusal is LEASE_LOST.
    let e = classify(Failure::conflict("LEASE_NOT_CURRENT", "lost"));
    assert_eq!(e.code(), codes::LEASE_LOST);
}

// ---------------------------------------------------------------------------
// ServeArtifactSink.
// ---------------------------------------------------------------------------

#[test]
fn artifact_sink_stores_a_supporting_artifact_without_a_transition() {
    let (w, t, r, s, a, _) = invoked_state();
    let dir = std::env::temp_dir().join(format!("central-test-{}", RunId::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("patch.txt");
    std::fs::write(&path, b"diff --git a/x b/x").unwrap();

    let artifacts = std::sync::Arc::new(FakeArtifacts::default());
    let sink = ServeArtifactSink::new(artifacts.clone());
    let outcome = block_on(ports::ArtifactSink::store(
        &sink,
        claimed(w, t, r, s, a),
        ArtifactRole::Patch,
        path.to_string_lossy().into_owned(),
    ))
    .unwrap();
    assert_eq!(outcome.kind, ArtifactOutcomeKind::Ready);
    let seen = artifacts.seen.lock().unwrap();
    assert_eq!(seen[0].0, format!("harness:{a}:patch"));
    assert_eq!(seen[0].1, "harness.patch");

    // The report is not a supporting role.
    let err = block_on(ports::ArtifactSink::store(
        &sink,
        claimed(w, t, r, s, a),
        ArtifactRole::Report,
        path.to_string_lossy().into_owned(),
    ))
    .unwrap_err();
    assert_eq!(err.code(), "artifact_capture_failed");

    // A gone capture file is a certain terminal failure.
    let outcome = block_on(ports::ArtifactSink::store(
        &sink,
        claimed(w, t, r, s, a),
        ArtifactRole::Patch,
        dir.join("gone.txt").to_string_lossy().into_owned(),
    ))
    .unwrap();
    assert_eq!(outcome.kind, ArtifactOutcomeKind::Terminal);
    assert_eq!(outcome.reason, FailureCode::ARTIFACT_CAPTURE_FAILED);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// ServeResumeSource — upstream `harnessResumeSource` coverage.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeAttempts {
    by_id: Mutex<HashMap<HarnessAttemptId, central_harness::attempt::Attempt>>,
}

impl hport::AttemptStore for FakeAttempts {
    fn create<'a>(
        &'a self,
        _attempt: &'a central_harness::attempt::Attempt,
    ) -> PortFuture<'a, Result<(), Failure>> {
        unimplemented!()
    }
    fn load<'a>(
        &'a self,
        _ws: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<central_harness::attempt::Attempt, Failure>> {
        let got = self.by_id.lock().unwrap().get(&id).cloned();
        Box::pin(async move {
            got.ok_or_else(|| Failure::not_found(hdomain::codes::ATTEMPT_NOT_FOUND, "no attempt"))
        })
    }
    fn live_attempt_for_run<'a>(
        &'a self,
        _ws: WorkspaceId,
        _run: RunId,
    ) -> PortFuture<'a, Result<Option<central_harness::attempt::Attempt>, Failure>> {
        unimplemented!()
    }
    fn save<'a>(
        &'a self,
        _expected: &'a central_harness::attempt::Attempt,
        _next: &'a central_harness::attempt::Attempt,
        _open: &'a [hport::ApprovalOpen],
    ) -> PortFuture<'a, Result<central_harness::attempt::Attempt, Failure>> {
        unimplemented!()
    }
    fn append_event<'a>(
        &'a self,
        _expected: &'a central_harness::attempt::Attempt,
        _next: &'a central_harness::attempt::Attempt,
        _rec: &'a central_harness::record::EventRecord,
        _open: &'a [hport::ApprovalOpen],
    ) -> PortFuture<'a, Result<central_harness::attempt::Attempt, Failure>> {
        unimplemented!()
    }
    fn expire_permission<'a>(
        &'a self,
        _attempt: &'a central_harness::attempt::Attempt,
        _id: central_foundation::identity::HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<central_harness::approval::PermissionApproval, Failure>> {
        unimplemented!()
    }
    fn load_approval<'a>(
        &'a self,
        _ws: WorkspaceId,
        _id: central_foundation::identity::HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<central_harness::approval::PermissionApproval, Failure>> {
        unimplemented!()
    }
}

#[derive(Default)]
struct FakeSummaries(Vec<central_harness::attempt::Attempt>);
impl RunChainRead for FakeSummaries {
    fn attempts_for_run<'a>(
        &'a self,
        _ws: WorkspaceId,
        _run: RunId,
    ) -> PortFuture<'a, Result<Vec<central_harness::attempt::Attempt>, Failure>> {
        let v = self.0.clone();
        Box::pin(async move { Ok(v) })
    }
}

struct FakeRecovery;
impl hport::RecoveryStore for FakeRecovery {
    fn list_recovery_candidates<'a>(
        &'a self,
        _after: hport::RecoveryCursor,
        _limit: usize,
    ) -> PortFuture<'a, Result<Vec<hport::RecoveryCandidate>, Failure>> {
        unimplemented!()
    }
    fn recover_attempt<'a>(
        &'a self,
        _expected: &'a central_harness::attempt::Attempt,
        _next: &'a central_harness::attempt::Attempt,
    ) -> PortFuture<'a, Result<central_harness::attempt::Attempt, Failure>> {
        unimplemented!()
    }
}

struct FixedClock;
impl ports::Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        NOW
    }
}

fn harness_attempt(
    w: WorkspaceId,
    r: RunId,
    id: StepAttemptId,
    state: hdomain::State,
) -> central_harness::attempt::Attempt {
    let mut a =
        central_harness::attempt::Attempt::prepare(central_harness::attempt::PrepareInput {
            id: central_harness::recovery::attempt_id_for_step_attempt(id).unwrap(),
            workspace_id: w,
            run_id: r,
            kind: hdomain::Kind::new("claude-code"),
            adapter_version: "v1".to_string(),
            workspace: hdomain::Workspace {
                path: "/tmp/w".to_string(),
                base_sha: "deadbeef".to_string(),
            },
            permission: PermissionPolicy::AutoAllow,
            fence: hdomain::Fence { generation: 1 },
            budget: Budget {
                cost_micro_usd: 5_000_000,
                wall_clock: Duration::hours(1),
                cost_defaulted: false,
                wall_clock_defaulted: false,
            },
            at: NOW,
        })
        .unwrap();
    a.state = state;
    a
}

fn resume_source(
    reads: std::sync::Arc<FakeReads>,
    attempts: std::sync::Arc<FakeAttempts>,
    summaries: std::sync::Arc<FakeSummaries>,
) -> ServeResumeSource {
    let resolve = std::sync::Arc::new(ServeResolveStore::new(
        attempts.clone(),
        std::sync::Arc::new(FakeRecovery),
    ));
    ServeResumeSource::new(
        reads,
        attempts,
        summaries,
        std::sync::Arc::new(central_harness::app::reconciler::Resolver::new(
            resolve,
            std::sync::Arc::new(FixedClock),
        )),
    )
}

#[test]
fn resume_source_finds_none_for_a_fresh_attempt() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptPrepared;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let source = resume_source(
        reads,
        std::sync::Arc::new(FakeAttempts::default()),
        std::sync::Arc::new(FakeSummaries::default()),
    );
    let got = block_on(ports::ResumeSource::resume_from(
        &source,
        claimed(w, t, r, s, a),
    ))
    .unwrap();
    assert!(got.is_none());
}

#[test]
fn resume_source_reads_the_own_rows_resume_of() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptPrepared;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);

    let pred_id = StepAttemptId::new();
    let mut pred = harness_attempt(w, r, pred_id, hdomain::State::Resolved);
    pred.harness_session_id = "sess-1".to_string();
    pred.resolution = hdomain::Resolution {
        kind: hdomain::ResolutionKind::Resume,
        decided_by: "recovery:operator_resume".to_string(),
    };
    let mut own = harness_attempt(w, r, a, hdomain::State::Prepared);
    own.resume_of = Some(pred.id);

    let attempts = std::sync::Arc::new(FakeAttempts::default());
    attempts.by_id.lock().unwrap().insert(pred.id, pred.clone());
    attempts.by_id.lock().unwrap().insert(own.id, own);
    let source = resume_source(
        reads,
        attempts,
        std::sync::Arc::new(FakeSummaries(vec![pred.clone()])),
    );
    let got = block_on(ports::ResumeSource::resume_from(
        &source,
        claimed(w, t, r, s, a),
    ))
    .unwrap()
    .expect("a resume source");
    assert_eq!(got.source.id, pred.id);
    assert_eq!(got.prompt, HARNESS_RESUME_PROMPT);
    assert_eq!(got.budget.cost_micro_usd, 5_000_000);
}

#[test]
fn resume_source_reads_the_predecessors_row() {
    let (w, t, r, s, a, mut state) = invoked_state();
    let pred_step_attempt = StepAttemptId::new();
    state.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptPrepared;
    state.attempt.as_mut().unwrap().predecessor_id = pred_step_attempt;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);

    let mut pred = harness_attempt(w, r, pred_step_attempt, hdomain::State::Resolved);
    pred.harness_session_id = "sess-2".to_string();
    pred.resolution = hdomain::Resolution {
        kind: hdomain::ResolutionKind::Resume,
        decided_by: "recovery:operator_resume".to_string(),
    };
    let attempts = std::sync::Arc::new(FakeAttempts::default());
    attempts.by_id.lock().unwrap().insert(pred.id, pred.clone());
    let source = resume_source(
        reads,
        attempts,
        std::sync::Arc::new(FakeSummaries(vec![pred.clone()])),
    );
    let got = block_on(ports::ResumeSource::resume_from(
        &source,
        claimed(w, t, r, s, a),
    ))
    .unwrap()
    .expect("a resume source");
    assert_eq!(got.source.id, pred.id);
}

#[test]
fn resume_source_refuses_a_late_step_without_a_source() {
    let (w, t, r, s, a, mut state) = invoked_state();
    state.step.as_mut().unwrap().sequence = 3;
    state.attempt.as_mut().unwrap().state = exec::AttemptState::AttemptPrepared;
    let reads = std::sync::Arc::new(FakeReads::default());
    reads.push_state(state);
    let source = resume_source(
        reads,
        std::sync::Arc::new(FakeAttempts::default()),
        std::sync::Arc::new(FakeSummaries::default()),
    );
    let err = block_on(ports::ResumeSource::resume_from(
        &source,
        claimed(w, t, r, s, a),
    ))
    .unwrap_err();
    assert_eq!(err.code(), codes::RESUME_UNAVAILABLE);
}

#[test]
fn resolve_store_delegates() {
    let (w, _t, r, _s, a, _) = invoked_state();
    let attempt = harness_attempt(w, r, a, hdomain::State::Ambiguous);
    let attempts = std::sync::Arc::new(FakeAttempts::default());
    attempts
        .by_id
        .lock()
        .unwrap()
        .insert(attempt.id, attempt.clone());
    let store = ServeResolveStore::new(attempts, std::sync::Arc::new(FakeRecovery));
    let got = block_on(ports::ResolveStore::load(&store, w, attempt.id)).unwrap();
    assert_eq!(got.id, attempt.id);
}
