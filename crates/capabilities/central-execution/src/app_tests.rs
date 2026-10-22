//! Service tests — port of the critical lanes from upstream
//! `internal/execution/app/service_test.go`:
//!
//! - `TestCommitPropagatesEvaluatedLeaseFenceAndAbsenceAssertion` —
//!   evaluator-produced fence provenance.
//! - `TestClaimDelegatesMandatoryRecoveryAdmissionToCompositeCommit` +
//!   `TestNonClaimDoesNotRequestRecoveryAdmission` — recovery admission
//!   belongs to claim/start_harness_run only.
//! - `TestExactReceiptReplaySkipsStateEvaluationAndCommit`,
//!   `TestMismatchedReceiptFingerprintConflictsBeforeStateEvaluation`,
//!   `TestEvaluationFailureDoesNotCommit` — pipeline ordering.
//!
//! Fixture construction mirrors `authorizedRouteFixture` /
//! `serviceEvaluationFixture` / `activeServiceCommandFixture`: the
//! caller-side `envelope.state` is a hint the service discards — the
//! fake store's `state` is the authoritative snapshot.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::*;
use central_task::domain as task;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use crate::app::Service;
use crate::domain::*;
use crate::port::*;

const NOW: OffsetDateTime = datetime!(2026-07-27 12:00 UTC);

/// Runs an immediately-ready future to completion (the fakes never
/// yield). `Waker::noop` keeps this unsafe-free.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Fakes (upstream fakeCompositeStore / fakeExecutionRead / fixedClock).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeInner {
    commits: Mutex<u32>,
    reads: Mutex<u32>,
    lookups: Mutex<u32>,
    last_commit: Mutex<Option<CommitRequest>>,
    last_read: Mutex<Option<ExecutionReadRequest>>,
    last_receipt: Mutex<Option<ReceiptLookupRequest>>,
    state: Mutex<Option<ExecutionState>>,
    receipt: Mutex<ReceiptLookupResult>,
    commit_err: Mutex<Option<Failure>>,
    read_err: Mutex<Option<Failure>>,
    receipt_err: Mutex<Option<Failure>>,
}

/// `fakeCompositeStore` + `fakeExecutionRead` fused — the Rust
/// `CompositeExecutionStore` bound covers read + receipt + commit.
#[derive(Clone, Default)]
struct FakeStore {
    inner: Arc<FakeInner>,
}

impl FakeStore {
    fn with_state(state: ExecutionState) -> Self {
        let store = Self::default();
        *store.inner.state.lock().unwrap() = Some(state);
        store
    }
    fn commits(&self) -> u32 {
        *self.inner.commits.lock().unwrap()
    }
    fn reads(&self) -> u32 {
        *self.inner.reads.lock().unwrap()
    }
    fn lookups(&self) -> u32 {
        *self.inner.lookups.lock().unwrap()
    }
    fn last_commit(&self) -> CommitRequest {
        self.inner.last_commit.lock().unwrap().clone().unwrap()
    }
}

impl ExecutionRead for FakeStore {
    async fn read_execution(
        &self,
        request: ExecutionReadRequest,
    ) -> Result<ExecutionReadResult, Failure> {
        *self.inner.reads.lock().unwrap() += 1;
        *self.inner.last_read.lock().unwrap() = Some(request);
        if let Some(err) = self.inner.read_err.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(ExecutionReadResult {
            state: self
                .inner
                .state
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| unreachable!("fake store lacks authoritative state")),
        })
    }
}

impl CompositeStore for FakeStore {
    fn issue_lease_credential(&self) -> Result<LeaseCredential, Failure> {
        LeaseCredential::new(&[b'l'; 32])
    }
    async fn commit(&self, request: CommitRequest) -> Result<CommitResult, Failure> {
        *self.inner.commits.lock().unwrap() += 1;
        *self.inner.last_commit.lock().unwrap() = Some(request.clone());
        if let Some(err) = self.inner.commit_err.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(CommitResult {
            result: request.result,
            replayed: false,
        })
    }
}

impl CompositeExecutionStore for FakeStore {
    async fn lookup_receipt(
        &self,
        request: ReceiptLookupRequest,
    ) -> Result<ReceiptLookupResult, Failure> {
        *self.inner.lookups.lock().unwrap() += 1;
        *self.inner.last_receipt.lock().unwrap() = Some(request);
        if let Some(err) = self.inner.receipt_err.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(self.inner.receipt.lock().unwrap().clone())
    }
}

/// `LeaseCredentialValidator` fake — always approves.
struct FakeValidator;
impl LeaseCredentialValidator for FakeValidator {
    async fn validate_lease(&self, _request: LeaseValidationRequest) -> Result<(), Failure> {
        Ok(())
    }
}

/// `fixedClock`.
struct FixedClock(OffsetDateTime);
impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Fixtures (upstream serviceEvaluationFixture & friends).
// ---------------------------------------------------------------------------

fn service_evaluation_fixture(capability: Capability) -> (CommandEnvelope, ExecutionState) {
    let workspace_id = WorkspaceId::new();
    let task_id = TaskId::new();
    let run_id = RunId::new();
    let step_id = StepId::new();
    let scope = TrustedScope::new("principal-1", workspace_id, &[capability]).unwrap();
    let task_row = task::Task {
        id: task_id,
        workspace_id,
        version: 7,
        status: task::TaskStatus::Running,
        current_run_id: Some(run_id),
        parent_task_id: None,
        last_run_index: 0,
        retry_count: 0,
        retry_eligible_at: None,
        waiting_reason: None,
        failure_reason: String::new(),
        input: "input".to_string(),
        title: "execution task".to_string(),
        permission_policy: task::PermissionPolicy::Deny,
        budget: task::Budget::default(),
        created_at: NOW,
        updated_at: NOW,
    };
    let run_row = task::Run {
        id: run_id,
        task_id,
        workspace_id,
        version: 5,
        status: task::RunStatus::Running,
        index: 0,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: NOW,
        updated_at: NOW,
    };
    let step = Step {
        id: step_id,
        workspace_id,
        task_id,
        run_id,
        version: 2,
        sequence: 1,
        state: StepState::StepQueued,
        created_at: NOW,
        updated_at: NOW,
    };
    let state = ExecutionState {
        task: task::TaskAggregate {
            task: task_row.clone(),
            current_run: Some(run_row.clone()),
        },
        step: Some(step.clone()),
        attempt: None,
        tool_calls: vec![],
        tool_attempts: vec![],
        lease: None,
        approval: None,
    };
    let envelope = CommandEnvelope {
        scope,
        workspace_id,
        task_id,
        run_id,
        step_id,
        attempt_id: StepAttemptId::new(),
        logical_operation: LogicalOperationId::new(),
        expected: ExpectedVersions {
            task: task_row.version,
            run: run_row.version,
            step: step.version,
            ..ExpectedVersions::default()
        },
        operation_digest: RequestFingerprint::default(),
        lease_credential: LeaseCredential::default(),
        lease_generation: 0,
        assert_no_active_lease: true,
        state: state.clone(),
    };
    (envelope, state)
}

fn active_service_command_fixture(
    capability: Capability,
    attempt_state: AttemptState,
) -> (CommandEnvelope, ExecutionState) {
    let (mut envelope, mut state) = service_evaluation_fixture(capability);
    state.step.as_mut().unwrap().state = StepState::StepRunning;
    let attempt = StepAttempt {
        id: envelope.attempt_id,
        step_id: envelope.step_id,
        workspace_id: envelope.workspace_id,
        task_id: envelope.task_id,
        run_id: envelope.run_id,
        logical_operation_id: envelope.logical_operation,
        physical_attempt_id: PhysicalAttemptId::new(),
        invocation_id: InvocationId::default(),
        predecessor_id: NIL_STEP_ATTEMPT_ID,
        version: 1,
        sequence: 1,
        state: attempt_state,
        created_at: NOW,
        updated_at: NOW,
    };
    state.attempt = Some(attempt.clone());
    envelope.state = state.clone();
    envelope.expected.attempt = attempt.version;
    (envelope, state)
}

fn attach_service_lease(envelope: &mut CommandEnvelope, generation: i64) {
    let verifier = LeaseCredential::new(&[b'f'; 32]).unwrap();
    let lease = Lease {
        workspace_id: envelope.workspace_id,
        run_id: envelope.run_id,
        credential: verifier,
        generation,
        expires_at: NOW + Duration::minutes(1),
        updated_at: NOW,
    };
    envelope.state.lease = Some(lease);
    envelope.lease_credential = verifier;
    envelope.lease_generation = generation;
}

fn attach_service_tool_hierarchy(
    envelope: &mut CommandEnvelope,
    call_state: ToolCallState,
    attempt_state: AttemptState,
) -> (ToolCall, ToolCallAttempt) {
    let call = ToolCall {
        id: ToolCallId::new(),
        step_attempt_id: envelope.attempt_id,
        workspace_id: envelope.workspace_id,
        task_id: envelope.task_id,
        run_id: envelope.run_id,
        logical_operation_id: LogicalOperationId::new(),
        version: 1,
        sequence: 1,
        state: call_state,
        created_at: NOW,
        updated_at: NOW,
    };
    let attempt = ToolCallAttempt {
        id: ToolCallAttemptId::new(),
        tool_call_id: call.id,
        step_attempt_id: envelope.attempt_id,
        workspace_id: envelope.workspace_id,
        task_id: envelope.task_id,
        run_id: envelope.run_id,
        logical_operation_id: call.logical_operation_id,
        physical_attempt_id: PhysicalAttemptId::new(),
        invocation_id: InvocationId::default(),
        predecessor_id: NIL_TOOL_CALL_ATTEMPT_ID,
        version: 1,
        sequence: 1,
        state: attempt_state,
        created_at: NOW,
        updated_at: NOW,
    };
    envelope.state.tool_calls = vec![call.clone()];
    envelope.state.tool_attempts = vec![attempt.clone()];
    (call, attempt)
}

fn approval_service_command_fixture(
    capability: Capability,
    approval_state: ApprovalState,
) -> (CommandEnvelope, ExecutionState) {
    let (mut envelope, mut state) = service_evaluation_fixture(capability);
    state.task.task.status = task::TaskStatus::Waiting;
    state.task.task.waiting_reason = Some(task::WaitingReason::Approval);
    let run = state.task.current_run.as_mut().unwrap();
    run.status = task::RunStatus::Waiting;
    run.waiting_reason = Some(task::WaitingReason::Approval);
    state.step.as_mut().unwrap().state = StepState::StepWaiting;
    if matches!(
        approval_state,
        ApprovalState::ApprovalRejected | ApprovalState::ApprovalExpired
    ) {
        state.step.as_mut().unwrap().state = StepState::StepCancelled;
    }
    let approval = Approval {
        id: ApprovalId::new(),
        workspace_id: envelope.workspace_id,
        task_id: envelope.task_id,
        run_id: envelope.run_id,
        step_id: envelope.step_id,
        state: approval_state,
        subject: ApprovalSubject {
            version: 1,
            logical_operation_id: envelope.logical_operation,
            operation_digest: new_request_fingerprint(b"approved operation"),
            expected_step_version: envelope.expected.step,
        },
        predecessor_id: NIL_APPROVAL_ID,
        actor: String::new(),
        reason_code: String::new(),
        decision_id: [0u8; 16],
        decided_at: ZERO_TIME,
        version: 1,
        recorded_at: NOW,
    };
    state.approval = Some(approval.clone());
    envelope.operation_digest = approval.subject.operation_digest;
    envelope.state = state.clone();
    envelope.expected.approval = approval.version;
    (envelope, state)
}

/// `authorizedRouteFixture` — builds `(command, authoritative_state,
/// meta)`. The caller envelope keeps the state hint; the service
/// replaces it with the store's authoritative snapshot.
fn authorized_route_fixture(
    route: &str,
    capability: Capability,
) -> (Command, CommandEnvelope, ExecutionState, EvaluationMetadata) {
    let (mut envelope, mut state) = match route {
        "claim" | "heartbeat" | "mark invoked" | "prepare tool" | "mark tool invoked"
        | "settle tool" | "settle" | "cancel" | "checkpoint" => {
            let attempt_state = match route {
                "prepare tool" | "mark tool invoked" | "settle tool" | "settle" => {
                    AttemptState::AttemptInvoked
                }
                _ => AttemptState::AttemptPrepared,
            };
            active_service_command_fixture(capability, attempt_state)
        }
        "resolve approval" | "expire approval" => {
            approval_service_command_fixture(capability, ApprovalState::ApprovalPending)
        }
        "approval successor" => {
            approval_service_command_fixture(capability, ApprovalState::ApprovalRejected)
        }
        "resolve reconciliation" => {
            active_service_command_fixture(capability, AttemptState::AttemptReconciliation)
        }
        _ => service_evaluation_fixture(capability),
    };
    match route {
        "claim" => {
            envelope.lease_credential = LeaseCredential::new(&[b'c'; 32]).unwrap();
            envelope.lease_generation = 1;
        }
        "heartbeat" => attach_service_lease(&mut envelope, 2),
        "mark invoked" | "checkpoint" => {
            attach_service_lease(&mut envelope, 1);
        }
        "prepare tool" | "mark tool invoked" | "settle tool" | "settle" => {
            state.attempt.as_mut().unwrap().invocation_id = InvocationId::new();
            envelope.state = state.clone();
            attach_service_lease(&mut envelope, 1);
        }
        "cancel" => {
            state.task.task.status = task::TaskStatus::Cancelling;
            state.task.current_run.as_mut().unwrap().status = task::RunStatus::Cancelling;
            envelope.state = state.clone();
        }
        "resolve reconciliation" => {
            state.step.as_mut().unwrap().state = StepState::StepReconciliation;
            state.attempt.as_mut().unwrap().invocation_id = InvocationId::new();
            envelope.state = state.clone();
        }
        "record approval" => {
            state.step.as_mut().unwrap().state = StepState::StepRunning;
            envelope.state = state.clone();
            envelope.operation_digest = new_request_fingerprint(b"record approval");
        }
        "approval successor" => {
            envelope.operation_digest = new_request_fingerprint(b"approval successor");
        }
        _ => {}
    }
    let command = match route {
        "prepare" => Command::Prepare(PrepareCommand {
            envelope: envelope.clone(),
            physical_attempt_id: PhysicalAttemptId::new(),
            step_sequence: state.step.as_ref().map_or(1, |s| s.sequence),
            attempt_sequence: 1,
            approval_subject_version: 0,
            approval_expected_step_version: 0,
        }),
        "claim" => Command::Claim(ClaimCommand {
            envelope: envelope.clone(),
        }),
        "heartbeat" => Command::Heartbeat(HeartbeatCommand {
            envelope: envelope.clone(),
        }),
        "mark invoked" => Command::MarkInvoked(MarkInvokedCommand {
            envelope: envelope.clone(),
            invocation_id: InvocationId::new(),
            approval_subject_version: 0,
            approval_expected_step_version: 0,
        }),
        "prepare tool" => Command::PrepareToolCall(PrepareToolCallCommand {
            envelope: envelope.clone(),
            tool_call_id: ToolCallId::new(),
            tool_attempt_id: ToolCallAttemptId::new(),
            tool_logical_operation_id: LogicalOperationId::new(),
            physical_attempt_id: PhysicalAttemptId::new(),
            call_sequence: 1,
            attempt_sequence: 1,
            approval_subject_version: 0,
            approval_expected_step_version: 0,
        }),
        "mark tool invoked" => {
            let (call, attempt) = attach_service_tool_hierarchy(
                &mut envelope,
                ToolCallState::ToolCallPrepared,
                AttemptState::AttemptPrepared,
            );
            envelope.expected.tool_call = call.version;
            envelope.expected.tool_attempt = attempt.version;
            Command::MarkToolCallInvoked(MarkToolCallInvokedCommand {
                envelope: envelope.clone(),
                tool_call_id: call.id,
                tool_attempt_id: attempt.id,
                tool_logical_operation_id: call.logical_operation_id,
                invocation_id: InvocationId::new(),
                approval_subject_version: 0,
                approval_expected_step_version: 0,
            })
        }
        "settle tool" => {
            let (call, mut attempt) = attach_service_tool_hierarchy(
                &mut envelope,
                ToolCallState::ToolCallInvoked,
                AttemptState::AttemptInvoked,
            );
            attempt.invocation_id = InvocationId::new();
            envelope.state.tool_attempts = vec![attempt.clone()];
            envelope.expected.tool_call = call.version;
            envelope.expected.tool_attempt = attempt.version;
            let outcome =
                new_outcome_payload(br#"{"schema_version":1,"status":"succeeded"}"#).unwrap();
            Command::SettleToolCall(SettleToolCallCommand {
                envelope: envelope.clone(),
                tool_call_id: call.id,
                tool_attempt_id: attempt.id,
                tool_logical_operation_id: call.logical_operation_id,
                final_state: AttemptState::AttemptSucceeded,
                outcome,
                context: vec![],
            })
        }
        "settle" => {
            let outcome =
                new_outcome_payload(br#"{"schema_version":1,"status":"succeeded"}"#).unwrap();
            Command::Settle(SettleCommand {
                envelope: envelope.clone(),
                final_state: AttemptState::AttemptSucceeded,
                outcome,
                context: vec![],
                reason_code: "",
            })
        }
        "cancel" => Command::Cancel(CancelCommand {
            envelope: envelope.clone(),
            reason_code: "operator_request".to_string(),
        }),
        "checkpoint" => {
            let checkpoint =
                new_checkpoint(br#"{"schema_version":1,"producer_version":"service-test"}"#)
                    .unwrap();
            Command::RecordCheckpoint(RecordCheckpointCommand {
                envelope: envelope.clone(),
                checkpoint,
            })
        }
        "record approval" => Command::RecordApproval(RecordApprovalCommand {
            envelope: envelope.clone(),
            approval: Approval {
                id: ApprovalId::new(),
                workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
                task_id: TaskId::from_trusted_db_bytes([0; 16]),
                run_id: RunId::from_trusted_db_bytes([0; 16]),
                step_id: NIL_STEP_ID,
                state: ApprovalState::ApprovalPending,
                subject: ApprovalSubject {
                    version: 1,
                    logical_operation_id: envelope.logical_operation,
                    operation_digest: envelope.operation_digest,
                    expected_step_version: envelope.expected.step,
                },
                predecessor_id: NIL_APPROVAL_ID,
                actor: String::new(),
                reason_code: String::new(),
                decision_id: [0u8; 16],
                decided_at: ZERO_TIME,
                version: 0,
                recorded_at: ZERO_TIME,
            },
        }),
        "resolve approval" => {
            let approval_id = envelope.state.approval.as_ref().unwrap().id;
            Command::ResolveApproval(ResolveApprovalCommand {
                envelope: envelope.clone(),
                approval_id,
                decision: ApprovalState::ApprovalApproved,
            })
        }
        "expire approval" => {
            let approval_id = envelope.state.approval.as_ref().unwrap().id;
            Command::ExpireApproval(ExpireApprovalCommand {
                envelope: envelope.clone(),
                approval_id,
            })
        }
        "approval successor" => {
            let prior = envelope.state.approval.as_ref().unwrap().clone();
            Command::CreateApprovalSuccessor(CreateApprovalSuccessorCommand {
                envelope: envelope.clone(),
                approval_id: prior.id,
                successor_step_id: StepId::new(),
                successor_approval_id: ApprovalId::new(),
                subject: ApprovalSubject {
                    version: prior.subject.version + 1,
                    logical_operation_id: LogicalOperationId::new(),
                    operation_digest: envelope.operation_digest,
                    expected_step_version: 1,
                },
            })
        }
        "resolve reconciliation" => Command::ResolveReconciliation(ResolveReconciliationCommand {
            envelope: envelope.clone(),
            disposition: ReconciliationDisposition::ReconciliationConfirmSucceeded,
            evidence: vec![ReconciliationEvidence {
                kind: ReconciliationEvidenceKind::ReconciliationEvidenceCompletionReceipt,
                reference: "completion-receipt".to_string(),
            }],
        }),
        _ => unreachable!("unknown route fixture {route}"),
    };
    let meta = EvaluationMetadata {
        principal_id: envelope.scope.principal_id.clone(),
        capability,
        idempotency_key: format!("idem-{route}"),
        fingerprint: new_request_fingerprint(format!("canonical-{route}").as_bytes()),
        now: NOW,
        event_id: ExecutionEventId::new(),
        outbox_id: OutboxId::new(),
        producer_id: "producer-1".to_string(),
    };
    // The envelope's state hint is the authoritative snapshot — every
    // fixture mutation flows through it (upstream `authoritativeState =
    // envelope.State` after command construction).
    let authoritative = envelope.state.clone();
    (command, envelope, authoritative, meta)
}

fn failure_code(result: Result<CommitResult, Failure>) -> (&'static str, FailureKind) {
    let err = match result {
        Err(err) => err,
        Ok(_) => unreachable!("expected failure"),
    };
    (err.code(), err.kind())
}

// ---------------------------------------------------------------------------
// TestCommitPropagatesEvaluatedLeaseFenceAndAbsenceAssertion
// ---------------------------------------------------------------------------

#[test]
fn commit_propagates_evaluated_lease_fence_and_absence_assertion() {
    struct Row {
        route: &'static str,
        capability: Capability,
        /// Attach an active authoritative lease + caller fence.
        active_operator: bool,
        want_fence: bool,
        want_no_active: bool,
        want_generation: i64,
    }
    let rows = [
        Row {
            route: "heartbeat",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 2,
        },
        Row {
            route: "mark invoked",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 1,
        },
        Row {
            route: "prepare tool",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 1,
        },
        Row {
            route: "mark tool invoked",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 1,
        },
        Row {
            route: "settle tool",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 1,
        },
        Row {
            route: "checkpoint",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 1,
        },
        Row {
            route: "settle",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: true,
            want_no_active: false,
            want_generation: 1,
        },
        Row {
            route: "cancel",
            capability: Capability::WorkspaceOperator,
            active_operator: true,
            want_fence: true,
            want_no_active: false,
            want_generation: 3,
        },
        Row {
            route: "cancel",
            capability: Capability::WorkspaceOperator,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
        Row {
            route: "resolve reconciliation",
            capability: Capability::WorkspaceOperator,
            active_operator: true,
            want_fence: true,
            want_no_active: false,
            want_generation: 3,
        },
        Row {
            route: "resolve reconciliation",
            capability: Capability::WorkspaceOperator,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
        Row {
            route: "prepare",
            capability: Capability::Executor,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
        Row {
            route: "record approval",
            capability: Capability::Approver,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
        Row {
            route: "resolve approval",
            capability: Capability::Approver,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
        Row {
            route: "expire approval",
            capability: Capability::Approver,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
        Row {
            route: "approval successor",
            capability: Capability::WorkspaceOperator,
            active_operator: false,
            want_fence: false,
            want_no_active: true,
            want_generation: 0,
        },
    ];
    for row in rows {
        let label = format!("{} (active={})", row.route, row.active_operator);
        let (command, mut envelope, mut state, meta) =
            authorized_route_fixture(row.route, row.capability);
        if row.active_operator {
            let verifier = LeaseCredential::new(&[b'o'; 32]).unwrap();
            state.lease = Some(Lease {
                workspace_id: envelope.workspace_id,
                run_id: envelope.run_id,
                credential: verifier,
                generation: row.want_generation,
                expires_at: NOW + Duration::minutes(1),
                updated_at: NOW,
            });
            envelope.lease_credential = verifier;
            envelope.lease_generation = row.want_generation;
            envelope.assert_no_active_lease = false;
        }
        let command = {
            let mut command = command;
            match &mut command {
                Command::Cancel(c) => c.envelope = envelope.clone(),
                Command::ResolveReconciliation(c) => c.envelope = envelope.clone(),
                _ => {}
            }
            command
        };
        let store = FakeStore::with_state(state.clone());
        let service = Service::new(store.clone(), FakeValidator, FixedClock(NOW));
        block_on(service.execute(command, meta))
            .unwrap_or_else(|e| unreachable!("service call for {label}: {}", e.code()));
        assert_eq!(store.commits(), 1, "{label}: composite commits");
        let last = store.last_commit();
        assert_eq!(
            last.assert_no_active_lease, row.want_no_active,
            "{label}: no-active-lease assertion"
        );
        if row.want_fence {
            let lease = state
                .lease
                .clone()
                .unwrap_or_else(|| unreachable!("{label}: fixture lacks authoritative lease"));
            assert_eq!(
                last.lease_credential, lease.credential,
                "{label}: commit fence verifier"
            );
            assert_eq!(
                last.lease_generation, row.want_generation,
                "{label}: commit fence generation"
            );
        } else {
            assert_eq!(
                last.lease_credential,
                LeaseCredential::default(),
                "{label}: unexpected commit fence verifier"
            );
            assert_eq!(last.lease_generation, 0, "{label}: unexpected generation");
        }
    }
}

// ---------------------------------------------------------------------------
// TestClaimDelegatesMandatoryRecoveryAdmissionToCompositeCommit +
// TestNonClaimDoesNotRequestRecoveryAdmission
// ---------------------------------------------------------------------------

#[test]
fn claim_delegates_mandatory_recovery_admission_to_composite_commit() {
    let (command, _envelope, state, meta) = authorized_route_fixture("claim", Capability::Executor);
    let store = FakeStore::with_state(state);
    let service = Service::new(store.clone(), FakeValidator, FixedClock(NOW));
    block_on(service.claim(command, meta)).unwrap();
    assert_eq!(store.lookups(), 1);
    assert_eq!(store.reads(), 1);
    assert_eq!(store.commits(), 1);
    assert!(
        store.last_commit().require_recovery_claimable,
        "claim omitted mandatory transaction-owned recovery admission"
    );
}

#[test]
fn non_claim_does_not_request_recovery_admission() {
    let (command, _envelope, state, meta) =
        authorized_route_fixture("heartbeat", Capability::Executor);
    let store = FakeStore::with_state(state);
    let service = Service::new(store.clone(), FakeValidator, FixedClock(NOW));
    block_on(service.execute(command, meta)).unwrap();
    assert!(
        !store.last_commit().require_recovery_claimable,
        "non-claim requested recovery claim admission"
    );
}

// ---------------------------------------------------------------------------
// TestExactReceiptReplaySkipsStateEvaluationAndCommit +
// TestMismatchedReceiptFingerprintConflictsBeforeStateEvaluation +
// TestEvaluationFailureDoesNotCommit
// ---------------------------------------------------------------------------

#[test]
fn exact_receipt_replay_skips_state_evaluation_and_commit() {
    let (command, envelope, _state, meta) =
        authorized_route_fixture("prepare", Capability::Executor);
    let want = DurableResult {
        workspace_id: envelope.workspace_id,
        task_id: envelope.task_id,
        run_id: envelope.run_id,
        step_id: envelope.step_id,
        attempt_id: envelope.attempt_id,
        event_id: ExecutionEventId::new(),
        event_kind: EVENT_TOOL_CALL_SETTLED.to_string(),
        approval_action: None,
    };
    let store = FakeStore::with_state(ExecutionState {
        task: task::TaskAggregate {
            task: task::Task {
                id: TaskId::new(),
                workspace_id: envelope.workspace_id,
                version: 1,
                status: task::TaskStatus::Running,
                current_run_id: None,
                parent_task_id: None,
                last_run_index: 0,
                retry_count: 0,
                retry_eligible_at: None,
                waiting_reason: None,
                failure_reason: String::new(),
                input: String::new(),
                title: String::new(),
                permission_policy: task::PermissionPolicy::Deny,
                budget: task::Budget::default(),
                created_at: NOW,
                updated_at: NOW,
            },
            current_run: None,
        },
        step: None,
        attempt: None,
        tool_calls: vec![],
        tool_attempts: vec![],
        lease: None,
        approval: None,
    });
    *store.inner.receipt.lock().unwrap() = ReceiptLookupResult {
        found: true,
        result: Some(want.clone()),
    };
    let service = Service::new(store.clone(), FakeValidator, FixedClock(NOW));
    let got = block_on(service.execute(command, meta)).unwrap();
    assert!(got.replayed);
    assert_eq!(got.result, want);
    assert_eq!(store.lookups(), 1);
    assert_eq!(store.reads(), 0, "replay must not read authoritative state");
    assert_eq!(store.commits(), 0, "replay must not commit");
}

#[test]
fn mismatched_receipt_fingerprint_conflicts_before_state_evaluation() {
    let (command, _envelope, state, meta) =
        authorized_route_fixture("prepare", Capability::Executor);
    let store = FakeStore::with_state(state);
    *store.inner.receipt_err.lock().unwrap() = Some(Failure::conflict(
        "IDEMPOTENCY_CONFLICT",
        "receipt fingerprint mismatch",
    ));
    let service = Service::new(store.clone(), FakeValidator, FixedClock(NOW));
    let result = block_on(service.execute(command, meta));
    assert_eq!(
        failure_code(result),
        ("IDEMPOTENCY_CONFLICT", FailureKind::Conflict)
    );
    assert_eq!(store.lookups(), 1);
    assert_eq!(store.reads(), 0, "receipt conflict must not read state");
    assert_eq!(store.commits(), 0, "receipt conflict must not commit");
}

#[test]
fn evaluation_failure_does_not_commit() {
    let (command, _envelope, _state, meta) =
        authorized_route_fixture("prepare", Capability::Executor);
    // An authoritative snapshot bound to different identities fails
    // evaluation at the scope check (upstream ExecutionState{}).
    let (_other_command, _other_envelope, other_state, _other_meta) =
        authorized_route_fixture("prepare", Capability::Executor);
    let store = FakeStore::with_state(other_state);
    let service = Service::new(store.clone(), FakeValidator, FixedClock(NOW));
    let result = block_on(service.execute(command, meta));
    assert_eq!(
        failure_code(result),
        ("STATE_SCOPE_MISMATCH", FailureKind::Invalid)
    );
    assert_eq!(store.lookups(), 1);
    assert_eq!(store.reads(), 1);
    assert_eq!(store.commits(), 0);
}
