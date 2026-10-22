//! Tests — ported scenarios from upstream
//! `internal/execution/{domain,harness_run,resume,cancel_lease,
//! recovery_cancellation}_test.go` and the application tests.
//!
//! Fixture construction mirrors `execution_facade_test.go` patterns:
//! task aggregates are minted through `central_task`'s own evaluators
//! so state shape is always domain-valid.

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::*;
use central_task::domain as task;
use time::Duration;
use time::OffsetDateTime;
use time::macros::datetime;

use crate::domain::*;
use crate::harness_run::*;
use crate::resume::*;

const T0: OffsetDateTime = datetime!(2026-09-28 12:00 UTC);

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

fn scope() -> TrustedScope {
    TrustedScope {
        principal_id: "principal-1".to_string(),
        workspace_id: WorkspaceId::new(),
        capabilities: [
            Capability::Executor,
            Capability::Approver,
            Capability::WorkspaceOperator,
        ]
        .into_iter()
        .collect(),
    }
}

fn queued_aggregate(workspace: WorkspaceId) -> task::TaskAggregate {
    let cs = task::submit_task(task::SubmitTaskRequest {
        workspace_id: workspace,
        title: "execution task".to_string(),
        input: "input".to_string(),
        permission_policy: None,
        budget: task::Budget::default(),
        run_key: None,
        now: T0 - Duration::hours(1),
    })
    .unwrap();
    task::TaskAggregate {
        task: cs.task.clone(),
        current_run: cs.runs.first().cloned(),
    }
}

fn running_aggregate(workspace: WorkspaceId) -> task::TaskAggregate {
    let queued = queued_aggregate(workspace);
    let cs = task::claim_current_run(task::ClaimCurrentRunRequest {
        input: task::MutationInput {
            aggregate: queued.clone(),
            expected_task_version: queued.task.version,
            expected_run_version: queued.current_run.as_ref().unwrap().version,
            now: T0 - Duration::minutes(30),
        },
        owner: "executor".to_string(),
    })
    .unwrap();
    task::TaskAggregate {
        task: cs.task.clone(),
        current_run: cs.runs.first().cloned(),
    }
}

fn waiting_reconciliation_aggregate(workspace: WorkspaceId) -> task::TaskAggregate {
    let running = running_aggregate(workspace);
    let cs = task::wait_task(task::WaitTaskRequest {
        input: task::MutationInput {
            aggregate: running.clone(),
            expected_task_version: running.task.version,
            expected_run_version: running.current_run.as_ref().unwrap().version,
            now: T0 - Duration::minutes(20),
        },
        reason: Some(task::WaitingReason::Reconciliation),
        detail: "reconcile".to_string(),
    })
    .unwrap();
    task::TaskAggregate {
        task: cs.task.clone(),
        current_run: cs.runs.first().cloned(),
    }
}

fn cancelling_aggregate(workspace: WorkspaceId) -> task::TaskAggregate {
    let running = running_aggregate(workspace);
    let cs = task::request_cancellation(task::RequestCancellationRequest {
        input: task::MutationInput {
            aggregate: running.clone(),
            expected_task_version: running.task.version,
            expected_run_version: running.current_run.as_ref().unwrap().version,
            now: T0 - Duration::minutes(10),
        },
    })
    .unwrap();
    task::TaskAggregate {
        task: cs.task.clone(),
        current_run: cs.runs.first().cloned(),
    }
}

fn meta() -> EvaluationMetadata {
    EvaluationMetadata {
        principal_id: "principal-1".to_string(),
        capability: Capability::Executor,
        idempotency_key: "idem-1".to_string(),
        fingerprint: new_request_fingerprint(b"request"),
        now: T0,
        event_id: ExecutionEventId::new(),
        outbox_id: OutboxId::new(),
        producer_id: "producer-1".to_string(),
    }
}

fn step(workspace: WorkspaceId, task_id: TaskId, run_id: RunId) -> Step {
    Step {
        id: StepId::new(),
        workspace_id: workspace,
        task_id,
        run_id,
        version: 1,
        sequence: 1,
        state: StepState::StepRunning,
        created_at: T0 - Duration::minutes(5),
        updated_at: T0 - Duration::minutes(5),
    }
}

fn prepared_attempt(step: &Step) -> StepAttempt {
    StepAttempt {
        id: StepAttemptId::new(),
        step_id: step.id,
        workspace_id: step.workspace_id,
        task_id: step.task_id,
        run_id: step.run_id,
        logical_operation_id: LogicalOperationId::new(),
        physical_attempt_id: PhysicalAttemptId::new(),
        invocation_id: InvocationId::default(),
        predecessor_id: NIL_STEP_ATTEMPT_ID,
        version: 1,
        sequence: 1,
        state: AttemptState::AttemptPrepared,
        created_at: T0 - Duration::minutes(4),
        updated_at: T0 - Duration::minutes(4),
    }
}

fn invoked_attempt(step: &Step) -> StepAttempt {
    let mut attempt = prepared_attempt(step);
    attempt.state = AttemptState::AttemptInvoked;
    attempt.invocation_id = InvocationId::new();
    attempt
}

fn lease(
    workspace: WorkspaceId,
    run_id: RunId,
    generation: i64,
    expires_at: OffsetDateTime,
) -> Lease {
    Lease {
        workspace_id: workspace,
        run_id,
        credential: LeaseCredential([7u8; 32]),
        generation,
        expires_at,
        updated_at: T0 - Duration::minutes(1),
    }
}

fn envelope(
    scope: &TrustedScope,
    agg: &task::TaskAggregate,
    state: ExecutionState,
) -> CommandEnvelope {
    CommandEnvelope {
        scope: scope.clone(),
        workspace_id: scope.workspace_id,
        task_id: agg.task.id,
        run_id: agg.current_run.as_ref().map_or(RunId::new(), |r| r.id),
        step_id: state.step.as_ref().map_or(StepId::new(), |s| s.id),
        attempt_id: state.attempt.as_ref().map_or(NIL_STEP_ATTEMPT_ID, |a| a.id),
        logical_operation: state
            .attempt
            .as_ref()
            .map_or_else(LogicalOperationId::new, |a| a.logical_operation_id),
        expected: ExpectedVersions {
            task: agg.task.version,
            run: agg.current_run.as_ref().map_or(0, |r| r.version),
            step: state.step.as_ref().map_or(0, |s| s.version),
            attempt: state.attempt.as_ref().map_or(0, |a| a.version),
            ..ExpectedVersions::default()
        },
        operation_digest: new_request_fingerprint(b"operation"),
        lease_credential: LeaseCredential::default(),
        lease_generation: 0,
        assert_no_active_lease: false,
        state,
    }
}

fn err_code(result: Result<ExecutionChangeSet, Failure>) -> (&'static str, FailureKind) {
    let e = match result {
        Err(e) => e,
        Ok(_) => unreachable!("expected failure"),
    };
    (e.code(), e.kind())
}

// ---------------------------------------------------------------------------
// domain_test.go — state machines and transition helpers.
// ---------------------------------------------------------------------------

#[test]
fn step_attempt_toolcall_closed_transitions() {
    let s = step(scope().workspace_id, TaskId::new(), RunId::new());
    assert!(transition_step(s.clone(), StepState::StepSucceeded).is_err());
    let settling = transition_step(s.clone(), StepState::StepSettling).unwrap();
    assert_eq!(settling.version, 2);
    assert!(transition_step(settling.clone(), StepState::StepSucceeded).is_ok());
    let e = transition_step(settling, StepState::StepRunning).unwrap_err();
    assert_eq!(e.code(), "INVALID_TRANSITION");

    let a = prepared_attempt(&s);
    assert!(transition_attempt(a.clone(), AttemptState::AttemptSucceeded).is_err());
    let invoked = mark_attempt_invoked(a, InvocationId::new()).unwrap();
    assert_eq!(invoked.state, AttemptState::AttemptInvoked);
    assert!(!invoked.invocation_id.is_nil());
    let e = mark_attempt_invoked(invoked, InvocationId::new()).unwrap_err();
    assert_eq!(e.code(), "IMMUTABLE_ATTEMPT");
}

#[test]
fn lease_credential_requires_256_bits() {
    assert!(!LeaseCredential::default().valid());
    assert!(LeaseCredential([1u8; 32]).valid());
}

// ---------------------------------------------------------------------------
// domain_test.go — claim semantics (generation fencing).
// ---------------------------------------------------------------------------

fn claim_state(
    agg: &task::TaskAggregate,
    s: &Step,
    a: &StepAttempt,
    lease_row: Option<Lease>,
) -> ExecutionState {
    ExecutionState {
        task: agg.clone(),
        step: Some(s.clone()),
        attempt: Some(a.clone()),
        tool_calls: vec![],
        tool_attempts: vec![],
        lease: lease_row,
        approval: None,
    }
}

#[test]
fn claim_mints_generation_one_and_conflicts_on_active_lease() {
    let sc = scope();
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let state = claim_state(&agg, &s, &a, None);
    let mut env = envelope(&sc, &agg, state);
    env.lease_credential = LeaseCredential([9u8; 32]);
    env.lease_generation = 1;
    let change = evaluate_command(Command::Claim(ClaimCommand { envelope: env }), &meta()).unwrap();
    assert_eq!(change.leases.len(), 1);
    assert_eq!(change.leases[0].generation, 1);
    assert_eq!(change.leases[0].expires_at, T0 + DEFAULT_LEASE_DURATION);
    assert_eq!(change.events[0].kind, EVENT_ATTEMPT_CLAIMED);

    // Active lease → conflict.
    let state = claim_state(
        &agg,
        &s,
        &a,
        Some(lease(
            sc.workspace_id,
            s.run_id,
            1,
            T0 + Duration::seconds(30),
        )),
    );
    let mut env = envelope(&sc, &agg, state);
    env.lease_credential = LeaseCredential([9u8; 32]);
    env.lease_generation = 2;
    let (code, kind) = err_code(evaluate_command(
        Command::Claim(ClaimCommand { envelope: env }),
        &meta(),
    ));
    assert_eq!(
        (code, kind),
        ("ACTIVE_LEASE_CONFLICT", FailureKind::Conflict)
    );

    // Expired lease row → next generation (B08: expiry, never delete).
    let state = claim_state(
        &agg,
        &s,
        &a,
        Some(lease(
            sc.workspace_id,
            s.run_id,
            4,
            T0 - Duration::seconds(1),
        )),
    );
    let mut env = envelope(&sc, &agg, state);
    env.lease_credential = LeaseCredential([9u8; 32]);
    env.lease_generation = 5;
    let change = evaluate_command(Command::Claim(ClaimCommand { envelope: env }), &meta()).unwrap();
    assert_eq!(change.leases[0].generation, 5);

    // Stale generation guess → fence.
    let state = claim_state(
        &agg,
        &s,
        &a,
        Some(lease(
            sc.workspace_id,
            s.run_id,
            4,
            T0 - Duration::seconds(1),
        )),
    );
    let mut env = envelope(&sc, &agg, state);
    env.lease_credential = LeaseCredential([9u8; 32]);
    env.lease_generation = 3;
    let (code, _) = err_code(evaluate_command(
        Command::Claim(ClaimCommand { envelope: env }),
        &meta(),
    ));
    assert_eq!(code, "STALE_LEASE_FENCE");
}

// ---------------------------------------------------------------------------
// domain_test.go — settle/cancel + lease fencing.
// ---------------------------------------------------------------------------

fn fenced_env(
    sc: &TrustedScope,
    agg: &task::TaskAggregate,
    state: ExecutionState,
    generation: i64,
) -> CommandEnvelope {
    let mut env = envelope(sc, agg, state);
    env.lease_credential = LeaseCredential([7u8; 32]);
    env.lease_generation = generation;
    env
}

#[test]
fn settle_releases_lease_and_completes_task() {
    let sc = scope();
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = invoked_attempt(&s);
    let lease_row = lease(sc.workspace_id, s.run_id, 1, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let env = fenced_env(&sc, &agg, state, 1);
    let change = evaluate_command(
        Command::Settle(SettleCommand {
            envelope: env,
            final_state: AttemptState::AttemptSucceeded,
            outcome: new_settlement_outcome(AttemptState::AttemptSucceeded, "").unwrap(),
            context: vec![],
            reason_code: "",
        }),
        &meta(),
    )
    .unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptSucceeded);
    assert_eq!(change.steps[0].state, StepState::StepSucceeded);
    assert_eq!(change.lease_releases.len(), 1);
    assert_eq!(change.settlements.len(), 1);
    assert_eq!(change.events[0].kind, EVENT_ATTEMPT_SETTLED);
    let transition = change.task_transition.unwrap();
    assert_eq!(
        transition.change_set.task.status,
        task::TaskStatus::Completed
    );
}

#[test]
fn settle_requires_fenced_lease() {
    let sc = scope();
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = invoked_attempt(&s);
    // No lease at all.
    let state = claim_state(&agg, &s, &a, None);
    let env = fenced_env(&sc, &agg, state, 1);
    let (code, _) = err_code(evaluate_command(
        Command::Settle(SettleCommand {
            envelope: env,
            final_state: AttemptState::AttemptSucceeded,
            outcome: new_settlement_outcome(AttemptState::AttemptSucceeded, "").unwrap(),
            context: vec![],
            reason_code: "",
        }),
        &meta(),
    ));
    assert_eq!(code, "STALE_LEASE_FENCE");
    // Expired lease is no lease.
    let state = claim_state(
        &agg,
        &s,
        &a,
        Some(lease(
            sc.workspace_id,
            s.run_id,
            1,
            T0 - Duration::seconds(1),
        )),
    );
    let env = fenced_env(&sc, &agg, state, 1);
    let (code, _) = err_code(evaluate_command(
        Command::Settle(SettleCommand {
            envelope: env,
            final_state: AttemptState::AttemptSucceeded,
            outcome: new_settlement_outcome(AttemptState::AttemptSucceeded, "").unwrap(),
            context: vec![],
            reason_code: "",
        }),
        &meta(),
    ));
    assert_eq!(code, "STALE_LEASE_FENCE");
}

#[test]
fn cancel_prepared_releases_lease_invoked_needs_reconciliation() {
    let sc = scope();
    let agg = cancelling_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let lease_row = lease(sc.workspace_id, s.run_id, 1, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let mut env = fenced_env(&sc, &agg, state, 1);
    env.expected.task = agg.task.version;
    env.expected.run = agg.current_run.as_ref().unwrap().version;
    let mut op_meta = meta();
    op_meta.capability = Capability::WorkspaceOperator;
    let change = evaluate_command(
        Command::Cancel(CancelCommand {
            envelope: env,
            reason_code: "operator_request".to_string(),
        }),
        &op_meta,
    )
    .unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptCancelled);
    assert_eq!(change.lease_releases.len(), 1);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Cancelled
    );

    // Invoked attempt cannot be cancelled directly.
    let a = invoked_attempt(&s);
    let state = claim_state(
        &agg,
        &s,
        &a,
        Some(lease(
            sc.workspace_id,
            s.run_id,
            1,
            T0 + Duration::seconds(30),
        )),
    );
    let env = fenced_env(&sc, &agg, state, 1);
    let (code, kind) = err_code(evaluate_command(
        Command::Cancel(CancelCommand {
            envelope: env,
            reason_code: "operator_request".to_string(),
        }),
        &op_meta,
    ));
    assert_eq!(
        (code, kind),
        ("RECONCILIATION_REQUIRED", FailureKind::Denied)
    );
}

// ---------------------------------------------------------------------------
// harness_run_test.go — failure vocabulary, start, abandon, settle-cancel.
// ---------------------------------------------------------------------------

#[test]
fn failure_reason_vocabulary_is_bounded() {
    assert!(failure_reason_known(FAILURE_REASON_HARNESS_API_ERROR));
    assert!(failure_reason_known(FAILURE_REASON_EXECUTION_FAILED));
    assert!(!failure_reason_known("clone failed: disk full"));
    assert!(!failure_reason_known("the model refused"));
    assert!(!failure_reason_known(""));
    let outcome = new_settlement_outcome(
        AttemptState::AttemptFailed,
        FAILURE_REASON_WORKSPACE_UNAVAILABLE,
    )
    .unwrap();
    let text = String::from_utf8(outcome).unwrap();
    assert!(text.contains("\"reason_code\":\"workspace_unavailable\""));
    assert!(new_settlement_outcome(AttemptState::AttemptFailed, "bogus").is_err());
    assert!(
        new_settlement_outcome(
            AttemptState::AttemptSucceeded,
            FAILURE_REASON_HARNESS_API_ERROR
        )
        .is_err()
    );
}

#[test]
fn start_harness_run_fuses_claim_step_attempt_lease() {
    let sc = scope();
    let agg = queued_aggregate(sc.workspace_id);
    let state = ExecutionState {
        task: agg.clone(),
        step: None,
        attempt: None,
        tool_calls: vec![],
        tool_attempts: vec![],
        lease: None,
        approval: None,
    };
    let mut env = envelope(&sc, &agg, state);
    env.attempt_id = StepAttemptId::new();
    env.step_id = StepId::new();
    env.lease_credential = LeaseCredential([3u8; 32]);
    env.lease_generation = 1;
    let change = evaluate_command(
        Command::StartHarnessRun(StartHarnessRunCommand {
            envelope: env,
            physical_attempt_id: PhysicalAttemptId::new(),
            step_sequence: 1,
            attempt_sequence: 1,
        }),
        &meta(),
    )
    .unwrap();
    assert_eq!(change.steps.len(), 1);
    assert_eq!(change.attempts.len(), 1);
    assert_eq!(change.leases.len(), 1);
    assert_eq!(change.events[0].kind, EVENT_HARNESS_RUN_STARTED);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Running
    );

    // A running task cannot be claimed again.
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let state = claim_state(&agg, &s, &a, None);
    let mut env = envelope(&sc, &agg, state);
    env.lease_credential = LeaseCredential([3u8; 32]);
    env.lease_generation = 1;
    let (code, _) = err_code(evaluate_command(
        Command::StartHarnessRun(StartHarnessRunCommand {
            envelope: env,
            physical_attempt_id: PhysicalAttemptId::new(),
            step_sequence: 2,
            attempt_sequence: 1,
        }),
        &meta(),
    ));
    assert_eq!(code, "ACTIVE_ATTEMPT_CONFLICT");
}

#[test]
fn start_harness_run_refuses_expected_attempt_and_pending_approval() {
    let sc = scope();
    let agg = queued_aggregate(sc.workspace_id);
    let state = ExecutionState {
        task: agg.clone(),
        step: None,
        attempt: None,
        tool_calls: vec![],
        tool_attempts: vec![],
        lease: None,
        approval: None,
    };
    let fresh_env = |state: ExecutionState| {
        let mut env = envelope(&sc, &agg, state);
        env.attempt_id = StepAttemptId::new();
        env.step_id = StepId::new();
        env.lease_credential = LeaseCredential([3u8; 32]);
        env.lease_generation = 1;
        env
    };
    let start = |env: CommandEnvelope| {
        evaluate_command(
            Command::StartHarnessRun(StartHarnessRunCommand {
                envelope: env,
                physical_attempt_id: PhysicalAttemptId::new(),
                step_sequence: 1,
                attempt_sequence: 1,
            }),
            &meta(),
        )
    };

    // An expected attempt version asserts an attempt that does not
    // exist (upstream harness_run.go:224-227 → ACTIVE_ATTEMPT_CONFLICT).
    let mut env = fresh_env(state.clone());
    env.expected.attempt = 1;
    let (code, kind) = err_code(start(env));
    assert_eq!(
        (code, kind),
        ("ACTIVE_ATTEMPT_CONFLICT", FailureKind::Conflict)
    );

    // A pending approval gates the run (upstream harness_run.go:228-230
    // → APPROVAL_REQUIRED).
    let mut env = fresh_env(state);
    env.state.approval = Some(Approval {
        id: ApprovalId::new(),
        workspace_id: sc.workspace_id,
        task_id: agg.task.id,
        run_id: env.run_id,
        step_id: env.step_id,
        state: ApprovalState::ApprovalPending,
        subject: ApprovalSubject {
            version: 1,
            logical_operation_id: env.logical_operation,
            operation_digest: env.operation_digest,
            expected_step_version: 0,
        },
        predecessor_id: NIL_APPROVAL_ID,
        actor: String::new(),
        reason_code: String::new(),
        decision_id: [0u8; 16],
        decided_at: ZERO_TIME,
        version: 1,
        recorded_at: T0,
    });
    let (code, kind) = err_code(start(env));
    assert_eq!((code, kind), ("APPROVAL_REQUIRED", FailureKind::Denied));
}

#[test]
fn abandon_prepared_and_settle_cancellation() {
    let sc = scope();
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let lease_row = lease(sc.workspace_id, s.run_id, 1, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let env = fenced_env(&sc, &agg, state, 1);
    let change = evaluate_command(
        Command::AbandonPrepared(AbandonPreparedCommand {
            envelope: env,
            reason_code: FAILURE_REASON_WORKSPACE_UNAVAILABLE,
        }),
        &meta(),
    )
    .unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptCancelled);
    assert_eq!(change.events[0].kind, EVENT_ATTEMPT_ABANDONED);
    assert_eq!(change.lease_releases.len(), 1);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Failed
    );

    // Unknown reason refused.
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let env = fenced_env(&sc, &agg, state, 1);
    let (code, _) = err_code(evaluate_command(
        Command::AbandonPrepared(AbandonPreparedCommand {
            envelope: env,
            reason_code: "b09_something",
        }),
        &meta(),
    ));
    assert_eq!(code, "INVALID_FAILURE_REASON");

    // A reconciliation-state attempt is immutable for abandon — only
    // Invoked/Settling map to RECONCILIATION_REQUIRED here (upstream
    // harness_run.go:303-309; cancel_prepared_for_recovery keeps the
    // wider arm deliberately).
    let mut a = prepared_attempt(&s);
    a.state = AttemptState::AttemptReconciliation;
    a.invocation_id = InvocationId::new();
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let env = fenced_env(&sc, &agg, state, 1);
    let (code, kind) = err_code(evaluate_command(
        Command::AbandonPrepared(AbandonPreparedCommand {
            envelope: env,
            reason_code: FAILURE_REASON_WORKSPACE_UNAVAILABLE,
        }),
        &meta(),
    ));
    assert_eq!((code, kind), ("IMMUTABLE_ATTEMPT", FailureKind::Denied));

    // SettleCancellation on a cancelling task: prepared → cancelled.
    let agg = cancelling_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let lease_row = lease(sc.workspace_id, s.run_id, 1, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let mut env = fenced_env(&sc, &agg, state, 1);
    env.expected.task = agg.task.version;
    env.expected.run = agg.current_run.as_ref().unwrap().version;
    let change = evaluate_command(
        Command::SettleCancellation(SettleCancellationCommand {
            envelope: env,
            executor_stopped: false,
        }),
        &meta(),
    )
    .unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptCancelled);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Cancelled
    );

    // Invoked + executor_stopped settles through reconciliation.
    let a = invoked_attempt(&s);
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let mut env = fenced_env(&sc, &agg, state, 1);
    env.expected.task = agg.task.version;
    env.expected.run = agg.current_run.as_ref().unwrap().version;
    let change = evaluate_command(
        Command::SettleCancellation(SettleCancellationCommand {
            envelope: env,
            executor_stopped: true,
        }),
        &meta(),
    )
    .unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptCancelled);

    // Not-requested task refuses.
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let lease_row = lease(sc.workspace_id, s.run_id, 1, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(lease_row.clone()));
    let env = fenced_env(&sc, &agg, state, 1);
    let (code, _) = err_code(evaluate_command(
        Command::SettleCancellation(SettleCancellationCommand {
            envelope: env,
            executor_stopped: false,
        }),
        &meta(),
    ));
    assert_eq!(code, "CANCELLATION_NOT_REQUESTED");
}

// ---------------------------------------------------------------------------
// B08 recovery evaluators — successor minting, cancellation, completion.
// ---------------------------------------------------------------------------

#[test]
fn recovery_mints_prepared_successor_for_never_invoked_attempt() {
    let sc = scope();
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    // Expired ownership row: recovery treats it as no lease.
    let expired = lease(sc.workspace_id, s.run_id, 2, T0 - Duration::seconds(5));
    let state = claim_state(&agg, &s, &a, Some(expired));
    let change = evaluate_recovery(&state, T0, 7, StepAttemptId::new()).unwrap();
    assert_eq!(change.attempts.len(), 2);
    assert_eq!(change.attempts[0].state, AttemptState::AttemptCancelled);
    assert_eq!(change.attempts[0].version, 2);
    let successor = &change.attempts[1];
    assert_eq!(successor.state, AttemptState::AttemptPrepared);
    assert_eq!(successor.sequence, 2);
    assert_eq!(successor.logical_operation_id, a.logical_operation_id);
    assert_eq!(successor.predecessor_id, a.id);
    assert_eq!(change.lease_assertions.len(), 1);

    // An active lease bars recovery.
    let active = lease(sc.workspace_id, s.run_id, 2, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(active));
    let e = evaluate_recovery(&state, T0, 7, StepAttemptId::new()).unwrap_err();
    assert_eq!(e.code(), "ACTIVE_LEASE_CONFLICT");
}

#[test]
fn recovery_cancellation_settles_prepared_attempt() {
    let sc = scope();
    let agg = cancelling_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = prepared_attempt(&s);
    let expired = lease(sc.workspace_id, s.run_id, 1, T0 - Duration::seconds(5));
    let state = claim_state(&agg, &s, &a, Some(expired));
    let change = evaluate_recovery_cancellation(&state, T0).unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptCancelled);
    assert_eq!(change.steps[0].state, StepState::StepCancelled);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Cancelled
    );
    assert_eq!(change.lease_assertions.len(), 1);
    assert!(change.lease_assertions[0].no_active);
}

#[test]
fn recovery_completion_settles_from_immutable_receipt() {
    let sc = scope();
    let agg = running_aggregate(sc.workspace_id);
    let s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    let a = invoked_attempt(&s);
    let expired = lease(sc.workspace_id, s.run_id, 1, T0 - Duration::seconds(5));
    let state = claim_state(&agg, &s, &a, Some(expired));
    let receipt = CompletionReceipt {
        workspace_id: sc.workspace_id,
        task_id: agg.task.id,
        run_id: s.run_id,
        step_id: s.id,
        attempt_id: a.id,
        logical_operation_id: a.logical_operation_id,
        physical_attempt_id: a.physical_attempt_id,
        invocation_id: a.invocation_id,
        invocation_generation: 1,
        final_state: AttemptState::AttemptSucceeded,
        outcome: new_settlement_outcome(AttemptState::AttemptSucceeded, "").unwrap(),
        context: vec![],
        b09_references: Vec::new(),
        producer_id: "producer-1".to_string(),
    };
    let change = evaluate_recovery_completion(&state, &receipt, T0).unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptSucceeded);
    assert_eq!(change.settlements.len(), 1);

    // Receipt bound to another invocation is refused.
    let mut forged = receipt.clone();
    forged.invocation_id = InvocationId::new();
    let e = evaluate_recovery_completion(&state, &forged, T0).unwrap_err();
    assert_eq!(e.code(), "COMPLETION_RECEIPT_MISMATCH");
}

// ---------------------------------------------------------------------------
// resume_test.go — reconciled-attempt resume + epoch claimability.
// ---------------------------------------------------------------------------

#[test]
fn resume_reconciled_attempt_mints_successor_pair() {
    let sc = scope();
    let agg = waiting_reconciliation_aggregate(sc.workspace_id);
    let mut s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    s.state = StepState::StepReconciliation;
    let mut a = prepared_attempt(&s);
    a.state = AttemptState::AttemptReconciliation;
    a.invocation_id = InvocationId::new();
    let state = claim_state(&agg, &s, &a, None);
    let mut env = envelope(&sc, &agg, state);
    env.assert_no_active_lease = true;
    env.logical_operation = a.logical_operation_id;
    let mut op_meta = meta();
    op_meta.capability = Capability::WorkspaceOperator;
    let change = evaluate_command(
        Command::ResumeReconciledAttempt(ResumeReconciledAttemptCommand {
            envelope: env.clone(),
            new_step_id: StepId::new(),
            new_attempt_id: StepAttemptId::new(),
            new_logical_operation: LogicalOperationId::new(),
            physical_attempt_id: PhysicalAttemptId::new(),
            evidence: vec![ReconciliationEvidence {
                kind: ReconciliationEvidenceKind::ReconciliationEvidenceOperatorAttestation,
                reference: "operator-ok".to_string(),
            }],
            max_step_sequence: 8,
            remaining_cost_micro_usd: 50_000,
        }),
        &op_meta,
    )
    .unwrap();
    assert_eq!(change.steps.len(), 2);
    assert_eq!(change.steps[0].state, StepState::StepFailed);
    assert_eq!(change.steps[1].state, StepState::StepRunning);
    assert_eq!(change.attempts.len(), 2);
    assert_eq!(change.attempts[0].state, AttemptState::AttemptFailed);
    assert_eq!(change.attempts[1].state, AttemptState::AttemptPrepared);
    assert_eq!(change.attempts[1].predecessor_id, a.id);
    assert_eq!(change.reconciliations.len(), 1);
    assert_eq!(
        change.reconciliations[0].disposition,
        ReconciliationDisposition::ReconciliationResume
    );
    assert_eq!(change.lease_assertions.len(), 1);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Running
    );
    assert_eq!(change.events[0].kind, EVENT_ATTEMPT_RESUMED);

    // Executor cannot resume.
    let mut cmd = ResumeReconciledAttemptCommand {
        envelope: env.clone(),
        new_step_id: StepId::new(),
        new_attempt_id: StepAttemptId::new(),
        new_logical_operation: LogicalOperationId::new(),
        physical_attempt_id: PhysicalAttemptId::new(),
        evidence: vec![ReconciliationEvidence {
            kind: ReconciliationEvidenceKind::ReconciliationEvidenceOperatorAttestation,
            reference: "operator-ok".to_string(),
        }],
        max_step_sequence: 8,
        remaining_cost_micro_usd: 50_000,
    };
    let (code, _) = err_code(evaluate_command(
        Command::ResumeReconciledAttempt(cmd.clone()),
        &meta(),
    ));
    assert_eq!(code, "INVALID_COMMAND_METADATA");

    // Budget floor.
    op_meta.capability = Capability::WorkspaceOperator;
    cmd.remaining_cost_micro_usd = 9_999;
    let (code, kind) = err_code(evaluate_command(
        Command::ResumeReconciledAttempt(cmd.clone()),
        &op_meta,
    ));
    assert_eq!(
        (code, kind),
        ("RESUME_BUDGET_EXHAUSTED", FailureKind::Denied)
    );
    cmd.remaining_cost_micro_usd = 50_000;
    cmd.max_step_sequence = 0;
    let (code, _) = err_code(evaluate_command(
        Command::ResumeReconciledAttempt(cmd.clone()),
        &op_meta,
    ));
    assert_eq!(code, "INVALID_RESUME_LIMIT");
    cmd.max_step_sequence = 1; // ceiling: sequence+1 = 2 > 1
    let (code, _) = err_code(evaluate_command(
        Command::ResumeReconciledAttempt(cmd.clone()),
        &op_meta,
    ));
    assert_eq!(code, "RESUME_ATTEMPT_LIMIT_REACHED");
}

#[test]
fn recovery_claimability_quarantines_pre_watermark_runs() {
    let workspace = WorkspaceId::new();
    let epoch = RecoveryEpoch {
        generation: 7,
        coordinator_fence: RecoveryCoordinatorFence { generation: 2 },
        state: RecoveryEpochState::RecoveryEpochRunning,
        scheduler_cursor: workspace,
        workspace_count: 1,
        processed_count: 0,
        claim_cycle: 0,
        retry_attempt: 3,
        snapshot_at: T0,
    };
    let work = RecoveryWorkspaceWork {
        epoch_generation: 7,
        workspace_id: workspace,
        state: RecoveryWorkspaceState::RecoveryWorkspaceFailed,
        watermark_created_at: T0 - Duration::hours(1),
        watermark_run_id: RunId::new(),
        cursor_created_at: ZERO_TIME,
        cursor_run_id: RunId::from_trusted_db_bytes([0; 16]),
        scanned_count: 0,
        reconciled_count: 0,
        retry_attempt: 0,
        failure_class: String::new(),
        failure_reason: String::new(),
    };
    // Pre-watermark, unreconciled → quarantined.
    let claimability =
        recovery_claimability(&epoch, &work, T0 - Duration::hours(2), RunId::new(), 0);
    assert!(!claimability.claimable);
    // Reconciled at/after the epoch → claimable.
    assert!(
        recovery_claimability(&epoch, &work, T0 - Duration::hours(2), RunId::new(), 7).claimable
    );
    // Post-watermark → claimable.
    assert!(recovery_claimability(&epoch, &work, T0, RunId::new(), 0).claimable);
    // Completed epoch → claimable.
    let mut done = epoch.clone();
    done.state = RecoveryEpochState::RecoveryEpochCompleted;
    assert!(
        recovery_claimability(&done, &work, T0 - Duration::hours(2), RunId::new(), 0).claimable
    );
}

#[test]
fn recovery_completion_state_never_clears_degradation() {
    assert_eq!(
        recovery_completion_state(RecoveryEpochState::RecoveryEpochDegraded, false, true),
        (RecoveryEpochState::RecoveryEpochDegraded, false)
    );
    assert_eq!(
        recovery_completion_state(RecoveryEpochState::RecoveryEpochRunning, true, false),
        (RecoveryEpochState::RecoveryEpochDegraded, false)
    );
    assert_eq!(
        recovery_completion_state(RecoveryEpochState::RecoveryEpochRunning, false, true),
        (RecoveryEpochState::RecoveryEpochCompleted, true)
    );
}

#[test]
fn resume_epoch_requires_matching_fingerprint() {
    let sc = TrustedScope {
        principal_id: "coordinator".to_string(),
        workspace_id: WorkspaceId::new(),
        capabilities: [
            Capability::WorkspaceOperator,
            Capability::RecoveryCoordinator,
        ]
        .into_iter()
        .collect(),
    };
    let epoch = RecoveryEpoch {
        generation: 3,
        coordinator_fence: RecoveryCoordinatorFence { generation: 1 },
        state: RecoveryEpochState::RecoveryEpochDegraded,
        scheduler_cursor: WorkspaceId::new(),
        workspace_count: 0,
        processed_count: 0,
        claim_cycle: 0,
        retry_attempt: 2,
        snapshot_at: T0,
    };
    let mut cmd = ResumeRecoveryEpochCommand {
        scope: sc,
        epoch_generation: 3,
        coordinator_fence: RecoveryCoordinatorFence { generation: 2 },
        expected_state: RecoveryEpochState::RecoveryEpochDegraded,
        expected_cursor: epoch.scheduler_cursor,
        expected_retry_attempt: 2,
        acknowledgement_reason: "ack".to_string(),
        idempotency_key: "resume-3".to_string(),
        capability: Capability::RecoveryCoordinator,
        fingerprint: RequestFingerprint::default(),
    };
    cmd.fingerprint = recovery_resume_fingerprint(&cmd);
    let next = evaluate_resume_recovery_epoch(&cmd, &epoch).unwrap();
    assert_eq!(next.state, RecoveryEpochState::RecoveryEpochRunning);
    assert_eq!(next.coordinator_fence.generation, 2);

    // Fingerprint drift is refused.
    cmd.acknowledgement_reason = "tampered".to_string();
    let e = evaluate_resume_recovery_epoch(&cmd, &epoch).unwrap_err();
    assert_eq!(e.code(), "INVALID_RECOVERY_RESUME");
}

// ---------------------------------------------------------------------------
// domain_test.go — reconciliation resolution + descriptors + retention.
// ---------------------------------------------------------------------------

#[test]
fn resolve_reconciliation_confirms_and_cancels() {
    let sc = scope();
    // Upstream resolves reconciliation against a running task — the
    // settlement transition completes it directly.
    let agg = running_aggregate(sc.workspace_id);
    let mut s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    s.state = StepState::StepReconciliation;
    let mut a = invoked_attempt(&s);
    a.state = AttemptState::AttemptReconciliation;
    let state = claim_state(&agg, &s, &a, None);
    let mut env = envelope(&sc, &agg, state);
    env.assert_no_active_lease = true;
    let mut op_meta = meta();
    op_meta.capability = Capability::WorkspaceOperator;
    let change = evaluate_command(
        Command::ResolveReconciliation(ResolveReconciliationCommand {
            envelope: env.clone(),
            disposition: ReconciliationDisposition::ReconciliationConfirmSucceeded,
            evidence: vec![ReconciliationEvidence {
                kind: ReconciliationEvidenceKind::ReconciliationEvidenceCompletionReceipt,
                reference: "receipt-1".to_string(),
            }],
        }),
        &op_meta,
    )
    .unwrap();
    assert_eq!(change.attempts[0].state, AttemptState::AttemptSucceeded);
    assert_eq!(change.steps[0].state, StepState::StepSucceeded);
    assert_eq!(change.reconciliations.len(), 1);
    assert_eq!(
        change.task_transition.unwrap().change_set.task.status,
        task::TaskStatus::Completed
    );

    // Resume is not a ResolveReconciliation disposition.
    let (code, _) = err_code(evaluate_command(
        Command::ResolveReconciliation(ResolveReconciliationCommand {
            envelope: env.clone(),
            disposition: ReconciliationDisposition::ReconciliationResume,
            evidence: vec![ReconciliationEvidence {
                kind: ReconciliationEvidenceKind::ReconciliationEvidenceOperatorAttestation,
                reference: "a".to_string(),
            }],
        }),
        &op_meta,
    ));
    assert_eq!(code, "INVALID_DISPOSITION");

    // Evidence is required.
    let (code, _) = err_code(evaluate_command(
        Command::ResolveReconciliation(ResolveReconciliationCommand {
            envelope: env,
            disposition: ReconciliationDisposition::ReconciliationConfirmFailed,
            evidence: vec![],
        }),
        &op_meta,
    ));
    assert_eq!(code, "RECONCILIATION_EVIDENCE_REQUIRED");
}

#[test]
fn describe_reconciliation_actions_gates_on_operator_scope() {
    let sc = scope();
    let agg = waiting_reconciliation_aggregate(sc.workspace_id);
    let mut s = step(
        sc.workspace_id,
        agg.task.id,
        agg.current_run.as_ref().unwrap().id,
    );
    s.state = StepState::StepReconciliation;
    let mut a = invoked_attempt(&s);
    a.state = AttemptState::AttemptReconciliation;
    let state = claim_state(&agg, &s, &a, None);
    let descriptor = describe_reconciliation_actions(&sc, &state, T0);
    assert!(descriptor.authorized);
    assert!(descriptor.requires_no_active_lease);
    assert_eq!(descriptor.actions.len(), 3);

    // Executor scope cannot resolve.
    let executor = TrustedScope {
        principal_id: "exec".to_string(),
        workspace_id: sc.workspace_id,
        capabilities: [Capability::Executor].into_iter().collect(),
    };
    let descriptor = describe_reconciliation_actions(&executor, &state, T0);
    assert!(!descriptor.authorized);

    // An active lease flips the descriptor to fenced resolution.
    let active = lease(sc.workspace_id, s.run_id, 3, T0 + Duration::seconds(30));
    let state = claim_state(&agg, &s, &a, Some(active));
    let descriptor = describe_reconciliation_actions(&sc, &state, T0);
    assert!(descriptor.authorized);
    assert!(descriptor.requires_active_lease_fence);
    assert_eq!(descriptor.lease_generation, 3);
}

#[test]
fn retention_policy_windows() {
    let policy = default_retention_policy();
    let eligible = policy.eligible_at(RetentionRecord {
        class: RetentionClass::Evidence,
        recorded_at: Some(T0),
        legal_hold: false,
    });
    assert_eq!(eligible, Some(T0 + RETENTION_EVIDENCE));
    assert_eq!(
        policy.eligible_at(RetentionRecord {
            class: RetentionClass::Operational,
            recorded_at: Some(T0),
            legal_hold: true,
        }),
        None
    );
    assert_eq!(
        policy.eligible_at(RetentionRecord {
            class: RetentionClass::Operational,
            recorded_at: None,
            legal_hold: false,
        }),
        None
    );
}

#[test]
fn payload_sanitization_and_fingerprint() {
    assert_eq!(new_request_fingerprint(b"x"), new_request_fingerprint(b"x"));
    assert_ne!(new_request_fingerprint(b"x"), new_request_fingerprint(b"y"));
    assert!(!fingerprint_valid(&RequestFingerprint::default()));
    // Non-object payloads are refused.
    let e = evaluate_command(
        Command::Settle(SettleCommand {
            envelope: {
                let sc = scope();
                let agg = running_aggregate(sc.workspace_id);
                let s = step(
                    sc.workspace_id,
                    agg.task.id,
                    agg.current_run.as_ref().unwrap().id,
                );
                let a = invoked_attempt(&s);
                let l = lease(sc.workspace_id, s.run_id, 1, T0 + Duration::seconds(30));
                fenced_env(&sc, &agg, claim_state(&agg, &s, &a, Some(l)), 1)
            },
            final_state: AttemptState::AttemptSucceeded,
            outcome: b"\"plain string\"".to_vec(),
            context: vec![],
            reason_code: "",
        }),
        &meta(),
    )
    .unwrap_err();
    assert_eq!(e.code(), "INVALID_PAYLOAD");
}

// ---------------------------------------------------------------------------
// harness_run.go — dispatchable-run projection request validation.
// ---------------------------------------------------------------------------

#[test]
fn list_dispatchable_runs_request_validate_bounds() {
    for limit in [1, MAX_DISPATCHABLE_RUNS_LIMIT] {
        ListDispatchableRunsRequest {
            limit,
            eligible_after: T0,
        }
        .validate()
        .unwrap();
    }
    for limit in [0, MAX_DISPATCHABLE_RUNS_LIMIT + 1] {
        let e = ListDispatchableRunsRequest {
            limit,
            eligible_after: T0,
        }
        .validate()
        .unwrap_err();
        assert_eq!(
            (e.code(), e.kind()),
            ("INVALID_DISPATCHABLE_RUNS_REQUEST", FailureKind::Invalid)
        );
    }
    let e = ListDispatchableRunsRequest {
        limit: 1,
        eligible_after: ZERO_TIME,
    }
    .validate()
    .unwrap_err();
    assert_eq!(
        (e.code(), e.kind()),
        ("INVALID_DISPATCHABLE_RUNS_REQUEST", FailureKind::Invalid)
    );
}

#[test]
fn dispatch_case_persisted_strings_round_trip() {
    assert_eq!(DispatchCase::DispatchQueued.as_str(), "queued");
    assert_eq!(
        DispatchCase::DispatchPreparedSuccessor.as_str(),
        "prepared_successor"
    );
    for case in [
        DispatchCase::DispatchQueued,
        DispatchCase::DispatchPreparedSuccessor,
    ] {
        assert_eq!(DispatchCase::parse(case.as_str()), Some(case));
    }
    assert_eq!(DispatchCase::parse("unknown"), None);
}
