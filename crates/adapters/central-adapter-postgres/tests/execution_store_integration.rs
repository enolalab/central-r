//! PostgreSQL integration tests for the Task-7c execution store
//! (`execution/*.rs`): the fenced commit seam, receipt replay, lease
//! credential validation, the recovery-epoch surface, the dispatchable
//! projection, and the B09 evidence lane.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `task_store_integration.rs`: a superuser DSN on a scratch cluster
//! whose `central_migration` / `central_runtime` roles exist. Every
//! test provisions its own database and installs the baseline through
//! [`BaselineInstaller::install`].

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::execution::Store;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_execution::domain::{
    self, AttemptState, Capability, EventIntent, ExecutionChangeSet, ExpectedVersions, Lease,
    LeaseCredential, LogicalOperationId, OutboxIntent, PhysicalAttemptId, Step, StepAttempt,
    StepState, TrustedScope,
};
use central_execution::harness_run::{
    B09EvidenceReference, DispatchCase, ListDispatchableRunsRequest,
};
use central_execution::port::{
    B09EvidenceStore, ClaimRecoveryWorkspaceRequest, CommitRequest,
    CompleteRecoveryWorkspaceRequest, CompositeExecutionStore, CompositeStore,
    DispatchableRunReader, ExecutionRead, ExecutionReadRequest, LeaseCredentialValidator,
    LeaseValidationRequest, OutboxStore, ReceiptBinding, ReceiptLookupRequest,
    RecoveryClaimabilityReader, RecoveryCoordinatorAcquireRequest, RecoveryStore,
    StartRecoveryEpochRequest,
};
use central_execution::resume::RecoveryWorkspaceState;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ExecutionEventId, InstanceId, OutboxId, RunId, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use central_task::domain as task;
use central_task::port::{ChangeSetStore, CommitTaskChangeSetRequest};
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use time::OffsetDateTime;

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

/// `id.as_bytes()` → `Uuid` — the adapter boundary conversion.
macro_rules! uuid_of {
    ($id:expr) => {
        uuid::Uuid::from_bytes(*$id.as_bytes())
    };
}

const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn admin_opts() -> Option<Opts> {
    let dsn = std::env::var("CENTRAL_TEST_DSN").ok()?;
    Opts::from_str(&dsn).ok()
}

macro_rules! skip {
    () => {
        if admin_opts().is_none() {
            eprintln!("CENTRAL_TEST_DSN unset — skipping PostgreSQL integration test");
            return Ok(());
        }
    };
}

fn require_opts() -> Result<Opts> {
    admin_opts().ok_or_else(|| Failure::internal("test_env", "CENTRAL_TEST_DSN unset"))
}

async fn admin_conn() -> Result<PgConnection> {
    PgConnection::connect_with(&require_opts()?)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn role_conn(db: &str, role: &str) -> Result<PgConnection> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn role_pool(db: &str, role: &str) -> Result<PgPool> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgPool::connect_with(opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn provision(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = format!("exec_test_{label}_{}", std::process::id());
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&mut *admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
        .execute(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(db)
}

async fn installed(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = provision(admin, label).await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    BaselineInstaller::new().install(&mut conn).await?;
    Ok(db)
}

async fn insert_workspace(conn: &mut PgConnection, id: uuid::Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id) \
         VALUES ($1, 'active', 'exec-test')",
    )
    .bind(id)
    .execute(conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture builders.
// ---------------------------------------------------------------------------

#[allow(clippy::expect_used)] // Integration-test fixture: a failure here is a fixture bug.
fn scope(ws: WorkspaceId) -> TrustedScope {
    TrustedScope::new("exec-principal", ws, &[Capability::Executor]).expect("test scope")
}

fn step(ws: WorkspaceId, task_id: TaskId, run_id: RunId) -> Step {
    Step {
        id: StepId::new(),
        workspace_id: ws,
        task_id,
        run_id,
        version: 1,
        sequence: 1,
        state: StepState::StepRunning,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn attempt(step: &Step) -> StepAttempt {
    StepAttempt {
        id: StepAttemptId::new(),
        step_id: step.id,
        workspace_id: step.workspace_id,
        task_id: step.task_id,
        run_id: step.run_id,
        logical_operation_id: LogicalOperationId(*uuid::Uuid::now_v7().as_bytes()),
        physical_attempt_id: PhysicalAttemptId(*uuid::Uuid::now_v7().as_bytes()),
        invocation_id: Default::default(),
        predecessor_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
        version: 1,
        sequence: 1,
        state: AttemptState::AttemptPrepared,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn event_intent(ws: WorkspaceId, task_id: TaskId, run_id: RunId) -> EventIntent {
    EventIntent {
        id: ExecutionEventId::new(),
        workspace_id: ws,
        task_id,
        run_id,
        step_id: StepId::from_trusted_db_bytes([0; 16]),
        attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
        tool_call_id: central_foundation::identity::ToolCallId::from_trusted_db_bytes([0; 16]),
        tool_attempt_id: central_foundation::identity::ToolCallAttemptId::from_trusted_db_bytes(
            [0; 16],
        ),
        kind: domain::EVENT_ATTEMPT_PREPARED,
        payload: br#"{"k":"v"}"#.to_vec(),
        occurred_at: NOW,
    }
}

fn outbox_intent(ws: WorkspaceId, event_id: ExecutionEventId, dedup: &str) -> OutboxIntent {
    OutboxIntent {
        id: OutboxId::new(),
        workspace_id: ws,
        event_id,
        catalog_type: "execution.test",
        payload: br#"{"o":1}"#.to_vec(),
        deduplication_key: dedup.to_owned(),
        producer_id: "exec-test".to_owned(),
        created_at: NOW,
    }
}

fn commit_req(
    ws: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    binding: ReceiptBinding,
    change_set: ExecutionChangeSet,
    key: &str,
) -> CommitRequest {
    CommitRequest {
        scope: scope(ws),
        command_scope: "execution.test".to_owned(),
        idempotency_key: key.to_owned(),
        fingerprint: [9u8; 32],
        principal_id: "exec-principal".to_owned(),
        capability: Capability::Executor,
        receipt_binding: binding.clone(),
        expected_versions: ExpectedVersions {
            task: 1,
            run: 1,
            ..ExpectedVersions::default()
        },
        require_recovery_claimable: false,
        lease_credential: LeaseCredential::default(),
        lease_generation: 0,
        assert_no_active_lease: true,
        result: central_execution::port::DurableResult {
            workspace_id: ws,
            task_id,
            run_id,
            step_id: binding.step_id,
            attempt_id: binding.attempt_id,
            event_id: ExecutionEventId::new(),
            event_kind: "execution.test.committed".to_owned(),
            approval_action: None,
        },
        change_set,
    }
}

/// Submit a task through the task store (the task half of the atomic
/// seam is covered by task_store_integration).
async fn submit_task(pool: &PgPool, ws: WorkspaceId, key: &str) -> Result<task::CommitResult> {
    let task_store = central_adapter_postgres::task::Store::new(pool.clone());
    let change_set = task::submit_task(task::SubmitTaskRequest {
        workspace_id: ws,
        title: "exec-test".to_owned(),
        input: "input.yaml".to_owned(),
        permission_policy: None,
        budget: task::Budget::default(),
        run_key: None,
        now: NOW,
    })?;
    task_store
        .commit_task_change_set(CommitTaskChangeSetRequest {
            workspace_id: ws,
            change_set,
            command_scope: "task.submit",
            idempotency_key: Some(key.to_owned()),
            correlation_id: None,
            causation_id: None,
        })
        .await
}

fn run_id_of(committed: &task::CommitResult) -> RunId {
    committed.runs.first().map_or_else(RunId::new, |r| r.id)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn commit_persists_rows_events_outbox_and_replays() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "commit").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "commit-task").await?;
    let run_id = run_id_of(&committed);

    let step = step(ws, committed.task.id, run_id);
    let att = attempt(&step);
    let event = event_intent(ws, committed.task.id, run_id);
    let outbox = outbox_intent(ws, event.id, "execution.test:k1");
    let mut cs = ExecutionChangeSet::new();
    cs.steps.push(step.clone());
    cs.attempts.push(att.clone());
    cs.events.push(event.clone());
    cs.outbox.push(outbox);
    let binding = ReceiptBinding {
        task_id: committed.task.id,
        run_id,
        step_id: step.id,
        attempt_id: att.id,
        logical_operation: att.logical_operation_id,
    };
    // The durable result's event id is the committed event — the
    // receipt's result_reference must name a real durable event.
    let mut req = commit_req(ws, committed.task.id, run_id, binding.clone(), cs, "k1");
    req.result.event_id = event.id;
    req.result.event_kind = event.kind.to_owned();
    let result = store.commit(req.clone()).await?;
    assert!(!result.replayed);

    // Durable evidence: step, attempt, event (sequence 2 — the submit
    // event took 1), outbox, receipt.
    let row = sqlx::query!(
        "SELECT (SELECT count(*) FROM central.steps WHERE id = $1) AS \"steps!\", \
         (SELECT count(*) FROM central.step_attempts WHERE id = $2) AS \"attempts!\", \
         (SELECT count(*) FROM central.events WHERE id = $3) AS \"events!\", \
         (SELECT count(*) FROM central.outbox WHERE workspace_id = $4 \
           AND deduplication_key = 'execution.test:k1') AS \"outbox!\", \
         (SELECT count(*) FROM central.execution_command_receipts \
           WHERE workspace_id = $4 AND command_scope = 'execution.test' \
           AND idempotency_key = 'k1') AS \"receipts!\"",
        uuid_of!(step.id),
        uuid_of!(att.id),
        uuid_of!(event.id),
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(
        (
            row.steps,
            row.attempts,
            row.events,
            row.outbox,
            row.receipts
        ),
        (1, 1, 1, 1, 1)
    );

    // Exact replay — same request returns the retained result.
    let replay = store.commit(req).await?;
    assert!(replay.replayed);
    assert_eq!(replay.result, result.result);

    // ReadExecution sees the authoritative snapshot.
    let read = store
        .read_execution(ExecutionReadRequest {
            scope: scope(ws),
            workspace_id: ws,
            task_id: committed.task.id,
            run_id,
            step_id: step.id,
            attempt_id: att.id,
        })
        .await?;
    assert_eq!(read.state.task.task.id, committed.task.id);
    assert_eq!(read.state.step.as_ref().map(|s| s.id), Some(step.id));
    assert_eq!(read.state.attempt.as_ref().map(|a| a.id), Some(att.id));

    // Pre-read lookup replays the same result.
    let lookup = store
        .lookup_receipt(ReceiptLookupRequest {
            scope: scope(ws),
            command_scope: "execution.test".to_owned(),
            idempotency_key: "k1".to_owned(),
            fingerprint: [9u8; 32],
            principal_id: "exec-principal".to_owned(),
            capability: Capability::Executor,
            binding,
            expected_versions: ExpectedVersions {
                task: 1,
                run: 1,
                ..ExpectedVersions::default()
            },
        })
        .await?;
    assert!(lookup.found);
    assert_eq!(
        lookup.result.map(|r| r.event_id),
        Some(result.result.event_id)
    );
    Ok(())
}

#[tokio::test]
async fn conflicting_receipt_fingerprint_is_a_conflict() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "conflict").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "conflict-task").await?;
    let run_id = run_id_of(&committed);
    let step = step(ws, committed.task.id, run_id);
    let att = attempt(&step);
    let mut cs = ExecutionChangeSet::new();
    cs.steps.push(step.clone());
    cs.attempts.push(att.clone());
    let binding = ReceiptBinding {
        task_id: committed.task.id,
        run_id,
        step_id: step.id,
        attempt_id: att.id,
        logical_operation: att.logical_operation_id,
    };
    let mut first = commit_req(ws, committed.task.id, run_id, binding.clone(), cs, "dup");
    first.result.event_id = ExecutionEventId::new();
    store.commit(first).await?;
    // Same identity, different fingerprint → request conflict.
    let mut req = commit_req(
        ws,
        committed.task.id,
        run_id,
        binding,
        ExecutionChangeSet::new(),
        "dup",
    );
    req.fingerprint = [1u8; 32];
    let err = store.commit(req).await.unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), "REASON_REQUEST_CONFLICT");
    Ok(())
}

#[tokio::test]
async fn lease_upsert_fences_and_validates() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "lease").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "lease-task").await?;
    let run_id = run_id_of(&committed);
    let step = step(ws, committed.task.id, run_id);
    let att = attempt(&step);

    let credential = store.issue_lease_credential()?;
    let expires = OffsetDateTime::now_utc() + time::Duration::seconds(30);
    let mut cs = ExecutionChangeSet::new();
    cs.steps.push(step.clone());
    cs.attempts.push(att.clone());
    cs.leases.push(Lease {
        workspace_id: ws,
        run_id,
        credential,
        generation: 1,
        expires_at: expires,
        updated_at: expires,
    });
    let binding = ReceiptBinding {
        task_id: committed.task.id,
        run_id,
        step_id: step.id,
        attempt_id: att.id,
        logical_operation: att.logical_operation_id,
    };
    store
        .commit(commit_req(
            ws,
            committed.task.id,
            run_id,
            binding.clone(),
            cs,
            "claim",
        ))
        .await?;

    // The minted bearer validates.
    store
        .validate_lease(LeaseValidationRequest {
            scope: scope(ws),
            workspace_id: ws,
            task_id: committed.task.id,
            run_id,
            step_id: step.id,
            attempt_id: att.id,
            lease_credential: credential,
            lease_generation: 1,
        })
        .await?;

    // A wrong bearer is fenced.
    let wrong = store.issue_lease_credential()?;
    let err = store
        .validate_lease(LeaseValidationRequest {
            scope: scope(ws),
            workspace_id: ws,
            task_id: committed.task.id,
            run_id,
            step_id: step.id,
            attempt_id: att.id,
            lease_credential: wrong,
            lease_generation: 1,
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind(), FailureKind::Denied);

    // A live lease rejects the assert_no_active_lease commit fence.
    let mut req = commit_req(
        ws,
        committed.task.id,
        run_id,
        binding.clone(),
        ExecutionChangeSet::new(),
        "assert-no-lease",
    );
    req.assert_no_active_lease = true;
    let err = store.commit(req).await.unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), "LEASE_ACTIVE");

    // …while the proven bearer clears the fence path.
    let mut fenced_req = commit_req(
        ws,
        committed.task.id,
        run_id,
        binding,
        ExecutionChangeSet::new(),
        "fenced-claim",
    );
    fenced_req.assert_no_active_lease = false;
    fenced_req.lease_credential = credential;
    fenced_req.lease_generation = 1;
    store.commit(fenced_req).await?;
    Ok(())
}

#[tokio::test]
async fn recovery_epoch_lifecycle_and_failed_listing() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recovery").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recovery-task").await?;
    let run_id = run_id_of(&committed);

    // Coordinator acquire is idempotent for the same instance.
    let instance = InstanceId::new();
    let lease = store
        .acquire_recovery_coordinator(RecoveryCoordinatorAcquireRequest {
            recovery_domain: "central.execution.recovery.v1".to_owned(),
            instance_id: instance,
        })
        .await?;
    assert!(lease.fence.generation > 0);

    let epoch = store
        .start_recovery_epoch(StartRecoveryEpochRequest {
            lease: lease.clone(),
            batch_size: 10,
        })
        .await?;
    assert!(epoch.generation > 0);
    assert_eq!(epoch.workspace_count, 1);

    // The run predates the watermark → recovery quarantines it.
    let claim = store
        .recovery_claimability(scope(ws), committed.task.id, run_id)
        .await?;
    assert!(!claim.claimable);
    assert_eq!(claim.epoch_generation, epoch.generation);

    // Claim the workspace page and complete it via the adapter scan.
    let claims = store
        .claim_recovery_workspaces(ClaimRecoveryWorkspaceRequest {
            lease: lease.clone(),
            epoch_generation: epoch.generation,
            batch_size: 10,
        })
        .await?;
    assert_eq!(claims.len(), 1);
    let claim = claims.into_iter().next().unwrap_or_default();
    assert_eq!(claim.work.workspace_id, ws);
    assert_eq!(
        claim.work.state,
        RecoveryWorkspaceState::RecoveryWorkspaceClaimed
    );

    store
        .complete_recovery_workspace(CompleteRecoveryWorkspaceRequest {
            lease: lease.clone(),
            epoch_generation: epoch.generation,
            workspace_id: ws,
            claim_token: claim.claim_token.clone(),
            degraded: false,
            failure_class: String::new(),
            failure_reason: String::new(),
        })
        .await?;

    // Run reconciled + epoch auto-completed → claimable again.
    let claim = store
        .recovery_claimability(scope(ws), committed.task.id, run_id)
        .await?;
    assert!(claim.claimable);
    let reconciled = sqlx::query!(
        "SELECT reconciled_epoch FROM central.runs WHERE id = $1",
        uuid_of!(run_id),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(reconciled.reconciled_epoch, epoch.generation);

    // Failed-workspace listing is empty for the completed epoch.
    let failed = store
        .list_failed_recovery_workspaces(epoch.generation, 10)
        .await?;
    assert_eq!(failed.total, 0);
    Ok(())
}

#[tokio::test]
async fn degraded_workspace_lists_as_failed() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "failed").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    submit_task(&pool, ws, "failed-task").await?;

    let lease = store
        .acquire_recovery_coordinator(RecoveryCoordinatorAcquireRequest {
            recovery_domain: "central.execution.recovery.v1".to_owned(),
            instance_id: InstanceId::new(),
        })
        .await?;
    let epoch = store
        .start_recovery_epoch(StartRecoveryEpochRequest {
            lease: lease.clone(),
            batch_size: 10,
        })
        .await?;
    let claims = store
        .claim_recovery_workspaces(ClaimRecoveryWorkspaceRequest {
            lease: lease.clone(),
            epoch_generation: epoch.generation,
            batch_size: 10,
        })
        .await?;
    let claim = claims.into_iter().next().unwrap_or_default();
    store
        .complete_recovery_workspace(CompleteRecoveryWorkspaceRequest {
            lease,
            epoch_generation: epoch.generation,
            workspace_id: ws,
            claim_token: claim.claim_token,
            degraded: true,
            failure_class: "scan_failed".to_owned(),
            failure_reason: "forced".to_owned(),
        })
        .await?;
    let failed = store
        .list_failed_recovery_workspaces(epoch.generation, 10)
        .await?;
    assert_eq!(failed.total, 1);
    assert_eq!(failed.ids, vec![ws]);
    Ok(())
}

#[tokio::test]
async fn dispatchable_lists_queued_run() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "dispatch").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "dispatch-task").await?;
    let run_id = run_id_of(&committed);

    let runs = store
        .list_dispatchable_runs(ListDispatchableRunsRequest {
            limit: 10,
            eligible_after: NOW,
        })
        .await?;
    let found = runs.iter().find(|r| r.run_id == run_id);
    let Some(found) = found else {
        return Err(Failure::internal(
            "test",
            "queued run missing from dispatchable",
        ));
    };
    assert_eq!(found.case, DispatchCase::DispatchQueued);
    assert_eq!(found.task_id, committed.task.id);
    Ok(())
}

#[tokio::test]
async fn publish_outbox_marks_dispatched_and_b09_references_persist() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "outbox").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "outbox-task").await?;
    let run_id = run_id_of(&committed);
    let step = step(ws, committed.task.id, run_id);
    let att = attempt(&step);
    let event = event_intent(ws, committed.task.id, run_id);
    let outbox = outbox_intent(ws, event.id, "execution.test:pub");
    let mut cs = ExecutionChangeSet::new();
    cs.steps.push(step.clone());
    cs.attempts.push(att.clone());
    cs.events.push(event);
    cs.outbox.push(outbox.clone());
    let binding = ReceiptBinding {
        task_id: committed.task.id,
        run_id,
        step_id: step.id,
        attempt_id: att.id,
        logical_operation: att.logical_operation_id,
    };
    store
        .commit(commit_req(
            ws,
            committed.task.id,
            run_id,
            binding,
            cs,
            "pub",
        ))
        .await?;
    store
        .publish_outbox(scope(ws), vec![outbox.clone()])
        .await?;
    let state = sqlx::query!(
        "SELECT delivery_state, delivered_at FROM central.outbox WHERE id = $1",
        uuid_of!(outbox.id),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(state.delivery_state, "dispatched");
    assert!(state.delivered_at.is_some());

    // B09 evidence lane — a completion receipt row exists first.
    sqlx::query!(
        "INSERT INTO central.execution_completion_receipts (\
         id, workspace_id, task_id, run_id, step_id, step_attempt_id, \
         logical_operation_id, physical_attempt_id, invocation_id, \
         invocation_generation, final_state, outcome, evidence_digest, \
         producer_id, eligible_after) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 'succeeded', \
         '{}'::jsonb, $10, 'exec-test', clock_timestamp() + interval '90 days')",
        uuid::Uuid::now_v7(),
        uuid_of!(ws),
        uuid_of!(committed.task.id),
        uuid_of!(run_id),
        uuid_of!(step.id),
        uuid_of!(att.id),
        uuid::Uuid::from_bytes(att.logical_operation_id.0),
        uuid::Uuid::from_bytes(att.physical_attempt_id.0),
        uuid::Uuid::now_v7(),
        &[7u8; 32][..],
    )
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    store
        .commit_b09_evidence(
            scope(ws),
            att.id,
            vec![B09EvidenceReference {
                kind: "provider_evidence".to_owned(),
                id: "ev-1".to_owned(),
            }],
        )
        .await?;
    let refs = sqlx::query!(
        "SELECT count(*) AS \"n!\" FROM central.provider_completion_references \
         WHERE workspace_id = $1 AND evidence_id = 'ev-1'",
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(refs.n, 1);
    Ok(())
}
