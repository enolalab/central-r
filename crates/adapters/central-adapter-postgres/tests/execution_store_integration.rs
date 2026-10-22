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
    LeaseAssertion, LeaseCredential, LogicalOperationId, OutboxIntent, PhysicalAttemptId, Step,
    StepAttempt, StepState, TrustedScope,
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

/// Command event leg — the persisted event must carry the binding's
/// step/attempt ids (receipt replay re-binds them) and a payload that
/// survives the closed event schema (`schema_version`/`type` only).
fn event_intent(
    ws: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    step_id: StepId,
    attempt_id: StepAttemptId,
    kind: domain::EventKind,
) -> EventIntent {
    EventIntent {
        id: ExecutionEventId::new(),
        workspace_id: ws,
        task_id,
        run_id,
        step_id,
        attempt_id,
        tool_call_id: central_foundation::identity::ToolCallId::from_trusted_db_bytes([0; 16]),
        tool_attempt_id: central_foundation::identity::ToolCallAttemptId::from_trusted_db_bytes(
            [0; 16],
        ),
        kind,
        payload: serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "type": kind,
        }))
        .unwrap_or_default(),
        occurred_at: NOW,
    }
}

/// Outbox leg — `catalog_type` is the command's closed catalog entry
/// and the payload stays inside the outbox schema.
fn outbox_intent(
    ws: WorkspaceId,
    event: &EventIntent,
    dedup: &str,
    catalog: domain::OutboxCatalogType,
) -> OutboxIntent {
    OutboxIntent {
        id: OutboxId::new(),
        workspace_id: ws,
        event_id: event.id,
        catalog_type: catalog,
        payload: serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "event_id": uuid_of!(event.id).to_string(),
            "catalog_type": catalog,
            "deduplication_key": dedup,
        }))
        .unwrap_or_default(),
        deduplication_key: dedup.to_owned(),
        producer_id: "exec-test".to_owned(),
        created_at: NOW,
    }
}

/// Command request — `command_scope` is a real upstream scope and the
/// durable result's event leg is the change set's command event
/// (`validateChangeSetOwnership` requires it).
fn commit_req(
    ws: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    command_scope: &str,
    binding: ReceiptBinding,
    change_set: ExecutionChangeSet,
    key: &str,
) -> CommitRequest {
    let (event_id, event_kind) = change_set.events.first().map_or_else(
        || (ExecutionEventId::from_trusted_db_bytes([0; 16]), ""),
        |e| (e.id, e.kind),
    );
    CommitRequest {
        scope: scope(ws),
        command_scope: command_scope.to_owned(),
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
            event_id,
            event_kind: event_kind.to_owned(),
            approval_action: None,
        },
        change_set,
    }
}

/// A complete `execution.prepare` commit request — the upstream
/// insertion-shaped command: fresh step + attempt, one
/// `attempt_prepared` event with its outbox leg, and the
/// no-active-lease assertion the prepare fence requires.
fn prepare_request(
    ws: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    key: &str,
) -> (CommitRequest, Step, StepAttempt, OutboxIntent) {
    let step = step(ws, task_id, run_id);
    let att = attempt(&step);
    let event = event_intent(
        ws,
        task_id,
        run_id,
        step.id,
        att.id,
        domain::EVENT_ATTEMPT_PREPARED,
    );
    let outbox = outbox_intent(
        ws,
        &event,
        &format!("execution.prepare:{key}"),
        domain::OUTBOX_ATTEMPT_PREPARED,
    );
    let mut cs = ExecutionChangeSet::new();
    cs.steps.push(step.clone());
    cs.attempts.push(att.clone());
    cs.events.push(event);
    cs.outbox.push(outbox.clone());
    cs.lease_assertions.push(LeaseAssertion {
        workspace_id: ws,
        run_id,
        no_active: true,
    });
    let binding = ReceiptBinding {
        task_id,
        run_id,
        step_id: step.id,
        attempt_id: att.id,
        logical_operation: att.logical_operation_id,
    };
    (
        commit_req(ws, task_id, run_id, "execution.prepare", binding, cs, key),
        step,
        att,
        outbox,
    )
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

    // `execution.prepare` — the upstream insertion-shaped command.
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "k1");
    let event_id = req.result.event_id;
    let binding = req.receipt_binding.clone();
    let result = store.commit(req.clone()).await?;
    assert!(!result.replayed);

    // Durable evidence: step, attempt, event (sequence 2 — the submit
    // event took 1), outbox, receipt.
    let row = sqlx::query!(
        "SELECT (SELECT count(*) FROM central.steps WHERE id = $1) AS \"steps!\", \
         (SELECT count(*) FROM central.step_attempts WHERE id = $2) AS \"attempts!\", \
         (SELECT count(*) FROM central.events WHERE id = $3) AS \"events!\", \
         (SELECT count(*) FROM central.outbox WHERE workspace_id = $4 \
           AND deduplication_key = 'execution.prepare:k1') AS \"outbox!\", \
         (SELECT count(*) FROM central.execution_command_receipts \
           WHERE workspace_id = $4 AND command_scope = 'execution.prepare' \
           AND idempotency_key = 'k1') AS \"receipts!\"",
        uuid_of!(step.id),
        uuid_of!(att.id),
        uuid_of!(event_id),
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
            command_scope: "execution.prepare".to_owned(),
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
    let (first, _, _, _) = prepare_request(ws, committed.task.id, run_id, "dup");
    store.commit(first).await?;
    // Same receipt identity, different fingerprint → request conflict.
    // The second request stays validation-clean so the mismatch is the
    // receipt's fingerprint check, not the pre-transaction gate.
    let (mut req, _, _, _) = prepare_request(ws, committed.task.id, run_id, "dup");
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

    // `execution.prepare` inserts the step + attempt under the
    // no-active-lease fence…
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prepare");
    let binding = req.receipt_binding.clone();
    store.commit(req).await?;

    // …then `execution.claim` grants the lease (the claim-scoped fence
    // requires exactly one durable lease grant).
    let credential = store.issue_lease_credential()?;
    let expires = OffsetDateTime::now_utc() + time::Duration::seconds(30);
    let claim_event = event_intent(
        ws,
        committed.task.id,
        run_id,
        step.id,
        att.id,
        domain::EVENT_ATTEMPT_CLAIMED,
    );
    let claim_outbox = outbox_intent(
        ws,
        &claim_event,
        "execution.claim:claim",
        domain::OUTBOX_ATTEMPT_CLAIMED,
    );
    let mut cs = ExecutionChangeSet::new();
    cs.events.push(claim_event);
    cs.outbox.push(claim_outbox);
    cs.leases.push(Lease {
        workspace_id: ws,
        run_id,
        credential,
        generation: 1,
        expires_at: expires,
        updated_at: expires,
    });
    let mut claim_req = commit_req(
        ws,
        committed.task.id,
        run_id,
        "execution.claim",
        binding.clone(),
        cs,
        "claim",
    );
    claim_req.assert_no_active_lease = false;
    claim_req.require_recovery_claimable = true;
    claim_req.expected_versions.step = 1;
    claim_req.expected_versions.attempt = 1;
    store.commit(claim_req).await?;

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
    let (req, _, _, _) = prepare_request(ws, committed.task.id, run_id, "assert-no-lease");
    let err = store.commit(req).await.unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), "ACTIVE_LEASE_CONFLICT");

    // …while the proven bearer clears the fence path (`heartbeat`'s
    // policy requires the active-lease credential).
    let beat_event = event_intent(
        ws,
        committed.task.id,
        run_id,
        step.id,
        att.id,
        domain::EVENT_ATTEMPT_HEARTBEAT,
    );
    let beat_outbox = outbox_intent(
        ws,
        &beat_event,
        "execution.heartbeat:fenced-claim",
        domain::OUTBOX_ATTEMPT_CLAIMED,
    );
    let mut cs = ExecutionChangeSet::new();
    cs.events.push(beat_event);
    cs.outbox.push(beat_outbox);
    let mut fenced_req = commit_req(
        ws,
        committed.task.id,
        run_id,
        "execution.heartbeat",
        binding,
        cs,
        "fenced-claim",
    );
    fenced_req.assert_no_active_lease = false;
    fenced_req.lease_credential = credential;
    fenced_req.lease_generation = 1;
    fenced_req.expected_versions.step = 1;
    fenced_req.expected_versions.attempt = 1;
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
    let (req, step, att, outbox) = prepare_request(ws, committed.task.id, run_id, "pub");
    store.commit(req).await?;
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

// ---------------------------------------------------------------------------
// B08 recovery decision ladder — driven through the fenced scan
// (acquire coordinator → start epoch → claim workspace → complete).
// ---------------------------------------------------------------------------

/// Full fenced scan for one claimed workspace; returns the epoch
/// generation the runs were reconciled under.
async fn drive_recovery_scan(store: &Store, ws: WorkspaceId) -> Result<i64> {
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
            degraded: false,
            failure_class: String::new(),
            failure_reason: String::new(),
        })
        .await?;
    Ok(epoch.generation)
}

/// Fixture mutation: pin the aggregate's persisted status pair.
async fn set_task_run_status(
    pool: &PgPool,
    task_id: TaskId,
    run_id: RunId,
    task_status: &str,
    run_status: &str,
) -> Result<()> {
    sqlx::query("UPDATE central.tasks SET status = $2 WHERE id = $1")
        .bind(uuid_of!(task_id))
        .bind(task_status)
        .execute(pool)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("UPDATE central.runs SET status = $2 WHERE id = $1")
        .bind(uuid_of!(run_id))
        .bind(run_status)
        .execute(pool)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// Fixture mutation: mark the attempt `invoked` under `invocation` —
/// the durable shape a live lease leaves behind when a run dies
/// mid-invocation.
async fn mark_attempt_invoked(
    pool: &PgPool,
    attempt_id: StepAttemptId,
    invocation: uuid::Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE central.step_attempts SET state = 'invoked', \
         invocation_id = $2, invocation_generation = 1, \
         version = version + 1, updated_at = clock_timestamp() \
         WHERE id = $1",
    )
    .bind(uuid_of!(attempt_id))
    .bind(invocation)
    .execute(pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// Fixture mutation: an `execution_completion_receipts` row under the
/// given identities — the immutable B10 handoff evidence.
#[allow(clippy::too_many_arguments)]
async fn insert_completion_receipt(
    pool: &PgPool,
    ws: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    step_id: StepId,
    attempt_id: StepAttemptId,
    logical: LogicalOperationId,
    physical: PhysicalAttemptId,
    invocation: uuid::Uuid,
    final_state: &str,
    outcome: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO central.execution_completion_receipts (\
         id, workspace_id, task_id, run_id, step_id, step_attempt_id, \
         logical_operation_id, physical_attempt_id, invocation_id, \
         invocation_generation, final_state, outcome, evidence_digest, \
         producer_id, eligible_after) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10, \
         $11::jsonb, $12, 'exec-test', clock_timestamp() + interval '90 days')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task_id))
    .bind(uuid_of!(run_id))
    .bind(uuid_of!(step_id))
    .bind(uuid_of!(attempt_id))
    .bind(uuid::Uuid::from_bytes(logical.0))
    .bind(uuid::Uuid::from_bytes(physical.0))
    .bind(invocation)
    .bind(final_state)
    .bind(outcome)
    .bind(&[7u8; 32][..])
    .execute(pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

#[tokio::test]
async fn recovery_mints_fenced_prepared_successor() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recsucc").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recsucc-task").await?;
    let run_id = run_id_of(&committed);
    let (req, _step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;

    let generation = drive_recovery_scan(&store, ws).await?;

    // Decision `prepared_successor_created`: the lost attempt is
    // cancelled and exactly one prepared successor carries its
    // predecessor link; the decision is durable evidence.
    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"predecessor!\", \
         (SELECT count(*) FROM central.step_attempts WHERE workspace_id = $2 \
           AND predecessor_id = $1 AND state = 'prepared') AS \"successors!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $2 \
           AND kind = 'execution.recovery.prepared_successor_created') AS \"evidence!\", \
         (SELECT reconciled_epoch FROM central.runs WHERE id = $3) AS \"reconciled!\"",
        uuid_of!(att.id),
        uuid_of!(ws),
        uuid_of!(run_id),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.predecessor, "cancelled");
    assert_eq!(row.successors, 1);
    assert_eq!(row.evidence, 1);
    assert_eq!(row.reconciled, generation);
    Ok(())
}

#[tokio::test]
async fn recovery_preserves_existing_prepared_successor() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "reckeep").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "reckeep-task").await?;
    let run_id = run_id_of(&committed);
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;

    // A prior pass already cancelled the predecessor and minted the
    // successor — the durable shape recovery must not double-mint.
    sqlx::query(
        "UPDATE central.step_attempts SET state = 'cancelled', \
         version = version + 1, updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(uuid_of!(att.id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let successor = StepAttemptId::new();
    sqlx::query(
        "INSERT INTO central.step_attempts (\
         id, workspace_id, step_id, task_id, run_id, version, \
         logical_operation_id, physical_attempt_id, invocation_id, \
         invocation_generation, predecessor_id, sequence, state, \
         created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, 1, $6, $7, NULL, NULL, $8, 2, \
         'prepared', clock_timestamp(), clock_timestamp())",
    )
    .bind(uuid_of!(successor))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(step.id))
    .bind(uuid_of!(committed.task.id))
    .bind(uuid_of!(run_id))
    .bind(uuid::Uuid::from_bytes(att.logical_operation_id.0))
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(att.id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    drive_recovery_scan(&store, ws).await?;

    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"successor!\", \
         (SELECT count(*) FROM central.step_attempts WHERE workspace_id = $2 \
           AND run_id = $3) AS \"attempts!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $2 \
           AND kind = 'execution.recovery.prepared_successor_preserved') AS \"evidence!\"",
        uuid_of!(successor),
        uuid_of!(ws),
        uuid_of!(run_id),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.successor, "prepared");
    assert_eq!(row.attempts, 2);
    assert_eq!(row.evidence, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_settles_prepared_cancellation() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "reccancel").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "reccancel-task").await?;
    let run_id = run_id_of(&committed);
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;
    set_task_run_status(&pool, committed.task.id, run_id, "cancelling", "cancelling").await?;

    drive_recovery_scan(&store, ws).await?;

    // Decision `cancellation_settled`: the attempt that never invoked
    // and its step close `cancelled`; the task aggregate completes the
    // cancel transition.
    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"attempt!\", \
         (SELECT state FROM central.steps WHERE id = $2) AS \"step!\", \
         (SELECT status FROM central.tasks WHERE id = $3) AS \"task!\", \
         (SELECT status FROM central.runs WHERE id = $4) AS \"run!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $5 \
           AND kind = 'execution.recovery.cancellation_settled') AS \"evidence!\"",
        uuid_of!(att.id),
        uuid_of!(step.id),
        uuid_of!(committed.task.id),
        uuid_of!(run_id),
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.attempt, "cancelled");
    assert_eq!(row.step, "cancelled");
    assert_eq!(row.task, "cancelled");
    assert_eq!(row.run, "cancelled");
    assert_eq!(row.evidence, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_settles_invoked_from_completion_receipt() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recsettle").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recsettle-task").await?;
    let run_id = run_id_of(&committed);
    set_task_run_status(&pool, committed.task.id, run_id, "running", "running").await?;
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;
    let invocation = uuid::Uuid::now_v7();
    mark_attempt_invoked(&pool, att.id, invocation).await?;
    insert_completion_receipt(
        &pool,
        ws,
        committed.task.id,
        run_id,
        step.id,
        att.id,
        att.logical_operation_id,
        att.physical_attempt_id,
        invocation,
        "succeeded",
        r#"{"schema_version":1,"status":"succeeded"}"#,
    )
    .await?;

    drive_recovery_scan(&store, ws).await?;

    // Decision `completion_succeeded`: the receipt settles the
    // attempt, the step, and the whole aggregate.
    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"attempt!\", \
         (SELECT outcome IS NOT NULL FROM central.step_attempts WHERE id = $1) AS \"settled!\", \
         (SELECT state FROM central.steps WHERE id = $2) AS \"step!\", \
         (SELECT status FROM central.tasks WHERE id = $3) AS \"task!\", \
         (SELECT status FROM central.runs WHERE id = $4) AS \"run!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $5 \
           AND kind = 'execution.recovery.completion_succeeded') AS \"evidence!\"",
        uuid_of!(att.id),
        uuid_of!(step.id),
        uuid_of!(committed.task.id),
        uuid_of!(run_id),
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.attempt, "succeeded");
    assert!(row.settled);
    assert_eq!(row.step, "succeeded");
    assert_eq!(row.task, "completed");
    assert_eq!(row.run, "succeeded");
    assert_eq!(row.evidence, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_invoked_without_receipt_requires_reconciliation() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recrecon").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recrecon-task").await?;
    let run_id = run_id_of(&committed);
    set_task_run_status(&pool, committed.task.id, run_id, "running", "running").await?;
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;
    mark_attempt_invoked(&pool, att.id, uuid::Uuid::now_v7()).await?;

    drive_recovery_scan(&store, ws).await?;

    // Decision `reconciliation_required`: the ambiguous projection
    // closes to `reconciliation`, the aggregate waits on it, and the
    // outbox carries the `execution.reconciliation.required` work.
    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"attempt!\", \
         (SELECT state FROM central.steps WHERE id = $2) AS \"step!\", \
         (SELECT status FROM central.tasks WHERE id = $3) AS \"task!\", \
         (SELECT waiting_reason FROM central.tasks WHERE id = $3) AS \"waiting!\", \
         (SELECT status FROM central.runs WHERE id = $4) AS \"run!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $5 \
           AND kind = 'execution.recovery.reconciliation_required') AS \"evidence!\", \
         (SELECT count(*) FROM central.outbox WHERE workspace_id = $5 \
           AND catalog_type = 'execution.reconciliation.required') AS \"outbox!\"",
        uuid_of!(att.id),
        uuid_of!(step.id),
        uuid_of!(committed.task.id),
        uuid_of!(run_id),
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.attempt, "reconciliation");
    assert_eq!(row.step, "reconciliation");
    assert_eq!(row.task, "waiting");
    assert_eq!(row.waiting, "reconciliation");
    assert_eq!(row.run, "waiting");
    assert_eq!(row.evidence, 1);
    assert_eq!(row.outbox, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_reconciles_contradictory_completion_receipt() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recontr").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recontr-task").await?;
    let run_id = run_id_of(&committed);
    set_task_run_status(&pool, committed.task.id, run_id, "running", "running").await?;
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;
    let invocation = uuid::Uuid::now_v7();
    mark_attempt_invoked(&pool, att.id, invocation).await?;
    // The receipt's logical operation names a different operation —
    // contradictory evidence never settles; it reconciles.
    insert_completion_receipt(
        &pool,
        ws,
        committed.task.id,
        run_id,
        step.id,
        att.id,
        LogicalOperationId::new(),
        att.physical_attempt_id,
        invocation,
        "succeeded",
        r#"{"schema_version":1,"status":"succeeded"}"#,
    )
    .await?;

    drive_recovery_scan(&store, ws).await?;

    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"attempt!\", \
         (SELECT state FROM central.steps WHERE id = $2) AS \"step!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $3 \
           AND kind = 'execution.recovery.reconciliation_required') AS \"evidence!\", \
         (SELECT count(*) FROM central.outbox WHERE workspace_id = $3 \
           AND catalog_type = 'execution.reconciliation.required') AS \"outbox!\"",
        uuid_of!(att.id),
        uuid_of!(step.id),
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.attempt, "reconciliation");
    assert_eq!(row.step, "reconciliation");
    assert_eq!(row.evidence, 1);
    assert_eq!(row.outbox, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_preserves_existing_reconciliation() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recpres").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recpres-task").await?;
    let run_id = run_id_of(&committed);
    let (req, step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;
    // A prior pass already moved the projection to reconciliation and
    // parked the aggregate on the reconciliation waiter.
    sqlx::query(
        "UPDATE central.step_attempts SET state = 'reconciliation', \
         version = version + 1, updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(uuid_of!(att.id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "UPDATE central.steps SET state = 'reconciliation', \
         version = version + 1, updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(uuid_of!(step.id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "UPDATE central.tasks SET status = 'waiting', \
         waiting_reason = 'reconciliation' WHERE id = $1",
    )
    .bind(uuid_of!(committed.task.id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "UPDATE central.runs SET status = 'waiting', \
         waiting_reason = 'reconciliation' WHERE id = $1",
    )
    .bind(uuid_of!(run_id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    drive_recovery_scan(&store, ws).await?;

    // `reconciliation_preserved` deliberately does not re-emit the
    // outbox work row.
    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"attempt!\", \
         (SELECT status FROM central.tasks WHERE id = $2) AS \"task!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $3 \
           AND kind = 'execution.recovery.reconciliation_preserved') AS \"evidence!\", \
         (SELECT count(*) FROM central.outbox WHERE workspace_id = $3 \
           AND catalog_type = 'execution.reconciliation.required') AS \"outbox!\"",
        uuid_of!(att.id),
        uuid_of!(committed.task.id),
        uuid_of!(ws),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.attempt, "reconciliation");
    assert_eq!(row.task, "waiting");
    assert_eq!(row.evidence, 1);
    assert_eq!(row.outbox, 0);
    Ok(())
}

#[tokio::test]
async fn recovery_leaves_terminal_attempt_untouched() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recterm").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "recterm-task").await?;
    let run_id = run_id_of(&committed);
    let (req, _step, att, _) = prepare_request(ws, committed.task.id, run_id, "prep");
    store.commit(req).await?;
    // Terminal durable shape — recovery must never reopen it.
    sqlx::query(
        "UPDATE central.step_attempts SET state = 'succeeded', \
         version = version + 1, updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(uuid_of!(att.id))
    .execute(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    drive_recovery_scan(&store, ws).await?;

    let row = sqlx::query!(
        "SELECT (SELECT state FROM central.step_attempts WHERE id = $1) AS \"attempt!\", \
         (SELECT count(*) FROM central.step_attempts WHERE workspace_id = $2 \
           AND run_id = $3) AS \"attempts!\", \
         (SELECT count(*) FROM central.events WHERE workspace_id = $2 \
           AND kind = 'execution.recovery.verified_no_unsettled_attempt') AS \"evidence!\"",
        uuid_of!(att.id),
        uuid_of!(ws),
        uuid_of!(run_id),
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.attempt, "succeeded");
    assert_eq!(row.attempts, 1);
    assert_eq!(row.evidence, 1);
    Ok(())
}

#[tokio::test]
async fn stale_coordinator_fence_is_a_conflict() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "fence").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let stale = store
        .acquire_recovery_coordinator(RecoveryCoordinatorAcquireRequest {
            recovery_domain: "central.execution.recovery.v1".to_owned(),
            instance_id: InstanceId::new(),
        })
        .await?;
    // The live lease lapses; a different instance takes the domain
    // over (fence +1) — the old lease is stale for every fenced call.
    sqlx::query(
        "UPDATE central.recovery_coordinators \
         SET lease_expires_at = clock_timestamp() - interval '1 second'",
    )
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let _fresh = store
        .acquire_recovery_coordinator(RecoveryCoordinatorAcquireRequest {
            recovery_domain: "central.execution.recovery.v1".to_owned(),
            instance_id: InstanceId::new(),
        })
        .await?;
    let err = store
        .start_recovery_epoch(StartRecoveryEpochRequest {
            lease: stale,
            batch_size: 10,
        })
        .await
        .unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), "STALE_RECOVERY_FENCE");
    Ok(())
}

#[tokio::test]
async fn expected_version_conflict_rejects_commit() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "cas").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "cas-task").await?;
    let run_id = run_id_of(&committed);
    let (mut req, _, _, _) = prepare_request(ws, committed.task.id, run_id, "cas");
    req.expected_versions.task = 99;
    let err = store.commit(req).await.unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), "EXPECTED_VERSION_CONFLICT");
    Ok(())
}

#[tokio::test]
async fn receipt_replay_of_missing_event_is_corruption() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "corrupt").await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = WorkspaceId::new();
    insert_workspace(&mut mig, uuid_of!(ws)).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let store = Store::new(pool.clone());
    let committed = submit_task(&pool, ws, "corrupt-task").await?;
    let run_id = run_id_of(&committed);
    let (req, _, _, _) = prepare_request(ws, committed.task.id, run_id, "k1");
    store.commit(req.clone()).await?;
    // Corrupt the receipt's result reference — replay must surface
    // corruption, never a silent empty result.
    sqlx::query(
        "UPDATE central.execution_command_receipts SET result_reference = $2 \
         WHERE workspace_id = $1 AND idempotency_key = 'k1'",
    )
    .bind(uuid_of!(ws))
    .bind(uuid::Uuid::now_v7())
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let err = store.commit(req).await.unwrap_err();
    assert_eq!(err.code(), "pg_data_corrupt");
    Ok(())
}
