//! PostgreSQL integration tests for the Task-7a stores
//! (`workspace.rs`, `authorization.rs`, `event.rs`, `checkpoint.rs`).
//!
//! Gated on `CENTRAL_TEST_DSN` — a superuser DSN on a scratch cluster
//! whose `central_migration`, `central_runtime`, and `central_outbox`
//! roles exist (passwords `<role>`), the same provisioning contract as
//! `migrate_integration.rs`. Every test provisions its own database
//! owned by `central_migration` and installs the baseline through
//! [`BaselineInstaller::install`].
//!
//! Role discipline: fixture inserts and the append paths that the
//! grant matrix withholds from `central_runtime` (workspaces INSERT,
//! `secret_use_evidence` INSERT) run on the `central_migration`
//! connection; every port operation the runtime role is granted runs
//! on the `central_runtime` pool — proving the serving-role path is
//! complete.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_authorization::domain::{
    ApprovalRecord, Capability, CapabilityScope, Effect, GrantRequest, ResourceClass,
    SecretUseEvidence,
};
use central_authorization::port::{ApprovalStore, SecretUseEvidenceLog};
use central_authorization::query::{ApprovalSummaryRead, ApprovalSummaryRequest};
use central_checkpoint::domain::{
    CheckpointIntent, CheckpointKind, CheckpointPayload, DEFAULT_INLINE_PAYLOAD_LIMIT, GcClass,
    ResumeCheckpoint, codes as checkpoint_codes,
};
use central_checkpoint::port::{CheckpointStore, ResumeCheckpointStore};
use central_checkpoint::query::{RunCheckpointRead, RunCheckpointRequest};
use central_event::domain::{
    ActorKind, EventActor, EventContext, EventIntent, EventPayload, StateTransition,
};
use central_event::port::EventJournal;
use central_event::query::{EventFeedRead, EventFeedRequest, SeekCursor};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    AggregateId, ArtifactId, ResumeCheckpointId, RunId, SessionAttemptId, TaskId, WorkflowNodeId,
    WorkspaceId,
};
use central_workspace::domain::{
    CreateWorkspaceCommand, WorkspaceChangeSet, WorkspaceGuard, WorkspaceSnapshot,
    codes as workspace_codes, evaluate_create,
};
use central_workspace::port::WorkspaceStore;
use central_workspace::query::{WorkspaceStatusRead, WorkspaceStatusRequest};
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

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
    let db = format!("store_test_{label}_{}", std::process::id());
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&mut *admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
        .execute(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(db)
}

async fn drop_db(admin: &mut PgConnection, db: &str) {
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&mut *admin)
        .await;
}

/// Installs the baseline in a freshly provisioned database.
async fn migrated_db(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = provision(admin, label).await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    BaselineInstaller::new().install(&mut conn).await?;
    Ok(db)
}

// ---------------------------------------------------------------------------
// Fixture inserts — administrative test provisioning (the same dynamic-SQL
// allowance the migrate integration suite uses); bound values only.
// ---------------------------------------------------------------------------

async fn insert_workspace(conn: &mut PgConnection, id: uuid::Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id) \
         VALUES ($1, 'active', 'store-test')",
    )
    .bind(id)
    .execute(conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

async fn insert_task_run(
    conn: &mut PgConnection,
    workspace_id: uuid::Uuid,
) -> Result<(uuid::Uuid, uuid::Uuid)> {
    let task = uuid::Uuid::now_v7();
    let run = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, status, title, input_spec) \
         VALUES ($1, $2, 'queued', 'store-test', '{}'::jsonb)",
    )
    .bind(task)
    .bind(workspace_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, status, run_index) \
         VALUES ($1, $2, $3, 'running', 0)",
    )
    .bind(run)
    .bind(workspace_id)
    .bind(task)
    .execute(conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok((task, run))
}

async fn insert_node_attempt(
    conn: &mut PgConnection,
    workspace_id: uuid::Uuid,
    run: uuid::Uuid,
) -> Result<(uuid::Uuid, uuid::Uuid)> {
    let node = uuid::Uuid::now_v7();
    let attempt = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.workflow_nodes \
         (id, run_id, workspace_id, node_key, harness, workspace_kind, depth, state, spec) \
         VALUES ($1, $2, $3, 'root', 'test-harness', 'worktree', 0, 'succeeded', '{}'::jsonb)",
    )
    .bind(node)
    .bind(run)
    .bind(workspace_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.session_attempts \
         (id, workspace_id, run_id, node_id, attempt_seq, workspace_kind, state) \
         VALUES ($1, $2, $3, $4, 1, 'worktree', 'ambiguous')",
    )
    .bind(attempt)
    .bind(workspace_id)
    .bind(run)
    .bind(node)
    .execute(conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok((node, attempt))
}

// ---------------------------------------------------------------------------
// workspace.rs
// ---------------------------------------------------------------------------

fn snapshot(
    id: WorkspaceId,
    state: central_workspace::domain::WorkspaceState,
) -> WorkspaceSnapshot {
    WorkspaceSnapshot {
        id,
        state,
        owner_principal_id: "store-test".to_owned(),
        quota_ready_bytes: 0,
        quota_ready_count: 0,
        quota_max_bytes: 1024,
        security_epoch: 0,
        restore_epoch: 0,
        created_at: NOW,
        updated_at: NOW,
    }
}

#[tokio::test]
async fn workspace_store_guard_semantics() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "ws").await?;
    let result = async {
        // workspaces INSERT is withheld from central_runtime — the
        // provisioning path runs under central_migration.
        let mig = role_pool(&db, "central_migration").await?;
        let store = central_adapter_postgres::workspace::Store::new(mig);
        let workspace_id = WorkspaceId::new();

        let create = evaluate_create(
            CreateWorkspaceCommand {
                workspace_id,
                owner_principal_id: "store-test".to_owned(),
                quota_max_bytes: Some(1024),
            },
            NOW,
        )?;
        let created = store.commit_change_set(create).await?;
        assert_eq!(created.id, workspace_id);
        assert_eq!(created.quota_max_bytes, 1024);

        // Duplicate insert under the Absent guard → already-exists conflict.
        let dupe = WorkspaceChangeSet {
            guard: WorkspaceGuard::Absent,
            next: snapshot(
                workspace_id,
                central_workspace::domain::WorkspaceState::Active,
            ),
        };
        let err = store.commit_change_set(dupe).await.expect_err("dup insert");
        assert_eq!(err.kind(), FailureKind::Conflict);
        assert_eq!(err.code(), workspace_codes::WORKSPACE_ALREADY_EXISTS);

        // Present-guard epoch advance.
        let mut next = created.clone();
        next.security_epoch = 7;
        let committed = store
            .commit_change_set(WorkspaceChangeSet {
                guard: WorkspaceGuard::from_snapshot(&created),
                next,
            })
            .await?;
        assert_eq!(committed.security_epoch, 7);
        assert!(committed.updated_at >= created.updated_at);

        // Stale guard (the pre-commit snapshot) → state conflict.
        let mut stale_next = committed.clone();
        stale_next.restore_epoch = 1;
        let err = store
            .commit_change_set(WorkspaceChangeSet {
                guard: WorkspaceGuard::from_snapshot(&created),
                next: stale_next,
            })
            .await
            .expect_err("stale guard must conflict");
        assert_eq!(err.kind(), FailureKind::Conflict);
        assert_eq!(err.code(), workspace_codes::WORKSPACE_STATE_CONFLICT);

        // Snapshot load round-trips the committed row.
        let loaded = store.load_snapshot(workspace_id).await?.expect("row");
        assert_eq!(loaded.security_epoch, 7);
        assert_eq!(loaded.restore_epoch, 0);

        let rt = role_pool(&db, "central_runtime").await?;
        let read = central_adapter_postgres::workspace::Store::new(rt);
        let projection = read.status(WorkspaceStatusRequest { workspace_id }).await?;
        assert_eq!(projection.quota_max_bytes, 1024);
        let absent = read
            .status(WorkspaceStatusRequest {
                workspace_id: WorkspaceId::new(),
            })
            .await
            .expect_err("missing workspace");
        assert_eq!(absent.kind(), FailureKind::NotFound);
        assert_eq!(absent.code(), workspace_codes::WORKSPACE_NOT_FOUND);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

// ---------------------------------------------------------------------------
// authorization.rs
// ---------------------------------------------------------------------------

fn grant(workspace_id: WorkspaceId, task_id: TaskId) -> Result<ApprovalRecord> {
    ApprovalRecord::grant(GrantRequest {
        workspace_id,
        capability: Capability::new(ResourceClass::Filesystem, Effect::Read)?,
        scope: CapabilityScope {
            task_id: Some(task_id),
            operation_key: None,
            selector: "/workspace/src".to_owned(),
        },
        actor_identity: "agent:worker".to_owned(),
        authority_identity: "local-operator".to_owned(),
        reason: "test grant".to_owned(),
        security_epoch: 0,
        issued_at: NOW,
        // Per-action grant — `expiry_at` is validated against the
        // database-stamped `created_at`, not `issued_at`.
        expiry_at: None,
    })
}

#[tokio::test]
async fn approval_store_lifecycle_and_batch_atomicity() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "appr").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let (task_uuid, _run_uuid) = insert_task_run(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let task_id = TaskId::from_trusted_db_bytes(task_uuid.into_bytes());

        let rt = role_pool(&db, "central_runtime").await?;
        let store = central_adapter_postgres::authorization::Store::new(rt);

        // insert_approval: fresh record at version 0.
        let record = grant(workspace_id, task_id)?;
        store.insert_approval(record.clone()).await?;
        let loaded = store.load_approval(workspace_id, record.id).await?;
        // created_at/updated_at are database-authoritative stamps.
        let mut expected = record;
        expected.created_at = loaded.created_at;
        expected.updated_at = loaded.updated_at;
        assert_eq!(loaded, expected);
        assert!(loaded.created_at > OffsetDateTime::UNIX_EPOCH);
        let missing = store
            .load_approval(
                workspace_id,
                central_foundation::identity::ApprovalId::new(),
            )
            .await
            .expect_err("absent approval");
        assert_eq!(
            missing.code(),
            central_authorization::domain::codes::APPROVAL_NOT_FOUND
        );

        // Guarded commit: revocation advances the version.
        let revocation = loaded.evaluate_revocation("no longer needed", NOW)?;
        store.commit_approval_change_set(revocation).await?;
        let revoked = store.load_approval(workspace_id, expected.id).await?;
        assert_eq!(revoked.version, 1);
        assert_eq!(
            revoked.state,
            central_authorization::domain::ApprovalState::Revoked
        );

        // Stale expected_version → Conflict.
        let stale = loaded.evaluate_suspension("stale", NOW)?;
        let err = store
            .commit_approval_change_set(stale)
            .await
            .expect_err("stale version");
        assert_eq!(err.kind(), FailureKind::Conflict);

        // Batch commit: two fresh grants, one stale set in the middle —
        // the whole batch must roll back.
        let a = grant(workspace_id, task_id)?;
        let b = grant(workspace_id, task_id)?;
        store.insert_approval(a.clone()).await?;
        store.insert_approval(b.clone()).await?;
        let good_a = a.evaluate_suspension("review", NOW)?;
        let mut wrong = b.clone();
        wrong.version = 99;
        let bad_b = wrong.evaluate_suspension("review", NOW)?;
        let err = store
            .commit_approval_change_sets(vec![good_a, bad_b])
            .await
            .expect_err("batch must abort");
        assert_eq!(err.kind(), FailureKind::Conflict);
        // a must be unchanged — all-or-nothing.
        let a_now = store.load_approval(workspace_id, a.id).await?;
        assert_eq!(a_now.version, 0);
        assert_eq!(
            a_now.state,
            central_authorization::domain::ApprovalState::Active
        );

        // Empty batch is a no-op; load_workspace_approvals returns all rows.
        store.commit_approval_change_sets(Vec::new()).await?;
        let all = store.load_workspace_approvals(workspace_id).await?;
        assert_eq!(all.len(), 3);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn approval_summary_seek_pagination() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "q5").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let (task_uuid, _run_uuid) = insert_task_run(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let task_id = TaskId::from_trusted_db_bytes(task_uuid.into_bytes());

        let rt = role_pool(&db, "central_runtime").await?;
        let store = central_adapter_postgres::authorization::Store::new(rt);

        for _ in 0..4 {
            let record = grant(workspace_id, task_id)?;
            store.insert_approval(record).await?;
        }
        {
            let mut record = grant(workspace_id, task_id)?;
            record.actor_identity = Some("agent:other".to_owned());
            store.insert_approval(record).await?;
        }
        let request = ApprovalSummaryRequest {
            workspace_id,
            task_id: None,
            approver: "agent:worker".to_owned(),
            cursor: None,
            limit: Some(3),
        };
        let page1 = store.read_page(&request).await?;
        assert_eq!(page1.approvals.len(), 3);
        assert!(page1.next_cursor.is_some());
        // Descending (updated_at, id).
        assert!(page1.approvals[0].updated_at >= page1.approvals[1].updated_at);

        let page2 = store
            .read_page(&ApprovalSummaryRequest {
                cursor: page1.next_cursor.clone(),
                ..request
            })
            .await?;
        assert_eq!(page2.approvals.len(), 1);
        assert!(page2.next_cursor.is_none());
        // No row repeats across pages.
        for row in &page2.approvals {
            assert!(!page1.approvals.contains(row));
        }
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn secret_use_evidence_appends() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "sec").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());

        // `secret_use_evidence` INSERT is withheld from central_runtime;
        // the audit write path runs under the owning role.
        let mig_pool = role_pool(&db, "central_migration").await?;
        let store = central_adapter_postgres::authorization::Store::new(mig_pool);
        let evidence = SecretUseEvidence::record(
            workspace_id,
            "secret-ref:deploy-key",
            "agent:worker",
            "operation:deploy",
            "allow",
            NOW,
        )?;
        store.append_secret_use(evidence.clone()).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM central.secret_use_evidence WHERE id = $1")
                .bind(uuid::Uuid::from_bytes(*evidence.id.as_bytes()))
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(count, 1);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

// ---------------------------------------------------------------------------
// event.rs
// ---------------------------------------------------------------------------

fn intent(workspace_id: WorkspaceId, aggregate_id: AggregateId) -> Result<EventIntent> {
    Ok(EventIntent {
        workspace_id,
        event_type: "task.transitioned".to_owned(),
        aggregate_type: "task".to_owned(),
        aggregate_id,
        aggregate_version: 1,
        occurred_at: NOW,
        correlation_id: None,
        causation_id: None,
        command_id: None,
        run_id: None,
        context: EventContext::default(),
        actor: EventActor::new("system:store-test", ActorKind::System)?,
        transition: StateTransition::new(Some("queued".to_owned()), "running", None)?,
        payload: EventPayload::sanitize(br#"{"type":"task.transitioned.v1","detail":"test"}"#)?,
    })
}

#[tokio::test]
async fn event_journal_allocates_sequences_and_feed_seeks() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "ev").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());

        let rt = role_pool(&db, "central_runtime").await?;
        let store = central_adapter_postgres::event::Store::new(rt);

        // Empty batch is a no-op; oversize is invalid.
        assert!(
            store
                .append_events(workspace_id, Vec::new())
                .await?
                .is_empty()
        );
        let oversized: Vec<EventIntent> = (0..9)
            .map(|_| intent(workspace_id, AggregateId::new()))
            .collect::<Result<Vec<_>>>()?;
        let err = store
            .append_events(workspace_id, oversized)
            .await
            .expect_err("oversize batch");
        assert_eq!(err.kind(), FailureKind::Invalid);

        let aggregate = AggregateId::new();
        let appended = store
            .append_events(
                workspace_id,
                vec![
                    intent(workspace_id, aggregate)?,
                    intent(workspace_id, AggregateId::new())?,
                    intent(workspace_id, aggregate)?,
                ],
            )
            .await?;
        assert_eq!(
            appended.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)]
        );

        // The next workspace append continues the sequence — no reuse.
        let more = store
            .append_events(workspace_id, vec![intent(workspace_id, aggregate)?])
            .await?;
        assert_eq!(more[0].sequence, Some(4));

        // Feed: first page of two has_more; second page ends the feed.
        let page1 = store
            .read_page(&EventFeedRequest {
                workspace_id,
                after: None,
                aggregate_id: None,
                run_id: None,
                limit: Some(2),
            })
            .await?;
        assert_eq!(page1.events.len(), 2);
        assert!(page1.has_more);
        assert_eq!(
            page1.next_cursor,
            Some(SeekCursor {
                workspace_id,
                event_sequence: 2
            })
        );
        // Envelope round-trip restores every semantic leg.
        let first = &page1.events[0];
        assert_eq!(first.event_type, "task.transitioned");
        assert_eq!(first.aggregate_type, "task");
        assert_eq!(first.aggregate_id, aggregate);
        assert_eq!(first.actor.kind, ActorKind::System);
        assert_eq!(first.transition.next_state, "running");
        assert_eq!(first.payload.payload_type(), "task.transitioned.v1");

        let page2 = store
            .read_page(&EventFeedRequest {
                workspace_id,
                after: page1.next_cursor,
                aggregate_id: None,
                run_id: None,
                limit: Some(2),
            })
            .await?;
        assert_eq!(page2.events.len(), 2);
        assert!(!page2.has_more);
        assert_eq!(page2.events[0].sequence, Some(3));

        // Aggregate filter and has_events_after.
        let filtered = store
            .read_page(&EventFeedRequest {
                workspace_id,
                after: None,
                aggregate_id: Some(aggregate),
                run_id: None,
                limit: Some(100),
            })
            .await?;
        assert_eq!(filtered.events.len(), 3);
        assert!(store.has_events_after(workspace_id, 3).await?);
        assert!(!store.has_events_after(workspace_id, 4).await?);

        // A cursor minted for another workspace is rejected.
        let foreign = store
            .read_page(&EventFeedRequest {
                workspace_id,
                after: Some(SeekCursor {
                    workspace_id: WorkspaceId::new(),
                    event_sequence: 0,
                }),
                aggregate_id: None,
                run_id: None,
                limit: None,
            })
            .await
            .expect_err("foreign cursor");
        assert_eq!(foreign.kind(), FailureKind::Invalid);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

// ---------------------------------------------------------------------------
// checkpoint.rs
// ---------------------------------------------------------------------------

fn checkpoint_payload() -> Result<CheckpointPayload> {
    CheckpointPayload::sanitize(
        br#"{"schema_version":1,"producer_version":"1.0","continuation":{"state":"ready","cursor":"c","sequence":1,"summary":"s","metadata":{"source":"x"}},"metadata":{"sequence":1}}"#,
        DEFAULT_INLINE_PAYLOAD_LIMIT,
    )
}

fn checkpoint(
    workspace_id: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    kind: CheckpointKind,
) -> Result<central_checkpoint::domain::Checkpoint> {
    CheckpointIntent {
        workspace_id,
        task_id,
        run_id,
        step_id: None,
        step_attempt_id: None,
        kind,
        producer_id: "central-executor".to_owned(),
        producer_version: "1.0".to_owned(),
        schema_version: 1,
        policy_fingerprint: "sha256:pol".to_owned(),
        agent_revision_fingerprint: "sha256:agent".to_owned(),
        payload: checkpoint_payload()?,
        metadata: None,
        eligible_after: NOW + Duration::days(90),
        legal_hold: false,
        source_checkpoint_id: None,
    }
    .seal(NOW)
}

#[tokio::test]
async fn checkpoint_store_append_load_and_page() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "ckpt").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let (task_uuid, run_uuid) = insert_task_run(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let task_id = TaskId::from_trusted_db_bytes(task_uuid.into_bytes());
        let run_id = RunId::from_trusted_db_bytes(run_uuid.into_bytes());

        let rt = role_pool(&db, "central_runtime").await?;
        let store = central_adapter_postgres::checkpoint::Store::new(rt);

        let first = checkpoint(workspace_id, task_id, run_id, CheckpointKind::RunStart)?;
        let second = checkpoint(workspace_id, task_id, run_id, CheckpointKind::StepBoundary)?;
        store.append_checkpoint(first.clone()).await?;
        // Brief ordering separation — created_at is clock-stamped.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        store.append_checkpoint(second.clone()).await?;

        // Duplicate identity is a conflict.
        let err = store
            .append_checkpoint(first.clone())
            .await
            .expect_err("duplicate checkpoint");
        assert_eq!(err.kind(), FailureKind::Conflict);

        let loaded = store
            .load_checkpoint(workspace_id, first.id)
            .await?
            .expect("row");
        assert_eq!(loaded.id, first.id);
        assert_eq!(loaded.kind, CheckpointKind::RunStart);
        assert_eq!(loaded.payload.as_bytes(), first.payload.as_bytes());
        assert_eq!(loaded.checksum, first.checksum);

        // Newest-first ordering for the run snapshot.
        let run_rows = store.load_run_checkpoints(workspace_id, run_id, 50).await?;
        assert_eq!(run_rows.len(), 2);
        assert!(run_rows[0].created_at >= run_rows[1].created_at);

        // Seek page: newest page of one, then created_before continues.
        let page1 = store
            .read_page(&RunCheckpointRequest {
                workspace_id,
                run_id,
                kinds: Vec::new(),
                created_before: None,
                limit: Some(1),
            })
            .await?;
        assert_eq!(page1.checkpoints.len(), 1);
        assert!(page1.next_boundary.is_some());
        let page2 = store
            .read_page(&RunCheckpointRequest {
                workspace_id,
                run_id,
                kinds: vec![CheckpointKind::RunStart],
                created_before: page1.next_boundary,
                limit: Some(1),
            })
            .await?;
        assert_eq!(page2.checkpoints.len(), 1);
        assert_eq!(page2.checkpoints[0].kind, CheckpointKind::RunStart);
        assert!(page2.next_boundary.is_none());
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn resume_checkpoint_dedupe_gc_roundtrip() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "rc").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let (_task_uuid, run_uuid) = insert_task_run(&mut mig, ws_uuid).await?;
        let (node_uuid, attempt_uuid) = insert_node_attempt(&mut mig, ws_uuid, run_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let run_id = RunId::from_trusted_db_bytes(run_uuid.into_bytes());
        let node_id = WorkflowNodeId::from_trusted_db_bytes(node_uuid.into_bytes());
        let attempt_id = SessionAttemptId::from_trusted_db_bytes(attempt_uuid.into_bytes());
        let artifact = ArtifactId::new();

        let rt = role_pool(&db, "central_runtime").await?;
        let store = central_adapter_postgres::checkpoint::Store::new(rt);

        let mut record = ResumeCheckpoint {
            id: ResumeCheckpointId::new(),
            workspace_id,
            run_id,
            node_id,
            attempt_id,
            checkpoint_seq: 1,
            format_version: central_checkpoint::domain::RESUME_FORMAT_VERSION.to_owned(),
            graph_schema_version: central_checkpoint::domain::GRAPH_SCHEMA_VERSION.to_owned(),
            event_watermark: 7,
            harness_session_id: Some("harness-session-1".to_owned()),
            workspace_digest: Some("sha256:ws".to_owned()),
            workspace_path: Some("/var/central/ws".to_owned()),
            completed_nodes: vec!["a".to_owned(), "b".to_owned()],
            finalized_artifacts: vec![artifact],
            in_flight_nodes: vec!["c".to_owned()],
            gc_class: GcClass::Supersedeable,
            created_at: NOW,
            expires_at: Some(NOW + Duration::days(30)),
            content_digest: String::new(),
        };
        record.content_digest = record.digest();

        // Fresh insert returns the recorded row.
        let written = store.insert_deduplicated(record.clone()).await?;
        assert_eq!(written.id, record.id);
        assert!(written.created_at >= NOW);

        // Identical retry is a no-op returning the recorded row.
        let replay = store.insert_deduplicated(record.clone()).await?;
        assert_eq!(replay.id, record.id);
        assert_eq!(replay.created_at, written.created_at);

        // Same coordinate, different fingerprint → DUPLICATE_IDEMPOTENCY.
        let mut conflicting = record.clone();
        conflicting.id = ResumeCheckpointId::new();
        conflicting.completed_nodes = vec!["different".to_owned()];
        conflicting.content_digest = conflicting.digest();
        let err = store
            .insert_deduplicated(conflicting)
            .await
            .expect_err("fingerprint mismatch");
        assert_eq!(err.kind(), FailureKind::Conflict);
        assert_eq!(err.code(), checkpoint_codes::DUPLICATE_IDEMPOTENCY);

        // Load + GC list + delete.
        let loaded = store
            .load_resume_checkpoint(workspace_id, record.id)
            .await?
            .expect("row");
        assert_eq!(loaded.content_digest, record.digest());
        assert_eq!(loaded.checkpoint_seq, 1);
        assert_eq!(loaded.completed_nodes, ["a", "b"]);
        assert_eq!(loaded.finalized_artifacts, vec![artifact]);

        let candidates = store.list_gc_candidates(workspace_id).await?;
        assert_eq!(candidates.len(), 1);

        let deleted = store.delete_checkpoints(workspace_id, &[record.id]).await?;
        assert_eq!(deleted, 1);
        assert!(
            store
                .load_resume_checkpoint(workspace_id, record.id)
                .await?
                .is_none()
        );
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}
