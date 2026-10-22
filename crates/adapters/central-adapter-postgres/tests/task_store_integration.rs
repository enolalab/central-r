//! PostgreSQL integration tests for the Task-7b task stores
//! (`task/store.rs`, `task/event_log_store.rs`,
//! `task/milestone_store.rs`).
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `store_integration.rs`: a superuser DSN on a scratch cluster whose
//! `central_migration` / `central_runtime` roles exist. Every test
//! provisions its own database owned by `central_migration` and
//! installs the baseline through [`BaselineInstaller::install`].
//!
//! Role discipline: `workspaces` INSERT runs on `central_migration`;
//! every task-store port operation runs on `central_runtime` — the
//! serving-role path the grant matrix promises.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::task::{
    DetailStore, EventLogStore, ListStore, MILESTONE_PRODUCER, Milestone, MilestoneStore, Store,
    milestone_event_id,
};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{RunId, TaskId, WorkspaceId};
use central_task::domain::{
    self, Budget, MutationInput, NO_EXISTING_VERSION, RunStatus, TaskStatus, codes as task_codes,
};
use central_task::port::{AggregateLoader, ChangeSetStore, CommitTaskChangeSetRequest};
use central_task::query::{
    RunSeekCursor, TaskDetailRead, TaskDetailRequest, TaskEventLogRead, TaskEventLogRequest,
    TaskListRead, TaskListRequest,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

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
    let db = format!("task_test_{label}_{}", std::process::id());
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

async fn migrated_db(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = provision(admin, label).await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    BaselineInstaller::new().install(&mut conn).await?;
    Ok(db)
}

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

// ---------------------------------------------------------------------------
// Domain change-set builders — the same evaluators `central-task::app`
// drives, so the adapter is tested against domain-approved writes.
// ---------------------------------------------------------------------------

const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn submit(workspace_id: WorkspaceId, title: &str) -> Result<domain::TaskChangeSet> {
    domain::submit_task(domain::SubmitTaskRequest {
        workspace_id,
        title: title.to_owned(),
        input: "input.yaml".to_owned(),
        permission_policy: None,
        budget: Budget::default(),
        run_key: None,
        now: NOW,
    })
}

fn commit_req(
    workspace_id: WorkspaceId,
    change_set: domain::TaskChangeSet,
    scope: &'static str,
    key: Option<&str>,
) -> CommitTaskChangeSetRequest {
    CommitTaskChangeSetRequest {
        workspace_id,
        change_set,
        command_scope: scope,
        idempotency_key: key.map(str::to_owned),
        correlation_id: None,
        causation_id: None,
    }
}

async fn submit_committed(
    store: &Store,
    workspace_id: WorkspaceId,
    title: &str,
) -> Result<domain::CommitResult> {
    store
        .commit_task_change_set(commit_req(
            workspace_id,
            submit(workspace_id, title)?,
            "task.submit",
            Some(title),
        ))
        .await
}

/// Loads the aggregate and wraps it in the mutation envelope the
/// transition evaluators take.
async fn mutation(
    store: &Store,
    workspace_id: WorkspaceId,
    task_id: TaskId,
    now: OffsetDateTime,
) -> Result<MutationInput> {
    let loaded = store.load_aggregate(workspace_id, task_id).await?;
    Ok(MutationInput {
        aggregate: loaded.aggregate,
        expected_task_version: loaded.task_version,
        expected_run_version: loaded.run_version.unwrap_or(NO_EXISTING_VERSION),
        now,
    })
}

// ---------------------------------------------------------------------------
// Commit path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_commit_submit_and_event_block() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "commit").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());

        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt);

        let committed = submit_committed(&store, workspace_id, "first").await?;
        assert_eq!(committed.task.status, TaskStatus::Queued);
        assert_eq!(committed.task.version, 1);
        assert_eq!(committed.runs.len(), 1);
        assert_eq!(committed.runs[0].status, RunStatus::Queued);
        assert_eq!(committed.events.len(), 1);
        assert_eq!(committed.task.input, "input.yaml");

        // The submit event block is contiguous starting at 1, and the
        // workspace counter landed on it.
        let seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT event_sequence FROM central.events \
             WHERE workspace_id = $1 ORDER BY event_sequence",
        )
        .bind(ws_uuid)
        .fetch_all(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(seqs, vec![1]);
        let counter: i64 = sqlx::query_scalar(
            "SELECT last_event_sequence FROM central.workspace_event_counters \
             WHERE workspace_id = $1",
        )
        .bind(ws_uuid)
        .fetch_one(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(counter, 1);

        // claim → wait appends the next contiguous block.
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let claim = domain::claim_current_run(domain::ClaimCurrentRunRequest {
            input,
            owner: "executor-1".to_owned(),
        })?;
        store
            .commit_task_change_set(commit_req(
                workspace_id,
                claim,
                "task.claim_current_run",
                None,
            ))
            .await?;
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let wait = domain::wait_task(domain::WaitTaskRequest {
            input,
            reason: Some(domain::WaitingReason::Approval),
            detail: "needs approval".to_owned(),
        })?;
        let settled = store
            .commit_task_change_set(commit_req(workspace_id, wait, "task.wait", None))
            .await?;
        assert_eq!(settled.task.status, TaskStatus::Waiting);
        let seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT event_sequence FROM central.events \
             WHERE workspace_id = $1 ORDER BY event_sequence",
        )
        .bind(ws_uuid)
        .fetch_all(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert!(seqs.len() >= 3 && seqs.windows(2).all(|w| w[1] == w[0] + 1));
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_commit_stale_version_and_missing_run_version() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "cas").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt);
        let committed = submit_committed(&store, workspace_id, "cas").await?;

        // A stale expected task version conflicts and writes nothing.
        let mut stale = submit(workspace_id, "no-write")?;
        stale.task.id = committed.task.id;
        stale.expected_task_version = 99;
        let err = store
            .commit_task_change_set(commit_req(workspace_id, stale, "task.wait", None))
            .await
            .expect_err("stale task version must conflict");
        assert_eq!(err.kind(), FailureKind::Conflict);
        assert_eq!(err.code(), task_codes::VERSION_CONFLICT);

        // A run without an entry in run_expected_versions is invalid.
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let mut claim = domain::claim_current_run(domain::ClaimCurrentRunRequest {
            input,
            owner: "executor-1".to_owned(),
        })?;
        claim.run_expected_versions.clear();
        let err = store
            .commit_task_change_set(commit_req(
                workspace_id,
                claim,
                "task.claim_current_run",
                None,
            ))
            .await
            .expect_err("missing run expected version is invalid");
        assert_eq!(err.kind(), FailureKind::Invalid);

        // And the run itself did not transition.
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let mut stale_run = domain::claim_current_run(domain::ClaimCurrentRunRequest {
            input,
            owner: "executor-2".to_owned(),
        })?;
        stale_run
            .run_expected_versions
            .insert(committed.runs[0].id, 42);
        let err = store
            .commit_task_change_set(commit_req(
                workspace_id,
                stale_run,
                "task.claim_current_run",
                None,
            ))
            .await
            .expect_err("stale run version must conflict");
        assert_eq!(err.kind(), FailureKind::Conflict);
        assert_eq!(err.code(), task_codes::VERSION_CONFLICT);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_commit_idempotent_replay_and_fingerprint_conflict() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "idem").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt);

        let req = commit_req(
            workspace_id,
            submit(workspace_id, "replayed")?,
            "task.submit",
            Some("same-key"),
        );
        let first = store.commit_task_change_set(req.clone()).await?;
        // Identical request replays the original committed rows.
        let second = store.commit_task_change_set(req).await?;
        assert_eq!(first.task.id, second.task.id);
        assert_eq!(first.runs.len(), second.runs.len());
        let tasks: i64 =
            sqlx::query_scalar("SELECT count(*) FROM central.tasks WHERE workspace_id = $1")
                .bind(ws_uuid)
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(tasks, 1);
        let receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM central.command_receipts WHERE workspace_id = $1",
        )
        .bind(ws_uuid)
        .fetch_one(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(receipts, 1);

        // Same key carrying a different payload conflicts.
        let err = store
            .commit_task_change_set(commit_req(
                workspace_id,
                submit(workspace_id, "different-payload")?,
                "task.submit",
                Some("same-key"),
            ))
            .await
            .expect_err("mismatched fingerprint must conflict");
        assert_eq!(err.kind(), FailureKind::Conflict);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_load_aggregate_and_workspace_isolation() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "load").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let other_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, other_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let other = WorkspaceId::from_trusted_db_bytes(other_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt);
        let committed = submit_committed(&store, workspace_id, "loaded").await?;

        let loaded = store
            .load_aggregate(workspace_id, committed.task.id)
            .await?;
        assert_eq!(loaded.task_version, 1);
        assert_eq!(loaded.run_version, Some(1));
        assert_eq!(
            loaded.aggregate.current_run.as_ref().map(|r| r.id),
            Some(committed.runs[0].id)
        );

        // Missing and cross-workspace both answer task_not_found.
        let err = store
            .load_aggregate(workspace_id, TaskId::new())
            .await
            .expect_err("missing task");
        assert_eq!(err.kind(), FailureKind::NotFound);
        assert_eq!(err.code(), task_codes::TASK_NOT_FOUND);
        let err = store
            .load_aggregate(other, committed.task.id)
            .await
            .expect_err("cross-workspace task");
        assert_eq!(err.code(), task_codes::TASK_NOT_FOUND);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_list_keyset_pagination() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "list").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt.clone());
        let list = ListStore::new(rt);

        for title in ["a", "b", "c"] {
            submit_committed(&store, workspace_id, title).await?;
        }
        let page1 = list
            .read(TaskListRequest {
                workspace_id,
                cursor: None,
                page_size: 2,
            })
            .await?;
        assert_eq!(page1.tasks.len(), 2);
        let cursor = page1.next_cursor.expect("full page emits a cursor");
        let page2 = list
            .read(TaskListRequest {
                workspace_id,
                cursor: Some(cursor),
                page_size: 2,
            })
            .await?;
        assert_eq!(page2.tasks.len(), 1);
        let ids: Vec<_> = page1
            .tasks
            .iter()
            .chain(&page2.tasks)
            .map(|t| t.task_id)
            .collect();
        let mut dedup = ids.clone();
        dedup.dedup();
        assert_eq!(ids.len(), dedup.len(), "no row repeats across pages");
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_detail_runs_revisions_and_lineage() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "detail").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt.clone());
        let detail = DetailStore::new(rt);

        let committed = submit_committed(&store, workspace_id, "detailed").await?;
        // claim → wait → schedule retry → activate a second run, so the
        // task has two run rows to keyset over.
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let claim = domain::claim_current_run(domain::ClaimCurrentRunRequest {
            input,
            owner: "exec".to_owned(),
        })?;
        store
            .commit_task_change_set(commit_req(
                workspace_id,
                claim,
                "task.claim_current_run",
                None,
            ))
            .await?;
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let failed = domain::fail_task(domain::FailTaskRequest {
            input,
            reason: "boom".to_owned(),
        })?;
        store
            .commit_task_change_set(commit_req(workspace_id, failed, "task.fail", None))
            .await?;
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let retry = domain::retry_failed_task(domain::RetryFailedTaskRequest { input })?;
        let settled = store
            .commit_task_change_set(commit_req(workspace_id, retry, "task.retry_failed", None))
            .await?;
        assert_eq!(settled.task.status, TaskStatus::Queued);
        assert_eq!(settled.runs.len(), 1);

        let proj = detail
            .read(TaskDetailRequest {
                workspace_id,
                task_id: committed.task.id,
                run_cursor: None,
                run_page_size: 1,
            })
            .await?;
        assert_eq!(proj.task.task_id, committed.task.id);
        assert_eq!(proj.runs.len(), 1);
        assert!(proj.task.event_revision > 0);
        let max_seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(event_sequence), 0) FROM central.events \
             WHERE workspace_id = $1 AND aggregate_id = $2",
        )
        .bind(ws_uuid)
        .bind(uuid::Uuid::from_bytes(*committed.task.id.as_bytes()))
        .fetch_one(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(proj.task.event_revision, max_seq);
        assert_eq!(proj.task.projection_revision, settled.task.version);

        let cursor: RunSeekCursor = proj.next_run_cursor.expect("full run page emits a cursor");
        let page2 = detail
            .read(TaskDetailRequest {
                workspace_id,
                task_id: committed.task.id,
                run_cursor: Some(cursor),
                run_page_size: 1,
            })
            .await?;
        assert_eq!(page2.runs.len(), 1);
        assert_ne!(page2.runs[0].run_id, proj.runs[0].run_id);

        // Lineage: cancel the task unclaimed then rerun it — the new
        // task's parent_task_id must round-trip.
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let cancel = domain::cancel_unclaimed_task(domain::CancelUnclaimedTaskRequest { input })?;
        store
            .commit_task_change_set(commit_req(
                workspace_id,
                cancel,
                "task.cancel_unclaimed",
                None,
            ))
            .await?;
        let source = store
            .load_aggregate(workspace_id, committed.task.id)
            .await?;
        let rerun = domain::rerun_cancelled_task(domain::RerunCancelledTaskRequest {
            source: source.aggregate,
            expected_task_version: source.task_version,
            now: NOW,
        })?;
        let rerun_task_id = rerun.task.id;
        store
            .commit_task_change_set(commit_req(
                workspace_id,
                rerun,
                "task.rerun_cancelled",
                None,
            ))
            .await?;
        let child = detail
            .read(TaskDetailRequest {
                workspace_id,
                task_id: rerun_task_id,
                run_cursor: None,
                run_page_size: 0,
            })
            .await?;
        assert_eq!(child.task.parent_task_id, Some(committed.task.id));
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_detail_required_artifact_and_ordering() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "art").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt.clone());
        let detail = DetailStore::new(rt);
        let committed = submit_committed(&store, workspace_id, "artifacts").await?;
        let task_uuid = uuid::Uuid::from_bytes(*committed.task.id.as_bytes());
        let run_uuid = uuid::Uuid::from_bytes(*committed.runs[0].id.as_bytes());

        // Three ready artifacts: patch first (older), an unroled one,
        // then the report — the projection must still pick the report.
        let mut report_uuid = uuid::Uuid::nil();
        for (role, delay_secs) in [
            ("harness.patch", -30i64),
            ("", -20i64),
            ("harness.report", -10i64),
        ] {
            let id = uuid::Uuid::now_v7();
            if role == "harness.report" {
                report_uuid = id;
            }
            let role_bind: Option<&str> = if role.is_empty() { None } else { Some(role) };
            sqlx::query(
                "INSERT INTO central.artifacts (\
                 id, workspace_id, task_id, run_id, state, staging_generation, \
                 object_key, sensitivity, disposition, required_role, size, \
                 ready_key, content_generation, checksum_value, ready_at, \
                 created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, 'ready', gen_random_uuid(), \
                 'obj-' || $1::text, 'unrestricted', 'inline', $5, 10, \
                 'rk-' || $1::text, gen_random_uuid(), \
                 decode(repeat('ab', 32), 'hex'), \
                 clock_timestamp() + ($6 || ' seconds')::interval, \
                 clock_timestamp() + ($6 || ' seconds')::interval, \
                 clock_timestamp() + ($6 || ' seconds')::interval)",
            )
            .bind(id)
            .bind(ws_uuid)
            .bind(task_uuid)
            .bind(run_uuid)
            .bind(role_bind)
            .bind(delay_secs.to_string())
            .execute(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        }
        // A delete-intent artifact is excluded entirely.
        sqlx::query(
            "INSERT INTO central.artifacts (\
             id, workspace_id, task_id, run_id, state, staging_generation, \
             object_key, sensitivity, disposition, required_role, size, \
             ready_key, content_generation, checksum_value, \
             delete_intent_at) \
             VALUES ($1, $2, $3, $4, 'ready', gen_random_uuid(), \
             'obj-' || $1::text, 'unrestricted', 'inline', 'harness.commits', 5, \
             'rk-' || $1::text, gen_random_uuid(), \
             decode(repeat('cd', 32), 'hex'), clock_timestamp())",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(ws_uuid)
        .bind(task_uuid)
        .bind(run_uuid)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;

        let proj = detail
            .read(TaskDetailRequest {
                workspace_id,
                task_id: committed.task.id,
                run_cursor: None,
                run_page_size: 0,
            })
            .await?;
        assert_eq!(
            proj.task
                .required_artifact_id
                .map(|a| uuid::Uuid::from_bytes(*a.as_bytes())),
            Some(report_uuid),
            "harness.report wins over newer ready artifacts"
        );
        let roles: Vec<&str> = proj
            .task
            .artifacts
            .iter()
            .map(|a| a.role.as_str())
            .collect();
        assert_eq!(roles[0], "harness.report");
        assert_eq!(roles[1], "harness.patch");
        assert_eq!(roles.len(), 3, "delete-intent artifact excluded");
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_event_log_ordering_seek_and_hidden() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "elog").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt.clone());
        let log = EventLogStore::new(rt.clone());
        let milestones = MilestoneStore::new(rt);
        let committed = submit_committed(&store, workspace_id, "logged").await?;

        // A milestone surfaces in the feed; a heartbeat is hidden.
        milestones
            .append(&Milestone {
                key: "m-1".to_owned(),
                kind: "harness.session_started".to_owned(),
                workspace_id,
                task_id: committed.task.id,
                run_id: committed.runs[0].id,
                attempt_id: None,
                status: "started".to_owned(),
                reason: String::new(),
                at: OffsetDateTime::now_utc(),
            })
            .await?;
        sqlx::query(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, run_id, payload, occurred_at, task_id, kind, \
             state, producer_id, policy_version, eligible_after, legal_hold) \
             VALUES (gen_random_uuid(), $1, \
             (SELECT last_event_sequence + 1 FROM central.workspace_event_counters WHERE workspace_id = $1), \
             'attempt_heartbeat', $2, 0, $3, '{}'::jsonb, clock_timestamp(), $2, \
             'attempt_heartbeat', 'recorded', 'central.test.v1', 1, \
             clock_timestamp() + interval '90 days', false)",
        )
        .bind(ws_uuid)
        .bind(uuid::Uuid::from_bytes(*committed.task.id.as_bytes()))
        .bind(run_uuid(&committed.runs[0].id))
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;

        let page = log
            .read(TaskEventLogRequest {
                workspace_id,
                task_id: Some(committed.task.id),
                cursor: None,
                page_size: 50,
            })
            .await?;
        let kinds: Vec<&str> = page.events.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"task.submitted"));
        assert!(kinds.contains(&"harness.session_started"));
        assert!(!kinds.contains(&"attempt_heartbeat"));
        // Newest-first ordering.
        let seqs: Vec<i64> = page.events.iter().map(|e| e.sequence).collect();
        assert!(seqs.windows(2).all(|w| w[0] > w[1]));

        // Keyset seek: a one-event page emits a cursor the next read
        // continues below.
        let page1 = log
            .read(TaskEventLogRequest {
                workspace_id,
                task_id: Some(committed.task.id),
                cursor: None,
                page_size: 1,
            })
            .await?;
        assert_eq!(page1.events.len(), 1);
        let cursor = page1.next_cursor.expect("full page emits a cursor");
        let page2 = log
            .read(TaskEventLogRequest {
                workspace_id,
                task_id: Some(committed.task.id),
                cursor: Some(cursor),
                page_size: 50,
            })
            .await?;
        assert!(
            page2
                .events
                .iter()
                .all(|e| e.sequence < page1.events[0].sequence)
        );
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

fn run_uuid(id: &RunId) -> uuid::Uuid {
    uuid::Uuid::from_bytes(*id.as_bytes())
}

// ---------------------------------------------------------------------------
// Milestone append
// ---------------------------------------------------------------------------

#[tokio::test]
async fn milestone_append_is_idempotent_and_deterministic() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "mile").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt.clone());
        let milestones = MilestoneStore::new(rt);
        let committed = submit_committed(&store, workspace_id, "milestones").await?;

        let milestone = Milestone {
            key: "run-started:1".to_owned(),
            kind: "harness.run_started".to_owned(),
            workspace_id,
            task_id: committed.task.id,
            run_id: committed.runs[0].id,
            attempt_id: None,
            status: "ok".to_owned(),
            reason: "ready".to_owned(),
            at: OffsetDateTime::now_utc(),
        };
        milestones.append(&milestone).await?;
        milestones.append(&milestone).await?; // duplicate key is a no-op

        let rows: Vec<(uuid::Uuid, String, String, Option<uuid::Uuid>)> = sqlx::query_as(
            "SELECT id, kind, producer_id, attempt_id FROM central.events \
             WHERE workspace_id = $1 AND kind = 'harness.run_started'",
        )
        .bind(ws_uuid)
        .fetch_all(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(rows.len(), 1);
        let (id, _kind, producer, attempt) = &rows[0];
        assert_eq!(*id, milestone_event_id("run-started:1"));
        assert_eq!(producer, MILESTONE_PRODUCER);
        assert_eq!(*attempt, None);

        // Incomplete milestones are rejected before touching the DB.
        let mut incomplete = milestone.clone();
        incomplete.kind = String::new();
        let err = milestones
            .append(&incomplete)
            .await
            .expect_err("incomplete milestone");
        assert_eq!(err.kind(), FailureKind::Invalid);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn task_commit_persists_scheduled_retry_null_run() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, "retry").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        let ws_uuid = uuid::Uuid::now_v7();
        insert_workspace(&mut mig, ws_uuid).await?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(ws_uuid.into_bytes());
        let rt = role_pool(&db, "central_runtime").await?;
        let store = Store::new(rt);
        let committed = submit_committed(&store, workspace_id, "retry").await?;

        // claim → schedule_run_retry marks the run failed and clears
        // current_run_id; the adapter must persist NULL (upstream's
        // `""` bind could not round-trip through `::uuid` —
        // Option<Uuid> writes NULL).
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let claim = domain::claim_current_run(domain::ClaimCurrentRunRequest {
            input,
            owner: "exec".to_owned(),
        })?;
        store
            .commit_task_change_set(commit_req(
                workspace_id,
                claim,
                "task.claim_current_run",
                None,
            ))
            .await?;
        let input = mutation(&store, workspace_id, committed.task.id, NOW).await?;
        let scheduled = domain::schedule_run_retry(domain::ScheduleRunRetryRequest {
            input,
            reason: Some(domain::WaitingReason::RetryDelay),
            retry_at: Some(NOW + Duration::seconds(60)),
            failure_note: "boom".to_owned(),
        })?;
        let cleared = store
            .commit_task_change_set(commit_req(
                workspace_id,
                scheduled,
                "task.schedule_run_retry",
                None,
            ))
            .await?;
        assert_eq!(cleared.task.current_run_id, None);
        let stored: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT current_run_id FROM central.tasks WHERE workspace_id = $1 AND id = $2",
        )
        .bind(ws_uuid)
        .bind(uuid::Uuid::from_bytes(*committed.task.id.as_bytes()))
        .fetch_one(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(stored, None);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}
