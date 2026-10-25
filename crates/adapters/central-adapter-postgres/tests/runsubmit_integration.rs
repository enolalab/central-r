//! PostgreSQL integration tests for the issue-#122 run-submission
//! saga (`runsubmit/`): one `Submit` composes the task submit +
//! `phase2` self-claim, the leader + flat-worker emits, and the ready
//! flip against real stores — the port of
//! `internal/runsubmit/live_test.go`.
//!
//! Upstream → port accounting:
//!
//! | upstream func | port |
//! |---|---|
//! | `TestLiveSubmitEndToEnd` | `live_submit_end_to_end` |
//! | `TestLiveKeyedReplayConverges` | `live_keyed_replay_converges` |
//! | `TestLiveKeyedMismatchConflicts` | `live_keyed_mismatch_conflicts` |
//! | `TestLiveKeylessDoubleSubmitMintsTwoRuns` | `live_keyless_double_submit_mints_two_runs` |
//! | `TestLiveSubmittedRunIsInvisibleToPhase1Dispatch` | `live_submitted_run_invisible_to_phase1_dispatch` |
//! | `TestLiveUnknownWorkspaceRefusal` | `live_unknown_workspace_refusal` |
//! | `TestLiveCancelPathPin` | `live_cancel_path_pin` |
//! | `TestLiveRuntimeRoleSubmit` | `live_runtime_role_submit` |
//!
//! Gated on `CENTRAL_TEST_DSN`. Fixture writes run under
//! `central_migration`; every store call runs under `central_runtime`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::str::FromStr;
use std::sync::Arc;

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::execution::Store as PgExecutionStore;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::task::{
    DetailStore as PgTaskDetailStore, ListStore as PgTaskListStore, Store as PgTaskStore,
};
use central_adapter_postgres::workflow::Store as PgWorkflowStore;
use central_execution::harness_run::ListDispatchableRunsRequest;
use central_execution::port::DispatchableRunReader;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::WorkspaceId;
use central_runsubmit::app::Service;
use central_runsubmit::domain::{
    self, LEADER_KEY, OWNER_PHASE2, SubmitRequest, codes as submit_codes,
};
use central_task::app::{CommandMeta, TaskService};
use central_task::domain::{MutationInput, RequestCancellationRequest, RunStatus, TaskStatus};
use central_task::port::AggregateLoader;
use central_workflow::domain::NodeStatus;
use central_workflow::port::WorkflowStore;
use sqlx::{Connection, PgConnection, PgPool};
use time::OffsetDateTime;

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

/// `id.as_bytes()` → `Uuid` — the adapter boundary conversion.
macro_rules! uuid_of {
    ($id:expr) => {
        uuid::Uuid::from_bytes(*$id.as_bytes())
    };
}

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
    let db = format!("runsubmit_test_{label}_{}", std::process::id());
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

/// `liveService` — the production composition: the task app service +
/// both task-store read seams + the workflow graph over one pool, with
/// the serve-parity claude-code-only harness seam.
fn live_service(
    pool: &PgPool,
) -> Service<
    TaskService<PgTaskStore, PgTaskListStore, PgTaskDetailStore>,
    PgTaskStore,
    PgTaskStore,
    PgWorkflowStore,
> {
    let tasks = PgTaskStore::new(pool.clone());
    let mut graph = PgWorkflowStore::new(pool.clone());
    graph.harness_registry = Some(Arc::new(|name: &str| name == domain::HARNESS_NAME));
    Service::new(
        TaskService::new(
            PgTaskStore::new(pool.clone()),
            PgTaskListStore::new(pool.clone()),
            PgTaskDetailStore::new(pool.clone()),
        ),
        tasks.clone(),
        tasks,
        graph,
    )
}

/// `liveWorkspace` — one `active` workspace row plus its event counter
/// (provisioning's shape), bound to a cleanup on test end.
async fn live_workspace(conn: &mut PgConnection, label: &str) -> Result<WorkspaceId> {
    let ws = WorkspaceId::new();
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', $2, 1073741824)",
    )
    .bind(uuid_of!(ws))
    .bind(format!("runsubmit-live-{label}"))
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)")
        .bind(uuid_of!(ws))
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(ws)
}

fn req(ws: WorkspaceId, title: &str, workers: i64, run_key: Option<&str>) -> SubmitRequest {
    SubmitRequest {
        workspace_id: ws,
        title: title.to_string(),
        workers,
        run_key: run_key.map(str::to_string),
        idempotency_key: None,
    }
}

/// `TestLiveSubmitEndToEnd` — a fresh submit commits the task running,
/// self-claims the run as `phase2`, and emits leader + N workers all
/// `ready`, parented to the leader, `claude-code`/`directory`.
#[tokio::test]
async fn live_submit_end_to_end() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "e2e").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let svc = live_service(&pool);
    let ws = live_workspace(&mut conn, "e2e").await?;

    let res = svc
        .submit(req(ws, "live-e2e", 2, Some("live-e2e-1")))
        .await?;
    assert!(!res.deduped, "res = {res:?}, want fresh");
    assert_eq!(res.nodes.len(), 3);
    for n in &res.nodes {
        assert_eq!(n.state, NodeStatus::Ready, "node {} not ready", n.node_key);
    }

    let tasks = PgTaskStore::new(pool.clone());
    let run = tasks.run_by_key(ws, "live-e2e-1").await?;
    assert_eq!(run.status, RunStatus::Running);
    assert_eq!(run.ownership_token, OWNER_PHASE2);
    let loaded = tasks.load_aggregate(ws, run.task_id).await?;
    assert_eq!(loaded.aggregate.task.status, TaskStatus::Running);

    let graph = PgWorkflowStore::new(pool);
    let nodes = graph.nodes_for_run(res.run_id).await?;
    let leader = nodes
        .iter()
        .find(|n| n.node_key == LEADER_KEY)
        .expect("leader node missing");
    for key in ["worker-1", "worker-2"] {
        let w = nodes
            .iter()
            .find(|n| n.node_key == key)
            .expect("worker node missing");
        assert_eq!(w.parent_id, Some(leader.id), "worker {key} lineage");
        assert_eq!(w.harness, domain::HARNESS_NAME);
        assert_eq!(w.workspace_kind, "directory");
    }
    Ok(())
}

/// `TestLiveKeyedReplayConverges` — the same `(workspace, run_key)`
/// plus the same request adopts the recorded run (`deduped`, same
/// `run_id`) and emits no second nodes.
#[tokio::test]
async fn live_keyed_replay_converges() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "replay").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let svc = live_service(&pool);
    let ws = live_workspace(&mut conn, "replay").await?;

    let first = svc
        .submit(req(ws, "replay", 2, Some("live-replay-1")))
        .await?;
    let second = svc
        .submit(req(ws, "replay", 2, Some("live-replay-1")))
        .await?;
    assert!(second.deduped, "replay = {second:?}, want deduped");
    assert_eq!(second.run_id, first.run_id);
    let graph = PgWorkflowStore::new(pool);
    let nodes = graph.nodes_for_run(first.run_id).await?;
    assert_eq!(nodes.len(), 3, "nodes after replay");
    Ok(())
}

/// `TestLiveKeyedMismatchConflicts` — a changed request under a
/// recorded `run_key` refuses `DUPLICATE_IDEMPOTENCY_KEY`; the
/// recorded row stands.
#[tokio::test]
async fn live_keyed_mismatch_conflicts() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "mismatch").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let svc = live_service(&pool);
    let ws = live_workspace(&mut conn, "mismatch").await?;

    svc.submit(req(ws, "original", 1, Some("live-mismatch-1")))
        .await?;
    let err = svc
        .submit(req(ws, "changed", 1, Some("live-mismatch-1")))
        .await
        .expect_err("mismatch must conflict");
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), submit_codes::DUPLICATE_IDEMPOTENCY_KEY);

    let tasks = PgTaskStore::new(pool);
    let run = tasks.run_by_key(ws, "live-mismatch-1").await?;
    let loaded = tasks.load_aggregate(ws, run.task_id).await?;
    assert_eq!(loaded.aggregate.task.title, "original");
    Ok(())
}

/// `TestLiveKeylessDoubleSubmitMintsTwoRuns` — no `run_key` means a
/// fresh run per call.
#[tokio::test]
async fn live_keyless_double_submit_mints_two_runs() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "keyless").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let svc = live_service(&pool);
    let ws = live_workspace(&mut conn, "keyless").await?;

    let a = svc.submit(req(ws, "a", 1, None)).await?;
    let b = svc.submit(req(ws, "a", 1, None)).await?;
    assert_ne!(a.run_id, b.run_id, "keyless submits share a run");
    Ok(())
}

/// `TestLiveSubmittedRunIsInvisibleToPhase1Dispatch` — the `phase2`
/// owner token excludes the submitted run from
/// `ListDispatchableRuns` case (a).
#[tokio::test]
async fn live_submitted_run_invisible_to_phase1_dispatch() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "dispatch").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let svc = live_service(&pool);
    let ws = live_workspace(&mut conn, "dispatch").await?;

    let res = svc
        .submit(req(ws, "dispatch-check", 1, Some("live-dispatch-1")))
        .await?;
    let exec = PgExecutionStore::new(pool);
    let listed = exec
        .list_dispatchable_runs(ListDispatchableRunsRequest {
            limit: 50,
            eligible_after: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;
    for d in &listed {
        assert_ne!(
            d.run_id, res.run_id,
            "submitted run listed dispatchable: {d:?}"
        );
        assert_ne!(d.task_id, res.task_id);
    }
    Ok(())
}

/// `TestLiveUnknownWorkspaceRefusal` — spec F3: no
/// workspace-existence pre-check; the first commit fails. The Rust
/// refusal is a classified store `Failure` (the adapter classifies
/// every sqlx error), so the pin is *not the domain's* vocabulary: no
/// request-validation or dup-key token escapes.
#[tokio::test]
async fn live_unknown_workspace_refusal() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "ghost").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let svc = live_service(&pool);
    let ghost = WorkspaceId::new();

    let err = svc
        .submit(req(ghost, "ghost", 1, Some("live-ghost-1")))
        .await
        .expect_err("ghost workspace accepted");
    assert_ne!(err.code(), submit_codes::REQUEST_VALIDATION);
    assert_ne!(err.code(), submit_codes::DUPLICATE_IDEMPOTENCY_KEY);
    Ok(())
}

/// `TestLiveCancelPathPin` — spec SR1: task-cancel of a
/// `phase2`-owned run is out of scope; this pins the CURRENT
/// cancel-path behavior — `request_cancellation` on a step-less
/// `phase2`-owned running run commits task+run to `cancelling` — and
/// fails on drift.
#[tokio::test]
async fn live_cancel_path_pin() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "cancelpin").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let svc = live_service(&pool);
    let ws = live_workspace(&mut conn, "cancelpin").await?;

    let res = svc
        .submit(req(ws, "cancel-pin", 1, Some("live-cancel-1")))
        .await?;
    let tasks = PgTaskStore::new(pool.clone());
    let run = tasks.run_by_key(ws, "live-cancel-1").await?;
    let loaded = tasks.load_aggregate(ws, run.task_id).await?;
    let task_svc = TaskService::new(
        PgTaskStore::new(pool.clone()),
        PgTaskListStore::new(pool.clone()),
        PgTaskDetailStore::new(pool.clone()),
    );
    let out = task_svc
        .request_cancellation(
            RequestCancellationRequest {
                input: MutationInput {
                    aggregate: loaded.aggregate.clone(),
                    expected_task_version: loaded.task_version,
                    expected_run_version: loaded
                        .run_version
                        .expect("current run carries a version"),
                    now: OffsetDateTime::now_utc(),
                },
            },
            CommandMeta {
                idempotency_key: Some("live-cancel-1".to_string()),
                ..CommandMeta::default()
            },
        )
        .await?;
    assert_eq!(
        out.task.status,
        TaskStatus::Cancelling,
        "SR1 drift: task status"
    );
    assert_eq!(out.runs.len(), 1);
    assert_eq!(out.runs[0].status, RunStatus::Cancelling);
    assert_eq!(out.runs[0].id, res.run_id);
    Ok(())
}

/// `TestLiveRuntimeRoleSubmit` — O3 grant proof: the full saga
/// commits as `central_runtime` (the production grant set), not just
/// as the migration owner.
#[tokio::test]
async fn live_runtime_role_submit() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "runtime").await?;
    // The workspace row is seeded over the migration conn
    // (provisioning owns workspaces); the submit itself runs as
    // runtime.
    let mut conn = role_conn(&db, "central_migration").await?;
    let ws = live_workspace(&mut conn, "runtime").await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let svc = live_service(&pool);

    let res = svc
        .submit(req(ws, "runtime-proof", 2, Some("live-runtime-1")))
        .await?;
    assert_eq!(res.nodes.len(), 3);
    assert_eq!(res.nodes[0].node_key, LEADER_KEY);
    Ok(())
}
