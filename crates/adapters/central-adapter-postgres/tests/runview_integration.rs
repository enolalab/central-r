//! PostgreSQL integration tests for `central-adapter-postgres/runview`
//! — the port of `internal/adapter/postgres/runview/store_test.go`:
//! the workspace-scoped census + keyset cursor, run/node scope
//! non-disclosure, graph edges, the journal projection, the attempt
//! ledger, the fleet projections (workers, live leases, deferred
//! admissions, outbox health), and the checkpoint anchors — all
//! against real stores.
//!
//! Gated on `CENTRAL_TEST_DSN`. Fixture writes run under
//! `central_migration`; every store call runs under `central_runtime`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::str::FromStr;

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::eventjournal::Store as PgJournal;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::runview::Store as PgRunview;
use central_eventjournal::domain::RunEvent;
use central_eventjournal::port::Writer;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    RunId, SessionAttemptId, TaskId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_runview::port::Reader;
use sqlx::{Connection, PgConnection, PgPool};
use time::OffsetDateTime;

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

macro_rules! uuid_of {
    ($id:expr) => {
        uuid::Uuid::from_bytes(*$id.as_bytes())
    };
}

fn admin_opts() -> Option<Opts> {
    Opts::from_str(&std::env::var("CENTRAL_TEST_DSN").ok()?).ok()
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

async fn role_pool(db: &str, role: &str) -> Result<PgPool> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgPool::connect_with(opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn provision(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = format!("runview_test_{label}_{}", std::process::id());
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
    let opts = require_opts()?.database(&db);
    let mut conn = PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    BaselineInstaller::new().install(&mut conn).await?;
    Ok(db)
}

/// The seeded workspace: two runs (one with a full graph + journal +
/// attempt + worker + lease + checkpoint, one bare), plus a second
/// workspace whose run the scoped projections must never disclose.
struct Fixture {
    store: PgRunview,
    journal: PgJournal,
    ws: WorkspaceId,
    ws2: WorkspaceId,
    task: TaskId,
    run: RunId,
    run2: RunId,
    foreign_run: RunId,
    node: WorkflowNodeId,
    node2: WorkflowNodeId,
    attempt: SessionAttemptId,
    worker: WorkerId,
}

async fn setup(db: &str) -> Result<Fixture> {
    let opts = require_opts()?.database(db);
    let mut mig = PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let runtime_pool = role_pool(db, "central_runtime").await?;
    let store = PgRunview::new(runtime_pool.clone());
    let journal = PgJournal::new(runtime_pool);

    let ws = WorkspaceId::new();
    let ws2 = WorkspaceId::new();
    let task = TaskId::new();
    let run = RunId::new();
    let run2 = RunId::new();
    let foreign_run = RunId::new();
    let node = WorkflowNodeId::new();
    let node2 = WorkflowNodeId::new();
    let attempt = SessionAttemptId::new();
    let worker = WorkerId::new();

    for w in [ws, ws2] {
        for q in [
            "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
             VALUES ($1, 'active', 'runview-test', 1073741824)",
            "INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)",
        ] {
            sqlx::query(q)
                .bind(uuid_of!(w))
                .execute(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))?;
        }
    }
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 2, 'runview', '{}'::jsonb)",
    )
    .bind(uuid_of!(task))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(run))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    // Run 2 is the older census row; run 1 the newer.
    for (r, idx, status) in [(run2, 1, "succeeded"), (run, 2, "running")] {
        sqlx::query(
            "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
             VALUES ($1, $2, $3, 1, $4, $5)",
        )
        .bind(uuid_of!(r))
        .bind(uuid_of!(ws))
        .bind(uuid_of!(task))
        .bind(status)
        .bind(idx)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    }
    // The foreign run (workspace two) — scoped reads must not see it.
    let foreign_task = TaskId::new();
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'foreign', '{}'::jsonb)",
    )
    .bind(uuid_of!(foreign_task))
    .bind(uuid_of!(ws2))
    .bind(uuid_of!(foreign_run))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(foreign_run))
    .bind(uuid_of!(ws2))
    .bind(uuid_of!(foreign_task))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    // Graph: node2 waits on node (ordering edge).
    for (n, key, state, parent) in [
        (node, "root-1", "running", None),
        (node2, "worker-1", "ready", Some(node)),
    ] {
        sqlx::query(
            "INSERT INTO central.workflow_nodes \
             (id, run_id, workspace_id, node_key, harness, workspace_kind, depth, state, spec, \
              max_attempts, parent_node_id) \
             VALUES ($1, $2, $3, $4, 'claude-code', 'worktree', 0, $5, '{}'::jsonb, 3, $6)",
        )
        .bind(uuid_of!(n))
        .bind(uuid_of!(run))
        .bind(uuid_of!(ws))
        .bind(key)
        .bind(state)
        .bind(parent.map(|p| uuid_of!(p)))
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    }
    sqlx::query(
        "INSERT INTO central.workflow_edges \
         (id, run_id, dependent_node_id, prerequisite_node_id, kind, artifact_id) \
         VALUES ($1, $2, $3, $4, 'ordering', NULL)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(run))
    .bind(uuid_of!(node2))
    .bind(uuid_of!(node))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    sqlx::query(
        "INSERT INTO central.session_attempts \
         (id, workspace_id, run_id, node_id, attempt_seq, workspace_kind, state, \
          claimed_at, started_at) \
         VALUES ($1, $2, $3, $4, 1, 'directory', 'started', now(), now())",
    )
    .bind(uuid_of!(attempt))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(run))
    .bind(uuid_of!(node))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    sqlx::query(
        "INSERT INTO central.worker_registrations \
         (id, workspace_id, protocol_version, harness_kinds, workspace_kinds, \
          max_concurrent_attempts, state, last_seen_at) \
         VALUES ($1, $2, 1, '{claude-code}', '{directory}', 4, 'active', now())",
    )
    .bind(uuid_of!(worker))
    .bind(uuid_of!(ws))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    sqlx::query(
        "INSERT INTO central.node_leases \
         (id, node_id, attempt_id, worker_id, issued_at, last_heartbeat_at, \
          expires_at, heartbeat_interval_seconds) \
         VALUES ($1, $2, $3, $4, now(), now(), now() + interval '5 minutes', 15)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(node))
    .bind(uuid_of!(attempt))
    .bind(uuid_of!(worker))
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    sqlx::query(
        "INSERT INTO central.resume_checkpoints \
         (checkpoint_id, workspace_id, run_id, node_id, attempt_id, \
          checkpoint_seq, format_version, graph_schema_version, \
          event_watermark, completed_nodes, finalized_artifacts, \
          in_flight_nodes, gc_class, content_digest, payload_fingerprint) \
         VALUES ($1, $2, $3, $4, $5, 1, 'central.checkpoint/v1', 'v1', 0, \
                 '{}'::text[], '{}'::uuid[], '{}'::text[], 'supersedeable', \
                 'digest', $6)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(ws))
    .bind(uuid_of!(run))
    .bind(uuid_of!(node))
    .bind(uuid_of!(attempt))
    .bind([7u8; 32])
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    Ok(Fixture {
        store,
        journal,
        ws,
        ws2,
        task,
        run,
        run2,
        foreign_run,
        node,
        node2,
        attempt,
        worker,
    })
}

impl Fixture {
    fn event(&self, node_id: Option<WorkflowNodeId>, kind: &str) -> RunEvent {
        RunEvent {
            id: central_foundation::identity::RunEventId::new(),
            workspace_id: self.ws,
            run_id: self.run,
            seq: 0,
            node_id,
            attempt_id: node_id.map(|_| self.attempt),
            kind: kind.to_string(),
            actor: "runview-test".to_string(),
            reason_code: None,
            payload: serde_json::json!({"schema_version": 1}),
            recorded_at: OffsetDateTime::now_utc(),
        }
    }
}

/// `TestRunviewCensusAndScope` — `list_runs` is the workspace census
/// (newest first, both runs incl. the zero-node one), the keyset
/// cursor pages without repeats, and `run_for_id`/`node_for_id`/`run_scope`
/// enforce the workspace boundary without disclosure.
#[tokio::test]
async fn live_census_keyset_and_scope() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "census").await?;
    let f = setup(&db).await?;

    // Census: newest run first; the zero-node run2 appears too.
    let page = f.store.list_runs(f.ws, None, 10).await?;
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].id, f.run);
    assert_eq!(page[1].id, f.run2);
    assert_eq!(page[0].task_id, f.task);
    assert_eq!(page[0].status, "running");
    // Node counts fold the materialized states.
    assert_eq!(page[0].node_counts.get("running"), Some(&1));
    assert_eq!(page[0].node_counts.get("ready"), Some(&1));
    assert!(page[1].node_counts.is_empty());

    // Keyset: page two starts strictly after the cursor row.
    let cursor = central_runview::domain::RunCursor {
        created_at: page[0].created_at,
        id: page[0].id,
    };
    let page2 = f.store.list_runs(f.ws, Some(cursor), 10).await?;
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, f.run2);

    // Cross-workspace census sees only its own run.
    let foreign = f.store.list_runs(f.ws2, None, 10).await?;
    assert_eq!(foreign.len(), 1);
    assert_eq!(foreign[0].id, f.foreign_run);

    // run_for_id: own run resolves; foreign and absent are the same
    // NotFound.
    assert_eq!(f.store.run_for_id(f.ws, f.run).await?.id, f.run);
    for id in [f.foreign_run, RunId::new()] {
        let err = f.store.run_for_id(f.ws, id).await.unwrap_err();
        assert_eq!(err.kind(), FailureKind::NotFound, "{id}");
    }

    // node_for_id carries the same scope.
    assert_eq!(f.store.node_for_id(f.ws, f.node).await?.key, "root-1");
    let err = f.store.node_for_id(f.ws2, f.node).await.unwrap_err();
    assert_eq!(err.kind(), FailureKind::NotFound);

    // run_scope answers the owning workspace, `None` when absent.
    assert_eq!(f.store.run_scope(f.run).await?, Some(f.ws));
    assert_eq!(f.store.run_scope(f.foreign_run).await?, Some(f.ws2));
    assert_eq!(f.store.run_scope(RunId::new()).await?, None);
    Ok(())
}

/// `TestRunviewGraphJournalAttempts` — the DAG projection carries
/// nodes + ordering edges, the journal projects in seq order, the
/// attempt ledger + materialized `nodes_current` agree with the
/// seeded rows.
#[tokio::test]
async fn live_graph_journal_attempts() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "graph").await?;
    let f = setup(&db).await?;

    // Journal two events through the real append path (seq-ordered,
    // also lands them in the outbox for `outbox_health`).
    let mut ev = f.event(Some(f.node), "node_dispatched");
    f.journal.append(ev.clone()).await?;
    ev = f.event(Some(f.node), "admission_deferred");
    ev.node_id = Some(f.node2);
    ev.attempt_id = None;
    ev.reason_code = Some("CAPACITY_ADMISSION_DEFERRED".to_string());
    f.journal.append(ev).await?;
    f.journal.append(f.event(None, "run_submitted")).await?;

    let graph = f.store.graph_for_run(f.run).await?;
    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.edges[0].from_key, "root-1");
    assert_eq!(graph.edges[0].to_key, "worker-1");
    assert_eq!(graph.edges[0].kind, "ordering");

    let events = f.store.events_for_run(f.run).await?;
    assert_eq!(events.len(), 3);
    assert!(events[0].seq < events[1].seq && events[1].seq < events[2].seq);
    assert_eq!(events[0].kind, "node_dispatched");
    assert_eq!(events[2].kind, "run_submitted");

    let attempts = f.store.attempts_for_node(f.node).await?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].id, f.attempt);
    assert_eq!(attempts[0].node_key, "root-1");
    assert_eq!(attempts[0].state, "started");

    let attempts_run = f.store.attempts_for_run(f.run).await?;
    assert_eq!(attempts_run.len(), 1);

    let current = f.store.nodes_current(f.run).await?;
    assert_eq!(current.get("root-1").map(String::as_str), Some("running"));
    assert_eq!(current.get("worker-1").map(String::as_str), Some("ready"));

    // Deferred admissions fold the journaled `admission_deferred` row.
    let deferred = f.store.deferred_admissions(f.run).await?;
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].node_key, "worker-1");
    assert_eq!(
        deferred[0].reason_code.as_deref(),
        Some("CAPACITY_ADMISSION_DEFERRED")
    );

    // Checkpoint anchors join the node key.
    let cps = f.store.checkpoints_for_run(f.run).await?;
    assert_eq!(cps.len(), 1);
    assert_eq!(cps[0].anchor_node_key, "root-1");
    assert_eq!(cps[0].gc_class, "supersedeable");
    Ok(())
}

/// `TestRunviewFleet` — the fleet projections: the registered worker
/// carries a server-measured beat age, the live lease joins node +
/// attempt coordinates, and `outbox_health` reflects the appended
/// unpublished rows.
#[tokio::test]
async fn live_fleet_projections() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "fleet").await?;
    let f = setup(&db).await?;
    f.journal.append(f.event(None, "run_submitted")).await?;

    let workers = f.store.workers(f.ws).await?;
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0].id, f.worker);
    assert_eq!(workers[0].state, "active");
    assert!(workers[0].beat_age_seconds.is_some());
    assert!(workers[0].last_seen_at.is_some());
    // The other workspace has no workers.
    assert!(f.store.workers(f.ws2).await?.is_empty());

    let leases = f.store.live_leases(f.ws).await?;
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].node_id, f.node);
    assert_eq!(leases[0].attempt_id, f.attempt);
    assert_eq!(leases[0].worker_id, f.worker);
    assert_eq!(leases[0].node_key, "root-1");
    assert!(leases[0].heartbeat_age_seconds >= 0);

    // One unpublished outbox row from the `append` above.
    let health = f.store.outbox_health().await?;
    assert!(health.unpublished_depth >= 1);
    assert!(health.oldest_unpublished.is_some());
    Ok(())
}
