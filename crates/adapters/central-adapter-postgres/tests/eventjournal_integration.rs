//! PostgreSQL integration tests for the b33/b37 canonical run journal
//! (`eventjournal/`): per-run `seq` allocation under the run-row
//! `FOR UPDATE` lock, `event_id` ingest dedupe, the `event_outbox` row
//! committed in the same transaction, `RunJournalRead` verbatim reads,
//! and the `DrainStore` claim/deliver/mark/GC surface
//! (`FOR UPDATE SKIP LOCKED`).
//!
//! Ports `internal/adapter/postgres/eventjournal/{store,outbox}_test.go`.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `execution_store_integration.rs`: a superuser DSN on a scratch
//! cluster whose `central_migration` / `central_runtime` roles exist.
//! Every test provisions its own database and installs the baseline
//! through [`BaselineInstaller::install`], so each test's outbox drain
//! sees only its own rows (upstream needed run filtering against a
//! shared database; per-test databases remove that hazard by
//! construction).
//!
//! Role discipline mirrors production: fixture inserts run under
//! `central_migration` (owner); every store call runs under
//! `central_runtime`, which is exactly what b33/b37 grant.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::eventjournal::Store;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_eventjournal::app::publisher::{DrainStore, EventDelivery, UnpublishedBacklog};
use central_eventjournal::domain::{EventKind, RunEvent, known};
use central_eventjournal::port::Writer;
use central_eventjournal::query::RunJournalRead;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    RunEventId, RunId, SessionAttemptId, TaskId, WorkflowNodeId, WorkspaceId,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

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
    let db = format!("eventjournal_test_{label}_{}", std::process::id());
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

/// `fixture` — one Workspace with a running Task/Run: the chain every
/// `run_events` row's foreign keys hang off.
struct Fixture {
    /// The store under `central_runtime` — the production role; proves
    /// the append-only `SELECT, INSERT` grants on `run_events` and the
    /// full `event_outbox` grants suffice.
    store: Store,
    /// Owner connection for fixture writes and assertions.
    conn: PgConnection,
    /// Runtime pool for raw tx composition (the `append_tx` tests).
    runtime_pool: PgPool,

    ws: WorkspaceId,
    task: TaskId,
    run: RunId,
}

async fn setup_fixture(db: &str) -> Result<Fixture> {
    let runtime_pool = role_pool(db, "central_runtime").await?;
    let mut conn = role_conn(db, "central_migration").await?;

    let ws = WorkspaceId::new();
    let task = TaskId::new();
    let run = RunId::new();

    for query in [
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', 'integration-test', 1073741824)",
        "INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)",
    ] {
        sqlx::query(query)
            .bind(uuid_of!(ws))
            .execute(&mut conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    }
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'integration', '{}'::jsonb)",
    )
    .bind(uuid_of!(task))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(run))
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(run))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task))
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    Ok(Fixture {
        store: Store::new(runtime_pool.clone()),
        conn,
        runtime_pool,
        ws,
        task,
        run,
    })
}

impl Fixture {
    /// `f.event(kind)` — a minimal envelope for the fixture's run.
    fn event(&self, kind: &str) -> RunEvent {
        RunEvent {
            id: RunEventId::new(),
            workspace_id: self.ws,
            run_id: self.run,
            seq: 0,
            node_id: None,
            attempt_id: None,
            kind: kind.to_string(),
            actor: "scheduler".to_string(),
            reason_code: None,
            payload: serde_json::json!({"schema_version": 1}),
            recorded_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// A second run in the same workspace, for interleaved drain order.
    async fn add_run(&mut self) -> Result<RunId> {
        let run2 = RunId::new();
        sqlx::query(
            "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
             VALUES ($1, $2, $3, 1, 'running', 2)",
        )
        .bind(uuid_of!(run2))
        .bind(uuid_of!(self.ws))
        .bind(uuid_of!(self.task))
        .execute(&mut self.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        Ok(run2)
    }

    async fn count(&mut self, sql_where: &str) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(sql_where)
            .bind(uuid_of!(self.run))
            .fetch_one(&mut self.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        Ok(row.0)
    }
}

/// The `drainCollect` callback — records delivered events in order.
struct Collect {
    seen: Vec<RunEvent>,
    fail_with: Option<Failure>,
}

impl EventDelivery for Collect {
    async fn deliver(&mut self, event: &RunEvent) -> std::result::Result<(), Failure> {
        if let Some(failure) = &self.fail_with {
            return Err(failure.clone());
        }
        self.seen.push(event.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// store_test.go ports
// ---------------------------------------------------------------------------

/// `TestAppendAssignsMonotonicPerRunSeq` — sequential appends to one run
/// receive seq 1, 2, … with no gaps (spec-6 OQ-1 allocation).
#[tokio::test]
async fn append_assigns_monotonic_per_run_seq() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "seq").await?;
    let fixture = setup_fixture(&db).await?;

    let seq1 = fixture
        .store
        .append(fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;
    let seq2 = fixture
        .store
        .append(fixture.event(EventKind::NodeReady.as_str()))
        .await?;
    assert_eq!((seq1, seq2), (1, 2), "per-run seq allocation");
    Ok(())
}

/// `TestAppendDuplicateEventIDReturnsExistingSeq` — a redelivered
/// `event_id` dedupes to the committed row's seq and writes no second
/// row (`DUPLICATE_EVENT_ID` semantics).
#[tokio::test]
async fn append_duplicate_event_id_returns_existing_seq() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "dupseq").await?;
    let mut fixture = setup_fixture(&db).await?;

    let ev = fixture.event(EventKind::NodeDeclared.as_str());
    let seq = fixture.store.append(ev.clone()).await?;
    let mut dup = fixture.event(EventKind::NodeCancelled.as_str());
    dup.id = ev.id;
    let dup_seq = fixture.store.append(dup).await?;
    assert_eq!(
        dup_seq, seq,
        "duplicate append must return the committed seq"
    );

    let row: (String,) = sqlx::query_as("SELECT kind FROM central.run_events WHERE id = $1")
        .bind(uuid_of!(ev.id))
        .fetch_one(&mut fixture.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let count = fixture
        .count("SELECT COUNT(*) FROM central.run_events WHERE run_id = $1")
        .await?;
    assert_eq!(row.0, EventKind::NodeDeclared.as_str());
    assert_eq!(count, 1, "deduped append must not insert a second row");
    Ok(())
}

/// `TestAppendUnknownRunFails` — the run-row lock fails closed: an
/// event for a run that does not exist cannot be journaled.
#[tokio::test]
async fn append_unknown_run_fails() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "norun").await?;
    let fixture = setup_fixture(&db).await?;

    let mut ev = fixture.event(EventKind::NodeDeclared.as_str());
    ev.run_id = RunId::new();
    let result = fixture.store.append(ev).await;
    assert!(result.is_err(), "append to an unknown run must fail");
    Ok(())
}

/// `TestAppendUnknownKindStoredVerbatim` — the store is dumb about
/// kinds: an undeclared kind is inserted raw; catalog membership is the
/// caller's check (`known`), not the writer's.
#[tokio::test]
async fn append_unknown_kind_stored_verbatim() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "alien").await?;
    let mut fixture = setup_fixture(&db).await?;

    let alien = "harness_mood_swing";
    assert!(!known(alien), "test premise: {alien} must not be cataloged");
    let seq = fixture.store.append(fixture.event(alien)).await?;
    let row: (String,) =
        sqlx::query_as("SELECT kind FROM central.run_events WHERE run_id = $1 AND seq = $2")
            .bind(uuid_of!(fixture.run))
            .bind(seq)
            .fetch_one(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.0, alien, "kind stored verbatim");
    Ok(())
}

/// `TestAppendTxSharesCallerTransaction` — the tx-scoped path a node
/// transition composes: two appends inside one caller transaction
/// allocate consecutive seqs and roll back together.
#[tokio::test]
async fn append_tx_shares_caller_transaction() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "txshare").await?;
    let mut fixture = setup_fixture(&db).await?;

    let mut tx = fixture
        .runtime_pool
        .begin()
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let seq1 = fixture
        .store
        .append_tx(&mut tx, &fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;
    let seq2 = fixture
        .store
        .append_tx(&mut tx, &fixture.event(EventKind::NodeReady.as_str()))
        .await?;
    assert_eq!((seq1, seq2), (1, 2));
    tx.rollback().await.map_err(|e| classify_sqlx(&e))?;

    let count = fixture
        .count("SELECT COUNT(*) FROM central.run_events WHERE run_id = $1")
        .await?;
    assert_eq!(count, 0, "rolled-back append must leave no rows");
    Ok(())
}

/// `TestAppendRecordedAtAndSubjects` — the nullable envelope fields
/// round-trip: `node_id`, `attempt_id`, `reason_code`, and
/// `recorded_at` land when set and stay NULL when absent.
#[tokio::test]
async fn append_recorded_at_and_subjects() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "subjects").await?;
    let mut fixture = setup_fixture(&db).await?;

    let node_id = WorkflowNodeId::new();
    sqlx::query(
        "INSERT INTO central.workflow_nodes \
         (id, run_id, workspace_id, node_key, harness, workspace_kind, depth, state, spec) \
         VALUES ($1, $2, $3, 'n1', 'claude-code', 'worktree', 0, 'declared', '{}'::jsonb)",
    )
    .bind(uuid_of!(node_id))
    .bind(uuid_of!(fixture.run))
    .bind(uuid_of!(fixture.ws))
    .execute(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let attempt_id = SessionAttemptId::new();
    let recorded = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000);

    let mut ev = fixture.event(EventKind::AttemptAmbiguous.as_str());
    ev.node_id = Some(node_id);
    ev.attempt_id = Some(attempt_id);
    ev.reason_code = Some("ATTEMPT_LOST".to_string());
    ev.recorded_at = recorded;
    let seq = fixture.store.append(ev).await?;

    let row: (
        Option<uuid::Uuid>,
        Option<uuid::Uuid>,
        Option<String>,
        OffsetDateTime,
    ) = sqlx::query_as(
        "SELECT node_id, attempt_id, reason_code, recorded_at \
             FROM central.run_events WHERE run_id = $1 AND seq = $2",
    )
    .bind(uuid_of!(fixture.run))
    .bind(seq)
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.0, Some(uuid_of!(node_id)));
    assert_eq!(row.1, Some(uuid_of!(attempt_id)));
    assert_eq!(row.2.as_deref(), Some("ATTEMPT_LOST"));
    // timestamptz stores to microsecond precision; the fixture value is
    // whole-second, so equality is exact.
    assert_eq!(row.3, recorded, "recorded_at must round-trip");

    let seq2 = fixture
        .store
        .append(fixture.event(EventKind::ChildSpecRejected.as_str()))
        .await?;
    let nulls: (Option<uuid::Uuid>, Option<uuid::Uuid>, Option<String>) = sqlx::query_as(
        "SELECT node_id, attempt_id, reason_code \
         FROM central.run_events WHERE run_id = $1 AND seq = $2",
    )
    .bind(uuid_of!(fixture.run))
    .bind(seq2)
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(nulls, (None, None, None), "absent subjects stay NULL");
    Ok(())
}

/// `TestAppendWritesOutboxRowInSameCommit` — every committed
/// `run_events` row has exactly one unpublished `event_outbox` twin
/// keyed `(run_id, seq)`.
#[tokio::test]
async fn append_writes_outbox_row_in_same_commit() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "outboxrow").await?;
    let mut fixture = setup_fixture(&db).await?;

    let ev = fixture.event(EventKind::NodeDeclared.as_str());
    let seq = fixture.store.append(ev.clone()).await?;

    let row: (uuid::Uuid, Option<OffsetDateTime>, i32) = sqlx::query_as(
        "SELECT event_id, published_at, publish_attempts \
         FROM central.event_outbox WHERE run_id = $1 AND seq = $2",
    )
    .bind(uuid_of!(fixture.run))
    .bind(seq)
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.0, uuid_of!(ev.id));
    assert_eq!((row.1, row.2), (None, 0), "fresh outbox row is unpublished");
    Ok(())
}

/// `TestAppendOutboxRowCountParity` — after N committed appends,
/// `run_events` and `event_outbox` hold exactly N rows for the run.
#[tokio::test]
async fn append_outbox_row_count_parity() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "parity").await?;
    let mut fixture = setup_fixture(&db).await?;

    for _ in 0..3 {
        fixture
            .store
            .append(fixture.event(EventKind::NodeDeclared.as_str()))
            .await?;
    }
    let events = fixture
        .count("SELECT COUNT(*) FROM central.run_events WHERE run_id = $1")
        .await?;
    let outbox = fixture
        .count("SELECT COUNT(*) FROM central.event_outbox WHERE run_id = $1")
        .await?;
    assert_eq!((events, outbox), (3, 3), "event/outbox parity broken");
    Ok(())
}

/// `TestAppendTxOutboxRollbackLeavesNothing` — the outbox row rolls
/// back with the journal row when the caller's transaction aborts.
#[tokio::test]
async fn append_tx_outbox_rollback_leaves_nothing() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "outboxrb").await?;
    let mut fixture = setup_fixture(&db).await?;

    let mut tx = fixture
        .runtime_pool
        .begin()
        .await
        .map_err(|e| classify_sqlx(&e))?;
    fixture
        .store
        .append_tx(&mut tx, &fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;
    tx.rollback().await.map_err(|e| classify_sqlx(&e))?;

    let outbox = fixture
        .count("SELECT COUNT(*) FROM central.event_outbox WHERE run_id = $1")
        .await?;
    assert_eq!(outbox, 0, "rolled-back append left outbox rows");
    Ok(())
}

/// `TestAppendDuplicateEventIDKeepsOneOutboxRow` — the id-conflict
/// re-read resolves the committed seq and the outbox insert dedupes on
/// it: a redelivery leaves exactly one `(run_id, seq)` row.
#[tokio::test]
async fn append_duplicate_event_id_keeps_one_outbox_row() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "dupoutbox").await?;
    let mut fixture = setup_fixture(&db).await?;

    let ev = fixture.event(EventKind::NodeDeclared.as_str());
    let seq = fixture.store.append(ev.clone()).await?;
    let mut dup = fixture.event(EventKind::NodeCancelled.as_str());
    dup.id = ev.id;
    let dup_seq = fixture.store.append(dup).await?;
    assert_eq!(dup_seq, seq);

    let rows: Vec<(i64, uuid::Uuid)> =
        sqlx::query_as("SELECT seq, event_id FROM central.event_outbox WHERE run_id = $1")
            .bind(uuid_of!(fixture.run))
            .fetch_all(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(rows, vec![(seq, uuid_of!(ev.id))]);
    Ok(())
}

/// `TestEventsForRunOrderedEnvelope` (upstream runview) — the verbatim
/// journal read returns committed events in `seq` order with the full
/// envelope intact.
#[tokio::test]
async fn events_for_run_returns_seq_order_envelope() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "readrun").await?;
    let fixture = setup_fixture(&db).await?;

    let first = fixture.event(EventKind::NodeDeclared.as_str());
    let second = fixture.event(EventKind::NodeReady.as_str());
    fixture.store.append(first.clone()).await?;
    fixture.store.append(second.clone()).await?;

    let events = fixture.store.events_for_run(fixture.run).await?;
    assert_eq!(events.len(), 2);
    assert_eq!((events[0].seq, events[1].seq), (1, 2));
    assert_eq!(events[0].id, first.id);
    assert_eq!(events[0].kind, EventKind::NodeDeclared.as_str());
    assert_eq!(events[1].id, second.id);
    assert_eq!(events[1].kind, EventKind::NodeReady.as_str());
    assert_eq!(events[0].workspace_id, fixture.ws);
    assert_eq!(events[0].actor, "scheduler");
    Ok(())
}

// ---------------------------------------------------------------------------
// outbox_test.go ports
// ---------------------------------------------------------------------------

/// `TestDrainPendingDeliversInRunSeqOrderAndMarksPublished` —
/// unpublished rows drain oldest-first per run, every delivered row is
/// stamped `published_at` with one `publish_attempt`, and a drained
/// row never comes back.
#[tokio::test]
async fn drain_pending_delivers_in_run_seq_order_and_marks_published() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "drainorder").await?;
    let mut fixture = setup_fixture(&db).await?;

    // A second run interleaves deliveries so the (run_id, seq) order is
    // observable rather than accidentally global-seq order.
    let run2 = fixture.add_run().await?;

    fixture
        .store
        .append(fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;
    let mut ev2 = fixture.event(EventKind::NodeReady.as_str());
    ev2.run_id = run2;
    fixture.store.append(ev2).await?;
    fixture
        .store
        .append(fixture.event(EventKind::AttemptStarted.as_str()))
        .await?;

    let mut collect = Collect {
        seen: Vec::new(),
        fail_with: None,
    };
    let delivered = fixture.store.drain_pending(200, &mut collect).await?;
    assert_eq!(delivered, 3);
    let seen = collect.seen;

    // (run_id, seq) ordering: run1's two events sort together by run id
    // when run1 < run2, or run2 lands first when its id is smaller.
    let want: Vec<(RunId, i64)> = if fixture.run < run2 {
        vec![(fixture.run, 1), (fixture.run, 2), (run2, 1)]
    } else {
        vec![(run2, 1), (fixture.run, 1), (fixture.run, 2)]
    };
    for (i, (run, seq)) in want.iter().enumerate() {
        let ev = &seen[i];
        assert_eq!(
            (&ev.run_id, ev.seq),
            (run, *seq),
            "delivery {i} must follow (run_id, seq) order"
        );
        assert!(!ev.kind.is_empty());
    }

    let row: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(publish_attempts),0) FROM central.event_outbox \
         WHERE run_id IN ($1, $2) AND published_at IS NOT NULL",
    )
    .bind(uuid_of!(fixture.run))
    .bind(uuid_of!(run2))
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row, (3, 3), "every delivered row marked with one attempt");

    // Published rows never come back.
    let mut again = Collect {
        seen: Vec::new(),
        fail_with: None,
    };
    let redelivered = fixture.store.drain_pending(200, &mut again).await?;
    assert_eq!(redelivered, 0, "published rows must not redeliver");
    assert!(again.seen.is_empty());
    Ok(())
}

/// `TestDrainPendingFailedConsumerLeavesUnpublished` — a consumer error
/// bumps `publish_attempts` but keeps `published_at` NULL, so the next
/// drain redelivers.
#[tokio::test]
async fn drain_pending_failed_consumer_leaves_unpublished() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "drainfail").await?;
    let mut fixture = setup_fixture(&db).await?;

    let ev = fixture.event(EventKind::NodeDeclared.as_str());
    fixture.store.append(ev.clone()).await?;

    let mut boom = Collect {
        seen: Vec::new(),
        fail_with: Some(Failure::internal("test_boom", "consumer exploded")),
    };
    let delivered = fixture.store.drain_pending(200, &mut boom).await?;
    assert_eq!(delivered, 0, "failed delivery marks nothing published");

    let row: (i32, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT publish_attempts, published_at FROM central.event_outbox WHERE run_id = $1",
    )
    .bind(uuid_of!(fixture.run))
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.0, 1, "the failed attempt is counted");
    assert_eq!(row.1, None, "failed delivery leaves published_at NULL");

    // A succeeding consumer now redelivers; every attempt is counted.
    let mut ok = Collect {
        seen: Vec::new(),
        fail_with: None,
    };
    let delivered = fixture.store.drain_pending(200, &mut ok).await?;
    assert_eq!(delivered, 1);
    assert_eq!(ok.seen[0].id, ev.id, "redelivery returns the same event");

    let row: (i32, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT publish_attempts, published_at FROM central.event_outbox WHERE run_id = $1",
    )
    .bind(uuid_of!(fixture.run))
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert!(row.0 >= 2 && row.1.is_some(), "redelivery marked published");
    Ok(())
}

/// `TestDrainPendingSkipsLockedRows` — `FOR UPDATE SKIP LOCKED`: a row
/// locked by another transaction is not claimed, so a second publisher
/// drains disjoint work instead of blocking.
#[tokio::test]
async fn drain_pending_skips_locked_rows() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "skiplocked").await?;
    let mut fixture = setup_fixture(&db).await?;

    fixture
        .store
        .append(fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;

    // A second runtime connection holds the row lock.
    let mut locker_conn = role_conn(&db, "central_runtime").await?;
    let mut locker = locker_conn.begin().await.map_err(|e| classify_sqlx(&e))?;
    let locked: Vec<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT run_id FROM central.event_outbox \
         WHERE run_id = $1 AND published_at IS NULL FOR UPDATE",
    )
    .bind(uuid_of!(fixture.run))
    .fetch_all(&mut *locker)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(locked.len(), 1, "locker holds the outbox row");

    // While the lock is held, the row must never be claimed.
    let mut collect = Collect {
        seen: Vec::new(),
        fail_with: None,
    };
    let delivered = fixture.store.drain_pending(200, &mut collect).await?;
    assert_eq!(delivered, 0, "locked rows are skipped, not delivered");
    let row: (i32, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT publish_attempts, published_at FROM central.event_outbox WHERE run_id = $1",
    )
    .bind(uuid_of!(fixture.run))
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row, (0, None), "locked row stays untouched");

    locker.rollback().await.map_err(|e| classify_sqlx(&e))?;
    let mut collect = Collect {
        seen: Vec::new(),
        fail_with: None,
    };
    let delivered = fixture.store.drain_pending(200, &mut collect).await?;
    assert_eq!(delivered, 1, "released row drains");
    Ok(())
}

/// `TestUnpublishedBacklogReportsDepthAndOldest` — the stall probe's
/// inputs: pending depth plus the oldest pending `created_at`.
#[tokio::test]
async fn unpublished_backlog_reports_depth_and_oldest() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "backlog").await?;
    let fixture = setup_fixture(&db).await?;

    let base = fixture.store.unpublished_backlog().await?;
    assert_eq!(
        base,
        UnpublishedBacklog {
            depth: 0,
            oldest: None
        }
    );

    fixture
        .store
        .append(fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;
    let append_at = OffsetDateTime::now_utc();
    fixture
        .store
        .append(fixture.event(EventKind::NodeReady.as_str()))
        .await?;

    let backlog = fixture.store.unpublished_backlog().await?;
    assert_eq!(backlog.depth, 2);
    let oldest = backlog
        .oldest
        .ok_or_else(|| Failure::internal("test", "oldest unset with pending rows"))?;
    assert!(
        oldest <= append_at,
        "oldest must not postdate the first append"
    );
    Ok(())
}

/// `TestCollectPublishedDeletesOnlyExpiredPublishedRows` — the OQ-3
/// retention sweep: published rows older than the cutoff go,
/// unpublished rows and freshly published rows stay.
#[tokio::test]
async fn collect_published_deletes_only_expired_published_rows() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "collect").await?;
    let mut fixture = setup_fixture(&db).await?;

    fixture
        .store
        .append(fixture.event(EventKind::NodeDeclared.as_str()))
        .await?;
    fixture
        .store
        .append(fixture.event(EventKind::NodeReady.as_str()))
        .await?;
    fixture
        .store
        .append(fixture.event(EventKind::AttemptStarted.as_str()))
        .await?;

    // Publish seq 1 and 2 directly, then age only seq 1 past the
    // cutoff — the test proves the collect boundary, not the drain.
    for sql in [
        "UPDATE central.event_outbox SET published_at = now(), publish_attempts = 1 \
         WHERE run_id = $1 AND seq IN (1, 2)",
        "UPDATE central.event_outbox SET published_at = clock_timestamp() - interval '8 days' \
         WHERE run_id = $1 AND seq = 1",
    ] {
        sqlx::query(sql)
            .bind(uuid_of!(fixture.run))
            .execute(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    }

    let cutoff = OffsetDateTime::now_utc() - Duration::days(7);
    let deleted = fixture.store.collect_published(cutoff).await?;
    assert_eq!(deleted, 1, "only the expired published row goes");

    let row: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE published_at IS NOT NULL), \
         COUNT(*) FILTER (WHERE published_at IS NULL) \
         FROM central.event_outbox WHERE run_id = $1",
    )
    .bind(uuid_of!(fixture.run))
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row, (1, 1), "one published and one pending survive");
    let gone = fixture
        .count("SELECT COUNT(*) FROM central.event_outbox WHERE run_id = $1 AND seq = 1")
        .await?;
    assert_eq!(gone, 0, "expired row deleted");
    Ok(())
}
