//! PostgreSQL integration tests for the b34 lineage stores
//! (`artifact/lineage_store.rs`) — the port of upstream
//! `lineage_store_test.go`: idempotent produce/read edge journaling,
//! attempt-scoped dedupe versus operator NULL-pair appends, the
//! reader-pair CHECK, `find_artifact`/`resolve_produced`, and the
//! `declared_scope` union of `artifact`-kind in-edges with
//! `input_artifact_refs`.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `artifact_store_integration.rs`. Fixture writes and assertion
//! reads run under `central_migration` (owner); every lineage store
//! call runs under `central_runtime`, which holds only
//! `SELECT, INSERT` on both append-only edge tables.

use central_adapter_postgres::artifact::Store;
use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_artifact::lineage::{ProduceEdge, ReadEdge};
use central_artifact::port::{LineageReader, ProduceEdgeStore, ReadEdgeStore, ReadStore};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, ProduceEdgeId, ReadEdgeId, RunId, SessionAttemptId, TaskId, WorkflowNodeId,
    WorkspaceId,
};
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
    let db = format!("artifact_lineage_test_{label}_{}", std::process::id());
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

/// `fixture` — one Workspace with a running Task/Run: every row the
/// lineage graph references (workflow nodes, artifacts, edges) hangs
/// off that chain.
struct Fixture {
    /// The store under `central_runtime` — the production role; it
    /// proves the append-only `SELECT, INSERT` grants suffice.
    store: Store,
    /// Owner connection for fixture writes.
    conn: PgConnection,

    ws: WorkspaceId,
    task: TaskId,
    run: RunId,
}

async fn setup_fixture(db: &str) -> Result<Fixture> {
    let runtime_pool = role_pool(db, "central_runtime").await?;
    let mut conn = role_conn(db, "central_migration").await?;

    let ws = WorkspaceId::new();
    let task_id = TaskId::new();
    let run_id = RunId::new();

    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', 'integration-test', 1000000000)",
    )
    .bind(uuid_of!(ws))
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'integration', '{}'::jsonb)",
    )
    .bind(uuid_of!(task_id))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(run_id))
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(run_id))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task_id))
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    Ok(Fixture {
        store: Store::new(runtime_pool),
        conn,
        ws,
        task: task_id,
        run: run_id,
    })
}

impl Fixture {
    /// `seedLineageNode` — one workflow node under the fixture's run.
    /// `input_refs` is the raw `input_artifact_refs` JSON document.
    /// The node id is a UUIDv4 — the same deliberately
    /// version-agnostic identity upstream seeds, exercised through
    /// `from_trusted_db_bytes`.
    async fn seed_lineage_node(
        &mut self,
        node_key: &str,
        input_refs: &str,
    ) -> Result<WorkflowNodeId> {
        let raw = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO central.workflow_nodes (\
             id, run_id, workspace_id, node_key, harness, workspace_kind, depth, \
             state, spec, input_artifact_refs) \
             VALUES ($1, $2, $3, $4, 'test-harness', 'worktree', 1, 'declared', \
             '{}'::jsonb, $5::jsonb)",
        )
        .bind(raw)
        .bind(uuid_of!(self.run))
        .bind(uuid_of!(self.ws))
        .bind(node_key)
        .bind(input_refs)
        .execute(&mut self.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        Ok(WorkflowNodeId::from_trusted_db_bytes(*raw.as_bytes()))
    }

    /// `seedLineageArtifact` — one ready artifact row under the
    /// fixture; the id is a UUIDv4 exactly as upstream's seed.
    async fn seed_lineage_artifact(&mut self, role: &str, checksum: &[u8]) -> Result<ArtifactId> {
        let raw = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO central.artifacts (\
             id, workspace_id, task_id, run_id, version, state, size, \
             staging_generation, object_key, sensitivity, disposition, \
             content_generation, ready_key, checksum_value, checksum_algorithm, \
             required_role) \
             VALUES ($1, $2, $3, $4, 3, 'ready', 16, \
             gen_random_uuid(), 'v1/lineage-legacy-key', 'restricted', 'attachment', \
             gen_random_uuid(), 'v1/ready/' || $1::text, $5, 'sha256', $6)",
        )
        .bind(raw)
        .bind(uuid_of!(self.ws))
        .bind(uuid_of!(self.task))
        .bind(uuid_of!(self.run))
        .bind(checksum)
        .bind(role)
        .execute(&mut self.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        Ok(ArtifactId::from_trusted_db_bytes(*raw.as_bytes()))
    }
}

/// A fresh produce edge identity — UUIDv4 journaled edge ids.
fn produce_edge_id() -> ProduceEdgeId {
    ProduceEdgeId::from_trusted_db_bytes(*uuid::Uuid::new_v4().as_bytes())
}

fn read_edge_id() -> ReadEdgeId {
    ReadEdgeId::from_trusted_db_bytes(*uuid::Uuid::new_v4().as_bytes())
}

fn session_attempt_id() -> SessionAttemptId {
    SessionAttemptId::from_trusted_db_bytes(*uuid::Uuid::new_v4().as_bytes())
}

// ---------------------------------------------------------------------------
// Produce edges (upstream TestLineageProduceEdgeInsertAndDedupe)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lineage_produce_edge_insert_and_dedupe() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "produce_edge").await?;
    let mut f = setup_fixture(&db).await?;

    let node = f.seed_lineage_node("producer", "[]").await?;
    let attempt = session_attempt_id();
    let artifact = f
        .seed_lineage_artifact("report", b"0123456789abcdef0123456789abcdef")
        .await?;

    let edge = f
        .store
        .insert_produce_edge(ProduceEdge {
            id: produce_edge_id(),
            run_id: f.run,
            node_id: node,
            attempt_id: attempt,
            artifact_id: artifact,
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;
    if edge.artifact_id != artifact || edge.node_id != node {
        return Err(Failure::internal(
            "test_assert",
            "journaled edge mismatched",
        ));
    }

    // Replayed materialization: same artifact, fresh edge id — the
    // unique(artifact_id) dedupe returns the journaled edge.
    let replayed = f
        .store
        .insert_produce_edge(ProduceEdge {
            id: produce_edge_id(),
            run_id: f.run,
            node_id: node,
            attempt_id: session_attempt_id(),
            artifact_id: artifact,
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;
    if replayed.id != edge.id || replayed.attempt_id != attempt {
        return Err(Failure::internal(
            "test_assert",
            "dedupe must return the journaled edge",
        ));
    }

    let got = f.store.produce_edge_for_artifact(artifact).await?;
    match got {
        Some(got) if got.id == edge.id => {}
        other => {
            return Err(Failure::internal(
                "test_assert",
                format!("produce_edge_for_artifact = {other:?}"),
            ));
        }
    }
    let missing = f
        .store
        .produce_edge_for_artifact(ArtifactId::from_trusted_db_bytes(
            *uuid::Uuid::new_v4().as_bytes(),
        ))
        .await?;
    if missing.is_some() {
        return Err(Failure::internal(
            "test_assert",
            "a missing artifact must report None",
        ));
    }

    let produced = f.store.produce_edges_for_node(node).await?;
    if produced.len() != 1 {
        return Err(Failure::internal(
            "test_assert",
            "produce_edges_for_node must return the one journaled edge",
        ));
    }
    let run_edges = f.store.produce_edges_for_run(f.run).await?;
    if run_edges.len() != 1 {
        return Err(Failure::internal(
            "test_assert",
            "produce_edges_for_run must return the one journaled edge",
        ));
    }
    let run_artifacts = f.store.run_produced_artifacts(f.run).await?;
    if run_artifacts != vec![artifact] {
        return Err(Failure::internal(
            "test_assert",
            "run_produced_artifacts must return the produced artifact id",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read edges (upstream TestLineageReadEdgeJournalsAndDedupes)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lineage_read_edge_journals_and_dedupes() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "read_edge").await?;
    let mut f = setup_fixture(&db).await?;

    let node = f.seed_lineage_node("reader", "[]").await?;
    let attempt = session_attempt_id();
    let artifact = f
        .seed_lineage_artifact("report", b"0123456789abcdef0123456789abcdef")
        .await?;

    let edge = f
        .store
        .insert_read_edge(ReadEdge {
            id: read_edge_id(),
            run_id: f.run,
            reader_node_id: Some(node),
            attempt_id: Some(attempt),
            artifact_id: artifact,
            declared: true,
            checksum: "deadbeef".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;
    if !edge.declared || edge.checksum != "deadbeef" {
        return Err(Failure::internal(
            "test_assert",
            "journaled edge mismatched",
        ));
    }

    // Retry after an ambiguous outcome: the attempt-scoped dedupe
    // returns the journaled edge rather than double-counting.
    let replayed = f
        .store
        .insert_read_edge(ReadEdge {
            id: read_edge_id(),
            run_id: f.run,
            reader_node_id: Some(node),
            attempt_id: Some(attempt),
            artifact_id: artifact,
            declared: true,
            checksum: "deadbeef".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;
    if replayed.id != edge.id {
        return Err(Failure::internal(
            "test_assert",
            "dedupe must return the journaled edge",
        ));
    }

    // A different attempt of the same node journals a second edge.
    f.store
        .insert_read_edge(ReadEdge {
            id: read_edge_id(),
            run_id: f.run,
            reader_node_id: Some(node),
            attempt_id: Some(session_attempt_id()),
            artifact_id: artifact,
            declared: false,
            checksum: "deadbeef".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;

    // Operator edges (the NULL pair) never dedupe.
    for _ in 0..2 {
        f.store
            .insert_read_edge(ReadEdge {
                id: read_edge_id(),
                run_id: f.run,
                reader_node_id: None,
                attempt_id: None,
                artifact_id: artifact,
                declared: false,
                checksum: "deadbeef".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await?;
    }

    let reads = f.store.read_edges_for_artifact(artifact).await?;
    if reads.len() != 4 {
        return Err(Failure::internal(
            "test_assert",
            format!("read_edges_for_artifact = {} edges, want 4", reads.len()),
        ));
    }
    let by_node = f.store.read_edges_for_node(node).await?;
    if by_node.len() != 2 {
        return Err(Failure::internal(
            "test_assert",
            format!("read_edges_for_node = {} edges, want 2", by_node.len()),
        ));
    }
    let by_run = f.store.read_edges_for_run(f.run).await?;
    if by_run.len() != 4 {
        return Err(Failure::internal(
            "test_assert",
            format!("read_edges_for_run = {} edges, want 4", by_run.len()),
        ));
    }

    // The NULL pair is all-or-nothing at the schema level too.
    let half_nil = f
        .store
        .insert_read_edge(ReadEdge {
            id: read_edge_id(),
            run_id: f.run,
            reader_node_id: Some(node),
            attempt_id: None,
            artifact_id: artifact,
            declared: false,
            checksum: "deadbeef".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await;
    if half_nil.is_ok() {
        return Err(Failure::internal(
            "test_assert",
            "a node-without-attempt edge must fail the reader-pair CHECK",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// find_artifact / resolve_produced (upstream
// TestLineageFindArtifactAndResolveProduced)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lineage_find_artifact_and_resolve_produced() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "find_artifact").await?;
    let mut f = setup_fixture(&db).await?;

    let checksum = b"0123456789abcdef0123456789abcdef"; // 32 bytes
    let node = f.seed_lineage_node("planner", "[]").await?;
    let artifact = f.seed_lineage_artifact("plan.md", checksum).await?;
    f.store
        .insert_produce_edge(ProduceEdge {
            id: produce_edge_id(),
            run_id: f.run,
            node_id: node,
            attempt_id: session_attempt_id(),
            artifact_id: artifact,
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;

    let found = f.store.find_artifact(artifact).await?;
    let Some(found) = found else {
        return Err(Failure::internal(
            "test_assert",
            "find_artifact must resolve the seeded artifact",
        ));
    };
    if found.state != central_artifact::domain::State::Ready || found.ready_key.is_empty() {
        return Err(Failure::internal(
            "test_assert",
            "lineage artifact must be ready with a ready key",
        ));
    }
    if found.checksum != "3031323334353637383961626364656630313233343536373839616263646566" {
        return Err(Failure::internal(
            "test_assert",
            "checksum must render as the bytea's hex form",
        ));
    }
    let missing = f
        .store
        .find_artifact(ArtifactId::from_trusted_db_bytes(
            *uuid::Uuid::new_v4().as_bytes(),
        ))
        .await?;
    if missing.is_some() {
        return Err(Failure::internal(
            "test_assert",
            "a missing artifact must report None",
        ));
    }

    // --from/--name resolves through the produce edge + node key + role.
    let matches = f
        .store
        .resolve_produced(Some(f.run), "planner", "plan.md")
        .await?;
    if matches.len() != 1 || matches[0].id != artifact {
        return Err(Failure::internal(
            "test_assert",
            "resolve_produced must return the produced artifact",
        ));
    }
    // Operator scope passes a nil run and still resolves.
    let matches = f.store.resolve_produced(None, "planner", "plan.md").await?;
    if matches.len() != 1 {
        return Err(Failure::internal(
            "test_assert",
            "operator-scope resolve_produced must still resolve",
        ));
    }
    let matches = f
        .store
        .resolve_produced(Some(f.run), "planner", "other.md")
        .await?;
    if !matches.is_empty() {
        return Err(Failure::internal(
            "test_assert",
            "a wrong name must resolve nothing",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// declared_scope (upstream TestLineageDeclaredScopeUnionsEdgesAndInputRefs)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lineage_declared_scope_unions_edges_and_input_refs() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "declared_scope").await?;
    let mut f = setup_fixture(&db).await?;

    // `input_artifact_refs` names an artifact that need not exist as a
    // row in this run's produce set (cross-run refs): the declared set
    // is the union of edge targets and ref ids.
    let ref_raw = uuid::Uuid::new_v4();
    let ref_artifact = ArtifactId::from_trusted_db_bytes(*ref_raw.as_bytes());
    let edge_artifact = f
        .seed_lineage_artifact("prior.txt", b"0123456789abcdef0123456789abcdef")
        .await?;
    let reader = f
        .seed_lineage_node("reader", &format!(r#"[{{"artifact_id": "{ref_raw}"}}]"#))
        .await?;
    let producer = f.seed_lineage_node("producer", "[]").await?;
    sqlx::query(
        "INSERT INTO central.workflow_edges \
         (id, run_id, dependent_node_id, prerequisite_node_id, kind, artifact_id) \
         VALUES ($1, $2, $3, $4, 'artifact', $5)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(uuid_of!(f.run))
    .bind(uuid_of!(reader))
    .bind(uuid_of!(producer))
    .bind(uuid_of!(edge_artifact))
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let scope = f.store.declared_scope(reader).await?;
    let mut found_edge = false;
    let mut found_ref = false;
    for id in &scope {
        if *id == edge_artifact {
            found_edge = true;
        }
        if *id == ref_artifact {
            found_ref = true;
        }
    }
    if !found_edge || !found_ref || scope.len() != 2 {
        return Err(Failure::internal(
            "test_assert",
            format!("scope = {scope:?}, want {{edge artifact, input ref}}"),
        ));
    }
    Ok(())
}
