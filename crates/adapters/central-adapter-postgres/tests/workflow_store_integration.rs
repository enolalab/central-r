//! PostgreSQL integration tests for the b33 workflow graph store
//! (`workflow/`): atomic child-spec emission with spec-fingerprint
//! dedup, ordering/artifact edge derivation, expected-state transitions
//! with `ready_at` stamping, event-driven readiness recomputation, the
//! spec-1 cancel cascade, and the one-row-ever `attempt_decisions`
//! replay/verdict machinery — all under the run-row `FOR UPDATE`
//! serialization point.
//!
//! Ports `internal/adapter/postgres/workflow/store_test.go`.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `execution_store_integration.rs`. Every test provisions its own
//! database and installs the baseline through
//! [`BaselineInstaller::install`].
//!
//! Role discipline mirrors production: fixture inserts (artifacts,
//! produce edges, parked session attempts) run under
//! `central_migration` (owner); every store call runs under
//! `central_runtime` — the b33/b35/b37 grants cover the whole surface.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::workflow::Store;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ArtifactId, RunId, SessionAttemptId, TaskId, WorkflowNodeId, WorkspaceId,
};
use central_workflow::domain::{
    ArtifactRef, CHILD_SPEC_VERSION, ChildSpec, ChildSpecNode, EdgeKind, Node, NodeStatus,
    REASON_ATTEMPT_DECISION_CONFLICT, REASON_DUPLICATE_IDEMPOTENCY_KEY,
};
use central_workflow::port::WorkflowStore;
use central_workflow::readiness::{AmbiguousDecision, ambiguous_decision_known};
use central_workflow::validate::REASON_SPEC_VALIDATION_FAILED;
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use std::sync::Arc;

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
    let db = format!("workflow_test_{label}_{}", std::process::id());
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

/// `fixture` — one Workspace with a running Task/Run; the store rides
/// the `central_runtime` pool with every validation seam admitted
/// (upstream `launchableAll`/`finalizedAll` test doubles — the
/// artifact-edge gating test exercises the real SQL instead).
struct Fixture {
    store: Store,
    conn: PgConnection,
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

    let mut store = Store::new(runtime_pool);
    store.harness_registry = Some(Arc::new(|name: &str| !name.is_empty()));
    store.artifact_finalized = Some(Arc::new(|_: ArtifactId, _: &str| true));
    Ok(Fixture {
        store,
        conn,
        ws,
        task,
        run,
    })
}

fn spec(children: Vec<ChildSpecNode>) -> ChildSpec {
    ChildSpec {
        version: CHILD_SPEC_VERSION.to_string(),
        children,
    }
}

fn child(node_key: &str, depends_on: &[&str], workspace_kind: &str) -> ChildSpecNode {
    ChildSpecNode {
        node_key: node_key.to_string(),
        depends_on: depends_on.iter().map(|d| (*d).to_string()).collect(),
        harness: "claude-code".to_string(),
        workspace_kind: workspace_kind.to_string(),
        input_artifact_refs: Vec::new(),
        budget: None,
        on_terminal_failure: String::new(),
        node_timeout_seconds: None,
        session_timeout_seconds: None,
        max_attempts: Default::default(),
        max_attempts_total: None,
    }
}

fn node_by_key(nodes: &[Node], key: &str) -> Result<Node> {
    nodes
        .iter()
        .find(|n| n.node_key == key)
        .cloned()
        .ok_or_else(|| Failure::internal("test", format!("node {key} not found")))
}

async fn event_kinds(fixture: &mut Fixture) -> Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM central.run_events WHERE run_id = $1 ORDER BY seq")
            .bind(uuid_of!(fixture.run))
            .fetch_all(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

async fn count_kind(
    fixture: &mut Fixture,
    kind: &str,
    node: Option<WorkflowNodeId>,
) -> Result<i64> {
    let row: (i64,) = match node {
        Some(node_id) => sqlx::query_as(
            "SELECT COUNT(*) FROM central.run_events \
             WHERE run_id = $1 AND kind = $2 AND node_id = $3",
        )
        .bind(uuid_of!(fixture.run))
        .bind(kind)
        .bind(uuid_of!(node_id))
        .fetch_one(&mut fixture.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?,
        None => sqlx::query_as(
            "SELECT COUNT(*) FROM central.run_events WHERE run_id = $1 AND kind = $2",
        )
        .bind(uuid_of!(fixture.run))
        .bind(kind)
        .fetch_one(&mut fixture.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?,
    };
    Ok(row.0)
}

async fn node_state(fixture: &Fixture, id: WorkflowNodeId) -> Result<NodeStatus> {
    Ok(fixture.store.node(id).await?.state)
}

/// `drive` — walk a node through the legal path to a target state.
async fn drive(fixture: &Fixture, id: WorkflowNodeId, to: NodeStatus) -> Result<()> {
    let path: &[NodeStatus] = match to {
        NodeStatus::Ready => &[NodeStatus::Ready],
        NodeStatus::Running => &[
            NodeStatus::Ready,
            NodeStatus::Dispatched,
            NodeStatus::Running,
        ],
        NodeStatus::AttemptAmbiguous => &[
            NodeStatus::Ready,
            NodeStatus::Dispatched,
            NodeStatus::Running,
            NodeStatus::AttemptAmbiguous,
        ],
        NodeStatus::Succeeded => &[
            NodeStatus::Ready,
            NodeStatus::Dispatched,
            NodeStatus::Running,
            NodeStatus::Succeeded,
        ],
        _ => {
            return Err(Failure::internal(
                "test",
                format!("drive: no path to {to}"),
            ));
        }
    };
    for step in path {
        fixture
            .store
            .transition(id, *step, "scheduler", None)
            .await?;
    }
    Ok(())
}

fn assert_denied(failure: &Failure, what: &str) {
    assert_eq!(
        failure.kind(),
        FailureKind::Denied,
        "{what}: want DENIED, got {failure:?}"
    );
}

// ---------------------------------------------------------------------------
// EmitBatch
// ---------------------------------------------------------------------------

/// `TestEmitBatchCommitsNodesEdgesAndDeclaredEvents` — one transaction
/// admits the batch, the ordering edge, and one `node_declared`
/// journal row per node.
#[tokio::test]
async fn emit_batch_commits_nodes_edges_and_declared_events() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "emit").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("a", &[], "worktree"),
                child("b", &["a"], "directory"),
            ]),
        )
        .await?;
    assert!(
        result.rejected.is_none(),
        "batch rejected: {:?}",
        result.rejected
    );
    assert_eq!(result.nodes.len(), 2);

    let nodes = fixture.store.nodes_for_run(fixture.run).await?;
    assert_eq!(nodes.len(), 2);
    let (a, b) = (node_by_key(&nodes, "a")?, node_by_key(&nodes, "b")?);
    assert_eq!((a.depth, b.depth), (0, 1), "absolute depths");
    assert_eq!(a.state, NodeStatus::Declared);
    assert_eq!(b.state, NodeStatus::Declared);

    let edges = fixture.store.edges_for_run(fixture.run).await?;
    assert_eq!(edges.len(), 1);
    let edge = &edges[0];
    assert_eq!(edge.kind, EdgeKind::Ordering);
    assert_eq!(edge.dependent_node_id, b.id);
    assert_eq!(edge.prerequisite_node_id, a.id);
    assert_eq!(edge.artifact_id, None, "ordering edge carries no artifact");

    let kinds = event_kinds(&mut fixture).await?;
    assert_eq!(kinds, vec!["node_declared", "node_declared"]);
    let node_scoped = fixture.store_node_scoped_events().await?;
    assert_eq!(node_scoped, 2);
    Ok(())
}

impl Fixture {
    async fn store_node_scoped_events(&mut self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM central.run_events \
             WHERE run_id = $1 AND node_id IS NOT NULL",
        )
        .bind(uuid_of!(self.run))
        .fetch_one(&mut self.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        Ok(row.0)
    }
}

/// `TestEmitBatchCycleRejectsAtomically` — a cyclic batch leaves zero
/// partial nodes and journals exactly one `child_spec_rejected` naming
/// the offending keys.
#[tokio::test]
async fn emit_batch_cycle_rejects_atomically() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "cycle").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("a", &["b"], "worktree"),
                child("b", &["a"], "worktree"),
            ]),
        )
        .await?;
    let rejection = result
        .rejected
        .as_ref()
        .ok_or_else(|| Failure::internal("test", "cyclic batch accepted"))?;
    assert_eq!(rejection.reason_code, REASON_SPEC_VALIDATION_FAILED);
    assert!(!rejection.offending_keys.is_empty());
    assert!(result.nodes.is_empty());

    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM central.workflow_nodes WHERE run_id = $1")
            .bind(uuid_of!(fixture.run))
            .fetch_one(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.0, 0, "rejected batch left nodes");

    let kinds = event_kinds(&mut fixture).await?;
    assert_eq!(kinds, vec!["child_spec_rejected"]);
    let event: (Option<String>, serde_json::Value) =
        sqlx::query_as("SELECT reason_code, payload FROM central.run_events WHERE run_id = $1")
            .bind(uuid_of!(fixture.run))
            .fetch_one(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(
        event.0.as_deref(),
        Some(REASON_SPEC_VALIDATION_FAILED.as_str())
    );
    let offending = event.1["offending_keys"]
        .as_array()
        .ok_or_else(|| Failure::internal("test", "payload lacks offending_keys"))?;
    assert_eq!(offending.len(), 2, "payload names the two cycle members");
    Ok(())
}

/// `TestEmitBatchReemitDedupes` — `(run_id, node_key)` idempotency on
/// `spec_fingerprint`: an identical re-emission returns the existing
/// nodes and journals `command_deduped` per replayed key; a same-key
/// different-spec re-emission fails `DUPLICATE_IDEMPOTENCY_KEY` and the
/// recorded rows stand.
#[tokio::test]
async fn emit_batch_reemit_dedupes() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "reemit").await?;
    let mut fixture = setup_fixture(&db).await?;

    let batch = spec(vec![
        child("a", &[], "worktree"),
        child("b", &["a"], "directory"),
    ]);
    let first = fixture
        .store
        .emit_batch(fixture.run, None, batch.clone())
        .await?;
    let second = fixture.store.emit_batch(fixture.run, None, batch).await?;
    assert!(second.rejected.is_none(), "identical re-emission rejected");
    assert_eq!(second.nodes.len(), 2);
    for (i, node) in first.nodes.iter().enumerate() {
        assert_eq!(
            second.nodes[i].id, node.id,
            "deduped node[{i}] must resolve to the committed row"
        );
    }

    let node_count = count_nodes(&mut fixture).await?;
    assert_eq!(node_count, 2, "re-emission must not duplicate nodes");
    assert_eq!(
        count_kind(&mut fixture, "node_declared", None).await?,
        2,
        "no duplicate node_declared"
    );
    // One command_deduped per replayed key — the replay is observable.
    assert_eq!(count_kind(&mut fixture, "command_deduped", None).await?, 2);

    // Same key, different spec payload: the spec-5 verdict is a
    // DUPLICATE_IDEMPOTENCY_KEY conflict; the recorded rows stand.
    let err = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![ChildSpecNode {
                harness: "other-harness".to_string(),
                ..child("a", &[], "worktree")
            }]),
        )
        .await
        .expect_err("conflicting re-emit must fail");
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), REASON_DUPLICATE_IDEMPOTENCY_KEY);
    assert_eq!(count_nodes(&mut fixture).await?, 2);
    let row: (String,) = sqlx::query_as(
        "SELECT spec->>'harness' FROM central.workflow_nodes \
         WHERE run_id = $1 AND node_key = 'a'",
    )
    .bind(uuid_of!(fixture.run))
    .fetch_one(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(row.0, "claude-code", "recorded spec stands");
    Ok(())
}

async fn count_nodes(fixture: &mut Fixture) -> Result<i64> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM central.workflow_nodes WHERE run_id = $1")
            .bind(uuid_of!(fixture.run))
            .fetch_one(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    Ok(row.0)
}

// ---------------------------------------------------------------------------
// Transition
// ---------------------------------------------------------------------------

/// `TestTransitionCommitsStateAndEvent` — each legal transition writes
/// the new state and its cataloged journal kind in one commit.
#[tokio::test]
async fn transition_commits_state_and_event() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "transit").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(fixture.run, None, spec(vec![child("a", &[], "worktree")]))
        .await?;
    let node = &result.nodes[0];

    for (to, _) in [
        (NodeStatus::Ready, "node_ready"),
        (NodeStatus::Dispatched, "node_dispatched"),
        (NodeStatus::Running, "attempt_started"),
        (NodeStatus::Succeeded, "node_succeeded"),
    ] {
        fixture
            .store
            .transition(node.id, to, "scheduler", None)
            .await?;
        assert_eq!(node_state(&fixture, node.id).await?, to);
    }
    let kinds = event_kinds(&mut fixture).await?;
    assert_eq!(
        kinds,
        vec![
            "node_declared",
            "node_ready",
            "node_dispatched",
            "attempt_started",
            "node_succeeded"
        ]
    );
    // The ready transition stamped ready_at.
    let row: (Option<time::OffsetDateTime>,) =
        sqlx::query_as("SELECT ready_at FROM central.workflow_nodes WHERE id = $1")
            .bind(uuid_of!(node.id))
            .fetch_one(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert!(row.0.is_some(), "→ ready must stamp ready_at");
    Ok(())
}

/// `TestTransitionRejectsIllegal` — an off-machine transition fails
/// with a DENIED domain failure and leaves both state and journal
/// untouched.
#[tokio::test]
async fn transition_rejects_illegal() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "illegal").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(fixture.run, None, spec(vec![child("a", &[], "worktree")]))
        .await?;
    let node = &result.nodes[0];

    let err = fixture
        .store
        .transition(node.id, NodeStatus::Dispatched, "scheduler", None)
        .await
        .expect_err("declared -> dispatched must fail");
    assert_denied(&err, "declared -> dispatched");
    assert_eq!(node_state(&fixture, node.id).await?, NodeStatus::Declared);
    let kinds = event_kinds(&mut fixture).await?;
    assert_eq!(kinds, vec!["node_declared"]);
    Ok(())
}

// ---------------------------------------------------------------------------
// RecomputeReady
// ---------------------------------------------------------------------------

/// `TestRecomputeReadyFlipsOnlySatisfiedNodes` — readiness is derived:
/// declared nodes flip exactly when every ordering in-edge source has
/// succeeded; a `failed_terminal` prerequisite never admits its
/// dependent.
#[tokio::test]
async fn recompute_ready_flips_only_satisfied_nodes() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "ready").await?;
    let fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("a", &[], "worktree"),
                child("b", &["a"], "worktree"),
            ]),
        )
        .await?;
    let (a, b) = (result.nodes[0].id, result.nodes[1].id);

    let ready = fixture.store.recompute_ready(fixture.run).await?;
    assert_eq!(ready, vec![a], "only a is ready");
    assert_eq!(node_state(&fixture, b).await?, NodeStatus::Declared);

    for to in [
        NodeStatus::Dispatched,
        NodeStatus::Running,
        NodeStatus::Succeeded,
    ] {
        fixture.store.transition(a, to, "scheduler", None).await?;
    }
    let ready = fixture.store.recompute_ready(fixture.run).await?;
    assert_eq!(ready, vec![b]);

    // A dependent of a failed_terminal node never becomes ready.
    let child_result = fixture
        .store
        .emit_batch(
            fixture.run,
            Some(b),
            spec(vec![child("c", &["b"], "worktree")]),
        )
        .await?;
    assert!(child_result.rejected.is_none());
    let c = child_result.nodes[0].id;
    assert_eq!(child_result.nodes[0].depth, 2, "c depth = parent depth + 1");
    for to in [
        NodeStatus::Dispatched,
        NodeStatus::Running,
        NodeStatus::FailedTerminal,
    ] {
        fixture
            .store
            .transition(b, to, "scheduler", Some("ATTEMPT_LOST"))
            .await?;
    }
    let ready = fixture.store.recompute_ready(fixture.run).await?;
    assert!(ready.is_empty(), "no node ready under failed prerequisite");
    assert_eq!(node_state(&fixture, c).await?, NodeStatus::Declared);
    Ok(())
}

/// `TestRecomputeReadyArtifactEdgeGates` — an artifact in-edge blocks
/// readiness until the artifact row itself reaches `ready`, and emit
/// resolves the in-run producer as the edge's prerequisite.
#[tokio::test]
async fn recompute_ready_artifact_edge_gates() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "artgate").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![child("producer", &[], "worktree")]),
        )
        .await?;
    let producer = result.nodes[0].id;

    let artifact_id = ArtifactId::new();
    sqlx::query(
        "INSERT INTO central.artifacts \
         (id, workspace_id, task_id, run_id, state, staging_generation, object_key, \
          sensitivity, disposition, reconciliation_state) \
         VALUES ($1, $2, $3, $4, 'reserved', $5, $6, 'unrestricted', 'attachment', \
          'legacy_unverified')",
    )
    .bind(uuid_of!(artifact_id))
    .bind(uuid_of!(fixture.ws))
    .bind(uuid_of!(fixture.task))
    .bind(uuid_of!(fixture.run))
    .bind(uuid::Uuid::now_v7())
    .bind(format!("test/{artifact_id}"))
    .execute(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.artifact_produce_edges (id, run_id, node_id, attempt_id, artifact_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(fixture.run))
    .bind(uuid_of!(producer))
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(artifact_id))
    .execute(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let reader = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![ChildSpecNode {
                input_artifact_refs: vec![ArtifactRef {
                    artifact_id,
                    checksum: "deadbeef".to_string(),
                }],
                ..child("reader", &[], "directory")
            }]),
        )
        .await?;
    assert!(
        reader.rejected.is_none(),
        "reader rejected: {:?}",
        reader.rejected
    );
    let reader_node = reader.nodes[0].id;

    let edges = fixture.store.edges_for_run(fixture.run).await?;
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, EdgeKind::Artifact);
    assert_eq!(edges[0].dependent_node_id, reader_node);
    assert_eq!(edges[0].prerequisite_node_id, producer);
    assert_eq!(edges[0].artifact_id, Some(artifact_id));

    // The artifact is 'reserved': the reader stays declared even though
    // its producer already succeeded.
    for to in [
        NodeStatus::Ready,
        NodeStatus::Dispatched,
        NodeStatus::Running,
        NodeStatus::Succeeded,
    ] {
        fixture
            .store
            .transition(producer, to, "scheduler", None)
            .await?;
    }
    let ready = fixture.store.recompute_ready(fixture.run).await?;
    assert!(
        !ready.contains(&reader_node),
        "reader became ready while its artifact edge target is unfinalized"
    );
    assert_eq!(
        node_state(&fixture, reader_node).await?,
        NodeStatus::Declared
    );

    sqlx::query("UPDATE central.artifacts SET state = 'ready' WHERE id = $1")
        .bind(uuid_of!(artifact_id))
        .execute(&mut fixture.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let ready = fixture.store.recompute_ready(fixture.run).await?;
    assert_eq!(ready, vec![reader_node]);
    assert_eq!(node_state(&fixture, reader_node).await?, NodeStatus::Ready);
    Ok(())
}

// ---------------------------------------------------------------------------
// CancelNode — the spec-1 cascade
// ---------------------------------------------------------------------------

/// `TestCancelNodeCascadesAllNonTerminalDescendants` — cancelling a
/// ready root cancels its whole declared/ready subtree in one commit
/// and journals one `node_cancelled` per node.
#[tokio::test]
async fn cancel_node_cascades_all_non_terminal_descendants() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "cascade").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("a", &[], "worktree"),
                child("b", &["a"], "worktree"),
                child("c", &["b"], "worktree"),
            ]),
        )
        .await?;
    fixture.store.recompute_ready(fixture.run).await?;
    let affected = fixture
        .store
        .cancel_node(result.nodes[0].id, "operator:test")
        .await?;
    assert_eq!(affected.len(), 3);
    for node in &result.nodes {
        assert_eq!(
            node_state(&fixture, node.id).await?,
            NodeStatus::Cancelled,
            "{} must be cancelled",
            node.node_key
        );
        assert_eq!(
            count_kind(&mut fixture, "node_cancelled", Some(node.id)).await?,
            1
        );
    }
    Ok(())
}

/// `TestCancelNodeSignalsLiveDescendant` — a live node keeps its
/// state: the running descendant receives only a `cancel_requested`
/// intent while the ready root and the declared grandchild cancel.
#[tokio::test]
async fn cancel_node_signals_live_descendant() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "signal").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("root", &[], "worktree"),
                child("live", &["root"], "worktree"),
                child("leaf", &["live"], "worktree"),
            ]),
        )
        .await?;
    let (root, live, leaf) = (result.nodes[0].id, result.nodes[1].id, result.nodes[2].id);

    fixture.store.recompute_ready(fixture.run).await?;
    drive(&fixture, live, NodeStatus::Running).await?;

    let affected = fixture.store.cancel_node(root, "operator:test").await?;
    assert_eq!(affected.len(), 3, "root+live+leaf reached");
    assert_eq!(node_state(&fixture, root).await?, NodeStatus::Cancelled);
    assert_eq!(
        node_state(&fixture, live).await?,
        NodeStatus::Running,
        "live node keeps its state (signal only)"
    );
    assert_eq!(
        count_kind(&mut fixture, "cancel_requested", Some(live)).await?,
        1
    );
    assert_eq!(
        count_kind(&mut fixture, "node_cancelled", Some(live)).await?,
        0
    );
    assert_eq!(node_state(&fixture, leaf).await?, NodeStatus::Cancelled);
    Ok(())
}

/// `TestCancelNodeParksAmbiguousButCascadesDescendants` — the ambiguous
/// node itself is exempt (parked for the operator decision) while the
/// cascade flows through it to its non-terminal descendants: a ready
/// child (via a finalized artifact edge) and a declared child (via an
/// ordering edge) both cancel.
#[tokio::test]
async fn cancel_node_parks_ambiguous_but_cascades_descendants() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "parked").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(fixture.run, None, spec(vec![child("a", &[], "worktree")]))
        .await?;
    let a = result.nodes[0].id;

    let artifact_id = ArtifactId::new();
    sqlx::query(
        "INSERT INTO central.artifacts \
         (id, workspace_id, task_id, run_id, state, staging_generation, object_key, \
          sensitivity, disposition, reconciliation_state) \
         VALUES ($1, $2, $3, $4, 'ready', $5, $6, 'unrestricted', 'attachment', \
          'legacy_unverified')",
    )
    .bind(uuid_of!(artifact_id))
    .bind(uuid_of!(fixture.ws))
    .bind(uuid_of!(fixture.task))
    .bind(uuid_of!(fixture.run))
    .bind(uuid::Uuid::now_v7())
    .bind(format!("test/{artifact_id}"))
    .execute(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.artifact_produce_edges (id, run_id, node_id, attempt_id, artifact_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(fixture.run))
    .bind(uuid_of!(a))
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(artifact_id))
    .execute(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let children = fixture
        .store
        .emit_batch(
            fixture.run,
            Some(a),
            spec(vec![
                ChildSpecNode {
                    input_artifact_refs: vec![ArtifactRef {
                        artifact_id,
                        checksum: "deadbeef".to_string(),
                    }],
                    ..child("ready-child", &[], "directory")
                },
                child("ordering-child", &["a"], "worktree"),
            ]),
        )
        .await?;
    assert!(children.rejected.is_none());
    let ready_child = children.nodes[0].id;
    let ordering_child = children.nodes[1].id;

    drive(&fixture, a, NodeStatus::AttemptAmbiguous).await?;

    // An ambiguous prerequisite blocks ordering readiness but not
    // artifact readiness.
    let ready = fixture.store.recompute_ready(fixture.run).await?;
    assert_eq!(
        node_state(&fixture, ready_child).await?,
        NodeStatus::Ready,
        "artifact finalized → ready-child flips"
    );
    assert_eq!(
        node_state(&fixture, ordering_child).await?,
        NodeStatus::Declared,
        "ordering-child blocked under ambiguous prerequisite"
    );
    assert!(!ready.contains(&ordering_child));

    let affected = fixture.store.cancel_node(a, "operator:test").await?;
    assert_eq!(affected.len(), 3, "a+children reached");
    assert_eq!(
        node_state(&fixture, a).await?,
        NodeStatus::AttemptAmbiguous,
        "ambiguous node parks"
    );
    assert_eq!(
        count_kind(&mut fixture, "cancel_requested", Some(a)).await?,
        0
    );
    for id in [ready_child, ordering_child] {
        assert_eq!(
            node_state(&fixture, id).await?,
            NodeStatus::Cancelled,
            "descendant cancels through the parked node"
        );
    }
    Ok(())
}

/// `TestCancelNodeTerminalAndIdempotent` — a succeeded root refuses as
/// DENIED while re-cancelling a cancelled node is a replay success.
#[tokio::test]
async fn cancel_node_terminal_and_idempotent() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "terminal").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("a", &[], "worktree"),
                child("b", &[], "worktree"),
            ]),
        )
        .await?;
    let (a, b) = (result.nodes[0].id, result.nodes[1].id);

    drive(&fixture, a, NodeStatus::Succeeded).await?;
    let err = fixture
        .store
        .cancel_node(a, "operator:test")
        .await
        .expect_err("cancel of succeeded node must fail");
    assert_denied(&err, "cancel of succeeded");

    fixture.store.cancel_node(b, "operator:test").await?;
    assert_eq!(node_state(&fixture, b).await?, NodeStatus::Cancelled);
    let affected = fixture.store.cancel_node(b, "operator:test").await?;
    assert!(affected.is_empty(), "re-cancel is an idempotent replay");
    assert_eq!(
        count_kind(&mut fixture, "node_cancelled", Some(b)).await?,
        1,
        "re-cancel must not journal a second node_cancelled"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ResolveAmbiguous
// ---------------------------------------------------------------------------

/// `seedAmbiguousAttempt` — park one `session_attempts` row
/// (`'ambiguous'`) on the node: the row `resolve_ambiguous`'s
/// `attempt_decisions` key binds.
async fn seed_ambiguous_attempt(
    fixture: &mut Fixture,
    node: WorkflowNodeId,
) -> Result<SessionAttemptId> {
    let id = SessionAttemptId::new();
    sqlx::query(
        "INSERT INTO central.session_attempts \
         (id, workspace_id, run_id, node_id, attempt_seq, workspace_kind, state, \
          claimed_at, started_at) \
         VALUES ($1, $2, $3, $4, 1, 'directory', 'ambiguous', now(), now())",
    )
    .bind(uuid_of!(id))
    .bind(uuid_of!(fixture.ws))
    .bind(uuid_of!(fixture.run))
    .bind(uuid_of!(node))
    .execute(&mut fixture.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

/// `decisionFingerprint` — a deterministic 32-byte fingerprint for the
/// test's decision payloads; replays must carry the same bytes.
fn decision_fingerprint(tag: u8) -> [u8; 32] {
    [tag; 32]
}

/// `TestResolveAmbiguous` — the parked node's two operator exits:
/// `resume` journals the decision and leaves the node parked
/// (idempotent on replay, conflicting on a different decision or
/// fingerprint), while `rerun` journals the decision and returns the
/// node to ready. `attempt_decisions` is one-row-ever per parked
/// attempt.
#[tokio::test]
async fn resolve_ambiguous() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "resolve").await?;
    let mut fixture = setup_fixture(&db).await?;

    let result = fixture
        .store
        .emit_batch(
            fixture.run,
            None,
            spec(vec![
                child("a", &[], "worktree"),
                child("b", &["a"], "worktree"),
                child("c", &[], "worktree"),
            ]),
        )
        .await?;
    let (a, b, c) = (result.nodes[0].id, result.nodes[1].id, result.nodes[2].id);

    drive(&fixture, a, NodeStatus::AttemptAmbiguous).await?;
    seed_ambiguous_attempt(&mut fixture, a).await?;
    assert_eq!(node_state(&fixture, b).await?, NodeStatus::Declared);

    let fp_resume = decision_fingerprint(0x01);
    let fp_resume_alt = decision_fingerprint(0x02);
    let fp_rerun = decision_fingerprint(0x03);

    // A non-ambiguous node admits no decision.
    let err = fixture
        .store
        .resolve_ambiguous(
            b,
            AmbiguousDecision::Rerun.as_str(),
            fp_rerun,
            "operator:test",
        )
        .await
        .expect_err("resolve on declared node must fail");
    assert_denied(&err, "resolve on declared");

    // An unknown decision is INVALID.
    let err = fixture
        .store
        .resolve_ambiguous(a, "abandon", fp_resume, "operator:test")
        .await
        .expect_err("unknown decision must fail");
    assert_eq!(err.kind(), FailureKind::Invalid);
    assert!(!ambiguous_decision_known("abandon"));

    // resume: decision row + journal land, node stays parked.
    fixture
        .store
        .resolve_ambiguous(
            a,
            AmbiguousDecision::Resume.as_str(),
            fp_resume,
            "operator:test",
        )
        .await?;
    assert_eq!(node_state(&fixture, a).await?, NodeStatus::AttemptAmbiguous);
    assert_eq!(
        count_kind(&mut fixture, "attempt_decision", Some(a)).await?,
        1
    );
    let decision_rows = count_decisions(&mut fixture, a).await?;
    assert_eq!(decision_rows, 1, "one-row-ever decision row");

    // Replay of the recorded decision + fingerprint dedupes to
    // command_deduped: no second decision row, no second decision event.
    fixture
        .store
        .resolve_ambiguous(
            a,
            AmbiguousDecision::Resume.as_str(),
            fp_resume,
            "operator:test",
        )
        .await?;
    assert_eq!(
        count_kind(&mut fixture, "attempt_decision", Some(a)).await?,
        1
    );
    assert_eq!(
        count_kind(&mut fixture, "command_deduped", Some(a)).await?,
        1
    );
    assert_eq!(count_decisions(&mut fixture, a).await?, 1);

    // Same decision under a different fingerprint is the spec-5
    // DUPLICATE_IDEMPOTENCY_KEY verdict (DENIED); the row stands.
    let err = fixture
        .store
        .resolve_ambiguous(
            a,
            AmbiguousDecision::Resume.as_str(),
            fp_resume_alt,
            "operator:test",
        )
        .await
        .expect_err("fingerprint-conflicting decision must fail");
    assert_denied(&err, "fingerprint conflict");
    assert_eq!(err.code(), REASON_DUPLICATE_IDEMPOTENCY_KEY);

    // A conflicting decision on the recorded attempt is refused.
    let err = fixture
        .store
        .resolve_ambiguous(
            a,
            AmbiguousDecision::Rerun.as_str(),
            fp_rerun,
            "operator:test",
        )
        .await
        .expect_err("conflicting decision must fail");
    assert_denied(&err, "decision conflict");
    assert_eq!(err.code(), REASON_ATTEMPT_DECISION_CONFLICT);

    // rerun on a second ambiguous node: decision + node_ready.
    drive(&fixture, c, NodeStatus::AttemptAmbiguous).await?;
    seed_ambiguous_attempt(&mut fixture, c).await?;
    fixture
        .store
        .resolve_ambiguous(
            c,
            AmbiguousDecision::Rerun.as_str(),
            fp_rerun,
            "operator:test",
        )
        .await?;
    assert_eq!(node_state(&fixture, c).await?, NodeStatus::Ready);
    assert_eq!(
        count_kind(&mut fixture, "attempt_decision", Some(c)).await?,
        1
    );
    // c carries two node_ready events: the drive path's
    // declared -> ready on the way to running, and the rerun decision's
    // ambiguous -> ready.
    assert_eq!(count_kind(&mut fixture, "node_ready", Some(c)).await?, 2);

    // Once unblocked the node is no longer ambiguous.
    fixture
        .store
        .resolve_ambiguous(
            c,
            AmbiguousDecision::Rerun.as_str(),
            fp_rerun,
            "operator:test",
        )
        .await
        .expect_err("second resolve on ready node must fail");
    Ok(())
}

async fn count_decisions(fixture: &mut Fixture, node: WorkflowNodeId) -> Result<i64> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM central.attempt_decisions WHERE node_id = $1")
            .bind(uuid_of!(node))
            .fetch_one(&mut fixture.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    Ok(row.0)
}
