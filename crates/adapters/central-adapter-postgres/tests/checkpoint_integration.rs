//! PostgreSQL integration tests for the Phase-2C checkpoint
//! orchestration surface — `checkpoint.rs`'s `ResumeStore` +
//! `CollectStore` implementations.
//!
//! These mirror upstream `internal/adapter/postgres/checkpoint/{store_test,gc_test}.go`:
//! quiescent-boundary writes, idempotent seq dedupe, token staleness,
//! the all-or-nothing preflight ladder, the subtree resume state
//! matrix, retention-class GC, pin/unpin, and listing/anchor
//! resolution.
//!
//! Gated on `CENTRAL_TEST_DSN` — a superuser DSN on a scratch cluster
//! whose `central_migration`/`central_runtime` roles exist (passwords
//! `<role>`), the same provisioning contract as `store_integration.rs`.
//! Every test provisions its own database owned by `central_migration`
//! and installs the baseline through [`BaselineInstaller::install`].
//!
//! Role discipline: fixture inserts run on the `central_migration`
//! connection; every port operation runs on the `central_runtime`
//! pool — proving the serving-role path is complete.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_checkpoint::domain::{
    GRAPH_SCHEMA_VERSION, GcClass, RESUME_FORMAT_VERSION, RUN_TERMINAL_RETENTION, ResumeCheckpoint,
    codes as checkpoint_codes,
};
use central_checkpoint::port::{CollectStore, Digester, ResumeStore};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ArtifactId, ResumeCheckpointId, RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
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
    let db = format!("ckpt_test_{label}_{}", std::process::id());
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

// ---------------------------------------------------------------------------
// FakeDigester — the injected workspace-digest seam (upstream
// `fakeDigester`): records calls and returns a canned digest or error.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeDigesterState {
    digest: String,
    err: Option<String>,
    calls: usize,
    last_path: Option<String>,
    last_kind: Option<String>,
}

struct FakeDigester {
    state: Mutex<FakeDigesterState>,
}

impl FakeDigester {
    fn new(digest: &str) -> Self {
        Self {
            state: Mutex::new(FakeDigesterState {
                digest: digest.to_owned(),
                ..Default::default()
            }),
        }
    }

    fn set_digest(&self, digest: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest = digest.to_owned();
    }

    fn set_err(&self, err: Option<&str>) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .err = err.map(str::to_owned);
    }

    fn calls(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .calls
    }

    fn last(&self) -> (Option<String>, Option<String>) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.last_path.clone(), state.last_kind.clone())
    }
}

impl Digester for FakeDigester {
    fn digest<'a>(
        &'a self,
        path: &'a str,
        kind: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.calls += 1;
            state.last_path = Some(path.to_owned());
            state.last_kind = Some(kind.to_owned());
            if let Some(err) = &state.err {
                return Err(Failure::internal("digester_error", err.clone()));
            }
            Ok(state.digest.clone())
        })
    }
}

// ---------------------------------------------------------------------------
// Fixture — one workspace + task + run per test (upstream `fixture`).
// ---------------------------------------------------------------------------

struct Fixture {
    store: central_adapter_postgres::checkpoint::Store,
    mig: PgConnection,
    digester: Arc<FakeDigester>,
    ws: uuid::Uuid,
    task: uuid::Uuid,
    run: uuid::Uuid,
    run_id: RunId,
}

/// Provisions an isolated database and the fixture run; returns the
/// admin connection (kept alive for teardown) plus the fixture.
/// `None` means `CENTRAL_TEST_DSN` is unset — the caller skipped.
async fn fixture(label: &str) -> Result<Option<(PgConnection, Fixture)>> {
    if admin_opts().is_none() {
        return Ok(None);
    }
    let mut admin = admin_conn().await?;
    let db = migrated_db(&mut admin, label).await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    let ws = uuid::Uuid::now_v7();
    let task = uuid::Uuid::now_v7();
    let run = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', 'ckpt-test', $2)",
    )
    .bind(ws)
    .bind(1_i64 << 30)
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, status, title, input_spec) \
         VALUES ($1, $2, 'running', 'ckpt test', '{}'::jsonb)",
    )
    .bind(task)
    .bind(ws)
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, status, run_index) \
         VALUES ($1, $2, $3, 'running', 1)",
    )
    .bind(run)
    .bind(ws)
    .bind(task)
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let pool = role_pool(&db, "central_runtime").await?;
    let digester = Arc::new(FakeDigester::new("sha256:workspace"));
    let store = central_adapter_postgres::checkpoint::Store::with_digester(pool, digester.clone());
    Ok(Some((
        admin,
        Fixture {
            store,
            mig,
            digester,
            ws,
            task,
            run,
            run_id: RunId::from_trusted_db_bytes(run.into_bytes()),
        },
    )))
}

impl Fixture {
    fn node(&self, id: uuid::Uuid) -> WorkflowNodeId {
        WorkflowNodeId::from_trusted_db_bytes(id.into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Seed helpers — administrative inserts on the migration connection
// (dynamic SQL with bound values, the same allowance the store suite
// uses).
// ---------------------------------------------------------------------------

async fn seed_node(
    f: &mut Fixture,
    key: &str,
    parent: Option<uuid::Uuid>,
    state: &str,
    depth: i32,
) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.workflow_nodes \
         (id, run_id, workspace_id, node_key, parent_node_id, harness, \
          workspace_kind, depth, state, spec, ready_at) \
         VALUES ($1, $2, $3, $4, $5, 'claude-code', 'directory', $6, $7, '{}'::jsonb, \
                 CASE WHEN $7 = 'ready' THEN now() ELSE NULL END)",
    )
    .bind(id)
    .bind(f.run)
    .bind(f.ws)
    .bind(key)
    .bind(parent)
    .bind(depth)
    .bind(state)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

async fn seed_attempt(
    f: &mut Fixture,
    node: uuid::Uuid,
    seq: i32,
    state: &str,
    ws_path: Option<&str>,
    session_id: Option<&str>,
) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.session_attempts \
         (id, workspace_id, run_id, node_id, attempt_seq, workspace_kind, \
          workspace_path, harness_session_id, state, claimed_at, started_at) \
         VALUES ($1, $2, $3, $4, $5, 'directory', $6, $7, $8, now(), \
                 CASE WHEN $8 IN ('started','succeeded','failed','ambiguous') \
                      THEN now() ELSE NULL END)",
    )
    .bind(id)
    .bind(f.ws)
    .bind(f.run)
    .bind(node)
    .bind(seq)
    .bind(ws_path)
    .bind(session_id)
    .bind(state)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

async fn seed_worker(f: &mut Fixture) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.worker_registrations \
         (id, workspace_id, protocol_version, harness_kinds, workspace_kinds, \
          max_concurrent_attempts, state) \
         VALUES ($1, $2, 1, '{claude-code}', '{directory}', 4, 'active')",
    )
    .bind(id)
    .bind(f.ws)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

async fn seed_lease(
    f: &mut Fixture,
    node: uuid::Uuid,
    attempt: uuid::Uuid,
    worker: uuid::Uuid,
) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.node_leases \
         (id, node_id, attempt_id, worker_id, issued_at, last_heartbeat_at, \
          expires_at, heartbeat_interval_seconds) \
         VALUES ($1, $2, $3, $4, now(), now(), now() + interval '5 minutes', 30)",
    )
    .bind(id)
    .bind(node)
    .bind(attempt)
    .bind(worker)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

async fn seed_ordering_edge(
    f: &mut Fixture,
    dependent: uuid::Uuid,
    prerequisite: uuid::Uuid,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO central.workflow_edges \
         (id, run_id, dependent_node_id, prerequisite_node_id, kind, artifact_id) \
         VALUES ($1, $2, $3, $4, 'ordering', NULL)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(f.run)
    .bind(dependent)
    .bind(prerequisite)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

async fn seed_artifact_edge(
    f: &mut Fixture,
    dependent: uuid::Uuid,
    prerequisite: uuid::Uuid,
    artifact: uuid::Uuid,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO central.workflow_edges \
         (id, run_id, dependent_node_id, prerequisite_node_id, kind, artifact_id) \
         VALUES ($1, $2, $3, $4, 'artifact', $5)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(f.run)
    .bind(dependent)
    .bind(prerequisite)
    .bind(artifact)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

async fn seed_artifact(f: &mut Fixture, state: &str) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::now_v7();
    // `reconciliation_state = 'legacy_unverified'` exempts the 'ready'
    // state from b10's ready-requires-metadata check — the same
    // sentinel upstream's fixture uses.
    sqlx::query(
        "INSERT INTO central.artifacts \
         (id, workspace_id, task_id, run_id, state, staging_generation, \
          object_key, staging_key, sensitivity, disposition, reconciliation_state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'unrestricted', 'attachment', \
                 'legacy_unverified')",
    )
    .bind(id)
    .bind(f.ws)
    .bind(f.task)
    .bind(f.run)
    .bind(state)
    .bind(uuid::Uuid::now_v7())
    .bind(format!("test/{id}"))
    .bind(format!("staging-{id}"))
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

async fn seed_produce_edge(
    f: &mut Fixture,
    node: uuid::Uuid,
    attempt: uuid::Uuid,
    artifact: uuid::Uuid,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO central.artifact_produce_edges \
         (id, run_id, node_id, attempt_id, artifact_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(f.run)
    .bind(node)
    .bind(attempt)
    .bind(artifact)
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// A `resume_checkpoints` row seeded directly — upstream
/// `writeCheckpointRow`: injects records `write_checkpoint` would
/// never produce (expired, incompatible versions, missing artifacts).
/// `checkpoint_seq` auto-assigns the next free coordinate on the
/// attempt when unset.
struct CkptSeed {
    node: uuid::Uuid,
    attempt: uuid::Uuid,
    format: String,
    schema: String,
    gc_class: GcClass,
    expires_at: Option<OffsetDateTime>,
    workspace_digest: Option<String>,
    workspace_path: Option<String>,
    completed: Vec<String>,
    artifacts: Vec<uuid::Uuid>,
    in_flight: Vec<String>,
}

impl CkptSeed {
    fn new(node: uuid::Uuid, attempt: uuid::Uuid) -> Self {
        Self {
            node,
            attempt,
            format: RESUME_FORMAT_VERSION.to_owned(),
            schema: GRAPH_SCHEMA_VERSION.to_owned(),
            gc_class: GcClass::Supersedeable,
            expires_at: None,
            workspace_digest: None,
            workspace_path: None,
            completed: Vec::new(),
            artifacts: Vec::new(),
            in_flight: Vec::new(),
        }
    }
}

async fn write_checkpoint_row(f: &mut Fixture, seed: CkptSeed) -> Result<ResumeCheckpoint> {
    let next_seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(checkpoint_seq), 0) + 1 FROM central.resume_checkpoints \
         WHERE attempt_id = $1",
    )
    .bind(seed.attempt)
    .fetch_one(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let mut record = ResumeCheckpoint {
        id: ResumeCheckpointId::new(),
        workspace_id: WorkspaceId::from_trusted_db_bytes(f.ws.into_bytes()),
        run_id: f.run_id,
        node_id: f.node(seed.node),
        attempt_id: SessionAttemptId::from_trusted_db_bytes(seed.attempt.into_bytes()),
        checkpoint_seq: next_seq,
        format_version: seed.format,
        graph_schema_version: seed.schema,
        event_watermark: 0,
        harness_session_id: None,
        workspace_digest: seed.workspace_digest,
        workspace_path: seed.workspace_path,
        completed_nodes: seed.completed,
        finalized_artifacts: seed
            .artifacts
            .iter()
            .map(|u| ArtifactId::from_trusted_db_bytes(u.into_bytes()))
            .collect(),
        in_flight_nodes: seed.in_flight,
        gc_class: seed.gc_class,
        created_at: OffsetDateTime::now_utc(),
        expires_at: seed.expires_at,
        content_digest: String::new(),
    };
    record.content_digest = record.digest();
    let fingerprint = record.fingerprint();
    let artifact_ids = seed.artifacts;

    sqlx::query(
        "INSERT INTO central.resume_checkpoints \
         (checkpoint_id, workspace_id, run_id, node_id, attempt_id, \
          checkpoint_seq, format_version, graph_schema_version, \
          event_watermark, harness_session_id, workspace_digest, \
          workspace_path, completed_nodes, finalized_artifacts, \
          in_flight_nodes, gc_class, expires_at, content_digest, \
          payload_fingerprint) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10, $11, \
                 $12::text[], $13::uuid[], $14::text[], $15, $16, $17, $18)",
    )
    .bind(uuid_of(record.id.as_bytes()))
    .bind(f.ws)
    .bind(f.run)
    .bind(seed.node)
    .bind(seed.attempt)
    .bind(next_seq)
    .bind(&record.format_version)
    .bind(&record.graph_schema_version)
    .bind(record.event_watermark)
    .bind(&record.workspace_digest)
    .bind(&record.workspace_path)
    .bind(&record.completed_nodes)
    .bind(&artifact_ids[..])
    .bind(&record.in_flight_nodes)
    .bind(record.gc_class.as_str())
    .bind(record.expires_at)
    .bind(&record.content_digest)
    .bind(&fingerprint[..])
    .execute(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(record)
}

async fn set_checkpoint_created_at(
    f: &mut Fixture,
    id: ResumeCheckpointId,
    at: OffsetDateTime,
) -> Result<()> {
    sqlx::query("UPDATE central.resume_checkpoints SET created_at = $2 WHERE checkpoint_id = $1")
        .bind(uuid_of(id.as_bytes()))
        .bind(at)
        .execute(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Assertion helpers — journal and state probes.
// ---------------------------------------------------------------------------

async fn node_states_snapshot(f: &mut Fixture) -> Result<HashMap<String, String>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT node_key, state FROM central.workflow_nodes WHERE run_id = $1",
    )
    .bind(f.run)
    .fetch_all(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(rows.into_iter().collect())
}

async fn count_events(f: &mut Fixture, kind: &str) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM central.run_events WHERE run_id = $1 AND kind = $2")
        .bind(f.run)
        .bind(kind)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn last_event_reason(f: &mut Fixture, kind: &str) -> Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT reason_code FROM central.run_events \
         WHERE run_id = $1 AND kind = $2 ORDER BY seq DESC LIMIT 1",
    )
    .bind(f.run)
    .bind(kind)
    .fetch_one(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))
}

async fn count_checkpoints(f: &mut Fixture) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM central.resume_checkpoints WHERE run_id = $1")
        .bind(f.run)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn checkpoint_exists(f: &mut Fixture, id: ResumeCheckpointId) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM central.resume_checkpoints WHERE checkpoint_id = $1)",
    )
    .bind(uuid_of(id.as_bytes()))
    .fetch_one(&mut f.mig)
    .await
    .map_err(|e| classify_sqlx(&e))
}

fn require_failure(err: &Failure, kind: FailureKind, code: &str) {
    assert_eq!(err.kind(), kind, "failure kind for {code}");
    assert_eq!(err.code(), code);
}

fn uuid_of(id: &[u8; 16]) -> uuid::Uuid {
    uuid::Uuid::from_bytes(*id)
}

// ---------------------------------------------------------------------------
// WriteCheckpoint — the quiescent-boundary write path (upstream T4)
// ---------------------------------------------------------------------------

/// A checkpoint requested while the anchor attempt is in its
/// claim-to-outcome window refuses CHECKPOINT_BOUNDARY_ILLEGAL: the
/// refusal journals checkpoint_refused in an event-only commit and no
/// checkpoint row lands (spec D2).
#[tokio::test]
async fn write_checkpoint_refuses_live_attempt() -> Result<()> {
    skip!();
    for state in ["claimed", "provisioning", "started"] {
        let Some((mut admin, mut f)) = fixture("wlive").await? else {
            return Ok(());
        };
        let result: Result<()> = async {
            let anchor = seed_node(&mut f, "anchor", None, "running", 0).await?;
            seed_attempt(&mut f, anchor, 1, state, None, None).await?;

            let err = f
                .store
                .write_checkpoint(
                    f.run_id,
                    f.node(anchor),
                    "operator-test",
                    GcClass::Supersedeable,
                    1,
                )
                .await
                .expect_err("live anchor attempt must refuse");
            require_failure(
                &err,
                FailureKind::Denied,
                checkpoint_codes::BOUNDARY_ILLEGAL,
            );
            assert_eq!(count_events(&mut f, "checkpoint_refused").await?, 1);
            assert_eq!(
                last_event_reason(&mut f, "checkpoint_refused").await?,
                Some(checkpoint_codes::BOUNDARY_ILLEGAL.to_owned())
            );
            assert_eq!(count_events(&mut f, "checkpoint_written").await?, 0);
            assert_eq!(count_checkpoints(&mut f).await?, 0);
            Ok(())
        }
        .await;
        drop_db(
            &mut admin,
            &format!("ckpt_test_wlive_{}", std::process::id()),
        )
        .await;
        result?;
    }
    Ok(())
}

/// A subtree artifact still moving through reserved/staging/verifying
/// finalization refuses the boundary even when the anchor is
/// quiescent.
#[tokio::test]
async fn write_checkpoint_refuses_mid_finalizing_artifact() -> Result<()> {
    skip!();
    for state in ["reserved", "staging", "verifying"] {
        let Some((mut admin, mut f)) = fixture("wfin").await? else {
            return Ok(());
        };
        let result: Result<()> = async {
            let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
            seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;
            let child = seed_node(&mut f, "child", Some(anchor), "running", 1).await?;
            let child_attempt = seed_attempt(&mut f, child, 1, "started", None, None).await?;
            let artifact = seed_artifact(&mut f, state).await?;
            seed_produce_edge(&mut f, child, child_attempt, artifact).await?;

            let err = f
                .store
                .write_checkpoint(
                    f.run_id,
                    f.node(anchor),
                    "operator-test",
                    GcClass::Supersedeable,
                    1,
                )
                .await
                .expect_err("mid-finalizing artifact must refuse");
            require_failure(
                &err,
                FailureKind::Denied,
                checkpoint_codes::BOUNDARY_ILLEGAL,
            );
            assert_eq!(count_events(&mut f, "checkpoint_refused").await?, 1);
            assert_eq!(count_checkpoints(&mut f).await?, 0);
            Ok(())
        }
        .await;
        drop_db(
            &mut admin,
            &format!("ckpt_test_wfin_{}", std::process::id()),
        )
        .await;
        result?;
    }
    Ok(())
}

/// A quiescent write commits the checkpoint row and its
/// checkpoint_written event in one transaction: event_watermark is the
/// appended event's seq, the subtree inventories are recorded, and a
/// sibling's live attempt is captured — not blocked (spec D2).
#[tokio::test]
async fn write_checkpoint_commits_record_and_event() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("wwrite").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let path = "/tmp/ws-anchor";
        let session = "harness-session-1";
        let anchor_attempt =
            seed_attempt(&mut f, anchor, 1, "succeeded", Some(path), Some(session)).await?;

        let done = seed_node(&mut f, "done", Some(anchor), "succeeded", 1).await?;
        let reader = seed_node(&mut f, "reader", Some(anchor), "declared", 1).await?;
        let flying = seed_node(&mut f, "flying", Some(anchor), "running", 1).await?;
        seed_attempt(&mut f, flying, 1, "started", None, None).await?;
        // A cancelled sibling rides the subtree but enters no inventory.
        seed_node(&mut f, "cancelled", Some(anchor), "cancelled", 1).await?;

        // The read set covers unfinished subtree nodes only: reader's
        // artifact in-edge plus flying's declared input_artifact_refs,
        // filtered to 'ready'. The 'reserved' artifact is declared but
        // not finalized — excluded.
        let ready_a = seed_artifact(&mut f, "ready").await?;
        let ready_b = seed_artifact(&mut f, "ready").await?;
        let reserved = seed_artifact(&mut f, "reserved").await?;
        seed_artifact_edge(&mut f, reader, done, ready_a).await?;
        sqlx::query(
            "UPDATE central.workflow_nodes SET input_artifact_refs = $2::jsonb WHERE id = $1",
        )
        .bind(flying)
        .bind(format!(
            r#"[{{"artifact_id":"{ready_b}","checksum":"c"}},{{"artifact_id":"{reserved}","checksum":"c"}}]"#
        ))
        .execute(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "UPDATE central.workflow_nodes SET input_artifact_refs = $2::jsonb WHERE id = $1",
        )
        .bind(reader)
        .bind(format!(r#"[{{"artifact_id":"{reserved}","checksum":"c"}}]"#))
        .execute(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;

        let record = f
            .store
            .write_checkpoint(f.run_id, f.node(anchor), "operator-test", GcClass::RunTerminal, 1)
            .await?;

        // The digest was computed over the anchor attempt's recorded
        // workspace before the transaction opened.
        let (last_path, last_kind) = f.digester.last();
        assert_eq!(f.digester.calls(), 1);
        assert_eq!(last_path.as_deref(), Some(path));
        assert_eq!(last_kind.as_deref(), Some("directory"));
        assert_eq!(
            record.workspace_digest.as_deref(),
            Some("sha256:workspace")
        );
        assert_eq!(record.workspace_path.as_deref(), Some(path));
        assert_eq!(record.harness_session_id.as_deref(), Some(session));
        assert_eq!(
            record.attempt_id,
            SessionAttemptId::from_trusted_db_bytes(anchor_attempt.into_bytes())
        );

        // One commit: the row exists, the event's seq is the watermark.
        let watermark_seq: i64 = sqlx::query_scalar(
            "SELECT seq FROM central.run_events \
             WHERE run_id = $1 AND kind = 'checkpoint_written'",
        )
        .bind(f.run)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(record.event_watermark, watermark_seq);
        let max_seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq),0) FROM central.run_events WHERE run_id = $1",
        )
        .bind(f.run)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(watermark_seq, max_seq);

        // Inventories.
        assert_eq!(record.completed_nodes, ["anchor", "done"]);
        let mut artifacts: Vec<uuid::Uuid> = record
            .finalized_artifacts
            .iter()
            .map(|id| uuid_of(id.as_bytes()))
            .collect();
        artifacts.sort();
        let mut want = vec![ready_a, ready_b];
        want.sort();
        assert_eq!(artifacts, want);
        assert_eq!(record.in_flight_nodes, ["flying"]);
        assert_eq!(record.gc_class, GcClass::RunTerminal);
        assert_eq!(record.expires_at, None);
        assert_eq!(record.content_digest, record.digest());

        // load_resume_checkpoint_by_id round-trips the persisted row.
        let loaded = f.store.load_resume_checkpoint_by_id(record.id).await?;
        assert_eq!(loaded.content_digest, record.content_digest);
        assert_eq!(loaded.event_watermark, record.event_watermark);
        assert_eq!(
            loaded.finalized_artifacts.len(),
            record.finalized_artifacts.len()
        );
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_wwrite_{}", std::process::id()),
    )
    .await;
    result
}

/// Spec-5 `(attempt_id, checkpoint_seq)` dedupe: an identical retry
/// resolves the recorded row and journals command_deduped; the same
/// seq carrying a different payload (here gc_class) refuses
/// DUPLICATE_IDEMPOTENCY_KEY and the recorded row stands; a fresh seq
/// commits a second row.
#[tokio::test]
async fn write_checkpoint_seq_dedupe() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("wdedup").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;

        let first = f
            .store
            .write_checkpoint(
                f.run_id,
                f.node(anchor),
                "operator-test",
                GcClass::RunTerminal,
                1,
            )
            .await?;
        assert_eq!(first.checkpoint_seq, 1);

        // Identical replay: same row id, no second checkpoint_written.
        let replay = f
            .store
            .write_checkpoint(
                f.run_id,
                f.node(anchor),
                "operator-test",
                GcClass::RunTerminal,
                1,
            )
            .await?;
        assert_eq!(replay.id, first.id);
        assert_eq!(count_checkpoints(&mut f).await?, 1);
        assert_eq!(count_events(&mut f, "checkpoint_written").await?, 1);
        assert_eq!(count_events(&mut f, "command_deduped").await?, 1);

        // Same seq, different payload → refusal, recorded row stands.
        let err = f
            .store
            .write_checkpoint(
                f.run_id,
                f.node(anchor),
                "operator-test",
                GcClass::Supersedeable,
                1,
            )
            .await
            .expect_err("fingerprint mismatch must refuse");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::DUPLICATE_IDEMPOTENCY,
        );
        assert_eq!(count_checkpoints(&mut f).await?, 1);
        let stored_class: String = sqlx::query_scalar(
            "SELECT gc_class FROM central.resume_checkpoints WHERE checkpoint_id = $1",
        )
        .bind(uuid_of(first.id.as_bytes()))
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(stored_class, GcClass::RunTerminal.as_str());

        // A fresh seq commits a second checkpoint on the same attempt.
        let second = f
            .store
            .write_checkpoint(
                f.run_id,
                f.node(anchor),
                "operator-test",
                GcClass::RunTerminal,
                2,
            )
            .await?;
        assert_ne!(second.id, first.id);
        assert_eq!(count_checkpoints(&mut f).await?, 2);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_wdedup_{}", std::process::id()),
    )
    .await;
    result
}

// ---------------------------------------------------------------------------
// Token resolution + preflight (upstream T5, spec D3)
// ---------------------------------------------------------------------------

/// A malformed or unresolvable token fails check 1 with
/// RESUME_TOKEN_STALE; a token naming an absent row carries no run
/// context so no resume_failed can journal.
#[tokio::test]
async fn resume_preflight_stale_tokens() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("pstale").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;

        let cases: Vec<(String, FailureKind)> = vec![
            ("garbage".to_owned(), FailureKind::Invalid),
            (
                format!("ckpt.not-a-uuid.{}", "a".repeat(32)),
                FailureKind::Invalid,
            ),
            (
                format!("ckpt.{}.", uuid::Uuid::now_v7()),
                FailureKind::Invalid,
            ),
            (
                format!("ckpt.{}.{}", uuid::Uuid::now_v7(), "A".repeat(32)),
                FailureKind::Invalid,
            ),
            (
                format!("ckpt.{}.{}", uuid::Uuid::now_v7(), "0".repeat(32)),
                FailureKind::Denied,
            ),
        ];
        for (token, kind) in cases {
            let err = f
                .store
                .resume_preflight(&token)
                .await
                .expect_err("stale token must fail preflight");
            require_failure(&err, kind, checkpoint_codes::RESUME_TOKEN_STALE);
        }
        assert_eq!(count_events(&mut f, "resume_failed").await?, 0);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_pstale_{}", std::process::id()),
    )
    .await;
    result
}

/// An expired row resolves then fails staleness; a token whose digest
/// prefix does not match the row's content fails staleness. Both
/// journal resume_failed against the resolved run.
#[tokio::test]
async fn resume_preflight_stale_row_and_digest_mismatch() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("prow").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;

        let mut seed = CkptSeed::new(anchor, attempt);
        seed.expires_at = Some(OffsetDateTime::now_utc() - Duration::hours(1));
        let expired = write_checkpoint_row(&mut f, seed).await?;
        let err = f
            .store
            .resume_preflight(&expired.encode_token())
            .await
            .expect_err("expired row must fail staleness");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::RESUME_TOKEN_STALE,
        );

        let live = write_checkpoint_row(&mut f, CkptSeed::new(anchor, attempt)).await?;
        let mut tampered: Vec<String> = live.encode_token().split('.').map(str::to_owned).collect();
        tampered[2] = "f".repeat(tampered[2].len());
        let err = f
            .store
            .resume_preflight(&tampered.join("."))
            .await
            .expect_err("digest mismatch must fail staleness");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::RESUME_TOKEN_STALE,
        );

        assert_eq!(count_events(&mut f, "resume_failed").await?, 2);
        assert_eq!(
            last_event_reason(&mut f, "resume_failed").await?,
            Some(checkpoint_codes::RESUME_TOKEN_STALE.to_owned())
        );
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_prow_{}", std::process::id()),
    )
    .await;
    result
}

/// A version-incompatible record fails check 2 with
/// CHECKPOINT_INCOMPATIBLE, journals resume_failed, and leaves every
/// node state untouched.
#[tokio::test]
async fn resume_preflight_incompatible() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("pinc").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;
        seed_node(&mut f, "child", Some(anchor), "declared", 1).await?;

        let mut seed = CkptSeed::new(anchor, attempt);
        seed.format = "central.checkpoint/v999".to_owned();
        let record = write_checkpoint_row(&mut f, seed).await?;
        let before = node_states_snapshot(&mut f).await?;

        let err = f
            .store
            .resume_preflight(&record.encode_token())
            .await
            .expect_err("incompatible format must fail preflight");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::FORMAT_INCOMPATIBLE,
        );
        assert_eq!(
            last_event_reason(&mut f, "resume_failed").await?,
            Some(checkpoint_codes::FORMAT_INCOMPATIBLE.to_owned())
        );
        assert_eq!(node_states_snapshot(&mut f).await?, before);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_pinc_{}", std::process::id()),
    )
    .await;
    result
}

/// A workspace that no longer digests to the recorded value fails
/// check 3 with WORKSPACE_DIGEST_MISMATCH; a re-digest failure
/// surfaces the same actionable verdict.
#[tokio::test]
async fn resume_preflight_workspace_digest_mismatch() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("pws").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;

        let mut seed = CkptSeed::new(anchor, attempt);
        seed.workspace_digest = Some("sha256:at-checkpoint".to_owned());
        seed.workspace_path = Some("/tmp/ws".to_owned());
        let record = write_checkpoint_row(&mut f, seed).await?;

        f.digester.set_digest("sha256:now");
        let err = f
            .store
            .resume_preflight(&record.encode_token())
            .await
            .expect_err("digest drift must fail preflight");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::WORKSPACE_DIGEST_MISMATCH,
        );

        f.digester.set_err(Some("fs gone"));
        let err = f
            .store
            .resume_preflight(&record.encode_token())
            .await
            .expect_err("re-digest failure must fail preflight");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::WORKSPACE_DIGEST_MISMATCH,
        );
        f.digester.set_err(None);

        assert_eq!(count_events(&mut f, "resume_failed").await?, 2);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &format!("ckpt_test_pws_{}", std::process::id())).await;
    result
}

/// A readable-set entry that no longer resolves as 'ready' fails
/// check 4 with CHECKPOINT_ARTIFACT_MISSING and reports the missing
/// ids in the journaled payload.
#[tokio::test]
async fn resume_preflight_artifact_missing() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("part").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;

        let ready = seed_artifact(&mut f, "ready").await?;
        let deleted = seed_artifact(&mut f, "deleted").await?;
        let gone = uuid::Uuid::now_v7();
        let mut seed = CkptSeed::new(anchor, attempt);
        seed.artifacts = vec![ready, deleted, gone];
        let record = write_checkpoint_row(&mut f, seed).await?;

        let err = f
            .store
            .resume_preflight(&record.encode_token())
            .await
            .expect_err("missing artifact must fail preflight");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::RESUME_ARTIFACT_MISSING,
        );
        assert_eq!(
            last_event_reason(&mut f, "resume_failed").await?,
            Some(checkpoint_codes::RESUME_ARTIFACT_MISSING.to_owned())
        );
        let missing: serde_json::Value = sqlx::query_scalar(
            "SELECT payload->'missing' FROM central.run_events \
             WHERE run_id = $1 AND kind = 'resume_failed' ORDER BY seq DESC LIMIT 1",
        )
        .bind(f.run)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(
            missing.as_array().map(Vec::len),
            Some(2),
            "deleted + absent ids report"
        );
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_part_{}", std::process::id()),
    )
    .await;
    result
}

// ---------------------------------------------------------------------------
// ResumeSubtree — the all-or-nothing resume transaction (upstream T5,
// spec D4)
// ---------------------------------------------------------------------------

/// The happy path: the checkpoint is written against the live
/// scenario, then resume_subtree rebuilds the ready set in one
/// transaction — completed stays, unfinished-but-ready flips with
/// ready_at stamped, an in-flight-at-watermark node parks
/// attempt_ambiguous with its attempt closed and lease released,
/// terminal-not-completed reports in terminal_held, and the
/// resume_started/resume_completed pair journals. A replay of the
/// same token changes no state.
#[tokio::test]
async fn resume_subtree_happy_path_and_replay() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("rhappy").await? else {
        return Ok(());
    };
    let result = async {
        // anchor parked ambiguous (node + attempt), done succeeded,
        // reader declared, flying dispatched under a live attempt +
        // lease, held failed_terminal, blocked declared behind the
        // failed node, waiting already ready.
        let anchor = seed_node(&mut f, "anchor", None, "attempt_ambiguous", 0).await?;
        seed_attempt(&mut f, anchor, 1, "ambiguous", None, None).await?;
        let done = seed_node(&mut f, "done", Some(anchor), "succeeded", 1).await?;
        let reader = seed_node(&mut f, "reader", Some(anchor), "declared", 1).await?;
        let flying = seed_node(&mut f, "flying", Some(anchor), "dispatched", 1).await?;
        let flying_attempt = seed_attempt(&mut f, flying, 1, "started", None, None).await?;
        let worker = seed_worker(&mut f).await?;
        let lease = seed_lease(&mut f, flying, flying_attempt, worker).await?;
        let held = seed_node(&mut f, "held", Some(anchor), "failed_terminal", 1).await?;
        let blocked = seed_node(&mut f, "blocked", Some(anchor), "declared", 1).await?;
        let waiting = seed_node(&mut f, "waiting", Some(anchor), "ready", 1).await?;

        seed_ordering_edge(&mut f, reader, done).await?;
        seed_ordering_edge(&mut f, blocked, held).await?;
        seed_ordering_edge(&mut f, waiting, done).await?;
        let readable = seed_artifact(&mut f, "ready").await?;
        seed_artifact_edge(&mut f, reader, done, readable).await?;

        let record = f
            .store
            .write_checkpoint(
                f.run_id,
                f.node(anchor),
                "operator-test",
                GcClass::Supersedeable,
                1,
            )
            .await?;
        let token = record.encode_token();

        f.store.resume_subtree(&token, "operator-resume").await?;

        let states = node_states_snapshot(&mut f).await?;
        let want: HashMap<String, String> = [
            ("anchor", "attempt_ambiguous"),
            ("done", "succeeded"),
            ("reader", "ready"),
            ("flying", "attempt_ambiguous"),
            ("held", "failed_terminal"),
            ("blocked", "declared"),
            ("waiting", "ready"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(states, want);

        // The parked node's live attempt closed 'ambiguous' carrying
        // the operator-decision reason; its lease released.
        let (attempt_state, reason, ended_at): (String, Option<String>, Option<OffsetDateTime>) =
            sqlx::query_as(
                "SELECT state, dispatch_reason_code, ended_at \
                 FROM central.session_attempts WHERE id = $1",
            )
            .bind(flying_attempt)
            .fetch_one(&mut f.mig)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(attempt_state, "ambiguous");
        assert_eq!(
            reason.as_deref(),
            Some(checkpoint_codes::RESUME_REQUIRES_OPERATOR)
        );
        assert!(ended_at.is_none(), "ambiguous attempt stays non-terminal");
        let released_at: Option<OffsetDateTime> =
            sqlx::query_scalar("SELECT released_at FROM central.node_leases WHERE id = $1")
                .bind(lease)
                .fetch_one(&mut f.mig)
                .await
                .map_err(|e| classify_sqlx(&e))?;
        assert!(released_at.is_some(), "parked node's lease must release");

        // ready_at stamped on the ->ready flip; the already-ready node
        // keeps its own stamp.
        for id in [reader, waiting] {
            let ready_at: Option<OffsetDateTime> =
                sqlx::query_scalar("SELECT ready_at FROM central.workflow_nodes WHERE id = $1")
                    .bind(id)
                    .fetch_one(&mut f.mig)
                    .await
                    .map_err(|e| classify_sqlx(&e))?;
            assert!(ready_at.is_some(), "ready_at must be stamped");
        }

        // Journal: resume_started, one node_ready (reader's flip), one
        // attempt_ambiguous (flying's park), resume_completed.
        assert_eq!(count_events(&mut f, "resume_started").await?, 1);
        assert_eq!(count_events(&mut f, "node_ready").await?, 1);
        assert_eq!(count_events(&mut f, "attempt_ambiguous").await?, 1);
        assert_eq!(count_events(&mut f, "resume_completed").await?, 1);
        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT payload FROM central.run_events \
             WHERE run_id = $1 AND kind = 'resume_completed'",
        )
        .bind(f.run)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(payload["dispatched_count"], serde_json::json!(2));
        assert_eq!(payload["parked"], serde_json::json!(["anchor", "flying"]));
        assert_eq!(payload["terminal_held"], serde_json::json!(["held"]));

        // Replay: same token, no state change, no per-node re-journal;
        // the re-invocation itself journals another started/completed
        // pair.
        f.store.resume_subtree(&token, "operator-resume").await?;
        assert_eq!(node_states_snapshot(&mut f).await?, want);
        assert_eq!(count_events(&mut f, "node_ready").await?, 1);
        assert_eq!(count_events(&mut f, "attempt_ambiguous").await?, 1);
        assert_eq!(count_events(&mut f, "resume_started").await?, 2);
        assert_eq!(count_events(&mut f, "resume_completed").await?, 2);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_rhappy_{}", std::process::id()),
    )
    .await;
    result
}

/// A preflight violation inside resume_subtree returns the same
/// Failure the standalone preflight reports — nothing else commits.
#[tokio::test]
async fn resume_subtree_propagates_preflight_failure() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("rpre").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;
        let mut seed = CkptSeed::new(anchor, attempt);
        seed.format = "bogus".to_owned();
        let record = write_checkpoint_row(&mut f, seed).await?;

        let err = f
            .store
            .resume_subtree(&record.encode_token(), "operator-resume")
            .await
            .expect_err("preflight failure must propagate");
        require_failure(
            &err,
            FailureKind::Denied,
            checkpoint_codes::FORMAT_INCOMPATIBLE,
        );
        assert_eq!(count_events(&mut f, "resume_started").await?, 0);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_rpre_{}", std::process::id()),
    )
    .await;
    result
}

// ---------------------------------------------------------------------------
// Retention-class GC + pin/unpin (upstream T6, spec D5)
// ---------------------------------------------------------------------------

/// One collect pass applies gc_pick per anchor: the fourth
/// supersedeable checkpoint collects the oldest, an expired
/// supersedeable row goes regardless of the keep-latest count, a
/// run_terminal row past the 30-day window goes, and pinned plus
/// in-window run_terminal survive. Every deletion journals
/// checkpoint_gc_collected against the row's run, and no node,
/// attempt, or event row is ever removed.
#[tokio::test]
async fn collect_applies_retention_classes() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("gcret").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;

        let now = OffsetDateTime::now_utc();
        let past = now - Duration::hours(1);

        // Four supersedeable rows, oldest → newest: gc_pick keeps the
        // latest three.
        let mut supersedeable = Vec::new();
        for i in 0i64..4 {
            let c = write_checkpoint_row(&mut f, CkptSeed::new(anchor, attempt)).await?;
            set_checkpoint_created_at(&mut f, c.id, now + Duration::minutes(i)).await?;
            supersedeable.push(c.id);
        }
        // An expired supersedeable row collects even inside keep-3.
        let mut seed = CkptSeed::new(anchor, attempt);
        seed.expires_at = Some(past);
        let expired = write_checkpoint_row(&mut f, seed).await?;
        // Pinned never collects — even with expires_at in the past.
        let mut seed = CkptSeed::new(anchor, attempt);
        seed.gc_class = GcClass::Pinned;
        seed.expires_at = Some(past);
        let pinned = write_checkpoint_row(&mut f, seed).await?;
        // run_terminal inside the 30-day window survives; past it
        // collects.
        let mut seed = CkptSeed::new(anchor, attempt);
        seed.gc_class = GcClass::RunTerminal;
        let recent_terminal = write_checkpoint_row(&mut f, seed).await?;
        let mut seed = CkptSeed::new(anchor, attempt);
        seed.gc_class = GcClass::RunTerminal;
        let old_terminal = write_checkpoint_row(&mut f, seed).await?;
        set_checkpoint_created_at(
            &mut f,
            old_terminal.id,
            now - RUN_TERMINAL_RETENTION - Duration::hours(1),
        )
        .await?;

        let attempts_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM central.session_attempts WHERE workspace_id = $1",
        )
        .bind(f.ws)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let nodes_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM central.workflow_nodes WHERE workspace_id = $1",
        )
        .bind(f.ws)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;

        let outcome = f.store.collect(now).await?;
        assert!(
            !outcome.has_failures(),
            "clean pass reports no partial failures: {:?}",
            outcome.failures
        );
        assert_eq!(outcome.collected, 3);

        for id in [supersedeable[0], expired.id, old_terminal.id] {
            assert!(!checkpoint_exists(&mut f, id).await?, "{id} survived GC");
        }
        for id in [
            supersedeable[1],
            supersedeable[2],
            supersedeable[3],
            pinned.id,
            recent_terminal.id,
        ] {
            assert!(
                checkpoint_exists(&mut f, id).await?,
                "{id} collected wrongly"
            );
        }

        // One journaled event per deletion, run_id from the deleted row.
        assert_eq!(count_events(&mut f, "checkpoint_gc_collected").await?, 3);
        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT payload FROM central.run_events \
             WHERE run_id = $1 AND kind = 'checkpoint_gc_collected' \
               AND payload->>'checkpoint_id' = $2",
        )
        .bind(f.run)
        .bind(supersedeable[0].to_string())
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(payload["node_key"], serde_json::json!("anchor"));
        assert_eq!(
            payload["gc_class"],
            serde_json::json!(GcClass::Supersedeable.as_str())
        );

        // GC deletes checkpoint rows only.
        let attempts_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM central.session_attempts WHERE workspace_id = $1",
        )
        .bind(f.ws)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let nodes_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM central.workflow_nodes WHERE workspace_id = $1",
        )
        .bind(f.ws)
        .fetch_one(&mut f.mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(attempts_before, attempts_after);
        assert_eq!(nodes_before, nodes_after);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_gcret_{}", std::process::id()),
    )
    .await;
    result
}

/// GC is anchor-scoped: supersedeable rows on different anchors are
/// independent groups, and a keep-3 overflow on one anchor does not
/// touch another.
#[tokio::test]
async fn collect_is_anchor_scoped() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("gcscope").await? else {
        return Ok(());
    };
    let result = async {
        let anchor_a = seed_node(&mut f, "a", None, "succeeded", 0).await?;
        let anchor_b = seed_node(&mut f, "b", None, "succeeded", 0).await?;
        let attempt_a = seed_attempt(&mut f, anchor_a, 1, "succeeded", None, None).await?;
        let attempt_b = seed_attempt(&mut f, anchor_b, 1, "succeeded", None, None).await?;

        let now = OffsetDateTime::now_utc();
        let mut a_ids = Vec::new();
        for i in 0i64..4 {
            let c = write_checkpoint_row(&mut f, CkptSeed::new(anchor_a, attempt_a)).await?;
            set_checkpoint_created_at(&mut f, c.id, now + Duration::minutes(i)).await?;
            a_ids.push(c.id);
        }
        let mut b_ids = Vec::new();
        for i in 0i64..2 {
            let c = write_checkpoint_row(&mut f, CkptSeed::new(anchor_b, attempt_b)).await?;
            set_checkpoint_created_at(&mut f, c.id, now + Duration::minutes(i)).await?;
            b_ids.push(c.id);
        }

        let outcome = f.store.collect(now).await?;
        assert_eq!(outcome.collected, 1);
        assert!(!checkpoint_exists(&mut f, a_ids[0]).await?);
        for id in b_ids {
            assert!(checkpoint_exists(&mut f, id).await?);
        }
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_gcscope_{}", std::process::id()),
    )
    .await;
    result
}

/// A clean pass over zero rows collects nothing and journals nothing.
#[tokio::test]
async fn collect_empty() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("gcempty").await? else {
        return Ok(());
    };
    let result = async {
        let outcome = f.store.collect(OffsetDateTime::now_utc()).await?;
        assert_eq!(outcome.collected, 0);
        assert!(!outcome.has_failures());
        assert_eq!(count_events(&mut f, "checkpoint_gc_collected").await?, 0);
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_gcempty_{}", std::process::id()),
    )
    .await;
    result
}

/// Pin/unpin flips gc_class without touching the content digest — a
/// live resume token keeps resolving across the flip — and an absent
/// row refuses CHECKPOINT_NOT_FOUND.
#[tokio::test]
async fn update_gc_class_round_trip() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("gcclass").await? else {
        return Ok(());
    };
    let result = async {
        let anchor = seed_node(&mut f, "anchor", None, "succeeded", 0).await?;
        let attempt = seed_attempt(&mut f, anchor, 1, "succeeded", None, None).await?;
        let record = write_checkpoint_row(&mut f, CkptSeed::new(anchor, attempt)).await?;
        let token = record.encode_token();

        f.store.update_gc_class(record.id, GcClass::Pinned).await?;
        let loaded = f.store.load_resume_checkpoint_by_id(record.id).await?;
        assert_eq!(loaded.gc_class, GcClass::Pinned);
        // The digest is GC-bookkeeping-exempt: the token minted before
        // the pin still resolves the row.
        f.store.resolve_token(&token).await?;

        f.store
            .update_gc_class(record.id, GcClass::Supersedeable)
            .await?;
        let loaded = f.store.load_resume_checkpoint_by_id(record.id).await?;
        assert_eq!(loaded.gc_class, GcClass::Supersedeable);

        let err = f
            .store
            .update_gc_class(ResumeCheckpointId::new(), GcClass::Pinned)
            .await
            .expect_err("absent row must refuse");
        require_failure(&err, FailureKind::Invalid, "CHECKPOINT_NOT_FOUND");
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_gcclass_{}", std::process::id()),
    )
    .await;
    result
}

/// list_checkpoints returns the run's rows newest-first and
/// list_by_anchor narrows to one anchor — the `checkpoint list`
/// projection.
#[tokio::test]
async fn list_checkpoints_and_list_by_anchor() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("gclist").await? else {
        return Ok(());
    };
    let result = async {
        let anchor_a = seed_node(&mut f, "a", None, "succeeded", 0).await?;
        let anchor_b = seed_node(&mut f, "b", None, "succeeded", 0).await?;
        let attempt_a = seed_attempt(&mut f, anchor_a, 1, "succeeded", None, None).await?;
        let attempt_b = seed_attempt(&mut f, anchor_b, 1, "succeeded", None, None).await?;

        let now = OffsetDateTime::now_utc();
        let older = write_checkpoint_row(&mut f, CkptSeed::new(anchor_a, attempt_a)).await?;
        set_checkpoint_created_at(&mut f, older.id, now - Duration::minutes(1)).await?;
        let newer = write_checkpoint_row(&mut f, CkptSeed::new(anchor_a, attempt_a)).await?;
        set_checkpoint_created_at(&mut f, newer.id, now).await?;
        let other = write_checkpoint_row(&mut f, CkptSeed::new(anchor_b, attempt_b)).await?;
        set_checkpoint_created_at(&mut f, other.id, now - Duration::minutes(2)).await?;

        let listed = f.store.list_checkpoints(f.run_id).await?;
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].id, newer.id, "newest-first");

        let by_anchor = f.store.list_by_anchor(f.run_id, f.node(anchor_a)).await?;
        assert_eq!(by_anchor.len(), 2);
        assert!(by_anchor.iter().all(|c| c.id != other.id));
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_gclist_{}", std::process::id()),
    )
    .await;
    result
}

/// anchor_for resolves an explicit node key inside the run, falls
/// back to the run's unique depth-0 root, and refuses a missing or
/// ambiguous root so the CLI can ask for --node.
#[tokio::test]
async fn anchor_for_resolution() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("anchor").await? else {
        return Ok(());
    };
    let result = async {
        let root = seed_node(&mut f, "root", None, "succeeded", 0).await?;
        let child = seed_node(&mut f, "child", Some(root), "succeeded", 1).await?;

        let id = f.store.anchor_for(f.run_id, "child").await?;
        assert_eq!(id, f.node(child));
        let id = f.store.anchor_for(f.run_id, "").await?;
        assert_eq!(id, f.node(root));

        let err = f
            .store
            .anchor_for(f.run_id, "nope")
            .await
            .expect_err("unknown key must refuse");
        require_failure(&err, FailureKind::Invalid, "CHECKPOINT_ANCHOR_MISSING");

        let err = f
            .store
            .anchor_for(RunId::new(), "")
            .await
            .expect_err("unknown run must refuse");
        require_failure(&err, FailureKind::Invalid, "CHECKPOINT_RUN_MISSING");
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_anchor_{}", std::process::id()),
    )
    .await;
    result
}

/// A second depth-0 root makes the default anchor ambiguous; the
/// failure tells the operator to pass --node.
#[tokio::test]
async fn anchor_for_ambiguous_root() -> Result<()> {
    skip!();
    let Some((mut admin, mut f)) = fixture("ambroot").await? else {
        return Ok(());
    };
    let result = async {
        seed_node(&mut f, "root-a", None, "succeeded", 0).await?;
        seed_node(&mut f, "root-b", None, "succeeded", 0).await?;

        let err = f
            .store
            .anchor_for(f.run_id, "")
            .await
            .expect_err("two roots must refuse ambiguous");
        require_failure(&err, FailureKind::Invalid, "CHECKPOINT_ANCHOR_AMBIGUOUS");
        assert!(
            err.message().contains("--node"),
            "ambiguous detail should direct to --node: {}",
            err.message()
        );
        Ok(())
    }
    .await;
    drop_db(
        &mut admin,
        &format!("ckpt_test_ambroot_{}", std::process::id()),
    )
    .await;
    result
}
