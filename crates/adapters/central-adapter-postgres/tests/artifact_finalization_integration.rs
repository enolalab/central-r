//! PostgreSQL integration tests for the spec-5 §5 attempt-scoped
//! visibility boundary (`artifact/finalization.rs`) — the port of
//! upstream `internal/adapter/postgres/artifact/finalize_test.go`.
//!
//! Every `finalize_attempt_artifact` call commits atomically: the
//! `artifact_finalizations` key row, the `verifying` → `ready`
//! transition, the journaled produce edge, and the `artifact_finalized`
//! run event with its `event_outbox` twin. A refused command leaves
//! every durable record unchanged.
//!
//! Also covered: RTM-14's premature-read refusal
//! (`ARTIFACT_NOT_FINALIZED` before the boundary, authorized after)
//! and the `ancestors`/`descendants`/`run_lineage_for_run` projections
//! over the edges the boundary itself journals.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `artifact_lineage_integration.rs`. Fixture writes run under
//! `central_migration` (owner); the store runs under `central_runtime`,
//! which holds `SELECT, INSERT` on `artifact_finalizations` and the
//! journal tables and `UPDATE` on `artifacts`/`runs`.

use central_adapter_postgres::artifact::Store;
use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_artifact::app::{ancestors, authorize_read, descendants, run_lineage_for_run};
use central_artifact::domain::State;
use central_artifact::lineage::{
    AttemptFinalization, FinalizeAttemptInput, ReadRequest, ReadScope, ReadSelector,
    attempt_finalization,
};
use central_artifact::port::{AttemptFinalizationStore, ReadEdgeStore};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ArtifactId, ContentGeneration, RunId, SessionAttemptId, TaskId, WorkflowNodeId, WorkspaceId,
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
    let db = format!("artifact_finalize_test_{label}_{}", std::process::id());
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
/// finalize row hangs off of.
struct Fixture {
    /// The store under `central_runtime` — the production role.
    store: Store,
    /// Owner connection for fixture writes and assertion reads.
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

/// `seedWorkflowNode` — the producing workflow node the session
/// attempt and produce edge hang off of (b33 columns).
async fn seed_workflow_node(f: &mut Fixture, node_key: &str) -> Result<WorkflowNodeId> {
    let raw = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.workflow_nodes \
         (id, run_id, workspace_id, node_key, harness, workspace_kind, depth, state, spec) \
         VALUES ($1, $2, $3, $4, 'claude-code', 'worktree', 0, 'running', '{}'::jsonb)",
    )
    .bind(raw)
    .bind(uuid_of!(f.run))
    .bind(uuid_of!(f.ws))
    .bind(node_key)
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(WorkflowNodeId::from_trusted_db_bytes(*raw.as_bytes()))
}

/// `seedSessionAttempt` — one started attempt on `node` under the
/// fixture's run, the producing context the finalize locks and
/// journals against (b35 columns).
async fn seed_session_attempt(
    f: &mut Fixture,
    node_id: WorkflowNodeId,
    seq: i32,
) -> Result<SessionAttemptId> {
    let raw = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.session_attempts \
         (id, workspace_id, run_id, node_id, attempt_seq, workspace_kind, state, started_at) \
         VALUES ($1, $2, $3, $4, $5, 'worktree', 'started', clock_timestamp())",
    )
    .bind(raw)
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(f.run))
    .bind(uuid_of!(node_id))
    .bind(seq)
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(SessionAttemptId::from_trusted_db_bytes(*raw.as_bytes()))
}

/// `seeded_artifact` — a direct artifacts-row insert. `promoted`
/// controls whether the promotion fields `ready_key` +
/// `content_generation` are present (upstream `advanceToVerifying` vs
/// `advanceToPromoted`).
struct SeededArtifact {
    artifact_id: ArtifactId,
    content_generation: ContentGeneration,
}

async fn seed_artifact(
    f: &mut Fixture,
    role: &str,
    checksum: &[u8; 32],
    promoted: bool,
) -> Result<SeededArtifact> {
    let raw = uuid::Uuid::now_v7();
    let generation_raw = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO central.artifacts (\
         id, workspace_id, task_id, run_id, version, state, size, \
         staging_generation, staging_key, object_key, sensitivity, disposition, \
         content_generation, ready_key, checksum_value, checksum_algorithm, \
         required_role) \
         VALUES ($1, $2, $3, $4, 3, 'verifying', 128, \
         gen_random_uuid(), 'v1/staging/' || $1::text, 'v1/object/' || $1::text, \
         'restricted', 'attachment', \
         CASE WHEN $7 THEN $8 ELSE NULL END, \
         CASE WHEN $7 THEN 'v1/ready/' || $1::text ELSE NULL END, \
         $5, 'sha256', $6)",
    )
    .bind(raw)
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(f.task))
    .bind(uuid_of!(f.run))
    .bind(&checksum[..])
    .bind(role)
    .bind(promoted)
    .bind(generation_raw)
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(SeededArtifact {
        artifact_id: ArtifactId::from_trusted_db_bytes(*raw.as_bytes()),
        content_generation: ContentGeneration::from_trusted_db_bytes(*generation_raw.as_bytes()),
    })
}

/// `finalizeTarget` — one promoted artifact plus the producing
/// node/attempt, the durable coordinates the finalize call needs.
struct FinalizeTarget {
    attempt_id: SessionAttemptId,
    node_id: WorkflowNodeId,
    artifact_id: ArtifactId,
    checksum: [u8; 32],
    fingerprint: [u8; 32],
    content_generation: ContentGeneration,
}

async fn finalize_target(
    f: &mut Fixture,
    node_key: &str,
    checksum: [u8; 32],
) -> Result<FinalizeTarget> {
    let seeded = seed_artifact(f, "report", &checksum, true).await?;
    let node_id = seed_workflow_node(f, node_key).await?;
    let attempt_id = seed_session_attempt(f, node_id, 1).await?;
    let mut fingerprint = [0u8; 32];
    fingerprint[31] = 0xF0;
    Ok(FinalizeTarget {
        attempt_id,
        node_id,
        artifact_id: seeded.artifact_id,
        checksum,
        fingerprint,
        content_generation: seeded.content_generation,
    })
}

/// The capability's half: evaluate the input into the change set the
/// store commits — the same call `Service::finalize_attempt_artifact`
/// makes.
fn change(f: &Fixture, target: &FinalizeTarget, name: &str) -> Result<AttemptFinalization> {
    Ok(attempt_finalization(&FinalizeAttemptInput {
        attempt_id: target.attempt_id,
        artifact_name: name.to_owned(),
        artifact_id: target.artifact_id,
        run_id: f.run,
        node_id: target.node_id,
        checksum: target.checksum,
        payload_fingerprint: target.fingerprint,
        content_generation: target.content_generation,
    })?)
}

/// `finalizeReadyInvariants` — the B10 ready-row contract
/// `artifacts_ready_requires_metadata_b10_check` enforces.
async fn assert_ready_invariants(f: &mut Fixture, artifact_id: ArtifactId) -> Result<()> {
    let row = sqlx::query(
        "SELECT state, ready_key, content_generation, checksum_value, ready_at \
         FROM central.artifacts WHERE id = $1",
    )
    .bind(uuid_of!(artifact_id))
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    use sqlx::Row;
    let state: String = row.try_get("state").map_err(|e| classify_sqlx(&e))?;
    let ready_key: Option<String> = row.try_get("ready_key").map_err(|e| classify_sqlx(&e))?;
    let generation: Option<uuid::Uuid> = row
        .try_get("content_generation")
        .map_err(|e| classify_sqlx(&e))?;
    let checksum: Option<Vec<u8>> = row
        .try_get("checksum_value")
        .map_err(|e| classify_sqlx(&e))?;
    let ready_at: Option<OffsetDateTime> =
        row.try_get("ready_at").map_err(|e| classify_sqlx(&e))?;
    if state != "ready"
        || ready_key.as_deref().unwrap_or_default().is_empty()
        || generation.is_none()
        || checksum.as_deref().map_or(0, |c| c.len()) != 32
        || ready_at.is_none()
    {
        return Err(Failure::internal(
            "test_assert",
            "ready invariants broken after finalize",
        ));
    }
    Ok(())
}

/// `countRows` with one uuid bind.
async fn count_rows_for(f: &mut Fixture, sql: &str, id: uuid::Uuid) -> Result<i64> {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&mut f.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

fn assert_failure(err: &Failure, kind: FailureKind, code: &str) -> Result<()> {
    if err.kind() == kind && err.code() == code {
        return Ok(());
    }
    Err(Failure::internal(
        "test_assert",
        format!(
            "failure = ({:?}, {:?}), want ({kind:?}, {code:?})",
            err.kind(),
            err.code()
        ),
    ))
}

fn checksum_of(body: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(body).into()
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactCommitsAllEffects
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_commits_all_effects() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "all_effects").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-a",
        checksum_of(b"finalized body producer-a"),
    )
    .await?;

    let got = f
        .store
        .finalize_attempt_artifact(change(&f, &target, "report")?)
        .await?;
    if got != target.artifact_id {
        return Err(Failure::internal("test_assert", "returned id mismatched"));
    }
    assert_ready_invariants(&mut f, target.artifact_id).await?;

    let rows = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_finalizations \
         WHERE attempt_id = $1 AND artifact_name = 'report'",
        uuid_of!(target.attempt_id),
    )
    .await?;
    if rows != 1 {
        return Err(Failure::internal("test_assert", "finalization rows != 1"));
    }

    let edge_attempt: uuid::Uuid = sqlx::query_scalar(
        "SELECT attempt_id FROM central.artifact_produce_edges WHERE artifact_id = $1",
    )
    .bind(uuid_of!(target.artifact_id))
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    if edge_attempt != uuid_of!(target.attempt_id) {
        return Err(Failure::internal(
            "test_assert",
            "produce edge attempt mismatched",
        ));
    }

    let run_uuid = uuid_of!(f.run);
    let events = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.run_events WHERE run_id = $1 AND kind = 'artifact_finalized'",
        run_uuid,
    )
    .await?;
    if events != 1 {
        return Err(Failure::internal(
            "test_assert",
            "artifact_finalized events != 1",
        ));
    }
    // The journal envelope's payload carries the spec-7 fields.
    let payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM central.run_events WHERE run_id = $1 AND kind = 'artifact_finalized'",
    )
    .bind(uuid_of!(f.run))
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let artifact_id = payload["artifact_id"].as_str().unwrap_or_default();
    let checksum = payload["checksum"].as_str().unwrap_or_default();
    let mut expected = String::with_capacity(64);
    for byte in target.checksum {
        expected.push_str(&format!("{byte:02x}"));
    }
    if artifact_id != target.artifact_id.to_string() || checksum != expected {
        return Err(Failure::internal(
            "test_assert",
            "artifact_finalized payload mismatched",
        ));
    }
    let outbox = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.event_outbox WHERE run_id = $1",
        run_uuid,
    )
    .await?;
    if outbox != 1 {
        return Err(Failure::internal("test_assert", "outbox rows != 1"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactReplaysSameChecksum
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_replays_same_checksum() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "replay").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-b",
        checksum_of(b"finalized body producer-b"),
    )
    .await?;

    let first = f
        .store
        .finalize_attempt_artifact(change(&f, &target, "report")?)
        .await?;
    // The retried command carries the same artifact id and checksum;
    // the key row is the authority and replays to the recorded artifact.
    let second = f
        .store
        .finalize_attempt_artifact(change(&f, &target, "report")?)
        .await?;
    if second != first {
        return Err(Failure::internal(
            "test_assert",
            "replay must return the recorded artifact",
        ));
    }
    let rows = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_finalizations WHERE attempt_id = $1",
        uuid_of!(target.attempt_id),
    )
    .await?;
    if rows != 1 {
        return Err(Failure::internal("test_assert", "finalization rows != 1"));
    }
    let edges = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_produce_edges WHERE artifact_id = $1",
        uuid_of!(target.artifact_id),
    )
    .await?;
    if edges != 1 {
        return Err(Failure::internal("test_assert", "produce edges != 1"));
    }
    let run_uuid = uuid_of!(f.run);
    let finalized = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.run_events WHERE run_id = $1 AND kind = 'artifact_finalized'",
        run_uuid,
    )
    .await?;
    if finalized != 1 {
        return Err(Failure::internal(
            "test_assert",
            "artifact_finalized events != 1",
        ));
    }
    let deduped = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.run_events WHERE run_id = $1 AND kind = 'command_deduped'",
        run_uuid,
    )
    .await?;
    if deduped != 1 {
        return Err(Failure::internal(
            "test_assert",
            "command_deduped events != 1",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactRejectsDifferentChecksum
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_rejects_different_checksum() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "diff_checksum").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-c",
        checksum_of(b"finalized body producer-c"),
    )
    .await?;

    f.store
        .finalize_attempt_artifact(change(&f, &target, "report")?)
        .await?;
    let mut replay = change(&f, &target, "report")?;
    replay.checksum = checksum_of(b"different body");
    let err = f
        .store
        .finalize_attempt_artifact(replay)
        .await
        .expect_err("a different checksum must be refused");
    assert_failure(&err, FailureKind::Conflict, "ARTIFACT_ALREADY_FINALIZED")?;

    let rows = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_finalizations WHERE attempt_id = $1",
        uuid_of!(target.attempt_id),
    )
    .await?;
    if rows != 1 {
        return Err(Failure::internal("test_assert", "finalization rows != 1"));
    }
    let run_uuid = uuid_of!(f.run);
    let events = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.run_events WHERE run_id = $1",
        run_uuid,
    )
    .await?;
    if events != 1 {
        return Err(Failure::internal(
            "test_assert",
            "events after conflict != 1 (the first finalize only)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactChecksumMismatchAborts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_checksum_mismatch_aborts() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "mismatch_abort").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-d",
        checksum_of(b"finalized body producer-d"),
    )
    .await?;

    let mut bad = change(&f, &target, "report")?;
    bad.checksum = checksum_of(b"not the verified body");
    let err = f
        .store
        .finalize_attempt_artifact(bad)
        .await
        .expect_err("a checksum mismatch must abort");
    assert_failure(&err, FailureKind::Conflict, "ARTIFACT_CHECKSUM_MISMATCH")?;

    let state: String = sqlx::query_scalar("SELECT state FROM central.artifacts WHERE id = $1")
        .bind(uuid_of!(target.artifact_id))
        .fetch_one(&mut f.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    if state != "verifying" {
        return Err(Failure::internal(
            "test_assert",
            "artifact must stay verifying after an aborted finalize",
        ));
    }
    for (sql, what) in [
        (
            "SELECT COUNT(*) FROM central.artifact_finalizations WHERE attempt_id = $1",
            "finalization rows",
        ),
        (
            "SELECT COUNT(*) FROM central.artifact_produce_edges WHERE artifact_id = $1",
            "produce edges",
        ),
        (
            "SELECT COUNT(*) FROM central.run_events WHERE run_id = $1",
            "run events",
        ),
        (
            "SELECT COUNT(*) FROM central.event_outbox WHERE run_id = $1",
            "outbox rows",
        ),
    ] {
        let id = if sql.contains("attempt_id") {
            uuid_of!(target.attempt_id)
        } else if sql.contains("artifact_id") {
            uuid_of!(target.artifact_id)
        } else {
            uuid_of!(f.run)
        };
        let rows = count_rows_for(&mut f, sql, id).await?;
        if rows != 0 {
            return Err(Failure::internal(
                "test_assert",
                format!("{what} != 0 after abort"),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactRejectsUnpromoted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_rejects_unpromoted() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "unpromoted").await?;
    let mut f = setup_fixture(&db).await?;
    let checksum = checksum_of(b"verified but unpromoted");
    let seeded = seed_artifact(&mut f, "report", &checksum, false).await?;
    let node_id = seed_workflow_node(&mut f, "producer-unpromoted").await?;
    let attempt_id = seed_session_attempt(&mut f, node_id, 1).await?;

    let target = FinalizeTarget {
        attempt_id,
        node_id,
        artifact_id: seeded.artifact_id,
        checksum,
        fingerprint: [0xF1; 32],
        content_generation: seeded.content_generation,
    };
    let err = f
        .store
        .finalize_attempt_artifact(change(&f, &target, "report")?)
        .await
        .expect_err("an unpromoted artifact must be refused");
    assert_failure(&err, FailureKind::Conflict, "INVALID_TRANSITION")?;
    let rows = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_finalizations WHERE attempt_id = $1",
        uuid_of!(attempt_id),
    )
    .await?;
    if rows != 0 {
        return Err(Failure::internal(
            "test_assert",
            "finalization rows != 0 (rolled back)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactRejectsNameMismatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_rejects_name_mismatch() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "name_mismatch").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-name",
        checksum_of(b"finalized body producer-name"),
    )
    .await?;

    let err = f
        .store
        .finalize_attempt_artifact(change(&f, &target, "stdout")?)
        .await
        .expect_err("a name the artifact was not reserved for must be refused");
    assert_failure(&err, FailureKind::Denied, "PRODUCER_CHAIN_MISMATCH")?;
    let rows = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_finalizations WHERE attempt_id = $1",
        uuid_of!(target.attempt_id),
    )
    .await?;
    if rows != 0 {
        return Err(Failure::internal(
            "test_assert",
            "finalization rows != 0 (rolled back)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TestFinalizeAttemptArtifactRejectsUnknownAttempt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finalize_attempt_artifact_rejects_unknown_attempt() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "unknown_attempt").await?;
    let f = setup_fixture(&db).await?;

    let err = f
        .store
        .finalize_attempt_artifact(AttemptFinalization {
            attempt_id: SessionAttemptId::new(),
            artifact_name: "report".to_owned(),
            artifact_id: ArtifactId::new(),
            run_id: f.run,
            node_id: WorkflowNodeId::new(),
            checksum: checksum_of(b"body"),
            payload_fingerprint: [0xF2; 32],
            content_generation: ContentGeneration::new(),
        })
        .await
        .expect_err("an unknown attempt must be refused");
    assert_failure(&err, FailureKind::Conflict, "ATTEMPT_NOT_FOUND")?;
    Ok(())
}

/// The change-set revalidation the Rust port adds: a caller claiming
/// run/node coordinates that disagree with the durable attempt row is
/// `PRODUCER_CHAIN_MISMATCH` — the same closed verdict the
/// artifact-side producer chain gets.
#[tokio::test]
async fn finalize_attempt_artifact_rejects_stale_run_node_claim() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "stale_claim").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-stale",
        checksum_of(b"finalized body producer-stale"),
    )
    .await?;

    let mut bad = change(&f, &target, "report")?;
    bad.node_id = WorkflowNodeId::new();
    let err = f
        .store
        .finalize_attempt_artifact(bad)
        .await
        .expect_err("a stale node claim must be refused");
    assert_failure(&err, FailureKind::Denied, "PRODUCER_CHAIN_MISMATCH")?;
    let rows = count_rows_for(
        &mut f,
        "SELECT COUNT(*) FROM central.artifact_finalizations WHERE attempt_id = $1",
        uuid_of!(target.attempt_id),
    )
    .await?;
    if rows != 0 {
        return Err(Failure::internal(
            "test_assert",
            "finalization rows != 0 (rolled back)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RTM-14: the visibility boundary is the read gate
// ---------------------------------------------------------------------------

/// A read of the artifact before the boundary lands is refused
/// `ARTIFACT_NOT_FINALIZED`; after `finalize_attempt_artifact`
/// commits, the same read authorizes and resolves through
/// `resolve_produced`.
#[tokio::test]
async fn premature_read_is_refused_not_finalized() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "premature").await?;
    let mut f = setup_fixture(&db).await?;
    let target = finalize_target(
        &mut f,
        "producer-rtm14",
        checksum_of(b"finalized body rtm14"),
    )
    .await?;

    let request = ReadRequest {
        scope: ReadScope::Operator,
        selector: ReadSelector::ByArtifactId(target.artifact_id),
    };
    let err = authorize_read(Some(&f.store), request.clone())
        .await
        .expect_err("a verifying artifact must not be readable");
    if err.code() != "ARTIFACT_NOT_FINALIZED" {
        return Err(Failure::internal(
            "test_assert",
            format!(
                "premature read = {:?}, want ARTIFACT_NOT_FINALIZED",
                err.code()
            ),
        ));
    }

    f.store
        .finalize_attempt_artifact(change(&f, &target, "report")?)
        .await?;
    let authorization = authorize_read(Some(&f.store), request).await?;
    if authorization.artifact.state != State::Ready {
        return Err(Failure::internal(
            "test_assert",
            "the finalized artifact must authorize",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Lineage projections over the journaled edges (b34)
// ---------------------------------------------------------------------------

/// Finalizes two artifacts where the second node's attempt reads the
/// first's, then walks the projections the edges support:
/// `ancestors`/`descendants`/`run_lineage_for_run` over the real
/// b34 rows.
#[tokio::test]
async fn lineage_projections_over_journaled_edges() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "projections").await?;
    let mut f = setup_fixture(&db).await?;

    let upstream = finalize_target(&mut f, "producer-up", checksum_of(b"upstream body")).await?;
    let downstream =
        finalize_target(&mut f, "producer-down", checksum_of(b"downstream body")).await?;
    f.store
        .finalize_attempt_artifact(change(&f, &upstream, "report")?)
        .await?;
    f.store
        .finalize_attempt_artifact(change(&f, &downstream, "report")?)
        .await?;

    // The downstream attempt's read of the upstream artifact journals
    // the read edge the walks traverse (declared: the graph edge was
    // declared in the node spec).
    use central_artifact::lineage::ReadEdge;
    use central_foundation::identity::ReadEdgeId;
    f.store
        .insert_read_edge(ReadEdge {
            id: ReadEdgeId::new(),
            run_id: f.run,
            reader_node_id: Some(downstream.node_id),
            attempt_id: Some(downstream.attempt_id),
            artifact_id: upstream.artifact_id,
            declared: true,
            checksum: upstream
                .checksum
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .await?;

    // `ancestors` is a BFS that pushes each visited artifact's own
    // produce edge, then recurses through the producing node's reads:
    // upstream's closure is just its own edge; downstream's is its own
    // edge plus upstream's (discovered through the journaled read).
    let up_ancestors = ancestors(&f.store, upstream.artifact_id).await?;
    if up_ancestors.len() != 1 || up_ancestors[0].artifact_id != upstream.artifact_id {
        return Err(Failure::internal(
            "test_assert",
            "upstream ancestors must be its own produce edge only",
        ));
    }
    let down_ancestors = ancestors(&f.store, downstream.artifact_id).await?;
    if down_ancestors.len() != 2
        || down_ancestors[0].artifact_id != downstream.artifact_id
        || down_ancestors[1].artifact_id != upstream.artifact_id
    {
        return Err(Failure::internal(
            "test_assert",
            "downstream ancestors must close over the upstream produce edge",
        ));
    }
    let down_descendants = descendants(&f.store, downstream.artifact_id).await?;
    if !down_descendants.is_empty() {
        return Err(Failure::internal(
            "test_assert",
            "nothing read the downstream artifact",
        ));
    }
    let up_descendants = descendants(&f.store, upstream.artifact_id).await?;
    if up_descendants.len() != 1 || up_descendants[0].artifact_id != downstream.artifact_id {
        return Err(Failure::internal(
            "test_assert",
            "upstream descendants must name the downstream produce edge",
        ));
    }

    let run_lineage = run_lineage_for_run(&f.store, f.run).await?;
    if run_lineage.produced.len() != 2 || run_lineage.read.len() != 1 {
        return Err(Failure::internal(
            "test_assert",
            "run lineage must carry both produce edges and the read edge",
        ));
    }
    Ok(())
}
