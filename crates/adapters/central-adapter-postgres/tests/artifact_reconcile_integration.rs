//! PostgreSQL integration tests for the B10 `ReconciliationStore`
//! (`artifact/reconcile.rs`) — the port of upstream
//! `reconcile_store_test.go` plus the `store_test.go` claim/progress
//! cases — and the `explain_test.go` index-plan assertions.
//!
//! Covered: the round-robin workspace cursor, the bounded
//! unparseable-workspace skip walk (64/call), claim fencing by
//! `sha256(claim_token)`, database-clock staging expiry, the
//! large-claim lifecycle under the SB-G4 `UPDATE` demotion
//! (`central_runtime` holds `SELECT, INSERT, UPDATE` — no `DELETE` —
//! on `central.artifact_reconciliation_claims`), rejected-staging
//! cleanup, and progress journaling.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `artifact_store_integration.rs`: a superuser DSN on a scratch
//! cluster whose `central_migration` / `central_runtime` roles exist.
//! Fixture inserts and assertion reads run under `central_migration`
//! (owner); every `ReconciliationStore` call runs under
//! `central_runtime`, the production role, which is what proves the
//! demotion works without the `DELETE` grant.

use central_adapter_postgres::artifact::Store;
use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_artifact::domain::{self, Artifact, Limits, OutcomeKind, State};
use central_artifact::port::{
    ClaimIncompleteRequest, ClaimIncompleteResult, ClaimLargeRequest, ClaimRejectedStagingRequest,
    ClearStagingKeyRequest, ExpireStagingRequest, ReconciliationCursor, ReconciliationProgress,
    ReconciliationStore, RecordLargeClaimRequest, ReleaseLargeClaimRequest, Store as ArtifactStore,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, RunId, StagingGeneration, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use std::time::Duration;
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
    let db = format!("artifact_reconcile_test_{label}_{}", std::process::id());
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

fn checksum_of(body: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(body).into()
}

/// `claimToken` — a distinct 32-byte coordinator claim token per seed.
fn claim_token(seed: u8) -> Vec<u8> {
    let mut token = vec![0u8; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    token
}

/// The `zero` cursor a first sweep starts from — nil identities plus
/// the zero-instant sentinel `UNIX_EPOCH` the adapter binds as NULL.
fn zero_cursor() -> ReconciliationCursor {
    ReconciliationCursor {
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        created_at: OffsetDateTime::UNIX_EPOCH,
        artifact_id: ArtifactId::from_trusted_db_bytes([0; 16]),
    }
}

/// `fixture` — one Workspace with a running Task/Run plus a Step /
/// StepAttempt ownership chain the reserve command persists; mirrors
/// upstream `testhelper_test.go`'s `setupFixture`. Reconciliation
/// commands fence on `artifact_reconciliation_claims` only — no B08
/// execution lease participates, so none is seeded.
struct Fixture {
    /// The store under `central_runtime` — the production role.
    store: Store,
    /// Owner connection for fixture writes and assertions.
    conn: PgConnection,

    ws: WorkspaceId,
    task: TaskId,
    run: RunId,
    step: StepId,
    attempt: StepAttemptId,
    producer: String,
}

async fn setup_fixture(db: &str, quota_max_bytes: i64) -> Result<Fixture> {
    let runtime_pool = role_pool(db, "central_runtime").await?;
    let mut conn = role_conn(db, "central_migration").await?;

    let ws = WorkspaceId::new();
    let task_id = TaskId::new();
    let run_id = RunId::new();
    let step_id = StepId::new();
    let attempt_id = StepAttemptId::new();

    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', 'integration-test', $2)",
    )
    .bind(uuid_of!(ws))
    .bind(quota_max_bytes)
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)")
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
    sqlx::query(
        "INSERT INTO central.steps (id, workspace_id, task_id, run_id, version, state, \
         logical_operation_id, sequence) \
         VALUES ($1, $2, $3, $4, 1, 'settling', $5, 1)",
    )
    .bind(uuid_of!(step_id))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task_id))
    .bind(uuid_of!(run_id))
    .bind(uuid::Uuid::now_v7())
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.step_attempts (id, workspace_id, step_id, task_id, run_id, \
         version, logical_operation_id, physical_attempt_id, invocation_id, \
         invocation_generation, sequence, state) \
         VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8, 1, 1, 'settling')",
    )
    .bind(uuid_of!(attempt_id))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(step_id))
    .bind(uuid_of!(task_id))
    .bind(uuid_of!(run_id))
    .bind(uuid::Uuid::now_v7())
    .bind(uuid::Uuid::now_v7())
    .bind(uuid::Uuid::now_v7())
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    Ok(Fixture {
        store: Store::new(runtime_pool),
        conn,
        ws,
        task: task_id,
        run: run_id,
        step: step_id,
        attempt: attempt_id,
        producer: "test-producer".to_owned(),
    })
}

impl Fixture {
    /// Runs the pure domain Reserve and persists it — the durable
    /// result. `idempotency_key` mirrors upstream's `"reserve-<fresh>"`
    /// caller key convention.
    async fn reserve_artifact(
        &self,
        max_bytes: i64,
        idempotency_key: &str,
    ) -> Result<domain::ReserveResult> {
        let pure = domain::reserve(&domain::ReserveInput {
            workspace_id: self.ws,
            artifact_id: ArtifactId::new(),
            staging_generation: StagingGeneration::new(),
            limits: Limits { max_bytes },
            idempotency_key,
            task_id: self.task,
            run_id: self.run,
            step_id: self.step,
            step_attempt_id: self.attempt,
            tool_call_attempt_id: None,
            producer_id: &self.producer,
            required_role: "report",
        })?;
        self.store.reserve_artifact(pure).await
    }

    /// `advanceToStaging` — Reserve -> BeginUpload so the record sits
    /// in staging with a live capacity reservation.
    async fn advance_to_staging(&self, max_bytes: i64) -> Result<Artifact> {
        let reserved = self
            .reserve_artifact(max_bytes, &format!("reserve-{}", ArtifactId::new()))
            .await?;
        let begin_pure = domain::begin_upload(&domain::BeginUploadInput {
            workspace_id: self.ws,
            artifact_id: reserved.artifact.artifact_id,
            expected: reserved.artifact.version,
            current: reserved.artifact,
        })?;
        Ok(self.store.record_begin_upload(begin_pure).await?.artifact)
    }

    /// `advanceToVerifying` — Reserve -> BeginUpload -> Verify
    /// (accepted) against `self.store`.
    async fn advance_to_verifying(
        &self,
        max_bytes: i64,
        size: i64,
        checksum: [u8; 32],
    ) -> Result<Artifact> {
        let staged = self.advance_to_staging(max_bytes).await?;
        let verify_pure = domain::verified(&domain::VerifiedInput {
            workspace_id: self.ws,
            artifact_id: staged.artifact_id,
            expected: staged.version,
            current: staged,
            size,
            checksum,
            secret_disclosure: false,
            rejection_code: "",
        })?;
        let verified = self.store.record_verification(verify_pure).await?;
        if verified.artifact.state != State::Verifying {
            return Err(Failure::internal(
                "test_fixture",
                "expected verifying state after accepted verify",
            ));
        }
        Ok(verified.artifact)
    }

    /// `claimForReconciliation` — one real `claim_incomplete` pass so
    /// the Artifact has an authentic active claim row under `token`.
    async fn claim_for_reconciliation(&self, token: &[u8]) -> Result<()> {
        self.store
            .claim_incomplete(ClaimIncompleteRequest {
                cursor: zero_cursor(),
                batch_size: 50,
                claim_token: token.to_vec(),
                lease_duration: Duration::from_secs(300),
                coordinator_generation: 1,
            })
            .await?;
        Ok(())
    }

    /// `backdateArtifact` — rewrites `created_at` so the record has
    /// genuinely outlived the lifetime the expiry query compares
    /// against database time.
    async fn backdate_artifact(&mut self, id: ArtifactId, age: Duration) -> Result<()> {
        sqlx::query(
            "UPDATE central.artifacts \
             SET created_at = clock_timestamp() - make_interval(secs => $3::double precision) \
             WHERE workspace_id = $1 AND id = $2",
        )
        .bind(uuid_of!(self.ws))
        .bind(uuid_of!(id))
        .bind(age.as_secs_f64())
        .execute(&mut self.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

async fn artifact_state(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    id: ArtifactId,
) -> Result<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT state FROM central.artifacts WHERE workspace_id = $1 AND id = $2",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(id))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

async fn capacity_state(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    id: ArtifactId,
) -> Result<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT state FROM central.capacity_reservations \
         WHERE workspace_id = $1 AND artifact_id = $2",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(id))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

async fn rejection_code(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    id: ArtifactId,
) -> Result<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(rejection ->> 'code', '') FROM central.artifacts \
         WHERE workspace_id = $1 AND id = $2",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(id))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

async fn claim_kind(conn: &mut PgConnection, ws: WorkspaceId, id: ArtifactId) -> Result<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT claim_kind FROM central.artifact_reconciliation_claims \
         WHERE workspace_id = $1 AND artifact_id = $2",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(id))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

async fn claim_row_count(conn: &mut PgConnection, ws: WorkspaceId, id: ArtifactId) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM central.artifact_reconciliation_claims \
         WHERE workspace_id = $1 AND artifact_id = $2",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(id))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

async fn receipt_count(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    id: ArtifactId,
    kind: &str,
) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM central.artifact_command_receipts \
         WHERE workspace_id = $1 AND artifact_id = $2 AND command_kind = $3",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(id))
    .bind(kind)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

fn contains_claim(result: &ClaimIncompleteResult, id: ArtifactId) -> bool {
    result.claims.iter().any(|claim| claim.artifact_id == id)
}

// ---------------------------------------------------------------------------
// ClaimIncomplete / claim fencing
// ---------------------------------------------------------------------------

/// Upstream `TestClaimRejectsStaleFence`: a second claimant under a
/// different token must not take the artifact or overwrite the active
/// claim's stored hash.
#[tokio::test]
async fn claim_rejects_stale_fence() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "stale_fence").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let reserved = f.reserve_artifact(1 << 10, "reserve-claim").await?;

    let token_a = claim_token(11);
    let first = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: token_a.clone(),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if !contains_claim(&first, reserved.artifact.artifact_id) {
        return Err(Failure::internal(
            "test_assert",
            "expected the first claim to include the reserved artifact",
        ));
    }

    let second = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(22),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if contains_claim(&second, reserved.artifact.artifact_id) {
        return Err(Failure::internal(
            "test_assert",
            "a second claimant must not claim an artifact under an active lease",
        ));
    }

    let stored_hash = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT claim_token_hash FROM central.artifact_reconciliation_claims \
         WHERE workspace_id = $1 AND artifact_id = $2",
    )
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(reserved.artifact.artifact_id))
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let want_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(&token_a)
    };
    if stored_hash != want_hash.as_slice() {
        return Err(Failure::internal(
            "test_assert",
            "stale claimant overwrote the active claim's token hash",
        ));
    }
    Ok(())
}

/// Upstream `TestClaimLargeSchedulesDedicatedClaim`: an elapsed
/// dedicated claim row is picked up once, then fenced by its new lease.
#[tokio::test]
async fn claim_large_schedules_dedicated_claim() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "claim_large").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let reserved = f.advance_to_staging(1 << 10).await?;

    sqlx::query(
        "INSERT INTO central.artifact_reconciliation_claims (\
         artifact_id, workspace_id, claim_kind, coordinator_generation, \
         claim_token_hash, lease_expires_at) \
         VALUES ($1, $2, 'large', 1, $3, now() - interval '1 minute')",
    )
    .bind(uuid_of!(reserved.artifact_id))
    .bind(uuid_of!(f.ws))
    .bind(b"seed".as_slice())
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let claim = f
        .store
        .claim_large(ClaimLargeRequest {
            claim_token: claim_token(29),
            lease_duration: Duration::from_secs(60),
        })
        .await?;
    let Some(claim) = claim else {
        return Err(Failure::internal(
            "test_assert",
            "expected an eligible large claim",
        ));
    };
    if claim.artifact_id != reserved.artifact_id {
        return Err(Failure::internal(
            "test_assert",
            "large claim named a different artifact",
        ));
    }

    let none = f
        .store
        .claim_large(ClaimLargeRequest {
            claim_token: claim_token(30),
            lease_duration: Duration::from_secs(60),
        })
        .await?;
    if none.is_some() {
        return Err(Failure::internal(
            "test_assert",
            "expected no eligible large claim while the lease is still active",
        ));
    }
    Ok(())
}

/// Upstream `TestRecordProgressPersistsCursor`: the singleton progress
/// row carries the cursor and cycle forward.
#[tokio::test]
async fn record_progress_persists_cursor() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "progress").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;

    let cursor = ReconciliationCursor {
        workspace_id: WorkspaceId::new(),
        created_at: OffsetDateTime::now_utc(),
        artifact_id: ArtifactId::new(),
    };
    f.store
        .record_progress(ReconciliationProgress {
            cursor,
            processed_count: 0,
            cycle: 3,
        })
        .await?;

    let (got_ws, got_artifact, got_cycle) = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid, i64)>(
        "SELECT cursor_workspace_id, cursor_artifact_id, cycle \
         FROM central.artifact_reconciliation_progress WHERE singleton = true",
    )
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    if got_ws != uuid_of!(cursor.workspace_id)
        || got_artifact != uuid_of!(cursor.artifact_id)
        || got_cycle != 3
    {
        return Err(Failure::internal(
            "test_assert",
            "reconciliation progress mismatch",
        ));
    }
    Ok(())
}

/// The round-robin contract: each `claim_incomplete` call targets one
/// workspace; once that workspace's backlog is drained past the cursor,
/// the next call walks forward to the next workspace in `uuid` order —
/// never stranding a sorting-behind workspace. Order-agnostic: the test
/// asserts relative progression, not which id happens to sort first.
#[tokio::test]
async fn claim_incomplete_round_robins_workspaces() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "round_robin").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let first = f.advance_to_staging(1 << 10).await?;

    // A second workspace with its own incomplete artifact; its sort
    // position relative to the fixture's is immaterial to the contract.
    let ws2 = WorkspaceId::new();
    let task2 = TaskId::new();
    let run2 = RunId::new();
    let artifact2 = ArtifactId::new();
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', 'integration-test', $2)",
    )
    .bind(uuid_of!(ws2))
    .bind(10_i64 << 20)
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'integration', '{}'::jsonb)",
    )
    .bind(uuid_of!(task2))
    .bind(uuid_of!(ws2))
    .bind(uuid_of!(run2))
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(run2))
    .bind(uuid_of!(ws2))
    .bind(uuid_of!(task2))
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.artifacts (id, workspace_id, task_id, run_id, version, state, \
         staging_generation, object_key, sensitivity, disposition, created_at) \
         VALUES ($1, $2, $3, $4, 1, 'reserved', $5, 'round-robin-object', 'unrestricted', \
         'inline', clock_timestamp())",
    )
    .bind(uuid_of!(artifact2))
    .bind(uuid_of!(ws2))
    .bind(uuid_of!(task2))
    .bind(uuid_of!(run2))
    .bind(uuid::Uuid::now_v7())
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    // First sweep: claims the workspace that sorts first, whichever
    // that is, and returns a cursor pinned inside it.
    let sweep1 = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(40),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if sweep1.claims.len() != 1 {
        return Err(Failure::internal(
            "test_assert",
            "first sweep must claim exactly one workspace's single artifact",
        ));
    }
    let claimed_ws = sweep1.claims[0].workspace_id;
    let claimed_id = sweep1.claims[0].artifact_id;
    let other_ws = if claimed_ws == f.ws { ws2 } else { f.ws };
    let other_id = if claimed_id == first.artifact_id {
        artifact2
    } else {
        first.artifact_id
    };
    if sweep1.next_cursor.workspace_id != claimed_ws {
        return Err(Failure::internal(
            "test_assert",
            "next cursor must stay inside the claimed workspace",
        ));
    }

    // Second sweep from the returned cursor: the claimed workspace's
    // remaining backlog is empty at/after the cursor (its one artifact
    // is leased, not scanned-away — but the workspace resolver re-picks
    // it only when incomplete rows exist past the cursor; the leased
    // row is still incomplete-state and sorts at the cursor, not after
    // it), so the walk lands on the other workspace's artifact.
    let sweep2 = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: sweep1.next_cursor,
            batch_size: 10,
            claim_token: claim_token(41),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if sweep2.claims.len() != 1
        || sweep2.claims[0].workspace_id != other_ws
        || sweep2.claims[0].artifact_id != other_id
    {
        return Err(Failure::internal(
            "test_assert",
            "second sweep must round-robin to the other workspace's artifact",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy non-UUIDv7 workspace skip walk (upstream store_test.go)
// ---------------------------------------------------------------------------

/// `seedLegacyIncompleteWorkspaceID` — a Workspace whose ID is not a
/// UUIDv7 plus one incomplete Artifact, so it appears in the
/// reconciliation resolver's candidate order. The all-zero leading
/// bytes sort it ahead of every UUIDv7 workspace (Postgres orders
/// `uuid` bytewise).
async fn seed_legacy_incomplete_workspace(
    conn: &mut PgConnection,
    workspace_id: uuid::Uuid,
) -> Result<()> {
    let task = TaskId::new();
    let run = RunId::new();
    let art = ArtifactId::new();

    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
         VALUES ($1, 'active', 'legacy-test', $2)",
    )
    .bind(workspace_id)
    .bind(10_i64 << 20)
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)")
        .bind(workspace_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'legacy', '{}'::jsonb)",
    )
    .bind(uuid_of!(task))
    .bind(workspace_id)
    .bind(uuid_of!(run))
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(run))
    .bind(workspace_id)
    .bind(uuid_of!(task))
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.artifacts (id, workspace_id, task_id, run_id, state, \
         staging_generation, object_key, sensitivity, disposition, created_at) \
         VALUES ($1, $2, $3, $4, 'reserved', $5, 'legacy-object-key', 'unrestricted', \
         'inline', now() - interval '1 hour')",
    )
    .bind(uuid_of!(art))
    .bind(workspace_id)
    .bind(uuid_of!(task))
    .bind(uuid_of!(run))
    .bind(uuid::Uuid::now_v7())
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// Upstream `TestClaimIncompleteSkipsLegacyNonUUIDv7Workspace`: an
/// unparseable workspace that sorts ahead of a valid one is skipped —
/// recorded, not silent — and never starves the workspace behind it.
#[tokio::test]
async fn claim_incomplete_skips_legacy_non_uuidv7_workspace() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "legacy_skip").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    seed_legacy_incomplete_workspace(
        &mut f.conn,
        uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001")
            .map_err(|e| Failure::internal("test_fixture", e.to_string()))?,
    )
    .await?;
    let reserved = f.reserve_artifact(1 << 10, "reserve-legacy-skip").await?;

    let result = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(60),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if !contains_claim(&result, reserved.artifact.artifact_id) {
        return Err(Failure::internal(
            "test_assert",
            "the valid workspace behind the legacy one was starved",
        ));
    }
    if result.skipped_workspaces != 1 {
        return Err(Failure::internal(
            "test_assert",
            "the skip must be recorded, not silent",
        ));
    }
    if result.skip_budget_exhausted {
        return Err(Failure::internal(
            "test_assert",
            "a walk that reached a valid workspace must not report an exhausted skip budget",
        ));
    }
    Ok(())
}

/// Upstream `TestClaimIncompleteReportsAnExhaustedSkipBudget`: one more
/// unparseable workspace than the walk's budget — the pass gives up,
/// reports the full 64 skips and flags the give-up so an operator can
/// tell it apart from an empty backlog.
#[tokio::test]
async fn claim_incomplete_reports_an_exhausted_skip_budget() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "skip_budget").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    for index in 1..=65_u32 {
        seed_legacy_incomplete_workspace(
            &mut f.conn,
            uuid::Uuid::parse_str(&format!("00000000-0000-4000-8000-{index:012}"))
                .map_err(|e| Failure::internal("test_fixture", e.to_string()))?,
        )
        .await?;
    }
    f.reserve_artifact(1 << 10, "reserve-skip-budget").await?;

    let result = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(61),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if !result.claims.is_empty() {
        return Err(Failure::internal(
            "test_assert",
            "the walk cannot reach a valid workspace within its budget",
        ));
    }
    if result.skipped_workspaces != 64 {
        return Err(Failure::internal(
            "test_assert",
            "skipped count must be the full budget of 64",
        ));
    }
    if !result.skip_budget_exhausted {
        return Err(Failure::internal(
            "test_assert",
            "an exhausted skip budget must be reported",
        ));
    }
    Ok(())
}

/// Upstream `TestClaimIncompleteRecordsCallersCoordinatorGeneration`:
/// the claim row's `coordinator_generation` carries the calling pass's
/// real fencing generation, never a placeholder.
#[tokio::test]
async fn claim_incomplete_records_callers_coordinator_generation() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "generation").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let reserved = f.reserve_artifact(1 << 10, "reserve-generation").await?;

    let generation: i64 = 7;
    let result = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(62),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: generation,
        })
        .await?;
    if !contains_claim(&result, reserved.artifact.artifact_id) {
        return Err(Failure::internal(
            "test_assert",
            "expected the reserved artifact to be claimed",
        ));
    }

    let stored = sqlx::query_scalar::<_, i64>(
        "SELECT coordinator_generation FROM central.artifact_reconciliation_claims \
         WHERE workspace_id = $1 AND artifact_id = $2",
    )
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(reserved.artifact.artifact_id))
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    if stored != generation {
        return Err(Failure::internal(
            "test_assert",
            "coordinator_generation was not the caller's real fence",
        ));
    }
    Ok(())
}

/// Upstream `TestClaimIncompleteRejectsMissingCoordinatorGeneration`:
/// a claim request with no real fencing generation fails closed.
#[tokio::test]
async fn claim_incomplete_rejects_missing_coordinator_generation() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "generation_missing").await?;
    let f = setup_fixture(&db, 10 << 20).await?;
    f.reserve_artifact(1 << 10, "reserve-generation-missing")
        .await?;

    let err = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(63),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 0,
        })
        .await;
    if err.is_ok() {
        return Err(Failure::internal(
            "test_assert",
            "a request with no coordinator fencing generation must fail closed",
        ));
    }
    Ok(())
}

/// Upstream `TestClaimIncompleteReportsDatabaseDerivedObservationTime`:
/// backlog ages are measured against `observed_at` — database-derived —
/// so a backdated record's measured age approximates the backdate.
#[tokio::test]
async fn claim_incomplete_reports_database_derived_observation_time() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "observed_at").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    f.backdate_artifact(staged.artifact_id, Duration::from_secs(3 * 3600))
        .await?;

    let result = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 50,
            claim_token: claim_token(64),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 1,
        })
        .await?;
    if result.observed_at == OffsetDateTime::UNIX_EPOCH {
        return Err(Failure::internal(
            "test_assert",
            "claims carried no database-derived observation time",
        ));
    }
    for claim in &result.claims {
        if claim.artifact_id != staged.artifact_id {
            continue;
        }
        let age = result.observed_at - claim.created_at;
        let three_hours = time::Duration::hours(3);
        let four_hours = time::Duration::hours(4);
        if age < three_hours || age > four_hours {
            return Err(Failure::internal(
                "test_assert",
                "measured backlog age must approximate the backdated 3h",
            ));
        }
        return Ok(());
    }
    Err(Failure::internal(
        "test_assert",
        "the backdated record was not claimed at all",
    ))
}

// ---------------------------------------------------------------------------
// RecordLargeClaim / ClaimLarge demotion lifecycle (C2 + SB-G4)
// ---------------------------------------------------------------------------

/// Upstream `TestRecordLargeClaimIsIdempotentAndLeavesTheClaimImmediatelyEligible`.
#[tokio::test]
async fn record_large_claim_is_idempotent_and_immediately_eligible() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "record_large").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    let token = claim_token(11);
    f.claim_for_reconciliation(&token).await?;

    let request = RecordLargeClaimRequest {
        workspace_id: f.ws,
        artifact_id: staged.artifact_id,
        expected_version: staged.version,
        coordinator_generation: 7,
        claim_token: token,
    };
    f.store.record_large_claim(request.clone()).await?;
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "large" {
        return Err(Failure::internal("test_assert", "claim kind must be large"));
    }
    if claim_row_count(&mut f.conn, f.ws, staged.artifact_id).await? != 1 {
        return Err(Failure::internal(
            "test_assert",
            "expected exactly one claim row",
        ));
    }

    // Re-declaring the same deferral is an idempotent success: one row,
    // still large.
    f.store.record_large_claim(request).await?;
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "large"
        || claim_row_count(&mut f.conn, f.ws, staged.artifact_id).await? != 1
    {
        return Err(Failure::internal(
            "test_assert",
            "repeated record must not duplicate the row",
        ));
    }

    // The deferring pass is not doing the work, so the recorded claim
    // is immediately eligible for the dedicated large pass.
    let claim = f
        .store
        .claim_large(ClaimLargeRequest {
            claim_token: claim_token(29),
            lease_duration: Duration::from_secs(900),
        })
        .await?;
    match claim {
        Some(claim) if claim.artifact_id == staged.artifact_id => Ok(()),
        other => Err(Failure::internal(
            "test_assert",
            format!("expected the deferred artifact's large claim, got {other:?}"),
        )),
    }
}

/// Upstream `TestRecordLargeClaimIsANonMutatingConflictForAStaleFenceOrVersion`.
#[tokio::test]
async fn record_large_claim_is_a_non_mutating_conflict_for_stale_fence_or_version() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "record_large_stale").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    let token = claim_token(11);
    f.claim_for_reconciliation(&token).await?;

    // A superseded coordinator holding a different token changes nothing.
    f.store
        .record_large_claim(RecordLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            coordinator_generation: 7,
            claim_token: claim_token(99),
        })
        .await?;
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "normal" {
        return Err(Failure::internal(
            "test_assert",
            "a stale fence must be a non-mutating conflict",
        ));
    }

    // A record that moved under the claim likewise changes nothing.
    f.store
        .record_large_claim(RecordLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version + 3,
            coordinator_generation: 7,
            claim_token: token,
        })
        .await?;
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "normal" {
        return Err(Failure::internal(
            "test_assert",
            "a moved version must be a non-mutating conflict",
        ));
    }

    // An unfenced request fails closed before touching anything.
    let err = f
        .store
        .record_large_claim(RecordLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            coordinator_generation: 0,
            claim_token: claim_token(11),
        })
        .await;
    if err.is_ok() {
        return Err(Failure::internal(
            "test_assert",
            "expected an invalid-claim failure for a zero coordinator generation",
        ));
    }
    Ok(())
}

/// Upstream `TestClaimLargeSkipsAndClearsAResolvedClaim` — the C2
/// regression — adapted for the SB-G4 fix: `central_runtime` holds no
/// `DELETE` on `artifact_reconciliation_claims`, so the resolved row
/// is *demoted* to `claim_kind = 'normal'` with an elapsed lease
/// rather than removed. `claim_large` can never re-select it; the
/// normal cursor still owns the (terminal) record.
#[tokio::test]
async fn claim_large_demotes_a_resolved_claim() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "demote_resolved").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    let token = claim_token(41);
    f.claim_for_reconciliation(&token).await?;

    f.store
        .record_large_claim(RecordLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            coordinator_generation: 7,
            claim_token: token,
        })
        .await?;
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "large" {
        return Err(Failure::internal("test_assert", "claim kind must be large"));
    }

    // The artifact resolves by any path — here, a durable rejection.
    sqlx::query(
        "UPDATE central.artifacts SET state = 'rejected' WHERE workspace_id = $1 AND id = $2",
    )
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(staged.artifact_id))
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let claim = f
        .store
        .claim_large(ClaimLargeRequest {
            claim_token: claim_token(43),
            lease_duration: Duration::from_secs(900),
        })
        .await?;
    if claim.is_some() {
        return Err(Failure::internal(
            "test_assert",
            "a resolved artifact's large claim was re-claimed",
        ));
    }
    // SB-G4: the stale row is demoted — not deleted — so it can never
    // be re-selected by the dedicated pass.
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "normal" {
        return Err(Failure::internal(
            "test_assert",
            "a resolved large claim must be demoted to normal",
        ));
    }
    Ok(())
}

/// Upstream `TestReleaseLargeClaimIsIdempotentAndRemovesTheRow` — SB-G4
/// adapted: release demotes (never deletes) the row; the dedicated
/// pass can never re-select it, and the still-incomplete artifact is
/// re-observed and re-deferred by the normal cursor on the next sweep.
#[tokio::test]
async fn release_large_claim_is_idempotent_and_demotes_the_row() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "release_large").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    let token = claim_token(45);
    f.claim_for_reconciliation(&token).await?;
    f.store
        .record_large_claim(RecordLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            coordinator_generation: 7,
            claim_token: token.clone(),
        })
        .await?;

    let request = ReleaseLargeClaimRequest {
        workspace_id: f.ws,
        artifact_id: staged.artifact_id,
        claim_token: token,
    };
    f.store.release_large_claim(request.clone()).await?;
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "normal" {
        return Err(Failure::internal(
            "test_assert",
            "a released large claim must be demoted to normal",
        ));
    }

    // Releasing an already-demoted claim is a success, never an error.
    f.store.release_large_claim(request).await?;

    let claim = f
        .store
        .claim_large(ClaimLargeRequest {
            claim_token: claim_token(47),
            lease_duration: Duration::from_secs(900),
        })
        .await?;
    if claim.is_some() {
        return Err(Failure::internal(
            "test_assert",
            "a released claim was still claimable",
        ));
    }

    // The demoted row's lease already elapsed, so the normal cursor
    // re-observes the still-incomplete artifact and re-defers it.
    let sweep = f
        .store
        .claim_incomplete(ClaimIncompleteRequest {
            cursor: zero_cursor(),
            batch_size: 10,
            claim_token: claim_token(48),
            lease_duration: Duration::from_secs(60),
            coordinator_generation: 2,
        })
        .await?;
    if !contains_claim(&sweep, staged.artifact_id) {
        return Err(Failure::internal(
            "test_assert",
            "the normal cursor must re-observe a released still-incomplete artifact",
        ));
    }
    if claim_kind(&mut f.conn, f.ws, staged.artifact_id).await? != "normal" {
        return Err(Failure::internal(
            "test_assert",
            "the re-observed claim must stay the normal kind",
        ));
    }
    Ok(())
}

/// Upstream `TestReleaseLargeClaimFailsClosedOnAnIncompleteRequest`.
#[tokio::test]
async fn release_large_claim_fails_closed_on_an_incomplete_request() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "release_closed").await?;
    let f = setup_fixture(&db, 100 << 20).await?;

    let nil_ws = WorkspaceId::from_trusted_db_bytes([0; 16]);
    let nil_art = ArtifactId::from_trusted_db_bytes([0; 16]);
    for request in [
        ReleaseLargeClaimRequest {
            workspace_id: nil_ws,
            artifact_id: ArtifactId::new(),
            claim_token: claim_token(1),
        },
        ReleaseLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: nil_art,
            claim_token: claim_token(1),
        },
        ReleaseLargeClaimRequest {
            workspace_id: f.ws,
            artifact_id: ArtifactId::new(),
            claim_token: Vec::new(),
        },
    ] {
        if f.store.release_large_claim(request).await.is_ok() {
            return Err(Failure::internal(
                "test_assert",
                "an incomplete release request must fail closed",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ExpireStaging
// ---------------------------------------------------------------------------

/// Upstream `TestExpireStagingUsesDatabaseTimeAndReleasesCapacityExactlyOnce`.
#[tokio::test]
async fn expire_staging_uses_database_time_and_releases_capacity_exactly_once() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "expire_dbtime").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    let token = claim_token(11);
    f.claim_for_reconciliation(&token).await?;

    let request = ExpireStagingRequest {
        workspace_id: f.ws,
        artifact_id: staged.artifact_id,
        expected_version: staged.version,
        claim_token: token,
        lifetime: Duration::from_secs(24 * 3600),
    };

    // Freshly created: inside the lifetime on the database's own clock.
    let result = f.store.expire_staging(request.clone()).await?;
    if result.expired {
        return Err(Failure::internal(
            "test_assert",
            "a record inside the installed lifetime must never expire",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, staged.artifact_id).await? != "staging"
        || capacity_state(&mut f.conn, f.ws, staged.artifact_id).await? != "reserved"
    {
        return Err(Failure::internal(
            "test_assert",
            "pre-expiry durable state moved",
        ));
    }

    // Backdate past the lifetime: the same call expires it.
    f.backdate_artifact(staged.artifact_id, Duration::from_secs(25 * 3600))
        .await?;
    let result = f.store.expire_staging(request.clone()).await?;
    if !result.expired {
        return Err(Failure::internal(
            "test_assert",
            "a record past the installed lifetime must expire",
        ));
    }
    if result.outcome.kind != OutcomeKind::Retryable
        || result.outcome.failure_code != domain::FAILURE_CODE_STAGING_EXPIRED
    {
        return Err(Failure::internal(
            "test_assert",
            "expiry outcome must be retryable STAGING_LIFETIME_EXPIRED",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, staged.artifact_id).await? != "rejected"
        || capacity_state(&mut f.conn, f.ws, staged.artifact_id).await? != "released"
        || rejection_code(&mut f.conn, f.ws, staged.artifact_id).await?
            != domain::FAILURE_CODE_STAGING_EXPIRED
    {
        return Err(Failure::internal(
            "test_assert",
            "post-expiry durable state wrong",
        ));
    }

    // A second sweep is a non-mutating no-op: the state guard means
    // capacity is never released twice.
    let again = f.store.expire_staging(request).await?;
    if again.expired {
        return Err(Failure::internal(
            "test_assert",
            "an already-rejected record must not expire a second time",
        ));
    }
    if receipt_count(&mut f.conn, f.ws, staged.artifact_id, "reject").await? != 1 {
        return Err(Failure::internal(
            "test_assert",
            "the reject receipt must be journaled exactly once",
        ));
    }
    Ok(())
}

/// Upstream `TestExpireStagingRecordsTheReservationReasonForAReservedRecord`.
#[tokio::test]
async fn expire_staging_records_the_reservation_reason_for_a_reserved_record() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "expire_reserved").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let reserved = f
        .reserve_artifact(1 << 20, &format!("reserve-expiry-{}", ArtifactId::new()))
        .await?;
    let token = claim_token(13);
    f.claim_for_reconciliation(&token).await?;
    f.backdate_artifact(
        reserved.artifact.artifact_id,
        Duration::from_secs(73 * 3600),
    )
    .await?;

    let result = f
        .store
        .expire_staging(ExpireStagingRequest {
            workspace_id: f.ws,
            artifact_id: reserved.artifact.artifact_id,
            expected_version: reserved.artifact.version,
            claim_token: token,
            lifetime: Duration::from_secs(72 * 3600),
        })
        .await?;
    if !result.expired || result.outcome.failure_code != domain::FAILURE_CODE_RESERVATION_EXPIRED {
        return Err(Failure::internal(
            "test_assert",
            "want the reserved-record expiry reason",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, reserved.artifact.artifact_id).await? != "rejected"
        || capacity_state(&mut f.conn, f.ws, reserved.artifact.artifact_id).await? != "released"
    {
        return Err(Failure::internal(
            "test_assert",
            "post-expiry durable state wrong",
        ));
    }
    Ok(())
}

/// Upstream `TestExpireStagingIsANonMutatingConflictWithoutTheActiveClaim`.
#[tokio::test]
async fn expire_staging_is_a_non_mutating_conflict_without_the_active_claim() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "expire_no_claim").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    f.backdate_artifact(staged.artifact_id, Duration::from_secs(100 * 3600))
        .await?;

    let base = ExpireStagingRequest {
        workspace_id: f.ws,
        artifact_id: staged.artifact_id,
        expected_version: staged.version,
        claim_token: claim_token(11),
        lifetime: Duration::from_secs(24 * 3600),
    };

    // No claim row at all.
    let result = f.store.expire_staging(base.clone()).await?;
    if result.expired {
        return Err(Failure::internal(
            "test_assert",
            "an unclaimed record must never be expired",
        ));
    }

    // A claim held by a different coordinator token is equally
    // non-mutating.
    f.claim_for_reconciliation(&claim_token(11)).await?;
    let mut stale = base.clone();
    stale.claim_token = claim_token(77);
    let result = f.store.expire_staging(stale).await?;
    if result.expired {
        return Err(Failure::internal(
            "test_assert",
            "a stale claim must never mutate durable state",
        ));
    }

    // A version that moved under the claim is likewise a non-mutating
    // skip.
    let mut moved = base;
    moved.expected_version = staged.version + 4;
    let result = f.store.expire_staging(moved).await?;
    if result.expired {
        return Err(Failure::internal(
            "test_assert",
            "a version that moved under the claim must not be expired",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, staged.artifact_id).await? != "staging"
        || capacity_state(&mut f.conn, f.ws, staged.artifact_id).await? != "reserved"
    {
        return Err(Failure::internal(
            "test_assert",
            "non-mutating conflicts must leave durable state untouched",
        ));
    }
    Ok(())
}

/// Upstream `TestExpireStagingNeverTouchesAFinalizableRecord`.
#[tokio::test]
async fn expire_staging_never_touches_a_finalizable_record() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "expire_verifying").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let body = b"verified body";
    let verifying = f
        .advance_to_verifying(1 << 20, body.len() as i64, checksum_of(body))
        .await?;
    let token = claim_token(17);
    f.claim_for_reconciliation(&token).await?;
    f.backdate_artifact(verifying.artifact_id, Duration::from_secs(200 * 3600))
        .await?;

    let result = f
        .store
        .expire_staging(ExpireStagingRequest {
            workspace_id: f.ws,
            artifact_id: verifying.artifact_id,
            expected_version: verifying.version,
            claim_token: token,
            lifetime: Duration::from_secs(24 * 3600),
        })
        .await?;
    if result.expired {
        return Err(Failure::internal(
            "test_assert",
            "a verifying record is finalizable and must never be expired",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, verifying.artifact_id).await? != "verifying"
        || capacity_state(&mut f.conn, f.ws, verifying.artifact_id).await? != "reserved"
    {
        return Err(Failure::internal(
            "test_assert",
            "a finalizable record must be left untouched",
        ));
    }
    Ok(())
}

/// Upstream `TestExpireStagingFailsClosedOnAnIncompleteRequest`.
#[tokio::test]
async fn expire_staging_fails_closed_on_an_incomplete_request() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "expire_closed").await?;
    let f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;

    let nil_ws = WorkspaceId::from_trusted_db_bytes([0; 16]);
    let nil_art = ArtifactId::from_trusted_db_bytes([0; 16]);
    for request in [
        // no claim token
        ExpireStagingRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            claim_token: Vec::new(),
            lifetime: Duration::from_secs(3600),
        },
        // no lifetime
        ExpireStagingRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            claim_token: claim_token(3),
            lifetime: Duration::ZERO,
        },
        // no workspace
        ExpireStagingRequest {
            workspace_id: nil_ws,
            artifact_id: staged.artifact_id,
            expected_version: staged.version,
            claim_token: claim_token(3),
            lifetime: Duration::from_secs(3600),
        },
        // no artifact
        ExpireStagingRequest {
            workspace_id: f.ws,
            artifact_id: nil_art,
            expected_version: staged.version,
            claim_token: claim_token(3),
            lifetime: Duration::from_secs(3600),
        },
    ] {
        if f.store.expire_staging(request).await.is_ok() {
            return Err(Failure::internal(
                "test_assert",
                "an incomplete expire request must fail closed",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rejected-staging cleanup (I3)
// ---------------------------------------------------------------------------

/// Upstream `TestRejectedStagingIsScannableAndDrainsOnceCleared` — the
/// I3 regression: a rejected record's staging object is scannable, and
/// once `clear_staging_key` records the removal the record leaves the
/// sweep permanently.
#[tokio::test]
async fn rejected_staging_is_scannable_and_drains_once_cleared() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "rejected_staging").await?;
    let mut f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;
    let token = claim_token(51);
    f.claim_for_reconciliation(&token).await?;

    let reject_pure = domain::reject(&domain::RejectInput {
        workspace_id: f.ws,
        artifact_id: staged.artifact_id,
        current: staged.clone(),
        expected: staged.version,
        reason: domain::FAILURE_CODE_UPLOAD_NON_DELIVERY,
    })?;
    f.store.record_rejection(reject_pure).await?;

    let found = f
        .store
        .claim_rejected_staging(ClaimRejectedStagingRequest {
            batch_size: 25,
            claim_token: token.clone(),
        })
        .await?;
    let claim = found
        .claims
        .iter()
        .find(|claim| claim.artifact_id == staged.artifact_id);
    let Some(claim) = claim else {
        return Err(Failure::internal(
            "test_assert",
            "a rejected record with an unremoved staging object was not scannable",
        ));
    };
    if claim.staging_key != staged.staging_key {
        return Err(Failure::internal(
            "test_assert",
            "the claim must carry the record's own derived staging key",
        ));
    }

    f.store
        .clear_staging_key(ClearStagingKeyRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            claim_token: token.clone(),
        })
        .await?;
    let after = f
        .store
        .claim_rejected_staging(ClaimRejectedStagingRequest {
            batch_size: 25,
            claim_token: token,
        })
        .await?;
    if after
        .claims
        .iter()
        .any(|claim| claim.artifact_id == staged.artifact_id)
    {
        return Err(Failure::internal(
            "test_assert",
            "a cleaned record must leave the sweep permanently",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, staged.artifact_id).await? != "rejected" {
        return Err(Failure::internal(
            "test_assert",
            "the record itself is untouched apart from its staging key",
        ));
    }
    Ok(())
}

/// Upstream `TestClearStagingKeyNeverTouchesANonRejectedRecord` — the
/// state predicate is the safety boundary: a record still using its
/// staging key keeps it.
#[tokio::test]
async fn clear_staging_key_never_touches_a_non_rejected_record() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "clear_non_rejected").await?;
    let f = setup_fixture(&db, 100 << 20).await?;
    let staged = f.advance_to_staging(1 << 20).await?;

    f.store
        .clear_staging_key(ClearStagingKeyRequest {
            workspace_id: f.ws,
            artifact_id: staged.artifact_id,
            claim_token: claim_token(53),
        })
        .await?;
    let loaded = f.store.load_artifact(f.ws, staged.artifact_id).await?;
    if loaded.staging_key != staged.staging_key {
        return Err(Failure::internal(
            "test_assert",
            "staging key must be untouched for a record still using it",
        ));
    }
    Ok(())
}

/// Upstream `TestRejectedStagingScanFailsClosedOnAnIncompleteRequest`.
#[tokio::test]
async fn rejected_staging_scan_fails_closed_on_an_incomplete_request() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "rejected_closed").await?;
    let _f = setup_fixture(&db, 100 << 20).await?;
    let store = _f.store;

    if store
        .claim_rejected_staging(ClaimRejectedStagingRequest {
            batch_size: 0,
            claim_token: claim_token(1),
        })
        .await
        .is_ok()
    {
        return Err(Failure::internal(
            "test_assert",
            "a zero batch size must fail closed",
        ));
    }
    if store
        .claim_rejected_staging(ClaimRejectedStagingRequest {
            batch_size: 5,
            claim_token: Vec::new(),
        })
        .await
        .is_ok()
    {
        return Err(Failure::internal(
            "test_assert",
            "an unfenced scan must fail closed",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EXPLAIN plan assertions (upstream explain_test.go + the
// rejected-staging scan the brief adds on
// `artifacts_workspace_staging_key_unique_idx`).
// ---------------------------------------------------------------------------

/// `seedExplainCorpus` — 10_000 ready + 100 staging artifacts across
/// three workspaces, each with one owning Task/Run, plus 200 rejected
/// rows (with retained staging keys) so the rejected-staging scan has
/// a real selectivity to plan against. Bulk SQL, not the Store: the
/// suite asserts on PostgreSQL's chosen plan, not store correctness.
async fn seed_explain_corpus(conn: &mut PgConnection) -> Result<Vec<WorkspaceId>> {
    const READY_PER_WORKSPACE: i64 = 10_000 / 3;
    const INCOMPLETE_PER_WORKSPACE: i64 = 100 / 3;

    let mut workspaces = Vec::new();
    for _ in 0..3 {
        let ws = WorkspaceId::new();
        let task = TaskId::new();
        let run = RunId::new();
        workspaces.push(ws);
        sqlx::query(
            "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
             VALUES ($1, 'active', 'explain-seed', 1000000000000)",
        )
        .bind(uuid_of!(ws))
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
             last_run_index, title, input_spec) \
             VALUES ($1, $2, 1, 'running', $3, 1, 'explain', '{}'::jsonb)",
        )
        .bind(uuid_of!(task))
        .bind(uuid_of!(ws))
        .bind(uuid_of!(run))
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
             VALUES ($1, $2, $3, 1, 'running', 1)",
        )
        .bind(uuid_of!(run))
        .bind(uuid_of!(ws))
        .bind(uuid_of!(task))
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;

        sqlx::query(
            "INSERT INTO central.artifacts (\
             id, workspace_id, task_id, run_id, version, state, size, \
             staging_generation, object_key, sensitivity, disposition, \
             staging_key, content_generation, ready_key, checksum_value, checksum_algorithm, \
             producer_id, limits_snapshot, created_at, updated_at, ready_at\
             ) \
             SELECT gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 3, 'ready', 100, \
             gen_random_uuid(), \
             'v1/staging/' || $1::text || '/' || gen_random_uuid()::text || '/' || gen_random_uuid()::text, \
             'restricted', 'attachment', \
             'v1/staging/' || $1::text || '/' || gen_random_uuid()::text || '/' || gen_random_uuid()::text, \
             gen_random_uuid(), \
             'v1/ready/' || $1::text || '/' || gen_random_uuid()::text || '/' || gen_random_uuid()::text, \
             sha256(convert_to(g::text, 'UTF8')), 'sha256', \
             'seed-producer', '{\"max_bytes\":1048576}'::jsonb, \
             now() - (g || ' seconds')::interval, now(), now() \
             FROM generate_series(1, $4) AS g",
        )
        .bind(uuid_of!(ws))
        .bind(uuid_of!(task))
        .bind(uuid_of!(run))
        .bind(READY_PER_WORKSPACE)
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;

        sqlx::query(
            "INSERT INTO central.artifacts (\
             id, workspace_id, task_id, run_id, version, state, size, \
             staging_generation, object_key, sensitivity, disposition, \
             staging_key, producer_id, limits_snapshot, created_at, updated_at\
             ) \
             SELECT gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 1, 'staging', 0, \
             gen_random_uuid(), \
             'v1/staging/' || $1::text || '/' || gen_random_uuid()::text || '/' || gen_random_uuid()::text, \
             'restricted', 'attachment', \
             'v1/staging/' || $1::text || '/' || gen_random_uuid()::text || '/' || gen_random_uuid()::text, \
             'seed-producer', '{\"max_bytes\":1048576}'::jsonb, \
             now() - (g || ' seconds')::interval, now() \
             FROM generate_series(1, $4) AS g",
        )
        .bind(uuid_of!(ws))
        .bind(uuid_of!(task))
        .bind(uuid_of!(run))
        .bind(INCOMPLETE_PER_WORKSPACE)
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    }

    // 200 rejected rows that still carry staging keys — the population
    // `queryScanRejectedStaging`'s partial-index plan is asserted on.
    // `artifacts_no_ready_key_b10_check` requires `ready_key IS NULL`
    // on a rejected row, so the ready metadata is dropped with the
    // transition.
    sqlx::query(
        "UPDATE central.artifacts SET state = 'rejected', ready_key = NULL \
         WHERE id IN (SELECT id FROM central.artifacts WHERE state = 'ready' LIMIT 200)",
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    sqlx::query("ANALYZE central.artifacts")
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(workspaces)
}

/// A bound `EXPLAIN` parameter — text binds cast inside the SQL
/// (`$n::uuid`, `$n::timestamptz`), `bigint` binds for `LIMIT`/version.
enum ExplainBind {
    Text(String),
    Bigint(i64),
    Timestamp(OffsetDateTime),
}

/// `runExplain` — `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` inside a
/// rolled-back transaction (ANALYZE executes the statement; nothing
/// mutates durable state).
async fn run_explain(
    conn: &mut PgConnection,
    sql: &str,
    binds: Vec<ExplainBind>,
) -> Result<serde_json::Value> {
    let mut tx = conn.begin().await.map_err(|e| classify_sqlx(&e))?;
    let statement = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}");
    let mut query = sqlx::query_scalar::<_, serde_json::Value>(&statement);
    for bind in binds {
        query = match bind {
            ExplainBind::Text(text) => query.bind(text),
            ExplainBind::Bigint(value) => query.bind(value),
            ExplainBind::Timestamp(value) => query.bind(value),
        };
    }
    let roots = query
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    tx.rollback().await.map_err(|e| classify_sqlx(&e))?;
    roots
        .as_array()
        .and_then(|roots| roots.first())
        .and_then(|root| root.get("Plan"))
        .cloned()
        .ok_or_else(|| Failure::internal("test_assert", "expected exactly one explain plan root"))
}

/// Walks every node in the plan tree.
fn plan_walk<'a>(plan: &'a serde_json::Value, visit: &mut dyn FnMut(&'a serde_json::Value)) {
    visit(plan);
    if let Some(children) = plan.get("Plans").and_then(serde_json::Value::as_array) {
        for child in children {
            plan_walk(child, visit);
        }
    }
}

fn plan_has_node_type(plan: &serde_json::Value, node_type: &str) -> bool {
    let mut found = false;
    plan_walk(plan, &mut |node| {
        if node.get("Node Type").and_then(serde_json::Value::as_str) == Some(node_type) {
            found = true;
        }
    });
    found
}

fn plan_has_seq_scan_on(plan: &serde_json::Value, relation: &str) -> bool {
    let mut found = false;
    plan_walk(plan, &mut |node| {
        let is_seq = node.get("Node Type").and_then(serde_json::Value::as_str) == Some("Seq Scan");
        let on_relation = node
            .get("Relation Name")
            .and_then(serde_json::Value::as_str)
            == Some(relation);
        if is_seq && on_relation {
            found = true;
        }
    });
    found
}

/// Upstream `usesAnyIndex`: an Index Scan / Index Only Scan node used
/// any of the named indexes.
fn plan_uses_any_index(plan: &serde_json::Value, index_names: &[&str]) -> bool {
    let mut found = false;
    plan_walk(plan, &mut |node| {
        let node_type = node.get("Node Type").and_then(serde_json::Value::as_str);
        if node_type != Some("Index Scan") && node_type != Some("Index Only Scan") {
            return;
        }
        let index = node.get("Index Name").and_then(serde_json::Value::as_str);
        if index_names.iter().any(|name| Some(*name) == index) {
            found = true;
        }
    });
    found
}

/// The combined corpus plan assertions — upstream `explain_test.go`'s
/// three plan tests plus the rejected-staging scan the brief requires
/// on `artifacts_workspace_staging_key_unique_idx`.
#[tokio::test]
async fn explain_plans_use_the_expected_indexes() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "explain").await?;
    let mut conn = role_conn(&db, "central_migration").await?;
    let workspaces = seed_explain_corpus(&mut conn).await?;

    let (sample_id, sample_version) = sqlx::query_as::<_, (uuid::Uuid, i64)>(
        "SELECT id, version FROM central.artifacts \
         WHERE workspace_id = $1 AND state = 'ready' LIMIT 1",
    )
    .bind(uuid_of!(workspaces[0]))
    .fetch_one(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    // Admission: the (workspace_id, id) lookup every admission makes —
    // upstream `TestExplainAdmissionByWorkspaceArtifactUsesIndexScan`.
    let plan = run_explain(
        &mut conn,
        "SELECT id FROM central.artifacts WHERE workspace_id = $1::uuid AND id = $2::uuid",
        vec![
            ExplainBind::Text(workspaces[0].to_string()),
            ExplainBind::Text(sample_id.to_string()),
        ],
    )
    .await?;
    if plan_has_seq_scan_on(&plan, "artifacts") {
        return Err(Failure::internal(
            "test_assert",
            "admission lookup must not Seq Scan artifacts",
        ));
    }
    if !plan_uses_any_index(
        &plan,
        &["artifacts_workspace_id_unique_idx", "artifacts_pkey"],
    ) {
        return Err(Failure::internal(
            "test_assert",
            "admission lookup must use an artifacts index",
        ));
    }
    if plan_has_node_type(&plan, "Sort") {
        return Err(Failure::internal(
            "test_assert",
            "admission lookup must not require a Sort",
        ));
    }

    // Finalization: the same probe plus the version guard — upstream
    // `TestExplainFinalizationByWorkspaceArtifactExpectedVersionUsesIndexScan`.
    let plan = run_explain(
        &mut conn,
        "SELECT id FROM central.artifacts \
         WHERE workspace_id = $1::uuid AND id = $2::uuid AND version = $3",
        vec![
            ExplainBind::Text(workspaces[0].to_string()),
            ExplainBind::Text(sample_id.to_string()),
            ExplainBind::Bigint(sample_version),
        ],
    )
    .await?;
    if plan_has_seq_scan_on(&plan, "artifacts") {
        return Err(Failure::internal(
            "test_assert",
            "finalization lookup must not Seq Scan artifacts",
        ));
    }
    if !plan_uses_any_index(
        &plan,
        &["artifacts_workspace_id_unique_idx", "artifacts_pkey"],
    ) {
        return Err(Failure::internal(
            "test_assert",
            "finalization lookup must use an artifacts index",
        ));
    }
    if plan_has_node_type(&plan, "Sort") {
        return Err(Failure::internal(
            "test_assert",
            "finalization lookup must not require a Sort",
        ));
    }

    // Reconciliation keyset seek — upstream
    // `TestExplainIncompleteKeysetSeekAfterCursorUsesIndexScanNoSort`:
    // the exact statement `queryScanIncompleteByWorkspaceAndState`
    // issues, bound to a cursor positioned before the seeded rows.
    let cursor_created_at = OffsetDateTime::now_utc() - time::Duration::hours(24);
    let plan = run_explain(
        &mut conn,
        "SELECT id, created_at FROM central.artifacts \
         WHERE workspace_id = $1::uuid AND state = $2 \
         AND ($3::timestamptz IS NULL OR created_at > $3::timestamptz) \
         ORDER BY created_at LIMIT $4",
        vec![
            ExplainBind::Text(workspaces[0].to_string()),
            ExplainBind::Text("staging".to_owned()),
            ExplainBind::Timestamp(cursor_created_at),
            ExplainBind::Bigint(100),
        ],
    )
    .await?;
    if plan_has_seq_scan_on(&plan, "artifacts") {
        return Err(Failure::internal(
            "test_assert",
            "incomplete-state keyset seek must not Seq Scan artifacts",
        ));
    }
    if !plan_uses_any_index(&plan, &["artifacts_state_expiry_idx"]) {
        return Err(Failure::internal(
            "test_assert",
            "incomplete-state keyset seek must use artifacts_state_expiry_idx",
        ));
    }
    if plan_has_node_type(&plan, "Sort") {
        return Err(Failure::internal(
            "test_assert",
            "incomplete-state keyset seek must not require a Sort",
        ));
    }

    // Rejected-staging cleanup scan — the brief's added assertion:
    // `queryScanRejectedStaging`'s WHERE matches the partial predicate
    // of `artifacts_workspace_staging_key_unique_idx` and its ORDER BY
    // the index's own column order, so no Seq Scan and no Sort.
    let plan = run_explain(
        &mut conn,
        "SELECT workspace_id, id, staging_key FROM central.artifacts \
         WHERE staging_key IS NOT NULL AND state = 'rejected' \
         ORDER BY workspace_id, staging_key LIMIT $1",
        vec![ExplainBind::Bigint(25)],
    )
    .await?;
    if plan_has_seq_scan_on(&plan, "artifacts") {
        return Err(Failure::internal(
            "test_assert",
            "rejected-staging scan must not Seq Scan artifacts",
        ));
    }
    if !plan_uses_any_index(&plan, &["artifacts_workspace_staging_key_unique_idx"]) {
        return Err(Failure::internal(
            "test_assert",
            "rejected-staging scan must use artifacts_workspace_staging_key_unique_idx",
        ));
    }
    if plan_has_node_type(&plan, "Sort") {
        return Err(Failure::internal(
            "test_assert",
            "rejected-staging scan must not require a Sort",
        ));
    }
    Ok(())
}
