//! PostgreSQL integration tests for the B10 artifact store
//! (`artifact/*.rs`): reservation admission and quota peak accounting,
//! command-stage receipt replay, capacity release, the two-phase
//! deletion + tombstone settlement, `ArtifactSummaryRead` keyset
//! pagination, and the atomic finalize-plus-completion commit under
//! the B08 lease fence.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as
//! `execution_store_integration.rs`: a superuser DSN on a scratch
//! cluster whose `central_migration` / `central_runtime` roles exist.
//! Every test provisions its own database and installs the baseline
//! through [`BaselineInstaller::install`].
//!
//! Role discipline mirrors production: fixture inserts and the
//! tombstone settlement run under `central_migration` (owner);
//! ordinary lifecycle commands run under `central_runtime`. The
//! tombstone INSERT is deliberately withheld from `central_runtime`.

use central_adapter_postgres::artifact::Store;
use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_artifact::domain::{self, Artifact, FinalizeResult, Limits, OutcomeKind};
use central_artifact::port::{
    ArtifactChangeSet, ArtifactCommandReceipt, CompletionContributor, Store as ArtifactStore,
    TwoPhaseDeleteStore,
};
use central_artifact::query::{ArtifactListRequest, ArtifactSeekCursor, ArtifactSummaryRead};
use central_execution::domain::{
    self as exec, AttemptState, EventIntent, ExecutionChangeSet, InvocationId, LeaseCredential,
    LeaseRelease, LogicalOperationId, OutboxIntent, PhysicalAttemptId, Settlement, Step,
    StepAttempt, StepState, transition_attempt, transition_step,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, ArtifactTombstoneId, ContentGeneration, ExecutionEventId, OutboxId, RunId,
    StagingGeneration, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use central_task::domain as task;
use central_task::execution_facade::{
    ExecutionCompleteRequest, ExecutionTransition, evaluate_execution_transition,
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
    let db = format!("artifact_test_{label}_{}", std::process::id());
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

/// `fixture` — one Workspace with a running Task/Run plus a `settling`
/// Step/StepAttempt chain (the shape B08 leaves when its Settle awaits
/// the required output) and an active B08 lease the completion change
/// set's fence names — mirrors upstream `testhelper_test.go`'s
/// `setupFixture`.
struct Fixture {
    /// The store under `central_runtime` — the production role for the
    /// lifecycle command surface.
    store: Store,
    /// The store under `central_migration` — required for the tombstone
    /// settlement, whose INSERT is withheld from the runtime role.
    owner_store: Store,
    /// Owner connection for fixture writes and assertions.
    conn: PgConnection,

    ws: WorkspaceId,
    task: TaskId,
    run: RunId,
    step: StepId,
    attempt: StepAttemptId,
    logical: LogicalOperationId,
    physical: PhysicalAttemptId,
    invocation: InvocationId,
    producer: String,

    lease_credential: LeaseCredential,
    lease_generation: i64,
}

async fn setup_fixture(db: &str, quota_max_bytes: i64) -> Result<Fixture> {
    let runtime_pool = role_pool(db, "central_runtime").await?;
    let owner_pool = role_pool(db, "central_migration").await?;
    let mut conn = role_conn(db, "central_migration").await?;

    let ws = WorkspaceId::new();
    let task_id = TaskId::new();
    let run_id = RunId::new();
    let step_id = StepId::new();
    let attempt_id = StepAttemptId::new();
    let logical = LogicalOperationId(*uuid::Uuid::now_v7().as_bytes());
    let physical = PhysicalAttemptId(*uuid::Uuid::now_v7().as_bytes());
    let invocation = InvocationId(*uuid::Uuid::now_v7().as_bytes());
    let lease_credential = LeaseCredential::new(&[b'l'; 32])?;
    let lease_generation = 1i64;

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
    // Step/StepAttempt start already in 'settling': B08's own Settle
    // flow drives running -> settling (awaiting the required output)
    // before B10's Finalize contributes the final settling -> succeeded
    // hop. Finalize never completes a required output from an earlier
    // Step/Attempt state.
    sqlx::query(
        "INSERT INTO central.steps (id, workspace_id, task_id, run_id, version, state, \
         logical_operation_id, sequence) \
         VALUES ($1, $2, $3, $4, 1, 'settling', $5, 1)",
    )
    .bind(uuid_of!(step_id))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task_id))
    .bind(uuid_of!(run_id))
    .bind(uuid::Uuid::from_bytes(logical.0))
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
    .bind(uuid::Uuid::from_bytes(logical.0))
    .bind(uuid::Uuid::from_bytes(physical.0))
    .bind(uuid::Uuid::from_bytes(invocation.0))
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    // An ACTIVE B08 lease for the Run — the completion commit enforces
    // the fence the change set carries (the SB-G5 live observation):
    // a contribution that cannot prove it still owns the Run is
    // refused. Mirrors the execution adapter's queryInsertLease shape.
    let verifier = {
        use sha2::Digest;
        sha2::Sha256::digest(lease_credential.0)
    };
    sqlx::query(
        "INSERT INTO central.execution_ownership (\
         id, workspace_id, owner_scope, owner_identity, heartbeat_at, \
         claimed_run_id, claimed_step_id, claimed_step_attempt_id, \
         run_id, lease_token_hash, fencing_generation, lease_expires_at, \
         created_at, updated_at) \
         VALUES ($1, $2, $3, 'integration-test', clock_timestamp(), \
         $4, $5, $6, $4, $7, $8, \
         clock_timestamp() + interval '5 minutes', \
         clock_timestamp(), clock_timestamp())",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(ws))
    .bind(format!("run:{}", uuid_of!(run_id)))
    .bind(uuid_of!(run_id))
    .bind(uuid_of!(step_id))
    .bind(uuid_of!(attempt_id))
    .bind(&verifier[..])
    .bind(lease_generation)
    .execute(&mut conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    Ok(Fixture {
        store: Store::new(runtime_pool),
        owner_store: Store::new(owner_pool),
        conn,
        ws,
        task: task_id,
        run: run_id,
        step: step_id,
        attempt: attempt_id,
        logical,
        physical,
        invocation,
        producer: "test-producer".to_owned(),
        lease_credential,
        lease_generation,
    })
}

impl Fixture {
    /// Runs the pure domain Reserve and persists it — the durable
    /// result. `idempotency_key` mirrors upstream's
    /// `"reserve-<fresh>"` caller key convention.
    async fn reserve_artifact(
        &self,
        store: &Store,
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
        store.reserve_artifact(pure).await
    }

    /// `advanceToVerifying` — Reserve -> BeginUpload -> Verify
    /// (accepted) against `self.store`.
    async fn advance_to_verifying(
        &self,
        max_bytes: i64,
        size: i64,
        checksum: [u8; 32],
    ) -> Result<Artifact> {
        let reserved = self
            .reserve_artifact(
                &self.store,
                max_bytes,
                &format!("reserve-{}", ArtifactId::new()),
            )
            .await?;
        // `expected` is the durable version the command guards: the
        // committed reserved row is version 1.
        let begin_pure = domain::begin_upload(&domain::BeginUploadInput {
            workspace_id: self.ws,
            artifact_id: reserved.artifact.artifact_id,
            current: reserved.artifact,
            expected: 1,
        })?;
        let begun = self.store.record_begin_upload(begin_pure).await?;
        let verify_pure = domain::verified(&domain::VerifiedInput {
            workspace_id: self.ws,
            artifact_id: begun.artifact.artifact_id,
            current: begun.artifact,
            expected: 2,
            size,
            checksum,
            secret_disclosure: false,
            rejection_code: "",
        })?;
        let verified = self.store.record_verification(verify_pure).await?;
        if verified.artifact.state != domain::State::Verifying {
            return Err(Failure::internal(
                "test_fixture",
                "expected verifying state after accepted verify",
            ));
        }
        Ok(verified.artifact)
    }

    /// `advanceToPromoted` — drives all the way through Promotion.
    async fn advance_to_promoted(
        &self,
        max_bytes: i64,
        size: i64,
        checksum: [u8; 32],
    ) -> Result<Artifact> {
        let verifying = self.advance_to_verifying(max_bytes, size, checksum).await?;
        let promote_pure = domain::promotion(&domain::PromotionInput {
            workspace_id: self.ws,
            artifact_id: verifying.artifact_id,
            expected: verifying.version,
            current: verifying,
            content_generation: ContentGeneration::new(),
        })?;
        Ok(self.store.record_promotion(promote_pure).await?.artifact)
    }

    /// `completionChangeSet` — the `ExecutionChangeSet` a required
    /// Artifact's Finalize commits alongside the ready transition: it
    /// settles the fixture's StepAttempt/Step to `succeeded`, advances
    /// the owning Task/Run to `completed`, and carries the lease
    /// release the commit's fence enforces (the SB-G5 live
    /// observation).
    fn completion_change_set(
        &self,
        task_version: i64,
        run_version: i64,
        step_version: i64,
        attempt_version: i64,
    ) -> Result<ExecutionChangeSet> {
        let now = OffsetDateTime::now_utc();
        let mut step = Step {
            id: self.step,
            workspace_id: self.ws,
            task_id: self.task,
            run_id: self.run,
            version: step_version,
            sequence: 1,
            state: StepState::StepSettling,
            created_at: now,
            updated_at: now,
        };
        step = transition_step(step, StepState::StepSucceeded)?;
        step.updated_at = now;

        let mut attempt = StepAttempt {
            id: self.attempt,
            step_id: self.step,
            workspace_id: self.ws,
            task_id: self.task,
            run_id: self.run,
            logical_operation_id: self.logical,
            physical_attempt_id: self.physical,
            invocation_id: self.invocation,
            predecessor_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
            version: attempt_version,
            sequence: 1,
            state: AttemptState::AttemptSettling,
            created_at: now,
            updated_at: now,
        };
        attempt = transition_attempt(attempt, AttemptState::AttemptSucceeded)?;
        attempt.updated_at = now;

        let transition = evaluate_execution_transition(ExecutionTransition::Complete(
            ExecutionCompleteRequest {
                aggregate: task::TaskAggregate {
                    task: task::Task {
                        id: self.task,
                        workspace_id: self.ws,
                        version: task_version,
                        status: task::TaskStatus::Running,
                        current_run_id: Some(self.run),
                        ..task_fixture()
                    },
                    current_run: Some(task::Run {
                        id: self.run,
                        task_id: self.task,
                        workspace_id: self.ws,
                        version: run_version,
                        status: task::RunStatus::Running,
                        index: 1,
                        ..run_fixture()
                    }),
                },
                now,
                expected_task_version: task_version,
                expected_run_version: run_version,
            },
        ))?;

        let event_id = ExecutionEventId::new();
        let outbox_id = OutboxId::new();
        let outcome =
            serde_json::to_vec(&serde_json::json!({"schema_version": 1})).unwrap_or_default();
        let event_payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "type": exec::EVENT_ATTEMPT_SETTLED,
        }))
        .unwrap_or_default();

        let mut change = ExecutionChangeSet::new();
        change.steps.push(step);
        change.attempts.push(attempt.clone());
        change.settlements.push(Settlement {
            workspace_id: self.ws,
            task_id: self.task,
            run_id: self.run,
            step_id: self.step,
            attempt_id: self.attempt,
            invocation_id: attempt.invocation_id,
            final_state: AttemptState::AttemptSucceeded,
            outcome,
            context: Vec::new(),
            settled_at: now,
        });
        change.lease_releases.push(LeaseRelease {
            workspace_id: self.ws,
            run_id: self.run,
            credential: self.lease_credential,
            generation: self.lease_generation,
        });
        change.events.push(EventIntent {
            id: event_id,
            workspace_id: self.ws,
            task_id: self.task,
            run_id: self.run,
            step_id: self.step,
            attempt_id: self.attempt,
            tool_call_id: central_foundation::identity::ToolCallId::from_trusted_db_bytes([0; 16]),
            tool_attempt_id: central_foundation::identity::ToolCallAttemptId::from_trusted_db_bytes(
                [0; 16],
            ),
            kind: exec::EVENT_ATTEMPT_SETTLED,
            payload: event_payload.clone(),
            occurred_at: now,
        });
        change.outbox.push(OutboxIntent {
            id: outbox_id,
            workspace_id: self.ws,
            event_id,
            catalog_type: exec::OUTBOX_ATTEMPT_SETTLED,
            payload: serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "event_id": uuid_of!(event_id).to_string(),
                "catalog_type": exec::OUTBOX_ATTEMPT_SETTLED,
                "deduplication_key": format!("test-{}", uuid_of!(event_id)),
            }))
            .unwrap_or_default(),
            deduplication_key: format!("test-{}", uuid_of!(event_id)),
            producer_id: "artifact-store-test".to_owned(),
            created_at: now,
        });
        change.task_transition = Some(transition);
        Ok(change)
    }
}

fn task_fixture() -> task::Task {
    task::Task {
        id: TaskId::from_trusted_db_bytes([0; 16]),
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        version: 0,
        status: task::TaskStatus::Running,
        current_run_id: None,
        parent_task_id: None,
        last_run_index: 0,
        retry_count: 0,
        retry_eligible_at: None,
        waiting_reason: None,
        failure_reason: String::new(),
        input: String::new(),
        title: String::new(),
        permission_policy: task::PermissionPolicy::Deny,
        budget: task::Budget::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn run_fixture() -> task::Run {
    task::Run {
        id: RunId::from_trusted_db_bytes([0; 16]),
        task_id: TaskId::from_trusted_db_bytes([0; 16]),
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        version: 0,
        status: task::RunStatus::Running,
        index: 0,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

// ---------------------------------------------------------------------------
// Assertion helpers (upstream assertArtifactState & friends).
// ---------------------------------------------------------------------------

async fn scalar_text(
    conn: &mut PgConnection,
    sql: &str,
    arg0: uuid::Uuid,
    arg1: uuid::Uuid,
) -> Result<String> {
    let (value,): (String,) = sqlx::query_as::<_, (String,)>(sql)
        .bind(arg0)
        .bind(arg1)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(value)
}

async fn artifact_state(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<String> {
    scalar_text(
        conn,
        "SELECT state FROM central.artifacts WHERE workspace_id = $1 AND id = $2",
        uuid_of!(ws),
        uuid_of!(artifact_id),
    )
    .await
}

async fn capacity_state(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<String> {
    scalar_text(
        conn,
        "SELECT state FROM central.capacity_reservations \
         WHERE workspace_id = $1 AND artifact_id = $2",
        uuid_of!(ws),
        uuid_of!(artifact_id),
    )
    .await
}

async fn task_status(conn: &mut PgConnection, ws: WorkspaceId, task_id: TaskId) -> Result<String> {
    scalar_text(
        conn,
        "SELECT status FROM central.tasks WHERE workspace_id = $1 AND id = $2",
        uuid_of!(ws),
        uuid_of!(task_id),
    )
    .await
}

async fn event_count_for_attempt(
    conn: &mut PgConnection,
    ws: WorkspaceId,
    attempt_id: StepAttemptId,
) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM central.events \
         WHERE workspace_id = $1 AND attempt_id = $2",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(attempt_id))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(count)
}

async fn quota_ready_bytes(conn: &mut PgConnection, ws: WorkspaceId) -> Result<i64> {
    let (bytes,): (i64,) =
        sqlx::query_as("SELECT quota_ready_bytes FROM central.workspaces WHERE id = $1")
            .bind(uuid_of!(ws))
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    Ok(bytes)
}

/// `finalizeFixture` — drives one fixture's Artifact all the way to a
/// Finalize input, ready to commit.
async fn finalize_fixture(
    db: &str,
    max_bytes: i64,
    quota_max_bytes: i64,
) -> Result<(Fixture, FinalizeResult)> {
    let f = setup_fixture(db, quota_max_bytes).await?;
    let body = b"# Report\n\nhello world";
    let checksum = checksum_of(body);
    let promoted = f
        .advance_to_promoted(max_bytes, body.len() as i64, checksum)
        .await?;
    let finalize_pure = domain::finalize(&domain::FinalizeInput {
        workspace_id: f.ws,
        artifact_id: promoted.artifact_id,
        expected: promoted.version,
        current: promoted,
        size: body.len() as i64,
        checksum,
        ready_object_version: String::new(),
    })?;
    Ok((f, finalize_pure))
}

fn artifact_change_set(finalize: &FinalizeResult, key: &str) -> ArtifactChangeSet {
    ArtifactChangeSet {
        finalize: finalize.clone(),
        receipt: ArtifactCommandReceipt {
            idempotency_key: key.to_owned(),
            identity: finalize.identity.clone(),
        },
    }
}

fn expect_code(result: Failure, code: &str) -> Result<()> {
    if result.code() == code {
        Ok(())
    } else {
        Err(Failure::internal(
            "test_assertion",
            "unexpected failure code",
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Upstream `TestFinalizeCommitsArtifactCapacityCompletionAndEventOnce`:
/// the first commit makes every effect durable in one transaction;
/// the exact replay returns the receipt with no second effect.
#[tokio::test]
async fn finalize_commits_artifact_capacity_completion_and_event_once() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "finalize_once").await?;
    let (mut f, finalize_pure) = finalize_fixture(&db, 1 << 20, 10 << 20).await?;
    let key = format!("finalize-{}", f.attempt);
    let change = artifact_change_set(&finalize_pure, &key);
    let exec_change = f.completion_change_set(1, 1, 1, 1)?;

    let result = f
        .store
        .commit_artifact(change.clone(), exec_change.clone())
        .await?;
    if result.replayed {
        return Err(Failure::internal(
            "test_assertion",
            "first commit must not report replayed",
        ));
    }
    if result.outcome.kind != OutcomeKind::Ready {
        return Err(Failure::internal("test_assertion", "expected OutcomeReady"));
    }
    if artifact_state(&mut f.conn, f.ws, finalize_pure.artifact.artifact_id).await? != "ready" {
        return Err(Failure::internal("test_assertion", "artifact is not ready"));
    }
    if capacity_state(&mut f.conn, f.ws, finalize_pure.artifact.artifact_id).await? != "settled" {
        return Err(Failure::internal(
            "test_assertion",
            "capacity reservation is not settled",
        ));
    }
    if task_status(&mut f.conn, f.ws, f.task).await? != "completed" {
        return Err(Failure::internal("test_assertion", "task is not completed"));
    }
    if event_count_for_attempt(&mut f.conn, f.ws, f.attempt).await? != 1 {
        return Err(Failure::internal(
            "test_assertion",
            "expected exactly one Event for the settled attempt",
        ));
    }

    // Replay: the exact same command identity must return the original
    // receipt, contribute no second Event, and settle capacity only
    // once.
    let replay = f.store.commit_artifact(change, exec_change).await?;
    if !replay.replayed {
        return Err(Failure::internal(
            "test_assertion",
            "second identical commit must report replayed",
        ));
    }
    if replay.outcome.kind != OutcomeKind::Ready {
        return Err(Failure::internal(
            "test_assertion",
            "replay outcome mismatch",
        ));
    }
    if event_count_for_attempt(&mut f.conn, f.ws, f.attempt).await? != 1 {
        return Err(Failure::internal(
            "test_assertion",
            "replay must not append a second Event",
        ));
    }
    if capacity_state(&mut f.conn, f.ws, finalize_pure.artifact.artifact_id).await? != "settled" {
        return Err(Failure::internal(
            "test_assertion",
            "capacity reservation must remain settled",
        ));
    }
    Ok(())
}

/// Upstream `TestFinalizeBindsTheReadyObjectVersionEvidence` — the
/// object-version evidence the caller observed is bound to the ready
/// row.
#[tokio::test]
async fn finalize_binds_the_ready_object_version_evidence() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "roversion").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let body = b"# Report\n\nhello world";
    let checksum = checksum_of(body);
    let promoted = f
        .advance_to_promoted(1 << 20, body.len() as i64, checksum)
        .await?;
    let finalize_pure = domain::finalize(&domain::FinalizeInput {
        workspace_id: f.ws,
        artifact_id: promoted.artifact_id,
        expected: promoted.version,
        current: promoted,
        size: body.len() as i64,
        checksum,
        ready_object_version: "object-version-1".to_owned(),
    })?;
    let key = format!("finalize-rov-{}", f.attempt);
    let change = artifact_change_set(&finalize_pure, &key);
    let exec_change = f.completion_change_set(1, 1, 1, 1)?;
    f.store.commit_artifact(change, exec_change).await?;

    let (bound,): (Option<String>,) = sqlx::query_as(
        "SELECT ready_object_version FROM central.artifacts \
         WHERE workspace_id = $1 AND id = $2",
    )
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(finalize_pure.artifact.artifact_id))
    .fetch_one(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    if bound.as_deref() != Some("object-version-1") {
        return Err(Failure::internal(
            "test_assertion",
            "ready_object_version was not bound",
        ));
    }
    Ok(())
}

/// Upstream quota admission: the reservation's peak — staging body plus
/// the promotion copy — is `2 * max_bytes`, enforced against
/// `ready + reserved + needed <= max_bytes`.
#[tokio::test]
async fn reserve_enforces_the_doubled_peak_quota() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "quota_peak").await?;
    // A 1 MiB artifact needs 2 MiB of peak headroom; admit exactly the
    // boundary, then refuse one byte over.
    let f = setup_fixture(&db, 4 << 20).await?;
    f.reserve_artifact(&f.store, 1 << 20, "reserve-quota-a")
        .await?;

    // The remaining headroom is 4 MiB - 2 MiB = 2 MiB, so a second
    // 1 MiB reservation (2 MiB peak) fits exactly.
    f.reserve_artifact(&f.store, 1 << 20, "reserve-quota-b")
        .await?;

    // A third reservation's 2 MiB peak exceeds the now-exhausted
    // headroom.
    let failure = f
        .reserve_artifact(&f.store, 1 << 20, "reserve-quota-c")
        .await
        .map(|_| ())
        .unwrap_err();
    expect_code(failure, "QUOTA_EXCEEDED")
}

/// Upstream `TestRecordVerificationRejectionReleasesCapacityExactlyOnce`:
/// a rejected verify releases the reservation in the same commit, and
/// an exact replay returns the journaled outcome without a second
/// release.
#[tokio::test]
async fn verification_rejection_releases_capacity_exactly_once() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "verify_reject").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let reserved = f.reserve_artifact(&f.store, 1 << 20, "reserve-vr").await?;
    let begun = f
        .store
        .record_begin_upload(domain::begin_upload(&domain::BeginUploadInput {
            workspace_id: f.ws,
            artifact_id: reserved.artifact.artifact_id,
            current: reserved.artifact.clone(),
            expected: 1,
        })?)
        .await?;
    // An over-limit body rejects at verify.
    let verify_pure = domain::verified(&domain::VerifiedInput {
        workspace_id: f.ws,
        artifact_id: begun.artifact.artifact_id,
        current: begun.artifact,
        expected: 2,
        size: (1 << 20) + 1,
        checksum: [7u8; 32],
        secret_disclosure: false,
        rejection_code: "",
    })?;
    let rejected = f.store.record_verification(verify_pure.clone()).await?;
    if rejected.artifact.state != domain::State::Rejected {
        return Err(Failure::internal(
            "test_assertion",
            "expected rejected state",
        ));
    }
    if capacity_state(&mut f.conn, f.ws, reserved.artifact.artifact_id).await? != "released" {
        return Err(Failure::internal(
            "test_assertion",
            "capacity reservation must be released exactly once",
        ));
    }

    // Exact replay returns the journaled terminal outcome — never a
    // second transition or a second release.
    let replay = f.store.record_verification(verify_pure).await?;
    if replay.artifact.state != domain::State::Rejected
        || replay.outcome.map(|o| o.kind) != Some(OutcomeKind::Terminal)
    {
        return Err(Failure::internal(
            "test_assertion",
            "replay must return the journaled rejection outcome",
        ));
    }
    Ok(())
}

/// Upstream `TestRecordRejectionReleasesCapacityExactlyOnceAndReplays`:
/// the explicit-reject path (a cause known before verification, e.g.
/// upload non-delivery) releases the reservation in its commit and
/// replays the journaled outcome.
#[tokio::test]
async fn explicit_rejection_releases_capacity_and_replays() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "reject_once").await?;
    let mut f = setup_fixture(&db, 10 << 20).await?;
    let reserved = f.reserve_artifact(&f.store, 1 << 20, "reserve-rj").await?;
    let reserved_id = reserved.artifact.artifact_id;
    let reject_pure = domain::reject(&domain::RejectInput {
        workspace_id: f.ws,
        artifact_id: reserved_id,
        current: reserved.artifact,
        expected: 1,
        reason: domain::FAILURE_CODE_UPLOAD_NON_DELIVERY,
    })?;
    let rejected = f.store.record_rejection(reject_pure.clone()).await?;
    if rejected.artifact.state != domain::State::Rejected {
        return Err(Failure::internal(
            "test_assertion",
            "expected rejected state",
        ));
    }
    if capacity_state(&mut f.conn, f.ws, reserved_id).await? != "released" {
        return Err(Failure::internal(
            "test_assertion",
            "capacity reservation must be released",
        ));
    }

    let replay = f.store.record_rejection(reject_pure).await?;
    if replay.artifact.state != domain::State::Rejected
        || replay.outcome.kind != OutcomeKind::Retryable
    {
        return Err(Failure::internal(
            "test_assertion",
            "replay must return the journaled reject outcome",
        ));
    }
    Ok(())
}

/// Upstream `TestReserveReplaysUnderAStableOperationIdentity` +
/// `TestReserveStillRejectsAReusedKeyBoundToDifferentFacts`: an exact
/// replay under the caller key returns the journaled reservation; the
/// same key bound to different content is a fingerprint conflict.
#[tokio::test]
async fn reserve_replays_and_rejects_fingerprint_mismatch() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "reserve_replay").await?;
    let f = setup_fixture(&db, 10 << 20).await?;

    // A stable operation identity derives the same ArtifactId and
    // StagingGeneration, so the replay is an exact command — the
    // durable receipt returns the journaled row.
    let (artifact_id, staging_generation) =
        domain::derive_reservation_identity("artifact-test-op-1")?;
    let reserve_pure = domain::reserve(&domain::ReserveInput {
        workspace_id: f.ws,
        artifact_id,
        staging_generation,
        limits: Limits { max_bytes: 1 << 20 },
        idempotency_key: "reserve-op-1",
        task_id: f.task,
        run_id: f.run,
        step_id: f.step,
        step_attempt_id: f.attempt,
        tool_call_attempt_id: None,
        producer_id: &f.producer,
        required_role: "report",
    })?;
    let first = f.store.reserve_artifact(reserve_pure.clone()).await?;
    let replay = f.store.reserve_artifact(reserve_pure).await?;
    if replay.artifact != first.artifact || replay.identity != first.identity {
        return Err(Failure::internal(
            "test_assertion",
            "replay must return the journaled reserve result",
        ));
    }

    // The same caller key bound to a different artifact is a hard
    // fingerprint conflict — never a replay.
    let different = domain::reserve(&domain::ReserveInput {
        workspace_id: f.ws,
        artifact_id: ArtifactId::new(),
        staging_generation: StagingGeneration::new(),
        limits: Limits { max_bytes: 1 << 20 },
        idempotency_key: "reserve-op-1",
        task_id: f.task,
        run_id: f.run,
        step_id: f.step,
        step_attempt_id: f.attempt,
        tool_call_attempt_id: None,
        producer_id: &f.producer,
        required_role: "report",
    })?;
    let failure = f
        .store
        .reserve_artifact(different)
        .await
        .map(|_| ())
        .unwrap_err();
    expect_code(failure, "IDEMPOTENCY_FINGERPRINT_MISMATCH")
}

/// The command-stage replays: an exact replay of BeginUpload / Verify /
/// Promote returns the durable snapshot rather than re-transitioning.
#[tokio::test]
async fn command_stage_replays_return_the_durable_result() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "stage_replay").await?;
    let f = setup_fixture(&db, 10 << 20).await?;
    let body = b"hello";
    let checksum = checksum_of(body);
    let reserved = f.reserve_artifact(&f.store, 1 << 20, "reserve-sr").await?;

    let begin_pure = domain::begin_upload(&domain::BeginUploadInput {
        workspace_id: f.ws,
        artifact_id: reserved.artifact.artifact_id,
        current: reserved.artifact.clone(),
        expected: 1,
    })?;
    let begun = f.store.record_begin_upload(begin_pure.clone()).await?;
    let replayed_begin = f.store.record_begin_upload(begin_pure).await?;
    if replayed_begin.artifact != begun.artifact {
        return Err(Failure::internal(
            "test_assertion",
            "begin-upload replay must return the durable snapshot",
        ));
    }

    let verify_pure = domain::verified(&domain::VerifiedInput {
        workspace_id: f.ws,
        artifact_id: begun.artifact.artifact_id,
        current: begun.artifact,
        expected: 2,
        size: body.len() as i64,
        checksum,
        secret_disclosure: false,
        rejection_code: "",
    })?;
    let verified = f.store.record_verification(verify_pure.clone()).await?;
    let replayed_verify = f.store.record_verification(verify_pure).await?;
    if replayed_verify.artifact != verified.artifact {
        return Err(Failure::internal(
            "test_assertion",
            "verify replay must return the durable snapshot",
        ));
    }

    let promote_pure = domain::promotion(&domain::PromotionInput {
        workspace_id: f.ws,
        artifact_id: verified.artifact.artifact_id,
        current: verified.artifact,
        expected: 3,
        content_generation: ContentGeneration::new(),
    })?;
    let promoted = f.store.record_promotion(promote_pure.clone()).await?;
    let replayed_promote = f.store.record_promotion(promote_pure).await?;
    if replayed_promote.artifact != promoted.artifact {
        return Err(Failure::internal(
            "test_assertion",
            "promote replay must return the durable snapshot",
        ));
    }
    Ok(())
}

/// Two-phase deletion: durable intent, atomic settlement with the
/// tombstone journal, the workspace quota release, and the replay that
/// returns the journaled settlement (`replayed`), never a second
/// tombstone.
#[tokio::test]
async fn two_phase_deletion_journals_and_releases_quota() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "two_phase").await?;
    let (mut f, finalize_pure) = finalize_fixture(&db, 1 << 20, 10 << 20).await?;
    let body_size = finalize_pure.artifact.verified_size;
    let key = format!("finalize-{}", f.attempt);
    f.store
        .commit_artifact(
            artifact_change_set(&finalize_pure, &key),
            f.completion_change_set(1, 1, 1, 1)?,
        )
        .await?;
    let ready = f
        .store
        .load_artifact(f.ws, finalize_pure.artifact.artifact_id)
        .await?;
    if ready.state != domain::State::Ready {
        return Err(Failure::internal("test_assertion", "artifact is not ready"));
    }
    let quota_before = quota_ready_bytes(&mut f.conn, f.ws).await?;

    // 1. Durable delete intent (runtime role — a plain UPDATE).
    let now = {
        let (t,): (OffsetDateTime,) = sqlx::query_as("SELECT clock_timestamp()")
            .fetch_one(&mut f.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        t
    };
    let intent = domain::mark_delete_pending(&domain::MarkDeletePendingInput {
        workspace_id: f.ws,
        artifact_id: ready.artifact_id,
        current: ready.clone(),
        expected: ready.version,
        delete_intent_at: now,
    })?;
    let pending = f.store.mark_delete_pending(intent.clone()).await?;
    if pending.state != domain::State::DeletePending || pending.delete_intent_at.is_none() {
        return Err(Failure::internal(
            "test_assertion",
            "delete intent must persist delete_pending + delete_intent_at",
        ));
    }

    // 2. The settlement under owner authority — the tombstone INSERT is
    //    withheld from central_runtime by design.
    let (next, tombstone) = domain::complete_deletion(&domain::CompleteDeletionInput {
        workspace_id: f.ws,
        artifact_id: pending.artifact_id,
        current: pending.clone(),
        expected: pending.version,
        tombstone_id: ArtifactTombstoneId::new(),
        deletion_reason: "test prune",
        deleted_at: now,
    })?;
    let settlement = f
        .owner_store
        .complete_deletion_with_tombstone(next, tombstone.clone())
        .await?;
    if settlement.replayed {
        return Err(Failure::internal(
            "test_assertion",
            "first settlement must not report replayed",
        ));
    }
    if settlement.artifact.state != domain::State::Deleted
        || settlement.tombstone.id != tombstone.id
    {
        return Err(Failure::internal(
            "test_assertion",
            "settlement must journal the tombstone and the deleted state",
        ));
    }
    if !f.store.has_tombstone(f.ws, pending.artifact_id).await? {
        return Err(Failure::internal(
            "test_assertion",
            "has_tombstone must see the journaled row",
        ));
    }
    let quota_after = quota_ready_bytes(&mut f.conn, f.ws).await?;
    if quota_after != quota_before - body_size {
        return Err(Failure::internal(
            "test_assertion",
            "the settlement must release the ready quota once",
        ));
    }

    // 3. A retried settlement returns the journaled settlement — never
    //    a second tombstone or a second quota release.
    let replayed = f
        .owner_store
        .complete_deletion_with_tombstone(settlement.artifact.clone(), tombstone)
        .await?;
    if !replayed.replayed || replayed.tombstone.id != settlement.tombstone.id {
        return Err(Failure::internal(
            "test_assertion",
            "a retried settlement must return the journaled tombstone",
        ));
    }
    if quota_ready_bytes(&mut f.conn, f.ws).await? != quota_after {
        return Err(Failure::internal(
            "test_assertion",
            "the replay must not release quota again",
        ));
    }
    Ok(())
}

/// `ArtifactSummaryRead` — bounded `(updated_at DESC, id DESC)` keyset
/// pages over the task's artifacts, with a `(updated_at, artifact_id)`
/// continuation and a `None` cursor at the end.
#[tokio::test]
async fn artifact_summary_read_pages_by_keyset() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "summary").await?;
    let f = setup_fixture(&db, 10 << 20).await?;

    let mut reserved_ids = Vec::new();
    for i in 0..5 {
        let reserved = f
            .reserve_artifact(&f.store, 1 << 20, &format!("reserve-page-{i}"))
            .await?;
        reserved_ids.push(reserved.artifact.artifact_id);
    }

    // First page of 2.
    let page1 = f
        .store
        .list_artifacts(&ArtifactListRequest {
            workspace_id: f.ws,
            task_id: f.task,
            cursor: None,
            page_size: 2,
        })
        .await?;
    if page1.artifacts.len() != 2 || page1.next_cursor.is_none() {
        return Err(Failure::internal(
            "test_assertion",
            "first page must carry 2 rows and a continuation",
        ));
    }
    // The cursor boundary is the page's last row — the next page must
    // strictly continue after it.
    let cursor: ArtifactSeekCursor = page1
        .next_cursor
        .expect("first page must carry a continuation cursor");
    let page2 = f
        .store
        .list_artifacts(&ArtifactListRequest {
            workspace_id: f.ws,
            task_id: f.task,
            cursor: Some(cursor),
            page_size: 2,
        })
        .await?;
    if page2.artifacts.len() != 2 || page2.next_cursor.is_none() {
        return Err(Failure::internal(
            "test_assertion",
            "second page must carry 2 rows and a continuation",
        ));
    }
    let cursor2 = page2
        .next_cursor
        .expect("second page must carry a continuation cursor");
    let page3 = f
        .store
        .list_artifacts(&ArtifactListRequest {
            workspace_id: f.ws,
            task_id: f.task,
            cursor: Some(cursor2),
            page_size: 2,
        })
        .await?;
    if page3.artifacts.len() != 1 || page3.next_cursor.is_some() {
        return Err(Failure::internal(
            "test_assertion",
            "last page must carry the final row and no continuation",
        ));
    }

    // No overlap and full coverage of the reserved set.
    let mut seen: Vec<ArtifactId> = page1
        .artifacts
        .iter()
        .chain(&page2.artifacts)
        .chain(&page3.artifacts)
        .map(|view| view.artifact_id)
        .collect();
    seen.sort();
    reserved_ids.sort();
    if seen != reserved_ids {
        return Err(Failure::internal(
            "test_assertion",
            "keyset pages must cover every artifact exactly once",
        ));
    }
    // The projection carries safe fields only — no keys, no versions.
    if page1.artifacts.iter().any(|view| view.verified_size != 0) {
        return Err(Failure::internal(
            "test_assertion",
            "reserved rows carry no verified size",
        ));
    }
    Ok(())
}

/// Upstream `TestCommitArtifactRefusesSupersededLeaseFence`: a
/// completion whose lease fence no longer matches the stored
/// `execution_ownership` row is refused with `STALE_LEASE_FENCE` and
/// commits nothing.
#[tokio::test]
async fn commit_artifact_refuses_a_superseded_lease_fence() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "stale_fence").await?;
    let (mut f, finalize_pure) = finalize_fixture(&db, 1 << 20, 10 << 20).await?;

    // A superseding pass rotates the lease: new credential, next
    // fencing generation. The fixture's release no longer describes
    // the stored row.
    sqlx::query(
        "UPDATE central.execution_ownership \
         SET lease_token_hash = $3, fencing_generation = fencing_generation + 1, \
         lease_expires_at = clock_timestamp() + interval '5 minutes' \
         WHERE workspace_id = $1 AND run_id = $2",
    )
    .bind(uuid_of!(f.ws))
    .bind(uuid_of!(f.run))
    .bind(&[9u8; 32][..])
    .execute(&mut f.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let key = format!("finalize-{}", f.attempt);
    let failure = f
        .store
        .commit_artifact(
            artifact_change_set(&finalize_pure, &key),
            f.completion_change_set(1, 1, 1, 1)?,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    if failure.code() != "STALE_LEASE_FENCE" {
        return Err(Failure::internal(
            "test_assertion",
            "expected STALE_LEASE_FENCE",
        ));
    }
    // Nothing committed: the artifact stays verifying, the task stays
    // running, no receipt was journaled.
    if artifact_state(&mut f.conn, f.ws, finalize_pure.artifact.artifact_id).await? != "verifying" {
        return Err(Failure::internal(
            "test_assertion",
            "a refused commit must leave the artifact verifying",
        ));
    }
    if task_status(&mut f.conn, f.ws, f.task).await? != "running" {
        return Err(Failure::internal(
            "test_assertion",
            "a refused commit must leave the task running",
        ));
    }
    Ok(())
}

/// Upstream `TestCommitArtifactRequiresALeaseFenceAlongsideASettlement`:
/// a settlement without its lease release cannot prove it still owns
/// the Run — `COMPLETION_LEASE_FENCE_REQUIRED` before any effect.
#[tokio::test]
async fn commit_artifact_requires_a_lease_fence_alongside_a_settlement() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "fence_required").await?;
    let (mut f, finalize_pure) = finalize_fixture(&db, 1 << 20, 10 << 20).await?;
    let mut exec_change = f.completion_change_set(1, 1, 1, 1)?;
    exec_change.lease_releases.clear();
    let key = format!("finalize-{}", f.attempt);
    let failure = f
        .store
        .commit_artifact(artifact_change_set(&finalize_pure, &key), exec_change)
        .await
        .map(|_| ())
        .unwrap_err();
    if failure.code() != "COMPLETION_LEASE_FENCE_REQUIRED" {
        return Err(Failure::internal(
            "test_assertion",
            "expected COMPLETION_LEASE_FENCE_REQUIRED",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, finalize_pure.artifact.artifact_id).await? != "verifying" {
        return Err(Failure::internal(
            "test_assertion",
            "a refused commit must leave the artifact verifying",
        ));
    }
    Ok(())
}

/// Upstream `TestCommitArtifactRejectsUnsupportedExecutionChange`: the
/// B10 completion path only ever settles one Step/Attempt and advances
/// its Task/Run — a change set carrying shapes it never produces (a
/// Checkpoint here) fails closed.
#[tokio::test]
async fn commit_artifact_rejects_unsupported_execution_change() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "unsupported").await?;
    let (mut f, finalize_pure) = finalize_fixture(&db, 1 << 20, 10 << 20).await?;
    let mut exec_change = f.completion_change_set(1, 1, 1, 1)?;
    // A checkpoint is a shape this path never legitimately carries.
    exec_change.checkpoints.push(exec::new_checkpoint(
        &serde_json::to_vec(&serde_json::json!({"schema_version": 1})).unwrap_or_default(),
    )?);
    let key = format!("finalize-{}", f.attempt);
    let failure = f
        .store
        .commit_artifact(artifact_change_set(&finalize_pure, &key), exec_change)
        .await
        .map(|_| ())
        .unwrap_err();
    if failure.code() != "UNSUPPORTED_EXECUTION_CHANGE" {
        return Err(Failure::internal(
            "test_assertion",
            "expected UNSUPPORTED_EXECUTION_CHANGE",
        ));
    }
    if artifact_state(&mut f.conn, f.ws, finalize_pure.artifact.artifact_id).await? != "verifying" {
        return Err(Failure::internal(
            "test_assertion",
            "a refused commit must leave the artifact verifying",
        ));
    }
    Ok(())
}

/// Upstream `TestReserveDoesNotDeadlockWithAnExecutionCommit` — harness
/// phase 3b's quota-lock fix: an "execution commit" holds the Task row
/// `FOR UPDATE`, then takes the Workspace `FOR KEY SHARE` (its event
/// counter's foreign-key check). The reservation locks the Workspace
/// quota `FOR NO KEY UPDATE` and blocks on the Task row's key-share
/// probe; `FOR UPDATE` would have closed the cycle. Both transactions
/// must complete.
#[tokio::test]
async fn reserve_does_not_deadlock_with_an_execution_commit() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "quota_lock").await?;
    let f = setup_fixture(&db, 1 << 30).await?;

    let mut other = role_conn(&db, "central_runtime").await?;
    let mut tx = other.begin().await.map_err(|e| classify_sqlx(&e))?;
    // The "execution commit" holds the Task row.
    sqlx::query("SELECT 1 FROM central.tasks WHERE workspace_id = $1 AND id = $2 FOR UPDATE")
        .bind(uuid_of!(f.ws))
        .bind(uuid_of!(f.task))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    let reserve_store = Store::new(role_pool(&db, "central_runtime").await?);
    let reserve_input = domain::reserve(&domain::ReserveInput {
        workspace_id: f.ws,
        artifact_id: ArtifactId::new(),
        staging_generation: StagingGeneration::new(),
        limits: Limits { max_bytes: 1 << 20 },
        idempotency_key: "reserve-deadlock",
        task_id: f.task,
        run_id: f.run,
        step_id: f.step,
        step_attempt_id: f.attempt,
        tool_call_attempt_id: None,
        producer_id: &f.producer,
        required_role: "report",
    })?;
    let done = tokio::spawn(async move {
        reserve_store
            .reserve_artifact(reserve_input)
            .await
            .map(|_| ())
    });
    // Let the reservation take its quota lock and block on the Task
    // row.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // The execution commit's foreign-key check on the Workspace row.
    sqlx::query("SELECT 1 FROM central.workspaces WHERE id = $1 FOR KEY SHARE")
        .bind(uuid_of!(f.ws))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    tx.commit().await.map_err(|e| classify_sqlx(&e))?;
    tokio::time::timeout(std::time::Duration::from_secs(10), done)
        .await
        .map_err(|_| Failure::internal("test_assertion", "ReserveArtifact did not finish"))?
        .map_err(|_| Failure::internal("test_assertion", "reserve task panicked"))??;
    Ok(())
}

/// Upstream `TestCompletionCommitDoesNotDeadlockWithAnExecutionCommit`
/// — the second half of the fix: the "execution commit" holds the
/// event counter first, then the Task row (its canonical order). The
/// completion commit takes the event counter first too, so it blocks
/// holding nothing and no cycle forms.
#[tokio::test]
async fn completion_commit_does_not_deadlock_with_an_execution_commit() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "commit_lock").await?;
    let (mut f, finalize_pure) = finalize_fixture(&db, 1 << 20, 10 << 20).await?;

    let mut other = role_conn(&db, "central_runtime").await?;
    let mut tx = other.begin().await.map_err(|e| classify_sqlx(&e))?;
    // The "execution commit" holds the event counter.
    sqlx::query(
        "UPDATE central.workspace_event_counters \
         SET last_event_sequence = last_event_sequence WHERE workspace_id = $1",
    )
    .bind(uuid_of!(f.ws))
    .execute(&mut *tx)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let commit_store = Store::new(role_pool(&db, "central_runtime").await?);
    let key = format!("finalize-order-{}", f.attempt);
    let change = artifact_change_set(&finalize_pure, &key);
    let exec_change = f.completion_change_set(1, 1, 1, 1)?;
    let done = tokio::spawn(async move { commit_store.commit_artifact(change, exec_change).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // Then its Task row.
    sqlx::query("SELECT 1 FROM central.tasks WHERE workspace_id = $1 AND id = $2 FOR UPDATE")
        .bind(uuid_of!(f.ws))
        .bind(uuid_of!(f.task))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    tx.commit().await.map_err(|e| classify_sqlx(&e))?;
    let committed = tokio::time::timeout(std::time::Duration::from_secs(10), done)
        .await
        .map_err(|_| Failure::internal("test_assertion", "CommitArtifact did not finish"))?
        .map_err(|_| Failure::internal("test_assertion", "commit task panicked"))??;
    if committed.replayed {
        return Err(Failure::internal(
            "test_assertion",
            "the blocked commit must still complete",
        ));
    }
    if task_status(&mut f.conn, f.ws, f.task).await? != "completed" {
        return Err(Failure::internal("test_assertion", "task is not completed"));
    }
    Ok(())
}
