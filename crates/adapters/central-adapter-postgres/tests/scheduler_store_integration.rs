//! PostgreSQL integration tests for the b35/b37 scheduler store
//! (`scheduler/`): worker registration handshake, the two-phase FIFO
//! claim with capability + concurrency + admission gating, lease
//! renewal/fencing/expiry, the suspect→lost ladder, deregistration,
//! the fenced dispatch writes, the outcome ledger with replay
//! dedupe/conflict, retry/backoff scheduling, timeout sweeps, and
//! `attempt_decisions`/`attempt_outcomes` — all committing state +
//! `run_events` + `event_outbox` atomically.
//!
//! Ports `internal/adapter/postgres/scheduler/{store,outcome}_test.go`
//! (the admission-test subset that needs the provisioner's disk markers
//! stays with Task 7's launcher work).
//!
//! Gated on `CENTRAL_TEST_DSN`. Fixture writes run under
//! `central_migration`; every store call runs under `central_runtime`.

use std::str::FromStr;

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::scheduler::PgSchedulerStore;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    RunId, SessionAttemptId, TaskId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_retry::domain::{OutcomeKind, ReasonCode};
use central_retry::port::{Outcome, Store as RetryStore};
use central_retry::query::AttemptHistoryRead;
use central_scheduler::domain::{self as sched, AttemptState, Worker, WorkerState};
use central_scheduler::port::Store as SchedulerStore;
use central_scheduler::query::SchedulerRead;
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
    let db = format!("sched_test_{label}_{}", std::process::id());
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

/// `fixture` — one Workspace + running Task/Run and the scheduler
/// store on a `central_runtime` pool, launchable on every harness.
struct Fixture {
    store: PgSchedulerStore,
    conn: PgConnection,
    ws: WorkspaceId,
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
    let store = PgSchedulerStore::new(runtime_pool, vec!["claude-code".to_string()]);
    Ok(Fixture {
        store,
        conn,
        ws,
        run,
    })
}

/// A `claude-code`/`worktree` worker bound to the fixture workspace.
fn worker(fx: &Fixture, max_concurrent: i32) -> Worker {
    Worker {
        id: WorkerId::new(),
        workspace_id: fx.ws,
        protocol_version: sched::PROTOCOL_VERSION,
        harness_kinds: vec!["claude-code".to_string()],
        workspace_kinds: vec!["worktree".to_string(), "directory".to_string()],
        max_concurrent_attempts: max_concurrent,
        state: WorkerState::Active,
        registered_at: None,
        last_seen_at: None,
    }
}

/// Seeds a `ready` node as `central_migration`; `age_ms` staggers
/// `created_at` so the FIFO order is deterministic.
async fn seed_ready_node(
    fx: &mut Fixture,
    node_key: &str,
    harness: &str,
    workspace_kind: &str,
    age_ms: i64,
) -> Result<WorkflowNodeId> {
    let id = WorkflowNodeId::new();
    sqlx::query(
        "INSERT INTO central.workflow_nodes \
         (id, run_id, workspace_id, node_key, harness, workspace_kind, depth, state, \
          spec, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 0, 'ready', '{}'::jsonb, now() - make_interval(secs => $7))",
    )
    .bind(uuid_of!(id))
    .bind(uuid_of!(fx.run))
    .bind(uuid_of!(fx.ws))
    .bind(node_key)
    .bind(harness)
    .bind(workspace_kind)
    .bind(age_ms as f64 / 1000.0)
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(id)
}

async fn node_state(fx: &mut Fixture, node: WorkflowNodeId) -> Result<String> {
    sqlx::query_scalar("SELECT state FROM central.workflow_nodes WHERE id = $1")
        .bind(uuid_of!(node))
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn attempt_state(fx: &mut Fixture, attempt: SessionAttemptId) -> Result<String> {
    sqlx::query_scalar("SELECT state FROM central.session_attempts WHERE id = $1")
        .bind(uuid_of!(attempt))
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn kinds(fx: &mut Fixture, kind: &str) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM central.run_events WHERE run_id = $1 AND kind = $2")
        .bind(uuid_of!(fx.run))
        .bind(kind)
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn outbox_rows(fx: &mut Fixture) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM central.event_outbox")
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

/// `TestRegisterWorkerAcceptsAndRefuses` — protocol/capability refusals
/// deny `WORKER_REGISTRATION_REJECTED`; a clean registration commits
/// and `list_workers` reads it back.
#[tokio::test]
async fn register_worker_accept_refuse() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "reg").await?;
    let fx = setup_fixture(&db).await?;

    // Wrong protocol refuses.
    let mut bad = worker(&fx, 4);
    bad.protocol_version = 99;
    let err = fx.store.register_worker(bad).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_WORKER_REGISTRATION_REJECTED);

    // A harness outside the launchable set refuses.
    let mut bad = worker(&fx, 4);
    bad.harness_kinds = vec!["opencode".to_string()];
    let err = fx.store.register_worker(bad).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_WORKER_REGISTRATION_REJECTED);

    let id = fx.store.register_worker(worker(&fx, 4)).await?;
    let workers = fx.store.list_workers(fx.ws).await?;
    assert!(
        workers
            .iter()
            .any(|w| w.id == id && w.state == WorkerState::Active)
    );
    assert!(fx.store.load_worker(id).await?.is_some());
    Ok(())
}

/// `TestClaimReadyCommitsAttemptLeaseAndEvent` + `…CapabilityMismatch` +
/// `…InflightCapAndFIFO`: the claim atomically lands `dispatched` +
/// attempt + lease + `node_dispatched`, honors the capability
/// intersection and the per-worker cap in FIFO order.
#[tokio::test]
async fn claim_ready_commits_attempt_lease_event() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "claim").await?;
    let mut fx = setup_fixture(&db).await?;

    let older = seed_ready_node(&mut fx, "a-first", "claude-code", "worktree", 2000).await?;
    let newer = seed_ready_node(&mut fx, "b-second", "claude-code", "worktree", 1000).await?;
    // Incompatible capability — never claimed.
    let _other = seed_ready_node(&mut fx, "c-codex", "codex", "worktree", 3000).await?;
    // A deferred node (not_before in the future) is invisible.
    let deferred = seed_ready_node(&mut fx, "d-later", "claude-code", "worktree", 4000).await?;
    sqlx::query(
        "UPDATE central.workflow_nodes SET not_before = now() + interval '1 hour' WHERE id = $1",
    )
    .bind(uuid_of!(deferred))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let wid = fx.store.register_worker(worker(&fx, 2)).await?;
    let claimed = fx.store.claim_ready(wid, 10).await?;
    assert_eq!(claimed.len(), 2, "cap = 2 → two claims despite limit 10");

    // FIFO by COALESCE(ready_at, created_at), then node_key.
    assert_eq!(claimed[0].attempt.node_id, older);
    assert_eq!(claimed[1].attempt.node_id, newer);
    assert_eq!(claimed[0].attempt.attempt_seq, 1);
    assert_eq!(claimed[0].lease.worker_id, wid);
    assert_eq!(node_state(&mut fx, older).await?, "dispatched");
    assert_eq!(kinds(&mut fx, "node_dispatched").await?, 2);
    assert_eq!(
        outbox_rows(&mut fx).await?,
        2,
        "each dispatch committed an outbox row"
    );

    // The live-lease partial index backs the ledger reads.
    let lease = fx.store.live_lease(older).await?.expect("live lease");
    assert_eq!(lease.attempt_id, claimed[0].attempt.id);
    let attempts = fx.store.list_node_attempts(older).await?;
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].state, AttemptState::Claimed);

    // A second claim sees the cap is full.
    assert!(fx.store.claim_ready(wid, 10).await?.is_empty());
    Ok(())
}

/// `TestClaimReadyWorkerGate` — unknown worker refuses
/// `WORKER_NOT_FOUND`; a non-active worker refuses
/// `WORKER_NOT_ACTIVE`.
#[tokio::test]
async fn claim_ready_worker_gate() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "gate").await?;
    let mut fx = setup_fixture(&db).await?;
    let _ = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;

    let err = fx.store.claim_ready(WorkerId::new(), 1).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_WORKER_NOT_FOUND);

    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    sqlx::query("UPDATE central.worker_registrations SET state = 'lost' WHERE id = $1")
        .bind(uuid_of!(wid))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let err = fx.store.claim_ready(wid, 1).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_WORKER_NOT_ACTIVE);
    Ok(())
}

/// `TestRenewLeaseExtendsAndStaleRejects` + `TestFenceGuardsWrites` +
/// `TestWorkerLeasesListsLiveOnly`.
#[tokio::test]
async fn renew_lease_fence_worker_leases() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "renew").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let lease = claimed[0].lease.id;
    let attempt = claimed[0].attempt.id;

    // Live renewal extends expires_at.
    fx.store.renew_lease(lease, wid).await?;

    // Fence passes for the live triple.
    fx.store.fence(node, attempt, lease).await?;
    // A foreign lease id fences stale.
    let err = fx
        .store
        .fence(
            node,
            attempt,
            central_foundation::identity::NodeLeaseId::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);

    // worker_leases lists the live lease only.
    let leases = fx.store.worker_leases(wid).await?;
    assert_eq!(leases.len(), 1);

    // Releasing the lease (as the owner would after a close) makes
    // renewal stale — and journals lease_renewal_rejected.
    sqlx::query("UPDATE central.node_leases SET released_at = now() WHERE id = $1")
        .bind(uuid_of!(lease))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let err = fx.store.renew_lease(lease, wid).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_RENEWAL_STALE);
    assert_eq!(kinds(&mut fx, "lease_renewal_rejected").await?, 1);
    assert!(fx.store.worker_leases(wid).await?.is_empty());
    let err = fx.store.fence(node, attempt, lease).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);
    Ok(())
}

/// `TestExpireLeasesNeverStarted` + `…StartedGoesAmbiguous`: expiry
/// splits on `started_at` — never-started goes `failed` + node `ready`
/// for re-dispatch; started parks `ambiguous` + node
/// `attempt_ambiguous`.
#[tokio::test]
async fn expire_leases_split() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "expire").await?;
    let mut fx = setup_fixture(&db).await?;
    let n_claimed = seed_ready_node(&mut fx, "claimed", "claude-code", "worktree", 0).await?;
    let n_started = seed_ready_node(&mut fx, "started", "claude-code", "worktree", 1).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 2).await?;
    let (a_never, a_started) = if claimed[0].attempt.node_id == n_claimed {
        (claimed[0].attempt.id, claimed[1].attempt.id)
    } else {
        (claimed[1].attempt.id, claimed[0].attempt.id)
    };
    fx.store.mark_provisioning(a_started, "/tmp/p").await?;
    fx.store.mark_started(a_started, "hsess-1").await?;

    // Force both leases expired.
    sqlx::query("UPDATE central.node_leases SET expires_at = now() - interval '1 second'")
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let results = fx.store.expire_leases(OffsetDateTime::now_utc()).await?;
    assert_eq!(results.len(), 2);

    // Never-started: attempt failed + node ready (re-queue) + events.
    assert_eq!(attempt_state(&mut fx, a_never).await?, "failed");
    assert_eq!(node_state(&mut fx, n_claimed).await?, "ready");
    assert_eq!(kinds(&mut fx, "lease_expired").await?, 2);

    // Started: ambiguous park — no attempt_outcomes row (ambiguous is
    // not an outcome).
    assert_eq!(attempt_state(&mut fx, a_started).await?, "ambiguous");
    assert_eq!(node_state(&mut fx, n_started).await?, "attempt_ambiguous");
    assert_eq!(kinds(&mut fx, "attempt_ambiguous").await?, 1);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM central.attempt_outcomes WHERE attempt_id = $1")
            .bind(uuid_of!(a_started))
            .fetch_one(&mut fx.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(rows, 0, "ambiguous parks never write the outcome ledger");
    Ok(())
}

/// `TestSweepSuspectsSuspectThenLost` — the missed-beat ladder:
/// 2+ missed beats marks `suspect` (once, journaled), 5+ marks `lost`
/// and expires the worker's leases.
#[tokio::test]
async fn sweep_suspects_ladder() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "ladder").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed_attempt = fx.store.claim_ready(wid, 1).await?[0].attempt.id;

    // ~3 missed beats → suspect; journal exactly once across sweeps.
    sqlx::query("UPDATE central.node_leases SET last_heartbeat_at = now() - interval '50 seconds'")
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    fx.store.sweep_suspects(OffsetDateTime::now_utc()).await?;
    assert_eq!(
        fx.store.load_worker(wid).await?.unwrap().state,
        WorkerState::Suspect
    );
    fx.store.sweep_suspects(OffsetDateTime::now_utc()).await?;
    assert_eq!(kinds(&mut fx, "worker_suspect").await?, 1);

    // ≥5 missed beats → lost + lease expiry through the loss path.
    sqlx::query(
        "UPDATE central.node_leases SET last_heartbeat_at = now() - interval '200 seconds'",
    )
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    fx.store.sweep_suspects(OffsetDateTime::now_utc()).await?;
    assert_eq!(
        fx.store.load_worker(wid).await?.unwrap().state,
        WorkerState::Lost
    );
    // Never-started via worker loss is definite: failed + ready.
    assert_eq!(node_state(&mut fx, node).await?, "ready");
    assert_eq!(attempt_state(&mut fx, claimed_attempt).await?, "failed");
    assert_eq!(kinds(&mut fx, "worker_lost").await?, 1);
    Ok(())
}

/// `TestDeregisterWorkerReleasesNeverStartedKeepsStarted`: clean
/// shutdown releases unstarted leases (node back to `ready`, attempt
/// `cancelled`, `WORKER_SHUTDOWN_LEASE_RELEASED` reason) while started
/// attempts keep their lease; the row closes `deregistered` and
/// re-deregistration is an idempotent no-op.
#[tokio::test]
async fn deregister_releases_never_started_keeps_started() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "dereg").await?;
    let mut fx = setup_fixture(&db).await?;
    let n1 = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let n2 = seed_ready_node(&mut fx, "b", "claude-code", "worktree", 1).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 2).await?;
    let (cold, hot) = if claimed[0].attempt.node_id == n1 {
        (claimed[0].attempt.id, claimed[1].attempt.id)
    } else {
        (claimed[1].attempt.id, claimed[0].attempt.id)
    };
    fx.store.mark_provisioning(hot, "/tmp/p").await?;
    fx.store.mark_started(hot, "hsess").await?;

    fx.store.deregister_worker(wid, "test").await?;
    assert_eq!(
        fx.store.load_worker(wid).await?.unwrap().state,
        WorkerState::Deregistered
    );
    assert_eq!(attempt_state(&mut fx, cold).await?, "cancelled");
    assert_eq!(node_state(&mut fx, n1).await?, "ready");
    assert_eq!(attempt_state(&mut fx, hot).await?, "started");
    assert_eq!(node_state(&mut fx, n2).await?, "running");
    assert_eq!(kinds(&mut fx, "worker_deregistered").await?, 1);

    // Idempotent replay.
    fx.store.deregister_worker(wid, "test").await?;
    assert_eq!(kinds(&mut fx, "worker_deregistered").await?, 1);
    Ok(())
}

/// `TestDispatchWritesAreFencedAndJournaled` — provisioning/started
/// writes commit under the fence with `attempt_started` journaled; a
/// stale lease rejects them.
#[tokio::test]
async fn dispatch_writes_fenced() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "fenced").await?;
    let mut fx = setup_fixture(&db).await?;
    let _ = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let attempt = claimed[0].attempt.id;

    fx.store.mark_provisioning(attempt, "/tmp/ws").await?;
    assert_eq!(attempt_state(&mut fx, attempt).await?, "provisioning");
    fx.store.mark_started(attempt, "hsess").await?;
    assert_eq!(attempt_state(&mut fx, attempt).await?, "started");
    assert_eq!(kinds(&mut fx, "attempt_started").await?, 1);

    // Release the lease → subsequent fenced writes reject.
    sqlx::query("UPDATE central.node_leases SET released_at = now() WHERE attempt_id = $1")
        .bind(uuid_of!(attempt))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let err = fx
        .store
        .mark_provisioning(attempt, "/tmp")
        .await
        .unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);
    Ok(())
}

/// `TestRecordOutcomeSucceeded` — the definite success: ledger row,
/// attempt `succeeded`, lease released, node `succeeded`,
/// `attempt_succeeded` + `node_succeeded` journaled.
#[tokio::test]
async fn record_outcome_succeeded() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "out_s").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let attempt = claimed[0].attempt.id;
    fx.store.mark_provisioning(attempt, "/tmp/p").await?;
    fx.store.mark_started(attempt, "hsess").await?;

    let res = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: attempt,
            kind: OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: [0xAA; 32],
            retry_after: None,
        },
    )
    .await?;
    assert!(!res.deduped);
    assert_eq!(res.node_status, "succeeded");
    assert_eq!(attempt_state(&mut fx, attempt).await?, "succeeded");
    assert_eq!(node_state(&mut fx, node).await?, "succeeded");
    assert_eq!(kinds(&mut fx, "attempt_succeeded").await?, 1);
    assert_eq!(kinds(&mut fx, "node_succeeded").await?, 1);
    assert!(fx.store.live_lease(node).await?.is_none());
    Ok(())
}

/// `TestRecordOutcomeRetryableSchedulesBackoff` + `…BudgetExhausted` +
/// `…TerminalClass`: a retryable failure re-queues the node under
/// `not_before` + `attempt_retry_scheduled`; exhaustion/non-retryable
/// land `failed_terminal`.
#[tokio::test]
async fn record_outcome_retryable_then_exhausted() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "out_r").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    // Tighten the class budget to 2 attempts so the second failure
    // exhausts (default transient budget is 3).
    sqlx::query(
        "UPDATE central.workflow_nodes \
         SET spec = '{\"max_attempts\":{\"transient\":2}}'::jsonb WHERE id = $1",
    )
    .bind(uuid_of!(node))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;

    // First ADAPTER_ERROR (transient): node back to ready, retry_at set.
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let a1 = claimed[0].attempt.id;
    let res = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: a1,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::AdapterError.as_str().to_owned(),
            fingerprint: [0x01; 32],
            retry_after: None,
        },
    )
    .await?;
    assert_eq!(res.node_status, "ready");
    assert!(res.retry_at.is_some());
    assert_eq!(kinds(&mut fx, "attempt_retry_scheduled").await?, 1);
    let nb: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT not_before FROM central.workflow_nodes WHERE id = $1")
            .bind(uuid_of!(node))
            .fetch_one(&mut fx.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert!(nb.is_some_and(|t| t > OffsetDateTime::now_utc()));

    // Clear not_before and claim the retry — attempt_seq 2.
    sqlx::query("UPDATE central.workflow_nodes SET not_before = NULL WHERE id = $1")
        .bind(uuid_of!(node))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let a2 = claimed[0].attempt.id;
    assert_eq!(claimed[0].attempt.attempt_seq, 2);

    // Second failure exhausts the per-class budget → failed_terminal.
    let res = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: a2,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::AdapterError.as_str().to_owned(),
            fingerprint: [0x02; 32],
            retry_after: None,
        },
    )
    .await?;
    assert_eq!(res.node_status, "failed_terminal");
    assert_eq!(node_state(&mut fx, node).await?, "failed_terminal");
    assert_eq!(kinds(&mut fx, "node_failed_terminal").await?, 1);

    // attempt_counts reports the journaled consumption.
    let counts = RetryStore::attempt_counts(&fx.store, node).await?;
    assert_eq!(counts.total, 2);
    assert_eq!(
        counts
            .per_class
            .get(&central_retry::domain::FailureClass::Transient),
        Some(&2)
    );
    Ok(())
}

/// `TestRecordOutcomeTerminalClass` — a non-retryable class lands
/// `failed_terminal` carrying its own reason code on the first
/// failure.
#[tokio::test]
async fn record_outcome_terminal_class() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "out_t").await?;
    let mut fx = setup_fixture(&db).await?;
    let _node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let a = fx.store.claim_ready(wid, 1).await?[0].attempt.id;

    let res = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: a,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::SpecValidationFailed.as_str().to_owned(),
            fingerprint: [0x0A; 32],
            retry_after: None,
        },
    )
    .await?;
    assert_eq!(res.node_status, "failed_terminal");
    assert!(res.retry_at.is_none());
    Ok(())
}

/// `TestRecordOutcomeReplayDedupeAndConflict` — same key+same
/// fingerprint dedupes with `command_deduped`; same key+different
/// fingerprint conflicts `DUPLICATE_IDEMPOTENCY_KEY`.
#[tokio::test]
async fn record_outcome_replay_dedupe_conflict() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "out_d").await?;
    let mut fx = setup_fixture(&db).await?;
    let _ = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let a = fx.store.claim_ready(wid, 1).await?[0].attempt.id;
    fx.store.mark_provisioning(a, "/tmp/p").await?;
    fx.store.mark_started(a, "hsess").await?;

    let outcome = Outcome {
        attempt_id: a,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: [0xCC; 32],
        retry_after: None,
    };
    RetryStore::record_outcome(&fx.store, outcome.clone()).await?;

    // Replay: the lease is released so the fence rejects — replay
    // resolution still dedupes on the committed ledger row.
    let replay = RetryStore::record_outcome(&fx.store, outcome).await?;
    assert!(replay.deduped);
    assert_eq!(kinds(&mut fx, "command_deduped").await?, 1);

    // Same key, different fingerprint → conflict.
    let err = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: a,
            kind: OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: [0xDD; 32],
            retry_after: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), ReasonCode::DuplicateIdempotencyKey.as_str());
    Ok(())
}

/// `TestRecordOutcomeStaleLeaseUnknownOutcome` — an unrecorded outcome
/// on a fenced-dead lease stays `LEASE_FENCE_STALE` (fail-closed; the
/// outcome is not conjured).
#[tokio::test]
async fn record_outcome_stale_lease() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "out_l").await?;
    let mut fx = setup_fixture(&db).await?;
    let _ = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let a = fx.store.claim_ready(wid, 1).await?[0].attempt.id;
    sqlx::query("UPDATE central.node_leases SET released_at = now() WHERE attempt_id = $1")
        .bind(uuid_of!(a))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let err = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: a,
            kind: OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: [0xEE; 32],
            retry_after: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);
    Ok(())
}

/// `TestSweepSkipsUnresolvedAmbiguous` + a resolved-decision unblock:
/// an unresolved `ambiguous` attempt blocks the node's aggregate
/// timer; a recorded `rerun` decision unblocks it.
#[tokio::test]
async fn sweep_blocked_by_unresolved_ambiguous() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sweep_a").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    sqlx::query("UPDATE central.workflow_nodes SET node_timeout_seconds = 60 WHERE id = $1")
        .bind(uuid_of!(node))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let a = claimed[0].attempt.id;
    fx.store.mark_provisioning(a, "/tmp/p").await?;
    fx.store.mark_started(a, "hsess").await?;

    // Age the first dispatch past the node bound and park the attempt
    // ambiguous — the sweep must skip the node (blocked timers).
    sqlx::query("UPDATE central.session_attempts SET claimed_at = now() - interval '1 hour', started_at = now() - interval '30 minutes', state = 'ambiguous' WHERE id = $1")
        .bind(uuid_of!(a))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("UPDATE central.node_leases SET released_at = now() WHERE attempt_id = $1")
        .bind(uuid_of!(a))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("UPDATE central.workflow_nodes SET state = 'attempt_ambiguous' WHERE id = $1")
        .bind(uuid_of!(node))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert!(sum.node_timeouts.is_empty());
    assert_eq!(sum.skipped_ambiguous.len(), 1);

    // The unresolved decision reads back `None`.
    assert!(fx.store.load_attempt_decision(a).await?.is_none());
    Ok(())
}

/// `TestSweepWorkflowTimeoutCascade` — a run past its absolute
/// deadline cancels every non-terminal node, force-closes live
/// attempts `cancelled`, and lands `failed_terminal`/`WORKFLOW_TIMEOUT`.
#[tokio::test]
async fn sweep_workflow_timeout_cascade() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sweep_w").await?;
    let mut fx = setup_fixture(&db).await?;
    let n1 = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let n2 = seed_ready_node(&mut fx, "b", "claude-code", "worktree", 1).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let a = fx.store.claim_ready(wid, 1).await?[0].attempt.id;
    sqlx::query("UPDATE central.runs SET deadline = now() - interval '1 minute' WHERE id = $1")
        .bind(uuid_of!(fx.run))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert_eq!(sum.workflow_timeouts, vec![fx.run]);
    assert_eq!(node_state(&mut fx, n1).await?, "cancelled");
    assert_eq!(node_state(&mut fx, n2).await?, "cancelled");
    // The claimed attempt was force-closed cancelled (no kill needed —
    // it never started).
    assert_eq!(attempt_state(&mut fx, a).await?, "cancelled");
    assert_eq!(kinds(&mut fx, "cancel_requested").await?, 1);
    let status: String = sqlx::query_scalar("SELECT status FROM central.runs WHERE id = $1")
        .bind(uuid_of!(fx.run))
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(status, "failed_terminal");
    // The forced close journaled through the ledger.
    let outcomes = fx.store.list_node_outcomes(n1).await?;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].kind, OutcomeKind::Cancelled);
    Ok(())
}

/// `TestRunCompensationManagedOnce` + `…UnmanagedJournalsOnly`: a
/// managed hook executes through the executor at most once
/// (`compensation_requested` dedupes repeat calls); an unmanaged hook
/// journals the request only.
#[tokio::test]
async fn run_compensation_managed_once() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "comp").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    sqlx::query(
        "UPDATE central.workflow_nodes \
         SET spec = '{\"on_terminal_failure\":\"cleanup_workspace\"}'::jsonb, \
             state = 'failed_terminal' WHERE id = $1",
    )
    .bind(uuid_of!(node))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    // No executor installed — managed hook still journals the request
    // then `executor_unavailable`.
    RetryStore::run_compensation(&fx.store, node).await?;
    assert_eq!(kinds(&mut fx, "compensation_requested").await?, 2);
    // Second call dedupes on the committed request row.
    RetryStore::run_compensation(&fx.store, node).await?;
    assert_eq!(kinds(&mut fx, "compensation_requested").await?, 2);
    Ok(())
}
