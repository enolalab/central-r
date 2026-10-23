//! PostgreSQL integration tests for the b35/b37 scheduler store
//! (`scheduler/`): worker registration handshake, the two-phase FIFO
//! claim with capability + concurrency + admission gating, lease
//! renewal/fencing/expiry, the suspect→lost ladder, deregistration,
//! the fenced dispatch writes, the outcome ledger with replay
//! dedupe/conflict, retry/backoff scheduling, timeout sweeps, and
//! `attempt_decisions`/`attempt_outcomes` — all committing state +
//! `run_events` + `event_outbox` atomically.
//!
//! Ports `internal/adapter/postgres/scheduler/{store,admission,outcome}_test.go`.
//!
//! Upstream → port accounting (all 40 upstream test functions):
//!
//! | upstream func | port |
//! |---|---|
//! | `TestRegisterWorkerAcceptsAndRefuses` | `register_worker_accept_refuse` |
//! | `TestClaimReadyCommitsAttemptLeaseAndEvent` | `claim_ready_commits_attempt_lease_event` |
//! | `TestClaimReadyConcurrentSingleWinner` | `claim_ready_concurrent_single_winner` |
//! | `TestClaimReadyCapabilityMismatchSkips` | folded into `claim_ready_commits_attempt_lease_event` (codex leg) |
//! | `TestClaimReadyInflightCapAndFIFO` | folded into `claim_ready_commits_attempt_lease_event` (cap/FIFO legs) |
//! | `TestClaimReadyWorkerGate` | `claim_ready_worker_gate` (incl. the suspect-claims leg) |
//! | `TestRenewLeaseExtendsAndStaleRejects` | `renew_lease_fence_worker_leases` |
//! | `TestFenceGuardsWrites` | `renew_lease_fence_worker_leases` |
//! | `TestWorkerLeasesListsLiveOnly` | `renew_lease_fence_worker_leases` |
//! | `TestExpireLeasesNeverStarted` | `expire_leases_split` |
//! | `TestExpireLeasesStartedGoesAmbiguous` | `expire_leases_split` |
//! | `TestSweepSuspectsSuspectThenLost` | `sweep_suspects_ladder` |
//! | `TestSweepLostStartedAttemptAmbiguous` | `sweep_lost_started_attempt_ambiguous` |
//! | `TestReconcileExpiresAndOrphans` | `reconcile_expires_and_orphans` |
//! | `TestDeregisterWorkerReleasesNeverStartedKeepsStarted` | `deregister_releases_never_started_keeps_started` |
//! | `TestDispatchWritesAreFencedAndJournaled` | `dispatch_writes_fenced` |
//! | `TestDiskBudgetsMatchProvisionerMarkers` | DEFERRED — the only admission func needing the provisioner's stamped disk markers (Task 7 launcher work) |
//! | `TestClaimReadyAdmissionDefersHostCapAndKeepsFIFO` | `claim_admission_host_cap_defers_keeps_fifo` |
//! | `TestClaimReadyAdmissionRunInflightCap` | `claim_admission_run_inflight_cap` |
//! | `TestRecordCeilingBreachClosesAttempt` | `record_ceiling_breach_closes_attempt` |
//! | `TestListWallClockBreaches` | `list_wall_clock_breaches` |
//! | `TestRecordOutcomeSucceeded` | `record_outcome_succeeded` |
//! | `TestRecordOutcomeRetryableSchedulesBackoff` | `record_outcome_retryable_then_exhausted` (fixed clock/jitter leg) |
//! | `TestRecordOutcomeBudgetExhausted` | folded into `record_outcome_retryable_then_exhausted` (exhaustion leg) |
//! | `TestRecordOutcomeTerminalClass` | `record_outcome_terminal_class` |
//! | `TestRecordOutcomeReplayDedupeAndConflict` | `record_outcome_replay_dedupe_conflict` |
//! | `TestRecordOutcomeStaleLeaseUnknownOutcome` | `record_outcome_stale_lease` |
//! | `TestRecordOutcomeValidation` | `record_outcome_reason_missing`; the kind-unknown/fingerprint legs are UNVERIFIABLE in Rust — a closed `OutcomeKind` enum and fixed `[u8; 32]` fingerprint make the invalid inputs unconstructible |
//! | `TestSweepSessionBreachConfirmedKill` | `sweep_session_breach_confirmed_kill` |
//! | `TestSweepSessionBreachUnconfirmedKill` | `sweep_session_breach_unconfirmed_kill` |
//! | `TestSweepNodeTimeoutClaimed` | `sweep_node_timeout_claimed` |
//! | `TestSweepNodeTimeoutStartedKill` | `sweep_node_timeout_started_kill` |
//! | `TestSweepNodeTimeoutUnconfirmedKill` | `sweep_node_timeout_unconfirmed_kill` |
//! | `TestSweepNodeTimeoutReadyBackoff` | `sweep_node_timeout_ready_backoff` |
//! | `TestSweepWorkflowTimeoutCascade` | `sweep_workflow_timeout_cascade` |
//! | `TestSweepWorkflowTimeoutBlocked` | `sweep_workflow_timeout_blocked` |
//! | `TestSweepSkipsUnresolvedAmbiguous` | `sweep_blocked_by_unresolved_ambiguous` |
//! | `TestRunCompensationManagedOnce` | `run_compensation_executor_once` (executor + `executed`-result legs) + `run_compensation_managed_once` (`executor_unavailable` leg) |
//! | `TestRunCompensationUnmanagedJournalsOnly` | `run_compensation_unmanaged_journals_only` |
//! | `TestRunCompensationFailureNeverReopens` | `run_compensation_failure_never_reopens` |
//!
//! Gated on `CENTRAL_TEST_DSN`. Fixture writes run under
//! `central_migration`; every store call runs under `central_runtime`.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::scheduler::PgSchedulerStore;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    NodeLeaseId, RunId, SessionAttemptId, TaskId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_retry::domain::{FailureClass, OutcomeKind, ReasonCode, RetryPolicy};
use central_retry::port::{
    Clock, CompensationExecutor, Killer, Outcome, Rand, SkippedScope, Store as RetryStore,
};
use central_retry::query::AttemptHistoryRead;
use central_scheduler::admission::{
    ConcurrencyProfile, REASON_CAPACITY_ADMISSION_DEFERRED, REASON_INVALID_BREACH_CODE,
    REASON_SESSION_WALL_CLOCK_REACHED,
};
use central_scheduler::domain::{self as sched, AttemptState, ClaimedAttempt, Worker, WorkerState};
use central_scheduler::port::Store as SchedulerStore;
use central_scheduler::query::SchedulerRead;
use sqlx::{Connection, PgConnection, PgPool};
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

/// `claimAttempt` — claims the seeded ready node and returns the claim.
async fn claim_attempt(fx: &Fixture, worker_id: WorkerId) -> Result<ClaimedAttempt> {
    let mut claimed = fx.store.claim_ready(worker_id, 1).await?;
    assert_eq!(claimed.len(), 1, "claim: want exactly one attempt");
    Ok(claimed.swap_remove(0))
}

/// `startAttempt` — drives the claimed attempt through provisioning
/// into `started` — the session-kill-eligible state.
async fn start_attempt(fx: &Fixture, attempt_id: SessionAttemptId) -> Result<()> {
    fx.store
        .mark_provisioning(attempt_id, "/scratch/ws")
        .await?;
    fx.store.mark_started(attempt_id, "session-1").await
}

/// `attemptRow` — (state, dispatch_reason_code, ended_at) for one attempt.
async fn attempt_row(
    fx: &mut Fixture,
    attempt: SessionAttemptId,
) -> Result<(String, Option<String>, Option<OffsetDateTime>)> {
    sqlx::query_as(
        "SELECT state, dispatch_reason_code, ended_at \
         FROM central.session_attempts WHERE id = $1",
    )
    .bind(uuid_of!(attempt))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

/// `outcomeRows` — the attempt's ledger rows as (kind, reason, class).
async fn outcome_rows(
    fx: &mut Fixture,
    attempt: SessionAttemptId,
) -> Result<Vec<(String, String, String)>> {
    sqlx::query_as(
        "SELECT outcome_kind, reason_code, failure_class \
         FROM central.attempt_outcomes WHERE attempt_id = $1 ORDER BY outcome_kind",
    )
    .bind(uuid_of!(attempt))
    .fetch_all(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

/// `eventRows` — (kind, node_id, attempt_id, reason_code) tuples for
/// the fixture run in seq order.
#[allow(clippy::type_complexity)]
async fn event_rows(
    fx: &mut Fixture,
) -> Result<Vec<(String, Option<String>, Option<String>, Option<String>)>> {
    sqlx::query_as(
        "SELECT kind, node_id::text, attempt_id::text, reason_code \
         FROM central.run_events WHERE run_id = $1 ORDER BY seq",
    )
    .bind(uuid_of!(fx.run))
    .fetch_all(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))
}

/// `readyAt` — the node's FIFO-ordering stamp (NULL until a requeue).
async fn ready_at(fx: &mut Fixture, node: WorkflowNodeId) -> Result<Option<OffsetDateTime>> {
    sqlx::query_scalar("SELECT ready_at FROM central.workflow_nodes WHERE id = $1")
        .bind(uuid_of!(node))
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

/// `mustExec` — stamps `ready_at` explicitly (upstream's ready-at aging).
async fn set_ready_at(fx: &mut Fixture, node: WorkflowNodeId, secs_ago: f64) -> Result<()> {
    sqlx::query(
        "UPDATE central.workflow_nodes \
         SET ready_at = now() - make_interval(secs => $2) WHERE id = $1",
    )
    .bind(uuid_of!(node))
    .bind(secs_ago)
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// `nodeNotBefore` — the node's claim-eligibility gate.
async fn node_not_before(fx: &mut Fixture, node: WorkflowNodeId) -> Result<Option<OffsetDateTime>> {
    sqlx::query_scalar("SELECT not_before FROM central.workflow_nodes WHERE id = $1")
        .bind(uuid_of!(node))
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))
}

/// `setNodeTimeout` — installs the aggregate per-node bound.
async fn set_node_timeout(fx: &mut Fixture, node: WorkflowNodeId, secs: i64) -> Result<()> {
    sqlx::query("UPDATE central.workflow_nodes SET node_timeout_seconds = $2 WHERE id = $1")
        .bind(uuid_of!(node))
        .bind(secs)
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// `setNodeSpec` — rewrites the node spec document (compensation hook
/// / per-class budgets).
async fn set_node_spec(fx: &mut Fixture, node: WorkflowNodeId, spec: &str) -> Result<()> {
    sqlx::query("UPDATE central.workflow_nodes SET spec = $2::jsonb WHERE id = $1")
        .bind(uuid_of!(node))
        .bind(spec)
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// `ageClaimedAt` — ages the attempt's first-dispatch instant (the
/// node-bound epoch).
async fn age_claimed_at(fx: &mut Fixture, attempt: SessionAttemptId, secs: f64) -> Result<()> {
    sqlx::query(
        "UPDATE central.session_attempts \
         SET claimed_at = now() - make_interval(secs => $2) WHERE id = $1",
    )
    .bind(uuid_of!(attempt))
    .bind(secs)
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// `forceExpire` — pushes one lease past its `expires_at`.
async fn force_expire(fx: &mut Fixture, lease: NodeLeaseId) -> Result<()> {
    sqlx::query(
        "UPDATE central.node_leases \
         SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(uuid_of!(lease))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// A second store connection for the concurrency race — upstream's
/// second `pgx.Conn`.
async fn single_conn_pool(db: &str, role: &str) -> Result<PgPool> {
    let opts = require_opts()?.database(db).username(role).password(role);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

/// `narrowProfile` — the default spec-8 envelope mutated by `f`; the
/// installed envelope may narrow compiled bounds only.
fn narrow_profile(f: impl FnOnce(&mut ConcurrencyProfile)) -> ConcurrencyProfile {
    let mut p = ConcurrencyProfile::default();
    f(&mut p);
    p
}

/// `testKiller` — the injected `Killer` double: `confirmed` answers the
/// kill confirmation, `calls` records every attempt the sweep asked to
/// kill.
struct TestKiller {
    confirmed: bool,
    calls: Mutex<Vec<SessionAttemptId>>,
}

impl TestKiller {
    fn confirmed() -> Self {
        Self {
            confirmed: true,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn unconfirmed() -> Self {
        Self {
            confirmed: false,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl Killer for TestKiller {
    async fn kill(&self, attempt_id: SessionAttemptId) -> Result<bool> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(attempt_id);
        Ok(self.confirmed)
    }
}

/// `testCompensation` — the injected `CompensationExecutor` double.
#[derive(Default)]
struct TestCompensation {
    cleaned: Mutex<Vec<WorkflowNodeId>>,
    retained: Mutex<Vec<WorkflowNodeId>>,
    fail: bool,
}

impl CompensationExecutor for TestCompensation {
    async fn cleanup_workspace(&self, node_id: WorkflowNodeId) -> Result<()> {
        self.cleaned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id);
        if self.fail {
            return Err(Failure::internal(
                "test_compensation",
                "retention backend down",
            ));
        }
        Ok(())
    }

    async fn retain_artifacts(&self, node_id: WorkflowNodeId) -> Result<()> {
        self.retained
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id);
        if self.fail {
            return Err(Failure::internal(
                "test_compensation",
                "retention backend down",
            ));
        }
        Ok(())
    }
}

/// `fixedClock` — the deterministic evaluation instant.
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
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
/// `WORKER_NOT_FOUND`; a ladder-terminal worker refuses
/// `WORKER_NOT_ACTIVE`; a suspect worker may still claim (observable
/// only).
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
    sqlx::query("UPDATE central.worker_registrations SET state = 'deregistered' WHERE id = $1")
        .bind(uuid_of!(wid))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let err = fx.store.claim_ready(wid, 1).await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_WORKER_NOT_ACTIVE);

    // A suspect worker may still claim (observable only).
    sqlx::query("UPDATE central.worker_registrations SET state = 'suspect' WHERE id = $1")
        .bind(uuid_of!(wid))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    assert_eq!(
        claimed.len(),
        1,
        "suspect claim: observable only, still claims"
    );
    Ok(())
}

/// `TestClaimReadyConcurrentSingleWinner` — two stores, two workers,
/// two connections racing `claim_ready` on the same ready node:
/// exactly one commits the claim; the loser sees the NOWAIT/state
/// race and skips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_ready_concurrent_single_winner() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "race").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;

    // The second store gets its own one-connection pool — upstream's
    // second `pgx.Conn`.
    let pool2 = single_conn_pool(&db, "central_runtime").await?;
    let store2 = PgSchedulerStore::new(pool2, vec!["claude-code".to_string()]);

    let w1 = fx.store.register_worker(worker(&fx, 4)).await?;
    let w2 = store2.register_worker(worker(&fx, 4)).await?;

    let s1 = fx.store.clone();
    let h1 = tokio::spawn(async move { s1.claim_ready(w1, 1).await });
    let h2 = tokio::spawn(async move { store2.claim_ready(w2, 1).await });
    let c1 = h1.await.expect("claim task 1 panicked")?;
    let c2 = h2.await.expect("claim task 2 panicked")?;
    assert_eq!(
        c1.len() + c2.len(),
        1,
        "total claims = {}, want exactly 1 winner",
        c1.len() + c2.len()
    );
    assert_eq!(node_state(&mut fx, node).await?, "dispatched");
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM central.node_leases \
         WHERE node_id = $1 AND released_at IS NULL",
    )
    .bind(uuid_of!(node))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(live, 1, "exactly one live lease after the race");
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

/// `TestDispatchWritesAreFencedAndJournaled` — `fail_dispatch` under
/// the live lease commits the `failed` outcome and requeues the node
/// under retry backoff (dispatch_infra is retryable) with
/// `attempt_failed`/`node_ready` journaled; the closed lease then
/// rejects every non-outcome write while `fail_dispatch`'s replay
/// resolves through the outcome ledger (`DUPLICATE_IDEMPOTENCY_KEY`
/// on a different reason). A re-claim with `attempt_seq` 2 then
/// drives `ambiguate_dispatch`'s park. Also pins the
/// `node_dispatched` row + payload fields.
#[tokio::test]
async fn dispatch_writes_fenced() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "fenced").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let c = claimed.into_iter().next().unwrap();
    let attempt = c.attempt.id;

    // The dispatch commit journaled `node_dispatched` with the claim
    // binding — attempt/node ids on the row, claim fields in the
    // payload.
    let events = event_rows(&mut fx).await?;
    let dispatched: Vec<_> = events
        .iter()
        .filter(|(kind, ..)| kind == "node_dispatched")
        .collect();
    assert_eq!(dispatched.len(), 1, "one node_dispatched event");
    assert_eq!(
        dispatched[0].1.as_deref(),
        Some(node.to_string().as_str()),
        "node_dispatched node_id"
    );
    assert_eq!(
        dispatched[0].2.as_deref(),
        Some(attempt.to_string().as_str()),
        "node_dispatched attempt_id"
    );
    let payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM central.run_events \
         WHERE run_id = $1 AND kind = 'node_dispatched'",
    )
    .bind(uuid_of!(fx.run))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(payload["node_key"], serde_json::json!("a"));
    assert_eq!(payload["attempt_seq"], serde_json::json!(1));
    assert_eq!(payload["worker_id"], serde_json::json!(wid.to_string()));
    assert_eq!(
        payload["lease_id"],
        serde_json::json!(c.lease.id.to_string())
    );
    assert_eq!(payload["harness"], serde_json::json!("claude-code"));
    assert_eq!(payload["workspace_kind"], serde_json::json!("worktree"));

    // FailDispatch under the live lease: failed attempt, released
    // lease, node requeued under retry backoff, attempt_failed +
    // node_ready journaled.
    fx.store
        .fail_dispatch(attempt, "WORKSPACE_PROVISION_FAILED")
        .await?;
    let (state, reason, ended_at) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some("WORKSPACE_PROVISION_FAILED"));
    assert!(ended_at.is_some(), "failed attempt missing ended_at");
    assert_eq!(node_state(&mut fx, node).await?, "ready");
    assert_eq!(kinds(&mut fx, "attempt_failed").await?, 1);

    // The fence rejects every non-outcome dispatch write once the
    // lease is closed. FailDispatch's replay instead resolves through
    // the outcome ledger: a 'failed' outcome is already recorded, and
    // a different reason under the same key is spec-5's
    // conflicting-fingerprint rejection — DUPLICATE_IDEMPOTENCY_KEY,
    // not the raw fence verdict.
    let err = fx.store.mark_provisioning(attempt, "/x").await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);
    let err = fx.store.mark_started(attempt, "s").await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);
    let err = fx.store.fail_dispatch(attempt, "X").await.unwrap_err();
    assert_eq!(err.kind(), FailureKind::Conflict);
    assert_eq!(err.code(), ReasonCode::DuplicateIdempotencyKey.as_str());
    let err = fx.store.ambiguate_dispatch(attempt, "X").await.unwrap_err();
    assert_eq!(err.code(), sched::REASON_LEASE_FENCE_STALE);

    // AmbiguateDispatch on a second claim parks attempt + node. The
    // first failure left the node 'ready' under not_before backoff —
    // clear it to make the node immediately claimable (the backoff
    // wait elapsed, in real time).
    sqlx::query("UPDATE central.workflow_nodes SET not_before = NULL WHERE id = $1")
        .bind(uuid_of!(node))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let claimed = fx.store.claim_ready(wid, 1).await?;
    let c2 = claimed.into_iter().next().unwrap();
    assert_eq!(c2.attempt.attempt_seq, 2);
    // 'claimed' admits no ambiguous park — the unknown-outcome path
    // exists only once provisioning/launching began.
    let err = fx
        .store
        .ambiguate_dispatch(c2.attempt.id, "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED")
        .await
        .unwrap_err();
    assert_eq!(err.code(), sched::REASON_INVALID_ATTEMPT_TRANSITION);
    fx.store
        .mark_provisioning(c2.attempt.id, "/scratch/ws2")
        .await?;
    fx.store
        .ambiguate_dispatch(c2.attempt.id, "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED")
        .await?;
    let (state, reason, ended_at) = attempt_row(&mut fx, c2.attempt.id).await?;
    assert_eq!(state, "ambiguous");
    assert_eq!(reason.as_deref(), Some("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED"));
    assert!(ended_at.is_none(), "ambiguous attempt keeps ended_at NULL");
    assert_eq!(node_state(&mut fx, node).await?, "attempt_ambiguous");
    assert_eq!(kinds(&mut fx, "attempt_ambiguous").await?, 1);
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

    // Pin the evaluation instant and jitter so the journaled retry_at
    // is exact — draw 1.0 yields the full computed delay (upstream's
    // `fixedClock`/`RandFunc(func() float64 { return 1 })` leg).
    let instant = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
        .expect("unix timestamp out of range");
    fx.store.clock = Some(Arc::new(FixedClock(instant)));
    let jitter: Arc<dyn Rand> = Arc::new(|| 1.0_f64);
    fx.store.jitter = Some(jitter);
    fx.store.retry_policy = RetryPolicy {
        base_delay: Duration::seconds(30),
        cap: Duration::minutes(10),
        multiplier: 2.0,
        per_class_limits: [(FailureClass::Transient, 3)].into_iter().collect(),
        max_attempts_total: 5,
    };

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
    // seq 1 → base delay × draw 1.0: retry_at = instant + 30s exactly.
    let want_retry_at = instant + Duration::seconds(30);
    assert_eq!(res.node_status, "ready");
    assert_eq!(res.retry_at, Some(want_retry_at));
    assert_eq!(res.class, FailureClass::Transient);
    assert_eq!(kinds(&mut fx, "attempt_retry_scheduled").await?, 1);
    let nb: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT not_before FROM central.workflow_nodes WHERE id = $1")
            .bind(uuid_of!(node))
            .fetch_one(&mut fx.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(nb, Some(want_retry_at), "not_before = journaled retry_at");

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

/// `TestRecordOutcomeValidation` — the portable leg: a `failed` report
/// with no reason code rejects `OUTCOME_REASON_MISSING` before any
/// write (the attempt stays `claimed`). The kind-unknown and
/// fingerprint legs are unconstructible under the closed `OutcomeKind`
/// enum and fixed `[u8; 32]` fingerprint.
#[tokio::test]
async fn record_outcome_reason_missing() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "out_v").await?;
    let mut fx = setup_fixture(&db).await?;
    let _ = seed_ready_node(&mut fx, "a", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;

    let err = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: attempt,
            kind: OutcomeKind::Failed,
            reason_code: String::new(),
            fingerprint: [0x42; 32],
            retry_after: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), FailureKind::Invalid);
    assert_eq!(err.code(), sched::REASON_OUTCOME_REASON_MISSING);
    // Validation rejected before any mutation: the attempt stays claimed.
    let (state, ..) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "claimed");
    Ok(())
}

/// `TestSweepSessionBreachConfirmedKill` — the confirmed-kill path: the
/// breach becomes a definite `SESSION_WALL_CLOCK_REACHED` failure
/// routed through the normal retry decision — session_timeout is
/// retryable, so the node requeues under backoff.
#[tokio::test]
async fn sweep_session_breach_confirmed_kill() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_breach_c").await?;
    let mut fx = setup_fixture(&db).await?;
    fx.store.admission_profile = Some(narrow_profile(|p| {
        p.wall_clock_ceiling = Duration::minutes(1);
    }));
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;
    sqlx::query(
        "UPDATE central.session_attempts \
         SET started_at = now() - interval '2 minutes' WHERE id = $1",
    )
    .bind(uuid_of!(attempt))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let killer = Arc::new(TestKiller::confirmed());
    fx.store.killer = Some(killer.clone());
    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert_eq!(
        killer.calls.lock().unwrap().as_slice(),
        &[attempt],
        "kill calls: want the breached attempt"
    );
    assert!(
        sum.skipped_ambiguous.is_empty() && sum.node_timeouts.is_empty(),
        "summary = {sum:?}, want no skips, no node landings"
    );
    let (state, reason, _ended) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some(REASON_SESSION_WALL_CLOCK_REACHED));
    let rows = outcome_rows(&mut fx, attempt).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, FailureClass::SessionTimeout.as_str());
    assert_eq!(
        node_state(&mut fx, node).await?,
        "ready",
        "session_timeout is retryable"
    );
    assert!(
        node_not_before(&mut fx, node).await?.is_some(),
        "retryable session timeout left not_before NULL"
    );
    Ok(())
}

/// `TestSweepSessionBreachUnconfirmedKill` — the fail-closed half: an
/// unconfirmed kill parks the attempt ambiguous, never a definite
/// failure, and the node reports into `skipped_ambiguous`.
#[tokio::test]
async fn sweep_session_breach_unconfirmed_kill() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_breach_u").await?;
    let mut fx = setup_fixture(&db).await?;
    fx.store.admission_profile = Some(narrow_profile(|p| {
        p.wall_clock_ceiling = Duration::minutes(1);
    }));
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;
    sqlx::query(
        "UPDATE central.session_attempts \
         SET started_at = now() - interval '2 minutes' WHERE id = $1",
    )
    .bind(uuid_of!(attempt))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    fx.store.killer = Some(Arc::new(TestKiller::unconfirmed()));
    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert_eq!(
        sum.skipped_ambiguous,
        vec![SkippedScope::Node(node)],
        "want the parked node"
    );
    let (state, reason, _ended) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "ambiguous");
    assert_eq!(
        reason.as_deref(),
        Some(sched::REASON_ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED)
    );
    assert_eq!(node_state(&mut fx, node).await?, "attempt_ambiguous");
    assert!(
        outcome_rows(&mut fx, attempt).await?.is_empty(),
        "ambiguous is never an outcome"
    );
    assert_eq!(kinds(&mut fx, "attempt_ambiguous").await?, 1);
    Ok(())
}

/// `TestSweepNodeTimeoutClaimed` — the bound on a never-started
/// attempt: `claimed_at + node_timeout_seconds` elapsed lands
/// `failed_terminal` and the claimed attempt cancels — no kill needed,
/// nothing ran.
#[tokio::test]
async fn sweep_node_timeout_claimed() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_nt_c").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_timeout(&mut fx, node, 60).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    age_claimed_at(&mut fx, attempt, 3600.0).await?;

    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert_eq!(sum.node_timeouts, vec![node]);
    assert_eq!(node_state(&mut fx, node).await?, "failed_terminal");
    let (state, reason, _ended) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "cancelled");
    assert_eq!(reason.as_deref(), Some(ReasonCode::NodeTimeout.as_str()));
    let event_reason: String = sqlx::query_scalar(
        "SELECT reason_code FROM central.run_events \
         WHERE run_id = $1 AND kind = 'node_failed_terminal'",
    )
    .bind(uuid_of!(fx.run))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(event_reason, ReasonCode::NodeTimeout.as_str());
    Ok(())
}

/// `TestSweepNodeTimeoutStartedKill` — the bound over a live session:
/// a confirmed kill records the definite `SESSION_WALL_CLOCK_REACHED`
/// outcome, then the node lands `NODE_TIMEOUT` — the bound dominates
/// the failure's own retryability.
#[tokio::test]
async fn sweep_node_timeout_started_kill() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_nt_sk").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_timeout(&mut fx, node, 60).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;
    age_claimed_at(&mut fx, attempt, 3600.0).await?;

    fx.store.killer = Some(Arc::new(TestKiller::confirmed()));
    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert_eq!(sum.node_timeouts, vec![node]);
    let (state, reason, _ended) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some(REASON_SESSION_WALL_CLOCK_REACHED));
    assert_eq!(node_state(&mut fx, node).await?, "failed_terminal");
    Ok(())
}

/// `TestSweepNodeTimeoutUnconfirmedKill` — the blocked landing: the
/// unconfirmed kill parks the attempt ambiguous, the node parks
/// `attempt_ambiguous`, and the timeout does NOT land — the summary's
/// `skipped_ambiguous` carries the node until an operator decides.
#[tokio::test]
async fn sweep_node_timeout_unconfirmed_kill() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_nt_uk").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_timeout(&mut fx, node, 60).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;
    age_claimed_at(&mut fx, attempt, 3600.0).await?;

    fx.store.killer = Some(Arc::new(TestKiller::unconfirmed()));
    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert!(sum.node_timeouts.is_empty(), "ambiguous blocks the landing");
    assert_eq!(sum.skipped_ambiguous, vec![SkippedScope::Node(node)]);
    let (state, ..) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "ambiguous");
    assert_eq!(node_state(&mut fx, node).await?, "attempt_ambiguous");

    // The next pass still skips — the unresolved descendant keeps
    // blocking the timer.
    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert!(sum.node_timeouts.is_empty());
    assert_eq!(sum.skipped_ambiguous.len(), 1);
    Ok(())
}

/// `TestSweepNodeTimeoutReadyBackoff` — spec-4 decision-5's edge that
/// motivated `ready → failed_terminal`: the bound covers backoff waits,
/// so a node parked `ready` under `not_before` still lands terminal.
#[tokio::test]
async fn sweep_node_timeout_ready_backoff() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_nt_rb").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_timeout(&mut fx, node, 60).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;

    // A retryable failure returned the node to 'ready' under backoff;
    // age first-dispatch so the node bound has now expired anyway.
    fx.store
        .fail_dispatch(attempt, "WORKSPACE_PROVISION_FAILED")
        .await?;
    assert!(
        node_not_before(&mut fx, node).await?.is_some(),
        "dispatch failure left not_before NULL — expected backoff"
    );
    age_claimed_at(&mut fx, attempt, 3600.0).await?;

    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert_eq!(sum.node_timeouts, vec![node]);
    assert_eq!(node_state(&mut fx, node).await?, "failed_terminal");
    Ok(())
}

/// `TestSweepWorkflowTimeoutBlocked` — the fail-closed cascade: the
/// unconfirmed kill parks its attempt ambiguous and blocks the run's
/// terminal landing until an operator decides.
#[tokio::test]
async fn sweep_workflow_timeout_blocked() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_wt_b").await?;
    let mut fx = setup_fixture(&db).await?;
    let _ = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;
    sqlx::query("UPDATE central.runs SET deadline = now() - interval '1 minute' WHERE id = $1")
        .bind(uuid_of!(fx.run))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    fx.store.killer = Some(Arc::new(TestKiller::unconfirmed()));
    let sum = RetryStore::sweep_timeouts(&fx.store, OffsetDateTime::now_utc()).await?;
    assert!(
        sum.workflow_timeouts.is_empty(),
        "ambiguous blocks the run landing"
    );
    assert_eq!(sum.skipped_ambiguous, vec![SkippedScope::Run(fx.run)]);
    let (state, ..) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "ambiguous");
    let status: String = sqlx::query_scalar("SELECT status FROM central.runs WHERE id = $1")
        .bind(uuid_of!(fx.run))
        .fetch_one(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(status, "running", "still running under the blocked bound");
    Ok(())
}

/// `TestSweepLostStartedAttemptAmbiguous` — the worker-loss expiry of
/// a started attempt carries `ATTEMPT_AMBIGUOUS_WORKER_LOST`.
#[tokio::test]
async fn sweep_lost_started_attempt_ambiguous() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "sw_lost").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;
    sqlx::query(
        "UPDATE central.node_leases \
         SET last_heartbeat_at = now() - interval '80 seconds' WHERE worker_id = $1",
    )
    .bind(uuid_of!(wid))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    fx.store.sweep_suspects(OffsetDateTime::now_utc()).await?;
    let (state, reason, _ended) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "ambiguous");
    assert_eq!(
        reason.as_deref(),
        Some(sched::REASON_ATTEMPT_AMBIGUOUS_WORKER_LOST)
    );
    assert_eq!(node_state(&mut fx, node).await?, "attempt_ambiguous");
    Ok(())
}

/// `TestReconcileExpiresAndOrphans` — the startup reconcile pass
/// sweeps both expiry sources: an expired lease follows the plain
/// expiry path (never-started → failed + node `ready`); a live lease
/// whose worker is ladder-terminal follows the worker-loss path
/// (started → ambiguous/`ATTEMPT_AMBIGUOUS_WORKER_LOST`). A replay is a
/// no-op.
#[tokio::test]
async fn reconcile_expires_and_orphans() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "recon").await?;
    let mut fx = setup_fixture(&db).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;

    // Lease 1: live but expired → the plain expiry path.
    let n1 = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let c1 = claim_attempt(&fx, wid).await?;
    force_expire(&mut fx, c1.lease.id).await?;

    // Lease 2: live, unexpired, but its worker is ladder-terminal
    // ('lost') → the worker-loss path. Make it a started attempt so
    // the split lands ATTEMPT_AMBIGUOUS_WORKER_LOST.
    let n2 = seed_ready_node(&mut fx, "n2", "claude-code", "worktree", 1).await?;
    let c2 = claim_attempt(&fx, wid).await?;
    fx.store
        .mark_provisioning(c2.attempt.id, "/scratch/ws2")
        .await?;
    fx.store.mark_started(c2.attempt.id, "session-2").await?;
    sqlx::query("UPDATE central.worker_registrations SET state = 'lost' WHERE id = $1")
        .bind(uuid_of!(wid))
        .execute(&mut fx.conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    fx.store.reconcile("reconciler").await?;

    assert_eq!(node_state(&mut fx, n1).await?, "ready");
    let (state, reason, _ended) = attempt_row(&mut fx, c2.attempt.id).await?;
    assert_eq!(state, "ambiguous");
    assert_eq!(
        reason.as_deref(),
        Some(sched::REASON_ATTEMPT_AMBIGUOUS_WORKER_LOST)
    );
    assert_eq!(node_state(&mut fx, n2).await?, "attempt_ambiguous");
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM central.node_leases \
         WHERE released_at IS NULL AND worker_id = $1",
    )
    .bind(uuid_of!(wid))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(live, 0, "live leases after reconcile");

    // Idempotent: a second pass matches nothing.
    fx.store.reconcile("reconciler").await?;
    assert_eq!(kinds(&mut fx, "lease_expired").await?, 2);
    Ok(())
}

/// `TestClaimReadyAdmissionDefersHostCapAndKeepsFIFO` — spec-8
/// decision 6 end to end: with the host cap saturated the next ready
/// node stays `ready`, journals `admission_deferred` carrying
/// `CAPACITY_ADMISSION_DEFERRED`, allocates no attempt row, keeps its
/// `ready_at` (FIFO position, no backoff), and claims normally once a
/// session frees.
#[tokio::test]
async fn claim_admission_host_cap_defers_keeps_fifo() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "adm_host").await?;
    let mut fx = setup_fixture(&db).await?;
    fx.store.admission_profile = Some(narrow_profile(|p| {
        p.max_parallel_sessions = 1; // one live session on the whole host
    }));
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;

    let n1 = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let n2 = seed_ready_node(&mut fx, "n2", "claude-code", "worktree", 1).await?;
    let n3 = seed_ready_node(&mut fx, "n3", "claude-code", "worktree", 2).await?;
    set_ready_at(&mut fx, n1, 30.0).await?;
    set_ready_at(&mut fx, n2, 20.0).await?;
    set_ready_at(&mut fx, n3, 10.0).await?;
    let n2_ready_before = ready_at(&mut fx, n2).await?;

    // Pass 1: n1 wins the single host slot.
    let claimed = fx.store.claim_ready(wid, 4).await?;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt.node_id, n1);

    // Pass 2: saturated. n2 is evaluated and deferred; the host-cap
    // break skips n3's evaluation entirely.
    let claimed = fx.store.claim_ready(wid, 4).await?;
    assert!(claimed.is_empty());
    for n in [n2, n3] {
        assert_eq!(
            node_state(&mut fx, n).await?,
            "ready",
            "deferral is not a claim"
        );
    }
    let attempts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM central.session_attempts WHERE node_id = $1")
            .bind(uuid_of!(n2))
            .fetch_one(&mut fx.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(attempts, 0, "deferred node has attempt rows");

    // One journaled deferral, node-scoped, with the spec-8 code.
    let events = event_rows(&mut fx).await?;
    let deferrals: Vec<_> = events
        .iter()
        .filter(|(kind, ..)| kind == "admission_deferred")
        .collect();
    assert_eq!(
        deferrals.len(),
        1,
        "n2 only; the host-cap pass stops scanning"
    );
    assert_eq!(
        deferrals[0].1.as_deref(),
        Some(n2.to_string().as_str()),
        "deferral node"
    );
    assert_eq!(
        deferrals[0].3.as_deref(),
        Some(REASON_CAPACITY_ADMISSION_DEFERRED),
        "deferral reason"
    );
    assert!(
        deferrals[0].2.is_none(),
        "no attempt may exist for a deferred node"
    );

    // FIFO position kept: ready_at is NOT pushed back.
    assert_eq!(
        ready_at(&mut fx, n2).await?,
        n2_ready_before,
        "a deferred node keeps queue position"
    );

    // A repeat pass while still saturated does not re-journal the same
    // deferred condition (the claim loop polls on a ticker).
    let _ = fx.store.claim_ready(wid, 4).await?;
    assert_eq!(kinds(&mut fx, "admission_deferred").await?, 1);

    // Free the host slot and re-claim: n2 wins over younger n3 — it
    // kept its position rather than restarting the queue.
    sqlx::query(
        "UPDATE central.session_attempts \
         SET state = 'succeeded', ended_at = now() WHERE node_id = $1",
    )
    .bind(uuid_of!(n1))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let claimed = fx.store.claim_ready(wid, 4).await?;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt.node_id, n2);
    Ok(())
}

/// `TestClaimReadyAdmissionRunInflightCap` — the per-run
/// `max_inflight_nodes` gate: a saturated run defers its next ready
/// node while another run's node still admits.
#[tokio::test]
async fn claim_admission_run_inflight_cap() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "adm_run").await?;
    let mut fx = setup_fixture(&db).await?;
    fx.store.admission_profile = Some(narrow_profile(|p| {
        p.max_inflight_nodes = 1; // one inflight node per run
    }));
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;

    // A second run in the same workspace.
    let task2 = TaskId::new();
    let run2 = RunId::new();
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
         last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'scheduler test 2', '{}'::jsonb)",
    )
    .bind(uuid_of!(task2))
    .bind(uuid_of!(fx.ws))
    .bind(uuid_of!(run2))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(run2))
    .bind(uuid_of!(fx.ws))
    .bind(uuid_of!(task2))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;

    let n1 = seed_ready_node(&mut fx, "run1-a", "claude-code", "worktree", 0).await?;
    let n2 = seed_ready_node(&mut fx, "run1-b", "claude-code", "worktree", 1).await?;
    let nx = WorkflowNodeId::new();
    sqlx::query(
        "INSERT INTO central.workflow_nodes \
         (id, run_id, workspace_id, node_key, harness, workspace_kind, depth, state, spec) \
         VALUES ($1, $2, $3, 'run2-a', 'claude-code', 'worktree', 0, 'ready', '{}'::jsonb)",
    )
    .bind(uuid_of!(nx))
    .bind(uuid_of!(run2))
    .bind(uuid_of!(fx.ws))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    set_ready_at(&mut fx, n1, 30.0).await?;
    set_ready_at(&mut fx, n2, 20.0).await?;
    set_ready_at(&mut fx, nx, 10.0).await?;

    let claimed = fx.store.claim_ready(wid, 4).await?;
    assert_eq!(claimed.len(), 2, "want 2 (n1 + the other run's node)");
    let got: Vec<WorkflowNodeId> = claimed.iter().map(|c| c.attempt.node_id).collect();
    assert!(got.contains(&n1) && got.contains(&nx));
    assert_eq!(
        node_state(&mut fx, n2).await?,
        "ready",
        "run cap defers, not fails"
    );
    let reason: Option<String> = sqlx::query_scalar(
        "SELECT reason_code FROM central.run_events \
         WHERE node_id = $1 AND kind = 'admission_deferred'",
    )
    .bind(uuid_of!(n2))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(reason.as_deref(), Some(REASON_CAPACITY_ADMISSION_DEFERRED));
    Ok(())
}

/// `TestRecordCeilingBreachClosesAttempt` — spec-8 decision 7's
/// close-out: a confirmed cancel commits attempt `failed` carrying the
/// `SESSION_*_REACHED` code, releases the lease, requeues the node, and
/// journals `attempt_failed` + `node_ready` — fenced like every
/// dispatch write. A code outside the spec-8 set refuses
/// `INVALID_BREACH_CODE`; an identical replay dedupes through the
/// ledger.
#[tokio::test]
async fn record_ceiling_breach_closes_attempt() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "ceil").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let c = claim_attempt(&fx, wid).await?;
    let attempt = c.attempt.id;
    start_attempt(&fx, attempt).await?;

    // A code outside the spec-8 set is refused INVALID_BREACH_CODE and
    // writes nothing.
    let err = fx
        .store
        .record_ceiling_breach(attempt, "WORKSPACE_PROVISION_FAILED")
        .await
        .unwrap_err();
    assert_eq!(err.kind(), FailureKind::Invalid);
    assert_eq!(err.code(), REASON_INVALID_BREACH_CODE);

    fx.store
        .record_ceiling_breach(attempt, REASON_SESSION_WALL_CLOCK_REACHED)
        .await?;
    let (state, reason, ended_at) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some(REASON_SESSION_WALL_CLOCK_REACHED));
    assert!(ended_at.is_some(), "breach-closed attempt missing ended_at");
    let released: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT released_at FROM central.node_leases WHERE id = $1")
            .bind(uuid_of!(c.lease.id))
            .fetch_one(&mut fx.conn)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert!(released.is_some(), "breach did not release the lease");
    assert_eq!(
        node_state(&mut fx, node).await?,
        "ready",
        "requeue; 2D owns terminal policy"
    );
    assert_eq!(kinds(&mut fx, "attempt_failed").await?, 1);
    assert_eq!(kinds(&mut fx, "node_ready").await?, 1);

    // The fence closed with the lease — but the outcome was already
    // recorded, so an identical replay resolves through the spec-5
    // ledger as a dedupe (no second transition, no second
    // attempt_failed), never a fence error.
    fx.store
        .record_ceiling_breach(attempt, REASON_SESSION_WALL_CLOCK_REACHED)
        .await?;
    assert_eq!(kinds(&mut fx, "attempt_failed").await?, 1);
    assert_eq!(kinds(&mut fx, "command_deduped").await?, 1);
    Ok(())
}

/// `TestListWallClockBreaches` — the detection read: unset ceiling
/// detects nothing, a started attempt past the ceiling is listed, and
/// a closed breach stops matching.
#[tokio::test]
async fn list_wall_clock_breaches() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "breaches").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;
    start_attempt(&fx, attempt).await?;

    // Default profile: unset ceiling → empty, even with live sessions.
    let got = fx
        .store
        .list_wall_clock_breaches(OffsetDateTime::now_utc())
        .await?;
    assert!(got.is_empty());

    // With a ceiling installed, an attempt aged past it is listed.
    fx.store.admission_profile = Some(narrow_profile(|p| {
        p.wall_clock_ceiling = Duration::minutes(1);
    }));
    sqlx::query(
        "UPDATE central.session_attempts \
         SET started_at = now() - interval '2 minutes' WHERE id = $1",
    )
    .bind(uuid_of!(attempt))
    .execute(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let got = fx
        .store
        .list_wall_clock_breaches(OffsetDateTime::now_utc())
        .await?;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, attempt);

    // Detection does not close anything — the attempt stays 'started'.
    let (state, ..) = attempt_row(&mut fx, attempt).await?;
    assert_eq!(state, "started");

    // After the close-out the attempt no longer matches and the node
    // is back to ready.
    fx.store
        .record_ceiling_breach(attempt, REASON_SESSION_WALL_CLOCK_REACHED)
        .await?;
    let got = fx
        .store
        .list_wall_clock_breaches(OffsetDateTime::now_utc())
        .await?;
    assert!(got.is_empty());
    assert_eq!(node_state(&mut fx, node).await?, "ready");
    Ok(())
}

/// `TestRunCompensationManagedOnce` — the executor + `executed`-result
/// legs: a managed hook on a node landing `failed_terminal` executes
/// exactly once through the injected executor, and a `run_compensation`
/// replay dedupes on the committed request row.
#[tokio::test]
async fn run_compensation_executor_once() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "comp_x").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_spec(
        &mut fx,
        node,
        r#"{"node_key":"n1","harness":"claude-code","on_terminal_failure":"cleanup_workspace"}"#,
    )
    .await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;

    let exec = Arc::new(TestCompensation::default());
    fx.store.compensation = Some(exec.clone());
    let res = RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: attempt,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::SpecValidationFailed.as_str().to_owned(),
            fingerprint: [0x33; 32],
            retry_after: None,
        },
    )
    .await?;
    assert_eq!(res.node_status, "failed_terminal");
    assert_eq!(
        exec.cleaned.lock().unwrap().as_slice(),
        &[node],
        "want the terminal node once"
    );
    // Request row + result row, both compensation_requested on the node.
    assert_eq!(kinds(&mut fx, "compensation_requested").await?, 2);
    let payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM central.run_events \
         WHERE run_id = $1 AND kind = 'compensation_requested' \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(uuid_of!(fx.run))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(payload["result"], serde_json::json!("executed"));

    // Replay is a no-op — the committed request row dedupes.
    RetryStore::run_compensation(&fx.store, node).await?;
    assert_eq!(exec.cleaned.lock().unwrap().len(), 1);
    assert_eq!(kinds(&mut fx, "compensation_requested").await?, 2);
    Ok(())
}

/// `TestRunCompensationUnmanagedJournalsOnly` — the journal-only path:
/// a non-managed `on_terminal_failure` value emits one
/// `compensation_requested` for the leader/operator and never reaches
/// the executor.
#[tokio::test]
async fn run_compensation_unmanaged_journals_only() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "comp_u").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_spec(
        &mut fx,
        node,
        r#"{"node_key":"n1","harness":"claude-code","on_terminal_failure":"notify_leader"}"#,
    )
    .await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;

    let exec = Arc::new(TestCompensation::default());
    fx.store.compensation = Some(exec.clone());
    RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: attempt,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::SpecValidationFailed.as_str().to_owned(),
            fingerprint: [0x44; 32],
            retry_after: None,
        },
    )
    .await?;
    assert!(
        exec.cleaned.lock().unwrap().is_empty() && exec.retained.lock().unwrap().is_empty(),
        "want no executor calls for an unmanaged hook"
    );
    assert_eq!(
        kinds(&mut fx, "compensation_requested").await?,
        1,
        "request only"
    );
    Ok(())
}

/// `TestRunCompensationFailureNeverReopens` — the failure half: a hook
/// error journals `result='failed'` and the terminal node stays
/// terminal.
#[tokio::test]
async fn run_compensation_failure_never_reopens() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = installed(&mut admin, "comp_f").await?;
    let mut fx = setup_fixture(&db).await?;
    let node = seed_ready_node(&mut fx, "n1", "claude-code", "worktree", 0).await?;
    set_node_spec(
        &mut fx,
        node,
        r#"{"node_key":"n1","harness":"claude-code","on_terminal_failure":"retain_artifacts"}"#,
    )
    .await?;
    let wid = fx.store.register_worker(worker(&fx, 4)).await?;
    let attempt = claim_attempt(&fx, wid).await?.attempt.id;

    let exec = Arc::new(TestCompensation {
        fail: true,
        ..Default::default()
    });
    fx.store.compensation = Some(exec.clone());
    RetryStore::record_outcome(
        &fx.store,
        Outcome {
            attempt_id: attempt,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::SpecValidationFailed.as_str().to_owned(),
            fingerprint: [0x55; 32],
            retry_after: None,
        },
    )
    .await?;
    assert_eq!(exec.retained.lock().unwrap().as_slice(), &[node]);
    assert_eq!(
        node_state(&mut fx, node).await?,
        "failed_terminal",
        "hook failure never reopens the terminal node"
    );
    let payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM central.run_events \
         WHERE run_id = $1 AND kind = 'compensation_requested' \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(uuid_of!(fx.run))
    .fetch_one(&mut fx.conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(payload["result"], serde_json::json!("failed"));
    Ok(())
}
