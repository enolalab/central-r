//! PostgreSQL integration tests for the harness store (`harness/*.rs`) —
//! the port of upstream `internal/adapter/postgres/harness`'s suite:
//! `store_test.go`, `approval_test.go`, `lease_recovery_test.go`,
//! `lease_refence_test.go`, `rerun_recovery_test.go`, `budget_test.go`
//! and `task_cost_test.go`.
//!
//! Gated on `CENTRAL_TEST_DSN` — the same provisioning contract as the
//! sibling suites: a superuser DSN on a scratch cluster whose
//! `central_migration`/`central_runtime` roles exist. Every test
//! provisions its own database and installs the baseline through
//! [`BaselineInstaller::install`]; the store under test connects as
//! `central_runtime` while fixture rows the runtime may not insert are
//! seeded as `central_migration`.
//!
//! Upstream's `liveAttemptStates` drift guard is covered behaviourally:
//! `live_attempt_for_run` is exercised with one attempt in every
//! non-terminal state plus every terminal state, so the index predicate's
//! IN-list and the domain's state vocabulary cannot diverge without a
//! seeded case failing. The parameterized-query test has no Rust
//! counterpart: `sqlx` query literals are compile-time checked and never
//! built by string interpolation.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::harness::PgHarnessStore;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, StepAttemptId, TaskId, WorkspaceId,
};
use central_harness::approval::{
    ApprovalState, DECIDED_BY_SUPERSEDED, DECIDED_BY_TIMEOUT, InputMac, PermissionApproval,
    compute_input_mac,
};
use central_harness::attempt::{Attempt, PrepareInput};
use central_harness::budget::{Budget, MAX_BUDGET_COST_MICRO_USD, MAX_BUDGET_WALL_CLOCK};
use central_harness::domain::{
    Fence, Kind, PermissionPolicy, Resolution, ResolutionKind, State, Terminal, TerminalStatus,
    Workspace, codes,
};
use central_harness::event::{
    Event, EventPayload, Message, MessageRole, PermissionOutcome, PermissionRequested,
    PermissionResolved, Plan, Reasoning, Retry, SessionStarted, TerminalReported, ToolCall,
    ToolResult, ToolStatus, Usage, UsageReport, UsageScope, Warning,
};
use central_harness::port::{
    ApprovalOpen, ApprovalStore, AttemptStore, DecidePermissionRequest, ExecutionLease,
    LeaseBinder, LinkedStepAttemptState, MAX_APPROVAL_HISTORY, MAX_RECOVERY_CANDIDATES,
    RecoveryCursor, RecoveryStore,
};
use central_harness::query::{
    AttemptSummaryRead, BudgetUsageRead, HarnessEventRead, HarnessEventRequest,
    MAX_ATTEMPTS_FOR_RUN,
};
use central_harness::record::{self, EventRecord};
use central_harness::recovery::{REASON_NOT_LAUNCHED, attempt_id_for_step_attempt};
use sqlx::{Connection, PgConnection, PgPool};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

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

/// `harnessSetupDB`: a fresh database installed by `central_migration`,
/// the store under test on a `central_runtime` pool, and the migration
/// connection for seeding rows the runtime may not insert.
async fn harness_setup(label: &str) -> Result<(PgHarnessStore, PgConnection)> {
    let mut admin = admin_conn().await?;
    let db = format!("harness_test_{label}_{}", std::process::id());
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&mut admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let mut mig = role_conn(&db, "central_migration").await?;
    BaselineInstaller::new().install(&mut mig).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&pool)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(role, "central_runtime", "store under test runs as {role}");
    Ok((PgHarnessStore::new(pool), mig))
}

// ---------------------------------------------------------------------------
// Fixtures — the upstream seeders, verbatim SQL where it runs as
// central_migration.
// ---------------------------------------------------------------------------

/// `seedRun`: a workspace, task and run, as `central_migration`.
async fn seed_run(admin: &mut PgConnection, ws: WorkspaceId) -> Result<RunId> {
    let task = TaskId::new();
    let run = RunId::new();
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id) \
         VALUES ($1, 'active', 'harness-suite') ON CONFLICT (id) DO NOTHING",
    )
    .bind(uuid_of!(ws))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, 1, 'harness suite', '{}'::jsonb)",
    )
    .bind(uuid_of!(task))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(run))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'running', 1)",
    )
    .bind(uuid_of!(run))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(run)
}

/// `taskOf`: the Task of `run`.
async fn task_of(admin: &mut PgConnection, run: RunId) -> Result<TaskId> {
    let task: uuid::Uuid = sqlx::query_scalar("SELECT task_id FROM central.runs WHERE id = $1")
        .bind(uuid_of!(run))
        .fetch_one(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(TaskId::from_trusted_db_bytes(*task.as_bytes()))
}

/// `seedTaskRuns`: one Task with `n` Runs (all `failed` but the current
/// last one, `running`), as `central_migration`.
async fn seed_task_runs(
    admin: &mut PgConnection,
    ws: WorkspaceId,
    n: i64,
) -> Result<(TaskId, Vec<RunId>)> {
    let task = TaskId::new();
    let runs: Vec<RunId> = (0..n).map(|_| RunId::new()).collect();
    sqlx::query(
        "INSERT INTO central.workspaces (id, state, owner_principal_id) \
         VALUES ($1, 'active', 'harness-suite') ON CONFLICT (id) DO NOTHING",
    )
    .bind(uuid_of!(ws))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, last_run_index, title, input_spec) \
         VALUES ($1, $2, 1, 'running', $3, $4, 'harness suite', '{}'::jsonb)",
    )
    .bind(uuid_of!(task))
    .bind(uuid_of!(ws))
    .bind(uuid_of!(runs[(n - 1) as usize]))
    .bind(n)
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    for (i, run) in runs.iter().enumerate() {
        let status = if i as i64 == n - 1 {
            "running"
        } else {
            "failed"
        };
        sqlx::query(
            "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
             VALUES ($1, $2, $3, 1, $4, $5)",
        )
        .bind(uuid_of!(*run))
        .bind(uuid_of!(ws))
        .bind(uuid_of!(task))
        .bind(status)
        .bind(i as i64 + 1)
        .execute(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    }
    Ok((task, runs))
}

/// A run with one execution Step and StepAttempt whose id is the harness
/// attempt id (`attempt_id_for_step_attempt`), plus the bearer of the
/// run's execution lease — upstream `linkedRun`.
struct LinkedRun {
    ws: WorkspaceId,
    run: RunId,
    task: TaskId,
    attempt: HarnessAttemptId,
    lease: ExecutionLease,
}

/// `seedLinkedRun`: a running Task and Run, a Step, a StepAttempt in
/// `step_state` and (when `lease_ttl` is `Some`) the run's ownership row
/// at generation 1 claiming that StepAttempt, expiring after `lease_ttl`
/// (negative: already expired).
async fn seed_linked_run(
    admin: &mut PgConnection,
    step_state: &str,
    lease_ttl: Option<Duration>,
) -> Result<LinkedRun> {
    let ws = WorkspaceId::new();
    let run = seed_run(admin, ws).await?;
    let task = task_of(admin, run).await?;
    let step_attempt = StepAttemptId::new();
    let attempt = attempt_id_for_step_attempt(step_attempt)?;
    let step = uuid::Uuid::now_v7();
    let logical = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.steps (id, workspace_id, task_id, run_id, version, state, logical_operation_id, sequence) \
         VALUES ($1, $2, $3, $4, 1, 'running', $5, 1)",
    )
    .bind(step)
    .bind(uuid_of!(ws))
    .bind(uuid_of!(task))
    .bind(uuid_of!(run))
    .bind(logical)
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let (invocation, generation): (Option<uuid::Uuid>, Option<i64>) =
        if step_state != "prepared" && step_state != "cancelled" {
            (Some(uuid::Uuid::now_v7()), Some(1))
        } else {
            (None, None)
        };
    sqlx::query(
        "INSERT INTO central.step_attempts (id, workspace_id, step_id, task_id, run_id, version, logical_operation_id, physical_attempt_id, invocation_id, invocation_generation, sequence, state) \
         VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8, $9, 1, $10)",
    )
    .bind(uuid_of!(step_attempt))
    .bind(uuid_of!(ws))
    .bind(step)
    .bind(uuid_of!(task))
    .bind(uuid_of!(run))
    .bind(logical)
    .bind(uuid::Uuid::now_v7())
    .bind(invocation)
    .bind(generation)
    .bind(step_state)
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let mut bearer = [0u8; 32];
    bearer.iter_mut().for_each(|b| *b = 0x5a);
    let out = LinkedRun {
        ws,
        run,
        task,
        attempt,
        lease: ExecutionLease {
            generation: 1,
            credential: bearer,
        },
    };
    if let Some(ttl) = lease_ttl {
        use sha2::{Digest, Sha256};
        let verifier: [u8; 32] = Sha256::digest(bearer).into();
        sqlx::query(
            "INSERT INTO central.execution_ownership (id, workspace_id, owner_scope, owner_identity, heartbeat_at, claimed_run_id, claimed_step_id, claimed_step_attempt_id, run_id, lease_token_hash, fencing_generation, lease_expires_at) \
             VALUES ($1, $2, $3, 'harness-suite', clock_timestamp(), $4, $5, $6, $4, $7, 1, clock_timestamp() + $8::interval)",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(uuid_of!(ws))
        .bind(format!("run:{}", uuid_of!(run)))
        .bind(uuid_of!(run))
        .bind(step)
        .bind(uuid_of!(step_attempt))
        .bind(&verifier[..])
        .bind(ttl.to_string())
        .execute(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    }
    Ok(out)
}

/// `seedResumeSuccessor`: what a committed ResumeReconciledAttempt
/// leaves beside the linked StepAttempt (harness phase 3g decision 2) —
/// a new running Step (sequence 2) holding a prepared StepAttempt whose
/// `predecessor_id` is the linked StepAttempt.
async fn seed_resume_successor(admin: &mut PgConnection, l: &LinkedRun) -> Result<()> {
    let step = uuid::Uuid::now_v7();
    let logical = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO central.steps (id, workspace_id, task_id, run_id, version, state, logical_operation_id, sequence) \
         VALUES ($1, $2, $3, $4, 1, 'running', $5, 2)",
    )
    .bind(step)
    .bind(uuid_of!(l.ws))
    .bind(uuid_of!(l.task))
    .bind(uuid_of!(l.run))
    .bind(logical)
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.step_attempts (id, workspace_id, step_id, task_id, run_id, version, logical_operation_id, physical_attempt_id, sequence, state, predecessor_id) \
         VALUES ($1, $2, $3, $4, $5, 1, $6, $7, 1, 'prepared', $8)",
    )
    .bind(uuid_of!(StepAttemptId::new()))
    .bind(uuid_of!(l.ws))
    .bind(step)
    .bind(uuid_of!(l.task))
    .bind(uuid_of!(l.run))
    .bind(logical)
    .bind(uuid::Uuid::now_v7())
    .bind(uuid_of!(l.attempt))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// `retryLinkedRun`: what a committed RetryFailedTask leaves around `l`
/// (harness phase 3k decision 4) — `l`'s run failed and the task naming
/// a new queued run of the same task (run_index 2) as current.
async fn retry_linked_run(admin: &mut PgConnection, l: &LinkedRun) -> Result<RunId> {
    let next = RunId::new();
    sqlx::query("UPDATE central.runs SET status = 'failed', version = version + 1 WHERE id = $1")
        .bind(uuid_of!(l.run))
        .execute(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
         VALUES ($1, $2, $3, 1, 'queued', 2)",
    )
    .bind(uuid_of!(next))
    .bind(uuid_of!(l.ws))
    .bind(uuid_of!(l.task))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "UPDATE central.tasks SET status = 'queued', current_run_id = $2, last_run_index = 2, version = version + 1 \
         WHERE id = $1",
    )
    .bind(uuid_of!(l.task))
    .bind(uuid_of!(next))
    .execute(&mut *admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(next)
}

// ---------------------------------------------------------------------------
// Domain builders — every stored row is one the domain itself produced.
// ---------------------------------------------------------------------------

/// `t0` carries nanoseconds so every round trip exercises the store's
/// microsecond truncation.
#[allow(clippy::expect_used)] // Integration-test fixture: a failure here is a fixture bug.
fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000)
        .expect("t0")
        .checked_add(Duration::nanoseconds(123_456_789))
        .expect("t0 nanos")
}

const FENCE: Fence = Fence { generation: 1 };
const DIGEST_KEY: &[u8] = b"pg-store-test-digest-key-0123456";
const MAC_KEY: &[u8] = b"approval-test-key-0123456789abcdef";

fn is_code(err: &Failure, code: &str) -> bool {
    err.code() == code
}

/// `requireNoDriverType` — a `pg_*` adapter code is a driver detail
/// crossing the port.
fn require_no_driver_type(err: &Failure) {
    assert!(
        !err.code().starts_with("pg_"),
        "driver error crossed the port: {err}"
    );
}

fn prepared_with_budget(
    ws: WorkspaceId,
    run: RunId,
    permission: PermissionPolicy,
    budget: Budget,
) -> Result<Attempt> {
    Attempt::prepare(PrepareInput {
        id: HarnessAttemptId::new(),
        workspace_id: ws,
        run_id: run,
        kind: Kind::new("claude-code"),
        adapter_version: "0.1.0".to_string(),
        workspace: Workspace {
            path: "/srv/central/worktrees/r1".to_string(),
            base_sha: "abc123".to_string(),
        },
        permission,
        fence: FENCE,
        budget,
        at: t0(),
    })
}

fn prepared(ws: WorkspaceId, run: RunId, permission: PermissionPolicy) -> Result<Attempt> {
    prepared_with_budget(
        ws,
        run,
        permission,
        Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: Duration::minutes(30),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
    )
}

fn running(a: Attempt) -> Result<Attempt> {
    let a = a.launch(FENCE, "scope-1", "2.1.0", t0() + Duration::seconds(1))?;
    a.reveal_session(FENCE, "sess-1", t0() + Duration::seconds(2))
}

/// `attemptIn` drives a fresh attempt through the domain mutators into
/// `state`.
fn attempt_in(ws: WorkspaceId, run: RunId, state: State) -> Result<Attempt> {
    let at = t0() + Duration::minutes(1);
    let exit = 3;
    match state {
        State::Prepared => prepared(ws, run, PermissionPolicy::Deny),
        State::Launching => {
            prepared(ws, run, PermissionPolicy::AutoAllow)?.launch(FENCE, "scope-1", "2.1.0", at)
        }
        State::Running => {
            let a = running(prepared(ws, run, PermissionPolicy::Bridge)?)?;
            let a = a.record_progress(FENCE, 4, at)?;
            a.apply_usage(
                FENCE,
                Usage {
                    tokens_in: 10,
                    tokens_out: 2,
                    cache_read: 3,
                    cache_write: 4,
                    cost_micro_usd: 5,
                    scope: UsageScope::Step,
                    estimated: true,
                },
                at,
            )
        }
        State::AwaitingPermission => running(prepared(ws, run, PermissionPolicy::Bridge)?)?
            .await_permission(FENCE, "perm-1", at),
        State::Ambiguous => running(prepared(ws, run, PermissionPolicy::Bridge)?)?.mark_ambiguous(
            FENCE,
            "scope lost after restart",
            at,
        ),
        State::Succeeded => {
            let a = running(prepared(ws, run, PermissionPolicy::Bridge)?)?;
            let a = a.apply_usage(
                FENCE,
                Usage {
                    tokens_in: 7,
                    scope: UsageScope::SessionCumulative,
                    ..Usage::default()
                },
                at,
            )?;
            a.terminate(
                FENCE,
                Terminal {
                    status: TerminalStatus::Succeeded,
                    reason: String::new(),
                    exit_code: Some(0),
                },
                at,
            )
        }
        State::Failed => {
            let a = running(prepared(ws, run, PermissionPolicy::Bridge)?)?;
            let a = a.apply_usage(
                FENCE,
                Usage {
                    tokens_out: 9,
                    cost_micro_usd: 11,
                    scope: UsageScope::Run,
                    ..Usage::default()
                },
                at,
            )?;
            a.terminate(
                FENCE,
                Terminal {
                    status: TerminalStatus::MaxTurns,
                    reason: "turn limit".to_string(),
                    exit_code: Some(exit),
                },
                at,
            )
        }
        State::Interrupted => running(prepared(ws, run, PermissionPolicy::Deny)?)?.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Interrupted,
                reason: String::new(),
                exit_code: None,
            },
            at,
        ),
        State::Killed => running(prepared(ws, run, PermissionPolicy::Deny)?)?.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Killed,
                reason: String::new(),
                exit_code: None,
            },
            at,
        ),
        State::BudgetExhausted => running(prepared(ws, run, PermissionPolicy::Deny)?)?.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Budget,
                reason: String::new(),
                exit_code: None,
            },
            at,
        ),
        State::Resolved => {
            let a = running(prepared(ws, run, PermissionPolicy::Bridge)?)?
                .mark_ambiguous(FENCE, "lost", at)?;
            a.resolve(
                FENCE,
                Resolution {
                    kind: ResolutionKind::Resume,
                    decided_by: "operator".to_string(),
                },
                at,
            )
        }
        _ => unreachable!("no builder for state {state:?}"),
    }
}

fn linked_prepared(l: &LinkedRun) -> Result<Attempt> {
    Attempt::prepare(PrepareInput {
        id: l.attempt,
        workspace_id: l.ws,
        run_id: l.run,
        kind: Kind::new("claude-code"),
        adapter_version: "0.1.0".to_string(),
        workspace: Workspace {
            path: "/var/lib/central-harness/worktrees/runs/r/repo".to_string(),
            base_sha: "abc123".to_string(),
        },
        permission: PermissionPolicy::Deny,
        fence: FENCE,
        budget: Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: Duration::minutes(30),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
        at: t0(),
    })
}

/// `applyEvent` maps one event onto the domain mutators: progress first,
/// usage second, the kind-specific mutator last; returns the next
/// attempt and the event's record.
fn apply_event(a: &Attempt, e: &Event) -> Result<(Attempt, EventRecord)> {
    let rec = record::record_of(e, DIGEST_KEY)?;
    let mut next = a.record_progress(FENCE, e.seq, e.at)?;
    if let Some(p) = &e.payload {
        next = match p {
            EventPayload::SessionStarted(started) => {
                next.reveal_session(FENCE, &started.harness_session_id, e.at)?
            }
            EventPayload::UsageReport(report) => next.apply_usage(FENCE, report.usage, e.at)?,
            EventPayload::PermissionRequested(req) => {
                next.await_permission(FENCE, &req.request_id, e.at)?
            }
            EventPayload::PermissionResolved(res) => {
                next.resolve_permission(FENCE, &res.request_id, e.at)?
            }
            EventPayload::TerminalReported(report) => {
                next.terminate(FENCE, report.terminal.clone(), e.at)?
            }
            _ => next,
        };
    }
    Ok((next, rec))
}

fn event(a: &Attempt, seq: u64, payload: EventPayload) -> Event {
    Event {
        attempt: a.id,
        seq,
        at: t0() + Duration::minutes(seq as i64),
        harness_session_id: "sess-1".to_string(),
        raw: format!(r#"{{"frame":{seq},"secret":"sk-ant-never-stored"}}"#).into_bytes(),
        payload: Some(payload),
    }
}

async fn stored(store: &PgHarnessStore, a: &Attempt) -> Result<Option<Attempt>> {
    match store.load(a.workspace_id, a.id).await {
        Ok(got) => Ok(Some(got)),
        Err(e) if is_code(&e, codes::ATTEMPT_NOT_FOUND) => Ok(None),
        Err(e) => Err(e),
    }
}

fn input_mac(input: &str) -> Result<InputMac> {
    compute_input_mac(MAC_KEY, input.as_bytes())
}

// ---------------------------------------------------------------------------
// store_test.go
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_load_round_trips_every_state_and_field() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("create_roundtrip").await?;
    let ws = WorkspaceId::new();
    for state in [
        State::Prepared,
        State::Launching,
        State::Running,
        State::AwaitingPermission,
        State::Ambiguous,
        State::Succeeded,
        State::Failed,
        State::Interrupted,
        State::Killed,
        State::BudgetExhausted,
        State::Resolved,
    ] {
        let a = attempt_in(ws, seed_run(&mut admin, ws).await?, state)?;
        store
            .create(&a)
            .await
            .map_err(|e| Failure::internal("test_assert", format!("create {state:?}: {e}")))?;
        let got = store.load(ws, a.id).await?;
        assert!(got.equal(&a), "round trip changed the attempt {state:?}");
    }

    // A resume link round-trips too: it references the previous attempt
    // through the workspace-scoped self foreign key.
    let run = seed_run(&mut admin, ws).await?;
    let prev = attempt_in(ws, run, State::Succeeded)?;
    store.create(&prev).await?;
    let resumed = Attempt::prepare_resume(
        &prev,
        PrepareInput {
            id: HarnessAttemptId::new(),
            workspace_id: ws,
            run_id: run,
            kind: prev.kind.clone(),
            adapter_version: "0.1.0".to_string(),
            workspace: prev.workspace.clone(),
            permission: PermissionPolicy::Bridge,
            fence: FENCE,
            budget: Budget {
                cost_micro_usd: 5_000_000,
                wall_clock: Duration::minutes(30),
                cost_defaulted: false,
                wall_clock_defaulted: false,
            },
            at: t0() + Duration::hours(1),
        },
    )?;
    store.create(&resumed).await?;
    let got = store.load(ws, resumed.id).await?;
    assert!(
        got.equal(&resumed) && got.resume_of == Some(prev.id) && got.resume_session_id == "sess-1"
    );
    Ok(())
}

#[tokio::test]
async fn create_is_idempotent_for_an_equal_retry_only() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("create_idem").await?;
    let ws = WorkspaceId::new();
    let a = attempt_in(ws, seed_run(&mut admin, ws).await?, State::Running)?;
    store.create(&a).await?;
    store.create(&a).await.map_err(|e| {
        Failure::internal(
            "test_assert",
            format!("retried create of an equal attempt: {e}"),
        )
    })?;
    let mut different = a.clone();
    different.adapter_version = "0.2.0".to_string();
    let err = store
        .create(&different)
        .await
        .expect_err("different content under a taken id");
    assert!(is_code(&err, codes::VERSION_CONFLICT), "{err}");
    Ok(())
}

#[tokio::test]
async fn create_rejects_a_second_live_attempt_for_a_run() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("create_live").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    store.create(&attempt_in(ws, run, State::Running)?).await?;
    let err = store
        .create(&attempt_in(ws, run, State::Prepared)?)
        .await
        .expect_err("second live attempt");
    assert!(is_code(&err, codes::LIVE_ATTEMPT_EXISTS), "{err}");
    require_no_driver_type(&err);
    store.create(&attempt_in(ws, run, State::Failed)?).await?;
    Ok(())
}

#[tokio::test]
async fn create_rejects_invalid_attempts() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("create_invalid").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;

    let mut versioned = attempt_in(ws, run, State::Prepared)?;
    versioned.version = 1;
    let mut invalid = attempt_in(ws, run, State::Prepared)?;
    invalid.workspace.base_sha = String::new();
    let unknown_run = attempt_in(ws, RunId::new(), State::Prepared)?;
    let other_workspace = attempt_in(WorkspaceId::new(), run, State::Prepared)?;
    let mut oversize = attempt_in(ws, run, State::Prepared)?;
    oversize.kind = Kind::new("k".repeat(65));
    for (name, a) in [
        ("non-zero version", versioned),
        ("fails Validate", invalid),
        ("unknown run", unknown_run),
        ("run in another workspace", other_workspace),
        ("oversize kind", oversize),
    ] {
        let err = store.create(&a).await.expect_err(name);
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "{name}: {err}");
        require_no_driver_type(&err);
    }
    Ok(())
}

#[tokio::test]
async fn load_reports_missing_and_corrupt_rows() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("load_corrupt").await?;
    let ws = WorkspaceId::new();
    let a = attempt_in(ws, seed_run(&mut admin, ws).await?, State::Running)?;
    store.create(&a).await?;
    let err = store
        .load(ws, HarnessAttemptId::new())
        .await
        .expect_err("unknown id");
    assert!(is_code(&err, codes::ATTEMPT_NOT_FOUND), "{err}");
    let err = store
        .load(WorkspaceId::new(), a.id)
        .await
        .expect_err("other workspace");
    assert!(is_code(&err, codes::ATTEMPT_NOT_FOUND), "{err}");
    // A row the domain would never write: running without a session id.
    sqlx::query("UPDATE central.harness_attempts SET harness_session_id = NULL WHERE id = $1")
        .bind(uuid_of!(a.id))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let err = store.load(ws, a.id).await.expect_err("corrupt row");
    assert!(
        is_code(&err, "pg_data_corrupt"),
        "corrupt row: {err} (upstream ErrInvalidAttempt becomes pg_data_corrupt here)"
    );
    for leaked in ["/srv/central", "scope-1", "sess-1"] {
        assert!(
            !err.to_string().contains(leaked),
            "corrupt-row error leaked {leaked}: {err}"
        );
    }
    let nil = HarnessAttemptId::from_trusted_db_bytes([0; 16]);
    let err = store.load(ws, nil).await.expect_err("zero id");
    assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
    Ok(())
}

#[tokio::test]
async fn live_attempt_for_run() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("live").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    assert!(store.live_attempt_for_run(ws, run).await?.is_none());
    store
        .create(&attempt_in(ws, run, State::Succeeded)?)
        .await?;
    assert!(store.live_attempt_for_run(ws, run).await?.is_none());
    let live = attempt_in(ws, run, State::Ambiguous)?;
    store.create(&live).await?;
    let got = store
        .live_attempt_for_run(ws, run)
        .await?
        .expect("live attempt");
    assert!(got.equal(&live));
    assert!(
        store
            .live_attempt_for_run(WorkspaceId::new(), run)
            .await?
            .is_none()
    );

    // The upstream liveAttemptStates drift guard, covered through
    // behavior: every non-terminal state is live, every terminal state
    // is not. One run per state.
    for state in [State::Launching, State::Running, State::AwaitingPermission] {
        let run = seed_run(&mut admin, ws).await?;
        store.create(&attempt_in(ws, run, state)?).await?;
        assert!(
            store.live_attempt_for_run(ws, run).await?.is_some(),
            "{state:?} must be live"
        );
    }
    for state in [
        State::Failed,
        State::Interrupted,
        State::Killed,
        State::BudgetExhausted,
    ] {
        let run = seed_run(&mut admin, ws).await?;
        store.create(&attempt_in(ws, run, state)?).await?;
        assert!(
            store.live_attempt_for_run(ws, run).await?.is_none(),
            "{state:?} must not be live"
        );
    }
    Ok(())
}

async fn create_running(store: &PgHarnessStore, admin: &mut PgConnection) -> Result<Attempt> {
    let ws = WorkspaceId::new();
    let a = attempt_in(ws, seed_run(admin, ws).await?, State::Running)?;
    store.create(&a).await?;
    Ok(a)
}

#[tokio::test]
async fn save_advances_the_stored_version() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("save_version").await?;
    let a = create_running(&store, &mut admin).await?;
    let at = t0() + Duration::minutes(2);

    let next = a.await_permission(FENCE, "perm-1", at)?;
    let stored = store.save(&a, &next, &[]).await?;
    let mut want = next.clone();
    want.version = 1;
    assert!(
        stored.version == 1 && stored.equal(&want),
        "stored = {stored:?}"
    );
    let loaded = store.load(a.workspace_id, a.id).await?;
    assert!(loaded.equal(&stored));
    // The returned attempt is the next expected value; one event may
    // drive several mutators before a single write.
    let next2 = stored.resolve_permission(FENCE, "perm-1", at)?;
    let next2 = next2.terminate(
        FENCE,
        Terminal {
            status: TerminalStatus::Succeeded,
            reason: String::new(),
            exit_code: None,
        },
        at,
    )?;
    let stored2 = store.save(&stored, &next2, &[]).await?;
    assert!(stored2.version == 2 && stored2.state == State::Succeeded);
    Ok(())
}

#[tokio::test]
async fn save_distinguishes_version_and_fence_conflicts() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("save_conflicts").await?;
    let a = create_running(&store, &mut admin).await?;
    let at = t0() + Duration::minutes(2);

    store
        .save(&a, &a.await_permission(FENCE, "perm-1", at)?, &[])
        .await?;
    // A second writer still holding version 0 loses, even under the same
    // fence.
    let err = store
        .save(&a, &a.mark_ambiguous(FENCE, "lost", at)?, &[])
        .await
        .expect_err("stale version");
    assert!(is_code(&err, codes::VERSION_CONFLICT), "{err}");
    require_no_driver_type(&err);

    let current = store.load(a.workspace_id, a.id).await?;
    // A holder whose fence was superseded loses on the fence, not the
    // version.
    let mut stale = current.clone();
    stale.fence = Fence { generation: 2 };
    let err = store
        .save(&stale, &stale.mark_ambiguous(stale.fence, "lost", at)?, &[])
        .await
        .expect_err("stale fence");
    assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
    let loaded = store.load(a.workspace_id, a.id).await?;
    assert!(
        loaded.equal(&current),
        "a rejected Save changed the stored attempt"
    );
    Ok(())
}

#[tokio::test]
async fn save_preconditions() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("save_pre").await?;
    let a = create_running(&store, &mut admin).await?;
    let at = t0() + Duration::minutes(2);
    let next = a.await_permission(FENCE, "perm-1", at)?;

    let mut other_id = next.clone();
    other_id.id = HarnessAttemptId::new();
    let mut other_ws = next.clone();
    other_ws.workspace_id = WorkspaceId::new();
    let mut other_run = next.clone();
    other_run.run_id = RunId::new();
    let mut bumped = next.clone();
    bumped.version = 1;
    let mut invalid = next.clone();
    invalid.pending_permission = String::new();
    for (name, expected, next, want) in [
        ("different id", &a, &other_id, codes::INVALID_ATTEMPT),
        ("different workspace", &a, &other_ws, codes::INVALID_ATTEMPT),
        ("different run", &a, &other_run, codes::INVALID_ATTEMPT),
        ("next bumps version", &a, &bumped, codes::VERSION_CONFLICT),
        ("empty write", &a, &a, codes::INVALID_ATTEMPT),
        ("invalid next", &a, &invalid, codes::INVALID_ATTEMPT),
    ] {
        let err = store.save(expected, next, &[]).await.expect_err(name);
        assert!(is_code(&err, want), "{name}: {err}");
    }
    let ghost = attempt_in(a.workspace_id, a.run_id, State::Running)?;
    let err = store
        .save(&ghost, &ghost.await_permission(FENCE, "p", at)?, &[])
        .await
        .expect_err("unknown attempt");
    assert!(is_code(&err, codes::ATTEMPT_NOT_FOUND), "{err}");

    // Save must never move the event cursor or usage: only append_event
    // may, atomically with the event row it records.
    let moved_seq = create_running(&store, &mut admin).await?;
    let mut moved_seq_next = moved_seq.await_permission(FENCE, "perm-1", at)?;
    moved_seq_next.last_event_seq += 1;
    let moved_usage = create_running(&store, &mut admin).await?;
    let mut moved_usage_next = moved_usage.await_permission(FENCE, "perm-1", at)?;
    moved_usage_next.usage = Usage {
        tokens_in: moved_usage.usage.tokens_in + 1,
        scope: moved_usage.usage.scope,
        ..Usage::default()
    };
    for (name, expected, next) in [
        ("moves LastEventSeq", &moved_seq, &moved_seq_next),
        ("moves Usage", &moved_usage, &moved_usage_next),
    ] {
        let err = store.save(expected, next, &[]).await.expect_err(name);
        assert!(is_code(&err, codes::INVALID_EVENT), "{name}: {err}");
        let loaded = store.load(expected.workspace_id, expected.id).await?;
        assert!(
            loaded.equal(expected),
            "{name}: a rejected cursor/usage-moving Save wrote"
        );
    }
    Ok(())
}

#[tokio::test]
async fn save_maps_the_live_attempt_index() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("save_live").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    // failed straight from prepared carries no launch fields, so the
    // same row is also a valid prepared attempt once its terminal is
    // cleared.
    let failed = prepared(ws, run, PermissionPolicy::Deny)?.terminate(
        FENCE,
        Terminal {
            status: TerminalStatus::Failed,
            reason: String::new(),
            exit_code: None,
        },
        t0(),
    )?;
    store.create(&failed).await?;
    store.create(&attempt_in(ws, run, State::Running)?).await?;
    let mut revived = failed.clone();
    revived.state = State::Prepared;
    revived.terminal = Terminal::default();
    revived.ended_at = None;
    let err = store
        .save(&failed, &revived, &[])
        .await
        .expect_err("second live attempt");
    assert!(is_code(&err, codes::LIVE_ATTEMPT_EXISTS), "{err}");
    require_no_driver_type(&err);
    Ok(())
}

#[tokio::test]
async fn append_event_records_every_kind_atomically() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("append_kinds").await?;
    let ws = WorkspaceId::new();
    let a = prepared(
        ws,
        seed_run(&mut admin, ws).await?,
        PermissionPolicy::Bridge,
    )?
    .launch(FENCE, "scope-1", "2.1.0", t0())?;
    store.create(&a).await?;
    let payloads = vec![
        EventPayload::SessionStarted(SessionStarted {
            harness_session_id: "sess-1".to_string(),
            harness_version: "2.1.0".to_string(),
            ..SessionStarted::default()
        }),
        EventPayload::Message(Message {
            role: MessageRole::Assistant,
            text: "sk-ant-never-stored".to_string(),
            ..Message::default()
        }),
        EventPayload::Reasoning(Reasoning {
            text: "thinking".to_string(),
        }),
        EventPayload::ToolCall(ToolCall {
            id: "t1".to_string(),
            name: "Bash".to_string(),
            input: b"go test".to_vec(),
            ..ToolCall::default()
        }),
        EventPayload::ToolResult(ToolResult {
            id: "t1".to_string(),
            status: ToolStatus::CutOff,
            output: b"ok".to_vec(),
        }),
        EventPayload::PermissionRequested(PermissionRequested {
            request_id: "perm-1".to_string(),
            tool: "Bash".to_string(),
            resources: vec!["/etc".to_string()],
            ..PermissionRequested::default()
        }),
        EventPayload::PermissionResolved(PermissionResolved {
            request_id: "perm-1".to_string(),
            decision: PermissionOutcome::Timeout,
            decided_by: String::new(),
        }),
        EventPayload::Plan(Plan {
            entries: vec!["a".to_string()],
        }),
        EventPayload::UsageReport(UsageReport {
            usage: Usage {
                tokens_in: 5,
                scope: UsageScope::SessionCumulative,
                ..Usage::default()
            },
        }),
        EventPayload::Retry(Retry {
            reason: "rate".to_string(),
        }),
        EventPayload::Warning(Warning {
            message: "w".to_string(),
        }),
        EventPayload::TerminalReported(TerminalReported {
            terminal: Terminal {
                status: TerminalStatus::Budget,
                reason: "cap".to_string(),
                exit_code: None,
            },
        }),
    ];
    let mut expected = a.clone();
    for (i, p) in payloads.iter().enumerate() {
        let e = event(&a, (i + 1) as u64, p.clone());
        let (next, rec) = apply_event(&expected, &e)?;
        let stored = store
            .append_event(&expected, &next, &rec, &[])
            .await
            .map_err(|err| {
                Failure::internal("test_assert", format!("append {:?}: {err}", p.event_kind()))
            })?;
        let mut want = next.clone();
        want.version = expected.version + 1;
        assert!(
            stored.equal(&want),
            "append {:?}: stored vs want",
            p.event_kind()
        );
        expected = stored;
    }
    assert_eq!(expected.state, State::BudgetExhausted);
    assert_eq!(expected.version, payloads.len() as i64);
    assert_eq!(expected.last_event_seq, payloads.len() as u64);
    let loaded = store.load(ws, a.id).await?;
    assert!(loaded.equal(&expected));

    let rows = sqlx::query(
        "SELECT seq, kind, raw_size, octet_length(raw_sha256),
                COALESCE(harness_session_id, ''), COALESCE(tool_call_id, ''), COALESCE(tool_name, ''), COALESCE(tool_status, ''),
                COALESCE(permission_request_id, ''), COALESCE(permission_outcome, ''), COALESCE(terminal_status, '')
         FROM central.harness_events WHERE workspace_id = $1 AND attempt_id = $2 ORDER BY seq",
    )
    .bind(uuid_of!(ws))
    .bind(uuid_of!(a.id))
    .fetch_all(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    use sqlx::Row;
    let mut got: Vec<String> = Vec::new();
    for row in &rows {
        let size: i64 = row.try_get("raw_size").map_err(|e| classify_sqlx(&e))?;
        let digest: i32 = row.try_get("octet_length").map_err(|e| classify_sqlx(&e))?;
        let session: String = row.try_get(4).map_err(|e| classify_sqlx(&e))?;
        assert!(size >= 1 && digest == 32 && session == "sess-1");
        let kind: String = row.try_get("kind").map_err(|e| classify_sqlx(&e))?;
        let call: String = row.try_get(5).map_err(|e| classify_sqlx(&e))?;
        let tool: String = row.try_get(6).map_err(|e| classify_sqlx(&e))?;
        let status: String = row.try_get(7).map_err(|e| classify_sqlx(&e))?;
        let request: String = row.try_get(8).map_err(|e| classify_sqlx(&e))?;
        let outcome: String = row.try_get(9).map_err(|e| classify_sqlx(&e))?;
        let terminal: String = row.try_get(10).map_err(|e| classify_sqlx(&e))?;
        got.push([kind, call, tool, status, request, outcome, terminal].join("|"));
    }
    let want = [
        "session_started||||||",
        "message||||||",
        "reasoning||||||",
        "tool_call|t1|Bash||||",
        "tool_result|t1||cut_off|||",
        "permission_requested||Bash||perm-1||",
        "permission_resolved||||perm-1|timeout|",
        "plan||||||",
        "usage_report||||||",
        "retry||||||",
        "warning||||||",
        "terminal_reported||||||budget",
    ];
    assert_eq!(got.join("\n"), want.join("\n"), "event rows");
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM central.harness_events e \
         WHERE position('sk-ant' in concat_ws('|', e.kind, e.harness_session_id, e.tool_call_id, e.tool_name, e.permission_request_id)) > 0",
    )
    .fetch_one(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(leaked, 0, "payload content reached the event table");
    Ok(())
}

#[tokio::test]
async fn append_event_rolls_back_the_event_when_the_cas_fails() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("append_rollback").await?;
    let a = create_running(&store, &mut admin).await?;
    let (first, rec) = apply_event(
        &a,
        &event(
            &a,
            5,
            EventPayload::Message(Message {
                role: MessageRole::Assistant,
                ..Message::default()
            }),
        ),
    )?;
    let stored = store.append_event(&a, &first, &rec, &[]).await?;

    // Stale version: the second writer still holds version 0.
    let (next, rec6) = apply_event(&a, &event(&a, 6, EventPayload::Plan(Plan::default())))?;
    let err = store
        .append_event(&a, &next, &rec6, &[])
        .await
        .expect_err("stale version");
    assert!(is_code(&err, codes::VERSION_CONFLICT), "{err}");
    // Superseded fence at the current version.
    let mut stale = stored.clone();
    stale.fence = Fence { generation: 2 };
    let stale_next = stale.record_progress(stale.fence, 6, t0() + Duration::hours(1))?;
    let err = store
        .append_event(&stale, &stale_next, &rec6, &[])
        .await
        .expect_err("stale fence");
    assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM central.harness_events WHERE attempt_id = $1 AND seq = 6",
    )
    .bind(uuid_of!(a.id))
    .fetch_one(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(events, 0, "a rejected append left event rows");
    let loaded = store.load(a.workspace_id, a.id).await?;
    assert!(
        loaded.equal(&stored),
        "a rejected append changed the stored attempt"
    );
    Ok(())
}

#[tokio::test]
async fn append_event_replay_is_idempotent() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("append_replay").await?;
    let a = create_running(&store, &mut admin).await?;
    let (next, rec) = apply_event(
        &a,
        &event(
            &a,
            5,
            EventPayload::Message(Message {
                role: MessageRole::Assistant,
                ..Message::default()
            }),
        ),
    )?;
    let stored = store.append_event(&a, &next, &rec, &[]).await?;
    let (more, rec6) = apply_event(&stored, &event(&a, 6, EventPayload::Plan(Plan::default())))?;
    let current = store.append_event(&stored, &more, &rec6, &[]).await?;

    // Retrying the first append (unknown commit outcome) returns what is
    // stored now, so the caller never reuses its stale next.
    let replayed = store.append_event(&a, &next, &rec, &[]).await?;
    assert!(
        replayed.equal(&current),
        "replay returned {replayed:?}, want {current:?}"
    );
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM central.harness_events WHERE attempt_id = $1")
            .bind(uuid_of!(a.id))
            .fetch_one(&mut admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(events, 2, "replay changed the event count");

    // The same (attempt, seq) with a different frame is a conflict.
    let mut other = rec.clone();
    other.raw_sha256[0] ^= 0xff;
    let err = store
        .append_event(&a, &next, &other, &[])
        .await
        .expect_err("different digest");
    assert!(is_code(&err, codes::EVENT_CONFLICT), "{err}");

    // An event row ahead of the attempt's cursor can only come from
    // outside the store; appending it again is a conflict, not a replay.
    let (ahead, rec9) = apply_event(
        &current,
        &event(&a, 9, EventPayload::Retry(Retry::default())),
    )?;
    sqlx::query(
        "INSERT INTO central.harness_events (workspace_id, attempt_id, seq, kind, at, raw_size, raw_sha256) \
         VALUES ($1, $2, 9, 'retry', now(), $3, $4)",
    )
    .bind(uuid_of!(a.workspace_id))
    .bind(uuid_of!(a.id))
    .bind(rec9.raw_size)
    .bind(&rec9.raw_sha256[..])
    .execute(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let err = store
        .append_event(&current, &ahead, &rec9, &[])
        .await
        .expect_err("event ahead");
    assert!(is_code(&err, codes::EVENT_CONFLICT), "{err}");
    Ok(())
}

#[tokio::test]
async fn append_event_preconditions() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("append_pre").await?;
    let a = create_running(&store, &mut admin).await?;
    let (next, rec) = apply_event(
        &a,
        &event(
            &a,
            5,
            EventPayload::Message(Message {
                role: MessageRole::Assistant,
                ..Message::default()
            }),
        ),
    )?;

    let mut foreign = rec.clone();
    foreign.attempt = HarnessAttemptId::new();
    let mut wrong_seq = rec.clone();
    wrong_seq.seq = 6;
    let mut invalid = rec.clone();
    invalid.raw_size = 0;
    let mut behind = a.clone();
    behind.last_event_seq = 5;
    for (name, expected, next, rec, want) in [
        (
            "record for another attempt",
            &a,
            &next,
            &foreign,
            codes::INVALID_EVENT,
        ),
        (
            "cursor differs from seq",
            &a,
            &next,
            &wrong_seq,
            codes::INVALID_EVENT,
        ),
        ("invalid record", &a, &next, &invalid, codes::INVALID_EVENT),
        (
            "seq not after the cursor",
            &behind,
            &next,
            &rec,
            codes::INVALID_EVENT,
        ),
        ("empty write", &next, &next, &rec, codes::INVALID_ATTEMPT),
    ] {
        let err = store
            .append_event(expected, next, rec, &[])
            .await
            .expect_err(name);
        assert!(is_code(&err, want), "{name}: {err}");
    }
    let ghost = attempt_in(a.workspace_id, a.run_id, State::Running)?;
    let (ghost_next, ghost_rec) = apply_event(
        &ghost,
        &event(&ghost, 5, EventPayload::Plan(Plan::default())),
    )?;
    let err = store
        .append_event(&ghost, &ghost_next, &ghost_rec, &[])
        .await
        .expect_err("unknown attempt");
    assert!(is_code(&err, codes::ATTEMPT_NOT_FOUND), "{err}");
    let (oversize, oversize_rec) = apply_event(
        &a,
        &event(
            &a,
            5,
            EventPayload::ToolCall(ToolCall {
                id: "t1".to_string(),
                name: "n".repeat(257),
                input: Vec::new(),
                ..ToolCall::default()
            }),
        ),
    )?;
    let err = store
        .append_event(&a, &oversize, &oversize_rec, &[])
        .await
        .expect_err("oversize tool name");
    assert!(is_code(&err, codes::INVALID_EVENT), "{err}");
    require_no_driver_type(&err);
    Ok(())
}

#[tokio::test]
async fn append_event_rejects_a_tool_name_with_a_nul_byte() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("append_nul").await?;
    let a = create_running(&store, &mut admin).await?;
    let (next, rec) = apply_event(
        &a,
        &event(
            &a,
            5,
            EventPayload::ToolCall(ToolCall {
                id: "t1".to_string(),
                name: "Ba\u{0}sh".to_string(),
                input: Vec::new(),
                ..ToolCall::default()
            }),
        ),
    )?;
    let err = store
        .append_event(&a, &next, &rec, &[])
        .await
        .expect_err("NUL byte");
    assert!(is_code(&err, codes::INVALID_EVENT), "{err}");
    require_no_driver_type(&err);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM central.harness_events WHERE attempt_id = $1 AND seq = 5",
    )
    .bind(uuid_of!(a.id))
    .fetch_one(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(events, 0, "a rejected append left event rows");
    let loaded = store.load(a.workspace_id, a.id).await?;
    assert!(loaded.equal(&a));
    Ok(())
}

#[tokio::test]
async fn save_rejects_a_terminal_reason_with_a_nul_byte() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("save_nul").await?;
    let a = create_running(&store, &mut admin).await?;
    let at = t0() + Duration::minutes(2);
    let next = a.terminate(
        FENCE,
        Terminal {
            status: TerminalStatus::Failed,
            reason: "boom\u{0}".to_string(),
            exit_code: None,
        },
        at,
    )?;
    let err = store.save(&a, &next, &[]).await.expect_err("NUL byte");
    assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
    require_no_driver_type(&err);
    let loaded = store.load(a.workspace_id, a.id).await?;
    assert!(loaded.equal(&a));
    Ok(())
}

// ---------------------------------------------------------------------------
// budget_test.go — the budget recorded at prepare, persisted exactly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_load_round_trips_the_budget() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("budget_roundtrip").await?;
    let ws = WorkspaceId::new();
    for budget in [
        Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: Duration::minutes(30),
            cost_defaulted: true,
            wall_clock_defaulted: true,
        },
        Budget {
            cost_micro_usd: 250_000,
            wall_clock: Duration::minutes(2),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
        Budget {
            cost_micro_usd: 10_000,
            wall_clock: Duration::hours(1),
            cost_defaulted: false,
            wall_clock_defaulted: true,
        },
        Budget {
            cost_micro_usd: MAX_BUDGET_COST_MICRO_USD,
            wall_clock: MAX_BUDGET_WALL_CLOCK,
            cost_defaulted: true,
            wall_clock_defaulted: false,
        },
        Budget {
            cost_micro_usd: 1,
            wall_clock: Duration::seconds(1),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
    ] {
        let run = seed_run(&mut admin, ws).await?;
        let a = prepared_with_budget(ws, run, PermissionPolicy::Deny, budget)?;
        store
            .create(&a)
            .await
            .map_err(|e| Failure::internal("test_assert", format!("create {budget:?}: {e}")))?;
        let loaded = store.load(ws, a.id).await?;
        assert!(
            loaded.budget == budget && loaded.equal(&a),
            "Load budget = {:?}",
            loaded.budget
        );
        let live = store
            .live_attempt_for_run(ws, run)
            .await?
            .expect("live attempt");
        assert_eq!(live.budget, budget);
        let (cost, seconds, cost_defaulted, wall_defaulted): (i64, i32, bool, bool) =
            sqlx::query_as(
                "SELECT budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted, budget_wall_clock_defaulted \
                 FROM central.harness_attempts WHERE id = $1",
            )
            .bind(uuid_of!(a.id))
            .fetch_one(&mut admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        assert!(
            cost == budget.cost_micro_usd
                && Duration::seconds(i64::from(seconds)) == budget.wall_clock
                && cost_defaulted == budget.cost_defaulted
                && wall_defaulted == budget.wall_clock_defaulted,
            "stored budget = {cost} {seconds}s {cost_defaulted} {wall_defaulted}, want {budget:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_wall_clock_that_is_not_whole_seconds() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("budget_whole").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    let a = prepared_with_budget(
        ws,
        run,
        PermissionPolicy::Deny,
        Budget {
            cost_micro_usd: 1_000_000,
            wall_clock: Duration::seconds(90) + Duration::milliseconds(1),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
    )?;
    let err = store.create(&a).await.expect_err("subsecond wall clock");
    assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
    let err = store
        .load(ws, a.id)
        .await
        .expect_err("refused attempt stored");
    assert!(is_code(&err, codes::ATTEMPT_NOT_FOUND), "{err}");
    Ok(())
}

#[tokio::test]
async fn save_never_changes_the_budget() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("budget_save").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    let budget = Budget {
        cost_micro_usd: 2_500_000,
        wall_clock: Duration::minutes(10),
        cost_defaulted: false,
        wall_clock_defaulted: true,
    };
    let a = prepared_with_budget(ws, run, PermissionPolicy::Deny, budget)?;
    store.create(&a).await?;
    let launching = a.launch(FENCE, "scope-1", "2.1.0", t0() + Duration::seconds(1))?;
    type BudgetEdit = fn(&mut Budget);
    let edits: [(&str, BudgetEdit); 4] = [
        ("cost", |b: &mut Budget| b.cost_micro_usd = 5_000_000),
        ("wall clock", |b: &mut Budget| {
            b.wall_clock = Duration::hours(1)
        }),
        ("cost defaulted", |b: &mut Budget| b.cost_defaulted = true),
        ("wall clock defaulted", |b: &mut Budget| {
            b.wall_clock_defaulted = false
        }),
    ];
    for (name, edit) in edits {
        let mut changed = launching.clone();
        edit(&mut changed.budget);
        let err = store.save(&a, &changed, &[]).await.expect_err(name);
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "{name}: {err}");
        let loaded = store.load(ws, a.id).await?;
        assert!(loaded.equal(&a), "{name}: a refused budget change wrote");
    }
    Ok(())
}

#[tokio::test]
async fn attempts_for_run_and_latest_are_bounded_and_ordered() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("attempts_order").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    // No attempts yet: empty page, no latest.
    assert!(store.attempts_for_run(ws, run).await?.is_empty());
    assert!(store.latest_attempt_for_run(ws, run).await?.is_none());
    // The later-prepared attempt is written first: the read orders by
    // prepared_at, not by insertion (upstream budget_test.go).
    let later = Attempt::prepare(PrepareInput {
        id: HarnessAttemptId::new(),
        workspace_id: ws,
        run_id: run,
        kind: Kind::new("claude-code"),
        adapter_version: "0.1.0".to_string(),
        workspace: Workspace {
            path: "/srv/central/worktrees/r1".to_string(),
            base_sha: "abc123".to_string(),
        },
        permission: PermissionPolicy::Deny,
        fence: FENCE,
        budget: Budget {
            cost_micro_usd: 400_000,
            wall_clock: Duration::minutes(1),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
        at: t0() + Duration::hours(1),
    })?;
    store.create(&later).await?;
    let later_failed = later.fail_unlaunched(FENCE, t0() + Duration::hours(2))?;
    let later_stored = store.save(&later, &later_failed, &[]).await?;
    let earlier = prepared(ws, run, PermissionPolicy::Deny)?;
    store.create(&earlier).await?;
    let attempts = store.attempts_for_run(ws, run).await?;
    assert_eq!(attempts.len(), 2);
    assert!(attempts[0].equal(&earlier) && attempts[1].equal(&later_stored));
    let latest = store
        .latest_attempt_for_run(ws, run)
        .await?
        .expect("latest");
    // Newest prepared wins, live or terminal.
    assert!(latest.equal(&later_stored));
    // Workspace scoping.
    assert!(
        store
            .attempts_for_run(WorkspaceId::new(), run)
            .await?
            .is_empty()
    );
    assert!(
        store
            .latest_attempt_for_run(WorkspaceId::new(), run)
            .await?
            .is_none()
    );
    // Nil ids.
    let nil = WorkspaceId::from_trusted_db_bytes([0; 16]);
    let err = store.attempts_for_run(nil, run).await.expect_err("nil ws");
    assert!(is_code(&err, codes::INVALID_ATTEMPT));
    Ok(())
}

#[tokio::test]
async fn attempts_for_run_refuses_more_than_the_bound() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("attempts_bound").await?;
    let ws = WorkspaceId::new();
    let run = seed_run(&mut admin, ws).await?;
    // The bound is a contract property, so insert rows directly rather
    // than drive MAX_ATTEMPTS_FOR_RUN+1 domain writes: every row is a
    // terminal attempt of the run.
    for i in 0..(MAX_ATTEMPTS_FOR_RUN + 1) as i64 {
        let a = attempt_in(ws, run, State::Failed)?;
        sqlx::query(
            "INSERT INTO central.harness_attempts (
                workspace_id, id, run_id, kind, adapter_version, permission,
                fence_generation, version, state, last_event_seq,
                usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                usage_estimated, prepared_at, updated_at, ended_at,
                budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted, budget_wall_clock_defaulted,
                terminal_status, terminal_reason, terminal_exit_code,
                workspace_path, base_sha)
             VALUES ($1, $2, $3, 'claude-code', '0.1.0', 'deny', 1, 0, 'failed', 0,
                     0, 0, 0, 0, 0, false, $4, $4, $4,
                     1, 1, false, false, 'failed', 'seeded', NULL, '/p', 's')",
        )
        .bind(uuid_of!(a.workspace_id))
        .bind(uuid_of!(a.id))
        .bind(uuid_of!(run))
        .bind(t0() + Duration::minutes(i))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    }
    let err = store
        .attempts_for_run(ws, run)
        .await
        .expect_err("over the bound");
    assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
    Ok(())
}

// ---------------------------------------------------------------------------
// task_cost_test.go — the task cost-cap aggregate.
// ---------------------------------------------------------------------------

/// `costedAttempt` — a failed attempt of `run` that recorded `cost`
/// micro-USD.
fn costed_attempt(ws: WorkspaceId, run: RunId, cost: i64) -> Result<Attempt> {
    let at = t0() + Duration::minutes(1);
    let a = running(prepared(ws, run, PermissionPolicy::Deny)?)?;
    let a = a.apply_usage(
        FENCE,
        Usage {
            cost_micro_usd: cost,
            scope: UsageScope::Run,
            ..Usage::default()
        },
        at,
    )?;
    a.terminate(
        FENCE,
        Terminal {
            status: TerminalStatus::Failed,
            reason: "harness_api_error".to_string(),
            exit_code: None,
        },
        at,
    )
}

#[tokio::test]
async fn cost_for_task_sums_every_run_of_the_task_in_its_workspace() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("cost").await?;
    let ws = WorkspaceId::new();
    let (task, runs) = seed_task_runs(&mut admin, ws, 2).await?;
    assert_eq!(
        store.cost_for_task(ws, task).await?,
        0,
        "a task without attempts"
    );
    // Two attempts in the first run (a resume chain), one in the second
    // (a retry).
    for a in [
        costed_attempt(ws, runs[0], 1_200_000)?,
        costed_attempt(ws, runs[0], 300_000)?,
        costed_attempt(ws, runs[1], 450_000)?,
    ] {
        store.create(&a).await?;
    }
    // Another task of the same workspace, and a task of another
    // workspace.
    let (_, sibling) = seed_task_runs(&mut admin, ws, 1).await?;
    store
        .create(&costed_attempt(ws, sibling[0], 7_000_000)?)
        .await?;
    let other_ws = WorkspaceId::new();
    let (other_task, other_runs) = seed_task_runs(&mut admin, other_ws, 1).await?;
    store
        .create(&costed_attempt(other_ws, other_runs[0], 9_000_000)?)
        .await?;

    assert_eq!(
        store.cost_for_task(ws, task).await?,
        1_950_000,
        "across both runs"
    );
    assert_eq!(
        store.cost_for_task(other_ws, task).await?,
        0,
        "task read under another workspace"
    );
    assert_eq!(store.cost_for_task(other_ws, other_task).await?, 9_000_000);
    assert_eq!(
        store.cost_for_task(ws, TaskId::new()).await?,
        0,
        "unknown task"
    );

    // Two runs whose recorded costs sum past int64: the read saturates.
    let (big, big_runs) = seed_task_runs(&mut admin, ws, 2).await?;
    for run in &big_runs {
        store
            .create(&costed_attempt(ws, *run, i64::MAX - 1)?)
            .await?;
    }
    assert_eq!(
        store.cost_for_task(ws, big).await?,
        i64::MAX,
        "saturating sum"
    );

    for (name, ws_id, task_id) in [
        (
            "zero workspace",
            WorkspaceId::from_trusted_db_bytes([0; 16]),
            task,
        ),
        ("zero task", ws, TaskId::from_trusted_db_bytes([0; 16])),
    ] {
        let err = store.cost_for_task(ws_id, task_id).await.expect_err(name);
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "{name}: {err}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HarnessEventRead — the keyset page over central.harness_events.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn harness_event_read_pages_by_keyset_and_scopes_the_workspace() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("events_read").await?;
    let a = create_running(&store, &mut admin).await?;
    let ws = a.workspace_id;
    // The running fixture has already recorded seqs 1..=4; the page
    // starts at 5.
    let mut expected = a.clone();
    for seq in 5..=7u64 {
        let (next, rec) = apply_event(
            &expected,
            &event(
                &a,
                seq,
                EventPayload::Message(Message {
                    role: MessageRole::Assistant,
                    ..Message::default()
                }),
            ),
        )?;
        expected = store.append_event(&expected, &next, &rec, &[]).await?;
    }
    let head = store
        .read_page(HarnessEventRequest {
            workspace_id: ws,
            attempt_id: a.id,
            cursor: None,
            page_size: 2,
        })
        .await?;
    assert_eq!(head.records.len(), 2);
    assert_eq!(head.records[0].seq, 5);
    let cursor = head.next_cursor.expect("more events");
    assert_eq!(cursor.attempt_id, a.id);
    let rest = store
        .read_page(HarnessEventRequest {
            workspace_id: ws,
            attempt_id: a.id,
            cursor: Some(cursor),
            page_size: 2,
        })
        .await?;
    assert_eq!(rest.records.len(), 1);
    assert_eq!(rest.records[0].seq, 7);
    assert!(rest.next_cursor.is_none());
    // A cursor minted for another attempt is INVALID_EVENT.
    let err = store
        .read_page(HarnessEventRequest {
            workspace_id: ws,
            attempt_id: HarnessAttemptId::new(),
            cursor: Some(cursor),
            page_size: 1,
        })
        .await
        .expect_err("foreign cursor");
    assert!(is_code(&err, codes::INVALID_EVENT), "{err}");
    // Other workspace: an empty page, never rows.
    let empty = store
        .read_page(HarnessEventRequest {
            workspace_id: WorkspaceId::new(),
            attempt_id: a.id,
            cursor: None,
            page_size: 10,
        })
        .await?;
    assert!(empty.records.is_empty() && empty.next_cursor.is_none());
    Ok(())
}

// ---------------------------------------------------------------------------
// lease_recovery_test.go / lease_refence_test.go — the live-lease gate and
// the lease-dead recovery lane.
// ---------------------------------------------------------------------------

/// `linkedAttempt` in `running` state under `l`'s linked ids.
fn linked_running(l: &LinkedRun) -> Result<Attempt> {
    let a = linked_prepared(l)?.launch(
        FENCE,
        &l.attempt.to_string(),
        "2.1.0",
        t0() + Duration::seconds(1),
    )?;
    a.reveal_session(FENCE, "sess-1", t0() + Duration::seconds(2))
}

#[tokio::test]
async fn lease_bound_writes_validate_the_live_execution_lease() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("lease_bound").await?;
    let thirty_seconds = Duration::seconds(30);

    // Valid lease writes.
    {
        let l = seed_linked_run(&mut admin, "prepared", Some(thirty_seconds)).await?;
        let bound = store.with_lease(l.lease);
        let a = linked_prepared(&l)?;
        bound.create(&a).await?;
        let launched = a.launch(
            FENCE,
            &l.attempt.to_string(),
            "2.1.0",
            t0() + Duration::seconds(1),
        )?;
        let saved = bound.save(&a, &launched, &[]).await?;
        let (next, rec) = apply_event(
            &saved,
            &event(
                &saved,
                1,
                EventPayload::SessionStarted(SessionStarted {
                    harness_session_id: "sess-1".to_string(),
                    ..SessionStarted::default()
                }),
            ),
        )?;
        bound.append_event(&saved, &next, &rec, &[]).await?;
    }

    // Create refusals.
    let expired_lease = Duration::seconds(-1);
    for (name, step_state, ttl, mutate, fence_gen) in [
        ("wrong bearer", "prepared", Some(thirty_seconds), 1u8, 1i64),
        ("expired lease", "prepared", Some(expired_lease), 0, 1),
        ("no lease row", "prepared", None, 0, 1),
        (
            "superseded generation",
            "prepared",
            Some(thirty_seconds),
            2,
            2,
        ),
        (
            "fence not the lease generation",
            "prepared",
            Some(thirty_seconds),
            0,
            2,
        ),
        (
            "lease claims another attempt",
            "prepared",
            Some(thirty_seconds),
            3,
            1,
        ),
    ] {
        let mut l = seed_linked_run(&mut admin, step_state, ttl).await?;
        match mutate {
            1 => l.lease.credential[0] ^= 0xff,
            2 => l.lease.generation = 2,
            3 => l.attempt = attempt_id_for_step_attempt(StepAttemptId::new())?,
            _ => {}
        }
        let mut a = linked_prepared(&l)?;
        a.fence = Fence {
            generation: fence_gen,
        };
        let err = store.with_lease(l.lease).create(&a).await.expect_err(name);
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{name}: {err}");
        require_no_driver_type(&err);
        assert!(
            stored(&store, &a).await?.is_none(),
            "{name}: refused create wrote the attempt"
        );
    }

    // Save and append refused after the lease expires.
    {
        let l = seed_linked_run(&mut admin, "prepared", Some(thirty_seconds)).await?;
        let bound = store.with_lease(l.lease);
        let a = linked_prepared(&l)?;
        bound.create(&a).await?;
        sqlx::query(
            "UPDATE central.execution_ownership SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE run_id = $1",
        )
        .bind(uuid_of!(l.run))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let launched = a.launch(
            FENCE,
            &l.attempt.to_string(),
            "2.1.0",
            t0() + Duration::seconds(1),
        )?;
        let err = bound
            .save(&a, &launched, &[])
            .await
            .expect_err("expired lease save");
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
        // An unbound store (phase 1b) still writes; the bound one never
        // does.
        let saved = store.save(&a, &launched, &[]).await?;
        let (next, rec) = apply_event(
            &saved,
            &event(
                &saved,
                1,
                EventPayload::SessionStarted(SessionStarted {
                    harness_session_id: "sess-1".to_string(),
                    ..SessionStarted::default()
                }),
            ),
        )?;
        let err = bound
            .append_event(&saved, &next, &rec, &[])
            .await
            .expect_err("expired lease append");
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
        let got = stored(&store, &a).await?.expect("stored");
        assert_eq!(got.last_event_seq, 0, "refused append moved the cursor");
        let events: i64 =
            sqlx::query_scalar("SELECT count(*) FROM central.harness_events WHERE attempt_id = $1")
                .bind(uuid_of!(a.id))
                .fetch_one(&mut admin)
                .await
                .map_err(|e| classify_sqlx(&e))?;
        assert_eq!(events, 0, "refused append left events");
    }
    Ok(())
}

#[tokio::test]
async fn lease_refence_binds_to_the_new_generation() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("refence").await?;
    let l = seed_linked_run(&mut admin, "prepared", Some(Duration::seconds(30))).await?;
    let a = linked_prepared(&l)?;
    store.with_lease(l.lease).create(&a).await?;

    let mut bearer = [0u8; 32];
    bearer.iter_mut().for_each(|b| *b = 0x6b);
    let next = ExecutionLease {
        generation: 2,
        credential: bearer,
    };
    use sha2::{Digest, Sha256};
    let verifier: [u8; 32] = Sha256::digest(bearer).into();
    sqlx::query(
        "UPDATE central.execution_ownership SET fencing_generation = 2, lease_token_hash = $3, lease_expires_at = clock_timestamp() + interval '30 seconds' WHERE workspace_id = $1 AND run_id = $2",
    )
    .bind(uuid_of!(l.ws))
    .bind(uuid_of!(l.run))
    .bind(&verifier[..])
    .execute(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let refenced = a.refence(a.fence, next.fence(), t0() + Duration::seconds(1))?;
    let err = store
        .with_lease(l.lease)
        .save(&a, &refenced, &[])
        .await
        .expect_err("old lease refences the row");
    assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
    let beyond = a.refence(
        a.fence,
        Fence { generation: 3 },
        t0() + Duration::seconds(1),
    )?;
    let err = store
        .with_lease(next)
        .save(&a, &beyond, &[])
        .await
        .expect_err("refenced past the bound lease");
    assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
    let got = store.with_lease(next).save(&a, &refenced, &[]).await?;
    assert_eq!(got.fence.generation, 2);
    assert_eq!(got.state, State::Prepared);
    assert_eq!(got.version, a.version + 1);
    let loaded = stored(&store, &a).await?.expect("stored");
    assert!(loaded.equal(&got));
    Ok(())
}

#[tokio::test]
async fn recover_attempt_requires_a_lease_dead_linked_step_attempt() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("recover_auth").await?;
    let at = t0() + Duration::hours(1);

    #[allow(clippy::expect_used)] // Fixture: a missing row here is a fixture bug.
    async fn create(store: &PgHarnessStore, a: &Attempt) -> Result<Attempt> {
        store.create(a).await?;
        Ok(stored(store, a).await?.expect("stored"))
    }

    // reconciliation -> ambiguous.
    {
        let l = seed_linked_run(&mut admin, "reconciliation", Some(Duration::seconds(-1))).await?;
        let a = create(&store, &linked_running(&l)?).await?;
        let next = a.mark_ambiguous(FENCE, "control plane restarted", at)?;
        // The budget is recorded once, at prepare: a recovery write that
        // carries another budget is refused and writes nothing.
        let mut rebudgeted = next.clone();
        rebudgeted.budget.cost_micro_usd += 1;
        let err = store
            .recover_attempt(&a, &rebudgeted)
            .await
            .expect_err("changed budget");
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
        let loaded = stored(&store, &a).await?.expect("stored");
        assert!(
            loaded.state == a.state && loaded.version == a.version && loaded.budget == a.budget
        );
        let got = store.recover_attempt(&a, &next).await?;
        assert_eq!(got.state, State::Ambiguous);
        assert_eq!(got.version, a.version + 1);

        // The operator's ConfirmFailed leaves the StepAttempt failed;
        // the ambiguous row may then be resolved(abandon), never
        // resolved(resume).
        sqlx::query("UPDATE central.step_attempts SET state = 'failed', version = version + 1 WHERE id = $1")
            .bind(uuid_of!(l.attempt))
            .execute(&mut admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        let resume = got.resolve(
            FENCE,
            Resolution {
                kind: ResolutionKind::Resume,
                decided_by: "operator".to_string(),
            },
            at,
        )?;
        let err = store
            .recover_attempt(&got, &resume)
            .await
            .expect_err("resolved(resume)");
        assert!(is_code(&err, codes::INVALID_TRANSITION), "{err}");
        let abandon = got.resolve(
            FENCE,
            Resolution {
                kind: ResolutionKind::Abandon,
                decided_by: "operator-session".to_string(),
            },
            at,
        )?;
        let resolved = store.recover_attempt(&got, &abandon).await?;
        assert_eq!(resolved.state, State::Resolved);
        assert_eq!(resolved.resolution.kind, ResolutionKind::Abandon);
    }

    // cancelled prepared successor -> failed unlaunched.
    {
        let l = seed_linked_run(&mut admin, "cancelled", Some(Duration::seconds(-6))).await?;
        let a = create(&store, &linked_prepared(&l)?).await?;
        let got = store
            .recover_attempt(&a, &a.fail_unlaunched(FENCE, at)?)
            .await?;
        assert_eq!(got.state, State::Failed);
        assert_eq!(got.terminal.reason, REASON_NOT_LAUNCHED);
        // The run's live-attempt slot is free for the successor's
        // attempt.
        assert!(store.live_attempt_for_run(l.ws, l.run).await?.is_none());
    }

    // settled by receipt -> matching terminal.
    {
        let l = seed_linked_run(&mut admin, "succeeded", None).await?;
        let a = create(&store, &linked_running(&l)?).await?;
        let next = a.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Succeeded,
                reason: String::new(),
                exit_code: None,
            },
            at,
        )?;
        let got = store.recover_attempt(&a, &next).await?;
        assert_eq!(got.state, State::Succeeded);
    }

    // Refusals.
    for (name, step_state, ttl, unlinked) in [
        (
            "prepared under a live lease",
            "prepared",
            Some(Duration::seconds(30)),
            false,
        ),
        (
            "invoked under a live lease",
            "invoked",
            Some(Duration::seconds(30)),
            false,
        ),
        (
            "invoked with an expired lease",
            "invoked",
            Some(Duration::seconds(-1)),
            false,
        ),
        (
            "reconciliation but lease-live",
            "reconciliation",
            Some(Duration::seconds(30)),
            false,
        ),
        (
            "no linked StepAttempt",
            "reconciliation",
            Some(Duration::seconds(-1)),
            true,
        ),
    ] {
        let l = seed_linked_run(&mut admin, step_state, ttl).await?;
        let a = if unlinked {
            running(prepared(l.ws, l.run, PermissionPolicy::Deny)?)?
        } else {
            linked_running(&l)?
        };
        let a = create(&store, &a).await?;
        let err = store
            .recover_attempt(&a, &a.mark_ambiguous(FENCE, "restart", at)?)
            .await
            .expect_err(name);
        assert!(
            is_code(&err, codes::RECOVERY_NOT_AUTHORIZED),
            "{name}: {err}"
        );
        require_no_driver_type(&err);
        let got = stored(&store, &a).await?.expect("stored");
        assert!(
            got.state == a.state && got.version == a.version,
            "{name}: a refused recovery wrote"
        );
    }

    // Recovery never refences or moves the cursor.
    {
        let l = seed_linked_run(&mut admin, "reconciliation", Some(Duration::seconds(-1))).await?;
        let a = create(&store, &linked_running(&l)?).await?;
        let next = a.mark_ambiguous(FENCE, "restart", at)?;
        let mut refenced = next.clone();
        refenced.fence = Fence { generation: 2 };
        let err = store
            .recover_attempt(&a, &refenced)
            .await
            .expect_err("refence");
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
        let mut moved = next.clone();
        moved.last_event_seq = 9;
        let err = store
            .recover_attempt(&a, &moved)
            .await
            .expect_err("cursor move");
        assert!(is_code(&err, codes::INVALID_EVENT), "{err}");
    }
    Ok(())
}

/// `ambiguous` — the launch→running→ambiguous linked attempt, stored.
async fn ambiguous(store: &PgHarnessStore, l: &LinkedRun) -> Result<Attempt> {
    let a = linked_running(l)?.mark_ambiguous(
        FENCE,
        "control plane restarted",
        t0() + Duration::seconds(3),
    )?;
    store.create(&a).await?;
    stored(store, &a)
        .await?
        .ok_or_else(|| Failure::internal("test_assert", "a just-created attempt did not load"))
}

fn resolve(a: &Attempt, kind: ResolutionKind) -> Result<Attempt> {
    a.resolve(
        FENCE,
        Resolution {
            kind,
            decided_by: "operator-session:p".to_string(),
        },
        t0() + Duration::hours(1),
    )
}

#[tokio::test]
async fn recover_attempt_accepts_resume_only_for_a_resumed_step_attempt() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("recover_resume").await?;

    async fn refused(store: &PgHarnessStore, a: &Attempt, next: &Attempt) -> Result<()> {
        let err = store
            .recover_attempt(a, next)
            .await
            .expect_err("refused recovery");
        assert!(is_code(&err, codes::INVALID_TRANSITION), "{err}");
        let got = stored(store, a).await?.expect("stored");
        assert!(
            got.state == a.state && got.version == a.version,
            "a refused recovery wrote"
        );
        Ok(())
    }

    // failed with a successor: resolved(resume) accepted.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        seed_resume_successor(&mut admin, &l).await?;
        let a = ambiguous(&store, &l).await?;
        let got = store
            .recover_attempt(&a, &resolve(&a, ResolutionKind::Resume)?)
            .await?;
        assert_eq!(got.state, State::Resolved);
        assert_eq!(got.resolution.kind, ResolutionKind::Resume);
        assert_eq!(got.version, a.version + 1);
        let loaded = stored(&store, &a).await?.expect("stored");
        assert_eq!(loaded.resolution.kind, ResolutionKind::Resume);
    }
    // failed with a successor: resolved(abandon) still accepted.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        seed_resume_successor(&mut admin, &l).await?;
        let a = ambiguous(&store, &l).await?;
        let got = store
            .recover_attempt(&a, &resolve(&a, ResolutionKind::Abandon)?)
            .await?;
        assert_eq!(got.resolution.kind, ResolutionKind::Abandon);
    }
    // failed without a successor: resolved(resume) refused.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        let a = ambiguous(&store, &l).await?;
        refused(&store, &a, &resolve(&a, ResolutionKind::Resume)?).await?;
    }
    // cancelled with a successor: resolved(resume) refused — a B08
    // successor follows a cancelled predecessor: cancelled is in the
    // accepted linked set, but it is never Resumed.
    {
        let l = seed_linked_run(&mut admin, "cancelled", Some(Duration::seconds(-1))).await?;
        seed_resume_successor(&mut admin, &l).await?;
        let a = ambiguous(&store, &l).await?;
        refused(&store, &a, &resolve(&a, ResolutionKind::Resume)?).await?;
    }
    Ok(())
}

#[tokio::test]
async fn list_recovery_candidates_reports_a_resumed_step_attempt() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("candidates_resumed").await?;
    let resumed = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
    seed_resume_successor(&mut admin, &resumed).await?;
    let plain = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;

    let first =
        linked_prepared(&resumed)?.launch(FENCE, "scope", "2.1.0", t0() + Duration::seconds(1))?;
    let first = first.mark_ambiguous(FENCE, "restart", t0() + Duration::seconds(2))?;
    let mut second = linked_prepared(&plain)?;
    second.prepared_at = t0() + Duration::minutes(1);
    second.updated_at = t0() + Duration::minutes(1);
    let second = second.launch(FENCE, "scope", "2.1.0", t0() + Duration::minutes(2))?;
    let second = second.mark_ambiguous(FENCE, "restart", t0() + Duration::minutes(3))?;
    for a in [&first, &second] {
        store.create(a).await?;
    }
    let page = store
        .list_recovery_candidates(RecoveryCursor::default(), MAX_RECOVERY_CANDIDATES)
        .await?;
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].attempt.id, first.id);
    assert_eq!(page[0].step_state, LinkedStepAttemptState::Resumed);
    assert!(!page[0].lease_live);
    assert_eq!(page[1].attempt.id, second.id);
    assert_eq!(page[1].step_state, LinkedStepAttemptState::Failed);
    Ok(())
}

#[tokio::test]
async fn list_recovery_candidates_pages_non_terminal_attempts_with_linked_state() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("candidates_page").await?;
    let reconciling =
        seed_linked_run(&mut admin, "reconciliation", Some(Duration::seconds(-1))).await?;
    let leased = seed_linked_run(&mut admin, "prepared", Some(Duration::seconds(30))).await?;
    let done = seed_linked_run(&mut admin, "succeeded", None).await?;

    let first = linked_prepared(&reconciling)?.launch(
        FENCE,
        "scope",
        "2.1.0",
        t0() + Duration::seconds(1),
    )?;
    let mut second = linked_prepared(&leased)?;
    second.prepared_at = t0() + Duration::minutes(1);
    second.updated_at = t0() + Duration::minutes(1);
    let terminal = linked_prepared(&done)?.fail_unlaunched(FENCE, t0() + Duration::seconds(1))?;
    for a in [&first, &second, &terminal] {
        store.create(a).await?;
    }
    let page = store
        .list_recovery_candidates(RecoveryCursor::default(), 1)
        .await?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].attempt.id, first.id);
    assert_eq!(page[0].step_state, LinkedStepAttemptState::Reconciliation);
    assert!(!page[0].lease_live);
    let rest = store
        .list_recovery_candidates(
            RecoveryCursor {
                prepared_at: page[0].attempt.prepared_at,
                id: page[0].attempt.id,
            },
            MAX_RECOVERY_CANDIDATES,
        )
        .await?;
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].attempt.id, second.id);
    assert_eq!(rest[0].step_state, LinkedStepAttemptState::Prepared);
    assert!(rest[0].lease_live);
    let err = store
        .list_recovery_candidates(RecoveryCursor::default(), 0)
        .await
        .expect_err("zero limit");
    assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
    // A half-set cursor is invalid.
    let err = store
        .list_recovery_candidates(
            RecoveryCursor {
                prepared_at: t0(),
                id: HarnessAttemptId::from_trusted_db_bytes([0; 16]),
            },
            1,
        )
        .await
        .expect_err("half cursor");
    assert!(is_code(&err, codes::INVALID_ATTEMPT), "{err}");
    Ok(())
}

#[tokio::test]
async fn recover_attempt_accepts_rerun_only_for_a_failed_step_attempt_of_a_retried_run()
-> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("recover_rerun").await?;

    async fn refused(store: &PgHarnessStore, a: &Attempt, want: &str) -> Result<()> {
        let err = store
            .recover_attempt(a, &resolve(a, ResolutionKind::Rerun)?)
            .await
            .expect_err("resolved(rerun)");
        assert!(is_code(&err, want), "{err} want {want}");
        require_no_driver_type(&err);
        let got = stored(store, a).await?.expect("stored");
        assert!(
            got.state == a.state && got.version == a.version,
            "a refused resolved(rerun) wrote"
        );
        Ok(())
    }

    // failed, run retried: accepted.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        let a = ambiguous(&store, &l).await?;
        retry_linked_run(&mut admin, &l).await?;
        let got = store
            .recover_attempt(&a, &resolve(&a, ResolutionKind::Rerun)?)
            .await?;
        assert_eq!(got.state, State::Resolved);
        assert_eq!(got.resolution.kind, ResolutionKind::Rerun);
        assert_eq!(got.version, a.version + 1);
        let loaded = stored(&store, &a).await?.expect("stored");
        assert_eq!(loaded.resolution.kind, ResolutionKind::Rerun);
    }
    // failed, run still current: refused, abandon accepted.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        let a = ambiguous(&store, &l).await?;
        refused(&store, &a, codes::INVALID_TRANSITION).await?;
        let got = store
            .recover_attempt(&a, &resolve(&a, ResolutionKind::Abandon)?)
            .await?;
        assert_eq!(got.resolution.kind, ResolutionKind::Abandon);
    }
    // reconciliation/cancelled/succeeded, run retried: refused.
    for state in ["reconciliation", "cancelled", "succeeded"] {
        let l = seed_linked_run(&mut admin, state, Some(Duration::seconds(-1))).await?;
        let a = ambiguous(&store, &l).await?;
        retry_linked_run(&mut admin, &l).await?;
        refused(&store, &a, codes::INVALID_TRANSITION).await?;
    }
    // resumed, run retried: refused.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        seed_resume_successor(&mut admin, &l).await?;
        let a = ambiguous(&store, &l).await?;
        retry_linked_run(&mut admin, &l).await?;
        refused(&store, &a, codes::INVALID_TRANSITION).await?;
    }
    // failed, run retried, live lease: refused.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(30))).await?;
        let a = ambiguous(&store, &l).await?;
        retry_linked_run(&mut admin, &l).await?;
        refused(&store, &a, codes::RECOVERY_NOT_AUTHORIZED).await?;
    }
    // Task current_run_id NULL after the retry: refused — NULL is read
    // fail-safe as "not replaced".
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        let a = ambiguous(&store, &l).await?;
        retry_linked_run(&mut admin, &l).await?;
        sqlx::query(
            "UPDATE central.tasks SET current_run_id = NULL, version = version + 1 \
             WHERE id = (SELECT task_id FROM central.runs WHERE id = $1)",
        )
        .bind(uuid_of!(l.run))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        refused(&store, &a, codes::INVALID_TRANSITION).await?;
    }
    // failed, run still current, live lease: the rerun rule refuses
    // first.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(30))).await?;
        let a = ambiguous(&store, &l).await?;
        refused(&store, &a, codes::INVALID_TRANSITION).await?;
    }
    // failed, run retried: abandon still accepted.
    {
        let l = seed_linked_run(&mut admin, "failed", Some(Duration::seconds(-1))).await?;
        let a = ambiguous(&store, &l).await?;
        retry_linked_run(&mut admin, &l).await?;
        let got = store
            .recover_attempt(&a, &resolve(&a, ResolutionKind::Abandon)?)
            .await?;
        assert_eq!(got.state, State::Resolved);
        assert_eq!(got.resolution.kind, ResolutionKind::Abandon);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// approval_test.go — the operator gate over a live lease.
// ---------------------------------------------------------------------------

/// `awaiting` — a lease-bound attempt that awaits one bridged request
/// with its approval open.
struct Awaiting {
    l: LinkedRun,
    task: TaskId,
    bound: Box<dyn AttemptStore>,
    attempt: Attempt,
    approval: HarnessPermissionApprovalId,
    mac: InputMac,
}

/// `openAwaiting` drives a linked attempt, under its live lease, to
/// running and then to `awaiting_permission` on `request_id` with the
/// approval opened in the same append_event; `expires_at` is the
/// approval's expiry.
async fn open_awaiting(
    store: &PgHarnessStore,
    admin: &mut PgConnection,
    step_state: &str,
    request_id: &str,
    expires_at: OffsetDateTime,
) -> Result<Awaiting> {
    let l = seed_linked_run(admin, step_state, Some(Duration::seconds(30))).await?;
    let bound = store.with_lease(l.lease);
    let mut a = linked_prepared(&l)?;
    a.permission = PermissionPolicy::Bridge;
    bound.create(&a).await?;
    let launched = bound
        .save(
            &a,
            &a.launch(
                FENCE,
                &l.attempt.to_string(),
                "2.1.0",
                t0() + Duration::seconds(1),
            )?,
            &[],
        )
        .await?;
    let (next, rec) = apply_event(
        &launched,
        &event(
            &launched,
            1,
            EventPayload::SessionStarted(SessionStarted {
                harness_session_id: "sess-1".to_string(),
                ..SessionStarted::default()
            }),
        ),
    )?;
    let running = bound.append_event(&launched, &next, &rec, &[]).await?;
    let mac = input_mac(r#"{"command":"ls"}"#)?;
    let approval = HarnessPermissionApprovalId::new();
    let (next, rec) = apply_event(
        &running,
        &event(
            &running,
            2,
            EventPayload::PermissionRequested(PermissionRequested {
                request_id: request_id.to_string(),
                tool_call_id: "toolu_1".to_string(),
                tool: "Bash".to_string(),
                input: br#"{"command":"ls"}"#.to_vec(),
                ..PermissionRequested::default()
            }),
        ),
    )?;
    let attempt = bound
        .append_event(
            &running,
            &next,
            &rec,
            &[ApprovalOpen {
                id: approval,
                task_id: l.task,
                request_id: request_id.to_string(),
                tool_call_id: "toolu_1".to_string(),
                tool: "Bash".to_string(),
                input_mac: mac,
                input_size: 16,
                expires_at,
            }],
        )
        .await
        .map_err(|e| {
            Failure::internal(
                "test_assert",
                format!("append_event with approval open: {e}"),
            )
        })?;
    Ok(Awaiting {
        task: l.task,
        bound,
        attempt,
        approval,
        mac,
        l,
    })
}

fn decide_req(w: &Awaiting, allow: bool, mac: InputMac) -> DecidePermissionRequest {
    DecidePermissionRequest {
        workspace_id: w.l.ws,
        approval_id: w.approval,
        allow,
        input_mac: mac,
        decided_by: "operator-session:alice".to_string(),
    }
}

async fn approval_state(
    store: &PgHarnessStore,
    ws: WorkspaceId,
    id: HarnessPermissionApprovalId,
) -> Result<PermissionApproval> {
    ApprovalStore::load_approval(store, ws, id).await
}

#[tokio::test]
async fn approval_opens_atomically_with_the_awaiting_write() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("appr_open").await?;
    let w = open_awaiting(
        &store,
        &mut admin,
        "invoked",
        "req-1",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    )
    .await?;
    assert_eq!(w.attempt.state, State::AwaitingPermission);
    assert_eq!(w.attempt.pending_permission, "req-1");
    let got = approval_state(&store, w.l.ws, w.approval).await?;
    assert_eq!(got.state, ApprovalState::Pending);
    assert_eq!(got.attempt_id, w.attempt.id);
    assert_eq!(got.task_id, w.task);
    assert_eq!(got.run_id, w.l.run);
    assert_eq!(got.request_id, "req-1");
    assert_eq!(got.tool_call_id, "toolu_1");
    assert_eq!(got.tool_name, "Bash");
    assert_eq!(got.input_mac, w.mac);
    assert_eq!(got.input_size, 16);
    assert_eq!(got.requested_at, w.attempt.updated_at);
    assert_eq!(got.version, 0);
    let p = store
        .pending_approval_for_run(w.l.ws, w.l.run)
        .await?
        .expect("pending");
    assert_eq!(p.id, w.approval);
    // The event recorded the tool call id and never the input.
    let (tool_call, n): (Option<String>, i64) = sqlx::query_as(
        "SELECT tool_call_id, (SELECT count(*) FROM central.harness_events WHERE attempt_id = $1) \
         FROM central.harness_events WHERE attempt_id = $1 AND seq = 2",
    )
    .bind(uuid_of!(w.attempt.id))
    .fetch_one(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(tool_call.as_deref(), Some("toolu_1"));
    assert_eq!(n, 2);
    Ok(())
}

#[tokio::test]
async fn approval_open_is_refused_unless_the_attempt_starts_awaiting_its_request() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("appr_open_refused").await?;
    let w = open_awaiting(
        &store,
        &mut admin,
        "invoked",
        "req-1",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    )
    .await?;
    let open = |request_id: &str| ApprovalOpen {
        id: HarnessPermissionApprovalId::new(),
        task_id: w.task,
        request_id: request_id.to_string(),
        tool_call_id: String::new(),
        tool: "Bash".to_string(),
        input_mac: w.mac,
        input_size: 0,
        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
    };
    // Still awaiting req-1: a second request's event opens nothing.
    let (next, rec) = apply_event(
        &w.attempt,
        &event(
            &w.attempt,
            3,
            EventPayload::Message(Message {
                role: MessageRole::Assistant,
                text: "x".to_string(),
                ..Message::default()
            }),
        ),
    )?;
    let err = w
        .bound
        .append_event(&w.attempt, &next, &rec, &[open("req-2")])
        .await
        .expect_err("open while already awaiting");
    assert!(is_code(&err, codes::INVALID_APPROVAL), "{err}");
    // Decide and resolve req-1, then open a request that the attempt
    // does not await.
    store
        .decide_permission(decide_req(&w, false, w.mac))
        .await?;
    let (resolved_next, resolved_rec) = apply_event(
        &w.attempt,
        &event(
            &w.attempt,
            3,
            EventPayload::PermissionResolved(PermissionResolved {
                request_id: "req-1".to_string(),
                decision: PermissionOutcome::Denied,
                decided_by: "operator-session:alice".to_string(),
            }),
        ),
    )?;
    let err = w
        .bound
        .append_event(&w.attempt, &resolved_next, &resolved_rec, &[open("req-1")])
        .await
        .expect_err("open on a resolve");
    assert!(is_code(&err, codes::INVALID_APPROVAL), "{err}");
    let running = w
        .bound
        .append_event(&w.attempt, &resolved_next, &resolved_rec, &[])
        .await?;
    let await_next = running.await_permission(FENCE, "req-3", t0() + Duration::hours(1))?;
    for (name, opens) in [
        ("another request id", vec![open("req-4")]),
        ("two opens", vec![open("req-3"), open("req-3")]),
    ] {
        let err = w
            .bound
            .save(&running, &await_next, &opens)
            .await
            .expect_err(name);
        assert!(is_code(&err, codes::INVALID_APPROVAL), "{name}: {err}");
    }
    let cur = stored(&store, &running).await?.expect("stored");
    assert!(
        cur.state == State::Running && cur.version == running.version,
        "a refused open wrote"
    );
    // Promotion: a save that enters awaiting with a new request opens
    // it.
    let promoted = open("req-3");
    w.bound
        .save(&running, &await_next, std::slice::from_ref(&promoted))
        .await?;
    let got = approval_state(&store, w.l.ws, promoted.id).await?;
    assert!(got.state == ApprovalState::Pending && got.request_id == "req-3");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM central.harness_permission_approvals WHERE attempt_id = $1",
    )
    .bind(uuid_of!(w.attempt.id))
    .fetch_one(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(count, 2, "want the first and the promoted one");
    Ok(())
}

#[tokio::test]
async fn approval_open_is_refused_for_another_task() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("appr_other_task").await?;
    let l = seed_linked_run(&mut admin, "invoked", Some(Duration::seconds(30))).await?;
    let other_run = seed_run(&mut admin, l.ws).await?;
    let other_task = task_of(&mut admin, other_run).await?;
    let bound = store.with_lease(l.lease);
    let mut a = linked_prepared(&l)?;
    a.permission = PermissionPolicy::Bridge;
    bound.create(&a).await?;
    let launched = bound
        .save(
            &a,
            &a.launch(
                FENCE,
                &l.attempt.to_string(),
                "2.1.0",
                t0() + Duration::seconds(1),
            )?,
            &[],
        )
        .await?;
    let (next, rec) = apply_event(
        &launched,
        &event(
            &launched,
            1,
            EventPayload::SessionStarted(SessionStarted {
                harness_session_id: "sess-1".to_string(),
                ..SessionStarted::default()
            }),
        ),
    )?;
    let running = bound.append_event(&launched, &next, &rec, &[]).await?;
    let mac = input_mac(r#"{"command":"ls"}"#)?;
    let (next, rec) = apply_event(
        &running,
        &event(
            &running,
            2,
            EventPayload::PermissionRequested(PermissionRequested {
                request_id: "req-1".to_string(),
                tool_call_id: "toolu_1".to_string(),
                tool: "Bash".to_string(),
                input: br#"{"command":"ls"}"#.to_vec(),
                ..PermissionRequested::default()
            }),
        ),
    )?;
    for (name, task) in [
        ("another task of the workspace", other_task),
        ("an unknown task", TaskId::new()),
    ] {
        let err = bound
            .append_event(
                &running,
                &next,
                &rec,
                &[ApprovalOpen {
                    id: HarnessPermissionApprovalId::new(),
                    task_id: task,
                    request_id: "req-1".to_string(),
                    tool_call_id: "toolu_1".to_string(),
                    tool: "Bash".to_string(),
                    input_mac: mac,
                    input_size: 16,
                    expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
                }],
            )
            .await
            .expect_err(name);
        assert!(is_code(&err, codes::INVALID_APPROVAL), "{name}: {err}");
    }
    let cur = stored(&store, &running).await?.expect("stored");
    assert!(cur.state == State::Running && cur.version == running.version);
    let (approvals, events): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM central.harness_permission_approvals WHERE attempt_id = $1), \
                (SELECT count(*) FROM central.harness_events WHERE attempt_id = $1 AND seq = 2)",
    )
    .bind(uuid_of!(running.id))
    .fetch_one(&mut admin)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert!(approvals == 0 && events == 0, "after the refused opens");
    // The run's own task opens it.
    bound
        .append_event(
            &running,
            &next,
            &rec,
            &[ApprovalOpen {
                id: HarnessPermissionApprovalId::new(),
                task_id: l.task,
                request_id: "req-1".to_string(),
                tool_call_id: "toolu_1".to_string(),
                tool: "Bash".to_string(),
                input_mac: mac,
                input_size: 16,
                expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
            }],
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn decide_permission_is_a_compare_and_set_under_a_live_lease() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("decide").await?;
    let in_ten = OffsetDateTime::now_utc() + Duration::minutes(10);

    // Allow wins once.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_ten).await?;
        let got = store.decide_permission(decide_req(&w, true, w.mac)).await?;
        assert_eq!(got.state, ApprovalState::Allowed);
        assert_eq!(got.decided_by, "operator-session:alice");
        assert_eq!(got.version, 1);
        assert!(got.decided_at.is_some());
        for allow in [true, false] {
            let err = store
                .decide_permission(decide_req(&w, allow, w.mac))
                .await
                .expect_err("second decision");
            assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{err}");
        }
    }

    // Refusals write nothing.
    for name in [
        "another input MAC",
        "another workspace",
        "an unknown approval",
    ] {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_ten).await?;
        let mut req = decide_req(&w, true, w.mac);
        match name {
            "another input MAC" => req.input_mac = input_mac(r#"{"command":"rm -rf /"}"#)?,
            "another workspace" => req.workspace_id = WorkspaceId::new(),
            _ => req.approval_id = HarnessPermissionApprovalId::new(),
        }
        let err = store.decide_permission(req).await.expect_err(name);
        assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{name}: {err}");
        let got = approval_state(&store, w.l.ws, w.approval).await?;
        assert!(
            got.state == ApprovalState::Pending && got.version == 0,
            "{name}: approval wrote"
        );
    }
    // Invalid requests: a policy decider, no MAC.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_ten).await?;
        for (name, req) in [
            (
                "a policy decider",
                DecidePermissionRequest {
                    workspace_id: w.l.ws,
                    approval_id: w.approval,
                    allow: true,
                    input_mac: w.mac,
                    decided_by: DECIDED_BY_TIMEOUT.to_string(),
                },
            ),
            (
                "no MAC",
                DecidePermissionRequest {
                    workspace_id: w.l.ws,
                    approval_id: w.approval,
                    allow: true,
                    input_mac: InputMac::ZERO,
                    decided_by: "operator-session:alice".to_string(),
                },
            ),
        ] {
            let err = store.decide_permission(req).await.expect_err(name);
            assert!(is_code(&err, codes::INVALID_APPROVAL), "{name}: {err}");
        }
    }

    // No live lease claims the run.
    for (name, edit) in [
        (
            "expired lease",
            "UPDATE central.execution_ownership SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE run_id = $1",
        ),
        (
            "reclaimed lease",
            "UPDATE central.execution_ownership SET fencing_generation = 2 WHERE run_id = $1",
        ),
    ] {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_ten).await?;
        sqlx::query(edit)
            .bind(uuid_of!(w.l.run))
            .execute(&mut admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        let err = store
            .decide_permission(decide_req(&w, true, w.mac))
            .await
            .expect_err(name);
        assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{name}: {err}");
        let got = approval_state(&store, w.l.ws, w.approval).await?;
        assert_eq!(got.state, ApprovalState::Pending);
    }

    // An expired approval.
    {
        let w = open_awaiting(
            &store,
            &mut admin,
            "invoked",
            "req-1",
            OffsetDateTime::now_utc() - Duration::seconds(1),
        )
        .await?;
        let err = store
            .decide_permission(decide_req(&w, true, w.mac))
            .await
            .expect_err("expired");
        assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{err}");
    }
    Ok(())
}

#[tokio::test]
async fn operator_and_timeout_race_has_exactly_one_winner() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("appr_race").await?;
    for round in 0..8 {
        let due = OffsetDateTime::now_utc() + Duration::milliseconds(150);
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", due).await?;
        // The operator's decision runs on its own pool, as a web request
        // does beside the orchestrator; the timeout's expiry loops on
        // the bound store.
        let operator = store.clone();
        let req = decide_req(&w, true, w.mac);
        // Upstream holds the operator's decision back until ~2ms before
        // expiry so the timeout branch is a real coin flip.
        let decide = async move {
            while OffsetDateTime::now_utc() < due - Duration::milliseconds(2) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            operator.decide_permission(req).await
        };
        let expire = async {
            loop {
                match w.bound.expire_permission(&w.attempt, w.approval).await {
                    Ok(a) if a.state == ApprovalState::Pending => {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                    other => break other,
                }
            }
        };
        let (decided, expired) = tokio::join!(decide, expire);
        let expired = expired?;
        let final_ = approval_state(&store, w.l.ws, w.approval).await?;
        match final_.state {
            ApprovalState::Allowed => {
                let decided = decided.map_err(|e| {
                    Failure::internal(
                        "test_assert",
                        format!("round {round}: operator won but decide failed: {e}"),
                    )
                })?;
                assert!(
                    decided.state == ApprovalState::Allowed
                        && expired.state == ApprovalState::Allowed
                );
            }
            ApprovalState::Expired => {
                let err = decided.expect_err("operator must lose when the timeout won");
                assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{err}");
                assert_eq!(expired.state, ApprovalState::Expired);
                assert_eq!(final_.decided_by, DECIDED_BY_TIMEOUT);
            }
            other => {
                return Err(Failure::internal(
                    "test_assert",
                    format!("round {round}: final state {other:?}"),
                ));
            }
        }
        assert_eq!(
            final_.version, 1,
            "round {round}: approval written {} times",
            final_.version
        );
    }
    Ok(())
}

#[tokio::test]
async fn expire_permission_is_fenced_and_answers_with_the_final_state() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("expire").await?;
    let in_ten = OffsetDateTime::now_utc() + Duration::minutes(10);
    let due_past = OffsetDateTime::now_utc() - Duration::seconds(1);

    // Not due yet.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_ten).await?;
        let got = w.bound.expire_permission(&w.attempt, w.approval).await?;
        assert!(got.state == ApprovalState::Pending && got.version == 0);
    }
    // Due.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", due_past).await?;
        let got = w.bound.expire_permission(&w.attempt, w.approval).await?;
        assert!(
            got.state == ApprovalState::Expired
                && got.decided_by == DECIDED_BY_TIMEOUT
                && !got.state.allows()
        );
    }
    // Decided first.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_ten).await?;
        store
            .decide_permission(decide_req(&w, false, w.mac))
            .await?;
        let got = w.bound.expire_permission(&w.attempt, w.approval).await?;
        assert!(got.state == ApprovalState::Denied && got.decided_by == "operator-session:alice");
    }
    // Fence refusals.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", due_past).await?;
        let mut stale = w.attempt.clone();
        stale.fence = Fence { generation: 2 };
        let err = w
            .bound
            .expire_permission(&stale, w.approval)
            .await
            .expect_err("stale fence");
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
        let mut wrong_bearer = w.l.lease;
        wrong_bearer.credential[0] ^= 0xff;
        let err = store
            .with_lease(wrong_bearer)
            .expire_permission(&w.attempt, w.approval)
            .await
            .expect_err("wrong bearer");
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
        sqlx::query(
            "UPDATE central.execution_ownership SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE run_id = $1",
        )
        .bind(uuid_of!(w.l.run))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let err = w
            .bound
            .expire_permission(&w.attempt, w.approval)
            .await
            .expect_err("expired lease");
        assert!(is_code(&err, codes::FENCE_MISMATCH), "{err}");
        let got = approval_state(&store, w.l.ws, w.approval).await?;
        assert_eq!(got.state, ApprovalState::Pending);
        let other = open_awaiting(&store, &mut admin, "invoked", "req-1", due_past).await?;
        let err = other
            .bound
            .expire_permission(&other.attempt, w.approval)
            .await
            .expect_err("another attempt's approval");
        assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{err}");
    }
    Ok(())
}

#[tokio::test]
async fn terminal_and_ambiguous_writes_supersede_in_the_same_transaction() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("supersede").await?;
    let at = t0() + Duration::hours(1);
    let in_hour = OffsetDateTime::now_utc() + Duration::hours(1);

    async fn superseded(store: &PgHarnessStore, w: &Awaiting) -> Result<()> {
        let got = approval_state(store, w.l.ws, w.approval).await?;
        assert_eq!(got.state, ApprovalState::Superseded, "approval = {got:?}");
        assert_eq!(got.decided_by, DECIDED_BY_SUPERSEDED);
        assert!(got.decided_at >= Some(got.requested_at));
        assert!(
            store
                .pending_approval_for_run(w.l.ws, w.l.run)
                .await?
                .is_none()
        );
        Ok(())
    }
    // makeRecoverable moves the linked StepAttempt to reconciliation
    // with no live lease, as B08 recovery leaves it.
    async fn make_recoverable(admin: &mut PgConnection, w: &Awaiting) -> Result<()> {
        sqlx::query("UPDATE central.step_attempts SET state = 'reconciliation', version = version + 1 WHERE id = $1")
            .bind(uuid_of!(w.l.attempt))
            .execute(&mut *admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        sqlx::query("UPDATE central.execution_ownership SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE run_id = $1")
            .bind(uuid_of!(w.l.run))
            .execute(&mut *admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        Ok(())
    }

    // Save terminal.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
        let mut stale = w.attempt.clone();
        stale.version -= 1;
        let err = w
            .bound
            .save(
                &stale,
                &stale.terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Failed,
                        reason: "permission_bridge_unavailable".to_string(),
                        exit_code: None,
                    },
                    at,
                )?,
                &[],
            )
            .await
            .expect_err("stale save");
        assert!(is_code(&err, codes::VERSION_CONFLICT), "{err}");
        let got = approval_state(&store, w.l.ws, w.approval).await?;
        assert_eq!(
            got.state,
            ApprovalState::Pending,
            "a failed write superseded"
        );
        w.bound
            .save(
                &w.attempt,
                &w.attempt.terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Failed,
                        reason: "permission_bridge_unavailable".to_string(),
                        exit_code: None,
                    },
                    at,
                )?,
                &[],
            )
            .await?;
        superseded(&store, &w).await?;
    }
    // AppendEvent terminal.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
        let (next, rec) = apply_event(
            &w.attempt,
            &event(
                &w.attempt,
                3,
                EventPayload::TerminalReported(TerminalReported {
                    terminal: Terminal {
                        status: TerminalStatus::Interrupted,
                        reason: "harness_aborted".to_string(),
                        exit_code: None,
                    },
                }),
            ),
        )?;
        w.bound.append_event(&w.attempt, &next, &rec, &[]).await?;
        superseded(&store, &w).await?;
    }
    // RecoverAttempt ambiguous, then the resolver.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
        make_recoverable(&mut admin, &w).await?;
        let amb = store
            .recover_attempt(
                &w.attempt,
                &w.attempt
                    .mark_ambiguous(FENCE, "control_plane_restart", at)?,
            )
            .await?;
        superseded(&store, &w).await?;
        store
            .recover_attempt(
                &amb,
                &amb.resolve(
                    FENCE,
                    Resolution {
                        kind: ResolutionKind::Abandon,
                        decided_by: "operator-session:alice".to_string(),
                    },
                    at,
                )?,
            )
            .await?;
        let got = approval_state(&store, w.l.ws, w.approval).await?;
        assert!(
            got.state == ApprovalState::Superseded && got.version == 1,
            "the resolver rewrote a closed approval"
        );
    }
    // RecoverAttempt terminate.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
        make_recoverable(&mut admin, &w).await?;
        sqlx::query("UPDATE central.step_attempts SET state = 'failed', version = version + 1 WHERE id = $1")
            .bind(uuid_of!(w.l.attempt))
            .execute(&mut admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        store
            .recover_attempt(
                &w.attempt,
                &w.attempt.terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Failed,
                        reason: "recovered_settlement".to_string(),
                        exit_code: None,
                    },
                    at,
                )?,
            )
            .await?;
        superseded(&store, &w).await?;
    }
    // A decided approval is never superseded.
    {
        let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
        store.decide_permission(decide_req(&w, true, w.mac)).await?;
        w.bound
            .save(
                &w.attempt,
                &w.attempt.terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Killed,
                        reason: String::new(),
                        exit_code: None,
                    },
                    at,
                )?,
                &[],
            )
            .await?;
        let got = approval_state(&store, w.l.ws, w.approval).await?;
        assert_eq!(got.state, ApprovalState::Allowed);
    }
    Ok(())
}

#[tokio::test]
async fn approval_reads_are_scoped_to_the_workspace() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("appr_scope").await?;
    let in_hour = OffsetDateTime::now_utc() + Duration::hours(1);
    let first = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
    let second = open_awaiting(&store, &mut admin, "invoked", "req-9", in_hour).await?;

    let summary = store.pending_approvals(first.l.ws).await?;
    assert!(
        summary.count == 1 && summary.oldest_task_id == Some(first.task),
        "summary = {summary:?}"
    );
    // Two pending approvals in one workspace: the oldest one's task
    // wins. (The FK to the attempt's workspace stops the move.)
    let moved = sqlx::query(
        "UPDATE central.harness_permission_approvals SET workspace_id = $1 WHERE id = $2",
    )
    .bind(uuid_of!(first.l.ws))
    .bind(uuid_of!(second.approval))
    .execute(&mut admin)
    .await;
    assert!(
        moved.is_err(),
        "an approval moved to another workspace than its attempt"
    );
    let stranger = WorkspaceId::new();
    let summary = store.pending_approvals(stranger).await?;
    assert!(
        summary.count == 0 && summary.oldest_task_id.is_none(),
        "stranger summary = {summary:?}"
    );
    let err = ApprovalStore::load_approval(&store, stranger, first.approval)
        .await
        .expect_err("across workspaces");
    assert!(is_code(&err, codes::NO_PENDING_APPROVAL), "{err}");
    assert!(
        store
            .pending_approval_for_run(stranger, first.l.run)
            .await?
            .is_none()
    );
    assert!(
        store
            .approval_history(second.l.ws, first.l.run, MAX_APPROVAL_HISTORY)
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn approval_history_is_newest_first_and_bounded() -> Result<()> {
    skip!();
    let (store, mut admin) = harness_setup("appr_history").await?;
    let in_hour = OffsetDateTime::now_utc() + Duration::hours(1);
    let w = open_awaiting(&store, &mut admin, "invoked", "req-1", in_hour).await?;
    store
        .decide_permission(decide_req(&w, false, w.mac))
        .await?;
    let (next, rec) = apply_event(
        &w.attempt,
        &event(
            &w.attempt,
            3,
            EventPayload::PermissionResolved(PermissionResolved {
                request_id: "req-1".to_string(),
                decision: PermissionOutcome::Denied,
                decided_by: "operator-session:alice".to_string(),
            }),
        ),
    )?;
    let running = w.bound.append_event(&w.attempt, &next, &rec, &[]).await?;
    let second = ApprovalOpen {
        id: HarnessPermissionApprovalId::new(),
        task_id: w.task,
        request_id: "req-2".to_string(),
        tool_call_id: String::new(),
        tool: "Write".to_string(),
        input_mac: w.mac,
        input_size: 3,
        expires_at: in_hour,
    };
    w.bound
        .save(
            &running,
            &running.await_permission(FENCE, "req-2", t0() + Duration::hours(2))?,
            std::slice::from_ref(&second),
        )
        .await?;
    let history = store
        .approval_history(w.l.ws, w.l.run, MAX_APPROVAL_HISTORY)
        .await?;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].id, second.id);
    assert_eq!(history[1].id, w.approval);
    assert_eq!(history[0].state, ApprovalState::Pending);
    assert_eq!(history[1].state, ApprovalState::Denied);
    let one = store.approval_history(w.l.ws, w.l.run, 1).await?;
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].id, second.id);
    for limit in [0usize, MAX_APPROVAL_HISTORY + 1] {
        let err = store
            .approval_history(w.l.ws, w.l.run, limit)
            .await
            .expect_err("bad limit");
        assert!(is_code(&err, codes::INVALID_APPROVAL), "{err}");
    }
    Ok(())
}
