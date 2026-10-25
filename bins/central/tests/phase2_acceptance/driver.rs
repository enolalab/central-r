//! The `matrixGraph` fixture — one scenario's composed real PostgreSQL
//! stores plus the deterministic injection seams (stub clock, scripted
//! digester/killer/launcher/provisioner). Port of upstream
//! `phase2_acceptance_test.go`'s `matrixGraph`: no concurrent runtime
//! loop — scenarios call store/service methods directly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use central_adapter_postgres::checkpoint::Store as PgCheckpointStore;
use central_adapter_postgres::eventjournal::Store as PgJournalStore;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::runview::Store as PgRunviewStore;
use central_adapter_postgres::scheduler::PgSchedulerStore;
use central_adapter_postgres::workflow::Store as PgWorkflowStore;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ArtifactId, NodeLeaseId, RunId, SessionAttemptId, TaskId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_retry::port::{Outcome, Store as RetryStore, SweepSummary};
use central_runview::port::Reader as RunviewReader;
use central_scheduler::app::dispatch::Dispatcher;
use central_scheduler::domain::{AttemptState, ClaimedAttempt, Worker, WorkerState};
use central_scheduler::port::{
    LaunchSpec, LaunchVerdict, NodeLauncher, Provisioner, Store as SchedStore,
};
use central_workflow::domain::{
    CHILD_SPEC_VERSION, ChildSpec, ChildSpecNode, EmitResult, NodeStatus,
};
use central_workflow::port::WorkflowStore;
use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions, PgConnection, PgPool};
use time::{Duration, OffsetDateTime};

pub type Result<T> = std::result::Result<T, Failure>;

/// Worker heartbeat cadence the spec-2 missed-beat ladder hangs off.
pub const HEARTBEAT: Duration = Duration::seconds(15);

fn fail(msg: impl Into<String>) -> Failure {
    Failure::new(FailureKind::Internal, "MATRIX_DRIVER", msg.into())
}

// ---------------------------------------------------------------------------
// Deterministic injection seams (ports of internal/phase2accept)
// ---------------------------------------------------------------------------

/// Upstream `ManualClock` — a mutex-held UTC instant every injected clock
/// trait delegates to.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<OffsetDateTime>,
}

impl ManualClock {
    pub fn new(now: OffsetDateTime) -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(now),
        })
    }
    pub fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap()
    }
    fn at(&self) -> OffsetDateTime {
        self.now()
    }
}

impl central_retry::port::Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        self.at()
    }
}
impl central_scheduler::port::Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        self.at()
    }
}
impl central_checkpoint::port::Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        self.at()
    }
}

/// Upstream `ScriptedDigester` — a default digest plus per-path overrides
/// so a scenario can mutate "workspace contents" between checkpoint and
/// preflight (RTM-09's mismatch path).
#[derive(Debug)]
pub struct ScriptedDigester {
    default: String,
    overrides: Mutex<HashMap<String, String>>,
}

impl ScriptedDigester {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            default: "sha256:matrix".to_string(),
            overrides: Mutex::new(HashMap::new()),
        })
    }
    pub fn set(&self, path: &str, digest: &str) {
        self.overrides
            .lock()
            .unwrap()
            .insert(path.to_string(), digest.to_string());
    }
}

impl central_checkpoint::port::Digester for ScriptedDigester {
    fn digest<'a>(
        &'a self,
        path: &'a str,
        _kind: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        let value = self
            .overrides
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or_else(|| self.default.clone());
        Box::pin(async move { Ok(value) })
    }
}

/// Upstream `ScriptedKiller` — per-attempt confirmed/unconfirmed scripts;
/// fails closed (unconfirmed) for unscripted attempts and records calls.
#[derive(Debug, Default)]
pub struct ScriptedKiller {
    scripts: Mutex<HashMap<SessionAttemptId, Result<bool>>>,
    pub calls: Mutex<Vec<SessionAttemptId>>,
}

impl ScriptedKiller {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn script(&self, attempt: SessionAttemptId, confirmed: bool) {
        self.scripts.lock().unwrap().insert(attempt, Ok(confirmed));
    }
}

impl central_retry::port::Killer for ScriptedKiller {
    async fn kill(&self, attempt_id: SessionAttemptId) -> Result<bool> {
        self.calls.lock().unwrap().push(attempt_id);
        match self.scripts.lock().unwrap().get(&attempt_id).cloned() {
            Some(verdict) => verdict,
            // Fail closed the way upstream's scripted killer does: an
            // unscripted kill is an ERROR, never a silent unconfirmed —
            // a silent `Ok(false)` would let a scenario park ambiguity it
            // never intended (upstream `scriptedKiller` returns an error).
            None => Err(fail(format!(
                "scripted killer: no kill outcome scripted for attempt {attempt_id}"
            ))),
        }
    }
}

/// Upstream `ScriptedLauncher` — per-attempt `LaunchVerdict` scripts;
/// fails closed with a definite refusal when unscripted (nothing ran).
#[derive(Debug, Default)]
pub struct ScriptedLauncher {
    scripts: Mutex<HashMap<SessionAttemptId, LaunchVerdict>>,
}

impl ScriptedLauncher {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn script(&self, attempt: SessionAttemptId, verdict: LaunchVerdict) {
        self.scripts.lock().unwrap().insert(attempt, verdict);
    }
}

impl NodeLauncher for ScriptedLauncher {
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
        let attempt = spec.attempt.attempt.id;
        self.scripts
            .lock()
            .unwrap()
            .get(&attempt)
            .cloned()
            .unwrap_or_else(|| {
                // Upstream's scripted launcher returns an ERROR for an
                // unscripted attempt — the dispatch aborts without a
                // durable effect. A `Refused` verdict here would commit a
                // durable `attempt_failed` the scenario never scripted,
                // so the seam panics (the matrix's panic-safe driver
                // records the scenario failed, like upstream's t.Fatalf).
                panic!("scripted launcher: no launch script for attempt {attempt}")
            })
    }
}

/// Deterministic provisioner — hands each attempt a stable path under a
/// scratch root; `free` is a no-op (paths are virtual).
#[derive(Debug, Default)]
pub struct ScriptProvisioner;

impl Provisioner for ScriptProvisioner {
    async fn provision(
        &self,
        _run_id: RunId,
        _node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        _kind: &str,
        _base_ref: &str,
    ) -> Result<String> {
        Ok(format!("/rtm/scratch/{attempt_id}"))
    }
    fn free(&self, _path: &str) -> Result<()> {
        Ok(())
    }
}

/// Upstream's scripted compensation executor — counts managed-hook
/// executions so RTM-13 asserts run-once/replay-deduped/unmanaged-off
/// (`sched.compensation` seam).
#[derive(Debug, Default)]
pub struct ScriptedCompensation {
    pub calls: Mutex<u32>,
}

impl central_retry::port::CompensationExecutor for ScriptedCompensation {
    async fn cleanup_workspace(&self, _node: WorkflowNodeId) -> Result<()> {
        *self.calls.lock().unwrap() += 1;
        Ok(())
    }
    async fn retain_artifacts(&self, _node: WorkflowNodeId) -> Result<()> {
        *self.calls.lock().unwrap() += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MatrixGraph — one scenario's composed runtime
// ---------------------------------------------------------------------------

/// One scenario's composed real stores + injected seams. Mirrors upstream
/// `matrixGraph`: sequential driver, real PostgreSQL, fakes at the seams.
pub struct Matrix {
    pub db: String,
    pub admin: PgConnection,
    pub pool: PgPool,
    pub sched: Arc<PgSchedulerStore>,
    pub wf: PgWorkflowStore,
    pub ck: PgCheckpointStore,
    pub journal: PgJournalStore,
    /// The read-projection store (`runview.Reader`): attempt rows, run
    /// summaries, outbox health, deferred admissions, checkpoints.
    pub views: PgRunviewStore,
    pub clock: Arc<ManualClock>,
    pub digester: Arc<ScriptedDigester>,
    pub killer: Arc<ScriptedKiller>,
    pub launcher: Arc<ScriptedLauncher>,
    pub provisioner: Arc<ScriptProvisioner>,
    /// The managed `on_terminal_failure` executor seam (RTM-13).
    pub compensation: Arc<ScriptedCompensation>,
    /// Artifact ids the emit-time `input_artifact_refs` checker treats as
    /// finalized — populated by `finalize_artifact`.
    pub finalized: Arc<Mutex<HashSet<ArtifactId>>>,
    /// Reason codes the scenario body actually asserted — drained into
    /// the evidence record (`recordScenario` parity).
    pub asserted_reasons: BTreeSet<String>,
    /// Event kinds the scenario body actually asserted.
    pub asserted_kinds: BTreeSet<String>,
    /// Every scenario run id the matrix recorded — RTM-18's global
    /// undeclared-kinds cross-check reads it (upstream `manifest.runs`).
    pub recorded_runs: Vec<RunId>,
    /// The run ids spawned inside this database for cross-run legs
    /// (RTM-14's foreign run, RTM-18's probe) — untracked, like
    /// upstream's unrecorded probe graphs.
    pub probe_runs: Vec<RunId>,
    /// The artifact read seam's body map — `ready_key → bytes`; upstream
    /// `matrixReadBackend.bodies` parity.
    pub bodies: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub ws: WorkspaceId,
    pub task: TaskId,
    pub run: RunId,
}

/// A second `(ws, task, run)` graph seeded inside the same scenario
/// database — upstream `setupGraph` on the shared connection (the
/// foreign-run probes RTM-14/RTM-18 need same-DB scope separation).
pub struct ProbeGraph {
    pub ws: WorkspaceId,
    pub task: TaskId,
    pub run: RunId,
}

pub fn admin_opts() -> Option<PgConnectOptions> {
    let dsn = std::env::var("CENTRAL_TEST_DSN").ok()?;
    PgConnectOptions::from_str(&dsn).ok()
}

/// Upstream `requirePG` — the gate fails closed, never skips: an absent
/// or unparseable `CENTRAL_TEST_DSN` panics the whole test binary like
/// upstream's `t.Fatal`.
pub fn require_opts() -> PgConnectOptions {
    admin_opts().expect(
        "CENTRAL_TEST_DSN is unset or unparsable; the phase-2 acceptance gate fails \
         closed, never skips",
    )
}

/// Fail-closed admin connection for the suite-level pass (stale-DB
/// sweep + host_profile's `SHOW server_version`).
pub async fn admin_conn() -> Result<PgConnection> {
    require_opts()
        .connect()
        .await
        .map_err(|e| fail(format!("admin connect: {e}")))
}

/// Suite-start hygiene: drop any `rtm_*` databases a crashed/panicked
/// prior run leaked (upstream relies on the shared DB + teardown; the
/// per-scenario database isolation needs the explicit sweep).
pub async fn drop_stale_scenario_dbs(admin: &mut PgConnection) -> Result<()> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT datname FROM pg_database WHERE datname LIKE 'rtm\\_%' ESCAPE '\\'",
    )
    .fetch_all(&mut *admin)
    .await
    .map_err(|e| fail(e.to_string()))?;
    for name in names {
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&mut *admin)
            .await;
    }
    Ok(())
}

async fn role_conn(db: &str, role: &str) -> Result<PgConnection> {
    let opts = require_opts().database(db).username(role).password(role);
    opts.connect()
        .await
        .map_err(|e| fail(format!("connect {role}@{db}: {e}")))
}

async fn role_pool(db: &str, role: &str) -> Result<PgPool> {
    let opts = require_opts().database(db).username(role).password(role);
    PgPool::connect_with(opts)
        .await
        .map_err(|e| fail(format!("pool {role}@{db}: {e}")))
}

impl Matrix {
    /// `setupGraph` — a fresh baseline-installed database, fixture
    /// workspace/task/run, and every store composed with the seams.
    /// Panic-safe teardown: any failure between `CREATE DATABASE` and the
    /// composed matrix drops the scenario database before propagating.
    pub async fn setup(label: &str) -> Result<Self> {
        let mut admin = admin_conn().await?;
        let db = format!(
            "rtm_{}_{}_{}",
            label.replace('-', "_"),
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000
        );
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
            .execute(&mut admin)
            .await
            .map_err(|e| fail(e.to_string()))?;
        sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
            .execute(&mut admin)
            .await
            .map_err(|e| fail(e.to_string()))?;
        match Self::setup_inside(&db).await {
            Ok(matrix) => Ok(matrix),
            Err(err) => {
                // The setup failed after CREATE DATABASE — drop the
                // half-built scenario DB so a failure cannot leak it.
                let mut admin = admin_conn().await?;
                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
                    .execute(&mut admin)
                    .await;
                Err(err)
            }
        }
    }

    async fn setup_inside(db: &str) -> Result<Self> {
        let mut mig = role_conn(db, "central_migration").await?;
        BaselineInstaller::new()
            .install(&mut mig)
            .await
            .map_err(|e| fail(format!("baseline: {e}")))?;

        let pool = role_pool(db, "central_runtime").await?;
        let finalized: Arc<Mutex<HashSet<ArtifactId>>> = Arc::new(Mutex::new(HashSet::new()));
        let finalized_check = finalized.clone();
        let clock = ManualClock::new(OffsetDateTime::now_utc());
        let digester = ScriptedDigester::new();
        let killer = ScriptedKiller::new();
        let launcher = ScriptedLauncher::new();
        let compensation = Arc::new(ScriptedCompensation::default());

        let mut sched = PgSchedulerStore::new(pool.clone(), vec!["claude-code".to_string()]);
        sched.clock = Some(clock.clone());
        sched.killer = Some(killer.clone());
        sched.compensation = Some(compensation.clone());
        // Upstream pins `Jitter = func() float64 { return 0 }` — the
        // zero draw zeroes the jittered component of every computed
        // backoff, so journaled `retry_at`/`not_before` values are
        // reproducible (hint-honored paths stay exact).
        sched.jitter = Some(Arc::new(|| 0.0_f64));
        let sched = Arc::new(sched);
        let ck = PgCheckpointStore::with_digester(pool.clone(), digester.clone());
        let mut wf = PgWorkflowStore::new(pool.clone());
        wf.harness_registry = Some(Arc::new(|name: &str| name == "claude-code"));
        wf.artifact_finalized = Some(Arc::new(move |id: ArtifactId, _checksum: &str| {
            finalized_check.lock().unwrap().contains(&id)
        }));

        let ws = WorkspaceId::new();
        let task = TaskId::new();
        let run = RunId::new();
        for q in [
            "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
             VALUES ($1, 'active', 'rtm', 1099511627776)",
            "INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)",
        ] {
            sqlx::query(q)
                .bind(uuid_of!(ws))
                .execute(&mut mig)
                .await
                .map_err(|e| fail(e.to_string()))?;
        }
        sqlx::query(
            "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
             last_run_index, title, input_spec) \
             VALUES ($1, $2, 1, 'running', $3, 1, 'rtm', '{}'::jsonb)",
        )
        .bind(uuid_of!(task))
        .bind(uuid_of!(ws))
        .bind(uuid_of!(run))
        .execute(&mut mig)
        .await
        .map_err(|e| fail(e.to_string()))?;
        sqlx::query(
            "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
             VALUES ($1, $2, $3, 1, 'running', 1)",
        )
        .bind(uuid_of!(run))
        .bind(uuid_of!(ws))
        .bind(uuid_of!(task))
        .execute(&mut mig)
        .await
        .map_err(|e| fail(e.to_string()))?;

        // `admin` is the scenario-DB inspection connection every SQL
        // assertion rides on — NOT the postgres-DB conn teardown uses.
        let admin = role_conn(db, "central_migration").await?;
        Ok(Self {
            db: db.to_string(),
            admin,
            pool: pool.clone(),
            sched,
            wf,
            ck,
            journal: PgJournalStore::new(pool.clone()),
            views: PgRunviewStore::new(pool),
            clock,
            digester,
            killer,
            launcher,
            provisioner: Arc::new(ScriptProvisioner),
            compensation,
            finalized,
            asserted_reasons: BTreeSet::new(),
            asserted_kinds: BTreeSet::new(),
            recorded_runs: Vec::new(),
            probe_runs: Vec::new(),
            bodies: Arc::new(Mutex::new(HashMap::new())),
            ws,
            task,
            run,
        })
    }

    /// `drop` — removes the scenario database (per-scenario isolation).
    /// `admin` holds the postgres-database connection, so the DROP never
    /// runs against the database it removes.
    pub async fn teardown(&mut self) {
        self.pool.close().await;
        // The DROP runs on a fresh postgres-DB connection — never on the
        // scenario-DB `admin` conn it would have to remove underneath.
        if let Ok(mut admin) = admin_conn().await {
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db))
                .execute(&mut admin)
                .await;
        }
    }

    /// Post-"restart" reopen (upstream `matrixGraph` reopen legs): a
    /// second pool + fresh store handles over the same database and the
    /// same seams — the reconcile-before-reinvoke and resume-preflight
    /// legs exercise real reconnect paths, not pooled reuse.
    pub async fn reopen(&mut self) -> Result<()> {
        self.pool.close().await;
        let pool = role_pool(&self.db, "central_runtime").await?;
        let finalized_check = self.finalized.clone();
        let mut sched = PgSchedulerStore::new(pool.clone(), vec!["claude-code".to_string()]);
        sched.clock = Some(self.clock.clone());
        sched.killer = Some(self.killer.clone());
        sched.compensation = Some(self.compensation.clone());
        sched.jitter = Some(Arc::new(|| 0.0_f64));
        // Carry the installed admission profile across the restart
        // (upstream `reopenGraph` carries AdmissionProfile).
        sched.admission_profile = self.sched.admission_profile;
        self.sched = Arc::new(sched);
        self.ck = PgCheckpointStore::with_digester(pool.clone(), self.digester.clone());
        let mut wf = PgWorkflowStore::new(pool.clone());
        wf.harness_registry = Some(Arc::new(|name: &str| name == "claude-code"));
        wf.artifact_finalized = Some(Arc::new(move |id: ArtifactId, _checksum: &str| {
            finalized_check.lock().unwrap().contains(&id)
        }));
        self.wf = wf;
        self.journal = PgJournalStore::new(pool.clone());
        self.views = PgRunviewStore::new(pool.clone());
        self.pool = pool;
        Ok(())
    }

    /// Seeds a second `(workspace, task, run)` fixture in THIS database —
    /// upstream's `setupGraph` on the shared connection, the same-DB
    /// scope separation the cross-run denial legs require. The probe is
    /// untracked (upstream's unrecorded probe graphs), but remembered in
    /// `probe_runs` for teardown-time diagnostics.
    pub async fn spawn_graph(&mut self) -> Result<ProbeGraph> {
        let probe = ProbeGraph {
            ws: WorkspaceId::new(),
            task: TaskId::new(),
            run: RunId::new(),
        };
        for q in [
            "INSERT INTO central.workspaces (id, state, owner_principal_id, quota_max_bytes) \
             VALUES ($1, 'active', 'rtm', 1099511627776)",
            "INSERT INTO central.workspace_event_counters (workspace_id) VALUES ($1)",
        ] {
            sqlx::query(q)
                .bind(uuid_of!(probe.ws))
                .execute(&mut self.admin)
                .await
                .map_err(|e| fail(e.to_string()))?;
        }
        sqlx::query(
            "INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, \
             last_run_index, title, input_spec) \
             VALUES ($1, $2, 1, 'running', $3, 1, 'rtm-probe', '{}'::jsonb)",
        )
        .bind(uuid_of!(probe.task))
        .bind(uuid_of!(probe.ws))
        .bind(uuid_of!(probe.run))
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        sqlx::query(
            "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index) \
             VALUES ($1, $2, $3, 1, 'running', 1)",
        )
        .bind(uuid_of!(probe.run))
        .bind(uuid_of!(probe.ws))
        .bind(uuid_of!(probe.task))
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        self.probe_runs.push(probe.run);
        Ok(probe)
    }

    /// Registers a `claude-code`/`worktree` worker (upstream
    /// `registerWorker`).
    pub async fn register_worker(&self, max_concurrent: i32) -> Result<WorkerId> {
        let worker = Worker {
            id: WorkerId::new(),
            workspace_id: self.ws,
            protocol_version: central_scheduler::domain::PROTOCOL_VERSION,
            harness_kinds: vec!["claude-code".to_string()],
            workspace_kinds: vec!["worktree".to_string(), "directory".to_string()],
            max_concurrent_attempts: max_concurrent,
            state: WorkerState::Active,
            registered_at: None,
            last_seen_at: None,
        };
        SchedStore::register_worker(&self.sched, worker).await
    }

    /// `emitNodes` — emits one `central.child-spec/v1` batch of root
    /// children under `parent` (None = run roots) through the real
    /// workflow store.
    pub async fn emit(
        &self,
        parent: Option<WorkflowNodeId>,
        children: Vec<ChildSpecNode>,
    ) -> Result<EmitResult> {
        let result = self.emit_raw(parent, children).await?;
        assert!(
            result.rejected.is_none(),
            "emit rejected: {:?}",
            result.rejected
        );
        Ok(result)
    }

    /// `emit` without the acceptance assert — RTM-12 reads the
    /// `rejected` payload directly (upstream's cycle leg).
    pub async fn emit_raw(
        &self,
        parent: Option<WorkflowNodeId>,
        children: Vec<ChildSpecNode>,
    ) -> Result<EmitResult> {
        let result = self
            .wf
            .emit_batch(
                self.run,
                parent,
                ChildSpec {
                    version: CHILD_SPEC_VERSION.to_string(),
                    children,
                },
            )
            .await?;
        // Upstream `recomputeReadiness` — readiness promotion rides the
        // same pass the transitions run.
        self.wf.recompute_ready(self.run).await?;
        Ok(result)
    }

    /// Failure-time diagnosis for an unexpected `claim_ready` result —
    /// every node's state/not_before plus the newest journal rows.
    async fn claim_diagnosis(&self) -> String {
        let states: Vec<(String, String, Option<OffsetDateTime>)> = sqlx::query_as(
            "SELECT node_key, state, not_before FROM central.workflow_nodes \
             WHERE run_id = $1 ORDER BY node_key",
        )
        .bind(uuid_of!(self.run))
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        let events: Vec<(String, Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT kind, reason, payload FROM central.run_events \
             WHERE run_id = $1 ORDER BY id DESC LIMIT 8",
        )
        .bind(uuid_of!(self.run))
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        let mut out = String::from("  nodes:");
        for (k, st, nb) in &states {
            out.push_str(&format!("\n    {k}: {st} not_before={nb:?}"));
        }
        out.push_str("\n  newest events:");
        for (k, r, pl) in &events {
            out.push_str(&format!("\n    {k} reason={r:?} payload={pl}"));
        }
        out
    }

    /// One `claude-code`/`worktree` child spec node.
    pub fn child(key: &str) -> ChildSpecNode {
        ChildSpecNode {
            node_key: key.to_string(),
            depends_on: Vec::new(),
            harness: "claude-code".to_string(),
            workspace_kind: "worktree".to_string(),
            input_artifact_refs: Vec::new(),
            budget: None,
            on_terminal_failure: String::new(),
            node_timeout_seconds: None,
            session_timeout_seconds: None,
            max_attempts: Default::default(),
            max_attempts_total: None,
        }
    }

    /// `claimAndDispatch` — claim one ready node and drive it through
    /// provision → launch → certainty persist via the real `Dispatcher`.
    pub async fn claim_and_dispatch(&self, worker: WorkerId) -> Result<ClaimedAttempt> {
        let mut claimed = self.sched.claim_ready(worker, 1).await?;
        if claimed.len() != 1 {
            panic!(
                "claim_ready: want exactly one
{}",
                self.claim_diagnosis().await
            );
        }
        let claim = claimed.swap_remove(0);
        self.launcher.script(
            claim.attempt.id,
            LaunchVerdict::Started(format!("sess-{}", claim.attempt.id)),
        );
        Dispatcher::new(
            self.sched.clone(),
            self.provisioner.clone(),
            self.launcher.clone(),
        )
        .dispatch(claim.clone())
        .await?;
        Ok(claim)
    }

    /// Claim without dispatch — the attempt stays `claimed`.
    pub async fn claim(&self, worker: WorkerId) -> Result<ClaimedAttempt> {
        let mut claimed = self.sched.claim_ready(worker, 1).await?;
        if claimed.len() != 1 {
            panic!(
                "claim_ready: want exactly one
{}",
                self.claim_diagnosis().await
            );
        }
        Ok(claimed.swap_remove(0))
    }

    /// Forces the lease's `expires_at` into the past (upstream
    /// `forceLeaseExpiry` — the deterministic expiry trigger).
    pub async fn force_expire(&mut self, lease: NodeLeaseId) -> Result<()> {
        sqlx::query(
            "UPDATE central.node_leases SET expires_at = now() - interval '1 s' WHERE id = $1",
        )
        .bind(uuid_of!(lease))
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// Ages the worker's leases' `last_heartbeat_at` by `secs` — the
    /// missed-beat ladder input `sweep_suspects` reads (upstream ages the
    /// lease heartbeat row, not the registration).
    pub async fn age_worker(&mut self, worker: WorkerId, secs: f64) -> Result<()> {
        sqlx::query(
            "UPDATE central.node_leases SET last_heartbeat_at = now() - make_interval(secs => $2) \
             WHERE worker_id = $1",
        )
        .bind(uuid_of!(worker))
        .bind(secs)
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// Ages the attempt's `claimed_at` (the node-bound epoch).
    pub async fn age_claimed_at(&mut self, attempt: SessionAttemptId, secs: f64) -> Result<()> {
        sqlx::query(
            "UPDATE central.session_attempts \
             SET claimed_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(uuid_of!(attempt))
        .bind(secs)
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// Sets the run's deadline for workflow-timeout evaluation.
    pub async fn set_run_deadline(&mut self, secs_ago: f64) -> Result<()> {
        sqlx::query(
            "UPDATE central.runs SET deadline = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(uuid_of!(self.run))
        .bind(secs_ago)
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// Reads one node's current state.
    pub async fn node_state(&mut self, node: WorkflowNodeId) -> Result<String> {
        sqlx::query_scalar("SELECT state FROM central.workflow_nodes WHERE id = $1")
            .bind(uuid_of!(node))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// Reads one attempt's current state.
    pub async fn attempt_state(&mut self, attempt: SessionAttemptId) -> Result<String> {
        sqlx::query_scalar("SELECT state FROM central.session_attempts WHERE id = $1")
            .bind(uuid_of!(attempt))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// `(kind, node_id, attempt_id, reason_code)` for the run, in `seq`
    /// order — the event-surface assertions ride on this.
    pub async fn events(
        &mut self,
    ) -> Result<Vec<(String, Option<String>, Option<String>, Option<String>)>> {
        sqlx::query_as(
            "SELECT kind, node_id::text, attempt_id::text, reason_code \
             FROM central.run_events WHERE run_id = $1 ORDER BY seq",
        )
        .bind(uuid_of!(self.run))
        .fetch_all(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))
    }

    /// Event kinds only, in order.
    pub async fn event_kinds(&mut self) -> Result<Vec<String>> {
        Ok(self
            .events()
            .await?
            .into_iter()
            .map(|(kind, _, _, _)| kind)
            .collect())
    }

    /// Asserts every wanted kind appears in the journal at least once.
    pub async fn assert_kinds(&mut self, want: &[&str]) -> Result<()> {
        let kinds = self.event_kinds().await?;
        for w in want {
            assert!(
                kinds.iter().any(|k| k == w),
                "missing event kind {w}; journal: {kinds:?}"
            );
        }
        Ok(())
    }

    /// Asserts a reason code rode on at least one event of `kind`.
    pub async fn assert_reason(&mut self, kind: &str, reason: &str) -> Result<()> {
        let events = self.events().await?;
        assert!(
            events
                .iter()
                .any(|(k, _, _, r)| k == kind && r.as_deref() == Some(reason)),
            "missing {kind} reason {reason}; journal: {events:?}"
        );
        Ok(())
    }

    /// Asserts no live leases remain for the run (upstream cleanup
    /// expectation).
    pub async fn assert_no_live_leases(&mut self) -> Result<()> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE a.run_id = $1 AND l.released_at IS NULL",
        )
        .bind(uuid_of!(self.run))
        .fetch_one(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        assert_eq!(n, 0, "live leases remain");
        Ok(())
    }

    /// The node's recorded spec document.
    pub async fn node_by_key(&mut self, key: &str) -> Result<WorkflowNodeId> {
        let text: String = sqlx::query_scalar(
            "SELECT id::text FROM central.workflow_nodes WHERE run_id = $1 AND node_key = $2",
        )
        .bind(uuid_of!(self.run))
        .bind(key)
        .fetch_one(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        WorkflowNodeId::parse(&text).map_err(|e| fail(format!("{e:?}")))
    }

    /// Asserts the node reached `state`.
    pub async fn assert_node_state(
        &mut self,
        node: WorkflowNodeId,
        state: NodeStatus,
    ) -> Result<()> {
        let got = self.node_state(node).await?;
        assert_eq!(got, state.as_str(), "node {node}");
        Ok(())
    }

    /// Asserts the attempt reached `state`.
    pub async fn assert_attempt_state(
        &mut self,
        attempt: SessionAttemptId,
        state: AttemptState,
    ) -> Result<()> {
        let got = self.attempt_state(attempt).await?;
        assert_eq!(got, state.as_str(), "attempt {attempt}");
        Ok(())
    }

    /// Seeds a `verifying` artifact row the way the B10 pipeline leaves it
    /// (fixture setup — the finalize commit under test is production).
    pub async fn seed_verifying_artifact(
        &mut self,
        artifact: central_foundation::identity::ArtifactId,
        checksum: [u8; 32],
        content_generation: central_foundation::identity::ContentGeneration,
        required_role: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO central.artifacts \
             (id, workspace_id, task_id, run_id, step_id, step_attempt_id, version, state, \
              declared_media_type, detected_media_type, size, checksum_algorithm, checksum_value, \
              producer_id, required_role, object_key, staging_key, ready_key, \
              staging_generation, content_generation, sensitivity, disposition) \
             VALUES ($1, $2, $3, $4, $5, $6, 3, 'verifying', 'text/plain', 'text/plain', \
              4, 'sha256', $7, 'rtm', $11, $8, $9, $10, $12, $13, 'unrestricted', 'attachment')",
        )
        .bind(uuid_of!(artifact))
        .bind(uuid_of!(self.ws))
        .bind(uuid_of!(self.task))
        .bind(uuid_of!(self.run))
        .bind(None::<sqlx::types::Uuid>)
        .bind(None::<sqlx::types::Uuid>)
        .bind(checksum.as_slice())
        .bind(format!("v1/ready/{artifact}"))
        .bind(format!("v1/staging/{artifact}"))
        .bind(format!("v1/ready/{artifact}"))
        .bind(required_role)
        .bind(uuid_of!(
            central_foundation::identity::StagingGeneration::new()
        ))
        .bind(uuid_of!(content_generation))
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// `finalize_attempt_artifact` through the real artifact store — the
    /// key row + verifying→ready + journaled produce edge + event.
    pub async fn finalize_artifact(
        &mut self,
        artifact: central_foundation::identity::ArtifactId,
        attempt: SessionAttemptId,
        node: WorkflowNodeId,
        name: &str,
        checksum: [u8; 32],
        content_generation: central_foundation::identity::ContentGeneration,
    ) -> Result<()> {
        let store = central_adapter_postgres::artifact::Store::new(self.pool.clone());
        let input = central_artifact::lineage::FinalizeAttemptInput {
            attempt_id: attempt,
            artifact_name: name.to_string(),
            artifact_id: artifact,
            run_id: self.run,
            node_id: node,
            checksum,
            payload_fingerprint: [3; 32],
            content_generation,
        };
        let change = central_artifact::lineage::attempt_finalization(&input)
            .map_err(|e| fail(e.to_string()))?;
        central_artifact::port::AttemptFinalizationStore::finalize_attempt_artifact(&store, change)
            .await?;
        self.finalized.lock().unwrap().insert(artifact);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Assertion bookkeeping (recordScenario parity)
    // -----------------------------------------------------------------

    /// Records one asserted reason code — fail-closed against the
    /// specs-1-8 catalog (upstream `recordScenario`'s `codeToSpec` gate).
    pub fn note_reason(&mut self, code: &str) {
        assert!(
            crate::evidence::code_to_spec(code).is_some(),
            "asserted reason code {code} is not cataloged; transcribe it into codeToSpec"
        );
        self.asserted_reasons.insert(code.to_string());
    }

    /// Records one asserted event kind — must be a cataloged kind.
    pub fn note_kind(&mut self, kind: &str) {
        assert!(
            central_eventjournal::domain::known(kind),
            "asserted event kind {kind} is not cataloged"
        );
        self.asserted_kinds.insert(kind.to_string());
    }

    /// Drains the recorded assertions into the evidence record.
    pub fn take_assertions(&mut self) -> (Vec<String>, Vec<String>) {
        (
            std::mem::take(&mut self.asserted_reasons)
                .into_iter()
                .collect(),
            std::mem::take(&mut self.asserted_kinds)
                .into_iter()
                .collect(),
        )
    }

    /// Asserts a failure carries `code` (and records it).
    pub fn expect_code(&mut self, err: &Failure, code: &str) {
        assert_eq!(err.code(), code, "failure kind {:?}", err.kind());
        self.note_reason(code);
    }

    /// Asserts a failure carries `code` under kind `Denied` (upstream's
    /// `requireSchedulerFailure`/denied probes).
    pub fn expect_denied(&mut self, err: &Failure, code: &str) {
        assert_eq!(err.kind(), FailureKind::Denied, "want denied: {err:?}");
        assert_eq!(err.code(), code, "denied code: {err:?}");
        self.note_reason(code);
    }

    /// Asserts a failure carries `code` under kind `Conflict`.
    pub fn expect_conflict(&mut self, err: &Failure, code: &str) {
        assert_eq!(err.kind(), FailureKind::Conflict, "want conflict: {err:?}");
        assert_eq!(err.code(), code, "conflict code: {err:?}");
        self.note_reason(code);
    }

    // -----------------------------------------------------------------
    // Store facades (upstream's direct-call driver)
    // -----------------------------------------------------------------

    /// `claimReady(worker, n)` without the one-claim assertion —
    /// saturation legs expect empty results.
    pub async fn claim_n(&self, worker: WorkerId, n: u32) -> Result<Vec<ClaimedAttempt>> {
        self.sched.claim_ready(worker, n).await
    }

    /// `Dispatch(claim)` through the real dispatcher — callers script
    /// the launch verdict first.
    pub async fn dispatch(&self, claim: &ClaimedAttempt) -> Result<()> {
        Dispatcher::new(
            self.sched.clone(),
            self.provisioner.clone(),
            self.launcher.clone(),
        )
        .dispatch(claim.clone())
        .await
    }

    /// `RecordAttemptOutcome` — the durable outcome ledger + node
    /// transition + journal commit (spec-4/5).
    pub async fn record_outcome(
        &self,
        outcome: Outcome,
    ) -> Result<central_retry::port::OutcomeResult> {
        RetryStore::record_outcome(self.sched.as_ref(), outcome).await
    }

    /// `SweepTimeouts` — the production three-level timeout sweep
    /// (`sweep_session_breach_tx` inclusive).
    pub async fn sweep_timeouts(&self) -> Result<SweepSummary> {
        RetryStore::sweep_timeouts(self.sched.as_ref(), self.clock.now()).await
    }

    /// `ExpireLeases` at the injected clock.
    pub async fn expire_leases(&self) -> Result<Vec<central_scheduler::domain::ExpiryResult>> {
        self.sched.expire_leases(self.clock.now()).await
    }

    /// `SweepSuspects` at the injected clock.
    pub async fn sweep_suspects(&self) -> Result<()> {
        self.sched.sweep_suspects(self.clock.now()).await
    }

    /// `Reconcile` — the startup pass that must precede post-restart
    /// dispatch.
    pub async fn reconcile(&self) -> Result<()> {
        self.sched.reconcile("rtm").await
    }

    /// `AttemptCounts` — the node's journaled consumption per class.
    pub async fn attempt_counts(
        &self,
        node: WorkflowNodeId,
    ) -> Result<central_retry::domain::AttemptCounts> {
        RetryStore::attempt_counts(self.sched.as_ref(), node).await
    }

    /// `FirstDispatchAt` — the starvation bound anchor.
    pub async fn first_dispatch_at(&self, node: WorkflowNodeId) -> Result<Option<OffsetDateTime>> {
        RetryStore::first_dispatch_at(self.sched.as_ref(), node).await
    }

    /// `RunCompensation` — the `on_terminal_failure` hook pass.
    pub async fn run_compensation(&self, node: WorkflowNodeId) -> Result<()> {
        RetryStore::run_compensation(self.sched.as_ref(), node).await
    }

    /// The scripted executor's invocation count (managed-hook evidence).
    pub fn compensation_calls(&self) -> u32 {
        *self.compensation.calls.lock().unwrap()
    }

    /// `Transition` — a node state edge + journaled event.
    pub async fn transition(
        &self,
        node: WorkflowNodeId,
        to: NodeStatus,
        reason: Option<&str>,
    ) -> Result<()> {
        self.wf.transition(node, to, "rtm", reason).await
    }

    /// `CancelNode` — the spec-1 cascade (BFS reach set returned).
    pub async fn cancel_node(&self, node: WorkflowNodeId) -> Result<Vec<WorkflowNodeId>> {
        self.wf.cancel_node(node, "rtm").await
    }

    /// `ResolveAmbiguous` — the operator decision (`rerun`|`resume`)
    /// keyed on the parked attempt's fingerprint.
    pub async fn resolve_ambiguous(
        &self,
        node: WorkflowNodeId,
        decision: &str,
        fingerprint: [u8; 32],
    ) -> Result<()> {
        self.wf
            .resolve_ambiguous(node, decision, fingerprint, "rtm")
            .await
    }

    /// `Fence` — the lease-as-fence durable-write guard.
    pub async fn fence(
        &self,
        node: WorkflowNodeId,
        attempt: SessionAttemptId,
        lease: NodeLeaseId,
    ) -> Result<()> {
        self.sched.fence(node, attempt, lease).await
    }

    /// `RenewLease` — heartbeat-time lease renewal.
    pub async fn renew_lease(&self, lease: NodeLeaseId, worker: WorkerId) -> Result<()> {
        self.sched.renew_lease(lease, worker).await
    }

    /// `WorkerLeases` — the worker's live lease set.
    pub async fn worker_leases(
        &self,
        worker: WorkerId,
    ) -> Result<Vec<central_scheduler::domain::Lease>> {
        self.sched.worker_leases(worker).await
    }

    /// `DeregisterWorker` — quiet-worker shutdown (leases released).
    pub async fn deregister_worker(&self, worker: WorkerId) -> Result<()> {
        self.sched.deregister_worker(worker, "rtm").await
    }

    /// Emits a batch under `parent` (upstream `mustEmitChildren`).
    pub async fn emit_children(
        &self,
        parent: WorkflowNodeId,
        children: Vec<ChildSpecNode>,
    ) -> Result<EmitResult> {
        self.emit(Some(parent), children).await
    }

    /// All run nodes via the workflow store.
    pub async fn nodes(&self) -> Result<Vec<central_workflow::domain::Node>> {
        self.wf.nodes_for_run(self.run).await
    }

    /// All run edges via the workflow store.
    pub async fn edges(&self) -> Result<Vec<central_workflow::domain::Edge>> {
        self.wf.edges_for_run(self.run).await
    }

    /// `mustEmitNodes` verbatim — emit WITHOUT the readiness recompute
    /// the `emit` facade folds in (RTM-14's declared→ready flip leg
    /// asserts on the un-recomputed emit, like upstream).
    pub async fn emit_no_recompute(
        &self,
        parent: Option<WorkflowNodeId>,
        children: Vec<ChildSpecNode>,
    ) -> Result<EmitResult> {
        let result = self
            .wf
            .emit_batch(
                self.run,
                parent,
                ChildSpec {
                    version: CHILD_SPEC_VERSION.to_string(),
                    children,
                },
            )
            .await?;
        assert!(
            result.rejected.is_none(),
            "emit rejected: {:?}",
            result.rejected
        );
        Ok(result)
    }

    // -----------------------------------------------------------------
    // Journal queries (upstream's admin-connection probes)
    // -----------------------------------------------------------------

    /// Full `RunEvent` rows for `run` via the read projection —
    /// `journal.EventsForRun` parity.
    pub async fn events_for(
        &self,
        run: RunId,
    ) -> Result<Vec<central_eventjournal::domain::RunEvent>> {
        self.views.events_for_run(run).await
    }

    /// Full `RunEvent` rows for the scenario run.
    pub async fn run_events(&self) -> Result<Vec<central_eventjournal::domain::RunEvent>> {
        self.events_for(self.run).await
    }

    /// Counts events of `kind` in the run journal.
    pub async fn count_kind(&mut self, kind: &str) -> Result<usize> {
        Ok(self
            .events()
            .await?
            .iter()
            .filter(|(k, _, _, _)| k == kind)
            .count())
    }

    /// Counts events of `kind` pinned to `node` (`countNodeKind`).
    pub async fn count_node_kind(&mut self, node: WorkflowNodeId, kind: &str) -> Result<usize> {
        let id = node.to_string();
        Ok(self
            .events()
            .await?
            .iter()
            .filter(|(k, n, _, _)| k == kind && n.as_deref() == Some(id.as_str()))
            .count())
    }

    /// The run journal's maximum `seq` (`maxEventSeq` — the "no second
    /// row" boundary the dedupe legs compare against).
    pub async fn max_event_seq(&mut self) -> Result<i64> {
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM central.run_events WHERE run_id = $1")
            .bind(uuid_of!(self.run))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// The node's highest event `seq` (`nodeEventSeq`).
    pub async fn node_event_seq(&mut self, node: WorkflowNodeId) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) FROM central.run_events \
             WHERE run_id = $1 AND node_id = $2",
        )
        .bind(uuid_of!(self.run))
        .bind(uuid_of!(node))
        .fetch_one(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))
    }

    /// The node's `(seq, state)` attempt rows — `nodeAttemptStates`.
    pub async fn node_attempt_states(
        &mut self,
        node: WorkflowNodeId,
    ) -> Result<Vec<(i32, String)>> {
        sqlx::query_as(
            "SELECT attempt_seq, state FROM central.session_attempts \
             WHERE node_id = $1 ORDER BY attempt_seq",
        )
        .bind(uuid_of!(node))
        .fetch_all(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))
    }

    /// The reason code journaled on the node's attempt — `nodeAttemptReason`.
    pub async fn node_attempt_reason(
        &mut self,
        node: WorkflowNodeId,
        attempt_seq: i32,
    ) -> Result<Option<String>> {
        sqlx::query_scalar(
            "SELECT dispatch_reason_code FROM central.session_attempts \
             WHERE node_id = $1 AND attempt_seq = $2",
        )
        .bind(uuid_of!(node))
        .bind(attempt_seq)
        .fetch_optional(&mut self.admin)
        .await
        .map(|row| row.flatten())
        .map_err(|e| fail(e.to_string()))
    }

    /// Ages the attempt's `started_at` (the wall-clock breach input).
    pub async fn age_started_at(&mut self, attempt: SessionAttemptId, secs: f64) -> Result<()> {
        sqlx::query(
            "UPDATE central.session_attempts \
             SET started_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(uuid_of!(attempt))
        .bind(secs)
        .execute(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// The node's `not_before` (the `retry_at` gate).
    pub async fn not_before(&mut self, node: WorkflowNodeId) -> Result<Option<OffsetDateTime>> {
        sqlx::query_scalar("SELECT not_before FROM central.workflow_nodes WHERE id = $1")
            .bind(uuid_of!(node))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// The node's `ready_at` (`readyAt` — starvation ordering anchor).
    pub async fn ready_at(&mut self, node: WorkflowNodeId) -> Result<Option<OffsetDateTime>> {
        sqlx::query_scalar("SELECT ready_at FROM central.workflow_nodes WHERE id = $1")
            .bind(uuid_of!(node))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// Clears the node's `not_before` (`clearNotBefore` — forces the
    /// claim-eligible leg upstream triggers with a timed wait).
    pub async fn clear_not_before(&mut self, node: WorkflowNodeId) -> Result<()> {
        sqlx::query("UPDATE central.workflow_nodes SET not_before = NULL WHERE id = $1")
            .bind(uuid_of!(node))
            .execute(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))?;
        Ok(())
    }

    /// `snapshotRunStates` — `node_key → state` for the whole run.
    pub async fn snapshot_run_states(&mut self) -> Result<BTreeMap<String, String>> {
        sqlx::query_as("SELECT node_key, state FROM central.workflow_nodes WHERE run_id = $1")
            .bind(uuid_of!(self.run))
            .fetch_all(&mut self.admin)
            .await
            .map(|rows: Vec<(String, String)>| rows.into_iter().collect())
            .map_err(|e| fail(e.to_string()))
    }

    /// `assertRunClean` — zero ready nodes, zero live leases in the run
    /// (upstream's per-scenario tail; keeps the global sweeps scoped).
    pub async fn assert_run_clean(&mut self) -> Result<()> {
        let ready: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM central.workflow_nodes \
             WHERE run_id = $1 AND state = 'ready'",
        )
        .bind(uuid_of!(self.run))
        .fetch_one(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        assert_eq!(ready, 0, "run is not clean: {ready} ready nodes remain");
        self.assert_no_live_leases().await
    }

    /// Live (unreleased) lease ids for the run.
    pub async fn live_lease_ids(&mut self) -> Result<Vec<NodeLeaseId>> {
        let rows: Vec<sqlx::types::Uuid> = sqlx::query_scalar(
            "SELECT l.id FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE a.run_id = $1 AND l.released_at IS NULL",
        )
        .bind(uuid_of!(self.run))
        .fetch_all(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|u| NodeLeaseId::from_trusted_db_bytes(*u.as_bytes()))
            .collect())
    }

    /// Journal row count for the run.
    pub async fn journal_row_count(&mut self) -> Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM central.run_events WHERE run_id = $1")
            .bind(uuid_of!(self.run))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// `outboxHealth` — the publisher stall probe's read model.
    pub async fn outbox_health(&self) -> Result<central_runview::domain::OutboxHealth> {
        self.views.outbox_health().await
    }

    /// `runForId` — the run summary (status, deadline) for any run.
    pub async fn run_summary(&self, run: RunId) -> Result<central_runview::domain::RunSummary> {
        self.views.run_for_id(self.ws, run).await
    }

    // -----------------------------------------------------------------
    // Artifact lineage surface (RTM-01/03/14 + RTM-09's GC leg)
    // -----------------------------------------------------------------

    /// `artifactEdges` — `(from_key, to_key, artifact_id)` produce rows
    /// plus `(from_key, to_key, artifact_id, declared, checksum)` read
    /// rows, as upstream's probe returns them.
    pub async fn produce_edges(&mut self) -> Result<Vec<(String, String, String)>> {
        sqlx::query_as(
            "SELECT n.node_key, e.artifact_id::text, e.attempt_id::text \
             FROM central.artifact_produce_edges e \
             JOIN central.workflow_nodes n ON n.id = e.node_id \
             WHERE e.run_id = $1 ORDER BY n.node_key",
        )
        .bind(uuid_of!(self.run))
        .fetch_all(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))
    }

    /// `readEdges` — `(consumer_node_key, artifact_id, declared,
    /// checksum)` read-edge rows.
    pub async fn read_edges(&mut self) -> Result<Vec<(String, String, bool, String)>> {
        sqlx::query_as(
            "SELECT n.node_key, e.artifact_id::text, e.declared, e.checksum \
             FROM central.artifact_read_edges e \
             JOIN central.workflow_nodes n ON n.id = e.reader_node_id \
             WHERE e.run_id = $1 ORDER BY n.node_key",
        )
        .bind(uuid_of!(self.run))
        .fetch_all(&mut self.admin)
        .await
        .map_err(|e| fail(e.to_string()))
    }

    /// `findArtifact` — the artifact's `(state, verified_checksum)` or
    /// `None`.
    pub async fn find_artifact(
        &mut self,
        artifact: ArtifactId,
    ) -> Result<Option<(String, Vec<u8>)>> {
        sqlx::query_as("SELECT state, checksum_value FROM central.artifacts WHERE id = $1")
            .bind(uuid_of!(artifact))
            .fetch_optional(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// `assertArtifactChecksum` — the durable verified checksum equals
    /// the expected body hash.
    pub async fn assert_artifact_checksum(
        &mut self,
        artifact: ArtifactId,
        expected: [u8; 32],
    ) -> Result<()> {
        let row = self.find_artifact(artifact).await?;
        let (_, checksum) = row.ok_or_else(|| fail(format!("artifact {artifact} absent")))?;
        assert_eq!(
            checksum.as_slice(),
            expected.as_slice(),
            "artifact {artifact} checksum drifted"
        );
        Ok(())
    }

    /// `ResolveProduced` — the production lineage resolution
    /// `(run, producer node_key, name)` → lineage artifacts
    /// (RTM-10's readable-set re-exposure leg).
    pub async fn resolve_produced(&self, node_key: &str, name: &str) -> Result<Vec<ArtifactId>> {
        let store = central_adapter_postgres::artifact::Store::new(self.pool.clone());
        let artifacts = central_artifact::port::ReadStore::resolve_produced(
            &store,
            Some(self.run),
            node_key,
            name,
        )
        .await?;
        Ok(artifacts.into_iter().map(|a| a.id).collect())
    }

    /// `readyKey` — the artifact's bound ready key (`resolveProduced`'s
    /// fetch target).
    pub async fn artifact_ready_key(&mut self, artifact: ArtifactId) -> Result<String> {
        sqlx::query_scalar("SELECT ready_key FROM central.artifacts WHERE id = $1")
            .bind(uuid_of!(artifact))
            .fetch_one(&mut self.admin)
            .await
            .map_err(|e| fail(e.to_string()))
    }

    /// `matrixArtifactRead` — the RTM-14 read seam: the production
    /// `authorize_read` + `record_read` path with bodies served from the
    /// scripted map (upstream `matrixReadBackend` parity). On
    /// `authorize_read` failure returns the failure verbatim; on success
    /// returns `(declared, checksum_hex, body)`.
    pub async fn matrix_read(
        &mut self,
        run: RunId,
        node: WorkflowNodeId,
        attempt: SessionAttemptId,
        selector: central_artifact::lineage::ReadSelector,
    ) -> Result<(bool, String, Vec<u8>)> {
        let store = central_adapter_postgres::artifact::Store::new(self.pool.clone());
        let auth = central_artifact::app::authorize_read(
            Some(&store),
            central_artifact::lineage::ReadRequest {
                scope: central_artifact::lineage::ReadScope::Attempt {
                    run_id: run,
                    node_id: node,
                    attempt_id: attempt,
                },
                selector,
            },
        )
        .await?;
        let key = auth.artifact.ready_key.clone();
        let body = self
            .bodies
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_else(|| b"rtm-body".to_vec());
        central_artifact::app::record_read(Some(&store), auth.edge(self.clock.now())).await?;
        Ok((auth.declared, auth.artifact.checksum.clone(), body))
    }

    /// Registers one scripted body for `ready_key` (upstream
    /// `matrixReadBackend` body pinning).
    pub fn script_body(&self, ready_key: &str, body: &[u8]) {
        self.bodies
            .lock()
            .unwrap()
            .insert(ready_key.to_string(), body.to_vec());
    }
}

/// `uuid_of` — the identity newtype → `uuid::Uuid` conversion the
/// fixture writes bind (mirrors the adapter-test macro).
macro_rules! uuid_of {
    ($id:expr) => {
        sqlx::types::Uuid::from_bytes(*$id.as_bytes())
    };
}
pub(crate) use uuid_of;
