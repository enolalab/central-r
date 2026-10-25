//! The `matrixGraph` fixture — one scenario's composed real PostgreSQL
//! stores plus the deterministic injection seams (stub clock, scripted
//! digester/killer/launcher/provisioner). Port of upstream
//! `phase2_acceptance_test.go`'s `matrixGraph`: no concurrent runtime
//! loop — scenarios call store/service methods directly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use central_adapter_postgres::checkpoint::Store as PgCheckpointStore;
use central_adapter_postgres::eventjournal::Store as PgJournalStore;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::scheduler::PgSchedulerStore;
use central_adapter_postgres::workflow::Store as PgWorkflowStore;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    NodeLeaseId, RunId, SessionAttemptId, TaskId, WorkerId, WorkflowNodeId, WorkspaceId,
};
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
/// Lease TTL = 3 heartbeats.
pub const LEASE_TTL: Duration = Duration::seconds(45);

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
    pub fn advance(&self, d: Duration) {
        let mut g = self.now.lock().unwrap();
        *g += d;
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
            None => Ok(false), // fail closed: unscripted kills are unconfirmed
        }
    }
}

/// Upstream `ScriptedLauncher` — per-attempt `LaunchVerdict` scripts;
/// fails closed with a definite refusal when unscripted (nothing ran),
/// and records every `LaunchSpec`.
#[derive(Debug, Default)]
pub struct ScriptedLauncher {
    scripts: Mutex<HashMap<SessionAttemptId, LaunchVerdict>>,
    pub calls: Mutex<Vec<LaunchSpec>>,
}

impl ScriptedLauncher {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn script(&self, attempt: SessionAttemptId, verdict: LaunchVerdict) {
        self.scripts.lock().unwrap().insert(attempt, verdict);
    }
    pub fn calls(&self) -> Vec<LaunchSpec> {
        self.calls.lock().unwrap().clone()
    }
}

impl NodeLauncher for ScriptedLauncher {
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
        let attempt = spec.attempt.attempt.id;
        self.calls.lock().unwrap().push(spec);
        self.scripts
            .lock()
            .unwrap()
            .get(&attempt)
            .cloned()
            .unwrap_or_else(|| LaunchVerdict::Refused(fail("scripted launcher: no script")))
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
    pub clock: Arc<ManualClock>,
    pub digester: Arc<ScriptedDigester>,
    pub killer: Arc<ScriptedKiller>,
    pub launcher: Arc<ScriptedLauncher>,
    pub provisioner: Arc<ScriptProvisioner>,
    /// Artifact ids the emit-time `input_artifact_refs` checker treats as
    /// finalized — populated by `finalize_artifact`.
    pub finalized: Arc<Mutex<HashSet<central_foundation::identity::ArtifactId>>>,
    pub ws: WorkspaceId,
    pub task: TaskId,
    pub run: RunId,
}

pub fn admin_opts() -> Option<PgConnectOptions> {
    let dsn = std::env::var("CENTRAL_TEST_DSN").ok()?;
    PgConnectOptions::from_str(&dsn).ok()
}

macro_rules! skip {
    () => {
        if crate::driver::admin_opts().is_none() {
            eprintln!("CENTRAL_TEST_DSN unset — skipping phase-2 acceptance scenario");
            return Ok(());
        }
    };
}
pub(crate) use skip;

async fn role_conn(db: &str, role: &str) -> Result<PgConnection> {
    let opts = admin_opts()
        .expect("gated")
        .database(db)
        .username(role)
        .password(role);
    opts.connect()
        .await
        .map_err(|e| fail(format!("connect {role}@{db}: {e}")))
}

async fn role_pool(db: &str, role: &str) -> Result<PgPool> {
    let opts = admin_opts()
        .expect("gated")
        .database(db)
        .username(role)
        .password(role);
    PgPool::connect_with(opts)
        .await
        .map_err(|e| fail(format!("pool {role}@{db}: {e}")))
}

impl Matrix {
    /// `setupGraph` — a fresh baseline-installed database, fixture
    /// workspace/task/run, and every store composed with the seams.
    pub async fn setup(label: &str) -> Result<Self> {
        let mut admin = admin_opts()
            .expect("gated")
            .connect()
            .await
            .map_err(|e| fail(format!("admin connect: {e}")))?;
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
        let mut mig = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new()
            .install(&mut mig)
            .await
            .map_err(|e| fail(format!("baseline: {e}")))?;

        let pool = role_pool(&db, "central_runtime").await?;
        let finalized: Arc<Mutex<HashSet<central_foundation::identity::ArtifactId>>> =
            Arc::new(Mutex::new(HashSet::new()));
        let finalized_check = finalized.clone();
        let clock = ManualClock::new(OffsetDateTime::now_utc());
        let digester = ScriptedDigester::new();
        let killer = ScriptedKiller::new();
        let launcher = ScriptedLauncher::new();

        let mut sched = PgSchedulerStore::new(pool.clone(), vec!["claude-code".to_string()]);
        sched.clock = Some(clock.clone());
        sched.killer = Some(killer.clone());
        let sched = Arc::new(sched);
        let ck = PgCheckpointStore::with_digester(pool.clone(), digester.clone());
        let mut wf = PgWorkflowStore::new(pool.clone());
        wf.harness_registry = Some(Arc::new(|name: &str| name == "claude-code"));
        wf.artifact_finalized = Some(Arc::new(
            move |id: central_foundation::identity::ArtifactId, _checksum: &str| {
                finalized_check.lock().unwrap().contains(&id)
            },
        ));

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

        Ok(Self {
            db,
            admin: mig,
            pool: pool.clone(),
            sched,
            wf,
            ck,
            journal: PgJournalStore::new(pool),
            clock,
            digester,
            killer,
            launcher,
            provisioner: Arc::new(ScriptProvisioner),
            finalized,
            ws,
            task,
            run,
        })
    }

    /// `drop` — removes the scenario database (per-scenario isolation).
    pub async fn teardown(&mut self) {
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db))
            .execute(&mut self.admin)
            .await;
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
        assert_eq!(claimed.len(), 1, "claim_ready: want exactly one");
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
        assert_eq!(claimed.len(), 1, "claim_ready: want exactly one");
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

    /// Sets the node's aggregate timeout bound.
    pub async fn set_node_timeout(&mut self, node: WorkflowNodeId, secs: i64) -> Result<()> {
        sqlx::query("UPDATE central.workflow_nodes SET node_timeout_seconds = $2 WHERE id = $1")
            .bind(uuid_of!(node))
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
}

/// `uuid_of` — the identity newtype → `uuid::Uuid` conversion the
/// fixture writes bind (mirrors the adapter-test macro).
macro_rules! uuid_of {
    ($id:expr) => {
        sqlx::types::Uuid::from_bytes(*$id.as_bytes())
    };
}
pub(crate) use uuid_of;
