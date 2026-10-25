//! Phase-2 Slice-2B scheduler environment + composition — the kernel's
//! port of upstream `cmd/central/scheduler_composition.go` (issue #93).
//!
//! The whole stack — startup reconciler, worker registration +
//! heartbeats, sweeper and claim loop — sits behind the
//! `CENTRAL_PHASE2_SCHEDULER` development gate and defaults OFF:
//! nothing puts workflow nodes into `ready` for it to claim until the
//! emit path of #94+ lands, and the launcher seam is the documented
//! [`StubLauncher`] stand-in unless the real harness pair composes,
//! so an ungated serve must stay exactly as before.
//!
//! ```text
//! CENTRAL_PHASE2_SCHEDULER              -- 1 enables the stack, 0/unset keeps it off
//! CENTRAL_PHASE2_SCHEDULER_SCRATCH_ROOT -- required when enabled: the instance
//!     scratch root the provisioner puts workspaces/ under (absolute, clean)
//! CENTRAL_PHASE2_SCHEDULER_SOURCE_REPO  -- optional: the repository 'worktree'
//!     nodes are checked out from; absent, the worker advertises directory
//!     workspaces only
//! CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB   -- 1 permits stub dispatch when
//!     harness execution is off; 0/unset refuses that combination at
//!     startup (issue #120: the stub is never the serve default)
//! ```

use std::path::Path;
use std::sync::Arc;

use central_adapter_linux::dispatch_provision::DispatchProvisioner;
use central_adapter_postgres::checkpoint::Store as PgCheckpointStore;
use central_adapter_postgres::eventjournal::Store as PgEventJournalStore;
use central_adapter_postgres::scheduler::{DynKiller, PgSchedulerStore};
use central_eventjournal::app::EventLog;
use central_eventjournal::app::consumers::LoggingConsumer;
use central_eventjournal::app::publisher::{DEFAULT_PUBLISH_INTERVAL, Publisher};
use central_eventjournal::port::Consumer;
use central_foundation::failure::Failure;
use central_foundation::identity::{SENTINEL_WORKSPACE_ID, WorkerId};
use central_retry::domain::RetryPolicy;
use central_retry::port::SystemClock;
use central_scheduler::admission::SUPPORTED_MAX_PARALLEL_SESSIONS;
use central_scheduler::app::claim_loop::ClaimLoop;
use central_scheduler::app::dispatch::{Dispatcher, StubLauncher};
use central_scheduler::app::reconciler::Reconciler;
use central_scheduler::app::sweeper::Sweeper;
use central_scheduler::app::worker::Worker;
use central_scheduler::port::{LaunchSpec, LaunchVerdict, NodeLauncher};
use sqlx::PgPool;
use time::Duration;
use tokio::task::JoinSet;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, interval_at};

use crate::BoxFuture;
use crate::lifecycle::Component;
use crate::retry_compose::UnconfirmedKiller;

/// `CENTRAL_PHASE2_SCHEDULER` — `1` enables the Phase-2 scheduler stack
/// (upstream `envSchedulerEnabled`). Unset/`0` keeps it off; the fleet
/// page renders residual rows under the disabled notice.
pub const ENV_SCHEDULER_ENABLED: &str = "CENTRAL_PHASE2_SCHEDULER";
/// `CENTRAL_PHASE2_SCHEDULER_SCRATCH_ROOT` — required when enabled.
pub const ENV_SCHEDULER_SCRATCH: &str = "CENTRAL_PHASE2_SCHEDULER_SCRATCH_ROOT";
/// `CENTRAL_PHASE2_SCHEDULER_SOURCE_REPO` — optional `worktree` source.
pub const ENV_SCHEDULER_SOURCE_REPO: &str = "CENTRAL_PHASE2_SCHEDULER_SOURCE_REPO";
/// `CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB` — the explicit stub dev gate.
pub const ENV_SCHEDULER_ALLOW_STUB: &str = "CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB";

/// `errSchedulerConfig` — every scheduler-environment failure carries
/// this code so `serve` classifies it `CONFIG_INVALID`.
const CODE_SCHEDULER_CONFIG: &str = "scheduler_config_invalid";

fn config_err(msg: impl Into<String>) -> Failure {
    Failure::invalid(CODE_SCHEDULER_CONFIG, msg.into())
}

/// `filepath.Clean(p) == p` plus a non-root guard for absolute paths —
/// the shared shape rule `loadSchedulerConfig` applies to every path
/// the environment supplies.
fn is_clean_absolute(p: &str) -> bool {
    let path = Path::new(p);
    if !path.is_absolute() {
        return false;
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    path.components()
        .collect::<std::path::PathBuf>()
        .as_os_str()
        == p
}

/// `schedulerConfig` — the validated scheduler environment.
#[derive(Debug, Clone, Default)]
pub struct SchedulerConfig {
    /// `CENTRAL_PHASE2_SCHEDULER=1`.
    pub enabled: bool,
    /// `CENTRAL_PHASE2_SCHEDULER_SCRATCH_ROOT` — required when enabled.
    pub scratch_root: String,
    /// `CENTRAL_PHASE2_SCHEDULER_SOURCE_REPO` — empty for a
    /// directory-only deployment.
    pub source_repo: String,
    /// `CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB` — permits stub dispatch
    /// when harness execution is off (issue #120). Read only while the
    /// scheduler is enabled; a disabled scheduler ignores it like
    /// every other variable.
    pub allow_stub: bool,
}

impl SchedulerConfig {
    /// `loadSchedulerConfig` — reads the scheduler environment through
    /// `getenv`. A disabled scheduler ignores every other variable; an
    /// enabled one requires a scratch root, and every supplied path
    /// must be absolute and clean — invalid values refuse the start
    /// like the harness env does.
    ///
    /// # Errors
    /// `scheduler_config_invalid` on any malformed value — the same
    /// `CONFIG_INVALID` class upstream's `errSchedulerConfig` feeds.
    pub fn load(getenv: impl Fn(&str) -> String) -> Result<Self, Failure> {
        let mut cfg = Self::default();
        match getenv(ENV_SCHEDULER_ENABLED).as_str() {
            "" | "0" => return Ok(cfg),
            "1" => cfg.enabled = true,
            _ => {
                return Err(config_err(format!(
                    "{ENV_SCHEDULER_ENABLED} must be 1 or 0"
                )));
            }
        }
        let root = getenv(ENV_SCHEDULER_SCRATCH);
        if !is_clean_absolute(&root) || root == "/" {
            return Err(config_err(format!(
                "{ENV_SCHEDULER_SCRATCH} must be an absolute, clean, non-root path when \
                 {ENV_SCHEDULER_ENABLED}=1"
            )));
        }
        cfg.scratch_root = root;
        let source = getenv(ENV_SCHEDULER_SOURCE_REPO);
        if !source.is_empty() {
            if !is_clean_absolute(&source) {
                return Err(config_err(format!(
                    "{ENV_SCHEDULER_SOURCE_REPO} must be an absolute, clean path"
                )));
            }
            cfg.source_repo = source;
        }
        match getenv(ENV_SCHEDULER_ALLOW_STUB).as_str() {
            "" | "0" => {}
            "1" => cfg.allow_stub = true,
            _ => {
                return Err(config_err(format!(
                    "{ENV_SCHEDULER_ALLOW_STUB} must be 1 or 0"
                )));
            }
        }
        Ok(cfg)
    }
}

/// `schedulerLaunchableHarnesses` — the launchable-harness set the
/// registration handshake intersects against: `claude-code` is the only
/// harness adapter this instance ships. Fail-closed stays intact — the
/// store still refuses a worker whose declared harness kinds miss it
/// entirely.
#[must_use]
pub fn scheduler_launchable_harnesses() -> Vec<String> {
    vec!["claude-code".to_string()]
}

/// The workspace kinds the composed worker advertises — `directory`
/// alone without a source repository, `worktree` + `directory` with
/// one, upstream's exact advertisement set.
#[must_use]
fn advertised_workspace_kinds(config: &SchedulerConfig) -> Vec<String> {
    if config.source_repo.is_empty() {
        vec!["directory".to_string()]
    } else {
        vec!["worktree".to_string(), "directory".to_string()]
    }
}

/// `newSchedulerStore` — builds the postgres scheduler store over the
/// shared runtime pool. Its components run concurrently — the claim
/// loop's dispatch tasks, the worker's heartbeats and the sweeper —
/// so the store must be pool-backed.
///
/// The Slice-2D (issue #95) fields are wired here explicitly rather
/// than left to their `None` defaults so the composition root, not a
/// fallback inside the store, owns each choice: the `Killer` the
/// caller chose (the real cancel control when the scheduler gate +
/// harness execution are on and contained, else the documented
/// unconfirmed kill boundary), the locked default retry/backoff
/// policy, wall-clock evaluation, and a real jitter draw.
/// Compensation is the one seam this function cannot wire — it needs
/// the validated scratch config, so `compose_serve` installs it (see
/// [`crate::retry_compose`]). A `None` killer selects
/// [`UnconfirmedKiller`] — the explicit harness-off default, never a
/// silent fallback.
#[must_use]
pub fn new_scheduler_store(pool: PgPool, killer: Option<Arc<dyn DynKiller>>) -> PgSchedulerStore {
    let mut store = PgSchedulerStore::new(pool, scheduler_launchable_harnesses());
    store.killer = Some(killer.unwrap_or_else(|| Arc::new(UnconfirmedKiller)));
    store.retry_policy = RetryPolicy::default();
    store.clock = Some(Arc::new(SystemClock));
    store.jitter = Some(Arc::new(rand::random::<f64>) as _);
    store
}

// ---------------------------------------------------------------------------
// Supervised component drivers — upstream's `kernel.Component` halves
// ---------------------------------------------------------------------------

/// One supervised `*_once` pass driven on its tick interval — the
/// shared driver for the lease sweeper, checkpoint janitor, retry
/// timeout sweeper and event outbox publisher. Every capability it
/// wraps documents the same TICK CONTRACT: one pass at component
/// start BEFORE the ticker begins, then one per `tick_interval`;
/// pass failures are contained inside the pass itself (each `*_once`
/// returns `()`), so the component never exits on a transient store
/// error — it only dies when the supervisor drops this future.
pub(crate) struct TickedPassComponent {
    name: &'static str,
    interval: std::time::Duration,
    pass: Box<dyn FnMut() -> BoxFuture<'static, ()> + Send>,
}

impl TickedPassComponent {
    /// Builds a driver that runs `pass` once at start, then every
    /// `interval` (resolved by the caller — each capability owns its
    /// `DEFAULT_*` fallback).
    pub(crate) fn new(
        name: &'static str,
        interval: std::time::Duration,
        pass: impl FnMut() -> BoxFuture<'static, ()> + Send + 'static,
    ) -> Self {
        Self {
            name,
            interval,
            pass: Box::new(pass),
        }
    }
}

impl Component for TickedPassComponent {
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            (self.pass)().await;
            let mut ticker = interval_at(TokioInstant::now() + self.interval, self.interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                tracing::debug!(component = self.name, "scheduler pass tick");
                (self.pass)().await;
            }
        })
    }

    /// Settlement is a no-op for every pass component: the pass's own
    /// durable transactions own cleanup (upstream `Shutdown` no-ops).
    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

/// The worker component (upstream `schedapp.Worker`'s `Run` +
/// `Shutdown`): `register` first — a refused handshake returns the
/// failure so the profile reads the exit as fatal (spec-2 decision 2)
/// — then one heartbeat at start and one per `tick_interval`;
/// `settle` is `deregister` (spec-2 decision 8's lease release).
struct SchedulerWorkerComponent {
    worker: Arc<Worker<Arc<PgSchedulerStore>>>,
}

impl Component for SchedulerWorkerComponent {
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let worker = self.worker.clone();
        Box::pin(async move {
            worker.register().await?;
            worker.heartbeat_once().await;
            let interval = to_std(worker.tick_interval());
            let mut ticker = interval_at(TokioInstant::now() + interval, interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                worker.heartbeat_once().await;
            }
        })
    }

    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let worker = self.worker.clone();
        Box::pin(async move { worker.deregister().await })
    }
}

/// The concrete launcher seam [`compose_scheduler`] wires — the
/// production [`crate::scheduler_harness::SchedulerNodeLauncher`] when
/// the harness pair composes, else the documented [`StubLauncher`].
/// Upstream carries the `schedport.Launcher` interface; Rust's
/// `Send`-made [`NodeLauncher`] trait is not dyn-compatible, so the
/// two shipped implementations sit behind one enum.
pub enum SchedulerLauncher {
    /// `schedapp.StubLauncher` — the dev-gated stand-in: no harness
    /// process runs.
    Stub(StubLauncher),
    /// The real harness-bound launcher pair.
    Harness(crate::scheduler_harness::SchedulerNodeLauncher),
}

impl NodeLauncher for SchedulerLauncher {
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
        match self {
            Self::Stub(launcher) => launcher.launch(spec).await,
            Self::Harness(launcher) => launcher.launch(spec).await,
        }
    }
}

/// The claim-loop component (upstream `schedapp.ClaimLoop`'s `Run` +
/// `Shutdown`): one claim poll at component start then one per
/// `tick_interval`; each claimed attempt fans out to `dispatch` on the
/// runtime, and `settle` waits the in-flight dispatches — upstream's
/// `wg.Wait()` drain. The `JoinSet` lives on `self`, not the run
/// future, so a dropped run leaves the dispatches running for the
/// settlement drain to join.
struct SchedulerClaimLoopComponent {
    claim_loop: Arc<ClaimLoop<PgSchedulerStore, DispatchProvisioner, SchedulerLauncher>>,
    dispatches: JoinSet<()>,
}

impl Component for SchedulerClaimLoopComponent {
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let interval = to_std(self.claim_loop.tick_interval());
            let mut ticker = interval_at(TokioInstant::now() + interval, interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                for claim in self.claim_loop.claims().await {
                    let claim_loop = self.claim_loop.clone();
                    self.dispatches.spawn(async move {
                        if let Err(failure) = claim_loop.dispatch(claim).await {
                            tracing::warn!(
                                code = failure.code(),
                                "kernel: scheduler dispatch failed"
                            );
                        }
                    });
                }
                ticker.tick().await;
            }
        })
    }

    /// Upstream `Shutdown`'s drain: join every in-flight dispatch the
    /// poll spawned — the durable dispatch commits own their outcome.
    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            while self.dispatches.join_next().await.is_some() {}
            Ok(())
        })
    }
}

/// `time::Duration` → `std::time::Duration` (both wrap seconds+nanos;
/// a negative ticks as zero — never produced by the capability
/// defaults).
fn to_std(d: Duration) -> std::time::Duration {
    std::time::Duration::new(
        d.whole_seconds().max(0) as u64,
        d.subsec_nanoseconds().max(0) as u32,
    )
}

/// The `tracing` sink `Publisher`/`LoggingConsumer` expect — Rust's
/// shape of upstream's injected `*slog.Logger`.
struct TracingEventLog;

impl EventLog for TracingEventLog {
    fn info(&self, message: &'static str, fields: &[(&'static str, String)]) {
        for (key, value) in fields {
            tracing::info!(%key, %value, "kernel: {message}");
        }
        if fields.is_empty() {
            tracing::info!("kernel: {message}");
        }
    }

    fn warn(&self, message: &'static str, fields: &[(&'static str, String)]) {
        for (key, value) in fields {
            tracing::warn!(%key, %value, "kernel: {message}");
        }
        if fields.is_empty() {
            tracing::warn!("kernel: {message}");
        }
    }
}

// ---------------------------------------------------------------------------
// schedulerCompositionRequest / schedulerCapability / composeScheduler
// ---------------------------------------------------------------------------

/// `schedulerCompositionRequest` — everything [`compose_scheduler`]
/// wires. Optional seams omit their component so composition tests
/// need no PG.
pub struct SchedulerCompositionRequest {
    /// The validated environment.
    pub config: SchedulerConfig,
    /// The durable substrate every component shares; required when
    /// `config.enabled`. Production passes the postgres adapter.
    pub store: Option<Arc<PgSchedulerStore>>,
    /// Invokes the harness launch machinery; `None` selects the
    /// documented [`StubLauncher`] stand-in — the only implementation
    /// Slice 2B ships, acceptable only because the whole stack is
    /// behind the gate (see `StubLauncher`'s own doc: no harness
    /// process runs).
    pub launcher: Option<SchedulerLauncher>,
    /// The slice-2C janitor's store (checkpoint `CollectStore`).
    /// Production passes the postgres adapter; `None` omits the
    /// janitor component so composition tests need no PG.
    pub checkpoint_gc: Option<PgCheckpointStore>,
    /// The slice-2D deadline substrate the timeout sweeper drives
    /// (`central_retry::port::Store` — `sweep_timeouts`; the same
    /// postgres scheduler store in production). `None` omits the
    /// component — the node/workflow timeout hierarchy then never
    /// fires.
    pub timeout_sweep: Option<PgSchedulerStore>,
    /// The `event_outbox` drain surface the slice-2D publisher drives
    /// (the postgres eventjournal store in production). `None` omits
    /// the component.
    pub outbox_drain: Option<PgEventJournalStore>,
    /// Receives every drained event at-least-once (each must dedupe on
    /// `event_id` per `central_eventjournal::port::Consumer`). `None`
    /// installs the shipped [`LoggingConsumer`] feed.
    pub outbox_consumers: Option<Vec<Arc<dyn Consumer>>>,
}

/// `schedulerCapability` — serve's Slice-2B scheduler stack: the
/// startup reconciler — a preflight step, deliberately not a component
/// — plus the worker, sweeper and claim loop as kernel components.
#[derive(Default)]
pub struct SchedulerCapability {
    reconciler: Option<Arc<Reconciler<Arc<PgSchedulerStore>>>>,
    components: Vec<Box<dyn Component>>,
    worker_id: Option<WorkerId>,
}

impl SchedulerCapability {
    /// `Preflight` — the startup reconciler for serve's recovery gate:
    /// reconcile-before-reinvoke (spec-2 decision 9) must complete
    /// before the claim loop accepts work, and kernel preflights run
    /// before any component starts. `None` while the gate is off.
    #[must_use]
    pub fn preflight(&self) -> Option<Arc<Reconciler<Arc<PgSchedulerStore>>>> {
        self.reconciler.clone()
    }

    /// `Components` — the scheduler's kernel components in start order:
    /// worker, sweeper, claim loop, then the optional janitor, timeout
    /// sweeper and outbox publisher — or empty while the gate is off.
    pub fn take_components(&mut self) -> Vec<Box<dyn Component>> {
        std::mem::take(&mut self.components)
    }

    /// The generated worker id the worker and claim loop share.
    #[must_use]
    pub const fn worker_id(&self) -> Option<WorkerId> {
        self.worker_id
    }
}

/// `composeScheduler` — builds the capability. The gate being off
/// yields a valid empty capability — no preflight, no components — so
/// the default serve path is untouched. When the gate is on, the store
/// and the validated config are required, and the launcher defaults to
/// the stub with a loud log line.
///
/// # Errors
/// `scheduler_config_invalid` when the gate is on but the store is
/// absent or the scratch config fails the provisioner's shape checks.
pub fn compose_scheduler(req: SchedulerCompositionRequest) -> Result<SchedulerCapability, Failure> {
    let mut cap = SchedulerCapability::default();
    if !req.config.enabled {
        return Ok(cap);
    }
    let Some(store) = req.store else {
        return Err(config_err(
            "scheduler composition: a store is required when the scheduler is enabled",
        ));
    };
    let prov = DispatchProvisioner::new(&req.config.scratch_root, &req.config.source_repo)
        .map_err(|f| config_err(format!("scheduler composition: {}", f.message())))?;
    let launcher = req.launcher.unwrap_or_else(|| {
        // The stub confirms a session id for a harness process nothing
        // launches; it is honest only behind the gate.
        tracing::warn!("scheduler launch seam is the stub launcher -- no harness process runs");
        SchedulerLauncher::Stub(StubLauncher::new())
    });
    // The claim loop and the worker share one worker id: it is
    // generated here (not left to Worker.run) so the loop can claim
    // for it before the worker component registers.
    let worker_id = WorkerId::new();
    // The worker advertises only what the provisioner can satisfy: a
    // deployment without a source repository cannot run 'worktree'
    // nodes, and claiming one would only churn
    // WORKSPACE_PROVISION_FAILED attempts.
    let workspace_kinds = advertised_workspace_kinds(&req.config);
    let worker = Arc::new({
        let mut worker = Worker::new(store.clone(), SENTINEL_WORKSPACE_ID);
        worker.worker_id = Some(worker_id);
        worker.harness_kinds = scheduler_launchable_harnesses();
        worker.workspace_kinds = workspace_kinds;
        worker.max_concurrent_attempts = SUPPORTED_MAX_PARALLEL_SESSIONS;
        worker
    });
    let dispatcher = Dispatcher::new(store.clone(), prov, launcher);
    let claim_loop = Arc::new(ClaimLoop::new(store.clone(), dispatcher, worker_id));
    let sweeper = Arc::new(Sweeper::new(store.clone()));
    cap.worker_id = Some(worker_id);
    cap.reconciler = Some(Arc::new(Reconciler::new(store.clone())));
    let mut components: Vec<Box<dyn Component>> = vec![
        Box::new(SchedulerWorkerComponent {
            worker: worker.clone(),
        }),
        Box::new({
            let sweeper = sweeper.clone();
            TickedPassComponent::new(
                "scheduler_lease_sweeper",
                to_std(sweeper.tick_interval()),
                move || {
                    let sweeper = sweeper.clone();
                    Box::pin(async move { sweeper.sweep_once().await })
                },
            )
        }),
        Box::new(SchedulerClaimLoopComponent {
            claim_loop,
            dispatches: JoinSet::new(),
        }),
    ];
    // The checkpoint janitor (slice 2C, P2C05) rides the same gate:
    // resume_checkpoints rows only exist for Phase-2 runs.
    if let Some(gc) = req.checkpoint_gc {
        components.push(Box::new(crate::checkpoint_compose::janitor_component(gc)));
    }
    // The slice-2D timeout sweeper (P2D03) rides the same gate: it
    // drives the store's `sweep_timeouts` so node and workflow
    // deadline bounds fire without a dispatcher on the write path.
    // Kill decisions stay fail-closed through the store's Killer seam,
    // which the composition root wires to the documented unconfirmed
    // boundary.
    if let Some(timeout_store) = req.timeout_sweep {
        components.push(Box::new(crate::retry_compose::timeout_sweeper_component(
            timeout_store,
        )));
    }
    // The slice-2D outbox publisher (P2D06) drains event_outbox in
    // process (spec-5 OQ-1): transitions never depend on publication,
    // so a stalled drain degrades feeds, never correctness.
    if let Some(drain) = req.outbox_drain {
        let consumers = req.outbox_consumers.unwrap_or_else(|| {
            vec![Arc::new(LoggingConsumer {
                log: Some(Arc::new(TracingEventLog)),
            }) as Arc<dyn Consumer>]
        });
        let publisher = Arc::new({
            let mut publisher = Publisher::new(drain);
            publisher.consumers = consumers;
            publisher.log = Some(Arc::new(TracingEventLog));
            publisher
        });
        let interval = publisher.interval;
        components.push(Box::new(TickedPassComponent::new(
            "event_outbox_publisher",
            to_std(if interval <= Duration::ZERO {
                DEFAULT_PUBLISH_INTERVAL
            } else {
                interval
            }),
            move || {
                let publisher = publisher.clone();
                Box::pin(async move { publisher.publish_once().await })
            },
        )));
    }
    cap.components = components;
    Ok(cap)
}

// ---------------------------------------------------------------------------
// Tests — the port of upstream scheduler_composition_test.go
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use sqlx::postgres::PgPoolOptions;

    /// `loadSchedulerConfig` — the full upstream table: gate values,
    /// scratch and source-repo shape rules, and the stub gate.
    #[test]
    fn load_scheduler_config_table() {
        let scratch = "/var/lib/central-ph2";
        let repo = "/srv/central-repo";
        struct Case {
            name: &'static str,
            env: Vec<(&'static str, &'static str)>,
            want_err: bool,
            check: Box<dyn Fn(&SchedulerConfig) + Send>,
        }
        let cases: Vec<Case> = vec![
            Case {
                name: "unset gate leaves the stack off",
                env: vec![],
                want_err: false,
                check: Box::new(|cfg| assert!(!cfg.enabled)),
            },
            Case {
                name: "gate zero leaves the stack off and ignores the rest",
                env: vec![(ENV_SCHEDULER_ENABLED, "0")],
                want_err: false,
                check: Box::new(|cfg| assert!(!cfg.enabled)),
            },
            Case {
                name: "invalid gate value refuses",
                env: vec![(ENV_SCHEDULER_ENABLED, "yes")],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "enabled without a scratch root refuses",
                env: vec![(ENV_SCHEDULER_ENABLED, "1")],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "enabled with a relative scratch root refuses",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, "relative/dir"),
                ],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "enabled with the filesystem root as scratch refuses",
                env: vec![(ENV_SCHEDULER_ENABLED, "1"), (ENV_SCHEDULER_SCRATCH, "/")],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "enabled with an unclean scratch root refuses",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, "/tmp/../tmp"),
                ],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "a relative source repo refuses",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                    (ENV_SCHEDULER_SOURCE_REPO, "repo"),
                ],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "enabled with a scratch root alone composes directory-only",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                ],
                want_err: false,
                check: Box::new(move |cfg| {
                    assert!(cfg.enabled);
                    assert_eq!(cfg.scratch_root, scratch);
                    assert_eq!(cfg.source_repo, "");
                }),
            },
            Case {
                name: "enabled with both paths composes fully",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                    (ENV_SCHEDULER_SOURCE_REPO, repo),
                ],
                want_err: false,
                check: Box::new(move |cfg| {
                    assert!(cfg.enabled);
                    assert_eq!(cfg.scratch_root, scratch);
                    assert_eq!(cfg.source_repo, repo);
                }),
            },
            // The stub gate (upstream TestLoadSchedulerConfigStubGate).
            Case {
                name: "enabled without the stub flag forbids the stub",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                ],
                want_err: false,
                check: Box::new(|cfg| assert!(!cfg.allow_stub)),
            },
            Case {
                name: "enabled with stub zero forbids the stub",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                    (ENV_SCHEDULER_ALLOW_STUB, "0"),
                ],
                want_err: false,
                check: Box::new(|cfg| assert!(!cfg.allow_stub)),
            },
            Case {
                name: "enabled with stub one allows the stub",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                    (ENV_SCHEDULER_ALLOW_STUB, "1"),
                ],
                want_err: false,
                check: Box::new(|cfg| assert!(cfg.allow_stub)),
            },
            Case {
                name: "an invalid stub value refuses",
                env: vec![
                    (ENV_SCHEDULER_ENABLED, "1"),
                    (ENV_SCHEDULER_SCRATCH, scratch),
                    (ENV_SCHEDULER_ALLOW_STUB, "yes"),
                ],
                want_err: true,
                check: Box::new(|_| {}),
            },
            Case {
                name: "gate off ignores the stub flag",
                env: vec![(ENV_SCHEDULER_ALLOW_STUB, "1")],
                want_err: false,
                check: Box::new(|cfg| assert!(!cfg.enabled && !cfg.allow_stub)),
            },
            Case {
                name: "gate off ignores an invalid stub value",
                env: vec![(ENV_SCHEDULER_ALLOW_STUB, "bogus")],
                want_err: false,
                check: Box::new(|cfg| assert!(!cfg.enabled && !cfg.allow_stub)),
            },
        ];
        for case in cases {
            let env: BTreeMap<&str, &str> = case.env.iter().copied().collect();
            let outcome = SchedulerConfig::load(|k| env.get(k).copied().unwrap_or("").to_string());
            if case.want_err {
                let err = match outcome {
                    Err(e) => e,
                    Ok(_) => unreachable!("{}: expected a config error", case.name),
                };
                assert_eq!(
                    err.code(),
                    CODE_SCHEDULER_CONFIG,
                    "{}: error not marked scheduler config invalid",
                    case.name
                );
                continue;
            }
            let cfg = outcome.unwrap_or_else(|f| unreachable!("{}: {f}", case.name));
            (case.check)(&cfg);
        }
    }

    /// `TestComposeSchedulerGateOffProducesNothing` — without the gate
    /// the capability composes empty: no preflight, no components, no
    /// worker id, and no store is required.
    #[test]
    fn compose_scheduler_gate_off_produces_nothing() {
        let mut cap = compose_scheduler(SchedulerCompositionRequest {
            config: SchedulerConfig::default(),
            store: None,
            launcher: None,
            checkpoint_gc: None,
            timeout_sweep: None,
            outbox_drain: None,
            outbox_consumers: None,
        })
        .expect("a disabled scheduler failed composition");
        assert!(
            cap.preflight().is_none(),
            "disabled scheduler produced a preflight"
        );
        assert!(cap.take_components().is_empty());
        assert!(cap.worker_id().is_none());
    }

    /// A lazy pool — the composition constructors never touch the
    /// connection, so a dead DSN is enough (upstream passed fakes;
    /// Rust's concrete stores only need the pool object).
    fn lazy_pool() -> PgPool {
        PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/central")
            .expect("lazy pool")
    }

    fn enabled_config(source_repo: &str) -> SchedulerConfig {
        SchedulerConfig {
            enabled: true,
            scratch_root: "/var/lib/central-ph2".to_string(),
            source_repo: source_repo.to_string(),
            allow_stub: false,
        }
    }

    /// `TestComposeSchedulerGateOnWiresTheFivePieces` — enabled needs a
    /// store, the reconciler preflight composes, and the components
    /// land in upstream's order: worker, lease sweeper, claim loop,
    /// then the optional janitor / timeout sweeper / outbox publisher.
    #[tokio::test(flavor = "current_thread")]
    async fn compose_scheduler_gate_on_wires_the_pieces() {
        // A missing store refuses composition.
        let err = match compose_scheduler(SchedulerCompositionRequest {
            config: enabled_config(""),
            store: None,
            launcher: None,
            checkpoint_gc: None,
            timeout_sweep: None,
            outbox_drain: None,
            outbox_consumers: None,
        }) {
            Err(e) => e,
            Ok(_) => unreachable!("an enabled scheduler composed without a store"),
        };
        assert_eq!(err.code(), CODE_SCHEDULER_CONFIG);
        assert!(err.message().contains("store is required"));

        // Reconciler preflight plus the always-on three components.
        let pool = lazy_pool();
        let mut cap = compose_scheduler(SchedulerCompositionRequest {
            config: enabled_config(""),
            store: Some(Arc::new(new_scheduler_store(pool.clone(), None))),
            launcher: None,
            checkpoint_gc: None,
            timeout_sweep: None,
            outbox_drain: None,
            outbox_consumers: None,
        })
        .expect("compose");
        assert!(cap.preflight().is_some(), "no reconciler preflight");
        assert!(cap.worker_id().is_some(), "no generated worker id");
        assert_eq!(
            cap.take_components().len(),
            3,
            "worker, lease sweeper, claim loop"
        );

        // The slice-2C/2D additions ride the same gate.
        let mut cap = compose_scheduler(SchedulerCompositionRequest {
            config: enabled_config(""),
            store: Some(Arc::new(new_scheduler_store(pool.clone(), None))),
            launcher: None,
            checkpoint_gc: Some(PgCheckpointStore::new(pool.clone())),
            timeout_sweep: Some(new_scheduler_store(pool.clone(), None)),
            outbox_drain: Some(PgEventJournalStore::new(pool)),
            outbox_consumers: None,
        })
        .expect("compose with the optional stores");
        assert_eq!(
            cap.take_components().len(),
            6,
            "worker, sweeper, claim loop, janitor, timeout sweeper, publisher"
        );
    }

    /// The worker advertises only what the provisioner can satisfy:
    /// `directory` alone without a source repo, `worktree` + `directory`
    /// with one — upstream's `worker capabilities follow the source
    /// repo` subtest, pinned through the kinds the composition selects.
    #[test]
    fn workspace_kinds_follow_the_source_repo() {
        assert_eq!(
            advertised_workspace_kinds(&enabled_config("")),
            vec!["directory".to_string()]
        );
        assert_eq!(
            advertised_workspace_kinds(&enabled_config("/srv/repo")),
            vec!["worktree".to_string(), "directory".to_string()]
        );
    }

    /// `scheduler_launchable_harnesses` — the registration handshake
    /// advertises the one harness this instance ships.
    #[test]
    fn launchable_harnesses_is_the_shipped_adapter() {
        assert_eq!(scheduler_launchable_harnesses(), vec!["claude-code"]);
    }
}
