//! The dispatcher — the port of `internal/harness/app/dispatcher.go`
//! (harness phase 3a decisions 1, 9, 10, 11, 13 and review T-I2). It
//! starts dispatchable Runs under a bounded concurrency: before each
//! claim round it checks free space and probes the harness; not logged
//! in, an unreachable launcher or low disk pause it — it claims
//! nothing, fails nothing, and re-checks every `pause_retry`. On its
//! first start it asks the launcher about every ambiguous attempt's
//! scope and kills a survivor, then checks and probes once, so serve
//! started with the launcher down reports paused at once; while
//! running it probes only when there is a Run to claim. On stop it
//! claims nothing more and cancels its attempts, each of which closes
//! its lifeline, then waits at most `shutdown_budget`. A Run whose
//! start is refused cools down (exponential back-off, bounded set) and
//! is skipped meanwhile, so it neither blocks the Runs listed after it
//! nor makes the dispatcher re-probe in a loop.
//!
//! CONCURRENCY (no capability-owned executor): upstream runs each
//! attempt on its own goroutine under a `WaitGroup`. This crate owns no
//! runtime, so [`Dispatcher::run`] multiplexes the in-flight attempt
//! futures *inside* its own polls — the same standing-arm pattern the
//! orchestrator uses — which needs no spawn at all. Kernels that want
//! real task-per-attempt fan-out instead drive [`Dispatcher::sweep`]
//! once, then loop [`Dispatcher::round`] + [`Dispatcher::sleep`],
//! spawning one task per [`Spawned`] running
//! [`Dispatcher::attempt`], and end with [`Dispatcher::shutdown`]. A
//! `Spawned` MUST be driven through `attempt` to completion: the claim
//! is already booked in `inflight` (upstream marks it in `round`), and
//! `attempt`'s tail runs `finish`'s bookkeeping.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, RunId, StepAttemptId, TaskId};
use time::{Duration, OffsetDateTime};

use crate::domain::{self, vocab};
use crate::port::{Adapter, PortFuture, ProcessLauncher, RecoveryCursor, RecoveryStore};

use super::orchestrator::Orchestrator;
use super::ports::{
    CancelSignal, Clock, DispatchableRun, HarnessResult, Milestone, MilestoneKind, Outcome,
    RunLifecycle, TaskEventSink, Ticker, WorkspaceProvisioner, codes,
};

/// Dispatcher defaults (decisions 1, 11 and 13) — upstream's const
/// block.
pub const MAX_CONCURRENCY: usize = 4;
/// `DefaultPollInterval`.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::seconds(2);
/// `DefaultPauseRetry`.
pub const DEFAULT_PAUSE_RETRY: Duration = Duration::seconds(30);
/// `DefaultShutdownBudget`.
pub const DEFAULT_SHUTDOWN_BUDGET: Duration = Duration::seconds(5);
/// `probeBudget` — bounds one harness probe and one launcher `is_alive`
/// of the startup sweep.
const PROBE_BUDGET: Duration = Duration::seconds(60);
/// `sweepKillBudget` — bounds one startup-sweep `kill_scope`.
const SWEEP_KILL_BUDGET: Duration = Duration::seconds(90);
/// `DefaultNotStartableCooldown` and
/// `DEFAULT_MAX_NOT_STARTABLE_COOLDOWN` bound the exponential back-off
/// of a Run whose start was refused (review T-I2): 30 s, doubling per
/// refusal, at most 10 min.
pub const DEFAULT_NOT_STARTABLE_COOLDOWN: Duration = Duration::seconds(30);
/// `DefaultMaxNotStartableCooldown`.
pub const DEFAULT_MAX_NOT_STARTABLE_COOLDOWN: Duration = Duration::minutes(10);
/// `maxCoolingRuns` bounds the cool-down set; the entry that expires
/// first is evicted when it is full.
const MAX_COOLING_RUNS: usize = 256;
/// `maxHeldRuns` bounds each of the lost and settle-failed sets; the
/// oldest entry is evicted when one is full. Forgetting a Run there is
/// safe: an invoked Run is never listed dispatchable again (only a
/// queued Run or a prepared successor is), and each such Run needs a
/// restart anyway.
const MAX_HELD_RUNS: usize = 256;
/// The `ListDispatchable` page bound — upstream's `if limit > 100`.
const MAX_LIST_LIMIT: usize = 100;

/// The sweep failure the launcher caused — upstream's wrapped
/// `errLauncher`.
const ERR_LAUNCHER: &str = "harness_app_launcher_unreachable";

vocab! {
    /// The dispatcher's lifecycle state, shown at `/health/harness` —
    /// upstream `DispatcherState`.
    DispatcherState {
        /// `disabled`.
        Disabled => "disabled",
        /// `starting`.
        Starting => "starting",
        /// `running`.
        Running => "running",
        /// `paused`.
        Paused => "paused",
        /// `stopped`.
        Stopped => "stopped",
    }
}

vocab! {
    /// Why the dispatcher claims nothing (decisions 11, 14) —
    /// upstream `PauseReason`.
    PauseReason {
        /// `not_logged_in`.
        NotLoggedIn => "not_logged_in",
        /// `launcher_unreachable`.
        LauncherUnreachable => "launcher_unreachable",
        /// `low_disk`.
        LowDisk => "low_disk",
    }
}

/// A snapshot of the dispatcher for health and the UI banner —
/// upstream `Status`. `lost` lists Runs whose lease was lost while
/// serve kept running (decision 10): they stay running until the next
/// restart reconciles them. `settle_failed` lists Runs whose harness
/// ended but whose settlement could not be written
/// (`HarnessResult::settle_failed`); they too wait for the next
/// restart. Neither is re-dispatched.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    /// The lifecycle state.
    pub state: DispatcherState,
    /// The pause reason, when `state` is [`DispatcherState::Paused`].
    pub pause: PauseReason,
    /// When the state last changed.
    pub since: OffsetDateTime,
    /// In-flight attempts.
    pub active: usize,
    /// Runs that lost their lease, sorted by id.
    pub lost: Vec<RunId>,
    /// Runs whose settlement could not be written, sorted by id.
    pub settle_failed: Vec<RunId>,
}

impl Status {
    /// `NeedsRestart` — some Run waits for the next restart's
    /// reconciliation (lost or settle-failed).
    #[must_use]
    pub fn needs_restart(&self) -> bool {
        !self.lost.is_empty() || !self.settle_failed.is_empty()
    }

    /// `Paused` — the dispatcher is paused.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.state == DispatcherState::Paused
    }
}

/// `DispatcherConfig` — upstream `DispatcherConfig` minus its `Logger`
/// field, which the Rust port carries on [`DispatcherDeps::logger`]
/// as the [`DispatchLog`] port. Zero durations take the defaults.
#[derive(Debug)]
pub struct DispatcherConfig {
    /// The number of attempts run at once, `1..=MAX_CONCURRENCY`.
    pub concurrency: usize,
    /// The probe's launch environment (the orchestrator's).
    pub launch_env: std::collections::BTreeMap<String, String>,
    /// Between claim rounds.
    pub poll_interval: Duration,
    /// Between admission re-checks while paused.
    pub pause_retry: Duration,
    /// Bounds the drain of in-flight attempts at stop.
    pub shutdown_budget: Duration,
    /// Bounds one harness probe and one launcher `is_alive` of the
    /// startup sweep; zero takes [`PROBE_BUDGET`].
    pub probe_budget: Duration,
    /// The first back-off of a Run whose start was refused; each
    /// further refusal doubles it up to `max_not_startable_cooldown`.
    pub not_startable_cooldown: Duration,
    /// The back-off cap.
    pub max_not_startable_cooldown: Duration,
}

/// `DispatcherConfig.Logger` — upstream's `*slog.Logger` shrunk to the
/// two levels the dispatcher logs at. Each call carries the message
/// and its `slog`-style fields; sinks format as they please.
/// [`DiscardLog`] is the nil-logger default.
pub trait DispatchLog: Send + Sync + 'static {
    /// `logger.Warn(msg, fields...)`.
    fn warn(&self, msg: &str, fields: &[(&str, String)]);
    /// `logger.Info(msg, fields...)` — default: same as `warn`.
    fn info(&self, msg: &str, fields: &[(&str, String)]) {
        self.warn(msg, fields);
    }
}

/// `slog.New(slog.NewTextHandler(io.Discard, nil))` — the default.
pub struct DiscardLog;

impl DispatchLog for DiscardLog {
    fn warn(&self, _msg: &str, _fields: &[(&str, String)]) {}
}

/// Runs one dispatchable Run — upstream `app.AttemptRunner`;
/// [`Orchestrator`] implements it. The `Arc` receiver plus an owned
/// `Arc<dyn CancelSignal>` make the returned future `'static`, so the
/// kernel can spawn it; upstream's `ctx` is `stop`.
pub trait AttemptRunner: Send + Sync + 'static {
    /// Upstream `Run(ctx, run, harnessVersion)` — the body of the
    /// per-attempt goroutine.
    fn run(
        self: Arc<Self>,
        run: DispatchableRun,
        harness_version: String,
        stop: Arc<dyn CancelSignal>,
    ) -> PortFuture<'static, HarnessResult>;
}

impl AttemptRunner for Orchestrator {
    fn run(
        self: Arc<Self>,
        run: DispatchableRun,
        harness_version: String,
        stop: Arc<dyn CancelSignal>,
    ) -> PortFuture<'static, HarnessResult> {
        Box::pin(async move { self.run_dispatchable(run, &harness_version, &*stop).await })
    }
}

/// `NewDispatcher`'s parameters — upstream's dependency list.
pub struct DispatcherDeps {
    /// `lifecycle` — the execution/task side of claims.
    pub lifecycle: Arc<dyn RunLifecycle>,
    /// `runner` — runs one claimed attempt.
    pub runner: Arc<dyn AttemptRunner>,
    /// `adapter` — the harness adapter (probed before every claim).
    pub adapter: Arc<dyn Adapter>,
    /// `launcher` — the process boundary (the startup sweep).
    pub launcher: Arc<dyn ProcessLauncher>,
    /// `recovery` — the recovery-authority candidate listing.
    pub recovery: Arc<dyn RecoveryStore>,
    /// `workspaces` — the free-space check.
    pub workspaces: Arc<dyn WorkspaceProvisioner>,
    /// `events` — the pause/resume milestone sink.
    pub events: Arc<dyn TaskEventSink>,
    /// `clock` — timestamps.
    pub clock: Arc<dyn Clock>,
    /// `ticker` — timers (poll, pause retry, budgets). The Rust form of
    /// upstream's `time.NewTimer`/`context.WithTimeout` uses.
    pub ticker: Arc<dyn Ticker>,
    /// `cfg.Logger` — warn/info records (pauses, sweep, outcomes).
    pub logger: Arc<dyn DispatchLog>,
    /// `cfg` — limits and timings.
    pub cfg: DispatcherConfig,
}

/// A Run `round` claimed for the caller to drive — the fan-out seam.
/// Opaque: hand it to [`Dispatcher::attempt`].
#[derive(Debug)]
pub struct Spawned {
    run: DispatchableRun,
    harness_version: String,
}

impl Spawned {
    /// The claimed Run's id — for the caller's log lines.
    #[must_use]
    pub fn run_id(&self) -> RunId {
        self.run.run_id
    }
}

/// What one [`Dispatcher::round`] produced — the kernel fan-out seam.
#[derive(Debug)]
pub struct Round {
    /// How long to wait before the next round — the [`Dispatcher::sleep`]
    /// bound, which also returns early on a completed attempt
    /// (upstream's `freed` wake) or a stop.
    pub wait: Duration,
    /// Runs claimed this round. Each MUST be driven through
    /// [`Dispatcher::attempt`] — the claim is already booked, and only
    /// `attempt`'s `finish` frees it.
    pub spawned: Vec<Spawned>,
    /// The `freed` epoch at this round's start — [`Dispatcher::sleep`]
    /// wakes on a finish that landed *during* the round too, as a token
    /// already queued in upstream's buffered `freed` channel does.
    freed_epoch: u64,
}

/// The mutable dispatcher state — upstream's `d.mu` block plus the
/// wake/wait machinery the Rust port needs.
struct Inner {
    status: Status,
    /// The pause episode a milestone key is stamped with.
    episode: OffsetDateTime,
    /// `d.inflight` — claimed Runs not yet finished.
    inflight: HashSet<RunId>,
    /// The local driver's attempt futures — empty in kernel-driven
    /// mode (spawned futures live on kernel tasks).
    futures: Vec<PortFuture<'static, HarnessResult>>,
    /// `d.lost`.
    lost: HashMap<RunId, OffsetDateTime>,
    /// `d.settleFailed`.
    settle_failed: HashMap<RunId, OffsetDateTime>,
    /// `d.lastProbe`.
    last_probe: OffsetDateTime,
    /// `d.notified` — Tasks told about the current pause episode.
    notified: HashMap<TaskId, DispatchableRun>,
    /// `d.cooling` — refused Runs and their back-off.
    cooling: HashMap<RunId, Cooldown>,
    /// Bumped by `finish` for every non-`NotStarted` outcome — the
    /// `freed` channel's counter form.
    freed_epoch: u64,
    /// Wakers of `sleep`/`shutdown` waiters (kernel-driven mode).
    wakers: Vec<Waker>,
}

/// `cooldown` — a refused Run's back-off: skipped until `until`; the
/// next refusal waits twice `backoff`.
#[derive(Debug, Clone, Copy)]
struct Cooldown {
    until: OffsetDateTime,
    backoff: Duration,
}

/// The shared half [`Dispatcher::attempt`]'s spawned futures own.
struct Shared {
    deps: DispatcherDeps,
    inner: Mutex<Inner>,
}

/// `app.Dispatcher`.
pub struct Dispatcher {
    shared: Arc<Shared>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            status: Status::default(),
            episode: domain::ZERO_TIME,
            inflight: HashSet::new(),
            futures: Vec::new(),
            lost: HashMap::new(),
            settle_failed: HashMap::new(),
            last_probe: domain::ZERO_TIME,
            notified: HashMap::new(),
            cooling: HashMap::new(),
            freed_epoch: 0,
            wakers: Vec::new(),
        }
    }
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: DispatcherState::default(),
            pause: PauseReason::default(),
            since: crate::domain::ZERO_TIME,
            active: 0,
            lost: Vec::new(),
            settle_failed: Vec::new(),
        }
    }
}

impl Dispatcher {
    /// `NewDispatcher` — validates dependencies and configuration.
    pub fn new(deps: DispatcherDeps) -> Result<Self, Failure> {
        let mut cfg = deps.cfg;
        if cfg.concurrency == 0 || cfg.concurrency > MAX_CONCURRENCY {
            return Err(Failure::invalid(
                domain::codes::INVALID_ATTEMPT,
                format!("harness app: concurrency must be 1 to {MAX_CONCURRENCY}"),
            ));
        }
        crate::env::validate_launch_env(
            &cfg.launch_env,
            &deps
                .adapter
                .env_extras()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )?;
        if cfg.poll_interval <= Duration::ZERO {
            cfg.poll_interval = DEFAULT_POLL_INTERVAL;
        }
        if cfg.pause_retry <= Duration::ZERO {
            cfg.pause_retry = DEFAULT_PAUSE_RETRY;
        }
        if cfg.shutdown_budget <= Duration::ZERO {
            cfg.shutdown_budget = DEFAULT_SHUTDOWN_BUDGET;
        }
        if cfg.probe_budget <= Duration::ZERO {
            cfg.probe_budget = PROBE_BUDGET;
        }
        if cfg.not_startable_cooldown <= Duration::ZERO {
            cfg.not_startable_cooldown = DEFAULT_NOT_STARTABLE_COOLDOWN;
        }
        if cfg.max_not_startable_cooldown < cfg.not_startable_cooldown {
            cfg.max_not_startable_cooldown = DEFAULT_MAX_NOT_STARTABLE_COOLDOWN;
            if cfg.max_not_startable_cooldown < cfg.not_startable_cooldown {
                cfg.max_not_startable_cooldown = cfg.not_startable_cooldown;
            }
        }
        let now = deps.clock.now();
        let shared = Shared {
            deps: DispatcherDeps { cfg, ..deps },
            inner: Mutex::new(Inner {
                status: Status {
                    state: DispatcherState::Starting,
                    since: now,
                    ..Status::default()
                },
                ..Inner::default()
            }),
        };
        Ok(Self {
            shared: Arc::new(shared),
        })
    }

    /// `Status` — a snapshot of the dispatcher.
    #[must_use]
    pub fn status(&self) -> Status {
        match self.shared.inner.lock() {
            Ok(g) => {
                let mut out = g.status.clone();
                out.active = g.inflight.len();
                out.lost = sorted_runs(&g.lost);
                out.settle_failed = sorted_runs(&g.settle_failed);
                out
            }
            Err(_) => Status::default(),
        }
    }

    /// `Run` — dispatches until `stop` is cancelled, then shuts down
    /// within `shutdown_budget`. `Ok(())` on a clean stop; `Err` only
    /// when attempts outlived the budget.
    ///
    /// CONCURRENCY: this is the complete local driver — the in-flight
    /// attempt futures are polled inside its own `poll_fn`s, so it
    /// needs no spawned tasks. A kernel wanting task-per-attempt
    /// fan-out uses [`sweep`](Self::sweep)/[`round`](Self::round)/
    /// [`attempt`](Self::attempt)/[`shutdown`](Self::shutdown)
    /// directly instead.
    pub async fn run(&self, stop: Arc<dyn CancelSignal>) -> Result<(), Failure> {
        let stop_dyn: &dyn CancelSignal = &*stop;
        while !stop_dyn.is_cancelled() {
            match self.sweep(stop_dyn).await {
                Ok(()) => {
                    // Check and probe once before the first round, so
                    // a launcher that is down (or a harness not logged
                    // in) shows as paused at once rather than at the
                    // first dispatchable Run. While paused, round
                    // re-probes every PauseRetry even with an empty
                    // queue.
                    self.admit(&[], stop_dyn).await;
                    break;
                }
                Err(e) => {
                    if stop_dyn.is_cancelled() {
                        break;
                    }
                    if e.code() == ERR_LAUNCHER {
                        self.shared.deps.logger.warn(
                            "harness startup sweep could not reach the launcher",
                            &[("error", e.to_string())],
                        );
                        self.mark_probed();
                        self.pause(PauseReason::LauncherUnreachable, &[], None)
                            .await;
                        self.sleep_for(self.shared.deps.cfg.pause_retry, stop_dyn)
                            .await;
                    } else {
                        self.shared.deps.logger.warn(
                            "harness startup sweep could not list ambiguous attempts",
                            &[("error", e.to_string())],
                        );
                        self.sleep_for(self.shared.deps.cfg.poll_interval, stop_dyn)
                            .await;
                    }
                }
            }
        }
        while !stop_dyn.is_cancelled() {
            let mut round = self.round(stop_dyn).await;
            for s in round.spawned.drain(..) {
                self.spawn_local(s, stop.clone());
            }
            self.sleep(&round, stop_dyn).await;
        }
        self.shutdown().await
    }

    /// The startup sweep — upstream `sweep` (decision 9): asks the
    /// launcher about each ambiguous attempt's scope and kills a
    /// survivor. Only the dispatcher's first start does this; the
    /// startup reconciler is DB-only. Errors wrap [`ERR_LAUNCHER`]
    /// when the launcher caused them (the driver pauses on them; a
    /// list failure retries at the poll interval).
    pub async fn sweep(&self, stop: &dyn CancelSignal) -> Result<(), Failure> {
        let launcher_err = |m: &str| {
            Failure::unavailable(
                ERR_LAUNCHER,
                format!("harness app: launcher unreachable: {m}"),
            )
        };
        let mut cursor = RecoveryCursor::default();
        loop {
            let page = match self
                .race(
                    stop,
                    self.shared
                        .deps
                        .recovery
                        .list_recovery_candidates(cursor, crate::port::MAX_RECOVERY_CANDIDATES),
                )
                .await
            {
                Sel::Done(Ok(p)) => p,
                Sel::Done(Err(e)) => return Err(e),
                Sel::Ended => {
                    return Err(Failure::cancelled(
                        codes::ATTEMPT_ENDED,
                        "dispatcher stop requested",
                    ));
                }
            };
            for c in &page {
                let a = &c.attempt;
                if a.state != domain::State::Ambiguous || a.sandbox_scope_id.is_empty() {
                    continue;
                }
                let alive = match self
                    .race(
                        stop,
                        bounded(
                            self.shared.deps.launcher.is_alive(&a.sandbox_scope_id),
                            self.shared
                                .deps
                                .ticker
                                .after(self.shared.deps.cfg.probe_budget),
                        ),
                    )
                    .await
                {
                    Sel::Ended => {
                        return Err(Failure::cancelled(
                            codes::ATTEMPT_ENDED,
                            "dispatcher stop requested",
                        ));
                    }
                    Sel::Done(Bounded::Elapsed) => {
                        return Err(launcher_err("alive probe timed out"));
                    }
                    Sel::Done(Bounded::Done(Err(e))) => {
                        return Err(launcher_err(e.message()));
                    }
                    Sel::Done(Bounded::Done(Ok(a))) => a,
                };
                if !alive {
                    continue;
                }
                self.shared.deps.logger.warn(
                    "harness scope of an ambiguous attempt survived a restart; killing it",
                    &[("attempt", a.id.to_string()), ("run", a.run_id.to_string())],
                );
                match self
                    .race(
                        stop,
                        bounded(
                            self.shared.deps.launcher.kill_scope(&a.sandbox_scope_id),
                            self.shared.deps.ticker.after(SWEEP_KILL_BUDGET),
                        ),
                    )
                    .await
                {
                    Sel::Ended => {
                        return Err(Failure::cancelled(
                            codes::ATTEMPT_ENDED,
                            "dispatcher stop requested",
                        ));
                    }
                    Sel::Done(Bounded::Elapsed) => {
                        return Err(launcher_err("kill timed out"));
                    }
                    Sel::Done(Bounded::Done(Err(e))) => {
                        return Err(launcher_err(e.message()));
                    }
                    Sel::Done(Bounded::Done(Ok(()))) => {}
                }
            }
            if page.len() < crate::port::MAX_RECOVERY_CANDIDATES {
                return Ok(());
            }
            let last = page[page.len() - 1].attempt.clone();
            cursor = RecoveryCursor {
                prepared_at: last.prepared_at,
                id: last.id,
            };
        }
    }

    /// One dispatch round — upstream `round` minus the per-attempt
    /// goroutine: it claims and books, and hands the caller the
    /// [`Spawned`] work plus the wait until the next round. In
    /// kernel-driven mode spawn one task per `spawned` running
    /// [`attempt`](Self::attempt); [`Dispatcher::run`] drives them
    /// locally.
    pub async fn round(&self, stop: &dyn CancelSignal) -> Round {
        // Baseline the wake epoch at the round's START: a `finish`
        // landing while the round runs must wake the following `sleep`
        // at once — upstream queues a token in the buffered `freed`
        // channel for exactly that.
        let freed_epoch = self.freed_epoch();
        let empty = |wait: Duration| Round {
            wait,
            spawned: Vec::new(),
            freed_epoch,
        };
        let (free, paused, since_probe, skip) = {
            let g = match self.shared.inner.lock() {
                Ok(g) => g,
                Err(_) => return empty(self.shared.deps.cfg.poll_interval),
            };
            let now = self.shared.deps.clock.now();
            let free = self
                .shared
                .deps
                .cfg
                .concurrency
                .saturating_sub(g.inflight.len());
            let paused = g.status.state == DispatcherState::Paused;
            let since_probe = now - g.last_probe;
            let mut skip = g.inflight.len() + g.lost.len() + g.settle_failed.len();
            for c in g.cooling.values() {
                if now < c.until {
                    skip += 1;
                }
            }
            (free, paused, since_probe, skip)
        };
        if free == 0 {
            return empty(self.shared.deps.cfg.poll_interval);
        }
        if paused && since_probe < self.shared.deps.cfg.pause_retry {
            return empty(self.shared.deps.cfg.pause_retry - since_probe);
        }
        let limit = (free + skip).min(MAX_LIST_LIMIT);
        let listed = match self
            .race(stop, self.shared.deps.lifecycle.list_dispatchable(limit))
            .await
        {
            Sel::Done(Ok(l)) => l,
            Sel::Done(Err(e)) => {
                if !stop.is_cancelled() {
                    self.shared
                        .deps
                        .logger
                        .warn("harness dispatch list failed", &[("error", e.to_string())]);
                }
                return empty(self.shared.deps.cfg.poll_interval);
            }
            Sel::Ended => return empty(self.shared.deps.cfg.poll_interval),
        };
        let mut candidates = self.filter(listed);
        if candidates.is_empty() && !paused {
            return empty(self.shared.deps.cfg.poll_interval);
        }
        let probe = match self.admit(&candidates, stop).await {
            Admit::Ended => return empty(self.shared.deps.cfg.poll_interval),
            Admit::Refused => return empty(self.shared.deps.cfg.pause_retry),
            Admit::Probed(p) => p,
        };
        candidates.truncate(free);
        let version = probe.harness_version;
        let spawned = candidates
            .into_iter()
            .map(|c| {
                if let Ok(mut g) = self.shared.inner.lock() {
                    g.inflight.insert(c.run_id);
                }
                Spawned {
                    run: c,
                    harness_version: version.clone(),
                }
            })
            .collect();
        Round {
            wait: self.shared.deps.cfg.poll_interval,
            spawned,
            freed_epoch,
        }
    }

    /// The body of upstream's per-attempt goroutine — `runner.Run`
    /// then `finish`. In kernel-driven mode spawn it on a task; a
    /// dropped future is upstream's goroutine abandoned at process
    /// end (the booking stays in `inflight`, so the Run is never
    /// re-dispatched and `shutdown` budgets out).
    pub fn attempt(
        &self,
        s: Spawned,
        stop: Arc<dyn CancelSignal>,
    ) -> PortFuture<'static, HarnessResult> {
        let shared = self.shared.clone();
        let c = s.run;
        let version = s.harness_version;
        Box::pin(async move {
            let res = shared
                .deps
                .runner
                .clone()
                .run(c.clone(), version, stop)
                .await;
            shared.finish(&c, res).await
        })
    }

    /// The local driver's spawn — pushes the attempt future into the
    /// shared vec `run` multiplexes.
    fn spawn_local(&self, s: Spawned, stop: Arc<dyn CancelSignal>) {
        let f = self.attempt(s, stop);
        if let Ok(mut g) = self.shared.inner.lock() {
            g.futures.push(f);
        }
    }

    /// `sleep` — waits `round.wait`, ending early on `stop` or on a
    /// completed attempt that was not a refused start (upstream's
    /// `freed` arm). The wake epoch is the round's own: a `finish`
    /// that landed while `round` ran still ends this sleep at once,
    /// as a token already queued in upstream's buffered `freed`
    /// channel does. Polls the local driver's in-flight futures — the
    /// only way they progress.
    pub async fn sleep(&self, round: &Round, stop: &dyn CancelSignal) {
        self.sleep_inner(round.freed_epoch, round.wait, stop).await
    }

    /// The sweep retries' wait — upstream passes a nil `freed` there:
    /// nothing can be in flight before the first `round`, so the wake
    /// epoch baselined at entry never moves.
    async fn sleep_for(&self, wait: Duration, stop: &dyn CancelSignal) {
        self.sleep_inner(self.freed_epoch(), wait, stop).await
    }

    async fn sleep_inner(&self, e0: u64, wait: Duration, stop: &dyn CancelSignal) {
        let mut timer = self.shared.deps.ticker.after(wait);
        let mut cancel = stop.cancelled();
        std::future::poll_fn(|cx| {
            self.poll_inflight(cx);
            {
                let mut g = match self.shared.inner.lock() {
                    Ok(g) => g,
                    Err(_) => return std::task::Poll::Ready(()),
                };
                if g.freed_epoch != e0 {
                    return std::task::Poll::Ready(());
                }
                g.wakers.push(cx.waker().clone());
            }
            if let std::task::Poll::Ready(()) = timer.as_mut().poll(cx) {
                return std::task::Poll::Ready(());
            }
            if let std::task::Poll::Ready(()) = cancel.as_mut().poll(cx) {
                return std::task::Poll::Ready(());
            }
            std::task::Poll::Pending
        })
        .await
    }

    /// `shutdown` — drains in-flight attempts, bounded by
    /// `shutdown_budget`. Sets `stopped` either way; `Err` only when
    /// attempts outlived the budget.
    pub async fn shutdown(&self) -> Result<(), Failure> {
        let mut timer = self
            .shared
            .deps
            .ticker
            .after(self.shared.deps.cfg.shutdown_budget);
        let exceeded = std::future::poll_fn(|cx| {
            self.poll_inflight(cx);
            {
                let mut g = match self.shared.inner.lock() {
                    Ok(g) => g,
                    Err(_) => return std::task::Poll::Ready(false),
                };
                if g.inflight.is_empty() && g.futures.is_empty() {
                    return std::task::Poll::Ready(false);
                }
                g.wakers.push(cx.waker().clone());
            }
            if let std::task::Poll::Ready(()) = timer.as_mut().poll(cx) {
                return std::task::Poll::Ready(true);
            }
            std::task::Poll::Pending
        })
        .await;
        let now = self.shared.deps.clock.now();
        if let Ok(mut g) = self.shared.inner.lock() {
            g.status = Status {
                state: DispatcherState::Stopped,
                since: now,
                ..Status::default()
            };
        }
        if exceeded {
            self.shared
                .deps
                .logger
                .warn("harness dispatcher shutdown budget exceeded", &[]);
            return Err(Failure::internal(
                codes::ATTEMPT_ENDED,
                "harness app: attempts did not stop within the shutdown budget",
            ));
        }
        Ok(())
    }

    /// `race` — `f` or the stop arm; also polls in-flight futures so
    /// attempts keep heartbeating during the dispatcher's own calls.
    async fn race<T, F: Future<Output = T>>(&self, stop: &dyn CancelSignal, f: F) -> Sel<T> {
        let mut f = std::pin::pin!(f);
        let mut cancel = stop.cancelled();
        std::future::poll_fn(|cx| {
            self.poll_inflight(cx);
            if let std::task::Poll::Ready(()) = cancel.as_mut().poll(cx) {
                return std::task::Poll::Ready(Sel::Ended);
            }
            match f.as_mut().poll(cx) {
                std::task::Poll::Ready(v) => std::task::Poll::Ready(Sel::Done(v)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
    }

    /// One pass over the local driver's in-flight futures; a completed
    /// attempt has already run `finish` inside itself — bookkeeping,
    /// `freed_epoch` and waker notification included — so this only
    /// drops it from the vec. The futures are taken out of the lock
    /// before polling: `finish` (inside each future) locks `inner`
    /// itself, so polling under the lock would deadlock.
    fn poll_inflight(&self, cx: &mut std::task::Context<'_>) {
        let mut futs = match self.shared.inner.lock() {
            Ok(mut g) => std::mem::take(&mut g.futures),
            Err(_) => return,
        };
        let mut keep = Vec::with_capacity(futs.len());
        for mut f in futs.drain(..) {
            match f.as_mut().poll(cx) {
                std::task::Poll::Ready(_) => {}
                std::task::Poll::Pending => keep.push(f),
            }
        }
        if let Ok(mut g) = self.shared.inner.lock() {
            // Futures pushed by `spawn_local` during the poll window
            // stay; the still-pending ones rejoin.
            g.futures.extend(keep);
        }
    }

    fn freed_epoch(&self) -> u64 {
        self.shared.inner.lock().map(|g| g.freed_epoch).unwrap_or(0)
    }

    /// `filter` — drops Runs this dispatcher is running, has lost,
    /// could not settle, or is cooling down after a refused start.
    fn filter(&self, listed: Vec<DispatchableRun>) -> Vec<DispatchableRun> {
        match self.shared.inner.lock() {
            Ok(g) => {
                let now = self.shared.deps.clock.now();
                listed
                    .into_iter()
                    .filter(|c| {
                        if g.inflight.contains(&c.run_id)
                            || g.lost.contains_key(&c.run_id)
                            || g.settle_failed.contains_key(&c.run_id)
                        {
                            return false;
                        }
                        !matches!(g.cooling.get(&c.run_id), Some(cool) if now < cool.until)
                    })
                    .collect()
            }
            Err(_) => Vec::new(),
        }
    }

    /// `admit` — checks free space, then probes the harness (decision
    /// 11). Low disk, an unreachable launcher or a harness not logged
    /// in pause the dispatcher (telling `waiting`); a good probe
    /// resumes it.
    async fn admit(&self, waiting: &[DispatchableRun], stop: &dyn CancelSignal) -> Admit {
        match self
            .race(stop, self.shared.deps.workspaces.check_free_space())
            .await
        {
            Sel::Ended => return Admit::Ended,
            Sel::Done(Err(e)) => {
                if stop.is_cancelled() {
                    return Admit::Ended;
                }
                self.mark_probed();
                self.shared.deps.logger.warn(
                    "harness dispatcher paused: low disk",
                    &[("error", e.to_string())],
                );
                self.pause(PauseReason::LowDisk, waiting, Some(stop)).await;
                return Admit::Refused;
            }
            Sel::Done(Ok(())) => {}
        }
        let env = crate::port::LaunchEnv {
            vars: self.shared.deps.cfg.launch_env.clone(),
            sandbox_scope_id: HarnessAttemptId::new().to_string(),
        };
        match self
            .race(
                stop,
                bounded(
                    self.shared.deps.adapter.probe(env),
                    self.shared
                        .deps
                        .ticker
                        .after(self.shared.deps.cfg.probe_budget),
                ),
            )
            .await
        {
            Sel::Ended => Admit::Ended,
            Sel::Done(Bounded::Elapsed) => {
                self.mark_probed();
                self.shared.deps.logger.warn(
                    "harness dispatcher paused: launcher unreachable",
                    &[("error", "probe timed out".to_string())],
                );
                self.pause(PauseReason::LauncherUnreachable, waiting, Some(stop))
                    .await;
                Admit::Refused
            }
            Sel::Done(Bounded::Done(Err(e))) => {
                if stop.is_cancelled() {
                    return Admit::Ended;
                }
                self.mark_probed();
                self.shared.deps.logger.warn(
                    "harness dispatcher paused: launcher unreachable",
                    &[("error", e.to_string())],
                );
                self.pause(PauseReason::LauncherUnreachable, waiting, Some(stop))
                    .await;
                Admit::Refused
            }
            Sel::Done(Bounded::Done(Ok(probe))) => {
                self.mark_probed();
                if !probe.authenticated {
                    self.pause(PauseReason::NotLoggedIn, waiting, Some(stop))
                        .await;
                    Admit::Refused
                } else {
                    self.resume(Some(stop)).await;
                    Admit::Probed(probe)
                }
            }
        }
    }

    /// `markProbed`.
    fn mark_probed(&self) {
        if let Ok(mut g) = self.shared.inner.lock() {
            g.last_probe = self.shared.deps.clock.now();
        }
    }

    /// `coolDown` — backs a refused Run off, doubling its previous
    /// back-off; returns the back-off applied (the log records it).
    /// Callers hold the inner lock.
    fn cool_down(
        g: &mut Inner,
        cfg: &DispatcherConfig,
        run: RunId,
        now: OffsetDateTime,
    ) -> Duration {
        let mut backoff = cfg.not_startable_cooldown;
        if let Some(prev) = g.cooling.get(&run) {
            // Go doubles into a negative on overflow and clamps it to
            // the cap; `checked_mul` reaches the cap the same way.
            backoff = prev
                .backoff
                .checked_mul(2)
                .unwrap_or(cfg.max_not_startable_cooldown);
            if backoff > cfg.max_not_startable_cooldown || backoff <= Duration::ZERO {
                backoff = cfg.max_not_startable_cooldown;
            }
        } else if g.cooling.len() >= MAX_COOLING_RUNS {
            // Forget entries long expired, then, if still full, the
            // one that expires first.
            let mut first: Option<(RunId, OffsetDateTime)> = None;
            let mut expired = Vec::new();
            for (id, c) in g.cooling.iter() {
                if now - c.until > cfg.max_not_startable_cooldown {
                    expired.push(*id);
                    continue;
                }
                if first.map(|(_, u)| c.until < u).unwrap_or(true) {
                    first = Some((*id, c.until));
                }
            }
            for id in expired {
                g.cooling.remove(&id);
            }
            if g.cooling.len() >= MAX_COOLING_RUNS
                && let Some((id, _)) = first
            {
                g.cooling.remove(&id);
            }
        }
        g.cooling.insert(
            run,
            Cooldown {
                until: now + backoff,
                backoff,
            },
        );
        backoff
    }

    /// `pause` — moves to (or stays in) paused with `reason` and
    /// records a paused milestone on each waiting Task not yet told in
    /// this pause episode.
    async fn pause(
        &self,
        reason: PauseReason,
        waiting: &[DispatchableRun],
        stop: Option<&dyn CancelSignal>,
    ) {
        let (episode, tell, changed) = {
            let mut g = match self.shared.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let now = self.shared.deps.clock.now();
            let changed = g.status.state != DispatcherState::Paused || g.status.pause != reason;
            if changed {
                if g.status.state != DispatcherState::Paused {
                    g.episode = now;
                }

                g.status = Status {
                    state: DispatcherState::Paused,
                    pause: reason,
                    since: now,
                    ..Status::default()
                };
            }
            let mut tell = Vec::new();
            for c in waiting {
                if let std::collections::hash_map::Entry::Vacant(e) = g.notified.entry(c.task_id) {
                    e.insert(c.clone());
                    tell.push(c.clone());
                }
            }
            (g.episode, tell, changed)
        };
        // Upstream logs only on a real transition — a re-pause with
        // the same reason records milestones, no second warn line.
        if changed {
            self.shared.deps.logger.warn(
                "harness dispatcher paused",
                &[("reason", reason.as_str().to_string())],
            );
        }
        for c in tell {
            self.record(
                stop,
                &c,
                MilestoneKind::DispatchPaused,
                episode,
                "paused",
                reason.as_str(),
            )
            .await;
        }
    }

    /// `resume` — moves to running and records a resumed milestone on
    /// each Task told about the pause.
    async fn resume(&self, stop: Option<&dyn CancelSignal>) {
        let (episode, tell, changed) = {
            let mut g = match self.shared.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let changed = g.status.state != DispatcherState::Running;
            if changed {
                g.status = Status {
                    state: DispatcherState::Running,
                    since: self.shared.deps.clock.now(),
                    ..Status::default()
                };
            }
            let tell: Vec<DispatchableRun> = g.notified.values().cloned().collect();
            g.notified.clear();
            (g.episode, tell, changed)
        };
        if changed {
            self.shared
                .deps
                .logger
                .info("harness dispatcher running", &[]);
        }
        for c in tell {
            self.record(
                stop,
                &c,
                MilestoneKind::DispatchResumed,
                episode,
                "resumed",
                "",
            )
            .await;
        }
    }

    /// `record` — a best-effort milestone append (a failure is logged
    /// upstream and never fails the pass).
    async fn record(
        &self,
        stop: Option<&dyn CancelSignal>,
        c: &DispatchableRun,
        kind: MilestoneKind,
        episode: OffsetDateTime,
        status: &str,
        reason: &str,
    ) {
        let m = Milestone {
            key: format!(
                "harness:dispatch:{}:{}:{}",
                c.run_id,
                episode.unix_timestamp_nanos(),
                status
            ),
            kind,
            workspace_id: c.workspace_id,
            task_id: c.task_id,
            run_id: c.run_id,
            // Upstream's `record` leaves `StepAttemptID` zero — a
            // dispatch milestone names the Task and Run, never the
            // step attempt.
            step_attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
            status: status.to_string(),
            reason: reason.to_string(),
            at: self.shared.deps.clock.now(),
        };
        let f = self.shared.deps.events.record(m);
        let res = match stop {
            Some(stop) => match self.race(stop, f).await {
                Sel::Done(r) => r,
                Sel::Ended => return,
            },
            None => f.await,
        };
        if let Err(e) = res {
            self.shared.deps.logger.warn(
                "harness dispatch milestone not recorded",
                &[
                    ("kind", kind.as_str().to_string()),
                    ("error", e.to_string()),
                ],
            );
        }
    }
}

/// The `round`/`admit` answer — `Ok(probe)` is
/// [`Admit::Probed`], `false` splits into refused (paused) and ended
/// (stopped).
enum Admit {
    /// `probe, true` — Runs may be claimed.
    Probed(crate::port::ProbeResult),
    /// `_, false` with ctx live — paused.
    Refused,
    /// `_, false` with ctx ended — stopped.
    Ended,
}

/// `Race`-style answer for the dispatcher's own calls.
enum Sel<T> {
    Done(T),
    Ended,
}

/// `bounded` — `f` or the timeout fires first (upstream's
/// `context.WithTimeout` races).
enum Bounded<T> {
    Done(T),
    Elapsed,
}

async fn bounded<T, F: Future<Output = T>>(f: F, mut t: PortFuture<'_, ()>) -> Bounded<T> {
    let mut f = std::pin::pin!(f);
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(cx) {
            return std::task::Poll::Ready(Bounded::Done(v));
        }
        if let std::task::Poll::Ready(()) = t.as_mut().poll(cx) {
            return std::task::Poll::Ready(Bounded::Elapsed);
        }
        std::task::Poll::Pending
    })
    .await
}

/// `sortedRuns` — the status's sorted run ids.
fn sorted_runs(set: &HashMap<RunId, OffsetDateTime>) -> Vec<RunId> {
    let mut out: Vec<RunId> = set.keys().copied().collect();
    out.sort();
    out
}

/// `hold` — records `run` in `set`, evicting the oldest entry when
/// `set` is full (`MAX_HELD_RUNS`).
fn hold(set: &mut HashMap<RunId, OffsetDateTime>, run: RunId, now: OffsetDateTime) {
    if !set.contains_key(&run) && set.len() >= MAX_HELD_RUNS {
        let oldest = set.iter().min_by_key(|(_, at)| *at).map(|(id, _)| *id);
        if let Some(id) = oldest {
            set.remove(&id);
        }
    }
    set.insert(run, now);
}

impl Shared {
    /// `finish` — frees the slot and applies the outcome bookkeeping:
    /// lost/settle-failed holds, cool-down of a refused start, the
    /// outcome's warn/info record, and the low-disk pause of an
    /// attempt-reported disk problem. A refused start frees its slot
    /// without waking the loop: the next round comes at the poll
    /// interval, never back to back with another probe.
    async fn finish(&self, c: &DispatchableRun, res: HarnessResult) -> HarnessResult {
        let now = self.deps.clock.now();
        let backoff = {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => {
                    return res;
                }
            };
            g.inflight.remove(&c.run_id);
            match res.outcome {
                Outcome::Lost => hold(&mut g.lost, c.run_id, now),
                _ if res.settle_failed => hold(&mut g.settle_failed, c.run_id, now),
                _ => {}
            }
            if res.outcome == Outcome::NotStarted {
                Dispatcher::cool_down(&mut g, &self.deps.cfg, c.run_id, now)
            } else {
                g.cooling.remove(&c.run_id);
                Duration::ZERO
            }
        };
        let run = c.run_id.to_string();
        let outcome = res.outcome.as_str().to_string();
        let err = res.err.as_ref().map(|e| e.to_string()).unwrap_or_default();
        if res.outcome == Outcome::Lost {
            self.deps.logger.warn(
                "harness run lost its lease; it is reconciled at the next start",
                &[("run", run), ("outcome", outcome), ("error", err)],
            );
        } else if res.settle_failed {
            self.deps.logger.warn(
                "harness run settlement not written; it is reconciled at the next start",
                &[("run", run), ("outcome", outcome), ("error", err)],
            );
        } else if res.outcome == Outcome::NotStarted {
            if let Some(e) = &res.err
                && e.code() != codes::NOT_STARTABLE
            {
                self.deps.logger.warn(
                    "harness run could not be started",
                    &[
                        ("run", run.clone()),
                        ("outcome", outcome),
                        ("error", err.clone()),
                    ],
                );
            }
            self.deps.logger.info(
                "harness run not started; cooling down",
                &[("run", run), ("backoff", backoff.to_string())],
            );
        } else if let Some(e) = &res.err {
            let e = e.to_string();
            self.deps.logger.warn(
                "harness run ended with an error",
                &[("run", run), ("outcome", outcome), ("error", e)],
            );
        }
        if res.low_disk {
            {
                if let Ok(mut g) = self.inner.lock() {
                    g.last_probe = self.deps.clock.now();
                }
            }
            self.pause_dispatch(PauseReason::LowDisk).await;
        }
        // Upstream's `freed <- struct{}{}` — sent only once `finish`
        // returned, so the low-disk pause above is already applied
        // before a woken `sleep` can run the next `round`. Only a
        // non-refused finish wakes `sleep`; every finish wakes
        // `shutdown`'s drain check (its `wg.Done`).
        if let Ok(mut g) = self.inner.lock() {
            if res.outcome != Outcome::NotStarted {
                g.freed_epoch += 1;
            }
            for w in g.wakers.drain(..) {
                w.wake();
            }
        }
        res
    }

    /// `pause(context.Background(), PauseLowDisk, nil)` — the
    /// milestone-free pause `finish` uses: the same transition and
    /// warn record, an empty `waiting` set.
    async fn pause_dispatch(&self, reason: PauseReason) {
        let now = self.deps.clock.now();
        if let Ok(mut g) = self.inner.lock()
            && (g.status.state != DispatcherState::Paused || g.status.pause != reason)
        {
            if g.status.state != DispatcherState::Paused {
                g.episode = now;
            }
            g.status = Status {
                state: DispatcherState::Paused,
                pause: reason,
                since: now,
                ..Status::default()
            };
            // Upstream logs under the lock, only on a real transition.
            self.deps.logger.warn(
                "harness dispatcher paused",
                &[("reason", reason.as_str().to_string())],
            );
        }
    }
}
