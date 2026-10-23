//! The orchestrator — the port of `internal/harness/app/orchestrator.go`
//! plus the attempt-side bridge methods of `bridge.go`. It launches the
//! claimed harness through an adapter and drives it to a durable
//! terminal settlement: durable `prepared` under the lease fence,
//! `mark_invoked`, `launching`, adapter start outside any DB
//! transaction (decision 3), then event-driven to the terminal write.
//!
//! Go `ctx` cancellation maps to [`Standing`]: heartbeat tick, in-flight
//! heartbeat and the serve-stop signal are *standing arms* polled inside
//! every `poll_fn` — the same `select` as upstream's
//! `race`/`pollStanding`. A future dropped by the select is the Go call
//! returning `ctx.Err()`. [`AttemptRun`] owns the domain state,
//! [`Standing`] the arms + end/cancel state, and [`DriveArms`] the
//! drive-loop arms that borrow the session, so the borrows stay
//! disjoint under `&mut`.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, HarnessPermissionApprovalId, WorkspaceId};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::approval::{self, ApprovalState, PermissionApproval, compute_input_mac};
use crate::attempt::{Attempt, PrepareInput};
use crate::budget::Budget;
use crate::domain::{
    self, Fence, Kind, PermissionPolicy, Resolution, State, Terminal, TerminalStatus, Workspace,
};
use crate::event::{
    Event, EventPayload, MessageRole, PermissionOutcome, PermissionRequested, PermissionResolved,
    ToolStatus, Usage,
};
use crate::port::{
    Adapter, ApprovalOpen, AttemptStore, LeaseBinder, PermissionDecision, PortFuture, Session,
    SessionRef, StartSpec,
};
use crate::record::{EventRecord, record_of};

pub use super::bridge::PendingRequest;
use super::bridge::{self, ApprovalRegistry, BridgeState, OpenApproval, decided_by_code};
use super::ports::{
    self, ArtifactOutcome, ArtifactOutcomeKind, ArtifactRole, CancelSignal, ClaimedRun, Clock,
    DispatchableRun, FailureCode, HarnessResult, Milestone, MilestoneKind, Outcome, ResumeFrom,
    Settlement, Ticker, codes,
};

// Upstream's timing consts (orchestrator.go's const block).
/// `writeAttempts` — a durable write is retried at most this often.
const WRITE_ATTEMPTS: usize = 3;
/// `writeBackoff` — the write retry's base backoff (`<<i` doubling).
const WRITE_BACKOFF: Duration = Duration::milliseconds(100);
/// `eventWriteBackoffMax` — the event-write retry's backoff cap.
const EVENT_WRITE_BACKOFF_MAX: Duration = Duration::seconds(5);
/// `permissionAnswerBudget` — bounds one `respond_permission` call.
const PERMISSION_ANSWER_BUDGET: Duration = Duration::seconds(5);
/// `sessionWaitBudget` — bounds `session.wait()`/`scopeReleased`'s
/// re-wait.
const SESSION_WAIT_BUDGET: Duration = Duration::seconds(10);
/// `captureReleaseBudget` — bounds `capture.release` (`WithoutCancel`,
/// so no standing race).
const CAPTURE_RELEASE_BUDGET: Duration = Duration::seconds(30);

/// `OrchestratorConfig` — upstream `app.OrchestratorConfig`.
pub struct OrchestratorConfig {
    /// `HeartbeatInterval` — between execution-lease heartbeats while
    /// an attempt is in flight.
    pub heartbeat_interval: Duration,
    /// `EventWriteBudget` — an event write keeps retrying transient
    /// store failures at most this long.
    pub event_write_budget: Duration,
    /// `LifelineBudget` — bounds the calls the process lifeline must
    /// answer (interrupt/kill on the background ctx).
    pub lifeline_budget: Duration,
    /// `InterruptGrace` — between interrupt and kill.
    pub interrupt_grace: Duration,
    /// `DefaultCostMicroUSD` — the effective budget when the claim's
    /// `cost` is unset (decision 5).
    pub default_cost_micro_usd: i64,
    /// `DefaultWallClock` — the effective wall-clock budget when unset.
    pub default_wall_clock: Duration,
    /// `MaxTokens` — the serve-wide billed-token ceiling (3l decision
    /// 5); 0 disables.
    pub max_tokens: i64,
    /// `ApprovalTimeout` — a bridged request expires after this.
    pub approval_timeout: Duration,
    /// `ApprovalRecheck` — an open approval row is re-read at most this
    /// often.
    pub approval_recheck: Duration,
    /// `AdapterVersion` — recorded on every attempt
    /// (`Attempt::adapter_version`).
    pub adapter_version: String,
    /// `Model` — passed verbatim to the start spec when set.
    pub model: String,
    /// `InputMACKey` — HMAC key for permission-input MACs and event raw
    /// digests; at least [`crate::approval::MIN_INPUT_MAC_KEY_BYTES`],
    /// generated when empty.
    pub input_mac_key: Vec<u8>,
    /// `Resume` — resolves a claimed attempt's resume source (3g).
    pub resume: Arc<dyn ports::ResumeSource>,
    /// `LaunchEnv` — extra env for every launch (validated against the
    /// adapter's forbidden names).
    pub launch_env: std::collections::BTreeMap<String, String>,
    /// `Events` — the task event sink; `None` disables milestone
    /// projection.
    pub events: Option<Arc<dyn ports::TaskEventSink>>,
}

impl fmt::Debug for OrchestratorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrchestratorConfig")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("event_write_budget", &self.event_write_budget)
            .field("lifeline_budget", &self.lifeline_budget)
            .field("interrupt_grace", &self.interrupt_grace)
            .field("default_cost_micro_usd", &self.default_cost_micro_usd)
            .field("default_wall_clock", &self.default_wall_clock)
            .field("max_tokens", &self.max_tokens)
            .field("approval_timeout", &self.approval_timeout)
            .field("approval_recheck", &self.approval_recheck)
            .field("adapter_version", &self.adapter_version)
            .field("model", &self.model)
            .field("input_mac_key", &"<redacted>")
            .field("launch_env", &self.launch_env.keys().collect::<Vec<_>>())
            .field("events", &self.events.is_some())
            .finish()
    }
}

impl OrchestratorConfig {
    /// The upstream defaults (`defaultTestConfig`'s timings).
    pub fn new(resume: Arc<dyn ports::ResumeSource>) -> Self {
        Self {
            heartbeat_interval: Duration::seconds(8),
            event_write_budget: Duration::seconds(10),
            lifeline_budget: Duration::seconds(5),
            interrupt_grace: Duration::milliseconds(200),
            default_cost_micro_usd: 5_000_000,
            default_wall_clock: Duration::minutes(30),
            max_tokens: 0,
            approval_timeout: bridge::DEFAULT_APPROVAL_TIMEOUT,
            approval_recheck: bridge::DEFAULT_APPROVAL_RECHECK,
            adapter_version: String::new(),
            model: String::new(),
            input_mac_key: Vec::new(),
            resume,
            launch_env: std::collections::BTreeMap::new(),
            events: None,
        }
    }
}

/// `OrchestratorDeps` — upstream `NewOrchestrator`'s parameters.
pub struct OrchestratorDeps {
    /// `lifecycle` — the execution/task side.
    pub lifecycle: Arc<dyn ports::RunLifecycle>,
    /// `attempts` — the lease binder that binds each run's store.
    pub attempts: Arc<dyn LeaseBinder>,
    /// `adapter` — the harness adapter.
    pub adapter: Arc<dyn Adapter>,
    /// `workspaces` — per-Run clones.
    pub workspaces: Arc<dyn ports::WorkspaceProvisioner>,
    /// `capture` — post-exit clone capture.
    pub capture: Arc<dyn ports::WorkspaceCapture>,
    /// `artifacts` — patch/commits body storage.
    pub artifacts: Arc<dyn ports::ArtifactSink>,
    /// `clock` — timestamps.
    pub clock: Arc<dyn Clock>,
    /// `ticker` — timers (heartbeat, retries, grace, expiry).
    pub ticker: Arc<dyn Ticker>,
    /// `cfg` — timing/budget/resume/env config.
    pub cfg: OrchestratorConfig,
}

/// `app.Orchestrator` — drives claimed Runs through the attempt's
/// lifecycle.
pub struct Orchestrator {
    deps: OrchestratorDeps,
    approvals: ApprovalRegistry,
    input_mac_key: Vec<u8>,
}

impl fmt::Debug for Orchestrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Orchestrator")
            .field("cfg", &self.deps.cfg)
            .finish_non_exhaustive()
    }
}

impl Orchestrator {
    /// Upstream `NewOrchestrator`: `adapter_version` must be set and the
    /// `launch_env` must validate against the adapter's forbidden
    /// names; an empty `input_mac_key` is generated (process-local,
    /// never stored — two UUIDv7s' ~148 bits of fresh entropy).
    pub fn new(deps: OrchestratorDeps) -> Result<Self, Failure> {
        if deps.cfg.adapter_version.is_empty() {
            return Err(Failure::invalid(
                domain::codes::INVALID_ATTEMPT,
                "harness app: adapter version required",
            ));
        }
        crate::env::validate_launch_env(
            &deps.cfg.launch_env,
            &deps
                .adapter
                .env_extras()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )?;
        let input_mac_key = if deps.cfg.input_mac_key.is_empty() {
            format!(
                "{}{}",
                HarnessPermissionApprovalId::new(),
                HarnessPermissionApprovalId::new()
            )
            .into_bytes()
        } else {
            if deps.cfg.input_mac_key.len() < approval::MIN_INPUT_MAC_KEY_BYTES {
                return Err(Failure::invalid(
                    domain::codes::INVALID_APPROVAL,
                    format!(
                        "input MAC key must be at least {} bytes",
                        approval::MIN_INPUT_MAC_KEY_BYTES
                    ),
                ));
            }
            deps.cfg.input_mac_key.clone()
        };
        Ok(Self {
            deps,
            approvals: ApprovalRegistry::default(),
            input_mac_key,
        })
    }

    /// `approvals` — the registry clone tests inspect through
    /// (shared interior).
    #[cfg(test)]
    pub(crate) fn approvals_handle(&self) -> super::bridge::ApprovalRegistry {
        self.approvals.clone()
    }

    /// Upstream `PendingRequest` — the bridged request the operator is
    /// shown, when this process holds it (decision 13).
    pub fn pending_request(
        &self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Option<PendingRequest> {
        self.approvals.pending_request(ws, id)
    }

    /// Upstream `SignalDecision` — wakes the attempt waiting on `id`'s
    /// decision; whether a waiter was found.
    pub fn signal_decision(&self, ws: WorkspaceId, id: HarnessPermissionApprovalId) -> bool {
        self.approvals.signal_decision(ws, id)
    }

    /// Upstream `Run`: `start` claims `d`'s Run — a refused claim is
    /// `not_started`, an unknown outcome `lost`, an invalid lease
    /// `lost`.
    pub async fn run_dispatchable<'o>(
        &'o self,
        d: DispatchableRun,
        harness_version: &str,
        stop: &'o dyn CancelSignal,
    ) -> HarnessResult {
        match self.deps.lifecycle.start(d).await {
            Ok(claimed) => self.run(claimed, harness_version, stop).await,
            Err(e) if e.code() == codes::START_OUTCOME_UNKNOWN => HarnessResult {
                outcome: Outcome::Lost,
                reason: FailureCode::LEASE_LOST,
                low_disk: false,
                settle_failed: false,
                err: Some(e),
            },
            Err(e) => HarnessResult::bare(Outcome::NotStarted, Some(e)),
        }
    }

    /// The second half of upstream `Run` — a claim without a usable
    /// lease authorizes no write.
    pub async fn run<'o>(
        &'o self,
        claimed: ClaimedRun,
        harness_version: &str,
        stop: &'o dyn CancelSignal,
    ) -> HarnessResult {
        if let Err(e) = claimed.lease.validate() {
            return HarnessResult {
                outcome: Outcome::Lost,
                reason: FailureCode::LEASE_LOST,
                low_disk: false,
                settle_failed: false,
                err: Some(Failure::conflict(
                    codes::LEASE_LOST,
                    format!("the claimed lease is unusable: {}", e.message()),
                )),
            };
        }
        let harness_version = if harness_version.is_empty() {
            "unknown"
        } else {
            harness_version
        };
        let mut r = AttemptRun::new(self, claimed, harness_version, stop);
        let res = r.execute_inner().await;
        // The upstream `defer`: however the orchestration ended, no
        // approval of this attempt is answerable any more (decision
        // 11), and the heartbeat is joined.
        if !r.attempt.id.is_nil() {
            r.o.approvals.drop_attempt(r.attempt.id);
        }
        r.stop_heartbeat();
        res
    }
}

// ---------------------------------------------------------------------------
// Select machinery — the Go ctx/standing-arm select as Rust arms
// ---------------------------------------------------------------------------

/// The attempt's end — upstream `r.end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum End {
    #[default]
    Live,
    /// `endLost` — the heartbeat proved the lease gone.
    Lost,
    /// `endStopped` — serve stop.
    Stopped,
}

/// `Race` — the Go `select` between an operation and the ctx arm.
enum Race<T> {
    Done(T),
    Ended,
}

/// `Bounded` — the Go `select` between a bounded call and its timeout.
enum Bounded<T> {
    Done(T),
    Elapsed,
}

/// `raceCtx(bounded(f, d))` — `f` or `d` fires first.
async fn bounded<T, F: Future<Output = T>>(f: F, mut t: PortFuture<'_, ()>) -> Bounded<T> {
    let mut f = std::pin::pin!(f);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = f.as_mut().poll(cx) {
            return Poll::Ready(Bounded::Done(v));
        }
        if let Poll::Ready(()) = t.as_mut().poll(cx) {
            return Poll::Ready(Bounded::Elapsed);
        }
        Poll::Pending
    })
    .await
}

/// The standing arms — upstream's `r.ctx`/`r.hbTick`/`r.hb` set — plus
/// the end/cancel state they drive. `poll` is `pollStanding`; `race`
/// and `work_race` are `r.ctx.race`/`r.work.race`.
struct Standing<'o> {
    o: &'o Orchestrator,
    /// `r.run` — heartbeats carry it.
    run: ClaimedRun,
    /// The attempt this orchestration serves — for `drop_attempt`
    /// (upstream's `bridgedAttempt` is always `r.attempt.ID`; a nil id
    /// disables the drop).
    attempt_id: HarnessAttemptId,
    /// `r.stop` — the serve-stop channel; `None` once it fired (a
    /// completed future is never polled again).
    stop: Option<PortFuture<'o, ()>>,
    /// `r.hbTick` — next heartbeat tick.
    hb_tick: PortFuture<'o, ()>,
    /// `r.hb` — a heartbeat in flight.
    hb: Option<PortFuture<'o, Result<bool, Failure>>>,
    /// `r.cancelReq`-closed — `requestCancel` ran (the upstream
    /// channel; `cancelHit` is `AttemptRun::cancel_consumed`).
    cancel_hit: bool,
    /// `r.end`.
    end: End,
    /// `r.lastBeatAt`.
    last_beat_at: OffsetDateTime,
    /// `stopHeartbeat` — settle writes have started; no new heartbeat.
    hb_stopped: bool,
}

impl<'o> Standing<'o> {
    fn new(o: &'o Orchestrator, run: ClaimedRun, stop: &'o dyn CancelSignal) -> Self {
        Self {
            o,
            run,
            attempt_id: HarnessAttemptId::from_trusted_db_bytes([0; 16]),
            hb_tick: o.deps.ticker.after(o.deps.cfg.heartbeat_interval),
            stop: Some(stop.cancelled()),
            hb: None,
            cancel_hit: false,
            end: End::Live,
            last_beat_at: o.deps.clock.now(),
            hb_stopped: false,
        }
    }

    /// `r.ctx.Err() != nil`.
    fn ended(&self) -> bool {
        self.end != End::Live
    }

    /// `requestCancel` — marks the cancel and drops this attempt's
    /// pending approvals (`dropAttemptApprovals`).
    fn request_cancel(&mut self) {
        if self.cancel_hit {
            return;
        }
        self.cancel_hit = true;
        if !self.attempt_id.is_nil() {
            self.o.approvals.drop_attempt(self.attempt_id);
        }
    }

    /// `r.cancel(cause)` — `WithCancelCause`: the first cause wins;
    /// a later one changes nothing (`interrupted`'s reported cause).
    fn end_with(&mut self, end: End) {
        if self.end == End::Live {
            self.end = end;
        }
    }

    /// `onHeartbeat` — applies one heartbeat result (upstream's
    /// heartbeat goroutine body).
    fn on_heartbeat(&mut self, res: Result<bool, Failure>) {
        match res {
            Ok(cancel) => {
                self.last_beat_at = self.o.deps.clock.now();
                if cancel {
                    self.request_cancel();
                }
            }
            Err(e) => {
                let code = e.code();
                if code == codes::CANCEL_REQUESTED {
                    self.last_beat_at = self.o.deps.clock.now();
                    self.request_cancel();
                } else if code == codes::LEASE_LOST {
                    self.end_with(End::Lost);
                }
                // Otherwise logged upstream; the next tick retries.
            }
        }
    }

    /// `pollStanding` — one non-blocking pass over the standing arms.
    fn poll(&mut self, cx: &mut std::task::Context<'_>) {
        if let Some(stop) = self.stop.as_mut()
            && let Poll::Ready(()) = stop.as_mut().poll(cx)
        {
            self.stop = None;
            self.end_with(End::Stopped);
        }
        if !self.hb_stopped {
            if let Poll::Ready(()) = self.hb_tick.as_mut().poll(cx) {
                // A tick while a heartbeat is in flight is dropped
                // (upstream's ticker drops it when unreceived).
                if self.hb.is_none() {
                    self.hb = Some(self.o.deps.lifecycle.heartbeat(self.run.clone()));
                }
                self.hb_tick = self.o.deps.ticker.after(self.o.deps.cfg.heartbeat_interval);
                // Poll the fresh timer now so it registers this pass's
                // waker: a timer that fires before its first poll can
                // never wake the executor.
                let _ = self.hb_tick.as_mut().poll(cx);
            }
            if let Some(hb) = self.hb.as_mut()
                && let Poll::Ready(res) = hb.as_mut().poll(cx)
            {
                self.hb = None;
                self.on_heartbeat(res);
            }
        }
    }

    /// `r.race` — `f` or the ctx end.
    async fn race<T, F: Future<Output = T>>(&mut self, f: F) -> Race<T> {
        let mut f = std::pin::pin!(f);
        std::future::poll_fn(|cx| {
            self.poll(cx);
            if self.ended() {
                return Poll::Ready(Race::Ended);
            }
            match f.as_mut().poll(cx) {
                Poll::Ready(v) => Poll::Ready(Race::Done(v)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    /// `r.work.race` — also ends on the recorded cancel request.
    async fn work_race<T, F: Future<Output = T>>(&mut self, f: F) -> Race<T> {
        let mut f = std::pin::pin!(f);
        std::future::poll_fn(|cx| {
            self.poll(cx);
            if self.ended() || self.cancel_hit {
                return Poll::Ready(Race::Ended);
            }
            match f.as_mut().poll(cx) {
                Poll::Ready(v) => Poll::Ready(Race::Done(v)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    /// `r.retry` — a write up to `WRITE_ATTEMPTS` times while it fails
    /// transiently and the attempt ctx is live. `make` builds the
    /// *unraced* future per call (upstream's `write func()`); `work`
    /// selects the work race.
    async fn retry<T, F2>(&mut self, work: bool, mut make: impl FnMut() -> F2) -> Result<T, Failure>
    where
        F2: Future<Output = Result<T, Failure>> + Send,
    {
        let mut err: Option<Failure> = None;
        for i in 0..WRITE_ATTEMPTS {
            let res = if work {
                self.work_race(make()).await
            } else {
                self.race(make()).await
            };
            match res {
                Race::Done(Ok(v)) => return Ok(v),
                Race::Done(Err(e)) => {
                    if !transient(&e) || self.ended() {
                        return Err(e);
                    }
                    err = Some(e);
                }
                Race::Ended => return Err(ended_err(self.end)),
            }
            let res = self
                .race(self.o.deps.ticker.after(WRITE_BACKOFF * (1 << i)))
                .await;
            if let Race::Ended = res {
                return Err(match err {
                    Some(e) => e,
                    None => ended_err(self.end),
                });
            }
        }
        Err(match err {
            Some(e) => e,
            None => Failure::internal(codes::ATTEMPT_ENDED, "write attempts exhausted"),
        })
    }
}

/// The drive loop's own arms — upstream's non-standing `select` cases.
/// Session futures borrow `session`.
struct DriveArms<'a> {
    /// The session every session-bound arm borrows.
    session: &'a dyn Session,
    /// `case ev, ok := <-events` — re-armed on each delivered event;
    /// `None` once the stream closed.
    next_event: Option<PortFuture<'a, Option<Event>>>,
    /// `case <-wall.C`.
    wall: Option<PortFuture<'a, ()>>,
    /// `case <-killTimer`.
    kill_timer: Option<PortFuture<'a, ()>>,
    /// `r.killAsync`'s goroutine, as a pending future (dropped with the
    /// loop = the Go goroutine abandoned at process end).
    kill_pending: Option<PortFuture<'a, Result<(), Failure>>>,
    /// `case <-r.approvalSignal()`.
    approval_signal: Option<PortFuture<'a, ()>>,
    /// `case <-r.approvalExpiry()`.
    approval_expiry: Option<PortFuture<'a, ()>>,
    /// `case <-recheck.C` — re-armed on fire.
    recheck: PortFuture<'a, ()>,
}

/// What one drive-loop pass selected — the upstream `select` cases.
enum Fired {
    /// `case <-r.ctx.Done()`.
    End,
    /// `case <-cancelReq`.
    Cancel,
    /// `case ev, ok := <-events` (`None` = stream closed).
    Event(Option<Box<Event>>),
    /// `case <-wall.C`.
    Wall,
    /// `case <-killTimer`.
    KillTimer,
    /// The kill goroutine answered (logged upstream; nothing else).
    KillDone,
    /// `case <-r.approvalSignal()`.
    ApprovalSignal,
    /// `case <-r.approvalExpiry()`.
    ApprovalExpiry,
    /// `case <-recheck.C`.
    Recheck,
}

impl<'a> DriveArms<'a> {
    /// One non-blocking pass over the drive arms — the upstream
    /// `select`'s cases. The timer and approval arms are polled before
    /// the event arm: upstream's `select` picks among ready cases at
    /// random, so a session that yields an event every pass must not
    /// starve the wall clock, the kill ladder or a decision. The
    /// approval arms are maintained by `opened`/`closeOpen`/`answer`
    /// (the upstream `approvalSignal()`/`approvalExpiry()` returning
    /// `nil` for a nil or answered open is their clearing).
    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Option<Fired> {
        if let Some(f) = self.wall.as_mut()
            && let Poll::Ready(()) = f.as_mut().poll(cx)
        {
            self.wall = None;
            return Some(Fired::Wall);
        }
        if let Some(f) = self.kill_timer.as_mut()
            && let Poll::Ready(()) = f.as_mut().poll(cx)
        {
            self.kill_timer = None;
            return Some(Fired::KillTimer);
        }
        if let Some(f) = self.kill_pending.as_mut()
            && let Poll::Ready(_res) = f.as_mut().poll(cx)
        {
            self.kill_pending = None;
            return Some(Fired::KillDone);
        }
        if let Some(f) = self.approval_signal.as_mut()
            && let Poll::Ready(()) = f.as_mut().poll(cx)
        {
            self.approval_signal = None;
            return Some(Fired::ApprovalSignal);
        }
        if let Some(f) = self.approval_expiry.as_mut()
            && let Poll::Ready(()) = f.as_mut().poll(cx)
        {
            self.approval_expiry = None;
            return Some(Fired::ApprovalExpiry);
        }
        if let Poll::Ready(()) = self.recheck.as_mut().poll(cx) {
            return Some(Fired::Recheck);
        }
        if let Some(f) = self.next_event.as_mut()
            && let Poll::Ready(ev) = f.as_mut().poll(cx)
        {
            return Some(match ev {
                Some(ev) => {
                    // One `next_event()` call per event (the `Session`
                    // contract): the next pull is armed now so the
                    // completed future is never polled again.
                    self.next_event = Some(self.session.next_event());
                    Fired::Event(Some(Box::new(ev)))
                }
                // `events = nil` — the closed stream is left `None`.
                None => {
                    self.next_event = None;
                    Fired::Event(None)
                }
            });
        }
        None
    }
}

/// `budgetCause` — the bound that made Central stop the session (3d
/// decision 6); the first cause wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetCause {
    WallClock,
    Cost,
    Tokens,
}

impl BudgetCause {
    /// `code` — the bounded failure reason of a Run Central stopped for
    /// this cause.
    fn code(self) -> FailureCode {
        match self {
            Self::Cost => FailureCode::BUDGET_COST,
            Self::Tokens => FailureCode::BUDGET_TOKENS,
            Self::WallClock => FailureCode::BUDGET_WALL_CLOCK,
        }
    }
}

// ---------------------------------------------------------------------------
// Small pure helpers — upstream's free functions
// ---------------------------------------------------------------------------

/// `transient` — a write failure worth retrying while the heartbeat
/// keeps the lease: everything except the permanent sentinels (domain
/// refusals, ctx/lifecycle sentinels) and `Permanent()` kinds.
pub(crate) fn transient(e: &Failure) -> bool {
    use central_foundation::failure::FailureKind as K;
    if matches!(e.kind(), K::Invalid | K::Denied | K::Cancelled) {
        return false;
    }
    !matches!(
        e.code(),
        codes::LEASE_LOST
            | codes::NOT_STARTABLE
            | codes::CANCEL_REQUESTED
            | codes::BRIDGE_UNAVAILABLE
            | codes::RESUME_UNAVAILABLE
            | domain::codes::FENCE_MISMATCH
            | domain::codes::VERSION_CONFLICT
            | domain::codes::LIVE_ATTEMPT_EXISTS
            | domain::codes::EVENT_CONFLICT
            | domain::codes::INVALID_ATTEMPT
            | domain::codes::INVALID_EVENT
            | domain::codes::INVALID_TRANSITION
            | domain::codes::ATTEMPT_NOT_FOUND
            | domain::codes::INVALID_APPROVAL
            | domain::codes::APPROVAL_NOT_PENDING
            | domain::codes::INPUT_MAC_MISMATCH
            | domain::codes::NO_PENDING_APPROVAL
            | domain::codes::CHAIN_BUDGET_EXHAUSTED
            | domain::codes::RESUME_NOT_ALLOWED
    )
}

/// `protocolError` — the harness domain refused the event itself; the
/// harness spoke a bad protocol.
fn protocol_error(e: &Failure) -> bool {
    matches!(
        e.code(),
        domain::codes::INVALID_EVENT
            | domain::codes::EVENT_CONFLICT
            | domain::codes::INVALID_TRANSITION
            | domain::codes::INVALID_ATTEMPT
    )
}

/// `billedTokens` — the token ceiling counts billed tokens: in, out and
/// cache writes, saturating (3l decision 1). Cache reads are not
/// counted.
pub(crate) fn billed_tokens(u: &Usage) -> i64 {
    let mut sum: i64 = 0;
    for n in [u.tokens_in, u.tokens_out, u.cache_write] {
        if n <= 0 {
            continue;
        }
        if n > i64::MAX - sum {
            return i64::MAX;
        }
        sum += n;
    }
    sum
}

/// `settlementFor` — a terminal attempt's Run settlement (decision 8).
fn settlement_for(a: &Attempt) -> Settlement {
    if a.state == State::Succeeded {
        return Settlement {
            succeeded: true,
            reason: FailureCode::default(),
        };
    }
    if !a.terminal.reason.is_empty() {
        return Settlement {
            succeeded: false,
            reason: FailureCode::new(a.terminal.reason.clone()),
        };
    }
    let reason = if a.terminal.status == TerminalStatus::MaxTurns {
        FailureCode::MAX_TURNS
    } else if a.state == State::BudgetExhausted {
        FailureCode::BUDGET
    } else if a.state == State::Interrupted || a.state == State::Killed {
        FailureCode::ABORTED
    } else {
        FailureCode::EXECUTION_FAILED
    };
    Settlement {
        succeeded: false,
        reason,
    }
}

/// `outcomeOf`.
fn outcome_of(s: &Settlement) -> Outcome {
    if s.succeeded {
        Outcome::Succeeded
    } else {
        Outcome::Failed
    }
}

/// `mustState` — the attempt state a terminal reports.
fn must_state(t: &Terminal) -> State {
    t.state().unwrap_or(State::Failed)
}

/// `captureFailure` — a `WorkspaceCapture` error's bounded reason.
fn capture_failure(e: &Failure) -> FailureCode {
    if e.code() == codes::CAPTURE_TOO_LARGE {
        FailureCode::ARTIFACT_TOO_LARGE
    } else {
        FailureCode::ARTIFACT_CAPTURE_FAILED
    }
}

/// The error a [`Race::Ended`] reports where upstream's `err` was the
/// ctx error.
fn ended_err(end: End) -> Failure {
    match end {
        End::Lost => Failure::conflict(codes::LEASE_LOST, "the execution lease is gone"),
        _ => Failure::cancelled(codes::ATTEMPT_ENDED, "the attempt context ended"),
    }
}

// ---------------------------------------------------------------------------
// AttemptRun — one in-flight attempt
// ---------------------------------------------------------------------------

/// The placeholder for [`AttemptRun::attempt`] before `prepare` — never
/// read: `created`/`state` gates guard every use.
pub(crate) fn blank_attempt() -> Attempt {
    Attempt {
        id: HarnessAttemptId::from_trusted_db_bytes([0; 16]),
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        run_id: central_foundation::identity::RunId::from_trusted_db_bytes([0; 16]),
        kind: Kind::new("unset"),
        adapter_version: String::new(),
        harness_version: String::new(),
        harness_session_id: String::new(),
        resume_of: None,
        resume_session_id: String::new(),
        workspace: Workspace::default(),
        permission: PermissionPolicy::Deny,
        sandbox_scope_id: String::new(),
        fence: Fence { generation: 0 },
        version: 0,
        state: State::Prepared,
        pending_permission: String::new(),
        terminal: Terminal::default(),
        resolution: Resolution::default(),
        ambiguity_reason: String::new(),
        last_event_seq: 0,
        usage: Usage::default(),
        budget: Budget::default(),
        prepared_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        ended_at: None,
    }
}

/// The state of one in-flight attempt — upstream's `attemptRun`. The
/// session is a `drive` local: Rust's ownership makes its `Drop` the
/// lifeline's close, and parameter-passing keeps `&mut self` free for
/// durable-write borrows (the upstream `r.session` field).
struct AttemptRun<'o> {
    o: &'o Orchestrator,
    /// Standing arms + end/cancel state (`r.ctx`/`r.hb*`/`r.cancelReq`).
    standing: Standing<'o>,
    /// The claimed Run.
    run: ClaimedRun,
    /// `r.harnessVersion` — recorded on `launching`.
    harness_version: String,
    /// `r.fence` — `run.lease.fence()`.
    fence: Fence,
    /// `r.store` — the lease-bound attempt store.
    store: Box<dyn AttemptStore>,
    /// `r.attempt`.
    attempt: Attempt,
    /// `r.created` — the attempt row exists.
    created: bool,
    /// `r.resume` — a resume's source (fixed continuation prompt).
    resume: Option<ResumeFrom>,
    /// `r.session != nil` — a session was handed to `drive`.
    session_started: bool,
    /// `r.bridge`.
    bridge: BridgeState,
    /// `r.budgetCause` — the first budget bound that stopped it.
    budget_cause: Option<BudgetCause>,
    /// `r.cancelHit` — the cancel arm was consumed.
    cancel_consumed: bool,
    /// `r.interruptSent`.
    interrupt_sent: bool,
    /// `r.killSent`.
    kill_sent: bool,
    /// `r.stopAfterEnd` — Interrupt hit `SESSION_ENDED`.
    stop_after_end: bool,
    /// `r.completed` — the Run's settlement committed.
    completed: bool,
    /// `r.captured` — `runCapture` ran.
    captured: bool,
    /// `r.lowDisk`.
    low_disk: bool,
    /// `r.intended` — the intended terminal when its write failed.
    intended: Option<State>,
    /// `r.report` — the last complete assistant message.
    report: String,
}

impl<'o> AttemptRun<'o> {
    fn new(
        o: &'o Orchestrator,
        run: ClaimedRun,
        harness_version: &str,
        stop: &'o dyn CancelSignal,
    ) -> Self {
        let fence = run.lease.fence();
        Self {
            store: o.deps.attempts.with_lease(run.lease),
            standing: Standing::new(o, run.clone(), stop),
            o,
            run,
            harness_version: harness_version.to_string(),
            fence,
            attempt: blank_attempt(),
            created: false,
            resume: None,
            session_started: false,
            bridge: BridgeState::default(),
            budget_cause: None,
            cancel_consumed: false,
            interrupt_sent: false,
            kill_sent: false,
            stop_after_end: false,
            completed: false,
            captured: false,
            low_disk: false,
            intended: None,
            report: String::new(),
        }
    }

    /// `r.now` — never behind the attempt's last write.
    fn now(&self) -> OffsetDateTime {
        let t = self.o.deps.clock.now();
        if t < self.attempt.updated_at {
            self.attempt.updated_at
        } else {
            t
        }
    }

    /// `r.leaseStale` — no heartbeat has succeeded for a lease duration.
    fn lease_stale(&self) -> bool {
        self.o.deps.clock.now() - self.standing.last_beat_at
            > 3 * self.o.deps.cfg.heartbeat_interval
    }

    /// `r.cancelRequested` — the cancel was requested (cancelReq closed).
    fn cancel_requested(&self) -> bool {
        self.standing.cancel_hit
    }

    /// `r.requestCancel` — the heartbeat/decision's cancel record.
    fn request_cancel(&mut self) {
        self.standing.attempt_id = self.attempt.id;
        self.standing.request_cancel();
    }

    /// `r.bridging`.
    fn bridging(&self) -> bool {
        self.attempt.permission == PermissionPolicy::Bridge
    }

    /// `r.stopping` — the Run is being stopped (cancel or budget).
    fn stopping(&self) -> bool {
        self.cancel_consumed || self.budget_cause.is_some() || self.standing.cancel_hit
    }

    /// `r.interrupted` — `Some(res)` when the end fired.
    fn interrupted(&self) -> Option<HarnessResult> {
        match self.standing.end {
            End::Lost => Some(HarnessResult {
                outcome: Outcome::Lost,
                reason: FailureCode::LEASE_LOST,
                low_disk: self.low_disk,
                settle_failed: false,
                err: Some(Failure::conflict(
                    codes::LEASE_LOST,
                    "the execution lease is gone",
                )),
            }),
            End::Stopped => Some(HarnessResult {
                outcome: Outcome::Stopped,
                reason: FailureCode::default(),
                low_disk: self.low_disk,
                settle_failed: false,
                err: Some(Failure::cancelled(
                    codes::ATTEMPT_ENDED,
                    "serve stop requested",
                )),
            }),
            End::Live => None,
        }
    }

    /// `r.lostOrStopped` — a write error that is the end: a lost lease
    /// or fence conflict ends the attempt as lost.
    fn lost_or_stopped(&mut self, err: &Failure) -> Option<HarnessResult> {
        if err.code() == codes::LEASE_LOST || err.code() == domain::codes::FENCE_MISMATCH {
            self.standing.end_with(End::Lost);
            return self.interrupted();
        }
        self.interrupted()
    }

    /// `r.stopAnswering` — drop the attempt's approvals: no operator
    /// decision may land that the harness would never receive.
    fn stop_answering(&self) {
        if !self.attempt.id.is_nil() {
            self.o.approvals.drop_attempt(self.attempt.id);
        }
    }

    /// `r.stopForBudget` — the first cause wins; stop answering.
    fn stop_for_budget(&mut self, cause: BudgetCause) {
        if self.budget_cause.is_none() {
            self.budget_cause = Some(cause);
        }
        self.stop_answering();
    }

    /// `r.stopHeartbeat`.
    fn stop_heartbeat(&mut self) {
        self.standing.hb_stopped = true;
    }

    /// `r.save` — `retry(→ store.Save(r.ctx, attempt, next, open...))`.
    async fn save<'b>(
        &'b mut self,
        next: &'b Attempt,
        open: &'b [ApprovalOpen],
    ) -> Result<(), Failure> {
        let stored = {
            let store = &*self.store;
            let expected = &self.attempt;
            self.standing
                .retry(false, move || store.save(expected, next, open))
                .await?
        };
        self.attempt = stored;
        Ok(())
    }

    // ------------------------------------------------------------------
    // execute — upstream's spine
    // ------------------------------------------------------------------

    async fn execute_inner(&mut self) -> HarnessResult {
        // CheckFreeSpace — under the work ctx (orchestrator.go:501):
        // a Task cancel aborts a hanging check.
        match self
            .standing
            .work_race(self.o.deps.workspaces.check_free_space())
            .await
        {
            Race::Done(Ok(())) => {}
            Race::Done(Err(e)) => {
                if let Some(r) = self.interrupted() {
                    return r;
                }
                if self.cancel_requested() {
                    return self.cancel_prepared().await;
                }
                return self
                    .abandon(
                        FailureCode::WORKSPACE_UNAVAILABLE,
                        e.code() == codes::LOW_DISK,
                        Some(e),
                    )
                    .await;
            }
            Race::Ended => {
                if let Some(r) = self.interrupted() {
                    return r;
                }
            }
        }

        // ResumeFrom — retried under the work ctx.
        let mut resuming = false;
        {
            let src = &*self.o.deps.cfg.resume;
            let run = self.run.clone();
            match self
                .standing
                .retry(true, move || src.resume_from(run.clone()))
                .await
            {
                Ok(Some(from)) => {
                    self.resume = Some(from);
                    resuming = true;
                }
                Ok(None) => {}
                Err(e) => {
                    if let Some(r) = self.interrupted() {
                        return r;
                    }
                    if self.cancel_requested() {
                        return self.cancel_prepared().await;
                    }
                    if e.code() == domain::codes::CHAIN_BUDGET_EXHAUSTED {
                        return self.abandon(FailureCode::BUDGET_COST, false, Some(e)).await;
                    }
                    return self
                        .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                        .await;
                }
            }
        }

        let id = match crate::recovery::attempt_id_for_step_attempt(self.run.step_attempt_id) {
            Ok(id) => id,
            Err(e) => {
                return self
                    .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                    .await;
            }
        };
        let permission = if self.run.permission.known() {
            self.run.permission
        } else {
            PermissionPolicy::Deny
        };
        let prepared = if resuming {
            match self.prepare_resume(id, permission).await {
                Ok(p) => p,
                Err(res) => return res,
            }
        } else {
            match self.prepare_fresh(id, permission).await {
                Ok(p) => p,
                Err(res) => return res,
            }
        };

        // Create — a `VERSION_CONFLICT` may be a re-claimed successor.
        {
            let store = &*self.store;
            {
                let prepared_ref = &prepared;
                match self
                    .standing
                    .retry(false, move || store.create(prepared_ref))
                    .await
                {
                    Ok(()) => {
                        self.standing.attempt_id = prepared.id;
                        self.attempt = prepared;
                        self.created = true;
                    }
                    Err(e) => {
                        if let Some(r) = self.lost_or_stopped(&e) {
                            return r;
                        }
                        if e.code() != domain::codes::VERSION_CONFLICT {
                            return self
                                .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                                .await;
                        }
                        if let Err(res) = self.adopt_prepared(&prepared).await {
                            return res;
                        }
                    }
                }
            }
        }

        if self.cancel_requested() {
            return self.cancel_prepared().await;
        }
        {
            let life = &*self.o.deps.lifecycle;
            let run = self.run.clone();
            match self
                .standing
                .retry(false, move || life.mark_invoked(run.clone()))
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    if let Some(r) = self.lost_or_stopped(&e) {
                        return r;
                    }
                    if e.code() == codes::CANCEL_REQUESTED {
                        self.request_cancel();
                        return self.cancel_prepared().await;
                    }
                    return self
                        .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                        .await;
                }
            }
        }
        self.launch().await
    }

    /// `workspaceFailure` — a failed `provision`/`reopen`: stop/cancel
    /// wins, else abandon `workspace_unavailable`.
    async fn workspace_failure(&mut self, err: Failure) -> HarnessResult {
        if let Some(r) = self.interrupted() {
            return r;
        }
        if self.cancel_requested() {
            return self.cancel_prepared().await;
        }
        self.abandon(
            FailureCode::WORKSPACE_UNAVAILABLE,
            err.code() == codes::LOW_DISK,
            Some(err),
        )
        .await
    }

    /// `prepareFresh` — provision + `Attempt::prepare`. `Err(res)` ends
    /// the orchestration.
    async fn prepare_fresh(
        &mut self,
        id: HarnessAttemptId,
        permission: PermissionPolicy,
    ) -> Result<Attempt, HarnessResult> {
        if self.run.prompt.is_empty() {
            return Err(self
                .abandon(
                    FailureCode::EXECUTION_FAILED,
                    false,
                    Some(Failure::internal(
                        codes::NOT_STARTABLE,
                        "harness app: task has no instruction",
                    )),
                )
                .await);
        }
        let ws = match self
            .standing
            .work_race(
                self.o
                    .deps
                    .workspaces
                    .provision(self.run.workspace_id, self.run.run_id),
            )
            .await
        {
            Race::Done(Ok(w)) => w,
            Race::Done(Err(e)) => return Err(self.workspace_failure(e).await),
            Race::Ended => {
                if let Some(r) = self.interrupted() {
                    return Err(r);
                }
                if self.cancel_requested() {
                    return Err(self.cancel_prepared().await);
                }
                return Err(self
                    .abandon(FailureCode::EXECUTION_FAILED, false, None)
                    .await);
            }
        };
        if self.cancel_requested() {
            return Err(self.cancel_prepared().await);
        }
        match Attempt::prepare(PrepareInput {
            id,
            workspace_id: self.run.workspace_id,
            run_id: self.run.run_id,
            kind: self.o.deps.adapter.kind(),
            adapter_version: self.o.deps.cfg.adapter_version.clone(),
            workspace: ws,
            permission,
            fence: self.fence,
            budget: self.effective_budget(),
            at: self.o.deps.clock.now(),
        }) {
            Ok(p) => Ok(p),
            Err(e) => Err(self
                .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                .await),
        }
    }

    /// `prepareResume` — reopen the existing clone + `PrepareResume`.
    async fn prepare_resume(
        &mut self,
        id: HarnessAttemptId,
        permission: PermissionPolicy,
    ) -> Result<Attempt, HarnessResult> {
        let from = match self.resume.clone() {
            Some(f) => f,
            None => {
                return Err(self
                    .abandon(FailureCode::EXECUTION_FAILED, false, None)
                    .await);
            }
        };
        if from.prompt.is_empty() {
            return Err(self
                .abandon(
                    FailureCode::EXECUTION_FAILED,
                    false,
                    Some(Failure::unavailable(
                        codes::RESUME_UNAVAILABLE,
                        "no continuation prompt",
                    )),
                )
                .await);
        }
        if !self.o.deps.adapter.capabilities().resume_by_id {
            return Err(self
                .abandon(
                    FailureCode::EXECUTION_FAILED,
                    false,
                    Some(Failure::unavailable(
                        codes::RESUME_UNAVAILABLE,
                        "the adapter cannot resume a session",
                    )),
                )
                .await);
        }
        match self
            .standing
            .work_race(self.o.deps.workspaces.reopen(
                self.run.workspace_id,
                self.run.run_id,
                from.source.workspace.clone(),
            ))
            .await
        {
            Race::Done(Ok(())) => {}
            Race::Done(Err(e)) => return Err(self.workspace_failure(e).await),
            Race::Ended => {
                if let Some(r) = self.interrupted() {
                    return Err(r);
                }
                if self.cancel_requested() {
                    return Err(self.cancel_prepared().await);
                }
                return Err(self
                    .abandon(FailureCode::EXECUTION_FAILED, false, None)
                    .await);
            }
        }
        if self.cancel_requested() {
            return Err(self.cancel_prepared().await);
        }
        match Attempt::prepare_resume(
            &from.source,
            PrepareInput {
                id,
                workspace_id: self.run.workspace_id,
                run_id: self.run.run_id,
                kind: self.o.deps.adapter.kind(),
                adapter_version: self.o.deps.cfg.adapter_version.clone(),
                workspace: from.source.workspace.clone(),
                permission,
                fence: self.fence,
                budget: from.budget,
                at: self.o.deps.clock.now(),
            },
        ) {
            Ok(p) => Ok(p),
            Err(e) => Err(self
                .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                .await),
        }
    }

    /// `adoptPrepared` — a `VERSION_CONFLICT` row may be a re-claimed
    /// prepared successor: adopt the never-launched row under the new
    /// lease. `Err(res)` ends the orchestration.
    async fn adopt_prepared(&mut self, prepared: &Attempt) -> Result<(), HarnessResult> {
        let stored = match self
            .standing
            .race(self.store.load(prepared.workspace_id, prepared.id))
            .await
        {
            Race::Done(Ok(a)) => a,
            Race::Done(Err(e)) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return Err(r);
                }
                return Err(self
                    .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                    .await);
            }
            Race::Ended => {
                if let Some(r) = self.interrupted() {
                    return Err(r);
                }
                return Err(self
                    .abandon(FailureCode::EXECUTION_FAILED, false, None)
                    .await);
            }
        };
        if stored.state != State::Prepared
            || stored.run_id != prepared.run_id
            || stored.kind != prepared.kind
            || stored.fence.generation >= self.fence.generation
            || stored.resume_of != prepared.resume_of
            || stored.resume_session_id != prepared.resume_session_id
        {
            return Err(self
                .abandon(
                    FailureCode::EXECUTION_FAILED,
                    false,
                    Some(Failure::conflict(
                        domain::codes::VERSION_CONFLICT,
                        format!(
                            "attempt exists as {} at fence {}",
                            stored.state.as_str(),
                            stored.fence.generation
                        ),
                    )),
                )
                .await);
        }
        if stored.workspace != prepared.workspace {
            return Err(self
                .abandon(
                    FailureCode::WORKSPACE_UNAVAILABLE,
                    false,
                    Some(Failure::unavailable(
                        codes::WORKSPACE_UNAVAILABLE,
                        "the source changed since the attempt was prepared",
                    )),
                )
                .await);
        }
        self.standing.attempt_id = stored.id;
        self.attempt = stored.clone();
        self.created = true;
        match stored.refence(stored.fence, self.fence, self.now()) {
            Ok(next) => match self.save(&next, &[]).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    if let Some(r) = self.lost_or_stopped(&e) {
                        return Err(r);
                    }
                    Err(self
                        .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                        .await)
                }
            },
            Err(e) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return Err(r);
                }
                Err(self
                    .abandon(FailureCode::EXECUTION_FAILED, false, Some(e))
                    .await)
            }
        }
    }

    /// `closeUnlaunched` — a created still-prepared row takes the
    /// never-launched terminal while the lease authorizes it.
    /// `Err(res)` ends the orchestration.
    async fn close_unlaunched(&mut self) -> Result<(), HarnessResult> {
        if !self.created || self.attempt.state != State::Prepared {
            return Ok(());
        }
        let res = match self.attempt.fail_unlaunched(self.fence, self.now()) {
            Ok(next) => self.save(&next, &[]).await,
            Err(e) => Err(e),
        };
        if let Err(e) = res
            && let Some(r) = self.lost_or_stopped(&e)
        {
            return Err(r);
        }
        Ok(())
    }

    /// `cancelPrepared` — a never-invoked Run whose Task is cancelling.
    async fn cancel_prepared(&mut self) -> HarnessResult {
        if let Err(res) = self.close_unlaunched().await {
            return res;
        }
        self.settle_cancellation(None).await
    }

    /// `settleCancellation` — settle a requested cancellation.
    async fn settle_cancellation(&mut self, cause: Option<Failure>) -> HarnessResult {
        let status = if self.attempt.state.is_terminal() {
            self.attempt.state.as_str().to_string()
        } else {
            ports::MILESTONE_REASON_CANCELLED.to_string()
        };
        self.stop_heartbeat();
        let life = &*self.o.deps.lifecycle;
        let run = self.run.clone();
        match self
            .standing
            .retry(false, move || life.settle_cancellation(run.clone()))
            .await
        {
            Ok(()) => {
                self.milestone(
                    MilestoneKind::Terminal,
                    "terminal",
                    &status,
                    ports::MILESTONE_REASON_CANCELLED,
                )
                .await;
                HarnessResult {
                    outcome: Outcome::Cancelled,
                    reason: FailureCode::default(),
                    low_disk: self.low_disk,
                    settle_failed: false,
                    err: cause,
                }
            }
            Err(e) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return r;
                }
                self.settle_failed(
                    HarnessResult {
                        outcome: Outcome::Cancelled,
                        reason: FailureCode::default(),
                        low_disk: self.low_disk,
                        settle_failed: false,
                        err: Some(e),
                    },
                    &status,
                    ports::MILESTONE_REASON_CANCELLED,
                )
                .await
            }
        }
    }

    /// `abandon` — a never-invoked Run (decision 2): the row takes the
    /// never-launched terminal, then `abandon_prepared` fails Task+Run.
    async fn abandon(
        &mut self,
        reason: FailureCode,
        low_disk: bool,
        cause: Option<Failure>,
    ) -> HarnessResult {
        self.low_disk = self.low_disk || low_disk;
        if let Err(res) = self.close_unlaunched().await {
            return res;
        }
        if self.cancel_requested() {
            return self.settle_cancellation(cause).await;
        }
        self.stop_heartbeat();
        let life = &*self.o.deps.lifecycle;
        let run = self.run.clone();
        let reason2 = reason.clone();
        match self
            .standing
            .retry(false, move || {
                life.abandon_prepared(run.clone(), reason2.clone())
            })
            .await
        {
            Ok(()) => {
                self.milestone(
                    MilestoneKind::Terminal,
                    "terminal",
                    "failed",
                    reason.as_str(),
                )
                .await;
                HarnessResult {
                    outcome: Outcome::Abandoned,
                    reason,
                    low_disk: self.low_disk,
                    settle_failed: false,
                    err: cause,
                }
            }
            Err(e) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return r;
                }
                if e.code() == codes::CANCEL_REQUESTED {
                    return self.settle_cancellation(cause).await;
                }
                self.settle_failed(
                    HarnessResult {
                        outcome: Outcome::Abandoned,
                        reason: reason.clone(),
                        low_disk: self.low_disk,
                        settle_failed: false,
                        err: Some(e),
                    },
                    "failed",
                    reason.as_str(),
                )
                .await
            }
        }
    }

    /// `effectiveBudget` — the claim's bounds with defaults flagged.
    fn effective_budget(&self) -> Budget {
        let mut b = self.run.budget;
        if b.cost_micro_usd <= 0 {
            b.cost_micro_usd = self.o.deps.cfg.default_cost_micro_usd;
            b.cost_defaulted = true;
        }
        if b.wall_clock <= Duration::ZERO {
            b.wall_clock = self.o.deps.cfg.default_wall_clock;
            b.wall_clock_defaulted = true;
        }
        b
    }

    // ------------------------------------------------------------------
    // launch + drive
    // ------------------------------------------------------------------

    /// `launch` — `launching`, then adapter start outside any
    /// transaction (decision 3), then `drive`.
    async fn launch(&mut self) -> HarnessResult {
        let scope = self.attempt.id.to_string();
        let launching =
            match self
                .attempt
                .launch(self.fence, &scope, &self.harness_version, self.now())
            {
                Ok(l) => l,
                Err(e) => {
                    return self
                        .finish(
                            Terminal {
                                status: TerminalStatus::Failed,
                                reason: FailureCode::LAUNCH_FAILED.to_string(),
                                ..Terminal::default()
                            },
                            None,
                            Some(e),
                        )
                        .await;
                }
            };
        if let Err(e) = self.save(&launching, &[]).await {
            if let Some(r) = self.lost_or_stopped(&e) {
                return r;
            }
            return self
                .finish(
                    Terminal {
                        status: TerminalStatus::Failed,
                        reason: FailureCode::LAUNCH_FAILED.to_string(),
                        ..Terminal::default()
                    },
                    None,
                    Some(e),
                )
                .await;
        }
        // The native cost limit goes to the harness only when the
        // adapter enforces one (3d decision 5).
        let max_cost = if self.o.deps.adapter.capabilities().native_cost_limit {
            self.attempt.budget.cost_micro_usd
        } else {
            0
        };
        let spec = StartSpec {
            attempt: self.attempt.id,
            fence: self.fence,
            workspace: self.attempt.workspace.clone(),
            prompt: if self.attempt.resume_of.is_some() {
                self.resume
                    .as_ref()
                    .map(|r| r.prompt.clone())
                    .unwrap_or_default()
            } else {
                self.run.prompt.clone()
            },
            model: self.o.deps.cfg.model.clone(),
            permission: self.attempt.permission,
            limits: crate::port::Limits {
                max_turns: 0,
                max_cost_micro_usd: max_cost,
            },
            env: crate::port::LaunchEnv {
                vars: self.o.deps.cfg.launch_env.clone(),
                sandbox_scope_id: scope.clone(),
            },
        };
        let res = {
            let adapter = &*self.o.deps.adapter;
            if self.attempt.resume_of.is_some() {
                // Upstream calls `Adapter.Resume` unconditionally once
                // `ResumeOf` is set (orchestrator.go:811-819): the
                // adapter's own error becomes `launch_failed` — a
                // capability gate here would start a fresh session on
                // a resume-prepared attempt instead.
                let spec2 = spec.clone();
                self.standing
                    .race(adapter.resume(
                        SessionRef {
                            harness_session_id: self.attempt.resume_session_id.clone(),
                        },
                        spec2,
                    ))
                    .await
            } else {
                self.standing.race(adapter.start(spec)).await
            }
        };
        let session = match res {
            Race::Done(Ok(s)) => s,
            Race::Done(Err(e)) => {
                if let Some(r) = self.interrupted() {
                    return r;
                }
                return self
                    .finish(
                        Terminal {
                            status: TerminalStatus::Failed,
                            reason: FailureCode::LAUNCH_FAILED.to_string(),
                            ..Terminal::default()
                        },
                        None,
                        Some(e),
                    )
                    .await;
            }
            Race::Ended => {
                if let Some(r) = self.interrupted() {
                    return r;
                }
                return self
                    .finish(
                        Terminal {
                            status: TerminalStatus::Failed,
                            reason: FailureCode::LAUNCH_FAILED.to_string(),
                            ..Terminal::default()
                        },
                        None,
                        Some(ended_err(self.standing.end)),
                    )
                    .await;
            }
        };
        self.session_started = true;
        self.milestone(MilestoneKind::AttemptLaunched, "launched", "launching", "")
            .await;
        self.drive(session).await
    }

    /// `drive` — the event loop.
    async fn drive(&mut self, session: Box<dyn Session>) -> HarnessResult {
        let session: &dyn Session = &*session;
        let mut arms = DriveArms {
            session,
            next_event: Some(session.next_event()),
            wall: Some(
                self.o
                    .deps
                    .ticker
                    .after(self.attempt.budget.wall_clock.max(Duration::nanoseconds(1))),
            ),
            kill_timer: None,
            kill_pending: None,
            approval_signal: None,
            approval_expiry: None,
            recheck: self.o.deps.ticker.after(self.o.deps.cfg.approval_recheck),
        };
        while arms.next_event.is_some() {
            let fired = std::future::poll_fn(|cx| {
                self.standing.poll(cx);
                if self.standing.ended() {
                    return Poll::Ready(Fired::End);
                }
                if self.standing.cancel_hit && !self.cancel_consumed {
                    return Poll::Ready(Fired::Cancel);
                }
                match arms.poll(cx) {
                    Some(f) => Poll::Ready(f),
                    None => Poll::Pending,
                }
            })
            .await;
            match fired {
                Fired::End => {
                    let res = self.interrupted();
                    self.close_lifeline(session).await;
                    return match res {
                        Some(r) => r,
                        None => self.stop_result(),
                    };
                }
                Fired::Cancel => {
                    self.cancel_consumed = true;
                    self.stop_answering();
                    if arms.kill_timer.is_none() && !self.kill_sent {
                        arms.kill_timer = self.interrupt(session, &mut arms).await;
                    }
                }
                Fired::Event(None) => {}
                Fired::Event(Some(ev)) => {
                    let ev = *ev;
                    if let Err(e) = self.persist_event(session, &mut arms, ev.clone()).await {
                        if self.lost_or_stopped(&e).is_some() {
                            self.close_lifeline(session).await;
                            return match self.interrupted() {
                                Some(r) => r,
                                None => self.stop_result(),
                            };
                        }
                        if e.code() == codes::BRIDGE_UNAVAILABLE {
                            return self.fail_bridge(session, e).await;
                        }
                        let reason = if protocol_error(&e) {
                            FailureCode::PROTOCOL_ERROR
                        } else {
                            FailureCode::EXECUTION_FAILED
                        };
                        self.close_lifeline(session).await;
                        return self
                            .finish(
                                Terminal {
                                    status: TerminalStatus::Failed,
                                    reason: reason.to_string(),
                                    ..Terminal::default()
                                },
                                Some(session),
                                Some(e),
                            )
                            .await;
                    }
                    if self.cost_reached(&ev) {
                        self.stop_for_budget(BudgetCause::Cost);
                        if arms.kill_timer.is_none() && !self.kill_sent {
                            arms.kill_timer = self.interrupt(session, &mut arms).await;
                        }
                    }
                    if self.tokens_reached(&ev) {
                        self.stop_for_budget(BudgetCause::Tokens);
                        if arms.kill_timer.is_none() && !self.kill_sent {
                            arms.kill_timer = self.interrupt(session, &mut arms).await;
                        }
                    }
                }
                Fired::Wall => {
                    if self.standing.cancel_hit {
                        continue;
                    }
                    self.stop_for_budget(BudgetCause::WallClock);
                    if arms.kill_timer.is_none() && !self.kill_sent {
                        arms.kill_timer = self.interrupt(session, &mut arms).await;
                    }
                }
                Fired::KillTimer => {
                    self.kill_async(session, &mut arms);
                }
                Fired::KillDone => {}
                Fired::ApprovalSignal => {
                    if let Err(e) = self.poll_approval(session, &mut arms, false).await {
                        return self.fail_bridge(session, e).await;
                    }
                }
                Fired::ApprovalExpiry => {
                    if let Err(e) = self.poll_approval(session, &mut arms, true).await {
                        return self.fail_bridge(session, e).await;
                    }
                }
                Fired::Recheck => {
                    arms.recheck = self.o.deps.ticker.after(self.o.deps.cfg.approval_recheck);
                    if let Err(e) = self.poll_approval(session, &mut arms, false).await {
                        return self.fail_bridge(session, e).await;
                    }
                }
            }
        }
        if !self.attempt.state.is_terminal() {
            let res = self
                .standing
                .race(bounded(
                    session.wait(),
                    self.o.deps.ticker.after(SESSION_WAIT_BUDGET),
                ))
                .await;
            let waited = match res {
                Race::Done(Bounded::Done(Ok(t))) if t.status != TerminalStatus::Unset => Some(t),
                _ => None,
            };
            if let Some(r) = self.interrupted() {
                return r;
            }
            let terminal = match waited {
                Some(t) => self.budgeted(t),
                None => {
                    if self.standing.cancel_hit {
                        self.budgeted(self.stopped_terminal())
                    } else {
                        self.budgeted(Terminal {
                            status: TerminalStatus::Failed,
                            reason: FailureCode::EXITED_WITHOUT_RESULT.to_string(),
                            ..Terminal::default()
                        })
                    }
                }
            };
            return self.finish(terminal, Some(session), None).await;
        }
        self.settle_with(settlement_for(&self.attempt), None, Some(session))
            .await
    }

    /// `stopResult` — the `interrupted()` result when the end fired
    /// (the `select`'s `ctx.Done` arm).
    fn stop_result(&self) -> HarnessResult {
        match self.interrupted() {
            Some(r) => r,
            None => HarnessResult {
                outcome: Outcome::Stopped,
                reason: FailureCode::default(),
                low_disk: self.low_disk,
                settle_failed: false,
                err: Some(Failure::cancelled(
                    codes::ATTEMPT_ENDED,
                    "serve stop requested",
                )),
            },
        }
    }

    /// `stoppedTerminal` — the terminal of a session stopped for a
    /// cancellation that never reported one.
    fn stopped_terminal(&self) -> Terminal {
        if self.kill_sent {
            Terminal {
                status: TerminalStatus::Killed,
                reason: FailureCode::ABORTED.to_string(),
                ..Terminal::default()
            }
        } else {
            Terminal {
                status: TerminalStatus::Interrupted,
                reason: FailureCode::ABORTED.to_string(),
                ..Terminal::default()
            }
        }
    }

    /// `persistEvent` — apply + durable append + milestones.
    async fn persist_event<'a>(
        &mut self,
        session: &'a dyn Session,
        arms: &mut DriveArms<'a>,
        ev: Event,
    ) -> Result<(), Failure>
    where
        'o: 'a,
    {
        let request = match ev.payload.as_ref() {
            Some(EventPayload::PermissionRequested(p)) => Some(p.clone()),
            _ => None,
        };
        let bridged = request.is_some() && self.bridging();
        let rec = record_of(&ev, &self.o.input_mac_key).map_err(|e| {
            if bridged {
                bridge::bridge_failure(e)
            } else {
                e
            }
        })?;
        let mut open: Option<ApprovalOpen> = None;
        if bridged && let Some(p) = request.as_ref() {
            open = self.requested(p)?;
        }
        if let Some(EventPayload::PermissionResolved(p)) = ev.payload.as_ref()
            && self.bridging()
        {
            self.unanswered(p)?;
        }
        let next = match self.apply(&ev) {
            Ok(n) => n,
            Err(e) => {
                if bridged {
                    return Err(bridge::bridge_failure(e));
                }
                return Err(e);
            }
        };
        if let Err(e) = self.append_event(&next, &rec, open.as_slice()).await {
            if open.is_some()
                && e.code() != codes::LEASE_LOST
                && e.code() != domain::codes::FENCE_MISMATCH
                && !self.standing.ended()
            {
                return Err(bridge::bridge_failure(e));
            }
            return Err(e);
        }
        if let (Some(o), Some(p)) = (open, request) {
            self.opened(o, p, arms).await?;
        }
        let seq = ev.seq.to_string();
        match ev.payload {
            Some(EventPayload::Message(m)) => {
                if m.role == MessageRole::Assistant && !m.partial {
                    self.report = m.text;
                }
            }
            Some(EventPayload::SessionStarted(_)) => {
                self.milestone(
                    MilestoneKind::SessionStarted,
                    "session_started",
                    "running",
                    "",
                )
                .await;
            }
            Some(EventPayload::PermissionRequested(p)) => {
                if !self.bridging() {
                    // Deny/AutoAllow never bridge: an adapter that
                    // honours them answers itself; one that reaches us
                    // anyway is denied.
                    let d = PermissionDecision {
                        request_id: p.request_id,
                        allow: false,
                        option_id: String::new(),
                        decided_by: bridge::DECIDED_BY_POLICY_DENY.to_string(),
                        input_sha256: [0; 32],
                    };
                    let _ = bounded(
                        session.respond_permission(d),
                        self.o.deps.ticker.after(PERMISSION_ANSWER_BUDGET),
                    )
                    .await;
                }
            }
            Some(EventPayload::PermissionResolved(p)) => {
                let (kind, status) = if p.decision == PermissionOutcome::Allowed {
                    (MilestoneKind::PermissionAllowed, "allow")
                } else {
                    (MilestoneKind::PermissionDenied, "deny")
                };
                let reason = decided_by_code(&p.decided_by);
                self.milestone(kind, &format!("seq:{seq}"), status, reason)
                    .await;
                if self.bridging()
                    && let Err(e) = self.resolved(&p, arms).await
                {
                    return Err(e);
                }
            }
            Some(EventPayload::ToolResult(t)) => {
                if t.status == ToolStatus::Denied {
                    self.milestone(
                        MilestoneKind::PermissionDenied,
                        &format!("seq:{seq}"),
                        "deny",
                        "",
                    )
                    .await;
                }
            }
            Some(EventPayload::Retry(_)) => {
                self.milestone(MilestoneKind::Retry, &format!("seq:{seq}"), "", "")
                    .await;
            }
            _ => {}
        }
        Ok(())
    }

    /// `appendEvent` — one fenced event write under the event-write
    /// budget (review I2).
    async fn append_event<'b>(
        &'b mut self,
        next: &'b Attempt,
        rec: &'b EventRecord,
        open: &'b [ApprovalOpen],
    ) -> Result<(), Failure> {
        let deadline = self.o.deps.clock.now() + self.o.deps.cfg.event_write_budget;
        let mut backoff = WRITE_BACKOFF;
        loop {
            let res = self
                .standing
                .race(self.store.append_event(&self.attempt, next, rec, open))
                .await;
            let last = match res {
                Race::Done(Ok(stored)) => {
                    self.attempt = stored;
                    return Ok(());
                }
                Race::Done(Err(e)) => {
                    if !transient(&e) || self.standing.ended() {
                        return Err(e);
                    }
                    e
                }
                Race::Ended => return Err(ended_err(self.standing.end)),
            };
            if self.lease_stale() {
                self.standing.end_with(End::Lost);
                return Err(Failure::conflict(
                    codes::LEASE_LOST,
                    "no heartbeat succeeded for a lease duration",
                ));
            }
            let wait = (deadline - self.o.deps.clock.now()).min(backoff);
            if wait <= Duration::ZERO {
                // `errEventWriteBudget` wraps the write's last error.
                return Err(Failure::internal(
                    last.code(),
                    format!("event write retry budget exhausted: {}", last.message()),
                ));
            }
            if let Race::Ended = self.standing.race(self.o.deps.ticker.after(wait)).await {
                // Upstream returns the write's error, not the ctx's.
                return Err(last);
            }
            backoff = (backoff + backoff).min(EVENT_WRITE_BACKOFF_MAX);
        }
    }

    /// `apply` — one event's attempt transition.
    fn apply(&self, ev: &Event) -> Result<Attempt, Failure> {
        let at = self.now();
        let mut next = self.attempt.clone();
        if let Some(EventPayload::SessionStarted(s)) = ev.payload.as_ref() {
            next = next.reveal_session(self.fence, &s.harness_session_id, at)?;
        }
        next = next.record_progress(self.fence, ev.seq, at)?;
        match ev.payload.as_ref() {
            Some(EventPayload::PermissionRequested(p)) if next.state == State::Running => {
                next.await_permission(self.fence, &p.request_id, at)
            }
            Some(EventPayload::PermissionResolved(p))
                if next.state == State::AwaitingPermission
                    && next.pending_permission == p.request_id =>
            {
                next.resolve_permission(self.fence, &p.request_id, at)
            }
            Some(EventPayload::UsageReport(u)) => next.apply_usage(self.fence, u.usage, at),
            Some(EventPayload::TerminalReported(t)) => {
                self.terminate(next, self.budgeted(t.terminal.clone()))
            }
            _ => Ok(next),
        }
    }

    /// `terminate` — a budget status the attempt's state cannot reach
    /// degrades to killed with the same reason.
    fn terminate(&self, a: Attempt, t: Terminal) -> Result<Attempt, Failure> {
        let at = self.now();
        match a.terminate(self.fence, t.clone(), at) {
            Ok(n) => Ok(n),
            Err(e)
                if e.code() == domain::codes::INVALID_TRANSITION
                    && t.status == TerminalStatus::Budget =>
            {
                let mut t2 = t;
                t2.status = TerminalStatus::Killed;
                a.terminate(self.fence, t2, at)
            }
            Err(e) => Err(e),
        }
    }

    /// `costReached` — the cost the harness reported while live reached
    /// the limit.
    fn cost_reached(&self, ev: &Event) -> bool {
        if !matches!(ev.payload, Some(EventPayload::UsageReport(_))) {
            return false;
        }
        self.budget_cause.is_none()
            && !self.cancel_consumed
            && !self.attempt.state.is_terminal()
            && self.attempt.usage.cost_micro_usd >= self.attempt.budget.cost_micro_usd
    }

    /// `tokensReached` — the token ceiling twin (3l decision 5).
    fn tokens_reached(&self, ev: &Event) -> bool {
        if !matches!(ev.payload, Some(EventPayload::UsageReport(_))) {
            return false;
        }
        self.o.deps.cfg.max_tokens > 0
            && self.budget_cause.is_none()
            && !self.cancel_consumed
            && !self.attempt.state.is_terminal()
            && billed_tokens(&self.attempt.usage) >= self.o.deps.cfg.max_tokens
    }

    /// `budgeted` — 3d's outcome rules once a bound stopped the session.
    fn budgeted(&self, t: Terminal) -> Terminal {
        let Some(cause) = self.budget_cause else {
            return t;
        };
        match t.status {
            TerminalStatus::Budget | TerminalStatus::Succeeded => return t,
            TerminalStatus::Interrupted | TerminalStatus::Killed => {}
            TerminalStatus::Failed => {
                if !self.interrupt_sent && !(self.kill_sent && !self.stop_after_end) {
                    return t;
                }
            }
            _ => return t,
        }
        Terminal {
            status: TerminalStatus::Budget,
            reason: cause.code().to_string(),
            exit_code: t.exit_code,
        }
    }

    /// `interrupt` — asks the session to stop (background ctx, bounded);
    /// returns the grace timer (or kills at once on error).
    async fn interrupt<'a>(
        &mut self,
        session: &'a dyn Session,
        arms: &mut DriveArms<'a>,
    ) -> Option<PortFuture<'a, ()>>
    where
        'o: 'a,
    {
        let res = bounded(
            session.interrupt(),
            self.o.deps.ticker.after(self.o.deps.cfg.lifeline_budget),
        )
        .await;
        match res {
            Bounded::Done(Err(e)) if e.code() == crate::port::codes::SESSION_ENDED => {
                self.stop_after_end = true;
                Some(self.o.deps.ticker.after(self.o.deps.cfg.interrupt_grace))
            }
            Bounded::Done(Err(_)) | Bounded::Elapsed => {
                self.kill_async(session, arms);
                None
            }
            Bounded::Done(Ok(())) => {
                self.interrupt_sent = true;
                Some(self.o.deps.ticker.after(self.o.deps.cfg.interrupt_grace))
            }
        }
    }

    /// `killAsync` — the grace-expired kill (a pending future standing
    /// in for the Go goroutine).
    fn kill_async<'a>(&mut self, session: &'a dyn Session, arms: &mut DriveArms<'a>)
    where
        'o: 'a,
    {
        self.kill_sent = true;
        arms.kill_pending = Some(session.kill());
    }

    /// `closeLifeline` — end the session without the kill ladder: a
    /// bounded `kill`, then the remaining events drained (upstream
    /// drains them in a background goroutine so the adapter's delivery
    /// ends; here the drain shares the lifeline budget and `Session`'s
    /// `Drop` covers whatever is left — the `Session` contract
    /// requires pulling until `None`).
    async fn close_lifeline(&mut self, session: &dyn Session) {
        let _ = bounded(
            session.kill(),
            self.o.deps.ticker.after(self.o.deps.cfg.lifeline_budget),
        )
        .await;
        let drain = async { while let Some(_ev) = session.next_event().await {} };
        let _ = bounded(
            drain,
            self.o.deps.ticker.after(self.o.deps.cfg.lifeline_budget),
        )
        .await;
    }

    // ------------------------------------------------------------------
    // finish / settle / complete — the settlement spine
    // ------------------------------------------------------------------

    /// `finish` — persist the harness terminal for a session that ended
    /// without reporting one, then settle.
    async fn finish(
        &mut self,
        t: Terminal,
        session: Option<&dyn Session>,
        cause: Option<Failure>,
    ) -> HarnessResult {
        if !self.attempt.state.is_terminal() {
            let next = self.terminate(self.attempt.clone(), t.clone());
            let err = match next {
                Ok(ref n) => self.save(n, &[]).await.err(),
                Err(e) => Some(e),
            };
            if let Some(e) = err {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return r;
                }
                // Settle from the intended terminal: the reconciler
                // mirrors the settled StepAttempt onto the row.
                self.intended = Some(must_state(&t));
                let mut a = self.attempt.clone();
                a.state = must_state(&t);
                a.terminal = t.clone();
                return self.settle_with(settlement_for(&a), cause, session).await;
            }
        }
        self.settle_with(settlement_for(&self.attempt), cause, session)
            .await
    }

    /// `settleWith` — cancellation wins; `defer releaseCapture` is the
    /// tail call.
    async fn settle_with(
        &mut self,
        s: Settlement,
        cause: Option<Failure>,
        session: Option<&dyn Session>,
    ) -> HarnessResult {
        if self.cancel_requested() {
            return self.settle_cancellation(cause).await;
        }
        let res = if s.succeeded {
            self.complete(cause.clone(), session).await
        } else {
            match self.capture_best_effort(&s.reason, session).await {
                Some(r) => r,
                None => self.settle_failure(&s, cause).await,
            }
        };
        self.release_capture().await;
        res
    }

    /// `settleFailure` — the completion receipt, then the Run's failed
    /// settlement.
    async fn settle_failure(&mut self, s: &Settlement, cause: Option<Failure>) -> HarnessResult {
        if self.cancel_requested() {
            return self.settle_cancellation(cause).await;
        }
        let status = if self.attempt.state.is_terminal() {
            self.attempt.state.as_str().to_string()
        } else {
            "failed".to_string()
        };
        let life = &*self.o.deps.lifecycle;
        let run = self.run.clone();
        let s2 = s.clone();
        match self
            .standing
            .retry(false, move || {
                life.record_completion(run.clone(), s2.clone())
            })
            .await
        {
            Ok(()) => {}
            Err(e) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return r;
                }
                if e.code() == codes::CANCEL_REQUESTED {
                    self.request_cancel();
                    return self.settle_cancellation(cause).await;
                }
                return self
                    .settle_failed(
                        HarnessResult {
                            outcome: outcome_of(s),
                            reason: s.reason.clone(),
                            low_disk: self.low_disk,
                            settle_failed: false,
                            err: Some(e),
                        },
                        &status,
                        s.reason.as_str(),
                    )
                    .await;
            }
        }
        self.stop_heartbeat();
        let run = self.run.clone();
        let s3 = s.clone();
        match self
            .standing
            .retry(false, move || life.settle(run.clone(), s3.clone()))
            .await
        {
            Ok(()) => {
                self.milestone(
                    MilestoneKind::Terminal,
                    "terminal",
                    &status,
                    s.reason.as_str(),
                )
                .await;
                HarnessResult {
                    outcome: outcome_of(s),
                    reason: s.reason.clone(),
                    low_disk: self.low_disk,
                    settle_failed: false,
                    err: cause,
                }
            }
            Err(e) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return r;
                }
                if e.code() == codes::CANCEL_REQUESTED {
                    self.request_cancel();
                    return self.settle_cancellation(cause).await;
                }
                self.settle_failed(
                    HarnessResult {
                        outcome: outcome_of(s),
                        reason: s.reason.clone(),
                        low_disk: self.low_disk,
                        settle_failed: false,
                        err: Some(e),
                    },
                    &status,
                    s.reason.as_str(),
                )
                .await
            }
        }
    }

    /// `complete` — the succeeded path (3b decision 8): capture, patch,
    /// commits, then `complete_with_report` — the only succeeding write.
    async fn complete(
        &mut self,
        cause: Option<Failure>,
        session: Option<&dyn Session>,
    ) -> HarnessResult {
        let cap = match self.run_capture(session).await {
            Ok(c) => c,
            Err(e) => {
                if let Some(r) = self.aborted(cause.clone(), session).await {
                    return r;
                }
                return self.fail_artifacts(capture_failure(&e), cause).await;
            }
        };
        for (role, path) in [
            (ArtifactRole::Patch, cap.patch.clone()),
            (ArtifactRole::Commits, cap.commits.clone()),
        ] {
            if let Some(r) = self.aborted(cause.clone(), session).await {
                return r;
            }
            // Upstream calls `Store` unconditionally (orchestrator.go:
            // 1406): the sink rejects an empty path itself.
            let (outcome, err) = self.store_artifact(role, path).await;
            if let Some(r) = self
                .on_artifact_outcome(&role, outcome, err, cause.clone(), session)
                .await
            {
                return r;
            }
        }
        if let Some(r) = self.aborted(cause.clone(), session).await {
            return r;
        }
        if self.report.trim().is_empty() {
            return self
                .fail_artifacts(FailureCode::HARNESS_REPORT_MISSING, cause)
                .await;
        }
        if self.report.len() > ports::MAX_REPORT_BYTES {
            return self
                .fail_artifacts(FailureCode::ARTIFACT_TOO_LARGE, cause)
                .await;
        }
        let res = self
            .standing
            .work_race(
                self.o
                    .deps
                    .lifecycle
                    .complete_with_report(self.run.clone(), self.report.clone().into_bytes()),
            )
            .await;
        let (outcome, err) = match res {
            Race::Done(Ok(o)) => (Some(o), None),
            Race::Done(Err(e)) => (None, Some(e)),
            Race::Ended => (None, Some(ended_err(self.standing.end))),
        };
        if let Some(r) = self
            .on_artifact_outcome(&ArtifactRole::Report, outcome, err, cause.clone(), session)
            .await
        {
            return r;
        }
        self.completed = true;
        self.stop_heartbeat();
        self.milestone(
            MilestoneKind::ArtifactsCaptured,
            "artifacts",
            "succeeded",
            "",
        )
        .await;
        self.milestone(MilestoneKind::Terminal, "terminal", "succeeded", "")
            .await;
        HarnessResult {
            outcome: Outcome::Succeeded,
            reason: FailureCode::default(),
            low_disk: self.low_disk,
            settle_failed: false,
            err: cause,
        }
    }

    /// `onArtifactOutcome` — `Some(res)` ends the orchestration.
    async fn on_artifact_outcome(
        &mut self,
        role: &ArtifactRole,
        outcome: Option<ArtifactOutcome>,
        err: Option<Failure>,
        cause: Option<Failure>,
        session: Option<&dyn Session>,
    ) -> Option<HarnessResult> {
        if err.is_none() && matches!(outcome, Some(ref o) if o.kind == ArtifactOutcomeKind::Ready) {
            return None;
        }
        if let Some(e) = err.as_ref()
            && e.code() == codes::LEASE_LOST
        {
            self.standing.end_with(End::Lost);
            return Some(HarnessResult {
                outcome: Outcome::Lost,
                reason: FailureCode::LEASE_LOST,
                low_disk: self.low_disk,
                settle_failed: false,
                err: Some(Failure::conflict(
                    codes::LEASE_LOST,
                    "the execution lease is gone",
                )),
            });
        }
        if let Some(r) = self.aborted(cause.clone(), session).await {
            return Some(r);
        }
        if let Some(e) = err.as_ref()
            && e.code() == codes::CANCEL_REQUESTED
        {
            self.request_cancel();
            return Some(self.settle_cancellation(cause).await);
        }
        if err.is_none()
            && let Some(o) = &outcome
            && matches!(
                o.kind,
                ArtifactOutcomeKind::Terminal | ArtifactOutcomeKind::Retryable
            )
        {
            let reason = if o.reason.is_empty() {
                FailureCode::ARTIFACT_CAPTURE_FAILED
            } else {
                o.reason.clone()
            };
            return Some(self.fail_artifacts(reason, cause).await);
        }
        // Unclassified error, or a reconciliation/missing outcome: the
        // ambiguity itself is the error (upstream synthesizes the
        // "not final" error here).
        let err = err.unwrap_or_else(|| {
            let kind = outcome
                .as_ref()
                .map(|o| o.kind.as_str())
                .unwrap_or("missing");
            Failure::internal(
                "artifact_outcome",
                format!(
                    "harness app: {} artifact outcome {kind} is not final",
                    role.as_str()
                ),
            )
        });
        Some(self.reconcile(role, Some(err)).await)
    }

    /// `failArtifacts` — a succeeded attempt's Run fails with the
    /// artifact's reason; the attempt row keeps `succeeded`.
    async fn fail_artifacts(
        &mut self,
        reason: FailureCode,
        cause: Option<Failure>,
    ) -> HarnessResult {
        self.settle_failure(
            &Settlement {
                succeeded: false,
                reason,
            },
            cause,
        )
        .await
    }

    /// `reconcile` — an ambiguous artifact outcome hands the attempt to
    /// B08.
    async fn reconcile(&mut self, _role: &ArtifactRole, cause: Option<Failure>) -> HarnessResult {
        let status = if self.attempt.state.is_terminal() {
            self.attempt.state.as_str().to_string()
        } else {
            self.intended
                .map(|s| s.as_str().to_string())
                .unwrap_or_else(|| self.attempt.state.as_str().to_string())
        };
        self.stop_heartbeat();
        let life = &*self.o.deps.lifecycle;
        let run = self.run.clone();
        match self
            .standing
            .retry(false, move || life.reconcile(run.clone()))
            .await
        {
            Ok(()) => {
                self.milestone(
                    MilestoneKind::Terminal,
                    "terminal",
                    &status,
                    ports::MILESTONE_REASON_RECONCILIATION,
                )
                .await;
                HarnessResult {
                    outcome: Outcome::Reconciliation,
                    reason: FailureCode::default(),
                    low_disk: self.low_disk,
                    settle_failed: false,
                    err: cause,
                }
            }
            Err(e) => {
                if let Some(r) = self.lost_or_stopped(&e) {
                    return r;
                }
                if e.code() == codes::CANCEL_REQUESTED {
                    self.request_cancel();
                    return self.settle_cancellation(cause).await;
                }
                self.settle_failed(
                    HarnessResult {
                        outcome: Outcome::Reconciliation,
                        reason: FailureCode::default(),
                        low_disk: self.low_disk,
                        settle_failed: false,
                        err: Some(e),
                    },
                    &status,
                    ports::MILESTONE_REASON_RECONCILIATION,
                )
                .await
            }
        }
    }

    /// `aborted` — `Some(res)` when the attempt context ended or the
    /// Task is cancelling mid-capture.
    async fn aborted(
        &mut self,
        cause: Option<Failure>,
        _session: Option<&dyn Session>,
    ) -> Option<HarnessResult> {
        if let Some(r) = self.interrupted() {
            return Some(r);
        }
        if self.cancel_requested() {
            return Some(self.settle_cancellation(cause).await);
        }
        None
    }

    /// `captureBestEffort` — a failed attempt's patch+commits, best
    /// effort (decision 10): errors only project `artifacts_partial`;
    /// `Some(res)` when the context ended.
    async fn capture_best_effort(
        &mut self,
        reason: &FailureCode,
        session: Option<&dyn Session>,
    ) -> Option<HarnessResult> {
        if session.is_none() || !self.session_started {
            return None;
        }
        let status = self.attempt.state.as_str().to_string();
        let mut failure = FailureCode::default();
        let mut skipped = false;
        match self.run_capture(session).await {
            Err(e) if e.code() == codes::CAPTURE_NOT_ATTEMPTED => {
                skipped = true;
            }
            Err(e) => {
                failure = capture_failure(&e);
            }
            Ok(c) => {
                for (role, path) in [
                    (ArtifactRole::Patch, c.patch),
                    (ArtifactRole::Commits, c.commits),
                ] {
                    // Upstream breaks only on the work ctx's end
                    // (orchestrator.go:1540); `Store` is called with an
                    // empty path too — the sink rejects it.
                    if self.standing.ended() || self.standing.cancel_hit {
                        break;
                    }
                    let (outcome, err) = self.store_artifact(role, path).await;
                    if err.is_none()
                        && matches!(outcome, Some(ref o) if o.kind == ArtifactOutcomeKind::Ready)
                    {
                        continue;
                    }
                    let code = outcome
                        .and_then(|o| {
                            if o.reason.is_empty() {
                                None
                            } else {
                                Some(o.reason)
                            }
                        })
                        .unwrap_or(FailureCode::ARTIFACT_CAPTURE_FAILED);
                    if failure.is_empty() {
                        failure = code;
                    }
                }
            }
        }
        if let Some(r) = self.interrupted() {
            return Some(r);
        }
        if self.cancel_requested() {
            return None; // settleFailure settles the cancellation
        }
        if skipped {
            // Capture never attempted: nothing to report (decision 8).
        } else if !failure.is_empty() {
            self.milestone(
                MilestoneKind::ArtifactsPartial,
                "artifacts",
                &status,
                failure.as_str(),
            )
            .await;
        } else {
            self.milestone(
                MilestoneKind::ArtifactsCaptured,
                "artifacts",
                &status,
                reason.as_str(),
            )
            .await;
        }
        None
    }

    /// `runCapture` — capture once the scope's exit is confirmed.
    async fn run_capture(
        &mut self,
        session: Option<&dyn Session>,
    ) -> Result<ports::Capture, Failure> {
        if !self.scope_released(session).await {
            return Err(Failure::internal(
                codes::CAPTURE_NOT_ATTEMPTED,
                "the launcher did not confirm the scope's exit; capture was not attempted",
            ));
        }
        self.captured = true;
        let res = self
            .standing
            .work_race(self.o.deps.capture.capture(
                self.run.workspace_id,
                self.attempt.workspace.clone(),
                self.run.run_id,
            ))
            .await;
        match res {
            Race::Done(v) => v,
            Race::Ended => Err(ended_err(self.standing.end)),
        }
    }

    /// `scopeReleased` — a fresh bounded `wait` proves the scope's exit
    /// (the launcher confirmed EXIT: a terminal with an exit code).
    async fn scope_released(&mut self, session: Option<&dyn Session>) -> bool {
        let Some(s) = session else {
            return false;
        };
        let res = self
            .standing
            .work_race(bounded(
                s.wait(),
                self.o.deps.ticker.after(SESSION_WAIT_BUDGET),
            ))
            .await;
        match res {
            Race::Done(Bounded::Done(Ok(t))) => t.exit_code.is_some(),
            _ => false,
        }
    }

    /// `storeArtifact` — one captured artifact, under the work race.
    async fn store_artifact(
        &mut self,
        role: ArtifactRole,
        path: String,
    ) -> (Option<ArtifactOutcome>, Option<Failure>) {
        let res = self
            .standing
            .work_race(self.o.deps.artifacts.store(self.run.clone(), role, path))
            .await;
        match res {
            Race::Done(Ok(o)) => (Some(o), None),
            Race::Done(Err(e)) => (None, Some(e)),
            Race::Ended => (None, Some(ended_err(self.standing.end))),
        }
    }

    /// `releaseCapture` — remove the capture files once the Run ended
    /// (`WithoutCancel`: bounded, never raced).
    async fn release_capture(&mut self) {
        if !self.captured {
            return;
        }
        let _ = bounded(
            self.o.deps.capture.release(self.run.run_id),
            self.o.deps.ticker.after(CAPTURE_RELEASE_BUDGET),
        )
        .await;
    }

    /// `settleFailed` — a settlement write failed permanently.
    async fn settle_failed(
        &mut self,
        mut res: HarnessResult,
        status: &str,
        reason: &str,
    ) -> HarnessResult {
        self.milestone(MilestoneKind::SettleFailed, "settle_failed", status, reason)
            .await;
        res.settle_failed = true;
        res
    }

    /// `failBridge` — a session whose permission bridge failed ends
    /// closed (decision 10).
    async fn fail_bridge(&mut self, session: &dyn Session, err: Failure) -> HarnessResult {
        if self.lost_or_stopped(&err).is_some() {
            self.close_lifeline(session).await;
            return match self.interrupted() {
                Some(r) => r,
                None => self.stop_result(),
            };
        }
        self.close_lifeline(session).await;
        self.finish(
            Terminal {
                status: TerminalStatus::Failed,
                reason: FailureCode::PERMISSION_BRIDGE_UNAVAILABLE.to_string(),
                ..Terminal::default()
            },
            Some(session),
            Some(err),
        )
        .await
    }

    // ------------------------------------------------------------------
    // Bridge — upstream bridge.go's AttemptRun methods
    // ------------------------------------------------------------------

    /// `approvalOpenFor` — the `ApprovalOpen` of `p`: fresh id, MAC of
    /// the input, expiry.
    fn approval_open_for(&self, p: &PermissionRequested) -> Result<ApprovalOpen, Failure> {
        let mac = compute_input_mac(&self.o.input_mac_key, &p.input)
            .map_err(|e| Failure::invalid(domain::codes::INVALID_APPROVAL, e.message()))?;
        Ok(ApprovalOpen {
            id: HarnessPermissionApprovalId::new(),
            task_id: self.run.task_id,
            request_id: p.request_id.clone(),
            tool_call_id: p.tool_call_id.clone(),
            tool: p.tool.clone(),
            input_mac: mac,
            input_size: p.input.len() as i64,
            expires_at: self.now() + self.o.deps.cfg.approval_timeout,
        })
    }

    /// `requested` — a bridged `PermissionRequested` before it is
    /// persisted: the `ApprovalOpen` to write with the event when the
    /// request reaches the head of the queue, else it queues (the
    /// input is copied — the queue never shares the event's buffer).
    fn requested(&mut self, p: &PermissionRequested) -> Result<Option<ApprovalOpen>, Failure> {
        if self.attempt.state != State::Running && self.attempt.state != State::AwaitingPermission {
            return Err(bridge::bridge_failure_msg(format!(
                "permission request while the attempt is {}",
                self.attempt.state.as_str()
            )));
        }
        if self.bridge.open.is_none()
            && self.bridge.queue.is_empty()
            && self.attempt.state == State::Running
        {
            let open = self.approval_open_for(p).map_err(bridge::bridge_failure)?;
            return Ok(Some(open));
        }
        if self.bridge.queue_len() >= bridge::MAX_QUEUED_PERMISSIONS {
            return Err(bridge::bridge_failure_msg(format!(
                "more than {} permission requests queued",
                bridge::MAX_QUEUED_PERMISSIONS
            )));
        }
        let mut q = p.clone();
        q.input = p.input.clone();
        self.bridge.queue.push_back(q);
        Ok(None)
    }

    /// `opened` — register the just-written approval: registry entry,
    /// signal + expiry arms, milestone.
    async fn opened<'a>(
        &mut self,
        open: ApprovalOpen,
        request: PermissionRequested,
        arms: &mut DriveArms<'a>,
    ) -> Result<(), Failure>
    where
        'o: 'a,
    {
        let a = open
            .approval(&self.attempt)
            .map_err(bridge::bridge_failure)?;
        let signal = if self.stopping() {
            None
        } else {
            Some(self.o.approvals.add(&a, &request.input, &request.resources))
        };
        if let Some(cell) = signal.clone() {
            arms.approval_signal = Some(cell.wait());
        }
        arms.approval_expiry = Some(self.o.deps.ticker.after(self.o.deps.cfg.approval_timeout));
        self.bridge.open = Some(OpenApproval {
            approval: a.clone(),
            input: request.input.clone(),
            signal,
            answered: false,
        });
        self.bridge.opened.fetch_add(1, Ordering::Relaxed);
        let aid = a.id;
        let tool = a.tool_name.clone();
        self.milestone(
            MilestoneKind::PermissionRequested,
            &format!("permission:{aid}"),
            ApprovalState::Pending.as_str(),
            &tool,
        )
        .await;
        Ok(())
    }

    /// `closeOpen` — forget the open approval once its request resolved.
    fn close_open(&mut self, arms: &mut DriveArms<'_>) {
        if let Some(open) = self.bridge.close_open() {
            self.o.approvals.drop(open.approval.id);
        }
        arms.approval_signal = None;
        arms.approval_expiry = None;
    }

    /// `unanswered` — refuse a `PermissionResolved` for a request this
    /// orchestrator never answered.
    fn unanswered(&mut self, p: &PermissionResolved) -> Result<(), Failure> {
        if let Some(open) = self.bridge.open.as_ref()
            && open.approval.request_id == p.request_id
            && !open.answered
        {
            return Err(bridge::bridge_failure_msg(format!(
                "the harness resolved permission request {} that was never answered",
                open.approval.id
            )));
        }
        for q in self.bridge.queue.iter() {
            if q.request_id == p.request_id {
                return Err(bridge::bridge_failure_msg(format!(
                    "the harness resolved permission request {} that was still queued, never opened",
                    p.request_id
                )));
            }
        }
        Ok(())
    }

    /// `resolved` — the recorded `PermissionResolved` closes the open
    /// approval and promotes the queue's head (decision 16).
    async fn resolved<'a>(
        &mut self,
        p: &PermissionResolved,
        arms: &mut DriveArms<'a>,
    ) -> Result<(), Failure>
    where
        'o: 'a,
    {
        let open_id = match self.bridge.open.as_ref() {
            Some(o) if o.approval.request_id == p.request_id => Some(o.approval.id),
            _ => None,
        };
        if open_id.is_none() {
            return Ok(());
        }
        self.close_open(arms);
        if self.bridge.queue.is_empty() || self.attempt.state != State::Running || self.stopping() {
            return Ok(());
        }
        let head = match self.bridge.queue.pop_front() {
            Some(h) => h,
            None => return Ok(()),
        };
        let open = self
            .approval_open_for(&head)
            .map_err(bridge::bridge_failure)?;
        let next = self
            .attempt
            .await_permission(self.fence, &head.request_id, self.now());
        match next {
            Ok(n) => {
                let open_slice = [open.clone()];
                if let Err(e) = self.save(&n, &open_slice).await {
                    if e.code() == codes::LEASE_LOST
                        || e.code() == domain::codes::FENCE_MISMATCH
                        || self.standing.ended()
                    {
                        return Err(e);
                    }
                    return Err(bridge::bridge_failure(e));
                }
                self.opened(open, head, arms).await
            }
            Err(e) => Err(bridge::bridge_failure(e)),
        }
    }

    /// `pollApproval` — re-read the open approval; expire when due;
    /// answer when decided (decision 8).
    async fn poll_approval<'a>(
        &mut self,
        session: &'a dyn Session,
        arms: &mut DriveArms<'a>,
        due: bool,
    ) -> Result<(), Failure>
    where
        'o: 'a,
    {
        let open_answered = self
            .bridge
            .open
            .as_ref()
            .map(|o| o.answered)
            .unwrap_or(true);
        if self.bridge.open.is_none()
            || open_answered
            || self.stopping()
            || self.standing.ended()
            || self.attempt.state.is_terminal()
        {
            return Ok(());
        }
        let id = match self.bridge.open.as_ref() {
            Some(o) => o.approval.id,
            None => return Ok(()),
        };
        let mut a = match self
            .standing
            .race(self.store.load_approval(self.run.workspace_id, id))
            .await
        {
            Race::Done(Ok(a)) => a,
            Race::Done(Err(e)) => {
                if e.code() == domain::codes::FENCE_MISMATCH
                    || e.code() == codes::LEASE_LOST
                    || self.standing.ended()
                {
                    return Err(e);
                }
                if !transient(&e) {
                    return Err(bridge::bridge_failure(e));
                }
                return Ok(());
            }
            Race::Ended => return Err(ended_err(self.standing.end)),
        };
        if a.state == ApprovalState::Pending && (due || self.o.deps.clock.now() >= a.expires_at) {
            match self
                .standing
                .race(self.store.expire_permission(&self.attempt, id))
                .await
            {
                Race::Done(Ok(a2)) => a = a2,
                Race::Done(Err(e)) => {
                    if e.code() == domain::codes::FENCE_MISMATCH
                        || e.code() == codes::LEASE_LOST
                        || self.standing.ended()
                    {
                        return Err(e);
                    }
                    if !transient(&e) {
                        return Err(bridge::bridge_failure(e));
                    }
                    return Ok(());
                }
                Race::Ended => return Err(ended_err(self.standing.end)),
            }
        }
        match a.state {
            ApprovalState::Pending => Ok(()),
            ApprovalState::Superseded => {
                if let Some(open) = self.bridge.open.as_mut() {
                    open.answered = true;
                }
                arms.approval_signal = None;
                arms.approval_expiry = None;
                self.o.approvals.drop(id);
                Ok(())
            }
            _ => self.answer(session, arms, &a).await,
        }
    }

    /// `answer` — deliver a decided approval to the harness, once.
    async fn answer<'a>(
        &mut self,
        session: &'a dyn Session,
        arms: &mut DriveArms<'a>,
        a: &PermissionApproval,
    ) -> Result<(), Failure>
    where
        'o: 'a,
    {
        let mut d = PermissionDecision {
            request_id: a.request_id.clone(),
            allow: false,
            option_id: String::new(),
            decided_by: a.decided_by.clone(),
            input_sha256: [0; 32],
        };
        match a.state {
            ApprovalState::Allowed => {
                let input = match self.bridge.open.as_ref() {
                    Some(o) => o.input.clone(),
                    None => Vec::new(),
                };
                let mac = compute_input_mac(&self.o.input_mac_key, &input)
                    .map_err(|e| Failure::invalid(domain::codes::INVALID_APPROVAL, e.message()))?;
                if !mac.equal(&a.input_mac) {
                    return Err(bridge::bridge_failure_msg(
                        "the allowed input MAC does not match the held input",
                    ));
                }
                d.allow = true;
                d.input_sha256 = Sha256::digest(&input).into();
            }
            ApprovalState::Denied | ApprovalState::Expired => {}
            _ => {
                return Err(bridge::bridge_failure_msg(format!(
                    "approval closed as {} while its attempt holds the lease",
                    a.state.as_str()
                )));
            }
        }
        let res = bounded(
            session.respond_permission(d),
            self.o.deps.ticker.after(PERMISSION_ANSWER_BUDGET),
        )
        .await;
        match res {
            Bounded::Done(Ok(())) => {}
            Bounded::Done(Err(e)) if e.code() == crate::port::codes::NO_PENDING_PERMISSION => {
                // Nothing waits for the answer — benign drain.
            }
            Bounded::Done(Err(e)) => {
                if let Some(r) = self.interrupted() {
                    return Err(r.err.unwrap_or(e));
                }
                return Err(bridge::bridge_failure(e));
            }
            Bounded::Elapsed => {
                return Err(bridge::bridge_failure_msg(
                    "the permission answer timed out",
                ));
            }
        }
        if let Some(open) = self.bridge.open.as_mut() {
            open.answered = true;
        }
        arms.approval_signal = None;
        arms.approval_expiry = None;
        if let Some(open) = self.bridge.open.as_ref() {
            self.o.approvals.drop(open.approval.id);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Milestones
    // ------------------------------------------------------------------

    /// `r.milestone` — best-effort; never written once the ctx ended
    /// (unless `completed`, whose settlement committed). Upstream
    /// `events.Record` is a blocking call whose error is only logged,
    /// so the record is awaited and its failure ignored.
    async fn milestone(&self, kind: MilestoneKind, key: &str, status: &str, reason: &str) {
        if !self.completed && self.standing.ended() {
            return;
        }
        let Some(sink) = self.o.deps.cfg.events.clone() else {
            return;
        };
        let m = Milestone {
            key: format!("harness:{}:{}", self.run.step_attempt_id, key),
            kind,
            workspace_id: self.run.workspace_id,
            task_id: self.run.task_id,
            run_id: self.run.run_id,
            step_attempt_id: self.run.step_attempt_id,
            status: status.to_string(),
            reason: reason.to_string(),
            at: self.o.deps.clock.now(),
        };
        let _ = sink.record(m).await;
    }
}
