//! Scripted, deterministic harness doubles for tests — a port of
//! upstream `internal/adapter/harness/fake`. [`FakeAdapter`] implements
//! `port::Adapter` without starting any process; [`FakeLauncher`]
//! implements `port::ProcessLauncher` for code that only probes and
//! kills scopes.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use central_foundation::failure::Failure;
use central_foundation::identity::HarnessAttemptId;
use central_harness::capability::Capabilities;
use central_harness::domain::{Kind, Terminal, TerminalStatus, codes as domain_codes};
use central_harness::env::validate_launch_env;
use central_harness::event::{
    Event, EventPayload, PermissionOutcome, PermissionResolved, TerminalReported,
};
use central_harness::port::{
    self, Adapter, LaunchEnv, OperatorInput, PermissionDecision, PortFuture, ProbeResult, Process,
    ProcessLauncher, ProcessSpec, ReconcileInput, ReconcileResult, Session, SessionRef, StartSpec,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};

use crate::process::Outcome;

/// Stable machine codes for the fake's own sentinels.
pub mod codes {
    /// `fake.ErrScriptExhausted` — Start or Resume has no script left.
    pub const SCRIPT_EXHAUSTED: &str = "harness_fake_script_exhausted";
    /// `fake.ErrLaunchUnsupported` — the fake launcher starts no
    /// process.
    pub const LAUNCH_UNSUPPORTED: &str = "harness_fake_launch_unsupported";
    /// `fake` resume refusal — resume requires a harness session id.
    pub const RESUME_NEEDS_REF: &str = "harness_fake_resume_needs_ref";
}

fn script_exhausted() -> Failure {
    Failure::internal(codes::SCRIPT_EXHAUSTED, "fake harness: script exhausted")
}
fn no_pending_permission() -> Failure {
    Failure::invalid(
        port::codes::NO_PENDING_PERMISSION,
        "fake harness: no pending permission",
    )
}
fn session_ended() -> Failure {
    Failure::conflict(port::codes::SESSION_ENDED, "fake harness: session ended")
}
fn unsupported(msg: &str) -> Failure {
    Failure::invalid(port::codes::UNSUPPORTED, format!("fake harness: {msg}"))
}

/// One scripted harness session — upstream `fake.Script`.
#[derive(Clone, Default)]
pub struct Script {
    /// Documents the id the script's `SessionStarted` payload reveals;
    /// the session id always comes from the payload, as upstream's run
    /// loop reads `started.HarnessSessionID`.
    pub session_id: String,
    /// The normalized payloads to emit, in order.
    pub payloads: Vec<EventPayload>,
    /// The terminal the session finishes with.
    pub terminal: Terminal,
    /// Makes `start`/`resume` fail with it after the call is recorded.
    pub start_err: Option<Failure>,
    /// Pauses after each `PermissionRequested` until
    /// `respond_permission`, `interrupt` or `kill` is called.
    pub wait_for_permission: bool,
    /// With `wait_for_permission`, emits a run of consecutive
    /// `PermissionRequested` payloads together, all pending at once,
    /// then waits until every one is answered (the harness phase 3c
    /// queue path).
    pub concurrent_permissions: bool,
    /// Makes every `respond_permission` fail with it, answering
    /// nothing, as a broken stdin does.
    pub respond_err: Option<Failure>,
    /// Makes `wait` return the terminal without an exit code, as a
    /// real session does when the launcher never confirmed the scope's
    /// exit (a lost lifeline). Otherwise `wait` reports exit code 0
    /// for a terminal that carries none: the scripted process exited.
    pub no_exit_status: bool,
}

/// One recorded `start`/`resume` call — upstream `fake.Call`.
#[derive(Clone)]
pub struct Call {
    /// `"start"` or `"resume"`.
    pub method: String,
    /// The spec passed.
    pub spec: StartSpec,
    /// The session ref (`resume` only).
    pub session_ref: SessionRef,
}

/// `RefSlot` — the state of the `Ref()` channel: the harness may reveal
/// its session id once or close without revealing it. `Closed` retains
/// a revealed ref so a `session_ref` that reads after the run's end
/// still gets it — upstream's buffered channel stays readable after
/// close.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RefSlot {
    Pending,
    Revealed(SessionRef),
    Closed(Option<SessionRef>),
}

/// `FakeAdapter` — a scripted `port::Adapter`, upstream `fake.Adapter`.
pub struct FakeAdapter {
    kind: Kind,
    caps: Capabilities,
    scripts: Mutex<VecDeque<Script>>,
    calls: Mutex<Vec<Call>>,
    inputs: Arc<Mutex<Vec<OperatorInput>>>,
    probe: Mutex<ProbeResult>,
    reconcile: Mutex<Option<ReconcileResult>>,
}

impl FakeAdapter {
    /// `New` — an adapter that plays `scripts` in order, one per
    /// `start`/`resume`.
    #[must_use]
    pub fn new(kind: Kind, caps: Capabilities, scripts: Vec<Script>) -> Self {
        Self {
            kind,
            caps,
            scripts: Mutex::new(scripts.into()),
            calls: Mutex::new(Vec::new()),
            inputs: Arc::new(Mutex::new(Vec::new())),
            probe: Mutex::new(ProbeResult::default()),
            reconcile: Mutex::new(None),
        }
    }

    /// `SetProbe` configures `probe`'s result.
    pub fn set_probe(&self, r: ProbeResult) {
        *self.probe.lock().unwrap_or_else(|p| p.into_inner()) = r;
    }

    /// `SetReconcile` configures `reconcile`'s result. A boxed session
    /// is handed out once; a second call sees the empty result.
    pub fn set_reconcile(&self, r: ReconcileResult) {
        *self.reconcile.lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
    }

    /// `Calls` — the recorded start/resume calls.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// `Inputs` — the operator inputs received through `send`.
    #[must_use]
    pub fn inputs(&self) -> Vec<OperatorInput> {
        self.inputs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn open(
        &self,
        method: &str,
        spec: StartSpec,
        session_ref: SessionRef,
    ) -> Result<Box<dyn Session>, Failure> {
        spec.validate(&[])?;
        // A native cost limit is honoured only when declared (harness
        // phase 3d decision 5): an adapter must never silently drop a
        // limit it cannot enforce.
        if spec.limits.max_cost_micro_usd > 0 && !self.caps.native_cost_limit {
            return Err(unsupported("native cost limit"));
        }
        let script = {
            let mut scripts = self.scripts.lock().unwrap_or_else(|p| p.into_inner());
            let Some(script) = scripts.pop_front() else {
                return Err(script_exhausted());
            };
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(Call {
                    method: method.to_string(),
                    spec: spec.clone(),
                    session_ref,
                });
            script
        };
        if let Some(e) = script.start_err.clone() {
            return Err(e);
        }
        let payloads = script.payloads.len();
        let (events_tx, events_rx) = mpsc::channel(2 * payloads + 2);
        let (permit_tx, permit_rx) = mpsc::channel(payloads + 1);
        let (ref_tx, ref_rx) = watch::channel(RefSlot::Pending);
        let inner = Arc::new(FakeSessionInner {
            caps: self.caps,
            inputs: self.inputs.clone(),
            attempt: spec.attempt,
            // `events_tx` is `Option` so `finish_run` can drop it to
            // close the stream from the sender side; the capacity is
            // `2*payloads + 2` so `emit`'s `try_send` never blocks.
            events_tx: Mutex::new(Some(events_tx)),
            events_rx: tokio::sync::Mutex::new(events_rx),
            permit_tx,
            permit_rx: tokio::sync::Mutex::new(permit_rx),
            ref_rx,
            notify: tokio::sync::Notify::new(),
            mu: Mutex::new(SessionMu::default()),
            finished: AtomicBool::new(false),
            outcome: Outcome::new(),
            respond_err: script.respond_err.clone(),
            no_exit_status: script.no_exit_status,
        });
        let runner = inner.clone();
        tokio::spawn(async move { runner.run(script, ref_tx).await });
        Ok(Box::new(FakeSession { inner }))
    }
}

impl Adapter for FakeAdapter {
    fn kind(&self) -> Kind {
        self.kind.clone()
    }

    fn capabilities(&self) -> Capabilities {
        self.caps
    }

    fn env_extras(&self) -> &[String] {
        &[]
    }

    fn probe<'a>(&'a self, env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>> {
        Box::pin(async move {
            validate_launch_env(&env.vars, &[])?;
            Ok(self.probe.lock().unwrap_or_else(|p| p.into_inner()).clone())
        })
    }

    fn start<'a>(&'a self, spec: StartSpec) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move { self.open("start", spec, SessionRef::default()) })
    }

    fn resume<'a>(
        &'a self,
        session_ref: SessionRef,
        spec: StartSpec,
    ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            if !self.caps.resume_by_id {
                return Err(unsupported("resume"));
            }
            if session_ref.harness_session_id.is_empty() {
                return Err(Failure::invalid(
                    codes::RESUME_NEEDS_REF,
                    "fake harness: resume requires a harness session id",
                ));
            }
            self.open("resume", spec, session_ref)
        })
    }

    fn reconcile<'a>(
        &'a self,
        _input: ReconcileInput,
    ) -> PortFuture<'a, Result<ReconcileResult, Failure>> {
        Box::pin(async move {
            let mut r = self.reconcile.lock().unwrap_or_else(|p| p.into_inner());
            let Some(result) = r.take() else {
                return Ok(ReconcileResult {
                    scope_alive: false,
                    reattached: None,
                    terminal: None,
                });
            };
            if result.reattached.is_some() && !self.caps.reattach {
                return Err(unsupported("reattach"));
            }
            Ok(result)
        })
    }
}

/// `session` — one scripted session; `FakeSession` is the `port::Session`
/// handle, `FakeSessionInner` the shared state its run task owns.
/// `mu` is upstream's single `sync.Mutex`: `pending` and `stop_status`
/// move under it together so `signal`'s "stop + clear pending" is one
/// critical section and no lock-order inversion exists.
struct FakeSessionInner {
    caps: Capabilities,
    inputs: Arc<Mutex<Vec<OperatorInput>>>,
    attempt: HarnessAttemptId,
    /// `events` send half — `Option` lets the run end close it (the
    /// upstream `defer close(s.events)`). `try_send` is used: the
    /// capacity covers every event a script can emit, so it never
    /// blocks and never loses a buffered event.
    events_tx: Mutex<Option<mpsc::Sender<Event>>>,
    events_rx: tokio::sync::Mutex<mpsc::Receiver<Event>>,
    permit_tx: mpsc::Sender<PermissionDecision>,
    permit_rx: tokio::sync::Mutex<mpsc::Receiver<PermissionDecision>>,
    ref_rx: watch::Receiver<RefSlot>,
    notify: tokio::sync::Notify,
    mu: Mutex<SessionMu>,
    /// `done` — closed at the run's end, before the event/ref
    /// senders drop, as upstream's deferred closes run.
    finished: AtomicBool,
    outcome: Outcome<Terminal>,
    respond_err: Option<Failure>,
    no_exit_status: bool,
}

#[derive(Default)]
struct SessionMu {
    /// Pending request id -> its input.
    pending: HashMap<String, Vec<u8>>,
    /// `None` until `interrupt` or `kill` is requested.
    stop_status: Option<TerminalStatus>,
}

/// `FakeSession` — the scripted `port::Session` `FakeAdapter` returns.
pub struct FakeSession {
    inner: Arc<FakeSessionInner>,
}

/// `clockBase` — a fixed base so events are deterministic.
fn event_at(seq: u64) -> OffsetDateTime {
    match OffsetDateTime::from_unix_timestamp(1_791_820_800 + seq as i64) {
        Ok(t) => t,
        Err(_) => OffsetDateTime::UNIX_EPOCH,
    }
}

impl FakeSessionInner {
    async fn emit(&self, seq: &mut u64, id: &str, payload: EventPayload) {
        *seq += 1;
        let raw = serde_json::to_vec(&payload)
            .unwrap_or_else(|_| payload.event_kind().as_str().as_bytes().to_vec());
        let tx = self.events_tx.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(tx) = tx.as_ref() {
            let _ = tx.try_send(Event {
                attempt: self.attempt,
                seq: *seq,
                at: event_at(*seq),
                harness_session_id: id.to_string(),
                raw,
                payload: Some(payload),
            });
        }
    }

    async fn emit_permission_resolved(&self, seq: &mut u64, id: &str, d: &PermissionDecision) {
        let outcome = if d.allow {
            PermissionOutcome::Allowed
        } else {
            PermissionOutcome::Denied
        };
        self.emit(
            seq,
            id,
            EventPayload::PermissionResolved(PermissionResolved {
                request_id: d.request_id.clone(),
                decision: outcome,
                decided_by: d.decided_by.clone(),
            }),
        )
        .await;
    }

    /// `run` — upstream's session goroutine.
    async fn run(self: Arc<Self>, script: Script, ref_tx: watch::Sender<RefSlot>) {
        let mut seq = 0u64;
        let mut id = String::new();
        let mut ref_sent = false;
        let mut permit_rx = self.permit_rx.lock().await;
        let payloads = script.payloads;
        let mut i = 0usize;
        while i < payloads.len() {
            // `select case <-s.notify: default:` — the recorded stop is
            // the signal; `notify` only wakes the blocking waits below.
            // The guard is bound and dropped before any `.await` so the
            // `std::sync::MutexGuard` never crosses one (it is !Send).
            let stopped = self
                .mu
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .stop_status
                .is_some();
            if stopped {
                drop(permit_rx);
                self.finish_on_stop(&mut seq, &id).await;
                self.finish_run(&ref_tx, ref_sent, &id);
                return;
            }
            let p = payloads[i].clone();
            if let EventPayload::SessionStarted(started) = &p {
                id = started.harness_session_id.clone();
                // A script with a second SessionStarted must not block
                // when session_ref goes unread; the event itself is
                // still emitted normally for every SessionStarted.
                if !ref_sent {
                    ref_sent = true;
                    let _ = ref_tx.send(RefSlot::Revealed(SessionRef {
                        harness_session_id: id.clone(),
                    }));
                }
            }
            let is_request = matches!(p, EventPayload::PermissionRequested(_));
            if !is_request || !script.wait_for_permission {
                self.emit(&mut seq, &id, p).await;
                i += 1;
                continue;
            }
            // The batch is this request alone, or, with
            // concurrent_permissions, the run of consecutive requests
            // starting here.
            let EventPayload::PermissionRequested(first) = p else {
                i += 1;
                continue;
            };
            let mut batch = vec![first];
            while script.concurrent_permissions && i + 1 < payloads.len() {
                if let EventPayload::PermissionRequested(next) = &payloads[i + 1] {
                    batch.push(next.clone());
                    i += 1;
                } else {
                    break;
                }
            }
            i += 1;
            let stopped = {
                let mut mu = self.mu.lock().unwrap_or_else(|p| p.into_inner());
                if mu.stop_status.is_some() {
                    true
                } else {
                    // Every pending request id must be visible to
                    // respond_permission before the event that
                    // announces it is emitted.
                    for request in &batch {
                        mu.pending
                            .insert(request.request_id.clone(), request.input.clone());
                    }
                    false
                }
            };
            if stopped {
                // Interrupt/Kill already recorded a stop before this
                // request could be made pending: finish on that stop
                // instead of announcing a request that could never be
                // answered.
                drop(permit_rx);
                self.finish_on_stop(&mut seq, &id).await;
                self.finish_run(&ref_tx, ref_sent, &id);
                return;
            }
            for request in batch.iter().cloned() {
                self.emit(&mut seq, &id, EventPayload::PermissionRequested(request))
                    .await;
            }
            for _ in 0..batch.len() {
                tokio::select! {
                    d = permit_rx.recv() => {
                        match d {
                            Some(d) => self.emit_permission_resolved(&mut seq, &id, &d).await,
                            // The sender lives in `self`; this is
                            // unreachable while the session does.
                            None => break,
                        }
                    }
                    _ = self.notify.notified() => {
                        drop(permit_rx);
                        self.finish_on_stop(&mut seq, &id).await;
                        self.finish_run(&ref_tx, ref_sent, &id);
                        return;
                    }
                }
            }
        }
        drop(permit_rx);
        self.finish(script.terminal.clone(), &mut seq, &id).await;
        self.finish_run(&ref_tx, ref_sent, &id);
    }

    /// `finishOnStop` — end on the recorded stop. It clears pending
    /// under the same lock `signal` used, then drains `permit`
    /// non-blockingly so a decision a concurrent `respond_permission`
    /// already sent is never lost: its `PermissionResolved` is always
    /// emitted before the stop's terminal event.
    async fn finish_on_stop(&self, seq: &mut u64, id: &str) {
        let status = {
            let mut mu = self.mu.lock().unwrap_or_else(|p| p.into_inner());
            mu.pending.clear();
            mu.stop_status.unwrap_or_default()
        };
        let mut permit_rx = self.permit_rx.lock().await;
        while let Ok(d) = permit_rx.try_recv() {
            self.emit_permission_resolved(seq, id, &d).await;
        }
        drop(permit_rx);
        self.finish(
            Terminal {
                status,
                ..Terminal::default()
            },
            seq,
            id,
        )
        .await;
        // `ref_tx` is owned by run(); on this path it is still held
        // there — the drop order is preserved by run's return.
    }

    /// `finish` — record the terminal and emit `TerminalReported`.
    async fn finish(&self, t: Terminal, seq: &mut u64, id: &str) {
        self.outcome.set(t.clone());
        self.emit(
            seq,
            id,
            EventPayload::TerminalReported(TerminalReported { terminal: t }),
        )
        .await;
    }

    /// The run's end: `done` first, then the event and ref channels
    /// close — upstream's deferred closes run LIFO (`done`, events,
    /// ref). Dropping the shared `events_tx` closes the stream:
    /// buffered events stay readable, then `next_event` resolves
    /// `None`. `Closed` retains a revealed ref so a late
    /// `session_ref` still gets it.
    fn finish_run(&self, ref_tx: &watch::Sender<RefSlot>, ref_sent: bool, id: &str) {
        self.finished.store(true, Ordering::SeqCst);
        let _ = self
            .events_tx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let revealed = if ref_sent {
            Some(SessionRef {
                harness_session_id: id.to_string(),
            })
        } else {
            None
        };
        let _ = ref_tx.send(RefSlot::Closed(revealed));
    }
}

impl Session for FakeSession {
    /// `Ref()` — resolves once the harness reveals its session id;
    /// `None` when the session ended before revealing it.
    fn session_ref(&self) -> PortFuture<'_, Option<SessionRef>> {
        Box::pin(async move {
            let mut rx = self.inner.ref_rx.clone();
            loop {
                match &*rx.borrow() {
                    RefSlot::Pending => {}
                    RefSlot::Revealed(r) | RefSlot::Closed(Some(r)) => {
                        return Some(r.clone());
                    }
                    RefSlot::Closed(None) => return None,
                }
                if rx.changed().await.is_err() {
                    return None;
                }
            }
        })
    }

    /// `Events()` — the next normalized event; `None` once the stream
    /// closes after the terminal event. Callers must keep pulling.
    fn next_event(&self) -> PortFuture<'_, Option<Event>> {
        Box::pin(async move {
            let mut rx = self.inner.events_rx.lock().await;
            rx.recv().await
        })
    }

    /// `Send` delivers operator follow-up input.
    fn send<'a>(&'a self, input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if !self.inner.caps.streaming_input {
                return Err(unsupported("send"));
            }
            self.inner
                .inputs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(input);
            Ok(())
        })
    }

    /// `Interrupt` — the graceful cancel. `SESSION_ENDED` once the
    /// session has finished, as a real adapter's does after the
    /// harness's final result.
    fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if self.inner.finished.load(Ordering::SeqCst) {
                return Err(session_ended());
            }
            self.inner.signal(TerminalStatus::Interrupted);
            Ok(())
        })
    }

    /// `RespondPermission` answers the pending permission request. See
    /// upstream: once `interrupt`/`kill` has been called, no
    /// `respond_permission` for that request can succeed afterwards —
    /// `signal` clears pending under the same lock it uses to record
    /// the stop, and the run task never establishes a new pending
    /// request once a stop is recorded. A genuinely concurrent call
    /// may still win the lock first: it is then accepted, and its
    /// `PermissionResolved` is emitted before the terminal event —
    /// `finish_on_stop` drains `permit` for exactly that in-flight
    /// decision. The event stream, not this return value, is the
    /// source of truth for what was decided.
    fn respond_permission<'a>(
        &'a self,
        decision: PermissionDecision,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if !self.inner.caps.permission_bridge {
                return Err(unsupported("respond permission"));
            }
            if let Some(e) = &self.inner.respond_err {
                return Err(e.clone());
            }
            let mut mu = self.inner.mu.lock().unwrap_or_else(|p| p.into_inner());
            if self.inner.finished.load(Ordering::SeqCst) || mu.pending.is_empty() {
                return Err(no_pending_permission());
            }
            let Some(input) = mu.pending.get(&decision.request_id).cloned() else {
                return Err(Failure::invalid(
                    domain_codes::PERMISSION_MISMATCH,
                    "fake harness: permission request is not pending",
                ));
            };
            // An allow must bind the exact input bytes, as a real
            // adapter's must (harness phase 3c decision 8).
            if decision.allow {
                let digest: [u8; 32] = Sha256::digest(&input).into();
                if decision.input_sha256 != digest {
                    return Err(Failure::invalid(
                        port::codes::PERMISSION_BINDING,
                        "fake harness: permission input binding mismatch",
                    ));
                }
            }
            mu.pending.remove(&decision.request_id);
            drop(mu);
            // Safe without fallback: `permit` holds one slot per
            // scripted payload, and each pending request is answered
            // at most once.
            self.inner.permit_tx.try_send(decision).map_err(|_| {
                Failure::internal(
                    "harness_fake_permit_full",
                    "fake harness: permit channel full",
                )
            })
        })
    }

    /// `Wait` — the session's terminal once it is knowable.
    fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>> {
        Box::pin(async move {
            let mut t = self.inner.outcome.wait().await;
            if t.exit_code.is_none() && !self.inner.no_exit_status {
                t.exit_code = Some(0);
            }
            Ok(t)
        })
    }

    /// `Kill` — kill always wins over a prior interrupt.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.inner.signal(TerminalStatus::Killed);
            Ok(())
        })
    }
}

impl FakeSessionInner {
    /// `signal` records the requested stop status and wakes the run
    /// task. Kill always wins: once killed is recorded, a later
    /// interrupt can never overwrite it, but killed always overwrites
    /// a prior interrupt. It also clears any pending permission
    /// request under the same lock, so a `respond_permission` call
    /// sequenced after this one deterministically observes no pending
    /// request instead of racing the run task's own handling of the
    /// stop.
    fn signal(&self, status: TerminalStatus) {
        {
            let mut mu = self.mu.lock().unwrap_or_else(|p| p.into_inner());
            if status == TerminalStatus::Killed || mu.stop_status.is_none() {
                mu.stop_status = Some(status);
            }
            mu.pending.clear();
        }
        self.notify.notify_one();
    }
}

/// `ErrLaunchUnsupported` — the fake launcher starts no process (the
/// fake adapter never launches one either). Upstream
/// `fake.ErrLaunchUnsupported`.
fn launch_unsupported() -> Failure {
    Failure::internal(
        codes::LAUNCH_UNSUPPORTED,
        "fake launcher: launch is not supported",
    )
}

/// `FakeLauncher` — a scripted `port::ProcessLauncher` for tests of
/// code that only probes and kills scopes, such as the phase 3a
/// dispatcher's startup sweep of ambiguous attempts. `is_alive`
/// reports the scripted liveness; `kill_scope` records the scope and
/// marks it dead; a scope never scripted is empty. Upstream
/// `fake.Launcher`.
#[derive(Default)]
pub struct FakeLauncher {
    state: Mutex<FakeLauncherState>,
}

#[derive(Default)]
struct FakeLauncherState {
    alive: HashMap<String, bool>,
    kills: Vec<String>,
    kill_err: Option<Failure>,
    alive_err: Option<Failure>,
}

impl FakeLauncher {
    /// `NewLauncher` — a launcher whose scopes are all empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `SetAlive` scripts a scope's liveness.
    pub fn set_alive(&self, scope_id: &str, alive: bool) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .alive
            .insert(scope_id.to_string(), alive);
    }

    /// `FailKill` makes every later `kill_scope` return `err`
    /// (`None` clears it).
    pub fn fail_kill(&self, err: Option<Failure>) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .kill_err = err;
    }

    /// `FailAlive` makes every later `is_alive` return `err`
    /// (`None` clears it), as when the launcher is unreachable.
    pub fn fail_alive(&self, err: Option<Failure>) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .alive_err = err;
    }

    /// `Kills` — the scopes passed to `kill_scope`, in order.
    #[must_use]
    pub fn kills(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .kills
            .clone()
    }
}

impl ProcessLauncher for FakeLauncher {
    /// `Launch` always fails with `LAUNCH_UNSUPPORTED`.
    fn launch<'a>(
        &'a self,
        _spec: ProcessSpec,
    ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
        Box::pin(async move { Err(launch_unsupported()) })
    }

    /// `Alive` reports the scripted liveness of `scope_id`.
    fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = &st.alive_err {
                return Err(e.clone());
            }
            Ok(st.alive.get(scope_id).copied().unwrap_or(false))
        })
    }

    /// `KillScope` records `scope_id` and marks it dead. A scope never
    /// scripted, or already dead, is a no-op kill that is still
    /// recorded.
    fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.kills.push(scope_id.to_string());
            if let Some(e) = &st.kill_err {
                return Err(e.clone());
            }
            st.alive.insert(scope_id.to_string(), false);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::identity::HarnessAttemptId;
    use central_harness::domain::{Fence, PermissionPolicy, Workspace};
    use central_harness::event::{PermissionRequested, SessionStarted as SessionStartedPayload};
    use std::collections::BTreeMap;

    fn caps() -> Capabilities {
        Capabilities {
            streaming_input: true,
            interrupt: true,
            resume_by_id: true,
            permission_bridge: true,
            ..Capabilities::default()
        }
    }

    fn spec() -> StartSpec {
        StartSpec {
            attempt: HarnessAttemptId::new(),
            fence: Fence { generation: 1 },
            workspace: Workspace {
                path: "/w".to_string(),
                ..Workspace::default()
            },
            prompt: "do it".to_string(),
            model: String::new(),
            permission: PermissionPolicy::Bridge,
            limits: Default::default(),
            env: LaunchEnv {
                vars: BTreeMap::new(),
                sandbox_scope_id: "scope-1".to_string(),
            },
        }
    }

    fn is_code(err: &Failure, code: &str) -> bool {
        err.code() == code
    }

    fn sha(input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }

    /// Upstream `TestStartPlaysScriptAndRef`.
    #[tokio::test]
    async fn start_plays_script_and_ref() {
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            caps(),
            vec![Script {
                session_id: "s1".to_string(),
                payloads: vec![
                    EventPayload::SessionStarted(SessionStartedPayload {
                        harness_session_id: "s1".to_string(),
                        ..SessionStartedPayload::default()
                    }),
                    EventPayload::Message(Default::default()),
                ],
                terminal: Terminal {
                    status: TerminalStatus::Succeeded,
                    ..Terminal::default()
                },
                ..Script::default()
            }],
        );
        let s = adapter.start(spec()).await.unwrap();
        let r = s.session_ref().await.unwrap();
        assert_eq!(r.harness_session_id, "s1");
        let mut kinds = Vec::new();
        while let Some(e) = s.next_event().await {
            kinds.push(e.payload.as_ref().unwrap().event_kind());
        }
        assert_eq!(
            kinds,
            vec![
                central_harness::event::EventKind::SessionStarted,
                central_harness::event::EventKind::Message,
                central_harness::event::EventKind::TerminalReported,
            ]
        );
        let t = s.wait().await.unwrap();
        assert_eq!(t.status, TerminalStatus::Succeeded);
        assert_eq!(t.exit_code, Some(0), "scripted exit status");
    }

    /// Upstream `TestScriptExhausted`.
    #[tokio::test]
    async fn script_exhausted() {
        let adapter = FakeAdapter::new(Kind::new("claude-code"), caps(), vec![]);
        let err = adapter.start(spec()).await.map(|_| ()).unwrap_err();
        assert!(is_code(&err, codes::SCRIPT_EXHAUSTED));
    }

    /// Upstream `TestResumeNeedsCapabilityAndRef`.
    #[tokio::test]
    async fn resume_needs_capability_and_ref() {
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            Capabilities {
                resume_by_id: false,
                ..caps()
            },
            vec![Script::default()],
        );
        let err = adapter
            .resume(
                SessionRef {
                    harness_session_id: "s".to_string(),
                },
                spec(),
            )
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, port::codes::UNSUPPORTED));

        let adapter = FakeAdapter::new(Kind::new("claude-code"), caps(), vec![Script::default()]);
        let err = adapter
            .resume(SessionRef::default(), spec())
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, codes::RESUME_NEEDS_REF));
    }

    /// Upstream `TestWaitForPermissionBlocks` (pending/binding/mismatch).
    #[tokio::test]
    async fn permission_waits_binds_and_answers() {
        let input = b"{\"cmd\":\"ls\"}".to_vec();
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            caps(),
            vec![Script {
                payloads: vec![
                    EventPayload::SessionStarted(SessionStartedPayload {
                        harness_session_id: "s1".to_string(),
                        ..SessionStartedPayload::default()
                    }),
                    EventPayload::PermissionRequested(PermissionRequested {
                        request_id: "p1".to_string(),
                        tool_call_id: "tc1".to_string(),
                        tool: "bash".to_string(),
                        input: input.clone(),
                        ..PermissionRequested::default()
                    }),
                ],
                terminal: Terminal {
                    status: TerminalStatus::Succeeded,
                    ..Terminal::default()
                },
                wait_for_permission: true,
                ..Script::default()
            }],
        );
        let s = adapter.start(spec()).await.unwrap();
        // Pull events until the request is announced.
        loop {
            let e = s.next_event().await.unwrap();
            if matches!(e.payload, Some(EventPayload::PermissionRequested(_))) {
                break;
            }
        }
        // Mismatched id.
        let err = s
            .respond_permission(PermissionDecision {
                request_id: "nope".to_string(),
                allow: false,
                ..decision()
            })
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, domain_codes::PERMISSION_MISMATCH));
        // Allow with a wrong binding.
        let err = s
            .respond_permission(PermissionDecision {
                request_id: "p1".to_string(),
                allow: true,
                input_sha256: [0u8; 32],
                ..decision()
            })
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, port::codes::PERMISSION_BINDING));
        // Allow binding the exact input bytes.
        s.respond_permission(PermissionDecision {
            request_id: "p1".to_string(),
            allow: true,
            input_sha256: sha(&input),
            ..decision()
        })
        .await
        .unwrap();
        // The resolved event precedes the terminal.
        let mut saw_resolved = false;
        while let Some(e) = s.next_event().await {
            if let Some(EventPayload::PermissionResolved(r)) = &e.payload {
                assert_eq!(r.decision, PermissionOutcome::Allowed);
                saw_resolved = true;
            }
        }
        assert!(saw_resolved, "PermissionResolved emitted");
        // No pending request left.
        let err = s
            .respond_permission(PermissionDecision {
                request_id: "p1".to_string(),
                ..decision()
            })
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, port::codes::NO_PENDING_PERMISSION));
    }

    fn decision() -> PermissionDecision {
        PermissionDecision {
            request_id: String::new(),
            allow: false,
            option_id: String::new(),
            decided_by: "operator_session:test".to_string(),
            input_sha256: [0u8; 32],
        }
    }

    /// Upstream `TestInterruptThenRespondGetsNoPending` and kill
    /// precedence.
    #[tokio::test]
    async fn interrupt_and_kill_clear_pending() {
        for kill_first in [false, true] {
            let adapter = FakeAdapter::new(
                Kind::new("claude-code"),
                caps(),
                vec![Script {
                    payloads: vec![
                        EventPayload::SessionStarted(SessionStartedPayload {
                            harness_session_id: "s1".to_string(),
                            ..SessionStartedPayload::default()
                        }),
                        EventPayload::PermissionRequested(PermissionRequested {
                            request_id: "p1".to_string(),
                            input: b"x".to_vec(),
                            ..PermissionRequested::default()
                        }),
                    ],
                    terminal: Terminal {
                        status: TerminalStatus::Succeeded,
                        ..Terminal::default()
                    },
                    wait_for_permission: true,
                    ..Script::default()
                }],
            );
            let s = adapter.start(spec()).await.unwrap();
            if kill_first {
                s.kill().await.unwrap();
                s.interrupt().await.unwrap();
            } else {
                s.interrupt().await.unwrap();
            }
            let err = s
                .respond_permission(PermissionDecision {
                    request_id: "p1".to_string(),
                    ..decision()
                })
                .await
                .map(|_| ())
                .unwrap_err();
            assert!(
                is_code(&err, port::codes::NO_PENDING_PERMISSION),
                "kill_first={kill_first}: {err}"
            );
            let t = s.wait().await.unwrap();
            assert_eq!(
                t.status,
                if kill_first {
                    TerminalStatus::Killed
                } else {
                    TerminalStatus::Interrupted
                },
                "kill_first={kill_first}"
            );
            while s.next_event().await.is_some() {}
        }
    }

    /// Upstream `TestInterruptAfterEndReturnsSessionEnded`.
    #[tokio::test]
    async fn interrupt_after_end_is_session_ended() {
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            caps(),
            vec![Script {
                terminal: Terminal {
                    status: TerminalStatus::Succeeded,
                    ..Terminal::default()
                },
                ..Script::default()
            }],
        );
        let s = adapter.start(spec()).await.unwrap();
        s.wait().await.unwrap();
        while s.next_event().await.is_some() {}
        // `done` latches when the run ends; give the run task a turn.
        tokio::task::yield_now().await;
        let err = s.interrupt().await.map(|_| ()).unwrap_err();
        assert!(is_code(&err, port::codes::SESSION_ENDED));
    }

    /// Upstream `TestSendNeedsStreamingInput` and input recording.
    #[tokio::test]
    async fn send_records_input_when_capable() {
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            caps(),
            vec![Script {
                wait_for_permission: true,
                payloads: vec![EventPayload::PermissionRequested(PermissionRequested {
                    request_id: "p".to_string(),
                    ..PermissionRequested::default()
                })],
                ..Script::default()
            }],
        );
        let s = adapter.start(spec()).await.unwrap();
        s.send(OperatorInput {
            text: "hello".to_string(),
        })
        .await
        .unwrap();
        assert_eq!(adapter.inputs().len(), 1);
        s.kill().await.unwrap();
        s.wait().await.unwrap();

        let no_stream = FakeAdapter::new(
            Kind::new("claude-code"),
            Capabilities::default(),
            vec![Script::default()],
        );
        let s = no_stream.start(spec()).await.unwrap();
        let err = s
            .send(OperatorInput {
                text: "x".to_string(),
            })
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, port::codes::UNSUPPORTED));
    }

    /// Upstream `TestNoExitStatusScript`.
    #[tokio::test]
    async fn no_exit_status_script() {
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            caps(),
            vec![Script {
                terminal: Terminal {
                    status: TerminalStatus::Failed,
                    ..Terminal::default()
                },
                no_exit_status: true,
                ..Script::default()
            }],
        );
        let s = adapter.start(spec()).await.unwrap();
        let t = s.wait().await.unwrap();
        assert_eq!(t.exit_code, None);
    }

    /// Upstream `TestStartErr` and call recording.
    #[tokio::test]
    async fn start_err_is_returned_after_recording() {
        let adapter = FakeAdapter::new(
            Kind::new("claude-code"),
            caps(),
            vec![Script {
                start_err: Some(Failure::internal("fake_start_err", "launcher refused")),
                ..Script::default()
            }],
        );
        let err = adapter.start(spec()).await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), "fake_start_err");
        assert_eq!(adapter.calls().len(), 1);
        assert_eq!(adapter.calls()[0].method, "start");
    }

    /// Upstream `launcher_test.go`: liveness, recorded kills, scripted
    /// errors, unsupported launch.
    #[tokio::test]
    async fn fake_launcher() {
        let l = FakeLauncher::new();
        assert!(!l.is_alive("s1").await.unwrap(), "unknown scope is dead");
        l.set_alive("s1", true);
        assert!(l.is_alive("s1").await.unwrap());
        l.kill_scope("s1").await.unwrap();
        assert!(
            !l.is_alive("s1").await.unwrap(),
            "kill marks the scope dead"
        );
        assert_eq!(l.kills(), vec!["s1".to_string()]);

        l.fail_kill(Some(Failure::internal("fake_kill_err", "kill failed")));
        let err = l.kill_scope("s1").await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), "fake_kill_err");
        l.fail_kill(None);

        l.fail_alive(Some(Failure::internal("fake_alive_err", "down")));
        let err = l.is_alive("s1").await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), "fake_alive_err");
        l.fail_alive(None);

        let spec = ProcessSpec {
            program: "claude".to_string(),
            args: vec![],
            env: BTreeMap::new(),
            work_dir: "/w".to_string(),
            scope_id: "s1".to_string(),
            env_extras: vec![],
        };
        let err = l.launch(spec).await.map(|_| ()).unwrap_err();
        assert!(is_code(&err, codes::LAUNCH_UNSUPPORTED));
    }
}
