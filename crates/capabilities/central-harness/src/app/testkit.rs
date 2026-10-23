//! The test world — the port of `internal/harness/app/fakes_test.go`
//! plus `internal/adapter/harness/fake`: a scripted
//! [`ports::RunLifecycle`], an in-memory [`AttemptStore`] with the
//! PostgreSQL store's compare-and-swap + approval rules, a scripted
//! provisioner/capture/artifacts/sink, a scripted [`Adapter`]
//! whose sessions are *state machines* (Rust futures are polled, so
//! the Go run goroutine becomes `next_event`'s advance), and a
//! `block_on` driver (the port crate owns no runtime).
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, StepAttemptId, StepId, TaskId,
    WorkspaceId,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::approval::{ApprovalDecision, ApprovalState, PermissionApproval};
use crate::attempt::Attempt;
use crate::budget::Budget;
use crate::capability::Capabilities;
use crate::domain::{self, Kind, PermissionPolicy, Terminal, TerminalStatus, Workspace};
use crate::event::{Event, EventKind, EventPayload, PermissionResolved};
use crate::port::{
    Adapter, ApprovalOpen, AttemptStore, ExecutionLease, LeaseBinder, OperatorInput,
    PermissionDecision, PortFuture, ProbeResult, ReconcileInput, ReconcileResult, Session,
    SessionRef, StartSpec,
};
use crate::record::EventRecord;

use super::orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorDeps};
use super::ports::{
    self, ArtifactOutcome, ArtifactOutcomeKind, ArtifactRole, CancelSignal, Capture, ClaimedRun,
    Clock, DispatchCase, DispatchableRun, FailureCode, HarnessResult, Milestone, MilestoneKind,
    ResumeFrom, Settlement, codes,
};

pub(crate) const BASE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

pub(crate) fn test_env() -> std::collections::BTreeMap<String, String> {
    [
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

// ---------------------------------------------------------------------------
// Executor + signal — the Go channels/goroutines as Rust futures
// ---------------------------------------------------------------------------

/// `block_on` — a park/unpark executor for the tests (the port crate
/// has no runtime).
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    struct T(std::thread::Thread);
    impl Wake for T {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(T(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// `waitFor` — polls `cond` until true (5s).
pub(crate) fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !cond() {
        assert!(
            std::time::Instant::now() <= deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// `context.WithCancel` — the test's manual stop signal.
#[derive(Debug, Default)]
pub(crate) struct ManualCancel {
    set: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ManualCancel {
    pub(crate) fn cancel(&self) {
        self.set.store(true, Ordering::SeqCst);
        if let Ok(mut g) = self.waker.lock()
            && let Some(w) = g.take()
        {
            w.wake();
        }
    }
}

impl CancelSignal for ManualCancel {
    fn cancelled(&self) -> PortFuture<'_, ()> {
        Box::pin(std::future::poll_fn(|cx| {
            if self.set.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
            if let Ok(mut g) = self.waker.lock() {
                *g = Some(cx.waker().clone());
            }
            Poll::Pending
        }))
    }

    fn is_cancelled(&self) -> bool {
        self.set.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// trace — the shared, ordered call log of every fake
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TraceInner {
    calls: Mutex<Vec<String>>,
}

/// `trace` — `add`/`all`/`index`/`count`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Trace {
    inner: Arc<TraceInner>,
}

impl Trace {
    pub(crate) fn add(&self, call: impl Into<String>) {
        if let Ok(mut g) = self.inner.calls.lock() {
            g.push(call.into());
        }
    }

    pub(crate) fn all(&self) -> Vec<String> {
        self.inner
            .calls
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub(crate) fn index(&self, prefix: &str) -> i64 {
        for (i, c) in self.all().iter().enumerate() {
            if c.starts_with(prefix) {
                return i as i64;
            }
        }
        -1
    }

    pub(crate) fn count(&self, prefix: &str) -> usize {
        self.all().iter().filter(|c| c.starts_with(prefix)).count()
    }
}

/// `realClock`.
pub(crate) struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// `errTransient` — a plain transient write failure.
pub(crate) fn err_transient() -> Failure {
    Failure::internal("transient", "transient failure")
}

// ---------------------------------------------------------------------------
// lifecycle — a scripted ports::RunLifecycle
// ---------------------------------------------------------------------------

pub(crate) struct Lifecycle {
    pub(crate) tr: Trace,
    inner: Mutex<LifecycleInner>,
    pub(crate) lease_lost: AtomicBool,
    pub(crate) heartbeat_failing: AtomicBool,
    pub(crate) cancelling: AtomicBool,
    pub(crate) cancel_at_settle: AtomicBool,
    pub(crate) cancel_at_report: AtomicBool,
    pub(crate) zero_lease: AtomicBool,
    pub(crate) heartbeats: AtomicI64,
    pub(crate) cancellations: AtomicI64,
    pub(crate) reconciled: AtomicI64,
    /// `heartbeat_block` makes Heartbeat pend until the executor drops
    /// it — `blockedHeartbeatLifecycle` (the join test).
    pub(crate) heartbeat_block: AtomicBool,
    /// `entered` — closed by the first blocked heartbeat (the join
    /// test's `entered` channel).
    pub(crate) hb_entered: Arc<AtomicBool>,
    hb_wake: Mutex<Option<Waker>>,
    /// `on_mark_invoked` — flakyLifecycle's fail hook: `Some(err)`
    /// overrides the call.
    on_mark_invoked: Mutex<Option<WriteHook>>,
    /// `on_record_completion`/`on_settle`/`on_abandon`/`on_cancel` —
    /// failingLifecycle's per-write overrides (`Some(err)` refuses).
    on_record_completion: Mutex<Option<WriteHook>>,
    on_settle: Mutex<Option<WriteHook>>,
    on_abandon: Mutex<Option<WriteHook>>,
    on_cancel: Mutex<Option<WriteHook>>,
}

/// A write-override hook: `Some(err)` refuses the call.
type WriteHook = Box<dyn Fn() -> Option<Failure> + Send>;

/// `FakeStore::beforeWrite` — sees an attempt write before it commits.
type AttemptHook = Box<dyn Fn(&Attempt) + Send>;

/// `FakeStore::saveErr` — Save's per-attempt error.
type SaveErrHook = Box<dyn Fn(&Attempt) -> Option<Failure> + Send>;

struct LifecycleInner {
    runs: Vec<DispatchableRun>,
    prompt: String,
    permission: PermissionPolicy,
    budget: Budget,
    generation: i64,
    started: Vec<DispatchableRun>,
    completion: Vec<Settlement>,
    settled: Vec<Settlement>,
    abandoned: Vec<FailureCode>,
    reports: Vec<String>,
    start_err: Option<Failure>,
    invoke_err: Option<Failure>,
    report_outcome: Option<ArtifactOutcome>,
    report_err: Option<Failure>,
    reconcile_err: Option<Failure>,
}

impl Lifecycle {
    pub(crate) fn new(tr: &Trace, runs: Vec<DispatchableRun>) -> Self {
        Self {
            tr: tr.clone(),
            inner: Mutex::new(LifecycleInner {
                runs,
                prompt: "create hello.txt containing hi and commit it".to_string(),
                permission: PermissionPolicy::Unset,
                budget: Budget::default(),
                generation: 0,
                started: Vec::new(),
                completion: Vec::new(),
                settled: Vec::new(),
                abandoned: Vec::new(),
                reports: Vec::new(),
                start_err: None,
                invoke_err: None,
                report_outcome: None,
                report_err: None,
                reconcile_err: None,
            }),
            lease_lost: AtomicBool::new(false),
            heartbeat_failing: AtomicBool::new(false),
            cancelling: AtomicBool::new(false),
            cancel_at_settle: AtomicBool::new(false),
            cancel_at_report: AtomicBool::new(false),
            zero_lease: AtomicBool::new(false),
            heartbeats: AtomicI64::new(0),
            cancellations: AtomicI64::new(0),
            reconciled: AtomicI64::new(0),
            heartbeat_block: AtomicBool::new(false),
            hb_entered: Arc::new(AtomicBool::new(false)),
            hb_wake: Mutex::new(None),
            on_mark_invoked: Mutex::new(None),
            on_record_completion: Mutex::new(None),
            on_settle: Mutex::new(None),
            on_abandon: Mutex::new(None),
            on_cancel: Mutex::new(None),
        }
    }

    pub(crate) fn set_permission(&self, p: PermissionPolicy) {
        if let Ok(mut g) = self.inner.lock() {
            g.permission = p;
        }
    }

    pub(crate) fn set_budget(&self, b: Budget) {
        if let Ok(mut i) = self.inner.lock() {
            i.budget = b;
        }
    }

    pub(crate) fn set_generation(&self, g: i64) {
        if let Ok(mut i) = self.inner.lock() {
            i.generation = g;
        }
    }

    pub(crate) fn set_prompt(&self, prompt: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.prompt = prompt.to_string();
        }
    }

    pub(crate) fn set_start_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.start_err = e;
        }
    }

    pub(crate) fn set_invoke_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.invoke_err = e;
        }
    }

    pub(crate) fn set_report(&self, outcome: Option<ArtifactOutcome>, err: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.report_outcome = outcome;
            g.report_err = err;
        }
    }

    pub(crate) fn set_reconcile_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.reconcile_err = e;
        }
    }

    pub(crate) fn set_on_mark_invoked(&self, hook: impl Fn() -> Option<Failure> + Send + 'static) {
        if let Ok(mut g) = self.on_mark_invoked.lock() {
            *g = Some(Box::new(hook));
        }
    }

    pub(crate) fn set_on_record_completion(
        &self,
        hook: impl Fn() -> Option<Failure> + Send + 'static,
    ) {
        if let Ok(mut g) = self.on_record_completion.lock() {
            *g = Some(Box::new(hook));
        }
    }

    pub(crate) fn set_on_settle(&self, hook: impl Fn() -> Option<Failure> + Send + 'static) {
        if let Ok(mut g) = self.on_settle.lock() {
            *g = Some(Box::new(hook));
        }
    }

    pub(crate) fn set_on_abandon(&self, hook: impl Fn() -> Option<Failure> + Send + 'static) {
        if let Ok(mut g) = self.on_abandon.lock() {
            *g = Some(Box::new(hook));
        }
    }

    pub(crate) fn set_on_cancel(&self, hook: impl Fn() -> Option<Failure> + Send + 'static) {
        if let Ok(mut g) = self.on_cancel.lock() {
            *g = Some(Box::new(hook));
        }
    }

    /// `lost` — the lease refusal.
    fn lost(&self) -> Result<(), Failure> {
        if self.lease_lost.load(Ordering::SeqCst) {
            return Err(Failure::conflict(
                codes::LEASE_LOST,
                "the execution lease is gone",
            ));
        }
        Ok(())
    }

    /// `refuse` — the lease or cancellation refusal of a write.
    fn refuse(&self) -> Result<(), Failure> {
        self.lost()?;
        if self.cancelling.load(Ordering::SeqCst) {
            return Err(Failure::cancelled(
                codes::CANCEL_REQUESTED,
                "task is cancelling",
            ));
        }
        Ok(())
    }

    pub(crate) fn reported(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|g| g.reports.clone())
            .unwrap_or_default()
    }

    pub(crate) fn started(&self) -> Vec<DispatchableRun> {
        self.inner
            .lock()
            .map(|g| g.started.clone())
            .unwrap_or_default()
    }

    pub(crate) fn snapshot(&self) -> (Vec<Settlement>, Vec<Settlement>, Vec<FailureCode>) {
        match self.inner.lock() {
            Ok(g) => (g.completion.clone(), g.settled.clone(), g.abandoned.clone()),
            Err(_) => (Vec::new(), Vec::new(), Vec::new()),
        }
    }
}

impl ports::RunLifecycle for Lifecycle {
    fn list_dispatchable<'a>(
        &'a self,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<DispatchableRun>, Failure>> {
        Box::pin(async move {
            let g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Ok(Vec::new()),
            };
            let started: std::collections::HashSet<RunId> =
                g.started.iter().map(|d| d.run_id).collect();
            let mut out = Vec::new();
            for r in g.runs.iter() {
                if !started.contains(&r.run_id) && out.len() < limit {
                    out.push(r.clone());
                }
            }
            Ok(out)
        })
    }

    fn start<'a>(&'a self, run: DispatchableRun) -> PortFuture<'a, Result<ClaimedRun, Failure>> {
        self.tr.add("lifecycle.Start");
        Box::pin(async move {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Err(Failure::internal("poisoned", "lifecycle lock poisoned")),
            };
            if let Some(e) = &g.start_err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            g.started.push(run.clone());
            g.generation += 1;
            let attempt = if run.step_attempt_id.is_nil() {
                StepAttemptId::new()
            } else {
                run.step_attempt_id
            };
            let credential = if self.zero_lease.load(Ordering::SeqCst) {
                [0; 32]
            } else {
                [1, 2, 3]
                    .into_iter()
                    .chain(std::iter::repeat(0))
                    .take(32)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap_or([0; 32])
            };
            Ok(ClaimedRun {
                workspace_id: run.workspace_id,
                task_id: run.task_id,
                run_id: run.run_id,
                step_id: StepId::new(),
                step_attempt_id: attempt,
                prompt: g.prompt.clone(),
                permission: g.permission,
                budget: g.budget,
                lease: ExecutionLease {
                    generation: g.generation,
                    credential,
                },
            })
        })
    }

    fn heartbeat<'a>(&'a self, _run: ClaimedRun) -> PortFuture<'a, Result<bool, Failure>> {
        self.tr.add("lifecycle.Heartbeat");
        self.heartbeats.fetch_add(1, Ordering::SeqCst);
        if self.heartbeat_block.load(Ordering::SeqCst) {
            // blockedHeartbeatLifecycle — pends forever; dropping the
            // future is the Go ctx's cancellation.
            self.hb_entered.store(true, Ordering::SeqCst);
            return Box::pin(std::future::pending());
        }
        if self.heartbeat_failing.load(Ordering::SeqCst) {
            return Box::pin(async move { Err(err_transient()) });
        }
        Box::pin(async move {
            match self.lost() {
                Err(e) => Err(e),
                Ok(()) => Ok(self.cancelling.load(Ordering::SeqCst)),
            }
        })
    }

    fn mark_invoked<'a>(&'a self, _run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("lifecycle.MarkInvoked");
        let hook = self
            .on_mark_invoked
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|_| ()))
            .and_then(|_| {
                self.on_mark_invoked
                    .lock()
                    .ok()
                    .and_then(|g| g.as_ref().and_then(|f| f()))
            });
        if let Some(e) = hook {
            return Box::pin(async move { Err(e) });
        }
        Box::pin(async move {
            self.refuse()?;
            match self.inner.lock() {
                Ok(g) => match &g.invoke_err {
                    Some(e) => Err(Failure::internal(e.code(), e.message())),
                    None => Ok(()),
                },
                Err(_) => Err(Failure::internal("poisoned", "lifecycle lock poisoned")),
            }
        })
    }

    fn abandon_prepared<'a>(
        &'a self,
        _run: ClaimedRun,
        reason: FailureCode,
    ) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add(format!("lifecycle.AbandonPrepared:{reason}"));
        let hook = self
            .on_abandon
            .lock()
            .ok()
            .and_then(|g| g.as_ref().and_then(|f| f()));
        if let Some(e) = hook {
            return Box::pin(async move { Err(e) });
        }
        Box::pin(async move {
            self.refuse()?;
            if let Ok(mut g) = self.inner.lock() {
                g.abandoned.push(reason);
            }
            Ok(())
        })
    }

    fn record_completion<'a>(
        &'a self,
        _run: ClaimedRun,
        s: Settlement,
    ) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("lifecycle.RecordCompletion");
        let hook = self
            .on_record_completion
            .lock()
            .ok()
            .and_then(|g| g.as_ref().and_then(|f| f()));
        if let Some(e) = hook {
            return Box::pin(async move { Err(e) });
        }
        Box::pin(async move {
            self.refuse()?;
            if let Ok(mut g) = self.inner.lock() {
                g.completion.push(s);
            }
            Ok(())
        })
    }

    fn settle<'a>(
        &'a self,
        _run: ClaimedRun,
        s: Settlement,
    ) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("lifecycle.Settle");
        let hook = self
            .on_settle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().and_then(|f| f()));
        if let Some(e) = hook {
            return Box::pin(async move { Err(e) });
        }
        Box::pin(async move {
            self.refuse()?;
            if self.cancel_at_settle.load(Ordering::SeqCst) {
                return Err(Failure::cancelled(
                    codes::CANCEL_REQUESTED,
                    "task is cancelling",
                ));
            }
            if let Ok(mut g) = self.inner.lock() {
                g.settled.push(s);
            }
            Ok(())
        })
    }

    fn settle_cancellation<'a>(&'a self, _run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("lifecycle.SettleCancellation");
        let hook = self
            .on_cancel
            .lock()
            .ok()
            .and_then(|g| g.as_ref().and_then(|f| f()));
        if let Some(e) = hook {
            return Box::pin(async move { Err(e) });
        }
        Box::pin(async move {
            self.lost()?;
            self.cancellations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn complete_with_report<'a>(
        &'a self,
        _run: ClaimedRun,
        report: Vec<u8>,
    ) -> PortFuture<'a, Result<ArtifactOutcome, Failure>> {
        self.tr.add("lifecycle.CompleteWithReport");
        Box::pin(async move {
            if self.cancel_at_report.load(Ordering::SeqCst) {
                self.cancelling.store(true, Ordering::SeqCst);
            }
            self.refuse()?;
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Err(Failure::internal("poisoned", "lifecycle lock poisoned")),
            };
            g.reports
                .push(String::from_utf8_lossy(&report).into_owned());
            if let Some(e) = &g.report_err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            Ok(g.report_outcome.clone().unwrap_or(ArtifactOutcome {
                kind: ArtifactOutcomeKind::Ready,
                reason: FailureCode::default(),
            }))
        })
    }

    fn reconcile<'a>(&'a self, _run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("lifecycle.Reconcile");
        Box::pin(async move {
            self.refuse()?;
            if let Ok(g) = self.inner.lock()
                && let Some(e) = &g.reconcile_err
            {
                return Err(Failure::internal(e.code(), e.message()));
            }
            self.reconciled.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

/// `queuedRun`.
pub(crate) fn queued_run() -> DispatchableRun {
    DispatchableRun {
        case: DispatchCase::Queued,
        workspace_id: WorkspaceId::new(),
        task_id: TaskId::new(),
        run_id: RunId::new(),
        step_id: StepId::from_trusted_db_bytes([0; 16]),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
    }
}

// ---------------------------------------------------------------------------
// store — in-memory AttemptStore/RecoveryStore/ResolveStore with the
// PostgreSQL rules + scripting knobs
// ---------------------------------------------------------------------------

pub(crate) struct FakeStore {
    me: Mutex<std::sync::Weak<FakeStore>>,
    pub(crate) tr: Trace,
    inner: Mutex<StoreInner>,
    pub(crate) lease_lost: AtomicBool,
    pub(crate) append_failures: AtomicI64,
    pub(crate) append_failing: AtomicBool,
    /// `beforeWrite` — sees every attempt write just before it commits.
    before_write: Mutex<Option<AttemptHook>>,
    /// `saveErr` — Save's error for `next` (3e).
    save_err: Mutex<Option<SaveErrHook>>,
    /// `attemptHook` — flaky stores (not used by the ported tests).
    candidates: Mutex<Vec<crate::port::RecoveryCandidate>>,
    refuse: Mutex<HashMap<HarnessAttemptId, Failure>>,
    recovered: Mutex<Vec<Attempt>>,
}

#[derive(Default)]
struct StoreInner {
    attempts: HashMap<HarnessAttemptId, Attempt>,
    records: Vec<EventRecord>,
    approvals: HashMap<HarnessPermissionApprovalId, PermissionApproval>,
    approval_order: Vec<HarnessPermissionApprovalId>,
    create_err: Option<Failure>,
    append_err: Option<Failure>,
    open_err: Option<Failure>,
    expire_err: Option<Failure>,
    load_err: Option<Failure>,
}

impl FakeStore {
    /// `new` returns `Arc<FakeStore>` — the bound store upgrades the
    /// weak self-handle the constructor installs.
    pub(crate) fn new(tr: &Trace) -> Arc<Self> {
        let s = Arc::new(Self {
            me: Mutex::new(std::sync::Weak::new()),
            tr: tr.clone(),
            inner: Mutex::new(StoreInner::default()),
            lease_lost: AtomicBool::new(false),
            append_failures: AtomicI64::new(0),
            append_failing: AtomicBool::new(false),
            before_write: Mutex::new(None),
            save_err: Mutex::new(None),
            candidates: Mutex::new(Vec::new()),
            refuse: Mutex::new(HashMap::new()),
            recovered: Mutex::new(Vec::new()),
        });
        if let Ok(mut g) = s.me.lock() {
            *g = Arc::downgrade(&s);
        }
        s
    }

    pub(crate) fn set_create_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.create_err = e;
        }
    }

    pub(crate) fn set_append_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.append_err = e;
        }
    }

    pub(crate) fn set_open_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.open_err = e;
        }
    }

    pub(crate) fn set_expire_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.expire_err = e;
        }
    }

    pub(crate) fn set_load_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.load_err = e;
        }
    }

    pub(crate) fn set_before_write(&self, f: impl Fn(&Attempt) + Send + 'static) {
        if let Ok(mut g) = self.before_write.lock() {
            *g = Some(Box::new(f));
        }
    }

    /// `set_save_err` — Save's error for `next` (3e).
    pub(crate) fn set_save_err(&self, f: impl Fn(&Attempt) -> Option<Failure> + Send + 'static) {
        if let Ok(mut g) = self.save_err.lock() {
            *g = Some(Box::new(f));
        }
    }

    /// `only` — the single stored attempt.
    pub(crate) fn only(&self) -> Attempt {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.attempts.values().next().cloned())
            .unwrap_or_else(blank)
    }

    /// `records` — every stored event record.
    pub(crate) fn records(&self) -> Vec<EventRecord> {
        self.inner
            .lock()
            .map(|g| g.records.clone())
            .unwrap_or_default()
    }

    /// `recordKinds`.
    pub(crate) fn record_kinds(&self) -> Vec<EventKind> {
        self.inner
            .lock()
            .map(|g| g.records.iter().map(|r| r.kind).collect())
            .unwrap_or_default()
    }

    /// `approvalList` — every approval in open order.
    pub(crate) fn approval_list(&self) -> Vec<PermissionApproval> {
        match self.inner.lock() {
            Ok(g) => g
                .approval_order
                .iter()
                .filter_map(|id| g.approvals.get(id).cloned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// `pending` — the pending approval, if any.
    pub(crate) fn pending(&self) -> Option<PermissionApproval> {
        self.approval_list()
            .into_iter()
            .find(|a| a.state == ApprovalState::Pending)
    }

    /// `decide` — the operator's compare-and-set (DecidePermission).
    pub(crate) fn decide(
        &self,
        id: HarnessPermissionApprovalId,
        allow: bool,
    ) -> Result<PermissionApproval, Failure> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| Failure::internal("poisoned", "store lock poisoned"))?;
        let Some(a) = g.approvals.get(&id).cloned() else {
            return Err(Failure::invalid(
                domain::codes::NO_PENDING_APPROVAL,
                "no pending approval",
            ));
        };
        if a.state != ApprovalState::Pending {
            return Err(Failure::invalid(
                domain::codes::NO_PENDING_APPROVAL,
                "no pending approval",
            ));
        }
        let attempt = g.attempts.get(&a.attempt_id).cloned();
        let awaiting = attempt
            .map(|t| {
                t.state == domain::State::AwaitingPermission && t.pending_permission == a.request_id
            })
            .unwrap_or(false);
        if !awaiting || self.lease_lost.load(Ordering::SeqCst) {
            return Err(Failure::invalid(
                domain::codes::NO_PENDING_APPROVAL,
                "no pending approval",
            ));
        }
        let mut decided = a
            .decide(
                ApprovalDecision {
                    allow,
                    input_mac: a.input_mac,
                    decided_by: "operator-session:alice".to_string(),
                },
                OffsetDateTime::now_utc(),
            )
            .map_err(|e| Failure::invalid(domain::codes::NO_PENDING_APPROVAL, e.message()))?;
        decided.version += 1;
        g.approvals.insert(id, decided.clone());
        Ok(decided)
    }

    /// `tamper` — rewrite a stored approval (a corrupted/foreign row).
    pub(crate) fn tamper(
        &self,
        id: HarnessPermissionApprovalId,
        edit: impl Fn(&mut PermissionApproval),
    ) {
        if let Ok(mut g) = self.inner.lock()
            && let Some(a) = g.approvals.get_mut(&id)
        {
            edit(a);
        }
    }

    /// `seedAttempt` — an attempt row with no recovery candidate.
    pub(crate) fn seed_attempt(&self, a: Attempt) {
        if let Ok(mut g) = self.inner.lock() {
            g.attempts.insert(a.id, a);
        }
    }

    /// `put` — seed an attempt and its recovery candidate.
    pub(crate) fn put(
        &self,
        a: Attempt,
        step: crate::port::LinkedStepAttemptState,
        lease_live: bool,
    ) {
        if let Ok(mut g) = self.inner.lock() {
            g.attempts.insert(a.id, a.clone());
        }
        if let Ok(mut c) = self.candidates.lock() {
            c.push(crate::port::RecoveryCandidate {
                attempt: a,
                step_state: step,
                lease_live,
            });
        }
    }

    /// The write's approval side — the PostgreSQL store's open +
    /// supersession rule. Callers hold the inner lock.
    fn approval_side(
        g: &mut StoreInner,
        expected: &Attempt,
        next: &Attempt,
        open: &[ApprovalOpen],
    ) -> Result<(), Failure> {
        if open.len() > 1
            || (open.len() == 1
                && !crate::port::opens_approval(expected, next, &open[0].request_id))
        {
            return Err(Failure::invalid(
                domain::codes::INVALID_APPROVAL,
                "an approval opens only as the attempt starts awaiting its request",
            ));
        }
        if crate::port::supersedes_approvals(next) {
            for a in g.approvals.values_mut() {
                if a.attempt_id == next.id
                    && a.state == ApprovalState::Pending
                    && let Ok(mut s) = a.supersede(next.updated_at)
                {
                    s.version += 1;
                    *a = s;
                }
            }
        }
        if let Some(o) = open.first() {
            let a = o.approval(next)?;
            if g.approvals.values().any(|other| {
                other.attempt_id == a.attempt_id && other.state == ApprovalState::Pending
            }) {
                return Err(Failure::invalid(
                    domain::codes::INVALID_APPROVAL,
                    "a pending approval already exists for the attempt",
                ));
            }
            g.approvals.insert(a.id, a.clone());
            g.approval_order.push(a.id);
        }
        Ok(())
    }
}

fn blank() -> Attempt {
    super::orchestrator::blank_attempt()
}

/// `boundStore` — a lease-bound view.
struct BoundStore {
    s: Arc<FakeStore>,
    lease: ExecutionLease,
}

impl BoundStore {
    /// `check` — the lease fence check.
    fn check(&self, a: &Attempt) -> Result<(), Failure> {
        if self.s.lease_lost.load(Ordering::SeqCst) || a.fence != self.lease.fence() {
            return Err(Failure::conflict(
                domain::codes::FENCE_MISMATCH,
                "the attempt fence is not the bound lease's",
            ));
        }
        Ok(())
    }

    /// `write` — the compare-and-swap.
    fn write(g: &mut StoreInner, expected: &Attempt, next: &Attempt) -> Result<Attempt, Failure> {
        next.validate()?;
        let stored = g.attempts.get(&expected.id).ok_or_else(|| {
            Failure::not_found(domain::codes::ATTEMPT_NOT_FOUND, "attempt not found")
        })?;
        if stored.version != expected.version || next.version != expected.version {
            return Err(Failure::conflict(
                domain::codes::VERSION_CONFLICT,
                "the attempt version moved on",
            ));
        }
        if stored.fence != expected.fence {
            return Err(Failure::conflict(
                domain::codes::FENCE_MISMATCH,
                "the attempt fence moved on",
            ));
        }
        let mut out = next.clone();
        out.version += 1;
        g.attempts.insert(out.id, out.clone());
        Ok(out)
    }

    /// `writeWithApprovals` — write + the approval side, atomically.
    fn write_with_approvals(
        &self,
        expected: &Attempt,
        next: &Attempt,
        open: &[ApprovalOpen],
    ) -> Result<Attempt, Failure> {
        if let Ok(hook) = self.s.before_write.lock()
            && let Some(f) = hook.as_ref()
        {
            f(next);
        }
        let mut g = self
            .s
            .inner
            .lock()
            .map_err(|_| Failure::internal("poisoned", "store lock poisoned"))?;
        let before = g.attempts.get(&expected.id).cloned();
        let out = Self::write(&mut g, expected, next)?;
        if let Err(e) = FakeStore::approval_side(&mut g, expected, &out, open) {
            if let Some(b) = before {
                g.attempts.insert(b.id, b);
            }
            return Err(e);
        }
        Ok(out)
    }
}

impl AttemptStore for BoundStore {
    fn create<'a>(&'a self, attempt: &'a Attempt) -> PortFuture<'a, Result<(), Failure>> {
        self.s.tr.add("store.Create");
        Box::pin(async move {
            self.check(attempt)?;
            if let Ok(mut g) = self.s.inner.lock() {
                if let Some(e) = &g.create_err {
                    return Err(Failure::internal(e.code(), e.message()));
                }
                attempt.validate()?;
                if let Some(stored) = g.attempts.get(&attempt.id) {
                    if stored.equal(attempt) {
                        return Ok(());
                    }
                    return Err(Failure::conflict(
                        domain::codes::VERSION_CONFLICT,
                        "a different attempt already holds the id",
                    ));
                }
                g.attempts.insert(attempt.id, attempt.clone());
            }
            Ok(())
        })
    }

    fn load<'a>(
        &'a self,
        _ws: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        Box::pin(async move {
            let g = self
                .s
                .inner
                .lock()
                .map_err(|_| Failure::internal("poisoned", "store lock poisoned"))?;
            g.attempts.get(&id).cloned().ok_or_else(|| {
                Failure::not_found(domain::codes::ATTEMPT_NOT_FOUND, "attempt not found")
            })
        })
    }

    fn live_attempt_for_run<'a>(
        &'a self,
        _ws: WorkspaceId,
        _run: RunId,
    ) -> PortFuture<'a, Result<Option<Attempt>, Failure>> {
        Box::pin(async move { Ok(None) })
    }

    fn save<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
        open: &'a [ApprovalOpen],
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        self.s.tr.add(format!("store.Save:{}", next.state.as_str()));
        Box::pin(async move {
            if let Ok(g) = self.s.save_err.lock()
                && let Some(f) = g.as_ref()
                && let Some(e) = f(next)
            {
                return Err(e);
            }
            if !open.is_empty()
                && let Ok(g) = self.s.inner.lock()
                && let Some(e) = &g.open_err
            {
                return Err(Failure::internal(e.code(), e.message()));
            }
            self.check(next)?;
            self.write_with_approvals(expected, next, open)
        })
    }

    fn append_event<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
        rec: &'a EventRecord,
        open: &'a [ApprovalOpen],
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        self.s
            .tr
            .add(format!("store.AppendEvent:{}", rec.kind.as_str()));
        Box::pin(async move {
            if let Ok(g) = self.s.inner.lock()
                && let Some(e) = &g.append_err
            {
                return Err(Failure::internal(e.code(), e.message()));
            }
            if !open.is_empty()
                && let Ok(g) = self.s.inner.lock()
                && let Some(e) = &g.open_err
            {
                return Err(Failure::internal(e.code(), e.message()));
            }
            if self.s.append_failing.load(Ordering::SeqCst)
                || self.s.append_failures.fetch_sub(1, Ordering::SeqCst) > 0
            {
                return Err(err_transient());
            }
            self.check(next)?;
            let out = self.write_with_approvals(expected, next, open)?;
            if let Ok(mut g) = self.s.inner.lock() {
                g.records.push(rec.clone());
            }
            Ok(out)
        })
    }

    fn expire_permission<'a>(
        &'a self,
        a: &'a Attempt,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
        self.s.tr.add("store.ExpirePermission");
        Box::pin(async move {
            self.check(a)?;
            let mut g = self
                .s
                .inner
                .lock()
                .map_err(|_| Failure::internal("poisoned", "store lock poisoned"))?;
            if let Some(e) = &g.expire_err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            let Some(approval) = g.approvals.get(&id).cloned() else {
                return Err(Failure::invalid(
                    domain::codes::NO_PENDING_APPROVAL,
                    "no pending approval",
                ));
            };
            if approval.attempt_id != a.id {
                return Err(Failure::invalid(
                    domain::codes::NO_PENDING_APPROVAL,
                    "no pending approval",
                ));
            }
            let now = OffsetDateTime::now_utc();
            if approval.state == ApprovalState::Pending && now >= approval.expires_at {
                let mut expired = approval.expire(now)?;
                expired.version += 1;
                g.approvals.insert(id, expired.clone());
                return Ok(expired);
            }
            Ok(approval)
        })
    }

    fn load_approval<'a>(
        &'a self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
        self.s.tr.add("store.LoadApproval");
        Box::pin(async move {
            let g = self
                .s
                .inner
                .lock()
                .map_err(|_| Failure::internal("poisoned", "store lock poisoned"))?;
            if let Some(e) = &g.load_err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            let a = g.approvals.get(&id).cloned();
            match a {
                Some(a) if a.workspace_id == ws => Ok(a),
                _ => Err(Failure::invalid(
                    domain::codes::NO_PENDING_APPROVAL,
                    "no pending approval",
                )),
            }
        })
    }
}

impl LeaseBinder for FakeStore {
    fn with_lease(&self, lease: ExecutionLease) -> Box<dyn AttemptStore> {
        Box::new(BoundStore {
            s: self
                .me
                .lock()
                .ok()
                .and_then(|g| g.upgrade())
                .expect("FakeStore used outside its world"),
            lease,
        })
    }
}

// ---------------------------------------------------------------------------
// provisioner / capturer / artifacts / sink
// ---------------------------------------------------------------------------

/// `reopenCall`.
#[derive(Debug, Clone)]
pub(crate) struct ReopenCall {
    pub(crate) ws: WorkspaceId,
    pub(crate) run: RunId,
    pub(crate) want: Workspace,
}

/// `provisioner` — a scripted [`ports::WorkspaceProvisioner`].
pub(crate) struct Provisioner {
    tr: Trace,
    ticker: Arc<dyn ports::Ticker>,
    inner: Mutex<ProvInner>,
}

struct ProvInner {
    space_err: Option<Failure>,
    err: Option<Failure>,
    delay: Duration,
    block: bool,
    reopen_err: Option<Failure>,
    reopens: Vec<ReopenCall>,
}

impl Provisioner {
    pub(crate) fn new(tr: &Trace, ticker: Arc<dyn ports::Ticker>) -> Self {
        Self {
            tr: tr.clone(),
            ticker,
            inner: Mutex::new(ProvInner {
                space_err: None,
                err: None,
                delay: Duration::ZERO,
                block: false,
                reopen_err: None,
                reopens: Vec::new(),
            }),
        }
    }

    pub(crate) fn set_space_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.space_err = e;
        }
    }

    pub(crate) fn set_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.err = e;
        }
    }

    pub(crate) fn set_delay(&self, d: Duration) {
        if let Ok(mut g) = self.inner.lock() {
            g.delay = d;
        }
    }

    pub(crate) fn set_block(&self, b: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.block = b;
        }
    }

    pub(crate) fn set_reopen_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.reopen_err = e;
        }
    }

    pub(crate) fn reopen_calls(&self) -> Vec<ReopenCall> {
        self.inner
            .lock()
            .map(|g| g.reopens.clone())
            .unwrap_or_default()
    }
}

impl ports::WorkspaceProvisioner for Provisioner {
    fn check_free_space<'a>(&'a self) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("provisioner.CheckFreeSpace");
        Box::pin(async move {
            match self.inner.lock() {
                Ok(g) => match &g.space_err {
                    Some(e) => Err(Failure::internal(e.code(), e.message())),
                    None => Ok(()),
                },
                Err(_) => Err(Failure::internal("poisoned", "provisioner lock poisoned")),
            }
        })
    }

    fn provision<'a>(
        &'a self,
        _ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Workspace, Failure>> {
        self.tr.add("provisioner.Provision");
        Box::pin(async move {
            let (delay, block, err) = match self.inner.lock() {
                Ok(g) => (
                    g.delay,
                    g.block,
                    g.err
                        .as_ref()
                        .map(|e| Failure::internal(e.code(), e.message())),
                ),
                Err(_) => (Duration::ZERO, false, None),
            };
            if block {
                std::future::pending::<()>().await;
            }
            if delay > Duration::ZERO {
                self.ticker.after(delay).await;
            }
            match err {
                Some(e) => Err(e),
                None => Ok(Workspace {
                    path: format!("/var/lib/central-harness/worktrees/runs/{run}/repo"),
                    base_sha: BASE_SHA.to_string(),
                }),
            }
        })
    }

    fn reopen<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
        want: Workspace,
    ) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("provisioner.Reopen");
        Box::pin(async move {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Err(Failure::internal("poisoned", "provisioner lock poisoned")),
            };
            g.reopens.push(ReopenCall { ws, run, want });
            match &g.reopen_err {
                Some(e) => Err(Failure::internal(e.code(), e.message())),
                None => Ok(()),
            }
        })
    }
}

/// `capturePaths`.
pub(crate) fn capture_paths(run: RunId) -> Capture {
    Capture {
        patch: format!("/capture/tmp/{run}/patch"),
        commits: format!("/capture/tmp/{run}/commits"),
        after_head: BASE_SHA.to_string(),
    }
}

/// `capturer` — a scripted [`ports::WorkspaceCapture`]; the body
/// "paths" are tokens naming the run.
pub(crate) struct Capturer {
    tr: Trace,
    inner: Mutex<CaptInner>,
    pub(crate) released: AtomicI64,
}

struct CaptInner {
    err: Option<Failure>,
    block: bool,
    on_call: Option<Box<dyn Fn() + Send>>,
}

impl Capturer {
    pub(crate) fn new(tr: &Trace) -> Self {
        Self {
            tr: tr.clone(),
            inner: Mutex::new(CaptInner {
                err: None,
                block: false,
                on_call: None,
            }),
            released: AtomicI64::new(0),
        }
    }

    pub(crate) fn set_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.inner.lock() {
            g.err = e;
        }
    }

    pub(crate) fn set_block(&self, b: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.block = b;
        }
    }

    pub(crate) fn set_on_call(&self, f: impl Fn() + Send + 'static) {
        if let Ok(mut g) = self.inner.lock() {
            g.on_call = Some(Box::new(f));
        }
    }
}

impl ports::WorkspaceCapture for Capturer {
    fn capture<'a>(
        &'a self,
        _ws: WorkspaceId,
        workspace: Workspace,
        run: RunId,
    ) -> PortFuture<'a, Result<Capture, Failure>> {
        self.tr.add("capture.Capture");
        Box::pin(async move {
            let (err, block, on_call) = match self.inner.lock() {
                Ok(g) => (
                    g.err
                        .as_ref()
                        .map(|e| Failure::internal(e.code(), e.message())),
                    g.block,
                    g.on_call.as_ref().map(|_| ()),
                ),
                Err(_) => (None, false, None),
            };
            if workspace.base_sha != BASE_SHA || !workspace.path.ends_with(&format!("{run}/repo")) {
                return Err(Failure::internal(
                    codes::CAPTURE_FAILED,
                    "capture of a foreign workspace",
                ));
            }
            if on_call.is_some()
                && let Ok(g) = self.inner.lock()
                && let Some(f) = &g.on_call
            {
                f();
            }
            if block {
                std::future::pending::<()>().await;
            }
            match err {
                Some(e) => Err(e),
                None => Ok(capture_paths(run)),
            }
        })
    }

    fn release<'a>(&'a self, _run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        self.tr.add("capture.Release");
        self.released.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(()) })
    }
}

/// `artifacts` — a scripted [`ports::ArtifactSink`].
pub(crate) struct Artifacts {
    tr: Trace,
    inner: Mutex<ArtsInner>,
    on_store: Mutex<Option<StoreHook>>,
}

/// `Artifacts::onStore` — sees each stored role.
type StoreHook = Box<dyn Fn(ArtifactRole) + Send>;

#[derive(Default)]
struct ArtsInner {
    outcomes: HashMap<ArtifactRole, ArtifactOutcome>,
    errs: HashMap<ArtifactRole, Failure>,
    bodies: HashMap<ArtifactRole, Vec<String>>,
}

impl Artifacts {
    pub(crate) fn new(tr: &Trace) -> Self {
        Self {
            tr: tr.clone(),
            inner: Mutex::new(ArtsInner::default()),
            on_store: Mutex::new(None),
        }
    }

    pub(crate) fn set_outcome(&self, role: ArtifactRole, outcome: ArtifactOutcome) {
        if let Ok(mut g) = self.inner.lock() {
            g.outcomes.insert(role, outcome);
        }
    }

    pub(crate) fn set_err(&self, role: ArtifactRole, e: Failure) {
        if let Ok(mut g) = self.inner.lock() {
            g.errs.insert(role, e);
        }
    }

    pub(crate) fn set_on_store(&self, f: impl Fn(ArtifactRole) + Send + 'static) {
        if let Ok(mut g) = self.on_store.lock() {
            *g = Some(Box::new(f));
        }
    }

    pub(crate) fn stored(&self, role: ArtifactRole) -> Vec<String> {
        self.inner
            .lock()
            .map(|g| g.bodies.get(&role).cloned().unwrap_or_default())
            .unwrap_or_default()
    }
}

impl ports::ArtifactSink for Artifacts {
    fn store<'a>(
        &'a self,
        _run: ClaimedRun,
        role: ArtifactRole,
        body: String,
    ) -> PortFuture<'a, Result<ArtifactOutcome, Failure>> {
        self.tr.add(format!("artifacts.Store:{role}"));
        Box::pin(async move {
            let (outcome, err, hook) = match self.inner.lock() {
                Ok(mut g) => {
                    g.bodies.entry(role).or_default().push(body);
                    (
                        g.outcomes.get(&role).cloned(),
                        g.errs
                            .get(&role)
                            .map(|e| Failure::internal(e.code(), e.message())),
                        self.on_store
                            .lock()
                            .ok()
                            .and_then(|h| h.as_ref().map(|_| ())),
                    )
                }
                Err(_) => (None, None, None),
            };
            if hook.is_some()
                && let Ok(g) = self.on_store.lock()
                && let Some(f) = g.as_ref()
            {
                f(role);
            }
            if let Some(e) = err {
                return Err(e);
            }
            Ok(outcome.unwrap_or(ArtifactOutcome {
                kind: ArtifactOutcomeKind::Ready,
                reason: FailureCode::default(),
            }))
        })
    }
}

/// `sink` — records milestones, deduped by key.
pub(crate) struct Sink {
    tr: Trace,
    inner: Mutex<SinkInner>,
    /// `tracing` mirrors each Record into `tr` — `tracingSink`.
    tracing: bool,
}

#[derive(Default)]
struct SinkInner {
    got: Vec<Milestone>,
    keys: std::collections::HashSet<String>,
}

impl Sink {
    pub(crate) fn new(tr: &Trace, tracing: bool) -> Self {
        Self {
            tr: tr.clone(),
            inner: Mutex::new(SinkInner::default()),
            tracing,
        }
    }

    pub(crate) fn kinds(&self) -> Vec<MilestoneKind> {
        self.inner
            .lock()
            .map(|g| g.got.iter().map(|m| m.kind).collect())
            .unwrap_or_default()
    }

    pub(crate) fn of(&self, kind: MilestoneKind) -> Vec<Milestone> {
        self.inner
            .lock()
            .map(|g| g.got.iter().filter(|m| m.kind == kind).cloned().collect())
            .unwrap_or_default()
    }
}

impl ports::TaskEventSink for Sink {
    fn record<'a>(&'a self, m: Milestone) -> PortFuture<'a, Result<(), Failure>> {
        if self.tracing {
            self.tr.add(format!("sink.Record:{}", m.kind.as_str()));
        }
        if let Ok(mut g) = self.inner.lock()
            && g.keys.insert(m.key.clone())
        {
            g.got.push(m);
        }
        Box::pin(async move { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Fake adapter + session — the scripted port.Adapter, as a state
// machine (Rust futures are polled)
// ---------------------------------------------------------------------------

/// `fake.Script`.
#[derive(Clone, Default)]
pub(crate) struct Script {
    pub(crate) session_id: String,
    pub(crate) payloads: Vec<EventPayload>,
    pub(crate) terminal: Terminal,
    pub(crate) start_err: Option<Failure>,
    pub(crate) wait_for_permission: bool,
    pub(crate) concurrent_permissions: bool,
    pub(crate) respond_err: Option<Failure>,
    pub(crate) no_exit_status: bool,
}

/// `fake.Call`.
pub(crate) struct Call {
    pub(crate) method: &'static str,
    pub(crate) spec: StartSpec,
    pub(crate) sref: SessionRef,
}

/// `fake.ErrScriptExhausted`.
pub(crate) fn err_script_exhausted() -> Failure {
    Failure::internal("script_exhausted", "fake harness: script exhausted")
}

const CLOCK_BASE_UNIX: i64 = 1_790_208_000; // 2026-09-27T00:00:00Z
fn clock_base() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(CLOCK_BASE_UNIX).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// The session's interior state — upstream `fake.session` + the test
/// adapter's wrapper knobs.
struct SessionInner {
    caps: Capabilities,
    attempt: HarnessAttemptId,
    script: Script,
    seq: u64,
    id: String,
    ref_sent: bool,
    ready: VecDeque<Event>,
    payloads: VecDeque<EventPayload>,
    /// Pending permission request ids, in order — the run waits on
    /// each.
    waiting: VecDeque<String>,
    /// request_id -> input (the exact bytes an allow binds).
    pending: HashMap<String, Vec<u8>>,
    /// Decisions taken by `respond_permission`, not yet consumed.
    permit: VecDeque<PermissionDecision>,
    stop_status: Option<TerminalStatus>,
    done: bool,
    terminal: Option<Terminal>,
    waker: Option<Waker>,
    // wrapper knobs
    swallow_interrupt: bool,
    interrupt_err: Option<Failure>,
    inject: Option<EventPayload>,
    injected: bool,
    drop_terminal: bool,
    // adapter-owned records
    inputs: Arc<Mutex<Vec<OperatorInput>>>,
}

impl SessionInner {
    /// `emit` — append one event (the run goroutine's emit).
    fn emit(&mut self, payload: EventPayload) {
        self.seq += 1;
        if let EventPayload::SessionStarted(s) = &payload {
            self.id = s.harness_session_id.clone();
            self.ref_sent = true;
        }
        // The raw frame is the marshaled {kind, payload} object —
        // upstream `json.Marshal(struct{Kind, Payload})`.
        let raw = serde_json::to_vec(&payload).unwrap_or_default();
        self.ready.push_back(Event {
            attempt: self.attempt,
            seq: self.seq,
            at: clock_base() + Duration::seconds(self.seq as i64),
            harness_session_id: self.id.clone(),
            raw,
            payload: Some(payload),
        });
    }

    /// `emitPermissionResolved`.
    fn emit_resolved(&mut self, d: &PermissionDecision) {
        let outcome = if d.allow {
            crate::event::PermissionOutcome::Allowed
        } else {
            crate::event::PermissionOutcome::Denied
        };
        self.emit(EventPayload::PermissionResolved(PermissionResolved {
            request_id: d.request_id.clone(),
            decision: outcome,
            decided_by: d.decided_by.clone(),
        }));
    }

    /// `finish` — emit the terminal and close the stream.
    fn finish(&mut self, t: Terminal) {
        self.terminal = Some(t.clone());
        self.emit(EventPayload::TerminalReported(
            crate::event::TerminalReported { terminal: t },
        ));
        self.done = true;
    }

    /// `finishOnStop` — clear pending, drain in-flight decisions, emit
    /// the stop's terminal.
    fn finish_on_stop(&mut self) {
        self.pending.clear();
        let status = self.stop_status.unwrap_or(TerminalStatus::Failed);
        while let Some(d) = self.permit.pop_front() {
            self.emit_resolved(&d);
        }
        self.finish(Terminal {
            status,
            ..Terminal::default()
        });
    }

    /// `signal` — Interrupt/Kill's stop record (kill wins).
    fn signal(&mut self, status: TerminalStatus) {
        if status == TerminalStatus::Killed || self.stop_status.is_none() {
            self.stop_status = Some(status);
        }
        self.pending.clear();
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }

    /// The run goroutine's next step — fills `ready` or pends.
    fn advance(&mut self, cx: &Context<'_>) -> Poll<Option<Event>> {
        loop {
            if let Some(ev) = self.ready.pop_front() {
                if self.drop_terminal
                    && matches!(ev.payload, Some(EventPayload::TerminalReported(_)))
                {
                    continue;
                }
                return Poll::Ready(Some(ev));
            }
            if self.done {
                return Poll::Ready(None);
            }
            if self.stop_status.is_some() {
                self.finish_on_stop();
                continue;
            }
            if !self.waiting.is_empty() {
                if let Some(d) = self.permit.pop_front() {
                    self.waiting.pop_front();
                    self.emit_resolved(&d);
                    continue;
                }
                self.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            match self.payloads.pop_front() {
                None => {
                    self.finish(self.script.terminal.clone());
                    continue;
                }
                Some(EventPayload::PermissionRequested(req)) if self.script.wait_for_permission => {
                    // The batch is this request alone, or, with
                    // concurrent_permissions, the run of consecutive
                    // requests starting here.
                    let mut batch = vec![req];
                    while self.script.concurrent_permissions
                        && matches!(
                            self.payloads.front(),
                            Some(EventPayload::PermissionRequested(_))
                        )
                    {
                        match self.payloads.pop_front() {
                            Some(EventPayload::PermissionRequested(n)) => batch.push(n),
                            _ => break,
                        }
                    }
                    if self.stop_status.is_some() {
                        self.finish_on_stop();
                        continue;
                    }
                    for r in &batch {
                        self.pending.insert(r.request_id.clone(), r.input.clone());
                        self.waiting.push_back(r.request_id.clone());
                    }
                    for r in batch {
                        self.emit(EventPayload::PermissionRequested(r));
                    }
                    continue;
                }
                Some(p) => {
                    self.emit(p);
                    continue;
                }
            }
        }
    }
}

/// `session` — the `dyn Session` over a shared inner.
pub(crate) struct FakeSession {
    inner: Arc<Mutex<SessionInner>>,
    interrupts: Arc<SessionShared>,
    kills: Arc<SessionShared>,
}

impl FakeSession {
    /// `Emit` the injected event after the first Interrupt.
    fn inject_event(inner: &mut SessionInner, inject: EventPayload) {
        inner.emit(inject);
    }
}

impl Session for FakeSession {
    fn session_ref(&self) -> PortFuture<'_, Option<SessionRef>> {
        Box::pin(async move {
            match self.inner.lock() {
                Ok(g) if g.ref_sent => Some(SessionRef {
                    harness_session_id: g.id.clone(),
                }),
                _ => None,
            }
        })
    }

    fn next_event(&self) -> PortFuture<'_, Option<Event>> {
        Box::pin(std::future::poll_fn(|cx| match self.inner.lock() {
            Ok(mut g) => g.advance(cx),
            Err(_) => Poll::Ready(None),
        }))
    }

    fn send<'a>(&'a self, input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let caps = self.inner.lock().map(|g| g.caps).unwrap_or_default();
            if !caps.streaming_input {
                return Err(Failure::invalid(
                    crate::port::codes::UNSUPPORTED,
                    "unsupported",
                ));
            }
            let inputs = match self.inner.lock() {
                Ok(g) => g.inputs.clone(),
                Err(_) => return Err(Failure::internal("poisoned", "session lock poisoned")),
            };
            if let Ok(mut g) = inputs.lock() {
                g.push(input);
            }
            Ok(())
        })
    }

    fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
        self.interrupts.interrupts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Ok(()),
            };
            if g.done {
                return Err(Failure::invalid(
                    crate::port::codes::SESSION_ENDED,
                    "the session already ended",
                ));
            }
            if !g.injected
                && let Some(inj) = g.inject.clone()
            {
                FakeSession::inject_event(&mut g, inj);
                g.injected = true;
            }
            if g.swallow_interrupt {
                return Ok(());
            }
            if let Some(e) = &g.interrupt_err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            g.signal(TerminalStatus::Interrupted);
            Ok(())
        })
    }

    fn respond_permission<'a>(
        &'a self,
        d: PermissionDecision,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Err(Failure::internal("poisoned", "session lock poisoned")),
            };
            if !g.caps.permission_bridge {
                return Err(Failure::invalid(
                    crate::port::codes::UNSUPPORTED,
                    "unsupported",
                ));
            }
            if let Some(e) = &g.script.respond_err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            if g.done || g.pending.is_empty() {
                return Err(Failure::invalid(
                    crate::port::codes::NO_PENDING_PERMISSION,
                    "fake harness: no pending permission",
                ));
            }
            let Some(input) = g.pending.get(&d.request_id).cloned() else {
                return Err(Failure::invalid(
                    domain::codes::PERMISSION_MISMATCH,
                    "fake harness: unknown permission request",
                ));
            };
            if d.allow && <[u8; 32]>::from(Sha256::digest(&input)) != d.input_sha256 {
                return Err(Failure::invalid(
                    crate::port::codes::PERMISSION_BINDING,
                    "fake harness: the allowed input does not bind",
                ));
            }
            g.pending.remove(&d.request_id);
            g.permit.push_back(d);
            if let Some(w) = g.waker.take() {
                w.wake();
            }
            Ok(())
        })
    }

    fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>> {
        Box::pin(std::future::poll_fn(|cx| match self.inner.lock() {
            Ok(mut g) => {
                if g.done {
                    let mut t = g.terminal.clone().unwrap_or_default();
                    if t.exit_code.is_none() && !g.script.no_exit_status {
                        t.exit_code = Some(0);
                    }
                    Poll::Ready(Ok(t))
                } else {
                    g.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => Poll::Ready(Err(Failure::internal("poisoned", "session lock poisoned"))),
        }))
    }

    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        self.kills.kills.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Ok(mut g) = self.inner.lock() {
                g.signal(TerminalStatus::Killed);
            }
            Ok(())
        })
    }
}

/// `adapter` — the scripted [`Adapter`] with the test wrapper's knobs.
pub(crate) struct FakeAdapter {
    kind: Kind,
    caps: Capabilities,
    tr: Trace,
    inner: Mutex<AdapterInner>,
    pub(crate) swallow_interrupt: AtomicBool,
    pub(crate) drop_terminal: AtomicBool,
    interrupt_err: Mutex<Option<Failure>>,
    inject_on_interrupt: Mutex<Option<EventPayload>>,
    sessions: Mutex<Vec<Arc<SessionShared>>>,
    probe_err: Mutex<Option<Failure>>,
}

struct AdapterInner {
    scripts: VecDeque<Script>,
    calls: Vec<Call>,
    inputs: Arc<Mutex<Vec<OperatorInput>>>,
    probe: ProbeResult,
    reconcile: ReconcileResult,
}

/// `session(i)` — the i-th opened session's inspectable counters.
pub(crate) struct SessionShared {
    pub(crate) interrupts: AtomicI64,
    pub(crate) kills: AtomicI64,
}

impl FakeAdapter {
    /// `fake.New` + `SetProbe`.
    pub(crate) fn new(tr: &Trace, kind: &str, caps: Capabilities, scripts: Vec<Script>) -> Self {
        Self {
            kind: Kind::new(kind),
            caps,
            tr: tr.clone(),
            inner: Mutex::new(AdapterInner {
                scripts: VecDeque::from(scripts),
                calls: Vec::new(),
                inputs: Arc::new(Mutex::new(Vec::new())),
                probe: ProbeResult {
                    harness_version: "2.1.283".to_string(),
                    authenticated: true,
                    detail: String::new(),
                },
                reconcile: ReconcileResult {
                    scope_alive: false,
                    reattached: None,
                    terminal: None,
                },
            }),
            swallow_interrupt: AtomicBool::new(false),
            drop_terminal: AtomicBool::new(false),
            interrupt_err: Mutex::new(None),
            inject_on_interrupt: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
            probe_err: Mutex::new(None),
        }
    }

    pub(crate) fn set_swallow_interrupt(&self, v: bool) {
        self.swallow_interrupt.store(v, Ordering::SeqCst);
    }

    pub(crate) fn set_drop_terminal(&self, v: bool) {
        self.drop_terminal.store(v, Ordering::SeqCst);
    }

    pub(crate) fn set_interrupt_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.interrupt_err.lock() {
            *g = e;
        }
    }

    pub(crate) fn set_inject_on_interrupt(&self, p: Option<EventPayload>) {
        if let Ok(mut g) = self.inject_on_interrupt.lock() {
            *g = p;
        }
    }

    pub(crate) fn set_probe_err(&self, e: Option<Failure>) {
        if let Ok(mut g) = self.probe_err.lock() {
            *g = e;
        }
    }

    /// `Calls`.
    pub(crate) fn calls(&self) -> Vec<(String, StartSpec, SessionRef)> {
        self.inner
            .lock()
            .map(|g| {
                g.calls
                    .iter()
                    .map(|c| (c.method.to_string(), c.spec.clone(), c.sref.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `Inputs`.
    pub(crate) fn inputs(&self) -> Vec<OperatorInput> {
        self.inner
            .lock()
            .map(|g| g.inputs.lock().map(|i| i.clone()).unwrap_or_default())
            .unwrap_or_default()
    }

    /// `session(i)` — inspectable counters of the i-th session.
    pub(crate) fn session_counts(&self, i: usize) -> Option<(i64, i64)> {
        self.sessions.lock().ok().and_then(|g| {
            g.get(i).map(|s| {
                (
                    s.interrupts.load(Ordering::SeqCst),
                    s.kills.load(Ordering::SeqCst),
                )
            })
        })
    }

    /// `open` — the shared Start/Resume body.
    fn open(
        &self,
        method: &'static str,
        spec: StartSpec,
        sref: SessionRef,
    ) -> Result<Box<dyn Session>, Failure> {
        spec.validate(
            &self
                .env_extras()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )?;
        if spec.limits.max_cost_micro_usd > 0 && !self.caps.native_cost_limit {
            return Err(Failure::invalid(
                crate::port::codes::UNSUPPORTED,
                "fake harness: native cost limit",
            ));
        }
        let mut g = self
            .inner
            .lock()
            .map_err(|_| Failure::internal("poisoned", "adapter lock poisoned"))?;
        let Some(script) = g.scripts.pop_front() else {
            return Err(err_script_exhausted());
        };
        g.calls.push(Call {
            method,
            spec: spec.clone(),
            sref,
        });
        let inputs = g.inputs.clone();
        drop(g);
        if let Some(e) = &script.start_err {
            return Err(Failure::internal(e.code(), e.message()));
        }
        let shared = Arc::new(SessionShared {
            interrupts: AtomicI64::new(0),
            kills: AtomicI64::new(0),
        });
        if let Ok(mut s) = self.sessions.lock() {
            s.push(shared.clone());
        }
        let shared2 = shared.clone();
        let inner = SessionInner {
            caps: self.caps,
            attempt: spec.attempt,
            seq: 0,
            id: script.session_id.clone(),
            ref_sent: false,
            ready: VecDeque::new(),
            payloads: VecDeque::from(script.payloads.clone()),
            waiting: VecDeque::new(),
            pending: HashMap::new(),
            permit: VecDeque::new(),
            stop_status: None,
            done: false,
            terminal: None,
            waker: None,
            swallow_interrupt: self.swallow_interrupt.load(Ordering::SeqCst),
            interrupt_err: self
                .interrupt_err
                .lock()
                .ok()
                .and_then(|e| e.as_ref().map(|f| Failure::internal(f.code(), f.message()))),
            inject: self.inject_on_interrupt.lock().ok().and_then(|p| p.clone()),
            injected: false,
            drop_terminal: self.drop_terminal.load(Ordering::SeqCst),
            inputs,
            script,
        };
        Ok(Box::new(FakeSession {
            inner: Arc::new(Mutex::new(inner)),
            interrupts: shared2,
            kills: shared,
        }))
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

    fn probe<'a>(
        &'a self,
        _env: crate::port::LaunchEnv,
    ) -> PortFuture<'a, Result<ProbeResult, Failure>> {
        self.tr.add("adapter.Probe");
        Box::pin(async move {
            let g = self
                .inner
                .lock()
                .map_err(|_| Failure::internal("poisoned", "adapter lock poisoned"))?;
            if let Some(e) = self
                .probe_err
                .lock()
                .ok()
                .and_then(|p| p.as_ref().map(|e| Failure::internal(e.code(), e.message())))
            {
                return Err(e);
            }
            Ok(g.probe.clone())
        })
    }

    fn start<'a>(&'a self, spec: StartSpec) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        self.tr.add("adapter.Start");
        Box::pin(async move { self.open("Start", spec, SessionRef::default()) })
    }

    fn resume<'a>(
        &'a self,
        sref: SessionRef,
        spec: StartSpec,
    ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        self.tr.add("adapter.Resume");
        Box::pin(async move {
            if !self.caps.resume_by_id {
                return Err(Failure::invalid(
                    crate::port::codes::UNSUPPORTED,
                    "unsupported",
                ));
            }
            if sref.harness_session_id.is_empty() {
                return Err(Failure::internal(
                    "resume",
                    "fake harness: resume requires a harness session id",
                ));
            }
            self.open("Resume", spec, sref)
        })
    }

    fn reconcile<'a>(
        &'a self,
        _input: ReconcileInput,
    ) -> PortFuture<'a, Result<ReconcileResult, Failure>> {
        Box::pin(async move {
            let g = self
                .inner
                .lock()
                .map_err(|_| Failure::internal("poisoned", "adapter lock poisoned"))?;
            if g.reconcile.reattached.is_some() && !self.caps.reattach {
                return Err(Failure::invalid(
                    crate::port::codes::UNSUPPORTED,
                    "unsupported",
                ));
            }
            Ok(ReconcileResult {
                scope_alive: g.reconcile.scope_alive,
                reattached: None,
                terminal: g.reconcile.terminal.clone(),
            })
        })
    }
}

/// `bridgeCaps` — the fake's capability set with the permission bridge.
pub(crate) fn bridge_caps() -> Capabilities {
    Capabilities {
        interrupt: true,
        permission_bridge: true,
        ..Capabilities::default()
    }
}

// ---------------------------------------------------------------------------
// ResumeSource
// ---------------------------------------------------------------------------

/// `noResume` — an ordinary claim's resume source: never a session.
pub(crate) struct NoResume;

impl ports::ResumeSource for NoResume {
    fn resume_from<'a>(
        &'a self,
        _run: ClaimedRun,
    ) -> PortFuture<'a, Result<Option<ResumeFrom>, Failure>> {
        Box::pin(async move { Ok(None) })
    }
}

/// `fakeResume` — the scripted resume source of a resuming attempt.
pub(crate) struct ScriptedResume {
    inner: Mutex<ScriptedResumeInner>,
}

#[derive(Default)]
struct ScriptedResumeInner {
    from: Option<ResumeFrom>,
    err: Option<Failure>,
    calls: u64,
}

impl ScriptedResume {
    pub(crate) fn new(from: Option<ResumeFrom>, err: Option<Failure>) -> Self {
        Self {
            inner: Mutex::new(ScriptedResumeInner {
                from,
                err,
                calls: 0,
            }),
        }
    }

    pub(crate) fn calls(&self) -> u64 {
        self.inner.lock().map(|g| g.calls).unwrap_or(0)
    }
}

impl ports::ResumeSource for ScriptedResume {
    fn resume_from<'a>(
        &'a self,
        _run: ClaimedRun,
    ) -> PortFuture<'a, Result<Option<ResumeFrom>, Failure>> {
        Box::pin(async move {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return Err(Failure::internal("poisoned", "resume lock poisoned")),
            };
            g.calls += 1;
            if let Some(e) = &g.err {
                return Err(Failure::internal(e.code(), e.message()));
            }
            Ok(g.from.clone())
        })
    }
}

/// `defaultTestConfig` — config with the `noResume` default source.
pub(crate) fn default_cfg() -> OrchestratorConfig {
    OrchestratorConfig::new(Arc::new(NoResume))
}

// ---------------------------------------------------------------------------
// world — the harness world for one orchestrator test
// ---------------------------------------------------------------------------

pub(crate) struct World {
    pub(crate) tr: Trace,
    pub(crate) life: Arc<Lifecycle>,
    pub(crate) st: Arc<FakeStore>,
    pub(crate) prov: Arc<Provisioner>,
    pub(crate) cap: Arc<Capturer>,
    pub(crate) arts: Arc<Artifacts>,
    pub(crate) sink: Arc<Sink>,
    pub(crate) ad: Arc<FakeAdapter>,
    pub(crate) ticker: Arc<dyn ports::Ticker>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) orch: Orchestrator,
    pub(crate) stop: Arc<ManualCancel>,
}

/// `newWorld` — defaults the adapter version, launch env and resume
/// source as upstream's does.
pub(crate) fn new_world(
    cfg: OrchestratorConfig,
    caps: Capabilities,
    scripts: Vec<Script>,
) -> World {
    new_world_with_sink(cfg, caps, scripts, false)
}

/// `newWorld` with `tracing` — `tracingSink`.
pub(crate) fn new_world_with_sink(
    mut cfg: OrchestratorConfig,
    caps: Capabilities,
    scripts: Vec<Script>,
    tracing: bool,
) -> World {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![queued_run()]));
    let st = FakeStore::new(&tr);
    let ticker: Arc<dyn ports::Ticker> = Arc::new(ports::RealTicker);
    let clock: Arc<dyn Clock> = Arc::new(RealClock);
    let prov = Arc::new(Provisioner::new(&tr, ticker.clone()));
    let cap = Arc::new(Capturer::new(&tr));
    let arts = Arc::new(Artifacts::new(&tr));
    let sink = Arc::new(Sink::new(&tr, tracing));
    let ad = Arc::new(FakeAdapter::new(&tr, "claude-code", caps, scripts));
    if cfg.adapter_version.is_empty() {
        cfg.adapter_version = "claudecode/3a".to_string();
    }
    if cfg.launch_env.is_empty() {
        cfg.launch_env = test_env();
    }
    cfg.events = Some(sink.clone());
    let orch = Orchestrator::new(OrchestratorDeps {
        lifecycle: life.clone(),
        attempts: st.clone(),
        adapter: ad.clone(),
        workspaces: prov.clone(),
        capture: cap.clone(),
        artifacts: arts.clone(),
        clock: clock.clone(),
        ticker: ticker.clone(),
        cfg,
    });
    let orch = orch.expect("NewOrchestrator");
    World {
        tr,
        life,
        st,
        prov,
        cap,
        arts,
        sink,
        ad,
        ticker,
        clock,
        orch,
        stop: Arc::new(ManualCancel::default()),
    }
}

impl World {
    /// `w.run(ctx)` — `orch.RunDispatchable(d, "2.1.283")` driven to
    /// completion on this thread.
    pub(crate) fn run(&self) -> HarnessResult {
        block_on(
            self.orch
                .run_dispatchable(self.life_run(), "2.1.283", &*self.stop),
        )
    }

    /// `orch.Run` over a custom lifecycle (`orchestratorOver`): build a
    /// new Orchestrator sharing w's fakes but `life`.
    pub(crate) fn orchestrator_over(
        &self,
        life: Arc<dyn ports::RunLifecycle>,
        mut cfg: OrchestratorConfig,
    ) -> Orchestrator {
        cfg.adapter_version = "claudecode/3a".to_string();
        cfg.launch_env = test_env();
        cfg.events = Some(self.sink.clone());
        Orchestrator::new(OrchestratorDeps {
            lifecycle: life,
            attempts: self.st.clone(),
            adapter: self.ad.clone(),
            workspaces: self.prov.clone(),
            capture: self.cap.clone(),
            artifacts: self.arts.clone(),
            clock: self.clock.clone(),
            ticker: self.ticker.clone(),
            cfg,
        })
        .expect("NewOrchestrator")
    }

    pub(crate) fn life_run(&self) -> DispatchableRun {
        self.life
            .inner
            .lock()
            .ok()
            .and_then(|g| g.runs.first().cloned())
            .unwrap_or_else(queued_run)
    }
}

/// `resumeFrom` — a resume source fixture.
pub(crate) fn resume_from(source: Attempt, prompt: &str, budget: Budget) -> ResumeFrom {
    ResumeFrom {
        source,
        budget,
        prompt: prompt.to_string(),
    }
}
