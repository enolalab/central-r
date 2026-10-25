//! The kernel's port of upstream `internal/adapter/schedulerharness`
//! (`brief.go`, `launcher.go`, `killer.go`, `registry.go`) merged with
//! `cmd/central/scheduler_harness_wiring.go` — the glue binding Phase-2
//! scheduler dispatch to real harness sessions (issue #111).
//!
//! Upstream ships the glue as an adapter package; in Rust it lives in
//! the kernel because no adapter crate may import two capabilities —
//! the launcher bridges `central_scheduler` (the `NodeLauncher` port),
//! `central_harness` (the `Adapter`/`ProcessLauncher` ports) and
//! `central_retry` (the `Killer` port). Scope ids are attempt uuids
//! (canonical, non-nil); both seams depend on the harness ports only.
//!
//! - [`SchedulerNodeLauncher`] implements
//!   [`central_scheduler::port::NodeLauncher`] over a harness
//!   [`Adapter`] — spec D2's outcome mapping.
//! - [`SchedulerKiller`] implements [`central_retry::port::Killer`]
//!   over a harness [`ProcessLauncher`] — spec D3.
//! - [`ScopeRegistry`] is the D3.0 launch-provenance record shared by
//!   the pair.
//! - [`interim_brief`] renders the fixed worker brief from durable
//!   node facts only (spec D4).
//! - [`compose_scheduler_harness`] / [`check_scheduler_launch_gate`]
//!   are the serve-composition seams (spec D6 / issue #120).

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{HarnessAttemptId, SessionAttemptId};
use central_harness::domain::{Fence, PermissionPolicy, Workspace};
use central_harness::port::{Adapter, LaunchEnv, Limits, ProcessLauncher, Session, StartSpec};
use central_retry::port::Killer;
use central_scheduler::port::{LaunchSpec, LaunchVerdict, NodeLauncher};

use crate::harness_compose::{ENV_HARNESS_ENABLED, HarnessConfig};
use crate::scheduler_compose::{ENV_SCHEDULER_ALLOW_STUB, SchedulerConfig};

const CODE_UNSUPPORTED_HARNESS: &str = "schedulerharness_unsupported_harness";
const CODE_MALFORMED_ENV: &str = "schedulerharness_malformed_env";
const CODE_ATTEMPT_ID: &str = "schedulerharness_attempt_id";
const CODE_PROMPT: &str = "schedulerharness_prompt";
const CODE_SCRATCH_ESCAPES: &str = "schedulerharness_scratch_escapes_root";
const CODE_LAUNCH_GATE: &str = "scheduler_launch_gate_unsatisfied";

// ---------------------------------------------------------------------------
// ScopeRegistry — the D3.0 launch-provenance record (upstream registry.go)
// ---------------------------------------------------------------------------

/// The set of scopes this process launched. A kill for a scope absent
/// here can never confirm — the scope is unobservable to this process
/// (post-restart or foreign), so its outcome is unknowable.
#[derive(Debug, Default)]
pub struct ScopeRegistry {
    launched: Mutex<HashSet<String>>,
}

impl ScopeRegistry {
    /// `NewScopeRegistry` — an empty registry. One registry is shared
    /// by the launcher/killer pair of a composition root.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `Record` — marks `scope` launched by this process.
    pub fn record(&self, scope: &str) {
        self.launched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(scope.to_string());
    }

    /// `Launched` — whether this process launched `scope`.
    #[must_use]
    pub fn launched(&self, scope: &str) -> bool {
        self.launched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(scope)
    }
}

// ---------------------------------------------------------------------------
// InterimBrief — the fixed worker brief (upstream brief.go)
// ---------------------------------------------------------------------------

/// `PromptSource` — resolves one launch prompt. It is an injected
/// function, not a domain port: prompt content is a composition
/// concern until instruction carriage exists (spec F1).
pub type PromptSource = Arc<dyn Fn(&LaunchSpec) -> Result<String, Failure> + Send + Sync>;

/// `InterimBrief` — renders the fixed worker brief from durable node
/// facts only (spec D4). It directs the agent to resolve its real
/// instructions from its declared input artifacts via
/// `central artifact read` and to do nothing outside its workspace.
/// It never fails on content: ids and paths are quoted verbatim,
/// never interpreted.
///
/// # Errors
/// Infallible today — the `Result` keeps the injected-source contract.
pub fn interim_brief(spec: &LaunchSpec) -> Result<String, Failure> {
    let mut scope = "";
    for kv in &spec.env {
        if let Some(v) = kv.strip_prefix("CENTRAL_ATTEMPT_SCOPE=") {
            scope = v;
        }
    }
    let attempt = &spec.attempt.attempt;
    Ok(format!(
        "Central Phase-2 worker brief (interim: instruction carriage not yet implemented).\n\n\
         Attempt: {} (seq {}). Scope: CENTRAL_ATTEMPT_SCOPE={}.\n\
         Workspace: {}. Harness: {}.\n\n\
         Resolve your real instructions from your declared input artifacts with\n\
         'central artifact read' (by id, or --from <producer_node_key> --name <name>,\n\
         releasing bytes to --out or --stdout) inside this workspace. Do all work\n\
         inside the workspace. Do not act outside it. Do not print secrets.",
        attempt.id, attempt.attempt_seq, scope, spec.workspace_path, spec.attempt.harness
    ))
}

// ---------------------------------------------------------------------------
// SchedulerNodeLauncher — NodeLauncher over a harness Adapter
// (upstream launcher.go)
// ---------------------------------------------------------------------------

/// `schedulerharness.Launcher` — [`NodeLauncher`] over a harness
/// [`Adapter`] (spec D2). Scope ids are attempt uuids; confirmed
/// success records the scope in the shared registry (D3.0 provenance)
/// and spawns the session drainer (D5).
pub struct SchedulerNodeLauncher {
    adapter: Arc<dyn Adapter>,
    proc: Arc<dyn ProcessLauncher>,
    scopes: Arc<ScopeRegistry>,
    prompt: PromptSource,
}

impl SchedulerNodeLauncher {
    /// `NewLauncher` — builds the launcher.
    pub fn new(
        adapter: Arc<dyn Adapter>,
        proc: Arc<dyn ProcessLauncher>,
        scopes: Arc<ScopeRegistry>,
        prompt: PromptSource,
    ) -> Self {
        Self {
            adapter,
            proc,
            scopes,
            prompt,
        }
    }

    /// `AdapterKind` — the harness kind this launcher's adapter serves.
    #[must_use]
    pub fn adapter_kind(&self) -> central_harness::domain::Kind {
        self.adapter.kind()
    }
}

impl NodeLauncher for SchedulerNodeLauncher {
    /// `Launch` — starts one real harness session for the claimed
    /// attempt. See spec D2 for the outcome mapping; `saw_live`
    /// (spec-review SR2) poisons any refusal into unconfirmed.
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
        // The attempt must name the composed adapter's own kind (spec
        // D2.0): a claude-code node never launches on an opencode
        // adapter or vice versa. Anything else is a confirmed
        // pre-start refusal.
        if spec.attempt.harness != self.adapter.kind().as_str() {
            return LaunchVerdict::Refused(Failure::denied(
                CODE_UNSUPPORTED_HARNESS,
                format!("unsupported harness: {:?}", spec.attempt.harness),
            ));
        }
        let prompt = match (self.prompt)(&spec) {
            Ok(p) => p,
            Err(f) => {
                return LaunchVerdict::Refused(Failure::invalid(
                    CODE_PROMPT,
                    format!("prompt: {}", f.message()),
                ));
            }
        };
        let mut vars = BTreeMap::new();
        for kv in &spec.env {
            let Some((name, value)) = kv.split_once('=') else {
                return LaunchVerdict::Refused(Failure::invalid(
                    CODE_MALFORMED_ENV,
                    format!("malformed env entry: {kv:?}"),
                ));
            };
            if name.is_empty() {
                return LaunchVerdict::Refused(Failure::invalid(
                    CODE_MALFORMED_ENV,
                    format!("malformed env entry: {kv:?}"),
                ));
            }
            vars.insert(name.to_string(), value.to_string());
        }
        let attempt_uuid = spec.attempt.attempt.id;
        let Ok(attempt) = HarnessAttemptId::parse(&attempt_uuid.to_string()) else {
            return LaunchVerdict::Refused(Failure::invalid(
                CODE_ATTEMPT_ID,
                "attempt id: not a canonical id",
            ));
        };
        let scope = attempt_uuid.to_string();
        let mut saw_live = false;
        let alive = match self.proc.is_alive(&scope).await {
            Err(_) => return LaunchVerdict::Unknown, // "scope guard"
            Ok(alive) => alive,
        };
        if alive {
            saw_live = true;
            if self.proc.kill_scope(&scope).await.is_err() {
                return LaunchVerdict::Unknown; // "reap orphan scope"
            }
            match self.proc.is_alive(&scope).await {
                Err(_) => return LaunchVerdict::Unknown, // "scope recheck"
                Ok(true) => {
                    return LaunchVerdict::Unknown; // errScopeBusy — unconfirmed
                }
                Ok(false) => {}
            }
        }
        match self
            .adapter
            .start(StartSpec {
                attempt,
                fence: Fence { generation: 1 },
                workspace: Workspace {
                    path: spec.workspace_path.clone(),
                    base_sha: String::new(),
                },
                prompt,
                model: String::new(),
                permission: PermissionPolicy::Deny,
                limits: Limits::default(),
                env: LaunchEnv {
                    vars,
                    sandbox_scope_id: scope.clone(),
                },
            })
            .await
        {
            Err(err) => {
                // A cancelled start reads unconfirmed — the Rust shape
                // of upstream's `ctx.Err()` arm (the future-drop half
                // already lands here when the adapter sees the drop).
                if err.kind() == FailureKind::Cancelled {
                    return LaunchVerdict::Unknown;
                }
                // Fail closed (SR2): an adapter that errors after a
                // partial exec must not read as "nothing ran".
                if self.proc.kill_scope(&scope).await.is_err() {
                    return LaunchVerdict::Unknown; // "post-error kill"
                }
                match self.proc.is_alive(&scope).await {
                    Err(_) => LaunchVerdict::Unknown, // "post-error recheck"
                    Ok(alive) if alive || saw_live => LaunchVerdict::Unknown,
                    Ok(_) => LaunchVerdict::Refused(err),
                }
            }
            Ok(session) => {
                self.scopes.record(&scope);
                tokio::spawn(drain_session(session, scope.clone()));
                LaunchVerdict::Started(attempt.to_string())
            }
        }
    }
}

/// `drainSession` — owns one confirmed session's delivery contract
/// (spec D5): drain events to close, then `wait`, then log the bounded
/// terminal. It never writes durable state; outcome collection is
/// spec F2.
async fn drain_session(session: Box<dyn Session>, scope: String) {
    while session.next_event().await.is_some() {}
    match session.wait().await {
        Err(err) => {
            tracing::warn!(
                scope = scope.as_str(),
                code = err.code(),
                "schedulerharness: session wait failed"
            );
        }
        Ok(terminal) => {
            tracing::info!(
                scope = scope.as_str(),
                terminal = ?terminal,
                "schedulerharness: session ended"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SchedulerKiller — retry Killer over a ProcessLauncher
// (upstream killer.go)
// ---------------------------------------------------------------------------

/// `schedulerharness.Killer` — implements
/// [`central_retry::port::Killer`] over a harness [`ProcessLauncher`]
/// (spec D3): `kill_scope`, then `is_alive` to confirm. A scope this
/// process never launched (D3.0) is reaped best-effort and reported
/// unconfirmed without consulting `is_alive`. Infrastructure errors
/// propagate so the sweep pass aborts and retries next tick.
pub struct SchedulerKiller {
    proc: Arc<dyn ProcessLauncher>,
    scopes: Arc<ScopeRegistry>,
}

impl SchedulerKiller {
    /// `NewKiller`.
    #[must_use]
    pub fn new(proc: Arc<dyn ProcessLauncher>, scopes: Arc<ScopeRegistry>) -> Self {
        Self { proc, scopes }
    }
}

impl Killer for SchedulerKiller {
    /// `Kill` — terminates the attempt's scope and reports whether the
    /// kill is KNOWN to have taken effect. Single-serve assumption
    /// (plan-review PR3): attempt ids are Central-generated and claims
    /// atomic, so no split-brain peer can own this scope.
    async fn kill(&self, attempt_id: SessionAttemptId) -> Result<bool, Failure> {
        let scope = attempt_id.to_string();
        if !self.scopes.launched(&scope) {
            // Unobservable scope: reap best-effort, never confirm.
            let _ = self.proc.kill_scope(&scope).await;
            return Ok(false);
        }
        self.proc
            .kill_scope(&scope)
            .await
            .map_err(|f| Failure::unavailable("schedulerharness_kill_scope", f.message()))?;
        let alive = self
            .proc
            .is_alive(&scope)
            .await
            .map_err(|f| Failure::unavailable("schedulerharness_scope_recheck", f.message()))?;
        Ok(!alive)
    }
}

// ---------------------------------------------------------------------------
// Composition seams — upstream scheduler_harness_wiring.go
// ---------------------------------------------------------------------------

/// `composeSchedulerHarness` — builds the production scheduler seams
/// (spec D6): its own launcher + adapter pair via the same factory +
/// config the Phase-1 harness chain uses. No instance is shared with
/// the Phase-1 path.
///
/// The scheduler scratch root must lie beneath (or equal) the harness
/// worktree root, because the host launcher refuses any workdir
/// outside it; otherwise composition refuses and serve must not start.
///
/// Upstream wires `newHarnessHostLauncher` unconditionally here — the
/// scheduler dispatch path never routes through the localexec dev gate.
///
/// # Errors
/// Propagates the launcher/adapter construction failures; returns a
/// `Denied` failure when the scratch root escapes the worktree root.
pub fn compose_scheduler_harness(
    hc: &HarnessConfig,
    sc: &SchedulerConfig,
) -> Result<(SchedulerNodeLauncher, SchedulerKiller), Failure> {
    // Upstream `filepath.Clean`s both sides before the prefix test:
    // collect the components back so `.` segments and doubled or
    // trailing separators cannot slip the containment check.
    let root = hc
        .worktree_root()
        .components()
        .collect::<std::path::PathBuf>();
    let scratch = std::path::Path::new(&sc.scratch_root)
        .components()
        .collect::<std::path::PathBuf>();
    if scratch != root && !scratch.starts_with(&root) {
        return Err(Failure::denied(
            CODE_SCRATCH_ESCAPES,
            format!(
                "scheduler harness wiring: scratch root {} escapes the harness worktree root {}",
                sc.scratch_root,
                root.display()
            ),
        ));
    }
    let proc = crate::harness_compose::build_host_launcher(
        hc,
        Arc::new(central_adapter_linux::launcher_client::SocketLauncherClient::new()),
    )?;
    let adapter = crate::harness_compose::build_adapter(hc, proc.clone())?;
    let scopes = Arc::new(ScopeRegistry::new());
    let launcher = SchedulerNodeLauncher::new(
        adapter,
        proc.clone(),
        scopes.clone(),
        Arc::new(interim_brief) as PromptSource,
    );
    let killer = SchedulerKiller::new(proc, scopes);
    Ok((launcher, killer))
}

/// `checkSchedulerLaunchGate` — the serve-path seam decision (issue
/// #120, spec D2): harness execution on proceeds to the real launcher
/// pair, harness off with the explicit stub dev gate proceeds to stub
/// dispatch, and harness off without it refuses so serve never
/// silently runs stub dispatch as a default. The caller reports the
/// returned error as `CONFIG_INVALID`.
///
/// # Errors
/// `Denied` when harness execution is off and the stub dev gate is
/// unset; the message names both env switches verbatim (upstream
/// asserts on them).
pub fn check_scheduler_launch_gate(
    hc: &HarnessConfig,
    sc: &SchedulerConfig,
) -> Result<(), Failure> {
    if hc.enabled || sc.allow_stub {
        return Ok(());
    }
    Err(Failure::denied(
        CODE_LAUNCH_GATE,
        format!(
            "scheduler requires harness execution ({ENV_HARNESS_ENABLED}=1) or the explicit \
             stub dev gate ({ENV_SCHEDULER_ALLOW_STUB}=1)"
        ),
    ))
}

// ---------------------------------------------------------------------------
// Tests — the port of upstream schedulerharness_test.go +
// scheduler_harness_wiring_test.go. The fakes keep every observable
// counter in shared Arc state so assertions run after the launcher
// owns its `Arc<dyn ...>` handles.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use central_foundation::identity::{NodeLeaseId, RunId, WorkerId, WorkflowNodeId, WorkspaceId};
    use central_harness::capability::Capabilities;
    use central_harness::domain::{Kind, Terminal, TerminalStatus};
    use central_harness::event::Event;
    use central_harness::port::{
        ExitStatus, OperatorInput, PermissionDecision, PortFuture, ProbeResult, Process,
        ProcessSpec, ReconcileInput, ReconcileResult, SessionRef,
    };
    use central_scheduler::domain::{AttemptState, ClaimedAttempt, Lease, SessionAttempt};
    use time::OffsetDateTime;

    use crate::harness_compose::Backend;
    use crate::scheduler_compose::{
        ENV_SCHEDULER_ALLOW_STUB, ENV_SCHEDULER_ENABLED, ENV_SCHEDULER_SCRATCH,
    };

    fn test_attempt(harness: &str) -> (SessionAttemptId, ClaimedAttempt) {
        let attempt_id = SessionAttemptId::new();
        let run_id = RunId::new();
        let node_id = WorkflowNodeId::new();
        let attempt = ClaimedAttempt {
            attempt: SessionAttempt {
                id: attempt_id,
                workspace_id: WorkspaceId::new(),
                run_id,
                node_id,
                attempt_seq: 1,
                worker_id: None,
                harness_attempt_id: None,
                workspace_path: None,
                workspace_kind: "directory".to_string(),
                state: AttemptState::Claimed,
                dispatch_reason_code: None,
                reservation_id: None,
                harness_session_id: None,
                claimed_at: OffsetDateTime::now_utc(),
                started_at: None,
                ended_at: None,
            },
            lease: Lease {
                id: NodeLeaseId::new(),
                node_id,
                attempt_id,
                worker_id: WorkerId::new(),
                issued_at: OffsetDateTime::now_utc(),
                last_heartbeat_at: OffsetDateTime::now_utc(),
                expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
                heartbeat_interval_sec: 15,
                released_at: None,
            },
            harness: harness.to_string(),
        };
        (attempt_id, attempt)
    }

    /// `testLaunchSpec` — one claimed attempt's launch spec.
    fn test_launch_spec(harness: &str) -> LaunchSpec {
        let (attempt_id, attempt) = test_attempt(harness);
        let scope_env = format!(
            "CENTRAL_ATTEMPT_SCOPE={}:{}:{attempt_id}",
            attempt.attempt.run_id, attempt.attempt.node_id
        );
        LaunchSpec {
            attempt,
            workspace_path: "/scratch/w".to_string(),
            env: vec![scope_env],
        }
    }

    fn ok_prompt() -> PromptSource {
        Arc::new(|_spec| Ok("brief".to_string()))
    }

    // -- scriptAdapter ---------------------------------------------------

    type OnStart = Box<dyn Fn(&StartSpec) + Send>;

    struct ScriptAdapter {
        kind: StdMutex<String>,
        start_err: StdMutex<Option<Failure>>,
        starts: Arc<AtomicUsize>,
        on_start: StdMutex<Option<OnStart>>,
    }

    impl ScriptAdapter {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                kind: StdMutex::new(String::new()),
                start_err: StdMutex::new(None),
                starts: Arc::new(AtomicUsize::new(0)),
                on_start: StdMutex::new(None),
            })
        }
    }

    impl Adapter for ScriptAdapter {
        fn kind(&self) -> Kind {
            let kind = self.kind.lock().unwrap();
            if kind.is_empty() {
                Kind::new("claude-code")
            } else {
                Kind::new(kind.clone())
            }
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
        }

        fn env_extras(&self) -> &[String] {
            &[]
        }

        fn probe<'a>(&'a self, _env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>> {
            Box::pin(async { Ok(ProbeResult::default()) })
        }

        fn start<'a>(
            &'a self,
            spec: StartSpec,
        ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            if let Some(on_start) = self.on_start.lock().unwrap().as_ref() {
                on_start(&spec);
            }
            if let Some(err) = self.start_err.lock().unwrap().clone() {
                return Box::pin(async move { Err(err) });
            }
            let session = Box::new(ScriptSession {
                session_ref: SessionRef {
                    harness_session_id: spec.attempt.to_string(),
                },
                ref_delivered: AtomicBool::new(false),
            });
            Box::pin(async move { Ok(session as Box<dyn Session>) })
        }

        fn resume<'a>(
            &'a self,
            _session_ref: SessionRef,
            spec: StartSpec,
        ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
            self.start(spec)
        }

        fn reconcile<'a>(
            &'a self,
            _input: ReconcileInput,
        ) -> PortFuture<'a, Result<ReconcileResult, Failure>> {
            Box::pin(async {
                Ok(ReconcileResult {
                    scope_alive: false,
                    reattached: None,
                    terminal: None,
                })
            })
        }
    }

    /// `scriptSession` — a closed session: `session_ref` delivers once,
    /// `next_event` is closed, `wait` reports a clean terminal.
    struct ScriptSession {
        session_ref: SessionRef,
        ref_delivered: AtomicBool,
    }

    impl Session for ScriptSession {
        fn session_ref(&self) -> PortFuture<'_, Option<SessionRef>> {
            let deliver = !self.ref_delivered.swap(true, Ordering::SeqCst);
            let session_ref = self.session_ref.clone();
            Box::pin(async move { if deliver { Some(session_ref) } else { None } })
        }

        fn next_event(&self) -> PortFuture<'_, Option<Event>> {
            Box::pin(async { None })
        }

        fn send<'a>(&'a self, _input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }

        fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }

        fn respond_permission<'a>(
            &'a self,
            _decision: PermissionDecision,
        ) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }

        fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>> {
            Box::pin(async {
                Ok(Terminal {
                    status: TerminalStatus::Succeeded,
                    reason: String::new(),
                    exit_code: Some(0),
                })
            })
        }

        fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// `scriptProcLauncher` — scripts `is_alive`/`kill_scope` per scope.
    #[derive(Default)]
    struct ScriptProcLauncher {
        alive: Arc<StdMutex<BTreeMap<String, bool>>>,
        alive_err: Arc<StdMutex<BTreeMap<String, Failure>>>,
        kill_err: Arc<StdMutex<BTreeMap<String, Failure>>>,
        killed: Arc<StdMutex<Vec<String>>>,
        /// `kill_scope` leaves these alive.
        stuck_live: Arc<StdMutex<BTreeMap<String, bool>>>,
    }

    impl ProcessLauncher for ScriptProcLauncher {
        fn launch<'a>(
            &'a self,
            _spec: ProcessSpec,
        ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
            Box::pin(async { Err(Failure::internal("script", "not scripted")) })
        }

        fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
            let err = self.alive_err.lock().unwrap().get(scope_id).cloned();
            let alive = self
                .alive
                .lock()
                .unwrap()
                .get(scope_id)
                .copied()
                .unwrap_or(false);
            Box::pin(async move {
                match err {
                    Some(e) => Err(e),
                    None => Ok(alive),
                }
            })
        }

        fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
            self.killed.lock().unwrap().push(scope_id.to_string());
            let err = self.kill_err.lock().unwrap().get(scope_id).cloned();
            let stuck = self
                .stuck_live
                .lock()
                .unwrap()
                .get(scope_id)
                .copied()
                .unwrap_or(false);
            if err.is_none() && !stuck {
                self.alive
                    .lock()
                    .unwrap()
                    .insert(scope_id.to_string(), false);
            }
            Box::pin(async move {
                match err {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            })
        }
    }

    // -- ScopeRegistry (upstream TestScopeRegistryRoundTrip) --------------

    #[test]
    fn scope_registry_round_trip() {
        let registry = ScopeRegistry::new();
        assert!(!registry.launched("scope-a"));
        registry.record("scope-a");
        assert!(registry.launched("scope-a"));
        assert!(!registry.launched("scope-b"));
    }

    // -- InterimBrief (upstream TestInterimBriefCarriesDurableFacts) ------

    #[test]
    fn interim_brief_carries_durable_facts() {
        let spec = test_launch_spec("claude-code");
        let attempt = &spec.attempt.attempt;
        let brief = interim_brief(&spec).expect("brief");
        for want in [
            attempt.run_id.to_string(),
            attempt.node_id.to_string(),
            attempt.id.to_string(),
            "/scratch/w".to_string(),
            "central artifact read".to_string(),
            "CENTRAL_ATTEMPT_SCOPE".to_string(),
        ] {
            assert!(brief.contains(&want), "brief missing {want:?}:\n{brief}");
        }
    }

    // -- Launch table (upstream TestLaunchTable) ---------------------------

    type Mutate =
        Box<dyn Fn(&mut LaunchSpec, &ScriptAdapter, &ScriptProcLauncher, &mut PromptSource) + Send>;

    struct LaunchCase {
        name: &'static str,
        mutate: Mutate,
        want_session: bool,
        want_ok: bool,
        want_err: bool,
        want_starts: usize,
    }

    #[tokio::test(flavor = "current_thread")]
    async fn launch_table() {
        let cases: Vec<LaunchCase> = vec![
            LaunchCase {
                name: "success",
                mutate: Box::new(|_, _, _, _| {}),
                want_session: true,
                want_ok: true,
                want_err: false,
                want_starts: 1,
            },
            LaunchCase {
                name: "wrong harness",
                mutate: Box::new(|spec, _, _, _| spec.attempt.harness = "opencode".into()),
                want_session: false,
                want_ok: true,
                want_err: true,
                want_starts: 0,
            },
            LaunchCase {
                // The gate follows the composed adapter's own kind: a
                // claude-code node on an opencode adapter refuses, and
                // an opencode node on it launches.
                name: "harness must match the composed adapter",
                mutate: Box::new(|spec, a, _, _| {
                    *a.kind.lock().unwrap() = "opencode".into();
                    spec.attempt.harness = "claude-code".into();
                }),
                want_session: false,
                want_ok: true,
                want_err: true,
                want_starts: 0,
            },
            LaunchCase {
                name: "opencode adapter launches opencode nodes",
                mutate: Box::new(|spec, a, _, _| {
                    *a.kind.lock().unwrap() = "opencode".into();
                    spec.attempt.harness = "opencode".into();
                }),
                want_session: true,
                want_ok: true,
                want_err: false,
                want_starts: 1,
            },
            LaunchCase {
                name: "prompt error",
                mutate: Box::new(|_, _, _, prompt| {
                    *prompt = Arc::new(|_| Err(Failure::internal("script", "no prompt")));
                }),
                want_session: false,
                want_ok: true,
                want_err: true,
                want_starts: 0,
            },
            LaunchCase {
                name: "malformed env",
                mutate: Box::new(|spec, _, _, _| spec.env = vec!["NOEQUALS".into()]),
                want_session: false,
                want_ok: true,
                want_err: true,
                want_starts: 0,
            },
            LaunchCase {
                name: "start refused",
                mutate: Box::new(|_, a, _, _| {
                    *a.start_err.lock().unwrap() = Some(Failure::internal("script", "refused"));
                }),
                want_session: false,
                want_ok: true,
                want_err: true,
                want_starts: 1,
            },
            LaunchCase {
                name: "ctx cancelled",
                mutate: Box::new(|_, a, _, _| {
                    *a.start_err.lock().unwrap() = Some(Failure::cancelled("script", "cancelled"));
                }),
                want_session: false,
                want_ok: false,
                want_err: true,
                want_starts: 1,
            },
            LaunchCase {
                name: "orphan reaped",
                mutate: Box::new(|spec, _, p, _| {
                    p.alive
                        .lock()
                        .unwrap()
                        .insert(spec.attempt.attempt.id.to_string(), true);
                }),
                want_session: true,
                want_ok: true,
                want_err: false,
                want_starts: 1,
            },
            LaunchCase {
                name: "orphan stuck",
                mutate: Box::new(|spec, _, p, _| {
                    let scope = spec.attempt.attempt.id.to_string();
                    p.alive.lock().unwrap().insert(scope.clone(), true);
                    p.stuck_live.lock().unwrap().insert(scope, true);
                }),
                want_session: false,
                want_ok: false,
                want_err: true,
                want_starts: 0,
            },
            LaunchCase {
                name: "guard alive errors",
                mutate: Box::new(|spec, _, p, _| {
                    p.alive_err.lock().unwrap().insert(
                        spec.attempt.attempt.id.to_string(),
                        Failure::unavailable("script", "daemon down"),
                    );
                }),
                want_session: false,
                want_ok: false,
                want_err: true,
                want_starts: 0,
            },
            LaunchCase {
                // Guard passes clean; the failed Start leaves a live
                // scope behind (partial exec) that even the post-error
                // kill cannot reap. Must read unconfirmed, never
                // refused.
                name: "post-error scope alive",
                mutate: Box::new(|spec, a, p, _| {
                    *a.start_err.lock().unwrap() = Some(Failure::internal("script", "refused"));
                    let scope = spec.attempt.attempt.id.to_string();
                    let alive = p.alive.clone();
                    let stuck = p.stuck_live.clone();
                    *a.on_start.lock().unwrap() = Some(Box::new(move |_| {
                        alive.lock().unwrap().insert(scope.clone(), true);
                        stuck.lock().unwrap().insert(scope.clone(), true);
                    }));
                }),
                want_session: false,
                want_ok: false,
                want_err: true,
                want_starts: 1,
            },
            LaunchCase {
                name: "post-error scope dead still poisons",
                mutate: Box::new(|spec, a, p, _| {
                    *a.start_err.lock().unwrap() = Some(Failure::internal("script", "refused"));
                    p.alive
                        .lock()
                        .unwrap()
                        .insert(spec.attempt.attempt.id.to_string(), true);
                }),
                want_session: false,
                want_ok: false,
                want_err: true,
                want_starts: 1,
            },
        ];
        for case in cases {
            let mut spec = test_launch_spec("claude-code");
            let adapter = ScriptAdapter::new();
            let proc = Arc::new(ScriptProcLauncher::default());
            let mut prompt = ok_prompt();
            (case.mutate)(&mut spec, &adapter, &proc, &mut prompt);
            let scopes = Arc::new(ScopeRegistry::new());
            let starts = adapter.starts.clone();
            let launcher = SchedulerNodeLauncher::new(
                adapter as Arc<dyn Adapter>,
                proc as Arc<dyn ProcessLauncher>,
                scopes.clone(),
                prompt,
            );
            let attempt_id = spec.attempt.attempt.id.to_string();
            let verdict = launcher.launch(spec).await;
            match (&verdict, case.want_ok, case.want_err) {
                (LaunchVerdict::Started(id), true, false) => {
                    assert_eq!(
                        *id, attempt_id,
                        "{}: session = {id}, want attempt id",
                        case.name
                    );
                    assert!(
                        case.want_session,
                        "{}: unexpected session verdict",
                        case.name
                    );
                }
                (LaunchVerdict::Refused(_), true, true) => {}
                (LaunchVerdict::Unknown, false, _) => {}
                other => unreachable!(
                    "{}: got {other:?}, want confirmed={} err={}",
                    case.name, case.want_ok, case.want_err
                ),
            }
            assert_eq!(
                starts.load(Ordering::SeqCst),
                case.want_starts,
                "{}: adapter starts",
                case.name
            );
            if case.want_ok && !case.want_err {
                assert!(
                    scopes.launched(&attempt_id),
                    "{}: confirmed launch did not record the scope",
                    case.name
                );
            }
            // The session drainer settles promptly on the closed fake
            // session; the drain task itself is leak-free either way.
            tokio::task::yield_now().await;
        }
    }

    // -- Killer table (upstream TestKillerTable) ---------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn killer_table() {
        let launched = SessionAttemptId::new();
        let foreign = SessionAttemptId::new();
        struct KillerCase {
            name: &'static str,
            scope: SessionAttemptId,
            alive: bool,
            kill_err: bool,
            alive_err: bool,
            want_ok: bool,
            want_err: bool,
            want_kills: usize,
        }
        let cases = vec![
            KillerCase {
                name: "confirmed",
                scope: launched,
                alive: true,
                kill_err: false,
                alive_err: false,
                want_ok: true,
                want_err: false,
                want_kills: 1,
            },
            KillerCase {
                name: "already dead",
                scope: launched,
                alive: false,
                kill_err: false,
                alive_err: false,
                want_ok: true,
                want_err: false,
                want_kills: 1,
            },
            KillerCase {
                name: "stuck alive",
                scope: launched,
                alive: true,
                kill_err: false,
                alive_err: false,
                want_ok: false,
                want_err: false,
                want_kills: 1,
            },
            KillerCase {
                name: "kill error propagates",
                scope: launched,
                alive: false,
                kill_err: true,
                alive_err: false,
                want_ok: false,
                want_err: true,
                want_kills: 1,
            },
            KillerCase {
                name: "alive error propagates",
                scope: launched,
                alive: false,
                kill_err: false,
                alive_err: true,
                want_ok: false,
                want_err: true,
                want_kills: 1,
            },
            KillerCase {
                name: "foreign scope never confirms",
                scope: foreign,
                alive: false,
                kill_err: false,
                alive_err: false,
                want_ok: false,
                want_err: false,
                want_kills: 1,
            },
            KillerCase {
                name: "foreign scope kill error ignored",
                scope: foreign,
                alive: false,
                kill_err: true,
                alive_err: false,
                want_ok: false,
                want_err: false,
                want_kills: 1,
            },
        ];
        for case in cases {
            let proc = ScriptProcLauncher::default();
            if case.alive {
                proc.alive
                    .lock()
                    .unwrap()
                    .insert(case.scope.to_string(), true);
            }
            if case.kill_err {
                proc.kill_err.lock().unwrap().insert(
                    case.scope.to_string(),
                    Failure::unavailable("script", "daemon down"),
                );
            }
            if case.alive_err {
                proc.alive_err.lock().unwrap().insert(
                    case.scope.to_string(),
                    Failure::unavailable("script", "daemon down"),
                );
            }
            if case.name == "stuck alive" {
                proc.stuck_live
                    .lock()
                    .unwrap()
                    .insert(launched.to_string(), true);
            }
            let killed = proc.killed.clone();
            let proc = Arc::new(proc);
            let scopes = Arc::new(ScopeRegistry::new());
            scopes.record(&launched.to_string());
            let killer = SchedulerKiller::new(proc, scopes);
            let outcome = killer.kill(case.scope).await;
            match (&outcome, case.want_ok, case.want_err) {
                (Ok(true), true, false) => {}
                (Ok(false), false, false) => {}
                (Err(_), false, true) => {}
                (Ok(v), _, _) => unreachable!(
                    "{}: got Ok({v}), want confirmed={} err={}",
                    case.name, case.want_ok, case.want_err
                ),
                (Err(e), _, _) => unreachable!(
                    "{}: got Err({e}), want confirmed={} err={}",
                    case.name, case.want_ok, case.want_err
                ),
            }
            assert_eq!(
                killed.lock().unwrap().len(),
                case.want_kills,
                "{}: kill_scope calls",
                case.name
            );
        }
    }

    // -- Composition wiring (upstream scheduler_harness_wiring_test.go) ---

    fn wiring_harness(backend: Backend) -> HarnessConfig {
        HarnessConfig {
            enabled: true,
            data_root: std::path::PathBuf::from("/var/lib/central-harness"),
            backend,
            ..HarnessConfig::default()
        }
    }

    /// `TestComposeSchedulerHarnessContainment` — scratch beneath the
    /// worktree root composes (no daemon dial — the socket client is
    /// lazy); escaping refuses; equal accepts.
    #[cfg(target_os = "linux")]
    #[test]
    fn compose_scheduler_harness_containment() {
        let hc = wiring_harness(Backend::ClaudeCode);
        let contained = SchedulerConfig {
            enabled: true,
            scratch_root: "/var/lib/central-harness/worktrees/ph2".to_string(),
            ..SchedulerConfig::default()
        };
        let (_launcher, _killer) =
            compose_scheduler_harness(&hc, &contained).expect("contained scratch refused");

        let escaping = SchedulerConfig {
            enabled: true,
            scratch_root: "/tmp/ph2-scratch".to_string(),
            ..SchedulerConfig::default()
        };
        assert!(
            compose_scheduler_harness(&hc, &escaping).is_err(),
            "escaping scratch accepted"
        );

        // Scratch equal to the worktree root: accepted (workspaces/
        // lands beneath).
        let equal = SchedulerConfig {
            enabled: true,
            scratch_root: "/var/lib/central-harness/worktrees".to_string(),
            ..SchedulerConfig::default()
        };
        compose_scheduler_harness(&hc, &equal).expect("equal scratch refused");
    }

    /// `TestComposeSchedulerHarnessSelectsTheBackend` — every shipped
    /// backend selects its adapter kind.
    #[cfg(target_os = "linux")]
    #[test]
    fn compose_scheduler_harness_selects_the_backend() {
        for (backend, want_kind) in [
            (Backend::ClaudeCode, "claude-code"),
            (Backend::Opencode, "opencode"),
            (Backend::Codex, "codex"),
            (Backend::Antigravity, "antigravity"),
        ] {
            let hc = wiring_harness(backend);
            let sc = SchedulerConfig {
                enabled: true,
                scratch_root: "/var/lib/central-harness/worktrees/ph2".to_string(),
                ..SchedulerConfig::default()
            };
            let (launcher, _killer) = compose_scheduler_harness(&hc, &sc)
                .unwrap_or_else(|f| unreachable!("backend {want_kind}: {f}"));
            assert_eq!(launcher.adapter_kind().as_str(), want_kind);
        }
    }

    /// `TestCheckSchedulerLaunchGate` — harness on proceeds, harness
    /// off needs the explicit stub gate, and the refusal names both env
    /// switches verbatim.
    #[test]
    fn check_scheduler_launch_gate_table() {
        for (harness_enabled, allow_stub, want_err) in [
            (true, false, false),
            (true, true, false),
            (false, true, false),
            (false, false, true),
        ] {
            let hc = HarnessConfig {
                enabled: harness_enabled,
                ..HarnessConfig::default()
            };
            let sc = SchedulerConfig {
                enabled: true,
                allow_stub,
                ..SchedulerConfig::default()
            };
            let outcome = check_scheduler_launch_gate(&hc, &sc);
            match (outcome, want_err) {
                (Ok(()), false) => {}
                (Err(f), true) => {
                    for want in [
                        "scheduler requires harness execution",
                        "CENTRAL_HARNESS_ENABLED",
                        "CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB",
                    ] {
                        assert!(
                            f.message().contains(want),
                            "refusal {:?} does not mention {want:?}",
                            f.message()
                        );
                    }
                }
                (Ok(()), true) => unreachable!("expected a refusal"),
                (Err(f), false) => unreachable!("unexpected refusal: {f}"),
            }
        }
        // The const names stay in lock-step with upstream's asserts.
        assert_eq!(
            ENV_SCHEDULER_ALLOW_STUB,
            "CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB"
        );
        assert_eq!(ENV_SCHEDULER_ENABLED, "CENTRAL_PHASE2_SCHEDULER");
        assert_eq!(
            ENV_SCHEDULER_SCRATCH,
            "CENTRAL_PHASE2_SCHEDULER_SCRATCH_ROOT"
        );
        let _ = Backend::ClaudeCode;
        let _ = ExitStatus::default;
    }
}
