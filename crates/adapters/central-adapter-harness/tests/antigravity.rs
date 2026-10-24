//! `adapter_test.go` + `probe_test.go` + `session_test.go` + the
//! identity half of `antigravity_test.go` — the scripted fake-harness
//! tests over the verbatim `testdata/` fixtures. A `ScriptedLauncher`
//! answers the `--version` probe with fixed output and hands every
//! session launch to a scripted in-memory `Process`; the play helpers
//! read the prompt user event, then replay fixture bytes exactly as
//! upstream's `scriptedSession` does.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use central_adapter_harness::antigravity::{self, Antigravity, Config};
use central_foundation::failure::Failure;
use central_foundation::identity::HarnessAttemptId;
use central_harness::domain::{Fence, PermissionPolicy, Terminal, TerminalStatus, Workspace};
use central_harness::event::{Event, EventPayload, ToolStatus, UsageScope};
use central_harness::port::{
    Adapter as _, ExitStatus, LaunchEnv, OperatorInput, PermissionDecision, PortFuture, Process,
    ProcessLauncher, ProcessSpec, ReconcileInput, Session, SessionRef, StartSpec,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/antigravity")
        .join(name);
    std::fs::read(p).unwrap()
}

fn start_spec(workdir: &str) -> StartSpec {
    StartSpec {
        attempt: HarnessAttemptId::new(),
        fence: Fence { generation: 1 },
        workspace: Workspace {
            path: workdir.to_string(),
            base_sha: "abc123".to_string(),
        },
        prompt: "marker-prompt- Run the Bash command: echo probe".to_string(),
        model: String::new(),
        permission: PermissionPolicy::Deny,
        limits: Default::default(),
        env: probe_env(),
    }
}

fn probe_env() -> LaunchEnv {
    LaunchEnv {
        vars: [
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]
        .into_iter()
        .collect(),
        sandbox_scope_id: "probe-scope".to_string(),
    }
}

static TMPDIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// `t.TempDir()` — a fresh empty directory per call.
fn tmpdir() -> String {
    let dir = std::env::temp_dir().join(format!(
        "central-antigravity-test-{}-{}",
        std::process::id(),
        TMPDIR_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

// =====================================================================
// session_test.go — the in-memory port.Process and scripted launcher
// =====================================================================

fn io_closed() -> Failure {
    Failure::new(
        central_foundation::failure::FailureKind::Internal,
        "E_IO",
        "stdin closed",
    )
}

/// `scriptedProcess` — an in-memory `port.Process` modeling upstream's
/// `io.Pipe` pair. A `write_stdin` pends until the script attaches a
/// reader or stdin dies; when `stdin_hold` is armed a write also pends
/// after recording until `release_writes` — the io.Pipe blocking that
/// keeps a follow-up `Send` "in the pipeline" while a result lands.
struct ScriptedProcess {
    scope: String,
    stdin_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdin_rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    stdin_attached: AtomicBool,
    stdin_dead: AtomicBool,
    stdin_closed: AtomicBool,
    stdin_gate: Notify,
    /// Arm/disarm per-write holds.
    stdin_hold: AtomicBool,
    stdin_release: Notify,
    stdin_got: Mutex<Vec<u8>>,
    stdout_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdout_rx: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    stdout_left: Mutex<(Vec<u8>, usize)>,
    stderr: Mutex<Vec<u8>>,
    exited: Notify,
    status: Mutex<Option<ExitStatus>>,
    kills: AtomicUsize,
}

impl ScriptedProcess {
    fn new(scope: &str) -> Arc<Self> {
        let (stdin_tx, stdin_rx) = mpsc::unbounded_channel();
        let (stdout_tx, stdout_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            scope: scope.to_string(),
            stdin_tx: Mutex::new(Some(stdin_tx)),
            stdin_rx: Mutex::new(Some(stdin_rx)),
            stdin_attached: AtomicBool::new(false),
            stdin_dead: AtomicBool::new(false),
            stdin_closed: AtomicBool::new(false),
            stdin_gate: Notify::new(),
            stdin_hold: AtomicBool::new(false),
            stdin_release: Notify::new(),
            stdin_got: Mutex::new(Vec::new()),
            stdout_tx: Mutex::new(Some(stdout_tx)),
            stdout_rx: AsyncMutex::new(stdout_rx),
            stdout_left: Mutex::new((Vec::new(), 0)),
            stderr: Mutex::new(b"account details never mapped to reason\n".to_vec()),
            exited: Notify::new(),
            status: Mutex::new(None),
            kills: AtomicUsize::new(0),
        })
    }

    fn take_stdin_rx(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        self.stdin_attached.store(true, Ordering::SeqCst);
        self.stdin_gate.notify_waiters();
        self.stdin_rx.lock().unwrap().take().expect("stdin rx once")
    }

    fn stdin_written(&self) -> Vec<u8> {
        self.stdin_got.lock().unwrap().clone()
    }

    /// Arm the next write to pend until `release_writes`.
    fn arm_hold(&self) {
        self.stdin_hold.store(true, Ordering::SeqCst);
    }

    /// Let every pended and future write complete.
    fn release_writes(&self) {
        self.stdin_hold.store(false, Ordering::SeqCst);
        self.stdin_release.notify_waiters();
    }

    fn exit(&self, status: ExitStatus) {
        let mut st = self.status.lock().unwrap();
        if st.is_some() {
            return;
        }
        *st = Some(status);
        drop(st);
        self.stdout_tx.lock().unwrap().take();
        self.stdin_tx.lock().unwrap().take();
        self.stdin_dead.store(true, Ordering::SeqCst);
        self.stdin_gate.notify_waiters();
        self.stdin_release.notify_waiters();
        self.exited.notify_waiters();
    }

    async fn emit_raw(&self, bytes: &[u8]) -> Result<(), ()> {
        if self.status.lock().unwrap().is_some() {
            return Err(());
        }
        let tx = self.stdout_tx.lock().unwrap().clone();
        match tx {
            Some(tx) => tx.send(bytes.to_vec()).map_err(|_| ()),
            None => Err(()),
        }
    }

    async fn exited_wait(&self) {
        loop {
            let n = self.exited.notified();
            if self.status.lock().unwrap().is_some() {
                return;
            }
            n.await;
        }
    }

    fn kill_count(&self) -> usize {
        self.kills.load(Ordering::SeqCst)
    }
}

impl Process for ScriptedProcess {
    fn scope_id(&self) -> &str {
        &self.scope
    }

    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            loop {
                let notified = self.stdin_gate.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.stdin_dead.load(Ordering::SeqCst)
                    || self.stdin_closed.load(Ordering::SeqCst)
                {
                    return Err(io_closed());
                }
                if self.stdin_attached.load(Ordering::SeqCst) {
                    break;
                }
                notified.await;
            }
            let tx = self.stdin_tx.lock().unwrap().clone();
            let Some(tx) = tx else {
                return Err(io_closed());
            };
            self.stdin_got.lock().unwrap().extend_from_slice(buf);
            let n = buf.len();
            tx.send(buf.to_vec()).map_err(|_| io_closed())?;
            // io.Pipe: the write pends while the script holds it.
            loop {
                if !self.stdin_hold.load(Ordering::SeqCst) {
                    return Ok(n);
                }
                let notified = self.stdin_release.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if !self.stdin_hold.load(Ordering::SeqCst) || self.stdin_dead.load(Ordering::SeqCst)
                {
                    if self.stdin_dead.load(Ordering::SeqCst) {
                        return Err(io_closed());
                    }
                    return Ok(n);
                }
                notified.await;
            }
        })
    }

    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.stdin_tx.lock().unwrap().take();
            self.stdin_closed.store(true, Ordering::SeqCst);
            self.stdin_gate.notify_waiters();
            Ok(())
        })
    }

    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            loop {
                {
                    let mut left = self.stdout_left.lock().unwrap();
                    let avail = left.0.len() - left.1;
                    if avail > 0 {
                        let n = avail.min(buf.len());
                        buf[..n].copy_from_slice(&left.0[left.1..left.1 + n]);
                        left.1 += n;
                        if left.1 == left.0.len() {
                            left.0.clear();
                            left.1 = 0;
                        }
                        return Ok(n);
                    }
                }
                match self.stdout_rx.lock().await.recv().await {
                    Some(chunk) => {
                        self.stdout_left.lock().unwrap().0.extend_from_slice(&chunk);
                    }
                    None => return Ok(0),
                }
            }
        })
    }

    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut e = self.stderr.lock().unwrap();
            if e.is_empty() {
                return Ok(0);
            }
            let n = e.len().min(buf.len());
            buf[..n].copy_from_slice(&e[..n]);
            e.drain(..n);
            Ok(n)
        })
    }

    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        Box::pin(async move {
            self.exited_wait().await;
            Ok(self.status.lock().unwrap().unwrap_or_default())
        })
    }

    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.kills.fetch_add(1, Ordering::SeqCst);
            self.exit(ExitStatus {
                code: 143,
                signaled: true,
            });
            Ok(())
        })
    }
}

struct StaticProcess {
    scope: String,
    stdout: Mutex<Vec<u8>>,
    code: i32,
}

impl Process for StaticProcess {
    fn scope_id(&self) -> &str {
        &self.scope
    }
    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move { Ok(buf.len()) })
    }
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move { Ok(()) })
    }
    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut o = self.stdout.lock().unwrap();
            if o.is_empty() {
                return Ok(0);
            }
            let n = o.len().min(buf.len());
            buf[..n].copy_from_slice(&o[..n]);
            o.drain(..n);
            Ok(n)
        })
    }
    fn read_stderr<'a>(&'a self, _buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move { Ok(0) })
    }
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        let code = self.code;
        Box::pin(async move {
            Ok(ExitStatus {
                code,
                signaled: false,
            })
        })
    }
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move { Ok(()) })
    }
}

type Script =
    Box<dyn FnOnce(Arc<ScriptedProcess>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

struct ScriptedLauncher {
    launches: Mutex<Vec<ProcessSpec>>,
    version: Mutex<String>,
    version_code: Mutex<i32>,
    alive: Mutex<HashMap<String, bool>>,
    alive_err: Mutex<Option<Failure>>,
    launch_err: Mutex<Option<Failure>>,
    script: Mutex<Option<Script>>,
    sessions: Mutex<Vec<Arc<ScriptedProcess>>>,
}

impl ScriptedLauncher {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            launches: Mutex::new(Vec::new()),
            version: Mutex::new("1.3.3\n".to_string()),
            version_code: Mutex::new(0),
            alive: Mutex::new(HashMap::new()),
            alive_err: Mutex::new(None),
            launch_err: Mutex::new(None),
            script: Mutex::new(Some(script)),
            sessions: Mutex::new(Vec::new()),
        })
    }

    fn unscripted() -> Arc<Self> {
        Self::new(Box::new(|_| Box::pin(async {})))
    }

    fn set_version_out(&self, out: &str, code: i32) {
        *self.version.lock().unwrap() = out.to_string();
        *self.version_code.lock().unwrap() = code;
    }

    fn set_launch_err(&self, e: Failure) {
        *self.launch_err.lock().unwrap() = Some(e);
    }

    fn set_alive(&self, scope: &str, alive: bool) {
        self.alive.lock().unwrap().insert(scope.to_string(), alive);
    }

    fn set_alive_err(&self, e: Failure) {
        *self.alive_err.lock().unwrap() = Some(e);
    }

    fn launches(&self) -> Vec<ProcessSpec> {
        self.launches.lock().unwrap().clone()
    }

    fn last_session(&self) -> Arc<ScriptedProcess> {
        self.sessions.lock().unwrap().last().unwrap().clone()
    }
}

impl ProcessLauncher for ScriptedLauncher {
    fn launch<'a>(
        &'a self,
        spec: ProcessSpec,
    ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
        Box::pin(async move {
            spec.validate()?;
            self.launches.lock().unwrap().push(spec.clone());
            if let Some(e) = self.launch_err.lock().unwrap().clone() {
                return Err(e);
            }
            if spec.args.as_slice() == ["--version"] {
                return Ok(Box::new(StaticProcess {
                    scope: spec.scope_id.clone(),
                    stdout: Mutex::new(self.version.lock().unwrap().as_bytes().to_vec()),
                    code: *self.version_code.lock().unwrap(),
                }) as Box<dyn Process>);
            }
            let p = ScriptedProcess::new(&spec.scope_id);
            self.sessions.lock().unwrap().push(p.clone());
            if let Some(script) = self.script.lock().unwrap().take() {
                let p2 = p.clone();
                tokio::spawn(async move { script(p2).await });
            }
            Ok(Box::new(ProcessHandle(p)))
        })
    }

    fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            if let Some(e) = self.alive_err.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(*self.alive.lock().unwrap().get(scope_id).unwrap_or(&false))
        })
    }

    fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.alive.lock().unwrap().remove(scope_id);
            Ok(())
        })
    }
}

struct ProcessHandle(Arc<ScriptedProcess>);

impl Process for ProcessHandle {
    fn scope_id(&self) -> &str {
        self.0.scope_id()
    }
    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        self.0.write_stdin(buf)
    }
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        self.0.close_stdin()
    }
    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        self.0.read_stdout(buf)
    }
    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        self.0.read_stderr(buf)
    }
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        self.0.wait()
    }
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        self.0.kill()
    }
}

/// `readPromptLine` — attach the stdin reader and consume exactly one
/// user-event line (the writer emits one line per call).
async fn read_line(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut buf = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out reading stdin line")
        {
            Some(chunk) => {
                buf.extend_from_slice(&chunk);
                if buf.ends_with(b"\n") {
                    return buf;
                }
            }
            None => return buf,
        }
    }
}

/// `play` — the standard fixture script: read the prompt user event,
/// emit the fixture, then exit `code`. Exit closes stdout (the EOF
/// the reader finishes on) and stdin, mirroring `p.exit` upstream.
fn play_agy(stdout: Vec<u8>, code: i32) -> Script {
    Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let mut rx = p.take_stdin_rx();
            let _prompt = read_line(&mut rx).await;
            if !stdout.is_empty() {
                let _ = p.emit_raw(&stdout).await;
            }
            p.exit(ExitStatus {
                code,
                signaled: false,
            });
        })
    })
}

struct Run {
    launcher: Arc<ScriptedLauncher>,
    session: Arc<dyn Session>,
}

fn new_adapter(l: Arc<dyn ProcessLauncher>) -> Antigravity {
    Antigravity::new(Config {
        launcher: Some(l),
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .unwrap()
}

async fn start_with(script: Script, spec: StartSpec) -> Run {
    let l = ScriptedLauncher::new(script);
    let a = new_adapter(l.clone());
    let s: Arc<dyn Session> = Arc::from(a.start(spec).await.expect("start"));
    Run {
        launcher: l,
        session: s,
    }
}

async fn collect(s: &dyn Session) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, s.next_event())
            .await
            .expect("timed out draining events")
        {
            Some(e) => {
                e.validate().expect("invalid event");
                assert_eq!(e.seq as usize, out.len() + 1, "seq");
                out.push(e);
            }
            None => return out,
        }
    }
}

fn terminal_of(events: &[Event]) -> Terminal {
    events
        .last()
        .and_then(|e| match &e.payload {
            Some(EventPayload::TerminalReported(t)) => Some(t.terminal.clone()),
            _ => None,
        })
        .expect("last event is not TerminalReported")
}

fn is_code(err: &Failure, code: &str) -> bool {
    err.code() == code
}

fn warning_messages(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Warning(w)) => Some(w.message.clone()),
            _ => None,
        })
        .collect()
}

fn messages(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Message(m)) => Some(m.text.clone()),
            _ => None,
        })
        .collect()
}

fn usages(events: &[Event]) -> Vec<central_harness::event::Usage> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::UsageReport(u)) => Some(u.usage),
            _ => None,
        })
        .collect()
}

// =====================================================================
// antigravity_test.go — identity, vocabulary, capabilities
// =====================================================================

#[test]
fn default_pinned_version() {
    assert_eq!(antigravity::DEFAULT_PINNED_VERSION, "1.3.3");
}

#[test]
fn kind_is_antigravity() {
    assert_eq!(antigravity::KIND, "antigravity");
}

#[test]
fn reasons_vocabulary() {
    assert_eq!(
        antigravity::reasons(),
        [
            "harness_api_error",
            "harness_exited_without_result",
            "harness_session_mismatch",
            "harness_protocol_error"
        ]
        .as_slice()
    );
}

/// `TestCapabilities` — the resident stream-json process: streaming
/// input, resume, step-scope tokens; nothing else.
#[test]
fn capabilities_matrix() {
    let c = antigravity::capabilities();
    assert!(c.streaming_input);
    assert!(c.resume_by_id);
    assert!(c.usage_tokens);
    assert_eq!(c.usage_scope, UsageScope::Step);
    assert!(!c.cost_usd);
    assert!(!c.interrupt);
    assert!(!c.preassign_session_id);
    assert!(!c.permission_bridge);
    assert!(!c.partial_deltas);
    assert!(!c.reattach);
    assert!(!c.native_cost_limit);
    c.validate().unwrap();
}

// =====================================================================
// adapter_test.go — config, refusals, launches, reconcile
// =====================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_validates() {
    assert!(Antigravity::new(Config::default()).is_err());
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    assert!(
        Antigravity::new(Config {
            launcher: Some(l.clone()),
            ..Config::default()
        })
        .is_ok()
    );
    assert!(
        Antigravity::new(Config {
            launcher: Some(l.clone()),
            pinned_version: "1.3".to_string(),
            ..Config::default()
        })
        .is_err()
    );
    assert!(
        Antigravity::new(Config {
            launcher: Some(l),
            pinned_version: "9.9.9".to_string(),
            ..Config::default()
        })
        .is_ok()
    );
}

/// `TestEnvExtrasPassValidation` — env validation accepts the one
/// extra the adapter declares and still refuses others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn env_extras_pass_validation() {
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    assert_eq!(a.env_extras(), [antigravity::AUTO_UPDATE_DISABLE_ENV]);
    // A spec carrying the declared extra validates; an undeclared
    // AGY_* var refuses.
    let mut env = probe_env();
    env.vars.insert(
        antigravity::AUTO_UPDATE_DISABLE_ENV.to_string(),
        "1".to_string(),
    );
    central_harness::env::validate_launch_env(&env.vars, &[antigravity::AUTO_UPDATE_DISABLE_ENV])
        .expect("declared extra validates");
    env.vars.insert("AGY_OTHER".to_string(), "x".to_string());
    assert!(
        central_harness::env::validate_launch_env(
            &env.vars,
            &[antigravity::AUTO_UPDATE_DISABLE_ENV],
        )
        .is_err()
    );
}

/// `TestStartLaunchesClosedArgv` — the session argv is exactly the
/// closed triple, the prompt travels as the first stdin user event,
/// and the launch env force-sets the disable var.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_launches_closed_argv() {
    let workdir = tmpdir();
    let run = start_with(play_agy(fixture("success.ndjson"), 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let session_spec = run.launcher.launches().last().unwrap().clone();
    assert_eq!(
        session_spec.args,
        [
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--disable-slash-commands"
        ]
    );
    assert_eq!(session_spec.program, "antigravity");
    assert_eq!(session_spec.work_dir, workdir);
    assert_eq!(
        session_spec
            .env
            .get(antigravity::AUTO_UPDATE_DISABLE_ENV)
            .map(String::as_str),
        Some("1"),
        "disable var force-set"
    );
    assert_eq!(
        session_spec.env_extras,
        [antigravity::AUTO_UPDATE_DISABLE_ENV]
    );
    assert!(!session_spec.args.iter().any(|a| a.contains("marker")));
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    // The prompt traveled as one NDJSON user event.
    let got = run.launcher.last_session().stdin_written();
    let text = String::from_utf8(got).unwrap();
    assert!(text.contains("\"event\":\"user\""), "{text}");
    assert!(
        text.contains("\"content\":\"marker-prompt- Run the Bash command: echo probe\""),
        "{text}"
    );
    assert!(text.ends_with("\n"));
}

/// `TestStartForceSetsDisableVar` — an operator-supplied value is
/// overridden, never trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_force_sets_disable_var() {
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.env.vars.insert(
        antigravity::AUTO_UPDATE_DISABLE_ENV.to_string(),
        "0".to_string(),
    );
    let run = start_with(play_agy(fixture("success.ndjson"), 0), spec).await;
    let _ = collect(&*run.session).await;
    let session_spec = run.launcher.launches().last().unwrap().clone();
    assert_eq!(
        session_spec
            .env
            .get(antigravity::AUTO_UPDATE_DISABLE_ENV)
            .map(String::as_str),
        Some("1")
    );
}

/// `TestStartRefusals` — policy, limits, project config and PATH all
/// refuse fail-closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refusals() {
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    for (name, mutate) in [
        (
            "bridge",
            Box::new(|s: &mut StartSpec| s.permission = PermissionPolicy::Bridge)
                as Box<dyn FnOnce(&mut StartSpec)>,
        ),
        (
            "auto allow",
            Box::new(|s: &mut StartSpec| s.permission = PermissionPolicy::AutoAllow)
                as Box<dyn FnOnce(&mut StartSpec)>,
        ),
        (
            "max turns",
            Box::new(|s: &mut StartSpec| s.limits.max_turns = 2) as Box<dyn FnOnce(&mut StartSpec)>,
        ),
        (
            "max cost",
            Box::new(|s: &mut StartSpec| s.limits.max_cost_micro_usd = 1)
                as Box<dyn FnOnce(&mut StartSpec)>,
        ),
    ] {
        let workdir = tmpdir();
        let mut spec = start_spec(&workdir);
        mutate(&mut spec);
        let err = a.start(spec).await.err().unwrap_or_else(|| unreachable!());
        assert!(
            is_code(&err, central_harness::port::codes::UNSUPPORTED),
            "{name}: {err:?}"
        );
    }
    // Every project-config name refuses.
    for name in [
        ".agent",
        "_agent",
        ".agents",
        "_agents",
        "codeium.yaml",
        ".codeium.yaml",
        "codeium.yml",
        ".codeium.yml",
        ".citc",
    ] {
        let workdir = tmpdir();
        std::fs::write(std::path::Path::new(&workdir).join(name), b"x").unwrap();
        let err = a
            .start(start_spec(&workdir))
            .await
            .err()
            .unwrap_or_else(|| unreachable!());
        assert!(is_code(&err, antigravity::codes::INVALID_LAUNCH), "{name}");
    }
    // Missing PATH refuses.
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.env.vars.remove("PATH");
    assert!(is_code(
        &a.start(spec).await.err().unwrap_or_else(|| unreachable!()),
        antigravity::codes::PATH_REQUIRED
    ));
    // Bad resume ids refuse.
    for bad in ["", "abc", "66666666-6666-4666-8666-66666666666G"] {
        let workdir = tmpdir();
        let err = a
            .resume(
                SessionRef {
                    harness_session_id: bad.to_string(),
                },
                start_spec(&workdir),
            )
            .await
            .err()
            .unwrap_or_else(|| unreachable!());
        assert!(is_code(&err, antigravity::codes::INVALID_LAUNCH), "{bad}");
    }
    // Version gate.
    let workdir = tmpdir();
    let l = ScriptedLauncher::unscripted();
    l.set_version_out("9.9.9\n", 0);
    let a = new_adapter(l);
    let err = a
        .start(start_spec(&workdir))
        .await
        .err()
        .unwrap_or_else(|| unreachable!());
    assert!(is_code(&err, antigravity::codes::UNPINNED_VERSION));
}

/// `TestResume` — `exec` argv carries `--conversation <id>`; a matching
/// conversation proceeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_launches_and_matches() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_agy(fixture("resume.ndjson"), 0));
    let a = new_adapter(l.clone());
    let mut spec = start_spec(&workdir);
    spec.model = "gemini-3.8-flash-low".to_string();
    let s: Arc<dyn Session> = Arc::from(
        a.resume(
            SessionRef {
                harness_session_id: "66666666-6666-6666-6666-666666666666".to_string(),
            },
            spec,
        )
        .await
        .expect("resume"),
    );
    let ev = collect(&*s).await;
    let session_spec = l.launches().last().unwrap().clone();
    assert_eq!(
        session_spec.args,
        [
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--disable-slash-commands",
            "--model",
            "gemini-3.8-flash-low",
            "--conversation",
            "66666666-6666-6666-6666-666666666666"
        ]
    );
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
}

/// `TestReconcile`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_scope_alive() {
    let l = ScriptedLauncher::unscripted();
    l.set_alive("s", true);
    let a = new_adapter(l.clone());
    let r = a
        .reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: "s".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .unwrap();
    assert!(r.scope_alive);
    l.set_alive_err(Failure::internal("E_UP", "x"));
    assert!(
        a.reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: "s".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .is_err()
    );
    assert!(
        a.reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: String::new(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .is_err()
    );
}

// =====================================================================
// probe_test.go
// =====================================================================

/// `TestProbeVersion` — version parsed strictly; always authenticated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_version() {
    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l.clone());
    let r = a.probe(probe_env()).await.unwrap();
    assert_eq!(r.harness_version, "1.3.3");
    assert!(r.authenticated);
    assert!(r.detail.contains("no probeable login"));
    let launches = l.launches();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].args, ["--version"]);
    assert_eq!(launches[0].work_dir, "/probe");
    assert_eq!(
        launches[0]
            .env
            .get(antigravity::AUTO_UPDATE_DISABLE_ENV)
            .map(String::as_str),
        Some("1")
    );
}

/// `TestProbePinVerdict`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_pin_verdict() {
    let l = ScriptedLauncher::unscripted();
    l.set_version_out("1.3.4\n", 0);
    let a = new_adapter(l.clone());
    let r = a.probe(probe_env()).await.unwrap();
    assert_eq!(r.harness_version, "1.3.4");
    assert!(r.detail.contains("differs from pinned"));
    assert!(r.detail.contains("Start refuses"));
    let a = Antigravity::new(Config {
        launcher: Some(l),
        allow_unpinned: true,
        ..Config::default()
    })
    .unwrap();
    let r = a.probe(probe_env()).await.unwrap();
    assert!(r.detail.contains("allowed by AllowUnpinned"));
}

/// `TestProbeFailures`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_failures() {
    for (name, out, code) in [
        ("garbage", "garbage", 0),
        ("nonzero", "1.3.3\n", 1),
        ("missing patch", "1.3\n", 0),
        ("suffixed", "1.3.3 (agy)\n", 0),
    ] {
        let l = ScriptedLauncher::unscripted();
        l.set_version_out(out, code);
        let a = new_adapter(l);
        let err = a
            .probe(probe_env())
            .await
            .err()
            .unwrap_or_else(|| unreachable!());
        assert!(
            is_code(&err, antigravity::codes::UNEXPECTED_PROBE_OUTPUT),
            "{name}: {err:?}"
        );
    }
    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    let mut env = probe_env();
    env.sandbox_scope_id.clear();
    assert!(a.probe(env).await.is_err());
    let mut env = probe_env();
    env.vars.remove("PATH");
    assert!(a.probe(env).await.is_err());
    let l = ScriptedLauncher::unscripted();
    l.set_launch_err(Failure::internal("E_UP", "down"));
    let a = new_adapter(l);
    assert!(a.probe(probe_env()).await.is_err());
}

// =====================================================================
// session_test.go
// =====================================================================

/// `TestSessionStartedFields` + `TestSuccessMessagesAndUsage` —
/// success.ndjson: reveal 1111…, two assistant messages (step +
/// final result), one step-scope usage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_started_fields_and_success() {
    let workdir = tmpdir();
    let run = start_with(play_agy(fixture("success.ndjson"), 0), start_spec(&workdir)).await;
    let r = run.session.session_ref().await.expect("ref");
    assert_eq!(r.harness_session_id, "11111111-1111-1111-1111-111111111111");
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert_eq!(t.exit_code, Some(0));
    match &ev[0].payload {
        Some(EventPayload::SessionStarted(s)) => {
            assert_eq!(s.harness_session_id, "11111111-1111-1111-1111-111111111111");
            assert_eq!(s.harness_version, "1.3.3");
        }
        p => unreachable!("first event: {p:?}"),
    }
    let msgs = messages(&ev);
    assert_eq!(msgs.len(), 2, "step message + final result message");
    assert_eq!(msgs[1], "FIX_OK\n");
    let us = usages(&ev);
    assert_eq!(us.len(), 1);
    assert_eq!(us[0].tokens_in, 11761);
    assert_eq!(us[0].tokens_out, 3);
    assert_eq!(us[0].scope, UsageScope::Step);
    assert_eq!(us[0].cost_micro_usd, 0);
}

/// `TestToolCallResultMapping` — tools.ndjson: two tools pair with
/// step-N ids; DONE output maps verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_call_result_mapping() {
    let workdir = tmpdir();
    let run = start_with(play_agy(fixture("tools.ndjson"), 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let calls: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolCall(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].id, "step-2");
    assert_eq!(calls[0].name, "write_to_file");
    assert_eq!(
        calls[0].input,
        br#"{"TargetFile":"/work/fix_tool.txt"}"#.to_vec()
    );
    assert_eq!(calls[1].id, "step-4");
    assert_eq!(calls[1].name, "run_command");
    assert_eq!(
        calls[1].input,
        br#"{"CommandLine":"echo FIXECHO"}"#.to_vec()
    );
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].status, ToolStatus::Ok);
    assert!(results[0].output.is_empty());
    assert_eq!(results[1].output, "FIXECHO\r\n".as_bytes().to_vec());
}

/// `TestToolErrorMapping` — an ERROR tool frame yields an error
/// result whose output is the error message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_error_mapping() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("tool-error.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "step-2");
    assert_eq!(results[0].status, ToolStatus::Error);
    let out = String::from_utf8(results[0].output.clone()).unwrap();
    assert!(
        out.contains("cannot view \"/work\": path is a directory"),
        "{out}"
    );
}

/// `TestDeniedTurnWarning` — denied_actions warns once; the turn
/// still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denied_turn_warning() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("denied-turn.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let warns = warning_messages(&ev);
    assert_eq!(warns, ["harness auto-denied tool actions"]);
    let raw = ev
        .iter()
        .find(|e| matches!(e.payload, Some(EventPayload::Warning(_))))
        .map(|e| String::from_utf8_lossy(&e.raw).to_string())
        .unwrap_or_default();
    assert!(raw.contains("denied_actions"), "{raw}");
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, ToolStatus::Ok);
    assert!(results[0].output.is_empty());
}

/// `TestBadModelError` — an idless ERROR result before binding is the
/// final word: no SessionStarted, failed/api_error, ref closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_model_error() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("api-error-bad-model.ndjson"), 1),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert!(
        !ev.iter()
            .any(|e| matches!(e.payload, Some(EventPayload::SessionStarted(_)))),
        "unexpected SessionStarted"
    );
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_api_error");
    assert!(run.session.session_ref().await.is_none());
}

/// `TestInterruptedResult` — an ERROR result fails api_error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_result() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("interrupted.ndjson"), 1),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_api_error");
}

/// `TestResumeAndSystemMessageSkipped` — resume.ndjson: system_message
/// steps skip silently; the resumed id binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_and_system_message_skipped() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_agy(fixture("resume.ndjson"), 0));
    let a = new_adapter(l);
    let s: Arc<dyn Session> = Arc::from(
        a.resume(
            SessionRef {
                harness_session_id: "66666666-6666-6666-6666-666666666666".to_string(),
            },
            start_spec(&workdir),
        )
        .await
        .expect("resume"),
    );
    let ev = collect(&*s).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let msgs = messages(&ev);
    // FIX_RESUME step text + final result response.
    assert_eq!(msgs[msgs.len() - 1], "FIX_RESUME\n");
    // Exactly one malformed warning: the system_message step.
    assert_eq!(warning_messages(&ev), ["malformed harness frame"]);
}

/// `TestUnknownTypeTolerance` — an unknown event warns
/// "unrecognized harness message"; a system-level unknown inside the
/// stream is tolerated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_type_tolerance() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("unknown-type.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    assert_eq!(warning_messages(&ev), ["unrecognized harness message"]);
}

/// `TestSlashLiteralFinalMessage` — the final result's response is
/// the last message (slash command ran as literal text).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slash_literal_final_message() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("slash-literal.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let msgs = messages(&ev);
    assert_eq!(msgs.len(), 2);
    assert!(msgs[1].contains("Available Slash Commands"), "final text");
    assert!(msgs[1].ends_with("Let me know what you would like to work on!\n"));
}

/// `TestMultiTurnFixtureFirstResultWins` — with nothing queued the
/// FIRST result ends the session; later frames are dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_turn_first_result_wins() {
    let workdir = tmpdir();
    let run = start_with(
        play_agy(fixture("multi-turn.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let msgs = messages(&ev);
    // Only turn one is processed: its result ends the session; the
    // second turn's frames are drained and dropped.
    assert_eq!(msgs.last().unwrap(), "FIX_ONE\n");
    assert!(!msgs.iter().any(|m| m.contains("FIX_TWO")));
}

/// `TestResumeMismatchStops` — a stream bound to a different
/// conversation than the resumed one never binds, stops with
/// session_mismatch and kills the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_mismatch_stops() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_agy(fixture("unknown-conversation.ndjson"), 0));
    let a = new_adapter(l.clone());
    let s: Arc<dyn Session> = Arc::from(
        a.resume(
            SessionRef {
                harness_session_id: "66666666-6666-6666-6666-666666666666".to_string(),
            },
            start_spec(&workdir),
        )
        .await
        .expect("resume"),
    );
    let ev = collect(&*s).await;
    assert!(
        !ev.iter()
            .any(|e| matches!(e.payload, Some(EventPayload::SessionStarted(_)))),
        "mismatched session bound"
    );
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_session_mismatch");
    assert!(l.last_session().kill_count() >= 1);
}

/// `TestMidStreamChangeStops` — a frame carrying a different
/// conversation id mid-stream stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn midstream_change_stops() {
    let mut stream = Vec::new();
    stream.extend_from_slice(
        b"{\"event\":\"init\",\"conversation_id\":\"11111111-1111-4111-8111-111111111111\",\"init\":{}}\n",
    );
    stream.extend_from_slice(
        b"{\"event\":\"step_update\",\"step_update\":{\"conversation_id\":\"22222222-2222-4222-8222-222222222222\",\"step_index\":0,\"state\":\"DONE\",\"step_type\":\"user_input\"}}\n",
    );
    let workdir = tmpdir();
    let run = start_with(play_agy(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.reason, "harness_session_mismatch");
}

/// `TestEmptyIDResultAfterBindingStops` — an idless result after the
/// session bound violates stream integrity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_id_result_after_binding_stops() {
    let mut stream = Vec::new();
    stream.extend_from_slice(
        b"{\"event\":\"init\",\"conversation_id\":\"11111111-1111-4111-8111-111111111111\",\"init\":{}}\n",
    );
    stream.extend_from_slice(
        b"{\"event\":\"result\",\"result\":{\"conversation_id\":\"\",\"status\":\"SUCCESS\",\"response\":\"x\"}}\n",
    );
    let workdir = tmpdir();
    let run = start_with(play_agy(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.reason, "harness_session_mismatch");
}

/// `TestMalformedAndOrphanWarn` — malformed lines warn; an orphan
/// terminal tool frame (no pending) warns; an idless step warns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_and_orphan_warn() {
    let mut stream = Vec::new();
    stream.extend_from_slice(b"not json\n");
    stream.extend_from_slice(
        b"{\"event\":\"init\",\"conversation_id\":\"11111111-1111-4111-8111-111111111111\",\"init\":{}}\n",
    );
    stream.extend_from_slice(b"{\"event\":\"step_update\",\"step_update\":{\"step_index\":9,\"state\":\"DONE\",\"step_type\":\"tool\",\"tool_name\":\"x\",\"tool_info\":{\"parameters\":{},\"output\":\"o\"}}}\n");
    stream.extend_from_slice(b"{\"event\":\"step_update\",\"step_update\":{}}\n");
    stream.extend_from_slice(
        b"{\"event\":\"result\",\"result\":{\"conversation_id\":\"11111111-1111-4111-8111-111111111111\",\"status\":\"SUCCESS\",\"response\":\"done\"}}\n",
    );
    let workdir = tmpdir();
    let run = start_with(play_agy(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let warns = warning_messages(&ev);
    assert_eq!(
        warns,
        [
            "malformed harness frame",
            "malformed harness frame",
            "malformed harness frame"
        ],
        "{warns:?}"
    );
}

/// `TestOversizeLineStops` — a line past the 16 MiB cap stops the
/// session with protocol_error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_line_stops() {
    let mut stream = Vec::new();
    stream.extend_from_slice(
        b"{\"event\":\"init\",\"conversation_id\":\"11111111-1111-4111-8111-111111111111\",\"init\":{}}\n",
    );
    stream.extend_from_slice(b"{\"event\":\"step_update\",\"pad\":\"");
    stream.extend(std::iter::repeat_n(b'a', (16 << 20) + 64));
    stream.extend_from_slice(b"\"}\n");
    let workdir = tmpdir();
    let run = start_with(play_agy(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_protocol_error");
}

/// `TestTerminalTable` — terminal mapping: result-SUCCESS wins over
/// the exit code; kill beats a harness self-report; no-result exits
/// map from the code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_table() {
    // Empty stream, exit 0 → succeeded.
    let workdir = tmpdir();
    let run = start_with(play_agy(Vec::new(), 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    // Empty stream, exit 1 → exited_without_result.
    let workdir = tmpdir();
    let run = start_with(play_agy(Vec::new(), 1), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.reason, "harness_exited_without_result");
    assert_eq!(t.exit_code, Some(1));
    // Success result + exit 1 → still succeeded (result wins over
    // the exit code).
    let workdir = tmpdir();
    let run = start_with(play_agy(fixture("success.ndjson"), 1), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert_eq!(t.exit_code, Some(1));
}

/// `TestInterruptBeforeAndAfter` — unsupported before the terminal,
/// session-ended after a recorded result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupt_before_and_after() {
    let workdir = tmpdir();
    let release = Arc::new(Notify::new());
    let rel = release.clone();
    let script: Script = Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let mut rx = p.take_stdin_rx();
            let _ = read_line(&mut rx).await;
            release.notified().await;
            p.exit(ExitStatus {
                code: 0,
                signaled: false,
            });
        })
    });
    let run = start_with(script, start_spec(&workdir)).await;
    let err = run
        .session
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!());
    assert!(is_code(&err, central_harness::port::codes::UNSUPPORTED));
    let err = run
        .session
        .respond_permission(PermissionDecision {
            request_id: "r".to_string(),
            allow: false,
            option_id: String::new(),
            decided_by: "t".to_string(),
            input_sha256: [0; 32],
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!());
    assert!(is_code(
        &err,
        central_harness::port::codes::NO_PENDING_PERMISSION
    ));
    run.session.kill().await.unwrap();
    let _ = rel;
    let _ = collect(&*run.session).await;
    let err = run
        .session
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!());
    assert!(is_code(&err, central_harness::port::codes::SESSION_ENDED));
}

/// `TestSendDeliveredBeforeResult` — a Send queued when a result
/// lands makes the result turn-only: stdin stays open, the follow-up
/// is delivered, and the next result ends the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_delivered_before_result() {
    let stdout = fixture("multi-turn.ndjson");
    let text = String::from_utf8(stdout).unwrap();
    let mut turn_one = String::new();
    let mut rest = String::new();
    let mut split = false;
    for line in text.lines() {
        if !split {
            turn_one.push_str(line);
            turn_one.push('\n');
            if line.contains("\"event\":\"result\"") {
                split = true;
            }
        } else {
            rest.push_str(line);
            rest.push('\n');
        }
    }
    assert!(!rest.is_empty(), "fixture has no second turn");
    let workdir = tmpdir();
    // The event stream is the only clock that orders the session's
    // decode against the stdin writes. The second `FIX_ONE` message is
    // turn one's result emitted turn-only — proof `queued()` was still
    // true when it was processed. Only then may the held writes
    // release, and turn two is emitted once the Send has resolved so
    // its result finds an empty pipeline and ends the session.
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let (rest_tx, rest_rx) = oneshot::channel::<()>();
    let script: Script = Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            // Arm before the stdin receiver attaches: no write can pass
            // the attach gate and still see the hold unarmed, so the
            // prompt write is always in flight when turn one's result
            // lands — `queued()` cannot lose the race the fixed sleeps
            // left open.
            p.arm_hold();
            let mut rx = p.take_stdin_rx();
            let line1 = read_line(&mut rx).await;
            assert!(String::from_utf8_lossy(&line1).contains("marker-prompt"));
            let _ = p.emit_raw(turn_one.as_bytes()).await;
            release_rx.await.expect("release signal");
            p.release_writes();
            let line2 = read_line(&mut rx).await;
            assert!(String::from_utf8_lossy(&line2).contains("follow-up"));
            rest_rx.await.expect("rest signal");
            let _ = p.emit_raw(rest.as_bytes()).await;
            while rx.recv().await.is_some() {}
            p.exit(ExitStatus {
                code: 0,
                signaled: false,
            });
        })
    });
    let run = start_with(script, start_spec(&workdir)).await;
    let s = run.session.clone();
    let send = tokio::spawn(async move {
        s.send(OperatorInput {
            text: "follow-up".to_string(),
        })
        .await
    });
    // Drain the whole stream; the second `FIX_ONE` message (step
    // update, then the queued-path result) proves turn one's result
    // was processed with `queued()` true, so the held writes may
    // release and — once the Send resolved, leaving an empty pipeline
    // — turn two is fed and its result ends the session.
    let mut ev = Vec::new();
    let mut fix_one = 0;
    let mut send = Some(send);
    let mut release_tx = Some(release_tx);
    let mut rest_tx = Some(rest_tx);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let e = match tokio::time::timeout_at(deadline, run.session.next_event())
            .await
            .expect("timed out draining events")
        {
            Some(e) => e,
            None => break,
        };
        e.validate().expect("invalid event");
        assert_eq!(e.seq as usize, ev.len() + 1, "seq");
        if let Some(EventPayload::Message(m)) = &e.payload
            && m.text == "FIX_ONE\n"
        {
            fix_one += 1;
        }
        ev.push(e);
        if fix_one == 2 && release_tx.is_some() {
            let _ = release_tx.take().expect("release sent once").send(());
            tokio::time::timeout_at(deadline, send.take().expect("send awaited once"))
                .await
                .expect("timed out awaiting send")
                .expect("send task")
                .expect("send delivered");
            let _ = rest_tx.take().expect("rest sent once").send(());
        }
    }
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let msgs = messages(&ev);
    assert_eq!(msgs.last().unwrap(), "FIX_TWO\n");
    // A Send after the end reports session-ended.
    let err = run
        .session
        .send(OperatorInput {
            text: "late".to_string(),
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!());
    assert!(is_code(&err, central_harness::port::codes::SESSION_ENDED));
}

/// `TestPromptDelivery` — a large prompt completes; an early exit
/// warns once and the terminal still comes from the exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_delivery() {
    // Large prompt completes without the failure warning.
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.prompt = "p".repeat(1 << 20);
    let run = start_with(play_agy(fixture("success.ndjson"), 0), spec).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    assert!(warning_messages(&ev).is_empty());
    let got = run.launcher.last_session().stdin_written();
    assert!(got.len() > (1 << 20));
    // Early exit: the prompt write fails, warns once, terminal from
    // the exit.
    let script: Script = Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            p.exit(ExitStatus {
                code: 1,
                signaled: false,
            });
        })
    });
    let workdir = tmpdir();
    let run = start_with(script, start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_exited_without_result");
    assert_eq!(warning_messages(&ev), ["delivering the prompt failed"]);
}

/// `TestKillEndsKilled` — Kill ends the session killed even when the
/// harness self-reports an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_ends_killed() {
    let workdir = tmpdir();
    let release = Arc::new(Notify::new());
    let rel = release.clone();
    let script: Script = Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let mut rx = p.take_stdin_rx();
            let _ = read_line(&mut rx).await;
            release.notified().await;
            p.exit(ExitStatus {
                code: 0,
                signaled: false,
            });
        })
    });
    let run = start_with(script, start_spec(&workdir)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    run.session.kill().await.unwrap();
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Killed);
    assert!(run.launcher.last_session().kill_count() >= 1);
    let _ = rel;
}

/// `TestTestdataHygiene` — every fixture is UTF-8 NDJSON.
#[test]
fn fixture_hygiene() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/antigravity");
    let mut count = 0usize;
    for e in std::fs::read_dir(&dir).unwrap() {
        let e = e.unwrap();
        if e.path().extension().and_then(|s| s.to_str()) != Some("ndjson") {
            continue;
        }
        count += 1;
        let bytes = std::fs::read(e.path()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "{}:{} not JSON",
                e.file_name().to_string_lossy(),
                i + 1
            );
        }
    }
    assert!(count >= 8, "expected the verbatim fixture set");
}
