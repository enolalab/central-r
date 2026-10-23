//! The contract between Central and a harness adapter (ADR 0035;
//! governing spec §5) — the port of `internal/harness/port`
//! (`port.go`, `store.go`, `launcher.go`). An adapter drives an
//! external harness that owns its own agent loop. The
//! non-intervention rule holds: [`StartSpec::prompt`] and
//! [`StartSpec::model`] are passed to the harness verbatim, and
//! [`Session::send`]/[`Session::respond_permission`] carry only
//! operator-originated input. Adapters never inject, relocate or
//! proxy harness credentials.
//!
//! Three seams live here:
//!
//! - the adapter boundary — [`Adapter`], [`Session`], and the value
//!   types they exchange;
//! - the process boundary — [`ProcessLauncher`]/[`Process`], because
//!   adapters never exec: they describe the process and a launcher
//!   starts it (phase 2a spec decision 2);
//! - the durable boundary — [`AttemptStore`], [`ApprovalStore`],
//!   [`LeaseBinder`] and [`RecoveryStore`], where every write
//!   compare-and-swaps on the attempt's store-owned `version` and its
//!   execution-lease fence.
//!
//! No `sqlx`, `tokio` or driver type crosses these traits; every
//! fallible method returns the workspace-wide
//! [`central_foundation::failure::Failure`] carrying a code from
//! [`crate::domain::codes`] or [`port::codes`](codes) — the
//! `errors.Is` surface upstream callers match on. Every async trait is
//! hand-written `Pin<Box<dyn Future + Send + 'a>>` rather than
//! `#[trait_variant::make(Send)]` exactly so it stays `dyn`-
//! compatible — `start`/`resume` return `Box<dyn Session>`, `launch`
//! returns `Box<dyn Process>`, `with_lease` returns
//! `Box<dyn AttemptStore>` — while still carrying the §2.3-required
//! explicit `+ Send` future bounds and `Send + Sync + 'static`
//! supertraits (the `central-eventjournal::port::Consumer` /
//! `central-artifact::port::ByteStream` precedent;
//! rust-application-boundaries.md §2.3).

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, TaskId, WorkspaceId,
};
use time::OffsetDateTime;

use crate::approval::{InputMac, OpenApprovalInput, PermissionApproval};
use crate::attempt::Attempt;
use crate::capability::Capabilities;
use crate::domain::{Fence, Kind, PermissionPolicy, State, Terminal, Workspace, ZERO_TIME, vocab};
use crate::env::validate_launch_env;
use crate::event::Event;
use crate::record::EventRecord;

/// The boxed `Send` future the port's async methods return. Every
/// trait here is `dyn`-compatible — sessions, processes and
/// lease-bound stores cross the boundary as `Box<dyn …>` — so
/// `#[trait_variant::make(Send)]` cannot be used: it desugars to
/// `impl Future` in return position, which is never `dyn`-
/// compatible. Hand-written instead, carrying the same explicit
/// `+ Send` bounds the §2.3 boundary convention requires (the
/// `central-eventjournal::port::Consumer` precedent).
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Stable machine codes standing in for the upstream `port.Err*`
/// sentinels — the `errors.Is` surface of `internal/harness/port`.
/// Callers match a [`Failure`]'s `code()`.
pub mod codes {
    /// `port.ErrUnsupported` — an adapter does not declare the
    /// capability an operation needs.
    pub const UNSUPPORTED: &str = "harness_port_unsupported";
    /// `port.ErrInvalidStartSpec` — [`super::StartSpec::validate`]
    /// refused the spec.
    pub const INVALID_START_SPEC: &str = "harness_port_invalid_start_spec";
    /// `port.ErrSessionEnded` — the session already saw its final
    /// result or was stopped: there is nothing left to interrupt, and
    /// the process is exiting on its own. A caller stopping the
    /// session treats it as done, never as a reason to kill (harness
    /// phase 3d decision 6).
    pub const SESSION_ENDED: &str = "harness_port_session_ended";
    /// `port.ErrNoPendingPermission` — the request is not pending: it
    /// was already answered, or the session has ended, been stopped or
    /// seen its last result. It is benign for a caller that is
    /// draining the session (harness phase 3c decision 10).
    pub const NO_PENDING_PERMISSION: &str = "harness_port_no_pending_permission";
    /// `port.ErrPermissionBinding` — an allow does not bind the exact
    /// input bytes the adapter would echo to the harness (harness
    /// phase 3c decision 8): nothing is written, and the request
    /// stays pending.
    pub const PERMISSION_BINDING: &str = "harness_port_permission_binding";
    /// `port.ErrInvalidProcessSpec` — [`super::ProcessSpec::validate`]
    /// refused the spec.
    pub const INVALID_PROCESS_SPEC: &str = "harness_port_invalid_process_spec";
}

// ---------------------------------------------------------------------------
// Adapter and Session — the adapter boundary
// ---------------------------------------------------------------------------

/// Names a harness-owned session — upstream `port.SessionRef`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRef {
    /// The harness's own session id, revealed by the harness.
    pub harness_session_id: String,
}

/// The non-secret environment and sandbox scope for a launch —
/// upstream `port.LaunchEnv`. `vars` is ordered (`BTreeMap`) so the
/// redacted [`fmt::Display`] prints names sorted, as upstream's
/// `String` does.
#[derive(Clone, Default)]
pub struct LaunchEnv {
    /// The launch environment variables — values are never printed.
    pub vars: BTreeMap<String, String>,
    /// The sandbox scope the process tree runs in, chosen by Central
    /// before the process exists.
    pub sandbox_scope_id: String,
}

impl fmt::Display for LaunchEnv {
    /// Upstream `String`/`GoString`: variable names only, sorted,
    /// never values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.vars.keys().map(String::as_str).collect::<Vec<_>>();
        write!(
            f,
            "port.LaunchEnv{{SandboxScopeID:{} Vars:[{}]}}",
            self.sandbox_scope_id,
            names.join(" ")
        )
    }
}

impl fmt::Debug for LaunchEnv {
    /// Matches `Display` — upstream `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Harness-native limits, passed only when an adapter supports them
/// (governing spec §13) — upstream `port.Limits`. A zero field means
/// no native limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// The harness-enforced turn limit.
    pub max_turns: i64,
    /// The harness-enforced cost limit, in micro-USD. The orchestrator
    /// sets it only when the adapter declares
    /// [`Capabilities::native_cost_limit`]; an adapter that does not
    /// declare it refuses a positive value in `start` (harness phase
    /// 3d decision 5).
    pub max_cost_micro_usd: i64,
}

/// Everything an adapter needs to start or resume a session —
/// upstream `port.StartSpec`. `prompt` is sensitive and never printed.
#[derive(Clone)]
pub struct StartSpec {
    /// The attempt this session serves.
    pub attempt: HarnessAttemptId,
    /// The execution-lease fence the attempt runs under.
    pub fence: Fence,
    /// The worktree the harness runs in.
    pub workspace: Workspace,
    /// The prompt — operator-authored, passed verbatim, never printed.
    pub prompt: String,
    /// The model — passed verbatim when set.
    pub model: String,
    /// The operator-chosen permission policy.
    pub permission: PermissionPolicy,
    /// The harness-native limits.
    pub limits: Limits,
    /// The launch environment and sandbox scope.
    pub env: LaunchEnv,
}

impl StartSpec {
    /// Upstream `StartSpec.Validate`: checks the spec against the
    /// adapter's declared `env_extras`.
    pub fn validate(&self, env_extras: &[&str]) -> Result<(), Failure> {
        let invalid = |msg: &str| Failure::invalid(codes::INVALID_START_SPEC, msg.to_string());
        if self.attempt.is_nil() {
            return Err(invalid("zero attempt"));
        }
        if self.fence.generation < 1 {
            return Err(invalid("fence generation must be >= 1"));
        }
        if self.workspace.path.is_empty() {
            return Err(invalid("workspace path is required"));
        }
        if self.env.sandbox_scope_id.is_empty() {
            return Err(invalid("sandbox scope id is required"));
        }
        if !self.permission.known() {
            return Err(invalid("unknown permission policy"));
        }
        if self.prompt.is_empty() {
            return Err(invalid("prompt is required"));
        }
        if self.limits.max_turns < 0 {
            return Err(invalid("MaxTurns must be >= 0"));
        }
        if self.limits.max_cost_micro_usd < 0 {
            return Err(invalid("MaxCostMicroUSD must be >= 0"));
        }
        validate_launch_env(&self.env.vars, env_extras)
    }
}

impl fmt::Display for StartSpec {
    /// Upstream `String`/`GoString`: never the prompt or env values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "port.StartSpec{{Attempt:{} Permission:{} Prompt:<redacted {} bytes> Env:<{} vars>}}",
            self.attempt,
            self.permission,
            self.prompt.len(),
            self.env.vars.len()
        )
    }
}

impl fmt::Debug for StartSpec {
    /// Matches `Display` — upstream `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Harness availability without starting a session — upstream
/// `port.ProbeResult`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeResult {
    /// The installed harness binary's version.
    pub harness_version: String,
    /// Whether the harness is authenticated for use.
    pub authenticated: bool,
    /// A short human detail line.
    pub detail: String,
}

/// Identifies an attempt to inspect after a restart — upstream
/// `port.ReconcileInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileInput {
    /// The attempt to inspect.
    pub attempt: HarnessAttemptId,
    /// The sandbox scope the process tree ran in.
    pub sandbox_scope_id: String,
    /// The harness-owned session id, once revealed.
    pub harness_session_id: String,
    /// The last event seq recorded.
    pub last_event_seq: u64,
}

/// What is knowable about an attempt after a restart — upstream
/// `port.ReconcileResult`. The caller, not the adapter, decides
/// whether the attempt becomes ambiguous.
pub struct ReconcileResult {
    /// Whether the sandbox scope still has live processes.
    pub scope_alive: bool,
    /// A session reattached to the still-live harness, when the
    /// adapter can drive one.
    pub reattached: Option<Box<dyn Session>>,
    /// The terminal the adapter can prove the session reached, if it
    /// can prove one.
    pub terminal: Option<Terminal>,
}

impl fmt::Debug for ReconcileResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconcileResult")
            .field("scope_alive", &self.scope_alive)
            .field("reattached", &self.reattached.is_some())
            .field("terminal", &self.terminal)
            .finish()
    }
}

/// Operator-authored follow-up text — upstream `port.OperatorInput`.
/// `text` is sensitive.
#[derive(Clone)]
pub struct OperatorInput {
    /// The follow-up text — never printed.
    pub text: String,
}

impl fmt::Display for OperatorInput {
    /// Upstream `String`/`GoString`: never `text`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "port.OperatorInput{{Text:<redacted {} bytes>}}",
            self.text.len()
        )
    }
}

impl fmt::Debug for OperatorInput {
    /// Matches `Display` — upstream `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The operator's (or operator policy's) answer — upstream
/// `port.PermissionDecision`.
///
/// `input_sha256` binds an allow to the input the operator was shown
/// (harness phase 3c decision 8): it is the SHA-256 of the
/// `PermissionRequested.input` bytes the decision answers. An adapter
/// recomputes the digest over the exact bytes it echoes to the
/// harness and refuses an allow on any mismatch with
/// [`codes::PERMISSION_BINDING`]. A deny echoes no input and needs no
/// binding. The durable record keeps only a keyed MAC of the input;
/// this unkeyed digest lives in memory, between the orchestrator and
/// the adapter.
#[derive(Clone)]
pub struct PermissionDecision {
    /// The harness permission request id being answered.
    pub request_id: String,
    /// `true` to allow, `false` to deny.
    pub allow: bool,
    /// The harness option id the operator chose, when the request
    /// offered options.
    pub option_id: String,
    /// Who decided — an `operator_session:*` decider or a policy.
    pub decided_by: String,
    /// SHA-256 of the input bytes an allow binds — see the type docs.
    pub input_sha256: [u8; 32],
}

impl fmt::Display for PermissionDecision {
    /// Upstream `String`/`GoString`: never prints the input digest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "port.PermissionDecision{{RequestID:{} Allow:{} DecidedBy:{}}}",
            self.request_id, self.allow, self.decided_by
        )
    }
}

impl fmt::Debug for PermissionDecision {
    /// Matches `Display` — upstream `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Drives one kind of harness — upstream `port.Adapter`. Hand-written
/// `dyn`-compatible (see [`PortFuture`]): `start`, `resume` and
/// `reconcile` hand back `Box<dyn Session>`.
pub trait Adapter: Send + Sync + 'static {
    /// The adapter's harness kind.
    fn kind(&self) -> Kind;

    /// What the adapter declares it can do.
    fn capabilities(&self) -> Capabilities;

    /// The launch-env names this adapter needs beyond the base
    /// allowlist — upstream `EnvExtras`. Each must still pass
    /// [`validate_launch_env`]'s denylist.
    fn env_extras(&self) -> &[String];

    /// Reports harness availability without starting a session —
    /// upstream `Probe`.
    fn probe<'a>(&'a self, env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>>;

    /// Starts a fresh session — upstream `Start`.
    fn start<'a>(&'a self, spec: StartSpec) -> PortFuture<'a, Result<Box<dyn Session>, Failure>>;

    /// Resumes a harness-owned session — upstream `Resume`.
    fn resume<'a>(
        &'a self,
        session_ref: SessionRef,
        spec: StartSpec,
    ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>>;

    /// Inspects an attempt after a control-plane restart — upstream
    /// `Reconcile`. It never relaunches.
    fn reconcile<'a>(
        &'a self,
        input: ReconcileInput,
    ) -> PortFuture<'a, Result<ReconcileResult, Failure>>;
}

/// One live harness session — upstream `port.Session`. Hand-written
/// `dyn`-compatible (see [`PortFuture`]).
///
/// `session_ref` and `next_event` are the Rust form of upstream's
/// `Ref()` and `Events()` channels: each pull awaits the next value,
/// and `None` is the closed channel. The channel could never carry an
/// error upstream, so neither can these.
pub trait Session: Send + Sync + 'static {
    /// Upstream `Ref() <-chan SessionRef`: resolves once the harness
    /// reveals its session id; `None` when the session ended before
    /// revealing it.
    fn session_ref(&self) -> PortFuture<'_, Option<SessionRef>>;

    /// Upstream `Events() <-chan harness.Event`: the next normalized
    /// event, `None` once the stream closes after the terminal event.
    /// Callers must keep pulling until `None`, even after `wait`
    /// returns or after `kill`: an adapter may buffer undelivered
    /// events (and their `raw` frames) and keep its delivery alive
    /// until they are read.
    fn next_event(&self) -> PortFuture<'_, Option<Event>>;

    /// Upstream `Send`: delivers operator follow-up input. A send
    /// that races the session's final result is best-effort: the
    /// harness may run another turn whose frames and cost are never
    /// reported, or the line may be dropped when stdin closes.
    fn send<'a>(&'a self, input: OperatorInput) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `Interrupt`: the graceful, harness-native cancel.
    /// [`codes::SESSION_ENDED`] means the session already ended — a
    /// caller treats that as done, never as a reason to kill.
    fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>>;

    /// Upstream `RespondPermission`: answers a pending
    /// `PermissionRequested`. It may return an error after
    /// `PermissionResolved` was already emitted for the decision: the
    /// event stream, not this return value, is the source of truth
    /// for what was decided. [`codes::NO_PENDING_PERMISSION`] is the
    /// benign no-such-pending refusal; [`codes::PERMISSION_BINDING`]
    /// is an allow that does not bind the pending input.
    fn respond_permission<'a>(
        &'a self,
        decision: PermissionDecision,
    ) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `Wait`: blocks until the session's terminal is
    /// knowable.
    fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>>;

    /// Upstream `Kill`: ends the session's process tree.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>>;
}

// ---------------------------------------------------------------------------
// Process and ProcessLauncher — the process boundary
// ---------------------------------------------------------------------------

/// One harness process launch — upstream `port.ProcessSpec` (phase 2a
/// spec decision 2). Adapters never exec: they describe the process
/// and a [`ProcessLauncher`] starts it. `program` is a symbolic name
/// such as `"claude"` that each launcher resolves through its own
/// allowlist. `env` is the complete environment the adapter asks for;
/// the launcher adds only `HOME`, `USER` and `LOGNAME` derived from
/// the target user's passwd entry and inherits nothing. `scope_id` is
/// chosen by Central ([`StartSpec::env`]'s `sandbox_scope_id`) so it
/// is recorded before the process exists. `args` may carry a harness
/// session id but never the prompt; neither `args` nor env values are
/// ever printed.
#[derive(Clone)]
pub struct ProcessSpec {
    /// The symbolic program name.
    pub program: String,
    /// The process arguments — never printed.
    pub args: Vec<String>,
    /// The complete launch environment — values never printed.
    pub env: BTreeMap<String, String>,
    /// The working directory.
    pub work_dir: String,
    /// The sandbox scope the tree runs in.
    pub scope_id: String,
    /// The launching adapter's [`Adapter::env_extras`], so the
    /// launch-env policy admits the adapter's declared extra names.
    /// Adapters with extras must set it; it is validation-only and
    /// never reaches the wire.
    pub env_extras: Vec<String>,
}

impl ProcessSpec {
    /// Upstream `ProcessSpec.Validate`: a program, a scope id and a
    /// workdir, plus the launch-env policy with the spec's extras.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| Failure::invalid(codes::INVALID_PROCESS_SPEC, msg.to_string());
        if self.program.is_empty() {
            return Err(invalid("program is required"));
        }
        if self.scope_id.is_empty() {
            return Err(invalid("scope id is required"));
        }
        if self.work_dir.is_empty() {
            return Err(invalid("workdir is required"));
        }
        let extras: Vec<&str> = self.env_extras.iter().map(String::as_str).collect();
        validate_launch_env(&self.env, &extras)
    }
}

impl fmt::Display for ProcessSpec {
    /// Upstream `String`/`GoString`: the program, scope, workdir, the
    /// number of args and the env names only, sorted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.env.keys().map(String::as_str).collect::<Vec<_>>();
        write!(
            f,
            "port.ProcessSpec{{Program:{} ScopeID:{} WorkDir:{} Args:<{} args> Env:[{}]}}",
            self.program,
            self.scope_id,
            self.work_dir,
            self.args.len(),
            names.join(" ")
        )
    }
}

impl fmt::Debug for ProcessSpec {
    /// Matches `Display` — upstream `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// How a launched process ended — upstream `port.ExitStatus`.
/// `signaled` is `true` when a signal ended it; `code` is then the
/// conventional `128 + signal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExitStatus {
    /// The exit code, or `128 + signal` when `signaled`.
    pub code: i32,
    /// Whether a signal ended the process.
    pub signaled: bool,
}

/// One launched harness process tree — upstream `port.Process`.
/// Hand-written `dyn`-compatible (see [`PortFuture`]): `launch`
/// returns `Box<dyn Process>`.
///
/// `write_stdin`/`close_stdin` are the `Stdin() io.WriteCloser` half;
/// `read_stdout`/`read_stderr` are the `Stdout()`/`Stderr()`
/// `io.Reader`s: each pulls at most `buf.len()` bytes and `Ok(0)` is
/// the reader's EOF — reached once every process of the tree has
/// closed the stream; the caller must drain both.
pub trait Process: Send + Sync + 'static {
    /// The sandbox scope this process tree runs in.
    fn scope_id(&self) -> &str;

    /// Writes to the harness's stdin — the `io.Writer` half of
    /// upstream's `Stdin()`. Returns the number of bytes accepted.
    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>>;

    /// Closes the harness's stdin — upstream
    /// `io.WriteCloser.Close`. Idempotent.
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>>;

    /// Reads from the harness's stdout — upstream `Stdout()`.
    /// `Ok(0)` at EOF.
    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>>;

    /// Reads from the harness's stderr — upstream `Stderr()`.
    /// `Ok(0)` at EOF.
    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>>;

    /// Upstream `Wait`: blocks until the process has exited. It never
    /// closes stdout or stderr.
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>>;

    /// Upstream `Kill`: ends the whole process tree — a graceful
    /// signal, a grace period, then a forced kill, then the leader is
    /// reaped. The ladder always runs to completion, even if the
    /// caller's deadline ends first: a deadline bounds only how long
    /// `kill` waits for it to return, never whether the forced kill
    /// is sent. Repeated calls wait for the same ladder.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>>;
}

/// Starts harness processes — upstream `port.ProcessLauncher`.
/// Hand-written `dyn`-compatible (see [`PortFuture`]): `launch`
/// returns `Box<dyn Process>`.
/// Implementations resolve [`ProcessSpec::program`] through their own
/// allowlist, never through `PATH` lookup.
///
/// An adapter may launch several processes one after another under
/// the same scope id: the Claude Code adapter runs its `--version`
/// probe and then the session under the attempt's scope, and probe
/// runs two commands under one scope. A launcher must therefore admit
/// a new `launch` under a scope once the previous process tree of
/// that scope is gone (it may refuse one while that tree still runs).
pub trait ProcessLauncher: Send + Sync + 'static {
    /// Upstream `Launch`: starts one process tree.
    fn launch<'a>(&'a self, spec: ProcessSpec)
    -> PortFuture<'a, Result<Box<dyn Process>, Failure>>;

    /// Upstream `Alive`: whether any process of the scope is still
    /// running, whichever launch under the scope started it — it may
    /// briefly report a probe that runs before the session.
    fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>>;

    /// Upstream `KillScope`: ends every process of the scope,
    /// whichever launch started it, without holding a [`Process`]
    /// handle (harness phase 3a decision 9: after a restart the
    /// dispatcher kills a survivor of an ambiguous attempt). A scope
    /// with no process, or one this launcher never started, is
    /// already empty: `kill_scope` returns `Ok(())`.
    fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>>;
}

// ---------------------------------------------------------------------------
// Attempt and approval stores — the durable boundary
// ---------------------------------------------------------------------------

/// Asks [`AttemptStore::save`] or [`AttemptStore::append_event`] to
/// open a pending permission approval atomically with the attempt
/// entering `awaiting_permission` (harness phase 3c decision 16) —
/// upstream `port.ApprovalOpen`. The id is chosen by the caller
/// before any retry, so a replayed write stays consistent.
/// `requested_at` is the attempt write's `updated_at`; the workspace,
/// attempt and run are the attempt's.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalOpen {
    /// The approval's id, chosen before any retry.
    pub id: HarnessPermissionApprovalId,
    /// The task the attempt serves.
    pub task_id: TaskId,
    /// The harness's permission request id.
    pub request_id: String,
    /// The tool call the request is about.
    pub tool_call_id: String,
    /// The tool name.
    pub tool: String,
    /// The keyed MAC of the input the operator will see.
    pub input_mac: InputMac,
    /// The input's size in bytes.
    pub input_size: i64,
    /// When the request times out.
    pub expires_at: OffsetDateTime,
}

impl ApprovalOpen {
    /// Upstream `ApprovalOpen.Approval`: the pending approval `self`
    /// opens for the attempt `next`.
    pub fn approval(&self, next: &Attempt) -> Result<PermissionApproval, Failure> {
        PermissionApproval::open(OpenApprovalInput {
            id: self.id,
            workspace_id: next.workspace_id,
            attempt_id: next.id,
            task_id: self.task_id,
            run_id: next.run_id,
            request_id: self.request_id.clone(),
            tool_call_id: self.tool_call_id.clone(),
            tool_name: self.tool.clone(),
            input_mac: self.input_mac,
            input_size: self.input_size,
            requested_at: next.updated_at,
            expires_at: self.expires_at,
        })
    }
}

/// Upstream `OpensApproval`: whether moving `expected` to `next` may
/// open a pending approval for `request_id` — `next` enters
/// `awaiting_permission` with `request_id` as a new
/// `pending_permission`.
#[must_use]
pub fn opens_approval(expected: &Attempt, next: &Attempt, request_id: &str) -> bool {
    next.state == State::AwaitingPermission
        && next.pending_permission == request_id
        && !request_id.is_empty()
        && (expected.state != State::AwaitingPermission
            || expected.pending_permission != request_id)
}

/// Upstream `SupersedesApprovals`: whether a write of `next` closes
/// the attempt's pending approval (decision 11) — `next` is terminal
/// or ambiguous.
#[must_use]
pub fn supersedes_approvals(next: &Attempt) -> bool {
    next.state.is_terminal() || next.state == State::Ambiguous
}

/// An operator's decision on one approval — upstream
/// `port.DecidePermissionRequest` (decision 8). `decided_by` is
/// [`crate::approval::operator_decider`] of the session's principal;
/// `input_mac` is the MAC the operator's page was rendered with.
#[derive(Debug, Clone, PartialEq)]
pub struct DecidePermissionRequest {
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The approval being decided.
    pub approval_id: HarnessPermissionApprovalId,
    /// `true` to allow, `false` to deny.
    pub allow: bool,
    /// The MAC the operator's page was rendered with.
    pub input_mac: InputMac,
    /// The operator-session decider.
    pub decided_by: String,
}

/// The banner's read — upstream `port.PendingApprovalSummary`
/// (decision 13): how many approvals of a workspace are pending, and
/// the task of the oldest one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingApprovalSummary {
    /// The number of pending approvals.
    pub count: usize,
    /// The task of the oldest pending approval; `None` when none are
    /// pending (upstream's zero `TaskID`).
    pub oldest_task_id: Option<TaskId>,
}

/// `port.MaxApprovalHistory` — bounds one `approval_history` read.
pub const MAX_APPROVAL_HISTORY: usize = 20;

/// Persists harness session attempts and their event records —
/// upstream `port.AttemptStore` (phase 1b design §7). Writes
/// compare-and-swap on the attempt's store-owned `version` and its
/// fence; failures carry the harness sentinels
/// ([`crate::domain::codes`]' `ATTEMPT_NOT_FOUND`, `VERSION_CONFLICT`,
/// `FENCE_MISMATCH`, `LIVE_ATTEMPT_EXISTS`, `EVENT_CONFLICT`,
/// `INVALID_ATTEMPT`, `INVALID_EVENT`, `INVALID_APPROVAL`,
/// `NO_PENDING_APPROVAL`), never driver types. Hand-written
/// `dyn`-compatible (see [`PortFuture`]): [`LeaseBinder::with_lease`]
/// returns `Box<dyn AttemptStore>`.
pub trait AttemptStore: Send + Sync + 'static {
    /// Upstream `Create`: inserts a new attempt with `version` 0.
    /// Retrying a create of an `equal` attempt succeeds; a different
    /// attempt under the same id is `VERSION_CONFLICT`, a second live
    /// attempt for the run is `LIVE_ATTEMPT_EXISTS`, and an unknown
    /// run or resume target is `INVALID_ATTEMPT`.
    fn create<'a>(&'a self, attempt: &'a Attempt) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `Load`: the stored attempt or `ATTEMPT_NOT_FOUND`.
    fn load<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<Attempt, Failure>>;

    /// Upstream `LiveAttemptForRun`: the run's live (non-terminal)
    /// attempt, if any.
    fn live_attempt_for_run<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<Attempt>, Failure>>;

    /// Upstream `Save`: replaces `expected` with `next` (`next`
    /// carries the same store-owned `version`) and returns the stored
    /// attempt at `version + 1`, in one transaction. `expected`'s
    /// stored version and fence must still stand — a missing row is
    /// `ATTEMPT_NOT_FOUND`, another writer's revision
    /// `VERSION_CONFLICT`, a superseded fence `FENCE_MISMATCH`. Save
    /// never moves the event cursor or usage: only `append_event`
    /// may, atomically with the event row it records.
    ///
    /// Harness phase 3c decisions 11 and 16: each [`ApprovalOpen`] in
    /// `open` opens a pending permission approval in the same
    /// transaction; it is refused unless `next` enters
    /// `awaiting_permission` with a new `pending_permission` equal to
    /// its `request_id` (see [`opens_approval`]). A write that moves
    /// the attempt to a terminal state or to ambiguous supersedes its
    /// pending approval, if any, in the same transaction (see
    /// [`supersedes_approvals`]).
    fn save<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
        open: &'a [ApprovalOpen],
    ) -> PortFuture<'a, Result<Attempt, Failure>>;

    /// Upstream `AppendEvent`: records `rec` and applies `save`'s
    /// compare-and-swap, and `save`'s approval rules, in one
    /// transaction. `next` must carry `rec`'s seq as its cursor,
    /// strictly after `expected`'s. Replaying an already-recorded
    /// `(attempt_id, seq)` returns the currently stored attempt
    /// without writing anything — the `ON CONFLICT DO NOTHING`
    /// semantics, the approval included — while the same seq under a
    /// different frame digest is `EVENT_CONFLICT`.
    fn append_event<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
        rec: &'a EventRecord,
        open: &'a [ApprovalOpen],
    ) -> PortFuture<'a, Result<Attempt, Failure>>;

    /// Upstream `ExpirePermission`: the approval timeout's
    /// compare-and-set (decision 9). Under `attempt`'s fence — and
    /// the bound lease when the store is lease-bound — the pending
    /// approval `id` of `attempt` becomes expired by `policy:timeout`
    /// once its expiry has passed on the database clock. It returns
    /// the approval as it stands afterwards: an operator decision
    /// that won the race, or a still pending approval that is not due
    /// yet, is returned as is. An unknown approval is
    /// `NO_PENDING_APPROVAL`.
    fn expire_permission<'a>(
        &'a self,
        attempt: &'a Attempt,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>>;

    /// Upstream `LoadApproval`: one approval of the workspace in its
    /// current state, or `NO_PENDING_APPROVAL` when there is none.
    fn load_approval<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>>;
}

/// The operator side of permission approvals — upstream
/// `port.ApprovalStore`: the decision compare-and-set and the
/// workspace-scoped reads the web pages render. Every method is
/// scoped to one workspace. Hand-written `dyn`-compatible (see
/// [`PortFuture`]).
pub trait ApprovalStore: Send + Sync + 'static {
    /// Upstream `DecidePermission`: the operator's compare-and-set
    /// (decision 8) — `pending` → `allowed` or `denied`, in one
    /// statement that also requires the approval unexpired, the
    /// attempt `awaiting_permission` on its request id, the posted
    /// MAC equal to the stored one, and an unexpired execution lease
    /// claiming the run at the attempt's fence. Anything else matches
    /// no row: `NO_PENDING_APPROVAL`.
    fn decide_permission<'a>(
        &'a self,
        request: DecidePermissionRequest,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>>;

    /// Upstream `LoadApproval`: one approval, or
    /// `NO_PENDING_APPROVAL`.
    fn load_approval<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>>;

    /// Upstream `PendingApprovalForRun`: the run's pending approval,
    /// if any.
    fn pending_approval_for_run<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<PermissionApproval>, Failure>>;

    /// Upstream `PendingApprovals`: summarizes the workspace's
    /// pending approvals.
    fn pending_approvals<'a>(
        &'a self,
        workspace_id: WorkspaceId,
    ) -> PortFuture<'a, Result<PendingApprovalSummary, Failure>>;

    /// Upstream `ApprovalHistory`: up to `limit`
    /// (`1..=MAX_APPROVAL_HISTORY`) of the run's approvals, newest
    /// first.
    fn approval_history<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<PermissionApproval>, Failure>>;
}

/// The run's live execution lease an orchestrator holds — upstream
/// `port.ExecutionLease` (harness phase 3a decision 3): the fencing
/// generation it uses as the attempt's [`Fence`] and the raw lease
/// bearer. The bearer is never printed and never stored; a store
/// compares only its SHA-256.
#[derive(Clone, Copy)]
pub struct ExecutionLease {
    /// The fencing generation; must be at least 1.
    pub generation: i64,
    /// The raw lease bearer — never printed, never stored.
    pub credential: [u8; 32],
}

impl ExecutionLease {
    /// Upstream `ExecutionLease.Validate`: a generation of at least 1
    /// and a non-zero bearer.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.generation < 1 || self.credential == [0; 32] {
            return Err(Failure::invalid(
                crate::domain::codes::INVALID_ATTEMPT,
                "execution lease requires a generation and a bearer",
            ));
        }
        Ok(())
    }

    /// Upstream `ExecutionLease.Fence`: the harness fence this lease
    /// authorizes.
    #[must_use]
    pub fn fence(&self) -> Fence {
        Fence {
            generation: self.generation,
        }
    }
}

impl fmt::Display for ExecutionLease {
    /// Upstream `String`/`GoString`: never the bearer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "port.ExecutionLease{{Generation:{} Credential:<redacted>}}",
            self.generation
        )
    }
}

impl fmt::Debug for ExecutionLease {
    /// Matches `Display` — upstream `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Upstream `port.LeaseBinder`: returns an [`AttemptStore`] whose
/// every write (`create`, `save`, `append_event`) is validated, in
/// the same transaction, against the run's live execution lease: the
/// ownership row's generation equals the attempt's fence and the
/// lease's generation, it is unexpired, its token hash matches the
/// bearer's SHA-256, and it claims the StepAttempt linked to the
/// attempt ([`crate::recovery::attempt_id_for_step_attempt`]). A
/// failed check is `FENCE_MISMATCH` and writes nothing.
pub trait LeaseBinder: Send + Sync + 'static {
    /// Upstream `WithLease` — synchronous: binding performs no I/O;
    /// the lease is re-checked inside every write's transaction.
    fn with_lease(&self, lease: ExecutionLease) -> Box<dyn AttemptStore>;
}

vocab! {
    /// The state of the execution StepAttempt a harness attempt is
    /// linked to (same id), as the recovery reconciler sees it —
    /// upstream `port.LinkedStepAttemptState`. The values are the
    /// execution domain's attempt states; `Unset` stands for
    /// `LinkedMissing` (`""`): no linked StepAttempt exists.
    LinkedStepAttemptState {
        /// `prepared`.
        Prepared => "prepared",
        /// `invoked`.
        Invoked => "invoked",
        /// `settling`.
        Settling => "settling",
        /// `succeeded`.
        Succeeded => "succeeded",
        /// `failed`.
        Failed => "failed",
        /// `cancelled`.
        Cancelled => "cancelled",
        /// `reconciliation`.
        Reconciliation => "reconciliation",
        /// `resumed` — the linked StepAttempt is `failed` AND a
        /// StepAttempt of the same run names it as `predecessor_id`
        /// (only a resume makes that; B08 predecessors are
        /// cancelled). Reported instead of `Failed` (harness phase 3g
        /// decision 6).
        Resumed => "resumed",
    }
}

/// One non-terminal harness attempt (ambiguous included) with its
/// linked StepAttempt's state and whether a live execution lease
/// still claims that StepAttempt — upstream `port.RecoveryCandidate`.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryCandidate {
    /// The non-terminal attempt.
    pub attempt: Attempt,
    /// The linked StepAttempt's state.
    pub step_state: LinkedStepAttemptState,
    /// Whether an unexpired lease claims the linked StepAttempt.
    pub lease_live: bool,
}

/// A keyset position over `(prepared_at, id)` — upstream
/// `port.RecoveryCursor`. The zero value
/// ([`RecoveryCursor::default`]: the zero time and a nil id) starts
/// from the beginning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCursor {
    /// The `prepared_at` at the page boundary.
    pub prepared_at: OffsetDateTime,
    /// The attempt id at the page boundary.
    pub id: HarnessAttemptId,
}

impl Default for RecoveryCursor {
    /// The zero cursor — starts the scan from the beginning.
    fn default() -> Self {
        Self {
            prepared_at: ZERO_TIME,
            id: HarnessAttemptId::from_trusted_db_bytes([0; 16]),
        }
    }
}

/// `port.MaxRecoveryCandidates` — bounds one
/// `list_recovery_candidates` page.
pub const MAX_RECOVERY_CANDIDATES: usize = 200;

/// The harness phase 3a decision 9 recovery authority — upstream
/// `port.RecoveryStore`. Hand-written `dyn`-compatible (see
/// [`PortFuture`]). It never uses a fence: `recover_attempt`
/// instead checks, in one transaction, that the attempt's linked
/// StepAttempt is no longer lease-live (it is `reconciliation`,
/// `succeeded`, `failed` or `cancelled`, and no unexpired lease
/// claims it). It is used by the DB-only startup reconciler after
/// B08 recovery and by the operator resolve action.
pub trait RecoveryStore: Send + Sync + 'static {
    /// Upstream `ListRecoveryCandidates`: up to `limit` non-terminal
    /// attempts across every workspace after `after`, ordered by
    /// `(prepared_at, id)` — keyset-ordered bounded pages.
    fn list_recovery_candidates<'a>(
        &'a self,
        after: RecoveryCursor,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<RecoveryCandidate>, Failure>>;

    /// Upstream `RecoverAttempt`: replaces `expected` with `next` and
    /// returns the stored attempt at `version + 1`. `next` must keep
    /// `expected`'s fence, event cursor and usage, and be one of:
    /// ambiguous; a terminal (`succeeded`, `failed`, `interrupted`,
    /// `killed`, `budget_exhausted`); resolved with
    /// `ResolutionKind::Abandon`; resolved with
    /// `ResolutionKind::Resume`, only when the linked StepAttempt is
    /// [`LinkedStepAttemptState::Resumed`]; or resolved with
    /// `ResolutionKind::Rerun`, only when the linked StepAttempt is
    /// [`LinkedStepAttemptState::Failed`] and its task names another
    /// run as current (a retry replaced the attempt's run, harness
    /// phase 3k decision 4); otherwise `INVALID_TRANSITION`. A
    /// lease-live or missing linked StepAttempt is
    /// `RECOVERY_NOT_AUTHORIZED`.
    fn recover_attempt<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
    ) -> PortFuture<'a, Result<Attempt, Failure>>;
}

// ---------------------------------------------------------------------------
// Tests — port of internal/harness/port/{port,launcher,decision}_test.go,
// plus the in-memory `memStore`/`scriptedLauncher` contract fakes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use central_foundation::identity::{HarnessPermissionApprovalId, TaskId, WorkspaceId};
    use sha2::{Digest, Sha256};
    use time::Duration;

    use super::*;
    use crate::approval::{self, ApprovalState, InputMac};
    use crate::attempt::PrepareInput;
    use crate::domain::{PermissionPolicy, TerminalStatus, codes as domain_codes};
    use crate::event::{Event, EventPayload, Message, MessageRole};
    use crate::testkit::{
        FENCE, Mutation, block_on, is_code, nil_attempt_id, ok, prepare_input, t0,
    };

    // Ports upstream `validSpec`.
    fn valid_spec() -> StartSpec {
        StartSpec {
            attempt: HarnessAttemptId::new(),
            fence: FENCE,
            workspace: Workspace {
                path: "/srv/central/worktrees/r1".to_string(),
                base_sha: "abc123".to_string(),
            },
            prompt: "fix the failing test".to_string(),
            model: String::new(),
            permission: PermissionPolicy::Deny,
            limits: Limits::default(),
            env: LaunchEnv {
                vars: BTreeMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
                sandbox_scope_id: "scope-1".to_string(),
            },
        }
    }

    // Ports upstream `TestStartSpecValidate`.
    #[test]
    fn start_spec_validate() {
        assert!(valid_spec().validate(&[]).is_ok(), "valid spec");
        let mutations: [Mutation<StartSpec>; 8] = [
            ("zero attempt", |s| s.attempt = nil_attempt_id()),
            ("zero fence", |s| s.fence = Fence { generation: 0 }),
            ("no workspace", |s| s.workspace.path = String::new()),
            ("bad permission", |s| {
                s.permission = PermissionPolicy::parse("maybe")
            }),
            ("empty prompt", |s| s.prompt = String::new()),
            ("negative turns", |s| s.limits.max_turns = -1),
            ("negative cost", |s| s.limits.max_cost_micro_usd = -1),
            ("no sandbox", |s| s.env.sandbox_scope_id = String::new()),
        ];
        for (name, mutate) in mutations {
            let mut s = valid_spec();
            mutate(&mut s);
            let err = s.validate(&[]).unwrap_err();
            assert!(is_code(&err, codes::INVALID_START_SPEC), "{name}: {err}");
        }
    }

    // Ports upstream `TestStartSpecAcceptsANativeCostLimit` (harness
    // phase 3d decision 5): whether the adapter supports the limit is
    // the adapter's and the orchestrator's check, not the spec's.
    #[test]
    fn start_spec_accepts_a_native_cost_limit() {
        for limit in [0i64, 1, 2_500_000, 1_000_000_000] {
            let mut s = valid_spec();
            s.limits.max_cost_micro_usd = limit;
            assert!(s.validate(&[]).is_ok(), "MaxCostMicroUSD {limit}");
        }
    }

    // Ports upstream `TestErrSessionEndedIsAPortSentinel`: the codes a
    // `Failure` carries stand in for the sentinels, so they must be
    // distinct.
    #[test]
    fn port_sentinels_are_distinct() {
        assert_ne!(codes::SESSION_ENDED, codes::NO_PENDING_PERMISSION);
        assert_ne!(codes::NO_PENDING_PERMISSION, codes::PERMISSION_BINDING);
        assert_ne!(codes::PERMISSION_BINDING, codes::NO_PENDING_PERMISSION);
        let err = Failure::conflict(codes::SESSION_ENDED, "adapter: session has ended");
        assert!(is_code(&err, codes::SESSION_ENDED));
        assert!(!is_code(&err, codes::NO_PENDING_PERMISSION));
    }

    // Ports upstream `TestStartSpecEnforcesLaunchEnvPolicy`.
    #[test]
    fn start_spec_enforces_launch_env_policy() {
        let mut s = valid_spec();
        s.env
            .vars
            .insert("ANTHROPIC_API_KEY".to_string(), "sk-ant-secret".to_string());
        let err = s.validate(&[]).unwrap_err();
        assert!(
            is_code(&err, domain_codes::FORBIDDEN_LAUNCH_ENV),
            "credential env accepted: {err}"
        );
        assert!(
            !err.message().contains("sk-ant-secret"),
            "error leaked an env value: {err}"
        );
        let mut s = valid_spec();
        s.env.vars.insert("EDITOR".to_string(), "vi".to_string());
        s.validate(&["EDITOR"]).unwrap();
    }

    // Ports upstream `TestStartSpecNeverPrintsPromptOrEnvValues`.
    #[test]
    fn start_spec_never_prints_prompt_or_env_values() {
        let mut s = valid_spec();
        s.prompt = "secret-prompt-body".to_string();
        s.env
            .vars
            .insert("LANG".to_string(), "secret-env-value".to_string());
        for out in [format!("{s}"), format!("{s:?}"), format!("{s:#?}")] {
            assert!(
                !out.contains("secret-prompt-body") && !out.contains("secret-env-value"),
                "sensitive content printed: {out}"
            );
        }
    }

    // Ports upstream `TestLaunchEnvAndOperatorInputNeverPrintValues`.
    #[test]
    fn launch_env_and_operator_input_never_print_values() {
        let env = LaunchEnv {
            vars: BTreeMap::from([
                ("ANTHROPIC_API_KEY".to_string(), "sk-ant-leak".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
            ]),
            sandbox_scope_id: "scope-1".to_string(),
        };
        let input = OperatorInput {
            text: "secret-follow-up".to_string(),
        };
        for out in [
            format!("{env}"),
            format!("{env:?}"),
            format!("{env:#?}"),
            format!("{input}"),
            format!("{input:?}"),
            format!("{input:#?}"),
        ] {
            assert!(
                !out.contains("sk-ant-leak")
                    && !out.contains("/usr/bin")
                    && !out.contains("secret-follow-up"),
                "sensitive content printed: {out}"
            );
        }
        let out = format!("{env}");
        assert!(
            out.contains("ANTHROPIC_API_KEY PATH"),
            "names not listed sorted: {out}"
        );
    }

    // Ports upstream `TestPermissionDecisionNeverPrintsTheInputDigest`.
    #[test]
    fn permission_decision_never_prints_the_input_digest() {
        let digest: [u8; 32] = Sha256::digest(br#"{"command":"ls"}"#).into();
        let d = PermissionDecision {
            request_id: "r1".to_string(),
            allow: true,
            option_id: String::new(),
            decided_by: "operator-session:p".to_string(),
            input_sha256: digest,
        };
        let hex4 = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        );
        for out in [format!("{d}"), format!("{d:?}"), format!("{d:#?}")] {
            assert!(!out.contains(&hex4), "digest printed: {out}");
            assert!(
                out.contains("RequestID:r1") && out.contains("Allow:true"),
                "decision not described: {out}"
            );
        }
    }

    // Ports upstream `TestExecutionLeaseValidate`/`String` (store.go
    // tests pin the same contract through the lease-bound store).
    #[test]
    fn execution_lease_validate_and_redaction() {
        let lease = ExecutionLease {
            generation: 3,
            credential: [7u8; 32],
        };
        assert!(lease.validate().is_ok());
        assert_eq!(lease.fence(), Fence { generation: 3 });
        for bad in [
            ExecutionLease {
                generation: 0,
                credential: [7u8; 32],
            },
            ExecutionLease {
                generation: 3,
                credential: [0; 32],
            },
        ] {
            let err = bad.validate().unwrap_err();
            assert!(is_code(&err, domain_codes::INVALID_ATTEMPT));
        }
        let secret = format!("{:02x}", 7u8);
        for out in [format!("{lease}"), format!("{lease:?}")] {
            assert!(out.contains("Generation:3"), "{out}");
            assert!(!out.contains(&secret.repeat(2)), "bearer printed: {out}");
        }
    }

    // Ports upstream `OpensApproval`/`SupersedesApprovals` truth table
    // (exercised through the postgres store tests).
    #[test]
    fn approval_write_predicates() {
        let prepared = ok(Attempt::prepare(prepare_input()));
        let running = ok(prepared
            .launch(FENCE, "scope-1", "2.1.0", t0())
            .and_then(|a| a.reveal_session(FENCE, "sess-1", t0())));
        let awaiting = ok(running.await_permission(FENCE, "perm-1", t0()));
        assert!(opens_approval(&running, &awaiting, "perm-1"));
        assert!(!opens_approval(&awaiting, &awaiting, "perm-1"));
        assert!(!opens_approval(&running, &awaiting, "perm-2"));
        assert!(!opens_approval(&running, &awaiting, ""));
        assert!(!opens_approval(&running, &running, "perm-1"));
        assert!(!supersedes_approvals(&running));
        assert!(!supersedes_approvals(&awaiting));
        let failed = ok(awaiting.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Failed,
                ..Terminal::default()
            },
            t0() + Duration::seconds(1),
        ));
        assert!(supersedes_approvals(&failed));
        let ambiguous = ok(awaiting.mark_ambiguous(FENCE, "lost", t0() + Duration::seconds(1)));
        assert!(supersedes_approvals(&ambiguous));
    }

    // --- memStore: an in-memory AttemptStore/ApprovalStore/LeaseBinder
    // exercising the durable contract (CAS on version+fence,
    // live-attempt uniqueness, event replay on (attempt_id, seq), the
    // approval open/supersede rules and the lease fence check). The
    // ownership-row half of the lease check — the unexpired
    // execution_ownership row claiming the linked StepAttempt — has no
    // in-memory analogue; T3's PostgreSQL tests cover it.

    struct MemInner {
        attempts: HashMap<HarnessAttemptId, Attempt>,
        events: HashMap<(HarnessAttemptId, u64), EventRecord>,
        approvals: HashMap<HarnessPermissionApprovalId, PermissionApproval>,
        db_now: OffsetDateTime,
    }

    impl Default for MemInner {
        fn default() -> Self {
            Self {
                attempts: HashMap::new(),
                events: HashMap::new(),
                approvals: HashMap::new(),
                db_now: ZERO_TIME,
            }
        }
    }

    struct MemStore {
        inner: Arc<Mutex<MemInner>>,
        lease: Option<ExecutionLease>,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(MemInner::default())),
                lease: None,
            }
        }

        fn set_db_now(&self, at: OffsetDateTime) {
            self.inner.lock().unwrap().db_now = at;
        }

        // Simulates another writer refencing the stored attempt
        // out-of-band: the CAS must refuse the stale caller's fence.
        fn refence_stored(&self, id: HarnessAttemptId, generation: i64) {
            if let Some(a) = self.inner.lock().unwrap().attempts.get_mut(&id) {
                a.fence = Fence { generation };
            }
        }

        // The write path's lease fence check (port.LeaseBinder docs):
        // a bound store refuses an attempt whose fence is not the
        // lease's generation. The bearer-hash and ownership-row halves
        // belong to a durable implementation.
        fn assert_lease(&self, a: &Attempt) -> Result<(), Failure> {
            let Some(lease) = &self.lease else {
                return Ok(());
            };
            lease.validate()?;
            if a.fence.generation != lease.generation {
                return Err(Failure::conflict(
                    domain_codes::FENCE_MISMATCH,
                    format!(
                        "attempt fence {} is not the bound lease generation",
                        a.fence.generation
                    ),
                ));
            }
            Ok(())
        }

        // The shared write gate (upstream prepareWrite + lockAttempt +
        // compareAndSwap): returns the attempt as it will be stored.
        fn prepare_write(
            inner: &MemInner,
            expected: &Attempt,
            next: &Attempt,
        ) -> Result<Attempt, Failure> {
            if expected.id != next.id
                || expected.workspace_id != next.workspace_id
                || expected.run_id != next.run_id
            {
                return Err(Failure::invalid(
                    domain_codes::INVALID_ATTEMPT,
                    "next must keep the attempt, workspace and run ids",
                ));
            }
            if next.version != expected.version {
                return Err(Failure::conflict(
                    domain_codes::VERSION_CONFLICT,
                    "next must carry the expected version",
                ));
            }
            if next.budget != expected.budget {
                return Err(Failure::invalid(
                    domain_codes::INVALID_ATTEMPT,
                    "the budget cannot change after prepare",
                ));
            }
            if next.equal(expected) {
                return Err(Failure::invalid(
                    domain_codes::INVALID_ATTEMPT,
                    "next changes nothing",
                ));
            }
            next.validate()?;
            let stored = inner.attempts.get(&expected.id).ok_or_else(|| {
                Failure::not_found(domain_codes::ATTEMPT_NOT_FOUND, "attempt not found")
            })?;
            if stored.version != expected.version {
                return Err(Failure::conflict(
                    domain_codes::VERSION_CONFLICT,
                    format!(
                        "attempt is at version {}, not {}",
                        stored.version, expected.version
                    ),
                ));
            }
            if stored.fence.generation != expected.fence.generation {
                return Err(Failure::conflict(
                    domain_codes::FENCE_MISMATCH,
                    "attempt fence mismatch",
                ));
            }
            let mut out = next.clone();
            out.version = expected.version + 1;
            Ok(out)
        }

        // planApprovalWrite + apply: validates the open set and
        // applies it plus any supersession to `inner`.
        fn apply_approval_write(
            inner: &mut MemInner,
            expected: &Attempt,
            stored_next: &Attempt,
            open: &[ApprovalOpen],
        ) -> Result<(), Failure> {
            if open.len() > 1 {
                return Err(Failure::invalid(
                    domain_codes::INVALID_APPROVAL,
                    "a write opens at most one approval",
                ));
            }
            let mut opened = None;
            if let Some(o) = open.first() {
                if !opens_approval(expected, stored_next, &o.request_id) {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_APPROVAL,
                        "an approval opens only as the attempt starts awaiting its request",
                    ));
                }
                opened = Some(o.approval(stored_next)?);
            }
            if supersedes_approvals(stored_next) {
                for a in inner.approvals.values_mut() {
                    if a.attempt_id == stored_next.id && a.state == ApprovalState::Pending {
                        *a = a.supersede(stored_next.updated_at)?;
                    }
                }
            }
            if let Some(a) = opened {
                inner.approvals.insert(a.id, a);
            }
            Ok(())
        }
    }

    impl AttemptStore for MemStore {
        fn create<'a>(&'a self, attempt: &'a Attempt) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async move {
                attempt.validate()?;
                if attempt.version != 0 {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_ATTEMPT,
                        "create requires version 0",
                    ));
                }
                self.assert_lease(attempt)?;
                let mut inner = self.inner.lock().unwrap();
                if let Some(stored) = inner.attempts.get(&attempt.id) {
                    return if stored.equal(attempt) {
                        Ok(())
                    } else {
                        Err(Failure::conflict(
                            domain_codes::VERSION_CONFLICT,
                            "attempt already exists with different content",
                        ))
                    };
                }
                if !attempt.state.is_terminal()
                    && inner
                        .attempts
                        .values()
                        .any(|a| a.run_id == attempt.run_id && !a.state.is_terminal())
                {
                    return Err(Failure::conflict(
                        domain_codes::LIVE_ATTEMPT_EXISTS,
                        "run already has a live attempt",
                    ));
                }
                inner.attempts.insert(attempt.id, attempt.clone());
                Ok(())
            })
        }

        fn load<'a>(
            &'a self,
            workspace_id: WorkspaceId,
            id: HarnessAttemptId,
        ) -> PortFuture<'a, Result<Attempt, Failure>> {
            Box::pin(async move {
                let inner = self.inner.lock().unwrap();
                match inner.attempts.get(&id) {
                    Some(a) if a.workspace_id == workspace_id => Ok(a.clone()),
                    _ => Err(Failure::not_found(
                        domain_codes::ATTEMPT_NOT_FOUND,
                        format!("attempt {id}"),
                    )),
                }
            })
        }

        fn live_attempt_for_run<'a>(
            &'a self,
            workspace_id: WorkspaceId,
            run: RunId,
        ) -> PortFuture<'a, Result<Option<Attempt>, Failure>> {
            Box::pin(async move {
                let inner = self.inner.lock().unwrap();
                Ok(inner
                    .attempts
                    .values()
                    .find(|a| {
                        a.workspace_id == workspace_id && a.run_id == run && !a.state.is_terminal()
                    })
                    .cloned())
            })
        }

        fn save<'a>(
            &'a self,
            expected: &'a Attempt,
            next: &'a Attempt,
            open: &'a [ApprovalOpen],
        ) -> PortFuture<'a, Result<Attempt, Failure>> {
            Box::pin(async move {
                if next.last_event_seq != expected.last_event_seq || next.usage != expected.usage {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_EVENT,
                        "save must not move the event cursor or usage; use append_event",
                    ));
                }
                self.assert_lease(next)?;
                let mut inner = self.inner.lock().unwrap();
                let stored = Self::prepare_write(&inner, expected, next)?;
                Self::apply_approval_write(&mut inner, expected, &stored, open)?;
                inner.attempts.insert(stored.id, stored.clone());
                Ok(stored)
            })
        }

        fn append_event<'a>(
            &'a self,
            expected: &'a Attempt,
            next: &'a Attempt,
            rec: &'a EventRecord,
            open: &'a [ApprovalOpen],
        ) -> PortFuture<'a, Result<Attempt, Failure>> {
            Box::pin(async move {
                rec.validate()?;
                if rec.attempt != next.id {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_EVENT,
                        "record belongs to another attempt",
                    ));
                }
                if next.last_event_seq != rec.seq || rec.seq <= expected.last_event_seq {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_EVENT,
                        "record seq must be the next cursor, after the expected one",
                    ));
                }
                self.assert_lease(next)?;
                let mut inner = self.inner.lock().unwrap();
                let current = inner.attempts.get(&expected.id).ok_or_else(|| {
                    Failure::not_found(domain_codes::ATTEMPT_NOT_FOUND, "attempt not found")
                })?;
                if let Some(recorded) = inner.events.get(&(rec.attempt, rec.seq)) {
                    // ON CONFLICT DO NOTHING: a replay writes nothing and
                    // returns the currently stored attempt; a conflicting
                    // digest is ErrEventConflict.
                    if recorded.raw_sha256 != rec.raw_sha256 {
                        return Err(Failure::conflict(
                            domain_codes::EVENT_CONFLICT,
                            format!(
                                "attempt {} seq {} was recorded with another frame",
                                rec.attempt, rec.seq
                            ),
                        ));
                    }
                    if current.last_event_seq < rec.seq {
                        return Err(Failure::conflict(
                            domain_codes::EVENT_CONFLICT,
                            "recorded seq is ahead of the attempt's cursor",
                        ));
                    }
                    return Ok(current.clone());
                }
                let stored = Self::prepare_write(&inner, expected, next)?;
                Self::apply_approval_write(&mut inner, expected, &stored, open)?;
                inner.events.insert((rec.attempt, rec.seq), rec.clone());
                inner.attempts.insert(stored.id, stored.clone());
                Ok(stored)
            })
        }

        fn expire_permission<'a>(
            &'a self,
            attempt: &'a Attempt,
            id: HarnessPermissionApprovalId,
        ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
            Box::pin(async move {
                if attempt.workspace_id.is_nil() || attempt.id.is_nil() || id.is_nil() {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_APPROVAL,
                        "expiry needs workspace, attempt and approval ids",
                    ));
                }
                self.assert_lease(attempt)?;
                let mut inner = self.inner.lock().unwrap();
                let stored = inner.attempts.get(&attempt.id).ok_or_else(|| {
                    Failure::not_found(domain_codes::ATTEMPT_NOT_FOUND, "attempt not found")
                })?;
                if stored.fence.generation != attempt.fence.generation {
                    return Err(Failure::conflict(
                        domain_codes::FENCE_MISMATCH,
                        "attempt fence mismatch",
                    ));
                }
                let now = inner.db_now;
                let approval = inner.approvals.get(&id).ok_or_else(|| {
                    Failure::not_found(domain_codes::NO_PENDING_APPROVAL, format!("approval {id}"))
                })?;
                if approval.workspace_id != attempt.workspace_id
                    || approval.attempt_id != attempt.id
                {
                    return Err(Failure::not_found(
                        domain_codes::NO_PENDING_APPROVAL,
                        format!("approval {id}"),
                    ));
                }
                if approval.state == ApprovalState::Pending && approval.expires_at <= now {
                    let expired = approval.expire(now)?;
                    inner.approvals.insert(id, expired.clone());
                    Ok(expired)
                } else {
                    Ok(approval.clone())
                }
            })
        }

        fn load_approval<'a>(
            &'a self,
            workspace_id: WorkspaceId,
            id: HarnessPermissionApprovalId,
        ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
            Box::pin(async move {
                let inner = self.inner.lock().unwrap();
                match inner.approvals.get(&id) {
                    Some(a) if a.workspace_id == workspace_id => Ok(a.clone()),
                    _ => Err(Failure::not_found(
                        domain_codes::NO_PENDING_APPROVAL,
                        format!("approval {id}"),
                    )),
                }
            })
        }
    }

    impl ApprovalStore for MemStore {
        fn decide_permission<'a>(
            &'a self,
            request: DecidePermissionRequest,
        ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
            Box::pin(async move {
                if request.workspace_id.is_nil() || request.approval_id.is_nil() {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_APPROVAL,
                        "a decision needs workspace and approval ids",
                    ));
                }
                if !approval::is_operator_decider(&request.decided_by) {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_APPROVAL,
                        "a decision needs an operator decider",
                    ));
                }
                if request.input_mac.is_zero() {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_APPROVAL,
                        "a decision needs the input MAC",
                    ));
                }
                let mut inner = self.inner.lock().unwrap();
                let now = inner.db_now;
                let a = inner.approvals.get(&request.approval_id);
                let Some(a) = a else {
                    return Err(Failure::not_found(
                        domain_codes::NO_PENDING_APPROVAL,
                        "no pending approval",
                    ));
                };
                let attempt = inner.attempts.get(&a.attempt_id);
                let applies = a.workspace_id == request.workspace_id
                    && a.state == ApprovalState::Pending
                    && a.expires_at > now
                    && a.input_mac.equal(&request.input_mac)
                    && attempt.is_some_and(|at| {
                        at.state == State::AwaitingPermission
                            && at.pending_permission == a.request_id
                    });
                if !applies {
                    return Err(Failure::not_found(
                        domain_codes::NO_PENDING_APPROVAL,
                        "no pending approval",
                    ));
                }
                let decided = a.decide(
                    approval::ApprovalDecision {
                        allow: request.allow,
                        input_mac: request.input_mac,
                        decided_by: request.decided_by.clone(),
                    },
                    now,
                )?;
                inner.approvals.insert(decided.id, decided.clone());
                Ok(decided)
            })
        }

        fn load_approval<'a>(
            &'a self,
            workspace_id: WorkspaceId,
            id: HarnessPermissionApprovalId,
        ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
            Box::pin(async move {
                let inner = self.inner.lock().unwrap();
                match inner.approvals.get(&id) {
                    Some(a) if a.workspace_id == workspace_id => Ok(a.clone()),
                    _ => Err(Failure::not_found(
                        domain_codes::NO_PENDING_APPROVAL,
                        format!("approval {id}"),
                    )),
                }
            })
        }

        fn pending_approval_for_run<'a>(
            &'a self,
            workspace_id: WorkspaceId,
            run: RunId,
        ) -> PortFuture<'a, Result<Option<PermissionApproval>, Failure>> {
            Box::pin(async move {
                let inner = self.inner.lock().unwrap();
                Ok(inner
                    .approvals
                    .values()
                    .filter(|a| {
                        a.workspace_id == workspace_id
                            && a.run_id == run
                            && a.state == ApprovalState::Pending
                    })
                    .max_by(|a, b| {
                        a.requested_at
                            .cmp(&b.requested_at)
                            .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
                    })
                    .cloned())
            })
        }

        fn pending_approvals<'a>(
            &'a self,
            workspace_id: WorkspaceId,
        ) -> PortFuture<'a, Result<PendingApprovalSummary, Failure>> {
            Box::pin(async move {
                let inner = self.inner.lock().unwrap();
                let mut pending: Vec<&PermissionApproval> = inner
                    .approvals
                    .values()
                    .filter(|a| a.workspace_id == workspace_id && a.state == ApprovalState::Pending)
                    .collect();
                pending.sort_by(|a, b| {
                    a.requested_at
                        .cmp(&b.requested_at)
                        .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
                });
                Ok(PendingApprovalSummary {
                    count: pending.len(),
                    oldest_task_id: pending.first().map(|a| a.task_id),
                })
            })
        }

        fn approval_history<'a>(
            &'a self,
            workspace_id: WorkspaceId,
            run: RunId,
            limit: usize,
        ) -> PortFuture<'a, Result<Vec<PermissionApproval>, Failure>> {
            Box::pin(async move {
                if !(1..=MAX_APPROVAL_HISTORY).contains(&limit) {
                    return Err(Failure::invalid(
                        domain_codes::INVALID_APPROVAL,
                        format!("history needs 1..{MAX_APPROVAL_HISTORY} rows"),
                    ));
                }
                let inner = self.inner.lock().unwrap();
                let mut out: Vec<PermissionApproval> = inner
                    .approvals
                    .values()
                    .filter(|a| a.workspace_id == workspace_id && a.run_id == run)
                    .cloned()
                    .collect();
                out.sort_by(|a, b| {
                    b.requested_at
                        .cmp(&a.requested_at)
                        .then_with(|| b.id.to_string().cmp(&a.id.to_string()))
                });
                out.truncate(limit);
                Ok(out)
            })
        }
    }

    impl LeaseBinder for MemStore {
        fn with_lease(&self, lease: ExecutionLease) -> Box<dyn AttemptStore> {
            Box::new(MemStore {
                inner: self.inner.clone(),
                lease: Some(lease),
            })
        }
    }

    // Ports upstream `memStore`'s purpose — the durable contract is
    // implementable without any driver type — exercised, not just
    // declared.
    #[test]
    fn mem_store_exercises_the_attempt_store_contract() {
        let store = MemStore::new();
        let prepared = ok(Attempt::prepare(prepare_input()));
        let ws = prepared.workspace_id;

        // Create is idempotent for an equal attempt and conflicts on a
        // different one under the same id.
        block_on(store.create(&prepared)).unwrap();
        block_on(store.create(&prepared)).unwrap();
        let mut other = prepared.clone();
        other.adapter_version = "9.9.9".to_string();
        let err = block_on(store.create(&other)).unwrap_err();
        assert!(is_code(&err, domain_codes::VERSION_CONFLICT), "{err}");

        assert_eq!(block_on(store.load(ws, prepared.id)).unwrap(), prepared);
        let err = block_on(store.load(ws, HarnessAttemptId::new())).unwrap_err();
        assert!(is_code(&err, domain_codes::ATTEMPT_NOT_FOUND), "{err}");

        // A second live attempt for the same run is refused.
        let mut rival = ok(Attempt::prepare(prepare_input()));
        rival.run_id = prepared.run_id;
        rival.workspace_id = ws;
        let err = block_on(store.create(&rival)).unwrap_err();
        assert!(is_code(&err, domain_codes::LIVE_ATTEMPT_EXISTS), "{err}");

        assert_eq!(
            block_on(store.live_attempt_for_run(ws, prepared.run_id))
                .unwrap()
                .map(|a| a.id),
            Some(prepared.id)
        );

        // Save applies the version CAS and returns version+1.
        let launched = ok(prepared.launch(FENCE, "scope-1", "2.1.0", t0()));
        let stored = block_on(store.save(&prepared, &launched, &[])).unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.state, State::Launching);

        // A stale expected conflicts on the stored version.
        let err = block_on(store.save(&prepared, &launched, &[])).unwrap_err();
        assert!(is_code(&err, domain_codes::VERSION_CONFLICT), "{err}");

        // A fence that moved under the caller refuses as FENCE_MISMATCH.
        let running = ok(stored.reveal_session(FENCE, "sess-1", t0()));
        store.refence_stored(stored.id, 9);
        let err = block_on(store.save(&stored, &running, &[])).unwrap_err();
        assert!(is_code(&err, domain_codes::FENCE_MISMATCH), "{err}");
        store.refence_stored(stored.id, FENCE.generation);

        // Save must not move the event cursor or usage.
        let mut moved = stored.clone();
        moved.last_event_seq = 3;
        let err = block_on(store.save(&stored, &moved, &[])).unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_EVENT), "{err}");
    }

    #[test]
    fn mem_store_exercises_event_append_and_replay() {
        let store = MemStore::new();
        let prepared = ok(Attempt::prepare(prepare_input()));
        block_on(store.create(&prepared)).unwrap();
        let launched = ok(prepared.launch(FENCE, "scope-1", "2.1.0", t0()));

        let mut rec = EventRecord {
            attempt: prepared.id,
            seq: 1,
            kind: crate::event::EventKind::SessionStarted,
            at: t0(),
            raw_size: 10,
            raw_sha256: [9; 32],
            ..EventRecord::default()
        };
        let next = ok(launched.record_progress(FENCE, 1, t0()));
        let stored = block_on(store.append_event(&prepared, &next, &rec, &[])).unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.last_event_seq, 1);

        // Replaying the same (attempt, seq) writes nothing and returns
        // the attempt as it stands.
        let replayed = block_on(store.append_event(&prepared, &next, &rec, &[])).unwrap();
        assert_eq!(replayed.version, 1);

        // The same seq under a different digest conflicts.
        rec.raw_sha256 = [8; 32];
        let err = block_on(store.append_event(&prepared, &next, &rec, &[])).unwrap_err();
        assert!(is_code(&err, domain_codes::EVENT_CONFLICT), "{err}");

        // A record whose seq is not next's event cursor is refused
        // (gaps are allowed: seq may jump strictly ahead of expected's
        // cursor).
        rec.raw_sha256 = [7; 32];
        rec.seq = 3;
        let bad_next = ok(stored.record_progress(FENCE, 4, t0()));
        let err = block_on(store.append_event(&stored, &bad_next, &rec, &[])).unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_EVENT), "{err}");
    }

    #[test]
    fn mem_store_exercises_the_approval_write_rules() {
        let store = MemStore::new();
        let prepared = ok(Attempt::prepare(prepare_input()));
        block_on(store.create(&prepared)).unwrap();
        let running = ok(prepared
            .launch(FENCE, "scope-1", "2.1.0", t0())
            .and_then(|a| a.reveal_session(FENCE, "sess-1", t0())));
        block_on(store.save(&prepared, &running, &[])).unwrap();
        let mut running = running;
        running.version = 1;

        let open = ApprovalOpen {
            id: HarnessPermissionApprovalId::new(),
            task_id: TaskId::new(),
            request_id: "perm-1".to_string(),
            tool_call_id: "toolu_1".to_string(),
            tool: "Bash".to_string(),
            input_mac: InputMac([1; 32]),
            input_size: 16,
            expires_at: t0() + Duration::minutes(5),
        };
        // An open is refused unless next enters awaiting_permission on
        // the request id.
        let err = block_on(store.save(
            &running,
            &running_terminal(&running),
            std::slice::from_ref(&open),
        ))
        .unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_APPROVAL), "{err}");

        let awaiting = ok(running.await_permission(FENCE, "perm-1", t0() + Duration::seconds(1)));
        let stored =
            block_on(store.save(&running, &awaiting, std::slice::from_ref(&open))).unwrap();
        assert_eq!(stored.state, State::AwaitingPermission);
        let approval = block_on(AttemptStore::load_approval(
            &store,
            stored.workspace_id,
            open.id,
        ))
        .unwrap();
        assert_eq!(approval.state, ApprovalState::Pending);
        assert_eq!(approval.request_id, "perm-1");
        assert_eq!(approval.attempt_id, stored.id);

        // Two opens in one write are refused.
        let mut two = open.clone();
        two.id = HarnessPermissionApprovalId::new();
        let err = block_on(store.save(&stored, &stored_terminal(&stored), &[open.clone(), two]))
            .unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_APPROVAL), "{err}");

        // A terminal write supersedes the pending approval.
        let failed = stored_terminal(&stored);
        let stored = block_on(store.save(&stored, &failed, &[])).unwrap();
        let approval = block_on(AttemptStore::load_approval(
            &store,
            stored.workspace_id,
            open.id,
        ))
        .unwrap();
        assert_eq!(approval.state, ApprovalState::Superseded);
        assert_eq!(approval.decided_by, approval::DECIDED_BY_SUPERSEDED);
    }

    fn running_terminal(a: &Attempt) -> Attempt {
        // A terminal next that is not awaiting the request — used to
        // prove an open is refused outside awaiting_permission.
        let mut next = a.clone();
        next.state = State::Failed;
        next.pending_permission = String::new();
        next.terminal = Terminal {
            status: TerminalStatus::Failed,
            ..Terminal::default()
        };
        next.updated_at = a.updated_at + Duration::seconds(1);
        next.ended_at = Some(next.updated_at);
        next
    }

    fn stored_terminal(a: &Attempt) -> Attempt {
        let mut next = running_terminal(a);
        next.pending_permission = String::new();
        next
    }

    #[test]
    fn mem_store_exercises_decide_and_expire() {
        let store = MemStore::new();
        let prepared = ok(Attempt::prepare(prepare_input()));
        block_on(store.create(&prepared)).unwrap();
        let running = ok(prepared
            .launch(FENCE, "scope-1", "2.1.0", t0())
            .and_then(|a| a.reveal_session(FENCE, "sess-1", t0())));
        block_on(store.save(&prepared, &running, &[])).unwrap();
        let mut running = running;
        running.version = 1;
        let open = ApprovalOpen {
            id: HarnessPermissionApprovalId::new(),
            task_id: TaskId::new(),
            request_id: "perm-1".to_string(),
            tool_call_id: "toolu_1".to_string(),
            tool: "Bash".to_string(),
            input_mac: InputMac([1; 32]),
            input_size: 16,
            expires_at: t0() + Duration::minutes(5),
        };
        let awaiting = ok(running.await_permission(FENCE, "perm-1", t0() + Duration::seconds(1)));
        block_on(store.save(&running, &awaiting, std::slice::from_ref(&open))).unwrap();
        let ws = running.workspace_id;

        store.set_db_now(t0() + Duration::minutes(1));

        // Decide: MAC mismatch matches no row; the right MAC decides.
        let req = DecidePermissionRequest {
            workspace_id: ws,
            approval_id: open.id,
            allow: true,
            input_mac: InputMac([2; 32]),
            decided_by: crate::testkit::operator(),
        };
        let err = block_on(ApprovalStore::decide_permission(&store, req.clone())).unwrap_err();
        assert!(is_code(&err, domain_codes::NO_PENDING_APPROVAL), "{err}");
        let decided = block_on(ApprovalStore::decide_permission(
            &store,
            DecidePermissionRequest {
                input_mac: open.input_mac,
                ..req.clone()
            },
        ))
        .unwrap();
        assert_eq!(decided.state, ApprovalState::Allowed);

        // A second decision no longer applies.
        let err = block_on(ApprovalStore::decide_permission(
            &store,
            DecidePermissionRequest {
                input_mac: open.input_mac,
                ..req
            },
        ))
        .unwrap_err();
        assert!(is_code(&err, domain_codes::NO_PENDING_APPROVAL), "{err}");

        // ExpirePermission returns the approval as it stands — the
        // operator's decision won the race.
        let got = block_on(store.expire_permission(&awaiting, open.id)).unwrap();
        assert_eq!(got.state, ApprovalState::Allowed);
        let err = block_on(store.expire_permission(&awaiting, HarnessPermissionApprovalId::new()))
            .unwrap_err();
        assert!(is_code(&err, domain_codes::NO_PENDING_APPROVAL), "{err}");

        // A pending approval past its expiry becomes policy:timeout.
        let store2 = MemStore::new();
        let prepared2 = ok(Attempt::prepare(prepare_input()));
        block_on(store2.create(&prepared2)).unwrap();
        let running2 = ok(prepared2
            .launch(FENCE, "scope-1", "2.1.0", t0())
            .and_then(|a| a.reveal_session(FENCE, "sess-1", t0())));
        block_on(store2.save(&prepared2, &running2, &[])).unwrap();
        let mut running2 = running2;
        running2.version = 1;
        let open2 = ApprovalOpen {
            expires_at: t0() + Duration::minutes(5),
            ..open.clone()
        };
        let awaiting2 = ok(running2.await_permission(FENCE, "perm-1", t0() + Duration::seconds(1)));
        block_on(store2.save(&running2, &awaiting2, std::slice::from_ref(&open2))).unwrap();
        store2.set_db_now(t0() + Duration::minutes(6));
        let expired = block_on(store2.expire_permission(&awaiting2, open2.id)).unwrap();
        assert_eq!(expired.state, ApprovalState::Expired);
        assert_eq!(expired.decided_by, approval::DECIDED_BY_TIMEOUT);
    }

    #[test]
    fn mem_store_exercises_the_lease_fence() {
        let store = MemStore::new();
        let lease = ExecutionLease {
            generation: 4,
            credential: [1; 32],
        };
        let bound = store.with_lease(lease);
        let attempt = ok(Attempt::prepare(PrepareInput {
            fence: Fence { generation: 4 },
            ..prepare_input()
        }));
        block_on(bound.create(&attempt)).unwrap();
        // An attempt fenced below the bound lease generation is refused.
        let low = ok(Attempt::prepare(PrepareInput {
            fence: Fence { generation: 3 },
            ..prepare_input()
        }));
        let err = block_on(bound.create(&low)).unwrap_err();
        assert!(is_code(&err, domain_codes::FENCE_MISMATCH), "{err}");
    }

    // --- scriptedLauncher / scriptedProcess: the upstream
    // launcher_test.go in-memory fakes.

    // Ports upstream `validProcessSpec`.
    fn valid_process_spec() -> ProcessSpec {
        ProcessSpec {
            program: "claude".to_string(),
            args: vec![
                "-p".to_string(),
                "--resume".to_string(),
                "11111111-2222-4333-8444-555555555555".to_string(),
            ],
            env: BTreeMap::from([
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
            ]),
            work_dir: "/srv/central/worktrees/r1".to_string(),
            scope_id: "scope-1".to_string(),
            env_extras: Vec::new(),
        }
    }

    // Ports upstream `TestProcessSpecValidate`.
    #[test]
    fn process_spec_validate() {
        assert!(valid_process_spec().validate().is_ok(), "valid spec");
        let mutations: [Mutation<ProcessSpec>; 3] = [
            ("no program", |s| s.program = String::new()),
            ("no scope", |s| s.scope_id = String::new()),
            ("no workdir", |s| s.work_dir = String::new()),
        ];
        for (name, mutate) in mutations {
            let mut s = valid_process_spec();
            mutate(&mut s);
            let err = s.validate().unwrap_err();
            assert!(is_code(&err, codes::INVALID_PROCESS_SPEC), "{name}: {err}");
        }
    }

    // Ports upstream `TestProcessSpecEnforcesLaunchEnvPolicy`: the
    // launcher boundary re-checks the env with the spec's extras, so a
    // credential or relocation variable can never reach a launcher even
    // if an adapter forgot to validate, while an adapter's declared
    // extras pass through.
    #[test]
    fn process_spec_enforces_launch_env_policy() {
        for name in [
            "HOME",
            "ANTHROPIC_API_KEY",
            "LD_PRELOAD",
            "https_proxy",
            "EDITOR",
        ] {
            let mut s = valid_process_spec();
            s.env = BTreeMap::from([
                ("PATH".to_string(), "/usr/bin".to_string()),
                (name.to_string(), "x".to_string()),
            ]);
            let err = s.validate().unwrap_err();
            assert!(
                is_code(&err, domain_codes::FORBIDDEN_LAUNCH_ENV),
                "{name}: {err}"
            );
        }
        let mut s = valid_process_spec();
        s.env = BTreeMap::new();
        assert!(s.validate().is_ok(), "empty env rejected");

        // A declared extra passes with the extras attached and refuses
        // without them; a denylisted name refuses even as an extra.
        let mut extra = valid_process_spec();
        extra.env = BTreeMap::from([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("AGY_CLI_DISABLE_AUTO_UPDATE".to_string(), "1".to_string()),
        ]);
        let err = extra.validate().unwrap_err();
        assert!(
            is_code(&err, domain_codes::FORBIDDEN_LAUNCH_ENV),
            "undeclared extra accepted: {err}"
        );
        extra.env_extras = vec!["AGY_CLI_DISABLE_AUTO_UPDATE".to_string()];
        extra.validate().unwrap();

        let mut denied = valid_process_spec();
        denied.env = BTreeMap::from([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/root".to_string()),
        ]);
        denied.env_extras = vec!["HOME".to_string()];
        let err = denied.validate().unwrap_err();
        assert!(
            is_code(&err, domain_codes::FORBIDDEN_LAUNCH_ENV),
            "denylisted extra accepted: {err}"
        );
    }

    // Ports upstream `TestProcessSpecNeverPrintsArgsOrEnvValues`.
    #[test]
    fn process_spec_never_prints_args_or_env_values() {
        let mut s = valid_process_spec();
        s.env
            .insert("TZ".to_string(), "sk-secret-looking-value".to_string());
        for out in [format!("{s}"), format!("{s:?}"), format!("{s:#?}")] {
            for leaked in [
                "11111111-2222-4333-8444-555555555555",
                "--resume",
                "sk-secret-looking-value",
                "/usr/bin",
            ] {
                assert!(!out.contains(leaked), "leaked {leaked:?}: {out}");
            }
            for shown in ["claude", "scope-1", "LANG PATH TZ", "3 args"] {
                assert!(out.contains(shown), "does not show {shown:?}: {out}");
            }
        }
    }

    // Ports upstream `scriptedProcess` and `scriptedLauncher`.
    struct ScriptedProcess {
        scope: String,
        out: Mutex<(Vec<u8>, usize)>,
    }

    impl Process for ScriptedProcess {
        fn scope_id(&self) -> &str {
            &self.scope
        }

        fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }

        fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
            Box::pin(async move {
                let mut guard = self.out.lock().unwrap();
                let (data, pos) = &mut *guard;
                let n = data.len().saturating_sub(*pos).min(buf.len());
                buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                Ok(n)
            })
        }

        fn read_stderr<'a>(&'a self, _buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
            Box::pin(async move { Ok(0) })
        }

        fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
            Box::pin(async {
                Ok(ExitStatus {
                    code: 0,
                    signaled: false,
                })
            })
        }

        fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ScriptedLauncher {
        live: Mutex<HashMap<String, bool>>,
    }

    impl ProcessLauncher for ScriptedLauncher {
        fn launch<'a>(
            &'a self,
            spec: ProcessSpec,
        ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
            Box::pin(async move {
                spec.validate()?;
                self.live
                    .lock()
                    .unwrap()
                    .insert(spec.scope_id.clone(), true);
                Ok(Box::new(ScriptedProcess {
                    scope: spec.scope_id,
                    out: Mutex::new((b"{}\n".to_vec(), 0)),
                }) as Box<dyn Process>)
            })
        }

        fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
            Box::pin(async move {
                Ok(self
                    .live
                    .lock()
                    .unwrap()
                    .get(scope_id)
                    .copied()
                    .unwrap_or(false))
            })
        }

        fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async move {
                self.live
                    .lock()
                    .unwrap()
                    .insert(scope_id.to_string(), false);
                Ok(())
            })
        }
    }

    // Ports upstream `TestProcessLauncherPortIsImplementableInMemory`.
    #[test]
    fn process_launcher_port_is_implementable_in_memory() {
        let l = ScriptedLauncher {
            live: Mutex::new(HashMap::new()),
        };
        let p = block_on(l.launch(valid_process_spec())).unwrap();
        assert_eq!(p.scope_id(), "scope-1");
        assert!(block_on(l.is_alive("scope-1")).unwrap());
        let err = block_on(l.launch(ProcessSpec {
            program: String::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            work_dir: String::new(),
            scope_id: String::new(),
            env_extras: Vec::new(),
        }))
        .map(|_| ())
        .unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_PROCESS_SPEC),
            "invalid spec launched: {err}"
        );
        let mut buf = [0u8; 8];
        let n = block_on(p.read_stdout(&mut buf)).unwrap();
        assert_eq!(&buf[..n], b"{}\n");
        assert_eq!(block_on(p.read_stdout(&mut buf)).unwrap(), 0);
        let status = block_on(p.wait()).unwrap();
        assert_eq!(
            status,
            ExitStatus {
                code: 0,
                signaled: false
            }
        );
        block_on(l.kill_scope("scope-1")).unwrap();
        assert!(!block_on(l.is_alive("scope-1")).unwrap());
        // Killing a never-started scope is a no-op.
        block_on(l.kill_scope("never")).unwrap();
    }

    // --- scriptedSession / scriptedAdapter: prove the adapter
    // boundary is implementable in memory (the upstream port package
    // pins implementability through its consumers; here the fake
    // exercises every method).

    struct ScriptedSession {
        events: Mutex<VecDeque<Event>>,
        sent: Mutex<Vec<String>>,
    }

    impl Session for ScriptedSession {
        fn session_ref(&self) -> PortFuture<'_, Option<SessionRef>> {
            Box::pin(async {
                Some(SessionRef {
                    harness_session_id: "sess-1".to_string(),
                })
            })
        }

        fn next_event(&self) -> PortFuture<'_, Option<Event>> {
            Box::pin(async move { self.events.lock().unwrap().pop_front() })
        }

        fn send<'a>(&'a self, input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async move {
                self.sent.lock().unwrap().push(input.text);
                Ok(())
            })
        }

        fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Err(Failure::conflict(codes::SESSION_ENDED, "session has ended")) })
        }

        fn respond_permission<'a>(
            &'a self,
            decision: PermissionDecision,
        ) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async move {
                if decision.request_id != "perm-1" {
                    return Err(Failure::not_found(
                        codes::NO_PENDING_PERMISSION,
                        "no such pending permission request",
                    ));
                }
                Ok(())
            })
        }

        fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>> {
            Box::pin(async {
                Ok(Terminal {
                    status: TerminalStatus::Succeeded,
                    ..Terminal::default()
                })
            })
        }

        fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ScriptedAdapter;

    impl Adapter for ScriptedAdapter {
        fn kind(&self) -> Kind {
            Kind::new("claude-code")
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                streaming_input: true,
                interrupt: true,
                permission_bridge: true,
                ..Capabilities::default()
            }
        }

        fn env_extras(&self) -> &[String] {
            &[]
        }

        fn probe<'a>(&'a self, _env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>> {
            Box::pin(async {
                Ok(ProbeResult {
                    harness_version: "2.1.0".to_string(),
                    authenticated: true,
                    detail: "ok".to_string(),
                })
            })
        }

        fn start<'a>(
            &'a self,
            spec: StartSpec,
        ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
            Box::pin(async move {
                let extras: Vec<&str> = self.env_extras().iter().map(String::as_str).collect();
                spec.validate(&extras)?;
                Ok(Box::new(ScriptedSession {
                    events: Mutex::new(VecDeque::from(vec![Event {
                        attempt: spec.attempt,
                        seq: 1,
                        at: t0(),
                        harness_session_id: "sess-1".to_string(),
                        raw: b"{}".to_vec(),
                        payload: Some(EventPayload::Message(Message {
                            role: MessageRole::Assistant,
                            text: "hi".to_string(),
                            partial: false,
                        })),
                    }])),
                    sent: Mutex::new(Vec::new()),
                }) as Box<dyn Session>)
            })
        }

        fn resume<'a>(
            &'a self,
            _session_ref: SessionRef,
            _spec: StartSpec,
        ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
            Box::pin(async {
                Err(Failure::invalid(
                    codes::UNSUPPORTED,
                    "resume unsupported by adapter",
                ))
            })
        }

        fn reconcile<'a>(
            &'a self,
            input: ReconcileInput,
        ) -> PortFuture<'a, Result<ReconcileResult, Failure>> {
            Box::pin(async move {
                Ok(ReconcileResult {
                    scope_alive: !input.sandbox_scope_id.is_empty(),
                    reattached: None,
                    terminal: None,
                })
            })
        }
    }

    #[test]
    fn adapter_and_session_ports_are_implementable_in_memory() {
        let adapter = ScriptedAdapter;
        assert_eq!(adapter.kind(), Kind::new("claude-code"));
        assert!(adapter.capabilities().permission_bridge);
        let probe = block_on(adapter.probe(LaunchEnv::default())).unwrap();
        assert_eq!(probe.harness_version, "2.1.0");

        let session = block_on(adapter.start(valid_spec())).unwrap();
        assert_eq!(
            block_on(session.session_ref()).map(|r| r.harness_session_id),
            Some("sess-1".to_string())
        );
        block_on(session.send(OperatorInput {
            text: "follow up".to_string(),
        }))
        .unwrap();
        let event = block_on(session.next_event()).unwrap();
        assert_eq!(event.seq, 1);
        assert!(block_on(session.next_event()).is_none());
        block_on(session.respond_permission(PermissionDecision {
            request_id: "perm-1".to_string(),
            allow: false,
            option_id: String::new(),
            decided_by: "operator-session:p".to_string(),
            input_sha256: [0; 32],
        }))
        .unwrap();
        let err = block_on(session.respond_permission(PermissionDecision {
            request_id: "gone".to_string(),
            allow: false,
            option_id: String::new(),
            decided_by: "operator-session:p".to_string(),
            input_sha256: [0; 32],
        }))
        .unwrap_err();
        assert!(is_code(&err, codes::NO_PENDING_PERMISSION), "{err}");
        let err = block_on(session.interrupt()).unwrap_err();
        assert!(is_code(&err, codes::SESSION_ENDED), "{err}");
        assert_eq!(
            block_on(session.wait()).unwrap().status,
            TerminalStatus::Succeeded
        );
        block_on(session.kill()).unwrap();

        let err = block_on(adapter.resume(SessionRef::default(), valid_spec()))
            .map(|_| ())
            .unwrap_err();
        assert!(is_code(&err, codes::UNSUPPORTED), "{err}");
        let result = block_on(adapter.reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: "scope-1".to_string(),
            harness_session_id: "sess-1".to_string(),
            last_event_seq: 3,
        }))
        .unwrap();
        assert!(result.scope_alive);
        assert!(result.reattached.is_none());
    }
}
