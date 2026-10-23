//! `claudecode` — drives the unmodified Claude Code CLI headlessly as
//! an ADR 0035 harness (phase 2a spec). It launches `claude` only
//! through a `port::ProcessLauncher`, passes only the declared launch
//! parameters, speaks the CLI's own stream-json protocol over stdio,
//! and never reads, stores, injects, relocates or proxies the
//! operator's Claude credentials or config.
//!
//! Upstream `internal/adapter/harness/claudecode`, split as:
//! - `mod` — `claudecode.go` + `adapter.go`: the adapter, its
//!   capabilities and the terminal-reason vocabulary;
//! - `argv` — the closed `claude` argv;
//! - `probe` — the version and auth probes;
//! - `protocol` — stream-JSON frames, usage accounting, outgoing lines;
//! - `session` — one live process's reader/writer and bridge;
//! - `json` — the byte-level JSON machinery (raw spans, `json.Compact`,
//!   the duplicate-member-name walk).

mod argv;
mod probe;
mod protocol;
mod session;

use std::sync::Arc;

use central_foundation::failure::{Failure, FailureKind};
use central_harness::capability::Capabilities;
use central_harness::domain::Kind;
use central_harness::event::UsageScope;
use central_harness::port::{
    Adapter, LaunchEnv, PortFuture, ProbeResult, ProcessLauncher, ProcessSpec, ReconcileInput,
    ReconcileResult, Session, SessionRef, StartSpec,
};

/// `Kind` — this adapter's harness kind.
pub const KIND: &str = "claude-code";

/// `DefaultPinnedVersion` — the Claude Code version the protocol
/// mapping was captured from (spec §2.2).
pub const DEFAULT_PINNED_VERSION: &str = "2.1.283";

/// `program` — the symbolic program name every launcher resolves.
pub(crate) fn program_name() -> &'static str {
    "claude"
}

/// The adapter's sentinel failure codes — the upstream `Err*` values
/// (`ErrInvalidLaunch`, `ErrPathRequired`, `ErrUnpinnedVersion`,
/// `ErrUnexpectedProbeOutput`). The `port::codes::*` sentinels it wraps
/// upstream (`ErrSessionEnded`, `ErrNoPendingPermission`,
/// `ErrPermissionBinding`, `ErrUnsupported`) stay `port::codes::*` so
/// orchestrator matching is unchanged.
pub mod codes {
    /// `ErrInvalidLaunch` — a launch would pass unsafe or undeclared
    /// parameters.
    pub const INVALID_LAUNCH: &str = "claudecode_invalid_launch";
    /// `ErrPathRequired` — PATH absent or not absolute-only.
    pub const PATH_REQUIRED: &str = "claudecode_path_required";
    /// `ErrUnpinnedVersion` — the running `claude` differs from the
    /// pinned version.
    pub const UNPINNED_VERSION: &str = "claudecode_unpinned_version";
    /// `ErrUnexpectedProbeOutput` — a probe's output is not the
    /// expected shape.
    pub const UNEXPECTED_PROBE_OUTPUT: &str = "claudecode_unexpected_probe_output";
}

/// The `Terminal.reason` vocabulary (spec decision 9). The adapter
/// never puts harness text in `reason`; these strings are the only
/// values it sets.
pub mod reasons {
    /// `ReasonNotAuthenticated`.
    pub const HARNESS_NOT_AUTHENTICATED: &str = "harness_not_authenticated";
    /// `ReasonAPIError`.
    pub const HARNESS_API_ERROR: &str = "harness_api_error";
    /// `ReasonAborted`.
    pub const HARNESS_ABORTED: &str = "harness_aborted";
    /// `ReasonExitedWithoutResult`.
    pub const HARNESS_EXITED_WITHOUT_RESULT: &str = "harness_exited_without_result";
    /// `ReasonSessionMismatch`.
    pub const HARNESS_SESSION_MISMATCH: &str = "harness_session_mismatch";
    /// `ReasonProtocolError`.
    pub const HARNESS_PROTOCOL_ERROR: &str = "harness_protocol_error";
    /// `ReasonMaxTurns`.
    pub const HARNESS_MAX_TURNS: &str = "harness_max_turns";
    /// `ReasonBudget`.
    pub const HARNESS_BUDGET: &str = "harness_budget";
    /// `ReasonPolicyMismatch`.
    pub const HARNESS_POLICY_MISMATCH: &str = "harness_policy_mismatch";
    /// `ReasonUntrustedProjectConfig` — reserved. Live checks showed
    /// that claude 2.1.283 under `-p --setting-sources user` neither
    /// starts a workspace `.mcp.json` server nor loads anything from a
    /// workspace `.claude/`, so the adapter does not refuse such a
    /// worktree today; the gated live test re-checks the `.claude/`
    /// part.
    pub const HARNESS_UNTRUSTED_PROJECT_CONFIG: &str = "harness_untrusted_project_config";
    /// `ReasonPermissionBridgeUnavailable` — ends a bridged session
    /// that sent a permission request the adapter cannot bridge safely
    /// (phase 3c decisions 5 and 7): a harness-controlled field out of
    /// bounds, a request id that is already pending, or a tool input
    /// that repeats an object member name at any depth. The request is
    /// never answered.
    pub const PERMISSION_BRIDGE_UNAVAILABLE: &str = "permission_bridge_unavailable";
}

/// `Reasons()` — the whole vocabulary in declaration order.
pub fn reasons() -> &'static [&'static str] {
    &[
        reasons::HARNESS_NOT_AUTHENTICATED,
        reasons::HARNESS_API_ERROR,
        reasons::HARNESS_ABORTED,
        reasons::HARNESS_EXITED_WITHOUT_RESULT,
        reasons::HARNESS_SESSION_MISMATCH,
        reasons::HARNESS_PROTOCOL_ERROR,
        reasons::HARNESS_MAX_TURNS,
        reasons::HARNESS_BUDGET,
        reasons::HARNESS_POLICY_MISMATCH,
        reasons::HARNESS_UNTRUSTED_PROJECT_CONFIG,
        reasons::PERMISSION_BRIDGE_UNAVAILABLE,
    ]
}

/// `Capabilities()` — the adapter's declared capabilities (spec
/// decision 16): no partial deltas, no fork, no reattach after a
/// control-plane restart; the native cost limit is `--max-budget-usd`
/// (phase 3d decision 5).
pub fn capabilities() -> Capabilities {
    Capabilities {
        streaming_input: true,
        interrupt: true,
        resume_by_id: true,
        preassign_session_id: true,
        permission_bridge: true,
        usage_tokens: true,
        cost_usd: true,
        usage_scope: UsageScope::SessionCumulative,
        native_cost_limit: true,
        ..Capabilities::default()
    }
}

/// `Config` — configures the adapter.
#[derive(Default)]
pub struct Config {
    /// `Launcher` starts every claude process; the adapter never
    /// execs. `None` is refused by [`ClaudeCode::new`].
    pub launcher: Option<Arc<dyn ProcessLauncher>>,
    /// The expected `claude --version`; empty means
    /// [`DEFAULT_PINNED_VERSION`].
    pub pinned_version: String,
    /// `AllowUnpinned` lets `start` proceed on a different version.
    pub allow_unpinned: bool,
    /// `ProbeWorkDir` — the working directory of the version and auth
    /// probes; empty means the system temp dir.
    pub probe_work_dir: String,
}

/// `Adapter` — drives the `claude` CLI. Implements `port::Adapter`.
pub struct ClaudeCode {
    pub(crate) launcher: Arc<dyn ProcessLauncher>,
    pub(crate) pinned: String,
    pub(crate) allow_unpinned: bool,
    pub(crate) probe_work_dir: String,
}

impl ClaudeCode {
    /// `New` — validates `cfg` and returns the adapter.
    pub fn new(cfg: Config) -> Result<Self, Failure> {
        let Some(launcher) = cfg.launcher else {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: a process launcher is required",
            ));
        };
        let pinned = if cfg.pinned_version.is_empty() {
            DEFAULT_PINNED_VERSION.to_string()
        } else {
            cfg.pinned_version
        };
        if !probe::version_shape(&pinned) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: pinned version must look like 1.2.3",
            ));
        }
        let probe_work_dir = if cfg.probe_work_dir.is_empty() {
            std::env::temp_dir().to_string_lossy().into_owned()
        } else {
            cfg.probe_work_dir
        };
        Ok(Self {
            launcher,
            pinned,
            allow_unpinned: cfg.allow_unpinned,
            probe_work_dir,
        })
    }

    /// `open` — validates, checks the pinned version, launches `claude`
    /// and starts the session. The future's lifetime bounds only the
    /// launch; the session lives until interrupt, result or kill.
    async fn open(&self, spec: StartSpec, resume_id: &str) -> Result<Box<dyn Session>, Failure> {
        spec.validate(&[])?;
        probe::require_path(&spec.env)?;
        if spec.limits.max_turns > 0 {
            // claude 2.1.283 has no --max-turns flag; a limit Central
            // cannot pass must not be silently dropped.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "claudecode: claude has no max-turns limit",
            ));
        }
        let attempt_session_id = spec.attempt.to_string();
        let mut args_in = argv::LaunchArgs {
            policy: spec.permission,
            session_id: "",
            resume_id: "",
            model: &spec.model,
            max_cost_micro_usd: spec.limits.max_cost_micro_usd,
        };
        let expected: String;
        if resume_id.is_empty() {
            expected = attempt_session_id.clone();
            args_in.session_id = &attempt_session_id;
        } else {
            args_in.resume_id = resume_id;
            expected = resume_id.to_string();
        }
        let args = argv::build_args(&args_in)?;
        let version = self.version(&spec.env).await?;
        if version != self.pinned && !self.allow_unpinned {
            return Err(Failure::invalid(
                codes::UNPINNED_VERSION,
                format!(
                    "claudecode: claude version differs from the pinned version: found {version}, pinned {}",
                    self.pinned
                ),
            ));
        }
        let proc = self
            .launcher
            .launch(ProcessSpec {
                program: program_name().to_string(),
                args,
                env: spec.env.vars.clone(),
                work_dir: spec.workspace.path.clone(),
                scope_id: spec.env.sandbox_scope_id.clone(),
                env_extras: Vec::new(),
            })
            .await
            .map_err(|e| {
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("claudecode: launch: {}", e.message()),
                )
            })?;
        let pinned = if self.allow_unpinned {
            String::new()
        } else {
            self.pinned.clone()
        };
        let session = session::ClaudeCodeSession::spawn(
            session::SessionCfg {
                attempt: spec.attempt,
                policy: spec.permission,
                expected_id: expected,
                expected_mode: argv::expected_permission_mode(spec.permission).to_string(),
                pinned_version: pinned,
            },
            proc,
            &spec.prompt,
        );
        Ok(Box::new(session))
    }
}

impl Adapter for ClaudeCode {
    fn kind(&self) -> Kind {
        Kind::new(KIND)
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    /// `EnvExtras` — nil upstream: the adapter needs nothing beyond the
    /// base allowlist.
    fn env_extras(&self) -> &[String] {
        &[]
    }

    fn probe<'a>(&'a self, env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>> {
        Box::pin(async move { self.probe_inner(&env).await })
    }

    /// `Start` — launches a fresh session whose id is the attempt id
    /// (`--session-id`).
    fn start<'a>(&'a self, spec: StartSpec) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move { self.open(spec, "").await })
    }

    /// `Resume` — relaunches the session with `--resume`; the harness
    /// keeps the id.
    fn resume<'a>(
        &'a self,
        session_ref: SessionRef,
        spec: StartSpec,
    ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            if session_ref.harness_session_id.is_empty() {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    "claudecode: resume requires a harness session id",
                ));
            }
            self.open(spec, &session_ref.harness_session_id).await
        })
    }

    /// `Reconcile` — reports only whether the attempt's scope is alive:
    /// the adapter cannot reattach, and the caller decides ambiguity.
    fn reconcile<'a>(
        &'a self,
        input: ReconcileInput,
    ) -> PortFuture<'a, Result<ReconcileResult, Failure>> {
        Box::pin(async move {
            if input.sandbox_scope_id.is_empty() {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    "claudecode: reconcile requires a sandbox scope id",
                ));
            }
            let alive = self
                .launcher
                .is_alive(&input.sandbox_scope_id)
                .await
                .map_err(|e| {
                    Failure::new(
                        e.kind(),
                        e.code(),
                        format!("claudecode: reconcile: {}", e.message()),
                    )
                })?;
            Ok(ReconcileResult {
                scope_alive: alive,
                reattached: None,
                terminal: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestCapabilities` — the declared matrix (spec decision 16).
    #[test]
    fn capabilities_matrix() {
        let c = capabilities();
        assert!(c.streaming_input);
        assert!(c.interrupt);
        assert!(c.resume_by_id);
        assert!(c.preassign_session_id);
        assert!(c.permission_bridge);
        assert!(!c.fork);
        assert!(!c.partial_deltas);
        assert!(!c.reattach);
        assert!(!c.auto_resume_on_restart);
        assert!(c.usage_tokens);
        assert!(c.cost_usd);
        assert_eq!(c.usage_scope, UsageScope::SessionCumulative);
        assert!(c.native_cost_limit);
        c.validate().unwrap();
    }

    /// `TestReasons` — declaration order and the whole vocabulary.
    #[test]
    fn reasons_vocabulary() {
        assert_eq!(reasons().len(), 11);
        assert_eq!(reasons()[0], "harness_not_authenticated");
        assert_eq!(reasons()[10], "permission_bridge_unavailable");
        for r in reasons() {
            assert!(r.starts_with("harness_") || *r == "permission_bridge_unavailable");
        }
    }

    /// `TestKind`.
    #[test]
    fn kind_is_claude_code() {
        assert_eq!(KIND, "claude-code");
        Kind::new(KIND).validate().unwrap();
    }

    /// `TestNew` — config validation.
    #[test]
    fn new_validates() {
        assert!(ClaudeCode::new(Config::default()).is_err(), "no launcher");
        let l: Arc<dyn ProcessLauncher> = Arc::new(crate::fake::FakeLauncher::default());
        let a = ClaudeCode::new(Config {
            launcher: Some(l.clone()),
            ..Config::default()
        })
        .unwrap();
        assert_eq!(a.pinned, DEFAULT_PINNED_VERSION);
        assert_eq!(a.probe_work_dir, std::env::temp_dir().to_string_lossy());
        assert!(
            ClaudeCode::new(Config {
                launcher: Some(l),
                pinned_version: "not-a-version".to_string(),
                ..Config::default()
            })
            .is_err()
        );
        assert!(
            ClaudeCode::new(Config {
                launcher: None,
                ..Config::default()
            })
            .is_err()
        );
    }
}
