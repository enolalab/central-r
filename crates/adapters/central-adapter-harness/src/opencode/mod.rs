//! `opencode` — drives the unmodified OpenCode CLI headlessly as an
//! ADR 0035 harness (issue #126 spec). It launches `opencode run
//! --format json` only through a `port::ProcessLauncher`, passes only
//! the declared launch parameters, delivers the prompt over stdin,
//! speaks the CLI's own NDJSON event protocol over stdout, and never
//! reads, stores, injects, relocates or proxies the operator's provider
//! credentials or config. Permission policy is Deny-only: the default
//! run auto-rejects every permission ask, and any other policy is
//! refused fail-closed.
//!
//! Upstream `internal/adapter/harness/opencode`, split as:
//! - `mod` — `opencode.go` + `adapter.go`: the adapter, its
//!   capabilities, the terminal-reason vocabulary, the launch refusals
//!   and the project-config rule;
//! - `argv` — the closed `opencode` argv;
//! - `probe` — the version probe;
//! - `protocol` — the NDJSON envelope grammar and part decoders;
//! - `session` — one live process's reader/writer and terminal logic.

mod argv;
mod probe;
mod protocol;
mod session;

use std::sync::Arc;

use central_foundation::failure::{Failure, FailureKind};
use central_harness::capability::Capabilities;
use central_harness::domain::{Kind, PermissionPolicy};
use central_harness::event::UsageScope;
use central_harness::port::{
    Adapter, LaunchEnv, PortFuture, ProbeResult, ProcessLauncher, ProcessSpec, ReconcileInput,
    ReconcileResult, Session, SessionRef, StartSpec,
};

/// `Kind` — this adapter's harness kind.
pub const KIND: &str = "opencode";

/// `DefaultPinnedVersion` — the OpenCode version the protocol mapping
/// was captured from (spec E1–E9).
pub const DEFAULT_PINNED_VERSION: &str = "1.18.32";

/// `program` — the symbolic program name every launcher resolves.
fn program_name() -> &'static str {
    "opencode"
}

/// The adapter's sentinel failure codes — the upstream `Err*` values
/// (`ErrInvalidLaunch`, `ErrPathRequired`, `ErrUnpinnedVersion`,
/// `ErrUnexpectedProbeOutput`). The `port::codes::*` sentinels it wraps
/// upstream (`ErrSessionEnded`, `ErrNoPendingPermission`,
/// `ErrUnsupported`) stay `port::codes::*` so orchestrator matching is
/// unchanged.
pub mod codes {
    /// `ErrInvalidLaunch` — a launch would pass unsafe or undeclared
    /// parameters.
    pub const INVALID_LAUNCH: &str = "opencode_invalid_launch";
    /// `ErrPathRequired` — PATH absent or not absolute-only.
    pub const PATH_REQUIRED: &str = "opencode_path_required";
    /// `ErrUnpinnedVersion` — the running `opencode` differs from the
    /// pinned version.
    pub const UNPINNED_VERSION: &str = "opencode_unpinned_version";
    /// `ErrUnexpectedProbeOutput` — the probe's output is not the
    /// expected shape.
    pub const UNEXPECTED_PROBE_OUTPUT: &str = "opencode_unexpected_probe_output";
}

/// The `Terminal.reason` vocabulary (spec D3/D4). The adapter never
/// puts harness text in `reason`; these strings are the only values it
/// sets, and each reuses an `execution` failure reason verbatim.
pub mod reasons {
    /// `ReasonAPIError`.
    pub const HARNESS_API_ERROR: &str = "harness_api_error";
    /// `ReasonExitedWithoutResult`.
    pub const HARNESS_EXITED_WITHOUT_RESULT: &str = "harness_exited_without_result";
    /// `ReasonSessionMismatch`.
    pub const HARNESS_SESSION_MISMATCH: &str = "harness_session_mismatch";
    /// `ReasonProtocolError`.
    pub const HARNESS_PROTOCOL_ERROR: &str = "harness_protocol_error";
}

/// `Reasons()` — the whole vocabulary in declaration order.
pub fn reasons() -> &'static [&'static str] {
    &[
        reasons::HARNESS_API_ERROR,
        reasons::HARNESS_EXITED_WITHOUT_RESULT,
        reasons::HARNESS_SESSION_MISMATCH,
        reasons::HARNESS_PROTOCOL_ERROR,
    ]
}

/// `Capabilities()` — the adapter's declared capabilities (spec D1).
/// `opencode run` is one-shot: no streaming input, no soft interrupt,
/// no preassigned session id, no permission bridge, no reattach after
/// a control-plane restart, and no native cost limit. It resumes by id
/// and reports per-step tokens and USD cost.
pub fn capabilities() -> Capabilities {
    Capabilities {
        resume_by_id: true,
        usage_tokens: true,
        cost_usd: true,
        usage_scope: UsageScope::Step,
        ..Capabilities::default()
    }
}

/// `Config` — configures the adapter.
#[derive(Default)]
pub struct Config {
    /// `Launcher` starts every opencode process; the adapter never
    /// execs. `None` is refused by [`OpenCode::new`].
    pub launcher: Option<Arc<dyn ProcessLauncher>>,
    /// The expected `opencode --version`; empty means
    /// [`DEFAULT_PINNED_VERSION`].
    pub pinned_version: String,
    /// `AllowUnpinned` lets `start` proceed on a different version.
    pub allow_unpinned: bool,
    /// `ProbeWorkDir` — the working directory of the version probe;
    /// empty means the system temp dir.
    pub probe_work_dir: String,
}

/// `Adapter` — drives the `opencode` CLI. Implements `port::Adapter`.
pub struct OpenCode {
    pub(crate) launcher: Arc<dyn ProcessLauncher>,
    pub(crate) pinned: String,
    pub(crate) allow_unpinned: bool,
    pub(crate) probe_work_dir: String,
}

impl OpenCode {
    /// `New` — validates `cfg` and returns the adapter.
    pub fn new(cfg: Config) -> Result<Self, Failure> {
        let Some(launcher) = cfg.launcher else {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "opencode: a process launcher is required",
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
                "opencode: pinned version must look like 1.2.3",
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

    /// `open` — validates, checks the pinned version, launches
    /// `opencode` and starts the session.
    async fn open(&self, spec: StartSpec, resume_id: &str) -> Result<Box<dyn Session>, Failure> {
        spec.validate(&[])?;
        require_path(&spec.env)?;
        if spec.permission != PermissionPolicy::Deny {
            // `opencode run` exposes no bridge channel and no scoped
            // auto-allow: only the default deny behavior (auto-reject)
            // is expressible. Anything else refuses rather than
            // downgrade.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "opencode: opencode supports only the deny permission policy",
            ));
        }
        if spec.limits.max_turns > 0 {
            // opencode 1.18.32 has no max-turns limit; a limit Central
            // cannot pass must not be silently dropped.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "opencode: opencode has no max-turns limit",
            ));
        }
        if spec.limits.max_cost_micro_usd > 0 {
            // No native cost limit exists either; the orchestrator
            // already withholds the limit when NativeCostLimit is
            // false.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "opencode: opencode has no native cost limit",
            ));
        }
        refuse_project_config(&spec.workspace.path)?;
        let args = argv::build_args(&argv::LaunchArgs {
            resume_id,
            model: &spec.model,
        })?;
        let version = self.version(&spec.env).await?;
        if version != self.pinned && !self.allow_unpinned {
            return Err(Failure::invalid(
                codes::UNPINNED_VERSION,
                format!(
                    "opencode: opencode version differs from the pinned version: found {version}, pinned {}",
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
                    format!("opencode: launch: {}", e.message()),
                )
            })?;
        let session = session::OpenCodeSession::spawn(
            session::SessionCfg {
                attempt: spec.attempt,
                resume_id: resume_id.to_string(),
                probed_version: version,
                model: spec.model.clone(),
            },
            proc,
            &spec.prompt,
        );
        Ok(Box::new(session))
    }
}

impl Adapter for OpenCode {
    fn kind(&self) -> Kind {
        Kind::new(KIND)
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    /// `EnvExtras` — nil upstream: the adapter needs nothing beyond
    /// the base allowlist.
    fn env_extras(&self) -> &[String] {
        &[]
    }

    /// `Probe`.
    fn probe<'a>(&'a self, env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>> {
        Box::pin(async move { self.probe_inner(&env).await })
    }

    /// `Start` — launches a fresh session; the harness assigns the
    /// session id, which the first event reveals.
    fn start<'a>(&'a self, spec: StartSpec) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move { self.open(spec, "").await })
    }

    /// `Resume` — relaunches ref's session with `--session`; the id
    /// guard in the event loop refuses any other session.
    fn resume<'a>(
        &'a self,
        session_ref: SessionRef,
        spec: StartSpec,
    ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            if !argv::valid_session_id(&session_ref.harness_session_id) {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    "opencode: resume requires a harness session id",
                ));
            }
            self.open(spec, &session_ref.harness_session_id).await
        })
    }

    /// `Reconcile` — reports only whether the attempt's scope is
    /// alive: the adapter cannot reattach, and the caller decides
    /// ambiguity.
    fn reconcile<'a>(
        &'a self,
        input: ReconcileInput,
    ) -> PortFuture<'a, Result<ReconcileResult, Failure>> {
        Box::pin(async move {
            if input.sandbox_scope_id.is_empty() {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    "opencode: reconcile requires a sandbox scope id",
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
                        format!("opencode: reconcile: {}", e.message()),
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

/// `projectConfigNames` — the worktree entries that make opencode
/// load project configuration (spec D6). The harness reads them from
/// the worktree root and Central cannot ignore them, so their
/// presence refuses the launch fail-closed.
const PROJECT_CONFIG_NAMES: &[&str] = &["opencode.json", "opencode.jsonc", ".opencode"];

/// `refuseProjectConfig` — refuses a worktree whose root carries
/// opencode project configuration. Any file type refuses, and a stat
/// error other than absence refuses too: the check must fail closed.
fn refuse_project_config(workdir: &str) -> Result<(), Failure> {
    for name in PROJECT_CONFIG_NAMES {
        match std::fs::symlink_metadata(std::path::Path::new(workdir).join(name)) {
            Ok(_) => {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    format!("opencode: worktree contains {name}"),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    format!("opencode: worktree contains {name}"),
                ));
            }
        }
    }
    Ok(())
}

/// `requirePath` — a PATH whose every entry is an absolute directory.
/// An empty entry (a leading, trailing or doubled `:`) or a relative
/// one would resolve commands against the untrusted worktree, the
/// harness's working directory. The value is never echoed.
fn require_path(env: &LaunchEnv) -> Result<(), Failure> {
    let path = env.vars.get("PATH").cloned().unwrap_or_default();
    if path.is_empty() {
        return Err(Failure::invalid(
            codes::PATH_REQUIRED,
            "opencode: PATH is required in the launch env and may list only absolute directories",
        ));
    }
    for dir in path.split(':') {
        if !std::path::Path::new(dir).is_absolute() {
            return Err(Failure::invalid(
                codes::PATH_REQUIRED,
                "opencode: PATH is required in the launch env and may list only absolute directories: an entry is empty or relative",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestCapabilities` / `TestReasons` / `TestKind` /
    /// `TestDefaultPinnedVersion` (opencode_test.go).
    #[test]
    fn identity_vocabulary() {
        assert_eq!(KIND, "opencode");
        Kind::new(KIND).validate().unwrap();
        assert_eq!(DEFAULT_PINNED_VERSION, "1.18.32");
        assert!(probe::version_shape(DEFAULT_PINNED_VERSION));
        assert_eq!(reasons().len(), 4);
        assert_eq!(reasons()[0], "harness_api_error");
        assert_eq!(reasons()[3], "harness_protocol_error");
        let c = capabilities();
        assert!(c.resume_by_id && c.usage_tokens && c.cost_usd);
        assert_eq!(c.usage_scope, UsageScope::Step);
        assert!(!c.streaming_input && !c.interrupt && !c.native_cost_limit);
        c.validate().unwrap();
    }

    /// `TestNew` (adapter_test.go) — the internal-field half.
    #[test]
    fn new_validates() {
        assert!(OpenCode::new(Config::default()).is_err(), "no launcher");
        let l: Arc<dyn ProcessLauncher> = Arc::new(crate::fake::FakeLauncher::default());
        let a = OpenCode::new(Config {
            launcher: Some(l.clone()),
            ..Config::default()
        })
        .unwrap();
        assert_eq!(a.pinned, DEFAULT_PINNED_VERSION);
        assert!(!a.probe_work_dir.is_empty());
        assert!(
            OpenCode::new(Config {
                launcher: Some(l.clone()),
                pinned_version: "1.18".to_string(),
                ..Config::default()
            })
            .is_err()
        );
        let a = OpenCode::new(Config {
            launcher: Some(l),
            pinned_version: "9.9.9".to_string(),
            ..Config::default()
        })
        .unwrap();
        assert_eq!(a.pinned, "9.9.9");
    }

    /// `TestRequirePath` (adapter_test.go) — the whole table; the
    /// error never echoes a value.
    #[test]
    fn require_path_table() {
        let env = |vars: &[(&str, &str)]| LaunchEnv {
            vars: vars
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            sandbox_scope_id: String::new(),
        };
        assert!(require_path(&env(&[("PATH", "/usr/bin:/bin")])).is_ok());
        for vars in [
            vec![],
            vec![("PATH", "")],
            vec![("PATH", "bin:/usr/bin")],
            vec![("PATH", "/usr/bin:")],
            vec![("PATH", "/usr/bin::/bin")],
        ] {
            let err = require_path(&env(&vars)).unwrap_err();
            assert_eq!(err.code(), codes::PATH_REQUIRED, "{vars:?}");
            let path = vars
                .iter()
                .find(|(k, _)| *k == "PATH")
                .map(|(_, v)| *v)
                .unwrap_or("");
            if path.len() > 1 {
                assert!(!err.message().contains("bin"), "error echoes the value");
            }
        }
    }
}
