//! `antigravity` — drives the unmodified Antigravity CLI (`agy`)
//! headlessly as an ADR 0035 harness (issue #129 spec). It launches
//! `agy --input-format stream-json --output-format stream-json
//! --disable-slash-commands` only through a `port::ProcessLauncher`,
//! passes only the declared launch parameters, delivers the prompt
//! over stdin as the first NDJSON user event, speaks the CLI's own
//! NDJSON event protocol over stdout, and never reads, stores,
//! injects, relocates or proxies the operator's provider credentials
//! or config. Permission policy is Deny-only: the default headless
//! run auto-denies tools it cannot prompt for, and any other policy
//! is refused fail-closed. Every launch and probe sets
//! `AGY_CLI_DISABLE_AUTO_UPDATE=1` so the pinned version stays
//! meaningful against the CLI's silent self-updater.
//!
//! Upstream `internal/adapter/harness/antigravity`, split as:
//! - `mod` — `antigravity.go` + `adapter.go`: the adapter, its
//!   capabilities, the terminal-reason vocabulary, the launch
//!   refusals, the project-config rule and the launch env;
//! - `argv` — the closed `agy` argv;
//! - `probe` — the version probe;
//! - `protocol` — the stream-json envelope grammar and the
//!   step/result decoders;
//! - `session` — one live process's reader/writer, follow-up `Send`
//!   and terminal logic.

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
pub const KIND: &str = "antigravity";

/// `DefaultPinnedVersion` — the agy version the protocol mapping was
/// captured from (spec E1–E16).
pub const DEFAULT_PINNED_VERSION: &str = "1.3.3";

/// `program` — the symbolic program name every launcher resolves: the
/// backend id, like the other adapters. The daemon configuration maps
/// it to the agy binary (`harness antigravity <path>`).
fn program_name() -> &'static str {
    "antigravity"
}

/// `autoUpdateDisableEnv` — the only `AGY_*` variable the adapter
/// ever passes. It is force-set to `"1"` on every launch and probe,
/// never taken from operator env.
pub const AUTO_UPDATE_DISABLE_ENV: &str = "AGY_CLI_DISABLE_AUTO_UPDATE";

/// The adapter's sentinel failure codes — the upstream `Err*` values.
pub mod codes {
    /// `ErrInvalidLaunch` — a launch would pass unsafe or undeclared
    /// parameters.
    pub const INVALID_LAUNCH: &str = "antigravity_invalid_launch";
    /// `ErrPathRequired` — PATH absent or not absolute-only.
    pub const PATH_REQUIRED: &str = "antigravity_path_required";
    /// `ErrUnpinnedVersion` — the running `agy` differs from the
    /// pinned version.
    pub const UNPINNED_VERSION: &str = "antigravity_unpinned_version";
    /// `ErrUnexpectedProbeOutput` — the probe's output is not the
    /// expected shape.
    pub const UNEXPECTED_PROBE_OUTPUT: &str = "antigravity_unexpected_probe_output";
}

/// The `Terminal.reason` vocabulary (spec D3/D4). The adapter never
/// puts harness text in `reason`; these strings are the only values
/// it sets, and each reuses an `execution` failure reason verbatim.
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
/// The resident stream-json process takes follow-up user events over
/// stdin, resumes by conversation id, and reports per-step token
/// usage (no cost). It has no soft interrupt, no preassigned session
/// id, no permission bridge, no partial deltas (deltas are buffered
/// per step), no reattach after a control-plane restart, and no
/// native cost limit.
pub fn capabilities() -> Capabilities {
    Capabilities {
        streaming_input: true,
        resume_by_id: true,
        usage_tokens: true,
        usage_scope: UsageScope::Step,
        ..Capabilities::default()
    }
}

/// `Config` — configures the adapter.
#[derive(Default)]
pub struct Config {
    /// `Launcher` starts every agy process; the adapter never execs.
    pub launcher: Option<Arc<dyn ProcessLauncher>>,
    /// The expected `agy --version`; empty means
    /// [`DEFAULT_PINNED_VERSION`].
    pub pinned_version: String,
    /// `AllowUnpinned` lets `start` proceed on a different version.
    pub allow_unpinned: bool,
    /// `ProbeWorkDir` — the working directory of the version probe;
    /// empty means the system temp dir.
    pub probe_work_dir: String,
}

/// `Adapter` — drives the `agy` CLI. Implements `port::Adapter`.
pub struct Antigravity {
    pub(crate) launcher: Arc<dyn ProcessLauncher>,
    pub(crate) pinned: String,
    pub(crate) allow_unpinned: bool,
    pub(crate) probe_work_dir: String,
}

impl Antigravity {
    /// `New` — validates `cfg` and returns the adapter.
    pub fn new(cfg: Config) -> Result<Self, Failure> {
        let Some(launcher) = cfg.launcher else {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "antigravity: a process launcher is required",
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
                "antigravity: pinned version must look like 1.2.3",
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

    /// `open` — validates, checks the pinned version, launches agy
    /// and starts the session.
    async fn open(&self, spec: StartSpec, resume_id: &str) -> Result<Box<dyn Session>, Failure> {
        spec.validate(&[AUTO_UPDATE_DISABLE_ENV])?;
        require_path(&spec.env)?;
        if spec.permission != PermissionPolicy::Deny {
            // Headless agy exposes no bridge channel and no scoped
            // auto-allow: only the default deny behavior (auto-deny
            // of the unpromptable) is expressible. Anything else
            // refuses rather than downgrade.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "antigravity: antigravity supports only the deny permission policy",
            ));
        }
        if spec.limits.max_turns > 0 {
            // agy 1.3.3 has no max-turns limit; a limit Central
            // cannot pass must not be silently dropped.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "antigravity: antigravity has no max-turns limit",
            ));
        }
        if spec.limits.max_cost_micro_usd > 0 {
            // No native cost limit exists either; the orchestrator
            // already withholds the limit when NativeCostLimit is
            // false.
            return Err(Failure::new(
                FailureKind::Invalid,
                central_harness::port::codes::UNSUPPORTED,
                "antigravity: antigravity has no native cost limit",
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
                    "antigravity: agy version differs from the pinned version: found {version}, pinned {}",
                    self.pinned
                ),
            ));
        }
        let proc = self
            .launcher
            .launch(ProcessSpec {
                program: program_name().to_string(),
                args,
                env: launch_env(&spec.env.vars),
                work_dir: spec.workspace.path.clone(),
                scope_id: spec.env.sandbox_scope_id.clone(),
                env_extras: self.env_extras().iter().map(|s| (*s).to_string()).collect(),
            })
            .await
            .map_err(|e| {
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("antigravity: launch: {}", e.message()),
                )
            })?;
        let session = session::AntigravitySession::spawn(
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

impl Adapter for Antigravity {
    fn kind(&self) -> Kind {
        Kind::new(KIND)
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    /// `EnvExtras` — the launch-env name this adapter needs beyond
    /// the base allowlist: the self-updater disable, force-set on
    /// every launch and probe (spec D6).
    fn env_extras(&self) -> &[String] {
        extras()
    }

    /// `Probe`.
    fn probe<'a>(&'a self, env: LaunchEnv) -> PortFuture<'a, Result<ProbeResult, Failure>> {
        Box::pin(async move { self.probe_inner(&env).await })
    }

    /// `Start` — launches a fresh session; the harness assigns the
    /// conversation id, which the first event reveals.
    fn start<'a>(&'a self, spec: StartSpec) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move { self.open(spec, "").await })
    }

    /// `Resume` — relaunches ref's conversation with `--conversation`;
    /// the id guard in the event loop refuses any other conversation.
    fn resume<'a>(
        &'a self,
        session_ref: SessionRef,
        spec: StartSpec,
    ) -> PortFuture<'a, Result<Box<dyn Session>, Failure>> {
        Box::pin(async move {
            if !argv::valid_session_id(&session_ref.harness_session_id) {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    "antigravity: resume requires a harness session id",
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
                    "antigravity: reconcile requires a sandbox scope id",
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
                        format!("antigravity: reconcile: {}", e.message()),
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

/// The `EnvExtras` slice (one entry).
fn extras() -> &'static [String] {
    static E: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    E.get_or_init(|| vec![AUTO_UPDATE_DISABLE_ENV.to_string()])
        .as_slice()
}

/// `projectConfigNames` — the worktree entries that make agy load
/// project configuration (spec D6, evidence E11/E12): custom-agent
/// directories, rules files, and the workspace marker. The harness
/// reads them from the worktree root and Central cannot ignore them,
/// so their presence refuses the launch fail-closed.
const PROJECT_CONFIG_NAMES: &[&str] = &[
    ".agent",
    "_agent",
    ".agents",
    "_agents",
    "codeium.yaml",
    ".codeium.yaml",
    "codeium.yml",
    ".codeium.yml",
    ".citc",
];

/// `refuseProjectConfig` — refuses a worktree whose root carries agy
/// project configuration (spec D6). Any file type refuses, and a
/// stat error other than absence refuses too: the check must fail
/// closed.
fn refuse_project_config(workdir: &str) -> Result<(), Failure> {
    for name in PROJECT_CONFIG_NAMES {
        match std::fs::symlink_metadata(std::path::Path::new(workdir).join(name)) {
            Ok(_) => {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    format!("antigravity: worktree contains {name}"),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(Failure::invalid(
                    codes::INVALID_LAUNCH,
                    format!("antigravity: worktree contains {name}"),
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
            "antigravity: PATH is required in the launch env and may list only absolute directories",
        ));
    }
    for dir in path.split(':') {
        if !std::path::Path::new(dir).is_absolute() {
            return Err(Failure::invalid(
                codes::PATH_REQUIRED,
                "antigravity: PATH is required in the launch env and may list only absolute directories: an entry is empty or relative",
            ));
        }
    }
    Ok(())
}

/// `launchEnv` — the launch env from the validated vars, force-
/// setting the self-updater disable: the value never comes from
/// operator env, so the pin stays meaningful against the CLI's
/// silent self-updater.
pub(crate) fn launch_env(
    vars: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    let mut out = vars.clone();
    out.insert(AUTO_UPDATE_DISABLE_ENV.to_string(), "1".to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestCapabilities` / `TestReasons` / `TestKind` /
    /// `TestDefaultPinnedVersion` (antigravity_test.go).
    #[test]
    fn identity_vocabulary() {
        assert_eq!(KIND, "antigravity");
        Kind::new(KIND).validate().unwrap();
        assert_eq!(DEFAULT_PINNED_VERSION, "1.3.3");
        assert!(probe::version_shape(DEFAULT_PINNED_VERSION));
        assert_eq!(reasons().len(), 4);
        let c = capabilities();
        assert!(c.streaming_input && c.resume_by_id && c.usage_tokens);
        assert_eq!(c.usage_scope, UsageScope::Step);
        assert!(!c.cost_usd && !c.interrupt && !c.permission_bridge);
        c.validate().unwrap();
    }

    /// `launchEnv` force-sets the disable var (adapter_test.go
    /// `TestStartForceSetsDisableVar` host half).
    #[test]
    fn launch_env_force_sets() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("PATH".to_string(), "/usr/bin".to_string());
        vars.insert(AUTO_UPDATE_DISABLE_ENV.to_string(), "0".to_string());
        let out = launch_env(&vars);
        assert_eq!(out.get(AUTO_UPDATE_DISABLE_ENV).unwrap(), "1");
        assert_eq!(out.get("PATH").unwrap(), "/usr/bin");
    }

    /// `requirePath` table (mirrors the siblings).
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
        ] {
            let err = require_path(&env(&vars)).unwrap_err();
            assert_eq!(err.code(), codes::PATH_REQUIRED, "{vars:?}");
        }
    }
}
