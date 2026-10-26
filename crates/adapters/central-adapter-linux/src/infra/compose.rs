//! `compose` — the B03 Compose adapter (upstream
//! `internal/adapter/infralifecycle/compose_linux.go`). It renders the
//! closed six-service Compose topology from a binding, prepared
//! dependency set, and the embedded policy; validates rendered models;
//! and executes the fixed `docker compose` protocol through an
//! injectable, closed-environment command boundary.
//!
//! Rendered YAML is byte-parity with upstream's template output; the
//! embedded `assets/compose-policy.json` is copied verbatim.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use central_foundation::failure::Failure;
use central_infra::domain::{LifecycleBinding, OciInventory, PreparedDependencySet, ServiceMode};

// ---------------------------------------------------------------------------
// Sentinel errors — upstream's `errors.Is` targets as a closed enum.
// ---------------------------------------------------------------------------

/// The compose validation/execution sentinel errors (upstream `Err*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    /// `ErrConsolePublished`.
    ConsolePublished(String),
    /// `ErrInvalidServiceCount`.
    InvalidServiceCount(usize),
    /// `ErrMissingService`.
    MissingService(String),
    /// `ErrExtraService`.
    ExtraService(String),
    /// `ErrMissingCapDrop`.
    MissingCapDrop(String),
    /// `ErrCapDropNotAll`.
    CapDropNotAll(String),
    /// `ErrHostNetwork`.
    HostNetwork(String),
    /// `ErrNonReadonlyRoot`.
    NonReadonlyRoot(String),
    /// `ErrHostNamespace`.
    HostNamespace(String),
    /// `ErrHostDevice`.
    HostDevice(String),
    /// `ErrHostSocket`.
    HostSocket(String),
    /// `ErrPrivilegedMode`.
    PrivilegedMode(String),
    /// `ErrMissingNoNewPrivileges`.
    MissingNoNewPrivileges(String),
    /// `ErrComposeExecutionUnavailable`.
    ExecutionUnavailable,
    /// `ErrCredentialInterpolation`.
    CredentialInterpolation(String),
    /// `ErrInvalidCredentialMount`.
    InvalidCredentialMount(String),
    /// Any other adapter failure (upstream's plain `fmt.Errorf`).
    Other(String),
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsolePublished(p) => {
                write!(
                    f,
                    "compose: minio console port must not be published: found port {p:?}"
                )
            }
            Self::InvalidServiceCount(n) => {
                write!(f, "compose: expected exactly 6 services: got {n}")
            }
            Self::MissingService(n) => write!(f, "compose: missing required service: {n:?}"),
            Self::ExtraService(n) => write!(f, "compose: unexpected extra service: {n:?}"),
            Self::MissingCapDrop(n) => {
                write!(
                    f,
                    "compose: service missing cap_drop: service {n:?} has no cap_drop"
                )
            }
            Self::CapDropNotAll(n) => {
                write!(f, "compose: cap_drop must contain ALL: service {n:?}")
            }
            Self::HostNetwork(n) => {
                write!(
                    f,
                    "compose: host network mode not allowed: service {n:?} uses host network"
                )
            }
            Self::NonReadonlyRoot(n) => {
                write!(
                    f,
                    "compose: root filesystem must be read-only: service {n:?} has writable root"
                )
            }
            Self::HostNamespace(n) => {
                write!(f, "compose: host namespace not allowed: service {n:?}")
            }
            Self::HostDevice(n) => {
                write!(f, "compose: host devices not allowed: service {n:?}")
            }
            Self::HostSocket(m) => write!(f, "compose: host socket not allowed: {m}"),
            Self::PrivilegedMode(n) => {
                write!(
                    f,
                    "compose: privileged mode not allowed: service {n:?} is privileged"
                )
            }
            Self::MissingNoNewPrivileges(n) => {
                write!(
                    f,
                    "compose: service missing no-new-privileges security option: service {n:?}"
                )
            }
            Self::ExecutionUnavailable => {
                write!(f, "compose: execution adapter is not installed")
            }
            Self::CredentialInterpolation(k) => {
                write!(f, "compose: credential interpolation is forbidden: {k}")
            }
            Self::InvalidCredentialMount(m) => {
                write!(
                    f,
                    "compose: credential mount is not the fixed read-only handoff: {m}"
                )
            }
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ComposeError {}

impl From<ComposeError> for Failure {
    fn from(e: ComposeError) -> Self {
        Failure::internal("COMPOSE", e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// `RenderedFile` — the rendered Compose file path + YAML content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedFile {
    /// The rendered file path under `/run/central-infra/<instance>/`.
    pub path: String,
    /// The YAML content.
    pub content: Vec<u8>,
}

/// `RenderedModel` — the parsed service map for policy validation.
#[derive(Debug, Clone, Default)]
pub struct RenderedModel {
    /// Service name → rendered service.
    pub services: BTreeMap<String, RenderedService>,
}

/// `RenderedService` — the fields policy validation reads.
#[derive(Debug, Clone, Default)]
pub struct RenderedService {
    /// Digest-qualified image reference.
    pub image: String,
    /// Published port mappings (compact form).
    pub ports: Vec<String>,
    /// `cap_drop`.
    pub cap_drop: Vec<String>,
    /// `cap_add`.
    pub cap_add: Vec<String>,
    /// `shm_size`.
    pub shm_size: String,
    /// `read_only`.
    pub read_only: bool,
    /// Whether `no-new-privileges:true` is in effect.
    pub no_new_privs: bool,
    /// `tmpfs` entries.
    pub tmpfs: Vec<String>,
    /// `environment`.
    pub env: BTreeMap<String, String>,
    /// `user`.
    pub user: String,
    /// `working_dir`.
    pub working_dir: String,
    /// Effective network mode (first network, `none`, or `host`).
    pub network_mode: String,
    /// `privileged`.
    pub privileged: bool,
    /// `pid_mode`.
    pub pid_mode: String,
    /// `ipc`.
    pub ipc_mode: String,
    /// `devices`.
    pub devices: Vec<String>,
    /// `volumes` (compact `src:tgt[:mode]` form).
    pub volumes: Vec<String>,
}

/// `ContainerInspection` — one container's observed state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerInspection {
    /// Container ID.
    pub id: String,
    /// Docker `State.Status`.
    pub state: String,
    /// Docker `State.Health.Status` (empty when no healthcheck).
    pub status: String,
    /// Docker `State.ExitCode`.
    pub exit_code: i64,
}

// ---------------------------------------------------------------------------
// ComposeRunner — the execution boundary. Sync: subprocess I/O is
// synchronous; future-drop cancellation is the caller's concern.
// ---------------------------------------------------------------------------

/// `ComposeRunner` (upstream interface). `run_with_input` returns the
/// real exit code; an `Err` means the subprocess could not be run at
/// all, matching upstream's `err != nil` contract.
pub trait ComposeRunner: Send + Sync {
    /// `Config` — `docker compose config --format json`, parsed+validated.
    fn config(&self, f: &RenderedFile) -> Result<RenderedModel, ComposeError>;
    /// `Up` — starts the given services (or all when empty).
    fn up(&self, f: &RenderedFile, services: &[String]) -> Result<(), ComposeError>;
    /// `RunWithInput` — `compose run --rm -T <service> <args...>` with
    /// stdin piped; returns the real exit code.
    fn run_with_input(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<i32, ComposeError>;
    /// `RunWithInputOutput` — the receipt-bearing variant returning
    /// capped stdout alongside the exit code.
    fn run_with_input_output(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<(Vec<u8>, i32), ComposeError>;
    /// `Down` — `compose down --remove-orphans`.
    fn down(&self, f: &RenderedFile) -> Result<(), ComposeError>;
    /// `Inspect` — `docker inspect --format {{json .}}` by container ID.
    fn inspect(&self, container_id: &str) -> Result<ContainerInspection, ComposeError>;
    /// `Containers` — resolves the exact current container per service.
    fn containers(
        &self,
        f: &RenderedFile,
        services: &[String],
    ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError>;
    /// `Stopped` — verifies no current container exists per service.
    fn stopped(&self, f: &RenderedFile, services: &[String]) -> Result<(), ComposeError>;
}

/// `CommandExecutor` — the injectable subprocess boundary.
pub type CommandExecutor =
    Box<dyn Fn(&str, &[String], &[String]) -> Result<Vec<u8>, String> + Send + Sync>;

/// `stdinCommandExecutor` — the narrow stdin-piping boundary; reports
/// the real exit code (nonzero with `Ok` means the process ran).
pub type StdinCommandExecutor =
    Box<dyn Fn(&str, &[String], &[String], &[u8]) -> Result<(Vec<u8>, i32), String> + Send + Sync>;

/// `CommandComposeRunner` — executes the fixed Docker Compose protocol
/// using an absolute Docker binary; never a shell wrapper.
pub struct CommandComposeRunner {
    docker_path: String,
    exec: CommandExecutor,
    exec_with_input: StdinCommandExecutor,
}

impl CommandComposeRunner {
    /// `NewCommandComposeRunner` — injected executors; `None` installs
    /// the real subprocess implementation.
    pub fn new(
        docker_path: &str,
        exec: Option<CommandExecutor>,
        exec_with_input: Option<StdinCommandExecutor>,
    ) -> Self {
        Self {
            docker_path: docker_path.to_owned(),
            exec: exec.unwrap_or_else(|| Box::new(execute_command)),
            exec_with_input: exec_with_input
                .unwrap_or_else(|| Box::new(execute_command_with_input)),
        }
    }

    fn run(&self, f: &RenderedFile, command: &[String]) -> Result<Vec<u8>, ComposeError> {
        let project = compose_project_for_file(f)?;
        let mut args = vec![
            "compose".to_owned(),
            "--project-name".to_owned(),
            project,
            "--file".to_owned(),
            f.path.clone(),
        ];
        args.extend(command.iter().cloned());
        (self.exec)(&self.docker_path, &args, &closed_docker_environment())
            .map_err(|e| ComposeError::Other(format!("compose: {e}")))
    }
}

/// `executeCommand` — the real subprocess implementation.
fn execute_command(name: &str, args: &[String], env: &[String]) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(name);
    cmd.args(args)
        .env_clear()
        .envs(env.iter().filter_map(|e| e.split_once('=')));
    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(output.stdout)
}

/// `executeCommandWithInput` — real subprocess with stdin piped, capped
/// 64KiB stdout, discarded stderr, real exit code.
fn execute_command_with_input(
    name: &str,
    args: &[String],
    env: &[String],
    stdin: &[u8],
) -> Result<(Vec<u8>, i32), String> {
    let mut cmd = Command::new(name);
    cmd.args(args)
        .env_clear()
        .envs(env.iter().filter_map(|e| e.split_once('=')))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let Some(mut w) = child.stdin.take() {
        let _ = w.write_all(stdin);
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    let code = output.status.code().unwrap_or(-1);
    if output.stdout.len() > 64 * 1024 {
        return Err("compose: subprocess stdout exceeds limit".to_owned());
    }
    Ok((output.stdout, code))
}

impl ComposeRunner for CommandComposeRunner {
    fn config(&self, f: &RenderedFile) -> Result<RenderedModel, ComposeError> {
        let output = self
            .run(
                f,
                &[
                    "config".to_owned(),
                    "--format".to_owned(),
                    "json".to_owned(),
                ],
            )
            .map_err(|e| ComposeError::Other(format!("compose: config: {e}")))?;
        let model = parse_rendered_model(&output)?;
        validate_model(&model)?;
        Ok(model)
    }

    fn up(&self, f: &RenderedFile, services: &[String]) -> Result<(), ComposeError> {
        // --wait + --pull never: see upstream's comment on the nonexistent
        // --no-pull flag (2026-08-17).
        let mut args = vec![
            "up".to_owned(),
            "--detach".to_owned(),
            "--wait".to_owned(),
            "--no-build".to_owned(),
            "--pull".to_owned(),
            "never".to_owned(),
        ];
        args.extend(services.iter().cloned());
        self.run(f, &args)
            .map_err(|e| ComposeError::Other(format!("compose: up: {e}")))?;
        Ok(())
    }

    fn run_with_input(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<i32, ComposeError> {
        let (_, code) = self.run_with_input_output(f, service, args, stdin)?;
        Ok(code)
    }

    fn run_with_input_output(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<(Vec<u8>, i32), ComposeError> {
        let project = compose_project_for_file(f)?;
        let mut compose_args = vec![
            "compose".to_owned(),
            "--project-name".to_owned(),
            project,
            "--file".to_owned(),
            f.path.clone(),
            "run".to_owned(),
            "--rm".to_owned(),
            "-T".to_owned(),
            service.to_owned(),
        ];
        compose_args.extend(args.iter().cloned());
        let (output, code) = (self.exec_with_input)(
            &self.docker_path,
            &compose_args,
            &closed_docker_environment(),
            stdin,
        )
        .map_err(|e| ComposeError::Other(format!("compose: run: {e}")))?;
        Ok((output, code))
    }

    fn down(&self, f: &RenderedFile) -> Result<(), ComposeError> {
        self.run(f, &["down".to_owned(), "--remove-orphans".to_owned()])
            .map_err(|e| ComposeError::Other(format!("compose: down: {e}")))?;
        Ok(())
    }

    fn inspect(&self, container_id: &str) -> Result<ContainerInspection, ComposeError> {
        if container_id.is_empty() || container_id.contains(['/', '\0']) {
            return Err(ComposeError::Other(
                "compose: invalid container id".to_owned(),
            ));
        }
        // SC-DEF-26: `{{json .}}` avoids inspect-template strictness on
        // containers with no HEALTHCHECK.
        let output = (self.exec)(
            &self.docker_path,
            &[
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{json .}}".to_owned(),
                container_id.to_owned(),
            ],
            &closed_docker_environment(),
        )
        .map_err(|e| ComposeError::Other(format!("compose: inspect: {e}")))?;
        #[derive(Deserialize)]
        struct InspectState {
            #[serde(rename = "Id")]
            id: String,
            #[serde(rename = "State")]
            state: StateBody,
        }
        #[derive(Deserialize)]
        struct StateBody {
            #[serde(rename = "Status")]
            status: String,
            #[serde(rename = "ExitCode")]
            exit_code: i64,
            #[serde(rename = "Health")]
            health: Option<HealthBody>,
        }
        #[derive(Deserialize)]
        struct HealthBody {
            #[serde(rename = "Status")]
            status: String,
        }
        let inspected: InspectState = serde_json::from_slice(&output)
            .map_err(|e| ComposeError::Other(format!("compose: invalid inspect output: {e}")))?;
        Ok(ContainerInspection {
            id: inspected.id,
            state: inspected.state.status,
            status: inspected.state.health.map(|h| h.status).unwrap_or_default(),
            exit_code: inspected.state.exit_code,
        })
    }

    fn containers(
        &self,
        f: &RenderedFile,
        services: &[String],
    ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError> {
        if services.is_empty() {
            return Err(ComposeError::Other(
                "compose: no services requested for inspection".to_owned(),
            ));
        }
        let mut containers = BTreeMap::new();
        for service in services {
            if service.is_empty() || service.contains(['/', '\0']) {
                return Err(ComposeError::Other(
                    "compose: invalid service name".to_owned(),
                ));
            }
            let output = self
                .run(
                    f,
                    &[
                        "ps".to_owned(),
                        "--all".to_owned(),
                        "--quiet".to_owned(),
                        service.clone(),
                    ],
                )
                .map_err(|e| {
                    ComposeError::Other(format!("compose: inspect service {service}: {e}"))
                })?;
            let id = String::from_utf8_lossy(&output).trim().to_owned();
            if id.is_empty() {
                containers.insert(service.clone(), ContainerInspection::default());
                continue;
            }
            if id.contains(['\n', '\r']) {
                return Err(ComposeError::Other(format!(
                    "compose: service {service} has no unique container"
                )));
            }
            let inspection = self.inspect(&id)?;
            containers.insert(service.clone(), inspection);
        }
        Ok(containers)
    }

    fn stopped(&self, f: &RenderedFile, services: &[String]) -> Result<(), ComposeError> {
        for service in services {
            let output = self
                .run(
                    f,
                    &[
                        "ps".to_owned(),
                        "--all".to_owned(),
                        "--quiet".to_owned(),
                        service.clone(),
                    ],
                )
                .map_err(|e| {
                    ComposeError::Other(format!("compose: verify stopped service {service}: {e}"))
                })?;
            if !String::from_utf8_lossy(&output).trim().is_empty() {
                return Err(ComposeError::Other(format!(
                    "compose: service {service} remains after teardown"
                )));
            }
        }
        Ok(())
    }
}

/// `composeProjectForFile` — resolves the project name; the file must
/// live at `/run/central-infra/<instance>/docker-compose.yaml`.
pub fn compose_project_for_file(f: &RenderedFile) -> Result<String, ComposeError> {
    let clean = normalize_path(&f.path);
    const PREFIX: &str = "/run/central-infra/";
    if !clean.starts_with(PREFIX) || clean.rsplit('/').next().unwrap_or("") != "docker-compose.yaml"
    {
        return Err(ComposeError::Other(
            "compose: rendered file is outside the protected runtime directory".to_owned(),
        ));
    }
    let dir = clean[..clean.len() - "/docker-compose.yaml".len()].to_owned();
    let instance_id = dir.rsplit('/').next().unwrap_or("").to_owned();
    if instance_id.is_empty() || instance_id == "." || instance_id.contains(['/', '\0']) {
        return Err(ComposeError::Other(
            "compose: invalid instance binding".to_owned(),
        ));
    }
    Ok(format!("central-{instance_id}"))
}

/// `filepath.Clean` equivalent for the constrained inputs here.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `closedDockerEnvironment`.
pub fn closed_docker_environment() -> Vec<String> {
    vec![
        "PATH=/usr/bin:/bin".to_owned(),
        "HOME=/nonexistent".to_owned(),
        "LANG=C".to_owned(),
        "LC_ALL=C".to_owned(),
    ]
}

/// `DummyComposeRunner` — fails closed so it cannot report a fabricated
/// Compose success.
pub struct DummyComposeRunner;

impl ComposeRunner for DummyComposeRunner {
    fn config(&self, _f: &RenderedFile) -> Result<RenderedModel, ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn up(&self, _f: &RenderedFile, _s: &[String]) -> Result<(), ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn run_with_input(
        &self,
        _f: &RenderedFile,
        _s: &str,
        _a: &[String],
        _i: &[u8],
    ) -> Result<i32, ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn run_with_input_output(
        &self,
        _f: &RenderedFile,
        _s: &str,
        _a: &[String],
        _i: &[u8],
    ) -> Result<(Vec<u8>, i32), ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn down(&self, _f: &RenderedFile) -> Result<(), ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn inspect(&self, _id: &str) -> Result<ContainerInspection, ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn containers(
        &self,
        _f: &RenderedFile,
        _s: &[String],
    ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
    fn stopped(&self, _f: &RenderedFile, _s: &[String]) -> Result<(), ComposeError> {
        Err(ComposeError::ExecutionUnavailable)
    }
}

// ---------------------------------------------------------------------------
// Policy types — serde field names are the JSON document's own.
// ---------------------------------------------------------------------------

/// `Policy` — the decoded compose-policy.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// `schema`.
    pub schema: String,
    /// `digest`.
    pub digest: String,
    /// `resources`.
    pub resources: PolicyResources,
    /// `postgresql_shm_size`.
    pub postgresql_shm_size: String,
    /// `security`.
    pub security: PolicySecurity,
    /// `network`.
    pub network: PolicyNetwork,
    /// `ports`.
    pub ports: PolicyPorts,
    /// `image_pull_policy`.
    pub image_pull_policy: String,
    /// `restart_policy`.
    pub restart_policy: String,
    /// `log`.
    pub log: PolicyLog,
    /// `services`.
    pub services: Vec<PolicyServiceSpec>,
}

/// `PolicyResources`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyResources {
    /// `postgres_daemon`.
    pub postgres_daemon: ResourceSpec,
    /// `minio_daemon`.
    pub minio_daemon: ResourceSpec,
    /// `fs_initializer`.
    pub fs_initializer: ResourceSpec,
    /// `provisioner`.
    pub provisioner: ResourceSpec,
}

/// `ResourceSpec`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSpec {
    /// `cpu`.
    pub cpu: String,
    /// `memory`.
    pub memory: String,
    /// `pids`.
    pub pids: i64,
}

/// `PolicySecurity`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicySecurity {
    /// `cap_drop`.
    pub cap_drop: Vec<String>,
    /// `no_new_privileges`.
    pub no_new_privileges: bool,
    /// `readonly_rootfs`.
    pub readonly_rootfs: bool,
    /// `seccomp`.
    pub seccomp: String,
    /// `apparmor`.
    pub apparmor: String,
    /// `propagation`.
    pub propagation: String,
    /// `host_devices`.
    pub host_devices: bool,
    /// `host_pid`.
    pub host_pid: bool,
    /// `host_ipc`.
    pub host_ipc: bool,
    /// `host_network`.
    pub host_network: bool,
    /// `host_socket`.
    pub host_socket: bool,
    /// `privileged`.
    pub privileged: bool,
}

/// `PolicyNetwork`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyNetwork {
    /// `internal`.
    pub internal: bool,
    /// `name`.
    pub name: String,
}

/// `PolicyPorts`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyPorts {
    /// `postgres`.
    pub postgres: Vec<String>,
    /// `minio`.
    pub minio: Vec<String>,
    /// `console_block`.
    pub console_block: bool,
}

/// `PolicyLog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyLog {
    /// `driver`.
    pub driver: String,
    /// `max_files`.
    pub max_files: i64,
    /// `max_size`.
    pub max_size: String,
}

/// `PolicyServiceSpec` — `ports` is computed at render, never from JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyServiceSpec {
    /// `name`.
    pub name: String,
    /// `role`.
    pub role: String,
    /// `cap_add`.
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// `network`.
    pub network: String,
    /// `working_dir`.
    pub working_dir: String,
    /// `user`.
    pub user: String,
    /// `shm_size`.
    #[serde(default)]
    pub shm_size: String,
    /// `tmpfs`.
    #[serde(default)]
    pub tmpfs: Vec<String>,
    /// `volumes`.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// `environment`.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// `command`.
    #[serde(default)]
    pub command: Vec<String>,
    /// `healthcheck`.
    pub healthcheck: Option<PolicyHealthcheck>,
    /// Render-computed published ports.
    #[serde(skip)]
    pub ports: Vec<String>,
}

/// `PolicyHealthcheck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyHealthcheck {
    /// `test`.
    pub test: Vec<String>,
    /// `interval`.
    pub interval: String,
    /// `timeout`.
    pub timeout: String,
    /// `retries`.
    pub retries: i64,
    /// `start_period`.
    pub start_period: String,
}

/// `requiredServiceModes` — the closed six-service census: B03's five
/// modes plus ADR 0014's on-demand `postgres-throughput-provision`.
/// `postgres-provision` was removed by ADR 0026 (see upstream comment).
pub const REQUIRED_SERVICE_MODES: [&str; 6] = [
    "postgres-fs-init",
    "minio-fs-init",
    "postgres",
    "minio",
    "minio-provision",
    "postgres-throughput-provision",
];

// ---------------------------------------------------------------------------
// Embedded policy
// ---------------------------------------------------------------------------

const DEFAULT_POLICY_JSON: &[u8] = include_bytes!("assets/compose-policy.json");

/// `LoadDefaultPolicy` — decodes the embedded compose-policy.json.
pub fn load_default_policy() -> Result<Policy, ComposeError> {
    serde_json::from_slice(DEFAULT_POLICY_JSON)
        .map_err(|e| ComposeError::Other(format!("compose: decode default policy: {e}")))
}

impl Policy {
    /// `ResourceForRole`.
    #[must_use]
    pub fn resource_for_role(&self, role: &str) -> Option<ResourceSpec> {
        resource_for_role(role, &self.resources)
    }
}

fn resource_for_role(role: &str, res: &PolicyResources) -> Option<ResourceSpec> {
    match role {
        "postgres_daemon" => Some(res.postgres_daemon.clone()),
        "minio_daemon" => Some(res.minio_daemon.clone()),
        "fs_initializer" => Some(res.fs_initializer.clone()),
        "provisioner" => Some(res.provisioner.clone()),
        _ => None,
    }
}

/// `ModeImageKey` — compose service name → dependency-prepare mode.
pub fn mode_image_key(service_name: &str) -> Result<ServiceMode, ComposeError> {
    match service_name {
        "postgres-fs-init" => Ok(ServiceMode::PostgresFsInit),
        "minio-fs-init" => Ok(ServiceMode::MinioFsInit),
        "postgres" => Ok(ServiceMode::Postgres),
        "minio" => Ok(ServiceMode::Minio),
        "minio-provision" => Ok(ServiceMode::MinioProvision),
        "postgres-throughput-provision" => Ok(ServiceMode::PostgresThroughputProvision),
        other => Err(ComposeError::Other(format!(
            "compose: unknown service {other:?}"
        ))),
    }
}

/// `dependencyprepare.BuiltImageRepository`.
pub const BUILT_IMAGE_REPOSITORY: &str = "central-minio";
/// `dependencyprepare.InfraImageRepository`.
pub const INFRA_IMAGE_REPOSITORY: &str = "ghcr.io/enolalab/central-local-infra";

/// `ImageReference` — the exact local image reference for one B02 mode.
/// ADR 0024 Decision 1 (Option 1B): the MinIO daemon is the B02-built
/// `central-minio` image, not a mode of `central-local-infra`.
pub fn image_reference(
    mode: ServiceMode,
    inventory: &OciInventory,
) -> Result<String, ComposeError> {
    if inventory.manifest_digest.is_empty() {
        return Err(ComposeError::Other(format!(
            "compose: mode {} lacks manifest digest",
            mode.as_str()
        )));
    }
    match mode {
        ServiceMode::Postgres | ServiceMode::PostgresProvision => Ok(format!(
            "library/postgres:16.14-bookworm@{}",
            inventory.manifest_digest
        )),
        ServiceMode::Minio => Ok(format!(
            "{BUILT_IMAGE_REPOSITORY}@{}",
            inventory.manifest_digest
        )),
        ServiceMode::PostgresFsInit
        | ServiceMode::MinioFsInit
        | ServiceMode::MinioProvision
        | ServiceMode::PostgresThroughputProvision => Ok(format!(
            "{INFRA_IMAGE_REPOSITORY}@{}",
            inventory.manifest_digest
        )),
    }
}

// ---------------------------------------------------------------------------
// Render — byte-parity port of upstream's composeYAML template.
// ---------------------------------------------------------------------------

/// `Render` — renders the Compose YAML satisfying `policy` for
/// `binding`/`set`.
pub fn render(
    binding: &LifecycleBinding,
    set: &PreparedDependencySet,
    policy: &Policy,
) -> Result<RenderedFile, ComposeError> {
    binding
        .validate()
        .map_err(|e| ComposeError::Other(format!("compose: render: {e}")))?;
    set.validate_b03()
        .map_err(|e| ComposeError::Other(format!("compose: render: {e}")))?;
    // The sixth rendered service needs its image even though
    // ValidateB03 does not require PostgresThroughputProvision.
    if !set
        .modes
        .iter()
        .any(|m| m.mode == ServiceMode::PostgresThroughputProvision)
    {
        return Err(ComposeError::Other(format!(
            "compose: render: missing prepared mode {}",
            ServiceMode::PostgresThroughputProvision.as_str()
        )));
    }

    let mut image_by_mode: BTreeMap<String, String> = BTreeMap::new();
    for pm in &set.modes {
        let r = image_reference(pm.mode, &pm.inventory)?;
        image_by_mode.insert(pm.mode.as_str().to_owned(), r);
    }

    let mut services = policy.services.clone();
    for service in &mut services {
        service.ports = ports_for_service_spec(&service.name, &policy.ports);
        service
            .volumes
            .extend(durable_data_mounts(&binding.instance_id, &service.name));
        add_fixed_secret_mount(binding, service)?;
        add_broker_socket_mount(binding, service);
        add_postgres_admin_passfile_mount(binding, service);
        add_postgres_init_script_mount(binding, service);
        validate_environment(&service.environment, &service.volumes)?;
    }

    let path = format!(
        "/run/central-infra/{}/docker-compose.yaml",
        binding.instance_id
    );
    let content = render_yaml(
        &format!("central-{}", binding.instance_id),
        binding,
        &services,
        &image_by_mode,
        policy,
    );
    Ok(RenderedFile {
        path,
        content: content.into_bytes(),
    })
}

/// The upstream `composeYAML` template rendered byte-parity. Conditional
/// blocks follow the `{{if}}…{{end}}` newline semantics: an `if` on its
/// own line emits the inner lines plus the newline before `{{end}}`;
/// `{{-` trims the preceding newline.
#[allow(clippy::too_many_lines)]
fn render_yaml(
    project_name: &str,
    binding: &LifecycleBinding,
    services: &[PolicyServiceSpec],
    image_by_mode: &BTreeMap<String, String>,
    policy: &Policy,
) -> String {
    let mut out = String::new();
    out.push_str("# Generated by central compose adapter\n");
    out.push_str(&format!(
        "# Binding: {} (epoch {})\n",
        binding.instance_id, binding.payload_epoch
    ));
    out.push_str(&format!("name: {project_name}\n\nservices:"));

    for svc in services {
        out.push_str(&format!("\n  {}:\n", svc.name));
        out.push_str(&format!(
            "    image: {}\n",
            image_by_mode.get(&svc.name).cloned().unwrap_or_default()
        ));
        out.push_str(&format!("    pull_policy: {}\n", policy.image_pull_policy));
        out.push_str(&format!("    restart: \"{}\"\n", policy.restart_policy));
        out.push_str(&format!(
            "    cap_drop: [{}]\n",
            policy.security.cap_drop.join(", ")
        ));
        out.push_str(&format!("    cap_add: [{}]\n", svc.cap_add.join(", ")));
        out.push_str("    security_opt:\n");
        if policy.security.no_new_privileges {
            out.push_str("\n      - \"no-new-privileges:true\"\n");
        }
        out.push('\n'); // newline after {{end}}
        out.push('\n'); // newline after the template comment block
        if !policy.security.seccomp.is_empty() && policy.security.seccomp != "default" {
            out.push_str(&format!("\n      - seccomp={}\n", policy.security.seccomp));
        }
        out.push('\n');
        if !policy.security.apparmor.is_empty() {
            out.push_str(&format!(
                "\n      - apparmor={}\n",
                policy.security.apparmor
            ));
        }
        out.push('\n');
        out.push_str(&format!(
            "    read_only: {}",
            policy.security.readonly_rootfs
        ));
        if !svc.shm_size.is_empty() {
            out.push_str(&format!("\n    shm_size: {}", svc.shm_size));
        }
        if !svc.tmpfs.is_empty() {
            out.push_str("\n    tmpfs:");
            for t in &svc.tmpfs {
                out.push_str(&format!("\n      - {t}"));
            }
        }
        if svc.network != "none" {
            out.push_str("\n    network_mode: \"\"\n\n    networks:\n");
            out.push_str(&format!("      {}:", svc.network));
            if !svc.ports.is_empty() {
                out.push_str(&format!("\n      {}-host:", policy.network.name));
            }
        } else {
            out.push_str("\n    network_mode: none");
        }
        if !svc.user.is_empty() {
            out.push_str(&format!("\n    user: \"{}\"", svc.user));
        }
        if !svc.working_dir.is_empty() {
            out.push_str(&format!("\n    working_dir: {}", svc.working_dir));
        }
        if !svc.environment.is_empty() {
            out.push_str("\n    environment:");
            for (k, v) in &svc.environment {
                out.push_str(&format!("\n      {k}: \"{v}\""));
            }
        }
        if !svc.command.is_empty() {
            out.push_str(&format!(
                "\n    command: {}",
                quote_strings_yaml(&svc.command)
            ));
        }
        if !svc.volumes.is_empty() {
            out.push_str("\n    volumes:");
            for v in &svc.volumes {
                out.push_str(&format!("\n      - \"{v}\""));
            }
        }
        if let Some(h) = &svc.healthcheck {
            out.push_str("\n    healthcheck:");
            out.push_str(&format!("\n      test: {}", quote_strings_yaml(&h.test)));
            out.push_str(&format!("\n      interval: \"{}\"", h.interval));
            out.push_str(&format!("\n      timeout: \"{}\"", h.timeout));
            out.push_str(&format!("\n      retries: {}", h.retries));
            out.push_str(&format!("\n      start_period: \"{}\"", h.start_period));
        }
        if !policy.log.driver.is_empty() {
            out.push_str("\n    logging:");
            out.push_str(&format!("\n      driver: {}", policy.log.driver));
            out.push_str("\n      options:");
            out.push_str(&format!("\n        max-file: \"{}\"", policy.log.max_files));
            out.push_str(&format!("\n        max-size: \"{}\"", policy.log.max_size));
        }
        let res = resource_for_role(&svc.role, &policy.resources).unwrap_or_default();
        out.push_str("\n    deploy:");
        out.push_str("\n      resources:");
        out.push_str("\n        limits:");
        out.push_str(&format!("\n          cpus: \"{}\"", res.cpu));
        out.push_str(&format!("\n          memory: {}", res.memory));
        out.push_str(&format!("\n          pids: {}", res.pids));
        if !svc.ports.is_empty() {
            out.push_str("\n    ports:");
            for p in &svc.ports {
                out.push_str(&format!("\n      - \"{p}\""));
            }
        }
    }

    out.push_str("\n\nnetworks:");
    out.push_str(&format!("\n  {}:", policy.network.name));
    out.push_str(&format!("\n    internal: {}", policy.network.internal));
    out.push_str(&format!("\n    name: {}", policy.network.name));
    out.push_str(&format!("\n  {}-host:", policy.network.name));
    out.push_str("\n    internal: false");
    out.push_str("\n    driver_opts:");
    out.push_str("\n      com.docker.network.bridge.enable_ip_masquerade: \"false\"");
    out.push_str(&format!("\n    name: {}-host\n", policy.network.name));
    out
}

fn quote_strings_yaml(s: &[String]) -> String {
    let quoted: Vec<String> = s.iter().map(|v| format!("{v:?}")).collect();
    format!("[{}]", quoted.join(", "))
}

fn ports_for_service_spec(svc_name: &str, ports: &PolicyPorts) -> Vec<String> {
    match svc_name {
        "postgres" => ports.postgres.clone(),
        "minio" => ports.minio.clone(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Durable data mounts and credential mounts
// ---------------------------------------------------------------------------

/// `fsInitPayloadContainerPath` + `fsInitTargetLeaf`.
pub const FS_INIT_PAYLOAD_CONTAINER_PATH: &str = "/payload";
/// `fsInitTargetLeaf`.
pub const FS_INIT_TARGET_LEAF: &str = "data";
/// `fsInitTargetContainerPath` — equals central-local-infra's
/// compiled-in `target.FSInitTargetPath`.
pub const FS_INIT_TARGET_CONTAINER_PATH: &str = "/payload/data";

/// `durableStateInstancesRoot` — the fixed authoritative instances
/// hierarchy (compiled in; never request-derived).
pub fn durable_state_instances_root() -> &'static str {
    "/var/lib/central-state/v1/instances"
}

/// `durableServiceRoot`.
pub fn durable_service_root(instance_id: &str, service: &str) -> String {
    format!(
        "{}/{}/data/{}",
        durable_state_instances_root(),
        instance_id,
        service
    )
}

/// `durableServiceDataRoot`.
pub fn durable_service_data_root(instance_id: &str, service: &str) -> String {
    format!(
        "{}/{}",
        durable_service_root(instance_id, service),
        FS_INIT_TARGET_LEAF
    )
}

/// `durableDataBindMounts` as (host, container, mode).
pub fn durable_data_bind_mounts(instance_id: &str, service: &str) -> Vec<(String, String, String)> {
    match service {
        "postgres-fs-init" => vec![(
            durable_service_root(instance_id, "postgres"),
            FS_INIT_PAYLOAD_CONTAINER_PATH.to_owned(),
            "rw".to_owned(),
        )],
        "minio-fs-init" => vec![(
            durable_service_root(instance_id, "minio"),
            FS_INIT_PAYLOAD_CONTAINER_PATH.to_owned(),
            "rw".to_owned(),
        )],
        "postgres" => vec![(
            durable_service_data_root(instance_id, "postgres"),
            "/var/lib/postgresql/data".to_owned(),
            "rw".to_owned(),
        )],
        "minio" => vec![(
            durable_service_data_root(instance_id, "minio"),
            "/data".to_owned(),
            "rw".to_owned(),
        )],
        _ => Vec::new(),
    }
}

/// `durableDataMounts` — compact `host:container:mode` strings.
pub fn durable_data_mounts(instance_id: &str, service: &str) -> Vec<String> {
    durable_data_bind_mounts(instance_id, service)
        .into_iter()
        .map(|(h, c, m)| format!("{h}:{c}:{m}"))
        .collect()
}

struct CredentialMountRule {
    env_key: &'static str,
    target: &'static str,
    source: &'static str,
}

/// `fixedCredentialMounts` — the closed (env key, target, source) table;
/// ADR 0012 (minio + minio-provision) + ADR 0019 (postgres superuser).
fn fixed_credential_mount(service: &str) -> Option<CredentialMountRule> {
    match service {
        "minio" | "minio-provision" => Some(CredentialMountRule {
            env_key: "MINIO_ROOT_PASSWORD_FILE",
            target: "/run/secrets/minio-root-password",
            source: "minio-root-password",
        }),
        "postgres" => Some(CredentialMountRule {
            env_key: "POSTGRES_PASSWORD_FILE",
            target: "/run/secrets/postgres-superuser-passfile",
            source: "postgres-superuser-passfile",
        }),
        _ => None,
    }
}

/// `brokerSocketTarget`.
pub const BROKER_SOCKET_TARGET: &str = "/run/broker/minio-provision.sock";

fn add_fixed_secret_mount(
    binding: &LifecycleBinding,
    service: &mut PolicyServiceSpec,
) -> Result<(), ComposeError> {
    for (key, target) in &service.environment {
        if !key.ends_with("_FILE") {
            continue;
        }
        let Some(rule) = fixed_credential_mount(&service.name) else {
            return Err(ComposeError::Other(format!(
                "compose: unsupported _FILE credential destination {key} for service {}",
                service.name
            )));
        };
        if key != rule.env_key || target != rule.target {
            return Err(ComposeError::Other(format!(
                "compose: unsupported _FILE credential destination {key} for service {}",
                service.name
            )));
        }
        let source = format!(
            "/run/central-infra/{}/secrets/{}",
            binding.instance_id, rule.source
        );
        let expected_dir = format!("/run/central-infra/{}/secrets", binding.instance_id);
        if dir_of(&source) != expected_dir {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "source {source:?} is outside current instance {:?}",
                binding.instance_id
            )));
        }
        service.volumes.push(format!("{source}:{target}:ro"));
    }
    Ok(())
}

fn add_broker_socket_mount(binding: &LifecycleBinding, service: &mut PolicyServiceSpec) {
    if service.name != "minio-provision" {
        return;
    }
    let source = format!(
        "/run/central-infra/{}/broker/minio-provision.sock",
        binding.instance_id
    );
    service
        .volumes
        .push(format!("{source}:{BROKER_SOCKET_TARGET}"));
}

/// `postgresAdminPassfileTarget` (ADR 0014 §4).
pub const POSTGRES_ADMIN_PASSFILE_TARGET: &str = "/run/secrets/postgres-admin-passfile";

fn add_postgres_admin_passfile_mount(binding: &LifecycleBinding, service: &mut PolicyServiceSpec) {
    if service.name != "postgres-throughput-provision" {
        return;
    }
    let source = format!(
        "/run/central-infra/{}/secrets/postgres-admin-passfile",
        binding.instance_id
    );
    service
        .volumes
        .push(format!("{source}:{POSTGRES_ADMIN_PASSFILE_TARGET}:ro"));
}

/// `PostgresInitScriptName` (ADR 0019 §3).
pub const POSTGRES_INIT_SCRIPT_NAME: &str = "001-central-roles.sql";
/// `postgresInitScriptTarget`.
pub const POSTGRES_INIT_SCRIPT_TARGET: &str = "/docker-entrypoint-initdb.d/001-central-roles.sql";

/// `PostgresInitScriptSQL` — NOLOGIN NOINHERIT roles, no password
/// material, idempotent DO blocks, `central_migration` owns `central`
/// (SC-DEF-43).
pub const POSTGRES_INIT_SCRIPT_SQL: &str = r"-- Generated by central compose adapter (ADR 0019).
-- First-boot role topology: NOLOGIN NOINHERIT roles with no passwords.
-- The root helper's rotate-then-sync protocol grants LOGIN and sets each
-- password from the protected store; nothing in this file is secret.
DO $$ BEGIN CREATE ROLE central_migration NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE central_runtime NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE central_outbox NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
ALTER DATABASE central OWNER TO central_migration;
";

/// `PostgresInitScriptHostPath` — the single-instance-anchored host
/// source the topology writer also targets.
#[must_use]
pub fn postgres_init_script_host_path(root: &str, instance_id: &str) -> String {
    let root = if root.is_empty() {
        "/run/central-infra"
    } else {
        root
    };
    format!("{root}/{instance_id}/init/{POSTGRES_INIT_SCRIPT_NAME}")
}

fn add_postgres_init_script_mount(binding: &LifecycleBinding, service: &mut PolicyServiceSpec) {
    if service.name != "postgres" {
        return;
    }
    let source = postgres_init_script_host_path("", &binding.instance_id);
    service
        .volumes
        .push(format!("{source}:{POSTGRES_INIT_SCRIPT_TARGET}:ro"));
}

fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(i) => path[..i].to_owned(),
    }
}

fn base_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `validateEnvironment`.
fn validate_environment(
    environment: &BTreeMap<String, String>,
    volumes: &[String],
) -> Result<(), ComposeError> {
    for (key, value) in environment {
        if value.contains("${") || value.contains("$${") {
            return Err(ComposeError::CredentialInterpolation(key.clone()));
        }
        if key.ends_with("_FILE") && !has_mount_target(value, volumes) {
            return Err(ComposeError::Other(format!(
                "compose: _FILE environment {key} has no fixed read-only mount"
            )));
        }
    }
    Ok(())
}

fn has_mount_target(target: &str, volumes: &[String]) -> bool {
    volumes.iter().any(|v| {
        let parts: Vec<&str> = v.split(':').collect();
        parts.len() >= 2 && parts[1] == target
    })
}

// ---------------------------------------------------------------------------
// ParseRenderedModel — accepts `docker compose config --format json`
// output (SC-DEF-19) and this renderer's own YAML subset.
// ---------------------------------------------------------------------------

/// `ParseRenderedModel` — parses either JSON (compose config output) or
/// the renderer's own YAML output into a [`RenderedModel`].
pub fn parse_rendered_model(content: &[u8]) -> Result<RenderedModel, ComposeError> {
    let trimmed = trim_ascii_start(content);
    if trimmed.first() == Some(&b'{') {
        return parse_rendered_model_json(content);
    }
    parse_rendered_model_yaml(content)
}

fn trim_ascii_start(b: &[u8]) -> &[u8] {
    let mut s = b;
    while let Some((&c, rest)) = s.split_first() {
        if !c.is_ascii_whitespace() {
            break;
        }
        s = rest;
    }
    s
}

/// The JSON shape `docker compose config --format json` emits.
#[derive(Deserialize)]
struct ComposeFileJson {
    #[serde(default)]
    services: BTreeMap<String, ComposeSvcJson>,
}

#[derive(Default, Deserialize)]
struct ComposeSvcJson {
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    cap_drop: Option<Vec<String>>,
    #[serde(default)]
    cap_add: Option<Vec<String>>,
    #[serde(default)]
    security_opt: Option<Vec<String>>,
    #[serde(default)]
    no_new_privileges: Option<bool>,
    #[serde(default)]
    read_only: Option<bool>,
    #[serde(default)]
    privileged: Option<bool>,
    #[serde(default)]
    pid_mode: Option<String>,
    #[serde(default)]
    ipc: Option<String>,
    #[serde(default)]
    devices: Option<Vec<String>>,
    #[serde(default)]
    shm_size: Option<String>,
    #[serde(default)]
    tmpfs: Option<Vec<String>>,
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default)]
    networks: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    environment: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    volumes: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    ports: Option<Vec<serde_json::Value>>,
}

fn parse_rendered_model_json(content: &[u8]) -> Result<RenderedModel, ComposeError> {
    let file: ComposeFileJson = serde_json::from_slice(content)
        .map_err(|e| ComposeError::Other(format!("compose: parse yaml: {e}")))?;
    let mut model = RenderedModel::default();
    for (name, svc) in file.services {
        model.services.insert(name, svc_json_to_rendered(svc));
    }
    Ok(model)
}

fn svc_json_to_rendered(svc: ComposeSvcJson) -> RenderedService {
    let mut net_mode = svc.network_mode.unwrap_or_default().trim().to_owned();
    if net_mode.is_empty()
        && let Some(nets) = &svc.networks
        && let Some(name) = nets.keys().next()
    {
        net_mode = name.clone();
    }
    if net_mode.is_empty() {
        net_mode = "none".to_owned();
    }
    let env: BTreeMap<String, String> = svc
        .environment
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, json_env_string(v)))
        .collect();
    let volumes = svc
        .volumes
        .unwrap_or_default()
        .iter()
        .map(json_volume_string)
        .collect();
    let ports = svc
        .ports
        .unwrap_or_default()
        .iter()
        .map(json_port_string)
        .collect();
    let no_new_privs = svc.no_new_privileges.unwrap_or(false)
        || contains_no_new_privileges(&svc.security_opt.unwrap_or_default());
    RenderedService {
        image: svc.image.unwrap_or_default(),
        ports,
        cap_drop: svc.cap_drop.unwrap_or_default(),
        cap_add: svc.cap_add.unwrap_or_default(),
        shm_size: svc.shm_size.unwrap_or_default(),
        read_only: svc.read_only.unwrap_or(false),
        no_new_privs,
        tmpfs: svc.tmpfs.unwrap_or_default(),
        env,
        user: svc.user.unwrap_or_default(),
        working_dir: svc.working_dir.unwrap_or_default(),
        network_mode: net_mode,
        privileged: svc.privileged.unwrap_or(false),
        pid_mode: svc.pid_mode.unwrap_or_default(),
        ipc_mode: svc.ipc.unwrap_or_default(),
        devices: svc.devices.unwrap_or_default(),
        volumes,
    }
}

fn json_env_string(v: serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `composeVolumeEntry` — compact or `{source,target,read_only}` form.
fn json_volume_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => {
            let source = map.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let target = map.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let ro = map
                .get("read_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut entry = format!("{source}:{target}");
            if ro {
                entry.push_str(":ro");
            }
            entry
        }
        other => other.to_string(),
    }
}

/// `composePortEntry` — compact or `{host_ip,target,published,protocol}`.
fn json_port_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => {
            let host_ip = map.get("host_ip").and_then(|v| v.as_str()).unwrap_or("");
            let target = map.get("target").and_then(|v| v.as_i64()).unwrap_or(0);
            let published = map
                .get("published")
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .unwrap_or_default();
            let protocol = map.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            let mut entry = format!("{published}:{target}");
            if !host_ip.is_empty() {
                entry = format!("{host_ip}:{entry}");
            }
            if !protocol.is_empty() && protocol != "tcp" {
                entry.push_str(&format!("/{protocol}"));
            }
            entry
        }
        other => other.to_string(),
    }
}

/// Minimal YAML-subset parser covering exactly the grammar this file's
/// renderer emits: two-space indents, `key: scalar`, `key:` nested maps,
/// `- item` sequences, `key: [a, b]` inline lists, and `#` comments.
fn parse_rendered_model_yaml(content: &[u8]) -> Result<RenderedModel, ComposeError> {
    let text = String::from_utf8_lossy(content);
    let lines: Vec<YamlLine> = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .map(|l| {
            let indent = l.len() - l.trim_start().len();
            YamlLine {
                indent,
                text: l.trim().to_owned(),
            }
        })
        .collect();

    let mut model = RenderedModel::default();
    let mut i = 0usize;
    // Find `services:` at indent 0.
    while i < lines.len() {
        if lines[i].indent == 0 && lines[i].text == "services:" {
            i += 1;
            break;
        }
        i += 1;
    }
    while i < lines.len() {
        let line = &lines[i];
        if line.indent == 0 {
            break; // networks: section — done.
        }
        if line.indent == 2 && line.text.ends_with(':') && !line.text.starts_with("- ") {
            let name = line.text.trim_end_matches(':').to_owned();
            let mut svc = RenderedService::default();
            let mut env_names: BTreeMap<String, String> = BTreeMap::new();
            let mut networks: Vec<String> = Vec::new();
            i += 1;
            while i < lines.len() && lines[i].indent >= 4 {
                let field = &lines[i];
                if field.indent != 4 {
                    i += 1;
                    continue;
                }
                let (key, value) = split_key_value(&field.text);
                match key.as_str() {
                    "image" => svc.image = unquote(&value),
                    "pull_policy" | "restart" => {}
                    "cap_drop" => svc.cap_drop = parse_inline_list(&value),
                    "cap_add" => svc.cap_add = parse_inline_list(&value),
                    "security_opt" => {
                        if value.is_empty() {
                            // nested sequence follows at indent 6
                            let mut opts = Vec::new();
                            let mut j = i + 1;
                            while j < lines.len()
                                && lines[j].indent == 6
                                && lines[j].text.starts_with("- ")
                            {
                                opts.push(unquote(lines[j].text.trim_start_matches("- ")));
                                j += 1;
                            }
                            svc.no_new_privs = contains_no_new_privileges(&opts);
                            i = j - 1;
                        }
                    }
                    "no_new_privileges" => {
                        if value == "true" {
                            svc.no_new_privs = true;
                        }
                    }
                    "read_only" => svc.read_only = value == "true",
                    "privileged" => svc.privileged = value == "true",
                    "pid_mode" => svc.pid_mode = unquote(&value),
                    "ipc" => svc.ipc_mode = unquote(&value),
                    "shm_size" => svc.shm_size = unquote(&value),
                    "network_mode" => svc.network_mode = unquote(&value),
                    "user" => svc.user = unquote(&value),
                    "working_dir" => svc.working_dir = unquote(&value),
                    "devices" | "tmpfs" | "volumes" | "ports" => {
                        let target = match key.as_str() {
                            "devices" => &mut svc.devices,
                            "tmpfs" => &mut svc.tmpfs,
                            "volumes" => &mut svc.volumes,
                            _ => &mut svc.ports,
                        };
                        if value.starts_with('[') {
                            *target = parse_inline_list(&value);
                        } else {
                            let mut j = i + 1;
                            while j < lines.len()
                                && lines[j].indent == 6
                                && lines[j].text.starts_with("- ")
                            {
                                target.push(unquote(lines[j].text.trim_start_matches("- ")));
                                j += 1;
                            }
                            i = j - 1;
                        }
                    }
                    "environment" => {
                        let mut j = i + 1;
                        while j < lines.len() && lines[j].indent == 6 {
                            let (k, v) = split_key_value(&lines[j].text);
                            env_names.insert(k, unquote(&v));
                            j += 1;
                        }
                        i = j - 1;
                    }
                    "networks" => {
                        let mut j = i + 1;
                        while j < lines.len()
                            && lines[j].indent == 6
                            && lines[j].text.ends_with(':')
                        {
                            networks.push(lines[j].text.trim_end_matches(':').to_owned());
                            j += 1;
                        }
                        i = j - 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            if svc.network_mode.is_empty() {
                svc.network_mode = networks
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "none".to_owned());
            }
            svc.env = env_names;
            model.services.insert(name, svc);
        } else {
            i += 1;
        }
    }
    Ok(model)
}

struct YamlLine {
    indent: usize,
    text: String,
}

fn split_key_value(text: &str) -> (String, String) {
    match text.find(':') {
        Some(i) => {
            let k = text[..i].trim().to_owned();
            let v = text[i + 1..].trim().to_owned();
            (k, v)
        }
        None => (text.to_owned(), String::new()),
    }
}

fn unquote(v: &str) -> String {
    let t = v.trim();
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        t[1..t.len() - 1].to_owned()
    } else {
        t.to_owned()
    }
}

fn parse_inline_list(v: &str) -> Vec<String> {
    let t = v.trim();
    if !(t.starts_with('[') && t.ends_with(']')) {
        return Vec::new();
    }
    let inner = &t[1..t.len() - 1];
    if inner.trim().is_empty() {
        return Vec::new();
    }
    inner.split(',').map(|s| unquote(s.trim())).collect()
}

// ---------------------------------------------------------------------------
// ValidateModel — the full upstream policy gate.
// ---------------------------------------------------------------------------

/// `ValidateModel` — validates a parsed model against the policy
/// constraints (closed service census, security posture, mount rules).
pub fn validate_model(model: &RenderedModel) -> Result<(), ComposeError> {
    for name in REQUIRED_SERVICE_MODES {
        if !model.services.contains_key(name) {
            return Err(ComposeError::MissingService(name.to_owned()));
        }
    }
    for name in model.services.keys() {
        if !REQUIRED_SERVICE_MODES.contains(&name.as_str()) {
            return Err(ComposeError::ExtraService(name.clone()));
        }
    }
    if model.services.len() != REQUIRED_SERVICE_MODES.len() {
        return Err(ComposeError::InvalidServiceCount(model.services.len()));
    }

    for name in REQUIRED_SERVICE_MODES {
        let svc = &model.services[name];
        if svc.cap_drop.is_empty() {
            return Err(ComposeError::MissingCapDrop(name.to_owned()));
        }
        if !svc.cap_drop.iter().any(|c| c.eq_ignore_ascii_case("ALL")) {
            return Err(ComposeError::CapDropNotAll(name.to_owned()));
        }
        if svc.network_mode == "host" {
            return Err(ComposeError::HostNetwork(name.to_owned()));
        }
        if !svc.read_only {
            return Err(ComposeError::NonReadonlyRoot(name.to_owned()));
        }
        if !svc.no_new_privs {
            return Err(ComposeError::MissingNoNewPrivileges(name.to_owned()));
        }
        if svc.privileged {
            return Err(ComposeError::PrivilegedMode(name.to_owned()));
        }
        if svc.pid_mode == "host" || svc.ipc_mode == "host" {
            return Err(ComposeError::HostNamespace(name.to_owned()));
        }
        if !svc.devices.is_empty() {
            return Err(ComposeError::HostDevice(name.to_owned()));
        }
        for vol in &svc.volumes {
            if vol.contains("docker.sock") {
                return Err(ComposeError::HostSocket(format!(
                    "service {name:?} mounts Docker socket: {vol:?}"
                )));
            }
        }
        validate_broker_socket_mount(name, &svc.volumes)?;
        validate_postgres_admin_passfile_mount(name, &svc.volumes)?;
        validate_postgres_init_script_mount(name, &svc.volumes)?;
        validate_secret_target_mounts(name, &svc.volumes)?;
        validate_credential_mount(name, &svc.env, &svc.volumes)?;
    }

    if let Some(svc) = model.services.get("minio") {
        for port in &svc.ports {
            if port.contains(":9001") || port.ends_with("9001") {
                return Err(ComposeError::ConsolePublished(port.clone()));
            }
        }
    }
    Ok(())
}

fn contains_no_new_privileges(options: &[String]) -> bool {
    options
        .iter()
        .any(|o| o.trim().eq_ignore_ascii_case("no-new-privileges:true"))
}

/// `validateSecretTargetMounts` — closes the `/run/secrets` namespace.
fn validate_secret_target_mounts(service: &str, volumes: &[String]) -> Result<(), ComposeError> {
    for volume in volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() < 2 || !parts[1].starts_with("/run/secrets/") {
            continue;
        }
        if let Some(rule) = fixed_credential_mount(service)
            && parts[1] == rule.target
        {
            continue;
        }
        if service == "postgres-throughput-provision" && parts[1] == POSTGRES_ADMIN_PASSFILE_TARGET
        {
            continue;
        }
        return Err(ComposeError::InvalidCredentialMount(format!(
            "service {service:?} mounts unauthorized secret target: {volume:?}"
        )));
    }
    Ok(())
}

/// `validatePostgresInitScriptMount`.
fn validate_postgres_init_script_mount(
    service: &str,
    volumes: &[String],
) -> Result<(), ComposeError> {
    for volume in volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() < 2 || !parts[1].starts_with("/docker-entrypoint-initdb.d/") {
            continue;
        }
        if service != "postgres" {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "service {service:?} mounts an initdb script: {volume:?}"
            )));
        }
        if parts.len() != 3
            || parts[2] != "ro"
            || parts[1] != POSTGRES_INIT_SCRIPT_TARGET
            || !parts[0].starts_with("/run/central-infra/")
            || base_of(parts[0]) != POSTGRES_INIT_SCRIPT_NAME
            || base_of(&dir_of(parts[0])) != "init"
        {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "service {service:?} has invalid initdb script mount: {volume:?}"
            )));
        }
    }
    Ok(())
}

/// `validateCredentialMount`.
fn validate_credential_mount(
    service: &str,
    environment: &BTreeMap<String, String>,
    volumes: &[String],
) -> Result<(), ComposeError> {
    for (key, target) in environment {
        if !key.ends_with("_FILE") {
            continue;
        }
        let Some(rule) = fixed_credential_mount(service) else {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "unsupported {key} for {service}"
            )));
        };
        if key != rule.env_key || target != rule.target {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "unsupported {key} for {service}"
            )));
        }
        let mut found = false;
        for volume in volumes {
            let parts: Vec<&str> = volume.split(':').collect();
            if parts.len() == 3
                && parts[0].starts_with("/run/central-infra/")
                && parts[1] == *target
                && parts[2] == "ro"
                && base_of(parts[0]) == rule.source
            {
                let source_dir = dir_of(parts[0]);
                if source_dir.starts_with("/run/central-infra/")
                    && base_of(&source_dir) == "secrets"
                {
                    found = true;
                }
            }
        }
        if !found {
            return Err(ComposeError::InvalidCredentialMount(key.clone()));
        }
    }
    Ok(())
}

/// `validateBrokerSocketMount`.
fn validate_broker_socket_mount(service: &str, volumes: &[String]) -> Result<(), ComposeError> {
    for volume in volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() < 2 || !parts[1].ends_with(".sock") {
            continue;
        }
        if volume.contains("docker.sock") {
            continue;
        }
        if service != "minio-provision" || parts[1] != BROKER_SOCKET_TARGET {
            return Err(ComposeError::HostSocket(format!(
                "service {service:?} mounts unexpected socket: {volume:?}"
            )));
        }
        if parts.len() != 2
            || !parts[0].starts_with("/run/central-infra/")
            || base_of(parts[0]) != "minio-provision.sock"
            || base_of(&dir_of(parts[0])) != "broker"
        {
            return Err(ComposeError::HostSocket(format!(
                "service {service:?} has invalid broker socket mount source: {volume:?}"
            )));
        }
    }
    Ok(())
}

/// `validatePostgresAdminPassfileMount`.
fn validate_postgres_admin_passfile_mount(
    service: &str,
    volumes: &[String],
) -> Result<(), ComposeError> {
    for volume in volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() < 2 || parts[1] != POSTGRES_ADMIN_PASSFILE_TARGET {
            continue;
        }
        if service != "postgres-throughput-provision" {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "service {service:?} mounts unexpected passfile target: {volume:?}"
            )));
        }
        if parts.len() != 3
            || parts[2] != "ro"
            || !parts[0].starts_with("/run/central-infra/")
            || base_of(parts[0]) != "postgres-admin-passfile"
            || base_of(&dir_of(parts[0])) != "secrets"
        {
            return Err(ComposeError::InvalidCredentialMount(format!(
                "service {service:?} has invalid passfile mount source: {volume:?}"
            )));
        }
    }
    Ok(())
}

/// `parseMemory` — "2GiB"/"256MiB" → bytes.
pub fn parse_memory(s: &str) -> Result<i64, ComposeError> {
    let s = s.trim();
    let (mult, num) = if let Some(n) = s.strip_suffix("GiB") {
        (1i64 << 30, n.to_owned())
    } else if let Some(n) = s.strip_suffix("MiB") {
        (1i64 << 20, n.to_owned())
    } else if let Some(n) = s.strip_suffix("KiB") {
        (1i64 << 10, n.to_owned())
    } else if let Some(n) = s.strip_suffix("GB") {
        (1_000_000_000, n.to_owned())
    } else if let Some(n) = s.strip_suffix("MB") {
        (1_000_000, n.to_owned())
    } else if s.ends_with('B') {
        return Err(ComposeError::Other(format!(
            "raw bytes not supported: {s:?}"
        )));
    } else {
        (1, s.to_owned())
    };
    let val: i64 = num
        .trim()
        .parse()
        .map_err(|_| ComposeError::Other(format!("invalid memory: {s:?}")))?;
    Ok(val * mult)
}

/// `PolicyDigest` — SHA-256 over the canonical JSON encoding (Go's
/// `json.Encoder` with `SetEscapeHTML(false)` + trailing newline).
pub fn policy_digest(p: &Policy) -> String {
    let mut bytes = serde_json::to_vec(p).unwrap_or_default();
    bytes.push(b'\n');
    format!("sha256:{}", hex_encode(&Sha256::digest(&bytes)))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::domain::{OciInventory, PreparedMode};

    fn valid_binding() -> LifecycleBinding {
        LifecycleBinding {
            instance_id: "test-instance-001".to_owned(),
            config_binding: "test-config-bind".to_owned(),
            admission_id: "adm-001".to_owned(),
            receipt_id: "receipt-001".to_owned(),
            model_digest: "sha256:test-model-digest".to_owned(),
            payload_epoch: "epoch-001".to_owned(),
            bootstrap_fingerprints: Vec::new(),
            b04: Default::default(),
        }
    }

    fn valid_inventory() -> OciInventory {
        OciInventory {
            index_digest: "sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"
                .to_owned(),
            manifest_digest:
                "sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28".to_owned(),
            config_digest:
                "sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e".to_owned(),
            layers: Vec::new(),
        }
    }

    /// The upstream `validDependencySet` — all seven modes in the lock.
    fn valid_dependency_set() -> PreparedDependencySet {
        let modes = [
            ServiceMode::PostgresFsInit,
            ServiceMode::MinioFsInit,
            ServiceMode::Postgres,
            ServiceMode::Minio,
            ServiceMode::PostgresProvision,
            ServiceMode::MinioProvision,
            ServiceMode::PostgresThroughputProvision,
        ];
        PreparedDependencySet {
            modes: modes
                .iter()
                .map(|mode| PreparedMode {
                    mode: *mode,
                    inventory: valid_inventory(),
                })
                .collect(),
        }
    }

    fn valid_model() -> RenderedModel {
        let f = render(
            &valid_binding(),
            &valid_dependency_set(),
            &load_default_policy().unwrap(),
        )
        .unwrap();
        parse_rendered_model(&f.content).unwrap()
    }

    // -- topology pins --------------------------------------------------------

    #[test]
    fn render_produces_exactly_the_six_service_topology() {
        let f = render(
            &valid_binding(),
            &valid_dependency_set(),
            &load_default_policy().unwrap(),
        )
        .unwrap();
        let m = parse_rendered_model(&f.content).unwrap();
        // THE six-service pin: B03's five modes plus ADR 0014's
        // postgres-throughput-provision (ADR 0026 removed
        // postgres-provision — it must NOT render).
        assert_eq!(m.services.len(), 6);
        for name in REQUIRED_SERVICE_MODES {
            assert!(m.services.contains_key(name), "missing {name}");
        }
        assert!(!m.services.contains_key("postgres-provision"));
        validate_model(&m).unwrap();
    }

    #[test]
    fn rendered_yaml_has_pinned_pull_policy_restart_and_security() {
        let f = render(
            &valid_binding(),
            &valid_dependency_set(),
            &load_default_policy().unwrap(),
        )
        .unwrap();
        let content = String::from_utf8_lossy(&f.content);
        assert!(content.contains("pull_policy: never"));
        assert!(content.contains("restart: \"no\""));
        assert!(content.contains("cap_drop: [ALL]"));
        assert!(content.contains("- \"no-new-privileges:true\""));
        assert!(content.contains("read_only: true"));
        assert!(!content.contains("no_new_privileges:"));
        assert!(content.contains("internal: true"));
        assert!(content.contains("json-file"));
        assert!(content.contains("max-file:"));
    }

    #[test]
    fn render_is_deterministic() {
        let b = valid_binding();
        let set = valid_dependency_set();
        let p = load_default_policy().unwrap();
        let f1 = render(&b, &set, &p).unwrap();
        let f2 = render(&b, &set, &p).unwrap();
        assert_eq!(f1.content, f2.content);
    }

    #[test]
    fn image_references_match_mode_identities() {
        let inv = valid_inventory();
        let manifest = &inv.manifest_digest;
        let cases: [(ServiceMode, &str); 7] = [
            (ServiceMode::Postgres, "library/postgres:16.14-bookworm@"),
            (
                ServiceMode::PostgresProvision,
                "library/postgres:16.14-bookworm@",
            ),
            (ServiceMode::Minio, "central-minio@"),
            (
                ServiceMode::PostgresFsInit,
                "ghcr.io/enolalab/central-local-infra@",
            ),
            (
                ServiceMode::MinioFsInit,
                "ghcr.io/enolalab/central-local-infra@",
            ),
            (
                ServiceMode::MinioProvision,
                "ghcr.io/enolalab/central-local-infra@",
            ),
            (
                ServiceMode::PostgresThroughputProvision,
                "ghcr.io/enolalab/central-local-infra@",
            ),
        ];
        for (mode, want_prefix) in cases {
            let got = image_reference(mode, &inv).unwrap();
            assert!(
                got.starts_with(want_prefix),
                "{mode:?} -> {got} want prefix {want_prefix}"
            );
            assert!(got.ends_with(manifest), "digest-qualified: {got}");
        }
        // The MinIO daemon is NOT a mode of central-local-infra.
        let daemon = image_reference(ServiceMode::Minio, &inv).unwrap();
        assert!(!daemon.contains("central-local-infra@"));
    }

    #[test]
    fn render_binds_each_service_to_its_durable_data_root() {
        let f = render(
            &valid_binding(),
            &valid_dependency_set(),
            &load_default_policy().unwrap(),
        )
        .unwrap();
        let content = String::from_utf8_lossy(&f.content);
        for mount in [
            "/var/lib/central-state/v1/instances/test-instance-001/data/postgres:/payload:rw",
            "/var/lib/central-state/v1/instances/test-instance-001/data/minio:/payload:rw",
            "/var/lib/central-state/v1/instances/test-instance-001/data/postgres/data:/var/lib/postgresql/data:rw",
            "/var/lib/central-state/v1/instances/test-instance-001/data/minio/data:/data:rw",
        ] {
            assert!(content.contains(mount), "missing mount {mount}\n{content}");
        }
        for stale in [
            "/var/lib/central-state/v1/instances/test-instance-001/data/postgres:/var/lib/postgresql/data:rw",
            "/var/lib/central-state/v1/instances/test-instance-001/data/minio:/data:rw",
        ] {
            assert!(!content.contains(stale), "stale mount {stale}");
        }
    }

    // -- credential + socket mount rules ---------------------------------------

    #[test]
    fn render_mounts_root_credential_and_broker_socket_on_minio_provision_only() {
        let m = valid_model();
        let provision = &m.services["minio-provision"];
        assert!(
            provision
                .volumes
                .iter()
                .any(|v| v.contains("/run/secrets/minio-root-password"))
        );
        assert!(
            provision
                .volumes
                .iter()
                .any(|v| v.contains("/run/broker/minio-provision.sock"))
        );
        assert!(provision.volumes.iter().any(|v| v.contains(
            "/run/central-infra/test-instance-001/broker/minio-provision.sock:/run/broker/minio-provision.sock"
        )));
        for (name, svc) in &m.services {
            if name == "minio" || name == "minio-provision" {
                continue;
            }
            assert!(
                !svc.volumes
                    .iter()
                    .any(|v| v.contains("/run/secrets/minio-root-password")),
                "{name} must not receive the credential mount"
            );
            assert!(
                !svc.volumes
                    .iter()
                    .any(|v| v.contains("/run/broker/minio-provision.sock")),
                "{name} must not receive the broker socket mount"
            );
        }
    }

    #[test]
    fn render_gives_postgres_first_boot_env_passfile_and_init_script() {
        let m = valid_model();
        let postgres = &m.services["postgres"];
        assert_eq!(
            postgres.env.get("POSTGRES_USER").map(String::as_str),
            Some("central")
        );
        assert_eq!(
            postgres.env.get("POSTGRES_DB").map(String::as_str),
            Some("central")
        );
        assert_eq!(
            postgres
                .env
                .get("POSTGRES_PASSWORD_FILE")
                .map(String::as_str),
            Some("/run/secrets/postgres-superuser-passfile")
        );
        assert!(
            postgres
                .volumes
                .iter()
                .any(|v| v.ends_with(":/run/secrets/postgres-superuser-passfile:ro"))
        );
        assert!(
            postgres
                .volumes
                .iter()
                .any(|v| v.ends_with("/docker-entrypoint-initdb.d/001-central-roles.sql:ro"))
        );
        // The init-script host path is single-instance anchored.
        assert!(postgres.volumes.iter().any(|v| {
            v.starts_with("/run/central-infra/test-instance-001/init/001-central-roles.sql:")
        }));
    }

    #[test]
    fn postgres_init_script_carries_no_password_material() {
        for role in ["central_migration", "central_runtime", "central_outbox"] {
            assert!(
                POSTGRES_INIT_SCRIPT_SQL.contains(&format!("CREATE ROLE {role} NOLOGIN NOINHERIT"))
            );
        }
        assert!(
            POSTGRES_INIT_SCRIPT_SQL.contains("ALTER DATABASE central OWNER TO central_migration")
        );
        for line in POSTGRES_INIT_SCRIPT_SQL.lines() {
            let s = line.trim();
            if s.is_empty() || s.starts_with("--") {
                continue;
            }
            let upper = s.to_uppercase();
            assert!(!upper.contains("PASSWORD"), "password material: {line}");
            assert!(
                !upper.replace("NOLOGIN", "").contains("LOGIN"),
                "grants LOGIN: {line}"
            );
        }
    }

    #[test]
    fn render_rejects_credential_interpolation() {
        let mut p = load_default_policy().unwrap();
        p.services[0].environment.insert(
            "POSTGRES_PASSWORD".to_owned(),
            "${POSTGRES_PASSWORD}".to_owned(),
        );
        let err = render(&valid_binding(), &valid_dependency_set(), &p).unwrap_err();
        assert!(
            matches!(err, ComposeError::CredentialInterpolation(_)),
            "{err}"
        );
    }

    #[test]
    fn rendered_yaml_never_contains_credential_values() {
        let f = render(
            &valid_binding(),
            &valid_dependency_set(),
            &load_default_policy().unwrap(),
        )
        .unwrap();
        let content = String::from_utf8_lossy(&f.content);
        assert!(!content.contains("${"));
        assert!(!content.contains("MINIO_ROOT_PASSWORD:"));
        assert!(!content.contains("POSTGRES_PASSWORD:"));
        // Only the _FILE indirection may appear.
        assert!(content.contains("MINIO_ROOT_PASSWORD_FILE"));
        assert!(content.contains("/run/secrets/minio-root-password"));
    }

    // -- validate_model denial paths --------------------------------------------

    #[test]
    fn validate_model_rejects_mutations() {
        let mut m = valid_model();
        m.services.remove("minio");
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::MissingService(_))
        ));

        let mut m = valid_model();
        m.services
            .insert("extra".to_owned(), RenderedService::default());
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::ExtraService(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().cap_drop = Vec::new();
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::MissingCapDrop(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().cap_drop = vec!["SYS_ADMIN".to_owned()];
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::CapDropNotAll(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().network_mode = "host".to_owned();
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::HostNetwork(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().read_only = false;
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::NonReadonlyRoot(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().privileged = true;
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::PrivilegedMode(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().pid_mode = "host".to_owned();
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::HostNamespace(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().devices = vec!["/dev/fuse:/dev/fuse".to_owned()];
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::HostDevice(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().volumes =
            vec!["/var/run/docker.sock:/var/run/docker.sock".to_owned()];
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::HostSocket(_))
        ));

        let mut m = valid_model();
        m.services.get_mut("postgres").unwrap().volumes.push(
            "/run/central-infra/test-instance-001/broker/minio-provision.sock:/run/broker/minio-provision.sock"
                .to_owned(),
        );
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::HostSocket(_))
        ));

        let mut m = valid_model();
        m.services
            .get_mut("minio")
            .unwrap()
            .ports
            .push("127.0.0.1:59001:9001".to_owned());
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::ConsolePublished(_))
        ));
    }

    #[test]
    fn validate_model_rejects_writable_or_substituted_credential_mount() {
        let mut m = valid_model();
        let minio = m.services.get_mut("minio").unwrap();
        minio.volumes = vec![
            "/run/central-infra/instance-a/secrets/other:/run/secrets/minio-root-password:rw"
                .to_owned(),
        ];
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::InvalidCredentialMount(_))
        ));
    }

    #[test]
    fn validate_model_rejects_init_script_mount_on_other_service() {
        let mut m = valid_model();
        m.services
            .get_mut("minio")
            .unwrap()
            .volumes
            .push(
                "/run/central-infra/i/init/001-central-roles.sql:/docker-entrypoint-initdb.d/001-central-roles.sql:ro"
                    .to_owned(),
            );
        assert!(matches!(
            validate_model(&m),
            Err(ComposeError::InvalidCredentialMount(_))
        ));
    }

    // -- runner pins --------------------------------------------------------------

    #[test]
    fn command_compose_runner_uses_closed_docker_invocation() {
        let (name, args, env) = {
            let captured = std::sync::Arc::new(std::sync::Mutex::new((
                String::new(),
                Vec::<String>::new(),
                Vec::<String>::new(),
            )));
            let c2 = captured.clone();
            let runner = CommandComposeRunner::new(
                "/usr/bin/docker",
                Some(Box::new(move |n, a, e| {
                    *c2.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        (n.to_owned(), a.to_vec(), e.to_vec());
                    Ok(Vec::new())
                })),
                None,
            );
            runner
                .up(
                    &RenderedFile {
                        path: "/run/central-infra/i/docker-compose.yaml".to_owned(),
                        content: Vec::new(),
                    },
                    &["postgres".to_owned()],
                )
                .unwrap();
            captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        assert_eq!(name, "/usr/bin/docker");
        assert_eq!(
            args.join(" "),
            "compose --project-name central-i --file /run/central-infra/i/docker-compose.yaml up --detach --wait --no-build --pull never postgres"
        );
        for entry in env {
            assert!(!entry.starts_with("DOCKER_HOST="));
            assert!(!entry.starts_with("COMPOSE_FILE="));
        }
    }

    #[test]
    fn run_with_input_pipes_stdin_and_returns_exit_code() {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let stdin_seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let c2 = captured.clone();
        let s2 = stdin_seen.clone();
        let runner = CommandComposeRunner::new(
            "/usr/bin/docker",
            None,
            Some(Box::new(move |_n, a, _e, stdin| {
                *c2.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = a.to_vec();
                *s2.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = stdin.to_vec();
                Ok((Vec::new(), 0))
            })),
        );
        let f = RenderedFile {
            path: "/run/central-infra/i/docker-compose.yaml".to_owned(),
            content: Vec::new(),
        };
        let code = runner
            .run_with_input(
                &f,
                "minio-provision",
                &["minio-provision".to_owned()],
                br#"{"mode":"minio-provision"}"#,
            )
            .unwrap();
        assert_eq!(code, 0);
        assert_eq!(
            captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .join(" "),
            "compose --project-name central-i --file /run/central-infra/i/docker-compose.yaml run --rm -T minio-provision minio-provision"
        );
        assert_eq!(
            *stdin_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            br#"{"mode":"minio-provision"}"#.to_vec()
        );
    }

    #[test]
    fn dummy_compose_runner_fails_closed() {
        let runner = DummyComposeRunner;
        assert!(matches!(
            runner.up(&RenderedFile::default(), &[]),
            Err(ComposeError::ExecutionUnavailable)
        ));
        assert!(matches!(
            runner.run_with_input(&RenderedFile::default(), "s", &[], &[]),
            Err(ComposeError::ExecutionUnavailable)
        ));
    }

    #[test]
    fn parse_rendered_model_accepts_compose_config_json() {
        // `docker compose config --format json` shape (SC-DEF-19).
        let content = br#"{"services":{"minio":{"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"read_only":true,"ports":[{"mode":"ingress","host_ip":"127.0.0.1","target":9000,"published":"59000","protocol":"tcp"}],"volumes":[{"type":"bind","source":"/run/central-infra/i/secrets/minio-root-password","target":"/run/secrets/minio-root-password","read_only":true,"bind":{}}]}}}"#;
        let model = parse_rendered_model(content).unwrap();
        let minio = &model.services["minio"];
        assert_eq!(minio.ports, vec!["127.0.0.1:59000:9000"]);
        assert!(minio.volumes.contains(
            &"/run/central-infra/i/secrets/minio-root-password:/run/secrets/minio-root-password:ro"
                .to_owned()
        ));
        assert!(minio.no_new_privs);
    }

    #[test]
    fn init_script_host_path_is_single_instance_anchored() {
        let binding = valid_binding();
        let got = postgres_init_script_host_path("", &binding.instance_id);
        assert_eq!(
            got,
            "/run/central-infra/test-instance-001/init/001-central-roles.sql"
        );
        assert_eq!(got.matches(&binding.instance_id).count(), 1);
    }
}
