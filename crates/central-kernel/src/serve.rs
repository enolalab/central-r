//! `central serve` composition — the kernel's port of upstream
//! `cmd/central/serve_composition.go` (`openServeDeps` +
//! `composeServe`) merged with `harness_composition.go` and the
//! `serve_artifact_composition.go` capability block.
//!
//! The composition order is upstream's:
//!
//! 1. Runtime credential → PostgreSQL pool
//!    (`CENTRAL_RUNTIME_CREDENTIAL_DESCRIPTOR` wins; `CENTRAL_DSN` is
//!    the local-first fallback, matching upstream's
//!    `envCredentialProvider` + `loadCredentialDescriptor` contract).
//! 2. Session store + dev-gated bootstrap → session service
//!    ([`crate::session_compose`]).
//! 3. Execution store + service + recovery coordinator.
//! 4. Task stores + task service → [`ServeTaskService`].
//! 5. Harness store, resolver, reconciler.
//! 6. B10 artifact capability — only when the object-store
//!    environment is complete (an unconfigured capability, never a
//!    degradation). Harness execution is refused while B10 is
//!    unavailable: the orchestrator's `ArtifactSink` is required, and
//!    a partial runtime graph that could mutate durable state is
//!    never published.
//! 7. Harness execution — only while `CENTRAL_HARNESS_ENABLED=1`:
//!    launcher selection ([`crate::harness_compose::select_launcher`]
//!    — `HostLauncher` by default, `LocalExec` only behind the dev
//!    gate), backend adapter, gitclone provisioner/capture sealed by
//!    `LinuxWorkspaceSealer`, [`ServeRunLifecycle`], orchestrator,
//!    dispatcher.
//! 8. [`ServeHarnessOperator`] — always built, even with the harness
//!    off, so ambiguous Tasks stay resolvable (harness phase 3a
//!    decision 9).
//! 9. Application + operations routers and their listener
//!    components.
//! 10. The startup recovery gate ([`ServeRecoveryPreflight`]): the
//!     recovery coordinator opens the epoch, B08 runs to completion,
//!     the harness reconciler mirrors it onto the attempt rows, and
//!     the fenced artifact startup recovery runs last — before any
//!     Run becomes claimable.
//!
//! Components settle in reverse registration order under the shared
//! shutdown budget ([`crate::lifecycle`]).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex};

use axum::Router;
use central_adapter_harness::gitclone::{GitClone, GitCloneConfig};
use central_adapter_linux::dev_restore_barrier::DevRestoreBarrier;
use central_adapter_linux::launcher_client::SocketLauncherClient;
use central_adapter_linux::lifecycle_watch::{
    BoundaryWatch as OsBoundaryWatch, ENV_CONTROLLER_FD, ENV_PARENT_PID, ENV_SUPERVISOR_PID,
    configured_fd, configured_pid, default_parent_pid,
};
use central_adapter_linux::workspace_seal::LinuxWorkspaceSealer;
use central_adapter_postgres::artifact::Store as PgArtifactStore;
use central_adapter_postgres::execution::Store as PgExecutionStore;
use central_adapter_postgres::harness::PgHarnessStore;
use central_adapter_postgres::migrate::Inspector as PgMigrateInspector;
use central_adapter_postgres::session::PgSessionStore;
use central_adapter_postgres::task::{
    DetailStore as PgTaskDetailStore, EventLogStore as PgTaskEventLogStore,
    ListStore as PgTaskListStore, MilestoneStore as PgMilestoneStore, Store as PgTaskStore,
};
use central_adapter_s3::{Config as ObjectConfig, S3ObjectStore};
use central_artifact::app::Service as ArtifactService;
use central_artifact::classifier::ReportClassifier;
use central_artifact::reconciler::{Fence as ArtifactFence, Reconciler as ArtifactReconciler};
use central_execution::app::{NoB09, RecoveryCoordinatorService, Service as ExecutionService};
use central_execution::domain::{Capability, TrustedScope};
use central_execution::port::{
    ArtifactWorkClaim, FailedRecoveryWorkspaces, RecoveryWorkspaceClaim,
};
use central_execution::resume::{
    RecoveryEpoch, RecoveryEpochState, ResumeRecoveryEpochCommand, recovery_resume_fingerprint,
};
use central_foundation::failure::{ExitClass, Failure, FailureKind};
use central_foundation::identity::{InstanceId, WorkspaceId};
use central_harness::app::dispatcher::{self, Dispatcher, DispatcherConfig, DispatcherDeps};
use central_harness::app::orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorDeps};
use central_harness::app::ports;
use central_harness::app::ports::CancelSignal;
use central_harness::app::reconciler::{Reconciler as HarnessReconciler, Resolver};
use central_harness::port::{Adapter, ProcessLauncher};
use central_session::app::Service as SessionService;
use central_session::domain::{ReconcileRequest, SecurityEpoch};
use central_session::port::SessionStore;
use central_transport_http::api;
use central_transport_http::health::{self, ProbeSnapshot, ProbeState};
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::ports as tports;
use central_transport_http::router::{TransportConfig, build_app_router, build_ops_router};
use central_transport_http::web::harness::HarnessBudgetDefaults;
use central_transport_http::web::{self, WebState};
use sqlx::Connection as _;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use time::{Duration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::BoxFuture;
use crate::artifact_reconcile::ArtifactReconcilerComponent;
use crate::harness_compose::{
    Backend, ENV_LOCALEXEC, HarnessConfig, LauncherSelection, LauncherSelectionArgs,
};
use crate::lifecycle::{
    BootstrapReconciler, BoundaryWatch, Component, ControlLock, ControlLockLease, ExitError,
    PreflightReport, Profile, ProfileConfig, ServingPreflight, WatchSource,
};
use crate::readiness::{self, Readiness};
use crate::readyproof::{ReadyProof, ReadyProofPublisher, new_runtime_launch_id};
use crate::serve_lifecycle::{
    ServeArtifactSink, ServeResolveStore, ServeResumeSource, ServeRunLifecycle,
};
use crate::serve_operator::{ApprovalBridge, ServeHarnessOperator, ServeHarnessOperatorDeps};
use crate::serve_support::{ServeRuntime, ServeTaskEventSink, TokenCancel, TokioClock};
use crate::serve_tasks::ServeTaskService;
use crate::session_compose::compose_session;

// ---------------------------------------------------------------------------
// Environment (upstream serve_composition.go constants + artifact_cli's
// object-store env names)
// ---------------------------------------------------------------------------

/// The runtime DSN the local-first slice accepts directly
/// (`databaseCredential.connString`'s local-development form).
pub const ENV_DSN: &str = "CENTRAL_DSN";
/// `CENTRAL_RUNTIME_CREDENTIAL_DESCRIPTOR` — a file whose first
/// non-empty line is the runtime DSN; takes precedence over
/// [`ENV_DSN`].
pub const ENV_CREDENTIAL_DESCRIPTOR: &str = "CENTRAL_RUNTIME_CREDENTIAL_DESCRIPTOR";
/// The application listener bind address.
pub const ENV_APP_LISTEN: &str = "CENTRAL_APP_LISTEN";
/// The operations listener bind address — loopback only.
pub const ENV_OPS_LISTEN: &str = "CENTRAL_OPS_LISTEN";
/// The fixed workspace the bootstrap exchange mints sessions for.
pub const ENV_WORKSPACE: &str = "CENTRAL_WORKSPACE_ID";
/// `serveAllowedWorkspaceRootsEnv`.
pub const ENV_ALLOWED_ROOTS: &str = "CENTRAL_B11_ALLOWED_WORKSPACE_ROOTS";
/// The dev bootstrap's registry directory.
pub const ENV_DEV_BOOTSTRAP_ROOT: &str = "CENTRAL_DEV_BOOTSTRAP_ROOT";
/// `CENTRAL_READY_PROOF_PATH`.
pub const ENV_READY_PROOF_PATH: &str = "CENTRAL_READY_PROOF_PATH";

/// `CENTRAL_RECOVERY_RESUME` — the operator's acknowledged resume of a
/// degraded epoch, `<generation>:<retry_attempt>`
/// (harness phase 3f decisions 3 and 11).
pub const ENV_RECOVERY_RESUME: &str = "CENTRAL_RECOVERY_RESUME";
/// `CENTRAL_RECOVERY_RESUME_REASON` — required with
/// [`ENV_RECOVERY_RESUME`].
pub const ENV_RECOVERY_RESUME_REASON: &str = "CENTRAL_RECOVERY_RESUME_REASON";

/// B10 object-store envs — the same names `artifact_cli` honors.
pub const ENV_OBJECT_ENDPOINT: &str = "CENTRAL_ARTIFACT_OBJECT_ENDPOINT";
/// `CENTRAL_ARTIFACT_OBJECT_BUCKET`.
pub const ENV_OBJECT_BUCKET: &str = "CENTRAL_ARTIFACT_OBJECT_BUCKET";
/// `CENTRAL_ARTIFACT_OBJECT_ACCESS_KEY`.
pub const ENV_OBJECT_ACCESS: &str = "CENTRAL_ARTIFACT_OBJECT_ACCESS_KEY";
/// `CENTRAL_ARTIFACT_OBJECT_SECRET_KEY`.
pub const ENV_OBJECT_SECRET: &str = "CENTRAL_ARTIFACT_OBJECT_SECRET_KEY";
/// `CENTRAL_ARTIFACT_OBJECT_REGION`.
pub const ENV_OBJECT_REGION: &str = "CENTRAL_ARTIFACT_OBJECT_REGION";
/// `CENTRAL_ARTIFACT_OBJECT_USE_TLS`.
pub const ENV_OBJECT_TLS: &str = "CENTRAL_ARTIFACT_OBJECT_USE_TLS";

/// Every config failure carries this code so `serve` classifies the
/// refusal `CONFIG_INVALID` (upstream `compositionExit`).
pub const ERR_SERVE_CONFIG: &str = "serve_config_invalid";

const DEFAULT_APP_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_OPS_LISTEN: &str = "127.0.0.1:9090";
/// Upstream `runtimePoolConfig`: `pool_max_conns` outside `1..=8`
/// clamps to 4; `validateExecutionPoolSize` refuses a pool under 3
/// (one bounded recovery acquisition plus two foreground slots).
const RUNTIME_POOL_CLAMP: u32 = 4;
const RUNTIME_POOL_MIN: u32 = 3;
const RUNTIME_POOL_MAX_ALLOWED: u32 = 8;
/// Upstream `servePreflightTimeout` — the bounded inspection window
/// inside the startup budget.
const SERVE_PREFLIGHT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Upstream `recoveryAcquireTimeout` — bounds only the recovery
/// connection acquisition, never the drain.
const RECOVERY_ACQUIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Upstream `controlLockHeartbeat` (5s) / `controlLockPingTimeout` (3s).
const CONTROL_LOCK_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(5);
const CONTROL_LOCK_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Upstream `backup.ServeTargetExclusionLockKey` — `"cent"` in
/// big-endian bytes.
const SERVE_TARGET_EXCLUSION_LOCK_KEY: i64 = 0x63656e74;
/// Upstream `serveMonitorInterval`.
const SERVE_MONITOR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Upstream's per-check timeout inside `serveEpochMonitor.Run`.
const EPOCH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// `recoveryResumePrincipal` — the resume is a deployment act: no web
/// session or harness principal holds it.
const RECOVERY_RESUME_PRINCIPAL: &str = "serve:recovery-resume-ack";
/// `maxRecoveryResumeWorkspaces` — caps the Workspace ids the stored
/// acknowledgement names.
const MAX_RECOVERY_RESUME_WORKSPACES: u32 = 50;
/// `maxRecoveryResumeReason` — the most characters the trimmed reason
/// may hold.
const MAX_RECOVERY_RESUME_REASON: usize = 500;

fn config_err(msg: impl Into<String>) -> ExitError {
    ExitError::new(
        ExitClass::Usage,
        "CONFIG_INVALID",
        Failure::invalid(ERR_SERVE_CONFIG, msg.into()),
    )
}

fn dep_err(msg: impl Into<String>) -> ExitError {
    ExitError::new(
        ExitClass::Unavailable,
        "DEPENDENCY_UNAVAILABLE",
        Failure::unavailable("serve_dependency", msg.into()),
    )
}

// ---------------------------------------------------------------------------
// ServeConfig — the validated serve environment
// ---------------------------------------------------------------------------

/// `ServeDeps`'s configuration half — every value the composition
/// consumes, loaded and validated before the pool is opened (upstream
/// validates the harness environment before anything is opened; this
/// loader does the same for every input).
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The runtime DSN (the descriptor file takes precedence).
    pub dsn: String,
    /// The application listener — `expected_host` derives from it so
    /// admission never accepts a different Host (upstream
    /// `Config.ExpectedHost`).
    pub app_listen: SocketAddr,
    /// The operations listener — asserted loopback-only.
    pub ops_listen: SocketAddr,
    /// The workspace sessions mint sessions for.
    pub workspace: WorkspaceId,
    /// The `workspace_root_id` allowlist for repository-analysis
    /// submissions; empty fails every submission closed.
    pub allowed_roots: Vec<String>,
    /// The dev bootstrap registry root (the `CENTRAL_LOCALEXEC=1`
    /// path; the broker bootstrap is deferred to R5).
    pub bootstrap_root: PathBuf,
    /// The validated harness environment (inert while disabled).
    pub harness: HarnessConfig,
    /// The B10 object store; `None` means the capability is
    /// unconfigured — never a degradation.
    pub objects: Option<ObjectConfig>,
    /// `CENTRAL_READY_PROOF_PATH` — the proof file a parent waits on.
    pub ready_proof_path: Option<PathBuf>,
    /// Lifecycle budgets.
    pub profile: ProfileConfig,
    /// Runtime pool size (`pool_max_conns` from the DSN, clamped to
    /// upstream's `runtimePoolConfig`).
    pub pool_max: u32,
    /// The `CENTRAL_RECOVERY_RESUME` acknowledgement (harness phase
    /// 3f decisions 3–11).
    pub recovery_resume: Option<RecoveryResumeAck>,
}

impl ServeConfig {
    /// Reads the process environment.
    ///
    /// # Errors
    /// `CONFIG_INVALID`/`DEPENDENCY_UNAVAILABLE` on malformed or
    /// missing required configuration.
    pub fn from_env() -> Result<Self, ExitError> {
        Self::load(|name| std::env::var(name).ok())
    }

    /// The testable loader — `getenv` returns `Some(value)` for set
    /// names (upstream's `getenv` injection seam).
    ///
    /// # Errors
    /// Same as [`Self::from_env`].
    pub fn load(getenv: impl Fn(&str) -> Option<String>) -> Result<Self, ExitError> {
        let dsn = load_dsn(&getenv)?;
        let app_listen = parse_addr(
            getenv(ENV_APP_LISTEN)
                .as_deref()
                .unwrap_or(DEFAULT_APP_LISTEN),
            ENV_APP_LISTEN,
        )?;
        let ops_listen = parse_addr(
            getenv(ENV_OPS_LISTEN)
                .as_deref()
                .unwrap_or(DEFAULT_OPS_LISTEN),
            ENV_OPS_LISTEN,
        )?;
        if !ops_listen.ip().is_loopback() {
            return Err(config_err(format!(
                "{ENV_OPS_LISTEN} must be loopback-only, got {ops_listen}"
            )));
        }
        let workspace_raw = getenv(ENV_WORKSPACE)
            .ok_or_else(|| config_err(format!("{ENV_WORKSPACE} is not set")))?;
        let workspace = workspace_raw
            .trim()
            .parse::<WorkspaceId>()
            .map_err(|_| config_err(format!("{ENV_WORKSPACE} {workspace_raw:?} is not a UUID")))?;
        let allowed_roots = getenv(ENV_ALLOWED_ROOTS)
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let bootstrap_root = getenv(ENV_DEV_BOOTSTRAP_ROOT)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/central-dev-bootstrap"));
        let harness = HarnessConfig::load(|name| getenv(name).unwrap_or_default())
            .map_err(|f| config_err(format!("harness config: {}", f.code())))?;
        let objects = load_objects(&getenv)?;
        let ready_proof_path = getenv(ENV_READY_PROOF_PATH).map(PathBuf::from);
        let pool_max = runtime_pool_max(&dsn)?;
        let recovery_resume = load_recovery_resume_config(&getenv)
            .map_err(|f| config_err(format!("{}: {}", f.code(), f.message())))?;
        Ok(Self {
            dsn,
            app_listen,
            ops_listen,
            workspace,
            allowed_roots,
            bootstrap_root,
            harness,
            objects,
            ready_proof_path,
            profile: ProfileConfig::default(),
            pool_max,
            recovery_resume,
        })
    }
}

/// `runtimePoolConfig` — reads `pool_max_conns` from the DSN query
/// string; values `<= 0` or `> 8` clamp to 4 (upstream's default), and
/// after clamping anything below the minimum execution pool of 3
/// refuses composition.
///
/// # Errors
/// `CONFIG_INVALID` on a non-integer value or a size below 3.
fn runtime_pool_max(dsn: &str) -> Result<u32, ExitError> {
    let raw = dsn
        .split_once('?')
        .and_then(|(_, query)| {
            query
                .split('&')
                .find_map(|kv| kv.strip_prefix("pool_max_conns="))
        })
        .map(str::trim);
    let max = match raw {
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| config_err("pool_max_conns must be an integer"))?,
        None => i64::from(RUNTIME_POOL_CLAMP),
    };
    let max = if max <= 0 || max > i64::from(RUNTIME_POOL_MAX_ALLOWED) {
        i64::from(RUNTIME_POOL_CLAMP)
    } else {
        max
    };
    if max < i64::from(RUNTIME_POOL_MIN) {
        return Err(config_err(format!(
            "runtime pool has {max} connections; B08 requires at least {RUNTIME_POOL_MIN}"
        )));
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(max as u32)
}

/// `envCredentialProvider.Credential` + `loadCredentialDescriptor`:
/// the descriptor file wins; `CENTRAL_DSN` is the local-first
/// fallback.
fn load_dsn(getenv: &impl Fn(&str) -> Option<String>) -> Result<String, ExitError> {
    if let Some(path) = getenv(ENV_CREDENTIAL_DESCRIPTOR) {
        let body = std::fs::read_to_string(&path)
            .map_err(|e| dep_err(format!("runtime credential descriptor {path}: {e}")))?;
        if let Some(dsn) = body.lines().map(str::trim).find(|l| !l.is_empty()) {
            return Ok(dsn.to_owned());
        }
        return Err(dep_err(format!(
            "runtime credential descriptor {path} is empty"
        )));
    }
    match getenv(ENV_DSN) {
        Some(dsn) if !dsn.trim().is_empty() => Ok(dsn),
        _ => Err(dep_err(format!(
            "neither {ENV_CREDENTIAL_DESCRIPTOR} nor {ENV_DSN} is set"
        ))),
    }
}

fn parse_addr(raw: &str, env: &str) -> Result<SocketAddr, ExitError> {
    raw.parse()
        .map_err(|_| config_err(format!("{env} {raw:?} is not host:port")))
}

/// `artifactObjectStoreConfig` — complete config or `None`; a partial
/// environment is a config error (never a silently degraded store).
fn load_objects(
    getenv: &impl Fn(&str) -> Option<String>,
) -> Result<Option<ObjectConfig>, ExitError> {
    let endpoint = getenv(ENV_OBJECT_ENDPOINT).unwrap_or_default();
    let bucket = getenv(ENV_OBJECT_BUCKET).unwrap_or_default();
    let access = getenv(ENV_OBJECT_ACCESS).unwrap_or_default();
    let secret = getenv(ENV_OBJECT_SECRET).unwrap_or_default();
    let any = [&endpoint, &bucket, &access, &secret]
        .iter()
        .any(|v| !v.is_empty());
    if !any {
        return Ok(None);
    }
    if endpoint.is_empty() || bucket.is_empty() || access.is_empty() || secret.is_empty() {
        return Err(config_err(
            "CENTRAL_ARTIFACT_OBJECT_* must be set together (endpoint, bucket, access key, secret key)",
        ));
    }
    let region = getenv(ENV_OBJECT_REGION)
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "us-east-1".to_owned());
    Ok(Some(ObjectConfig {
        endpoint,
        bucket,
        access_key_id: access,
        secret_access_key: secret,
        session_token: String::new(),
        region,
        use_tls: matches!(getenv(ENV_OBJECT_TLS).as_deref(), Some("true") | Some("1")),
    }))
}

// ---------------------------------------------------------------------------
// Readiness probe adapter — upstream `readinessAdapter`
// ---------------------------------------------------------------------------

struct KernelProbe {
    readiness: Readiness,
}

impl health::ReadinessProbe for KernelProbe {
    fn health(&self) -> ProbeSnapshot {
        let h = self.readiness.health();
        ProbeSnapshot {
            state: match h.state {
                readiness::State::Starting => ProbeState::Starting,
                readiness::State::Ready => ProbeState::Ready,
                readiness::State::NotReady => ProbeState::NotReady,
                readiness::State::ShuttingDown => ProbeState::ShuttingDown,
                readiness::State::Failed => ProbeState::Failed,
            },
            reason: h.reason,
            remediation: h.remediation,
            failure_class: h.failure_class,
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact delivery — transport's `ArtifactDelivery` port over the
// service's `deliver_ready_artifact` (which takes `&request`)
// ---------------------------------------------------------------------------

type PgArtifactService =
    ArtifactService<PgArtifactStore, S3ObjectStore, ReportClassifier, PgArtifactStore>;

struct ServeArtifactDelivery {
    service: Arc<PgArtifactService>,
}

impl tports::ArtifactDelivery for ServeArtifactDelivery {
    fn deliver_ready_artifact(
        &self,
        request: central_artifact::app::DeliverReadyArtifactRequest,
    ) -> BoxFuture<'_, Result<central_artifact::app::DeliverArtifactOutcome, Failure>> {
        Box::pin(async move { self.service.deliver_ready_artifact(&request).await })
    }
}

/// The unconfigured-B10 answer — every delivery refused unavailable
/// (upstream's nil service renders the same unavailable surface).
struct UnconfiguredArtifactDelivery;

impl tports::ArtifactDelivery for UnconfiguredArtifactDelivery {
    fn deliver_ready_artifact(
        &self,
        _request: central_artifact::app::DeliverReadyArtifactRequest,
    ) -> BoxFuture<'_, Result<central_artifact::app::DeliverArtifactOutcome, Failure>> {
        Box::pin(async {
            Err(Failure::unavailable(
                "artifact_unconfigured",
                "artifact delivery is not configured",
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Listener component — one supervised axum listener
// ---------------------------------------------------------------------------

/// A bound `TcpListener` serving an axum `Router` — the kernel's port
/// of upstream's HTTP component (`Serve` + `Shutdown` through the
/// profile token).
struct HttpListenerComponent {
    listener: Option<TcpListener>,
    router: Router,
    token: CancellationToken,
}

impl Component for HttpListenerComponent {
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let Some(listener) = self.listener.take() else {
            return Box::pin(async {
                Err(Failure::internal(
                    "http_listener_reused",
                    "a listener component ran twice",
                ))
            });
        };
        let router = self.router.clone();
        let token = self.token.clone();
        Box::pin(async move {
            axum::serve(listener, router.into_make_service())
                .with_graceful_shutdown(token.cancelled_owned())
                .await
                .map_err(|e| Failure::internal("http_listener_serve", e.to_string()))
        })
    }

    /// Upstream `Shutdown` is bounded by the profile's settlement
    /// budget — axum's graceful shutdown already ran under `run`.
    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Dispatcher component
// ---------------------------------------------------------------------------

/// The harness dispatcher as a supervised component — `Run` under the
/// profile token; its internal drain makes `settle` a no-op.
struct HarnessDispatcherComponent {
    dispatcher: Arc<Dispatcher>,
    stop: Arc<TokenCancel>,
}

impl Component for HarnessDispatcherComponent {
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let dispatcher = self.dispatcher.clone();
        let stop: Arc<dyn CancelSignal> = self.stop.clone();
        Box::pin(async move { dispatcher.run(stop).await })
    }

    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Startup recovery gate — the preflight that opens the epoch and runs
// B08 → harness reconcile → artifact recovery before readiness
// ---------------------------------------------------------------------------

/// The shared opened-epoch cell the deferred artifact component's
/// `epoch_source` consults once at run start (upstream
/// `openedEpoch`).
type OpenedEpoch = Arc<StdMutex<Option<RecoveryEpoch>>>;

/// Upstream `ClaimBatch`'s 100-row bounded slice.
const RECOVERY_CLAIM_BATCH: u32 = 100;

/// The recovery coordinator surface the gate consumes — narrowed so
/// tests drive it with doubles (upstream's `*app.RecoveryCoordinator`
/// plus `recoveryResumeCoordinator`'s two resume calls).
pub trait RecoveryGateCoordinator: Send + Sync + 'static {
    /// `RunEpoch` — opens (or joins) the serving epoch.
    fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>>;
    /// `ClaimBatch` — one round-robin slice of the epoch's workspace
    /// recovery work.
    fn claim_batch<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>>;
    /// `CompleteWorkspace` — durable bookkeeping completion of one
    /// claim (B08 bookkeeping only; no provider, no tool).
    fn complete_workspace<'a>(
        &'a self,
        claim: &'a RecoveryWorkspaceClaim,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ClaimArtifactWork` — the artifact-startup fence.
    fn claim_artifact_work<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>>;
    /// `ListFailedRecoveryWorkspaces` — the failed rows a resume
    /// acknowledgement names.
    fn list_failed_workspaces<'a>(
        &'a self,
        epoch_generation: i64,
        limit: u32,
    ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>>;
    /// `ResumeEpoch` — the audited operator resume of a degraded epoch.
    fn resume_epoch<'a>(
        &'a self,
        command: ResumeRecoveryEpochCommand,
    ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>>;
}

impl<R, C> RecoveryGateCoordinator for RecoveryCoordinatorService<R, C>
where
    R: central_execution::port::RecoveryStore + Send + Sync + 'static,
    C: central_execution::port::Clock + Send + Sync + 'static,
{
    fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
        Box::pin(RecoveryCoordinatorService::run_epoch(self))
    }
    fn claim_batch<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
        Box::pin(RecoveryCoordinatorService::claim_batch(
            self,
            epoch,
            RECOVERY_CLAIM_BATCH,
        ))
    }
    fn complete_workspace<'a>(
        &'a self,
        claim: &'a RecoveryWorkspaceClaim,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(RecoveryCoordinatorService::complete_workspace(
            self, claim, false, "", "",
        ))
    }
    fn claim_artifact_work<'a>(
        &'a self,
        epoch: &'a RecoveryEpoch,
    ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
        Box::pin(RecoveryCoordinatorService::claim_artifact_work(self, epoch))
    }
    fn list_failed_workspaces<'a>(
        &'a self,
        epoch_generation: i64,
        limit: u32,
    ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
        Box::pin(RecoveryCoordinatorService::list_failed_workspaces(
            self,
            epoch_generation,
            limit,
        ))
    }
    fn resume_epoch<'a>(
        &'a self,
        command: ResumeRecoveryEpochCommand,
    ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
        Box::pin(RecoveryCoordinatorService::resume_epoch(self, command))
    }
}

/// The artifact startup-recovery surface — one bounded fenced pass
/// (upstream `artifactRecovery`'s startup half, narrowed so tests
/// substitute a double).
pub trait ArtifactStartupRecovery: Send + Sync + 'static {
    /// One fenced startup pass.
    fn recover<'a>(&'a self, fence: &'a ArtifactFence) -> BoxFuture<'a, Result<(), Failure>>;
}

impl<C, R, O, L> ArtifactStartupRecovery for ArtifactReconciler<C, R, O, L>
where
    C: central_artifact::port::ReconciliationStore,
    R: central_artifact::port::Store,
    O: central_artifact::port::ObjectStore,
    L: central_artifact::app::ResumeLifecycle,
{
    fn recover<'a>(&'a self, fence: &'a ArtifactFence) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move { self.reconcile(fence).await.map(|_| ()) })
    }
}

/// `protectedHardlinksPath`.
const PROTECTED_HARDLINKS_PATH: &str = "/proc/sys/fs/protected_hardlinks";

/// `probeHarnessCaptureHost` — the harness phase 3b startup probe
/// (decision 4, open item 3): `fs.protected_hardlinks` must be 1, so
/// the harness cannot hardlink a file it cannot read into its clone
/// for capture to copy, and `data_root/capture` must be the
/// runtime-owned 0700 directory setup creates.
///
/// # Errors
/// `CONFIG_INVALID` when the sysctl cannot be read or is not `1`, or
/// the capture directory is not ready.
fn probe_harness_capture_host(
    clone: &GitClone,
    hardlinks_path: Option<&str>,
) -> Result<(), ExitError> {
    let path = hardlinks_path.unwrap_or(PROTECTED_HARDLINKS_PATH);
    let protected = std::fs::read_to_string(path)
        .map_err(|e| config_err(format!("harness capture: read fs.protected_hardlinks: {e}")))?;
    if protected.trim() != "1" {
        return Err(config_err(
            "harness capture: fs.protected_hardlinks must be 1 (see the harness runbook)",
        ));
    }
    clone.check_capture_dir().map_err(|_| {
        config_err("harness capture: the capture directory is not ready (run the harness setup)")
    })
}

// ---------------------------------------------------------------------------
// Startup gate halves — inspection under the bounded window, recovery on
// the runtime context (upstream `servePreflight` + `serveRecoveryPreflight`
// merged through `kernel.ServingPreflight.RunForServe`)
// ---------------------------------------------------------------------------

/// The read-only restore-barrier half of the inspection — upstream
/// `port.RestoreBarrierInspector` (`InspectRestoreBarrier`): the broker
/// in production, the dev journal under `CENTRAL_LOCALEXEC`.
trait RestoreBarrierInspector: Send + Sync + 'static {
    /// `Some(operation_id)` while a non-terminal restore occupies the
    /// barrier.
    fn inspect(&self) -> BoxFuture<'_, Result<Option<String>, Failure>>;
}

impl RestoreBarrierInspector for DevRestoreBarrier {
    fn inspect(&self) -> BoxFuture<'_, Result<Option<String>, Failure>> {
        Box::pin(async move { DevRestoreBarrier::inspect(self) })
    }
}

/// `port.MigrationInspector` — the narrow surface the composition
/// substitutes in tests (the production value is
/// [`PgMigrateInspector`] over a dedicated read-only connection).
trait MigrationInspection: Send + Sync + 'static {
    /// `Inspector.Inspect` — read-only schema/epoch facts.
    fn inspect(
        &mut self,
    ) -> BoxFuture<'_, Result<central_backup::port::PostgresMigrationFacts, Failure>>;
    /// `Inspector.VerifyServeBaseline` — the authoritative B05/B08
    /// shape check.
    fn verify_serve_baseline(&mut self) -> BoxFuture<'_, Result<(), Failure>>;
}

/// Wraps the dedicated-connection inspector.
struct PgInspector {
    inner: PgMigrateInspector<'static>,
}

impl MigrationInspection for PgInspector {
    fn inspect(
        &mut self,
    ) -> BoxFuture<'_, Result<central_backup::port::PostgresMigrationFacts, Failure>> {
        Box::pin(async move { self.inner.inspect().await })
    }

    fn verify_serve_baseline(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move { self.inner.verify_serve_baseline().await })
    }
}

/// `servePreflight` — the authoritative, read-only admission
/// inspection: restore barrier, migration facts, serve baseline, epoch
/// markers. `epochs` receives the authoritative markers so the runtime
/// watch, the bootstrap reconciler, and readiness all publish the same
/// value.
struct ServeInspection {
    inspector: Box<dyn MigrationInspection>,
    barrier: Option<Box<dyn RestoreBarrierInspector>>,
    epochs: Arc<EpochMonitorShared>,
    /// The dedicated `preflight` connection — held alive for the
    /// composition so the role check upstream performs on it stays
    /// bound to a live session (upstream `NewInspectorForConn` shares
    /// this connection; the Rust inspector opens its own max-1
    /// session through `Inspector::connect`). `None` is the test seam.
    _preflight_conn: Option<sqlx::PgConnection>,
    b08_ready: bool,
}

impl ServeInspection {
    /// `servePreflight.Run` — upstream's exact step order and failure
    /// classes: barrier → inspect → provision/dirty → baseline →
    /// epochs.
    async fn run(&mut self) -> Result<(), Failure> {
        let Some(barrier) = self.barrier.as_ref() else {
            return Err(Failure::conflict(
                "RESTORE_BARRIER_UNAVAILABLE",
                "restore protected broker authority before serving",
            ));
        };
        let active = barrier.inspect().await.map_err(|_| {
            Failure::conflict(
                "RESTORE_BARRIER_UNAVAILABLE",
                "inspect and repair the protected restore journal before serving",
            )
        })?;
        if let Some(operation) = active {
            return Err(Failure::internal(
                "RESTORE_RESUME_REQUIRED",
                format!("resume protected restore operation {operation} before serving"),
            ));
        }
        // Upstream `mapInspectError`: a typed failure passes through;
        // anything else is POSTGRES_INCOMPATIBLE. The Rust inspector
        // already yields `Failure`, so this is a pass-through.
        let facts = self.inspector.inspect().await?;
        if !facts.initialized {
            return Err(Failure::denied(
                "PROVISION_REQUIRED",
                "run central migrate up to initialize the target",
            ));
        }
        if facts.dirty.is_some() {
            return Err(Failure::internal(
                "REPAIR_REQUIRED",
                "run central migrate resume to reconcile the dirty version",
            ));
        }
        self.inspector.verify_serve_baseline().await.map_err(|_| {
            Failure::conflict(
                "POSTGRES_INCOMPATIBLE",
                "the runtime database does not match the required B05 baseline",
            )
        })?;
        self.b08_ready = true;
        self.epochs
            .set_epochs(facts.epochs.security.epoch, facts.epochs.migration.epoch);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Control lock — `pgControlLock`/`pgControlLockLease` on a dedicated,
// non-borrowable connection
// ---------------------------------------------------------------------------

/// `broker.NewRestoreBarrierClient` — upstream always composes the
/// broker client; the R3 slice has no protected broker, so the
/// `CENTRAL_LOCALEXEC=1` dev path substitutes a file-backed journal at
/// `<bootstrap_root>/restore-journal` and anything else stays
/// `None` — the inspection then refuses `RESTORE_BARRIER_UNAVAILABLE`
/// rather than silently serving without a restore fence.
fn select_restore_barrier(
    getenv: impl Fn(&str) -> Option<String>,
    root: &std::path::Path,
) -> Option<Box<dyn RestoreBarrierInspector>> {
    if getenv(ENV_LOCALEXEC).as_deref() == Some("1") {
        return DevRestoreBarrier::new(root.join("restore-journal"))
            .ok()
            .map(|b| Box::new(b) as Box<dyn RestoreBarrierInspector>);
    }
    None
}

/// `openDedicatedConn` — connects with
/// `application_name=central_serve_{label}` and refuses a credential
/// that does not authenticate as `central_runtime` (the upstream role
/// check for both dedicated connections).
async fn open_dedicated_conn(
    dsn: &str,
    label: &'static str,
) -> Result<sqlx::PgConnection, ExitError> {
    let options = PgConnectOptions::from_str(dsn)
        .map_err(|e| dep_err(format!("{label} connection: parse DSN: {e}")))?
        .application_name(&format!("central_serve_{label}"));
    let mut conn = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        sqlx::ConnectOptions::connect(&options),
    )
    .await
    .map_err(|_| dep_err(format!("{label} connection: connect timed out")))?
    .map_err(|e| dep_err(format!("{label} connection: {e}")))?;
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut conn)
        .await
        .map_err(|e| dep_err(format!("{label} connection: role check: {e}")))?;
    if role != "central_runtime" {
        return Err(ExitError::new(
            ExitClass::Denied,
            "AUTHORITY_DENIED",
            Failure::denied(
                "serve_runtime_role",
                "authenticated postgres role is not central_runtime",
            ),
        ));
    }
    Ok(conn)
}

/// `pgControlLock` — the deployment-wide singleton on a dedicated,
/// non-borrowable connection (upstream `ControlConnectionDedicatedNonBorrowable`).
struct PgControlLock {
    conn: Option<sqlx::PgConnection>,
}

impl ControlLock for PgControlLock {
    /// `Acquire` — `SELECT pg_advisory_lock($1)` under the caller's
    /// startup deadline; spawns the heartbeat that pings the dedicated
    /// connection every 5s (bounded 3s) so a dead control session
    /// signals `lost` rather than running as a stale singleton.
    fn acquire(&mut self) -> BoxFuture<'_, Result<Box<dyn ControlLockLease>, Failure>> {
        Box::pin(async move {
            let Some(mut conn) = self.conn.take() else {
                return Err(Failure::internal(
                    "control_lock_reacquire",
                    "control lock acquire is single-shot",
                ));
            };
            if let Err(e) = sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(SERVE_TARGET_EXCLUSION_LOCK_KEY)
                .execute(&mut conn)
                .await
            {
                self.conn = Some(conn);
                return Err(Failure::unavailable(
                    "control_lock_acquire",
                    format!("control lock: acquire advisory lock: {e}"),
                ));
            }
            Ok(Box::new(PgControlLease::start(conn)) as Box<dyn ControlLockLease>)
        })
    }
}

/// `pgControlLockLease` — heartbeat task + one-shot `lost` channel;
/// `close` cancels the heartbeat, awaits its join, then runs
/// `pg_advisory_unlock` and closes the dedicated connection.
struct PgControlLease {
    conn: Arc<tokio::sync::Mutex<Option<sqlx::PgConnection>>>,
    lost: WatchSource,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl PgControlLease {
    fn start(conn: sqlx::PgConnection) -> Self {
        let shared = Arc::new(tokio::sync::Mutex::new(Some(conn)));
        let lost = WatchSource::new();
        let stop = CancellationToken::new();
        let task = {
            let conn = shared.clone();
            let lost_tx = lost.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(CONTROL_LOCK_HEARTBEAT);
                tick.tick().await;
                loop {
                    tokio::select! {
                        () = stop.cancelled() => return,
                        _ = tick.tick() => {
                            let ping = {
                                let mut conn = conn.lock().await;
                                match conn.as_mut() {
                                    Some(conn) => {
                                        tokio::time::timeout(
                                            CONTROL_LOCK_PING_TIMEOUT,
                                            conn.ping(),
                                        )
                                        .await
                                    }
                                    None => {
                                        lost_tx.signal(Failure::unavailable(
                                            "control_lock_lost",
                                            "control lock heartbeat: connection closed",
                                        ));
                                        return;
                                    }
                                }
                            };
                            match ping {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    lost_tx.signal(Failure::unavailable(
                                        "control_lock_lost",
                                        format!("control lock heartbeat: {e}"),
                                    ));
                                    return;
                                }
                                Err(_) => {
                                    lost_tx.signal(Failure::unavailable(
                                        "control_lock_lost",
                                        "control lock heartbeat timed out".to_owned(),
                                    ));
                                    return;
                                }
                            }
                        }
                    }
                }
            })
        };
        Self {
            conn: shared,
            lost,
            stop,
            task: Some(task),
        }
    }
}

impl ControlLockLease for PgControlLease {
    fn lost(&self) -> BoxFuture<'static, Failure> {
        self.lost.watch()
    }

    fn close(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.stop.cancel();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            let mut guard = self.conn.lock().await;
            let Some(mut conn) = guard.take() else {
                return Ok(());
            };
            let mut failure = None;
            if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(SERVE_TARGET_EXCLUSION_LOCK_KEY)
                .execute(&mut conn)
                .await
            {
                failure = Some(Failure::unavailable(
                    "control_lock_release",
                    format!("control lock: release advisory lock: {e}"),
                ));
            }
            if let Err(e) = conn.close().await
                && failure.is_none()
            {
                failure = Some(Failure::unavailable(
                    "control_lock_release",
                    format!("control lock: close connection: {e}"),
                ));
            }
            match failure {
                Some(f) => Err(f),
                None => Ok(()),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Epoch / lifecycle / execution monitors (upstream `serve_monitors.go`)
// ---------------------------------------------------------------------------

/// `serveEpochMonitor` — a bounded, read-only watch on
/// `central.epoch_markers`. The serving gate's inspection installs the
/// authoritative pair via [`EpochMonitorShared::set_epochs`]; every
/// later read must match or the runtime fails `EPOCH_MISMATCH` — a
/// query failure is a security loss, not a transient success.
struct ServeEpochMonitor {
    pool: sqlx::PgPool,
    shared: Arc<EpochMonitorShared>,
}

/// The epoch monitor's shared state — the startup-observed pair, the
/// published security epoch, and the one-shot `Changed` channel.
#[derive(Default)]
struct EpochMonitorShared {
    initial: StdMutex<Option<(u64, u64)>>,
    security: AtomicU64,
    changed: WatchSource,
}

impl EpochMonitorShared {
    /// `SetEpochs` — records the startup-observed authoritative pair.
    fn set_epochs(&self, security: u64, restore: u64) {
        *self.initial.lock().unwrap_or_else(|p| p.into_inner()) = Some((security, restore));
        self.security.store(security, AtomicOrdering::SeqCst);
    }

    /// `SecurityEpoch` — the value readiness and the bootstrap
    /// reconciler publish.
    fn security_epoch(&self) -> u64 {
        self.security.load(AtomicOrdering::SeqCst)
    }
}

impl BoundaryWatch for EpochMonitorShared {
    /// `Changed` — the epoch-drift boundary the runtime select consumes.
    fn tripped(&self) -> BoxFuture<'static, Failure> {
        self.changed.watch()
    }
}

impl BoundaryWatch for Arc<EpochMonitorShared> {
    fn tripped(&self) -> BoxFuture<'static, Failure> {
        (**self).tripped()
    }
}

impl Component for ServeEpochMonitor {
    /// `Run` — polls every 5s with a 2s query bound. After signaling it
    /// stays pending rather than completing: the monitor must never
    /// look like a normal component exit (the boundary arm reports the
    /// drift deterministically).
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let pool = self.pool.clone();
        let shared = self.shared.clone();
        Box::pin(async move {
            let mut tick = tokio::time::interval(SERVE_MONITOR_INTERVAL);
            loop {
                tick.tick().await;
                let check = sqlx::query(
                    "SELECT COALESCE(security_epoch, 0), COALESCE(restore_epoch, 0) \
                     FROM central.epoch_markers ORDER BY updated_at DESC LIMIT 1",
                )
                .map(|row: sqlx::postgres::PgRow| {
                    use sqlx::Row;
                    let security: i64 = row.get(0);
                    let restore: i64 = row.get(1);
                    (security, restore)
                })
                .fetch_one(&pool);
                match tokio::time::timeout(EPOCH_CHECK_TIMEOUT, check).await {
                    Err(_) | Ok(Err(_)) => {
                        shared.changed.signal(Failure::unavailable(
                            "epoch_monitor",
                            "security epoch read failed",
                        ));
                        std::future::pending::<()>().await;
                    }
                    Ok(Ok((security, restore))) => {
                        let initial = *shared.initial.lock().unwrap_or_else(|p| p.into_inner());
                        match initial {
                            Some((expected_security, expected_restore))
                                if security >= 0
                                    && restore >= 0
                                    && security as u64 == expected_security
                                    && restore as u64 == expected_restore => {}
                            _ => {
                                shared.changed.signal(Failure::conflict(
                                    "epoch_monitor",
                                    "security epoch changed",
                                ));
                                std::future::pending::<()>().await;
                            }
                        }
                    }
                }
            }
        })
    }

    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

/// `serveLifecycleMonitor` — observes the descriptor and process
/// boundaries created by the installed runtime supervisor. A
/// `controller` trip reports on `disconnected` (the runtime's
/// intentional-stop arm); `supervisor`/`parent` trips report on `died`
/// (the terminal arm). Cancellation only stops observation.
struct ServeLifecycleMonitor {
    controller: Option<OsBoundaryWatch>,
    supervisor: Option<OsBoundaryWatch>,
    parent: Option<OsBoundaryWatch>,
    disconnected: Arc<WatchSource>,
    died: Arc<WatchSource>,
}

impl ServeLifecycleMonitor {
    /// `newServeLifecycleMonitor` — `CENTRAL_CONTROLLER_FD` is the
    /// supervisor-attached boundary: upstream refuses composition when
    /// it is unprovisioned. The R3 dev slice (`CENTRAL_LOCALEXEC=1`)
    /// substitutes a no-controller monitor — the supervisor/parent
    /// pidfd watches still apply.
    fn new(getenv: impl Fn(&str) -> Option<String>) -> Result<Self, ExitError> {
        let authority_denied = |what: &'static str| {
            ExitError::new(
                ExitClass::Denied,
                "AUTHORITY_DENIED",
                Failure::invalid("lifecycle_boundary", what),
            )
        };
        let controller = match configured_fd(ENV_CONTROLLER_FD, &getenv) {
            Ok(fd) => Some(
                OsBoundaryWatch::from_inherited_fd(fd, "controller")
                    .map_err(|_| authority_denied("controller boundary is unavailable"))?,
            ),
            Err(_) if getenv(ENV_LOCALEXEC).as_deref() == Some("1") => None,
            Err(_) => {
                return Err(authority_denied(
                    "runtime supervisor boundary is unavailable",
                ));
            }
        };
        let fallback = default_parent_pid();
        let supervisor_pid = configured_pid(ENV_SUPERVISOR_PID, fallback, &getenv)
            .map_err(|_| authority_denied("supervisor boundary is unavailable"))?;
        let supervisor = OsBoundaryWatch::for_pid(supervisor_pid, "supervisor")
            .map_err(|_| authority_denied("supervisor boundary is unavailable"))?;
        let parent_pid = configured_pid(ENV_PARENT_PID, fallback, &getenv)
            .map_err(|_| authority_denied("parent boundary is unavailable"))?;
        let parent = if parent_pid != supervisor_pid {
            Some(
                OsBoundaryWatch::for_pid(parent_pid, "parent")
                    .map_err(|_| authority_denied("parent boundary is unavailable"))?,
            )
        } else {
            None
        };
        Ok(Self {
            controller,
            supervisor: Some(supervisor),
            parent,
            disconnected: Arc::new(WatchSource::new()),
            died: Arc::new(WatchSource::new()),
        })
    }
}

/// The parent-death boundary view (upstream `Died`).
struct ParentDeathWatch {
    source: Arc<WatchSource>,
}

impl BoundaryWatch for ParentDeathWatch {
    fn tripped(&self) -> BoxFuture<'static, Failure> {
        self.source.watch()
    }
}

/// The controller-disconnect boundary view (upstream `Disconnected`).
struct ControllerWatch {
    source: Arc<WatchSource>,
}

impl BoundaryWatch for ControllerWatch {
    fn tripped(&self) -> BoxFuture<'static, Failure> {
        self.source.watch()
    }
}

impl Component for ServeLifecycleMonitor {
    /// `Run` — waits on each boundary; the first trip signals its
    /// channel and the monitor stays pending (never a normal
    /// component exit).
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let controller = self.controller.take();
        let supervisor = self.supervisor.take();
        let parent = self.parent.take();
        let disconnected = self.disconnected.clone();
        let died = self.died.clone();
        Box::pin(async move {
            tokio::select! {
                failure = boundary_wait(controller) => {
                    disconnected.signal(failure);
                }
                failure = boundary_wait(supervisor) => {
                    died.signal(failure);
                }
                failure = boundary_wait(parent) => {
                    died.signal(failure);
                }
            }
            std::future::pending::<Result<(), Failure>>().await
        })
    }

    /// `Shutdown` — dropping the watches closes their descriptors.
    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

async fn boundary_wait(watch: Option<OsBoundaryWatch>) -> Failure {
    match watch {
        Some(watch) => match watch.wait().await {
            Ok(()) => Failure::internal("lifecycle_watch", "boundary watch ended without a trip"),
            Err(failure) => failure,
        },
        None => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// Recovery monitor + execution monitor — the identifier-free B08
// diagnostics (`serveRecoveryMonitor`, `serveExecutionMonitor`)
// ---------------------------------------------------------------------------

/// `serveRecoveryStatus` — deliberately identifier-free: facts come
/// only from the durable epoch the coordinator returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeRecoveryStatus {
    /// Epoch generation.
    pub generation: i64,
    /// Epoch state (`RecoveryEpochState`'s string form).
    pub phase: String,
    /// Retry attempt counter.
    pub retry_count: i64,
    /// Whether the epoch is degraded or failed.
    pub degraded: bool,
    /// `claimable` or `pre_watermark_quarantine`.
    pub claimability: String,
}

/// `serveRecoveryMonitor` — records the gate-observed epoch; the
/// execution monitor projects it into the safe diagnostics surface.
struct ServeRecoveryMonitor {
    status: StdMutex<ServeRecoveryStatus>,
}

impl ServeRecoveryMonitor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            status: StdMutex::new(ServeRecoveryStatus::default()),
        })
    }

    /// `Record` — `projectServeRecoveryStatus`.
    fn record(&self, epoch: &RecoveryEpoch) {
        let degraded = matches!(
            epoch.state,
            RecoveryEpochState::RecoveryEpochDegraded | RecoveryEpochState::RecoveryEpochFailed
        );
        *self.status.lock().unwrap_or_else(|p| p.into_inner()) = ServeRecoveryStatus {
            generation: epoch.generation.max(0),
            retry_count: epoch.retry_attempt.max(0),
            phase: epoch.state.as_str().to_owned(),
            degraded,
            claimability: if degraded {
                "pre_watermark_quarantine".to_owned()
            } else {
                "claimable".to_owned()
            },
        };
    }

    fn snapshot(&self) -> ServeRecoveryStatus {
        self.status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// `serveExecutionMetrics` — the deliberately small monitor projection
/// of B08 aggregates; every identifier, token, principal, payload, and
/// failure string is omitted before a serving surface can observe it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeExecutionMetrics {
    /// Whether the recorded epoch is degraded.
    pub degraded: bool,
    /// `RecoveryBatchDuration` nanoseconds.
    pub recovery_batch_nanos: i64,
    /// `RecoveredRows`.
    pub recovered_rows: i64,
    /// `RecoveryLockWait` nanoseconds.
    pub recovery_lock_nanos: i64,
    /// `SchedulerQueueDepth`.
    pub scheduler_queue_depth: i64,
    /// `PoolWait` nanoseconds.
    pub pool_wait_nanos: i64,
    /// `OldestRecordAge` nanoseconds.
    pub oldest_record_nanos: i64,
    /// `TableRowCount`.
    pub table_row_count: i64,
    /// `HeldRecordCount`.
    pub held_record_count: i64,
    /// `PendingOutboxCount`.
    pub pending_outbox_count: i64,
    /// `ReconciliationBacklog`.
    pub reconciliation_backlog: i64,
}

/// The shared metrics+status cell — the execution monitor's
/// `Snapshot()` backing store.
type ServeMetricsShared = Arc<StdMutex<(ServeExecutionMetrics, ServeRecoveryStatus)>>;

/// `serveExecutionMonitor` — polls the same store metrics foreground
/// commands use, every `serveMonitorInterval`; a read failure is a
/// terminal component error, exactly like upstream `Run`.
struct ServeExecutionMonitor {
    reader: Arc<PgExecutionStore>,
    recovery: Arc<ServeRecoveryMonitor>,
    shared: ServeMetricsShared,
}

/// `projectServeExecutionMetrics` — clamps every aggregate at zero.
fn project_metrics(
    snapshot: central_execution::port::ExecutionMetricsSnapshot,
    degraded: bool,
) -> ServeExecutionMetrics {
    ServeExecutionMetrics {
        degraded,
        recovery_batch_nanos: snapshot.recovery_batch_nanos.max(0),
        recovered_rows: snapshot.recovered_rows.max(0),
        recovery_lock_nanos: snapshot.recovery_lock_nanos.max(0),
        scheduler_queue_depth: snapshot.scheduler_queue_depth.max(0),
        pool_wait_nanos: snapshot.pool_wait_nanos.max(0),
        oldest_record_nanos: snapshot.oldest_record_nanos.max(0),
        table_row_count: snapshot.table_row_count.max(0),
        held_record_count: snapshot.held_record_count.max(0),
        pending_outbox_count: snapshot.pending_outbox_count.max(0),
        reconciliation_backlog: snapshot.reconciliation_backlog.max(0),
    }
}

impl Component for ServeExecutionMonitor {
    /// `Run` — one refresh, then a 5s tick; any read failure is
    /// terminal (upstream returns the error).
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let reader = self.reader.clone();
        let recovery = self.recovery.clone();
        let shared = self.shared.clone();
        Box::pin(async move {
            let refresh = |shared: &ServeMetricsShared| {
                let shared = shared.clone();
                let reader = reader.clone();
                let recovery = recovery.clone();
                async move {
                    let snapshot = reader.execution_metrics().await?;
                    let status = recovery.snapshot();
                    *shared.lock().unwrap_or_else(|p| p.into_inner()) =
                        (project_metrics(snapshot, status.degraded), status);
                    Ok::<(), Failure>(())
                }
            };
            refresh(&shared).await?;
            let mut tick = tokio::time::interval(SERVE_MONITOR_INTERVAL);
            loop {
                tick.tick().await;
                refresh(&shared).await?;
            }
        })
    }

    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Bootstrap reconciler — `serveBootstrapReconciler` over the session
// service + the durable candidate source + the epoch monitor
// ---------------------------------------------------------------------------

/// `serveBootstrapReconciler` — discovers the durable
/// `delivery_pending` candidate set and drives it through the session
/// service's fail-closed reconciliation before readiness publishes.
struct ServeBootstrapReconciler {
    service: Arc<
        SessionService<
            PgSessionStore,
            central_adapter_linux::dev_bootstrap::DevFileProtectedBootstrap,
        >,
    >,
    candidates: PgSessionStore,
    epochs: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl BootstrapReconciler for ServeBootstrapReconciler {
    fn reconcile_bootstrap(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let candidates = self
                .candidates
                .discover_bootstrap_candidates()
                .await
                .map_err(|_| {
                    Failure::conflict(
                        "BOOTSTRAP_RECONCILIATION_FAILED",
                        "retry central serve after reconciling bootstrap sessions",
                    )
                })?;
            let epoch = (self.epochs)();
            self.service
                .reconcile_bootstrap(ReconcileRequest {
                    epoch: SecurityEpoch(epoch),
                    candidates,
                })
                .await
                .map(|_| ())
                .map_err(|_| {
                    Failure::conflict(
                        "BOOTSTRAP_RECONCILIATION_FAILED",
                        "retry central serve after reconciling bootstrap sessions",
                    )
                })
        })
    }
}

// ---------------------------------------------------------------------------
// Recovery resume acknowledgement — `CENTRAL_RECOVERY_RESUME{_REASON}`
// (harness phase 3f decisions 3–11)
// ---------------------------------------------------------------------------

/// `recoveryResumeAck` — the operator's acknowledgment of one degraded
/// epoch state; applies only while the epoch is degraded or failed at
/// exactly `generation` and `retry_attempt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResumeAck {
    /// Epoch generation (> 0).
    pub generation: i64,
    /// Retry attempt (>= 0).
    pub retry_attempt: i64,
    /// The bounded acknowledgement text.
    pub reason: String,
}

/// `loadRecoveryResumeConfig` — both variables set together or neither;
/// the pair is `<generation>:<retry_attempt>` (positive generation,
/// non-negative retry, decimal, no sign, no leading zero); the reason
/// is 1–500 printable characters without control or format characters
/// (plus U+2028/U+2029, which break log lines).
///
/// # Errors
/// `Failure::invalid` (`recovery_resume_config_invalid`) on any
/// malformed acknowledgment.
pub fn load_recovery_resume_config(
    getenv: impl Fn(&str) -> Option<String>,
) -> Result<Option<RecoveryResumeAck>, Failure> {
    fn invalid(msg: &'static str) -> Failure {
        Failure::invalid("recovery_resume_config_invalid", msg)
    }
    let pair = getenv(ENV_RECOVERY_RESUME).unwrap_or_default();
    let reason = getenv(ENV_RECOVERY_RESUME_REASON).unwrap_or_default();
    if pair.is_empty() && reason.is_empty() {
        return Ok(None);
    }
    if pair.is_empty() {
        return Err(invalid(
            "CENTRAL_RECOVERY_RESUME is required when CENTRAL_RECOVERY_RESUME_REASON is set",
        ));
    }
    if reason.is_empty() {
        return Err(invalid(
            "CENTRAL_RECOVERY_RESUME_REASON is required when CENTRAL_RECOVERY_RESUME is set",
        ));
    }
    let Some((generation, retry_attempt)) = parse_resume_pair(&pair) else {
        return Err(invalid(
            "CENTRAL_RECOVERY_RESUME must be <generation>:<retry_attempt>, as the serve log hint or central.recovery_epochs show them",
        ));
    };
    let text = reason.trim();
    if text.is_empty()
        || text.chars().count() > MAX_RECOVERY_RESUME_REASON
        || !reason.chars().all(printable_resume_reason_char)
    {
        return Err(invalid(
            "CENTRAL_RECOVERY_RESUME_REASON must be 1 to 500 characters of printable text, without control or format characters",
        ));
    }
    Ok(Some(RecoveryResumeAck {
        generation,
        retry_attempt,
        reason: text.to_owned(),
    }))
}

/// The `recoveryResumePair` shape: `^([1-9][0-9]*):(0|[1-9][0-9]*)$`.
fn parse_resume_pair(pair: &str) -> Option<(i64, i64)> {
    let (generation, retry) = pair.split_once(':')?;
    // `recoveryResumePair` — `^([1-9][0-9]*):(0|[1-9][0-9]*)$`.
    let gen_ok = !generation.is_empty()
        && generation.chars().all(|c| c.is_ascii_digit())
        && !generation.starts_with('0');
    let retry_ok = !retry.is_empty()
        && retry.chars().all(|c| c.is_ascii_digit())
        && (retry == "0" || !retry.starts_with('0'));
    if !(gen_ok && retry_ok) {
        return None;
    }
    Some((generation.parse().ok()?, retry.parse().ok()?))
}

/// `printableRecoveryResumeReason` — no control (Cc) or format (Cf)
/// characters, and never U+2028/U+2029.
fn printable_resume_reason_char(c: char) -> bool {
    if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
        return false;
    }
    // Unicode general category Cf (format) — the assigned blocks.
    let cp = c as u32;
    !matches!(cp,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891
        | 0x08E2 | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064
        | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD
        | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE0001 | 0xE0020..=0xE007F)
}

/// `applyRecoveryResume` — the gate's resume step between
/// `runServingRecoveryEpoch` and the gate steps (decisions 4–7):
/// returns the epoch the rest of the gate runs with — the one
/// `resume_epoch` returned after a resume, the taken-over epoch
/// otherwise.
///
/// - The epoch is not degraded/failed, or the acknowledgment does not
///   name its exact generation and retry attempt: nothing happens
///   except a log line.
/// - A degraded epoch without an applicable acknowledgment logs the
///   exact values to set (decision 7).
/// - `RECOVERY_RESUME_EXPECTATION_CONFLICT` and
///   `RECOVERY_EPOCH_NOT_RESUMABLE` log and continue degraded; any
///   other error fails the start with `RECOVERY_FAILED` (decision 6).
async fn apply_recovery_resume(
    ack: Option<&RecoveryResumeAck>,
    epoch: RecoveryEpoch,
    coordinator: &dyn RecoveryGateCoordinator,
) -> Result<RecoveryEpoch, Failure> {
    let degraded = matches!(
        epoch.state,
        RecoveryEpochState::RecoveryEpochDegraded | RecoveryEpochState::RecoveryEpochFailed
    );
    let mut ack = ack;
    if ack.is_some()
        && (!degraded
            || ack.is_some_and(|a| {
                a.generation != epoch.generation || a.retry_attempt != epoch.retry_attempt
            }))
    {
        tracing::warn!(
            state = epoch.state.as_str(),
            generation = epoch.generation,
            retry_attempt = epoch.retry_attempt,
            "recovery resume not applied: epoch does not match the acknowledgement"
        );
        ack = None;
    }
    if !degraded {
        return Ok(epoch);
    }
    let Some(ack) = ack else {
        log_recovery_resume_hint(&epoch);
        return Ok(epoch);
    };
    let failed = coordinator
        .list_failed_workspaces(epoch.generation, MAX_RECOVERY_RESUME_WORKSPACES)
        .await
        .map_err(|_| {
            Failure::internal(
                "RECOVERY_FAILED",
                "inspect the durable recovery epoch and resume it before serving",
            )
        })?;
    if failed.ids.is_empty() {
        tracing::warn!(
            generation = epoch.generation,
            "recovery resume not applied: epoch has no failed workspace"
        );
        return Ok(epoch);
    }
    let command = recovery_resume_command(ack, &epoch, &failed)?;
    match coordinator.resume_epoch(command).await {
        Ok(resumed) => {
            tracing::info!(
                generation = resumed.generation,
                retry_attempt = resumed.retry_attempt,
                workspaces = recovery_resume_workspaces(&failed),
                reason = ack.reason.as_str(),
                "recovery epoch resumed"
            );
            Ok(resumed)
        }
        Err(cause) => {
            if matches!(
                cause.code(),
                "RECOVERY_RESUME_EXPECTATION_CONFLICT" | "RECOVERY_EPOCH_NOT_RESUMABLE"
            ) {
                tracing::warn!(code = cause.code(), "recovery resume not applied");
                log_recovery_resume_hint(&epoch);
                Ok(epoch)
            } else {
                Err(Failure::internal(
                    "RECOVERY_FAILED",
                    "inspect the durable recovery epoch and resume it before serving",
                ))
            }
        }
    }
}

/// `recoveryResumeCommand` — the audited command: the epoch is resumed
/// as a whole, but the command carries one Workspace scope for its
/// event and receipt — the lowest failed Workspace; the
/// acknowledgement names the affected set.
fn recovery_resume_command(
    ack: &RecoveryResumeAck,
    epoch: &RecoveryEpoch,
    failed: &FailedRecoveryWorkspaces,
) -> Result<ResumeRecoveryEpochCommand, Failure> {
    let scope = TrustedScope::new(
        RECOVERY_RESUME_PRINCIPAL,
        failed.ids[0],
        &[
            Capability::WorkspaceOperator,
            Capability::RecoveryCoordinator,
        ],
    )?;
    let mut command = ResumeRecoveryEpochCommand {
        scope,
        epoch_generation: epoch.generation,
        coordinator_fence: epoch.coordinator_fence,
        expected_state: epoch.state,
        expected_cursor: epoch.scheduler_cursor,
        expected_retry_attempt: epoch.retry_attempt,
        acknowledgement_reason: format!(
            "{} [workspaces: {}]",
            ack.reason,
            recovery_resume_workspaces(failed)
        ),
        idempotency_key: format!(
            "recovery-resume:{}:{}",
            epoch.generation, epoch.retry_attempt
        ),
        capability: Capability::RecoveryCoordinator,
        fingerprint: Default::default(),
    };
    command.fingerprint = recovery_resume_fingerprint(&command);
    command.validate()?;
    Ok(command)
}

/// `recoveryResumeWorkspaces` — ids in store order (ascending), then
/// `(+N more)`.
fn recovery_resume_workspaces(failed: &FailedRecoveryWorkspaces) -> String {
    let mut list = failed
        .ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let more = failed.total - failed.ids.len() as i64;
    if more > 0 {
        list.push_str(&format!(" (+{more} more)"));
    }
    list
}

/// `logRecoveryResumeHint` — names the exact values that resume the
/// epoch (decision 7).
fn log_recovery_resume_hint(epoch: &RecoveryEpoch) {
    tracing::warn!(
        generation = epoch.generation,
        state = epoch.state.as_str(),
        retry_attempt = epoch.retry_attempt,
        "recovery epoch is degraded; to resume set \
         CENTRAL_RECOVERY_RESUME={gen}:{retry} and CENTRAL_RECOVERY_RESUME_REASON=...",
        gen = epoch.generation,
        retry = epoch.retry_attempt,
    );
}

/// `isDurableRecoveryQuarantine` — the durable quarantine reasons that
/// degrade the epoch and let the gate continue.
fn is_durable_recovery_quarantine(cause: &Failure) -> bool {
    matches!(
        cause.code(),
        "RECOVERY_EPOCH_QUARANTINED"
            | "RECOVERY_RETRY_EXHAUSTED"
            | "RECOVERY_WORKSPACE_QUARANTINED"
    )
}

/// `servingRecoveryFailure` — a recovery error that is neither
/// cancellation nor a durable quarantine fails the start as
/// `RECOVERY_FAILED` (upstream `ClassResumable` → exit 6, the reason
/// collapses to `POSTGRES_INCOMPATIBLE` in the safe diagnostic).
fn serving_recovery_failure() -> Failure {
    Failure::internal(
        "RECOVERY_FAILED",
        "inspect the durable recovery epoch and resume it before serving",
    )
}

/// `recoveryContextError` — runtime cancellation during the gate is the
/// cooperative shutdown signal, not a recovery failure (upstream
/// returns `ctx.Err()`, which `startupFailure` maps to
/// `POSTGRES_INCOMPATIBLE`/exit 5).
fn runtime_cancelled_failure() -> Failure {
    Failure::new(
        FailureKind::Conflict,
        "kernel_runtime_cancelled",
        "startup recovery interrupted by runtime shutdown",
    )
}

/// Awaits `future` but resolves early with the runtime-cancellation
/// failure — the `ctx.Done` check upstream's recovery loop performs at
/// every step.
async fn or_runtime<T>(
    runtime: &CancellationToken,
    future: impl std::future::Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    tokio::select! {
        () = runtime.cancelled() => Err(runtime_cancelled_failure()),
        result = future => result,
    }
}

/// `serveRecoveryPreflight` — the [`ServingPreflight`] port of
/// upstream's recovery gate. `run_for_serve` splits the bounded
/// admission window (`startup_deadline` covers the read-only
/// inspection and the recovery-connection acquisition) from the
/// durable drain, which runs on `runtime` and outlives the five-second
/// admission window by design.
struct ServeRecoveryPreflight {
    inspection: ServeInspection,
    /// `Some` in production; `None` is the test seam that skips the
    /// capacity-reserving acquisition (upstream injects
    /// `acquireServingRecoveryConnection` for the same reason).
    pool: Option<sqlx::PgPool>,
    coordinator: Arc<dyn RecoveryGateCoordinator>,
    harness_reconcile: Option<Arc<HarnessReconciler>>,
    artifact_startup: Option<Arc<dyn ArtifactStartupRecovery>>,
    recovery: Arc<ServeRecoveryMonitor>,
    resume: Option<RecoveryResumeAck>,
    opened: OpenedEpoch,
}

impl ServingPreflight for ServeRecoveryPreflight {
    fn run_for_serve(
        &mut self,
        runtime: CancellationToken,
        startup_deadline: Instant,
    ) -> BoxFuture<'_, Result<PreflightReport, Failure>> {
        Box::pin(async move {
            // `p.preflight.Run(startupCtx)` — the inspection is the only
            // authority that may admit a B08 schema.
            let inspected = timeout_at(
                startup_deadline.min(Instant::now() + SERVE_PREFLIGHT_TIMEOUT),
                self.inspection.run(),
            )
            .await;
            match inspected {
                Err(_) => {
                    return Err(Failure::conflict(
                        "POSTGRES_INCOMPATIBLE",
                        "the runtime read-only preflight could not complete; check postgres health",
                    ));
                }
                Ok(Err(cause)) => return Err(cause),
                Ok(Ok(())) => {}
            }
            if !self.inspection.b08_ready {
                return Err(Failure::conflict(
                    "POSTGRES_INCOMPATIBLE",
                    "run the B08 migration before serving",
                ));
            }

            // `acquireServingRecoveryConnection` — only the acquisition
            // is bounded (min(startup, 5s)); the resulting drain is not
            // truncated by the admission window. The held pool slot
            // reserves recovery's capacity for the gate's duration
            // (upstream additionally binds the coordinator to that one
            // connection via `WithDB`; the Rust coordinator issues
            // statements on the pool — the coordinator lease fence
            // still serializes durable recovery, so safety is
            // identical while per-statement scheduling differs).
            let acquire_deadline = startup_deadline.min(Instant::now() + RECOVERY_ACQUIRE_TIMEOUT);
            let _reserved = match &self.pool {
                None => None,
                Some(pool) => match timeout_at(acquire_deadline, pool.acquire()).await {
                    Ok(Ok(conn)) => Some(conn),
                    _ if runtime.is_cancelled() => {
                        return Err(runtime_cancelled_failure());
                    }
                    Ok(Err(_)) | Err(_) => {
                        return Err(Failure::internal(
                            "RECOVERY_UNAVAILABLE",
                            "check PostgreSQL capacity and retry serving",
                        ));
                    }
                },
            };

            // `runServingRecoveryEpoch` — epoch open on the runtime
            // context.
            let epoch = match or_runtime(&runtime, self.coordinator.run_epoch()).await {
                Ok(epoch) => epoch,
                Err(cause) => {
                    return Err(
                        if runtime.is_cancelled() || cause.code() == "kernel_runtime_cancelled" {
                            cause
                        } else {
                            serving_recovery_failure()
                        },
                    );
                }
            };
            // `runOpenedEpoch`: the acknowledged resume, then the epoch
            // the gate runs with is published (monitor, the periodic
            // pass) and the gate steps drain it.
            let current =
                apply_recovery_resume(self.resume.as_ref(), epoch, self.coordinator.as_ref())
                    .await?;
            self.recovery.record(&current);
            *self.opened.lock().unwrap_or_else(|p| p.into_inner()) = Some(current.clone());
            self.run_gate_steps(&runtime, &current).await?;
            Ok(PreflightReport {
                security_epoch: Some(self.inspection.epochs.security_epoch()),
            })
        })
    }
}

impl ServeRecoveryPreflight {
    /// `runGateSteps` — B08 to completion, harness reconciliation,
    /// then the fenced B10 startup pass last.
    async fn run_gate_steps(
        &self,
        runtime: &CancellationToken,
        epoch: &RecoveryEpoch,
    ) -> Result<(), Failure> {
        self.run_recovery_to_completion(runtime, epoch).await?;
        if let Some(reconcile) = &self.harness_reconcile {
            let (_summary, result) =
                or_runtime(runtime, async { Ok(reconcile.run().await) }).await?;
            result?;
        }
        // `runArtifactRecovery` — an unconfigured capability is not a
        // degradation: nothing runs and readiness is untouched.
        if let Some(startup) = &self.artifact_startup {
            let claim = or_runtime(runtime, self.coordinator.claim_artifact_work(epoch)).await?;
            startup
                .recover(&ArtifactFence {
                    generation: claim.fence.generation,
                    epoch_generation: claim.epoch_generation,
                    claim_token: claim.claim_token.clone(),
                })
                .await?;
        }
        Ok(())
    }

    /// `runRecoveryToCompletion` — B08 bookkeeping only: claim each
    /// bounded workspace unit and durably complete it. A durable
    /// quarantine records the degraded monitor state and lets the gate
    /// continue (upstream `isDurableRecoveryQuarantine` →
    /// `recordDegradedRecovery` → `return nil`); the degraded epoch's
    /// `RecoveryClaimability` quarantines only the unverified
    /// pre-watermark runs, not the whole workspace.
    async fn run_recovery_to_completion(
        &self,
        runtime: &CancellationToken,
        epoch: &RecoveryEpoch,
    ) -> Result<(), Failure> {
        loop {
            let claims = match or_runtime(runtime, self.coordinator.claim_batch(epoch)).await {
                Ok(claims) => claims,
                Err(cause) => {
                    if runtime.is_cancelled() || cause.code() == "kernel_runtime_cancelled" {
                        return Err(cause);
                    }
                    if is_durable_recovery_quarantine(&cause) {
                        self.record_degraded(epoch);
                        return Ok(());
                    }
                    return Err(serving_recovery_failure());
                }
            };
            for claim in claims {
                if claim.completed {
                    self.recovery.record(&claim.epoch);
                    return Ok(());
                }
                if !claim.claimed {
                    if matches!(
                        claim.epoch.state,
                        RecoveryEpochState::RecoveryEpochDegraded
                            | RecoveryEpochState::RecoveryEpochFailed
                    ) {
                        self.recovery.record(&claim.epoch);
                        return Ok(());
                    }
                    let delay = if claim.retry_after > Duration::ZERO {
                        claim.retry_after
                    } else {
                        Duration::milliseconds(100)
                    };
                    // Upstream's `timer`/`ctx.Done` pair: the sleep is
                    // interruptible by runtime cancellation.
                    tokio::select! {
                        () = runtime.cancelled() => return Err(runtime_cancelled_failure()),
                        () = tokio::time::sleep(delay.unsigned_abs()) => {}
                    }
                    continue;
                }
                match or_runtime(runtime, self.coordinator.complete_workspace(&claim)).await {
                    Ok(()) => {}
                    Err(cause) => {
                        if runtime.is_cancelled() || cause.code() == "kernel_runtime_cancelled" {
                            return Err(cause);
                        }
                        if is_durable_recovery_quarantine(&cause) {
                            self.record_degraded(&claim.epoch);
                            return Ok(());
                        }
                        return Err(serving_recovery_failure());
                    }
                }
            }
        }
    }

    /// `recordDegradedRecovery` — mark the epoch degraded and record
    /// it (upstream mutates the observed epoch the same way).
    fn record_degraded(&self, epoch: &RecoveryEpoch) {
        let mut degraded = epoch.clone();
        degraded.state = RecoveryEpochState::RecoveryEpochDegraded;
        self.recovery.record(&degraded);
    }
}

// ---------------------------------------------------------------------------
// Proof publisher — CENTRAL_READY_PROOF_PATH file
// ---------------------------------------------------------------------------

/// `ReadyProofPublisher` over `CENTRAL_READY_PROOF_PATH` — writes the
/// safe JSON projection (the nonce never leaves the process;
/// upstream's `fileReadyProofPublisher`).
struct FileReadyProofPublisher {
    path: PathBuf,
    published: StdMutex<Option<String>>,
}

impl ReadyProofPublisher for FileReadyProofPublisher {
    fn begin_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }

    fn publish(&mut self, proof: ReadyProof) -> BoxFuture<'_, Result<(), Failure>> {
        let path = self.path.clone();
        let generation = proof.runtime_generation.clone();
        let body = serde_json::json!({
            "launch_id": proof.launch_id,
            "runtime_generation": proof.runtime_generation,
            "expires_at": proof.expires_at,
        })
        .to_string();
        Box::pin(async move {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, body)
                .and_then(|()| std::fs::rename(&tmp, &path))
                .map_err(|e| Failure::unavailable("ready_proof_publish", e.to_string()))?;
            *self.published.lock().unwrap_or_else(|p| p.into_inner()) = Some(generation);
            Ok(())
        })
    }

    fn revoke(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        let path = self.path.clone();
        Box::pin(async move {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(Failure::unavailable("ready_proof_revoke", e.to_string())),
            }
        })
    }

    fn revoke_if_generation(&mut self, generation: String) -> BoxFuture<'_, Result<(), Failure>> {
        let held = self
            .published
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if held.as_deref() == Some(generation.as_str()) {
            return self.revoke();
        }
        Box::pin(async { Ok(()) })
    }

    fn abort_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// The composition entry point
// ---------------------------------------------------------------------------

/// `ServeComposition` — the assembled profile plus the handles the
/// composition boundary keeps for trusted callers (upstream's
/// `ExecutionService`/`ArtifactService` fields on `ServeDeps`).
pub struct ServeComposition {
    /// The supervised serve profile — preflights, components,
    /// readiness, proof publisher installed.
    pub profile: Profile,
    /// The readiness shared with the probe and the web surface.
    pub readiness: Readiness,
    /// The execution capability (upstream `ExecutionService` — kept
    /// at the boundary for trusted callers; not exposed over HTTP in
    /// this slice).
    pub execution: Arc<ExecutionService<PgExecutionStore, PgExecutionStore, TokioClock, NoB09>>,
    /// The B10 capability when configured — `None` means
    /// unconfigured, never degraded.
    pub artifact: Option<Arc<PgArtifactService>>,
    /// The harness operator surface — always composed so ambiguous
    /// attempts stay resolvable.
    pub operator: Arc<dyn web::harness::HarnessOperator>,
    /// The task service the transport and operator share.
    pub tasks: Arc<ServeTaskService>,
}

/// `openServeDeps` + `composeServe` — opens the pool, composes every
/// capability in upstream's order, and returns the assembled
/// [`Profile`]. All durable composition happens here; `Profile::run`
/// owns supervision only.
///
/// # Errors
/// `ExitError` carrying the classified refusal (`CONFIG_INVALID`,
/// `DEPENDENCY_UNAVAILABLE`, `AUTHORITY_DENIED`).
pub async fn compose_serve(config: &ServeConfig) -> Result<ServeComposition, ExitError> {
    let runtime = ServeRuntime::new();

    // 1. Runtime pool (upstream `openRuntimePool` — `pool_max_conns`
    //    already clamped by `ServeConfig::load`).
    let pool = PgPoolOptions::new()
        .max_connections(config.pool_max)
        .connect(&config.dsn)
        .await
        .map_err(|e| dep_err(format!("runtime pool: {e}")))?;

    // 2. The two dedicated, non-borrowable sessions — control lock and
    //    preflight inspector (`openDedicatedConn` runs the
    //    `central_runtime` role check; a role mismatch is
    //    AUTHORITY_DENIED in upstream).
    let control_conn = open_dedicated_conn(&config.dsn, "control").await?;
    let preflight_conn = open_dedicated_conn(&config.dsn, "preflight").await?;

    // 3. Session capability (`pgsession.New` + bootstrap + service);
    //    a bootstrap-authority refusal is upstream's
    //    AUTHORITY_DENIED (7), not a config error.
    let session = compose_session(pool.clone(), &config.bootstrap_root).map_err(|_| {
        ExitError::new(
            ExitClass::Denied,
            "AUTHORITY_DENIED",
            Failure::denied(
                "serve_bootstrap_authority",
                "bootstrap authority is unavailable",
            ),
        )
    })?;

    // 4. The shared epoch state + the authoritative admission
    //    inspection — `basePreflight.Run(ctx)` runs before any
    //    execution adapter exists so a partially constructed runtime
    //    never holds an execution capability against an unverified
    //    schema.
    let epochs = Arc::new(EpochMonitorShared::default());
    let inspector = PgMigrateInspector::connect(&config.dsn)
        .await
        .map_err(|f| dep_err(format!("preflight inspector: {}", f.message())))?;
    let barrier = select_restore_barrier(|name| std::env::var(name).ok(), &config.bootstrap_root);
    let mut inspection = ServeInspection {
        inspector: Box::new(PgInspector { inner: inspector }),
        barrier,
        epochs: epochs.clone(),
        _preflight_conn: Some(preflight_conn),
        b08_ready: false,
    };
    match tokio::time::timeout(SERVE_PREFLIGHT_TIMEOUT, inspection.run()).await {
        Err(_) => {
            return Err(ExitError::new(
                ExitClass::Timeout,
                "PREFLIGHT_TIMEOUT",
                Failure::unavailable(
                    "serve_preflight_timeout",
                    "the runtime read-only preflight could not complete; check postgres health",
                ),
            ));
        }
        Ok(Err(failure)) => {
            return Err(ExitError::new(
                failure.kind().exit_class(),
                failure.code(),
                failure,
            ));
        }
        Ok(Ok(())) if !inspection.b08_ready => {
            return Err(ExitError::new(
                ExitClass::Incompatible,
                "POSTGRES_INCOMPATIBLE",
                Failure::conflict(
                    "postgres_incompatible",
                    "run the B08 migration before serving",
                ),
            ));
        }
        Ok(Ok(())) => {}
    }

    // 3. Execution store/service + recovery coordinator — the same
    // store instance serves commands, reads, and lease validation
    // (upstream `app.New(executionStore, executionStore, clock)`).
    let exec_store = Arc::new(PgExecutionStore::new(pool.clone()));
    let execution: Arc<ExecutionService<PgExecutionStore, PgExecutionStore, TokioClock, NoB09>> =
        Arc::new(ExecutionService::new(
            PgExecutionStore::new(pool.clone()),
            PgExecutionStore::new(pool.clone()),
            TokioClock,
        ));
    let coordinator = Arc::new(RecoveryCoordinatorService::new(
        PgExecutionStore::new(pool.clone()),
        TokioClock,
        InstanceId::new(),
    ));

    // 4. Task stores + service + transport adapter.
    let task_app_svc = Arc::new(central_task::app::TaskService::new(
        PgTaskStore::new(pool.clone()),
        PgTaskListStore::new(pool.clone()),
        PgTaskDetailStore::new(pool.clone()),
    ));
    let tasks = Arc::new(ServeTaskService::new(
        task_app_svc,
        Arc::new(PgTaskStore::new(pool.clone())),
        Arc::new(PgTaskEventLogStore::new(pool.clone())),
    ));
    let task_events: Arc<dyn ports::TaskEventSink> = Arc::new(ServeTaskEventSink::new(Arc::new(
        PgMilestoneStore::new(pool.clone()),
    )));

    // 5. Harness store + resolver + reconciler.
    let harness_store = Arc::new(PgHarnessStore::new(pool.clone()));
    let resolver = Arc::new(Resolver::new(
        Arc::new(ServeResolveStore::new(
            harness_store.clone(),
            harness_store.clone(),
        )),
        runtime.clock.clone(),
    ));
    let harness_reconcile = Arc::new(HarnessReconciler::new(
        harness_store.clone(),
        runtime.clock.clone(),
        Some(runtime.log.clone()),
    ));

    // 6. B10 artifact capability — unconfigured is not a degradation.
    //    One service instance serves the sink, the web delivery port,
    //    the reconciler lifecycle, and the boundary handle.
    let mut artifact: Option<Arc<PgArtifactService>> = None;
    let mut artifact_reconciler: Option<
        Arc<ArtifactReconciler<PgArtifactStore, PgArtifactStore, S3ObjectStore, PgArtifactService>>,
    > = None;
    if let Some(objects_cfg) = config.objects.clone() {
        let build_objects = || {
            S3ObjectStore::new(objects_cfg.clone())
                .map_err(|f| dep_err(format!("object store: {}", f.reason)))
        };
        let service: Arc<PgArtifactService> = Arc::new(ArtifactService::new(
            PgArtifactStore::new(pool.clone()),
            build_objects()?,
            ReportClassifier::new(),
            PgArtifactStore::new(pool.clone()),
        ));
        // The reconciler's `ResumeLifecycle` port is a second service
        // value over the same stores — services are stateless, so this
        // is upstream's shared `*artifactapp.Service` reference split
        // into Rust's ownership shape.
        artifact_reconciler = Some(Arc::new(ArtifactReconciler::new(
            PgArtifactStore::new(pool.clone()),
            PgArtifactStore::new(pool.clone()),
            build_objects()?,
            ArtifactService::new(
                PgArtifactStore::new(pool.clone()),
                build_objects()?,
                ReportClassifier::new(),
                PgArtifactStore::new(pool.clone()),
            ),
        )));
        artifact = Some(service);
    }

    // Harness execution requires the B10 artifact sink — a partial
    // runtime graph that could mutate durable state is never
    // published.
    if config.harness.enabled && artifact.is_none() {
        return Err(config_err(
            "CENTRAL_HARNESS_ENABLED=1 requires the B10 object store \
             (CENTRAL_ARTIFACT_OBJECT_*); harness execution cannot run \
             without durable artifact materialization",
        ));
    }

    // 7. Harness execution chain (only while enabled).
    let mut dispatcher: Option<Arc<Dispatcher>> = None;
    let mut approval_bridge: Option<Arc<dyn ApprovalBridge>> = None;
    if config.harness.enabled {
        let cfg = &config.harness;
        let Some(artifact_service) = artifact.clone() else {
            return Err(config_err(
                "CENTRAL_HARNESS_ENABLED=1 requires the B10 object store \
                 (CENTRAL_ARTIFACT_OBJECT_*); harness execution cannot run \
                 without durable artifact materialization",
            ));
        };

        // Launcher — HostLauncher by default; LocalExec only under
        // the dev gate (issue #120/#124). The one-time `Box::leak`
        // gives the typed getter the `&'static` value its signature
        // requires; it runs once per process start.
        let localexec_env: &'static str = Box::leak(
            std::env::var(ENV_LOCALEXEC)
                .unwrap_or_default()
                .into_boxed_str(),
        );
        let selection =
            crate::harness_compose::select_launcher(|_| LauncherSelectionArgs(localexec_env));
        let launcher: Arc<dyn ProcessLauncher> = match selection {
            LauncherSelection::Real => crate::harness_compose::build_host_launcher(
                cfg,
                Arc::new(SocketLauncherClient::new()),
            )
            .map_err(|f| config_err(format!("host launcher: {}", f.code())))?,
            LauncherSelection::LocalExec => crate::harness_compose::build_localexec_launcher(
                cfg,
                selection,
                Arc::new(central_adapter_linux::group_signals::LinuxGroupSignals),
                localexec_programs(cfg),
            )
            .map_err(|f| config_err(format!("localexec launcher: {}", f.code())))?,
        };

        // Backend adapter (upstream `newHarnessAdapter`). The
        // persisted adapter identifier is the fixed adapter id —
        // `Backend::adapter_version` (`claudecode/phase-3a`,
        // `opencode/issue-126`, `codex/issue-128`,
        // `antigravity/issue-129`), never the pinned tool version
        // (upstream `newHarnessAdapter` returns it alongside the
        // adapter).
        let probe_dir = cfg.probe_work_dir().to_string_lossy().into_owned();
        let adapter: Arc<dyn Adapter> = match cfg.backend {
            Backend::ClaudeCode => Arc::new(
                central_adapter_harness::claudecode::ClaudeCode::new(
                    central_adapter_harness::claudecode::Config {
                        launcher: Some(launcher.clone()),
                        pinned_version: cfg.claude_version.clone(),
                        allow_unpinned: false,
                        probe_work_dir: probe_dir.clone(),
                    },
                )
                .map_err(|f| config_err(format!("claude-code adapter: {}", f.code())))?,
            ),
            Backend::Opencode => Arc::new(
                central_adapter_harness::opencode::OpenCode::new(
                    central_adapter_harness::opencode::Config {
                        launcher: Some(launcher.clone()),
                        pinned_version: cfg.opencode_version.clone(),
                        allow_unpinned: false,
                        probe_work_dir: probe_dir.clone(),
                    },
                )
                .map_err(|f| config_err(format!("opencode adapter: {}", f.code())))?,
            ),
            Backend::Codex => Arc::new(
                central_adapter_harness::codex::Codex::new(
                    central_adapter_harness::codex::Config {
                        launcher: Some(launcher.clone()),
                        pinned_version: cfg.codex_version.clone(),
                        allow_unpinned: false,
                        probe_work_dir: probe_dir.clone(),
                    },
                )
                .map_err(|f| config_err(format!("codex adapter: {}", f.code())))?,
            ),
            Backend::Antigravity => Arc::new(
                central_adapter_harness::antigravity::Antigravity::new(
                    central_adapter_harness::antigravity::Config {
                        launcher: Some(launcher.clone()),
                        pinned_version: cfg.antigravity_version.clone(),
                        allow_unpinned: false,
                        probe_work_dir: probe_dir.clone(),
                    },
                )
                .map_err(|f| config_err(format!("antigravity adapter: {}", f.code())))?,
            ),
        };
        let adapter_version = cfg.backend.adapter_version().to_owned();

        // Sealed gitclone provisioner/capture (the D2 boundary), then
        // the harness phase 3b startup probe (decision 4, open item
        // 3): `fs.protected_hardlinks` must be 1 and the capture
        // directory must be the runtime-owned 0700 directory setup
        // creates — upstream `probeHarnessCaptureHost`.
        let runtime_uid = rustix::process::getuid().as_raw();
        let gitclone = Arc::new(
            GitClone::new(
                GitCloneConfig {
                    data_root: cfg.data_root.clone(),
                    operator_uid: cfg.operator_uid,
                    runtime_uid,
                    min_free: cfg.min_free,
                    ..GitCloneConfig::default()
                },
                Arc::new(LinuxWorkspaceSealer::new(
                    cfg.data_root.clone(),
                    cfg.operator_uid,
                    runtime_uid,
                    cfg.min_free,
                )),
            )
            .map_err(|f| config_err(format!("gitclone: {}", f.code())))?,
        );
        probe_harness_capture_host(&gitclone, None)?;

        // Lifecycle, resume, orchestrator, dispatcher.
        let budget_defaults = crate::serve_lifecycle::HarnessBudgetDefaults {
            cost_micro_usd: cfg.max_cost_micro_usd,
            wall_clock: cfg.wall_clock,
        };
        let lifecycle = Arc::new(
            ServeRunLifecycle::new(
                execution.clone(),
                exec_store.clone(),
                artifact_service.clone(),
                cfg.eligible_after,
            )
            .with_budget(
                budget_defaults,
                Some(harness_store.clone()),
                cfg.task_cost_cap_micro_usd,
            ),
        );
        let resume = Arc::new(ServeResumeSource::new(
            exec_store.clone(),
            harness_store.clone(),
            harness_store.clone(),
            resolver.clone(),
        ));
        let orchestrator = Arc::new(
            Orchestrator::new(OrchestratorDeps {
                lifecycle: lifecycle.clone(),
                attempts: harness_store.clone(),
                adapter: adapter.clone(),
                workspaces: gitclone.clone(),
                capture: gitclone.clone(),
                artifacts: Arc::new(ServeArtifactSink::new(artifact_service)),
                clock: runtime.clock.clone(),
                ticker: runtime.ticker.clone(),
                cfg: {
                    let mut c = OrchestratorConfig::new(resume);
                    c.adapter_version = adapter_version;
                    c.default_cost_micro_usd = cfg.max_cost_micro_usd;
                    c.default_wall_clock = cfg.wall_clock;
                    c.max_tokens = cfg.max_tokens;
                    c.approval_timeout = cfg.approval_timeout;
                    c.launch_env = cfg.launch_env();
                    c.events = Some(task_events.clone());
                    c
                },
            })
            .map_err(|f| config_err(format!("orchestrator: {}", f.code())))?,
        );
        approval_bridge = Some(orchestrator.clone());
        dispatcher = Some(Arc::new(
            Dispatcher::new(DispatcherDeps {
                lifecycle,
                runner: orchestrator,
                adapter,
                launcher,
                recovery: harness_store.clone(),
                workspaces: gitclone,
                events: task_events.clone(),
                clock: runtime.clock.clone(),
                ticker: runtime.ticker.clone(),
                logger: runtime.log.clone(),
                cfg: DispatcherConfig {
                    concurrency: cfg.concurrency,
                    launch_env: cfg.launch_env(),
                    poll_interval: Duration::ZERO,
                    pause_retry: Duration::ZERO,
                    shutdown_budget: Duration::ZERO,
                    probe_budget: Duration::ZERO,
                    not_startable_cooldown: Duration::ZERO,
                    max_not_startable_cooldown: Duration::ZERO,
                },
            })
            .map_err(|f| config_err(format!("dispatcher: {}", f.code())))?,
        ));
    }

    // 8. The operator surface — always composed.
    let dispatcher_for_status = dispatcher.clone();
    let operator: Arc<dyn web::harness::HarnessOperator> =
        Arc::new(ServeHarnessOperator::new(ServeHarnessOperatorDeps {
            status: Arc::new(move || match &dispatcher_for_status {
                Some(d) => d.status(),
                None => dispatcher::Status::default(),
            }),
            reads: exec_store.clone(),
            commands: execution.clone(),
            tasks: Some(tasks.clone()),
            rerun_tasks: Some(tasks.clone()),
            attempts: harness_store.clone(),
            bridge: approval_bridge,
            policies_enabled: config.harness.enabled,
            backend: config.harness.backend.as_str(),
            budget_defaults: HarnessBudgetDefaults {
                cost_micro_usd: config.harness.max_cost_micro_usd,
                wall_clock: config.harness.wall_clock.unsigned_abs(),
            },
            max_attempts: if config.harness.enabled {
                config.harness.max_attempts
            } else {
                0
            },
            eligible_after: if config.harness.enabled {
                config.harness.eligible_after
            } else {
                OffsetDateTime::UNIX_EPOCH
            },
            task_cost_cap_micro_usd: if config.harness.enabled {
                config.harness.task_cost_cap_micro_usd
            } else {
                0
            },
            resolver: resolver.clone(),
            clock: runtime.clock.clone(),
        }));

    // 9. Routers + listeners. The security epoch source is shared
    //    between session validation and readiness so both see the same
    //    startup-observed value.
    let readiness = Readiness::new();
    let epoch_source: Arc<dyn Fn() -> central_session::domain::SecurityEpoch + Send + Sync> = {
        let r = readiness.clone();
        Arc::new(move || central_session::domain::SecurityEpoch(r.security_epoch()))
    };
    let artifacts: Arc<dyn tports::ArtifactDelivery> = match &artifact {
        Some(service) => Arc::new(ServeArtifactDelivery {
            service: service.clone(),
        }),
        None => Arc::new(UnconfiguredArtifactDelivery),
    };
    let web_state = Arc::new(WebState {
        readiness: Arc::new(KernelProbe {
            readiness: readiness.clone(),
        }),
        sessions: session.service.clone(),
        tasks: tasks.clone(),
        artifacts,
        claimability: exec_store.clone(),
        turn_activity: None,
        harness: Some(operator.clone()),
        workspace: config.workspace,
        allowed_roots: config.allowed_roots.clone(),
        epoch_source: epoch_source.clone(),
    });
    let mut routes = web::routes(&web_state);
    routes.extend(api::routes(&web_state));
    let app_router = build_app_router(
        routes,
        TransportConfig {
            admission: AdmissionConfig {
                expected_host: Some(config.app_listen.to_string()),
                ..AdmissionConfig::default()
            },
            expected_origin: format!("http://{}", config.app_listen),
            preauth: session.service.clone(),
            sessions: session.service.clone(),
            delivery: session.service.clone(),
            epoch_source,
            observer: None,
        },
    )
    .map_err(|f| config_err(format!("app router: {}", f.code())))?;
    let ops_router = build_ops_router(
        Arc::new(KernelProbe {
            readiness: readiness.clone(),
        }),
        Arc::new(prometheus_client::registry::Registry::default()),
        None,
    )
    .map_err(|f| config_err(format!("ops router: {}", f.code())))?;

    let app_listener = TcpListener::bind(config.app_listen)
        .await
        .map_err(|e| dep_err(format!("app listener {}: {e}", config.app_listen)))?;
    let ops_listener = TcpListener::bind(config.ops_listen)
        .await
        .map_err(|e| dep_err(format!("ops listener {}: {e}", config.ops_listen)))?;

    // 10. Profile — upstream `kernel.Profile` wiring: the deployment
    //     control lock first, the serving gate (inspection + recovery)
    //     under it, bootstrap reconciliation after the gate and before
    //     readiness, then the monitors ahead of the listeners so an
    //     epoch or boundary trip races an early failure the same way
    //     upstream's component order does.
    let mut profile = Profile::new(config.profile, readiness.clone());
    profile.set_launch_id(new_runtime_launch_id(OffsetDateTime::now_utc()));
    if let Some(path) = &config.ready_proof_path {
        profile.set_proof_publisher(FileReadyProofPublisher {
            path: path.clone(),
            published: StdMutex::new(None),
        });
    }
    profile.set_control_lock(PgControlLock {
        conn: Some(control_conn),
    });

    let opened: OpenedEpoch = Arc::new(StdMutex::new(None));
    let recovery_monitor = ServeRecoveryMonitor::new();
    profile.set_serving_preflight(ServeRecoveryPreflight {
        inspection,
        pool: Some(pool.clone()),
        coordinator: coordinator.clone(),
        harness_reconcile: Some(harness_reconcile),
        artifact_startup: artifact_reconciler
            .clone()
            .map(|r| r as Arc<dyn ArtifactStartupRecovery>),
        recovery: recovery_monitor.clone(),
        resume: config.recovery_resume.clone(),
        opened: opened.clone(),
    });
    {
        let epochs = epochs.clone();
        profile.set_bootstrap_reconciler(ServeBootstrapReconciler {
            service: session.service.clone(),
            candidates: session.candidates.clone(),
            epochs: Arc::new(move || epochs.security_epoch()),
        });
    }

    // `composeServe`'s watch set: the lifecycle monitor's
    // controller/parent boundaries and the epoch monitor's `Changed`.
    let lifecycle_monitor = ServeLifecycleMonitor::new(|name| std::env::var(name).ok())?;
    profile.set_controller_watch(ControllerWatch {
        source: lifecycle_monitor.disconnected.clone(),
    });
    profile.set_parent_watch(ParentDeathWatch {
        source: lifecycle_monitor.died.clone(),
    });
    profile.set_epoch_watch(epochs.clone());

    let token = profile.cancellation_token();
    // Upstream `components := []kernel.Component{epochMonitor,
    // lifecycleMonitor, executionMonitor, listeners..., dispatcher,
    // artifactReconciler}`.
    profile.add_component(ServeEpochMonitor {
        pool: pool.clone(),
        shared: epochs.clone(),
    });
    profile.add_component(lifecycle_monitor);
    profile.add_component(ServeExecutionMonitor {
        reader: exec_store.clone(),
        recovery: recovery_monitor.clone(),
        shared: Arc::new(StdMutex::new((
            ServeExecutionMetrics::default(),
            ServeRecoveryStatus::default(),
        ))),
    });
    profile.add_component(HttpListenerComponent {
        listener: Some(app_listener),
        router: app_router,
        token: token.clone(),
    });
    profile.add_component(HttpListenerComponent {
        listener: Some(ops_listener),
        router: ops_router,
        token: token.clone(),
    });
    if let Some(d) = dispatcher {
        profile.add_component(HarnessDispatcherComponent {
            dispatcher: d,
            stop: Arc::new(TokenCancel::new(token.clone())),
        });
    }
    if let Some(reconciler) = artifact_reconciler {
        let source = opened.clone();
        profile.add_component(ArtifactReconcilerComponent::with_epoch_source(
            reconciler,
            coordinator.clone(),
            move || source.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        ));
    }

    Ok(ServeComposition {
        profile,
        readiness,
        execution,
        artifact,
        operator,
        tasks,
    })
}

/// The `programs` map the dev-gated `LocalExec` launcher resolves —
/// the backend binary name bound to its absolute path inside the
/// configured `CENTRAL_HARNESS_PATH` directories. An absent binary
/// leaves the name unbound; the adapter's version probe reports the
/// launcher unreachable rather than inventing a path.
fn localexec_programs(cfg: &HarnessConfig) -> BTreeMap<String, PathBuf> {
    let binary = match cfg.backend {
        Backend::ClaudeCode => "claude",
        Backend::Opencode => "opencode",
        Backend::Codex => "codex",
        Backend::Antigravity => "antigravity",
    };
    let mut programs = BTreeMap::new();
    for dir in cfg.path.split(':').filter(|d| !d.is_empty()) {
        let candidate = PathBuf::from(dir).join(binary);
        if candidate.is_file() {
            programs.insert(binary.to_string(), candidate);
            break;
        }
    }
    programs
}

// ---------------------------------------------------------------------------
// Tests — the recovery gate's ordering contract (kernel Step 1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use central_backup::port::{EpochMarker, EpochMarkers, PostgresMigrationFacts};
    use central_execution::domain::ZERO_TIME;
    use central_execution::resume::RecoveryCoordinatorFence;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A passing inspection — initialized schema, no dirty record,
    /// authoritative epoch markers.
    struct TestInspector {
        epochs: EpochMarkers,
    }

    impl MigrationInspection for TestInspector {
        fn inspect(&mut self) -> BoxFuture<'_, Result<PostgresMigrationFacts, Failure>> {
            let epochs = self.epochs.clone();
            Box::pin(async move {
                Ok(PostgresMigrationFacts {
                    initialized: true,
                    applied_versions: vec![],
                    dirty: None,
                    epochs,
                })
            })
        }

        fn verify_serve_baseline(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A clear restore barrier.
    struct ClearBarrier;

    impl RestoreBarrierInspector for ClearBarrier {
        fn inspect(&self) -> BoxFuture<'_, Result<Option<String>, Failure>> {
            Box::pin(async { Ok(None) })
        }
    }

    fn test_inspection(security: u64) -> ServeInspection {
        ServeInspection {
            inspector: Box::new(TestInspector {
                epochs: EpochMarkers {
                    migration: EpochMarker {
                        epoch: 9,
                        digest: String::new(),
                    },
                    security: EpochMarker {
                        epoch: security,
                        digest: String::new(),
                    },
                },
            }),
            barrier: Some(Box::new(ClearBarrier)),
            epochs: Arc::new(EpochMonitorShared::default()),
            _preflight_conn: None,
            b08_ready: false,
        }
    }

    fn test_gate(
        coordinator: Arc<dyn RecoveryGateCoordinator>,
        artifact_startup: Option<Arc<dyn ArtifactStartupRecovery>>,
        opened: OpenedEpoch,
    ) -> (ServeRecoveryPreflight, Arc<ServeRecoveryMonitor>) {
        let recovery = ServeRecoveryMonitor::new();
        (
            ServeRecoveryPreflight {
                inspection: test_inspection(42),
                pool: None,
                coordinator,
                harness_reconcile: None,
                artifact_startup,
                recovery: recovery.clone(),
                resume: None,
                opened,
            },
            recovery,
        )
    }

    fn runtime() -> CancellationToken {
        CancellationToken::new()
    }

    fn far_startup() -> Instant {
        Instant::now() + std::time::Duration::from_secs(30)
    }

    fn epoch() -> RecoveryEpoch {
        RecoveryEpoch {
            generation: 7,
            coordinator_fence: RecoveryCoordinatorFence { generation: 3 },
            state: RecoveryEpochState::RecoveryEpochOpen,
            scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
            workspace_count: 0,
            processed_count: 0,
            claim_cycle: 0,
            retry_attempt: 0,
            snapshot_at: ZERO_TIME,
        }
    }

    fn completed_claim(epoch: &RecoveryEpoch) -> RecoveryWorkspaceClaim {
        RecoveryWorkspaceClaim {
            epoch: epoch.clone(),
            claimed: false,
            completed: true,
            ..RecoveryWorkspaceClaim::default()
        }
    }

    /// Records the call order of the four gate steps.
    struct ScriptedCoordinator {
        calls: Arc<AtomicUsize>,
        order: Arc<StdMutex<Vec<&'static str>>>,
        epoch: RecoveryEpoch,
    }

    impl ScriptedCoordinator {
        fn note(&self, step: &'static str) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.order.lock().unwrap().push(step);
        }
    }

    impl RecoveryGateCoordinator for ScriptedCoordinator {
        fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
            self.note("epoch");
            let e = self.epoch.clone();
            Box::pin(async move { Ok(e) })
        }
        fn claim_batch<'a>(
            &'a self,
            epoch: &'a RecoveryEpoch,
        ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
            self.note("claim");
            let c = vec![completed_claim(epoch)];
            Box::pin(async move { Ok(c) })
        }
        fn complete_workspace<'a>(
            &'a self,
            _claim: &'a RecoveryWorkspaceClaim,
        ) -> BoxFuture<'a, Result<(), Failure>> {
            self.note("complete");
            Box::pin(async { Ok(()) })
        }
        fn claim_artifact_work<'a>(
            &'a self,
            _epoch: &'a RecoveryEpoch,
        ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
            self.note("artifact_fence");
            Box::pin(async move {
                Ok(ArtifactWorkClaim {
                    fence: RecoveryCoordinatorFence { generation: 3 },
                    epoch_generation: 7,
                    claim_token: vec![0xCD; 32],
                    expires_at: ZERO_TIME,
                    claimed: true,
                })
            })
        }
        fn list_failed_workspaces<'a>(
            &'a self,
            _epoch_generation: i64,
            _limit: u32,
        ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
            Box::pin(async { Ok(FailedRecoveryWorkspaces::default()) })
        }
        fn resume_epoch<'a>(
            &'a self,
            _command: ResumeRecoveryEpochCommand,
        ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
            Box::pin(async { Err(Failure::internal("unused", "unused")) })
        }
    }

    struct RecordingArtifactRecovery {
        order: Arc<StdMutex<Vec<&'static str>>>,
        saw_fence: Arc<StdMutex<Option<ArtifactFence>>>,
    }

    impl ArtifactStartupRecovery for RecordingArtifactRecovery {
        fn recover<'a>(&'a self, fence: &'a ArtifactFence) -> BoxFuture<'a, Result<(), Failure>> {
            self.order.lock().unwrap().push("artifact");
            *self.saw_fence.lock().unwrap() = Some(fence.clone());
            Box::pin(async { Ok(()) })
        }
    }

    fn claim_count_claim(epoch: &RecoveryEpoch, claimed: bool) -> RecoveryWorkspaceClaim {
        RecoveryWorkspaceClaim {
            epoch: epoch.clone(),
            claimed,
            completed: false,
            ..RecoveryWorkspaceClaim::default()
        }
    }

    /// The gate runs its steps in upstream's order: epoch → B08 →
    /// harness reconcile → artifact recovery last, under the artifact
    /// work fence, and publishes the opened epoch.
    #[tokio::test(flavor = "current_thread")]
    async fn gate_orders_epoch_b08_harness_artifact_and_publishes() {
        let order = Arc::new(StdMutex::new(Vec::new()));
        let coordinator = Arc::new(ScriptedCoordinator {
            calls: Arc::new(AtomicUsize::new(0)),
            order: order.clone(),
            epoch: epoch(),
        });
        let saw_fence = Arc::new(StdMutex::new(None));
        let artifact = Arc::new(RecordingArtifactRecovery {
            order: order.clone(),
            saw_fence: saw_fence.clone(),
        });
        let opened: OpenedEpoch = Arc::new(StdMutex::new(None));
        let (mut preflight, _recovery) = test_gate(coordinator, Some(artifact), opened.clone());
        // The harness reconciler is store-bound; its ordering is
        // covered by the claim→complete→artifact sequence here.
        let report = preflight
            .run_for_serve(runtime(), far_startup())
            .await
            .unwrap();
        assert_eq!(report.security_epoch, Some(42));
        assert_eq!(
            order.lock().unwrap().as_slice(),
            &["epoch", "claim", "artifact_fence", "artifact"],
            "epoch opens, B08 completes, artifact recovery runs last under its fence"
        );
        assert_eq!(
            saw_fence.lock().unwrap().as_ref().unwrap().epoch_generation,
            7
        );
        assert_eq!(
            opened.lock().unwrap().as_ref().unwrap().generation,
            7,
            "the deferred artifact component's epoch source resolves the opened epoch"
        );
    }

    /// An epoch with live workspace work completes each claim before
    /// the artifact pass (B08 bookkeeping is upstream's first gate
    /// step — `runRecoveryToCompletion`).
    #[tokio::test(flavor = "current_thread")]
    async fn gate_completes_claimed_work_before_artifact() {
        struct TwoBatch {
            order: Arc<StdMutex<Vec<&'static str>>>,
            epoch: RecoveryEpoch,
            batches: Arc<AtomicUsize>,
        }
        impl RecoveryGateCoordinator for TwoBatch {
            fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                let e = self.epoch.clone();
                Box::pin(async move { Ok(e) })
            }
            fn claim_batch<'a>(
                &'a self,
                epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
                let n = self.batches.fetch_add(1, Ordering::SeqCst);
                let claims = if n == 0 {
                    vec![claim_count_claim(epoch, true)]
                } else {
                    vec![completed_claim(epoch)]
                };
                Box::pin(async move { Ok(claims) })
            }
            fn complete_workspace<'a>(
                &'a self,
                _claim: &'a RecoveryWorkspaceClaim,
            ) -> BoxFuture<'a, Result<(), Failure>> {
                self.order.lock().unwrap().push("complete");
                Box::pin(async { Ok(()) })
            }
            fn claim_artifact_work<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
                self.order.lock().unwrap().push("artifact_fence");
                Box::pin(async move {
                    Ok(ArtifactWorkClaim {
                        fence: RecoveryCoordinatorFence { generation: 3 },
                        epoch_generation: 7,
                        claim_token: vec![0xCD; 32],
                        expires_at: ZERO_TIME,
                        claimed: true,
                    })
                })
            }
            fn list_failed_workspaces<'a>(
                &'a self,
                _epoch_generation: i64,
                _limit: u32,
            ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
                Box::pin(async { Ok(FailedRecoveryWorkspaces::default()) })
            }
            fn resume_epoch<'a>(
                &'a self,
                _command: ResumeRecoveryEpochCommand,
            ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
        }
        let order = Arc::new(StdMutex::new(Vec::new()));
        let opened: OpenedEpoch = Arc::new(StdMutex::new(None));
        let (mut preflight, _recovery) = test_gate(
            Arc::new(TwoBatch {
                order: order.clone(),
                epoch: epoch(),
                batches: Arc::new(AtomicUsize::new(0)),
            }),
            Some(Arc::new(RecordingArtifactRecovery {
                order: order.clone(),
                saw_fence: Arc::new(StdMutex::new(None)),
            })),
            opened,
        );
        preflight
            .run_for_serve(runtime(), far_startup())
            .await
            .unwrap();
        assert_eq!(
            order.lock().unwrap().as_slice(),
            &["complete", "artifact_fence", "artifact"]
        );
    }

    /// A durable quarantine on a B08 claim step records the degraded
    /// monitor state and lets the gate continue — the remaining steps
    /// still run in order (upstream `isDurableRecoveryQuarantine` →
    /// `recordDegradedRecovery` → `return nil`).
    #[tokio::test(flavor = "current_thread")]
    async fn quarantine_degrades_and_preserves_order() {
        struct Quarantined {
            order: Arc<StdMutex<Vec<&'static str>>>,
        }
        impl RecoveryGateCoordinator for Quarantined {
            fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                self.order.lock().unwrap().push("epoch");
                Box::pin(async move { Ok(epoch()) })
            }
            fn claim_batch<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
                self.order.lock().unwrap().push("claim");
                Box::pin(async move {
                    Err(Failure::conflict(
                        "RECOVERY_EPOCH_QUARANTINED",
                        "epoch quarantined",
                    ))
                })
            }
            fn complete_workspace<'a>(
                &'a self,
                _claim: &'a RecoveryWorkspaceClaim,
            ) -> BoxFuture<'a, Result<(), Failure>> {
                self.order.lock().unwrap().push("complete");
                Box::pin(async { Ok(()) })
            }
            fn claim_artifact_work<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
                self.order.lock().unwrap().push("artifact_fence");
                Box::pin(async move {
                    Ok(ArtifactWorkClaim {
                        fence: RecoveryCoordinatorFence { generation: 3 },
                        epoch_generation: 7,
                        claim_token: vec![0xCD; 32],
                        expires_at: ZERO_TIME,
                        claimed: true,
                    })
                })
            }
            fn list_failed_workspaces<'a>(
                &'a self,
                _epoch_generation: i64,
                _limit: u32,
            ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
                Box::pin(async { Ok(FailedRecoveryWorkspaces::default()) })
            }
            fn resume_epoch<'a>(
                &'a self,
                _command: ResumeRecoveryEpochCommand,
            ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
        }
        let order = Arc::new(StdMutex::new(Vec::new()));
        let (mut preflight, recovery) = test_gate(
            Arc::new(Quarantined {
                order: order.clone(),
            }),
            Some(Arc::new(RecordingArtifactRecovery {
                order: order.clone(),
                saw_fence: Arc::new(StdMutex::new(None)),
            })),
            Arc::new(StdMutex::new(None)),
        );
        // Degraded is not a startup failure — the gate reports
        // success and the monitor carries the degraded projection.
        let report = preflight
            .run_for_serve(runtime(), far_startup())
            .await
            .expect("a durable quarantine must not fail startup");
        assert_eq!(report.security_epoch, Some(42));
        assert_eq!(
            order.lock().unwrap().as_slice(),
            &["epoch", "claim", "artifact_fence", "artifact"],
            "the degraded epoch still runs the remaining gate steps in order"
        );
        assert!(
            recovery.snapshot().degraded,
            "the monitor records the degraded recovery state"
        );
        assert_eq!(recovery.snapshot().claimability, "pre_watermark_quarantine");
    }

    /// A non-durable recovery failure is `RECOVERY_FAILED` and stops
    /// the gate — the artifact pass never runs.
    #[tokio::test(flavor = "current_thread")]
    async fn non_durable_recovery_failure_fails_start() {
        struct Failing {
            order: Arc<StdMutex<Vec<&'static str>>>,
        }
        impl RecoveryGateCoordinator for Failing {
            fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async move { Ok(epoch()) })
            }
            fn claim_batch<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
                Box::pin(async move { Err(Failure::unavailable("STORE", "read failed")) })
            }
            fn complete_workspace<'a>(
                &'a self,
                _claim: &'a RecoveryWorkspaceClaim,
            ) -> BoxFuture<'a, Result<(), Failure>> {
                Box::pin(async { Ok(()) })
            }
            fn claim_artifact_work<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
                self.order.lock().unwrap().push("artifact_fence");
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
            fn list_failed_workspaces<'a>(
                &'a self,
                _epoch_generation: i64,
                _limit: u32,
            ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
                Box::pin(async { Ok(FailedRecoveryWorkspaces::default()) })
            }
            fn resume_epoch<'a>(
                &'a self,
                _command: ResumeRecoveryEpochCommand,
            ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
        }
        let order = Arc::new(StdMutex::new(Vec::new()));
        let (mut preflight, _recovery) = test_gate(
            Arc::new(Failing {
                order: order.clone(),
            }),
            Some(Arc::new(RecordingArtifactRecovery {
                order: order.clone(),
                saw_fence: Arc::new(StdMutex::new(None)),
            })),
            Arc::new(StdMutex::new(None)),
        );
        let err = preflight
            .run_for_serve(runtime(), far_startup())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "RECOVERY_FAILED");
        assert!(order.lock().unwrap().is_empty());
    }

    /// C2 regression — the durable drain is not truncated by the
    /// bounded admission window. The claim's `retry_after` lands past
    /// `startup_deadline`; only the runtime context may interrupt it.
    /// With the startup deadline wrapped around the drain this test
    /// fails with a timeout-shaped error.
    #[tokio::test(flavor = "current_thread")]
    async fn recovery_drain_outlives_startup_deadline() {
        struct SlowClaim {
            polled: Arc<AtomicUsize>,
        }
        impl RecoveryGateCoordinator for SlowClaim {
            fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async move { Ok(epoch()) })
            }
            fn claim_batch<'a>(
                &'a self,
                epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
                let n = self.polled.fetch_add(1, Ordering::SeqCst);
                let claims = if n == 0 {
                    let mut claim = claim_count_claim(epoch, false);
                    claim.retry_after = Duration::milliseconds(250);
                    vec![claim]
                } else {
                    vec![completed_claim(epoch)]
                };
                Box::pin(async move { Ok(claims) })
            }
            fn complete_workspace<'a>(
                &'a self,
                _claim: &'a RecoveryWorkspaceClaim,
            ) -> BoxFuture<'a, Result<(), Failure>> {
                Box::pin(async { Ok(()) })
            }
            fn claim_artifact_work<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
                Box::pin(async move {
                    Ok(ArtifactWorkClaim {
                        fence: RecoveryCoordinatorFence { generation: 3 },
                        epoch_generation: 7,
                        claim_token: vec![0xCD; 32],
                        expires_at: ZERO_TIME,
                        claimed: true,
                    })
                })
            }
            fn list_failed_workspaces<'a>(
                &'a self,
                _epoch_generation: i64,
                _limit: u32,
            ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
                Box::pin(async { Ok(FailedRecoveryWorkspaces::default()) })
            }
            fn resume_epoch<'a>(
                &'a self,
                _command: ResumeRecoveryEpochCommand,
            ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
        }
        let (mut preflight, _recovery) = test_gate(
            Arc::new(SlowClaim {
                polled: Arc::new(AtomicUsize::new(0)),
            }),
            None,
            Arc::new(StdMutex::new(None)),
        );
        // The admission window is 60ms; the drain sleeps 250ms inside
        // it. Only the runtime context bounds the drain.
        let startup_deadline = Instant::now() + std::time::Duration::from_millis(60);
        let report = preflight
            .run_for_serve(runtime(), startup_deadline)
            .await
            .expect("the recovery drain must outlive the admission window");
        assert_eq!(report.security_epoch, Some(42));
    }

    /// C1 — the profile invokes bootstrap reconciliation after the
    /// serving gate and before readiness publishes; the reconciler
    /// observes the security epoch the gate's inspection installed.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_reconcile_runs_after_gate_before_ready() {
        struct FakeGate;
        impl ServingPreflight for FakeGate {
            fn run_for_serve(
                &mut self,
                _runtime: CancellationToken,
                _deadline: Instant,
            ) -> BoxFuture<'_, Result<PreflightReport, Failure>> {
                Box::pin(async {
                    Ok(PreflightReport {
                        security_epoch: Some(42),
                    })
                })
            }
        }
        struct Spy {
            called: Arc<AtomicBool>,
            saw_epoch: Arc<AtomicU64>,
            readiness: Readiness,
        }
        impl BootstrapReconciler for Spy {
            fn reconcile_bootstrap(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
                self.called.store(true, Ordering::SeqCst);
                self.saw_epoch
                    .store(self.readiness.security_epoch(), Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }
        }
        let readiness = Readiness::new();
        let called = Arc::new(AtomicBool::new(false));
        let saw_epoch = Arc::new(AtomicU64::new(0));
        let mut profile = Profile::new(ProfileConfig::default(), readiness.clone());
        profile.set_serving_preflight(FakeGate);
        profile.set_bootstrap_reconciler(Spy {
            called: called.clone(),
            saw_epoch: saw_epoch.clone(),
            readiness: readiness.clone(),
        });
        profile
            .run(std::future::ready(()))
            .await
            .expect("profile stops cleanly");
        assert!(
            called.load(Ordering::SeqCst),
            "bootstrap reconciliation must be invoked before readiness"
        );
        assert_eq!(
            saw_epoch.load(Ordering::SeqCst),
            42,
            "reconciliation observes the inspected security epoch"
        );
    }

    /// `loadRecoveryResumeConfig` — the env pair contract (decisions
    /// 3–11).
    #[test]
    fn recovery_resume_config_pair_rules() {
        let env = |pair: Option<&str>, reason: Option<&str>| {
            load_recovery_resume_config(|name| match name {
                ENV_RECOVERY_RESUME => pair.map(str::to_owned),
                ENV_RECOVERY_RESUME_REASON => reason.map(str::to_owned),
                _ => None,
            })
        };
        // Neither set → no acknowledgment.
        assert_eq!(env(None, None).unwrap(), None);
        // Well-formed pair + reason.
        assert_eq!(
            env(Some("3:0"), Some("operator-approved")).unwrap(),
            Some(RecoveryResumeAck {
                generation: 3,
                retry_attempt: 0,
                reason: "operator-approved".to_owned(),
            })
        );
        for (pair, reason, why) in [
            (None, Some("r"), "reason without pair is refused"),
            (Some("3:0"), None, "pair without reason is refused"),
            (Some("0:1"), Some("r"), "generation must be positive"),
            (Some("03:1"), Some("r"), "no leading zero"),
            (Some("3:"), Some("r"), "missing retry"),
            (
                Some("3:00"),
                Some("r"),
                "retry must not carry leading zeros",
            ),
            (Some("3:1"), Some(""), "reason may not be empty"),
            (Some("3:1"), Some("\t"), "control characters are refused"),
        ] {
            assert!(env(pair, reason).is_err(), "{why}");
        }
        let long = "x".repeat(MAX_RECOVERY_RESUME_REASON + 1);
        assert!(env(Some("3:1"), Some(long.as_str())).is_err());
    }

    /// `runtimePoolConfig` — `pool_max_conns <= 0 || > 8` clamps to 4;
    /// a clamped value below 3 refuses composition; unset defaults to
    /// 4.
    #[test]
    fn runtime_pool_max_clamps_to_upstream() {
        let max = |dsn: &str| runtime_pool_max(dsn);
        assert_eq!(max("postgres://u@h/d").unwrap(), 4);
        assert_eq!(max("postgres://u@h/d?pool_max_conns=12").unwrap(), 4);
        assert_eq!(max("postgres://u@h/d?pool_max_conns=0").unwrap(), 4);
        assert_eq!(max("postgres://u@h/d?pool_max_conns=-3").unwrap(), 4);
        assert_eq!(max("postgres://u@h/d?pool_max_conns=5").unwrap(), 5);
        assert_eq!(max("postgres://u@h/d?pool_max_conns=8").unwrap(), 8);
        assert!(max("postgres://u@h/d?pool_max_conns=2").is_err());
        assert!(max("postgres://u@h/d?pool_max_conns=abc").is_err());
    }

    /// `newHarnessAdapter` — the persisted adapter identifier is the
    /// fixed id, never the pinned tool version.
    #[test]
    fn adapter_version_is_the_fixed_identifier() {
        assert_eq!(Backend::ClaudeCode.adapter_version(), "claudecode/phase-3a");
        assert_eq!(Backend::Opencode.adapter_version(), "opencode/issue-126");
        assert_eq!(Backend::Codex.adapter_version(), "codex/issue-128");
        assert_eq!(
            Backend::Antigravity.adapter_version(),
            "antigravity/issue-129"
        );
    }

    /// `applyRecoveryResume` — a degraded epoch with a matching
    /// acknowledgement drives `resume_epoch` with the audited command
    /// and the gate continues with the resumed epoch.
    #[tokio::test(flavor = "current_thread")]
    async fn resume_applies_only_to_the_matching_degraded_epoch() {
        struct Resumable {
            seen_command: StdMutex<Option<ResumeRecoveryEpochCommand>>,
        }
        impl RecoveryGateCoordinator for Resumable {
            fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
            fn claim_batch<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
                Box::pin(async { Ok(vec![]) })
            }
            fn complete_workspace<'a>(
                &'a self,
                _claim: &'a RecoveryWorkspaceClaim,
            ) -> BoxFuture<'a, Result<(), Failure>> {
                Box::pin(async { Ok(()) })
            }
            fn claim_artifact_work<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
            fn list_failed_workspaces<'a>(
                &'a self,
                epoch_generation: i64,
                limit: u32,
            ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
                assert_eq!(epoch_generation, 7);
                assert_eq!(limit, MAX_RECOVERY_RESUME_WORKSPACES);
                Box::pin(async move {
                    Ok(FailedRecoveryWorkspaces {
                        ids: vec![WorkspaceId::from_trusted_db_bytes([0x0F; 16])],
                        total: 1,
                    })
                })
            }
            fn resume_epoch<'a>(
                &'a self,
                command: ResumeRecoveryEpochCommand,
            ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                *self.seen_command.lock().unwrap() = Some(command.clone());
                let mut resumed = epoch();
                resumed.state = RecoveryEpochState::RecoveryEpochRunning;
                resumed.retry_attempt = 1;
                Box::pin(async move { Ok(resumed) })
            }
        }
        let coordinator = Resumable {
            seen_command: StdMutex::new(None),
        };
        let mut degraded = epoch();
        degraded.state = RecoveryEpochState::RecoveryEpochDegraded;
        let ack = RecoveryResumeAck {
            generation: 7,
            retry_attempt: 0,
            reason: "acknowledged".to_owned(),
        };
        let resumed = apply_recovery_resume(Some(&ack), degraded.clone(), &coordinator)
            .await
            .unwrap();
        assert_eq!(resumed.state, RecoveryEpochState::RecoveryEpochRunning);
        let command = coordinator
            .seen_command
            .lock()
            .unwrap()
            .clone()
            .expect("resume_epoch ran");
        assert_eq!(command.epoch_generation, 7);
        assert_eq!(command.expected_retry_attempt, 0);
        assert_eq!(command.expected_state, degraded.state);
        assert_eq!(command.scope.principal_id, RECOVERY_RESUME_PRINCIPAL);
        assert!(command.acknowledgement_reason.contains("[workspaces:"));

        // A stale acknowledgment (wrong generation) leaves the epoch
        // degraded and never calls resume.
        let coordinator = Resumable {
            seen_command: StdMutex::new(None),
        };
        let stale = RecoveryResumeAck {
            generation: 99,
            retry_attempt: 0,
            reason: "stale".to_owned(),
        };
        let kept = apply_recovery_resume(Some(&stale), degraded.clone(), &coordinator)
            .await
            .unwrap();
        assert_eq!(kept.state, RecoveryEpochState::RecoveryEpochDegraded);
        assert!(coordinator.seen_command.lock().unwrap().is_none());

        // A refused resume (expectation conflict) continues degraded.
        struct Refusing;
        impl RecoveryGateCoordinator for Refusing {
            fn run_epoch<'a>(&'a self) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
            fn claim_batch<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<Vec<RecoveryWorkspaceClaim>, Failure>> {
                Box::pin(async { Ok(vec![]) })
            }
            fn complete_workspace<'a>(
                &'a self,
                _claim: &'a RecoveryWorkspaceClaim,
            ) -> BoxFuture<'a, Result<(), Failure>> {
                Box::pin(async { Ok(()) })
            }
            fn claim_artifact_work<'a>(
                &'a self,
                _epoch: &'a RecoveryEpoch,
            ) -> BoxFuture<'a, Result<ArtifactWorkClaim, Failure>> {
                Box::pin(async { Err(Failure::internal("unused", "unused")) })
            }
            fn list_failed_workspaces<'a>(
                &'a self,
                _epoch_generation: i64,
                _limit: u32,
            ) -> BoxFuture<'a, Result<FailedRecoveryWorkspaces, Failure>> {
                Box::pin(async move {
                    Ok(FailedRecoveryWorkspaces {
                        ids: vec![WorkspaceId::from_trusted_db_bytes([0x0F; 16])],
                        total: 1,
                    })
                })
            }
            fn resume_epoch<'a>(
                &'a self,
                _command: ResumeRecoveryEpochCommand,
            ) -> BoxFuture<'a, Result<RecoveryEpoch, Failure>> {
                Box::pin(async {
                    Err(Failure::conflict(
                        "RECOVERY_RESUME_EXPECTATION_CONFLICT",
                        "cursor moved",
                    ))
                })
            }
        }
        let kept = apply_recovery_resume(Some(&ack), degraded, &Refusing)
            .await
            .unwrap();
        assert_eq!(kept.state, RecoveryEpochState::RecoveryEpochDegraded);
    }

    /// `probeHarnessCaptureHost` — `fs.protected_hardlinks` must read
    /// `1` and the capture directory must be the runtime-owned 0700
    /// directory.
    #[test]
    fn capture_probe_requires_hardlinks_and_0700() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "central-capture-probe-{}-{}",
            std::process::id(),
            "t"
        ));
        let _ = std::fs::remove_dir_all(&root);
        let capture = root.join("capture");
        std::fs::create_dir_all(&capture).unwrap();
        std::fs::set_permissions(&capture, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sysctl = root.join("protected_hardlinks");
        let sealer = Arc::new(LinuxWorkspaceSealer::new(
            root.clone(),
            1,
            rustix::process::getuid().as_raw(),
            0,
        ));
        let clone = GitClone::new(
            GitCloneConfig {
                data_root: root.clone(),
                operator_uid: 1,
                runtime_uid: rustix::process::getuid().as_raw(),
                min_free: 0,
                ..GitCloneConfig::default()
            },
            sealer,
        )
        .unwrap();

        // Unreadable sysctl → refused.
        assert!(
            probe_harness_capture_host(&clone, Some(root.join("missing").to_str().unwrap()))
                .is_err()
        );
        // `0` → refused.
        std::fs::write(&sysctl, "0\n").unwrap();
        assert!(probe_harness_capture_host(&clone, Some(sysctl.to_str().unwrap())).is_err());
        // `1` + ready capture dir → admitted.
        std::fs::write(&sysctl, "1\n").unwrap();
        probe_harness_capture_host(&clone, Some(sysctl.to_str().unwrap())).unwrap();
        // Capture dir with loose permissions → refused.
        std::fs::set_permissions(&capture, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(probe_harness_capture_host(&clone, Some(sysctl.to_str().unwrap())).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
