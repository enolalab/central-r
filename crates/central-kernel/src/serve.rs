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
use std::sync::{Arc, Mutex as StdMutex};

use axum::Router;
use central_adapter_harness::gitclone::{GitClone, GitCloneConfig};
use central_adapter_linux::launcher_client::SocketLauncherClient;
use central_adapter_linux::workspace_seal::LinuxWorkspaceSealer;
use central_adapter_postgres::artifact::Store as PgArtifactStore;
use central_adapter_postgres::execution::Store as PgExecutionStore;
use central_adapter_postgres::harness::PgHarnessStore;
use central_adapter_postgres::task::{
    DetailStore as PgTaskDetailStore, EventLogStore as PgTaskEventLogStore,
    ListStore as PgTaskListStore, MilestoneStore as PgMilestoneStore, Store as PgTaskStore,
};
use central_adapter_s3::{Config as ObjectConfig, S3ObjectStore};
use central_artifact::app::Service as ArtifactService;
use central_artifact::classifier::ReportClassifier;
use central_artifact::reconciler::{Fence as ArtifactFence, Reconciler as ArtifactReconciler};
use central_execution::app::{NoB09, RecoveryCoordinatorService, Service as ExecutionService};
use central_execution::port::{ArtifactWorkClaim, RecoveryWorkspaceClaim};
use central_execution::resume::{RecoveryEpoch, RecoveryEpochState};
use central_foundation::failure::{ExitClass, Failure};
use central_foundation::identity::{InstanceId, WorkspaceId};
use central_harness::app::dispatcher::{self, Dispatcher, DispatcherConfig, DispatcherDeps};
use central_harness::app::orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorDeps};
use central_harness::app::ports;
use central_harness::app::ports::CancelSignal;
use central_harness::app::reconciler::{Reconciler as HarnessReconciler, Resolver};
use central_harness::port::{Adapter, ProcessLauncher};
use central_transport_http::api;
use central_transport_http::health::{self, ProbeSnapshot, ProbeState};
use central_transport_http::middleware::admission::AdmissionConfig;
use central_transport_http::ports as tports;
use central_transport_http::router::{TransportConfig, build_app_router, build_ops_router};
use central_transport_http::web::harness::HarnessBudgetDefaults;
use central_transport_http::web::{self, WebState};
use sqlx::postgres::PgPoolOptions;
use time::{Duration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::BoxFuture;
use crate::artifact_reconcile::ArtifactReconcilerComponent;
use crate::harness_compose::{
    Backend, ENV_LOCALEXEC, HarnessConfig, LauncherSelection, LauncherSelectionArgs,
};
use crate::lifecycle::{Component, ExitError, Preflight, PreflightReport, Profile, ProfileConfig};
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
/// `minimumExecutionPoolConnections` upstream is 3; the Rust slice
/// keeps a small bounded pool for one operator.
const RUNTIME_POOL_MAX: u32 = 8;

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
    /// Runtime pool size.
    pub pool_max: u32,
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
            pool_max: RUNTIME_POOL_MAX,
        })
    }
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
/// tests drive it with doubles (upstream's `*app.RecoveryCoordinator`).
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

/// `serveRecoveryPreflight` — upstream's startup recovery gate. The
/// steps run inside one supervised preflight under the startup
/// budget, in upstream's order: open the recovery epoch, run B08's
/// bookkeeping to completion, reconcile the harness attempt rows,
/// then run the one-shot fenced artifact recovery last so no Run is
/// exposed behind an unrecovered Artifact.
struct ServeRecoveryPreflight {
    coordinator: Arc<dyn RecoveryGateCoordinator>,
    harness_reconcile: Option<Arc<HarnessReconciler>>,
    artifact_startup: Option<Arc<dyn ArtifactStartupRecovery>>,
    opened: OpenedEpoch,
}

impl Preflight for ServeRecoveryPreflight {
    fn run(&mut self) -> BoxFuture<'_, Result<PreflightReport, Failure>> {
        Box::pin(async move {
            let epoch = self.coordinator.run_epoch().await?;
            self.run_to_completion(&epoch).await?;
            if let Some(reconcile) = &self.harness_reconcile {
                let (_summary, result) = reconcile.run().await;
                result?;
            }
            if let Some(startup) = &self.artifact_startup {
                let claim = self.coordinator.claim_artifact_work(&epoch).await?;
                startup
                    .recover(&ArtifactFence {
                        generation: claim.fence.generation,
                        epoch_generation: claim.epoch_generation,
                        claim_token: claim.claim_token.clone(),
                    })
                    .await?;
            }
            *self.opened.lock().unwrap_or_else(|p| p.into_inner()) = Some(epoch);
            Ok(PreflightReport::default())
        })
    }
}

impl ServeRecoveryPreflight {
    /// `runRecoveryToCompletion` — B08 bookkeeping only: claim each
    /// bounded workspace unit and durably complete it. A degraded or
    /// exhausted epoch ends the loop (upstream records the degraded
    /// monitor state; `RecoveryClaimability` quarantines only the
    /// unverified pre-watermark runs, not the whole workspace).
    async fn run_to_completion(&self, epoch: &RecoveryEpoch) -> Result<(), Failure> {
        loop {
            let claims = self.coordinator.claim_batch(epoch).await?;
            if claims.is_empty() {
                return Ok(());
            }
            for claim in claims {
                if claim.completed {
                    return Ok(());
                }
                if !claim.claimed {
                    if matches!(
                        claim.epoch.state,
                        RecoveryEpochState::RecoveryEpochDegraded
                            | RecoveryEpochState::RecoveryEpochFailed
                            | RecoveryEpochState::RecoveryEpochCompleted
                    ) {
                        return Ok(());
                    }
                    let delay = if claim.retry_after > Duration::ZERO {
                        claim.retry_after
                    } else {
                        Duration::milliseconds(100)
                    };
                    tokio::time::sleep(delay.unsigned_abs()).await;
                    continue;
                }
                self.coordinator.complete_workspace(&claim).await?;
            }
        }
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

    // 1. Runtime pool (upstream `openRuntimePool`).
    let pool = PgPoolOptions::new()
        .max_connections(config.pool_max)
        .connect(&config.dsn)
        .await
        .map_err(|e| dep_err(format!("runtime pool: {e}")))?;

    // 2. Session capability (`pgsession.New` + bootstrap + service).
    let session = compose_session(pool.clone(), &config.bootstrap_root)
        .map_err(|f| config_err(format!("session bootstrap: {}", f.code())))?;

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

        // Backend adapter (upstream `newHarnessAdapter`).
        let probe_dir = cfg.probe_work_dir().to_string_lossy().into_owned();
        let (adapter, adapter_version): (Arc<dyn Adapter>, String) = match cfg.backend {
            Backend::ClaudeCode => (
                Arc::new(
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
                cfg.claude_version.clone(),
            ),
            Backend::Opencode => (
                Arc::new(
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
                cfg.opencode_version.clone(),
            ),
            Backend::Codex => (
                Arc::new(
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
                cfg.codex_version.clone(),
            ),
            Backend::Antigravity => (
                Arc::new(
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
                cfg.antigravity_version.clone(),
            ),
        };

        // Sealed gitclone provisioner/capture (the D2 boundary).
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

    // 10. Profile — the recovery gate preflight first, then
    //     components in upstream's order (app listener, ops listener,
    //     dispatcher, fenced artifact reconciler); settlement is
    //     reverse-registration.
    let mut profile = Profile::new(config.profile, readiness.clone());
    profile.set_launch_id(new_runtime_launch_id(OffsetDateTime::now_utc()));
    if let Some(path) = &config.ready_proof_path {
        profile.set_proof_publisher(FileReadyProofPublisher {
            path: path.clone(),
            published: StdMutex::new(None),
        });
    }

    let opened: OpenedEpoch = Arc::new(StdMutex::new(None));
    profile.add_preflight(ServeRecoveryPreflight {
        coordinator: coordinator.clone(),
        harness_reconcile: Some(harness_reconcile),
        artifact_startup: artifact_reconciler
            .clone()
            .map(|r| r as Arc<dyn ArtifactStartupRecovery>),
        opened: opened.clone(),
    });

    let token = profile.cancellation_token();
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
    use central_execution::domain::ZERO_TIME;
    use central_execution::resume::RecoveryCoordinatorFence;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let mut preflight = ServeRecoveryPreflight {
            coordinator,
            // The harness reconciler is store-bound; its ordering is
            // covered by the claim→complete→artifact sequence here.
            harness_reconcile: None,
            artifact_startup: Some(artifact),
            opened: opened.clone(),
        };
        let report = preflight.run().await.unwrap();
        assert_eq!(report, PreflightReport::default());
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
        }
        let order = Arc::new(StdMutex::new(Vec::new()));
        let mut preflight = ServeRecoveryPreflight {
            coordinator: Arc::new(TwoBatch {
                order: order.clone(),
                epoch: epoch(),
                batches: Arc::new(AtomicUsize::new(0)),
            }),
            harness_reconcile: None,
            artifact_startup: Some(Arc::new(RecordingArtifactRecovery {
                order: order.clone(),
                saw_fence: Arc::new(StdMutex::new(None)),
            })),
            opened: Arc::new(StdMutex::new(None)),
        };
        preflight.run().await.unwrap();
        assert_eq!(
            order.lock().unwrap().as_slice(),
            &["complete", "artifact_fence", "artifact"]
        );
    }
}
