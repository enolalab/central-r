//! `runHelperDaemon` (`cmd/central/main.go`) — the `--helper` mode's
//! whole body after the mode gates: `LISTEN_FDS` admission, the
//! genesis/instance branch, `helperPeerPolicyFromEnvironment`, signal
//! cancellation, and `Serve`/`ServeGenesis` on the systemd-supplied
//! descriptor 3.
//!
//! What this slice composes is the production handler set: the peer
//! and socket policies, the closed matrix, the genesis transport
//! (init admitted, everything else denied), and — on the instance
//! branch — the full handler graph including the broker-backed
//! lifecycle arm (`newHelperLifecycleHandler`: the B01 evaluator, B02
//! candidate store, B04 broker authority, ADR 0019 postgres
//! credential stores, and the authorized production handler).
//! `init` is real on both branches — the genesis handler on an
//! absent host, the present-instance answer on the ordinary server
//! (R5 T13).

use super::browser::{
    BootstrapShowHandler, BrowserHandler, Presentation, PresentationGuard,
    PresentationLeaseStarterV2, SystemControllingTty, SystemFreshPam, SystemWaylandSeat,
};
use super::browser_runtime::{
    ChromiumManagedLauncher, FileManagedBrowserState, FileReadyProofSource,
    ProtectedBootstrapPresenter, broker_socket_path, browser_approval_path, ready_proof_path,
    remove_browser_approval, runtime_generation_path,
};
use super::client::PRODUCTION_SOCKET_PATH;
use super::grant::CeremonyScope;
use super::init::{GenesisInitHandler, PresentInitHandler};
use super::pam_ceremony::PamConfirmer;
use super::prepare::UnavailablePrepareHandler;
use super::server::{GenesisServer, PeerPolicy, Server, SocketPolicy, serve, serve_genesis};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

/// `helperPeerPolicyFromEnvironment` — operator ids from
/// `CENTRAL_OPERATOR_UID`/`CENTRAL_OPERATOR_GID` (nonzero `ParseUint`
/// results only); the daemon uid is 0 and the socket policy names the
/// configured socket path, owner root, operator group, 0660.
///
/// Upstream's `strconv.ParseUint(_, 10, 32)` accepts a leading `+`
/// but no whitespace or sign-minus; nonzero required.
pub(crate) fn parse_u32_strict(raw: &str) -> Option<u32> {
    if raw.is_empty() {
        return None;
    }
    let digits = raw.strip_prefix('+').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok()
}

pub fn helper_peer_policy_from_env(
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(PeerPolicy, SocketPolicy), String> {
    let uid = env("CENTRAL_OPERATOR_UID")
        .and_then(|v| parse_u32_strict(&v))
        .filter(|v| *v != 0);
    let Some(uid) = uid else {
        return Err("operator UID policy is not provisioned".to_owned());
    };
    let gid = env("CENTRAL_OPERATOR_GID")
        .and_then(|v| parse_u32_strict(&v))
        .filter(|v| *v != 0);
    let Some(gid) = gid else {
        return Err("operator GID policy is not provisioned".to_owned());
    };
    Ok((
        PeerPolicy {
            daemon_uid: 0,
            operator_uid: uid,
            operator_gid: gid,
        },
        SocketPolicy {
            path: helper_socket_path(env),
            owner_uid: 0,
            group_gid: gid,
            mode: 0o660,
        },
    ))
}

/// `helperSocketPath` — `CENTRAL_HELPER_SOCKET` or the production path.
pub fn helper_socket_path(env: &dyn Fn(&str) -> Option<String>) -> String {
    env("CENTRAL_HELPER_SOCKET")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned())
}

/// The daemon's shared accept-loop budget — `60 * time.Second`,
/// upstream's `Serve(ctx, 3, srv, 60*time.Second)`.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The bin-supplied runtime pieces the adapter cannot own:
/// `runtimePresentationGuard` opens a dedicated `central_runtime`
/// PostgreSQL connection per call inside upstream's `cmd` — this crate
/// holds no `sqlx`, so the bin bridges it behind the two trait shapes
/// the one upstream object fills. `begin` feeds the browser-open V2
/// lease slot; `validate` feeds the bootstrap-show guard. Both or
/// neither — upstream's PAM-and-TTY-together rule for injected host
/// seams.
pub struct HelperRuntimeDeps {
    pub begin_presentation: Option<Box<dyn PresentationLeaseStarterV2>>,
    pub validate_presentation: Option<Box<dyn PresentationGuard>>,
}

impl HelperRuntimeDeps {
    /// The reference-host/test arm: no presentation bridge — the
    /// browser and bootstrap verbs stay unconfigured and deny.
    pub const fn absent() -> Self {
        Self {
            begin_presentation: None,
            validate_presentation: None,
        }
    }
}

/// `main.go`'s `runHelperDaemon` browser/bootstrap composition —
/// `fileReadyProofSource`, `removeBrowserApproval`, the managed
/// chromium launcher, the broker bootstrap presenter, and the default
/// PAM/TTY seams. A partial `deps` is a composition error, exactly
/// like upstream's "host bootstrap seams must provide PAM and TTY
/// together".
fn compose_browser_handlers(
    env: &dyn Fn(&str) -> Option<String>,
    deps: HelperRuntimeDeps,
) -> Result<(Option<BrowserHandler>, Option<BootstrapShowHandler>), String> {
    let (begin, validate) = match (deps.begin_presentation, deps.validate_presentation) {
        (None, None) => return Ok((None, None)),
        (Some(b), Some(v)) => (b, v),
        _ => {
            return Err(
                "host bootstrap presentation seams must provide begin and validate together"
                    .to_owned(),
            );
        }
    };
    let proofs = FileReadyProofSource::new(ready_proof_path(env), runtime_generation_path(env));
    let approval = browser_approval_path(env);
    // `_ = removeBrowserApproval()` — the startup clear's error is
    // deliberately dropped upstream.
    let _ = remove_browser_approval(&approval);
    let launcher = ChromiumManagedLauncher::new(approval.clone());
    let browser = BrowserHandler::with_presentation(
        Box::new(proofs.clone()),
        Box::new(SystemWaylandSeat),
        Box::new(launcher.clone()),
        Some(Box::new(launcher)),
        Presentation::LeaseV2(begin),
    )
    .map_err(|e| format!("browser handler: {e}"))?;
    let producer =
        crate::broker::bootstrap_session::BootstrapPresenter::new(broker_socket_path(env).into())
            .map_err(|e| format!("bootstrap presenter: {e}"))?;
    let show = BootstrapShowHandler::with_presentation(
        Box::new(proofs),
        Box::new(FileManagedBrowserState::new(approval.clone())),
        Some(Box::new(FileManagedBrowserState::new(approval))),
        Box::new(SystemFreshPam),
        Box::new(SystemControllingTty),
        Box::new(ProtectedBootstrapPresenter::new(producer)),
        Presentation::Guard(validate),
    )
    .map_err(|e| format!("bootstrap-show handler: {e}"))?;
    Ok((Some(browser), Some(show)))
}

/// `runHelperDaemon` — returns the process exit code; `stderr` is the
/// daemon's journal line writer. `env` is the environment seam so the
/// grammar-level tests can exercise the failure arms without systemd.
/// `genesis_absent` is the mode split upstream takes from
/// `productionGenesisEnv().state(ctx)`; a broken state lands on the
/// instance branch, exactly as `helperModeFor` decides. `deps` carries
/// the PostgreSQL presentation bridge the bin owns (see
/// [`HelperRuntimeDeps`]); [`HelperRuntimeDeps::absent`] leaves the
/// browser and bootstrap-show verbs configured-but-denying.
pub fn run_helper_daemon(
    genesis_absent: bool,
    env: &dyn Fn(&str) -> Option<String>,
    deps: HelperRuntimeDeps,
    stderr: &mut dyn Write,
) -> u8 {
    // `strconv.Atoi(os.Getenv("LISTEN_FDS"))` must parse to >= 1: the
    // activated descriptor count, with fd 3 the socket.
    let raw = env("LISTEN_FDS").unwrap_or_default();
    let count = raw.parse::<i64>().unwrap_or(-1);
    if count < 1 {
        let _ = writeln!(stderr, "helper: no socket fd (LISTEN_FDS={raw:?})");
        return 3;
    }
    let (peer, socket) = match helper_peer_policy_from_env(env) {
        Ok(ok) => ok,
        Err(e) => {
            let which = if genesis_absent {
                "genesis composition"
            } else {
                "composition"
            };
            let _ = writeln!(stderr, "helper: {which}: {e}");
            return 6;
        }
    };
    let (cancel, _waiter) = match cancel_on_signal() {
        Ok(pair) => pair,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 3;
        }
    };
    // fd 3 = activation index 0, proven open by F_GETFD before the
    // audited wrapper claims ownership.
    let listen = match crate::sys::audited::socket_activation_fd(0) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = writeln!(stderr, "helper: socket fd 3: {e}");
            return 3;
        }
    };
    if genesis_absent {
        // `newGenesisHelperServer`: the physical-TTY confirmer
        // (`NewPAMConfirmer` directly — the instance ceremony store
        // does not exist yet), the physical console, and the genesis
        // grant store under the protected root.
        let srv = Arc::new(GenesisServer {
            peer_policy: Some(peer),
            socket: Some(socket),
            init: Box::new(GenesisInitHandler::production(
                Box::new(PamConfirmer::new()),
            )),
            auditor: None,
        });
        if let Err(e) = serve_genesis(listen, &srv, IDLE_TIMEOUT, cancel) {
            let _ = writeln!(stderr, "helper: {e}");
            return 3;
        }
        return 0;
    }
    let (browser_slot, bootstrap_show_slot) = match compose_browser_handlers(env, deps) {
        Ok(pair) => pair,
        Err(e) => {
            let _ = writeln!(stderr, "helper: composition: {e}");
            return 6;
        }
    };
    // `resolveProductionInstanceComposition` — upstream resolves the
    // validated instance (id + authoritative roots) before composing
    // any backup/restore seam; a broken instance fails the daemon,
    // not just one verb.
    let composition = match crate::broker::daemon::resolve_production_instance_composition() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "helper: composition: {e}");
            return 6;
        }
    };
    let broker_path: std::path::PathBuf = broker_socket_path(env).into();
    let backup_repository_root =
        std::path::PathBuf::from(&composition.authoritative_state_root).join("backups");
    // `newHelperConfirmer` — ONE confirmer in the instance's installed
    // ceremony mode, shared across every handler slot (upstream
    // main.go:510-514) so handlers cannot disagree about whether this
    // instance confirms at a console or against a grant. `clone()`
    // hands each slot a handle on the same logical confirmer, never a
    // second instance; a composition refusal exits 6 exactly like the
    // per-slot construction did.
    let confirmer = match helper_confirmer(&composition) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "helper: composition: {e}");
            return 6;
        }
    };
    // `newHelperLifecycleHandler` — hoisted ahead of the Server
    // literal because TWO slots share this instance: the `lifecycle`
    // verb itself and the rescue cleanup, which delegates `down`
    // through it as a second ceremony (upstream's
    // `newProductionRescueHandler(composition, confirmer, lifecycle)`).
    // A composition refusal exits 6 — the daemon never serves a
    // half-composed lifecycle.
    let lifecycle_handler: Arc<dyn super::lifecycle::LifecycleHandler> =
        match helper_lifecycle_handler(&composition, &broker_path, confirmer.clone(), stderr) {
            Ok(h) => Arc::new(h),
            Err(e) => {
                let _ = writeln!(stderr, "helper: composition: {e}");
                return 6;
            }
        };
    // `newProductionRestoreAbandonHandler` — composable in this
    // slice: the PAM confirmer, the one-purpose broker client, and
    // the fixed instance/target scope are all real. Upstream fails
    // the whole composition when the client cannot be built, so the
    // daemon exits 6 here too rather than serving a half seam.
    // `newProductionRestoreEngineLauncher` — the one launcher the
    // apply/resume handler and the verify runner share, exactly as
    // upstream's `restoreLauncher` is handed to both. A launcher that
    // cannot resolve its protected root or repository fails the
    // whole helper composition, upstream's `return nil, err`.
    let restore_launcher =
        match super::restore_launcher::ProductionRestoreEngineLauncher::new_production(
            &composition,
            &broker_path,
        ) {
            Ok(launcher) => Arc::new(launcher),
            Err(e) => {
                let _ = writeln!(stderr, "helper: composition: {}", e.message());
                return 6;
            }
        };
    // `newProductionRestoreApplyHandler` — upstream composes the
    // destructive path `WithEngine` only: the fresh ceremony's
    // one-use authorization never leaves this root process — it is
    // spent inside the launch, so a confirmation cannot be harvested
    // and replayed against a differently composed engine. The one
    // handler backs both apply and resume, upstream's
    // `apply: restoreApply, resume: restoreApply`.
    let restore_apply_issuer =
        match crate::broker::recovery_authority::RestoreApplyAuthorizationIssuer::new(
            broker_path.clone(),
        ) {
            Ok(issuer) => issuer,
            Err(e) => {
                let _ = writeln!(stderr, "helper: composition: {}", e.message());
                return 6;
            }
        };
    let restore_operations = Arc::new(
        super::restore::RestoreApplyAuthorizationHandler::with_engine(
            Some(Box::new(confirmer.clone())),
            Some(Box::new(restore_apply_issuer)),
            CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            },
            Box::new(super::restore_launcher::SharedRestoreEngineLauncher(
                restore_launcher.clone(),
            )),
        ),
    );
    let restore_abandon =
        match crate::broker::recovery_authority::RestoreAbandonClient::new(broker_path.clone()) {
            Ok(client) => Some(Box::new(super::restore::RestoreAbandonHandlerImpl::new(
                Some(Box::new(confirmer.clone())),
                Some(Box::new(client)),
                CeremonyScope {
                    instance_id: "default".to_owned(),
                    target_id: "postgres:central".to_owned(),
                },
            ))
                as Box<dyn super::restore::RestoreAbandonHandler>),
            Err(e) => {
                let _ = writeln!(stderr, "helper: composition: {}", e.message());
                return 6;
            }
        };
    // `NewRestoreBarrierClient` — the read-only view of the
    // broker-owned restore barrier and issued-ticket barrier that
    // `resolvingRestoreOperationHandler` resolves against. Upstream
    // fails composition when the client cannot be built, so a bad
    // socket exits 6 here too.
    let restore_barrier =
        match crate::broker::restore_barrier::RestoreBarrierClient::new(broker_path.clone()) {
            Ok(client) => Arc::new(client),
            Err(e) => {
                let _ = writeln!(stderr, "helper: composition: {}", e.message());
                return 6;
            }
        };
    // `newProductionBackupMinioPreparer` — the real provisioner
    // chain behind `backup create`'s operation-bound MinIO handoff.
    // Upstream fails the helper composition when it cannot be built;
    // the same exit here rather than serving a half seam.
    let backup_minio =
        match crate::helper::minio_provision::ProductionBackupMinioPreparer::new_production(
            &composition,
            &broker_path,
        ) {
            Ok(preparer) => {
                Box::new(preparer) as Box<dyn super::backup::BackupMinioCredentialPreparer>
            }
            Err(e) => {
                let _ = writeln!(stderr, "helper: composition: {}", e.message());
                return 6;
            }
        };
    let resolving = Arc::new(
        super::restore_resolvers::ResolvingRestoreOperationHandler::new(
            Some(Box::new(
                super::restore_resolvers::BrokerRestoreBarrierOperations::new(
                    restore_barrier.clone(),
                ),
            )),
            Some(Box::new(
                super::restore_resolvers::BrokerRestoreTicketOperations::new(
                    restore_barrier.clone(),
                ),
            )),
            Some(Box::new(restore_operations.clone())),
            Some(Box::new(restore_operations)),
            restore_abandon,
        ),
    );
    let srv = Arc::new(Server {
        peer_policy: Some(peer),
        socket: Some(socket),
        // `newProductionPrepareHandlerWithConfirmer` — the shared
        // confirmer, the shared B01 evaluator, the verified lock's
        // `helper_release` identity, and the confirmation binding
        // minted over the composition's own `config_binding` (the
        // sha256 of the protected config — never request input).
        // `prepareRootsFor`: the work dir is a sibling of the
        // dependency store, `<state_root>/dependency-prepare`.
        //
        // A host that cannot compose the prepare graph still serves
        // every other verb: it refuses explicitly rather than being
        // left unset — upstream's `unavailablePrepareHandler` — and
        // the reason is journalled at startup, never onto the wire.
        // A confirmer that cannot compose is fatal exactly as
        // upstream's shared-confirmer construction is.
        prepare: {
            let handler: Box<dyn super::server::PrepareHandler> =
                match crate::infra::prepare::LockAdapter::new().and_then(|lock| {
                    let source = super::prepare::PrepareConfirmationSource {
                        config_binding: composition.config_binding.clone(),
                        helper_release: super::prepare::helper_release_identity(
                            &lock.lock().helper_release_digest,
                        ),
                        boot_id: String::new(),
                        now: None,
                    };
                    crate::infra::prepare::new_prepare_handler(
                        &crate::infra::prepare::PrepareRoots {
                            work_dir: std::path::PathBuf::from(
                                &composition.authoritative_state_root,
                            )
                            .join("dependency-prepare"),
                            dependency_root: std::path::PathBuf::from(&composition.dependency_root),
                        },
                        Box::new(helper_advisory_evaluator(
                            &composition,
                            &broker_path,
                            stderr,
                        )),
                        Box::new(confirmer.clone()),
                        source,
                    )
                }) {
                    Ok(handler) => Box::new(handler),
                    Err(e) => {
                        let _ = writeln!(
                            stderr,
                            "helper: dependency prepare is unavailable on this host: {}",
                            e.message()
                        );
                        Box::new(UnavailablePrepareHandler)
                    }
                };
            Some(handler)
        },
        // `newPresentInitHandler` — the ordinary server's init:
        // the resolved instance's three IDs with no ceremony and no
        // mutation.
        init: Some(Box::new(PresentInitHandler::production())),
        // `browser`/`bootstrap_show` — `main.go`'s managed-browser
        // composition: stored-proof source, chromium launcher, broker
        // presenter, default PAM/TTY, and the bin's PostgreSQL
        // presentation bridge. A composition refusal exits 6 like the
        // policy arm above.
        browser: browser_slot,
        bootstrap_show: bootstrap_show_slot,
        // `newProductionMigrationLaunchHandler` — the physical-TTY
        // confirmer, the broker evidence issuer over the configured
        // socket, and the native CML1 launcher. The reset scope is
        // composition identity, never request input.
        migration: {
            let mut handler = super::migration_launch::MigrationLaunchHandler::new(
                Box::new(confirmer.clone()),
                Box::new(super::migration_launch::BrokerLaunchEvidenceIssuer::new(
                    broker_socket_path(env),
                )),
                Box::new(super::migration_launch::NativeMigrationProcessLauncher::new()),
            );
            handler.set_reset_scope(CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            });
            Some(Box::new(handler) as Box<dyn super::migration_launch::MigrationLauncher>)
        },
        // `newProductionMigrationOutcomeReader` — the broker read
        // proxy the operator's own CLI cannot perform (SC-DEF-41).
        migration_outcome: Some(Box::new(
            super::migration_launch::ProductionMigrationOutcomeReader::new(broker_socket_path(env)),
        )),
        // `newProductionBackupThroughputGateForComposition` — the
        // complete C02 authority chain: PostgreSQL fixture
        // provisioner, MinIO fixture manager, cleanup census,
        // broker throughput authority + launch issuer, native backup
        // process launcher, static binding builder, gate. Upstream
        // fails helper composition when it cannot be built.
        backup_create: {
            let throughput = match crate::helper::backup_throughput::ProductionBackupThroughputGate::new_production_for_composition(&composition, &broker_path) {
                Ok(gate) => gate,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {}", e.message());
                    return 6;
                }
            };
            // `newProductionBackupCreateHandler` — every seam the
            // production handler needs is installed: confirmer, C01/
            // C02 throughput gate, launch issuer, MinIO preparer,
            // fixed repository source, native launcher, attestor,
            // broker reaper + completer.
            Some(Box::new(super::backup::BackupCreateHandler::new(
                Box::new(confirmer.clone()),
                Box::new(throughput),
                Box::new(crate::broker::backup_authority::BackupLaunchIssuer::new(
                    broker_path.clone(),
                )),
                backup_minio,
                Box::new(super::backup::FixedBackupRepositorySource {
                    root: backup_repository_root.clone(),
                    instance_id: composition.instance_id.clone(),
                }),
                Box::new(super::backup::NativeBackupProcessLauncher::new()),
                Box::new(super::backup::DescriptorBackupRepositoryAttestor {
                    profile: central_backup::backup::capacity::default_recovery_profile(),
                }),
                Box::new(
                    crate::broker::backup_authority::BackupAttestationClient::new(
                        broker_path.clone(),
                    ),
                ),
                Box::new(
                    crate::broker::backup_authority::BackupAttestationClient::new(
                        broker_path.clone(),
                    ),
                ),
            )))
        },
        // `newProductionBackupReadHandler` — the fixed descriptor
        // source plus the root-helper-only broker read client and
        // the default recovery profile; every seam real.
        backup_read: Some(Box::new(super::backup::BackupReadHandler::new(
            Box::new(super::backup::FixedBackupRepositorySource {
                root: backup_repository_root.clone(),
                instance_id: composition.instance_id.clone(),
            }),
            Box::new(
                crate::broker::backup_authority::BackupOperatorAuthorityClient::new(
                    broker_path.clone(),
                ),
            ),
            central_backup::backup::capacity::default_recovery_profile(),
        ))),
        // `resolvingRestoreOperationHandler` — the one decorator
        // backs all three operation verbs, upstream-fashion: the
        // helper resolves the transport identity the CLI sent to the
        // single protected operation the barrier reports (resume and
        // abandon) or the single issued-ticket operation (apply,
        // SC-DEF-59), runs the inner handler against that protected
        // identity, and rebinds the transport ID onto the response
        // envelope. The barrier client is the same protected broker
        // socket the issuers already use; the one `Arc` clones into
        // all three slots exactly as `newHelperServer` installs the
        // one decorator.
        restore_abandon: Some(Box::new(resolving.clone())),
        restore_apply: Some(Box::new(resolving.clone())),
        restore_resume: Some(Box::new(resolving)),
        // `newProductionRestoreVerifyHandler` — the non-mutating
        // verify path: the same engine launcher (as its
        // `RestoreVerifyLauncher` face), the repository's own
        // sealed-backup index as the candidate source, and nothing
        // else — no PAM confirmer, no issuer, no abandonment
        // authority.
        restore_verify: Some(Box::new(super::restore::RestoreVerifyHandlerImpl::new(
            Some(Box::new(
                super::restore_launcher::ProductionRestoreVerifyRunner::new(
                    restore_launcher.clone(),
                    Box::new(super::restore_launcher::RepositoryRestoreVerifyCandidates {
                        root: backup_repository_root.clone(),
                        instance_id: composition.instance_id.clone(),
                    }),
                ),
            )),
        ))),
        // `newProductionWipeHandler` — D01 composed from the installed
        // composition, the shared confirmer, the B01 evaluator, and
        // the backup-read surface. The wipe roots derive from the
        // resolved composition (the instances parent is the state
        // root's own parent), with production ownership. The B01
        // evaluator is the shared production resolution — a
        // composition failure inside it is the deny-only
        // `unavailableLifecycleEvaluator` answer, never a fabricated
        // admission.
        wipe: Some(Box::new(super::wipe::WipeHandlerImpl::new(
            Some(Box::new(confirmer.clone())),
            Some(Box::new(helper_advisory_evaluator(
                &composition,
                &broker_path,
                stderr,
            ))),
            Some(Box::new(super::wipe::BackupReaderCheckpointVerifier {
                read: Box::new(super::backup::BackupReadHandler::new(
                    Box::new(super::backup::FixedBackupRepositorySource {
                        root: backup_repository_root.clone(),
                        instance_id: composition.instance_id.clone(),
                    }),
                    Box::new(
                        crate::broker::backup_authority::BackupOperatorAuthorityClient::new(
                            broker_path.clone(),
                        ),
                    ),
                    central_backup::backup::capacity::default_recovery_profile(),
                )),
            })),
            CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            },
            super::wipe::WipeRoots {
                instances_root: std::path::PathBuf::from(&composition.authoritative_state_root)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                protected_parent: crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES.to_owned(),
                runtime_base: "/run/central-infra".to_owned(),
                parent_uid: 0,
                parent_gid: 0,
                instance_uid: central_infra::authority::CENTRAL_RUNTIME_UID,
                instance_gid: central_infra::authority::CENTRAL_RUNTIME_GID,
            },
            super::wipe::production_app_armor_deps(),
        ))),
        // `newProductionExportHandler` — D02. The broker protected dir
        // resolves through the same `resolveProductionBrokerRoot` check
        // upstream runs; a refusal fails the whole composition rather
        // than exporting without the TLS-authority pin.
        export: {
            let broker_root = match crate::broker::daemon::production_broker_root_at(
                &composition,
                crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
                0,
                0,
            ) {
                Ok(root) => root,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {e}");
                    return 6;
                }
            };
            Some(Box::new(super::export::ExportHandlerImpl::new(
                Some(Box::new(confirmer.clone())),
                CeremonyScope {
                    instance_id: "default".to_owned(),
                    target_id: "postgres:central".to_owned(),
                },
                super::export::ExportRoots {
                    instance_id: composition.instance_id.clone(),
                    state_root: composition.authoritative_state_root.clone(),
                    broker_protected_dir: broker_root.to_string_lossy().into_owned(),
                    instances_parent_uid: 0,
                    instances_parent_gid: 0,
                    instance_uid: central_infra::authority::CENTRAL_RUNTIME_UID,
                    instance_gid: central_infra::authority::CENTRAL_RUNTIME_GID,
                    staging_parent: std::path::PathBuf::from(&composition.authoritative_state_root)
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                },
                Some(Box::new(super::export::RepositoryExportSource {
                    root: backup_repository_root.clone(),
                    instance_id: composition.instance_id.clone(),
                    profile: central_backup::backup::capacity::default_recovery_profile(),
                })),
            )) as Box<dyn super::export::ExportHandler>)
        },
        // `newProductionImportHandler` — D03 composed `WithEngine`
        // only: the restore launcher is mandatory upstream
        // (`import: production composition has no restore engine`), and
        // the same `Arc` handle serves apply/resume and import alike.
        import: {
            let broker_root = match crate::broker::daemon::production_broker_root_at(
                &composition,
                crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
                0,
                0,
            ) {
                Ok(root) => root,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {e}");
                    return 6;
                }
            };
            Some(Box::new(super::import::ImportHandlerImpl::with_engine(
                Some(Box::new(confirmer.clone())),
                CeremonyScope {
                    instance_id: "default".to_owned(),
                    target_id: "postgres:central".to_owned(),
                },
                super::import::ImportRoots {
                    instance_id: composition.instance_id.clone(),
                    state_root: composition.authoritative_state_root.clone(),
                    broker_protected_dir: broker_root.to_string_lossy().into_owned(),
                    staging_parent: std::path::PathBuf::from(&composition.authoritative_state_root)
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    instance_uid: central_infra::authority::CENTRAL_RUNTIME_UID,
                    instance_gid: central_infra::authority::CENTRAL_RUNTIME_GID,
                    parent_uid: 0,
                    parent_gid: 0,
                },
                Some(Box::new(
                    super::restore_launcher::SharedRestoreEngineLauncher(restore_launcher.clone()),
                )),
            )) as Box<dyn super::import::ImportHandler>)
        },
        // `newProductionDeleteHandler` — D04 delete. The backup source
        // and reference checker are unavailable until the
        // repository-delete and PG plumbing land — upstream's own
        // `unavailableDeleteSource`/`unavailableDeleteRefs` stand-ins.
        // The shared B01 evaluator runs first: a non-`current` verdict
        // (or an uncomposed evaluator) refuses `DELETE_DENIED_SIGNED`
        // before any ceremony; the unavailable seams refuse
        // `DELETE_UNAVAILABLE` only after a signed admission.
        delete: Some(Box::new(super::delete::DeleteHandlerImpl::new(
            Some(Box::new(confirmer.clone())),
            Some(Box::new(helper_advisory_evaluator(
                &composition,
                &broker_path,
                stderr,
            ))),
            Some(Box::new(super::delete::UnavailableDeleteSource)),
            Some(Box::new(super::delete::UnavailableDeleteRefs)),
            CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            },
            super::delete::DeleteRoots {
                journal_dir: std::path::PathBuf::from(&composition.authoritative_state_root)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                journal_uid: 0,
                journal_gid: 0,
            },
        ))),
        // `newProductionPruneHandler` — D04 prune. The engine (PG
        // inventory + journal as central_migration, MinIO body
        // deletes) is not plumbed yet — upstream's nil engine made
        // explicit: `PRUNE_UNAVAILABLE` on both plan and apply rather
        // than inventing eligibility without PG. The shared B01
        // evaluator gates both actions on a `current` verdict first.
        prune: Some(Box::new(super::prune::PruneHandlerImpl::new(
            Some(Box::new(confirmer.clone())),
            Some(Box::new(helper_advisory_evaluator(
                &composition,
                &broker_path,
                stderr,
            ))),
            None,
            CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            },
        ))),
        // `newProductionSecurityUpdateHandler` — B01's write path:
        // `install_active_bundle` installs the operator's signed
        // envelope beneath the authoritative state root, bound to the
        // instance id. `newHelperConfirmer` fails composition on a
        // mis-provisioned ceremony mode, upstream-exact.
        security_update: Some(super::security_update::SecurityUpdateHandler {
            pam: Some(Box::new(confirmer.clone())),
            install: Some(Box::new(|root, binding, envelope| {
                crate::infra::advisory_fetch::install_active_bundle(root, binding, envelope)
            })),
            root_path: composition.authoritative_state_root.clone(),
            binding_id: composition.instance_id.clone(),
        }),
        // `newProductionAuditHandler` — D05: the B01 evaluator, the
        // D01 wipe ceremony scope (repair runs under it), and the
        // broker protected root as the audited hierarchy. The deny-safe
        // record lives in that same root, hashed like every protected
        // file.
        audit: {
            let broker_root = match crate::broker::daemon::production_broker_root_at(
                &composition,
                crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
                0,
                0,
            ) {
                Ok(root) => root,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {e}");
                    return 6;
                }
            };
            Some(Box::new(super::audit::AuditHandlerImpl {
                pam: Some(Box::new(confirmer.clone())),
                advisory: Some(Box::new(helper_advisory_evaluator(
                    &composition,
                    &broker_path,
                    stderr,
                ))),
                scope: CeremonyScope {
                    instance_id: "default".to_owned(),
                    target_id: "postgres:central".to_owned(),
                },
                roots: super::audit::Roots {
                    protected_dir: broker_root.to_string_lossy().into_owned(),
                    audit_dir: broker_root.join("audit").to_string_lossy().into_owned(),
                    instance_id: composition.instance_id.clone(),
                    audit_uid: 0,
                    audit_gid: 0,
                },
            }) as Box<dyn super::audit::AuditHandler>)
        },
        // `newProductionRescueHandler` — D06: the B01 evaluator
        // (installed verdicts are branches, never gates), the
        // candidate evaluator over the same facts/witness/trust minus
        // the recorder, and the lifecycle-down cleanup — the same
        // composed `lifecycle` handler, invoked for a second ceremony
        // (upstream passes `lifecycle` into the rescue handler). The
        // deny-safe record sits in the broker protected root — the
        // same dir the transport gate arms on below.
        rescue: {
            let broker_root = match crate::broker::daemon::production_broker_root_at(
                &composition,
                crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
                0,
                0,
            ) {
                Ok(root) => root,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {e}");
                    return 6;
                }
            };
            let witness = match crate::infra::advisory_fetch::TimeWitnessStore::new(
                &composition.authoritative_state_root,
            ) {
                Ok(w) => w,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {}", e.message());
                    return 6;
                }
            };
            Some(Box::new(super::rescue::RescueHandlerImpl {
                pam: Some(Box::new(confirmer.clone())),
                installed: Some(Box::new(helper_advisory_evaluator(
                    &composition,
                    &broker_path,
                    stderr,
                ))),
                candidate: Some(Box::new(ProductionCandidateEvaluator {
                    facts: crate::infra::advisory_fetch::HostFactsCollector::new(),
                    witness,
                    verifier: central_infra::advisory::Verifier::production(),
                })),
                cleanup: Some(Box::new(LifecycleDownRescueCleanup {
                    lifecycle: Arc::clone(&lifecycle_handler),
                })),
                store: Some(crate::infra::advisory_fetch::FileDenySafeStore::new(
                    &broker_root,
                    0,
                    0,
                )),
                scope: CeremonyScope {
                    instance_id: "default".to_owned(),
                    target_id: "postgres:central".to_owned(),
                },
                roots: super::rescue::RescueRoots {
                    deny_safe_dir: broker_root.to_string_lossy().into_owned(),
                    deny_safe_uid: 0,
                    deny_safe_gid: 0,
                },
            }) as Box<dyn super::rescue::RescueHandler>)
        },
        // `newProductionMaintenanceHandler` — E01: the protected
        // matrix store and the host-facts probes. A missing probe
        // leaves the dependency "unprobed" — reported, never
        // fabricated.
        maintenance: {
            let broker_root = match crate::broker::daemon::production_broker_root_at(
                &composition,
                crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
                0,
                0,
            ) {
                Ok(root) => root,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {e}");
                    return 6;
                }
            };
            Some(Box::new(super::maintenance::MaintenanceHandlerImpl {
                store: Some(central_infra::maintenance::new_store(&broker_root)),
                probes: maintenance_probes(true),
            })
                as Box<dyn super::maintenance::MaintenanceHandler>)
        },
        // `newProductionMaintenanceApplyHandler` — E02/E03: the same
        // store and probes, the ceremony confirmer, and the image
        // probe that asks the local docker daemon whether a digest
        // resolves. The gate observes; it never pulls.
        maintenance_apply: {
            let broker_root = match crate::broker::daemon::production_broker_root_at(
                &composition,
                crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
                0,
                0,
            ) {
                Ok(root) => root,
                Err(e) => {
                    let _ = writeln!(stderr, "helper: composition: {e}");
                    return 6;
                }
            };
            Some(Box::new(super::maintenance::MaintenanceApplyHandlerImpl {
                store: Some(central_infra::maintenance::new_store(&broker_root)),
                probes: maintenance_probes(false),
                images: Some(Box::new(maintenance_image_probe)),
                pam: Some(Box::new(confirmer.clone())),
                scope: CeremonyScope {
                    instance_id: "default".to_owned(),
                    target_id: "postgres:central".to_owned(),
                },
            })
                as Box<dyn super::maintenance::MaintenanceApplyHandler>)
        },
        // `denySafeDirForComposition` — the same broker protected dir
        // the rescue handler records to. Resolution failure disables
        // the gate (empty dir) rather than guessing a path — but the
        // rescue handler itself refused to compose in that case, so a
        // running helper never serves rescue without its gate armed on
        // the same dir.
        deny_safe_dir: crate::broker::daemon::production_broker_root_at(
            &composition,
            crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
            0,
            0,
        )
        .ok()
        .map(|root| root.to_string_lossy().into_owned()),
        // `newHelperLifecycleHandler` — the complete broker-backed
        // lifecycle chain: ADR 0020's version-zero dependency receipt,
        // the read-only B02 candidate store, the shared B01 evaluator,
        // the typed B04 broker client (authorization, dead-owner
        // verification, the SCM_RIGHTS custody path), the ADR 0019
        // postgres credential stores, the production service over the
        // service-role-decorated runner, the first-boot-decorated
        // bootstrap, and the broker rendezvous — sealed by the
        // per-request active-receipt resolver and the authorized
        // handler bound to the shared confirmer. Composed once above
        // and shared with the rescue cleanup; a composition refusal
        // already exited 6 before this literal — the daemon never
        // serves a half seam.
        lifecycle: Some(lifecycle_handler),
        ..Server::new()
    });
    // `runHelperRestoreCapacityReserveStartupSweep` — the sweep's
    // first named call site: this daemon's own startup reconciliation
    // pass. It is the pass that recovers from a crash — a host that
    // came back up holding reserve objects nothing claims frees them
    // here, before any new restore attempt is admitted — and it
    // publishes the bucketed inspection digest the hardened broker
    // serves on frame `0xc5`. It runs after composition and before
    // `serve`, and its failure is reported rather than fatal:
    // refusing to start the helper because a housekeeping pass failed
    // would take away the operator's only path to a recovery.
    run_restore_capacity_startup_sweep(&composition, stderr);
    if let Err(e) = serve(listen, &srv, IDLE_TIMEOUT, cancel) {
        let _ = writeln!(stderr, "helper: {e}");
        return 3;
    }
    0
}

/// `runHelperRestoreCapacityReserveStartupSweep` —
/// [`SweepCaller::HelperStartup`]'s whole call site. It resolves the
/// same protected root every other helper capability resolves, builds
/// the narrow reserve view over it — never a whole broker `Service`
/// (see [`ReserveHelperAuthority`]) — runs one reconciliation pass,
/// and publishes its findings.
///
/// Every failure is reported to the journal and swallowed: neither a
/// failed sweep nor a failed publish is a reason to refuse a
/// recovery, and a disaster-recovery tool that will not run because
/// its housekeeping pass failed is the failure mode this whole plan
/// exists to avoid. The message carries the call site and the
/// failure's own sanitized text, never a pathname.
fn run_restore_capacity_startup_sweep(
    composition: &crate::broker::daemon::ProductionInstanceComposition,
    stderr: &mut dyn Write,
) {
    const SITE: &str = "helper-startup";
    let root = match crate::broker::daemon::production_broker_root_at(
        composition,
        crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
        0,
        0,
    ) {
        Ok(root) => root,
        Err(e) => {
            report_sweep_failure(SITE, e, stderr);
            return;
        }
    };
    let authority = match crate::broker::restore_capacity::helper::ReserveHelperAuthority::new(
        &root,
        composition.role_roots.clone(),
        crate::broker::restore_capacity::sweep::SweepCaller::HelperStartup,
    ) {
        Ok(authority) => authority,
        Err(e) => {
            report_sweep_failure(SITE, e.message(), stderr);
            return;
        }
    };
    if let Err((_, e)) = authority.sweep_and_publish(time::OffsetDateTime::now_utc()) {
        report_sweep_failure(SITE, e.message(), stderr);
    }
}

// ---------------------------------------------------------------------------
// R6-13 composition helpers — `cmd/central`'s *_helper_composition.go
// adapters.
// ---------------------------------------------------------------------------

/// `helperCeremonyInstanceID`/`helperCeremonyTargetID` are already
/// bound into the `CeremonyScope` literals above — this is the shared
/// confirmer constructor upstream calls `newHelperConfirmer`.
///
/// `newHelperConfirmer` — whichever ceremony mode the instance has
/// installed. `physical_tty` (the default, and what an instance
/// without a mode file gets) is exactly the ADR 0023 confirmer. Grant
/// mode opens the instance's grant store and refuses to compose at
/// all if it is missing or mis-owned: a helper that silently fell
/// back to the console when its grant store was absent would hang
/// every unattended run at a prompt nobody is watching.
fn helper_confirmer(
    composition: &crate::broker::daemon::ProductionInstanceComposition,
) -> Result<PamConfirmer, String> {
    if composition.authoritative_state_root.is_empty() {
        return Err("ceremony: instance composition names no state root".to_owned());
    }
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    match super::grant::read_ceremony_mode(&composition.authoritative_state_root, uid, gid)
        .map_err(|e| format!("ceremony: {}", e.message()))?
    {
        super::grant::CeremonyMode::PhysicalTty => Ok(PamConfirmer::new()),
        super::grant::CeremonyMode::Grant => {
            let store_dir =
                std::path::Path::new(&composition.authoritative_state_root).join("grants");
            let store = super::grant::GrantStore::open(&store_dir.to_string_lossy(), uid, gid)
                .map_err(|e| format!("ceremony: {}", e.message()))?;
            Ok(PamConfirmer::with_grants(
                store,
                "default",
                "postgres:central",
            ))
        }
    }
}

/// The concrete `app.Service` shape `newProductionAdvisoryEvaluator`
/// composes — `deny_safe` stays `None` exactly as upstream's helper
/// evaluator carries no `DenySafeDir` (the serve path's evaluator owns
/// deny-safe entry; the helper only reads installed verdicts).
type HelperEvaluationService = central_infra::advisory::EvaluationService<
    crate::infra::advisory_fetch::ActiveBundleSource,
    crate::infra::advisory_fetch::HostFactsCollector,
    crate::infra::advisory_fetch::SystemAdvisoryClock,
    crate::infra::advisory_fetch::TimeWitnessStore,
    crate::infra::advisory_fetch::AdvisoryTransitionRecorder<
        crate::infra::advisory_fetch::AdvisoryEvaluationJournalClient,
    >,
    crate::infra::advisory_fetch::FileDenySafeStore,
>;

/// `HelperAdvisoryEvaluator` — `newHelperAdvisoryEvaluator` over the
/// helper's narrow seams: `None` is upstream's
/// `unavailableLifecycleEvaluator` fallback (a production evaluator
/// that fails to compose — most often a fresh instance whose state
/// root does not exist yet — falls back deny-only rather than taking
/// the whole helper down).
struct HelperAdvisoryEvaluator {
    service: Option<HelperEvaluationService>,
}

impl HelperAdvisoryEvaluator {
    /// `Service.Evaluate` — upstream's `(Result, Admission, error)`
    /// triple: the verdict plus the journaled admission the destructive
    /// and prepare seams carry through. `service: None` is upstream's
    /// `unavailableLifecycleEvaluator{}` refusal verbatim — a `Denied`
    /// answer, never a fabricated admission.
    fn evaluate_pair(
        &self,
    ) -> Result<
        (
            central_infra::advisory::Outcome,
            central_infra::advisory::Admission,
        ),
        central_foundation::failure::Failure,
    > {
        let Some(service) = &self.service else {
            return Err(central_foundation::failure::Failure::unavailable(
                "advisory_evaluator_unavailable",
                "B01 lifecycle admission evaluator is unavailable",
            ));
        };
        crate::infra::lifecycle::block_on(service.evaluate()).map_err(|e| e.source)
    }

    /// The installed advisory's verdict, or the evaluator's own
    /// failure — both surfaces upstream's `(Result, error)` return.
    fn outcome(
        &self,
    ) -> Result<central_infra::advisory::Outcome, central_foundation::failure::Failure> {
        self.evaluate_pair().map(|(outcome, _)| outcome)
    }

    /// The narrowed `(AdvisoryResult, AdvisoryAdmission)` pair every
    /// non-lifecycle consumer takes — upstream's helper interfaces all
    /// reduce `Service.Evaluate` to these two strings plus the receipt
    /// id.
    fn narrowed(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        central_foundation::failure::Failure,
    > {
        let (outcome, admission) = self.evaluate_pair()?;
        Ok((
            super::prepare::AdvisoryResult {
                state: outcome.state.as_str().to_owned(),
                code: outcome.code.as_str().to_owned(),
            },
            super::prepare::AdvisoryAdmission {
                receipt_id: admission.receipt_id().to_owned(),
            },
        ))
    }
}

impl crate::infra::lifecycle::AdvisoryEvaluator for HelperAdvisoryEvaluator {
    /// The lifecycle handler's B01 boundary — the same one resolution
    /// upstream hands `NewProductionService`, composed into
    /// `helper_lifecycle_handler` above.
    fn evaluate(
        &self,
    ) -> Result<
        (
            central_infra::advisory::Outcome,
            central_infra::advisory::Admission,
        ),
        central_foundation::failure::Failure,
    > {
        self.evaluate_pair()
    }
}

impl super::prepare::EvaluateService for HelperAdvisoryEvaluator {
    /// The dependency-prepare evaluator seam — upstream hands the same
    /// helper evaluator to `NewPrepareHandlerWithPAM`.
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        central_foundation::failure::Failure,
    > {
        self.narrowed()
    }
}

impl super::wipe::WipeAdvisoryEvaluator for HelperAdvisoryEvaluator {
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        central_foundation::failure::Failure,
    > {
        self.narrowed()
    }
}

impl super::delete::DeleteAdvisoryEvaluator for HelperAdvisoryEvaluator {
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        central_foundation::failure::Failure,
    > {
        self.narrowed()
    }
}

impl super::prune::PruneAdvisoryEvaluator for HelperAdvisoryEvaluator {
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        central_foundation::failure::Failure,
    > {
        self.narrowed()
    }
}

impl super::rescue::RescueAdvisoryEvaluator for HelperAdvisoryEvaluator {
    fn evaluate(
        &self,
    ) -> Result<central_infra::advisory::Outcome, central_foundation::failure::Failure> {
        self.outcome()
    }
}

impl super::audit::AuditAdvisoryEvaluator for HelperAdvisoryEvaluator {
    fn evaluate(
        &self,
    ) -> Result<super::audit::AdvisoryVerdict, central_foundation::failure::Failure> {
        Ok(match self.outcome()?.state {
            central_infra::advisory::State::Current => super::audit::AdvisoryVerdict::Current,
            _ => super::audit::AdvisoryVerdict::NotCurrent,
        })
    }
}

/// `newHelperAdvisoryEvaluator` — the one B01 evaluator this helper
/// process admits work with; lifecycle, prepare, wipe, delete, prune,
/// audit, and rescue all take it from here rather than each resolving
/// their own: a second resolution is a second place for a deny-only
/// default to be swapped for something more permissive, and prepare's
/// promotion gate re-runs exactly the evaluation that admitted the
/// request.
///
/// There is no development-admission path in this slice — this always
/// composes the real production evaluator
/// (`newProductionAdvisoryEvaluator`, upstream's post-
/// `CENTRAL_DEVELOPMENT_LOCAL_ONLY` arm). A
/// production evaluator that fails to compose — most often a fresh
/// instance whose authoritative state root does not exist yet — falls
/// back to the deny-only `None` arm rather than taking the whole
/// helper down with it: every other verb (lifecycle status, backup,
/// restore) has nothing to do with B01, the same reasoning
/// `newProductionPrepareHandlerWithConfirmer`'s
/// `unavailablePrepareHandler` precedent already established.
fn helper_advisory_evaluator(
    composition: &crate::broker::daemon::ProductionInstanceComposition,
    broker_path: &std::path::Path,
    stderr: &mut dyn Write,
) -> HelperAdvisoryEvaluator {
    if composition.authoritative_state_root.is_empty() || composition.instance_id.is_empty() {
        return HelperAdvisoryEvaluator { service: None };
    }
    let service = (|| -> Result<_, String> {
        let source = crate::infra::advisory_fetch::ActiveBundleSource::new(
            &composition.authoritative_state_root,
            &composition.instance_id,
        )
        .map_err(|e| e.message().to_string())?;
        let witness = crate::infra::advisory_fetch::TimeWitnessStore::new(
            &composition.authoritative_state_root,
        )
        .map_err(|e| e.message().to_string())?;
        let journal = crate::infra::advisory_fetch::AdvisoryEvaluationJournalClient::new(
            broker_path.to_path_buf(),
        );
        Ok(HelperEvaluationService {
            source,
            facts: crate::infra::advisory_fetch::HostFactsCollector::new(),
            clock: crate::infra::advisory_fetch::SystemAdvisoryClock,
            witness,
            recorder: crate::infra::advisory_fetch::AdvisoryTransitionRecorder::new(journal),
            verifier: central_infra::advisory::Verifier::production(),
            deny_safe: None,
        })
    })();
    match service {
        Ok(service) => HelperAdvisoryEvaluator {
            service: Some(service),
        },
        Err(e) => {
            // Upstream main.go logs the composition error and falls
            // back deny-only; the evaluator still answers, it just
            // never admits.
            let _ = writeln!(
                stderr,
                "helper: B01 advisory evaluator is unavailable on this host: {e}"
            );
            HelperAdvisoryEvaluator { service: None }
        }
    }
}

/// `newHelperLifecycleHandler` — the complete B03 chain in upstream's
/// order: ADR 0020's version-zero dependency receipt before any
/// receipt read can resolve one, the read-only candidate store
/// (`NewCandidateStore(nil, dependencyRoot)`), the shared B01
/// evaluator, the typed broker lifecycle client, the ADR 0019
/// postgres credential stores, the production service over the
/// service-role-decorated runner and the first-boot-decorated
/// bootstrap with the broker rendezvous, the per-request
/// active-receipt resolver, and the authorized handler bound to the
/// shared confirmer. A composition refusal is the daemon's exit 6,
/// exactly like upstream's `return nil, err` at the call site.
fn helper_lifecycle_handler(
    composition: &crate::broker::daemon::ProductionInstanceComposition,
    broker_path: &std::path::Path,
    confirmer: PamConfirmer,
    stderr: &mut dyn Write,
) -> Result<super::lifecycle::ProductionLifecycleHandler, String> {
    // `cmd`'s pinned literals: the host's docker binary, and
    // `ProductionServiceConfig.RuntimeRoot` = `/run/central-infra` —
    // the generic runtime root `Topology` joins the instance id onto
    // itself (SC-DEF-32); the composition's already-scoped runtime
    // root would double-append it.
    const DOCKER_BINARY_PATH: &str = "/usr/bin/docker";
    const CENTRAL_INFRA_ROOT: &str = "/run/central-infra";
    let dependency_root = std::path::PathBuf::from(&composition.dependency_root);
    let lifecycle_root = std::path::PathBuf::from(&composition.lifecycle_root);
    // ADR 0020: first-write-only, and it refuses to repair a corrupt
    // existing selector — a broken dependency store fails the daemon,
    // it never gets repaired behind the operator's back.
    crate::infra::prepare::ensure_version_zero_receipt(
        crate::infra::prepare::OpDeadline::NONE,
        &dependency_root,
    )
    .map_err(|e| format!("version-zero dependency receipt: {}", e.message()))?;
    let receipts: Arc<dyn crate::infra::lifecycle::ActiveReceiptReader> = Arc::new(
        crate::infra::prepare::CandidateStore::new(None, &dependency_root),
    );
    let evaluator = helper_advisory_evaluator(composition, broker_path, stderr);
    let broker_client = Arc::new(crate::broker::lifecycle_client::LifecycleClient::new(
        broker_path.to_path_buf(),
    ));
    // ADR 0019: the superuser store first — the service-role store's
    // `ALTER ROLE` calls authenticate with whatever password it
    // currently has live.
    let superuser = Arc::new(
        super::pg_credentials::ProductionPostgresSuperuserCredentialStore::new_production(
            composition,
        )
        .map_err(|e| format!("postgres superuser credential store: {}", e.message()))?,
    );
    let roles: Option<Arc<dyn super::lifecycle_compose::PostgresServiceRoleSync>> = Some(Arc::new(
        super::pg_credentials::ProductionPostgresServiceRoleCredentialStore::new_production(
            composition,
            superuser.clone(),
            broker_client.clone(),
        )
        .map_err(|e| format!("postgres service role credential store: {}", e.message()))?,
    ));
    let clock: Arc<dyn central_infra::port::LifecycleClock> =
        Arc::new(crate::infra::lifecycle::SystemClock);
    let runner: Arc<dyn crate::infra::compose::ComposeRunner> = Arc::new(
        super::lifecycle_compose::PostgresServiceRoleComposeRunner::new(
            Arc::new(crate::infra::compose::CommandComposeRunner::new(
                DOCKER_BINARY_PATH,
                None,
                None,
            )),
            roles,
        ),
    );
    let bootstrap = Arc::new(super::lifecycle_compose::PostgresFirstBootBootstrap::new(
        Arc::new(crate::infra::lifecycle::FileBootstrap::new(
            lifecycle_root.join("bootstrap"),
            clock.clone(),
            broker_client.clone(),
        )),
        superuser.clone(),
    ));
    let service = crate::infra::lifecycle::new_production_service(
        crate::infra::lifecycle::ProductionServiceConfig {
            evaluator: Arc::new(evaluator),
            receipts: receipts.clone(),
            inspector: Arc::new(crate::infra::lifecycle::DockerReceiptInspector::new(
                DOCKER_BINARY_PATH,
                None,
            )),
            runner,
            journal_root: lifecycle_root,
            runtime_root: std::path::PathBuf::from(CENTRAL_INFRA_ROOT),
            capacity_root: std::path::PathBuf::from(&composition.authoritative_state_root),
            lock_lifetime: None,
            clock,
            owner_verifier: broker_client.clone(),
            bootstrap: Some(bootstrap),
            b04_bootstrap: broker_client.clone(),
            rendezvous: Arc::new(super::lifecycle_compose::LifecycleBrokerRendezvous::new(
                &broker_path.to_string_lossy(),
            )),
        },
    )
    .map_err(|e| format!("helper lifecycle service: {}", e.message()))?;
    // Upstream's `resolve` closure: the binding the bridge stamps is
    // upstream's helper-level `infralifecycle.Binding` — the resolver
    // fills every request field the request itself may name, so the
    // composed binding carries only what the helper never exposes.
    let bridge = crate::infra::lifecycle::LifecycleApplicationBridge::new(
        service,
        central_infra::domain::LifecycleBinding::default(),
    );
    let resolver = crate::infra::lifecycle::ProductionRequestResolver::new(
        receipts,
        &composition.instance_id,
        &composition.config_binding,
    );
    Ok(
        super::lifecycle::ProductionLifecycleHandler::new_authorized(
            Box::new(bridge),
            Box::new(resolver),
            Box::new(crate::broker::lifecycle_client::LifecycleClient::new(
                broker_path.to_path_buf(),
            )),
            Box::new(confirmer),
        ),
    )
}

/// `productionCandidateEvaluator` — runs B01 over operator-carried
/// candidate bytes with the installed evaluator's own facts, witness,
/// and release trust — minus the recorder: candidate evaluation
/// records nothing and advances nothing. The deny-safe attempt record
/// is where the outcome lands.
struct ProductionCandidateEvaluator {
    facts: crate::infra::advisory_fetch::HostFactsCollector,
    witness: crate::infra::advisory_fetch::TimeWitnessStore,
    verifier: central_infra::advisory::Verifier,
}

impl super::rescue::RescueCandidateEvaluator for ProductionCandidateEvaluator {
    fn evaluate_candidate(
        &self,
        candidate: &[u8],
    ) -> Result<central_infra::advisory::Outcome, central_foundation::failure::Failure> {
        Ok(central_infra::advisory::evaluate_candidate(
            &self.verifier,
            &self.facts,
            &self.witness,
            time::OffsetDateTime::now_utc(),
            candidate,
        )
        .1)
    }
}

/// `lifecycleDownCleanup` — the deny-safe cleanup delegates to the
/// composed lifecycle handler with verb `down`: the rescue ceremony is
/// followed by a second, full lifecycle-down ceremony — peer
/// availability, PAM/grant confirmation, bound broker
/// authorization/consume, lifecycle journaling, lock custody, and
/// stopped-topology verification all run, D01's precedent (upstream
/// `Cleanup` calls `lifecycle.HandleLifecycle` on the same instance
/// the `lifecycle` verb serves, never a bare compose down). The
/// caller's own peer/deadline carry through, the operation id is a
/// freshly minted uuidv7, and `config_binding` stays empty exactly as
/// upstream's `helper.LifecycleRequest{}`. Idempotent by
/// construction: `down` on a stopped project is a no-op.
struct LifecycleDownRescueCleanup {
    lifecycle: Arc<dyn super::lifecycle::LifecycleHandler>,
}

impl super::rescue::RescueCleanup for LifecycleDownRescueCleanup {
    /// `Cleanup` — `HandleLifecycle(ctx, Request{uuidv7, "down"},
    /// LifecycleRequest{})`: any non-success outcome or nonzero exit
    /// is `rescue: lifecycle down failed: <reason>`, upstream
    /// verbatim.
    fn cleanup(
        &self,
        peer: super::PeerIdentity,
        deadline: std::time::Instant,
    ) -> Result<(), central_foundation::failure::Failure> {
        let request = super::protocol::Request {
            operation_id: uuid::Uuid::now_v7().to_string(),
            verb: super::verb::DOWN.to_owned(),
            payload: None,
        };
        let resp = self.lifecycle.handle_lifecycle(
            peer,
            deadline,
            &request,
            super::protocol::LifecycleRequest::default(),
        );
        if resp.outcome != "success" || resp.exit_code != 0 {
            return Err(central_foundation::failure::Failure::unavailable(
                "rescue_cleanup",
                format!("rescue: lifecycle down failed: {}", resp.reason),
            ));
        }
        Ok(())
    }
}

/// `maintenanceProbes` — the four host-facts probes upstream installs:
/// the toolchain is the running binary's own language toolchain (the
/// rustc version observed on the host, the Rust port's equivalent of
/// `runtime.Version()`); the docker/compose/psql probes share the
/// advisory host-facts collector. `shared` is upstream's `factsOnce`
/// distinction: the plan handler caches one collect across the three
/// probes; apply collects per probe call.
fn maintenance_probes(shared: bool) -> super::maintenance::MaintenanceProbes {
    let collector = std::sync::Arc::new(crate::infra::advisory_fetch::HostFactsCollector::new());
    let cache: std::sync::Arc<std::sync::Mutex<Option<central_infra::advisory::HostFacts>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let facts = move || -> central_infra::advisory::HostFacts {
        if shared {
            let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(f) = &*guard {
                return f.clone();
            }
            let f = collector.collect_facts();
            *guard = Some(f.clone());
            f
        } else {
            collector.collect_facts()
        }
    };
    let facts = std::sync::Arc::new(facts);
    let mut probes: super::maintenance::MaintenanceProbes = std::collections::BTreeMap::new();
    probes.insert(
        "go-toolchain".to_owned(),
        Box::new(|| {
            // The Rust port's `runtime.Version()` equivalent: the
            // installed rustc, reported as `x.y.z`.
            let out = std::process::Command::new("rustc")
                .arg("--version")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .output()
                .map_err(|e| {
                    central_foundation::failure::Failure::unavailable(
                        "maintenance_probe",
                        format!("rustc probe: {e}"),
                    )
                })?;
            if !out.status.success() {
                return Err(central_foundation::failure::Failure::unavailable(
                    "maintenance_probe",
                    "rustc probe failed",
                ));
            }
            let text = String::from_utf8_lossy(&out.stdout);
            let version = text
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            if version.is_empty() {
                return Err(central_foundation::failure::Failure::unavailable(
                    "maintenance_probe",
                    "rustc probe reported nothing",
                ));
            }
            Ok(version)
        }),
    );
    for (name, pick) in [
        ("postgresql", "psql"),
        ("docker-engine", "docker"),
        ("docker-compose", "compose"),
    ] {
        let facts = facts.clone();
        probes.insert(
            name.to_owned(),
            Box::new(move || {
                let f = facts();
                let v = match pick {
                    "psql" => f.psql,
                    "docker" => f.docker,
                    _ => f.compose,
                };
                if v.is_empty() {
                    return Err(central_foundation::failure::Failure::unavailable(
                        "maintenance_probe",
                        format!("{name} probe reported nothing"),
                    ));
                }
                Ok(v)
            }),
        );
    }
    probes
}

/// `maintenanceImageProbe` — `docker image inspect <digest>` bounded
/// to fifteen seconds. It resolves a digest already present on the
/// host; it never pulls. A non-zero exit means not present.
fn maintenance_image_probe(digest: &str) -> Result<bool, central_foundation::failure::Failure> {
    let mut cmd = std::process::Command::new("/usr/bin/docker");
    cmd.arg("image")
        .arg("inspect")
        .arg(digest)
        .env_clear()
        .envs(
            crate::infra::compose::closed_docker_environment()
                .iter()
                .filter_map(|kv| kv.split_once('=')),
        );
    let out = crate::infra::compose::run_compose_bounded(
        crate::infra::prepare::OpDeadline::after(std::time::Duration::from_secs(15)),
        &mut cmd,
        None,
    )
    .map_err(|e| {
        central_foundation::failure::Failure::unavailable(
            "maintenance_image_probe",
            format!("image probe: {e}"),
        )
    })?;
    Ok(out.status.success())
}

/// `reportRestoreCapacityReserveSweepFailure` — the one place a sweep
/// or publish failure is surfaced.
fn report_sweep_failure(site: &str, err: &str, stderr: &mut dyn Write) {
    let _ = writeln!(
        stderr,
        "central: restore capacity reserve sweep ({site}): {err}"
    );
}

/// `signal.NotifyContext(SIGINT, SIGTERM)` — an eventfd that becomes
/// readable when either signal arrives, via a current-thread tokio
/// runtime on a spawned waiter (tokio is the workspace's signal
/// owner). The write end is a duplicated descriptor so the waiter may
/// outlive the server's return path without keeping it alive.
fn cancel_on_signal() -> Result<(OwnedFd, std::thread::JoinHandle<()>), String> {
    let efd = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
        .map_err(|e| format!("helper: cancel fd: {e}"))?;
    let writer = efd
        .try_clone()
        .map_err(|e| format!("helper: cancel fd: {e}"))?;
    let waiter = std::thread::Builder::new()
        .name("helper-signal".to_owned())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async {
                let mut int =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                let mut term =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                tokio::select! {
                    _ = int.recv() => {}
                    _ = term.recv() => {}
                }
            });
            let _ = rustix::io::write(&writer, &1u64.to_ne_bytes());
        })
        .map_err(|e| format!("helper: cancel waiter: {e}"))?;
    Ok((efd, waiter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    /// `helperPeerPolicyFromEnvironment` — unset, malformed, and zero
    /// collapse to the two provisioned-policy messages; `+1` parses
    /// like upstream `ParseUint`.
    #[test]
    fn peer_policy_from_env() {
        let empty = env_of(&[]);
        assert_eq!(
            helper_peer_policy_from_env(&empty).unwrap_err(),
            "operator UID policy is not provisioned"
        );
        for bad in ["", "abc", "-1", " 1", "0", "4294967296"] {
            let env = env_of(&[("CENTRAL_OPERATOR_UID", bad), ("CENTRAL_OPERATOR_GID", "1")]);
            assert_eq!(
                helper_peer_policy_from_env(&env).unwrap_err(),
                "operator UID policy is not provisioned",
                "{bad:?}"
            );
        }
        let no_gid = env_of(&[("CENTRAL_OPERATOR_UID", "1000")]);
        assert_eq!(
            helper_peer_policy_from_env(&no_gid).unwrap_err(),
            "operator GID policy is not provisioned"
        );
        let env = env_of(&[
            ("CENTRAL_OPERATOR_UID", "+1000"),
            ("CENTRAL_OPERATOR_GID", "1001"),
        ]);
        let (peer, socket) = helper_peer_policy_from_env(&env).unwrap();
        assert_eq!(peer.daemon_uid, 0);
        assert_eq!(peer.operator_uid, 1000);
        assert_eq!(peer.operator_gid, 1001);
        assert_eq!(socket.path, PRODUCTION_SOCKET_PATH);
        assert_eq!(socket.owner_uid, 0);
        assert_eq!(socket.group_gid, 1001);
        assert_eq!(socket.mode & 0o777, 0o660);
    }

    /// The env socket override wins; the production path is the default.
    #[test]
    fn socket_path_env_override() {
        let env = env_of(&[("CENTRAL_HELPER_SOCKET", "/run/test/helper.sock")]);
        assert_eq!(helper_socket_path(&env), "/run/test/helper.sock");
        let env = env_of(&[("CENTRAL_HELPER_SOCKET", "")]);
        assert_eq!(helper_socket_path(&env), PRODUCTION_SOCKET_PATH);
    }

    /// `runHelperDaemon`'s own LISTEN_FDS check: unset, malformed, and
    /// zero each print upstream's `no socket fd` line and exit 3 —
    /// before any composition is attempted.
    #[test]
    fn missing_listen_fds_exits_3() {
        for raw in ["", "abc", "0", "-1"] {
            let env = env_of(&[("LISTEN_FDS", raw)]);
            let mut stderr = Vec::new();
            assert_eq!(
                run_helper_daemon(true, &env, HelperRuntimeDeps::absent(), &mut stderr),
                3,
                "{raw:?}"
            );
            assert_eq!(
                String::from_utf8(stderr).unwrap(),
                format!("helper: no socket fd (LISTEN_FDS={raw:?})\n")
            );
        }
        // With LISTEN_FDS present but no operator ids: composition
        // fails at 6 on the right branch name.
        let env = env_of(&[("LISTEN_FDS", "1")]);
        let mut stderr = Vec::new();
        assert_eq!(
            run_helper_daemon(true, &env, HelperRuntimeDeps::absent(), &mut stderr),
            6
        );
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: genesis composition: operator UID policy is not provisioned\n"
        );
        let env = env_of(&[("LISTEN_FDS", "1")]);
        let mut stderr = Vec::new();
        assert_eq!(
            run_helper_daemon(false, &env, HelperRuntimeDeps::absent(), &mut stderr),
            6
        );
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: composition: operator UID policy is not provisioned\n"
        );
    }

    /// `newHelperAdvisoryEvaluator`'s fallback arm: an instance
    /// composition without a state root/instance id yields the
    /// deny-only evaluator — every narrow trait impl surfaces
    /// upstream's `unavailableLifecycleEvaluator` refusal rather than
    /// a fabricated admission. A host that cannot compose the
    /// evaluator still serves every other verb.
    #[test]
    fn advisory_evaluator_falls_back_deny_only() {
        let empty = crate::broker::daemon::ProductionInstanceComposition {
            instance_id: String::new(),
            config_binding: String::new(),
            authoritative_state_root: String::new(),
            dependency_root: String::new(),
            lifecycle_root: String::new(),
            role_roots: Default::default(),
            backup_repository_root: String::new(),
            compose_path: String::new(),
            object_store_bucket: String::new(),
            backup_policy_digest: String::new(),
            restore_policy_digest: String::new(),
            import_policy_digest: String::new(),
        };
        let evaluator = helper_advisory_evaluator(
            &empty,
            std::path::Path::new("/nonexistent.sock"),
            &mut Vec::new(),
        );
        let err = evaluator.narrowed().unwrap_err();
        assert_eq!(
            err.message(),
            "B01 lifecycle admission evaluator is unavailable"
        );
        let err = crate::helper::wipe::WipeAdvisoryEvaluator::evaluate(&evaluator).unwrap_err();
        assert_eq!(
            err.message(),
            "B01 lifecycle admission evaluator is unavailable"
        );
        let err = crate::helper::delete::DeleteAdvisoryEvaluator::evaluate(&evaluator).unwrap_err();
        assert_eq!(
            err.message(),
            "B01 lifecycle admission evaluator is unavailable"
        );
        let err = crate::helper::prune::PruneAdvisoryEvaluator::evaluate(&evaluator).unwrap_err();
        assert_eq!(
            err.message(),
            "B01 lifecycle admission evaluator is unavailable"
        );
        let err = crate::helper::prepare::EvaluateService::evaluate(&evaluator).unwrap_err();
        assert_eq!(
            err.message(),
            "B01 lifecycle admission evaluator is unavailable"
        );
        let err = crate::infra::lifecycle::AdvisoryEvaluator::evaluate(&evaluator).unwrap_err();
        assert_eq!(
            err.message(),
            "B01 lifecycle admission evaluator is unavailable"
        );
    }
}
