//! `runHelperDaemon` (`cmd/central/main.go`) — the `--helper` mode's
//! whole body after the mode gates: `LISTEN_FDS` admission, the
//! genesis/instance branch, `helperPeerPolicyFromEnvironment`, signal
//! cancellation, and `Serve`/`ServeGenesis` on the systemd-supplied
//! descriptor 3.
//!
//! What this slice composes is deliberately the protocol shell: the
//! peer and socket policies, the closed matrix, the genesis transport
//! (init admitted, everything else denied), and `prepare`'s explicit
//! unavailable answer. `init` is real on both branches — the genesis
//! handler on an absent host, the present-instance answer on the
//! ordinary server (R5 T13). The handlers that need the
//! infralifecycle service, the advisory evaluator, or the broker are
//! the later tasks' composition; their verbs keep upstream's
//! unconfigured-handler answers, never a made-up success.

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
fn parse_u32_strict(raw: &str) -> Option<u32> {
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
            Some(Box::new(PamConfirmer::new())),
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
                Some(Box::new(PamConfirmer::new())),
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
        // A host that cannot compose the prepare graph still serves
        // every other verb; it refuses explicitly rather than being
        // left unset — upstream's `unavailablePrepareHandler`. The real
        // pipeline exists at `infra::prepare::new_prepare_handler`
        // (service + handler, `PreparePamConfirmer` implemented on
        // `PamConfirmer`); what this daemon still lacks is a production
        // `EvaluateService` (advisory evaluation is a later task's
        // seam), so the handler stays the explicit refusal until that
        // composition can complete — upstream's rule verbatim.
        prepare: Some(Box::new(UnavailablePrepareHandler)),
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
                Box::new(PamConfirmer::new()),
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
                Box::new(PamConfirmer::new()),
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
        // `lifecycle` stays unset for the same dependency-chain reason,
        // one link deeper: `infra::lifecycle::new_production_service`
        // needs (1) the B01 advisory evaluator — the same deferred seam
        // as prepare — (2) the B02 active-receipt reader, (3) the OCI
        // receipt inspector, (4) a `ComposeRunner`, (5) the typed B04
        // broker authority (SCM_RIGHTS custody path), (6) the broker
        // rendezvous for the minio-provision socket, and (7) the
        // dead-owner verifier the lock takeover consults. The port of
        // upstream's handler exists — `infra::lifecycle`'s
        // `LifecycleApplicationBridge` + `production_lifecycle_handler`
        // — but installing it without the full chain would be a
        // made-up success, so the matrix's `LIFECYCLE_SERVICE_UNAVAILABLE`
        // answer stands until the evaluator link lands. This is
        // upstream's production status verbatim, not dead code: the
        // bridge drives the domain service synchronously and maps its
        // result onto the wire shape once composed.
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
}
