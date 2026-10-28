//! `server.go` — admission prologue (SO_PEERCRED, bounded read, peer
//! policy), the closed matrix gate, the deny-safe transport gate, the
//! verb dispatch table, and the systemd-activation accept loop.
//!
//! Every request that clears `admit_helper_conn` produces exactly one
//! [`DecisionRecord`] through the server's optional auditor seam, so a
//! caller can prove one audit record exists per post-admission
//! decision including denials. Requests that fail inside admission —
//! `SO_PEERCRED` failure, an unreadable frame, an unadmitted peer —
//! precede the seam and mint no record. That hook is the R5 slice's
//! answer to the task's audit-per-decision requirement; upstream
//! records these only in its stderr journal.

use super::PeerIdentity;
use super::audit::{REASON_DENY_SAFE_ACTIVE, is_deny_safe_active, parse_audit_request};
use super::init::{
    INIT_REASON_INVALID_REQUEST, InitHandler, genesis_mode_denial, parse_init_request,
};
use super::lifecycle::{LifecycleHandler, lifecycle_operation_deadline};
use super::matrix::Matrix;
use super::protocol::*;
use super::verb;
use crate::sys::peercred::{PeerCred, peercred};
use std::os::unix::io::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// `maxConcurrentHelperConnections`.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;
/// `connWriteGrace` — the write margin past a verb's own budget.
pub const CONN_WRITE_GRACE: Duration = Duration::from_secs(5);

/// `restoreCeremonyDeadline` — the human-paced share every
/// ceremony-bearing verb pays; two minutes, upstream's bound.
pub const CEREMONY_BUDGET: Duration = Duration::from_secs(120);
/// `preparePipelineDeadline` = `dependencyprepare.OperationBudget` (20
/// min) + the ceremony share.
pub const PREPARE_BUDGET: Duration = Duration::from_secs(20 * 60 + 120);
/// `initDeadline` = the ceremony share + three machine minutes.
pub const INIT_BUDGET: Duration = Duration::from_secs(120 + 180);
/// `migrationLaunchDeadline`.
pub const MIGRATION_LAUNCH_BUDGET: Duration = Duration::from_secs(30);
/// `migrationOutcomeReadDeadline`.
pub const MIGRATION_OUTCOME_BUDGET: Duration = Duration::from_secs(10);
/// `backupStatusDeadline`.
pub const BACKUP_STATUS_BUDGET: Duration = Duration::from_secs(5);
/// `backupCreateDeadline`.
pub const BACKUP_CREATE_BUDGET: Duration = Duration::from_secs(2 * 60 * 60);
/// `backupVerifyDeadline`.
pub const BACKUP_VERIFY_BUDGET: Duration = Duration::from_secs(2 * 60);

/// `restoreVerifyDeadline` — derived from the default recovery
/// profile's media-verification bound over the helper's two walks
/// (the launcher's own plus the child's single walk), exactly as
/// upstream's `restoreVerifyDeadline()`. An underivable bound
/// collapses to `0`, which `handle_conn` refuses as unsupported —
/// a verb without a positive budget never runs.
pub fn restore_verify_deadline() -> Duration {
    central_backup::backup::capacity::default_recovery_profile()
        .media_verification_deadline(super::restore::RESTORE_VERIFY_HELPER_MEDIA_WALKS)
        .map(|d| d.unsigned_abs())
        .unwrap_or(Duration::ZERO)
}

/// `restoreApplyDeadline` — the profile's restore-run bound with the
/// two-minute ceremony share priced in, exactly as upstream's
/// `restoreApplyDeadline()`/`restoreResumeDeadline()`. The clamp is
/// inside `restore_run_deadline` — a saturating profile shortens the
/// engine share, never the ceremony.
pub fn restore_apply_deadline() -> Duration {
    central_backup::backup::capacity::default_recovery_profile()
        .restore_run_deadline(time::Duration::seconds(2 * 60))
        .map(|d| d.unsigned_abs())
        .unwrap_or(Duration::ZERO)
}

/// `helperVerbDeadline` — this slice's rows; every later row collapses
/// to `lifecycle_operation_deadline`'s 0 exactly as upstream's
/// unregistered arm did.
pub fn helper_verb_deadline(verb: &str) -> Duration {
    match verb {
        v if v == verb::INIT => INIT_BUDGET,
        v if v == verb::MIGRATE_LAUNCH => MIGRATION_LAUNCH_BUDGET,
        v if v == verb::MIGRATE_READ_OUTCOME => MIGRATION_OUTCOME_BUDGET,
        v if v == verb::PREPARE => PREPARE_BUDGET,
        v if v == verb::RESTORE_VERIFY => restore_verify_deadline(),
        v if v == verb::RESTORE_APPLY => restore_apply_deadline(),
        v if v == verb::RESTORE_RESUME => restore_apply_deadline(),
        v if v == verb::RESTORE_ABANDON => CEREMONY_BUDGET,
        v if v == verb::BACKUP_CREATE => BACKUP_CREATE_BUDGET,
        v if v == verb::BACKUP_VERIFY => BACKUP_VERIFY_BUDGET,
        v if v == verb::BACKUP_STATUS => BACKUP_STATUS_BUDGET,
        v if v == verb::WIPE => CEREMONY_BUDGET + Duration::from_secs(13 * 60),
        // `exportDeadline` — the ceremony share plus just under an
        // hour of machine work; the sealed backup's own profile bound
        // substitutes for a per-request size derivation.
        v if v == verb::BACKUP_EXPORT => CEREMONY_BUDGET + Duration::from_secs(58 * 60),
        // `importDeadline` — `restoreApplyDeadline() + importStagingShare`:
        // ceremony, 28-minute staging share, and the full engine share.
        v if v == verb::BACKUP_IMPORT => restore_apply_deadline() + Duration::from_secs(28 * 60),
        v if v == verb::BACKUP_DELETE => CEREMONY_BUDGET + Duration::from_secs(8 * 60),
        v if v == verb::BACKUP_PRUNE => CEREMONY_BUDGET + Duration::from_secs(58 * 60),
        v if v == verb::BROWSER_OPEN => Duration::from_secs(30),
        v if v == verb::TRUST_INSTALL => Duration::from_secs(120),
        v if v == verb::BOOTSTRAP_SHOW => Duration::from_secs(5),
        _ => lifecycle_operation_deadline(verb),
    }
}

/// `PeerPolicy` — the closed peer admission policy. `daemon` verbs admit
/// only `daemon_uid`; operator verbs only the exact configured pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPolicy {
    pub daemon_uid: u32,
    pub operator_uid: u32,
    pub operator_gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerArm {
    Daemon,
    Operator,
}

impl PeerPolicy {
    /// `DefaultPeerPolicy` — the process's own ids.
    pub fn for_process() -> Self {
        use rustix::process::{getegid, geteuid};
        PeerPolicy {
            daemon_uid: geteuid().as_raw(),
            operator_uid: geteuid().as_raw(),
            operator_gid: getegid().as_raw(),
        }
    }

    /// `Allows` — `pid <= 0` never admits; the operator arm also refuses
    /// the daemon's own uid.
    pub fn allows(&self, arm: PeerArm, uid: u32, gid: u32, pid: i32) -> bool {
        if pid <= 0 {
            return false;
        }
        match arm {
            PeerArm::Daemon => uid == self.daemon_uid,
            PeerArm::Operator => {
                uid == self.operator_uid && gid == self.operator_gid && uid != self.daemon_uid
            }
        }
    }
}

/// `SocketPolicy` — the systemd-created socket's expected shape;
/// `validate` runs before the first accept.
#[derive(Debug, Clone)]
pub struct SocketPolicy {
    pub path: String,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub mode: u32,
}

impl SocketPolicy {
    /// `Validate` — lstat the socket; a replacement socket cannot widen
    /// admission after startup.
    pub fn validate(&self) -> Result<(), String> {
        if self.path.is_empty() || self.mode & 0o777 != 0o660 {
            return Err("helper: socket policy is incomplete".to_owned());
        }
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::symlink_metadata(&self.path)
            .map_err(|_| "helper: socket is not a protected Unix socket".to_owned())?;
        let ft = meta.file_type();
        if ft.is_symlink() || !ft.is_socket() {
            return Err("helper: socket is not a protected Unix socket".to_owned());
        }
        if meta.uid() != self.owner_uid
            || meta.gid() != self.group_gid
            || meta.mode() & 0o777 != self.mode & 0o777
        {
            return Err("helper: socket ownership or permissions are invalid".to_owned());
        }
        Ok(())
    }
}

/// One audit record per post-admission helper decision. `peer` carries
/// the kernel-reported identity; `admitted=false` is the field's shape
/// for a refusal recorded before a response was writable — admission
/// failures precede the seam, so every emitted record today carries
/// `admitted=true`.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    pub operation_id: String,
    pub verb: String,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<i32>,
    pub admitted: bool,
    pub outcome: String,
    pub exit_code: i64,
    pub reason: String,
}

/// The decision-audit seam. `record` is invoked exactly once per
/// `handle_conn` decision that survives `admit_helper_conn` —
/// unsupported verbs, deny-safe refusals, and handler answers. Parse
/// errors and unadmitted peers err inside admission before any record
/// is minted, so the seam sees post-admission decisions only.
pub trait DecisionAuditor: Send + Sync {
    fn record(&self, decision: &DecisionRecord);
}

/// `PrepareHandler` — the conditional injection arm.
pub trait PrepareHandler: Send + Sync {
    fn prepare(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        req: &Request,
        pr: PrepareRequest,
    ) -> Response;
}

/// `Server` — the ordinary instance helper.
pub struct Server {
    pub matrix: Matrix,
    pub peer_policy: Option<PeerPolicy>,
    pub socket: Option<SocketPolicy>,
    pub prepare: Option<Box<dyn PrepareHandler>>,
    pub lifecycle: Option<Box<dyn LifecycleHandler>>,
    pub init: Option<Box<dyn InitHandler>>,
    /// `Server.Migration` — the `migrate-launch` handler.
    pub migration: Option<Box<dyn super::migration_launch::MigrationLauncher>>,
    /// `Server.MigrationOutcome` — the `migrate-read-outcome` proxy.
    pub migration_outcome: Option<Box<dyn super::migration_launch::MigrationOutcomeReader>>,
    /// `Server.BackupCreate` — the `backup-create` handler.
    pub backup_create: Option<Box<dyn super::backup::BackupCreator>>,
    /// `Server.BackupRead` — backs both `backup-verify` and
    /// `backup-status`, upstream-fashion.
    pub backup_read: Option<Box<dyn super::backup::BackupReader>>,
    /// `Server.RestoreVerify`.
    pub restore_verify: Option<Box<dyn super::restore::RestoreVerifyHandler>>,
    /// `Server.RestoreApply`.
    pub restore_apply: Option<Box<dyn super::restore::RestoreApplyHandler>>,
    /// `Server.RestoreResume`.
    pub restore_resume: Option<Box<dyn super::restore::RestoreResumeHandler>>,
    /// `Server.RestoreAbandon`.
    pub restore_abandon: Option<Box<dyn super::restore::RestoreAbandonHandler>>,
    /// `Wipe` — D01, a separate seam so a composition can install wipe
    /// without installing any other destructive verb.
    pub wipe: Option<Box<dyn super::wipe::WipeHandler>>,
    /// `Export` — D02, a separate seam so a composition can install
    /// export without installing any other destructive verb.
    pub export: Option<Box<dyn super::export::ExportHandler>>,
    /// `Import` — D03, a separate seam so a composition can install
    /// import without installing any other destructive verb.
    pub import: Option<Box<dyn super::import::ImportHandler>>,
    /// `Delete` — D04 delete, a separate seam so a composition can
    /// substitute a stub.
    pub delete: Option<Box<dyn super::delete::DeleteHandler>>,
    /// `Prune` — D04 prune plan and apply, a separate seam so a
    /// composition can substitute a stub.
    pub prune: Option<Box<dyn super::prune::PruneHandler>>,
    pub browser: Option<super::browser::BrowserHandler>,
    pub bootstrap_show: Option<super::browser::BootstrapShowHandler>,
    /// Arms the deny-safe gate while non-empty.
    pub deny_safe_dir: Option<String>,
    /// One audit record per decision; `None` records nothing.
    pub auditor: Option<Box<dyn DecisionAuditor>>,
}

impl Server {
    pub fn new() -> Self {
        Server {
            matrix: Matrix::new(),
            peer_policy: None,
            socket: None,
            prepare: None,
            lifecycle: None,
            init: None,
            migration: None,
            migration_outcome: None,
            backup_create: None,
            backup_read: None,
            restore_verify: None,
            restore_apply: None,
            restore_resume: None,
            restore_abandon: None,
            wipe: None,
            export: None,
            import: None,
            delete: None,
            prune: None,
            browser: None,
            bootstrap_show: None,
            deny_safe_dir: None,
            auditor: None,
        }
    }

    fn policy(&self) -> PeerPolicy {
        self.peer_policy.unwrap_or_else(PeerPolicy::for_process)
    }

    fn decide(
        &self,
        peer: Option<PeerIdentity>,
        req_op: &str,
        verb: &str,
        admitted: bool,
        resp: &Response,
    ) {
        if let Some(auditor) = &self.auditor {
            auditor.record(&DecisionRecord {
                operation_id: req_op.to_owned(),
                verb: verb.to_owned(),
                peer_uid: peer.map(|p| p.uid),
                peer_pid: peer.map(|p| p.pid),
                admitted,
                outcome: resp.outcome.clone(),
                exit_code: resp.exit_code,
                reason: resp.reason.clone(),
            });
        }
    }

    fn respond(&self, conn: &mut UnixStream, peer: PeerIdentity, verb: &str, resp: &Response) {
        self.decide(Some(peer), &resp.operation_id.clone(), verb, true, resp);
        let _ = write_response(conn, resp);
    }

    /// `HandleConn` — one connection's whole exchange; the caller owns
    /// and closes `conn`.
    pub fn handle_conn(&self, mut conn: UnixStream) -> Result<(), String> {
        let (peer, req) = admit_helper_conn(&mut conn, self.policy(), || {
            Response::denied("unknown", 7, "invalid request")
        })?;
        let identity = PeerIdentity {
            uid: peer.uid.as_raw(),
            gid: peer.gid.as_raw(),
            pid: peer.pid.as_raw_pid(),
        };
        let verb_str = req.verb.as_str();
        let Some(op) = self.matrix.lookup(verb_str) else {
            let resp = Response::denied(&req.operation_id, 5, "UNSUPPORTED_IN_THIS_SLICE");
            self.respond(&mut conn, identity, verb_str, &resp);
            return Ok(());
        };
        if !op.implemented {
            if verb_str == verb::PREPARE && self.prepare.is_some() {
                let pr = match parse_prepare_request(&req) {
                    Ok(pr) => pr,
                    Err(_) => {
                        let resp =
                            Response::denied(&req.operation_id, 7, "INVALID_PREPARE_REQUEST");
                        self.respond(&mut conn, identity, verb_str, &resp);
                        return Ok(());
                    }
                };
                let budget = helper_verb_deadline(verb_str);
                if budget <= Duration::ZERO {
                    let resp = Response::denied(&req.operation_id, 5, "UNSUPPORTED_IN_THIS_SLICE");
                    self.respond(&mut conn, identity, verb_str, &resp);
                    return Ok(());
                }
                extend_conn_deadline(&conn, budget);
                let resp = self
                    .prepare
                    .as_ref()
                    .map(|h| h.prepare(identity, Instant::now() + budget, &req, pr))
                    .unwrap_or_else(|| {
                        Response::deferred(&req.operation_id, "UNSUPPORTED_IN_THIS_SLICE")
                    });
                self.respond(&mut conn, identity, verb_str, &resp);
                return Ok(());
            }
            let resp = Response::deferred(&req.operation_id, "UNSUPPORTED_IN_THIS_SLICE");
            self.respond(&mut conn, identity, verb_str, &resp);
            return Ok(());
        }

        // The deny-safe gate runs after the Implemented check so
        // deferred verbs keep their UNSUPPORTED answer.
        if let Some(dir) = &self.deny_safe_dir
            && is_deny_safe_active(dir)
            && !deny_safe_admits_helper(verb_str, &req)
        {
            let resp = Response::denied(&req.operation_id, 7, REASON_DENY_SAFE_ACTIVE);
            self.respond(&mut conn, identity, verb_str, &resp);
            return Ok(());
        }

        let deadline = helper_verb_deadline(verb_str);
        if deadline <= Duration::ZERO {
            let resp = Response::denied(&req.operation_id, 5, "UNSUPPORTED_IN_THIS_SLICE");
            self.respond(&mut conn, identity, verb_str, &resp);
            return Ok(());
        }
        extend_conn_deadline(&conn, deadline);
        let op_deadline = Instant::now() + deadline;
        let resp = self.dispatch_verb(verb_str, &req, identity, op_deadline);
        self.respond(&mut conn, identity, verb_str, &resp);
        Ok(())
    }

    /// `dispatchVerb` — only this slice's arms are real; a configured
    /// handler that is `None` answers upstream's exact deferred reason.
    fn dispatch_verb(
        &self,
        verb_str: &str,
        req: &Request,
        peer: PeerIdentity,
        deadline: Instant,
    ) -> Response {
        match verb_str {
            v if v == verb::INIT => self.handle_init(req, peer, deadline),
            v if v == verb::UP || v == verb::DOWN || v == verb::STATUS => {
                self.handle_lifecycle(req, peer, deadline)
            }
            v if v == verb::BROWSER_OPEN => self.handle_browser_open(req, peer),
            v if v == verb::BOOTSTRAP_SHOW => self.handle_bootstrap_show(req, peer, deadline),
            v if v == verb::PREPARE => {
                // Prepare's one route is the injection arm; reaching
                // dispatch directly gets the matrix's own refusal.
                Response::deferred(&req.operation_id, "UNSUPPORTED_IN_THIS_SLICE")
            }
            v if v == verb::MIGRATE_LAUNCH => {
                let Some(handler) = &self.migration else {
                    return Response::deferred(&req.operation_id, "MIGRATION_LAUNCH_UNAVAILABLE");
                };
                match super::migration_launch::parse_migration_launch_request(req) {
                    Ok(launch) => handler.launch(launch, &peer),
                    Err(_) => Response::denied(&req.operation_id, 2, "INVALID_MIGRATION_COMMAND"),
                }
            }
            v if v == verb::MIGRATE_READ_OUTCOME => {
                let Some(reader) = &self.migration_outcome else {
                    return Response::deferred(&req.operation_id, "MIGRATION_OUTCOME_UNAVAILABLE");
                };
                match super::migration_launch::parse_migration_outcome_read_request(req) {
                    Ok(read) => reader.read_outcome(&read, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_MIGRATION_OUTCOME_REQUEST")
                    }
                }
            }
            v if v == verb::BACKUP_CREATE => {
                let Some(handler) = &self.backup_create else {
                    return Response::deferred(&req.operation_id, "BACKUP_CREATE_UNAVAILABLE");
                };
                match super::backup::parse_backup_create_request(req) {
                    Ok(create) => handler.create_backup(deadline, create, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_BACKUP_CREATE_REQUEST")
                    }
                }
            }
            v if v == verb::BACKUP_VERIFY => {
                let Some(reader) = &self.backup_read else {
                    return Response::deferred(&req.operation_id, "BACKUP_VERIFY_UNAVAILABLE");
                };
                match super::backup::parse_backup_verify_request(req) {
                    Ok(verify) => reader.verify_backup(deadline, verify, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_BACKUP_VERIFY_REQUEST")
                    }
                }
            }
            v if v == verb::BACKUP_STATUS => {
                let Some(reader) = &self.backup_read else {
                    return Response::deferred(&req.operation_id, "BACKUP_STATUS_UNAVAILABLE");
                };
                match super::backup::parse_backup_status_request(req) {
                    Ok(status) => reader.read_backup_status(deadline, status, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_BACKUP_STATUS_REQUEST")
                    }
                }
            }
            v if v == verb::RESTORE_VERIFY => {
                let Some(handler) = &self.restore_verify else {
                    return Response::deferred(&req.operation_id, "RESTORE_VERIFY_UNAVAILABLE");
                };
                match super::restore::parse_restore_verify_request(req) {
                    Ok(verify) => handler.verify_restore(deadline, verify, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_RESTORE_VERIFY_REQUEST")
                    }
                }
            }
            v if v == verb::RESTORE_APPLY => {
                let Some(handler) = &self.restore_apply else {
                    return Response::deferred(
                        &req.operation_id,
                        "RESTORE_APPLY_AUTHORIZATION_UNAVAILABLE",
                    );
                };
                match super::restore::parse_restore_apply_request(req) {
                    Ok(apply) => handler.authorize_restore_apply(deadline, apply, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_RESTORE_APPLY_REQUEST")
                    }
                }
            }
            v if v == verb::RESTORE_RESUME => {
                let Some(handler) = &self.restore_resume else {
                    return Response::deferred(
                        &req.operation_id,
                        "RESTORE_RESUME_AUTHORIZATION_UNAVAILABLE",
                    );
                };
                match super::restore::parse_restore_resume_request(req) {
                    Ok(resume) => handler.authorize_restore_resume(deadline, resume, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_RESTORE_RESUME_REQUEST")
                    }
                }
            }
            v if v == verb::RESTORE_ABANDON => {
                let Some(handler) = &self.restore_abandon else {
                    return Response::deferred(
                        &req.operation_id,
                        "RESTORE_ABANDON_AUTHORIZATION_UNAVAILABLE",
                    );
                };
                match super::restore::parse_restore_abandon_request(req) {
                    Ok(abandon) => handler.authorize_restore_abandon(deadline, abandon, &peer),
                    Err(_) => {
                        Response::denied(&req.operation_id, 2, "INVALID_RESTORE_ABANDON_REQUEST")
                    }
                }
            }
            v if v == verb::WIPE => {
                let Some(handler) = &self.wipe else {
                    return Response::deferred(&req.operation_id, "WIPE_UNAVAILABLE");
                };
                match super::wipe::parse_wipe_request(req) {
                    Ok(wipe) => handler.wipe(deadline, wipe, &peer),
                    Err(_) => Response::denied(&req.operation_id, 2, "INVALID_WIPE_REQUEST"),
                }
            }
            v if v == verb::BACKUP_DELETE => {
                let Some(handler) = &self.delete else {
                    return Response::deferred(&req.operation_id, "DELETE_UNAVAILABLE");
                };
                match super::delete::parse_delete_request(req) {
                    Ok(delete) => handler.delete(deadline, delete, &peer),
                    Err(_) => Response::denied(&req.operation_id, 2, "INVALID_DELETE_REQUEST"),
                }
            }
            v if v == verb::BACKUP_PRUNE => {
                let Some(handler) = &self.prune else {
                    return Response::deferred(&req.operation_id, "PRUNE_UNAVAILABLE");
                };
                match super::prune::parse_prune_request(req) {
                    Ok(prune) => handler.prune(deadline, prune, &peer),
                    Err(_) => Response::denied(&req.operation_id, 2, "INVALID_PRUNE_REQUEST"),
                }
            }
            v if v == verb::BACKUP_EXPORT => {
                let Some(handler) = &self.export else {
                    return Response::deferred(
                        &req.operation_id,
                        central_infra::portable::REASON_EXPORT_UNAVAILABLE,
                    );
                };
                match super::export::parse_export_request(req) {
                    Ok(parsed) => handler.export(deadline, parsed, &peer),
                    Err(_) => Response::denied(
                        &req.operation_id,
                        2,
                        central_infra::portable::REASON_EXPORT_INVALID_REQUEST,
                    ),
                }
            }
            v if v == verb::BACKUP_IMPORT => {
                let Some(handler) = &self.import else {
                    return Response::deferred(
                        &req.operation_id,
                        central_infra::portable::REASON_IMPORT_UNAVAILABLE,
                    );
                };
                match super::import::parse_import_request(req) {
                    Ok(parsed) => handler.import(deadline, parsed, &peer),
                    Err(_) => Response::denied(
                        &req.operation_id,
                        2,
                        central_infra::portable::REASON_IMPORT_INVALID_REQUEST,
                    ),
                }
            }
            v if v == verb::TRUST_INSTALL => {
                Response::denied(&req.operation_id, 5, "UNSUPPORTED_IN_THIS_SLICE")
            }
            _ => Response::deferred(&req.operation_id, "UNSUPPORTED_IN_THIS_SLICE"),
        }
    }

    fn handle_init(&self, req: &Request, peer: PeerIdentity, deadline: Instant) -> Response {
        let Some(handler) = &self.init else {
            return Response::deferred(&req.operation_id, "UNSUPPORTED_IN_THIS_SLICE");
        };
        let request = match parse_init_request(req) {
            Ok(r) => r,
            Err(_) => {
                return super::init::new_init_denial(
                    &req.operation_id,
                    2,
                    INIT_REASON_INVALID_REQUEST,
                );
            }
        };
        handler.init(peer, deadline, request)
    }

    fn handle_lifecycle(&self, req: &Request, peer: PeerIdentity, deadline: Instant) -> Response {
        let lifecycle = match parse_lifecycle_request(req) {
            Ok(l) => l,
            Err(_) => return Response::denied(&req.operation_id, 7, "INVALID_LIFECYCLE_REQUEST"),
        };
        let Some(handler) = &self.lifecycle else {
            return Response::deferred(&req.operation_id, "LIFECYCLE_SERVICE_UNAVAILABLE");
        };
        handler.handle_lifecycle(peer, deadline, req, lifecycle)
    }

    /// `handleBrowserOpen` — empty payload = OpenCurrent; otherwise the
    /// presented proof must be complete and match the current one.
    fn handle_browser_open(&self, req: &Request, _peer: PeerIdentity) -> Response {
        let Some(browser) = &self.browser else {
            return Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED");
        };
        let parsed = match parse_browser_open_request(req) {
            Ok(p) => p,
            Err(_) => return Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED"),
        };
        let payload = req.payload_bytes();
        let trimmed: &[u8] = {
            let s = payload
                .iter()
                .position(|c| !c.is_ascii_whitespace())
                .unwrap_or(payload.len());
            let e = payload
                .iter()
                .rposition(|c| !c.is_ascii_whitespace())
                .map_or(s, |i| i + 1);
            &payload[s..e.max(s)]
        };
        let result = if trimmed.is_empty() || trimmed == b"{}" {
            browser.open_current()
        } else {
            parsed
                .ready_proof()
                .map_err(|_| super::err_denied())
                .and_then(|proof| browser.open(&proof))
        };
        match result {
            Ok(()) => Response::new(&req.operation_id, "success", 0, ""),
            Err(_) => Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED"),
        }
    }

    /// `handleBootstrapShow` — the peer and the operation window are
    /// what upstream's `ctx` carried into PAM, the TTY check, and the
    /// controlling-TTY write.
    fn handle_bootstrap_show(
        &self,
        req: &Request,
        peer: PeerIdentity,
        deadline: Instant,
    ) -> Response {
        match (&self.bootstrap_show, parse_bootstrap_show_request(req)) {
            (Some(show), Ok(_)) => match show.show_current(&peer, Some(deadline)) {
                Ok(()) => Response::new(&req.operation_id, "success", 0, ""),
                Err(_) => Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED"),
            },
            _ => Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED"),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// `denySafeAdmitsHelper` — the read-only allowlist: status, doctor,
/// rescue, maintenance-plan, and non-repair audit. An unparseable audit
/// payload passes the gate and is denied downstream, upstream-fashion.
fn deny_safe_admits_helper(verb_str: &str, req: &Request) -> bool {
    match verb_str {
        v if v == verb::STATUS
            || v == verb::DOCTOR
            || v == verb::SECURITY_RESCUE
            || v == verb::MAINTENANCE_PLAN =>
        {
            true
        }
        v if v == verb::STATE_AUDIT => match parse_audit_request(req) {
            Ok(parsed) => !parsed.repair,
            Err(_) => true,
        },
        _ => false,
    }
}

/// `admitHelperConn` — peercred, one bounded read, policy, peer arm. An
/// unadmitted peer is closed unanswered; an unreadable request is
/// answered with `unreadable()`.
fn admit_helper_conn(
    conn: &mut UnixStream,
    policy: PeerPolicy,
    unreadable: impl FnOnce() -> Response,
) -> Result<(PeerCred, Request), String> {
    let peer =
        peercred(&conn).map_err(|e| format!("helper: SO_PEERCRED failed: {}", e.message()))?;
    let req = match read_request(conn) {
        Ok(req) => req,
        Err(e) => {
            let _ = write_response(conn, &unreadable());
            return Err(e);
        }
    };
    if !admitted_helper_peer(&req.verb, &peer, policy) {
        return Err(format!(
            "helper: peer credentials are not authorized for {}",
            req.verb
        ));
    }
    Ok((peer, req))
}

/// `admittedHelperPeer` — the complete arm table, verbatim: every
/// operator verb lands on `PeerArm::Operator`, the rest on the daemon
/// default. Admission runs *before* the Implemented check, so a
/// later-implemented verb inherits the arm it was given here.
fn admitted_helper_peer(verb_str: &str, peer: &PeerCred, policy: PeerPolicy) -> bool {
    let arm = match verb_str {
        v if v == verb::BROWSER_OPEN
            || v == verb::BOOTSTRAP_SHOW
            || v == verb::TRUST_INSTALL
            || v == verb::INIT
            || v == verb::SECURITY_UPDATE
            || v == verb::MIGRATE_LAUNCH
            || v == verb::BACKUP_CREATE
            || v == verb::BACKUP_VERIFY
            || v == verb::BACKUP_STATUS
            || v == verb::MIGRATE_READ_OUTCOME
            || v == verb::RESTORE_VERIFY
            || v == verb::PREPARE
            || v == verb::RESTORE_APPLY
            || v == verb::RESTORE_RESUME
            || v == verb::RESTORE_ABANDON
            || v == verb::UP
            || v == verb::DOWN
            || v == verb::STATUS
            || v == verb::WIPE
            || v == verb::BACKUP_EXPORT
            || v == verb::BACKUP_IMPORT
            || v == verb::BACKUP_DELETE
            || v == verb::BACKUP_PRUNE
            || v == verb::STATE_AUDIT
            || v == verb::SECURITY_RESCUE
            || v == verb::MAINTENANCE_PLAN
            || v == verb::MAINTENANCE_APPLY =>
        {
            PeerArm::Operator
        }
        _ => PeerArm::Daemon,
    };
    policy.allows(
        arm,
        peer.uid.as_raw(),
        peer.gid.as_raw(),
        peer.pid.as_raw_pid(),
    )
}

fn extend_conn_deadline(conn: &UnixStream, budget: Duration) {
    let t = Some(budget + CONN_WRITE_GRACE);
    let _ = conn.set_read_timeout(t);
    let _ = conn.set_write_timeout(t);
}

/// The `slots` semaphore — `maxConcurrentHelperConnections`: the accept
/// loop blocks until a connection slot frees, exactly as upstream's
/// buffered channel does.
struct ConnSlots {
    state: std::sync::Mutex<usize>,
    freed: std::sync::Condvar,
}

struct ConnPermit {
    slots: std::sync::Arc<ConnSlots>,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut n = self.slots.state.lock().unwrap_or_else(|e| e.into_inner());
        *n = n.saturating_sub(1);
        self.slots.freed.notify_one();
    }
}

impl ConnSlots {
    fn acquire(self: &std::sync::Arc<Self>) -> ConnPermit {
        let mut n = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while *n >= MAX_CONCURRENT_CONNECTIONS {
            n = self.freed.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        *n += 1;
        ConnPermit {
            slots: self.clone(),
        }
    }
}

/// `inFlight.Wait` — a `sync.WaitGroup` over the held permits:
/// dropping this guard blocks until every admitted connection has
/// returned its slot. `serve_genesis` holds one across its accept
/// loop so it never returns while a connection is in flight.
struct ConnDrain(std::sync::Arc<ConnSlots>);

impl Drop for ConnDrain {
    fn drop(&mut self) {
        let mut n = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        while *n != 0 {
            n = self.0.freed.wait(n).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// `Serve` — accept on the systemd-supplied descriptor until `cancel`
/// becomes readable; each connection runs on its own thread bounded by
/// `idle_timeout` until its verb's real budget takes over.
pub fn serve(
    listen: OwnedFd,
    srv: &std::sync::Arc<Server>,
    idle_timeout: Duration,
    cancel: impl AsFd,
) -> Result<(), String> {
    if let Some(socket) = &srv.socket {
        socket.validate()?;
    }
    let listener = std::os::unix::net::UnixListener::from(listen);
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("helper: listener: {e}"))?;
    let idle = if idle_timeout <= Duration::ZERO {
        Duration::from_secs(60)
    } else {
        idle_timeout
    };
    let slots = std::sync::Arc::new(ConnSlots {
        state: std::sync::Mutex::new(0),
        freed: std::sync::Condvar::new(),
    });
    loop {
        match poll_readable(&listener, &cancel, Duration::from_millis(250)) {
            PollOut::Cancel => return Ok(()),
            PollOut::Timeout => continue,
            PollOut::Ready => {}
        }
        let (conn, _) = match listener.accept() {
            Ok(ok) => ok,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("helper: accept: {e}")),
        };
        let permit = slots.acquire();
        let t = Some(idle);
        let _ = conn.set_read_timeout(t);
        let _ = conn.set_write_timeout(t);
        let srv = srv.clone();
        std::thread::spawn(move || {
            let _permit = permit;
            if let Err(e) = srv.handle_conn(conn) {
                eprintln!("helper: connection error: {e}");
            }
        });
    }
}

enum PollOut {
    Ready,
    Timeout,
    Cancel,
}

fn poll_readable(
    listener: &std::os::unix::net::UnixListener,
    cancel: impl AsFd,
    max: Duration,
) -> PollOut {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let mut fds = [
        PollFd::new(&listener, PollFlags::IN),
        PollFd::new(&cancel, PollFlags::IN),
    ];
    let timeout = Timespec {
        tv_sec: i64::try_from(max.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(max.subsec_nanos()),
    };
    match poll(&mut fds, Some(&timeout)) {
        Ok(0) | Err(_) => PollOut::Timeout,
        Ok(_) => {
            if fds[1].revents().contains(PollFlags::IN) {
                return PollOut::Cancel;
            }
            if fds[0].revents().contains(PollFlags::IN) {
                return PollOut::Ready;
            }
            PollOut::Timeout
        }
    }
}

/// `GenesisServer` — the helper before an instance exists: admits only
/// `init` on the operator arm, answers every other verb with the
/// genesis denial, and stops serving after an answer that means the
/// host is no longer absent.
pub struct GenesisServer {
    pub peer_policy: Option<PeerPolicy>,
    pub socket: Option<SocketPolicy>,
    pub init: Box<dyn InitHandler>,
    pub auditor: Option<Box<dyn DecisionAuditor>>,
}

impl GenesisServer {
    /// `genesisServerStopsAfter`.
    pub fn stops_after(resp: &Response) -> bool {
        if resp.outcome == "success" && resp.exit_code == 0 {
            return true;
        }
        matches!(
            resp.reason.as_str(),
            super::init::INIT_REASON_MUTATION_FAILED
                | super::init::INIT_REASON_UNCONFIRMED
                | super::init::INIT_REASON_INSTANCE_BROKEN
        )
    }

    fn policy(&self) -> PeerPolicy {
        self.peer_policy.unwrap_or_else(PeerPolicy::for_process)
    }

    /// `handleConn` — one connection's whole exchange; the bool is
    /// `genesisServerStopsAfter(resp)` and travels independently of
    /// the response write's result, exactly like upstream's
    /// `(done, err)` pair: a dropped write still reports whether the
    /// host left `absent`.
    pub fn handle_conn(
        &self,
        mut conn: UnixStream,
        deadline: Instant,
    ) -> (bool, Result<(), String>) {
        let (peer, req) = match admit_helper_conn(&mut conn, self.policy(), || {
            super::init::new_init_denial("unknown", 2, INIT_REASON_INVALID_REQUEST)
        }) {
            Ok(pair) => pair,
            Err(e) => return (false, Err(e)),
        };
        let identity = PeerIdentity {
            uid: peer.uid.as_raw(),
            gid: peer.gid.as_raw(),
            pid: peer.pid.as_raw_pid(),
        };
        if req.verb != verb::INIT {
            let resp = genesis_mode_denial(&req);
            if let Some(a) = &self.auditor {
                a.record(&DecisionRecord {
                    operation_id: req.operation_id.clone(),
                    verb: req.verb.clone(),
                    peer_uid: Some(identity.uid),
                    peer_pid: Some(identity.pid),
                    admitted: true,
                    outcome: resp.outcome.clone(),
                    exit_code: resp.exit_code,
                    reason: resp.reason.clone(),
                });
            }
            let _ = write_response(&mut conn, &resp);
            return (false, Ok(()));
        }
        let request = match parse_init_request(&req) {
            Ok(r) => r,
            Err(_) => {
                let resp =
                    super::init::new_init_denial(&req.operation_id, 2, INIT_REASON_INVALID_REQUEST);
                if let Some(a) = &self.auditor {
                    a.record(&DecisionRecord {
                        operation_id: req.operation_id.clone(),
                        verb: req.verb.clone(),
                        peer_uid: Some(identity.uid),
                        peer_pid: Some(identity.pid),
                        admitted: true,
                        outcome: resp.outcome.clone(),
                        exit_code: resp.exit_code,
                        reason: resp.reason.clone(),
                    });
                }
                let _ = write_response(&mut conn, &resp);
                return (false, Ok(()));
            }
        };
        let resp = self.init.init(identity, deadline, request);
        if let Some(a) = &self.auditor {
            a.record(&DecisionRecord {
                operation_id: req.operation_id.clone(),
                verb: req.verb.clone(),
                peer_uid: Some(identity.uid),
                peer_pid: Some(identity.pid),
                admitted: true,
                outcome: resp.outcome.clone(),
                exit_code: resp.exit_code,
                reason: resp.reason.clone(),
            });
        }
        // `return genesisServerStopsAfter(resp), WriteResponse(conn,
        // resp)` — the stop decision is returned even when the write
        // fails; a wedged client cannot hide the host's transition.
        (Self::stops_after(&resp), write_response(&mut conn, &resp))
    }
}

/// `ServeGenesis` — like `serve` but one init that leaves the host
/// non-absent stops accepting, then in-flight connections drain.
pub fn serve_genesis(
    listen: OwnedFd,
    srv: &std::sync::Arc<GenesisServer>,
    idle_timeout: Duration,
    cancel: impl AsFd,
) -> Result<(), String> {
    if let Some(socket) = &srv.socket {
        socket.validate()?;
    }
    let listener = std::os::unix::net::UnixListener::from(listen);
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("helper: listener: {e}"))?;
    let idle = if idle_timeout <= Duration::ZERO {
        Duration::from_secs(60)
    } else {
        idle_timeout
    };
    let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let slots = std::sync::Arc::new(ConnSlots {
        state: std::sync::Mutex::new(0),
        freed: std::sync::Condvar::new(),
    });
    // `defer inFlight.Wait()` — the genesis server does not return
    // while a connection it admitted is still being served, on every
    // exit path including accept errors and cancellation.
    let _drain = ConnDrain(slots.clone());
    loop {
        if stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        match poll_readable(&listener, &cancel, Duration::from_millis(250)) {
            PollOut::Cancel => return Ok(()),
            PollOut::Timeout => continue,
            PollOut::Ready => {}
        }
        let (conn, _) = match listener.accept() {
            Ok(ok) => ok,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("helper: accept: {e}")),
        };
        let permit = slots.acquire();
        let t = Some(idle);
        let _ = conn.set_read_timeout(t);
        let _ = conn.set_write_timeout(t);
        let deadline = Instant::now() + helper_verb_deadline(verb::INIT);
        extend_conn_deadline(&conn, helper_verb_deadline(verb::INIT));
        let flag = stopping.clone();
        let srv = srv.clone();
        std::thread::spawn(move || {
            let _permit = permit;
            // `(done, err)` — the write error is journaled, the stop
            // decision honored regardless.
            let (done, result) = srv.handle_conn(conn, deadline);
            if let Err(e) = result {
                eprintln!("helper: genesis connection error: {e}");
            }
            if done {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingAuditor {
        seen: std::sync::Mutex<Vec<DecisionRecord>>,
    }
    impl DecisionAuditor for RecordingAuditor {
        fn record(&self, d: &DecisionRecord) {
            self.seen.lock().unwrap().push(d.clone());
        }
    }

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            daemon_uid: 0,
            operator_uid: 1000,
            operator_gid: 1000,
        }
    }

    /// The admission arm table × caller identity, pinned for the whole
    /// matrix: operator verbs admit only the configured operator uid+gid,
    /// daemon verbs only the daemon uid, and a `pid <= 0` peer admits
    /// nothing.
    #[test]
    fn peer_policy_arm_table() {
        let p = policy();
        assert!(p.allows(PeerArm::Operator, 1000, 1000, 42));
        assert!(!p.allows(PeerArm::Operator, 1000, 1001, 42));
        assert!(!p.allows(PeerArm::Operator, 0, 0, 42));
        assert!(!p.allows(PeerArm::Operator, 1000, 1000, 0));
        assert!(p.allows(PeerArm::Daemon, 0, 0, 42));
        assert!(!p.allows(PeerArm::Daemon, 1000, 1000, 42));
        let cred = PeerCred {
            pid: rustix::process::Pid::from_raw(42).unwrap(),
            uid: rustix::process::Uid::from_raw(1000),
            gid: rustix::process::Gid::from_raw(1000),
        };
        let daemon = PeerCred {
            pid: rustix::process::Pid::from_raw(42).unwrap(),
            uid: rustix::process::Uid::from_raw(0),
            gid: rustix::process::Gid::from_raw(0),
        };
        for v in [
            verb::UP,
            verb::DOWN,
            verb::STATUS,
            verb::INIT,
            verb::PREPARE,
            verb::BROWSER_OPEN,
            verb::BOOTSTRAP_SHOW,
            verb::WIPE,
            verb::STATE_AUDIT,
            verb::RESTORE_ABANDON,
            verb::SECURITY_RESCUE,
            verb::MAINTENANCE_APPLY,
            verb::BACKUP_EXPORT,
            verb::MIGRATE_READ_OUTCOME,
        ] {
            assert!(
                admitted_helper_peer(v, &cred, p),
                "{v} must be on the operator arm"
            );
            assert!(
                !admitted_helper_peer(v, &daemon, p),
                "{v} must refuse the daemon peer"
            );
        }
        for v in [
            "frobnicate",
            verb::RUNTIME_START,
            verb::INIT_STATUS,
            verb::DOCTOR,
            verb::SECURITY_RESCUE_CLEANUP,
        ] {
            assert!(
                !admitted_helper_peer(v, &cred, p),
                "{v} must stay on the daemon arm"
            );
            assert!(admitted_helper_peer(v, &daemon, p), "{v} daemon arm");
        }
    }

    /// Every unimplemented verb — including all R6 operations — is
    /// answered `UNSUPPORTED_IN_THIS_SLICE`, and exactly one decision
    /// record is emitted per request.
    #[test]
    fn closed_matrix_denies_later_verbs_and_records_every_decision() {
        struct Wrap(std::sync::Arc<RecordingAuditor>);
        impl DecisionAuditor for Wrap {
            fn record(&self, d: &DecisionRecord) {
                self.0.record(d);
            }
        }
        let auditor = std::sync::Arc::new(RecordingAuditor {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let srv = Server {
            // The operator arm is where every deferred verb lives; the
            // daemon arm would refuse this same-process peer outright
            // (the `uid != daemon_uid` rule), so the operator arm is the
            // only one a socketpair can exercise.
            peer_policy: Some(PeerPolicy {
                daemon_uid: u32::MAX - 2,
                operator_uid: rustix::process::geteuid().as_raw(),
                operator_gid: rustix::process::getegid().as_raw(),
            }),
            auditor: Some(Box::new(Wrap(auditor.clone()))),
            ..Server::new()
        };
        assert!(
            srv.matrix.lookup("bogus-verb").is_none(),
            "unregistered verbs deny closed"
        );
        let cases = [
            // Implemented but unconfigured: each destructive verb
            // answers with its own upstream unavailable token, not the
            // matrix's closed refusal — exactly upstream's
            // `wipeUnavailable`/`deleteUnavailable`/`pruneUnavailable`
            // fallbacks for a server built without the handler.
            (verb::WIPE, "deferred", "WIPE_UNAVAILABLE"),
            (verb::BACKUP_DELETE, "deferred", "DELETE_UNAVAILABLE"),
            (verb::BACKUP_PRUNE, "deferred", "PRUNE_UNAVAILABLE"),
            // Implemented but unconfigured: the verb's own upstream
            // unavailable answer, not the matrix's closed refusal.
            (
                verb::RESTORE_APPLY,
                "deferred",
                "RESTORE_APPLY_AUTHORIZATION_UNAVAILABLE",
            ),
            (
                verb::RESTORE_VERIFY,
                "deferred",
                "RESTORE_VERIFY_UNAVAILABLE",
            ),
            (verb::BACKUP_CREATE, "deferred", "BACKUP_CREATE_UNAVAILABLE"),
            (verb::STATE_AUDIT, "deferred", "UNSUPPORTED_IN_THIS_SLICE"),
            // Implemented but unconfigured: the verb's own upstream
            // unavailable answer, not the matrix's closed refusal —
            // `exportUnavailable`/`importUnavailable`.
            (verb::BACKUP_EXPORT, "deferred", "EXPORT_UNAVAILABLE"),
            (verb::BACKUP_IMPORT, "deferred", "IMPORT_UNAVAILABLE"),
            (
                verb::MAINTENANCE_APPLY,
                "deferred",
                "UNSUPPORTED_IN_THIS_SLICE",
            ),
            (
                verb::SECURITY_RESCUE,
                "deferred",
                "UNSUPPORTED_IN_THIS_SLICE",
            ),
            (verb::UP, "deferred", "LIFECYCLE_SERVICE_UNAVAILABLE"),
            (verb::STATUS, "deferred", "LIFECYCLE_SERVICE_UNAVAILABLE"),
        ];
        for (v, outcome, reason) in cases {
            let (mut client, conn) = pair();
            let req = Request {
                operation_id: format!("op-{v}"),
                verb: v.to_owned(),
                payload: None,
            };
            write_request(&mut client, &req).unwrap();
            srv.handle_conn(conn).unwrap();
            let resp = read_response(&mut client).unwrap();
            assert_eq!(resp.outcome, outcome, "{v}");
            assert_eq!(resp.reason, reason, "{v}");
            assert_eq!(resp.exit_code, 5);
        }
        let records = auditor.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(records.len(), cases.len(), "one record per decision");
        for r in records.iter() {
            assert!(r.admitted);
        }
    }

    /// The operator arm a same-process socketpair can exercise.
    fn self_operator_policy() -> PeerPolicy {
        PeerPolicy {
            daemon_uid: u32::MAX - 2,
            operator_uid: rustix::process::geteuid().as_raw(),
            operator_gid: rustix::process::getegid().as_raw(),
        }
    }

    /// `(done, err)` — upstream returns `genesisServerStopsAfter(resp)`
    /// independently of the response write: a client that hangs up
    /// before the answer lands still stops genesis serving.
    #[test]
    fn genesis_handle_conn_reports_done_despite_a_failed_write() {
        struct StopInit;
        impl crate::helper::init::InitHandler for StopInit {
            fn init(
                &self,
                _peer: PeerIdentity,
                _deadline: Instant,
                request: crate::helper::init::InitRequest,
            ) -> Response {
                Response {
                    operation_id: request.operation_id,
                    outcome: "success".to_owned(),
                    exit_code: 0,
                    reason: String::new(),
                    result: None,
                }
            }
        }
        let srv = GenesisServer {
            peer_policy: Some(self_operator_policy()),
            socket: None,
            init: Box::new(StopInit),
            auditor: None,
        };
        let (mut client, server_end) = pair();
        let req = Request {
            operation_id: "op-1".to_owned(),
            verb: verb::INIT.to_owned(),
            payload: None,
        };
        write_request(&mut client, &req).unwrap();
        // Hung up before the answer is written — the write errors
        // EPIPE but the success answer still means stop. Shutdown is
        // the explicit half of the hang-up: RCV_SHUTDOWN lands on the
        // live peer before close, so the server's write cannot land
        // even if close teardown were deferred past it.
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let (done, result) = srv.handle_conn(server_end, Instant::now() + Duration::from_secs(30));
        assert!(
            done,
            "a success answer stops genesis even when its write fails"
        );
        assert!(result.is_err());
    }

    /// `defer inFlight.Wait()` — a cancelled accept loop still waits
    /// for the connection it admitted to drain before returning.
    #[test]
    fn serve_genesis_drains_the_in_flight_connection_on_cancel() {
        use std::io::Write as _;
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::{Receiver, SyncSender, channel, sync_channel};

        struct BlockingInit {
            release: std::sync::Mutex<Receiver<()>>,
            started: SyncSender<()>,
        }
        impl crate::helper::init::InitHandler for BlockingInit {
            fn init(
                &self,
                _peer: PeerIdentity,
                _deadline: Instant,
                request: crate::helper::init::InitRequest,
            ) -> Response {
                let _ = self.started.send(());
                let _ = self
                    .release
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .recv();
                Response {
                    operation_id: request.operation_id,
                    outcome: "denied".to_owned(),
                    exit_code: 7,
                    reason: "AUTHORITY_DENIED".to_owned(),
                    result: None,
                }
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "central-serve-genesis-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let listen_fd: OwnedFd = listener.into();
        let (cancel_read, mut cancel_write) = UnixStream::pair().unwrap();
        let (release_tx, release_rx) = channel::<()>();
        let (started_tx, started_rx) = sync_channel::<()>(1);
        let srv = std::sync::Arc::new(GenesisServer {
            peer_policy: Some(self_operator_policy()),
            socket: None,
            init: Box::new(BlockingInit {
                release: std::sync::Mutex::new(release_rx),
                started: started_tx,
            }),
            auditor: None,
        });
        let returned = std::sync::Arc::new(AtomicBool::new(false));
        let seen = returned.clone();
        let srv_ref = srv.clone();
        let serve = std::thread::spawn(move || {
            let _ = serve_genesis(listen_fd, &srv_ref, Duration::from_secs(60), cancel_read);
            seen.store(true, Ordering::SeqCst);
        });
        let mut client = UnixStream::connect(&path).unwrap();
        let req = Request {
            operation_id: "op-1".to_owned(),
            verb: verb::INIT.to_owned(),
            payload: None,
        };
        write_request(&mut client, &req).unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the init handler is in flight");
        // Cancel the accept loop — it cannot return while the
        // admitted connection still holds its slot.
        cancel_write.write_all(b"x").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !returned.load(Ordering::SeqCst),
            "serve_genesis returned with a connection in flight"
        );
        let _ = release_tx.send(());
        serve.join().expect("serve thread");
        assert!(returned.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
