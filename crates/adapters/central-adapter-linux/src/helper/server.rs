//! `server.go` — admission prologue (SO_PEERCRED, bounded read, peer
//! policy), the closed matrix gate, the deny-safe transport gate, the
//! verb dispatch table, and the systemd-activation accept loop.
//!
//! Every answered request — admitted or not — produces exactly one
//! [`DecisionRecord`] through the server's optional auditor seam, so a
//! caller can prove one audit record exists per decision including
//! denials. That hook is the R5 slice's answer to the task's
//! audit-per-decision requirement; upstream records these only in its
//! stderr journal.

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

/// `helperVerbDeadline` — this slice's rows; every later row collapses
/// to `lifecycle_operation_deadline`'s 0 exactly as upstream's
/// unregistered arm did.
pub fn helper_verb_deadline(verb: &str) -> Duration {
    match verb {
        v if v == verb::INIT => INIT_BUDGET,
        v if v == verb::MIGRATE_LAUNCH => MIGRATION_LAUNCH_BUDGET,
        v if v == verb::MIGRATE_READ_OUTCOME => MIGRATION_OUTCOME_BUDGET,
        v if v == verb::PREPARE => PREPARE_BUDGET,
        v if v == verb::BACKUP_STATUS => BACKUP_STATUS_BUDGET,
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

/// One audit record per helper decision. `peer` carries the
/// kernel-reported identity; `admitted=false` marks the
/// closed-unanswered refusals (no response was writable).
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
/// `handle_conn`, including parse errors, unadmitted peers, unsupported
/// verbs, deny-safe refusals, and handler answers.
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
            v if v == verb::BOOTSTRAP_SHOW => self.handle_bootstrap_show(req, peer),
            v if v == verb::PREPARE => {
                // Prepare's one route is the injection arm; reaching
                // dispatch directly gets the matrix's own refusal.
                Response::deferred(&req.operation_id, "UNSUPPORTED_IN_THIS_SLICE")
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

    fn handle_bootstrap_show(&self, req: &Request, _peer: PeerIdentity) -> Response {
        match (&self.bootstrap_show, parse_bootstrap_show_request(req)) {
            (Some(show), Ok(_)) => match show.show_current() {
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

    /// Returns `true` when this connection ended genesis serving.
    pub fn handle_conn(&self, mut conn: UnixStream, deadline: Instant) -> Result<bool, String> {
        let (peer, req) = admit_helper_conn(&mut conn, self.policy(), || {
            super::init::new_init_denial("unknown", 2, INIT_REASON_INVALID_REQUEST)
        })?;
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
            return Ok(false);
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
                return Ok(false);
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
        let write_result = write_response(&mut conn, &resp);
        let stops = Self::stops_after(&resp);
        write_result.map(|_| stops)
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
            match srv.handle_conn(conn, deadline) {
                Ok(true) => flag.store(true, std::sync::atomic::Ordering::SeqCst),
                Ok(false) => {}
                Err(e) => eprintln!("helper: genesis connection error: {e}"),
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
            (verb::WIPE, "deferred", "UNSUPPORTED_IN_THIS_SLICE"),
            (verb::RESTORE_APPLY, "deferred", "UNSUPPORTED_IN_THIS_SLICE"),
            (verb::STATE_AUDIT, "deferred", "UNSUPPORTED_IN_THIS_SLICE"),
            (verb::BACKUP_EXPORT, "deferred", "UNSUPPORTED_IN_THIS_SLICE"),
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
}
