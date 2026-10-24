//! central-harness-launcherd: the root, socket-activated launcher of
//! operator harness sessions (ADR 0036; phase 2b design) — upstream
//! `main.c`. This file holds the socket loop, the peer check, request
//! dispatch and scope ownership (decision 2): the daemon keeps only
//! scope -> control socket of the owning monitor, forwards ALIVE and
//! KILL for an owned scope to it, answers an unowned scope from its
//! cgroup, and cleans up after a monitor that dies. Its event loop
//! never blocks: not on a KILL, and not on a monitor (its end of every
//! control socket is non-blocking; a forward that would block is
//! answered from the cgroup instead). The wire format is PROTOCOL.md.

mod cgroup;
mod knobs;
mod policy;
mod protocol;
mod session;
mod sys;

use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use central_adapter_harness::launcher::protocol as wire;
use wire::{Opcode, Reason, Scope};

use rustix::event::Timespec;
#[cfg(feature = "test-build")]
use rustix::fs::{Mode, unlink};
use rustix::io::Errno;
#[cfg(feature = "test-build")]
use rustix::net::{AddressFamily, SocketAddrUnix, bind, listen, socket_with};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SocketFlags, SocketType, accept_with,
    recv, recvmsg, send, sockopt,
};
use rustix::process::{WaitOptions, wait};

use policy::{ArgvKind, Config, HarnessEntry, Operator};
use protocol::{log, log_step};
use session::{CTL_ALIVE, CTL_KILL, CTL_RELEASE, CTL_RELEASED, Plan, send_fds};
use sys::Fork;

/// Landlock (decision 7): the daemon refuses to start below this ABI.
const LANDLOCK_MIN_ABI: i32 = 6;

const MAX_SCOPES: usize = 64;
const MAX_KILL_WAITERS: usize = 16;
const MAX_RECEIVED_FDS: usize = 16;

static STOPPING: AtomicBool = AtomicBool::new(false);

fn ms_timespec(ms: i64) -> Timespec {
    Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    }
}

fn unreachable_() -> ! {
    // Checked by construction at every call site; a wrong reach is a
    // daemon bug, reported as launch_failed rather than a panic message.
    std::process::abort()
}

extern "C" fn stop_handler(_sig: libc::c_int) {
    STOPPING.store(true, Ordering::Relaxed);
}

/// A scope is owned by its monitor (control >= 0), and/or being cleaned
/// by its one short-lived cleaner (cleaner > 0): after its monitor died,
/// for an unowned KILL, or for a KILL its monitor could not take. Every
/// KILL that waits on the cleaner is a waiter, answered when the
/// cleaner ends.
struct ScopeEntry {
    used: bool,
    id: Scope,
    control: Option<OwnedFd>,
    monitor: i32,
    cleaner: i32,
    waiters: Vec<OwnedFd>,
}

impl ScopeEntry {
    fn new() -> Self {
        Self {
            used: false,
            id: Scope::default(),
            control: None,
            monitor: 0,
            cleaner: 0,
            waiters: Vec::new(),
        }
    }
}

struct Scopes {
    table: Vec<ScopeEntry>,
}

impl Scopes {
    fn new() -> Self {
        Self {
            table: (0..MAX_SCOPES).map(|_| ScopeEntry::new()).collect(),
        }
    }

    fn find(&mut self, id: &Scope) -> Option<usize> {
        (0..MAX_SCOPES).find(|&i| self.table[i].used && self.table[i].id == *id)
    }

    fn fresh(&mut self, id: &Scope) -> Option<usize> {
        for i in 0..MAX_SCOPES {
            if !self.table[i].used {
                let e = &mut self.table[i];
                *e = ScopeEntry::new();
                e.used = true;
                e.id = *id;
                return Some(i);
            }
        }
        None
    }
}

fn respond(conn: RawFd, op: Opcode, status: Reason, p0: u8) {
    let r = wire::Response {
        op,
        status,
        alive: p0 != 0,
        ..wire::Response::default()
    };
    let Ok(frame) = wire::encode_response(&r) else {
        return;
    };
    let _ = send(sys::borrow(conn), &frame, rustix::net::SendFlags::NOSIGNAL);
}

fn answer_waiters(e: &mut ScopeEntry, status: Reason) {
    for w in e.waiters.drain(..) {
        respond(w.as_raw_fd(), Opcode::Kill, status, 0);
    }
}

fn drop_scope(e: &mut ScopeEntry) {
    e.control = None;
    answer_waiters(e, Reason::LaunchFailed);
    let id = e.id;
    *e = ScopeEntry::new();
    e.id = id;
    e.used = false;
}

/// `add_waiter` keeps a copy of a KILL connection until the scope's
/// cleaner ends.
fn add_waiter(e: &mut ScopeEntry, conn: RawFd) -> bool {
    if e.waiters.len() == MAX_KILL_WAITERS {
        return false;
    }
    let Ok(fd) = sys::dupfd_cloexec(conn, 0) else {
        return false;
    };
    e.waiters.push(fd);
    true
}

/// `send_control` sends to a monitor without ever blocking the loop for
/// longer than `wait_ms`: the daemon's end is non-blocking, and a full
/// socket is waited on for at most `wait_ms`.
fn send_control(control: RawFd, msg: &[u8], fds: &[RawFd], wait_ms: i32) -> bool {
    if send_fds(control, msg, fds).is_ok() {
        return true;
    }
    if wait_ms <= 0 {
        return false;
    }
    let control_b = sys::borrow(control);
    let mut pfd = [rustix::event::PollFd::new(
        &control_b,
        rustix::event::PollFlags::OUT,
    )];
    matches!(
        rustix::event::poll(&mut pfd, Some(&ms_timespec(i64::from(wait_ms)))),
        Ok(n) if n > 0
    ) && send_fds(control, msg, fds).is_ok()
}

/// `receive_request` reads one datagram. It closes every descriptor
/// that came with it and reports, through `tainted`, a datagram that
/// carried any, was truncated, or filled the buffer.
fn receive_request(conn: RawFd, buf: &mut [u8], tainted: &mut bool) -> Option<usize> {
    let conn_b = sys::borrow(conn);
    let mut pfd = [rustix::event::PollFd::new(
        &conn_b,
        rustix::event::PollFlags::IN,
    )];
    loop {
        match rustix::event::poll(
            &mut pfd,
            Some(&ms_timespec(i64::from(knobs::receive_timeout_ms()))),
        ) {
            Err(Errno::INTR) if !STOPPING.load(Ordering::Relaxed) => continue,
            Ok(n) if n > 0 && pfd[0].revents().contains(rustix::event::PollFlags::IN) => break,
            _ => return None,
        }
    }
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg_space =
        [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_RECEIVED_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut cmsg_space);
    let msg = recvmsg(
        conn_b,
        &mut iov,
        &mut control,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )
    .ok()?;
    *tainted = msg
        .flags
        .intersects(rustix::net::ReturnFlags::TRUNC | rustix::net::ReturnFlags::CTRUNC)
        || msg.bytes > wire::MAX_FRAME;
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            // OwnedFd drops (closes) each received descriptor.
            for _fd in it {}
        }
        *tainted = true;
    }
    Some(msg.bytes)
}

/* ---- cleaners: short-lived children, so the loop never blocks ---- */

/// `spawn_cleaner` kills the scope's cgroup, waits (bounded) for it to
/// empty and removes it when asked; its exit status is the result. It
/// keeps no inherited descriptor but stdio: not the listener, not a
/// control socket (a monitor must see the daemon's death as EOF), not a
/// client connection.
fn spawn_cleaner(scope: &Scope, remove: bool) -> i32 {
    match sys::fork() {
        Ok(Fork::Parent(p)) => p.as_raw_nonzero().get(),
        Ok(Fork::Child) => {
            sys::close_from(3);
            if cgroup::reopen().is_err() {
                sys::exit(1);
            }
            let _ = cgroup::scope_kill(scope);
            let mut ok = cgroup::scope_wait_empty(scope, knobs::clean_timeout_ms()).is_ok();
            if ok && remove {
                ok = cgroup::scope_remove(scope).is_ok();
            }
            log(
                if ok {
                    "scope_cleaned"
                } else {
                    "scope_clean_failed"
                },
                if ok { Reason::Ok } else { Reason::LaunchFailed },
                Some(scope),
            );
            sys::exit(if ok { 0 } else { 1 });
        }
        Err(_) => -1,
    }
}

/// `ensure_cleaner` starts the scope's cleaner unless one runs already:
/// at most one per scope.
fn ensure_cleaner(e: &mut ScopeEntry) -> bool {
    if e.cleaner > 0 {
        return true;
    }
    let cleaner = spawn_cleaner(&e.id, e.control.is_none());
    if cleaner < 0 {
        return false;
    }
    e.cleaner = cleaner;
    true
}

/// `monitor_gone` handles a monitor that ended without releasing its
/// scope: a harness without a monitor has no lifeline, so the scope is
/// killed and cleaned as an unowned one.
fn monitor_gone(e: &mut ScopeEntry) {
    e.control = None;
    e.monitor = 0;
    log("monitor_lost", Reason::LaunchFailed, Some(&e.id));
    if !ensure_cleaner(e) {
        drop_scope(e);
    }
}

fn handle_control(e: &mut ScopeEntry) {
    let mut msg = [0u8; 8];
    let Some(control) = e.control.as_ref() else {
        return;
    };
    let n = loop {
        match recv(control, &mut msg[..], RecvFlags::DONTWAIT) {
            Err(Errno::INTR) => continue,
            other => break other,
        }
    };
    let n = match n {
        Err(Errno::AGAIN) => return,
        other => other.map(|o| o.1),
    };
    if let Ok(size) = n
        && size > 0
        && msg[0] == CTL_RELEASE
    {
        // The monitor is reading now, so a full socket drains
        // quickly; the wait is bounded all the same.
        let ack = [CTL_RELEASED];
        let fd = e.control.as_ref().map(|c| c.as_raw_fd()).unwrap_or(-1);
        if fd >= 0 {
            let _ = send_control(fd, &ack, &[], 100);
        }
        log("scope_released", Reason::Ok, Some(&e.id));
        if e.cleaner > 0 {
            // A fallback cleaner still runs: the entry stays,
            // unowned, until it ends.
            e.control = None;
            e.monitor = 0;
            return;
        }
        drop_scope(e);
        return;
    }
    monitor_gone(e);
}

fn reap_children(scopes: &mut Scopes) {
    while let Ok(Some((pid, status))) = wait(WaitOptions::NOHANG) {
        let pid = pid.as_raw_nonzero().get();
        for e in scopes.table.iter_mut() {
            if !e.used {
                continue;
            }
            if e.cleaner == pid {
                let ok = status.exit_status() == Some(0);
                e.cleaner = 0;
                answer_waiters(e, if ok { Reason::Ok } else { Reason::LaunchFailed });
                // Unowned: the entry ends with its cleaner. An
                // empty leftover is removed.
                if e.control.is_none() {
                    if cgroup::scope_populated(&e.id) == Ok(false) {
                        let _ = cgroup::scope_remove(&e.id);
                    }
                    drop_scope(e);
                }
            } else if e.monitor == pid {
                e.monitor = 0; // its control EOF follows
            }
        }
    }
}

/* ---- requests ---- */

/// `validate_launch` runs PROTOCOL.md §3.1.1 steps 5-11.
fn validate_launch<'a>(
    config: &'a Config,
    req: &wire::RawLaunch,
    op: &mut Operator,
    harness: &mut Option<&'a HarnessEntry>,
    kind: &mut ArgvKind,
    root_out: &mut Option<rustix::fs::Stat>,
) -> Reason {
    let r = policy::resolve_operator(config, op);
    if r != Reason::Ok {
        return r;
    }
    let root = match policy::check_home_config(config, op) {
        Err(r) => return r,
        Ok(root) => root,
    };
    *root_out = Some(root);
    *harness = policy::find_harness(config, &req.harness);
    let Some(h) = *harness else {
        return Reason::UnknownHarness;
    };
    let _ = h;
    let argv: Vec<&[u8]> = req.argv.iter().map(Vec::as_slice).collect();
    *kind = policy::argv_kind(&req.harness, &argv);
    if *kind == ArgvKind::Refused {
        return Reason::ArgvRefused;
    }
    if !policy::env_allowed(&req.env) {
        return Reason::EnvRefused;
    }
    let r = policy::check_workdir(
        config,
        &req.work_dir,
        *kind,
        root_out.as_ref().unwrap_or_else(|| unreachable_()),
    );
    if r != Reason::Ok {
        return r;
    }
    policy::check_harness_home(config, op, h)
}

/// `program_in_view` — where the harness program appears inside the
/// mount view: a program beneath HOME/<source> of an ro entry appears
/// beneath HOME/<target>. Without isolation it is the real path.
fn program_in_view(config: &Config, op: &Operator, h: &HarnessEntry) -> Option<Vec<u8>> {
    if !knobs::no_isolation() {
        for m in &config.mounts {
            if m.harness != h.id || !m.read_only {
                continue;
            }
            let mut source = op.home.clone();
            source.push(b'/');
            source.extend_from_slice(&m.source);
            if source.len() >= 4096 || !policy::path_beneath(&source, &h.program) {
                continue;
            }
            let mut out = op.home.clone();
            out.push(b'/');
            out.extend_from_slice(&m.target);
            out.extend_from_slice(&h.program[source.len()..]);
            return Some(out);
        }
    }
    Some(h.program.clone())
}

/// `admit` — decision 12's admission: a scope that is owned, being
/// cleaned or populated is busy; an unowned, unpopulated leftover
/// directory is removed.
fn admit(scopes: &mut Scopes, scope: &Scope) -> Reason {
    if scopes.find(scope).is_some() {
        return Reason::ScopeBusy;
    }
    if cgroup::scope_populated(scope).unwrap_or(true) {
        return Reason::ScopeBusy;
    }
    if cgroup::scope_exists(scope) && cgroup::scope_remove(scope).is_err() {
        return Reason::ScopeBusy;
    }
    Reason::Ok
}

/// Everything `validate_launch` proved, bundled for `start_session`.
struct ValidLaunch<'a> {
    config: &'a Config,
    req: &'a wire::RawLaunch,
    op: &'a Operator,
    harness: &'a HarnessEntry,
    root: &'a rustix::fs::Stat,
}

/// `start_session` creates the scope and forks its monitor, which takes
/// over `conn` as the lifeline.
fn start_session(
    scopes: &mut Scopes,
    conn: RawFd,
    v: &ValidLaunch,
    step: &mut i32,
    err: &mut i32,
) -> Reason {
    let ValidLaunch {
        config,
        req,
        op,
        harness,
        root,
    } = *v;
    let Some(idx) = scopes.fresh(&req.scope) else {
        *step = protocol::STEP_SCOPE_TABLE;
        *err = 0;
        return Reason::LaunchFailed;
    };
    let program = program_in_view(config, op, harness);
    let program_c = program.as_ref().and_then(|p| sys::bytes_cstring(p));
    let envp = policy::build_env(&req.env, op)
        .iter()
        .map(|e| sys::bytes_cstring(e))
        .collect::<Option<Vec<_>>>();
    let mut argv: Vec<std::ffi::CString> = Vec::with_capacity(req.argv.len() + 1);
    if let Some(p) = &program_c {
        argv.push(p.clone());
    }
    for a in &req.argv {
        match sys::bytes_cstring(a) {
            Some(c) => argv.push(c),
            None => break,
        }
    }
    let tty_gid = sys::getgrnam(c"tty");
    let mut result = Reason::LaunchFailed;
    *step = protocol::STEP_PLAN_ALLOC;
    *err = libc::ENOMEM;
    'out: {
        let (Some(program_c), Some(envp)) = (program_c, envp) else {
            break 'out;
        };
        if argv.len() != req.argv.len() + 1 {
            break 'out;
        }
        let plan = Plan {
            scope: req.scope,
            op: op.clone(),
            config: config.clone(),
            harness: harness.clone(),
            workdir: req.work_dir.clone(),
            root_dev: root.st_dev,
            root_ino: root.st_ino,
            program: program_c,
            argv,
            envp,
            tty_gid,
        };
        if let Err(e) = cgroup::scope_create(&req.scope, config) {
            *step = protocol::STEP_SCOPE_CREATE;
            *err = e.raw_os_error();
            break 'out;
        }
        // The daemon's end is non-blocking: a monitor that stops reading
        // must never stall the loop (decision 2).
        let pair = session::control_pair().and_then(|(a, b)| {
            sys::set_nonblock(a.as_raw_fd())?;
            Ok((a, b))
        });
        let pair = match pair {
            Err(e) => {
                *step = protocol::STEP_CONTROL_SOCKET;
                *err = e.raw_os_error();
                let _ = cgroup::scope_remove(&req.scope);
                break 'out;
            }
            Ok(p) => p,
        };
        match sys::fork() {
            Ok(Fork::Child) => {
                sys::close(pair.0.as_raw_fd());
                session::monitor_main(conn, pair.1.as_raw_fd(), &plan);
            }
            Ok(Fork::Parent(pid)) => {
                let e = &mut scopes.table[idx];
                e.control = Some(pair.0);
                e.monitor = pid.as_raw_nonzero().get();
                result = Reason::Ok;
            }
            Err(e) => {
                *step = protocol::STEP_MONITOR_FORK;
                *err = e.raw_os_error();
                let _ = cgroup::scope_remove(&req.scope);
            }
        }
    }
    if result != Reason::Ok {
        drop_scope(&mut scopes.table[idx]);
    }
    result
}

fn handle_launch(scopes: &mut Scopes, conn: RawFd, config: &Config, req: &wire::RawLaunch) {
    let mut op = Operator::default();
    let mut harness: Option<&HarnessEntry> = None;
    let mut kind = ArgvKind::Refused;
    let mut root: Option<rustix::fs::Stat> = None;
    let r = validate_launch(config, req, &mut op, &mut harness, &mut kind, &mut root);
    #[cfg(feature = "test-build")]
    if knobs::validate_only() && r == Reason::Ok {
        log("launch_validated", Reason::Ok, Some(&req.scope));
        respond(conn, Opcode::Launch, Reason::Ok, 0);
        return;
    }
    let mut step = protocol::STEP_NONE;
    let mut err = 0;
    let r = if r == Reason::Ok {
        admit(scopes, &req.scope)
    } else {
        r
    };
    let r = if r == Reason::Ok {
        match (harness, &root) {
            (Some(h), Some(root)) => {
                let v = ValidLaunch {
                    config,
                    req,
                    op: &op,
                    harness: h,
                    root,
                };
                start_session(scopes, conn, &v, &mut step, &mut err)
            }
            _ => Reason::UnknownHarness,
        }
    } else {
        r
    };
    if r != Reason::Ok {
        if step != protocol::STEP_NONE {
            log_step("launch_refused", r, Some(&req.scope), step, err);
        } else {
            log("launch_refused", r, Some(&req.scope));
        }
        respond(conn, Opcode::Launch, r, 0);
    }
}

/// `forward` hands `conn` to the owning monitor, which answers it. It
/// never waits: false when there is no monitor or its socket would
/// block (a wedged monitor) or failed.
fn forward(e: &mut ScopeEntry, conn: RawFd, op: Opcode, grace_ms: u32) -> bool {
    let Some(control) = e.control.as_ref() else {
        return false;
    };
    let mut msg = [0u8; 5];
    msg[0] = if op == Opcode::Alive {
        CTL_ALIVE
    } else {
        CTL_KILL
    };
    msg[1..5].copy_from_slice(&grace_ms.to_be_bytes());
    if send_control(control.as_raw_fd(), &msg, &[conn], 0) {
        return true;
    }
    log("forward_failed", Reason::LaunchFailed, Some(&e.id));
    false
}

fn handle_alive(scopes: &mut Scopes, conn: RawFd, req: &wire::Request) {
    if let Some(i) = scopes.find(&req.scope)
        && forward(&mut scopes.table[i], conn, Opcode::Alive, 0)
    {
        return;
    }
    // Unowned, or its monitor cannot take it: the cgroup answers, so a
    // populated scope is never reported dead.
    match cgroup::scope_populated(&req.scope) {
        Err(_) => respond(conn, Opcode::Alive, Reason::LaunchFailed, 0),
        Ok(p) => respond(conn, Opcode::Alive, Reason::Ok, u8::from(p)),
    }
}

fn handle_kill(scopes: &mut Scopes, conn: RawFd, req: &wire::Request) {
    let mut idx = scopes.find(&req.scope);
    if let Some(i) = idx
        && forward(&mut scopes.table[i], conn, Opcode::Kill, req.grace_ms)
    {
        return;
    }
    if idx.is_none() {
        if !cgroup::scope_exists(&req.scope) {
            respond(conn, Opcode::Kill, Reason::Ok, 0);
            return;
        }
        idx = scopes.fresh(&req.scope);
        let Some(i) = idx else {
            respond(conn, Opcode::Kill, Reason::LaunchFailed, 0);
            return;
        };
        idx = Some(i);
    }
    // Unowned, being cleaned, or owned by a monitor that cannot take the
    // KILL: the scope's one cleaner writes cgroup.kill (with no grace)
    // and this KILL waits on it.
    let i = idx.unwrap_or(0);
    let e = &mut scopes.table[i];
    if !ensure_cleaner(e) || !add_waiter(e, conn) {
        respond(conn, Opcode::Kill, Reason::LaunchFailed, 0);
        if e.control.is_none() && e.cleaner <= 0 {
            drop_scope(e);
        }
    }
}

fn handle_connection(scopes: &mut Scopes, conn: RawFd, buf: &mut [u8]) {
    let Ok(peer) = sockopt::socket_peercred(sys::borrow(conn)) else {
        return;
    };
    if peer.pid.as_raw_nonzero().get() <= 0 {
        return;
    }
    let mut tainted = false;
    let Some(size) = receive_request(conn, buf, &mut tainted) else {
        return;
    };
    let frame = &buf[..size];
    let Some(op) = protocol::header_opcode(frame) else {
        // No usable header: there is no opcode to answer with.
        log("request_dropped", Reason::RequestMalformed, None);
        return;
    };
    let mut config = Config::default();
    if policy::load_config(&mut config) != Reason::Ok {
        log("request_refused", Reason::ConfigInvalid, None);
        respond(conn, op, Reason::ConfigInvalid, 0);
        return;
    }
    let Some(admitted) = policy::runtime_uid(&config) else {
        log("request_refused", Reason::ConfigInvalid, None);
        respond(conn, op, Reason::ConfigInvalid, 0);
        return;
    };
    if peer.uid.as_raw() != admitted {
        log("request_refused", Reason::PeerDenied, None);
        respond(conn, op, Reason::PeerDenied, 0);
        return;
    }
    let req = if tainted {
        None
    } else {
        wire::decode_request(frame).ok()
    };
    let Some(req) = req else {
        log("request_refused", Reason::RequestMalformed, None);
        respond(conn, op, Reason::RequestMalformed, 0);
        return;
    };
    match req.op {
        Opcode::Launch => handle_launch(scopes, conn, &config, &req.launch),
        Opcode::Alive => handle_alive(scopes, conn, &req),
        Opcode::Kill => handle_kill(scopes, conn, &req),
        Opcode::Exit => {}
    }
}

fn listener_from_systemd() -> Option<OwnedFd> {
    let pid = std::env::var_os("LISTEN_PID")?;
    let fds = std::env::var_os("LISTEN_FDS")?;
    let pid: i64 = pid.to_str()?.parse().ok()?;
    let fds: i64 = fds.to_str()?.parse().ok()?;
    if pid != i64::from(rustix::process::getpid().as_raw_nonzero().get()) || fds != 1 {
        return None;
    }
    let sock_type = sockopt::socket_type(sys::borrow(3)).ok()?;
    if sock_type != SocketType::SEQPACKET {
        return None;
    }
    let listener = sys::dupfd_cloexec(3, 3).ok()?;
    sys::close(3);
    sys::unsetenv(c"LISTEN_PID");
    sys::unsetenv(c"LISTEN_FDS");
    sys::unsetenv(c"LISTEN_FDNAMES");
    Some(listener)
}

/// Test builds may bind the socket path from `CHL_TEST_SOCKET` when no
/// socket activation arrived. A production build has no fallback.
#[cfg(not(feature = "test-build"))]
fn test_listener() -> Option<OwnedFd> {
    None
}

#[cfg(feature = "test-build")]
fn test_listener() -> Option<OwnedFd> {
    let path = knobs::socket_path()?;
    let path = std::path::PathBuf::from(path);
    if path.as_os_str().len() >= 108 {
        return None;
    }
    let listener = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .ok()?;
    let _ = unlink(&path);
    let addr = SocketAddrUnix::new(&path).ok()?;
    let ok = bind(&listener, &addr).is_ok()
        && rustix::fs::chmod(&path, Mode::from_bits_retain(0o600)).is_ok()
        && listen(&listener, 64).is_ok();
    if ok { Some(listener) } else { None }
}

/// `landlock_ok` — the start-up check of decision 7: every harness and
/// init scopes itself with Landlock ABI 6, so without it the daemon
/// fails closed rather than fail every launch. A test build may fake
/// the probed version; a no-isolation build checks only then.
fn landlock_ok() -> bool {
    #[cfg(feature = "test-build")]
    {
        if let Some(abi) = knobs::landlock_abi() {
            return abi >= LANDLOCK_MIN_ABI;
        }
        if knobs::no_isolation() {
            return true;
        }
    }
    sys::landlock_abi() >= LANDLOCK_MIN_ABI
}

fn main() -> std::process::ExitCode {
    #[cfg(feature = "test-build")]
    if knobs::no_isolation() && rustix::process::geteuid().is_root() {
        eprintln!("central-harness-launcherd: a no-isolation test build refuses to run as root");
        return std::process::ExitCode::from(1);
    }
    sys::sigaction_handler(libc::SIGTERM, stop_handler as *const () as usize);
    sys::sigaction_handler(libc::SIGINT, stop_handler as *const () as usize);
    sys::sigaction_handler(libc::SIGPIPE, sys::SIG_IGN);

    let mut scopes = Scopes::new();
    let listener = listener_from_systemd().or_else(test_listener);
    let Some(listener) = listener else {
        eprintln!("central-harness-launcherd: no listening socket (socket activation required)");
        return std::process::ExitCode::from(1);
    };
    if !landlock_ok() {
        log("landlock_unavailable", Reason::LaunchFailed, None);
        return std::process::ExitCode::from(1);
    }
    // Decision 12: fail closed without cgroup v2 cgroup.kill; then kill
    // and remove every scope a previous instance left.
    if cgroup::setup().is_err() {
        log("cgroup_unavailable", Reason::LaunchFailed, None);
        return std::process::ExitCode::from(1);
    }
    cgroup::sweep();
    log("started", Reason::Ok, None);

    let mut frame_buf = vec![0u8; wire::MAX_FRAME + 1];
    while !STOPPING.load(Ordering::Relaxed) {
        reap_children(&mut scopes);
        let mut pfds: Vec<rustix::event::PollFd> = Vec::with_capacity(MAX_SCOPES + 1);
        let mut owners: Vec<Option<usize>> = Vec::with_capacity(MAX_SCOPES + 1);
        let mut polled_fds: Vec<RawFd> = Vec::with_capacity(MAX_SCOPES);
        pfds.push(rustix::event::PollFd::new(
            &listener,
            rustix::event::PollFlags::IN,
        ));
        owners.push(None);
        // The control sockets live in the table for the whole loop; a
        // 'static BorrowedFd frees the table for mutable use below.
        for (i, e) in scopes.table.iter().enumerate() {
            if !e.used {
                continue;
            }
            if let Some(c) = &e.control {
                pfds.push(rustix::event::PollFd::from_borrowed_fd(
                    sys::borrow(c.as_raw_fd()),
                    rustix::event::PollFlags::IN,
                ));
                polled_fds.push(c.as_raw_fd());
                owners.push(Some(i));
            }
        }
        let Ok(ready) = rustix::event::poll(&mut pfds, Some(&ms_timespec(100))) else {
            continue;
        };
        if ready == 0 {
            continue;
        }
        for i in 1..pfds.len() {
            if pfds[i].revents().is_empty() {
                continue;
            }
            if let Some(Some(idx)) = owners.get(i).copied() {
                let e = &mut scopes.table[idx];
                let still = e.used
                    && e.control
                        .as_ref()
                        .is_some_and(|c| c.as_raw_fd() == polled_fds[i - 1]);
                if still {
                    handle_control(e);
                }
            }
        }
        if pfds[0].revents().contains(rustix::event::PollFlags::IN)
            && let Ok(conn) = accept_with(&listener, SocketFlags::CLOEXEC)
        {
            handle_connection(&mut scopes, conn.as_raw_fd(), &mut frame_buf);
        }
    }
    // Stopping: every monitor kills its session. Under systemd the
    // control-group kill does the same.
    for e in scopes.table.iter() {
        if e.used && e.monitor > 0 {
            let _ = sys::kill_pid(e.monitor, libc::SIGTERM);
        }
    }
    drop(listener);
    std::process::ExitCode::SUCCESS
}
