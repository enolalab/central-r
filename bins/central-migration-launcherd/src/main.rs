//! `central-migration-launcherd` — a faithful Rust port of upstream
//! `cmd/central-migration-launcherd/main.c`.
//!
//! The daemon is the only process allowed to create a
//! `central_migration`-identity operator (ADR 0011): it listens on a
//! root-owned `SOCK_SEQPACKET` socket, admits only the configured
//! peer uid over `SO_PEERCRED`, and runs exactly three operations on
//! the `CML1` wire —
//!
//! - **launch**: `fork`+`execve` of the fixed migration binary with
//!   the fixed argv (`<command> <op-uuid>`), a fresh evidence pipe on
//!   FD3, an `ALLOW_SEALING` `0400` memfd the broker fills as the FD4
//!   credential destination, a diagnostics pipe on FD5, stdio to
//!   `/dev/null`, and the identity drop to `986:986`; the caller gets
//!   a 28-byte reply plus the child's pidfd over `SCM_RIGHTS`.
//! - **commit**: write the broker-issued 16-byte evidence UUID to the
//!   record's evidence write end and close it — idempotent only for
//!   the same evidence id.
//! - **abort**: SIGKILL + reap an uncommitted launch.
//!
//! Up to `MAX_LAUNCHES` records are tracked; each holds the permit
//! flock pair for the launch's whole life. An uncommitted launch past
//! its deadline is killed and reaped, as is every tracked launch at
//! shutdown.

mod knobs;
mod policy;
mod protocol;
mod sys;

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{MemfdFlags, Mode};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use rustix::pipe::PipeFlags;

use central_adapter_linux::sys::peercred::peercred;
use central_adapter_linux::sys::scm_rights;

/// `MAX_LAUNCHES`.
const MAX_LAUNCHES: usize = 32;
/// Upstream's `listen(listener, 16)` backlog.
const LISTEN_BACKLOG: i32 = 16;
/// The main-loop poll quantum — also the reaping cadence.
const LOOP_POLL_MS: i64 = 250;
/// `CONNECTION_RECEIVE_TIMEOUT_MS`.
const REQUEST_TIMEOUT_MS: i64 = 100;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn ms_timespec(ms: i64) -> Timespec {
    Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    }
}

fn poll_in(fd: impl AsFd, ms: i64) -> bool {
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    match rustix::event::poll(&mut fds, Some(&ms_timespec(ms))) {
        Ok(n) => n > 0 && fds[0].revents().contains(PollFlags::IN),
        Err(_) => false,
    }
}

/// `struct launch_record` — the fields a tracked launch carries.
struct Record {
    pid: i32,
    launch_id: [u8; 16],
    /// `evidence_fd` — the parent's write end of the FD3 pipe;
    /// `None` once commit has written+closed it.
    evidence_fd: Option<OwnedFd>,
    pidfd: OwnedFd,
    /// `permit_fd_a`/`permit_fd_b` — held (and locked) for the
    /// launch's life; the field is read only by `Drop`.
    #[allow(dead_code)]
    permits: policy::PermitHold,
    deadline: Instant,
    committed: bool,
    /// `evidence_id` — set on commit; the idempotence comparison.
    evidence_id: [u8; 16],
}

/// `uuid_string` — lowercase hyphenated UUID text.
fn uuid_text(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, v) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        out.push_str(&format!("{v:02x}"));
    }
    out
}

/// `random_uuid` — 16 `getrandom` bytes, non-nil, version/variant
/// bits set the way upstream sets them (`|0x70` / `|0x80`).
fn random_uuid() -> Result<[u8; 16], rustix::io::Errno> {
    let mut b = [0u8; 16];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())?;
    if b.iter().all(|v| *v == 0) {
        return Err(rustix::io::Errno::INVAL);
    }
    b[6] = (b[6] & 0x0f) | 0x70;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(b)
}

/// `spawn_child` — the launch itself. On success returns the child's
/// pid and the parent's evidence write end; the caller opens the
/// pidfd and fills the record. Every error path closes the fds this
/// call opened and reaps the child when one exists.
fn spawn_launch(
    migrate_path: &CString,
    command: &'static str,
    operation_id: &[u8; 16],
    permits: &policy::PermitHold,
    uid: u32,
    gid: u32,
    test_peer: bool,
) -> Result<(i32, OwnedFd), String> {
    let (ev_read, ev_write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)
        .map_err(|e| format!("launch: evidence pipe: {e}"))?;
    let (err_read, err_write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)
        .map_err(|e| format!("launch: errors pipe: {e}"))?;
    // `central-migration-credential` — the FD4 destination the broker
    // fills through the B05 descriptor transport; `ALLOW_SEALING` so
    // the broker's `F_ADD_SEALS` can freeze it.
    let credential = rustix::fs::memfd_create(
        "central-migration-credential",
        MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
    )
    .map_err(|e| format!("launch: credential memfd: {e}"))?;
    rustix::fs::fchmod(&credential, Mode::from_raw_mode(0o400))
        .map_err(|e| format!("launch: credential chmod: {e}"))?;

    // argv/envp are built here but consumed only in the child.
    let op_text = match CString::new(uuid_text(operation_id)) {
        Ok(v) => v,
        Err(_) => return Err("launch: operation id".to_owned()),
    };
    let cmd = match CString::new(command) {
        Ok(v) => v,
        Err(_) => return Err("launch: command".to_owned()),
    };
    let argv_ptrs: [*const libc::c_char; 4] = [
        migrate_path.as_ptr(),
        cmd.as_ptr(),
        op_text.as_ptr(),
        std::ptr::null(),
    ];
    let env0 = c"PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    let env1 = c"LANG=C";
    let env2 = c"LC_ALL=C";
    let envp: [*const libc::c_char; 4] = [
        env0.as_ptr(),
        env1.as_ptr(),
        env2.as_ptr(),
        std::ptr::null(),
    ];

    let ev_read_raw = ev_read.as_raw_fd();
    let ev_write_raw = ev_write.as_raw_fd();
    let err_read_raw = err_read.as_raw_fd();
    let err_write_raw = err_write.as_raw_fd();
    let cred_raw = credential.as_raw_fd();
    let (pa, pb) = permits.raw_fds();

    match sys::fork() {
        Err(e) => Err(format!("launch: fork: {e}")),
        Ok(sys::Fork::Child) => {
            // Pre-exec: only syscall shuffles, ending in execve or
            // _exit — no Rust-managed state.
            sys::close(pa);
            sys::close(pb);
            sys::close(err_read_raw);
            sys::close(ev_write_raw);
            let mut error_fd = err_write_raw;
            let result = (|| -> Result<(), rustix::io::Errno> {
                // FD4 is the credential descriptor — it must survive
                // exec, so diagnostics live on FD5 (upstream's comment
                // warns FD4-for-diagnostics silently replaced the
                // credential descriptor).
                if cred_raw != 4 {
                    sys::dup3(cred_raw, 4, false)?;
                    sys::close(cred_raw);
                } else {
                    sys::clear_cloexec(4)?;
                }
                if ev_read_raw != 3 {
                    sys::dup3(ev_read_raw, 3, false)?;
                    sys::close(ev_read_raw);
                } else {
                    sys::clear_cloexec(3)?;
                }
                if error_fd != 5 {
                    sys::dup3(error_fd, 5, true)?;
                    sys::close(error_fd);
                    error_fd = 5;
                }
                sys::close_from(6);
                let null_fd = sys::open_rdwr_cloexec(c"/dev/null")?;
                sys::dup2(null_fd, 0)?;
                sys::dup2(null_fd, 1)?;
                sys::dup2(null_fd, 2)?;
                if null_fd > 2 {
                    sys::close(null_fd);
                }
                if !test_peer {
                    sys::set_groups_none()?;
                }
                sys::drop_to(uid, gid)?;
                Err(sys::execve(migrate_path, &argv_ptrs, &envp))
            })();
            if let Err(e) = result {
                let code = e.raw_os_error();
                let _ = sys::write_raw(error_fd, &code.to_ne_bytes());
            }
            sys::exit(127);
        }
        Ok(sys::Fork::Parent(pid)) => {
            // Take ownership out of the descriptors before the manual
            // closes — closing a fd an `OwnedFd` still owns and then
            // dropping it is a double-close (the I/O-safety runtime
            // aborts on it).
            sys::close(ev_read.into_raw_fd());
            sys::close(credential.into_raw_fd());
            sys::close(err_write.into_raw_fd());
            // `read_pipe_error` — one `read` for the child's errno;
            // EOF is exec success.
            let mut report = [0u8; 4];
            let mut got = 0usize;
            loop {
                match rustix::io::read(&err_read, &mut report[got..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        got += n;
                        if got >= report.len() {
                            break;
                        }
                    }
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => {
                        got = report.len();
                        break;
                    }
                }
            }
            drop(err_read);
            if got != 0 {
                let _ = sys::wait_pid(pid, false);
                return Err("launch: child setup failed".to_owned());
            }
            Ok((pid, ev_write))
        }
    }
}

fn find_record<'a>(records: &'a mut [Record], launch_id: &[u8; 16]) -> Option<&'a mut Record> {
    records.iter_mut().find(|r| &r.launch_id == launch_id)
}

/// `kill_record` — SIGKILL through the pidfd (falling back to
/// `kill(2)`), blocking `waitpid`, then the record's descriptors drop
/// (evidence write end, pidfd, permit hold).
fn kill_record(rec: &Record) {
    if sys::pidfd_send_signal(rec.pidfd.as_raw_fd(), libc::SIGKILL).is_err() {
        let _ = sys::kill_pid(rec.pid, libc::SIGKILL);
    }
    let _ = sys::wait_pid(rec.pid, false);
}

/// `reap_records` — drop every exited record; kill every uncommitted
/// launch whose monotonic deadline has passed.
fn reap_records(records: &mut Vec<Record>) {
    let now = Instant::now();
    let mut i = 0;
    while i < records.len() {
        let reaped = matches!(sys::wait_pid(records[i].pid, true), Ok(Some(_)));
        let expired = !records[i].committed && now >= records[i].deadline;
        if reaped || expired {
            if !reaped {
                kill_record(&records[i]);
            }
            records.swap_remove(i);
        } else {
            i += 1;
        }
    }
}

fn send_frame(conn: &OwnedFd, frame: &[u8]) {
    let _ = rustix::net::send(conn, frame, SendFlags::NOSIGNAL);
}

fn send_denied(conn: &OwnedFd, opcode: u8) {
    send_frame(
        conn,
        &protocol::encode_common(opcode, protocol::STATUS_DENIED),
    );
}

/// `handle_connection` — peer-credential check, a short request
/// window, one frame, one response, close.
fn handle_conn(conn: OwnedFd, records: &mut Vec<Record>, cfg: &Config) {
    let admitted = match peercred(&conn) {
        Ok(peer) => peer.pid.as_raw_pid() > 0 && peer.uid.as_raw() == cfg.required_peer_uid,
        Err(_) => false,
    };
    if !admitted {
        return; // a refused peer gets no bytes.
    }
    if !poll_in(&conn, REQUEST_TIMEOUT_MS) {
        return;
    }
    let mut buf = [0u8; protocol::REQUEST_BUFFER];
    let n = match rustix::net::recv(&conn, &mut buf, RecvFlags::DONTWAIT) {
        Ok((n, _)) => n,
        Err(_) => return,
    };
    match protocol::decode(&buf[..n]) {
        protocol::Outcome::Silent => {}
        protocol::Outcome::Denied(opcode) => send_denied(&conn, opcode),
        protocol::Outcome::Request(req) => handle_request(&conn, records, cfg, req),
    }
}

fn handle_request(conn: &OwnedFd, records: &mut Vec<Record>, cfg: &Config, req: protocol::Request) {
    match req {
        protocol::Request::Launch {
            command,
            operation_id,
        } => {
            let Some(command) = protocol::COMMANDS.get(command as usize).copied() else {
                send_denied(conn, protocol::OP_LAUNCH);
                return;
            };
            if records.len() >= MAX_LAUNCHES || command.is_empty() {
                send_denied(conn, protocol::OP_LAUNCH);
                return;
            }
            // Upstream acquires the permit pair per launch, before
            // fork — the record holds the locks for the launch's life.
            let permits = match cfg.permits.acquire() {
                Ok(p) => p,
                Err(why) => {
                    eprintln!("central-migration-launcherd: {why}");
                    send_denied(conn, protocol::OP_LAUNCH);
                    return;
                }
            };
            let launch = spawn_launch(
                &cfg.migrate_path,
                command,
                &operation_id,
                &permits,
                cfg.migrate_uid,
                cfg.migrate_gid,
                cfg.test_peer,
            );
            let launch_id = random_uuid();
            match (launch, launch_id) {
                (Ok((pid, evidence_fd)), Ok(launch_id)) => match sys::pidfd_open(pid) {
                    Ok(pidfd) => {
                        let frame = protocol::encode_launch(protocol::STATUS_OK, pid, &launch_id);
                        let _ = scm_rights::send(conn, &frame, &[pidfd.as_fd()]);
                        records.push(Record {
                            pid,
                            launch_id,
                            evidence_fd: Some(evidence_fd),
                            pidfd,
                            permits,
                            deadline: Instant::now() + Duration::from_secs(cfg.launch_timeout_s),
                            committed: false,
                            evidence_id: [0u8; 16],
                        });
                    }
                    Err(e) => {
                        eprintln!("central-migration-launcherd: launch: pidfd_open: {e}");
                        let _ = sys::kill_pid(pid, libc::SIGKILL);
                        let _ = sys::wait_pid(pid, false);
                        send_denied(conn, protocol::OP_LAUNCH);
                    }
                },
                (Err(why), _) => {
                    eprintln!("central-migration-launcherd: {why}");
                    send_denied(conn, protocol::OP_LAUNCH);
                }
                (Ok((pid, _ev)), Err(_)) => {
                    let _ = sys::kill_pid(pid, libc::SIGKILL);
                    let _ = sys::wait_pid(pid, false);
                    send_denied(conn, protocol::OP_LAUNCH);
                }
            }
        }
        protocol::Request::Commit {
            launch_id,
            evidence_id,
        } => {
            let status = match find_record(records, &launch_id) {
                None => protocol::STATUS_DENIED,
                Some(rec) if rec.committed => {
                    // Idempotent for the exact broker evidence — a
                    // lost client ACK may retry, a rebind may not.
                    if rec.evidence_id == evidence_id {
                        protocol::STATUS_OK
                    } else {
                        protocol::STATUS_DENIED
                    }
                }
                Some(rec) => match write_evidence(rec, &evidence_id) {
                    Ok(()) => {
                        rec.committed = true;
                        rec.evidence_id = evidence_id;
                        protocol::STATUS_OK
                    }
                    Err(()) => protocol::STATUS_DENIED,
                },
            };
            send_frame(conn, &protocol::encode_common(protocol::OP_COMMIT, status));
        }
        protocol::Request::Abort { launch_id } => {
            let mut status = protocol::STATUS_DENIED;
            let idx = records.iter().position(|r| r.launch_id == launch_id);
            if let Some(idx) = idx
                && !records[idx].committed
            {
                kill_record(&records[idx]);
                records.remove(idx);
                status = protocol::STATUS_OK;
            }
            send_frame(conn, &protocol::encode_common(protocol::OP_ABORT, status));
        }
    }
}

/// The commit write — exactly 16 evidence bytes to the record's
/// evidence write end, then the descriptor closes (upstream sets
/// `evidence_fd = -1` on every path, so a failed commit can never be
/// retried against the same record).
fn write_evidence(rec: &mut Record, evidence_id: &[u8; 16]) -> Result<(), ()> {
    let Some(fd) = rec.evidence_fd.take() else {
        return Err(());
    };
    let mut written = 0usize;
    while written < 16 {
        match rustix::io::write(&fd, &evidence_id[written..]) {
            Ok(n) if n > 0 => written += n,
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => break,
        }
    }
    drop(fd);
    if written == 16 { Ok(()) } else { Err(()) }
}

struct Config {
    socket_path: String,
    migrate_path: CString,
    migrate_uid: u32,
    migrate_gid: u32,
    required_peer_uid: u32,
    launch_timeout_s: u64,
    permits: policy::PermitGate,
    test_peer: bool,
}

#[cfg(not(feature = "test-build"))]
fn config() -> Result<Config, String> {
    let migrate_path = sys::bytes_cstring(knobs::MIGRATE_PATH.as_bytes())
        .ok_or_else(|| "migrate path".to_owned())?;
    Ok(Config {
        socket_path: knobs::SOCKET_PATH.to_owned(),
        migrate_path,
        migrate_uid: knobs::MIGRATE_UID,
        migrate_gid: knobs::MIGRATE_GID,
        required_peer_uid: knobs::REQUIRED_PEER_UID,
        launch_timeout_s: knobs::LAUNCH_TIMEOUT_S,
        permits: policy::PermitGate::initialize(
            [
                knobs::PERMIT_PATHS[0].to_owned(),
                knobs::PERMIT_PATHS[1].to_owned(),
            ],
            knobs::PERMIT_UID,
            knobs::PERMIT_GID,
        )?,
        test_peer: false,
    })
}

#[cfg(feature = "test-build")]
fn config() -> Result<Config, String> {
    let migrate_path = sys::bytes_cstring(knobs::migrate_path().as_bytes())
        .ok_or_else(|| "migrate path".to_owned())?;
    Ok(Config {
        socket_path: knobs::socket_path(),
        migrate_path,
        migrate_uid: knobs::migrate_uid(),
        migrate_gid: knobs::migrate_gid(),
        required_peer_uid: knobs::required_peer_uid(),
        launch_timeout_s: knobs::launch_timeout_s(),
        permits: policy::PermitGate::initialize(
            knobs::permit_paths(),
            knobs::permit_uid(),
            knobs::permit_gid(),
        )?,
        test_peer: knobs::test_peer_build(),
    })
}

/// `listener_from_systemd` — `LISTEN_PID == getpid()` and
/// `LISTEN_FDS == 1` adopt fd 3 via `F_DUPFD_CLOEXEC` to fd ≥5.
fn listener_from_systemd() -> Option<OwnedFd> {
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        == Some(rustix::process::getpid().as_raw_pid());
    let fds_ok = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        == Some(1);
    if !pid_ok || !fds_ok {
        return None;
    }
    let fd = sys::dupfd_cloexec(3, 5).ok()?;
    sys::close(3);
    Some(fd)
}

/// `bind_listener` — systemd activation first, then bind+chmod+listen
/// on the configured path.
fn bind_listener(path: &str) -> Result<OwnedFd, String> {
    if let Some(fd) = listener_from_systemd() {
        return Ok(fd);
    }
    let sock = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| format!("socket: {e}"))?;
    let _ = rustix::fs::unlink(path);
    let addr = rustix::net::SocketAddrUnix::new(path).map_err(|e| format!("sockaddr: {e}"))?;
    rustix::net::bind(&sock, &addr).map_err(|e| format!("bind {path}: {e}"))?;
    rustix::fs::chmod(path, Mode::from_raw_mode(0o600))
        .map_err(|e| format!("chmod {path}: {e}"))?;
    rustix::net::listen(&sock, LISTEN_BACKLOG).map_err(|e| format!("listen: {e}"))?;
    Ok(sock)
}

fn run() -> Result<u8, String> {
    let cfg = config()?; // also performs `initialize_permits`
    sys::sigaction_handler(libc::SIGTERM, on_stop as *const () as usize);
    sys::sigaction_handler(libc::SIGINT, on_stop as *const () as usize);
    sys::sigaction_handler(libc::SIGPIPE, sys::SIG_IGN);

    let listener = bind_listener(&cfg.socket_path)?;
    let mut records: Vec<Record> = Vec::new();
    while !STOP.load(Ordering::SeqCst) {
        reap_records(&mut records);
        if !poll_in(&listener, LOOP_POLL_MS) {
            continue;
        }
        match rustix::net::accept_with(&listener, SocketFlags::CLOEXEC) {
            Ok(conn) => handle_conn(conn, &mut records, &cfg),
            Err(_) => continue,
        }
    }
    for rec in &records {
        kill_record(rec);
    }
    Ok(0)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(why) => {
            eprintln!("central-migration-launcherd: {why}");
            std::process::ExitCode::from(1)
        }
    }
}
