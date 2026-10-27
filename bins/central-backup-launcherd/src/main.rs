//! `central-backup-launcherd` — the backup/restore launch boundary.
//! Root-only `SOCK_SEQPACKET` daemon (`/run/central/backup-launcher.sock`)
//! that runs `central-backup` on a caller-supplied repository
//! descriptor under the fixed backup identity, keeps an exclusive
//! hold on the offline-mutation permit pair for the launch's life,
//! retains the worker's handed-off target lock, and speaks upstream's
//! `CBL1`/`CBW1` protocol byte-for-byte — every refusal is a
//! locator-free denial frame (or the silent close upstream chose).
//!
//! The crate's modules keep to the deployment's layering rule
//! (workflow §5.2): [`protocol`] is the wire codec, [`policy`] the
//! admission gates, [`session`] the launch/monitor record state
//! machine, and [`sys`] the only `unsafe` site.

mod knobs;
mod policy;
mod protocol;
mod session;
mod sys;

use std::os::fd::{AsFd, AsRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use central_adapter_linux::sys::peercred::peercred;
use central_adapter_linux::sys::scm_rights;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::Mode;
use rustix::net::{
    AddressFamily, SendFlags, SocketFlags, SocketType, accept_with, bind, listen, socket_with,
};

use session::Record;

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

/// `handle_connection`'s request window — `poll(POLLIN,
/// CONNECTION_RECEIVE_TIMEOUT_MS)` retried on `EINTR` while the
/// daemon isn't stopping.
fn poll_request(conn: &OwnedFd, timeout_ms: i64) -> bool {
    loop {
        let mut fds = [PollFd::new(conn, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&ms_timespec(timeout_ms))) {
            Ok(n) => return n > 0 && fds[0].revents().contains(PollFlags::IN),
            Err(rustix::io::Errno::INTR) => {
                if STOP.load(Ordering::SeqCst) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
}

fn send_frame(conn: &OwnedFd, frame: &[u8]) {
    let _ = rustix::net::send(conn, frame, SendFlags::NOSIGNAL);
}

/// `send_response(connection, OP_LAUNCH, STATUS_DENIED, 0, NULL, -1)`
/// — the 28-byte launch reply with mode 0, pid 0, a nil id, and no
/// descriptor.
fn send_launch_denied(conn: &OwnedFd) {
    send_frame(
        conn,
        &protocol::encode_launch(protocol::STATUS_DENIED, 0, &[0u8; 16], 0),
    );
}

struct Config {
    socket_path: String,
    spec: session::SpawnSpec,
    required_peer_uid: u32,
    launch_timeout_s: u64,
    result_retention_s: u64,
    backup_deadline_s: u64,
    probe_deadline_s: u64,
    receive_timeout_ms: i64,
    permits: policy::PermitGate,
}

#[cfg(not(feature = "test-build"))]
fn config() -> Result<Config, String> {
    let backup_path = sys::bytes_cstring(knobs::BACKUP_PATH.as_bytes())
        .ok_or_else(|| "backup path".to_owned())?;
    Ok(Config {
        socket_path: knobs::SOCKET_PATH.to_owned(),
        spec: session::SpawnSpec {
            backup_path,
            backup_uid: knobs::BACKUP_UID,
            backup_gid: knobs::BACKUP_GID,
            test_peer: false,
            retained_port: knobs::RETAINED_PEER_PORT,
        },
        required_peer_uid: knobs::REQUIRED_PEER_UID,
        launch_timeout_s: knobs::LAUNCH_TIMEOUT_S,
        result_retention_s: knobs::RESULT_RETENTION_S,
        backup_deadline_s: knobs::BACKUP_DEADLINE_S,
        probe_deadline_s: knobs::PROBE_DEADLINE_S,
        receive_timeout_ms: knobs::RECEIVE_TIMEOUT_MS,
        permits: policy::PermitGate::initialize(
            [
                knobs::PERMIT_PATHS[0].to_owned(),
                knobs::PERMIT_PATHS[1].to_owned(),
            ],
            knobs::PERMIT_UID,
            knobs::PERMIT_GID,
        )?,
    })
}

#[cfg(feature = "test-build")]
fn config() -> Result<Config, String> {
    let backup_path = sys::bytes_cstring(knobs::backup_path().as_bytes())
        .ok_or_else(|| "backup path".to_owned())?;
    Ok(Config {
        socket_path: knobs::socket_path(),
        spec: session::SpawnSpec {
            backup_path,
            backup_uid: knobs::backup_uid(),
            backup_gid: knobs::backup_gid(),
            test_peer: knobs::test_peer_build(),
            retained_port: knobs::RETAINED_PEER_PORT,
        },
        required_peer_uid: knobs::required_peer_uid(),
        launch_timeout_s: knobs::launch_timeout_s(),
        result_retention_s: knobs::result_retention_s(),
        backup_deadline_s: knobs::backup_deadline_s(),
        probe_deadline_s: knobs::probe_deadline_s(),
        receive_timeout_ms: knobs::receive_timeout_ms(),
        permits: policy::PermitGate::initialize(
            knobs::permit_paths(),
            knobs::permit_uid(),
            knobs::permit_gid(),
        )?,
    })
}

/// `listener_from_systemd` — `LISTEN_PID == getpid()`,
/// `LISTEN_FDS == 1`, the fd 3 socket is `SOCK_SEQPACKET`, adopted via
/// `F_DUPFD_CLOEXEC` (upstream's minimum is 6).
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
    // The dup doubles as the fd-3-liveness probe: it fails `EBADF`
    // exactly like upstream's `getsockopt` would.
    let fd = sys::dupfd_cloexec(3, 6).ok()?;
    let ty = rustix::net::sockopt::socket_type(&fd).ok()?;
    if ty != SocketType::SEQPACKET {
        return None;
    }
    sys::close(3);
    Some(fd)
}

/// `bind_listener` — systemd activation first, then
/// socket/unlink/bind/chmod 0600/listen(16) on the configured path.
fn bind_listener(path: &str) -> Result<OwnedFd, String> {
    if let Some(fd) = listener_from_systemd() {
        return Ok(fd);
    }
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| format!("socket: {e}"))?;
    let _ = rustix::fs::unlink(path);
    let addr = rustix::net::SocketAddrUnix::new(path).map_err(|e| format!("sockaddr: {e}"))?;
    bind(&sock, &addr).map_err(|e| format!("bind {path}: {e}"))?;
    rustix::fs::chmod(path, Mode::from_raw_mode(0o600))
        .map_err(|e| format!("chmod {path}: {e}"))?;
    listen(&sock, 16).map_err(|e| format!("listen: {e}"))?;
    Ok(sock)
}

/// `handle_connection` — `SO_PEERCRED` before reading a byte; a short
/// request window; one frame; the opcode ladder's response. The
/// connection is closed on return unless an OP_WAIT stored it as a
/// record's waiter.
fn handle_conn(conn: OwnedFd, records: &mut Vec<Record>, cfg: &Config) {
    let admitted = match peercred(&conn) {
        Ok(peer) => peer.pid.as_raw_pid() > 0 && peer.uid.as_raw() == cfg.required_peer_uid,
        Err(_) => false,
    };
    if !admitted {
        return; // a refused peer gets no bytes.
    }
    if !poll_request(&conn, cfg.receive_timeout_ms) {
        return;
    }
    let packet = match session::recv_packet(&conn) {
        Ok(p) => p,
        Err(()) => return,
    };
    match protocol::decode(&packet.frame[..packet.len], packet.fds.len()) {
        protocol::Outcome::Silent => {}
        protocol::Outcome::LaunchDenied => send_launch_denied(&conn),
        protocol::Outcome::Request(protocol::Request::Launch { mode, operation_id }) => {
            handle_launch(conn, records, cfg, packet.fds, mode, operation_id)
        }
        protocol::Outcome::Request(req) => handle_request(conn, records, req),
    }
}

/// The LAUNCH branch — repository-fd validation, a free slot, the
/// permit pair, `spawn_supervised_child`, pidfds, and the response
/// carrying the worker's pidfd.
fn handle_launch(
    conn: OwnedFd,
    records: &mut Vec<Record>,
    cfg: &Config,
    mut fds: Vec<OwnedFd>,
    mode: u8,
    operation_id: [u8; 16],
) {
    let Some(repository_fd) = fds.pop() else {
        send_launch_denied(&conn);
        return;
    };
    let repo_raw = repository_fd.as_raw_fd();
    if policy::validate_repository_fd(&repository_fd, cfg.spec.backup_uid, cfg.spec.backup_gid)
        .is_err()
        || !session::ensure_slot(records)
    {
        send_launch_denied(&conn);
        return;
    }
    let permits = match cfg.permits.acquire() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("central-backup-launcherd: {why}");
            send_launch_denied(&conn);
            return;
        }
    };
    let spawned =
        session::spawn_supervised(mode, &operation_id, repo_raw, permits.raw_fds(), &cfg.spec);
    drop(repository_fd); // `close_received_fds` — the monitor owns it now.
    let spawned = match spawned {
        Ok(s) => s,
        Err(e) => {
            eprintln!("central-backup-launcherd: launch: spawn: {e}");
            send_launch_denied(&conn);
            return;
        }
    };
    let worker_pidfd = session_pidfd(spawned.worker_pid);
    let monitor_pidfd = session_pidfd(spawned.monitor_pid);
    let launch_id = session::random_uuid();
    let (worker_pidfd, monitor_pidfd, launch_id) = match (worker_pidfd, monitor_pidfd, launch_id) {
        (Ok(a), Ok(b), Ok(id)) => (a, b, id),
        _ => {
            // `terminate_record` + `clear_record` — fill the record,
            // abort it through the monitor, release the permits.
            let mut record =
                Record::new(mode, operation_id, spawned, permits, None, None, [0u8; 16]);
            record.terminate(true);
            send_launch_denied(&conn);
            return;
        }
    };
    let worker_pid = spawned.worker_pid;
    let now = Instant::now();
    let mut record = Record::new(
        mode,
        operation_id,
        spawned,
        permits,
        Some(worker_pidfd),
        Some(monitor_pidfd),
        launch_id,
    );
    record.deadline = now + Duration::from_secs(cfg.launch_timeout_s);
    record.hard_deadline = now
        + Duration::from_secs(if mode == protocol::MODE_THROUGHPUT_PROBE {
            cfg.probe_deadline_s
        } else {
            cfg.backup_deadline_s
        });
    records.push(record);
    // `send_launch_response(... STATUS_OK, pid, id, child_pidfd, mode)`
    // — the worker's pidfd over SCM_RIGHTS.
    let frame = protocol::encode_launch(protocol::STATUS_OK, worker_pid, &launch_id, mode);
    let pidfd = records.last().and_then(|r| r.pidfd.as_ref());
    match pidfd {
        Some(fd) => {
            let _ = scm_rights::send(&conn, &frame, &[fd.as_fd()]);
        }
        None => {
            send_frame(&conn, &frame);
        }
    }
}

/// `open_pidfd` — a pidfd on `pid` (CLOEXEC applied by session).
fn session_pidfd(pid: i32) -> Result<OwnedFd, rustix::io::Errno> {
    if pid <= 0 {
        return Err(rustix::io::Errno::INVAL);
    }
    let fd = sys::pidfd_open(pid)?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(fd)
}

/// The non-launch opcode ladder — `commit`/`abort`/`wait`/
/// `assert-retained`/`release`/`census`, upstream's deny semantics
/// verbatim.
fn handle_request(conn: OwnedFd, records: &mut [Record], req: protocol::Request) {
    match req {
        protocol::Request::Commit {
            launch_id,
            evidence_id,
        } => {
            let status = match session::find_record(records, &launch_id) {
                None => protocol::STATUS_DENIED,
                Some(i) if records[i].aborted => protocol::STATUS_DENIED,
                Some(i) if records[i].committed => {
                    // Idempotent for the exact broker evidence — a lost
                    // ACK may retry; a different id may not rebind.
                    if records[i].evidence_id == evidence_id {
                        protocol::STATUS_OK
                    } else {
                        protocol::STATUS_DENIED
                    }
                }
                Some(i) if records[i].finished || records[i].evidence_fd.is_none() => {
                    protocol::STATUS_DENIED
                }
                Some(i) => match write_evidence(&mut records[i], &evidence_id) {
                    Ok(()) => {
                        records[i].committed = true;
                        records[i].evidence_id = evidence_id;
                        protocol::STATUS_OK
                    }
                    Err(()) => {
                        records[i].terminate(true);
                        protocol::STATUS_DENIED
                    }
                },
            };
            send_frame(&conn, &protocol::encode_common(protocol::OP_COMMIT, status));
        }
        protocol::Request::Abort { launch_id } => {
            // SC-DEF-38: an id this daemon no longer tracks has nothing
            // left to abort — that is the state asked for: OK, never a
            // denial.
            if let Some(i) = session::find_record(records, &launch_id)
                && !records[i].aborted
            {
                records[i].terminate(true);
            }
            send_frame(
                &conn,
                &protocol::encode_common(protocol::OP_ABORT, protocol::STATUS_OK),
            );
        }
        protocol::Request::Wait { launch_id } => {
            let Some(i) = session::find_record(records, &launch_id) else {
                send_frame(
                    &conn,
                    &protocol::encode_wait(protocol::STATUS_DENIED, 0, 0, 0, None),
                );
                return;
            };
            let rec = &mut records[i];
            if !rec.committed || rec.aborted || rec.waiter.is_some() {
                send_frame(
                    &conn,
                    &protocol::encode_wait(protocol::STATUS_DENIED, 0, 0, 0, None),
                );
            } else if rec.worker_finished {
                let success_ready =
                    rec.worker_outcome != protocol::WORKER_SUCCEEDED || rec.retained;
                if rec.reap_proven && success_ready {
                    let proof = if rec.worker_outcome == protocol::WORKER_SUCCEEDED && rec.retained
                    {
                        Some(&rec.target_lock_proof)
                    } else {
                        None
                    };
                    send_frame(
                        &conn,
                        &protocol::encode_wait(
                            protocol::STATUS_OK,
                            rec.worker_outcome,
                            rec.exit_code,
                            rec.signal_number,
                            proof,
                        ),
                    );
                } else {
                    send_frame(
                        &conn,
                        &protocol::encode_wait(protocol::STATUS_DENIED, 0, 0, 0, None),
                    );
                }
            } else {
                // The connection becomes the launch's wait-response
                // channel; the record owns it until `notify_waiter`.
                rec.waiter = Some(conn);
            }
        }
        protocol::Request::AssertRetained { launch_id } => {
            let mut proof = [0u8; 32];
            let can_assert = match session::find_record(records, &launch_id) {
                Some(i) => {
                    let r = &records[i];
                    protocol::valid_mode(r.mode)
                        && r.worker_finished
                        && r.reap_proven
                        && r.retained
                        && !r.finished
                        && !r.aborted
                        && !protocol::zero_digest(&r.target_lock_proof)
                }
                None => false,
            };
            let ok = can_assert
                && match session::find_record(records, &launch_id) {
                    Some(i) => match records[i].assert_retained(&mut proof) {
                        Ok(()) => true,
                        Err(()) => {
                            records[i].terminate(false);
                            false
                        }
                    },
                    None => false,
                };
            if ok {
                send_frame(
                    &conn,
                    &protocol::encode_retained(protocol::STATUS_OK, Some(&proof)),
                );
            } else {
                send_frame(
                    &conn,
                    &protocol::encode_retained(protocol::STATUS_DENIED, None),
                );
            }
        }
        protocol::Request::Release { launch_id } => {
            let idx = session::find_record(records, &launch_id);
            let released = match idx {
                Some(i) => {
                    let r = &mut records[i];
                    protocol::valid_mode(r.mode)
                        && !r.aborted
                        && (r.released || r.release().is_ok())
                }
                None => false,
            };
            if !released && let Some(i) = idx {
                let r = &mut records[i];
                if protocol::valid_mode(r.mode) && !r.finished {
                    r.terminate(false);
                }
            }
            send_frame(
                &conn,
                &protocol::encode_common(
                    protocol::OP_RELEASE,
                    if released {
                        protocol::STATUS_OK
                    } else {
                        protocol::STATUS_DENIED
                    },
                ),
            );
        }
        protocol::Request::Census { launch_id } => {
            // The named launch excludes itself; an unknown id excludes
            // nothing — census never denies.
            let excluded = session::find_record(records, &launch_id);
            let mut live_processes = 0u32;
            let mut held_permits = 0u32;
            for (i, r) in records.iter().enumerate() {
                if Some(i) == excluded {
                    continue;
                }
                if !r.finished {
                    live_processes += 1;
                }
                if r.permits.is_some() {
                    held_permits += 1;
                }
            }
            send_frame(
                &conn,
                &protocol::encode_census(protocol::STATUS_OK, live_processes, held_permits),
            );
        }
        // `decode` routes launches to `handle_launch`; none reach here.
        protocol::Request::Launch { .. } => {}
    }
}

/// The commit write — exactly 16 evidence bytes to the record's
/// evidence write end, then the descriptor is closed and its close
/// result checked (upstream `close_result != 0` denies). A failed
/// commit can never be retried against the same record.
fn write_evidence(rec: &mut Record, evidence_id: &[u8; 16]) -> Result<(), ()> {
    let Some(fd) = rec.evidence_fd.take() else {
        return Err(());
    };
    let raw = fd.into_raw_fd();
    let mut written = 0usize;
    while written < 16 {
        match rustix::io::write(sys::borrow(raw), &evidence_id[written..]) {
            Ok(n) if n > 0 => written += n,
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => break,
        }
    }
    let closed = sys::close_checked(raw);
    if written == 16 && closed.is_ok() {
        Ok(())
    } else {
        Err(())
    }
}

fn run() -> Result<u8, String> {
    sys::sigaction_handler(libc::SIGTERM, on_stop as *const () as usize);
    sys::sigaction_handler(libc::SIGINT, on_stop as *const () as usize);
    sys::sigaction_handler(libc::SIGPIPE, sys::SIG_IGN);
    sys::set_child_subreaper().map_err(|e| format!("subreaper: {e}"))?;
    let cfg = config()?; // also performs `initialize_permits`
    let listener = bind_listener(&cfg.socket_path)?;
    let mut records: Vec<Record> = Vec::new();
    while !STOP.load(Ordering::SeqCst) {
        session::reap_records(&mut records, cfg.result_retention_s);
        if !poll_in(&listener, 100) {
            continue;
        }
        match accept_with(&listener, SocketFlags::CLOEXEC) {
            Ok(conn) => handle_conn(conn, &mut records, &cfg),
            Err(_) => continue,
        }
    }
    for rec in &mut records {
        if !rec.finished {
            rec.terminate(true);
        }
    }
    Ok(0)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(why) => {
            eprintln!("central-backup-launcherd: {why}");
            std::process::ExitCode::from(1)
        }
    }
}
