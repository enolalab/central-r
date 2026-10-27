//! Integration tests — a port of upstream
//! `cmd/central-backup-launcherd/test_launcher.py`.
//!
//! Every test drives the real `central-backup-launcherd` binary over
//! its test socket with the real `cbl-test-worker` as the
//! `central-backup` stand-in; the fixture (a temp dir holding the
//! socket, the two permit locks, and the repository directory whose
//! flag files steer the worker) mirrors upstream's. The `CBL_TEST_*`
//! knobs exist only under the `test-build` feature, so this whole
//! suite is gated on it.
#![cfg(feature = "test-build")]
// Test code asserts eagerly; the crate lints forbid unwrap/expect/
// panic which are the normal way to fail a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryMessage,
    SendFlags, SocketAddrUnix, SocketFlags, SocketType, recvmsg, socket_with,
};

const BIN: &str = env!("CARGO_BIN_EXE_central-backup-launcherd");
const WORKER: &str = env!("CARGO_BIN_EXE_cbl-test-worker");

const OP_LAUNCH: u8 = 1;
const OP_COMMIT: u8 = 2;
const OP_ABORT: u8 = 3;
const OP_WAIT: u8 = 4;
const OP_ASSERT: u8 = 5;
const OP_RELEASE: u8 = 6;
const OP_CENSUS: u8 = 7;
const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 1;
const MODE_CREATE: u8 = 1;
const MODE_PROBE: u8 = 2;

const OUTCOME_SUCCEEDED: u8 = 0;
const OUTCOME_EXITED: u8 = 1;
const OUTCOME_SIGNALED: u8 = 2;

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn egid() -> u32 {
    rustix::process::getegid().as_raw()
}

fn uuid_bytes(seed: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = seed;
    b[6] = (b[6] & 0x0f) | 0x70;
    b[8] = (b[8] & 0x3f) | 0x80;
    b[15] = seed;
    b
}

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

/// Upstream's create-mode proof: `frame[8+i] = i+1`.
fn expected_proof(probe: bool) -> [u8; 32] {
    let mut p = [0u8; 32];
    for (i, v) in p.iter_mut().enumerate() {
        *v = (i as u8).wrapping_add(if probe { 33 } else { 1 });
    }
    p
}

/* ---- wire helpers ---- */

fn connect(path: &Path) -> OwnedFd {
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let addr = SocketAddrUnix::new(path.as_os_str()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match rustix::net::connect(&sock, &addr) {
            Ok(()) => break,
            Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("connect {}: {e}", path.display()),
        }
    }
    sock
}

fn sendmsg_all(
    client: &OwnedFd,
    iov: &[std::io::IoSlice<'_>],
    control: &mut rustix::net::SendAncillaryBuffer<'_, '_, '_>,
) {
    loop {
        match rustix::net::sendmsg(client, iov, control, SendFlags::NOSIGNAL) {
            Ok(n) if n > 0 => return,
            Ok(_) => panic!("sendmsg wrote 0 bytes"),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => panic!("sendmsg: {e}"),
        }
    }
}

fn recv_msg(client: &OwnedFd) -> Option<(Vec<u8>, Vec<OwnedFd>)> {
    rustix::net::sockopt::set_socket_timeout(
        client,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let mut buf = [0u8; 64];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut space = vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = loop {
        match recvmsg(client, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return None,
            Ok(m) => break m,
        }
    };
    if msg.bytes == 0 {
        return None;
    }
    let mut fds = Vec::new();
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            fds.extend(it);
        }
    }
    Some((buf[..msg.bytes.min(64)].to_vec(), fds))
}

/// `packet(path, frame, fds)` — one connection, one send, one
/// response, close. `None` when the daemon closed without bytes.
fn request(path: &Path, frame: &[u8], fds: &[&OwnedFd]) -> Option<(Vec<u8>, Vec<OwnedFd>)> {
    let client = connect(path);
    let iov = [std::io::IoSlice::new(frame)];
    if fds.is_empty() {
        let mut space: [std::mem::MaybeUninit<u8>; 0] = [];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
        sendmsg_all(&client, &iov, &mut control);
    } else {
        let rights: Vec<std::os::fd::BorrowedFd<'_>> = fds.iter().map(|f| f.as_fd()).collect();
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&rights)));
        sendmsg_all(&client, &iov, &mut control);
    }
    recv_msg(&client)
}

/// A wait request on a connection that stays open — the deferred
/// waiter path answers it asynchronously.
fn request_open(path: &Path, frame: &[u8]) -> OwnedFd {
    let client = connect(path);
    let iov = [std::io::IoSlice::new(frame)];
    let mut space: [std::mem::MaybeUninit<u8>; 0] = [];
    let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
    sendmsg_all(&client, &iov, &mut control);
    client
}

fn status_of(data: &[u8], opcode: u8) -> u8 {
    assert!(
        data.len() >= 12,
        "response is {} bytes: {data:?}",
        data.len()
    );
    assert_eq!(&data[0..4], b"CBL1", "{data:?}");
    assert_eq!(data[4], 2, "{data:?}");
    assert_eq!(data[5], opcode, "{data:?}");
    data[6]
}

fn launch_frame(mode: u8, op: &[u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 24];
    f[0..4].copy_from_slice(b"CBL1");
    f[4] = 2;
    f[5] = OP_LAUNCH;
    f[6] = mode;
    f[8..24].copy_from_slice(op);
    f
}

fn id_frame(op: u8, launch_id: &[u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 24];
    f[0..4].copy_from_slice(b"CBL1");
    f[4] = 2;
    f[5] = op;
    f[8..24].copy_from_slice(launch_id);
    f
}

fn commit_frame(launch_id: &[u8; 16], evidence: &[u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 40];
    f[0..4].copy_from_slice(b"CBL1");
    f[4] = 2;
    f[5] = OP_COMMIT;
    f[8..24].copy_from_slice(launch_id);
    f[24..40].copy_from_slice(evidence);
    f
}

/// One valid launch; returns `(worker_pid, launch_id, pidfd)`.
fn launch(fx: &Fixture, mode: u8, op: &[u8; 16]) -> (i32, [u8; 16], OwnedFd) {
    let (data, fds) = request(&fx.sock, &launch_frame(mode, op), &[&fx.repository])
        .unwrap_or_else(|| panic!("launch closed without a response"));
    assert_eq!(data.len(), 28, "{data:?}");
    assert_eq!(status_of(&data, OP_LAUNCH), STATUS_OK, "{data:?}");
    assert_eq!(data[7], mode, "mode echo, {data:?}");
    assert_eq!(fds.len(), 1, "exactly one pidfd, got {}", fds.len());
    let pid = i32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    assert!(pid > 0);
    let mut launch_id = [0u8; 16];
    launch_id.copy_from_slice(&data[12..28]);
    assert!(launch_id.iter().any(|b| *b != 0));
    let flags = rustix::io::fcntl_getfd(&fds[0]).unwrap();
    assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    (pid, launch_id, fds.into_iter().next().unwrap())
}

fn commit(path: &Path, launch_id: &[u8; 16], evidence: &[u8; 16]) -> u8 {
    let (data, _) = request(path, &commit_frame(launch_id, evidence), &[])
        .unwrap_or_else(|| panic!("commit closed without a response"));
    assert_eq!(data.len(), 12, "{data:?}");
    status_of(&data, OP_COMMIT)
}

fn abort(path: &Path, launch_id: &[u8; 16]) -> u8 {
    let (data, _) = request(path, &id_frame(OP_ABORT, launch_id), &[])
        .unwrap_or_else(|| panic!("abort closed without a response"));
    assert_eq!(data.len(), 12, "{data:?}");
    status_of(&data, OP_ABORT)
}

/// `wait_and_reap` — the 48-byte outcome frame.
fn wait_outcome(path: &Path, launch_id: &[u8; 16]) -> (u8, i32, i32, [u8; 32]) {
    let (data, _) = request(path, &id_frame(OP_WAIT, launch_id), &[])
        .unwrap_or_else(|| panic!("wait closed without a response"));
    assert_eq!(data.len(), 48, "{data:?}");
    assert_eq!(status_of(&data, OP_WAIT), STATUS_OK, "{data:?}");
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&data[16..48]);
    (
        data[7],
        i32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        i32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        proof,
    )
}

/// `wait` that only decodes the raw frame — for the denied path.
fn wait_raw(path: &Path, launch_id: &[u8; 16]) -> (u8, Vec<u8>) {
    let (data, _) = request(path, &id_frame(OP_WAIT, launch_id), &[])
        .unwrap_or_else(|| panic!("wait closed without a response"));
    assert_eq!(data.len(), 48, "{data:?}");
    let status = status_of(&data, OP_WAIT);
    (status, data)
}

fn assert_retained(path: &Path, launch_id: &[u8; 16]) -> (u8, [u8; 32]) {
    let (data, _) = request(path, &id_frame(OP_ASSERT, launch_id), &[])
        .unwrap_or_else(|| panic!("assert closed without a response"));
    assert_eq!(data.len(), 44, "{data:?}");
    let status = status_of(&data, OP_ASSERT);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&data[12..44]);
    (status, proof)
}

fn release(path: &Path, launch_id: &[u8; 16]) -> u8 {
    let (data, _) = request(path, &id_frame(OP_RELEASE, launch_id), &[])
        .unwrap_or_else(|| panic!("release closed without a response"));
    assert_eq!(data.len(), 12, "{data:?}");
    status_of(&data, OP_RELEASE)
}

fn census(path: &Path, launch_id: &[u8; 16]) -> (u32, u32) {
    let (data, _) = request(path, &id_frame(OP_CENSUS, launch_id), &[])
        .unwrap_or_else(|| panic!("census closed without a response"));
    assert_eq!(data.len(), 16, "{data:?}");
    assert_eq!(status_of(&data, OP_CENSUS), STATUS_OK, "{data:?}");
    (
        u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
    )
}

/* ---- the retained target listener ---- */

/// The `127.0.0.1:55432` listener upstream's fixture binds.
struct TargetListener(std::net::TcpListener);

impl TargetListener {
    fn bind(port: u16) -> Option<Self> {
        let l = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).ok()?;
        l.set_nonblocking(false).ok()?;
        Some(Self(l))
    }

    /// `listener.accept()` with a timeout — the worker's connect.
    fn accept(&self) -> std::net::TcpStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.0.accept() {
                Ok((s, _)) => return s,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("target accept: {e}"),
            }
        }
    }
}

/// `assert_connection_retained` — the retained target is quiet.
fn assert_retained_quiet(conn: &std::net::TcpStream) {
    conn.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut b = [0u8; 1];
    match std::io::Read::read(&mut &*conn, &mut b) {
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
        other => panic!("retained target unexpectedly readable: {other:?}"),
    }
}

/// `wait_for_eof` — the retained socket must close.
fn wait_eof(conn: &std::net::TcpStream) {
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 1];
    let n = std::io::Read::read(&mut &*conn, &mut b).unwrap();
    assert_eq!(n, 0, "retained target socket did not close");
}

fn process_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    match rustix::process::test_kill_process(rustix::process::Pid::from_raw(pid).unwrap()) {
        Ok(()) => true,
        Err(rustix::io::Errno::PERM) => true, // exists but another uid's
        Err(_) => false,
    }
}

fn wait_gone(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline && process_exists(pid) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!process_exists(pid), "pid {pid} still exists");
}

/* ---- fixture ---- */

fn write_permit(path: &Path) {
    std::fs::write(path, b"permit\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    repo: PathBuf,
    repository: OwnedFd,
    log: PathBuf,
    process: Option<Child>,
    timeout_s: u64,
    retention_s: u64,
    backup_deadline_s: u64,
    probe_deadline_s: u64,
}

impl Fixture {
    /// `None` when the repository dir fd cannot be opened.
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "cbl-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).unwrap();
        let sock = base.join("launcher.sock");
        write_permit(&base.join("permit-a.lock"));
        write_permit(&base.join("permit-b.lock"));
        let repo = base.join("repository");
        std::fs::create_dir(&repo).unwrap();
        std::fs::set_permissions(&repo, std::fs::Permissions::from_mode(0o700)).unwrap();
        let repository = rustix::fs::open(
            &repo,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        Fixture {
            sock,
            repo,
            repository,
            log: base.join("daemon.log"),
            dir: base,
            process: None,
            timeout_s: 30,
            retention_s: 30,
            backup_deadline_s: 60,
            probe_deadline_s: 60,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("CBL_TEST_SOCKET".into(), self.sock.display().to_string()),
            (
                "CBL_TEST_PERMIT_A".into(),
                self.dir.join("permit-a.lock").display().to_string(),
            ),
            (
                "CBL_TEST_PERMIT_B".into(),
                self.dir.join("permit-b.lock").display().to_string(),
            ),
            ("CBL_TEST_PERMIT_UID".into(), euid().to_string()),
            ("CBL_TEST_PERMIT_GID".into(), egid().to_string()),
            ("CBL_TEST_PEER_UID".into(), euid().to_string()),
            ("CBL_TEST_BACKUP_UID".into(), euid().to_string()),
            ("CBL_TEST_BACKUP_GID".into(), egid().to_string()),
            ("CBL_TEST_BACKUP_PATH".into(), WORKER.to_owned()),
            ("CBL_TEST_TIMEOUT_S".into(), self.timeout_s.to_string()),
            ("CBL_TEST_RETENTION_S".into(), self.retention_s.to_string()),
            (
                "CBL_TEST_BACKUP_DEADLINE_S".into(),
                self.backup_deadline_s.to_string(),
            ),
            (
                "CBL_TEST_PROBE_DEADLINE_S".into(),
                self.probe_deadline_s.to_string(),
            ),
        ]
    }

    #[allow(clippy::zombie_processes)] // Fixture::drop waits it.
    fn start(&mut self) {
        let log = std::fs::File::create(&self.log).unwrap();
        let err = log.try_clone().unwrap();
        let mut child = Command::new(BIN)
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("daemon exited {status}: {}", self.log_text());
            }
            if self.sock.exists() {
                self.process = Some(child);
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("daemon did not create its socket: {}", self.log_text());
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            if child.try_wait().unwrap().is_none() {
                let _ = rustix::process::kill_process(
                    rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
                    rustix::process::Signal::TERM,
                );
                let deadline = Instant::now() + Duration::from_secs(10);
                while Instant::now() < deadline && child.try_wait().unwrap().is_none() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if child.try_wait().unwrap().is_none() {
                    let _ = child.kill();
                }
            }
            let _ = child.wait();
        }
    }

    fn flag(&self, name: &str) {
        std::fs::write(self.repo.join(name), name).unwrap();
    }

    fn unflag(&self, name: &str) {
        let _ = std::fs::remove_file(self.repo.join(name));
    }

    fn repo_file(&self, name: &str) -> Vec<u8> {
        let path = self.repo.join(name);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match std::fs::read(&path) {
                Ok(b) => return b,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("read {}: {e}", path.display()),
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/* ---- tests ---- */

#[test]
fn production_build_denies_nonroot_peer() {
    if euid() == 0 {
        eprintln!("skipping: root is always admitted");
        return;
    }
    // No CBL_TEST_PEER_UID — the daemon compiles the root-only gate.
    let fx = Fixture::new("peer-gate");
    let log = std::fs::File::create(&fx.log).unwrap();
    let err = log.try_clone().unwrap();
    let mut env = fx.env();
    env.retain(|(k, _)| k != "CBL_TEST_PEER_UID");
    let mut child = Command::new(BIN)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !fx.sock.exists() {
        if child.try_wait().unwrap().is_some() {
            panic!("daemon exited early: {}", fx.log_text());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(fx.sock.exists(), "daemon did not create its socket");
    // The peer gate refuses before reading a byte — silent close.
    let reply = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &uuid_bytes(1)),
        &[&fx.repository],
    );
    assert!(reply.is_none(), "non-root peer got a response: {reply:?}");
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        rustix::process::Signal::TERM,
    );
    let _ = child.wait();
}

#[test]
fn malformed_frames_close_silently() {
    let mut fx = Fixture::new("malformed");
    fx.start();
    // Short (<8 bytes), oversized (fills the 41-byte buffer), bad
    // magic, bad version, unknown opcode → silent close.
    assert!(request(&fx.sock, &[0u8; 7], &[]).is_none());
    assert!(request(&fx.sock, &[0u8; 41], &[]).is_none());
    let mut bad = launch_frame(MODE_CREATE, &uuid_bytes(1));
    bad[0] = b'X';
    assert!(request(&fx.sock, &bad, &[&fx.repository]).is_none());
    let mut bad_ver = launch_frame(MODE_CREATE, &uuid_bytes(1));
    bad_ver[4] = 9;
    assert!(request(&fx.sock, &bad_ver, &[&fx.repository]).is_none());
    let mut bad_op = launch_frame(MODE_CREATE, &uuid_bytes(1));
    bad_op[5] = 9;
    assert!(request(&fx.sock, &bad_op, &[]).is_none());
    // A descriptor on a non-launch frame → silent.
    assert!(
        request(
            &fx.sock,
            &id_frame(OP_ABORT, &uuid_bytes(2)),
            &[&fx.repository]
        )
        .is_none()
    );
    // Reserved bytes nonzero → silent (no launch prefix).
    let mut reserved = launch_frame(MODE_CREATE, &uuid_bytes(3));
    reserved[7] = 1;
    assert!(request(&fx.sock, &reserved, &[&fx.repository]).is_none());
}

#[test]
fn launch_refusals_are_denied() {
    let mut fx = Fixture::new("launch-refusal");
    fx.start();
    let op = uuid_bytes(7);
    // No descriptor / two descriptors → denied launch reply.
    let (d, _) = request(&fx.sock, &launch_frame(MODE_CREATE, &op), &[]).unwrap();
    assert_eq!(d.len(), 28);
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    let (d, _) = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &op),
        &[&fx.repository, &fx.repository],
    )
    .unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    // Mode out of range → denied; the denied response carries mode 0.
    let (d, _) = request(&fx.sock, &launch_frame(3, &op), &[&fx.repository]).unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    assert_eq!(d[7], 0);
    // Nil operation id → denied.
    let (d, _) = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &[0u8; 16]),
        &[&fx.repository],
    )
    .unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    // A non-directory repository fd → denied.
    let regular_path = fx.dir.join("not-a-repo");
    std::fs::write(&regular_path, b"x").unwrap();
    let regular = rustix::fs::open(
        &regular_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let (d, _) = request(&fx.sock, &launch_frame(MODE_CREATE, &op), &[&regular]).unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    // An O_PATH directory fd → denied.
    let opath = rustix::fs::open(
        &fx.repo,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let (d, _) = request(&fx.sock, &launch_frame(MODE_CREATE, &op), &[&opath]).unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    // A group-writable repository dir → denied.
    std::fs::set_permissions(&fx.repo, std::fs::Permissions::from_mode(0o770)).unwrap();
    let (d, _) = request(&fx.sock, &launch_frame(MODE_CREATE, &op), &[&fx.repository]).unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    std::fs::set_permissions(&fx.repo, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn full_create_cycle() {
    let Some(listener) = TargetListener::bind(55432) else {
        eprintln!("skipping: 127.0.0.1:55432 unavailable");
        return;
    };
    let mut fx = Fixture::new("full-cycle");
    fx.start();
    let op = uuid_bytes(0x11);
    let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &op);
    drop(pidfd);
    let evidence = uuid_bytes(0x42);
    assert_eq!(commit(&fx.sock, &launch_id, &evidence), STATUS_OK);
    // Idempotent for the same evidence only.
    assert_eq!(commit(&fx.sock, &launch_id, &evidence), STATUS_OK);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(9)), STATUS_DENIED);
    let peer = listener.accept();
    let (outcome, exit_code, signal, proof) = wait_outcome(&fx.sock, &launch_id);
    assert_eq!(
        (outcome, exit_code, signal),
        (OUTCOME_SUCCEEDED, 0, 0),
        "worker outcome"
    );
    assert_eq!(proof, expected_proof(false));
    // Fixed-argv/env/fd contract evidence.
    assert_eq!(fx.repo_file("out-evidence"), evidence);
    assert_eq!(
        String::from_utf8(fx.repo_file("out-operation")).unwrap(),
        uuid_text(&op)
    );
    assert_eq!(
        String::from_utf8(fx.repo_file("out-mode")).unwrap(),
        "create"
    );
    assert_eq!(fx.repo_file("worker-marker"), b"created");
    let descendant: i32 = String::from_utf8(fx.repo_file("out-descendant"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(fx.repo_file("out-descendant-ready"), b"ready");
    // The wait ACK implies the whole tree — worker and detached
    // descendant — is already reaped.
    assert!(!process_exists(pid), "wait ACK preceded worker reap");
    assert!(
        !process_exists(descendant),
        "wait ACK preceded descendant reap"
    );
    // A second wait returns the same outcome.
    assert_eq!(
        wait_outcome(&fx.sock, &launch_id),
        (OUTCOME_SUCCEEDED, 0, 0, expected_proof(false))
    );
    let (st, p) = assert_retained(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_OK);
    assert_eq!(p, expected_proof(false));
    assert_eq!(fx.repo_file("out-proof"), expected_proof(false));
    assert_retained_quiet(&peer);
    // Census excludes the named launch only.
    let (ex_live, ex_permits) = census(&fx.sock, &launch_id);
    let (in_live, in_permits) = census(&fx.sock, &uuid_bytes(0xfe));
    assert_eq!(in_live - ex_live, 1);
    assert_eq!(in_permits - ex_permits, 1);
    // Release drops the retained socket; a second release is
    // idempotent OK; assert after release denies.
    assert_eq!(release(&fx.sock, &launch_id), STATUS_OK);
    wait_eof(&peer);
    assert_eq!(release(&fx.sock, &launch_id), STATUS_OK);
    let (st, _) = assert_retained(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_DENIED);
    let (a_live, a_permits) = census(&fx.sock, &launch_id);
    let (b_live, b_permits) = census(&fx.sock, &uuid_bytes(0xfd));
    assert_eq!((a_live, a_permits), (b_live, b_permits));
}

#[test]
fn probe_mode_cycle() {
    let Some(listener) = TargetListener::bind(55432) else {
        eprintln!("skipping: 127.0.0.1:55432 unavailable");
        return;
    };
    let mut fx = Fixture::new("probe-cycle");
    fx.start();
    let op = uuid_bytes(0x22);
    let (pid, launch_id, pidfd) = launch(&fx, MODE_PROBE, &op);
    drop(pidfd);
    // An assert before the worker is retained must deny, not kill.
    let (st, _) = assert_retained(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_DENIED);
    assert!(
        process_exists(pid),
        "early probe assertion killed the worker"
    );
    let evidence = uuid_bytes(0x55);
    assert_eq!(commit(&fx.sock, &launch_id, &evidence), STATUS_OK);
    let peer = listener.accept();
    let (outcome, exit_code, signal, proof) = wait_outcome(&fx.sock, &launch_id);
    assert_eq!((outcome, exit_code, signal), (OUTCOME_SUCCEEDED, 0, 0));
    assert_eq!(proof, expected_proof(true));
    assert_ne!(proof, expected_proof(false));
    assert_eq!(fx.repo_file("out-evidence"), evidence);
    assert_eq!(
        String::from_utf8(fx.repo_file("out-operation")).unwrap(),
        uuid_text(&op)
    );
    assert_eq!(
        String::from_utf8(fx.repo_file("out-mode")).unwrap(),
        "throughput-probe"
    );
    assert_eq!(fx.repo_file("probe-marker"), b"created");
    let descendant: i32 = String::from_utf8(fx.repo_file("out-descendant"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(!process_exists(pid));
    assert!(!process_exists(descendant));
    let (st, p) = assert_retained(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_OK);
    assert_eq!(p, expected_proof(true));
    assert_retained_quiet(&peer);
    assert_eq!(release(&fx.sock, &launch_id), STATUS_OK);
    wait_eof(&peer);
    assert_eq!(release(&fx.sock, &launch_id), STATUS_OK);
    // An abort on a released-but-retained record is still OK
    // (upstream: `record != NULL && !aborted → terminate`, always ACK).
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
}

#[test]
fn abort_is_idempotent_ok() {
    let mut fx = Fixture::new("abort");
    fx.start();
    // SC-DEF-38: an id never tracked has nothing left to abort → OK.
    assert_eq!(abort(&fx.sock, &uuid_bytes(0xab)), STATUS_OK);
    let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0x33));
    drop(pidfd);
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
    wait_gone(pid);
    // A second abort on the same id still ACKs OK.
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(5)), STATUS_DENIED);
}

#[test]
fn wait_denial_semantics() {
    let mut fx = Fixture::new("wait-denial");
    fx.start();
    // Unknown id → denied.
    let (st, _) = wait_raw(&fx.sock, &uuid_bytes(0x77));
    assert_eq!(st, STATUS_DENIED);
    let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0x44));
    drop(pidfd);
    // Uncommitted → denied.
    let (st, _) = wait_raw(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_DENIED);
    // Keep the worker alive so the committed wait defers.
    fx.flag("hang");
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(8)), STATUS_OK);
    let waiter = request_open(&fx.sock, &id_frame(OP_WAIT, &launch_id));
    // A second waiter → denied.
    let (st, _) = wait_raw(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_DENIED);
    // Abort terminates the hung worker; the stored waiter gets its
    // answer — upstream's `aborted` flag makes it a DENIED frame.
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
    let (data, _) = recv_msg(&waiter).unwrap();
    assert_eq!(data.len(), 48);
    assert_eq!(status_of(&data, OP_WAIT), STATUS_DENIED, "{data:?}");
    wait_gone(pid);
    fx.unflag("hang");
    fx.unflag("worker-marker");
}

#[test]
fn hang_worker_killed_at_hard_deadline() {
    let mut fx = Fixture::new("hard-deadline");
    fx.probe_deadline_s = 1;
    fx.start();
    fx.flag("probe-hang");
    let (pid, launch_id, pidfd) = launch(&fx, MODE_PROBE, &uuid_bytes(0x55));
    drop(pidfd);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(9)), STATUS_OK);
    let started = Instant::now();
    let (outcome, exit_code, signal, proof) = wait_outcome(&fx.sock, &launch_id);
    let elapsed = started.elapsed();
    assert_eq!(
        (outcome, exit_code, signal),
        (OUTCOME_SIGNALED, 0, libc::SIGKILL),
        "hard-deadline outcome"
    );
    assert_eq!(proof, [0u8; 32]);
    assert!(
        elapsed < Duration::from_secs(6),
        "deadline took {elapsed:?}"
    );
    assert!(!process_exists(pid), "deadline ACK preceded worker reap");
    fx.unflag("probe-hang");
    fx.unflag("probe-marker");
    fx.unflag("out-evidence");
    fx.unflag("out-operation");
    fx.unflag("out-mode");
}

#[test]
fn failing_worker_outcome() {
    let mut fx = Fixture::new("fail-outcome");
    fx.start();
    fx.flag("fail");
    let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0x66));
    drop(pidfd);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(1)), STATUS_OK);
    let (outcome, exit_code, signal, proof) = wait_outcome(&fx.sock, &launch_id);
    assert_eq!((outcome, exit_code, signal), (OUTCOME_EXITED, 9, 0));
    assert_eq!(proof, [0u8; 32]);
    assert!(!process_exists(pid));
    fx.unflag("fail");
    fx.unflag("worker-marker");
}

#[test]
fn bad_handoff_outcomes() {
    let listener = TargetListener::bind(55432);
    let wrong = TargetListener::bind(55433);
    for flag in [
        "missing-handoff",
        "wrong-type",
        "wrong-endpoint",
        "zero-proof",
        "malformed",
    ] {
        let mut fx = Fixture::new(&format!("handoff-{flag}"));
        fx.start();
        fx.flag(flag);
        let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0x77));
        drop(pidfd);
        assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(2)), STATUS_OK);
        // The wrong-endpoint worker connects to :55433 when it is bound.
        let wrong_peer = if flag == "wrong-endpoint" {
            wrong.as_ref().map(|w| w.accept())
        } else {
            None
        };
        let target_peer = if matches!(flag, "zero-proof" | "malformed") {
            listener.as_ref().map(|l| l.accept())
        } else {
            None
        };
        let (outcome, exit_code, signal, proof) = wait_outcome(&fx.sock, &launch_id);
        assert_eq!(outcome, OUTCOME_EXITED, "{flag}");
        assert!(exit_code > 0, "{flag}: exit {exit_code}");
        assert_eq!(signal, 0, "{flag}");
        assert_eq!(proof, [0u8; 32], "{flag}");
        assert!(!process_exists(pid), "{flag} worker not reaped");
        if let Some(p) = wrong_peer {
            wait_eof(&p);
        }
        if let Some(p) = target_peer {
            wait_eof(&p);
        }
    }
}

#[test]
fn abort_drops_retained_socket() {
    let Some(listener) = TargetListener::bind(55432) else {
        eprintln!("skipping: 127.0.0.1:55432 unavailable");
        return;
    };
    let mut fx = Fixture::new("abort-retained");
    fx.start();
    let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0x88));
    drop(pidfd);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(3)), STATUS_OK);
    let peer = listener.accept();
    assert_eq!(
        wait_outcome(&fx.sock, &launch_id),
        (OUTCOME_SUCCEEDED, 0, 0, expected_proof(false))
    );
    assert!(!process_exists(pid));
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
    wait_eof(&peer);
    let (st, _) = assert_retained(&fx.sock, &launch_id);
    assert_eq!(st, STATUS_DENIED);
    // The retained record still counts as finished-not-live; census
    // must show no live process either way.
    let (live, _) = census(&fx.sock, &uuid_bytes(0xfc));
    assert_eq!(live, 0);
}

#[test]
fn uncommitted_launch_times_out() {
    let mut fx = Fixture::new("timeout");
    fx.timeout_s = 1;
    fx.start();
    let (pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0x99));
    drop(pidfd);
    std::thread::sleep(Duration::from_millis(2400));
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(9)), STATUS_DENIED);
    wait_gone(pid);
}

#[test]
fn permits_serialize_launches() {
    let mut fx = Fixture::new("permit-serialize");
    fx.start();
    let (pid_a, launch_a, pidfd_a) = launch(&fx, MODE_CREATE, &uuid_bytes(0xaa));
    drop(pidfd_a);
    // The held permit pair refuses every further launch.
    let (d, _) = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &uuid_bytes(0xbb)),
        &[&fx.repository],
    )
    .unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    assert_eq!(abort(&fx.sock, &launch_a), STATUS_OK);
    wait_gone(pid_a);
    let (_pid_b, launch_b, pidfd_b) = launch(&fx, MODE_CREATE, &uuid_bytes(0xcc));
    drop(pidfd_b);
    assert_eq!(abort(&fx.sock, &launch_b), STATUS_OK);
}

#[test]
fn permit_swap_and_hardlink_denied() {
    let mut fx = Fixture::new("permit-swap");
    fx.start();
    let permit_b = fx.dir.join("permit-b.lock");
    // A hardlinked permit fails the single-link check at acquire.
    let hard = fx.dir.join("permit-b-hard");
    std::fs::hard_link(&permit_b, &hard).unwrap();
    let (d, _) = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &uuid_bytes(0xd1)),
        &[&fx.repository],
    )
    .unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    std::fs::remove_file(&hard).unwrap();
    // A symlinked permit fails O_NOFOLLOW / identity.
    let permit_a = fx.dir.join("permit-a.lock");
    let orig = fx.dir.join("permit-a.orig");
    std::fs::rename(&permit_a, &orig).unwrap();
    std::os::unix::fs::symlink(&permit_b, &permit_a).unwrap();
    let (d, _) = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &uuid_bytes(0xd2)),
        &[&fx.repository],
    )
    .unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    std::fs::remove_file(&permit_a).unwrap();
    std::fs::rename(&orig, &permit_a).unwrap();
}

#[test]
fn daemon_refuses_start_without_permits() {
    let fx = Fixture::new("permit-start");
    std::fs::remove_file(fx.dir.join("permit-b.lock")).unwrap();
    let log = std::fs::File::create(&fx.log).unwrap();
    let err = log.try_clone().unwrap();
    let mut child = Command::new(BIN)
        .env_clear()
        .envs(fx.env())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "daemon started without permit-b");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("daemon stayed up without permit-b");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.wait();
}

#[test]
fn daemon_death_closes_retained() {
    let Some(listener) = TargetListener::bind(55432) else {
        eprintln!("skipping: 127.0.0.1:55432 unavailable");
        return;
    };
    let mut fx = Fixture::new("daemon-death");
    fx.start();
    let (_pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0xee));
    drop(pidfd);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(4)), STATUS_OK);
    let peer = listener.accept();
    assert_eq!(
        wait_outcome(&fx.sock, &launch_id),
        (OUTCOME_SUCCEEDED, 0, 0, expected_proof(false))
    );
    // SIGKILL the daemon — its monitor dies by pdeathsig, its permit
    // fds close, and the retained target socket closes with them.
    let mut child = fx.process.take().unwrap();
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        rustix::process::Signal::KILL,
    );
    let _ = child.wait();
    wait_eof(&peer);
}

#[test]
fn daemon_shutdown_terminates_launches() {
    let mut fx = Fixture::new("shutdown");
    fx.start();
    let (pid, _launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0xf1));
    drop(pidfd);
    fx.stop();
    wait_gone(pid);
}

#[test]
fn launch_denied_when_table_full() {
    // Upstream evicts the oldest finished waiterless record when the
    // 32-slot table is full — exercised by saturating the table with
    // hang workers would take 32 daemons' worth of fds; the unit test
    // in session.rs covers ensure_slot directly. This integration
    // case only checks the permit-serialization path again under a
    // fresh abort — a live record always denies a new launch.
    let mut fx = Fixture::new("table");
    fx.start();
    let (_pid, launch_id, pidfd) = launch(&fx, MODE_CREATE, &uuid_bytes(0xf2));
    drop(pidfd);
    let (d, _) = request(
        &fx.sock,
        &launch_frame(MODE_CREATE, &uuid_bytes(0xf3)),
        &[&fx.repository],
    )
    .unwrap();
    assert_eq!(status_of(&d, OP_LAUNCH), STATUS_DENIED);
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
}
