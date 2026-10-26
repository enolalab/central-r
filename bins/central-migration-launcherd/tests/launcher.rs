//! Integration tests — a port of upstream
//! `cmd/central-migration-launcherd/test_launcher.py`.
//!
//! Every test drives the real binary over its test socket; the
//! fixture (a temp dir holding the socket, the two permit locks, and
//! a fake `central-migrate` shell script that records its argv, its
//! env, its FD3 evidence bytes and its FD4 descriptor shape) mirrors
//! upstream's. The `CML_TEST_*` knobs exist only under the
//! `test-build` feature, so this whole suite is gated on it.
#![cfg(feature = "test-build")]
// Test code asserts eagerly; the crate lints forbid unwrap/expect/
// panic which are the normal way to fail a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, recvmsg, socket_with,
};

const BIN: &str = env!("CARGO_BIN_EXE_central-migration-launcherd");

const OP_LAUNCH: u8 = 1;
const OP_COMMIT: u8 = 2;
const OP_ABORT: u8 = 3;
const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 1;

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

/// The response frame and any `SCM_RIGHTS` descriptors; `None` when
/// the daemon closed without bytes (upstream's silent-close paths).
fn request(path: &Path, frame: &[u8]) -> Option<(Vec<u8>, Vec<OwnedFd>)> {
    let client = connect(path);
    let iov = [std::io::IoSlice::new(frame)];
    let mut space: [std::mem::MaybeUninit<u8>; 0] = [];
    let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
    sendmsg_all(&client, &iov, &mut control);
    recv_msg(&client)
}

fn sendmsg_all(
    client: &OwnedFd,
    iov: &[std::io::IoSlice<'_>],
    control: &mut rustix::net::SendAncillaryBuffer<'_, '_, '_>,
) {
    let mut sent = 0usize;
    while sent == 0 {
        match rustix::net::sendmsg(client, iov, control, SendFlags::NOSIGNAL) {
            Ok(n) => sent = n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => panic!("sendmsg: {e}"),
        }
    }
}

fn recv_msg(client: &OwnedFd) -> Option<(Vec<u8>, Vec<OwnedFd>)> {
    rustix::net::sockopt::set_socket_timeout(
        client,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let mut buf = [0u8; 64];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut space = vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = loop {
        match recvmsg(client, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC) {
            Err(rustix::io::Errno::INTR) => continue,
            // Timeout or peer-close without bytes → the silent path.
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

fn status_of(data: &[u8], opcode: u8) -> u8 {
    assert!(
        data.len() >= 12,
        "response is {} bytes: {data:?}",
        data.len()
    );
    assert_eq!(&data[0..4], b"CML1", "{data:?}");
    assert_eq!(data[4], 1, "{data:?}");
    assert_eq!(data[5], opcode, "{data:?}");
    data[6]
}

fn launch_frame(command: u8, op: &[u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 24];
    f[0..4].copy_from_slice(b"CML1");
    f[4] = 1;
    f[5] = OP_LAUNCH;
    f[6] = command;
    f[8..24].copy_from_slice(op);
    f
}

fn commit_frame(launch_id: &[u8; 16], evidence: &[u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 40];
    f[0..4].copy_from_slice(b"CML1");
    f[4] = 1;
    f[5] = OP_COMMIT;
    f[8..24].copy_from_slice(launch_id);
    f[24..40].copy_from_slice(evidence);
    f
}

fn abort_frame(launch_id: &[u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 24];
    f[0..4].copy_from_slice(b"CML1");
    f[4] = 1;
    f[5] = OP_ABORT;
    f[8..24].copy_from_slice(launch_id);
    f
}

/// One valid launch; returns `(pid, launch_id, pidfd)`.
fn launch(path: &Path, command: u8, op: &[u8; 16]) -> (i32, [u8; 16], OwnedFd) {
    let (data, fds) = request(path, &launch_frame(command, op))
        .unwrap_or_else(|| panic!("launch closed without a response"));
    assert_eq!(data.len(), 28, "{data:?}");
    assert_eq!(status_of(&data, OP_LAUNCH), STATUS_OK, "{data:?}");
    assert_eq!(fds.len(), 1, "exactly one pidfd, got {}", fds.len());
    let pid = i32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    assert!(pid > 0);
    let mut launch_id = [0u8; 16];
    launch_id.copy_from_slice(&data[12..28]);
    assert!(launch_id.iter().any(|b| *b != 0));
    // The pidfd must carry FD_CLOEXEC — MSG_CMSG_CLOEXEC is not the
    // point; the daemon sets it on the descriptor itself.
    let flags = rustix::io::fcntl_getfd(&fds[0]).unwrap();
    assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    (pid, launch_id, fds.into_iter().next().unwrap())
}

fn commit(path: &Path, launch_id: &[u8; 16], evidence: &[u8; 16]) -> u8 {
    let (data, _fds) = request(path, &commit_frame(launch_id, evidence))
        .unwrap_or_else(|| panic!("commit closed without a response"));
    status_of(&data, OP_COMMIT)
}

fn abort(path: &Path, launch_id: &[u8; 16]) -> u8 {
    let (data, _fds) = request(path, &abort_frame(launch_id))
        .unwrap_or_else(|| panic!("abort closed without a response"));
    status_of(&data, OP_ABORT)
}

/* ---- fixture ---- */

/// The fake `central-migrate`: records argv, environment, FD4's link
/// target, the absence of FD5+, then blocks on FD3 until the launcher
/// commits (or the fd closes) and records the evidence hex.
fn write_fake_migrate(dir: &Path) -> PathBuf {
    let p = dir.join("fake-migrate");
    std::fs::write(
        &p,
        r#"#!/bin/sh
cmd="$1"; op="$2"; dir="$(dirname "$0")"
{
  echo "argv:$cmd:$op"
  echo "env:$(env | sort | tr '\n' '|')"
  echo "fd3:$(readlink /proc/self/fd/3 2>/dev/null || echo absent)"
  echo "fd4:$(readlink /proc/self/fd/4 2>/dev/null || echo absent)"
  echo "fd5:$([ -e /proc/self/fd/5 ] && echo present || echo absent)"
  echo "fd6:$([ -e /proc/self/fd/6 ] && echo present || echo absent)"
  echo "id:$(id -u):$(id -g)"
} > "$dir/out-$op.txt" 2>&1
ev="$(dd bs=4096 count=1 <&3 2>/dev/null | od -An -tx1 | tr -d ' \n')"
echo "evidence:$ev" >> "$dir/out-$op.txt"
exit 0
"#,
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn write_permit(path: &Path) {
    std::fs::write(path, b"permit\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    fake: PathBuf,
    log: PathBuf,
    process: Option<Child>,
    timeout_s: u64,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "cml-test-{}-{}-{name}",
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
        let fake = write_fake_migrate(&base);
        Fixture {
            sock,
            fake,
            log: base.join("daemon.log"),
            dir: base,
            process: None,
            timeout_s: 30,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("CML_TEST_SOCKET".into(), self.sock.display().to_string()),
            (
                "CML_TEST_PERMIT_A".into(),
                self.dir.join("permit-a.lock").display().to_string(),
            ),
            (
                "CML_TEST_PERMIT_B".into(),
                self.dir.join("permit-b.lock").display().to_string(),
            ),
            ("CML_TEST_PERMIT_UID".into(), euid().to_string()),
            ("CML_TEST_PERMIT_GID".into(), egid().to_string()),
            ("CML_TEST_PEER_UID".into(), euid().to_string()),
            ("CML_TEST_MIGRATE_UID".into(), euid().to_string()),
            ("CML_TEST_MIGRATE_GID".into(), egid().to_string()),
            (
                "CML_TEST_MIGRATE_PATH".into(),
                self.fake.display().to_string(),
            ),
            ("CML_TEST_TIMEOUT_S".into(), self.timeout_s.to_string()),
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

    /// The fake operator's report for `op`, waiting briefly for the
    /// child to write it.
    fn operator_out(&self, op: &[u8; 16]) -> String {
        let path = self.dir.join(format!("out-{}.txt", uuid_text(op)));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && (text.contains("evidence:") || Instant::now() >= deadline)
            {
                return text;
            }
            if Instant::now() >= deadline {
                return String::new();
            }
            std::thread::sleep(Duration::from_millis(25));
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
fn malformed_frames_close_silently() {
    let mut fx = Fixture::new("malformed");
    fx.start();
    // Short (<8 bytes), oversized (fills the 41-byte buffer), and a
    // bad magic — upstream closes without a response.
    assert!(request(&fx.sock, &[0u8; 7]).is_none());
    assert!(request(&fx.sock, &[0u8; 41]).is_none());
    let mut bad = launch_frame(1, &uuid_bytes(1));
    bad[0] = b'X';
    assert!(request(&fx.sock, &bad).is_none());
    let mut bad_ver = launch_frame(1, &uuid_bytes(1));
    bad_ver[4] = 9;
    assert!(request(&fx.sock, &bad_ver).is_none());
}

#[test]
fn launch_refusals_are_denied() {
    let mut fx = Fixture::new("launch-refusal");
    fx.start();
    // Command byte outside 1..=5 → STATUS_DENIED.
    for cmd in [0u8, 6, 9] {
        let (data, _) = request(&fx.sock, &launch_frame(cmd, &uuid_bytes(7))).unwrap();
        assert_eq!(status_of(&data, OP_LAUNCH), STATUS_DENIED);
    }
    // A nil operation id → denied.
    let (data, _) = request(&fx.sock, &launch_frame(1, &[0u8; 16])).unwrap();
    assert_eq!(status_of(&data, OP_LAUNCH), STATUS_DENIED);
    // A 23-byte launch frame → denied.
    let mut short = launch_frame(1, &uuid_bytes(7));
    short.truncate(23);
    let (data, _) = request(&fx.sock, &short).unwrap();
    assert_eq!(status_of(&data, OP_LAUNCH), STATUS_DENIED);
}

#[test]
fn launch_spawns_operator_with_fixed_argv_and_fds() {
    let mut fx = Fixture::new("launch-ok");
    fx.start();
    let op = uuid_bytes(0x11);
    let (pid, launch_id, _pidfd) = launch(&fx.sock, 1, &op);
    let evidence = uuid_bytes(0x42);
    assert_eq!(commit(&fx.sock, &launch_id, &evidence), STATUS_OK);
    let out = fx.operator_out(&op);
    assert!(
        out.contains(&format!("argv:up:{}", uuid_text(&op))),
        "{out}"
    );
    // The fixed environment — no inherited state, no caller data.
    assert!(
        out.contains("env:LANG=C|LC_ALL=C|PATH=/usr/sbin:/usr/bin:/sbin:/bin|"),
        "{out}"
    );
    // FD4 survives exec as the credential memfd; the diagnostics pipe
    // (FD5) does not.
    assert!(
        out.contains("fd4:/memfd:central-migration-credential"),
        "{out}"
    );
    assert!(out.contains("fd5:absent"), "{out}");
    assert!(out.contains("fd6:absent"), "{out}");
    assert!(
        out.contains(&format!("id:{euid}:{egid}", euid = euid(), egid = egid())),
        "{out}"
    );
    // FD3 delivered the evidence bytes, then EOF.
    let want_hex: String = evidence.iter().map(|b| format!("{b:02x}")).collect();
    assert!(out.contains(&format!("evidence:{want_hex}")), "{out}");
    let _ = pid;
}

#[test]
fn commit_semantics() {
    let mut fx = Fixture::new("commit");
    fx.start();
    // Unknown launch → denied.
    assert_eq!(
        commit(&fx.sock, &uuid_bytes(0xee), &uuid_bytes(1)),
        STATUS_DENIED
    );
    let op = uuid_bytes(0x22);
    let (_pid, launch_id, _pidfd) = launch(&fx.sock, 2, &op);
    let evidence = uuid_bytes(0x99);
    assert_eq!(commit(&fx.sock, &launch_id, &evidence), STATUS_OK);
    // Idempotent for the same evidence only.
    assert_eq!(commit(&fx.sock, &launch_id, &evidence), STATUS_OK);
    assert_eq!(
        commit(&fx.sock, &launch_id, &uuid_bytes(0x77)),
        STATUS_DENIED
    );
    let out = fx.operator_out(&op);
    assert!(out.contains("argv:resume:"), "{out}");
}

#[test]
fn abort_semantics() {
    let mut fx = Fixture::new("abort");
    fx.start();
    assert_eq!(abort(&fx.sock, &uuid_bytes(0xab)), STATUS_DENIED);
    let op = uuid_bytes(0x33);
    let (pid, launch_id, _pidfd) = launch(&fx.sock, 3, &op);
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_OK);
    // The child is dead — the pid is gone (or reaped).
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && Path::new(&format!("/proc/{pid}")).exists() {
        std::thread::sleep(Duration::from_millis(25));
    }
    // A second abort finds no record → denied; commit likewise.
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_DENIED);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(5)), STATUS_DENIED);
    let _ = op;
}

#[test]
fn abort_after_commit_denied() {
    let mut fx = Fixture::new("abort-committed");
    fx.start();
    let op = uuid_bytes(0x44);
    let (_pid, launch_id, _pidfd) = launch(&fx.sock, 4, &op);
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(8)), STATUS_OK);
    assert_eq!(abort(&fx.sock, &launch_id), STATUS_DENIED);
    let _ = fx.operator_out(&op);
}

#[test]
fn permits_serialize_launches() {
    let mut fx = Fixture::new("permit-serialize");
    fx.start();
    // A live launch holds the exclusive permit flocks — a second
    // launch cannot acquire them while the first record exists.
    let op_a = uuid_bytes(0x55);
    let (_p1, launch_a, _f1) = launch(&fx.sock, 1, &op_a);
    let (data, _) = request(&fx.sock, &launch_frame(1, &uuid_bytes(0x66))).unwrap();
    assert_eq!(status_of(&data, OP_LAUNCH), STATUS_DENIED);
    // After the first launch is aborted the permits release.
    assert_eq!(abort(&fx.sock, &launch_a), STATUS_OK);
    let op_b = uuid_bytes(0x66);
    let (_p2, launch_b, _f2) = launch(&fx.sock, 1, &op_b);
    assert_eq!(abort(&fx.sock, &launch_b), STATUS_OK);
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
fn uncommitted_launch_times_out() {
    let mut fx = Fixture::new("timeout");
    fx.timeout_s = 1;
    fx.start();
    let op = uuid_bytes(0x77);
    let (pid, launch_id, _pidfd) = launch(&fx.sock, 1, &op);
    // Past the deadline the reaper kills the uncommitted launch — a
    // commit then finds no record.
    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(commit(&fx.sock, &launch_id, &uuid_bytes(9)), STATUS_DENIED);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && Path::new(&format!("/proc/{pid}")).exists() {
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn daemon_shutdown_kills_live_launches() {
    let mut fx = Fixture::new("shutdown");
    fx.start();
    let op = uuid_bytes(0x88);
    let (pid, _launch_id, _pidfd) = launch(&fx.sock, 1, &op);
    fx.stop();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && Path::new(&format!("/proc/{pid}")).exists() {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "child {pid} survived daemon shutdown"
    );
}
