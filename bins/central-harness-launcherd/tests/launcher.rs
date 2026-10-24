//! Integration tests — a port of upstream
//! `cmd/central-harness-launcherd/test_launcher.py` for the Rust daemon.
//!
//! Every test drives the real binary over its test socket; the fixture
//! (a fake HOME, worktree root, config and fake cgroup root under one
//! temp dir) mirrors upstream's. Test-only knobs exist only under the
//! `test-build` feature, so this whole suite is gated on it; a
//! production build compiles no test knob and these tests compile to
//! nothing.
#![cfg(feature = "test-build")]
// Test code asserts eagerly; the crate's lints forbid unwrap/expect/panic
// which are the normal way to fail a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, open};
use rustix::io::{Errno, read, write};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType, recvmsg, sendmsg,
    socket_with,
};
use rustix::process::{Signal, kill_process};

const BIN: &str = env!("CARGO_BIN_EXE_central-harness-launcherd");
const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/capabilities/central-harness/testdata/launch-env-vectors.json"
);

const OP_LAUNCH: u8 = 1;
const OP_ALIVE: u8 = 2;
const OP_KILL: u8 = 3;
const OP_EXIT: u8 = 4;

mod reasons {
    pub const OK: u8 = 0;
    pub const PEER_DENIED: u8 = 1;
    pub const CONFIG_INVALID: u8 = 2;
    pub const REQUEST_MALFORMED: u8 = 3;
    pub const UNKNOWN_HARNESS: u8 = 4;
    pub const WORKDIR_INVALID: u8 = 5;
    pub const ARGV_REFUSED: u8 = 6;
    pub const ENV_REFUSED: u8 = 7;
    pub const SCOPE_BUSY: u8 = 8;
    pub const OPERATOR_INVALID: u8 = 9;
    pub const LAUNCH_FAILED: u8 = 10;
}

/* ---- small utilities ---- */

fn me() -> String {
    if let Ok(u) = std::env::var("USER")
        && !u.is_empty()
    {
        return u;
    }
    let out = Command::new("id").arg("-un").output().expect("id -un");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn uniq_id() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    nanos
        ^ ((SEQ.fetch_add(1, Ordering::Relaxed) as u128) << 64)
        ^ ((std::process::id() as u128) << 32)
}

/// A random 16-byte scope id (UUIDv4 shape).
fn scope_id() -> [u8; 16] {
    let mut b = uniq_id().to_be_bytes();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    b
}

fn scope_text(scope: &[u8; 16]) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        hex(&scope[0..4]),
        hex(&scope[4..6]),
        hex(&scope[6..8]),
        hex(&scope[8..10]),
        hex(&scope[10..16])
    )
}

fn wait_until(mut pred: impl FnMut() -> bool, timeout: Duration, what: &str) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/* ---- procfs ---- */

fn pid_alive(pid: i32) -> bool {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(rest) = text.rsplit(')').next() else {
        return false;
    };
    rest.split_whitespace().next() != Some("Z")
}

fn ppid_of(pid: i32) -> i32 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let rest = text.rsplit(')').next().unwrap();
    rest.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn children_of(pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap() {
        let e = e.unwrap();
        let name = e.file_name();
        let Ok(child) = name.to_str().unwrap_or("").parse::<i32>() else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{child}/stat"))
            && let Some(rest) = text.rsplit(')').next()
            && rest.split_whitespace().nth(1) == Some(pid.to_string().as_str())
        {
            out.push(child);
        }
    }
    out
}

fn kill(pid: i32, sig: Signal) {
    let Some(p) = rustix::process::Pid::from_raw(pid) else {
        return;
    };
    let _ = kill_process(p, sig);
}

fn poll_ready(fd: &OwnedFd, timeout: Duration) -> bool {
    let b = fd.as_fd();
    let mut p = [PollFd::new(&b, PollFlags::IN | PollFlags::RDHUP)];
    let ts = Timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: timeout.subsec_nanos() as i64,
    };
    matches!(poll(&mut p, Some(&ts)), Ok(n) if n > 0) && !p[0].revents().is_empty()
}

fn read_all(fd: &OwnedFd, timeout: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no EOF on fd after {timeout:?}: {out:?}");
        if !poll_ready(fd, left.min(Duration::from_millis(200))) {
            continue;
        }
        let mut buf = [0u8; 65536];
        match read(fd, &mut buf) {
            Ok(0) => return out,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno::INTR) => continue,
            Err(e) => panic!("read: {e}"),
        }
    }
}

fn read_line(fd: &OwnedFd, timeout: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let deadline = Instant::now() + timeout;
    while !out.ends_with(b"\n") {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no line on fd: {out:?}");
        if !poll_ready(fd, left.min(Duration::from_millis(200))) {
            continue;
        }
        let mut b = [0u8; 1];
        match read(fd, &mut b) {
            Ok(1) => out.push(b[0]),
            Ok(0) => panic!("EOF before a line: {out:?}"),
            Ok(_) => unreachable!(),
            Err(Errno::INTR) => continue,
            Err(e) => panic!("read: {e}"),
        }
    }
    out
}

/* ---- wire frames (upstream test_launcher.py) ---- */

fn header(op: u8, status: u8, reserved: u8) -> Vec<u8> {
    let mut h = b"CHL1".to_vec();
    h.extend_from_slice(&[1, op, status, reserved]);
    h
}

fn f16(v: &[u8]) -> Vec<u8> {
    let mut out = ((v.len() as u16).to_be_bytes()).to_vec();
    out.extend_from_slice(v);
    out
}

const PREFIX: &[&str] = &[
    "-p",
    "--verbose",
    "--output-format",
    "stream-json",
    "--input-format",
    "stream-json",
    "--setting-sources",
    "user",
];
const DENY: &[&str] = &[
    "--permission-mode",
    "dontAsk",
    "--permission-prompts",
    "none",
];
const BRIDGE: &[&str] = &[
    "--permission-mode",
    "manual",
    "--permission-prompts",
    "host",
    "--permission-prompt-tool",
    "stdio",
];
const BYPASS: &[&str] = &["--permission-mode", "bypassPermissions"];

fn session_argv(
    model: Option<&str>,
    policy: &[&str],
    flag: &str,
    sid: Option<String>,
    budget: Option<&str>,
) -> Vec<Vec<u8>> {
    let mut a: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    a.push(flag.as_bytes().to_vec());
    a.push(sid.unwrap_or_else(|| scope_text(&scope_id())).into_bytes());
    a.extend(policy.iter().map(|s| s.as_bytes().to_vec()));
    if let Some(m) = model {
        a.push(b"--model".to_vec());
        a.push(m.as_bytes().to_vec());
    }
    if let Some(bud) = budget {
        a.push(b"--max-budget-usd".to_vec());
        a.push(bud.as_bytes().to_vec());
    }
    a
}

fn default_argv() -> Vec<Vec<u8>> {
    session_argv(None, DENY, "--session-id", None, None)
}

fn launch_frame(
    scope: Option<[u8; 16]>,
    harness: &[u8],
    workdir: &[u8],
    argv: Option<Vec<Vec<u8>>>,
    env: Option<Vec<Vec<u8>>>,
) -> Vec<u8> {
    let scope = scope.unwrap_or_else(scope_id);
    let argv = argv.unwrap_or_else(default_argv);
    let env = env.unwrap_or_else(|| vec![b"PATH=/usr/bin:/bin".to_vec(), b"LANG=C.UTF-8".to_vec()]);
    let mut f = header(OP_LAUNCH, 0, 0);
    f.extend_from_slice(&scope);
    f.push(harness.len() as u8);
    f.extend_from_slice(harness);
    f.extend_from_slice(&f16(workdir));
    f.push(argv.len() as u8);
    for a in &argv {
        f.extend_from_slice(&f16(a));
    }
    f.push(env.len() as u8);
    for e in &env {
        f.extend_from_slice(&f16(e));
    }
    f
}

fn alive_frame(scope: &[u8; 16]) -> Vec<u8> {
    let mut f = header(OP_ALIVE, 0, 0);
    f.extend_from_slice(scope);
    f
}

fn kill_frame(scope: &[u8; 16], grace_ms: u32) -> Vec<u8> {
    let mut f = header(OP_KILL, 0, 0);
    f.extend_from_slice(scope);
    f.extend_from_slice(&grace_ms.to_be_bytes());
    f
}

/* ---- socket client ---- */

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
            Err(Errno::AGAIN) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("connect {}: {e}", path.display()),
        }
    }
    rustix::net::sockopt::set_socket_timeout(
        &sock,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(15)),
    )
    .unwrap();
    sock
}

fn recv_msg(client: &OwnedFd, max_fds: usize) -> (Vec<u8>, Vec<OwnedFd>) {
    let mut buf = [0u8; 64];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut space = vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = loop {
        match recvmsg(
            client,
            &mut iov,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC,
        ) {
            Err(Errno::INTR) => continue,
            Err(e) => panic!("recvmsg: {e}"),
            Ok(m) => break m,
        }
    };
    let _ = max_fds;
    let mut fds = Vec::new();
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            fds.extend(it);
        }
    }
    (buf[..msg.bytes.min(64)].to_vec(), fds)
}

/// Send one frame; the response's first 64 bytes and its descriptors.
fn request(path: &Path, frame: &[u8], send_fds: &[OwnedFd]) -> (Vec<u8>, Vec<OwnedFd>) {
    let client = connect(path);
    if send_fds.is_empty() {
        let iov = [std::io::IoSlice::new(frame)];
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
    } else {
        let borrowed: Vec<_> = send_fds.iter().map(|f| f.as_fd()).collect();
        let iov = [std::io::IoSlice::new(frame)];
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        control.push(SendAncillaryMessage::ScmRights(&borrowed));
        let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
    }
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| recv_msg(&client, 8)));
    res.unwrap_or_else(|_| (Vec::new(), Vec::new()))
}

fn status_of(data: &[u8], op: u8) -> u8 {
    assert!(
        data.len() == 12,
        "response is {} bytes: {data:?}",
        data.len()
    );
    assert!(
        data[..4] == *b"CHL1" && data[4] == 1 && data[5] == op && data[7] == 0,
        "{data:?}"
    );
    data[6]
}

/// `expect` — one request whose response must be `reason`.
fn expect(path: &Path, frame: &[u8], reason: u8, op: u8, send_fds: &[OwnedFd]) -> Vec<u8> {
    let (data, fds) = request(path, frame, send_fds);
    for f in &fds {
        let _ = f;
    }
    let got = status_of(&data, op);
    assert!(got == reason, "op {op}: got reason {got}, want {reason}");
    data
}

fn expect_launch(path: &Path, frame: &[u8], reason: u8) -> Vec<u8> {
    expect(path, frame, reason, OP_LAUNCH, &[])
}

/* ---- the fixture ---- */

const FAKE_HARNESS: &str = r#"#!/bin/sh
# Stand-in for the claude binary. It never reads a credential. With the
# session argv it picks a behaviour from the --model value.
case "$*" in
  "--version") echo "2.1.283 (Claude Code)"; exit 0 ;;
  "auth status") echo '{"loggedIn":true,"authMethod":"claude.ai"}'; exit 0 ;;
esac
model=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--model" ]; then model="$arg"; fi
  prev="$arg"
done
case "$model" in
  echo) exec cat ;;
  exit0) exit 0 ;;
  exit1) echo failing >&2; exit 1 ;;
  sleep) exec sleep 1000 ;;
  ignoreterm) trap '' TERM; echo ready; while :; do sleep 1; done ;;
  env) env | sort; exit 0 ;;
  pwd) pwd; exit 0 ;;
  fds) ls /proc/self/fd | sort -n | tr '\n' ' '; echo; exit 0 ;;
  ipc)
    # Landlock scoping: connect to an abstract socket of this session and
    # to one of the runner, and signal the runner. The targets come from
    # $HOME/ipc-target: "<abstract name> <pid> <port>".
    exec python3 - <<'PY'
import errno, os, socket
def err(e):
    return "denied " + errno.errorcode.get(e.errno, str(e.errno))
def connect(name):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(chr(0) + name)
        return "connected"
    except OSError as e:
        return err(e)
    finally:
        s.close()
name, pid, port = open(os.path.join(os.environ["HOME"], "ipc-target")).read().split()
own = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
own.bind(chr(0) + name + "-own")
own.listen(1)
print("own=" + connect(name + "-own"))
print("abstract=" + connect(name))
try:
    os.kill(int(pid), 0)
    print("signal=sent")
except OSError as e:
    print("signal=" + err(e))
for key, family, host, number in (("bind4", socket.AF_INET, "0.0.0.0", int(port)),
                                  ("bind6", socket.AF_INET6, "::", int(port)),
                                  ("port0", socket.AF_INET, "0.0.0.0", 0)):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        print(key + "=unavailable")
        continue
    try:
        s.bind((host, number))
        print(key + "=bound")
    except OSError as e:
        print(key + "=" + err(e))
    finally:
        s.close()
PY
    ;;
esac
exit 0
"#;

struct Fixture {
    dir: PathBuf,
    home: PathBuf,
    worktrees: PathBuf,
    harness_home: PathBuf,
    program: PathBuf,
    config: PathBuf,
    socket: PathBuf,
    cgroup: PathBuf,
    lines: Vec<String>,
    log: PathBuf,
    process: Option<Child>,
    env_overrides: BTreeMap<String, String>,
}

impl Fixture {
    fn new() -> Self {
        Self::with(None, true, true)
    }

    fn with(
        config_edit: Option<fn(&mut Fixture) -> Vec<String>>,
        cgroup: bool,
        cgroup_kill: bool,
    ) -> Self {
        let dir = std::env::temp_dir()
            .join(format!("chl-{:x}", uniq_id()))
            .canonicalize()
            .unwrap_or_else(|_| {
                let d = std::env::temp_dir().join(format!("chl-{:x}", uniq_id()));
                std::fs::create_dir(&d).unwrap();
                d.canonicalize().unwrap()
            });
        std::fs::create_dir_all(&dir).unwrap();
        let home = dir.join("home");
        let worktrees = dir.join("worktrees");
        let harness_home = home.join(".local/state/central/harness-home/claude");
        let program = home.join(".local/share/claude/versions/fake");
        for d in [
            home.join(".claude"),
            program.parent().unwrap().to_path_buf(),
            harness_home.join(".claude"),
            harness_home.join(".local/share/claude"),
            worktrees.join("attempt-1/repo"),
        ] {
            std::fs::create_dir_all(&d).unwrap();
        }
        // The tree-owner/mode checks require non-group-writable dirs even
        // under a permissive umask.
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            chmod(&d, 0o755);
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    stack.push(e.path());
                }
            }
        }
        std::fs::write(&program, FAKE_HARNESS).unwrap();
        chmod(&program, 0o755);
        let config = dir.join("harness-launcher.conf");
        let socket = dir.join("sock");
        let cgroup_dir = dir.join("cgroup");
        if cgroup {
            std::fs::create_dir(&cgroup_dir).unwrap();
            std::fs::write(cgroup_dir.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
            if cgroup_kill {
                std::fs::write(cgroup_dir.join("cgroup.kill"), "").unwrap();
            }
        }
        let mut fx = Self {
            dir,
            home,
            worktrees,
            harness_home,
            program,
            config,
            socket,
            cgroup: cgroup_dir,
            lines: Vec::new(),
            log: PathBuf::new(),
            process: None,
            env_overrides: BTreeMap::new(),
        };
        fx.log = fx.dir.join("daemon.log");
        fx.lines = fx.default_config();
        if let Some(edit) = config_edit {
            fx.lines = edit(&mut fx);
        }
        fx.write_config(None, 0o600);
        fx
    }

    fn default_config(&self) -> Vec<String> {
        vec![
            format!("operator_user {}", me()),
            format!("runtime_user {}", me()),
            format!("worktree_root {}", self.worktrees.display()),
            format!("harness claude {}", self.program.display()),
            "home_dir claude .local/state/central/harness-home/claude".to_string(),
            "mount claude .claude .claude rw dir".to_string(),
            "mount claude .local/share/claude .local/share/claude ro dir".to_string(),
        ]
    }

    fn write_config(&self, text: Option<String>, mode: u32) {
        if self.config.symlink_metadata().is_ok() {
            std::fs::remove_file(&self.config).unwrap();
        }
        let text = text.unwrap_or_else(|| self.lines.join("\n") + "\n");
        std::fs::write(&self.config, text).unwrap();
        chmod(&self.config, mode);
    }

    fn env(&self) -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        e.insert("PATH".into(), "/usr/bin:/bin".into());
        e.insert("CHL_TEST_SOCKET".into(), self.socket.display().to_string());
        e.insert("CHL_TEST_CONFIG".into(), self.config.display().to_string());
        e.insert("CHL_TEST_HOME".into(), self.home.display().to_string());
        e.insert(
            "CHL_TEST_CGROUP_ROOT".into(),
            self.cgroup.display().to_string(),
        );
        e.insert(
            "CHL_TEST_TRUSTED_DIR".into(),
            self.dir.display().to_string(),
        );
        e.extend(
            self.env_overrides
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        e
    }

    /// `true` once the daemon logged " started " (bound + cgroup setup).
    fn started(&self) -> bool {
        self.socket.exists() && self.log_text().contains(" started ")
    }

    fn start(&mut self) {
        self.start_inner(false);
    }

    fn start_expect_exit(&mut self) -> Option<i32> {
        self.start_inner(true)
    }

    #[allow(clippy::zombie_processes)] // Fixture::stop() waits it
    fn start_inner(&mut self, expect_exit: bool) -> Option<i32> {
        let logfile = std::fs::File::create(&self.log).unwrap();
        let err = logfile.try_clone().unwrap();
        let mut cmd = Command::new(BIN);
        cmd.env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::from(logfile))
            .stderr(Stdio::from(err));
        let mut child = cmd.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(expect_exit, "daemon exited {status}: {}", self.log_text());
                self.process = Some(child);
                return status.code();
            }
            if self.started() {
                self.process = Some(child);
                return None;
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
                kill(child.id() as i32, Signal::TERM);
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

    /// `restart` — a daemon with extra environment (test builds only).
    fn restart(&mut self, overrides: &[(&str, &str)]) {
        self.stop();
        self.env_overrides = overrides
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let _ = std::fs::remove_file(&self.socket);
        self.start();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        if std::env::var_os("CHL_TEST_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.dir);
        } else {
            eprintln!("kept {}", self.dir.display());
        }
    }
}

/// `fake_scope` — an unowned scope directory under the fake cgroup.
fn fake_scope(fx: &Fixture, populated: bool) -> ([u8; 16], PathBuf) {
    let scope = scope_id();
    let d = fx.cgroup.join("scopes").join(scope_text(&scope));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("cgroup.events"),
        format!("populated {}\nfrozen 0\n", i32::from(populated)),
    )
    .unwrap();
    std::fs::write(d.join("cgroup.kill"), "").unwrap();
    (scope, d)
}

fn alive(fx: &Fixture, scope: &[u8; 16]) -> bool {
    let data = expect(&fx.socket, &alive_frame(scope), reasons::OK, OP_ALIVE, &[]);
    assert!(data[8] <= 1 && data[9..] == [0, 0, 0], "{data:?}");
    data[8] == 1
}

/* ---- a live session ---- */

struct Session {
    scope: [u8; 16],
    conn: Option<OwnedFd>,
    stdin: Option<OwnedFd>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    pidfd: Option<OwnedFd>,
}

impl Session {
    fn launch(fx: &Fixture, frame: &[u8]) -> Self {
        let mut scope = [0u8; 16];
        scope.copy_from_slice(&frame[8..24]);
        let conn = connect(&fx.socket);
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let iov = [std::io::IoSlice::new(frame)];
        let _ = sendmsg(&conn, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
        let (data, mut fds) = recv_msg(&conn, 8);
        assert!(status_of(&data, OP_LAUNCH) == 0, "LAUNCH failed: {data:?}");
        assert!(fds.len() == 4, "expected 4 handoff fds, got {}", fds.len());
        Self {
            scope,
            conn: Some(conn),
            stdin: Some(fds.remove(0)),
            stdout: Some(fds.remove(0)),
            stderr: Some(fds.remove(0)),
            pidfd: Some(fds.remove(0)),
        }
    }

    fn expect_fail(fx: &Fixture, frame: &[u8], status: u8) {
        let conn = connect(&fx.socket);
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let iov = [std::io::IoSlice::new(frame)];
        let _ = sendmsg(&conn, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
        let (data, fds) = recv_msg(&conn, 8);
        assert!(
            status_of(&data, OP_LAUNCH) == status && fds.is_empty(),
            "{data:?}"
        );
    }

    fn init_pid(&self) -> i32 {
        let text = std::fs::read_to_string(format!(
            "/proc/self/fdinfo/{}",
            self.pidfd.as_ref().unwrap().as_raw_fd()
        ))
        .unwrap();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("Pid:") {
                return v.trim().parse().unwrap();
            }
        }
        panic!("no Pid in pidfd fdinfo");
    }

    fn harness_pid(&self) -> i32 {
        let init = self.init_pid();
        let mut found = 0;
        wait_until(
            || {
                let c = children_of(init);
                if let Some(first) = c.first() {
                    found = *first;
                    true
                } else {
                    false
                }
            },
            Duration::from_secs(10),
            "the harness process",
        );
        found
    }

    /// `(signaled, code)` from EXIT; `None` when the lifeline closed
    /// without one.
    fn wait_exit(&mut self, timeout: Duration) -> Option<(bool, u16)> {
        let conn = self.conn.as_ref().unwrap();
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 64];
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "no EXIT after {timeout:?}");
            match recvmsg(
                conn,
                &mut iov,
                &mut control,
                RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
            ) {
                Err(Errno::INTR) | Err(Errno::AGAIN) => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(Errno::CONNRESET) => return None,
                Err(e) => panic!("recvmsg: {e}"),
                Ok(m) => {
                    let data = &buf[..m.bytes.min(64)];
                    if m.bytes == 0 {
                        return None;
                    }
                    assert!(status_of(data, OP_EXIT) == reasons::OK, "{data:?}");
                    assert!(data[9] == 0);
                    return Some((data[8] == 1, u16::from_be_bytes([data[10], data[11]])));
                }
            }
        }
    }
}

/* ======================= validate-build tests ======================= */

fn validate_fixture() -> Fixture {
    let mut fx = Fixture::new();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.start();
    fx
}

fn session_fixture() -> Fixture {
    let mut fx = Fixture::new();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_SWEEP_TIMEOUT_MS".into(), "2000".into());
    fx.env_overrides
        .insert("CHL_TEST_CLEAN_TIMEOUT_MS".into(), "20000".into());
    fx.env_overrides
        .insert("CHL_TEST_DRAIN_TIMEOUT_MS".into(), "5000".into());
    fx.start();
    fx
}

#[test]
fn every_allowed_argv_form_is_accepted() {
    let fx = validate_fixture();
    for argv in [
        vec![b"--version".to_vec()],
        vec![b"auth".to_vec(), b"status".to_vec()],
    ] {
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"", Some(argv.clone()), None),
            reasons::OK,
        );
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", Some(argv), None),
            reasons::OK,
        );
    }
    for policy in [DENY, BRIDGE, BYPASS] {
        for flag in ["--session-id", "--resume"] {
            for model in [
                None,
                Some("haiku"),
                Some("claude-sonnet-4-5-20250929"),
                Some("a"),
                Some("Opus4.1:beta_x"),
                Some("opus[1m]"),
                Some("claude-3-5-haiku@20241022"),
                Some("a/b"),
            ] {
                expect_launch(
                    &fx.socket,
                    &launch_frame(
                        None,
                        b"claude",
                        b"attempt-1/repo",
                        Some(session_argv(model, policy, flag, None, None)),
                        None,
                    ),
                    reasons::OK,
                );
            }
        }
    }
    for budget in ["0.01", "0.50", "5.00", "12.34", "999.99", "1000.00"] {
        for model in [None, Some("haiku")] {
            expect_launch(
                &fx.socket,
                &launch_frame(
                    None,
                    b"claude",
                    b"attempt-1/repo",
                    Some(session_argv(
                        model,
                        DENY,
                        "--session-id",
                        None,
                        Some(budget),
                    )),
                    None,
                ),
                reasons::OK,
            );
            expect_launch(
                &fx.socket,
                &launch_frame(
                    None,
                    b"claude",
                    b"attempt-1/repo",
                    Some(session_argv(model, BRIDGE, "--resume", None, Some(budget))),
                    None,
                ),
                reasons::OK,
            );
            expect_launch(
                &fx.socket,
                &launch_frame(
                    None,
                    b"claude",
                    b"attempt-1/repo",
                    Some(session_argv(
                        model,
                        BYPASS,
                        "--session-id",
                        None,
                        Some(budget),
                    )),
                    None,
                ),
                reasons::OK,
            );
        }
    }
}

#[test]
fn argv_outside_the_grammar_is_refused() {
    let fx = validate_fixture();
    let sid = scope_text(&scope_id());
    let base = session_argv(None, DENY, "--session-id", Some(sid.clone()), None);
    let b = |extra: &[&str]| -> Vec<Vec<u8>> {
        let mut v = base.clone();
        v.extend(extra.iter().map(|s| s.as_bytes().to_vec()));
        v
    };
    let strv = |v: &[&str]| -> Vec<Vec<u8>> { v.iter().map(|s| s.as_bytes().to_vec()).collect() };
    let mut refused: Vec<Vec<Vec<u8>>> = vec![
        vec![],
        strv(&["-p"]),
        strv(&["auth", "login"]),
        strv(&["auth", "logout"]),
        strv(&["auth", "status", "--json"]),
        strv(&["--version", "--json"]),
        strv(&["--version", "--version"]),
        strv(&["auth"]),
        strv(&["status"]),
        strv(&["--help"]),
        b(&["--settings", "/tmp/s.json"]),
        b(&["--mcp-config", "/tmp/m.json"]),
        b(&["--add-dir", "/tmp"]),
        b(&["--dangerously-skip-permissions"]),
        b(&["hello"]),
        b(&["--verbose"]),
        {
            let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
            v.push(format!("--session-id={sid}").into_bytes());
            v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
            v
        },
        {
            let mut v = base[..base.len() - 4].to_vec();
            v.extend(strv(&[
                "--permission-mode=dontAsk",
                "--permission-prompts",
                "none",
            ]));
            v
        },
        b(&["--model=haiku"]),
        b(&["--model"]),
        b(&["--model", "-x"]),
        b(&["--model", ""]),
        b(&["--model", "haiku", "--model", "haiku"]),
        b(&["--max-budget-usd"]),
        b(&["--max-budget-usd=5.00"]),
        b(&["--max-budget-usd", ""]),
        b(&["--max-budget-usd", "5"]),
        b(&["--max-budget-usd", "5.0"]),
        b(&["--max-budget-usd", "5.000"]),
        b(&["--max-budget-usd", "0.00"]),
        b(&["--max-budget-usd", "1000.01"]),
        b(&["--max-budget-usd", "10000.00"]),
        b(&["--max-budget-usd", "-5.00"]),
        b(&["--max-budget-usd", "+5.00"]),
        b(&["--max-budget-usd", "5,00"]),
        b(&["--max-budget-usd", "5.00 "]),
        b(&["--max-budget-usd", "--verbose"]),
        b(&["--max-budget-usd", "5.00", "--max-budget-usd", "5.00"]),
        b(&["--max-budget-usd", "5.00", "--model", "haiku"]),
        b(&["--model", "haiku", "--max-budget-usd", "5.00", "--verbose"]),
        b(&["--max-budget-usd", "1e3"]),
        b(&["--max-budget-usd", "0x1.00"]),
        b(&["--max-budget-usd", "00.01"]),
        b(&["--max-budget-usd", "0999.99"]),
        b(&["--max-budget-usd", "0100.00"]),
        b(&["--max-budget-usd", "01.00"]),
        b(&["--max-budget-usd", " 5.00"]),
        b(&["--max-budget-usd", "5.00\n"]),
        b(&["--model", "haiku", "--max-budget-usd"]),
        b(&[
            "--model",
            "haiku",
            "--max-budget-usd",
            "5.00",
            "--model",
            "haiku",
        ]),
    ];
    // model value limits
    refused.push(b(&["--model"]));
    refused.push({
        let mut v = base.clone();
        v.push(b"--model".to_vec());
        v.push(vec![b'x'; 129]);
        v
    });
    refused.push(b(&["--model", "a b"]));
    refused.push(b(&["--model", "a=b"]));
    // session-id grammar
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.to_uppercase().into_bytes());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(b"not-a-uuid".to_vec());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.push(b"--resume".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    v.extend(BYPASS.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX[1..].iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    let mut v: Vec<Vec<u8>> = vec![b"--verbose".to_vec()];
    v.extend(PREFIX.iter().map(|s| s.as_bytes().to_vec()));
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    for mode in ["default", "acceptEdits", "plan"] {
        let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
        v.push(b"--session-id".to_vec());
        v.push(sid.clone().into_bytes());
        v.extend(vec![
            b"--permission-mode".to_vec(),
            mode.as_bytes().to_vec(),
        ]);
        refused.push(v);
    }
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(vec![
        b"--permission-mode".to_vec(),
        b"manual".to_vec(),
        b"--permission-prompts".to_vec(),
        b"host".to_vec(),
    ]);
    refused.push(v);
    let mut v: Vec<Vec<u8>> = PREFIX.iter().map(|s| s.as_bytes().to_vec()).collect();
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(vec![b"--permission-mode".to_vec(), b"dontAsk".to_vec()]);
    refused.push(v);
    let mut v: Vec<Vec<u8>> = vec![
        b"-p".to_vec(),
        b"--verbose".to_vec(),
        b"--output-format".to_vec(),
        b"text".to_vec(),
    ];
    v.extend(PREFIX[4..].iter().map(|s| s.as_bytes().to_vec()));
    v.push(b"--session-id".to_vec());
    v.push(sid.clone().into_bytes());
    v.extend(DENY.iter().map(|s| s.as_bytes().to_vec()));
    refused.push(v);
    for argv in refused {
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", Some(argv.clone()), None),
            reasons::ARGV_REFUSED,
        );
    }
}

fn opencode_fixture_config(fx: &mut Fixture) -> Vec<String> {
    let program = fx.home.join(".opencode/bin/fake-opencode");
    let home = fx.home.join(".local/state/central/harness-home/opencode");
    for d in [
        fx.home.join(".config/opencode"),
        fx.home.join(".local/share/opencode"),
        fx.home.join(".cache/opencode"),
        program.parent().unwrap().to_path_buf(),
        home.join(".config/opencode"),
        home.join(".local/share/opencode"),
        home.join(".cache/opencode"),
        home.join(".opencode/bin"),
    ] {
        std::fs::create_dir_all(&d).unwrap();
    }
    std::fs::write(&program, FAKE_HARNESS).unwrap();
    chmod(&program, 0o755);
    let mut lines = fx.lines.clone();
    lines.push(format!("harness opencode {}", program.display()));
    lines.push("home_dir opencode .local/state/central/harness-home/opencode".into());
    lines.push("mount opencode .config/opencode .config/opencode rw dir".into());
    lines.push("mount opencode .local/share/opencode .local/share/opencode rw dir".into());
    lines.push("mount opencode .cache/opencode .cache/opencode rw dir".into());
    lines.push("mount opencode .opencode/bin .opencode/bin ro dir".into());
    lines
}

fn codex_fixture_config(fx: &mut Fixture) -> Vec<String> {
    let program = fx.home.join(".codex-bin/fake-codex");
    let home = fx.home.join(".local/state/central/harness-home/codex");
    for d in [
        fx.home.join(".codex"),
        program.parent().unwrap().to_path_buf(),
        home.join(".codex"),
        home.join(".codex-bin"),
    ] {
        std::fs::create_dir_all(&d).unwrap();
    }
    std::fs::write(&program, FAKE_HARNESS).unwrap();
    chmod(&program, 0o755);
    let mut lines = fx.lines.clone();
    lines.push(format!("harness codex {}", program.display()));
    lines.push("home_dir codex .local/state/central/harness-home/codex".into());
    lines.push("mount codex .codex .codex rw dir".into());
    lines.push("mount codex .codex-bin .codex-bin ro dir".into());
    lines
}

fn antigravity_fixture_config(fx: &mut Fixture) -> Vec<String> {
    let program = fx.home.join(".local/bin/fake-agy");
    let home = fx
        .home
        .join(".local/state/central/harness-home/antigravity");
    for d in [
        fx.home.join(".gemini/antigravity-cli"),
        program.parent().unwrap().to_path_buf(),
        home.join(".gemini/antigravity-cli"),
        home.join(".local/bin"),
    ] {
        std::fs::create_dir_all(&d).unwrap();
    }
    std::fs::write(&program, FAKE_HARNESS).unwrap();
    chmod(&program, 0o755);
    let mut lines = fx.lines.clone();
    lines.push(format!("harness antigravity {}", program.display()));
    lines.push("home_dir antigravity .local/state/central/harness-home/antigravity".into());
    lines.push("mount antigravity .gemini/antigravity-cli .gemini/antigravity-cli rw dir".into());
    lines.push("mount antigravity .local/bin .local/bin ro dir".into());
    lines
}

const OPENCODE_SESSION: &str = "ses_ed9de340effe7fBtzPkP81yXKj";
const CODEX_THREAD: &str = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
const AGY_CONVERSATION: &str = "9eafbf42-15c3-46f1-b4c0-e851a8f89112";

fn opencode_session_argv(model: Option<&str>, session: Option<&str>) -> Vec<Vec<u8>> {
    let mut a = vec![b"run".to_vec(), b"--format".to_vec(), b"json".to_vec()];
    if let Some(m) = model {
        a.push(b"--model".to_vec());
        a.push(m.as_bytes().to_vec());
    }
    if let Some(s) = session {
        a.push(b"--session".to_vec());
        a.push(s.as_bytes().to_vec());
    }
    a
}

fn codex_session_argv(model: Option<&str>, resume: bool) -> Vec<Vec<u8>> {
    let mut a: Vec<Vec<u8>> = if resume {
        vec![
            b"exec".to_vec(),
            b"resume".to_vec(),
            b"--json".to_vec(),
            b"-c".to_vec(),
            b"sandbox_mode=\"workspace-write\"".to_vec(),
        ]
    } else {
        vec![
            b"exec".to_vec(),
            b"--json".to_vec(),
            b"-s".to_vec(),
            b"workspace-write".to_vec(),
        ]
    };
    if let Some(m) = model {
        a.push(b"--model".to_vec());
        a.push(m.as_bytes().to_vec());
    }
    if resume {
        a.push(CODEX_THREAD.as_bytes().to_vec());
    }
    a.push(b"-".to_vec());
    a
}

fn antigravity_session_argv(model: Option<&str>, conversation: Option<&str>) -> Vec<Vec<u8>> {
    let mut a = vec![
        b"--input-format".to_vec(),
        b"stream-json".to_vec(),
        b"--output-format".to_vec(),
        b"stream-json".to_vec(),
        b"--disable-slash-commands".to_vec(),
    ];
    if let Some(m) = model {
        a.push(b"--model".to_vec());
        a.push(m.as_bytes().to_vec());
    }
    if let Some(c) = conversation {
        a.push(b"--conversation".to_vec());
        a.push(c.as_bytes().to_vec());
    }
    a
}

#[test]
fn opencode_argv_grammar() {
    let mut fx = Fixture::with(Some(opencode_fixture_config), true, true);
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.start();
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"opencode",
            b"",
            Some(vec![b"--version".to_vec()]),
            None,
        ),
        reasons::OK,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"opencode",
            b"attempt-1/repo",
            Some(vec![b"--version".to_vec()]),
            None,
        ),
        reasons::OK,
    );
    for model in [
        None,
        Some("m"),
        Some("opencode/mimo-v2.6-flash-free"),
        Some("nvidia/meta/llama-3.2-1b-instruct"),
        Some("x.ai/grok-code-fast-1"),
        Some("a"),
    ] {
        for session in [None, Some(OPENCODE_SESSION)] {
            expect_launch(
                &fx.socket,
                &launch_frame(
                    None,
                    b"opencode",
                    b"attempt-1/repo",
                    Some(opencode_session_argv(model, session)),
                    None,
                ),
                reasons::OK,
            );
        }
    }
    for argv in [
        vec![],
        vec![b"run".to_vec()],
        vec![b"run".to_vec(), b"--format".to_vec()],
        vec![b"run".to_vec(), b"--format".to_vec(), b"jsonl".to_vec()],
        vec![
            b"run".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"--model".to_vec(),
        ],
        vec![
            b"run".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"--model".to_vec(),
            b"".to_vec(),
        ],
        vec![
            b"run".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"--model".to_vec(),
            b"a b".to_vec(),
        ],
        vec![
            b"run".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"--session".to_vec(),
        ],
        vec![
            b"run".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"--session".to_vec(),
            b"bad".to_vec(),
        ],
        vec![
            b"run".to_vec(),
            b"--format".to_vec(),
            b"json".to_vec(),
            b"extra".to_vec(),
        ],
        vec![b"--version".to_vec(), b"--version".to_vec()],
        vec![
            b"exec".to_vec(),
            b"--json".to_vec(),
            b"-s".to_vec(),
            b"workspace-write".to_vec(),
            b"-".to_vec(),
        ],
    ] {
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"opencode", b"attempt-1/repo", Some(argv), None),
            reasons::ARGV_REFUSED,
        );
    }
}

#[test]
fn codex_argv_grammar() {
    let mut fx = Fixture::with(Some(codex_fixture_config), true, true);
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.start();
    for (wd, argv) in [
        (b"".as_slice(), vec![b"--version".to_vec()]),
        (b"attempt-1/repo".as_slice(), vec![b"--version".to_vec()]),
        (b"".as_slice(), vec![b"login".to_vec(), b"status".to_vec()]),
        (
            b"attempt-1/repo".as_slice(),
            vec![b"login".to_vec(), b"status".to_vec()],
        ),
    ] {
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"codex", wd, Some(argv), None),
            reasons::OK,
        );
    }
    for model in [
        None,
        Some("m"),
        Some("openai/gpt-5.2-codex"),
        Some("a:b_c.d/e[f]g@h"),
        Some(&"x".repeat(128)),
    ] {
        for resume in [false, true] {
            expect_launch(
                &fx.socket,
                &launch_frame(
                    None,
                    b"codex",
                    b"attempt-1/repo",
                    Some(codex_session_argv(model, resume)),
                    None,
                ),
                reasons::OK,
            );
        }
    }
    let strv = |v: &[&str]| -> Vec<Vec<u8>> { v.iter().map(|s| s.as_bytes().to_vec()).collect() };
    let base = codex_session_argv(None, false);
    let base = &base[..base.len() - 1]; // without "-"
    let resume = codex_session_argv(None, true);
    let resume = &resume[..resume.len() - 2]; // without thread and "-"
    let t = CODEX_THREAD;
    let mut refused: Vec<Vec<Vec<u8>>> = vec![
        vec![],
        strv(&["exec"]),
        strv(&["exec", "--json"]),
        strv(&["exec", "--json", "-s"]),
        {
            let mut v = base.to_vec();
            v.push(b"hello".to_vec());
            v
        },
        {
            let mut v = base.to_vec();
            v.push(b"--last".to_vec());
            v
        },
        {
            let mut v = base.to_vec();
            v.extend(strv(&["-", "-"]));
            v
        },
        strv(&["exec", "--json", "-s", "read-only", "-"]),
        strv(&["exec", "resume", "--json", t, "-"]),
        strv(&[
            "exec",
            "resume",
            "--json",
            "-c",
            "sandbox_mode=\"workspace-write\"",
            "-",
        ]),
        strv(&[
            "exec",
            "resume",
            "--json",
            "-c",
            "sandbox_mode=\"workspace-write\"",
            t,
        ]),
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["-s", "workspace-write", t, "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["-c", "sandbox_mode=\"workspace-write\"", t, "-"]));
            v
        },
        strv(&[
            "exec",
            "--json",
            "-s",
            "workspace-write",
            "-c",
            "sandbox_mode=\"workspace-write\"",
            "-",
        ]),
        strv(&[
            "exec",
            "--json",
            "-s",
            "workspace-write",
            "-c",
            "sandbox_mode=\"read-only\"",
            "-",
        ]),
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["--model"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["--model", ""]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["--model", "-x"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["--model", "a b"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["--model", "a;b"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.push(b"--model".to_vec());
            v.push(vec![b'x'; 129]);
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["--model", "m", "--model", "n", t, "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["", "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["abc123", "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["AAAAAAAA-AAAA-4AAA-AAAA-AAAAAAAAAAAA", "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&["{aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa}", "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&[t]));
            v.last_mut().unwrap().push(b'0');
            v.push(b"-".to_vec());
            v
        },
        {
            let mut v = resume.to_vec();
            let mut bad = t.to_string();
            bad.replace_range(35..36, "g");
            v.push(bad.into_bytes());
            v.push(b"-".to_vec());
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&[t, t, "-"]));
            v
        },
        {
            let mut v = resume.to_vec();
            v.extend(strv(&[t, "--model", "m", "-"]));
            v
        },
        {
            let mut v = base.to_vec();
            v.extend(strv(&["--model", "m", "-", "--verbose"]));
            v
        },
        {
            let mut v = strv(&["--model", "m"]);
            v.extend(base.to_vec());
            v.push(b"-".to_vec());
            v
        },
    ];
    for extra in [
        &["--skip-git-repo-check"] as &[_],
        &["--ephemeral"],
        &["--approve-for-me"],
        &["--dangerously-bypass-approvals-and-sandbox"],
        &["-C", "/tmp"],
        &["--add-dir", "/tmp"],
        &["--worktree", "w"],
        &["--profile", "p"],
        &["--oss"],
        &["-i", "img.png"],
        &["-o", "out"],
        &["--output-schema", "s"],
        &["--color", "never"],
    ] {
        let mut v = base.to_vec();
        v.extend(extra.iter().map(|s| s.as_bytes().to_vec()));
        v.push(b"-".to_vec());
        refused.push(v);
    }
    refused.push(strv(&["auth", "status"]));
    for argv in refused {
        let (data, _) = request(
            &fx.socket,
            &launch_frame(None, b"codex", b"attempt-1/repo", Some(argv.clone()), None),
            &[],
        );
        assert!(
            status_of(&data, OP_LAUNCH) == reasons::ARGV_REFUSED,
            "{argv:?}"
        );
    }
    // Grammar isolation against claude (the default fixture harness).
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"codex",
            b"attempt-1/repo",
            Some(default_argv()),
            None,
        ),
        reasons::ARGV_REFUSED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(codex_session_argv(None, false)),
            None,
        ),
        reasons::ARGV_REFUSED,
    );
}

#[test]
fn antigravity_argv_grammar() {
    let mut fx = Fixture::with(Some(antigravity_fixture_config), true, true);
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.start();
    for model in [None, Some("gemini-3-pro-preview"), Some("a")] {
        for conv in [None, Some(AGY_CONVERSATION)] {
            expect_launch(
                &fx.socket,
                &launch_frame(
                    None,
                    b"antigravity",
                    b"attempt-1/repo",
                    Some(antigravity_session_argv(model, conv)),
                    None,
                ),
                reasons::OK,
            );
        }
    }
    for argv in [
        vec![],
        vec![b"--input-format".to_vec()],
        vec![
            b"--input-format".to_vec(),
            b"text".to_vec(),
            b"--output-format".to_vec(),
            b"stream-json".to_vec(),
            b"--disable-slash-commands".to_vec(),
        ],
        {
            let mut v = antigravity_session_argv(None, None);
            v.push(b"--conversation".to_vec());
            v
        },
        {
            let mut v = antigravity_session_argv(None, None);
            v.push(b"--conversation".to_vec());
            v.push(b"not-a-uuid".to_vec());
            v
        },
        {
            let mut v = antigravity_session_argv(None, Some(AGY_CONVERSATION));
            v.push(b"extra".to_vec());
            v
        },
    ] {
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"antigravity", b"attempt-1/repo", Some(argv), None),
            reasons::ARGV_REFUSED,
        );
    }
}

#[test]
fn codex_and_opencode_grammars_are_isolated() {
    let mut fx = Fixture::new();
    fx.lines = {
        let l1 = opencode_fixture_config(&mut fx);
        fx.lines = l1;
        codex_fixture_config(&mut fx)
    };
    fx.write_config(None, 0o600);
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.start();
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"opencode",
            b"attempt-1/repo",
            Some(codex_session_argv(None, false)),
            None,
        ),
        reasons::ARGV_REFUSED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"codex",
            b"attempt-1/repo",
            Some(opencode_session_argv(None, None)),
            None,
        ),
        reasons::ARGV_REFUSED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"codex",
            b"attempt-1/repo",
            Some(codex_session_argv(None, true)),
            None,
        ),
        reasons::OK,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"opencode",
            b"attempt-1/repo",
            Some(opencode_session_argv(None, None)),
            None,
        ),
        reasons::OK,
    );
}

/* A minimal JSON reader for the flat launch-env-vectors file:
 * `{"vectors": [{"id","env":{str:str},"accept":bool,"wire"?:bool}]}`. */
fn parse_env_vectors() -> Vec<(String, Vec<Vec<u8>>, bool, bool)> {
    let text = std::fs::read_to_string(VECTORS).unwrap();
    let b = text.as_bytes();
    let mut i = 0usize;
    let ws = |i: &mut usize| {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    };
    fn string(b: &[u8], i: &mut usize) -> String {
        assert!(b[*i] == b'"');
        *i += 1;
        let mut out = String::new();
        while b[*i] != b'"' {
            if b[*i] == b'\\' {
                *i += 1;
                match b[*i] {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'\\' => out.push('\\'),
                    b'"' => out.push('"'),
                    b'u' => {
                        let hex = std::str::from_utf8(&b[*i + 1..*i + 5]).unwrap();
                        let cp = u32::from_str_radix(hex, 16).unwrap();
                        out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        *i += 4;
                    }
                    c => out.push(c as char),
                }
            } else {
                out.push(b[*i] as char);
            }
            *i += 1;
        }
        *i += 1;
        out
    }
    let mut out = Vec::new();
    while i < b.len() {
        ws(&mut i);
        if i >= b.len() {
            break;
        }
        if b[i] == b'{' {
            // An object: collect id/env/accept/wire if present.
            let mut id = String::new();
            let mut env = Vec::new();
            let mut accept = false;
            let mut wire = true;
            i += 1;
            loop {
                ws(&mut i);
                if b[i] == b'}' {
                    i += 1;
                    break;
                }
                if b[i] == b',' {
                    i += 1;
                    continue;
                }
                let key = string(b, &mut i);
                ws(&mut i);
                assert!(b[i] == b':');
                i += 1;
                ws(&mut i);
                match key.as_str() {
                    "id" => id = string(b, &mut i),
                    "accept" => {
                        accept = b[i..].starts_with(b"true");
                        while i < b.len() && (b[i].is_ascii_alphabetic()) {
                            i += 1;
                        }
                    }
                    "wire" => {
                        wire = b[i..].starts_with(b"true");
                        while i < b.len() && (b[i].is_ascii_alphabetic()) {
                            i += 1;
                        }
                    }
                    "env" => {
                        assert!(b[i] == b'{');
                        i += 1;
                        loop {
                            ws(&mut i);
                            if b[i] == b'}' {
                                i += 1;
                                break;
                            }
                            if b[i] == b',' {
                                i += 1;
                                continue;
                            }
                            let name = string(b, &mut i);
                            ws(&mut i);
                            assert!(b[i] == b':');
                            i += 1;
                            ws(&mut i);
                            let value = string(b, &mut i);
                            env.push(format!("{name}={value}").into_bytes());
                        }
                    }
                    _ => {
                        // "comment" or anything else: skip a scalar.
                        while i < b.len() && !matches!(b[i], b',' | b'}') {
                            if b[i] == b'"' {
                                let _ = string(b, &mut i);
                            } else {
                                i += 1;
                            }
                        }
                    }
                }
            }
            if !id.is_empty() {
                out.push((id, env, accept, wire));
            }
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn shared_env_vectors_hold() {
    let fx = validate_fixture();
    let mut sent = 0usize;
    for (id, env, accept, wire) in parse_env_vectors() {
        if !wire {
            continue;
        }
        let want = if accept {
            reasons::OK
        } else {
            reasons::ENV_REFUSED
        };
        let (data, _) = request(
            &fx.socket,
            &launch_frame(
                None,
                b"claude",
                b"",
                Some(vec![b"--version".to_vec()]),
                Some(env),
            ),
            &[],
        );
        assert!(status_of(&data, OP_LAUNCH) == want, "vector {id:?}");
        sent += 1;
    }
    assert!(sent >= 50, "only {sent} vectors");
}

#[test]
fn workdir_is_confined_to_the_worktree_root() {
    let fx = validate_fixture();
    std::fs::write(fx.worktrees.join("attempt-1/file"), "x").unwrap();
    std::os::unix::fs::symlink(fx.worktrees.join("attempt-1"), fx.worktrees.join("link")).unwrap();
    std::os::unix::fs::symlink(&fx.home, fx.worktrees.join("attempt-1/escape")).unwrap();
    for workdir in [
        "..".as_bytes().to_vec(),
        b"../x".to_vec(),
        b"/abs".to_vec(),
        fx.worktrees
            .join("attempt-1")
            .as_os_str()
            .as_bytes()
            .to_vec(),
        b"attempt-1/../attempt-1".to_vec(),
        b"./attempt-1".to_vec(),
        b"attempt-1//repo".to_vec(),
        b"attempt-1/".to_vec(),
        b".".to_vec(),
        b"missing".to_vec(),
        b"attempt-1/file".to_vec(),
        b"link".to_vec(),
        b"link/repo".to_vec(),
        b"attempt-1/escape".to_vec(),
        b"attempt-1/\x01".to_vec(),
    ] {
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", &workdir, None, None),
            reasons::WORKDIR_INVALID,
        );
    }
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"", None, None),
        reasons::WORKDIR_INVALID,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1", None, None),
        reasons::OK,
    );
}

#[test]
fn an_unconfigured_harness_is_unknown() {
    let fx = validate_fixture();
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"opencode",
            b"",
            Some(vec![b"--version".to_vec()]),
            None,
        ),
        reasons::UNKNOWN_HARNESS,
    );
    for bad in [
        b"Claude".to_vec(),
        b"".to_vec(),
        vec![b'x'; 33],
        b"../claude".to_vec(),
        b"claude\x00".to_vec(),
    ] {
        expect_launch(
            &fx.socket,
            &launch_frame(None, &bad, b"attempt-1/repo", None, None),
            reasons::REQUEST_MALFORMED,
        );
    }
}

#[test]
fn malformed_frames_are_refused() {
    let fx = validate_fixture();
    let good = launch_frame(None, b"claude", b"attempt-1/repo", None, None);
    expect_launch(&fx.socket, &good, reasons::OK);
    for n in [8usize, 23, 24, 25, good.len() - 1] {
        expect_launch(&fx.socket, &good[..n], reasons::REQUEST_MALFORMED);
    }
    let mut f = good.clone();
    f.push(0);
    expect_launch(&fx.socket, &f, reasons::REQUEST_MALFORMED);
    let mut f = header(OP_LAUNCH, 1, 0);
    f.extend_from_slice(&good[8..]);
    expect_launch(&fx.socket, &f, reasons::REQUEST_MALFORMED);
    let mut f = header(OP_LAUNCH, 0, 1);
    f.extend_from_slice(&good[8..]);
    expect_launch(&fx.socket, &f, reasons::REQUEST_MALFORMED);
    expect_launch(
        &fx.socket,
        &launch_frame(Some([0u8; 16]), b"claude", b"attempt-1/repo", None, None),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(vec![b"x".to_vec(); 65]),
            None,
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(vec![vec![b'x'; 4097]]),
            None,
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some((0..65).map(|i| format!("LC_{i}=v").into_bytes()).collect()),
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some(vec![format!("LC_A={}", "v".repeat(8188)).into_bytes()]),
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some(vec![format!("LC_A={}", "v".repeat(8187)).into_bytes()]),
        ),
        reasons::OK,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some(vec![b"PATH".to_vec()]),
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some(vec![b"PATH=/a".to_vec(), b"PATH=/b".to_vec()]),
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some(vec![b"".to_vec()]),
        ),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", &vec![b'a'; 4097], None, None),
        reasons::REQUEST_MALFORMED,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(vec![b"--ver\x00sion".to_vec()]),
            None,
        ),
        reasons::REQUEST_MALFORMED,
    );
    // Oversized: over the 64 KiB total with each field within its cap.
    let big = launch_frame(
        None,
        b"claude",
        b"attempt-1/repo",
        Some(vec![vec![b'a'; 4096]; 16]),
        None,
    );
    assert!(big.len() > 65536);
    expect_launch(&fx.socket, &big, reasons::REQUEST_MALFORMED);
    // At the cap exactly is parsed (and then refused by the grammar).
    let base = launch_frame(
        None,
        b"claude",
        b"attempt-1/repo",
        Some(vec![vec![b'a'; 4096]; 15]),
        Some(vec![]),
    );
    let fill = 65536 - base.len() - 2;
    let exact = launch_frame(
        None,
        b"claude",
        b"attempt-1/repo",
        Some(vec![vec![b'a'; 4096]; 15]),
        Some(vec![format!("A={}", "v".repeat(fill - 2)).into_bytes()]),
    );
    assert!(exact.len() == 65536, "{}", exact.len());
    expect_launch(&fx.socket, &exact, reasons::ARGV_REFUSED);
    // Descriptors attached to a request are closed and refused.
    let (r, w) = rustix::pipe::pipe().unwrap();
    expect(
        &fx.socket,
        &good,
        reasons::REQUEST_MALFORMED,
        OP_LAUNCH,
        &[r],
    );
    drop(w);
    // ALIVE and KILL shapes.
    let scope = scope_id();
    let mut f = alive_frame(&scope);
    f.push(0);
    expect(&fx.socket, &f, reasons::REQUEST_MALFORMED, OP_ALIVE, &[]);
    expect(
        &fx.socket,
        &alive_frame(&[0u8; 16]),
        reasons::REQUEST_MALFORMED,
        OP_ALIVE,
        &[],
    );
    expect(
        &fx.socket,
        &kill_frame(&scope, 30001),
        reasons::REQUEST_MALFORMED,
        OP_KILL,
        &[],
    );
    expect(
        &fx.socket,
        &kill_frame(&[0u8; 16], 0),
        reasons::REQUEST_MALFORMED,
        OP_KILL,
        &[],
    );
    expect(
        &fx.socket,
        &kill_frame(&scope, 0)[..27],
        reasons::REQUEST_MALFORMED,
        OP_KILL,
        &[],
    );
    // No usable header: no opcode to answer with, so the connection closes.
    for frame in [
        b"CHL2".to_vec(),
        {
            let mut v = b"CHL1\x02".to_vec();
            v.extend_from_slice(&good[5..]);
            v
        },
        {
            let mut v = header(OP_EXIT, 0, 0);
            v.extend_from_slice(&scope);
            v
        },
        {
            let mut v = header(9, 0, 0);
            v.extend_from_slice(&scope);
            v
        },
    ] {
        let (data, _) = request(&fx.socket, &frame, &[]);
        assert!(data.is_empty(), "{frame:?}");
    }
    let (data, _) = request(&fx.socket, b"", &[]);
    assert!(data.is_empty());
}

#[test]
fn reasons_never_echo_request_values() {
    let fx = validate_fixture();
    let marker = format!("zzmarker{:x}", uniq_id() & 0xffff_ffff);
    let frames = vec![
        launch_frame(None, b"claude", marker.as_bytes(), None, None),
        launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some({
                let mut v = session_argv(Some(&marker), DENY, "--session-id", None, None);
                v.push(marker.as_bytes().to_vec());
                v
            }),
            None,
        ),
        launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            None,
            Some(vec![
                format!("LC_{marker}={marker}").into_bytes(),
                format!("EDITOR={marker}").into_bytes(),
            ]),
        ),
        launch_frame(
            None,
            b"opencode",
            b"attempt-1/repo",
            Some(vec![marker.as_bytes().to_vec()]),
            None,
        ),
    ];
    for frame in frames {
        let (data, fds) = request(&fx.socket, &frame, &[]);
        assert!(
            data.len() == 12
                && fds.is_empty()
                && !data.windows(marker.len()).any(|w| w == marker.as_bytes())
        );
    }
    fx_log_flushed(&fx, |log| log.contains("reason="));
    let log = fx.log_text();
    assert!(!log.contains(&marker), "the daemon logged a request value");
    assert!(log.contains("reason="));
}

fn fx_log_flushed(fx: &Fixture, pred: impl Fn(&str) -> bool) {
    wait_until(
        || pred(&fx.log_text()),
        Duration::from_secs(3),
        "a daemon log line",
    );
}

#[test]
fn operator_must_be_a_real_unprivileged_login() {
    let mut fx = validate_fixture();
    for name in [
        "root",
        "daemon",
        &format!("no-such-user-{:x}", uniq_id() & 0xffffff),
    ] {
        fx.lines = fx
            .default_config()
            .into_iter()
            .filter(|l| !l.starts_with("operator_user"))
            .chain(std::iter::once(format!("operator_user {name}")))
            .collect();
        fx.write_config(None, 0o600);
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::OPERATOR_INVALID,
        );
    }
}

#[test]
fn config_file_metadata_is_checked() {
    let fx = validate_fixture();
    let probe = launch_frame(None, b"claude", b"attempt-1/repo", None, None);
    for mode in [0o640u32, 0o666, 0o400, 0o700, 0o604] {
        fx.write_config(None, mode);
        expect_launch(&fx.socket, &probe, reasons::CONFIG_INVALID);
    }
    for mode in [0o600u32, 0o644] {
        fx.write_config(None, mode);
        expect_launch(&fx.socket, &probe, reasons::OK);
    }
    // Hard link (nlink 2).
    let link = fx.dir.join("hardlink.conf");
    std::fs::hard_link(&fx.config, &link).unwrap();
    expect_launch(&fx.socket, &probe, reasons::CONFIG_INVALID);
    std::fs::remove_file(&link).unwrap();
    expect_launch(&fx.socket, &probe, reasons::OK);
    // Symlink.
    let real = fx.dir.join("real.conf");
    std::fs::rename(&fx.config, &real).unwrap();
    std::os::unix::fs::symlink(&real, &fx.config).unwrap();
    expect_launch(&fx.socket, &probe, reasons::CONFIG_INVALID);
    std::fs::remove_file(&fx.config).unwrap();
    std::fs::rename(&real, &fx.config).unwrap();
    // Directory and missing file.
    std::fs::remove_file(&fx.config).unwrap();
    expect_launch(&fx.socket, &probe, reasons::CONFIG_INVALID);
    std::fs::create_dir(&fx.config).unwrap();
    expect_launch(&fx.socket, &probe, reasons::CONFIG_INVALID);
    std::fs::remove_dir(&fx.config).unwrap();
    fx.write_config(None, 0o600);
    expect_launch(&fx.socket, &probe, reasons::OK);
    // ALIVE and KILL are refused the same way.
    chmod(&fx.config, 0o666);
    expect(
        &fx.socket,
        &alive_frame(&scope_id()),
        reasons::CONFIG_INVALID,
        OP_ALIVE,
        &[],
    );
    expect(
        &fx.socket,
        &kill_frame(&scope_id(), 0),
        reasons::CONFIG_INVALID,
        OP_KILL,
        &[],
    );
}

#[test]
fn config_syntax_is_closed() {
    let fx = validate_fixture();
    let base = fx.default_config();
    let drop_key = |key: &str| -> Vec<String> {
        base.iter()
            .filter(|l| !l.starts_with(&format!("{key} ")))
            .cloned()
            .collect()
    };
    let replace = |key: &str, value: String| -> Vec<String> {
        base.iter()
            .map(|l| {
                if l.starts_with(&format!("{key} ")) {
                    format!("{key} {value}")
                } else {
                    l.clone()
                }
            })
            .collect()
    };
    let mut cases: Vec<Vec<String>> = vec![
        [base.clone(), vec![base[0].clone()]].concat(),
        [base.clone(), vec![base[2].clone()]].concat(),
        [base.clone(), vec!["harness claude /usr/bin/true".into()]].concat(),
        [base.clone(), vec!["home_dir claude .x".into()]].concat(),
        [
            base.clone(),
            vec!["mount claude .other .claude rw dir".into()],
        ]
        .concat(),
        [
            base.clone(),
            vec!["pids_max 10".into(), "pids_max 20".into()],
        ]
        .concat(),
        [base.clone(), vec!["unknown_key value".into()]].concat(),
        [base.clone(), vec!["operator_user".into()]].concat(),
        [base.clone(), vec!["mount claude .claude .claude rw".into()]].concat(),
        [
            base.clone(),
            vec!["mount claude .claude .claude rw dir extra".into()],
        ]
        .concat(),
        [
            base.clone(),
            vec!["mount claude .claude .claude rx dir".into()],
        ]
        .concat(),
        [
            base.clone(),
            vec!["mount claude .claude .claude rw fifo".into()],
        ]
        .concat(),
        [base.clone(), vec!["mount claude ../x .x ro dir".into()]].concat(),
        [base.clone(), vec!["mount claude /abs .x ro dir".into()]].concat(),
        [base.clone(), vec!["mount claude .x ./y ro dir".into()]].concat(),
        [base.clone(), vec!["mount other .x .y ro dir".into()]].concat(),
        [base.clone(), vec!["home_dir other .x".into()]].concat(),
        [base.clone(), vec!["harness opencode /usr/bin/true".into()]].concat(),
        drop_key("home_dir"),
        drop_key("operator_user"),
        drop_key("runtime_user"),
        drop_key("worktree_root"),
        drop_key("harness"),
        replace("harness", format!("claude {}", "relative/claude")),
        replace("worktree_root", format!("{}/", fx.worktrees.display())),
        replace(
            "worktree_root",
            format!("{}/../worktrees", fx.worktrees.display()),
        ),
        [base.clone(), vec!["pids_max 0".into()]].concat(),
        [base.clone(), vec!["pids_max -1".into()]].concat(),
        [base.clone(), vec!["pids_max 12x".into()]].concat(),
        [base.clone(), vec!["memory_max 1".into()]].concat(),
        [base.clone(), vec!["cpu_max 50000".into()]].concat(),
        [base.clone(), vec!["cpu_max 50000 10".into()]].concat(),
        [base.clone(), vec!["cpu_max none 100000".into()]].concat(),
        [base.clone(), vec!["operator_user\tsecond".into()]].concat(),
        [vec!["operator_user -rf".into()], base[1..].to_vec()].concat(),
    ];
    cases.dedup();
    for lines in cases {
        let last = lines.last().cloned().unwrap_or_default();
        fx.write_config(Some(lines.join("\n") + "\n"), 0o600);
        let (data, _) = request(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            &[],
        );
        assert!(
            status_of(&data, OP_LAUNCH) == reasons::CONFIG_INVALID,
            "{last:?}"
        );
    }
    // Comments, a config ending without newline, the 64 KiB cap.
    let good = format!(
        "# comment\n\n{}\n  # indented comment\npids_max 64\nmemory_max 1073741824\ncpu_max max 100000\n",
        base.join("\n")
    );
    fx.write_config(Some(good), 0o600);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
    let long_comments = vec![
        "# Central harness launcher configuration, owned by root and read on every launch."
            .to_string(),
        "  \t# an indented comment with far more than seven words in it, all ignored".to_string(),
        "#no space after the hash and still more than seven words here".to_string(),
        "   ".to_string(),
    ];
    let mut both = long_comments.clone();
    both.extend(base.clone());
    both.extend(long_comments);
    fx.write_config(Some(both.join("\n") + "\n"), 0o600);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
    fx.write_config(Some(base.join("\n")), 0o600); // no final newline
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
    fx.write_config(Some(base.join("\n") + "\r\n"), 0o600);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    fx.write_config(
        Some(base.join("\n") + "\n" + &"#".repeat(70000) + "\n"),
        0o600,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
}

#[test]
fn home_dependent_config_is_checked() {
    let mut fx = validate_fixture();
    let ok = |fx: &Fixture, label: &str| {
        let (data, _) = request(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            &[],
        );
        assert!(status_of(&data, OP_LAUNCH) == reasons::OK, "{label}");
    };
    let base = fx.default_config();
    let replace = |key: &str, value: String| -> Vec<String> {
        base.iter()
            .map(|l| {
                if l.starts_with(&format!("{key} ")) {
                    format!("{key} {value}")
                } else {
                    l.clone()
                }
            })
            .collect()
    };
    let probe = || {
        launch_frame(
            None,
            b"claude",
            b"",
            Some(vec![b"--version".to_vec()]),
            None,
        )
    };
    // worktree_root at or beneath HOME, or containing it.
    std::fs::create_dir(fx.home.join("wt")).unwrap();
    for root in [fx.home.join("wt"), fx.home.clone(), fx.dir.clone()] {
        fx.write_config(
            Some(replace("worktree_root", root.display().to_string()).join("\n") + "\n"),
            0o600,
        );
        expect_launch(&fx.socket, &probe(), reasons::CONFIG_INVALID);
    }
    // A worktree root reached through a symlink into HOME.
    std::os::unix::fs::symlink(fx.home.join("wt"), fx.dir.join("wt-link")).unwrap();
    fx.write_config(
        Some(
            replace(
                "worktree_root",
                fx.dir.join("wt-link").display().to_string(),
            )
            .join("\n")
                + "\n",
        ),
        0o600,
    );
    expect_launch(&fx.socket, &probe(), reasons::CONFIG_INVALID);
    // Program under HOME but not under an ro dir entry.
    let other = fx.home.join("bin/claude");
    std::fs::create_dir(other.parent().unwrap()).unwrap();
    chmod(other.parent().unwrap(), 0o755);
    std::fs::copy(&fx.program, &other).unwrap();
    for lines in [
        replace("harness", format!("claude {}", other.display())),
        base.iter()
            .map(|l| l.replace(" ro dir", " rw dir"))
            .collect(),
        replace(
            "harness",
            format!("claude {}/claude", fx.harness_home.display()),
        ),
    ] {
        fx.write_config(Some(lines.join("\n") + "\n"), 0o600);
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::CONFIG_INVALID,
        );
    }
    // Under an ro dir entry, but one the view does not show at the
    // program's own path, or with an rw entry at or beneath that target.
    std::fs::create_dir_all(fx.harness_home.join(".local/share/other")).unwrap();
    std::fs::create_dir_all(fx.harness_home.join(".local/share/claude/versions/nested")).unwrap();
    let ro_line = "mount claude .local/share/claude .local/share/claude ro dir";
    for lines in [
        base.iter()
            .map(|l| {
                l.replace(
                    ro_line,
                    "mount claude .local/share/claude .local/share/other ro dir",
                )
            })
            .collect::<Vec<_>>(),
        [
            base.clone(),
            vec!["mount claude .claude .local/share/claude/versions rw dir".into()],
        ]
        .concat(),
        [
            base.clone(),
            vec!["mount claude .claude .local/share/claude/versions/nested rw dir".into()],
        ]
        .concat(),
    ] {
        fx.write_config(Some(lines.join("\n") + "\n"), 0o600);
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::CONFIG_INVALID,
        );
    }
    // No other entry may overlap the ro target, and no rw entry its source.
    std::fs::create_dir(fx.harness_home.join(".x")).unwrap();
    std::fs::write(fx.harness_home.join(".bin"), "").unwrap();
    let program_rel = fx
        .program
        .strip_prefix(&fx.home)
        .unwrap()
        .to_str()
        .unwrap()
        .trim_start_matches('/')
        .to_string();
    for lines in [
        [
            base.clone(),
            vec!["mount claude .local/share/claude .x rw dir".into()],
        ]
        .concat(),
        [base.clone(), vec!["mount claude .local .x rw dir".into()]].concat(),
        [
            base.clone(),
            vec![format!("mount claude {program_rel} .bin rw file")],
        ]
        .concat(),
        [
            base.clone(),
            vec!["mount claude .claude .local rw dir".into()],
        ]
        .concat(),
        [
            base.clone(),
            vec!["mount claude .claude .local/share/claude/versions ro dir".into()],
        ]
        .concat(),
    ] {
        let last = lines.last().cloned().unwrap_or_default();
        fx.write_config(Some(lines.join("\n") + "\n"), 0o600);
        let (data, _) = request(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            &[],
        );
        assert!(
            status_of(&data, OP_LAUNCH) == reasons::CONFIG_INVALID,
            "{last:?}"
        );
    }
    // The home_dir is an implicit rw source too.
    for lines in [
        replace("home_dir", "claude .local/share/claude".into()),
        replace("home_dir", "claude .local/share".into()),
    ] {
        let last = lines.last().cloned().unwrap_or_default();
        fx.write_config(Some(lines.join("\n") + "\n"), 0o600);
        let (data, _) = request(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            &[],
        );
        assert!(
            status_of(&data, OP_LAUNCH) == reasons::CONFIG_INVALID,
            "{last:?}"
        );
    }
    // An ro entry of the same source elsewhere keeps the program read-only.
    fx.write_config(
        Some(
            [
                base.clone(),
                vec!["mount claude .local/share/claude .x ro dir".into()],
            ]
            .concat()
            .join("\n")
                + "\n",
        ),
        0o600,
    );
    ok(&fx, "ro entry of the same source elsewhere");
    // An rw entry beside the ro target is fine.
    std::fs::create_dir(fx.harness_home.join(".local/share/claude-rw")).unwrap();
    fx.write_config(
        Some(
            [
                base.clone(),
                vec!["mount claude .claude .local/share/claude-rw rw dir".into()],
            ]
            .concat()
            .join("\n")
                + "\n",
        ),
        0o600,
    );
    ok(&fx, "rw entry beside the ro target");
    // A program outside HOME is accepted (no-isolation skips the view check).
    let outside = fx.dir.join("claude-outside");
    std::fs::copy(&fx.program, &outside).unwrap();
    chmod(&outside, 0o755);
    fx.write_config(
        Some(replace("harness", format!("claude {}", outside.display())).join("\n") + "\n"),
        0o600,
    );
    ok(&fx, "program outside home");
    // ... but not through a symlink on any component.
    std::fs::create_dir(fx.dir.join("bin")).unwrap();
    chmod(&fx.dir.join("bin"), 0o755);
    std::fs::copy(&fx.program, fx.dir.join("bin/claude")).unwrap();
    chmod(&fx.dir.join("bin/claude"), 0o755);
    std::os::unix::fs::symlink(fx.dir.join("bin"), fx.dir.join("bin-link")).unwrap();
    std::os::unix::fs::symlink(&outside, fx.dir.join("claude-link")).unwrap();
    fx.write_config(
        Some(
            replace("harness", format!("claude {}/bin/claude", fx.dir.display())).join("\n") + "\n",
        ),
        0o600,
    );
    ok(&fx, "program under dir/bin");
    for program in [fx.dir.join("bin-link/claude"), fx.dir.join("claude-link")] {
        fx.write_config(
            Some(replace("harness", format!("claude {}", program.display())).join("\n") + "\n"),
            0o600,
        );
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::CONFIG_INVALID,
        );
    }
    // Owner and mode of the program's tree.
    fx.write_config(
        Some(
            replace("harness", format!("claude {}/bin/claude", fx.dir.display())).join("\n") + "\n",
        ),
        0o600,
    );
    for (path, mode) in [
        (fx.dir.join("bin"), 0o775u32),
        (fx.dir.join("bin"), 0o757),
        (fx.dir.join("bin/claude"), 0o775),
        (fx.dir.join("bin/claude"), 0o757),
    ] {
        let restore = std::fs::metadata(&path).unwrap().permissions().mode();
        chmod(&path, mode);
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::CONFIG_INVALID,
        );
        chmod(&path, restore);
    }
    ok(&fx, "mode restored");
    // Owned by someone else: the trusted prefix keeps the refusal to the
    // program's own tree.
    let other_uid = (euid() + 1).to_string();
    let trusted = fx.worktrees.display().to_string();
    fx.restart(&[
        ("CHL_TEST_TREE_OWNER_UID", other_uid.as_str()),
        ("CHL_TEST_TRUSTED_DIR", trusted.as_str()),
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    fx.write_config(Some(base.join("\n") + "\n"), 0o600);
    ok(&fx, "other tree owner, base config");
    for program in [fx.dir.join("bin/claude"), outside.clone()] {
        fx.write_config(
            Some(replace("harness", format!("claude {}", program.display())).join("\n") + "\n"),
            0o600,
        );
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::CONFIG_INVALID,
        );
    }
    fx.restart(&[
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    // Program missing or not executable.
    fx.write_config(
        Some(replace("harness", format!("claude {}/missing", fx.dir.display())).join("\n") + "\n"),
        0o600,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    chmod(&outside, 0o644);
    fx.write_config(
        Some(replace("harness", format!("claude {}", outside.display())).join("\n") + "\n"),
        0o600,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
}

#[test]
fn harness_home_mount_points_must_exist_as_real_entries() {
    let fx = validate_fixture();
    let target = fx.harness_home.join(".claude");
    std::fs::remove_dir(&target).unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::os::unix::fs::symlink(fx.home.join(".claude"), &target).unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::fs::remove_file(&target).unwrap();
    std::fs::write(&target, "not a dir").unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::fs::remove_file(&target).unwrap();
    std::fs::create_dir(&target).unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
    // A mount source that is missing or of the wrong type.
    std::fs::remove_dir_all(fx.home.join(".claude")).unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::fs::write(fx.home.join(".claude"), "file").unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::fs::remove_file(fx.home.join(".claude")).unwrap();
    std::fs::create_dir(fx.home.join(".claude")).unwrap();
    // file entries need regular files at both ends.
    let mut lines = fx.default_config();
    lines.push("mount claude .gitconfig .gitconfig ro file".into());
    fx.write_config(Some(lines.join("\n") + "\n"), 0o600);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::fs::write(fx.home.join(".gitconfig"), "").unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
    std::fs::write(fx.harness_home.join(".gitconfig"), "").unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
    // The harness home itself must exist with no symlink on the way.
    std::fs::remove_dir_all(&fx.harness_home).unwrap();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
}

#[test]
fn worktree_root_is_reached_without_symlinks_through_owned_directories() {
    let mut fx = validate_fixture();
    let base = fx.default_config();
    let replace = |value: &Path| -> Vec<String> {
        base.iter()
            .map(|l| {
                if l.starts_with("worktree_root ") {
                    format!("worktree_root {}", value.display())
                } else {
                    l.clone()
                }
            })
            .collect()
    };
    let probe = || {
        launch_frame(
            None,
            b"claude",
            b"",
            Some(vec![b"--version".to_vec()]),
            None,
        )
    };
    let refused = |fx: &Fixture, root: &Path| {
        fx.write_config(Some(replace(root).join("\n") + "\n"), 0o600);
        expect_launch(&fx.socket, &probe(), reasons::CONFIG_INVALID);
        expect_launch(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            reasons::CONFIG_INVALID,
        );
    };
    let accepted = |fx: &Fixture, root: &Path| {
        fx.write_config(Some(replace(root).join("\n") + "\n"), 0o600);
        let (data, _) = request(&fx.socket, &probe(), &[]);
        assert!(
            status_of(&data, OP_LAUNCH) == reasons::OK,
            "probe root {root:?}"
        );
        let (data, _) = request(
            &fx.socket,
            &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
            &[],
        );
        assert!(
            status_of(&data, OP_LAUNCH) == reasons::OK,
            "launch root {root:?}"
        );
    };
    accepted(&fx, &fx.worktrees);
    // worktree_root itself a symlink: refused although the target passes.
    std::os::unix::fs::symlink(&fx.worktrees, fx.dir.join("wt-link")).unwrap();
    refused(&fx, &fx.dir.join("wt-link"));
    // A symlink on an ancestor.
    std::os::unix::fs::symlink(&fx.dir, fx.dir.join("alias")).unwrap();
    refused(&fx, &fx.dir.join("alias/worktrees"));
    // An ancestor, or worktree_root itself, writable by group or others.
    let open_parent = fx.dir.join("open");
    std::fs::create_dir_all(open_parent.join("worktrees/attempt-1/repo")).unwrap();
    for d in [
        open_parent.join("worktrees/attempt-1/repo"),
        open_parent.join("worktrees/attempt-1"),
        open_parent.join("worktrees"),
    ] {
        chmod(&d, 0o755); // deterministic under any umask
    }
    for mode in [0o775u32, 0o757, 0o777] {
        chmod(&open_parent, mode);
        refused(&fx, &open_parent.join("worktrees"));
    }
    chmod(&open_parent, 0o755);
    accepted(&fx, &open_parent.join("worktrees"));
    for mode in [0o775u32, 0o757] {
        chmod(&fx.worktrees, mode);
        refused(&fx, &fx.worktrees);
    }
    chmod(&fx.worktrees, 0o755);
    accepted(&fx, &fx.worktrees);
    // Not a directory.
    std::fs::write(fx.dir.join("plain"), "x").unwrap();
    refused(&fx, &fx.dir.join("plain"));
    // Owned by someone other than the tree owner.
    let other_uid = (euid() + 1).to_string();
    fx.restart(&[
        ("CHL_TEST_TREE_OWNER_UID", other_uid.as_str()),
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    refused(&fx, &fx.worktrees);
    fx.restart(&[
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    accepted(&fx, &fx.worktrees);
}

#[test]
fn a_home_reached_through_a_symlink_is_operator_invalid() {
    let mut fx = validate_fixture();
    let link = fx.dir.join("home-link");
    std::os::unix::fs::symlink(&fx.home, &link).unwrap();
    fx.restart(&[
        ("CHL_TEST_HOME", link.to_str().unwrap()),
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OPERATOR_INVALID,
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            None,
            b"claude",
            b"",
            Some(vec![b"--version".to_vec()]),
            None,
        ),
        reasons::OPERATOR_INVALID,
    );
    std::fs::create_dir(fx.dir.join("real")).unwrap();
    chmod(&fx.dir.join("real"), 0o755);
    std::os::unix::fs::symlink(&fx.home, fx.dir.join("real/home")).unwrap();
    let p = fx.dir.join("real/home");
    fx.restart(&[
        ("CHL_TEST_HOME", p.to_str().unwrap()),
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OPERATOR_INVALID,
    );
    let p = fx.dir.join("missing");
    fx.restart(&[
        ("CHL_TEST_HOME", p.to_str().unwrap()),
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OPERATOR_INVALID,
    );
    fx.restart(&[
        ("CHL_TEST_NO_ISOLATION", "1"),
        ("CHL_TEST_VALIDATE_ONLY", "1"),
    ]);
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
}

#[test]
fn a_peer_other_than_the_runtime_user_is_denied() {
    let mut fx = Fixture::new();
    let other = (euid() + 1).to_string();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.env_overrides.insert("CHL_TEST_PEER_UID".into(), other);
    fx.start();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::PEER_DENIED,
    );
    expect(
        &fx.socket,
        &alive_frame(&scope_id()),
        reasons::PEER_DENIED,
        OP_ALIVE,
        &[],
    );
}

#[test]
fn the_runtime_user_is_the_admitted_peer() {
    let fx = validate_fixture();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::OK,
    );
}

#[test]
fn a_config_not_owned_by_the_expected_owner_is_invalid() {
    let mut fx = Fixture::new();
    let other = (euid() + 1).to_string();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_VALIDATE_ONLY".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_CONFIG_OWNER_UID".into(), other);
    fx.start();
    expect_launch(
        &fx.socket,
        &launch_frame(None, b"claude", b"attempt-1/repo", None, None),
        reasons::CONFIG_INVALID,
    );
}

#[test]
fn a_no_isolation_build_refuses_to_run_as_root() {
    if euid() != 0 {
        return; // root-gated (upstream: the check only bites as root)
    }
    let mut fx = Fixture::new();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    let code = fx.start_expect_exit();
    assert!(code == Some(1));
    assert!(fx.log_text().contains("refuses to run as root"));
}

/* ======================= session tests ======================= */

#[test]
fn a_session_pipes_stdio_and_reports_its_exit() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(Some("echo"), DENY, "--session-id", None, None)),
            None,
        ),
    );
    let scope_dir = fx.cgroup.join("scopes").join(scope_text(&s.scope));
    assert!(std::fs::read_to_string(scope_dir.join("pids.max")).unwrap() == "512\n");
    assert!(
        std::fs::read_to_string(scope_dir.join("memory.max")).unwrap()
            == format!("{}\n", 2u64 << 30)
    );
    let _ = write(s.stdin.as_ref().unwrap(), b"hello\n");
    drop(s.stdin.take());
    assert!(read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15)) == b"hello\n");
    assert!(read_all(s.stderr.as_ref().unwrap(), Duration::from_secs(15)).is_empty());
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
    assert!(!scope_dir.exists(), "EXIT before the scope was removed");
    drop(s);

    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("exit1"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    assert!(read_all(s.stderr.as_ref().unwrap(), Duration::from_secs(15)) == b"failing\n");
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 1)));
    drop(s);

    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(Some("pwd"), DENY, "--session-id", None, None)),
            None,
        ),
    );
    let out = read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15));
    assert!(
        String::from_utf8_lossy(&out).trim()
            == fx
                .worktrees
                .join("attempt-1/repo")
                .display()
                .to_string()
                .as_str()
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
    drop(s);

    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"",
            Some(vec![b"--version".to_vec()]),
            None,
        ),
    );
    assert!(
        read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15)) == b"2.1.283 (Claude Code)\n"
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
    drop(s);
}

#[test]
fn kill_ends_a_session_with_sigterm_then_cgroup_kill() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    assert!(alive(&fx, &s.scope));
    expect(
        &fx.socket,
        &kill_frame(&s.scope, 5000),
        reasons::OK,
        OP_KILL,
        &[],
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((true, 143)));
    assert!(!alive(&fx, &s.scope));
    // already gone
    expect(
        &fx.socket,
        &kill_frame(&s.scope, 5000),
        reasons::OK,
        OP_KILL,
        &[],
    );
    drop(s);

    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("ignoreterm"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    assert!(read_line(s.stdout.as_ref().unwrap(), Duration::from_secs(15)) == b"ready\n");
    // A second name for the fake cgroup.kill: the monitor removes the
    // scope directory before EXIT, and the write must still be readable.
    let kill_seen = fx.dir.join("cgroup.kill-seen");
    std::fs::hard_link(
        fx.cgroup
            .join("scopes")
            .join(scope_text(&s.scope))
            .join("cgroup.kill"),
        &kill_seen,
    )
    .unwrap();
    assert!(std::fs::read_to_string(&kill_seen).unwrap().is_empty());
    let started = Instant::now();
    expect(
        &fx.socket,
        &kill_frame(&s.scope, 300),
        reasons::OK,
        OP_KILL,
        &[],
    );
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "SIGKILL came before the grace"
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((true, 137)));
    assert!(
        std::fs::read_to_string(&kill_seen).unwrap() == "1",
        "the grace expired without a cgroup.kill write"
    );
    drop(s);
}

#[test]
fn an_init_killed_by_sigkill_still_gets_an_exit() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let harness = s.harness_pid();
    kill(s.init_pid(), Signal::KILL);
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((true, 137)));
    wait_until(
        || !pid_alive(harness),
        Duration::from_secs(10),
        "the harness to die with its init",
    );
    drop(s);
}

#[test]
fn closing_the_lifeline_kills_and_releases_the_scope() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let init = s.init_pid();
    let harness = s.harness_pid();
    let scope_dir = fx.cgroup.join("scopes").join(scope_text(&s.scope));
    drop(s.conn.take());
    wait_until(
        || poll_ready(s.pidfd.as_ref().unwrap(), Duration::ZERO),
        Duration::from_secs(10),
        "the init to exit",
    );
    wait_until(
        || !pid_alive(harness),
        Duration::from_secs(10),
        "the harness to die",
    );
    wait_until(
        || !scope_dir.exists(),
        Duration::from_secs(10),
        "the scope to be removed",
    );
    assert!(read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15)).is_empty());
    assert!(!alive(&fx, &s.scope));
    assert!(!pid_alive(init));
    drop(s);
}

#[test]
fn a_scope_relaunches_right_after_exit() {
    let fx = session_fixture();
    let scope = scope_id();
    for _ in 0..5 {
        let mut s = Session::launch(
            &fx,
            &launch_frame(
                Some(scope),
                b"claude",
                b"",
                Some(vec![b"--version".to_vec()]),
                None,
            ),
        );
        assert!(
            read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15)).starts_with(b"2.1.283")
        );
        assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
        drop(s);
        let mut s = Session::launch(
            &fx,
            &launch_frame(
                Some(scope),
                b"claude",
                b"attempt-1/repo",
                Some(session_argv(
                    Some("exit0"),
                    DENY,
                    "--session-id",
                    None,
                    None,
                )),
                None,
            ),
        );
        assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
        drop(s);
    }
}

#[test]
fn a_busy_scope_is_refused_and_alive_reads_the_cgroup() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            Some(s.scope),
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("exit0"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
        reasons::SCOPE_BUSY,
    );
    assert!(alive(&fx, &s.scope));
    expect(
        &fx.socket,
        &kill_frame(&s.scope, 1000),
        reasons::OK,
        OP_KILL,
        &[],
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((true, 143)));
    drop(s);
    // An unowned populated scope (a leftover this daemon does not own).
    let (scope, d) = fake_scope(&fx, true);
    expect_launch(
        &fx.socket,
        &launch_frame(Some(scope), b"claude", b"attempt-1/repo", None, None),
        reasons::SCOPE_BUSY,
    );
    assert!(alive(&fx, &scope));
    std::fs::write(d.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
    assert!(!alive(&fx, &scope));
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            Some(scope),
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("exit0"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
    drop(s);
    assert!(!alive(&fx, &scope_id()));
}

#[test]
fn an_unowned_kill_writes_cgroup_kill_and_answers_once_empty() {
    let fx = session_fixture();
    expect(
        &fx.socket,
        &kill_frame(&scope_id(), 0),
        reasons::OK,
        OP_KILL,
        &[],
    );
    let (scope, d) = fake_scope(&fx, true);
    let client = connect(&fx.socket);
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let frame = kill_frame(&scope, 0);
    let iov = [std::io::IoSlice::new(&frame)];
    let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
    wait_until(
        || std::fs::read_to_string(d.join("cgroup.kill")).unwrap_or_default() == "1",
        Duration::from_secs(10),
        "cgroup.kill",
    );
    // The KILL stays unanswered while the scope is populated.
    assert!(
        !poll_ready(&client, Duration::from_millis(300)),
        "KILL answered while the scope was populated"
    );
    expect_launch(
        &fx.socket,
        &launch_frame(Some(scope), b"claude", b"attempt-1/repo", None, None),
        reasons::SCOPE_BUSY,
    );
    std::fs::write(d.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
    rustix::net::sockopt::set_socket_timeout(
        &client,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let (data, fds) = recv_msg(&client, 8);
    assert!(
        status_of(&data, OP_KILL) == reasons::OK && fds.is_empty(),
        "{data:?}"
    );
    wait_until(
        || !d.exists(),
        Duration::from_secs(10),
        "the scope to be removed",
    );
}

#[test]
fn a_dead_monitor_leaves_its_scope_killed_and_cleaned() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let init = s.init_pid();
    let harness = s.harness_pid();
    let monitor = ppid_of(init);
    let d = fx.cgroup.join("scopes").join(scope_text(&s.scope));
    kill(monitor, Signal::KILL);
    assert!(
        s.wait_exit(Duration::from_secs(20)).is_none(),
        "EXIT after the monitor died"
    );
    wait_until(
        || std::fs::read_to_string(d.join("cgroup.kill")).unwrap_or_default() == "1",
        Duration::from_secs(10),
        "the daemon's cgroup.kill",
    );
    // Unowned now, and still populated: never reported dead.
    assert!(alive(&fx, &s.scope));
    expect_launch(
        &fx.socket,
        &launch_frame(
            Some(s.scope),
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("exit0"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
        reasons::SCOPE_BUSY,
    );
    for pid in [harness, init] {
        kill(pid, Signal::KILL);
    }
    std::fs::write(d.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
    wait_until(
        || !d.exists(),
        Duration::from_secs(10),
        "the cleaner to remove the scope",
    );
    assert!(!alive(&fx, &s.scope));
    // A relaunch of the cleaned scope.
    let mut relaunched = false;
    wait_until(
        || {
            let conn = connect(&fx.socket);
            let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
            let mut control = SendAncillaryBuffer::new(&mut space);
            let frame = launch_frame(
                Some(s.scope),
                b"claude",
                b"attempt-1/repo",
                Some(session_argv(
                    Some("exit0"),
                    DENY,
                    "--session-id",
                    None,
                    None,
                )),
                None,
            );
            let iov = [std::io::IoSlice::new(&frame)];
            let _ = sendmsg(&conn, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
            let (data, fds) = recv_msg(&conn, 8);
            if status_of(&data, OP_LAUNCH) != 0 {
                return false;
            }
            drop(fds);
            let (resp, _) = recv_msg(&conn, 8);
            let ok = status_of(&resp, OP_EXIT) == 0;
            relaunched = ok;
            ok
        },
        Duration::from_secs(15),
        "a relaunch of the cleaned scope",
    );
    assert!(relaunched);
    drop(s);
}

#[test]
fn the_harness_gets_passwd_identity_and_only_stdio() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(Some("env"), DENY, "--session-id", None, None)),
            Some(vec![
                b"PATH=/usr/bin:/bin".to_vec(),
                b"USER=evil".to_vec(),
                b"LOGNAME=evil".to_vec(),
                b"LC_ALL=C".to_vec(),
            ]),
        ),
    );
    let out = read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15));
    let lines: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .filter(|l| !["PWD", "OLDPWD", "SHLVL", "_"].contains(&l.split('=').next().unwrap_or("")))
        .map(str::to_string)
        .collect();
    let mut want = vec![
        format!("HOME={}", fx.home.display()),
        "LC_ALL=C".to_string(),
        format!("LOGNAME={}", me()),
        "PATH=/usr/bin:/bin".to_string(),
        format!("USER={}", me()),
    ];
    let mut got = lines;
    want.sort();
    got.sort();
    assert!(got == want, "{got:?}");
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((false, 0)));
    drop(s);

    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let harness = s.harness_pid();
    wait_until(
        || {
            std::fs::read_to_string(format!("/proc/{harness}/comm"))
                .map(|t| t.trim() == "sleep")
                .unwrap_or(false)
        },
        Duration::from_secs(10),
        "the harness exec",
    );
    let mut fds: Vec<String> = std::fs::read_dir(format!("/proc/{harness}/fd"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    fds.sort_by_key(|f| f.parse::<i32>().unwrap());
    assert!(fds == ["0", "1", "2"], "{fds:?}");
    let status = std::fs::read_to_string(format!("/proc/{harness}/status")).unwrap();
    let field = |k: &str| -> String {
        status
            .lines()
            .find(|l| l.starts_with(&format!("{k}:")))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim()
            .to_string()
    };
    assert!(field("NoNewPrivs") == "1");
    for cap in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert!(u64::from_str_radix(&field(cap), 16).unwrap() == 0, "{cap}");
    }
    // The init dropped to the same UID and is not dumpable: a process of
    // that UID cannot open its fds or its memory to forge the channel.
    let init = s.init_pid();
    for path in [format!("/proc/{init}/fd"), format!("/proc/{init}/mem")] {
        let denied = if path.ends_with("fd") {
            std::fs::read_dir(&path).is_err()
        } else {
            open::<&OsStr>(
                OsStr::new(&path),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .is_err()
        };
        assert!(denied, "{path} is open to the operator's UID");
    }
    expect(
        &fx.socket,
        &kill_frame(&s.scope, 1000),
        reasons::OK,
        OP_KILL,
        &[],
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((true, 143)));
    drop(s);
}

/// The `launch_failed` log line of `scope`, waited for.
fn failed_launch_line(fx: &Fixture, scope: &[u8; 16]) -> String {
    let prefix = format!(
        "central-harness-launcherd: launch_failed reason=launch_failed scope={} ",
        scope_text(scope)
    );
    wait_until(
        || fx.log_text().contains(&prefix),
        Duration::from_secs(5),
        "the launch_failed log line",
    );
    fx.log_text()
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap()
        .to_string()
}

fn assert_failed_step(
    fx: &Fixture,
    scope: &[u8; 16],
    step: &str,
    errno_number: i32,
    secrets: &[String],
) {
    let line = failed_launch_line(fx, scope);
    assert!(
        line.ends_with(&format!(" step={step} errno={errno_number}")),
        "{line}"
    );
    let re_ok = line
        .starts_with("central-harness-launcherd: launch_failed reason=launch_failed scope=")
        && line.contains(&scope_text(scope));
    assert!(re_ok, "{line}");
    let log = fx.log_text();
    for secret in secrets {
        assert!(!log.contains(secret.as_str()), "the log echoes {secret:?}");
    }
}

#[test]
fn a_failed_exec_is_launch_failed_and_releases_the_scope() {
    let fx = session_fixture();
    std::fs::write(&fx.program, "#!/nonexistent/interpreter\n").unwrap();
    let scope = scope_id();
    let sid = scope_text(&scope_id());
    Session::expect_fail(
        &fx,
        &launch_frame(
            Some(scope),
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("exit0"),
                DENY,
                "--session-id",
                Some(sid.clone()),
                None,
            )),
            None,
        ),
        reasons::LAUNCH_FAILED,
    );
    wait_until(
        || !fx.cgroup.join("scopes").join(scope_text(&scope)).exists(),
        Duration::from_secs(10),
        "the failed scope to be removed",
    );
    assert_failed_step(
        &fx,
        &scope,
        "exec",
        2, // ENOENT
        &[
            fx.program.display().to_string(),
            fx.home.display().to_string(),
            "nonexistent".into(),
            sid,
            "exit0".into(),
        ],
    );
    std::fs::write(&fx.program, FAKE_HARNESS).unwrap();
    chmod(&fx.program, 0o755);
    let mut ok = false;
    wait_until(
        || {
            let conn = connect(&fx.socket);
            let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
            let mut control = SendAncillaryBuffer::new(&mut space);
            let frame = launch_frame(
                Some(scope),
                b"claude",
                b"attempt-1/repo",
                Some(session_argv(
                    Some("exit0"),
                    DENY,
                    "--session-id",
                    None,
                    None,
                )),
                None,
            );
            let iov = [std::io::IoSlice::new(&frame)];
            let _ = sendmsg(&conn, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
            let (data, fds) = recv_msg(&conn, 8);
            if status_of(&data, OP_LAUNCH) != 0 {
                return false;
            }
            drop(fds);
            let (resp, _) = recv_msg(&conn, 8);
            ok = status_of(&resp, OP_EXIT) == 0;
            ok
        },
        Duration::from_secs(15),
        "a relaunch after a failed exec",
    );
    assert!(ok);
}

#[test]
fn a_failed_launch_logs_its_step_and_errno_only() {
    let fx = session_fixture();
    // An exec refused EACCES (the program's interpreter is not executable).
    let interpreter = fx
        .dir
        .join(format!("zzinterp{:x}", uniq_id() & 0xffff_ffff));
    std::fs::write(&interpreter, "").unwrap();
    chmod(&interpreter, 0o644);
    std::fs::write(&fx.program, format!("#!{}\n", interpreter.display())).unwrap();
    chmod(&fx.program, 0o755);
    let scope = scope_id();
    let marker = format!("zzmarker{:x}", uniq_id() & 0xffff_ffff);
    Session::expect_fail(
        &fx,
        &launch_frame(
            Some(scope),
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some(&marker),
                DENY,
                "--session-id",
                None,
                None,
            )),
            Some(vec![
                b"PATH=/usr/bin:/bin".to_vec(),
                format!("LC_ALL={marker}").into_bytes(),
            ]),
        ),
        reasons::LAUNCH_FAILED,
    );
    assert_failed_step(
        &fx,
        &scope,
        "exec",
        13, // EACCES
        &[
            interpreter.display().to_string(),
            fx.program.display().to_string(),
            fx.worktrees.display().to_string(),
            marker,
        ],
    );
    wait_until(
        || !fx.cgroup.join("scopes").join(scope_text(&scope)).exists(),
        Duration::from_secs(10),
        "the failed scope to be removed",
    );
}

fn daemon_children(fx: &Fixture) -> Vec<i32> {
    children_of(fx.process.as_ref().unwrap().id() as i32)
}

/// `fire` — send one request and hang up without reading the answer.
fn fire(fx: &Fixture, frame: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let client = loop {
        match std::panic::catch_unwind(|| connect(&fx.socket)) {
            Ok(c) => break c,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => std::panic::resume_unwind(e),
        }
    };
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let iov = [std::io::IoSlice::new(frame)];
    let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
}

#[test]
fn a_wedged_monitor_never_blocks_the_daemon() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let monitor = ppid_of(s.init_pid());
    let d = fx.cgroup.join("scopes").join(scope_text(&s.scope));
    kill(monitor, Signal::STOP);
    let started = Instant::now();
    for _ in 0..2000 {
        fire(&fx, &alive_frame(&s.scope));
    }
    // The daemon is not stuck: a fresh ALIVE is answered (populated,
    // from the cgroup), and so is another scope.
    let client = connect(&fx.socket);
    rustix::net::sockopt::set_socket_timeout(
        &client,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let frame = alive_frame(&s.scope);
    let iov = [std::io::IoSlice::new(&frame)];
    let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
    let (data, _) = recv_msg(&client, 8);
    assert!(status_of(&data, OP_ALIVE) == 0 && data[8] == 1, "{data:?}");
    assert!(
        fx.log_text().contains("forward_failed"),
        "no forward ever failed"
    );
    {
        let mut other = Session::launch(
            &fx,
            &launch_frame(
                None,
                b"claude",
                b"attempt-1/repo",
                Some(session_argv(
                    Some("exit0"),
                    DENY,
                    "--session-id",
                    None,
                    None,
                )),
                None,
            ),
        );
        assert!(other.wait_exit(Duration::from_secs(10)) == Some((false, 0)));
    }
    assert!(started.elapsed() < Duration::from_secs(30));
    // KILL falls back to the cleaner: one for the scope however many
    // KILLs wait on it, and each is answered once the scope is empty.
    let before = daemon_children(&fx);
    let mut waiting = Vec::new();
    for _ in 0..3 {
        let client = connect(&fx.socket);
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let frame = kill_frame(&s.scope, 1000);
        let iov = [std::io::IoSlice::new(&frame)];
        let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
        waiting.push(client);
    }
    wait_until(
        || std::fs::read_to_string(d.join("cgroup.kill")).unwrap_or_default() == "1",
        Duration::from_secs(10),
        "the cleaner's cgroup.kill",
    );
    let extra: Vec<i32> = daemon_children(&fx)
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    assert!(
        extra.len() == 1,
        "more than one cleaner for one scope: {extra:?}"
    );
    std::fs::write(d.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
    for client in waiting {
        let (data, fds) = recv_msg(&client, 8);
        assert!(
            status_of(&data, OP_KILL) == reasons::OK && fds.is_empty(),
            "{data:?}"
        );
    }
    kill(monitor, Signal::CONT);
    // The monitor catches up and still ends its session.
    drop(s.conn.take());
    wait_until(
        || !pid_alive(monitor),
        Duration::from_secs(20),
        "the monitor to finish",
    );
    drop(s);
}

#[test]
fn a_release_while_a_fallback_cleaner_runs_keeps_the_scope_tracked() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let monitor = ppid_of(s.init_pid());
    let d = fx.cgroup.join("scopes").join(scope_text(&s.scope));
    kill(monitor, Signal::STOP);
    for i in 0..5000 {
        fire(&fx, &alive_frame(&s.scope));
        if i % 50 == 0 && fx.log_text().contains("forward_failed") {
            break;
        }
    }
    wait_until(
        || fx.log_text().contains("forward_failed"),
        Duration::from_secs(10),
        "a forward to fail",
    );
    let before = daemon_children(&fx);
    let waiter = connect(&fx.socket);
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let frame = kill_frame(&s.scope, 1000);
    let iov = [std::io::IoSlice::new(&frame)];
    let _ = sendmsg(&waiter, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
    wait_until(
        || std::fs::read_to_string(d.join("cgroup.kill")).unwrap_or_default() == "1",
        Duration::from_secs(10),
        "the cleaner's cgroup.kill",
    );
    let cleaners: Vec<i32> = daemon_children(&fx)
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    assert!(cleaners.len() == 1, "{cleaners:?}");
    let cleaner = cleaners[0];
    kill(cleaner, Signal::STOP);
    kill(monitor, Signal::CONT);
    // The monitor ends its session and releases the scope; it exits only
    // once the daemon has acknowledged the release.
    drop(s.conn.take());
    wait_until(
        || !pid_alive(monitor),
        Duration::from_secs(20),
        "the monitor to release and exit",
    );
    assert!(!d.exists());
    // The waiting KILL is still unanswered: the cleaner runs.
    assert!(
        !poll_ready(&waiter, Duration::from_millis(300)),
        "KILL answered while its cleaner still ran"
    );
    expect_launch(
        &fx.socket,
        &launch_frame(
            Some(s.scope),
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("exit0"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
        reasons::SCOPE_BUSY,
    );
    kill(cleaner, Signal::CONT);
    rustix::net::sockopt::set_socket_timeout(
        &waiter,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let (data, fds) = recv_msg(&waiter, 8);
    assert!(
        status_of(&data, OP_KILL) == reasons::OK && fds.is_empty(),
        "{data:?}"
    );
    let mut ok = false;
    wait_until(
        || {
            let conn = connect(&fx.socket);
            let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
            let mut control = SendAncillaryBuffer::new(&mut space);
            let frame = launch_frame(
                Some(s.scope),
                b"claude",
                b"attempt-1/repo",
                Some(session_argv(
                    Some("exit0"),
                    DENY,
                    "--session-id",
                    None,
                    None,
                )),
                None,
            );
            let iov = [std::io::IoSlice::new(&frame)];
            let _ = sendmsg(&conn, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
            let (data, fds) = recv_msg(&conn, 8);
            if status_of(&data, OP_LAUNCH) != 0 {
                return false;
            }
            drop(fds);
            let (resp, _) = recv_msg(&conn, 8);
            ok = status_of(&resp, OP_EXIT) == 0;
            ok
        },
        Duration::from_secs(15),
        "a relaunch once the cleaner ended",
    );
    assert!(ok);
    drop(s);
}

#[test]
fn one_cleaner_per_scope_and_it_keeps_no_inherited_descriptor() {
    let fx = session_fixture();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(
                Some("sleep"),
                DENY,
                "--session-id",
                None,
                None,
            )),
            None,
        ),
    );
    let monitor = ppid_of(s.init_pid());
    let (scope, d) = fake_scope(&fx, true);
    let mut waiting = Vec::new();
    for _ in 0..4 {
        let client = connect(&fx.socket);
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 64];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let frame = kill_frame(&scope, 0);
        let iov = [std::io::IoSlice::new(&frame)];
        let _ = sendmsg(&client, &iov, &mut control, SendFlags::NOSIGNAL).unwrap();
        waiting.push(client);
    }
    wait_until(
        || std::fs::read_to_string(d.join("cgroup.kill")).unwrap_or_default() == "1",
        Duration::from_secs(10),
        "cgroup.kill",
    );
    let cleaners: Vec<i32> = daemon_children(&fx)
        .into_iter()
        .filter(|p| *p != monitor)
        .collect();
    assert!(cleaners.len() == 1, "{cleaners:?}");
    let cleaner = cleaners[0];
    // The cleaner holds no socket (not the listener, not a monitor's
    // control socket, not a client connection).
    let mut socket_links = Vec::new();
    for e in std::fs::read_dir(format!("/proc/{cleaner}/fd")).unwrap() {
        let e = e.unwrap();
        if let Ok(link) = std::fs::read_link(e.path())
            && link.to_string_lossy().starts_with("socket:")
        {
            socket_links.push(link);
        }
    }
    assert!(socket_links.is_empty(), "{socket_links:?}");
    std::fs::write(d.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
    for client in waiting {
        let (data, fds) = recv_msg(&client, 8);
        assert!(
            status_of(&data, OP_KILL) == reasons::OK && fds.is_empty(),
            "{data:?}"
        );
    }
    wait_until(
        || !d.exists(),
        Duration::from_secs(10),
        "the scope to be removed",
    );
    expect(
        &fx.socket,
        &kill_frame(&s.scope, 1000),
        reasons::OK,
        OP_KILL,
        &[],
    );
    assert!(s.wait_exit(Duration::from_secs(20)) == Some((true, 143)));
    drop(s);
}

#[test]
fn the_daemon_fails_closed_without_cgroup_kill() {
    let mut fx = Fixture::with(None, true, false);
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    assert!(fx.start_expect_exit() == Some(1));
    assert!(fx.log_text().contains("cgroup_unavailable"));
}

#[test]
fn the_daemon_fails_closed_without_a_cgroup_root() {
    let mut fx = Fixture::with(None, false, false);
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    assert!(fx.start_expect_exit() == Some(1));
}

#[test]
fn startup_sweeps_leftover_scopes() {
    let mut fx = Fixture::new();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_SWEEP_TIMEOUT_MS".into(), "2000".into());
    std::fs::create_dir_all(fx.cgroup.join("scopes")).unwrap();
    let (_empty, empty_dir) = fake_scope(&fx, false);
    let (stuck, stuck_dir) = fake_scope(&fx, true);
    let started = Instant::now();
    fx.start();
    assert!(
        !empty_dir.exists(),
        "an empty leftover scope was not removed"
    );
    assert!(
        std::fs::read_to_string(stuck_dir.join("cgroup.kill")).unwrap() == "1",
        "a populated leftover was not killed"
    );
    assert!(stuck_dir.exists() && started.elapsed() >= Duration::from_secs(2));
    expect_launch(
        &fx.socket,
        &launch_frame(Some(stuck), b"claude", b"attempt-1/repo", None, None),
        reasons::SCOPE_BUSY,
    );
}

fn host_landlock_abi() -> i32 {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION).
    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn syscall(num: i64, ...) -> i64;
    }
    #[allow(unsafe_code)]
    let abi = unsafe { syscall(444, std::ptr::null::<u8>(), 0usize, 1u32) };
    (abi as i32).max(0)
}

#[test]
fn the_daemon_fails_closed_below_landlock_abi_6() {
    // In a no-isolation build AND in the isolating build (whose check runs
    // before anything that needs root).
    for isolating in [false, true] {
        for abi in ["0", "5"] {
            let mut fx = Fixture::new();
            fx.env_overrides
                .insert("CHL_TEST_LANDLOCK_ABI".into(), abi.into());
            if !isolating {
                fx.env_overrides
                    .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
            }
            let code = fx.start_expect_exit();
            assert!(code == Some(1), "isolating={isolating} abi={abi}");
            assert!(
                fx.log_text().contains("landlock_unavailable"),
                "{}",
                fx.log_text()
            );
        }
    }
    let mut fx = Fixture::new();
    fx.env_overrides
        .insert("CHL_TEST_NO_ISOLATION".into(), "1".into());
    fx.env_overrides
        .insert("CHL_TEST_LANDLOCK_ABI".into(), "6".into());
    fx.start();
    assert!(!alive(&fx, &scope_id()));
}

#[test]
fn a_session_reaches_no_abstract_socket_and_signals_nothing_outside() {
    // Needs a listening abstract unix socket of this (unsandboxed) runner:
    // the runner is the test process, so bind it here.
    let name = format!("chl-test-{:x}", uniq_id());
    let listener = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .unwrap();
    let addr = SocketAddrUnix::new_abstract_name(name.as_bytes()).unwrap();
    rustix::net::bind(&listener, &addr).unwrap();
    rustix::net::listen(&listener, 4).unwrap();
    let fx = session_fixture();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        fx.home.join("ipc-target"),
        format!("{name} {} {port}\n", std::process::id()),
    )
    .unwrap();
    let mut s = Session::launch(
        &fx,
        &launch_frame(
            None,
            b"claude",
            b"attempt-1/repo",
            Some(session_argv(Some("ipc"), DENY, "--session-id", None, None)),
            None,
        ),
    );
    let out = read_all(s.stdout.as_ref().unwrap(), Duration::from_secs(15));
    let result: BTreeMap<String, String> = String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    assert!(
        s.wait_exit(Duration::from_secs(20)) == Some((false, 0)),
        "{result:?}"
    );
    assert!(
        result.get("own").map(|v| v.as_str()) == Some("connected"),
        "{result:?}"
    );
    if host_landlock_abi() < 6 {
        eprintln!("note: Landlock ABI < 6 here; the session was not scoped: {result:?}");
        return;
    }
    assert!(
        result.get("abstract").map(|v| v.as_str()) == Some("denied EPERM"),
        "{result:?}"
    );
    assert!(
        result.get("signal").map(|v| v.as_str()) == Some("denied EPERM"),
        "{result:?}"
    );
    // The runner's listener must never see a connection.
    assert!(
        !poll_ready(&listener, Duration::ZERO),
        "a session connected to the runner's abstract socket"
    );
    drop(s);
}
