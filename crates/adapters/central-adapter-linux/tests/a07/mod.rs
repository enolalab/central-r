//! Shared A07 denial-suite harness.
//!
//! Every `a07_*.rs` binary includes this module: scratch-directory
//! management, the `UnixStream::pair()` wire exchanges against
//! `helper::server::Server::handle_conn` and
//! `broker::server::handle_conn`, the Tier-3 gate, and the small
//! fixture builders the denial scenarios share.
//!
//! The suite's two tiers (see `tests/a07/README.md`):
//!
//! - **Portable** — everything that runs as the current non-root user:
//!   wire-level peer/authority denials, descriptor smuggling,
//!   journal crash recovery, the closed helper matrix, grants, the
//!   genesis/lifecycle/barrier precondition denials, and the
//!   `openat2` path-race checks on test-owned trees.
//! - **Tier 3** — reference-host-only scenarios gated on
//!   `CENTRAL_TIER3=1` + euid 0 + the Ubuntu ≥ 24.04 x86_64 reference
//!   host: multi-UID peer denial, root-owned path traversal, the
//!   physical-console exclusive lease, and the live PAM denial.
//!   Unavailable conditions print an explicit `SKIP [a07]` line and
//!   return — a documented skip, never a silent pass.
//!
//! Denial identifiers are asserted byte-exact where upstream pins
//! them (`sys_scm_rights_denied`, `sys_tty_not_console`,
//! `UNSUPPORTED_IN_THIS_SLICE`, `BARRIER_CONFLICT`, …): a weakened
//! check fails the suite, never the other way round.

// Each `a07_*.rs` binary includes this module but only ever uses a
// subset of the helpers — dead code on the unused subset is expected.
#![allow(dead_code)]
// The `clippy.toml` test relaxation only reaches `#[test]` fns; this
// harness and the helpers in the sibling binaries unwrap/expect
// deliberately — a fixture that cannot be built is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use central_adapter_linux::helper::protocol::{Request, Response};
use central_adapter_linux::helper::{self};
use central_adapter_linux::sys::peercred::PeerCred;
use central_foundation::failure::Failure;
use rustix::process::{Gid, Pid, Uid};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// `euid`/`egid` of the test process — every policy fixture is built
/// relative to them so the suite runs under any account.
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}
pub fn egid() -> u32 {
    rustix::process::getegid().as_raw()
}
pub fn self_pid() -> i32 {
    rustix::process::getpid().as_raw_pid()
}

/// A fabricated `SO_PEERCRED` triple for the pure peer-predicate
/// checks — the wire-level tests exercise the real `getsockopt`.
pub fn peer(uid: u32, gid: u32, pid: i32) -> PeerCred {
    PeerCred {
        pid: Pid::from_raw(pid).unwrap_or_else(|| Pid::from_raw(1).unwrap()),
        uid: Uid::from_raw(uid),
        gid: Gid::from_raw(gid),
    }
}

// ---------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// A test-owned directory tree, removed on drop. Nested layout is up
/// to each scenario; `dir()` creates a `0700` subdirectory.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("central-a07-{name}-{}-{seq}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("scratch mode");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    /// A `mode`-permissioned directory beneath the scratch root.
    pub fn dir(&self, rel: &str, mode: u32) -> PathBuf {
        let p = self.join(rel);
        std::fs::create_dir_all(&p).expect("mkdir");
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .expect("chmod");
        p
    }

    /// A `mode`-permissioned file beneath the scratch root.
    pub fn file(&self, rel: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let p = self.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir parent");
        }
        std::fs::write(&p, bytes).expect("write file");
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .expect("chmod");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

// ---------------------------------------------------------------------------
// Tier 3 gate — CENTRAL_TIER3=1 && euid 0 && the reference host
// ---------------------------------------------------------------------------

/// The pinned reference host: Ubuntu ≥ 24.04 on x86_64, the same
/// shape the launcher suites gate on.
pub fn reference_host() -> bool {
    if std::env::consts::ARCH != "x86_64" {
        return false;
    }
    let Ok(release) = std::fs::read_to_string("/etc/os-release") else {
        return false;
    };
    let mut ubuntu = false;
    let mut version_ok = false;
    for line in release.lines() {
        if line == "ID=ubuntu" {
            ubuntu = true;
        }
        if let Some(v) = line.strip_prefix("VERSION_ID=") {
            let v = v.trim_matches('"');
            if let Some(major) = v.split('.').next().and_then(|m| m.parse::<u32>().ok()) {
                version_ok = major >= 24;
            }
        }
    }
    ubuntu && version_ok
}

/// `true` when Tier 3 may run: `CENTRAL_TIER3=1`, root, reference
/// host. Otherwise prints the explicit skip line and returns `false`.
pub fn tier3(scenario: &str) -> bool {
    if std::env::var("CENTRAL_TIER3").ok().as_deref() != Some("1") {
        return skip(&format!(
            "{scenario}: CENTRAL_TIER3=1 not set — reference-host scenario not exercised"
        ));
    }
    if !rustix::process::geteuid().is_root() {
        return skip(&format!(
            "{scenario}: not root — privileged peer/console scenario skipped"
        ));
    }
    if !reference_host() {
        return skip(&format!(
            "{scenario}: not the pinned reference host (Ubuntu >= 24.04 x86_64)"
        ));
    }
    true
}

/// A documented skip: one `SKIP [a07]` line on stderr, `false`.
pub fn skip(reason: &str) -> bool {
    eprintln!("SKIP [a07] {reason}");
    false
}

// ---------------------------------------------------------------------------
// Wire exchanges
// ---------------------------------------------------------------------------

/// Drive `helper::Server::handle_conn` over a connected socket pair:
/// writes `line` (one JSON request, `\n`-terminated by the caller if
/// wanted — the helper reads one line) and returns the raw response
/// line, or `None` when the server closed unanswered.
pub fn helper_exchange(server: &helper::Server, line: &[u8]) -> Option<Vec<u8>> {
    let (mut client, srv) = UnixStream::pair().expect("socketpair");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    std::thread::scope(|s| {
        s.spawn(|| {
            let _ = server.handle_conn(srv);
        });
        client.write_all(line).expect("write request");
        client.shutdown(std::net::Shutdown::Write).ok();
        let mut buf = Vec::new();
        let n = client
            .take(64 * 1024)
            .read_to_end(&mut buf)
            .expect("read response");
        if n == 0 { None } else { Some(buf) }
    })
}

/// `helper_exchange` plus the response decode — the server must have
/// answered (a closed-unanswered exchange is a separate assertion).
pub fn helper_request(server: &helper::Server, req: &Request) -> Response {
    let mut line = serde_json::to_vec(req).expect("marshal request");
    line.push(b'\n');
    let raw = helper_exchange(server, &line).expect("server answered the request");
    serde_json::from_slice::<Response>(raw.trim_ascii_end()).expect("valid response line")
}

/// Drive `broker::server::handle_conn` over a connected socket pair:
/// writes `bytes` verbatim (marker, frame, or JSON line) and returns
/// the one JSON response line decoded as `serde_json::Value`, or
/// `None` when the broker closed unanswered.
pub fn broker_exchange(
    svc: &central_adapter_linux::broker::server::Service,
    bytes: &[u8],
) -> Option<serde_json::Value> {
    let (mut client, srv) = UnixStream::pair().expect("socketpair");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    std::thread::scope(|s| {
        s.spawn(|| {
            let _ = central_adapter_linux::broker::server::handle_conn(srv, svc);
        });
        client.write_all(bytes).expect("write request");
        client.shutdown(std::net::Shutdown::Write).ok();
        let mut line = Vec::new();
        let n = BufReader::new(&client)
            .read_until(b'\n', &mut line)
            .expect("read response");
        if n == 0 {
            return None;
        }
        Some(serde_json::from_slice(line.trim_ascii_end()).expect("valid broker response"))
    })
}

/// One `Service` over a scratch root — persistent signing, TLS,
/// journal, provisioning, proofs, payload epochs all materialize
/// under `root` exactly as production.
pub fn broker_service(
    scratch: &Scratch,
    runtime_uid: u32,
) -> central_adapter_linux::broker::server::Service {
    central_adapter_linux::broker::server::Service::new(scratch.join("broker"), runtime_uid)
        .expect("broker service")
}

/// A `BrokerRequest` with only the fields the dispatch needs.
pub fn broker_request(op: &str, purpose: &str) -> central_infra::authority::BrokerRequest {
    central_infra::authority::BrokerRequest {
        operation_id: op.to_owned(),
        purpose: purpose.to_owned(),
        session_token: String::new(),
        payload: None,
    }
}

/// Assert the exact `Failure` a denial scenario must produce: `kind`
/// plus the pinned `code`, and (when `msg` is given) the message
/// fragment upstream's tests pin.
pub fn assert_denial(
    err: &Failure,
    kind: central_foundation::failure::FailureKind,
    code: &str,
    msg: &str,
) {
    assert_eq!(
        err.kind(),
        kind,
        "failure kind for {code}: {}",
        err.message()
    );
    assert_eq!(err.code(), code, "failure code: {}", err.message());
    if !msg.is_empty() {
        assert!(
            err.message().contains(msg),
            "message for {code} must contain {msg:?}: {}",
            err.message()
        );
    }
}
