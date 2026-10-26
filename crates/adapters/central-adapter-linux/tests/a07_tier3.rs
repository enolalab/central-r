//! A07 — Tier 3: the denial legs that only a root process on the
//! pinned reference host (Ubuntu ≥ 24.04, x86_64) can reach (threats
//! T17/T19/T23, upstream's root-gated `authority` platform tests).
//!
//! - multi-UID `SO_PEERCRED` denial — a child spawned under a foreign
//!   uid/gid is the only honest way to put a non-self identity on the
//!   wire (`Command::uid`/`gid`, no `unsafe`);
//! - root-owned traversal — a genuinely foreign-owned or
//!   group/other-writable ancestor, shapes a non-root process cannot
//!   manufacture;
//! - the physical-console exclusive lease — `TIOCEXCL` on a real VT,
//!   the *unprivileged* second opener's `EBUSY` that
//!   `sys_tty_console_unfit` reports (open(2) enforces the bit only
//!   against non-`CAP_SYS_ADMIN` callers, so the refusal must come
//!   from the foreign-uid probe);
//! - the live PAM denial — `pam_authenticate` against the host's real
//!   `central-helper` stack, where every non-`PAM_SUCCESS` is the
//!   closed `sys_pam_auth` refusal.
//!
//! Every leg gates through [`tier3`]: `CENTRAL_TIER3=1` + root + the
//! reference host, else an explicit `SKIP [a07]` — never a silent
//! pass.

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::genesis;
use central_adapter_linux::helper::grant::GrantStore;
use central_adapter_linux::helper::{PeerPolicy, Server};
use central_adapter_linux::sys::{pam, tty};
use central_foundation::failure::FailureKind;
use rustix::fs::{FileType, Gid, Mode, OFlags, Uid};
use rustix::io::Errno;
use rustix::process::Pid;
use rustix::termios::ioctl_tiocnxcl;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The probe the multi-UID and console tests re-exec as a foreign
/// uid/gid. Run directly (no `A07_PROBE_*` env) it documents its own
/// skip — the parent asserts on its exit status. `A07_PROBE_PATH` is
/// the socket the peer probes connect to, or the device node the
/// console probes open.
#[test]
fn tier3_probe_as_child() {
    let (Ok(path), Ok(kind)) = (
        std::env::var("A07_PROBE_PATH"),
        std::env::var("A07_PROBE_KIND"),
    ) else {
        eprintln!("SKIP [a07] probe: not spawned by the tier3 parent");
        return;
    };
    match kind.as_str() {
        "helper" => {
            let mut conn =
                UnixStream::connect(&path).expect("probe connects to the service socket");
            conn.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("probe read deadline");
            conn.write_all(b"{\"operation_id\":\"op-t3\",\"verb\":\"status\",\"payload\":null}\n")
                .expect("probe writes its request");
            conn.shutdown(std::net::Shutdown::Write).ok();
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).expect("probe reads to EOF");
            assert!(
                buf.is_empty(),
                "a foreign peer must be closed unanswered, got {buf:?}"
            );
        }
        "broker" => {
            let mut conn =
                UnixStream::connect(&path).expect("probe connects to the service socket");
            conn.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("probe read deadline");
            conn.write_all(
                b"{\"operation_id\":\"op-t3\",\"purpose\":\"hmac_fingerprint\",\"payload\":{}}\n",
            )
            .expect("probe writes its request");
            conn.shutdown(std::net::Shutdown::Write).ok();
            let mut line = Vec::new();
            BufReader::new(&conn)
                .read_until(b'\n', &mut line)
                .expect("probe reads the denial line");
            let resp: serde_json::Value =
                serde_json::from_slice(line.trim_ascii_end()).expect("valid broker response");
            assert_eq!(resp["outcome"], "denied");
            assert_eq!(resp["evidence"]["message"], "authority denied");
        }
        "console-busy" => {
            // `TIOCEXCL` only sets the tty's `TTY_EXCLUSIVE` bit — it
            // is `open(2)` itself that refuses a held console with
            // `EBUSY`, and only for an opener without `CAP_SYS_ADMIN`
            // (which is exactly why this probe runs as uid 9999: the
            // root parent's own re-open is never refused). The error
            // is what `open_physical_tty` reports wrapped as
            // `sys_tty_console_unfit`.
            let err = rustix::fs::open(&path, console_flags(), Mode::empty())
                .expect_err("a foreign open must not take the held console lease");
            assert_eq!(err, Errno::BUSY, "want the lease's EBUSY, got {err}");
        }
        "console-open" => {
            // The same foreign opener, the same node — admitted once
            // the lease is released. Taking and handing back
            // `TIOCEXCL` proves the *lease* was the gate, not the
            // probe's identity or the node's DAC.
            let fd = rustix::fs::open(&path, console_flags(), Mode::empty())
                .expect("the released lease admits a foreign open");
            tty::lock_tty_exclusive(&fd).expect("the released lease re-takes");
            ioctl_tiocnxcl(&fd).expect("the probe hands the lease back");
        }
        other => unreachable!("unknown probe kind {other}"),
    }
}

/// `O_RDWR|O_NONBLOCK|O_CLOEXEC` — the flags `open_physical_tty`
/// opens a console with; `O_NONBLOCK` is load-bearing (a serial line
/// without carrier would otherwise block inside `open(2)`).
fn console_flags() -> OFlags {
    OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC
}

/// Re-exec this binary as the probe child under `9999:9999` — a
/// kernel-attested foreign identity for `SO_PEERCRED`, DAC, and the
/// console lease's `!CAP_SYS_ADMIN` arm.
fn spawn_probe(exe: &Path, kind: &str, path: &Path) -> Child {
    Command::new(exe)
        .args(["--exact", "tier3_probe_as_child"])
        .env("A07_PROBE_PATH", path)
        .env("A07_PROBE_KIND", kind)
        .uid(9999)
        .gid(9999)
        .stdin(Stdio::null())
        .spawn()
        .expect("probe child spawns")
}

/// How long the parent gives a probe child to connect/exchange/exit:
/// generous against a slow exec, but a hard bound — a wedged child
/// must fail the test, never hang the suite.
const PROBE_BUDGET: Duration = Duration::from_secs(10);

/// `accept()` bounded by [`PROBE_BUDGET`]: the probe is a separate
/// process, so a regression that kills it before it connects must not
/// strand the parent on a connection that never arrives.
fn accept_bounded(listener: &UnixListener) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let deadline = Instant::now() + PROBE_BUDGET;
    loop {
        match listener.accept() {
            Ok((conn, _)) => return conn,
            Err(e) => {
                assert!(
                    e.kind() == std::io::ErrorKind::WouldBlock,
                    "probe accept: {e}"
                );
                assert!(
                    Instant::now() < deadline,
                    "probe did not connect within {PROBE_BUDGET:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// `wait()` bounded by [`PROBE_BUDGET`]; on expiry the child is
/// killed and the test fails rather than hanging the suite.
fn wait_bounded(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + PROBE_BUDGET;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("probe wait") {
            return status;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    unreachable!("probe child did not exit within {PROBE_BUDGET:?}")
}

/// Hands `TTY_EXCLUSIVE` back on drop — the bit clears only on
/// `TIOCNXCL` or the tty's final close, so a failing leg must not be
/// able to strand the host's VT in exclusive mode.
struct ExclGuard(OwnedFd);

impl ExclGuard {
    /// Explicit release: dropping the fd alone does not clear
    /// `TTY_EXCLUSIVE` while another opener still holds the tty.
    fn release(&self) {
        ioctl_tiocnxcl(&self.0).expect("release the console lease");
    }
}

impl Drop for ExclGuard {
    fn drop(&mut self) {
        let _ = ioctl_tiocnxcl(&self.0);
    }
}

/// Multi-UID peer denial: a real child process running `9999:9999` —
/// a kernel-attested foreign identity, not a fabricated `PeerCred` —
/// is refused by both gates. The helper closes it unanswered (the
/// admitted-only contract); the broker answers `authority denied`.
#[test]
fn tier3_multi_uid_peer_denied() {
    if !tier3("multi-uid peer denial") {
        return;
    }
    let scratch = Scratch::new("tier3-peers");
    // The foreign-uid probe must reach the sockets on its own: the
    // fixture's default `0700` root would refuse it at ancestor
    // traversal (EACCES — the peer gate never sees it). `0711` keeps
    // the root root-owned and grants traverse-only to other uids —
    // no listing, no creation — so the `SO_PEERCRED` gate remains the
    // only thing between the peer and the service.
    std::fs::set_permissions(scratch.path(), PermissionsExt::from_mode(0o711))
        .expect("traverse-only scratch root");
    let exe = std::env::current_exe().expect("test binary path");

    // The helper's operator arm: root's own pair is the configured
    // operator here (this test runs as euid 0), the foreign 9999:9999
    // child is nobody the arm knows.
    let mut server = Server::new();
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: euid() + 1,
        operator_uid: euid(),
        operator_gid: egid(),
    });
    let sock = scratch.join("helper.sock");
    let listener = UnixListener::bind(&sock).expect("helper listener");
    // The file gate is not under test — open it so the child reaches
    // the peer gate itself.
    std::fs::set_permissions(&sock, PermissionsExt::from_mode(0o666)).expect("chmod socket");
    let mut child = spawn_probe(&exe, "helper", &sock);
    let conn = accept_bounded(&listener);
    let _ = server.handle_conn(conn);
    assert!(
        wait_bounded(&mut child).success(),
        "the helper must close a foreign peer unanswered"
    );

    // The broker's JSON transport: the same foreign peer is read and
    // answered with the exact `authority denied` evidence.
    let svc = broker_service(&scratch, euid());
    let sock = scratch.join("broker.sock");
    let listener = UnixListener::bind(&sock).expect("broker listener");
    std::fs::set_permissions(&sock, PermissionsExt::from_mode(0o666)).expect("chmod socket");
    let mut child = spawn_probe(&exe, "broker", &sock);
    let conn = accept_bounded(&listener);
    let _ = central_adapter_linux::broker::server::handle_conn(conn, &svc);
    assert!(
        wait_bounded(&mut child).success(),
        "the broker must answer a foreign peer `authority denied`"
    );
}

/// Root-owned traversal: as root the scratch tree is *really*
/// root-owned — the ancestor gate's `missing-or-exact` contract is
/// exercised against owners a non-root test can never manufacture: a
/// foreign-owned ancestor (`12345:12345`) and a group/other-writable
/// root-owned one.
#[test]
fn tier3_root_owned_traversal_denied() {
    if !tier3("root-owned ancestor traversal") {
        return;
    }
    let scratch = Scratch::new("tier3-ancestors");

    // A genuinely root-owned `0700` ancestor is admitted.
    let dir = scratch.dir("root-owned", 0o700);
    genesis::genesis_ancestor_missing_or_root_owned(&dir, 0).expect("a root-owned ancestor admits");

    // A foreign-owned ancestor is refused — this shape cannot exist
    // without root's chown.
    rustix::fs::chown(&dir, Some(Uid::from_raw(12345)), Some(Gid::from_raw(12345)))
        .expect("chown to a foreign uid");
    let err = genesis::genesis_ancestor_missing_or_root_owned(&dir, 0).unwrap_err();
    assert!(
        err.contains("not owned by 0 or is group- or other-writable"),
        "{err}"
    );

    // A group/other-writable ancestor is refused even root-owned.
    let writable = scratch.dir("writable-root", 0o755);
    let err = genesis::genesis_ancestor_missing_or_root_owned(&writable, 0).unwrap_err();
    assert!(
        err.contains("not owned by 0 or is group- or other-writable"),
        "{err}"
    );

    // The grant store on a real `0:0` `0700` opens; once foreign-owned
    // it refuses — the store's identity check, not the file DAC.
    let store_dir = scratch.dir("store", 0o700);
    GrantStore::open(store_dir.to_str().expect("utf8"), 0, 0).expect("root-owned store opens");
    rustix::fs::chown(
        &store_dir,
        Some(Uid::from_raw(12345)),
        Some(Gid::from_raw(12345)),
    )
    .expect("chown store");
    let err = GrantStore::open(store_dir.to_str().expect("utf8"), 0, 0)
        .err()
        .expect("a foreign-owned store must refuse");
    assert_denial(&err, FailureKind::Denied, "sys_grant_store", "owned");
}

/// The physical-console exclusive lease: `TIOCEXCL` on a real VT.
///
/// The lease lives on the tty and is enforced inside `tty_open(2)`:
/// `TIOCEXCL` only sets `TTY_EXCLUSIVE` — it is *open(2)* that turns
/// the bit into `EBUSY`, and only for an opener without
/// `CAP_SYS_ADMIN`. Both facts shape this test: as euid 0 our own
/// second open is never refused, so the colliding attempt must come
/// from the uid-9999 probe; and the probe must reach the same
/// `tty_struct` through a node it may open — the real `/dev/tty0` is
/// `0600 root:tty`, where a foreign uid dies at DAC (`EACCES`) before
/// the lease is ever checked — so a `0666` `mknod` alias in the
/// scratch carries the device. The probe's `EBUSY` is the refusal
/// `open_physical_tty` surfaces as `sys_tty_console_unfit`.
#[test]
fn tier3_physical_console_exclusive_lease() {
    if !tier3("physical-console exclusive lease") {
        return;
    }
    // `/dev/tty0` (the current-VT alias): `open_physical_tty`'s seat
    // predicate accepts `/dev/tty*` only, so `/dev/console` cannot
    // anchor the peer's fd 0 — it is refused `sys_tty_not_console`
    // there, not the lease refusal under test.
    let console = "/dev/tty0";
    if !Path::new(console).exists() {
        eprintln!("SKIP [a07] console lease: no /dev/tty0 on this host");
        return;
    }
    let held = match rustix::fs::open(console, console_flags(), Mode::empty()) {
        Ok(fd) => ExclGuard(fd),
        Err(e) => {
            eprintln!("SKIP [a07] console lease: {console} does not open ({e})");
            return;
        }
    };
    tty::lock_tty_exclusive(&held.0).expect("the first exclusive lock takes");

    // The probe's path to the same tty: a `0666` node for the
    // console's dev_t beneath a traverse-only scratch root, so DAC
    // admits the foreign uid and the lease is the only refusal left.
    let scratch = Scratch::new("tier3-console");
    std::fs::set_permissions(scratch.path(), PermissionsExt::from_mode(0o711))
        .expect("traverse-only scratch root");
    let rdev = std::fs::metadata(console).expect("console metadata").rdev();
    let node = scratch.join("vt0");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &node,
        FileType::CharacterDevice,
        Mode::empty(),
        rdev,
    )
    .expect("console device node");
    std::fs::set_permissions(&node, PermissionsExt::from_mode(0o666))
        .expect("foreign-openable node");

    // Held: a foreign opener's `open(2)` on the same tty must fail
    // `EBUSY` — the exclusive-lease refusal for an unprivileged peer.
    let exe = std::env::current_exe().expect("test binary path");
    let mut denied = spawn_probe(&exe, "console-busy", &node);
    assert!(
        wait_bounded(&mut denied).success(),
        "an unprivileged second open of the leased console must fail EBUSY"
    );

    // Released: the same foreign opener, the same node — admitted,
    // and it takes `TIOCEXCL` of its own. The pair proves the lease,
    // not the identity, was the gate.
    held.release();
    let mut admitted = spawn_probe(&exe, "console-open", &node);
    assert!(
        wait_bounded(&mut admitted).success(),
        "the released console must admit the same unprivileged opener"
    );

    // The ceremony entry on the real path: a peer whose fd 0 resolves
    // under `/dev/tty*` passes `open_physical_tty`'s seat predicate
    // and the call takes the lease — the production shape. As euid 0
    // our own open is the one caller the lease never refuses, so the
    // refusal evidence above lives entirely in the probe legs.
    let stdin = rustix::fs::open(console, console_flags(), Mode::empty()).expect("peer stdin");
    let mut peer = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::from(stdin))
        .spawn()
        .expect("console peer child");
    let pid = Pid::from_raw(peer.id() as i32).expect("peer pid");
    let console_fd =
        tty::open_physical_tty(pid).expect("the peer's physical console takes the ceremony lease");
    drop(console_fd);
    let _ = peer.kill();
    let _ = peer.wait();
}

/// The live PAM denial: a wrong secret against the host's real
/// `central-helper` service — or, on a host where the service file is
/// absent, the unconfigured-service path — lands in the same closed
/// `sys_pam_auth` envelope. `PAM_SUCCESS` is the only non-denial the
/// boundary can produce.
#[test]
fn tier3_live_pam_denial() {
    if !tier3("live PAM denial") {
        return;
    }
    let configured = std::path::Path::new("/etc/pam.d/central-helper").exists();
    let err = pam::authenticate("root", b"a07-definitely-not-the-password").unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_pam_auth",
        "authentication failed",
    );
    if !configured {
        eprintln!(
            "SKIP [a07] live PAM leg: /etc/pam.d/central-helper absent — the \
             exercised leg is the fail-closed unconfigured-service path"
        );
    }
}
