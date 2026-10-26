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
//!   the second opener's `EBUSY` that `sys_tty_console_unfit`
//!   reports;
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
use rustix::fs::{Gid, Mode, OFlags, Uid};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

/// The probe the multi-UID test re-execs as a foreign uid/gid. Run
/// directly (no `A07_PROBE_*` env) it documents its own skip — the
/// parent asserts on its exit status.
#[test]
fn tier3_probe_peer_as_child() {
    let (Ok(sock), Ok(kind)) = (
        std::env::var("A07_PROBE_SOCK"),
        std::env::var("A07_PROBE_KIND"),
    ) else {
        eprintln!("SKIP [a07] peer probe: not spawned by the tier3 parent");
        return;
    };
    let mut conn = UnixStream::connect(&sock).expect("probe connects to the service socket");
    match kind.as_str() {
        "helper" => {
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
        other => unreachable!("unknown probe kind {other}"),
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
    let exe = std::env::current_exe().expect("test binary path");
    let probe = |kind: &str, sock: &std::path::Path| {
        Command::new(&exe)
            .args(["--exact", "tier3_probe_peer_as_child"])
            .env("A07_PROBE_SOCK", sock)
            .env("A07_PROBE_KIND", kind)
            .uid(9999)
            .gid(9999)
            .stdin(Stdio::null())
            .spawn()
            .expect("probe child spawns")
    };

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
    let mut child = probe("helper", &sock);
    let (conn, _) = listener.accept().expect("accept probe");
    let _ = server.handle_conn(conn);
    assert!(
        child.wait().expect("probe exits").success(),
        "the helper must close a foreign peer unanswered"
    );

    // The broker's JSON transport: the same foreign peer is read and
    // answered with the exact `authority denied` evidence.
    let svc = broker_service(&scratch, euid());
    let sock = scratch.join("broker.sock");
    let listener = UnixListener::bind(&sock).expect("broker listener");
    std::fs::set_permissions(&sock, PermissionsExt::from_mode(0o666)).expect("chmod socket");
    let mut child = probe("broker", &sock);
    let (conn, _) = listener.accept().expect("accept probe");
    let _ = central_adapter_linux::broker::server::handle_conn(conn, &svc);
    assert!(
        child.wait().expect("probe exits").success(),
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

/// The physical-console exclusive lease: `TIOCEXCL` on a real VT —
/// the second opener's `EBUSY` surfaces as `sys_tty_console_unfit`,
/// and `open_physical_tty` on a child whose stdin IS the console
/// takes the lease only once we release ours.
#[test]
fn tier3_physical_console_exclusive_lease() {
    if !tier3("physical-console exclusive lease") {
        return;
    }
    let console = ["/dev/tty0", "/dev/console"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied();
    let Some(console) = console else {
        eprintln!("SKIP [a07] console lease: no /dev/tty0 or /dev/console on this host");
        return;
    };
    let flags = OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let held = match rustix::fs::open(console, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("SKIP [a07] console lease: {console} does not open ({e})");
            return;
        }
    };
    tty::lock_tty_exclusive(&held).expect("the first exclusive lock takes");

    // A second opener collides: TIOCEXCL → EBUSY → console_unfit.
    let second = rustix::fs::open(console, flags, Mode::empty()).expect("second open");
    let err = tty::lock_tty_exclusive(&second).unwrap_err();
    assert_eq!(err.code(), "sys_tty_console_unfit");

    // A child whose stdin is the console is a physical-console peer:
    // `open_physical_tty` must refuse while our lease holds and admit
    // once it is released.
    let stdin = rustix::fs::open(console, flags, Mode::empty()).expect("child stdin");
    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::from(stdin))
        .spawn()
        .expect("console peer child");
    let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("child pid");
    let err = tty::open_physical_tty(pid)
        .err()
        .expect("the held lease refuses a second ceremony");
    assert_eq!(err.code(), "sys_tty_console_unfit");

    drop(held);
    let console_fd =
        tty::open_physical_tty(pid).expect("the released lease admits the ceremony console");
    drop(console_fd);
    drop(second);
    let _ = child.kill();
    let _ = child.wait();
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
