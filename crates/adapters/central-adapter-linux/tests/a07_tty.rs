//! A07 — TTY spoofing denials (threat T19, upstream
//! `tty_ceremony_read_linux_test.go`, `init_confirm_portable_test.go`,
//! `pam_linux.go` credential gate).
//!
//! The physical-console contract: only a peer whose fd 0 is a real
//! console (`/dev/tty*`, never `/dev/pts/*`) can carry a ceremony.
//! A pseudo-terminal, a pipe, `/dev/null`, and a dead peer are all
//! refused before a byte of prompt is written. The confirmation
//! dialog's own denial ladder — empty phrase, mismatched phrase,
//! exhausted budget — and the pre-PAM credential gate are asserted
//! byte-exact.

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::helper::{self, PeerIdentity};
use central_adapter_linux::sys::{pam, tty};
use central_foundation::failure::{Failure, FailureKind};
use rustix::fs::{Mode, OFlags, open};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use std::io::Write;
use std::time::{Duration, Instant};

/// Spawn a child whose fd 0 is `stdin_fd`, return its pid; the child
/// sleeps until killed. `None` when the spawn fails.
fn child_with_stdin(stdin: impl Into<std::process::Stdio>) -> Option<std::process::Child> {
    std::process::Command::new("/bin/sleep")
        .arg("30")
        .stdin(stdin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
}

fn pid_of(child: &std::process::Child) -> rustix::process::Pid {
    rustix::process::Pid::from_raw(child.id() as i32).expect("child pid")
}

/// A peer on a pipe — never a console.
#[test]
fn open_physical_tty_refuses_pipe_stdin() {
    let mut child = child_with_stdin(std::process::Stdio::piped()).expect("spawn");
    let err = tty::open_physical_tty(pid_of(&child))
        .err()
        .expect("a pipe must not open as a physical console");
    child.kill().ok();
    child.wait().ok();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_tty_not_console",
        "physical console",
    );
}

/// A peer on `/dev/null` — never a console.
#[test]
fn open_physical_tty_refuses_null_stdin() {
    let mut child = child_with_stdin(std::process::Stdio::null()).expect("spawn");
    let err = tty::open_physical_tty(pid_of(&child))
        .err()
        .expect("/dev/null must not open as a physical console");
    child.kill().ok();
    child.wait().ok();
    assert_denial(&err, FailureKind::Denied, "sys_tty_not_console", "");
}

/// The TTY-spoofing case upstream's check exists for: a peer whose
/// stdin is a pseudo-terminal. `/dev/pts/N` is a terminal but never a
/// physical console — the forged-console shape is refused by name.
#[test]
fn open_physical_tty_refuses_pty_stdin() {
    let Some((_master, slave)) = (|| {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::CLOEXEC).ok()?;
        grantpt(&master).ok()?;
        unlockpt(&master).ok()?;
        let name = ptsname(&master, Vec::new()).ok()?;
        let slave = open(
            std::path::PathBuf::from(name.to_string_lossy().into_owned()),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        Some((master, slave))
    })() else {
        eprintln!("SKIP [a07] pty-refusal: no pseudo-terminal on this host");
        return;
    };
    // The child holds the pty slave on fd 0 — its `/proc/<pid>/fd/0`
    // resolves to `/dev/pts/N`.
    let mut child = match child_with_stdin(std::process::Stdio::from(slave)) {
        Some(c) => c,
        None => {
            eprintln!("SKIP [a07] pty-refusal: could not spawn a peer on the pty");
            return;
        }
    };
    // Let the child's fd table settle before readlink.
    std::thread::sleep(Duration::from_millis(100));
    let link = std::fs::read_link(format!("/proc/{}/fd/0", child.id()));
    assert!(
        link.as_ref()
            .map(|p| p.to_string_lossy().starts_with("/dev/pts/"))
            .unwrap_or(false),
        "fixture: child stdin must resolve to a pts, got {link:?}"
    );
    let err = tty::open_physical_tty(pid_of(&child))
        .err()
        .expect("a pty slave must not open as a physical console");
    child.kill().ok();
    child.wait().ok();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_tty_not_console",
        "physical console",
    );
}

/// An unavailable peer (`pid <= 0`) refuses before any /proc lookup.
#[test]
fn tty_ceremony_refuses_unavailable_peer() {
    let peer = PeerIdentity {
        uid: euid(),
        gid: egid(),
        pid: 0,
    };
    let err = helper::tty_ceremony::perform_tty_ceremony(peer, None, "op-1", "").unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_tty_console_unfit",
        "Unix peer is unavailable",
    );
}

/// The scoped destructive ceremonies refuse an incomplete scope —
/// an empty instance/target/operation can never mint a phrase.
#[test]
fn scoped_ceremony_incomplete_scope_refused() {
    let peer = PeerIdentity {
        uid: euid(),
        gid: egid(),
        pid: self_pid(),
    };
    let err =
        helper::tty_ceremony::perform_wipe_tty_ceremony(peer, None, "", "", "op-1").unwrap_err();
    assert_eq!(err.code(), "sys_tty_scope");
    assert_eq!(err.kind(), FailureKind::Invalid);
}

// ---------------------------------------------------------------------------
// The confirmation dialog's own denial ladder (scripted console)
// ---------------------------------------------------------------------------

/// A scripted `CeremonyConsole` capturing every write — the dialog
/// never sees a request-controlled byte, only helper-owned prompts.
struct ScriptConsole {
    written: Vec<u8>,
}

impl Write for ScriptConsole {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tty::CeremonyConsole for ScriptConsole {}

/// An empty phrase is refused before anything is written —
/// `sys_tty_init_phrase`, `Invalid`.
#[test]
fn init_ceremony_empty_phrase_refused() {
    let mut console = ScriptConsole {
        written: Vec::new(),
    };
    let mut read_line = || Ok(String::from("anything"));
    let mut now = Instant::now;
    let err =
        tty::run_init_confirmation(None, &mut console, &mut read_line, "", &mut now).unwrap_err();
    assert_eq!(err.code(), "sys_tty_init_phrase");
    assert_eq!(err.kind(), FailureKind::Invalid);
    assert!(console.written.is_empty(), "nothing may be prompted");
}

/// Two wrong answers exhaust the attempts and produce the pinned
/// `sys_tty_init_mismatch` — the phrase is never accepted
/// approximately and the mistyped line is flushed before the retry.
#[test]
fn init_ceremony_wrong_phrase_twice_is_mismatch() {
    struct FlushConsole {
        written: Vec<u8>,
        flushed: u32,
    }
    impl Write for FlushConsole {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl tty::CeremonyConsole for FlushConsole {
        fn flush_input(&mut self) -> Result<bool, Failure> {
            self.flushed += 1;
            Ok(true)
        }
    }
    let mut console = FlushConsole {
        written: Vec::new(),
        flushed: 0,
    };
    let mut reads = 0u32;
    let mut read_line = || {
        reads += 1;
        Ok(String::from("WRONG PHRASE"))
    };
    let mut now = Instant::now;
    let err = tty::run_init_confirmation(
        None,
        &mut console,
        &mut read_line,
        "CONFIRM abc123 init",
        &mut now,
    )
    .unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_tty_init_mismatch",
        "did not match",
    );
    assert_eq!(reads, 2, "two bounded attempts, no more");
    assert_eq!(console.flushed, 1, "the mistyped line is discarded once");
}

/// No whole second left in the budget: `sys_tty_budget`, never a
/// "within 0 seconds" prompt and never a mismatch.
#[test]
fn init_ceremony_expired_budget_denied() {
    let mut console = ScriptConsole {
        written: Vec::new(),
    };
    let mut read_line = || Ok(String::from("CONFIRM abc123 init"));
    let mut now = Instant::now;
    let err = tty::run_init_confirmation(
        Some(Instant::now() - Duration::from_secs(1)),
        &mut console,
        &mut read_line,
        "CONFIRM abc123 init",
        &mut now,
    )
    .unwrap_err();
    assert_eq!(err.code(), "sys_tty_budget");
}

/// `confirmation_phrase_matches` is an exact match on the trimmed
/// line — a near-miss, a case difference, or a different ceremony's
/// phrase all fail.
#[test]
fn confirmation_phrase_matches_exactly() {
    assert!(tty::phrase::confirmation_phrase_matches(
        "CONFIRM 7f3a init",
        "CONFIRM 7f3a init"
    ));
    assert!(tty::phrase::confirmation_phrase_matches(
        "  CONFIRM 7f3a init\n",
        "CONFIRM 7f3a init"
    ));
    for wrong in [
        "CONFIRM 7f3a",            // truncated
        "CONFIRM 7f3a wipe",       // a different ceremony's suffix
        "confirm 7f3a init",       // case
        "CONFIRM 7f3a  init",      // doubled space
        "CONFIRM 7f3a init extra", // trailing junk
    ] {
        assert!(
            !tty::phrase::confirmation_phrase_matches(wrong, "CONFIRM 7f3a init"),
            "{wrong:?} must not satisfy the phrase"
        );
    }
    // The per-verb phrases are distinct: approval minted for one
    // destructive act can never satisfy another.
    let wipe = tty::phrase::wipe_phrase("i1", "t1", "o1");
    let export = tty::phrase::export_phrase("i1", "t1", "o1");
    assert_ne!(wipe, export);
    assert!(!tty::phrase::confirmation_phrase_matches(&wipe, &export));
}

// ---------------------------------------------------------------------------
// PAM — the credential gate and the closed auth envelope
// ---------------------------------------------------------------------------

/// Empty username/secret and interior NULs are refused as
/// `sys_pam_credential` before libpam is ever invoked — upstream's
/// pre-PAM gate, exact.
#[test]
fn pam_credentials_refuse_before_pam() {
    for (user, secret) in [("", b"x".as_slice()), ("operator", b""), ("", b"")] {
        let err = pam::authenticate(user, secret).unwrap_err();
        assert_eq!(err.code(), "sys_pam_credential");
    }
    for (user, secret) in [("op\0extra", b"x".as_slice()), ("op", b"sec\0ret")] {
        let err = pam::authenticate(user, secret).unwrap_err();
        assert_eq!(err.code(), "sys_pam_credential");
    }
}

/// `describe_authentication_failure` — a console failure stays a
/// console failure (`sys_tty_console_unfit`, Unavailable); every
/// other failure becomes the closed `sys_pam_auth` denial.
#[test]
fn authentication_failure_description_is_closed() {
    let console_err = Failure::unavailable("sys_tty_console_unfit", "console gone");
    let described = tty::describe_authentication_failure(console_err);
    assert_eq!(described.code(), "sys_tty_console_unfit");
    assert_eq!(described.kind(), FailureKind::Unavailable);

    let pam_err = Failure::denied("sys_pam_auth", "pam: authentication failed (code 7)");
    let described = tty::describe_authentication_failure(pam_err);
    assert_eq!(described.code(), "sys_pam_auth");
    assert_eq!(described.kind(), FailureKind::Denied);
    assert!(described.message().contains("authentication failed"));
}

/// The grant-mode confirmer refuses `ConfirmInit` outright — no grant
/// kind authorizes genesis through the confirmer (`sys_grant_init`);
/// and an unavailable peer is refused as `sys_grant_peer` before any
/// store lookup.
#[test]
fn pam_confirmer_grant_mode_denies_init_and_dead_peer() {
    let scratch = Scratch::new("confirmer-grants");
    let dir = scratch.dir("grants", 0o700);
    let store = helper::grant::GrantStore::open(dir.to_str().expect("utf8"), euid(), egid())
        .expect("grant store");
    let confirmer = helper::pam_ceremony::PamConfirmer::with_grants(store, "i1", "t1");
    let peer = PeerIdentity {
        uid: euid(),
        gid: egid(),
        pid: self_pid(),
    };
    let err = confirmer.confirm_init(peer, None, "op-1").unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_grant_init",
        "init grants authorize genesis only",
    );

    let dead = PeerIdentity {
        uid: euid(),
        gid: egid(),
        pid: 0,
    };
    let err = confirmer.confirm(dead, None, "op-1").unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_grant_peer",
        "Unix peer is unavailable",
    );
}

/// A forged or replayed confirmation token never verifies — the
/// one-use map only contains what the ceremony itself minted.
#[test]
fn confirmation_tokens_are_single_use_and_unforgeable() {
    let confirmer = helper::pam_ceremony::PamConfirmer::new();
    assert!(!confirmer.verify_and_consume("forged-token"));
    assert!(!confirmer.verify_and_consume(""));
}

/// Live PAM: a wrong password against the configured `central-helper`
/// service denies in the closed `sys_pam_auth` envelope — never
/// errors open. Skips (documented) on hosts without the service file,
/// the same gate upstream's `pam` build tag performs.
#[test]
fn pam_wrong_password_denied_when_service_present() {
    if !std::path::Path::new("/etc/pam.d/central-helper").exists() {
        eprintln!("SKIP [a07] live PAM: no /etc/pam.d/central-helper on this host");
        return;
    }
    let err = pam::authenticate("root", b"definitely-not-the-password-a07").unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_pam_auth",
        "authentication failed",
    );
}
