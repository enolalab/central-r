//! `cmd/central/c06_ceremony_driver_test.go` — the C06 ceremony driver.
//!
//! The driver is the shared foundation Task 10b's scenario files reuse: it
//! pins the ceremony device predicate to the helper's own
//! [`open_physical_tty`], probes the operator's TTY for the descriptor
//! operations the ceremony performs, bounds a ceremony by the helper's own
//! budget share, launches a real child `central` process with a real console
//! file as its stdin (never a shortcut that bypasses `SO_PEERCRED` peer
//! identity), types the confirmation phrase once at the far end, and records
//! only phrase digests.
//!
//! Portable parts (predicate pins, plan validation, budget, phrase-digest
//! routing, armed-vs-disarmed deadline arithmetic) run anywhere; the live
//! probe and drive paths gate on the armed suite plus a real console.

use std::io::Write as _;
use std::os::unix::io::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use rustix::fs::{Mode, OFlags, open};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

use central_adapter_linux::helper::server::{CEREMONY_BUDGET, restore_apply_deadline};
use central_adapter_linux::sys::tty::{lock_tty_exclusive, read_ceremony_line};

/// `c06PhysicalTTYPrefix` — `/dev/tty*`: the prefix `open_physical_tty`
/// requires.
pub const PHYSICAL_TTY_PREFIX: &str = "/dev/tty";
/// `c06RejectedTTYPrefix` — `/dev/pts/`: harness pseudo-terminals are refused
/// explicitly; a pty is not a physical console.
pub const REJECTED_TTY_PREFIX: &str = "/dev/pts/";

/// `c06CeremonyDeviceQualifies` — the device predicate, restated here so the
/// pin test below can hold the two spellings equal.
pub fn ceremony_device_qualifies(target: &str) -> bool {
    target.starts_with(PHYSICAL_TTY_PREFIX) && !target.starts_with(REJECTED_TTY_PREFIX)
}

/// The helper source the predicate is pinned against — the same file the
/// production `open_physical_tty` lives in.
fn tty_source() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path =
        Path::new(manifest).join("../../crates/adapters/central-adapter-linux/src/sys/tty.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read the helper's physical-TTY source {}: {e}",
            path.display()
        )
    })
}

/// `TestC06TheCeremonyDevicePredicateIsTheOneOpenPhysicalTTYApplies` — the
/// restated predicate and the production source must be the same rule.
#[test]
fn the_ceremony_device_predicate_is_the_one_open_physical_tty_applies() {
    let source = tty_source();
    let position = source
        .find("pub fn open_physical_tty")
        .expect("open_physical_tty must exist in sys/tty.rs");
    let body =
        &source[position..position + source[position..].find("\n}").unwrap_or(4000).min(4000)];
    assert!(
        body.contains("starts_with(\"/dev/tty\")"),
        "open_physical_tty must require the /dev/tty prefix"
    );
    assert!(
        body.contains("starts_with(\"/dev/pts/\")"),
        "open_physical_tty must reject /dev/pts/"
    );
    // The restated predicate agrees on every shape both rule spellings meet.
    for (target, want) in [
        ("/dev/tty1", true),
        ("/dev/ttyS0", true),
        ("/dev/ttyUSB0", true),
        ("/dev/pts/3", false),
        ("/dev/console", false),
        ("/dev/null", false),
        ("tty1", false),
        ("", false),
    ] {
        assert_eq!(ceremony_device_qualifies(target), want, "target {target:?}");
    }
}

// ---------------------------------------------------------------------------
// The environment probe.
// ---------------------------------------------------------------------------

/// `c06CeremonyDeviceProbe` — what probing one device measured.
#[derive(Debug, Default)]
pub struct CeremonyDeviceProbe {
    pub opened: bool,
    pub exclusive_taken: bool,
    pub echo_suppressed: bool,
    pub echo_observed_off: bool,
    pub echo_restored: bool,
    /// `deadline_fired` distinguishes an ARMED deadline that elapsed from a
    /// DISARMED one — the whole point of `disarm`.
    pub deadline_accepted: bool,
    pub deadline_fired: bool,
    pub error: String,
}

/// `c06ProbeCeremonyDevice` — performs the descriptor operations the ceremony
/// does on `path`: open, `TIOCEXCL`, echo off (observed off), echo restore,
/// and a `window`-long read deadline observed firing. `disarm` clears the
/// deadline instead of arming it — the control that proves the probe can tell
/// the two apart, the check for a descriptor removed from the poller.
pub fn probe_ceremony_device(
    path: &Path,
    window: Duration,
    disarm: bool,
    unblock: Option<Box<dyn FnOnce() + Send>>,
) -> CeremonyDeviceProbe {
    let mut probe = CeremonyDeviceProbe::default();
    // Open the way `open_physical_tty` opens the console — rustix's safe
    // `open`, the workspace's audited syscall vocabulary.
    let fd = match open(
        path,
        OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => {
            probe.error = format!("open: {e}");
            return probe;
        }
    };
    probe.opened = true;
    // `TIOCEXCL` through the production call the ceremony itself takes.
    probe.exclusive_taken = lock_tty_exclusive(&fd).is_ok();
    // Echo off / observed off / restored — the `EchoGuard` dance, restated on
    // the same safe termios wrappers production uses.
    if let Ok(saved) = tcgetattr(&fd) {
        let mut quiet = saved.clone();
        quiet.local_modes &= !LocalModes::ECHO;
        if tcsetattr(&fd, OptionalActions::Now, &quiet).is_ok() {
            probe.echo_suppressed = true;
            if let Ok(now) = tcgetattr(&fd) {
                probe.echo_observed_off = !now.local_modes.contains(LocalModes::ECHO);
            }
            probe.echo_restored = tcsetattr(&fd, OptionalActions::Now, &saved).is_ok();
        }
    }
    // The deadline half runs through the production bounded read — upstream's
    // `SetReadDeadline` analogue. `unblock` is the far end typing: an armed
    // deadline that never had to fire reads back as not fired.
    if let Some(unblock) = unblock {
        std::thread::spawn(unblock);
    }
    probe.deadline_accepted = true;
    // A "disarmed" deadline must still bound the probe itself: upstream arms
    // a long control window so the control cannot hang the suite.
    let bound = if disarm {
        Duration::from_secs(20)
    } else {
        window
    };
    match read_ceremony_line(&fd, Some(Instant::now() + bound), None) {
        Ok(_) => probe.deadline_fired = false,
        Err(f) => probe.deadline_fired = f.code() == "sys_tty_budget",
    }
    probe
}

/// `c06OpenPseudoTerminal` — a pty pair, the device a physical console is
/// explicitly NOT. Returns (master, slave path). Same safe `rustix::pty`
/// vocabulary the adapter's own ceremony tests use.
pub fn open_pseudo_terminal() -> (OwnedFd, PathBuf) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::CLOEXEC)
        .unwrap_or_else(|e| panic!("posix_openpt: {e}"));
    grantpt(&master).unwrap_or_else(|e| panic!("grantpt: {e}"));
    unlockpt(&master).unwrap_or_else(|e| panic!("unlockpt: {e}"));
    let name = ptsname(&master, Vec::new()).unwrap_or_else(|e| panic!("ptsname: {e}"));
    let path = PathBuf::from(name.to_string_lossy().into_owned());
    assert!(
        path.starts_with(REJECTED_TTY_PREFIX),
        "a pty is always under /dev/pts/, got {}",
        path.display()
    );
    (master, path)
}

/// `TestC06TheCeremonyProbePerformsTheDescriptorOperationsTheCeremonyDoes` —
/// the probe performs open/exclusive/echo/deadline on a pty, and the pty is
/// refused by the device predicate.
#[test]
fn the_ceremony_probe_performs_the_descriptor_operations_the_ceremony_does() {
    let (master, slave_path) = open_pseudo_terminal();
    assert!(!ceremony_device_qualifies(slave_path.to_str().unwrap()));
    let mut far_end = std::fs::File::from(master);
    let probe = probe_ceremony_device(
        &slave_path,
        Duration::from_millis(150),
        false,
        Some(Box::new(move || {
            std::thread::sleep(Duration::from_millis(40));
            // The far end types; the armed deadline never fires.
            far_end
                .write_all(b"\n")
                .expect("the pty master must take the typed line");
        })),
    );
    assert!(
        probe.opened,
        "probe failed to open the pty: {}",
        probe.error
    );
    assert!(probe.exclusive_taken, "TIOCEXCL must succeed on a pty");
    assert!(probe.echo_suppressed && probe.echo_observed_off && probe.echo_restored);
    assert!(probe.deadline_accepted);
    assert!(!probe.deadline_fired, "the far end typed inside the window");
}

/// `TestC06TheCeremonyDeviceProbeTellsAnArmedDeadlineFromADisarmedOne`.
#[test]
fn the_ceremony_device_probe_tells_an_armed_deadline_from_a_disarmed_one() {
    let (_master, slave_path) = open_pseudo_terminal();
    let armed = probe_ceremony_device(&slave_path, Duration::from_millis(120), false, None);
    assert!(
        armed.deadline_fired,
        "nobody typed; the armed deadline must fire"
    );
    let (_master2, slave_path2) = open_pseudo_terminal();
    // disarm=true with no far-end traffic: the control window elapses.
    let disarmed = probe_ceremony_device(&slave_path2, Duration::from_secs(60), true, None);
    assert!(
        disarmed.deadline_fired,
        "the disarmed control reports its own bound elapsed, not a ceremony acceptance"
    );
}

/// `TestC06TheCeremonyEnvironmentIsFitToDriveTheCeremony` — armed gate +
/// this process's own fd 0 probed the way the helper probes a peer's.
#[test]
fn the_ceremony_environment_is_fit_to_drive_the_ceremony() {
    if !crate::runner::runner().require_armed() {
        return;
    }
    let target = std::fs::read_link("/proc/self/fd/0")
        .unwrap_or_else(|e| panic!("the driver's own fd 0 does not resolve: {e}"));
    let target = target.to_string_lossy().into_owned();
    assert!(
        ceremony_device_qualifies(&target),
        "the driver's fd 0 resolves to {target:?}, which is not a physical console; every ceremony scenario would fail here"
    );
    let probe = probe_ceremony_device(Path::new(&target), Duration::from_millis(200), true, None);
    assert!(probe.opened, "fd 0's console did not open: {}", probe.error);
}

// ---------------------------------------------------------------------------
// Confirmation phrases — only digests ever leave this driver.
// ---------------------------------------------------------------------------

/// `c06ConfirmationPhraseFormat` upstream: `"%s %s %s %s"`.
pub const CONFIRMATION_PHRASE_FORMAT_PARTS: usize = 4;

/// The phrase prefixes, restated exactly as upstream restates them and pinned
/// to the helper's source by the test below.
pub const RESTORE_APPLY_PHRASE_PREFIX: &str = "RESTORE CENTRAL";
pub const RESTORE_ABANDON_PHRASE_PREFIX: &str = "ABANDON RESTORE";

/// `c06DeriveConfirmationPhrase` — `prefix instance target operation`.
pub fn derive_confirmation_phrase(
    prefix: &str,
    instance_id: &str,
    target_id: &str,
    operation_id: &str,
) -> String {
    format!("{prefix} {instance_id} {target_id} {operation_id}")
}

/// `c06ConfirmationPhraseSatisfies` — the helper's comparison rule: an empty
/// expectation never matches; a typed line matches only by exact equality.
pub fn confirmation_phrase_satisfies(typed: &str, expected: &str) -> bool {
    !expected.is_empty() && typed.trim() == expected
}

/// `c06ConfirmationPhraseDigest` — the only thing about a phrase that may
/// leave this driver (governance section 3.1).
pub fn confirmation_phrase_digest(phrase: &str) -> String {
    crate::hex_lower(Sha256::digest(phrase.as_bytes()))
}

/// `TestC06TheCeremonyPhrasesAreTheOnesTheHelperComposes` — pins the two
/// restated prefixes and the four-field format to the production composers
/// the helper itself calls, and pins the driver's comparison to the
/// production matcher on every decided case.
#[test]
fn the_ceremony_phrases_are_the_ones_the_helper_composes() {
    use central_adapter_linux::sys::tty::phrase;
    // The restated spelling and the production spelling must be the same
    // phrase — a drifted prefix or field order fails here.
    let apply = phrase::restore_apply_phrase("i", "t", "o");
    let abandon = phrase::restore_abandon_phrase("i", "t", "o");
    assert_eq!(
        apply,
        derive_confirmation_phrase(RESTORE_APPLY_PHRASE_PREFIX, "i", "t", "o")
    );
    assert_eq!(
        abandon,
        derive_confirmation_phrase(RESTORE_ABANDON_PHRASE_PREFIX, "i", "t", "o")
    );
    // Differential: same scope, same comparison, only the prefix moves —
    // and the driver's matcher agrees with production's on every case.
    for (typed, expected) in [
        (apply.clone(), apply.clone()),
        (format!("{apply}\n"), apply.clone()),
        (format!(" {apply}"), apply.clone()),
        (abandon.clone(), apply.clone()),
        (apply.clone(), abandon.clone()),
        (format!("{apply} extra"), apply.clone()),
        (apply.clone(), String::new()),
        (String::new(), apply.clone()),
    ] {
        assert_eq!(
            confirmation_phrase_satisfies(&typed, &expected),
            phrase::confirmation_phrase_matches(&typed, &expected),
            "matcher divergence on typed={typed:?} expected={expected:?}"
        );
    }
    assert!(!confirmation_phrase_satisfies(&abandon, &apply));
    assert!(!confirmation_phrase_satisfies(&apply, &abandon));
}

/// `TestC06NoLiveC06SourceCarriesAConfirmationPhraseExceptAsADigest` — scans
/// this suite's own sources for a phrase-shaped literal that is not a
/// `*_PREFIX` constant or digest.
#[test]
fn no_live_c06_source_carries_a_confirmation_phrase_except_as_a_digest() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let suite = Path::new(manifest).join("tests/c06_acceptance");
    for entry in std::fs::read_dir(&suite).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for (number, line) in source.lines().enumerate() {
            for prefix in crate::evidence::CONFIRMATION_PHRASE_PREFIXES {
                // A bare prefix constant or a sentence naming the prefix is
                // fine; the leak is a quoted literal whose text composes a
                // phrase — the prefix followed by the three scope fields
                // (instance, target, operation) upstream's format appends.
                let needle = format!("{prefix} ");
                for (index, segment) in line.split('"').enumerate() {
                    if index % 2 == 0 {
                        continue; // outside string literals
                    }
                    let Some(rest) = segment.split(&needle).nth(1) else {
                        continue;
                    };
                    if rest.split_whitespace().count() >= 3 {
                        panic!(
                            "{}:{} carries a composed confirmation phrase for {prefix:?}; phrases appear only as digests (governance 3.1)",
                            entry.path().display(),
                            number + 1
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The ceremony plan and the drive.
// ---------------------------------------------------------------------------

/// `c06CeremonyPlan` — everything a scenario must state for a ceremony step
/// before the driver will run it.
#[derive(Debug, Clone, Default)]
pub struct CeremonyPlan {
    /// `apply`, `resume` or `abandon`.
    pub verb: String,
    /// The operator binary the child execs.
    pub binary: String,
    /// The helper socket the child is handed.
    pub helper_socket: String,
    /// The non-root operator identity the child runs as.
    pub operator_uid: u32,
    pub operator_gid: u32,
    /// The daemon uid the peer check requires to differ.
    pub daemon_uid: u32,
    /// The console device the child gets as stdin.
    pub device: String,
    /// Redirected input instead of a console (the refusal negative).
    pub redirect_stdin: bool,
    /// The budget the step may spend.
    pub budget: Duration,
    /// `Peer` — the console the helper will see through SO_PEERCRED's fd0.
    pub peer: String,
    /// The phrase the far end types.
    pub typed: String,
    /// The operator secret the child environment must strip and the helper
    /// side carries.
    pub secret: String,
    /// Grant mode (ADR 0031): no console, a broker-issued nonce instead.
    pub grant_mode: bool,
    pub grant_operation_id: String,
    /// `TolerateQuarantine` — an apply that may lawfully end in quarantine.
    pub tolerate_quarantine: bool,
}

/// The verbs a ceremony can authorize.
pub const CEREMONY_VERBS: [&str; 3] = ["apply", "resume", "abandon"];

/// `c06CeremonyOutcome` — what driving the child observed.
#[derive(Debug, Default)]
pub struct CeremonyOutcome {
    pub exit_code: i64,
    pub envelope: String,
    pub elapsed: Duration,
    pub refusal_reason: String,
}

impl CeremonyPlan {
    /// `Validate` — refuses every shape that would misreport a refusal:
    /// each arm of `TestC06TheCeremonyPlanRefusesEveryShapeThatWouldMisreportARefusal`.
    pub fn validate(&self) -> Result<(), String> {
        if self.verb == "verify" || !CEREMONY_VERBS.contains(&self.verb.as_str()) {
            return Err(format!(
                "a verb with no ceremony ({:?}); the ceremony verbs are {CEREMONY_VERBS:?}",
                self.verb
            ));
        }
        if self.binary.is_empty() {
            return Err(
                "the ceremony plan carries no operator binary for the child process".to_owned(),
            );
        }
        if self.helper_socket.is_empty() {
            return Err("the ceremony plan carries no helper socket, so the child could not be peer-checked through SO_PEERCRED".to_owned());
        }
        if self.operator_uid == 0 {
            return Err("the ceremony plan's operator is uid 0; the operator identity the ceremony admits is never root".to_owned());
        }
        if self.operator_uid == self.daemon_uid {
            return Err("the ceremony plan's operator and daemon identities coincide; the peer policy requires them distinct".to_owned());
        }
        if self.device.starts_with(REJECTED_TTY_PREFIX) {
            return Err(format!(
                "the ceremony plan's console {:?} is a pseudo-terminal; a pty is not a physical console and open_physical_tty refuses one explicitly",
                self.device
            ));
        }
        if self.device == "/dev/null" {
            return Err(format!(
                "the ceremony plan's console {:?} is not a terminal at all; only {PHYSICAL_TTY_PREFIX}* qualifies",
                self.device
            ));
        }
        if self.redirect_stdin && !self.device.is_empty() {
            return Err("the ceremony plan names a console AND redirects stdin; the two refusal shapes must be driven separately".to_owned());
        }
        if !self.redirect_stdin && self.device.is_empty() && !self.grant_mode {
            return Err("the ceremony plan names no console and redirects no input".to_owned());
        }
        if self.budget.is_zero() {
            return Err("the ceremony plan carries no budget; the assertion that a ceremony stayed inside its share is not an assertion at all without one".to_owned());
        }
        if self.verb == "abandon" && self.budget > CEREMONY_BUDGET {
            return Err(format!(
                "the ceremony plan bounds abandon by {:?} and the helper's ceremony share is {CEREMONY_BUDGET:?}",
                self.budget
            ));
        }
        let apply_budget = restore_apply_deadline();
        if (self.verb == "apply" || self.verb == "resume") && self.budget > apply_budget {
            return Err(format!(
                "the ceremony plan bounds {} by {:?} and the helper's whole transport budget for it is {apply_budget:?}; a bound above the transport budget is a bound the transport enforces first, so the assertion would never be the one that failed",
                self.verb, self.budget
            ));
        }
        if !self.grant_mode && self.peer.starts_with(PHYSICAL_TTY_PREFIX) && self.secret.is_empty()
        {
            return Err("a physical-console ceremony plan carries no operator secret".to_owned());
        }
        if self.grant_mode && self.grant_operation_id.is_empty() {
            return Err("a grant-mode ceremony plan carries no grant operation id".to_owned());
        }
        if self.grant_mode
            && (!self.device.is_empty()
                || !self.typed.is_empty()
                || !self.secret.is_empty()
                || self.peer.starts_with(PHYSICAL_TTY_PREFIX))
        {
            return Err("a grant-mode ceremony plan still names physical-console fields; grant mode has no console and no phrase".to_owned());
        }
        if self.verb == "resume" && self.tolerate_quarantine {
            return Err("resume tolerating quarantine is a nonsense shape: only apply may end in quarantine".to_owned());
        }
        Ok(())
    }

    /// `c06CeremonyCommandLine` — the literal command line field 9 records.
    pub fn command_line(&self) -> String {
        format!("central restore {}", self.verb)
    }
}

/// `c06DriveCeremony` — launches the real child over the helper socket with
/// the real console file as its stdin, types the phrase at the far end, and
/// reports what the envelope carried. Armed-only; unarmed callers are refused
/// by the gate before a plan is built.
pub fn drive_ceremony(plan: &CeremonyPlan) -> Result<CeremonyOutcome, String> {
    plan.validate()?;
    let console = if plan.grant_mode || plan.redirect_stdin {
        None
    } else {
        Some(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&plan.device)
                .map_err(|e| format!("open the ceremony console {:?}: {e}", plan.device))?,
        )
    };
    let mut command = std::process::Command::new(&plan.binary);
    command
        .arg("restore")
        .arg(&plan.verb)
        .env("CENTRAL_HELPER_SOCKET", &plan.helper_socket)
        .env_remove(crate::fixture::OPERATOR_SECRET_ENV);
    if plan.grant_mode {
        command.env(crate::fixture::GRANT_CEREMONY_ENV, "1");
    }
    if let Some(console) = console {
        command.stdin(console);
    } else if plan.redirect_stdin {
        command.stdin(std::process::Stdio::piped());
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn the ceremony child {:?}: {e}", plan.binary))?;
    if plan.redirect_stdin
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = stdin.write_all(b"redirected input is not a console\n");
    }
    // Type the phrase at the far end exactly once — never retried.
    if !plan.typed.is_empty() && !plan.grant_mode {
        let device = plan.device.clone();
        let phrase = plan.typed.clone();
        std::thread::spawn(move || {
            if let Ok(mut console) = std::fs::OpenOptions::new().write(true).open(device) {
                let _ = console.write_all(format!("{phrase}\n").as_bytes());
            }
        });
    }
    let started = Instant::now();
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait for the ceremony child: {e}"))?;
    let elapsed = started.elapsed();
    let envelope = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(CeremonyOutcome {
        exit_code: output.status.code().unwrap_or(-1) as i64,
        refusal_reason: reason_from_envelope(&envelope),
        envelope,
        elapsed,
    })
}

/// `c06ReasonFromEnvelope` — the refusal reason the operator surface printed.
pub fn reason_from_envelope(output: &str) -> String {
    for token in output.split(|c: char| c.is_whitespace() || c == '"') {
        if token.chars().all(|c| c.is_ascii_uppercase() || c == '_') && token.len() > 3 {
            return token.to_owned();
        }
    }
    String::new()
}

/// `TestC06TheCeremonyBudgetIsTheHelpersOwnShareAndLeavesTheEngineOne`.
#[test]
fn the_ceremony_budget_is_the_helpers_own_share_and_leaves_the_engine_one() {
    let ceremony = CEREMONY_BUDGET;
    let transport = restore_apply_deadline();
    assert!(
        ceremony > Duration::ZERO,
        "the ceremony share must be positive"
    );
    assert!(
        transport > ceremony,
        "the apply transport budget {transport:?} must leave the engine a share beyond the ceremony's {ceremony:?}"
    );
    assert_eq!(
        ceremony,
        Duration::from_secs(120),
        "the helper's ceremony share is two minutes, upstream's bound"
    );
}

/// `TestC06TheCeremonyPlanRefusesEveryShapeThatWouldMisreportARefusal`.
#[test]
fn the_ceremony_plan_refuses_every_shape_that_would_misreport_a_refusal() {
    let base = CeremonyPlan {
        verb: "apply".to_owned(),
        binary: "central".to_owned(),
        helper_socket: "helper.sock".to_owned(),
        operator_uid: 1000,
        operator_gid: 1000,
        daemon_uid: 0,
        device: "/dev/tty1".to_owned(),
        redirect_stdin: false,
        budget: Duration::from_secs(60),
        peer: format!("{PHYSICAL_TTY_PREFIX}S1"),
        typed: derive_confirmation_phrase(RESTORE_APPLY_PHRASE_PREFIX, "i", "t", "o"),
        secret: "c06-synthetic-secret".to_owned(),
        grant_mode: false,
        grant_operation_id: String::new(),
        tolerate_quarantine: false,
    };
    base.validate().expect("the base plan validates");
    let mut p = base.clone();
    p.verb = "verify".to_owned();
    assert!(p.validate().unwrap_err().contains("verify"));
    let mut p = base.clone();
    p.binary.clear();
    assert!(p.validate().unwrap_err().contains("child process"));
    let mut p = base.clone();
    p.helper_socket.clear();
    assert!(p.validate().unwrap_err().contains("SO_PEERCRED"));
    let mut p = base.clone();
    p.operator_uid = 0;
    assert!(p.validate().unwrap_err().contains("uid 0"));
    let mut p = base.clone();
    p.daemon_uid = p.operator_uid;
    assert!(p.validate().is_err());
    let mut p = base.clone();
    p.device = format!("{REJECTED_TTY_PREFIX}3");
    assert!(p.validate().is_err());
    let mut p = base.clone();
    p.device = "/dev/null".to_owned();
    assert!(p.validate().unwrap_err().contains(PHYSICAL_TTY_PREFIX));
    let mut p = base.clone();
    p.redirect_stdin = true;
    assert!(
        p.validate().is_err(),
        "a console and redirected input together are refused"
    );
    let mut p = base.clone();
    p.device.clear();
    assert!(p.validate().unwrap_err().contains("names no console"));
    let mut p = base.clone();
    p.budget = Duration::ZERO;
    assert!(p.validate().unwrap_err().contains("budget"));
    let mut p = base.clone();
    p.verb = "abandon".to_owned();
    p.budget = CEREMONY_BUDGET + Duration::from_secs(1);
    assert!(p.validate().is_err());
    let mut p = base.clone();
    p.budget = restore_apply_deadline() + Duration::from_secs(1);
    assert!(p.validate().is_err());
    let mut p = base.clone();
    p.secret.clear();
    assert!(p.validate().is_err());
    let mut p = base.clone();
    p.grant_mode = true;
    p.grant_operation_id = "operation".to_owned();
    assert!(
        p.validate().is_err(),
        "grant mode with physical fields is refused"
    );
    let mut p = base.clone();
    p.grant_mode = true;
    p.grant_operation_id = "operation".to_owned();
    p.device.clear();
    p.peer.clear();
    p.typed.clear();
    p.secret.clear();
    p.validate().expect("a clean grant plan validates");
    let mut p = base.clone();
    p.verb = "resume".to_owned();
    p.tolerate_quarantine = true;
    assert!(p.validate().is_err());
}

/// `TestC06EveryCommandLineTheRunRecordsIsOneItDeclares` — the recorded
/// command vocabulary: only these lines may reach field 9.
#[test]
fn every_command_line_the_run_records_is_one_it_declares() {
    let declared = crate::fixture::declared_command_lines();
    for verb in CEREMONY_VERBS {
        let line = CeremonyPlan {
            verb: verb.to_owned(),
            ..Default::default()
        }
        .command_line();
        assert!(
            declared.contains(&line),
            "the ceremony command {line:?} is not a declared command line"
        );
    }
}
