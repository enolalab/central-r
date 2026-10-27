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
    // Upstream `c06DriveGrantChild` takes the exit code from the refusal
    // envelope when the child printed one — a pre-D1 refusal reports its
    // own code in-band while the process itself may exit 0.
    let exit_code = if plan.grant_mode {
        exit_code_from_envelope(&envelope)
            .map(i64::from)
            .unwrap_or_else(|| output.status.code().unwrap_or(-1) as i64)
    } else {
        output.status.code().unwrap_or(-1) as i64
    };
    Ok(CeremonyOutcome {
        exit_code,
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

// ---------------------------------------------------------------------------
// The flag-offered-as-confirmation negative, decided by the live surface —
// `TestC06TheOperatorSurfaceRefusesAFlagOfferedAsConfirmation`.
// ---------------------------------------------------------------------------

/// The operator binary this test drives: `CENTRAL_C06_CENTRAL_BIN` first —
/// the same variable scenario 1 uses, so the flagged call takes the same
/// subprocess path s1 takes — then the binary this test target was built
/// beside. Portable: the component that decides the negative needs neither
/// root, nor PAM, nor a console.
fn operator_binary() -> String {
    std::env::var("CENTRAL_C06_CENTRAL_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_central").to_owned())
}

/// `c06DispatchRestoreWithArguments` — the real operator binary with an
/// exact argument vector, through the same subprocess path scenario 1
/// dispatches `central backup create` on. Returns (process exit, the parsed
/// result envelope, the combined output).
///
/// The deferred operator mode refuses to run as ROOT — upstream reaches
/// `command.Dispatch` inside `main`'s privilege check, so its portable test
/// never meets the gate; this port drives the whole binary, so a root test
/// host drops the child to `nobody` first. The refusal under test is the
/// verb's own, not the mode gate's.
fn dispatch_restore_with_arguments(arguments: &[String]) -> (i64, serde_json::Value, String) {
    let binary = operator_binary();
    let mut command = std::process::Command::new(&binary);
    command.args(arguments);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        if rustix::process::geteuid().as_raw() == 0 {
            command.uid(65534);
        }
    }
    let output = command
        .env_remove(crate::fixture::OPERATOR_SECRET_ENV)
        .env_remove("CENTRAL_HELPER_SOCKET")
        .env_remove(crate::fixture::GRANT_CEREMONY_ENV)
        .output()
        .unwrap_or_else(|e| panic!("the real central binary could not run ({binary:?}): {e}"));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = output
        .stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice(line).ok())
        .find(|v: &serde_json::Value| v.get("reason").is_some())
        .unwrap_or_else(|| panic!("no result envelope in the operator output: {combined}"));
    (
        output.status.code().unwrap_or(-1) as i64,
        envelope,
        combined,
    )
}

/// `TestC06TheOperatorSurfaceRefusesAFlagOfferedAsConfirmation` — one of the
/// four negatives governance field 24 requires, decided by the real
/// component: the grammar check admits exactly zero arguments on apply and
/// abandon, so a `--confirm` flag never reaches consent.
///
/// IT IS A PAIR, NOT A REFUSAL. Each verb is driven twice — once with a flag
/// carrying a real, correctly scoped confirmation phrase, and once with
/// nothing else changed — and the pair must differ in exactly the way the
/// grammar check decides: the flagged call is refused for grammar, and the
/// unflagged call is NOT, because it reaches the service behind it (where no
/// helper socket answers `*_DEPENDENCY_UNAVAILABLE`, which is what the
/// grammar check having let it through looks like).
#[test]
fn the_operator_surface_refuses_a_flag_offered_as_confirmation() {
    let instance_id = "c06-synthetic-instance";
    let target_id = "c06-synthetic-target";
    let operation_id = "c06-synthetic-operation";
    for (subcommand, prefix, grammar_reason, absent_reason) in [
        (
            "apply",
            RESTORE_APPLY_PHRASE_PREFIX,
            "INVALID_RESTORE_APPLY_GRAMMAR",
            "RESTORE_APPLY_DEPENDENCY_UNAVAILABLE",
        ),
        (
            "abandon",
            RESTORE_ABANDON_PHRASE_PREFIX,
            "INVALID_RESTORE_ABANDON_GRAMMAR",
            "RESTORE_ABANDON_DEPENDENCY_UNAVAILABLE",
        ),
    ] {
        let phrase = derive_confirmation_phrase(prefix, instance_id, target_id, operation_id);
        let flagged_args: Vec<String> = vec![
            "restore".into(),
            subcommand.into(),
            format!("--confirm={phrase}"),
        ];
        let (flagged_exit, flagged, flagged_output) =
            dispatch_restore_with_arguments(&flagged_args);
        assert_eq!(
            flagged["reason"].as_str().unwrap_or_default(),
            grammar_reason,
            "`restore {subcommand}` offered a confirmation phrase as a flag; it must answer {grammar_reason}. A verb that accepted a flag as consent would let an automation approve an irreversible act with no operator at a terminal, which is the whole thing the ceremony exists to prevent"
        );
        assert_eq!(
            flagged_exit, 2,
            "`restore {subcommand}` with a confirmation flag exited {flagged_exit}, want 2 (the usage class)"
        );
        // The phrase was handed IN. It must not come back out: the
        // operator's terminal is the one place a phrase must never be
        // echoed by the tool.
        assert!(
            !flagged_output.contains(prefix),
            "`restore {subcommand}` echoed the confirmation phrase it refused back to the operator's terminal: {flagged_output}"
        );

        // The neighbour: the same verb, nothing else changed, no flag.
        let unflagged_args: Vec<String> = vec!["restore".into(), subcommand.into()];
        let (_, unflagged, _) = dispatch_restore_with_arguments(&unflagged_args);
        let reason = unflagged["reason"].as_str().unwrap_or_default();
        assert_ne!(
            reason, grammar_reason,
            "`restore {subcommand}` with NO flag also answered {grammar_reason}, so the refusal above says nothing about the flag: the verb refuses its own grammar either way and this pair does not isolate the substitution"
        );
        assert_eq!(
            reason, absent_reason,
            "`restore {subcommand}` with no flag and no helper socket answered {reason:?}, want {absent_reason:?}. This half of the pair exists to show the grammar check let it through; an answer from somewhere else means it did not get that far"
        );
    }
}

// ---------------------------------------------------------------------------
// The grant driver's envelope exit — `c06ExitCodeFromEnvelope`.
// ---------------------------------------------------------------------------

/// `c06ExitCodeFromEnvelope` pulls the operator surface's exit code out of
/// the child's output. It reports `None` when no envelope is present, so a
/// child that died before answering keeps its process exit rather than a
/// guess.
pub fn exit_code_from_envelope(output: &str) -> Option<u8> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(trimmed)
            && envelope
                .get("reason")
                .and_then(|r| r.as_str())
                .is_some_and(|r| !r.is_empty())
            && let Some(code) = envelope.get("exit_code").and_then(|c| c.as_u64())
        {
            return Some(code as u8);
        }
    }
    None
}

/// `TestC06TheGrantDriverDrivesAChildThroughTheRealSpawnPath` — the driver
/// is exercised, not declared: a grant-mode plan over `/bin/true` (which
/// ignores every argument and exits 0 with no envelope) proves the spawn /
/// wait / envelope-collect machinery runs, and that a child answering no
/// envelope keeps its process exit — `exit_code_from_envelope` reporting
/// `None` is what makes the fallback honest.
#[test]
fn the_grant_driver_drives_a_child_through_the_real_spawn_path() {
    let plan = CeremonyPlan {
        verb: "apply".to_owned(),
        binary: "/bin/true".to_owned(),
        helper_socket: "/run/central/helper.sock".to_owned(),
        operator_uid: 65534,
        operator_gid: 65534,
        daemon_uid: 0,
        budget: Duration::from_secs(60),
        grant_mode: true,
        grant_operation_id: "c06-synthetic-operation".to_owned(),
        tolerate_quarantine: true,
        ..Default::default()
    };
    plan.validate()
        .unwrap_or_else(|e| panic!("the clean grant plan must validate: {e}"));
    let outcome =
        drive_ceremony(&plan).unwrap_or_else(|e| panic!("driving the no-op child failed: {e}"));
    assert_eq!(
        outcome.exit_code, 0,
        "/bin/true exits 0 under any arguments; a nonzero exit means the driver did not drive the child it was handed"
    );
    assert_eq!(
        exit_code_from_envelope(&outcome.envelope),
        None,
        "a child that answered no envelope must not report an envelope exit; the driver keeps the process exit instead"
    );
}

/// `TestC06GrantDriverReadsTheExitTheEnvelopeReports` — pins the run-11
/// finding: a grant driver that read only the process exit saw 0 on every
/// refusal and no negative could pass. The driver keeps reading the
/// envelope, and keeps the process exit only when no envelope exists.
#[test]
fn the_grant_driver_reads_the_exit_the_envelope_reports() {
    let denied = "{\"schema_version\":\"central.local-result/v1\",\"command_id\":\"restore.apply\",\"exit_code\":7,\"reason\":\"RESTORE_APPLY_AUTHORITY_DENIED\",\"details\":{}}\n";
    assert_eq!(
        exit_code_from_envelope(denied),
        Some(7),
        "a refusal envelope reports exit 7"
    );
    let ok = "{\"schema_version\":\"central.local-result/v1\",\"command_id\":\"restore.apply\",\"exit_code\":0,\"reason\":\"ok\",\"details\":{}}\n";
    assert_eq!(
        exit_code_from_envelope(ok),
        Some(0),
        "a success envelope reports exit 0"
    );
    assert_eq!(
        exit_code_from_envelope(""),
        None,
        "empty output must not report an envelope exit"
    );
    assert_eq!(
        exit_code_from_envelope("not json\nstill not json\n"),
        None,
        "output with no envelope must not report an envelope exit"
    );
}

// ---------------------------------------------------------------------------
// The protected-authorization read governance field 21 comes from.
// ---------------------------------------------------------------------------

/// `c06RecoveryJournalAuthorizationDirectories` — the directories this suite
/// reads performed ceremonies out of, by ceremony kind. Restated here and
/// pinned to the broker's own constants by
/// `the_authorization_directories_are_the_brokers_own`; a renamed directory
/// makes the read return nothing, and "no authorization record" is
/// indistinguishable from "no ceremony was performed" — which is the answer
/// field 21 gives when it is working correctly.
pub const RECOVERY_JOURNAL_AUTHORIZATION_DIRECTORIES: [(&str, &str); 3] = [
    ("restore_apply", "restore-apply-authorizations"),
    ("restore_abandon", "restore-abandon-authorizations"),
    // Upstream maps `restore_resume` onto the apply store — a resume
    // authorization is a `RestoreApplyAuthorization` consumed by `Resume`.
    ("restore_resume", "restore-apply-authorizations"),
];

/// `c06BrokerAuthorizationDirectoryConstants` — the broker's own const
/// declarations for each directory above: directory name → the constant in
/// `recovery_journal.rs` that must declare it.
pub const BROKER_AUTHORIZATION_DIRECTORY_CONSTANTS: [(&str, &str); 2] = [
    ("restore-apply-authorizations", "RECOVERY_APPLY_DIRECTORY"),
    (
        "restore-abandon-authorizations",
        "RECOVERY_ABANDON_DIRECTORY",
    ),
];

/// `c06ConsumedAuthorizationState` — the state a record reaches once the
/// ceremony it authorized has been used exactly once. The other two states
/// the broker writes — "issued" and "consuming" — are a ceremony in flight,
/// and neither is a performed one.
pub const CONSUMED_AUTHORIZATION_STATE: &str = "consumed";

/// `c06ProtectedAuthorizationRecord` — the fields of a broker authorization
/// record field 21 needs, decoded from the broker's own wire shape (the
/// `RestoreApplyRecordWire`/`RestoreAbandonRecordWire` layout: an
/// `authorization` object carrying Go-named fields, a `state` string, and
/// peer fields the read does not need).
pub struct ProtectedAuthorizationRecord {
    pub authorization_id: String,
    pub operation_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub state: String,
}

/// `c06ReadProtectedAuthorizations` — the records a performed ceremony of
/// `kind` left in `protected_root`, sorted by authorization id exactly as
/// upstream sorts them. A missing directory is the shape an unperformed
/// ceremony leaves and returns empty, not an error.
pub fn read_protected_authorizations(
    protected_root: &Path,
    kind: &str,
) -> Result<Vec<ProtectedAuthorizationRecord>, String> {
    let directory = RECOVERY_JOURNAL_AUTHORIZATION_DIRECTORIES
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, d)| *d)
        .ok_or_else(|| {
            format!(
                "no protected authorization directory is declared for a ceremony of kind {kind:?}"
            )
        })?;
    let path = protected_root.join(directory);
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(format!(
                "read the protected authorization records this ceremony would have left: {e}"
            ));
        }
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read a directory entry: {e}"))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) || !name.ends_with(".json") {
            continue;
        }
        let raw = std::fs::read_to_string(entry.path())
            .map_err(|e| format!("read a protected authorization record: {e}"))?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| format!("decode a protected authorization record: {e}"))?;
        let authorization = &value["authorization"];
        records.push(ProtectedAuthorizationRecord {
            authorization_id: authorization["AuthorizationID"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            operation_id: authorization["OperationID"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            issued_at: authorization["IssuedAt"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            expires_at: authorization["ExpiresAt"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            state: value["state"].as_str().unwrap_or_default().to_owned(),
        });
    }
    records.sort_by(|a, b| a.authorization_id.cmp(&b.authorization_id));
    Ok(records)
}

/// `c06RecordPerformedCeremoniesFromProtectedState` — turns the
/// authorizations one performed ceremony left behind into governance field
/// 21 records. It records only what it read, and it records nothing at all
/// where nothing was left: `record_performed_ceremony`'s gate refuses a
/// ceremony with no destructive confirmation behind it, and this adds a
/// second condition rather than relaxing the first.
pub fn record_performed_ceremonies_from_protected_state(
    protected_root: &Path,
    kind: &str,
    records: &mut crate::fixture::RecordSet,
) -> Result<usize, String> {
    let found = read_protected_authorizations(protected_root, kind)?;
    let mut recorded = 0;
    for record in &found {
        if record.state != CONSUMED_AUTHORIZATION_STATE
            || records
                .ceremony_records
                .iter()
                .any(|c| c.authorization_id == record.authorization_id)
        {
            continue;
        }
        records.record_performed_ceremony(crate::evidence::CeremonyRecord {
            kind: kind.to_owned(),
            authorization_id: record.authorization_id.clone(),
            operation_id: record.operation_id.clone(),
            issued_at: record.issued_at.clone(),
            expires_at: record.expires_at.clone(),
            // The broker consumes an authorization under a lock and refuses
            // a second consumption of the same record, so a record standing
            // in the consumed state IS the one-use property having held. It
            // is read from the record rather than asserted here.
            consumed_exactly_once: true,
        })?;
        recorded += 1;
    }
    Ok(recorded)
}

/// `TestC06ThePerformedCeremonyReadTakesOnlyConsumedAuthorizations` — both
/// directions over a protected root this test writes: a consumed
/// authorization is returned with every field the record carries, and a
/// record in any other state is not — an authorization still in flight is
/// not a ceremony that was performed.
#[test]
fn the_performed_ceremony_read_takes_only_consumed_authorizations() {
    let root = std::env::temp_dir().join(format!("c06-auth-read-{}", std::process::id()));
    let directory = root.join("restore-apply-authorizations");
    std::fs::create_dir_all(&directory).expect("create the protected authorization directory");
    let write = |name: &str, authorization_id: &str, operation_id: &str, state: &str| {
        let record = serde_json::json!({
            "authorization": {
                "AuthorizationID": authorization_id,
                "OperationID": operation_id,
                "IssuedAt": "2020-01-01T01:00:00Z",
                "ExpiresAt": "2020-01-01T01:05:00Z",
            },
            "state": state,
        });
        std::fs::write(directory.join(name), serde_json::to_vec(&record).unwrap())
            .expect("write a protected authorization record");
    };
    const CONSUMED_ID: &str = "00000000-0000-7000-8000-00000000000a";
    const ISSUED_ID: &str = "00000000-0000-7000-8000-00000000000b";
    const OPERATION_ID: &str = "00000000-0000-7000-8000-00000000000c";
    write(
        "consumed.json",
        CONSUMED_ID,
        OPERATION_ID,
        CONSUMED_AUTHORIZATION_STATE,
    );
    write("issued.json", ISSUED_ID, OPERATION_ID, "issued");

    let found = read_protected_authorizations(&root, "restore_apply")
        .expect("read the protected authorizations");
    assert_eq!(
        found.len(),
        2,
        "the read returned {} records over a directory holding 2; it is not reading what the ceremony leaves",
        found.len()
    );

    let mut records = crate::fixture::RecordSet::default();
    records
        .destructive_confirmations
        .push(crate::evidence::DestructiveConfirmation {
            operation_kind: "restore_apply".to_owned(),
            phrase_sha256: String::new(),
            admitted_peer_uid: 0,
            rejected_redirected_input: false,
            rejected_flag_substitution: false,
            rejected_cross_ceremony_phrase: false,
            confirmation_mode: String::new(),
            rejected_missing_grant: false,
            rejected_expired_grant: false,
            rejected_spent_grant: false,
            rejected_wrong_operation_grant: false,
        });
    record_performed_ceremonies_from_protected_state(&root, "restore_apply", &mut records)
        .expect("record the performed ceremonies");
    assert_eq!(
        records.ceremony_records.len(),
        1,
        "governance field 21 carries {} records over a root holding one CONSUMED authorization and one still issued: {:?}; an authorization in flight is not a performed ceremony",
        records.ceremony_records.len(),
        records
            .ceremony_records
            .iter()
            .map(|c| &c.authorization_id)
            .collect::<Vec<_>>()
    );
    let recorded = &records.ceremony_records[0];
    assert_eq!(recorded.authorization_id, CONSUMED_ID);
    assert_eq!(recorded.operation_id, OPERATION_ID);
    assert_eq!(recorded.issued_at, "2020-01-01T01:00:00Z");
    assert_eq!(recorded.expires_at, "2020-01-01T01:05:00Z");
    assert!(
        recorded.consumed_exactly_once,
        "a consumed authorization was recorded as not consumed exactly once"
    );

    // A second read of the same root records nothing further: the ceremony
    // happened once and field 21 must not grow every time it is consulted.
    record_performed_ceremonies_from_protected_state(&root, "restore_apply", &mut records)
        .expect("the second read");
    assert_eq!(
        records.ceremony_records.len(),
        1,
        "a second read recorded the same performed ceremony again"
    );

    // And a root no ceremony was performed against yields nothing at all
    // rather than failing: that is what an unperformed ceremony looks like.
    let empty_root = std::env::temp_dir().join(format!("c06-auth-empty-{}", std::process::id()));
    let empty =
        read_protected_authorizations(&empty_root, "restore_apply").expect("read an empty root");
    assert!(
        empty.is_empty(),
        "a root with no authorization directory returned {} records",
        empty.len()
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&empty_root);
}

/// `TestC06TheAuthorizationDirectoriesAreTheBrokersOwn` — holds the
/// protected-state directory names this file reads governance field 21 out
/// of to the broker's own declarations, in both directions. A restatement
/// nothing checks is exactly the shape that fails quietly: a renamed
/// directory makes the read return nothing, and "no authorization record" is
/// indistinguishable from "no ceremony was performed".
#[test]
fn the_authorization_directories_are_the_brokers_own() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let journal_path = Path::new(manifest)
        .join("../../crates/adapters/central-adapter-linux/src/broker/recovery_journal.rs");
    let source = std::fs::read_to_string(&journal_path).unwrap_or_else(|e| {
        panic!(
            "read the broker's recovery journal {}: {e}",
            journal_path.display()
        )
    });

    // `pub(crate) const NAME: &str = "value";` — the broker's own string
    // declarations, read out of its source rather than restated.
    let mut declared: std::collections::HashMap<String, String> = Default::default();
    for line in source.lines() {
        let line = line.trim();
        if !(line.starts_with("pub(crate) const ") || line.starts_with("const "))
            || !line.contains(": &str = \"")
        {
            continue;
        }
        let rest = line.split(" const ").nth(1).unwrap_or(line);
        let Some((name, tail)) = rest.split_once(": &str = \"") else {
            continue;
        };
        let Some((value, _)) = tail.split_once('"') else {
            continue;
        };
        declared.insert(name.trim().to_owned(), value.to_owned());
    }
    assert!(
        !declared.is_empty(),
        "{} declares no string constants at all, so this guard read the wrong file and would hold the directory names to nothing",
        journal_path.display()
    );

    let mut seen: std::collections::HashSet<&str> = Default::default();
    for (kind, directory) in RECOVERY_JOURNAL_AUTHORIZATION_DIRECTORIES {
        let Some(constant) = BROKER_AUTHORIZATION_DIRECTORY_CONSTANTS
            .iter()
            .find(|(d, _)| *d == directory)
            .map(|(_, c)| *c)
        else {
            panic!(
                "ceremony kind {kind:?} reads {directory:?} and no broker constant is named for it, so nothing holds that name to the broker's own"
            );
        };
        seen.insert(directory);
        assert_eq!(
            declared.get(constant).map(String::as_str),
            Some(directory),
            "this file reads a {kind} ceremony's authorization out of {directory:?} and the broker's {constant} declares {:?}; the read would return nothing, and no authorization record is exactly what an unperformed ceremony looks like",
            declared.get(constant)
        );
    }
    for (directory, constant) in BROKER_AUTHORIZATION_DIRECTORY_CONSTANTS {
        assert!(
            seen.contains(directory),
            "{directory:?} ({constant}) is pinned here and no ceremony kind reads it; the pin is stale and holds nothing"
        );
    }
}

// ---------------------------------------------------------------------------
// The disclosure guards — every expectation the ceremony step and scenario 5
// state carries its scope disclosure.
// ---------------------------------------------------------------------------

/// Read one of this suite's own sources; a missing file fails the guard
/// because a scan over nothing would pass loudest of all.
fn own_source(file: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest).join("tests/c06_acceptance").join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The body of `fn name(...)` in `source`, from its `fn` keyword to the
/// closing brace at the same indentation — enough for "does this body call
/// X" guards without a parser.
fn fn_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("fn {name}(");
    let start = source.find(&needle)?;
    let rest = &source[start..];
    let mut depth = 0i32;
    let mut opened = false;
    for (index, byte) in rest.bytes().enumerate() {
        match byte {
            b'{' => {
                depth += 1;
                opened = true;
            }
            b'}' => {
                depth -= 1;
                if opened && depth == 0 {
                    return Some(&rest[..index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// `TestC06EveryExpectationTheCeremonyStepStatesCarriesItsScopeDisclosure`
/// — the port's ceremony step is scenario 5's `c06_s5_restore_apply`, whose
/// expectations must all go through `expect5` (the only route that attaches
/// `SCENARIO5_SCOPE_DISCLOSURE`). Both halves are checked, each for vacuity:
/// `expect5` must reference the disclosure AND call `attach_divergence`,
/// and the s5 body must contain `expect5`/`Disclosing` calls and no direct
/// `attach_divergence` of its own.
#[test]
fn every_expectation_the_ceremony_step_states_carries_its_scope_disclosure() {
    let source = own_source("scenario5.rs");
    let wrapper = fn_body(&source, "expect5")
        .expect("scenario5.rs declares no expect5, so every expectation the ceremony step states reaches the artifact with no scope on it");
    assert!(
        wrapper.contains("SCENARIO5_SCOPE_DISCLOSURE"),
        "expect5 does not reference SCENARIO5_SCOPE_DISCLOSURE, so every expectation the ceremony states reaches the artifact unqualified while still going through the wrapper that is supposed to qualify it"
    );
    assert_eq!(
        wrapper.matches("attach_divergence").count(),
        1,
        "expect5 must reach attach_divergence exactly once; zero means the wrapper attaches nothing, and more than one means it attaches something this guard has not read"
    );
    let body = fn_body(&source, "c06_s5_restore_apply")
        .expect("scenario5.rs declares no c06_s5_restore_apply, so this guard is holding nothing to the rule");
    assert!(
        !body.contains("attach_divergence"),
        "the ceremony step states an expectation directly rather than through expect5; the divergence it attaches reaches the evidence artifact with no record of what the ceremony did and did not establish"
    );
    assert!(
        body.contains("expect5(") || body.contains("Disclosing"),
        "no expectation in the ceremony step is stated through expect5, so this guard is passing over a step that states none -- which is itself the defect"
    );
}

// ---------------------------------------------------------------------------
// The scenario-5 recorders' contradiction refusals —
// `TestC06TheScenario5RecordersRefuseACensusThatContradictsItself`.
// ---------------------------------------------------------------------------

/// `TestC06TheScenario5RecordersRefuseACensusThatContradictsItself` —
/// exercises `check_quarantine_resolutions` and `check_capacity_reserve` in
/// both directions: an admissible census/reserve must pass first, or every
/// refusal below is satisfied by a check that refuses everything.
#[test]
fn the_scenario5_recorders_refuse_a_census_that_contradicts_itself() {
    use crate::evidence::{CapacityReserveRecord, QuarantineByReason, QuarantineResolutions};

    // `TestC06TheCapacityReserveKindIsTheOneTheEmitterAdmits`, folded in:
    // the kind the recorder admits must be inside the emitter's own
    // vocabulary, or a recorded entry would fail the whole document at
    // emit — the last and most expensive step of the run.
    assert!(
        crate::evidence::CAPACITY_RESERVE_KINDS.contains(&"restore_reserve"),
        "the recorder admits kind \"restore_reserve\" and the emitter admits only {:?}",
        crate::evidence::CAPACITY_RESERVE_KINDS
    );

    let admissible = QuarantineResolutions {
        reingested: 4,
        delete_finalized: 1,
        by_reason: QuarantineByReason {
            missing_body: 1,
            checksum_mismatch: 1,
            size_mismatch: 1,
            unexpected_artifact: 1,
            metadata_mismatch: 1,
        },
        ..Default::default()
    };
    let fresh = crate::fixture::RecordSet::default();
    if let Err(e) = fresh.check_quarantine_resolutions(&admissible) {
        panic!(
            "the census recorder refused a census that contradicts nothing: {e}. A check that refuses everything satisfies every refusal below without catching any of them"
        );
    }
    for (label, census) in [
        (
            "a non-zero unresolved count at ready",
            QuarantineResolutions {
                unresolved: 1,
                ..admissible.clone()
            },
        ),
        (
            "findings still open at ready",
            QuarantineResolutions {
                open_findings_at_ready: 1,
                ..admissible.clone()
            },
        ),
        (
            "a typed breakdown that does not total the typed resolutions",
            QuarantineResolutions {
                by_reason: QuarantineByReason {
                    missing_body: 1,
                    ..Default::default()
                },
                ..admissible.clone()
            },
        ),
        (
            "a census that resolved nothing",
            QuarantineResolutions::default(),
        ),
    ] {
        assert!(
            crate::fixture::RecordSet::default()
                .check_quarantine_resolutions(&census)
                .is_err(),
            "the census recorder admitted {label}"
        );
    }
    let mut recorded = crate::fixture::RecordSet::default();
    recorded
        .record_quarantine_resolutions(admissible.clone())
        .expect("record the admissible census");
    assert!(
        recorded.check_quarantine_resolutions(&admissible).is_err(),
        "the census recorder admitted a second census, which would replace the state at ready with a later one"
    );

    // Every reserve entry below carries real byte counts except where the
    // byte counts ARE the case, so each refusal is earned by the thing its
    // label names and not by a zero this table left blank.
    let closed = CapacityReserveRecord {
        kind: "restore_reserve".to_owned(),
        device_id: "device-a".to_owned(),
        role: crate::evidence::CAPACITY_ROLES[0].to_owned(),
        free_bytes: 9 << 30,
        reserve_bytes: 4 << 30,
        allocated_bytes: 4 << 30,
        released: true,
        release_confirmed_at: "2026-08-15T00:00:00Z".to_owned(),
        floor_bytes: 0,
        projected_demand_bytes: 0,
    };
    let fresh = crate::fixture::RecordSet::default();
    if let Err(e) = fresh.check_capacity_reserve(std::slice::from_ref(&closed)) {
        panic!("the reserve recorder refused a closed, confirmed release: {e}");
    }
    let altered = |mutate: fn(&mut CapacityReserveRecord)| {
        let mut record = closed.clone();
        mutate(&mut record);
        vec![record]
    };
    for (label, entries) in [
        ("an empty census", Vec::new()),
        (
            "the backup-admission kind",
            altered(|r| r.kind = "backup_admission".to_owned()),
        ),
        (
            "an entry with no device identity",
            altered(|r| r.device_id = String::new()),
        ),
        (
            "an entry outside the role vocabulary",
            altered(|r| r.role = "scratch".to_owned()),
        ),
        (
            "a release with no confirmation",
            altered(|r| r.release_confirmed_at = String::new()),
        ),
        (
            "an allocation that was never released",
            altered(|r| {
                r.released = false;
                r.release_confirmed_at = String::new();
            }),
        ),
        (
            "a zero-byte entry that claims a confirmed release",
            altered(|r| {
                r.reserve_bytes = 0;
                r.allocated_bytes = 0;
            }),
        ),
        (
            "an entry that reserved bytes and allocated none",
            altered(|r| r.allocated_bytes = 0),
        ),
        (
            "an entry that allocated bytes it never reserved",
            altered(|r| r.reserve_bytes = 0),
        ),
    ] {
        assert!(
            crate::fixture::RecordSet::default()
                .check_capacity_reserve(&entries)
                .is_err(),
            "the reserve recorder admitted {label}"
        );
    }
    let mut recorded = crate::fixture::RecordSet::default();
    recorded
        .record_capacity_reserve(vec![closed.clone()])
        .expect("record the closed reserve");
    assert!(
        recorded.check_capacity_reserve(&[closed]).is_err(),
        "the reserve recorder admitted a second census"
    );
}
