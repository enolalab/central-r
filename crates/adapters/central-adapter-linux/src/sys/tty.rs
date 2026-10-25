//! `tty` — the physical-console boundary the PAM/TTY ceremonies are
//! built on (R5 task 5), ported from upstream
//! `internal/adapter/authority/helper/{tty_ceremony_read_linux,
//! pam_linux,confirmation_phrase,init_ceremony_prompt}.go`.
//!
//! What lives here:
//!
//! - [`open_physical_tty`] — the D-1 seat check: the peer's fd 0 must
//!   resolve under `/dev/tty*` and not under `/dev/pts/`, the console
//!   is opened `O_RDWR|O_NONBLOCK|O_CLOEXEC` (`O_NONBLOCK` is
//!   load-bearing — a serial line with `CLOCAL` clear and no carrier
//!   parks the open in `tty_port_block_til_ready` forever), then the
//!   `TIOCEXCL` exclusive lock is taken. The predicate refusal is a
//!   boundary denial (`sys_tty_not_console`); a console that cannot be
//!   opened or locked is `sys_tty_console_unfit`.
//! - [`read_ceremony_line`] / [`read_ceremony_secret`] — the only
//!   bounded reads a ceremony performs. The bound is a `poll(2)`
//!   deadline — the Rust analogue of Go's `SetReadDeadline` — plus an
//!   optional cancellation descriptor, which is what upstream's
//!   `ctx.Done()` watcher becomes here: a cancelled read answers the
//!   same `sys_tty_budget` refusal a timed-out one does. A descriptor
//!   `poll` cannot truthfully bound (a regular file or directory —
//!   the kinds Go's epoll-based deadline refuses) is rejected before
//!   any read, fail closed. `read_ceremony_secret` additionally
//!   suppresses `ECHO` for the read's duration and restores it even
//!   on panic — a `TCGETS`/`TCSETS` failure is the first place a dead
//!   console (`/dev/ttyS*` with no UART) reports itself, so it is
//!   marked `sys_tty_console_unfit` rather than folded into a
//!   credential failure (upstream P-2).
//! - [`PhysicalConsole`] — the opened seat, with `poll`-bounded
//!   writes for [`write_init_line`] and [`prompt_password`], and the
//!   [`CeremonyConsole`] impl the init dialog bounds its prompts
//!   through.
//! - [`describe_authentication_failure`] — the console-vs-credential
//!   diagnosis every ceremony entry point reports through.
//! - The confirmation-phrase vocabulary (`confirmation_phrase.go`):
//!   one verb per destructive ceremony, [`confirmation_phrase_matches`]
//!   the single exact-match comparison, [`random_confirmation_code`]
//!   the Crockford-base32 code.
//! - [`run_init_confirmation`] — the init ceremony's prompt/retry
//!   dialog (`init_ceremony_prompt.go`), generic over
//!   [`CeremonyConsole`] so its text and retry rule stay falsifiable
//!   without a physical console.
//!
//! Everything is `rustix` safe wrappers — `TIOCEXCL`, `TCGETS`,
//! `TCSETS`, `TCFLSH`, `poll` — there is no `unsafe` here. What this
//! module does not carry is the helper-context orchestration
//! (`lifecyclePeerFromContext`, `PAMSession`, grants, the
//! `Perform*TTYCeremony` entry points): those belong to the R5
//! task-8 helper server, which composes these primitives.

use std::cell::Cell;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{FileType, Mode, OFlags, Timespec, fstat, open};
use rustix::io::Errno;
use rustix::process::Pid;
use rustix::rand::{GetRandomFlags, getrandom};
use rustix::termios::{
    LocalModes, OptionalActions, QueueSelector, Termios, ioctl_tiocexcl, tcflush, tcgetattr,
    tcsetattr,
};
use zeroize::Zeroizing;

/// `sys_tty_console_unfit` — the `errCeremonyConsoleUnfit` marker,
/// carried as the [`Failure::code`] so the diagnosis can find it in a
/// flat failure rather than an error chain. A console failure is the
/// operator's CONSOLE, not the operator's ANSWER: on a serial node
/// with no UART the open and `TIOCEXCL` both succeed and the first
/// call that reaches the missing hardware is the `TCGETS`/`TCSETS`
/// pair that keeps the password off the screen.
pub const CONSOLE_UNFIT: &str = "sys_tty_console_unfit";

fn console_unfit(detail: impl Into<String>) -> Failure {
    Failure::unavailable(
        CONSOLE_UNFIT,
        format!(
            "tty_ceremony: the operator's physical console cannot host the ceremony: {}",
            detail.into()
        ),
    )
}

fn unboundable(detail: impl Into<String>) -> Failure {
    Failure::unavailable(
        "sys_tty_unboundable",
        format!(
            "tty_ceremony: the operator's terminal cannot be bounded by the ceremony's budget: {}",
            detail.into()
        ),
    )
}

fn budget_expired() -> Failure {
    Failure::cancelled(
        "sys_tty_budget",
        "tty_ceremony: the operator's confirmation did not arrive within the ceremony's share of the budget",
    )
}

fn read_failure(e: impl std::fmt::Display) -> Failure {
    Failure::unavailable(
        "sys_tty_read",
        format!("tty_ceremony: read confirmation: {e}"),
    )
}

fn write_failure(e: impl std::fmt::Display) -> Failure {
    Failure::unavailable(
        "sys_tty_console_write",
        format!("tty_ceremony: console write: {e}"),
    )
}

/// The seat check and exclusive lock from upstream `openPhysicalTTY`.
///
/// `peer_pid` is the socket peer's pid — the console is *the peer's*,
/// resolved through `/proc/<pid>/fd/0`, never the helper's own
/// environment. A target is a physical console only when it lives
/// under `/dev/tty*` and does not live under `/dev/pts/` — upstream's
/// literal rule, which accepts `/dev/ttyN`, `/dev/ttyS*`,
/// `/dev/ttyUSB*` and refuses pseudo-terminals, `/dev/console` and
/// every other path.
///
/// # Errors
/// `sys_tty_not_console` (`Denied`) when the peer's fd 0 does not
/// resolve to a physical console — a boundary refusal, not a
/// breakage; `sys_tty_console_unfit` (`Unavailable`) when the console
/// cannot be opened `O_RDWR|O_NONBLOCK|O_CLOEXEC` or refuses the
/// `TIOCEXCL` lock.
pub fn open_physical_tty(peer_pid: Pid) -> Result<PhysicalConsole, Failure> {
    let path = PathBuf::from(format!("/proc/{}/fd/0", peer_pid.as_raw_pid()));
    let target = std::fs::read_link(&path).map_err(|_| {
        Failure::denied(
            "sys_tty_not_console",
            "tty_ceremony: peer does not own a physical console TTY",
        )
    })?;
    let target = target.to_string_lossy();
    if !target.starts_with("/dev/tty") || target.starts_with("/dev/pts/") {
        return Err(Failure::denied(
            "sys_tty_not_console",
            "tty_ceremony: peer does not own a physical console TTY",
        ));
    }
    // O_NONBLOCK is load-bearing, upstream verbatim: without it, a
    // serial console whose CLOCAL is clear and whose carrier is absent
    // blocks inside the kernel's tty_port_block_til_ready and no
    // deadline anywhere can interrupt an open(2). The descriptor stays
    // non-blocking — every read and write below bounds itself through
    // poll(2), which is the same shape the Go runtime poller gave the
    // upstream ceremony.
    let fd = open(
        &path,
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        console_unfit(format!(
            "it could not be opened for reading and writing: {e}"
        ))
    })?;
    lock_tty_exclusive(&fd).map_err(|e| {
        console_unfit(format!(
            "it refused the exclusive lock the ceremony takes before it prompts: {e}"
        ))
    })?;
    Ok(PhysicalConsole {
        fd,
        write_deadline: Cell::new(None),
    })
}

/// `ioctl(fd, TIOCEXCL)` — the exclusive lock the ceremony takes
/// before prompting; a second opener gets `EBUSY`.
///
/// Upstream reaches this through `SyscallConn` so the descriptor stays
/// inside the Go runtime poller; the poll-bounded I/O below never
/// leaves the descriptor unboundable, so the same hazard cannot exist
/// here.
///
/// # Errors
/// `sys_tty_console_unfit` when the ioctl fails.
pub fn lock_tty_exclusive<Fd: AsFd>(fd: Fd) -> Result<(), Failure> {
    ioctl_tiocexcl(fd).map_err(|e| {
        console_unfit(format!(
            "it refused the exclusive lock the ceremony takes before it prompts: {e}"
        ))
    })
}

/// `tcflush(fd, TCIFLUSH)` — discard input typed on the terminal but
/// not yet read. The init dialog flushes before its retry prompt so a
/// line typed after the mismatch is not read as the second attempt.
///
/// # Errors
/// `sys_tty_flush` when the ioctl fails.
pub fn flush_tty_input<Fd: AsFd>(fd: Fd) -> Result<(), Failure> {
    tcflush(fd, QueueSelector::IFlush)
        .map_err(|e| Failure::unavailable("sys_tty_flush", format!("tty_ceremony: {e}")))
}

/// The descriptor kinds `poll(2)` cannot truthfully bound — a regular
/// file or a directory reports ready no matter what, so a deadline
/// against one is a bound that does not bind. These are exactly the
/// kinds Go's epoll-based `SetReadDeadline` refuses, and a refusal is
/// what upstream pins: a read that only *looks* bounded is worse than
/// an honest blocking one.
fn boundable<Fd: AsFd>(fd: Fd) -> Result<bool, Failure> {
    let stat = fstat(fd).map_err(|e| {
        unboundable(format!(
            "the descriptor could not be inspected for a bound: {e}"
        ))
    })?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    Ok(!(kind.is_file() || kind.is_dir()))
}

/// `wait_io` — one `poll(2)` bound shared by ceremony reads and
/// console writes. `EINTR` retries with the remaining budget
/// recomputed — what Go's poller does with signal interruptions too:
/// there is no signal-driven early return in the upstream ceremony
/// either. A readable `cancel` descriptor is upstream's `ctx.Done()`
/// watcher; it answers the same `sys_tty_budget` refusal a timeout
/// produces.
fn wait_io<Fd: AsFd>(
    fd: Fd,
    events: PollFlags,
    deadline: Option<Instant>,
    cancel: Option<BorrowedFd<'_>>,
) -> Result<(), Failure> {
    let fd = fd.as_fd();
    loop {
        let timeout = deadline.map(|d| {
            let left = d.saturating_duration_since(Instant::now());
            Timespec::try_from(left).unwrap_or(Timespec {
                tv_sec: i64::MAX,
                tv_nsec: 999_999_999,
            })
        });
        let revents = match cancel {
            Some(cancel_fd) => {
                let mut pair = [
                    PollFd::new(&fd, events),
                    PollFd::new(&cancel_fd, PollFlags::IN),
                ];
                match poll(&mut pair, timeout.as_ref()) {
                    Ok(_) => {
                        if pair[1]
                            .revents()
                            .intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP)
                        {
                            return Err(budget_expired());
                        }
                        pair[0].revents()
                    }
                    Err(Errno::INTR) => continue,
                    Err(e) => {
                        return Err(Failure::unavailable(
                            "sys_tty_read",
                            format!(
                                "tty_ceremony: the operator's terminal could not be polled for the ceremony's bounded read: {e}"
                            ),
                        ));
                    }
                }
            }
            None => {
                let mut fds = [PollFd::new(&fd, events)];
                match poll(&mut fds, timeout.as_ref()) {
                    Ok(_) => fds[0].revents(),
                    Err(Errno::INTR) => continue,
                    Err(e) => {
                        return Err(Failure::unavailable(
                            "sys_tty_read",
                            format!(
                                "tty_ceremony: the operator's terminal could not be polled for the ceremony's bounded read: {e}"
                            ),
                        ));
                    }
                }
            }
        };
        if revents.is_empty() {
            return Err(budget_expired());
        }
        // IN/OUT is readiness; ERR/HUP/NVAL surface as "ready" too —
        // the following read()/write() turns them into the honest
        // error, exactly as the Go poller surfaces them.
        if revents.intersects(events | PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            return Ok(());
        }
    }
}

/// `EchoGuard` — `TCGETS`, clear `ECHO` with `TCSETS`, restore on
/// drop. Suppressing echo is the first call that reaches dead
/// hardware on a UART-less `/dev/ttyS*`, so both halves of the pair
/// map to `sys_tty_console_unfit`: this is where upstream's P-2 fix
/// bites, and the operator must hear "console", not "password".
struct EchoGuard<'fd> {
    fd: BorrowedFd<'fd>,
    saved: Termios,
}

impl<'fd> EchoGuard<'fd> {
    fn engage(fd: BorrowedFd<'fd>) -> Result<Self, Failure> {
        let saved = tcgetattr(fd).map_err(|e| {
            console_unfit(format!(
                "it refused the terminal-mode change that keeps the operator's password off the screen: {e}"
            ))
        })?;
        let mut quiet = saved.clone();
        quiet.local_modes &= !LocalModes::ECHO;
        tcsetattr(fd, OptionalActions::Now, &quiet).map_err(|e| {
            console_unfit(format!(
                "it refused the terminal-mode change that keeps the operator's password off the screen: {e}"
            ))
        })?;
        Ok(Self { fd, saved })
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        // Best-effort restore, upstream's `defer undo()`: a failed
        // restore cannot be reported from a drop, and the console's
        // next owner opens it fresh anyway.
        let _ = tcsetattr(self.fd, OptionalActions::Now, &self.saved);
    }
}

/// The shared bounded read behind [`read_ceremony_line`] and
/// [`read_ceremony_secret`], upstream `readCeremonyInput`.
///
/// Order is upstream's order: first the bound is proven (a deadline
/// on a descriptor `poll` cannot bound is a refusal, never a read),
/// then the echo change, then the deadline-bounded read loop.
fn read_ceremony_input<Fd: AsFd>(
    fd: Fd,
    deadline: Option<Instant>,
    cancel: Option<BorrowedFd<'_>>,
    echo_off: bool,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let fd = fd.as_fd();
    if deadline.is_some() && !boundable(fd)? {
        return Err(unboundable(
            "the descriptor is not one a read deadline can be honoured on",
        ));
    }
    // The echo guard is a console-unfit failure, upstream
    // errCeremonyConsoleUnfit verbatim — it must never read as a
    // credential problem.
    let _echo = if echo_off {
        Some(EchoGuard::engage(fd)?)
    } else {
        None
    };

    let mut line = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        wait_io(fd, PollFlags::IN, deadline, cancel)?;
        match rustix::io::read(fd, &mut chunk[..]) {
            Ok(0) => {
                return Err(read_failure("unexpected end of terminal input"));
            }
            Ok(n) => {
                line.extend_from_slice(&chunk[..n]);
                if let Some(end) = line.iter().position(|&b| b == b'\n') {
                    line.truncate(end + 1);
                    return Ok(line);
                }
            }
            Err(Errno::INTR | Errno::AGAIN) => continue,
            Err(e) => return Err(read_failure(e)),
        }
    }
}

/// `readCeremonyLine` — one line from the operator's physical
/// terminal, bounded by `deadline` and interruptible by `cancel`
/// becoming readable. The line keeps its terminator; trimming is the
/// matcher's job.
///
/// # Errors
/// `sys_tty_unboundable` when a deadline is asked of a descriptor it
/// cannot bind; `sys_tty_budget` when the share elapses or `cancel`
/// fires; `sys_tty_read` on a descriptor error.
pub fn read_ceremony_line<Fd: AsFd>(
    fd: Fd,
    deadline: Option<Instant>,
    cancel: Option<BorrowedFd<'_>>,
) -> Result<String, Failure> {
    let line = read_ceremony_input(fd, deadline, cancel, false)?;
    // Lossy is the honest conversion: the upstream matcher compares
    // bytes a Rust `str` could not hold, and an undecodable line is a
    // mismatch either way — the phrase is pure ASCII.
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// `readCeremonySecret` — the same bounded read with terminal echo
/// suppressed for the PAM password prompt. The returned buffer is
/// `Zeroizing`: the secret is wiped on every exit path, panic
/// included, and the echo is restored by the guard before the
/// trailing newline is written — upstream's exact ordering.
///
/// # Errors
/// `sys_tty_console_unfit` when the terminal-mode change fails;
/// otherwise as [`read_ceremony_line`].
pub fn read_ceremony_secret<Fd: AsFd>(
    fd: Fd,
    deadline: Option<Instant>,
    cancel: Option<BorrowedFd<'_>>,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let fd = fd.as_fd();
    let line = read_ceremony_input(fd, deadline, cancel, true);
    // Upstream writes the newline unconditionally after the read, so
    // the cursor lands on a fresh line for the next prompt even when
    // the read failed; its error is ignored there and here.
    let _ = rustix::io::write(fd, b"\n");
    line.map(|l| Zeroizing::new(trim_ascii_space(l.as_slice())))
}

/// ASCII whitespace trim for the secret — the byte-string form of
/// upstream's `strings.TrimSpace`, applied to raw bytes so a password
/// keeps every non-whitespace byte it was typed with.
fn trim_ascii_space(bytes: &[u8]) -> Vec<u8> {
    const SPACE: &[u8] = b" \t\n\x0b\x0c\r";
    let start = bytes
        .iter()
        .position(|b| !SPACE.contains(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !SPACE.contains(b))
        .map_or(start, |e| e + 1);
    bytes[start..end.max(start)].to_vec()
}

/// The opened physical console — upstream's `*os.File` from
/// `openPhysicalTTY`, carrying the `O_NONBLOCK` descriptor plus the
/// write deadline [`CeremonyConsole`] installs.
///
/// Every read and write goes through `poll(2)` on the descriptor, so
/// the non-blocking open flag that keeps a carrier-less serial line
/// from parking `open(2)` never produces an `EAGAIN` surface error.
pub struct PhysicalConsole {
    fd: OwnedFd,
    write_deadline: Cell<Option<Instant>>,
}

impl AsFd for PhysicalConsole {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl PhysicalConsole {
    /// A `poll`-bounded `write_all` — `None` waits without a bound,
    /// the same shape upstream's deadline-less `fmt.Fprint` had; a
    /// set deadline fails the write with `sys_tty_console_write`.
    fn write_bounded(&self, bytes: &[u8], deadline: Option<Instant>) -> Result<(), Failure> {
        let mut written = 0;
        while written < bytes.len() {
            wait_io(&self.fd, PollFlags::OUT, deadline, None)
                .map_err(|e| write_failure(e.message()))?;
            match rustix::io::write(&self.fd, &bytes[written..]) {
                Ok(0) => {
                    return Err(write_failure("the terminal accepted none of the line"));
                }
                Ok(n) => written += n,
                Err(Errno::INTR | Errno::AGAIN) => continue,
                Err(e) => return Err(write_failure(e)),
            }
        }
        Ok(())
    }
}

/// `WriteInitLine` — write one of init's operator lines to the peer's
/// physical console through the same [`open_physical_tty`] the init
/// ceremony uses, so the line reaches exactly the console the
/// operator confirmed at. The write is bounded by
/// [`INIT_CONSOLE_WRITE_TIMEOUT`] alone, even past the verb's
/// deadline — upstream's rule, so the cleanup line outlives the
/// failure it reports on.
///
/// # Errors
/// As [`open_physical_tty`], plus `sys_tty_console_write` when the
/// bounded write fails.
pub fn write_init_line(peer_pid: Pid, line: &[u8]) -> Result<(), Failure> {
    let console = open_physical_tty(peer_pid)?;
    console.write_bounded(line, Some(Instant::now() + INIT_CONSOLE_WRITE_TIMEOUT))
}

/// `promptPassword` — collect the PAM password from the same verified
/// physical console the confirmation ceremony will use. The prompt
/// write is upstream's plain `fmt.Fprint` — unbounded, its error
/// deliberately ignored so the *read's* error is the one that
/// surfaces.
///
/// # Errors
/// As [`open_physical_tty`] and [`read_ceremony_secret`].
pub fn prompt_password(
    peer_pid: Pid,
    deadline: Option<Instant>,
    cancel: Option<BorrowedFd<'_>>,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let console = open_physical_tty(peer_pid)?;
    let _ = console.write_bounded(b"Central PAM password: ", None);
    read_ceremony_secret(&console, deadline, cancel)
}

/// `describeAuthenticationFailure` — how a ceremony reports that the
/// PAM step produced no session: CONSOLE for a console failure
/// (`sys_tty_console_unfit`), AUTHENTICATION for everything else.
/// The wrong-password direction is the one that must not regress — a
/// mistyped password keeps saying "authentication failed", and a dead
/// console never says it.
pub fn describe_authentication_failure(err: Failure) -> Failure {
    if err.code() == CONSOLE_UNFIT {
        Failure::unavailable(
            CONSOLE_UNFIT,
            format!(
                "tty: the ceremony could not take the operator's password from the physical console, so no credential was ever tested -- this is a console failure and not an authentication failure, and the console is what to check: {}",
                err.message()
            ),
        )
    } else {
        Failure::denied(
            "sys_pam_auth",
            format!("pam: authentication failed: {}", err.message()),
        )
    }
}

/// `confirmation_phrase.go` — one verb per destructive ceremony, so
/// approval of one destructive act cannot be replayed as approval of
/// another. Every phrase is built entirely from helper-owned scope
/// (instance, target, operation ID); no request payload reaches any
/// of them.
pub mod phrase {
    const MIGRATION_RESET_PREFIX: &str = "RESET VERSION-ZERO";
    const RESTORE_APPLY_PREFIX: &str = "RESTORE CENTRAL";
    const RESTORE_ABANDON_PREFIX: &str = "ABANDON RESTORE";
    const WIPE_PREFIX: &str = "WIPE CENTRAL";
    const EXPORT_PREFIX: &str = "EXPORT CENTRAL";
    const IMPORT_PREFIX: &str = "IMPORT CENTRAL";
    const DELETE_PREFIX: &str = "DELETE BACKUP";
    const PRUNE_PREFIX: &str = "PRUNE ARTIFACTS";
    const RESCUE_PREFIX: &str = "RESCUE CENTRAL";
    const PATCH_PREFIX: &str = "PATCH CENTRAL";

    /// The word the init ceremony appends to the generic
    /// `CONFIRM <code>` phrase — the typed text names the act, so a
    /// lifecycle confirmation cannot create an instance.
    const INIT_TARGET: &str = "init";

    fn confirmation_phrase(prefix: &str, instance: &str, target: &str, operation: &str) -> String {
        format!("{prefix} {instance} {target} {operation}")
    }

    /// `CONFIRM <code> init` — the genesis phrase. There is no
    /// instance or target to name yet: genesis creates them.
    pub fn init_confirmation_phrase(code: &str) -> String {
        format!("CONFIRM {code} {INIT_TARGET}")
    }

    /// `RESET VERSION-ZERO <instance> <target> <operation>` — the
    /// ADR 0011 destructive reset phrase.
    pub fn migration_reset_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(MIGRATION_RESET_PREFIX, instance, target, operation)
    }

    /// `RESTORE CENTRAL <instance> <target> <operation>` — the
    /// restore-apply phrase.
    pub fn restore_apply_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(RESTORE_APPLY_PREFIX, instance, target, operation)
    }

    /// `ABANDON RESTORE <instance> <target> <operation>` — the
    /// abandon phrase; irreversible, and distinct from apply in both
    /// directions.
    pub fn restore_abandon_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(RESTORE_ABANDON_PREFIX, instance, target, operation)
    }

    /// `WIPE CENTRAL <instance> <target> <operation>` — the wipe
    /// phrase; no restore-scoped consent may satisfy it.
    pub fn wipe_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(WIPE_PREFIX, instance, target, operation)
    }

    /// `EXPORT CENTRAL <instance> <target> <operation>` — identity
    /// and key material leave the host.
    pub fn export_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(EXPORT_PREFIX, instance, target, operation)
    }

    /// `IMPORT CENTRAL <instance> <target> <operation>` — foreign
    /// data replaces this fresh instance's whole state.
    pub fn import_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(IMPORT_PREFIX, instance, target, operation)
    }

    /// `DELETE BACKUP <instance> <target> <operation>` — a sealed
    /// backup, once deleted, cannot be rebuilt.
    pub fn delete_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(DELETE_PREFIX, instance, target, operation)
    }

    /// `PRUNE ARTIFACTS <instance> <target> <operation>` — the
    /// prune-apply phrase; the operation names the plan being
    /// applied.
    pub fn prune_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(PRUNE_PREFIX, instance, target, operation)
    }

    /// `RESCUE CENTRAL <instance> <target> <operation>` — re-arming a
    /// denied instance reopens every mutation.
    pub fn rescue_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(RESCUE_PREFIX, instance, target, operation)
    }

    /// `PATCH CENTRAL <instance> <target> <operation>` — recording a
    /// matrix-approved transition moves the authorized pin.
    pub fn maintenance_apply_phrase(instance: &str, target: &str, operation: &str) -> String {
        confirmation_phrase(PATCH_PREFIX, instance, target, operation)
    }

    /// `confirmationPhraseMatches` — the single comparison every
    /// ceremony uses: trim only the line terminator and require exact
    /// equality. A phrase that merely contains the expected text, or
    /// approves a different act, is not a match; an empty expectation
    /// never matches, so a ceremony that failed to build its phrase
    /// cannot be satisfied by an empty line.
    pub fn confirmation_phrase_matches(typed: &str, expected: &str) -> bool {
        !expected.is_empty() && typed.trim() == expected
    }
}

pub use phrase::confirmation_phrase_matches;

/// Crockford's base32 (excludes I, L, O, U) — no character an
/// operator can misread or mistype for another under time pressure.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Six symbols: short enough to type accurately on the first try,
/// still ~1.07 billion possibilities per ceremony.
const CODE_LENGTH: usize = 6;

/// `randomConfirmationCode` — the code an operator types back at the
/// console. Fresh and unpredictable each time is the whole guarantee;
/// the low five bits of a uniform byte are uniform over a 32-symbol
/// alphabet, so there is no modulo bias to correct.
///
/// # Errors
/// `sys_tty_code` when `getrandom` fails.
pub fn random_confirmation_code() -> Result<String, Failure> {
    let mut raw = [0u8; CODE_LENGTH];
    getrandom(&mut raw, GetRandomFlags::empty()).map_err(|e| {
        Failure::internal(
            "sys_tty_code",
            format!("tty_ceremony: generate confirmation code: {e}"),
        )
    })?;
    let mut code = String::with_capacity(CODE_LENGTH);
    for b in raw {
        code.push(char::from(CODE_ALPHABET[usize::from(b & 0x1f)]));
    }
    Ok(code)
}

/// `initCeremonyDeadline` — the init ceremony's own share of the
/// verb's budget; upstream sets it equal to `restoreCeremonyDeadline`
/// (two minutes).
pub const INIT_CEREMONY_DEADLINE: Duration = Duration::from_secs(120);

/// `initConsoleWriteTimeout` — the bound on one console write, shorter
/// than the connection write grace so a console that does not drain
/// cannot hold the verb.
pub const INIT_CONSOLE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// `initConfirmationAttempts` — one retry after a mismatch, inside
/// the same share and with the same one-use code; a second guess at
/// a 32^6 code is negligible.
pub const INIT_CONFIRMATION_ATTEMPTS: u32 = 2;

/// `initMismatchLine` — what the console shows after a first
/// mismatch; a host input method once changed the typed letters while
/// the screen showed the right ones.
const INIT_MISMATCH_LINE: &str =
    "That did not match. Turn off any input method and type it again.\n";

/// `ErrInitConfirmationMismatch` as a failure — every attempt typed
/// and none matched. The genesis handler answers it with the
/// confirmation-mismatch wire reason (T8 wires that mapping).
fn init_mismatch() -> Failure {
    Failure::denied(
        "sys_tty_init_mismatch",
        "tty_ceremony: the typed init phrase did not match",
    )
}

/// `initCeremonyPrompt` — the phrase unquoted on a line of its own,
/// then the instruction with the seconds left. A first attempt opens
/// with what the act is; a retry opens with the mismatch line.
fn init_ceremony_prompt(phrase: &str, seconds_left: u64, retry: bool) -> String {
    let opening = if retry {
        INIT_MISMATCH_LINE
    } else {
        "Central instance genesis: a new Central instance is created on this host. The confirmation phrase is:\n"
    };
    let unit = if seconds_left == 1 {
        " second: "
    } else {
        " seconds: "
    };
    format!(
        "{opening}\n{phrase}\n\nType it exactly as shown (plain keyboard layout, no input method) within {seconds_left}{unit}"
    )
}

/// `initCeremonySecondsLeft` — the whole seconds left of the ceremony
/// share at `now`. Without a deadline it is the whole share.
fn init_ceremony_seconds_left(deadline: Option<Instant>, now: Instant) -> u64 {
    match deadline {
        None => INIT_CEREMONY_DEADLINE.as_secs(),
        Some(d) => d.saturating_duration_since(now).as_secs(),
    }
}

/// The console capabilities the init dialog needs — upstream's
/// `initConsoleDeadliner` / `initConsoleInputFlusher` interface
/// assertions, expressed as one trait with `Ok(false)` meaning "the
/// capability is not there" exactly as a failed assertion meant it.
///
/// - `Ok(true)` — the capability exists and was applied;
/// - `Ok(false)` — the console does not have the capability, and the
///   dialog proceeds without it (upstream: the interface check
///   failed, the write is unbounded / the flush is skipped);
/// - `Err` — the capability exists and refused: the prompt is not
///   written / the dialog aborts. Fail closed, as upstream.
pub trait CeremonyConsole: Write {
    /// Bound the next write to `at`. See the trait docs for the
    /// `Ok(false)`/`Err` meanings.
    fn set_write_deadline(&mut self, _at: Instant) -> Result<bool, Failure> {
        Ok(false)
    }
    /// Release a bound previously applied by `set_write_deadline`.
    /// Called only when the set returned `Ok(true)`; errors are
    /// ignored as upstream ignores them.
    fn clear_write_deadline(&mut self) {}
    /// Discard input typed but not yet read (`TCIFLUSH`). See the
    /// trait docs for the `Ok(false)`/`Err` meanings.
    fn flush_input(&mut self) -> Result<bool, Failure> {
        Ok(false)
    }
}

impl Write for PhysicalConsole {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let deadline = self.write_deadline.get();
        self.write_bounded(buf, deadline)
            .map(|()| buf.len())
            .map_err(|e| std::io::Error::other(e.message().to_owned()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CeremonyConsole for PhysicalConsole {
    fn set_write_deadline(&mut self, at: Instant) -> Result<bool, Failure> {
        self.write_deadline.set(Some(at));
        Ok(true)
    }

    fn clear_write_deadline(&mut self) {
        self.write_deadline.set(None);
    }

    fn flush_input(&mut self) -> Result<bool, Failure> {
        tcflush(&self.fd, QueueSelector::IFlush)
            .map_err(|e| Failure::unavailable("sys_tty_flush", format!("tty_ceremony: {e}")))?;
        Ok(true)
    }
}

/// `writeInitConsole` — one prompt write, bounded when the console
/// can be. A console that refuses the bound is not written to.
fn write_init_console(
    console: &mut dyn CeremonyConsole,
    text: &str,
    now: &mut dyn FnMut() -> Instant,
) -> Result<(), Failure> {
    let bounded = console
        .set_write_deadline(now() + INIT_CONSOLE_WRITE_TIMEOUT)
        .map_err(|e| {
            Failure::unavailable(
                "sys_tty_console_write",
                format!(
                    "tty_ceremony: the console refused a write deadline: {}",
                    e.message()
                ),
            )
        })?;
    let result = console.write_all(text.as_bytes()).map_err(|e| {
        Failure::unavailable(
            "sys_tty_console_write",
            format!("tty_ceremony: prompt: {e}"),
        )
    });
    if bounded {
        console.clear_write_deadline();
    }
    result
}

/// `runInitConfirmation` — the init ceremony's dialog on an opened
/// console: prompt, read one line under `deadline`, compare with
/// [`confirmation_phrase_matches`], and after a mismatch flush the
/// typed input and prompt once more.
///
/// `read_line` is the caller's bounded line read — the production
/// caller passes [`read_ceremony_line`] on the opened console; the
/// tests script it. `now` is the clock the prompts' "seconds left"
/// count against.
///
/// # Errors
/// `sys_tty_init_phrase` for an empty phrase (nothing is written);
/// `sys_tty_init_mismatch` after `INIT_CONFIRMATION_ATTEMPTS`
/// mismatches; the read's own error when a line does not arrive;
/// `sys_tty_budget` with no whole second left to prompt in (never a
/// "within 0 seconds" prompt, never a mismatch).
pub fn run_init_confirmation(
    deadline: Option<Instant>,
    console: &mut dyn CeremonyConsole,
    read_line: &mut dyn FnMut() -> Result<String, Failure>,
    phrase: &str,
    now: &mut dyn FnMut() -> Instant,
) -> Result<(), Failure> {
    if phrase.is_empty() {
        return Err(Failure::invalid(
            "sys_tty_init_phrase",
            "tty_ceremony: the init ceremony has no phrase to confirm",
        ));
    }
    for attempt in 1..=INIT_CONFIRMATION_ATTEMPTS {
        let retry = attempt > 1;
        if retry {
            console.flush_input().map_err(|e| {
                Failure::unavailable(
                    "sys_tty_flush",
                    format!(
                        "tty_ceremony: discard the input typed after the mismatch: {}",
                        e.message()
                    ),
                )
            })?;
        }
        let seconds_left = init_ceremony_seconds_left(deadline, now());
        if seconds_left < 1 {
            return Err(budget_expired());
        }
        write_init_console(
            console,
            &init_ceremony_prompt(phrase, seconds_left, retry),
            now,
        )?;
        let line = read_line()?;
        if confirmation_phrase_matches(&line, phrase) {
            return Ok(());
        }
        if attempt < INIT_CONFIRMATION_ATTEMPTS {
            write_init_console(console, "\n", now)?;
        }
    }
    Err(init_mismatch())
}

#[cfg(test)]
mod tests {
    //! The ceremony's two-minute share of the restore transport
    //! budget was, until upstream's fix, a number that bounded
    //! nothing; these tests pin the bound on a real pseudo-terminal,
    //! because a pipe would prove the wrong thing — the question is
    //! whether `poll(2)` can bound the character device this code
    //! actually opens, and it is answerable only on one.

    use super::*;
    use central_foundation::failure::FailureKind;
    use rustix::event::{EventfdFlags, eventfd};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use std::thread;

    /// `newCeremonyPTY` — master and slave of a fresh pty; the slave
    /// is what the ceremony code sees, opened the way
    /// `open_physical_tty` opens the real console. `None` = this host
    /// cannot grant a pty: the tests skip, upstream-fashion.
    fn ceremony_pty() -> Option<(OwnedFd, OwnedFd, PathBuf)> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::CLOEXEC).ok()?;
        grantpt(&master).ok()?;
        unlockpt(&master).ok()?;
        let name = ptsname(&master, Vec::new()).ok()?;
        let path = PathBuf::from(name.to_string_lossy().into_owned());
        let slave = open(
            &path,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        Some((master, slave, path))
    }

    macro_rules! pty_or_skip {
        () => {
            match ceremony_pty() {
                Some(pty) => pty,
                None => {
                    eprintln!(
                        "SKIP: no pseudo-terminal on this host; the ceremony's read bound is not being checked here"
                    );
                    return;
                }
            }
        };
    }

    /// `readCeremonyLineWithin` — run the bounded read off the test
    /// thread so a bound that does not bind fails in seconds with a
    /// clear message, instead of hanging to the package timeout.
    fn read_line_within(
        fd: OwnedFd,
        deadline: Option<Instant>,
        patience: Duration,
    ) -> (Result<String, Failure>, Duration) {
        let started = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(read_ceremony_line(&fd, deadline, None));
        });
        let result = rx.recv_timeout(patience).expect(
            "read_ceremony_line did not return within the patience window: the operator's terminal read is NOT bounded by the ceremony deadline",
        );
        (result, started.elapsed())
    }

    /// Nobody types, and the read has to end anyway — the
    /// load-bearing case.
    #[test]
    fn read_stops_when_the_ceremony_budget_elapses() {
        let (_master, slave, _path) = pty_or_skip!();
        let deadline = Instant::now() + Duration::from_millis(250);
        let (result, elapsed) = read_line_within(slave, Some(deadline), Duration::from_secs(5));
        let err = result.unwrap_err();
        assert_eq!(err.code(), "sys_tty_budget", "unanswered prompt: {err:?}");
        assert!(
            elapsed < Duration::from_secs(3),
            "the read took {elapsed:?} to honour a 250ms budget"
        );
    }

    /// The second enforcement path: a cancellation that arrives
    /// after the read is already blocked — upstream's `ctx.Done()`
    /// watcher, here the cancel descriptor. The deadline is only a
    /// backstop so a broken cancel cannot hang the suite.
    #[test]
    fn read_unblocks_when_the_ceremony_is_cancelled() {
        let (_master, slave, _path) = pty_or_skip!();
        // The cancellation descriptor upstream's ctx.Done() watcher
        // becomes: an eventfd the test bumps after the read blocks.
        let cancel = eventfd(0, EventfdFlags::CLOEXEC).expect("eventfd");
        let cancel_write = cancel.try_clone().expect("eventfd clone");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            let _ = rustix::io::write(&cancel_write, &1u64.to_ne_bytes());
        });
        let backstop = Instant::now() + Duration::from_secs(5);
        let started = Instant::now();
        let err = read_ceremony_line(&slave, Some(backstop), Some(cancel.as_fd())).unwrap_err();
        assert_eq!(err.code(), "sys_tty_budget", "cancelled ceremony: {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the cancel did not interrupt the read"
        );
    }

    /// A descriptor the bound cannot bind is refused, not read from
    /// optimistically: the remaining-budget refusal downstream is
    /// written on the promise that the ceremony stays inside its
    /// share.
    #[test]
    fn read_refuses_a_terminal_it_cannot_bound() {
        let path =
            std::env::temp_dir().join(format!("central-t5-notaterminal-{}", std::process::id()));
        std::fs::write(&path, b"APPLY RESTORE\n").expect("write fixture");
        let file = open(&path, OFlags::RDWR, Mode::empty()).expect("open fixture");
        let err = read_ceremony_line(&file, Some(Instant::now() + Duration::from_secs(60)), None)
            .unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            err.code(),
            "sys_tty_unboundable",
            "a regular file was read as a ceremony terminal: {err:?}"
        );
    }

    /// The control: a bound that also broke the ordinary path would
    /// make every restore impossible rather than every overrun
    /// refused.
    #[test]
    fn read_returns_what_the_operator_typed() {
        let (master, slave, _path) = pty_or_skip!();
        let phrase = "APPLY RESTORE default postgres:central";
        // Type the line before the read starts; `master` must outlive
        // the read — closing it sends the slave to end-of-input.
        rustix::io::write(&master, format!("{phrase}\n").as_bytes()).expect("write phrase");
        let deadline = Instant::now() + Duration::from_secs(10);
        let (result, _elapsed) = read_line_within(slave, Some(deadline), Duration::from_secs(10));
        drop(master);
        let line = result.expect("a typed confirmation was refused");
        assert_eq!(line.trim(), phrase);
        assert!(
            confirmation_phrase_matches(&line, phrase),
            "the bounded read produced a line the phrase matcher rejects: {line:?}"
        );
    }

    /// `TestExclusiveTTYLockLeavesTheDescriptorBoundable` — the lock
    /// is real (a second open is `EBUSY`) and the bounded read still
    /// works on the locked descriptor.
    #[test]
    fn exclusive_lock_leaves_the_descriptor_boundable() {
        let (_master, slave, path) = pty_or_skip!();
        lock_tty_exclusive(&slave).expect("lock_tty_exclusive");
        // The lock must be real, not merely harmless: a second open
        // of the same terminal is refused EBUSY.
        let err = open(
            &path,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect_err("TIOCEXCL did not take: the terminal could be opened a second time");
        assert_eq!(err, Errno::BUSY, "second open of a locked terminal");
        let deadline = Instant::now() + Duration::from_millis(250);
        let (result, _elapsed) = read_line_within(slave, Some(deadline), Duration::from_secs(5));
        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            "sys_tty_budget",
            "locked-terminal read: {err:?}"
        );
    }

    /// `TCIFLUSH` discards the lines typed before it — the init
    /// dialog's retry guarantee.
    #[test]
    fn flush_discards_the_lines_typed_before_it() {
        let (master, slave, _path) = pty_or_skip!();
        rustix::io::write(&master, b"typed too early\n").expect("write early");
        thread::sleep(Duration::from_millis(50)); // let the line discipline take the line
        flush_tty_input(&slave).expect("flush_tty_input");
        rustix::io::write(&master, b"typed after the prompt\n").expect("write late");
        let deadline = Instant::now() + Duration::from_secs(2);
        let (result, _elapsed) = read_line_within(slave, Some(deadline), Duration::from_secs(5));
        let line = result.expect("the post-flush read failed");
        assert_eq!(line.trim(), "typed after the prompt");
    }

    /// A console opened the ceremony way — `O_RDWR|O_NONBLOCK|
    /// O_CLOEXEC` — keeps taking the exclusive lock, writes the
    /// prompt, and honours the read bound. `EAGAIN` surfacing to the
    /// operator would be a worse defect than the one the flag fixes.
    #[test]
    fn nonblocking_console_stays_lockable_writable_and_boundable() {
        let (_master, _slave, path) = pty_or_skip!();
        let console = open(
            &path,
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("reopen with ceremony flags");
        lock_tty_exclusive(&console).expect("TIOCEXCL on a non-blocking console");
        let pc = PhysicalConsole {
            fd: console,
            write_deadline: Cell::new(None),
        };
        pc.write_bounded(b"Central PAM password: ", None)
            .expect("writing the prompt to a non-blocking console failed");
        let deadline = Instant::now() + Duration::from_millis(250);
        let started = Instant::now();
        let err = read_ceremony_line(&pc, Some(deadline), None).unwrap_err();
        assert_eq!(err.code(), "sys_tty_budget");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the bounded read did not honour the budget on a non-blocking console"
        );
    }

    /// The P-2 diagnosis: a descriptor whose terminal-mode change
    /// fails is a dead CONSOLE — the error carries
    /// `sys_tty_console_unfit` and names the console, never the
    /// credential. The pipe is upstream's stand-in: `TCGETS` answers
    /// `ENOTTY` where a UART-less serial node answers `EIO`.
    #[test]
    fn dead_console_is_named_console_failure_not_credential() {
        // An eventfd answers TCGETS ENOTTY — upstream's pipe stand-in.
        let dead = eventfd(0, EventfdFlags::CLOEXEC).expect("eventfd");
        // No deadline: the unboundable branch is a different refusal,
        // and it would mask this one — the same choice upstream's
        // diagnosis test makes with context.Background().
        let err = read_ceremony_secret(&dead, None, None).unwrap_err();
        assert_eq!(
            err.code(),
            "sys_tty_console_unfit",
            "the terminal-mode failure did not carry the console-unfit marker: {err:?}"
        );
        assert!(
            err.message().contains("console"),
            "the terminal-mode failure does not name the console: {err:?}"
        );
    }

    /// The control on the test above: a working console returns the
    /// secret unmarked, and an operator who walks away is a timeout —
    /// never a console failure.
    #[test]
    fn working_console_is_not_accused_of_being_dead() {
        let (master, slave, _path) = pty_or_skip!();
        // Typed before the read, with `master` alive for its duration.
        rustix::io::write(&master, b"correct horse\n").expect("write secret");
        let deadline = Instant::now() + Duration::from_secs(10);
        let secret = read_ceremony_secret(&slave, Some(deadline), None)
            .expect("a real terminal was refused");
        assert_eq!(secret.as_slice(), b"correct horse");

        let deadline = Instant::now() + Duration::from_millis(250);
        let err = read_ceremony_secret(&slave, Some(deadline), None).unwrap_err();
        assert_eq!(err.code(), "sys_tty_budget");
        assert_ne!(
            err.code(),
            "sys_tty_console_unfit",
            "an operator who did not answer was reported as a broken console"
        );
    }

    /// The surface: a dead console is a console failure at the
    /// report, a wrong password stays an authentication failure, and
    /// the peer-predicate refusal keeps its shape — the three
    /// directions upstream pins.
    #[test]
    fn dead_console_is_not_reported_as_an_authentication_failure() {
        let dead = describe_authentication_failure(console_unfit(
            "it refused the terminal-mode change that keeps the operator's password off the screen: input/output error",
        ));
        assert!(!dead.message().contains("pam: authentication failed"));
        assert!(dead.message().contains("console"));
        assert!(
            dead.message().contains("input/output error"),
            "the console diagnosis dropped the underlying errno text"
        );

        let wrong = describe_authentication_failure(Failure::denied(
            "sys_pam_auth",
            "pam: authentication failed (code 7)",
        ));
        assert!(wrong.message().contains("pam: authentication failed"));
        assert!(!wrong.message().contains("console failure"));

        let redirected = describe_authentication_failure(Failure::denied(
            "sys_tty_not_console",
            "tty_ceremony: peer does not own a physical console TTY",
        ));
        assert!(
            redirected.message().contains("pam: authentication failed"),
            "the predicate refusal changed shape"
        );
    }

    /// The predicate refusal itself: a peer whose fd 0 is a
    /// pseudo-terminal is D-1's boundary — refused as
    /// `sys_tty_not_console`, a denial and not a breakage.
    #[test]
    fn peer_on_a_pseudo_terminal_is_refused() {
        let (_master, slave, _path) = pty_or_skip!();
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .stdin(std::process::Stdio::from(std::fs::File::from(slave)))
            .spawn()
            .expect("spawn child on the pty");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("pid fits")).expect("nonzero pid");
        let err = open_physical_tty(pid).err().expect("a pty was accepted");
        child.kill().expect("kill child");
        let _ = child.wait();
        assert_eq!(err.code(), "sys_tty_not_console");
        assert_eq!(err.kind(), FailureKind::Denied);
    }

    /// And so is a peer whose fd 0 is not a console of any kind —
    /// this process's own stdin under cargo test is the stand-in. If
    /// the suite ever runs at a real `/dev/tty*` seat the refusal
    /// cannot be produced here and the test skips.
    #[test]
    fn peer_without_a_console_is_refused() {
        let target = std::fs::read_link("/proc/self/fd/0")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if target.starts_with("/dev/tty") && !target.starts_with("/dev/pts/") {
            eprintln!(
                "SKIP: this test runs at a real physical console; the refusal cannot be produced on self"
            );
            return;
        }
        let err = open_physical_tty(rustix::process::getpid())
            .err()
            .expect("a non-console was accepted");
        assert_eq!(err.code(), "sys_tty_not_console");
    }

    /// The confirmation code is six Crockford-base32 symbols, fresh
    /// each time — the property upstream's code shape asserts by
    /// construction.
    #[test]
    fn confirmation_code_is_six_crockford_symbols() {
        let alphabet: std::collections::HashSet<char> =
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ".chars().collect();
        let a = random_confirmation_code().expect("code");
        let b = random_confirmation_code().expect("code");
        assert_eq!(a.len(), 6);
        assert!(a.chars().all(|c| alphabet.contains(&c)));
        assert_ne!(a, b, "two minted codes collided");
    }

    /// `confirmation_phrase.go` — the destructive ceremonies do not
    /// share a phrase, and approval of one cannot satisfy another.
    mod phrase_tests {
        use super::phrase::*;

        #[test]
        fn destructive_phrases_are_mutually_unsatisfiable() {
            const INSTANCE: &str = "instance-a";
            const TARGET: &str = "target-a";
            const OPERATION: &str = "operation-a";
            let phrases = [
                (
                    "migration reset",
                    migration_reset_phrase(INSTANCE, TARGET, OPERATION),
                ),
                (
                    "restore apply",
                    restore_apply_phrase(INSTANCE, TARGET, OPERATION),
                ),
                (
                    "restore abandon",
                    restore_abandon_phrase(INSTANCE, TARGET, OPERATION),
                ),
                ("wipe", wipe_phrase(INSTANCE, TARGET, OPERATION)),
                ("export", export_phrase(INSTANCE, TARGET, OPERATION)),
                ("import", import_phrase(INSTANCE, TARGET, OPERATION)),
                ("delete", delete_phrase(INSTANCE, TARGET, OPERATION)),
                ("prune", prune_phrase(INSTANCE, TARGET, OPERATION)),
                ("rescue", rescue_phrase(INSTANCE, TARGET, OPERATION)),
            ];
            for (name, phrase) in &phrases {
                assert!(!phrase.is_empty(), "{name} built an empty phrase");
                for (other_name, other) in &phrases {
                    if name == other_name {
                        assert!(
                            confirmation_phrase_matches(phrase, other),
                            "{name} does not accept its own phrase {phrase:?}"
                        );
                    } else {
                        assert_ne!(phrase, other, "{name} and {other_name} share a phrase");
                        assert!(
                            !confirmation_phrase_matches(phrase, other),
                            "typing the {name} phrase {phrase:?} satisfies the {other_name} ceremony"
                        );
                    }
                }
            }
        }

        #[test]
        fn wipe_phrase_is_its_own_verb() {
            let got = wipe_phrase("default", "postgres:central", "op-1");
            assert_eq!(got, "WIPE CENTRAL default postgres:central op-1");
            assert!(!confirmation_phrase_matches(
                "RESTORE CENTRAL default postgres:central op-1",
                &got
            ));
        }

        #[test]
        fn restore_abandon_phrase_is_its_own_verb() {
            let got = restore_abandon_phrase("default", "postgres:central", "op-1");
            assert_eq!(got, "ABANDON RESTORE default postgres:central op-1");
            // The operator types a line; the terminator must not
            // defeat the match, and nothing else is forgiven.
            assert!(confirmation_phrase_matches(&format!("{got}\n"), &got));
            for typed in [
                "abandon restore default postgres:central op-1",
                "ABANDON RESTORE default postgres:central op-2",
                "yes ABANDON RESTORE default postgres:central op-1",
                "ABANDON RESTORE default postgres:central",
                "",
            ] {
                assert!(
                    !confirmation_phrase_matches(typed, &got),
                    "the abandonment ceremony accepted {typed:?}"
                );
            }
            assert!(!confirmation_phrase_matches("", ""));
        }

        #[test]
        fn init_phrase_names_the_act_and_is_no_other_ceremonys_phrase() {
            let got = init_confirmation_phrase("ABC234");
            assert_eq!(got, "CONFIRM ABC234 init");
            assert!(confirmation_phrase_matches(&format!("{got}\n"), &got));
            const INSTANCE: &str = "instance-a";
            const TARGET: &str = "target-a";
            const OPERATION: &str = "operation-a";
            for (name, other) in [
                ("lifecycle", "CONFIRM ABC234".to_owned()),
                (
                    "migration reset",
                    migration_reset_phrase(INSTANCE, TARGET, OPERATION),
                ),
                (
                    "restore apply",
                    restore_apply_phrase(INSTANCE, TARGET, OPERATION),
                ),
                (
                    "restore abandon",
                    restore_abandon_phrase(INSTANCE, TARGET, OPERATION),
                ),
                ("wipe", wipe_phrase(INSTANCE, TARGET, OPERATION)),
                ("import", import_phrase(INSTANCE, TARGET, OPERATION)),
                ("rescue", rescue_phrase(INSTANCE, TARGET, OPERATION)),
            ] {
                assert!(
                    !confirmation_phrase_matches(&other, &got),
                    "typing the {name} phrase {other:?} satisfies the init ceremony"
                );
            }
        }
    }

    /// `init_ceremony_prompt.go` — the init dialog, driven through
    /// `run_init_confirmation` with a scripted console exactly as
    /// upstream tests it, because the ceremony itself needs a
    /// physical console.
    mod init_dialog_tests {
        use super::*;
        use std::collections::VecDeque;

        const TEST_PHRASE: &str = "CONFIRM ABC234 init";

        /// The scripted answer lines: one per read, then the read's
        /// own timeout — upstream's `scriptedConsole.readLine`.
        struct Lines {
            lines: VecDeque<String>,
            reads: usize,
        }

        impl Lines {
            fn new(lines: &[&str]) -> Self {
                Self {
                    lines: lines.iter().map(|s| (*s).to_owned()).collect(),
                    reads: 0,
                }
            }
            fn next_line(&mut self) -> Result<String, Failure> {
                match self.lines.pop_front() {
                    Some(line) => {
                        self.reads += 1;
                        Ok(line)
                    }
                    None => Err(budget_expired()),
                }
            }
        }

        /// The console the dialog writes to — records every byte.
        #[derive(Default)]
        struct Out {
            out: String,
        }

        impl Write for Out {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.out.push_str(&String::from_utf8_lossy(buf));
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl CeremonyConsole for Out {}

        /// The bounded console: takes write deadlines and input
        /// flushes as the physical console does, records the order.
        #[derive(Default)]
        struct BoundedOut {
            out: String,
            events: Vec<String>,
            deadline_err: bool,
            flush_err: bool,
        }

        impl Write for BoundedOut {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.events.push("write".to_owned());
                self.out.push_str(&String::from_utf8_lossy(buf));
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl CeremonyConsole for BoundedOut {
            fn set_write_deadline(&mut self, _at: Instant) -> Result<bool, Failure> {
                if self.deadline_err {
                    return Err(Failure::unavailable("test", "no deadline"));
                }
                self.events.push("deadline".to_owned());
                Ok(true)
            }
            fn clear_write_deadline(&mut self) {
                self.events.push("clear".to_owned());
            }
            fn flush_input(&mut self) -> Result<bool, Failure> {
                self.events.push("flush".to_owned());
                if self.flush_err {
                    return Err(Failure::unavailable("test", "ioctl"));
                }
                Ok(true)
            }
        }

        /// `fixedClock` — the given instants in turn, then the last
        /// one forever.
        fn fixed_clock(instants: &[Instant]) -> impl FnMut() -> Instant + use<> {
            let mut queue: VecDeque<Instant> = instants.iter().copied().collect();
            move || {
                if queue.len() > 1 {
                    queue.pop_front().expect("clock")
                } else {
                    *queue.front().expect("clock")
                }
            }
        }

        #[test]
        fn prompt_shows_the_phrase_unquoted_with_time_left() {
            let first = init_ceremony_prompt(TEST_PHRASE, 97, false);
            let want = "Central instance genesis: a new Central instance is created on this host. The confirmation phrase is:\n\nCONFIRM ABC234 init\n\nType it exactly as shown (plain keyboard layout, no input method) within 97 seconds: ";
            assert_eq!(first, want);
            let retry = init_ceremony_prompt(TEST_PHRASE, 41, true);
            let want_retry = "That did not match. Turn off any input method and type it again.\n\nCONFIRM ABC234 init\n\nType it exactly as shown (plain keyboard layout, no input method) within 41 seconds: ";
            assert_eq!(retry, want_retry);
            for prompt in [&first, &retry] {
                assert!(
                    !prompt.contains(&['"', '\'', '`'][..]),
                    "the prompt quotes something, which invites typing the quotes: {prompt:?}"
                );
                assert!(
                    prompt.contains(&format!("\n{TEST_PHRASE}\n")),
                    "the phrase is not on a line of its own: {prompt:?}"
                );
            }
        }

        #[test]
        fn seconds_left_is_the_share_still_on_the_deadline() {
            let start = Instant::now();
            let deadline = start + INIT_CEREMONY_DEADLINE;
            for (offset_ms, want) in [(0u64, 120), (23_400, 96), (119_700, 0), (121_000, 0)] {
                let now = start + Duration::from_millis(offset_ms);
                assert_eq!(
                    init_ceremony_seconds_left(Some(deadline), now),
                    want,
                    "at +{offset_ms}ms"
                );
            }
            assert_eq!(
                init_ceremony_seconds_left(None, start),
                INIT_CEREMONY_DEADLINE.as_secs()
            );
        }

        #[test]
        fn exact_phrase_accepted_at_first_attempt() {
            let start = Instant::now();
            let mut lines = Lines::new(&["CONFIRM ABC234 init\n"]);
            let mut console = Out::default();
            let mut reader = || lines.next_line();
            let mut clock = fixed_clock(&[start]);
            let result = run_init_confirmation(
                Some(start + Duration::from_secs(100)),
                &mut console,
                &mut reader,
                TEST_PHRASE,
                &mut clock,
            );
            assert!(result.is_ok(), "the exact phrase was refused");
            assert_eq!(lines.reads, 1);
            assert_eq!(console.out, init_ceremony_prompt(TEST_PHRASE, 100, false));
        }

        #[test]
        fn one_more_attempt_with_the_same_code_after_a_mismatch() {
            let start = Instant::now();
            let mut lines = Lines::new(&["CONFIRM ABC234 inịt\n", "CONFIRM ABC234 init\n"]);
            let mut console = Out::default();
            let mut reader = || lines.next_line();
            let mut clock = fixed_clock(&[start, start + Duration::from_secs(30)]);
            let result = run_init_confirmation(
                Some(start + Duration::from_secs(100)),
                &mut console,
                &mut reader,
                TEST_PHRASE,
                &mut clock,
            );
            assert!(
                result.is_ok(),
                "the exact phrase at the second attempt was refused"
            );
            let want = format!(
                "{}\n{}",
                init_ceremony_prompt(TEST_PHRASE, 100, false),
                init_ceremony_prompt(TEST_PHRASE, 70, true)
            );
            assert_eq!(lines.reads, 2);
            assert_eq!(console.out, want);
        }

        #[test]
        fn a_second_mismatch_is_refused() {
            let start = Instant::now();
            for typed in [
                ["\"CONFIRM ABC234 init\"\n", "\"CONFIRM ABC234 init\"\n"].as_slice(),
                ["confirm abc234 init\n", "CONFIRM ABC234 init please\n"].as_slice(),
                ["CONFIRM ABC234\n", "CONFIRM ABC234 up\n"].as_slice(),
            ] {
                let mut lines = Lines::new(typed);
                let mut console = Out::default();
                let mut reader = || lines.next_line();
                let mut clock = fixed_clock(&[start]);
                let err = run_init_confirmation(
                    Some(start + Duration::from_secs(100)),
                    &mut console,
                    &mut reader,
                    TEST_PHRASE,
                    &mut clock,
                )
                .unwrap_err();
                assert_eq!(
                    err.code(),
                    "sys_tty_init_mismatch",
                    "typed {typed:?}: want the init-mismatch refusal"
                );
                assert_eq!(
                    lines.reads,
                    usize::try_from(INIT_CONFIRMATION_ATTEMPTS).unwrap()
                );
            }
            assert_eq!(INIT_CONFIRMATION_ATTEMPTS, 2);
        }

        #[test]
        fn a_timeout_is_not_a_mismatch() {
            let start = Instant::now();
            for typed in [
                Vec::<&str>::new().as_slice(),
                ["CONFIRM ABC234 int\n"].as_slice(),
            ] {
                let mut lines = Lines::new(typed);
                let mut console = Out::default();
                let mut reader = || lines.next_line();
                let mut clock = fixed_clock(&[start]);
                let err = run_init_confirmation(
                    Some(start + Duration::from_secs(100)),
                    &mut console,
                    &mut reader,
                    TEST_PHRASE,
                    &mut clock,
                )
                .unwrap_err();
                assert_eq!(
                    err.code(),
                    "sys_tty_budget",
                    "typed {typed:?} then nothing: want the read's timeout, not a mismatch"
                );
            }
        }

        #[test]
        fn an_empty_phrase_refuses_without_prompting() {
            let mut lines = Lines::new(&["\n"]);
            let mut console = Out::default();
            let mut reader = || lines.next_line();
            let mut clock = fixed_clock(&[Instant::now()]);
            let err =
                run_init_confirmation(None, &mut console, &mut reader, "", &mut clock).unwrap_err();
            assert_eq!(err.code(), "sys_tty_init_phrase");
            assert_eq!(lines.reads, 0);
            assert!(console.out.is_empty());
        }

        /// Each prompt write is bounded like `write_init_line`, and
        /// the input typed after a mismatch is flushed before the
        /// retry prompt — never before the first.
        #[test]
        fn every_prompt_write_is_bounded_and_flush_precedes_retry() {
            let start = Instant::now();
            let mut lines = Lines::new(&["CONFIRM ABC234 inịt\n", "CONFIRM ABC234 init\n"]);
            let mut console = BoundedOut::default();
            let mut reader = || lines.next_line();
            let mut clock = fixed_clock(&[start]);
            let result = run_init_confirmation(
                Some(start + Duration::from_secs(100)),
                &mut console,
                &mut reader,
                TEST_PHRASE,
                &mut clock,
            );
            assert!(
                result.is_ok(),
                "the exact phrase at the second attempt was refused"
            );
            assert_eq!(
                console.events,
                vec![
                    "deadline", "write", "clear", "deadline", "write", "clear", "flush",
                    "deadline", "write", "clear",
                ]
            );

            // A console that refuses the bound is not written to.
            let mut refusing = BoundedOut {
                deadline_err: true,
                ..BoundedOut::default()
            };
            let mut reader = || lines.next_line();
            let mut clock = fixed_clock(&[start]);
            let err = run_init_confirmation(
                Some(start + Duration::from_secs(100)),
                &mut refusing,
                &mut reader,
                TEST_PHRASE,
                &mut clock,
            )
            .unwrap_err();
            assert!(err.message().contains("refused a write deadline"));
            assert!(refusing.out.is_empty());

            // A failed flush refuses before the retry prompt.
            let mut flushing = BoundedOut {
                flush_err: true,
                ..BoundedOut::default()
            };
            let mut lines2 = Lines::new(&["wrong\n", "CONFIRM ABC234 init\n"]);
            let mut reader = || lines2.next_line();
            let mut clock = fixed_clock(&[start]);
            let err = run_init_confirmation(
                Some(start + Duration::from_secs(100)),
                &mut flushing,
                &mut reader,
                TEST_PHRASE,
                &mut clock,
            )
            .unwrap_err();
            assert_eq!(err.code(), "sys_tty_flush");
            assert_eq!(lines2.reads, 1);
        }

        /// With less than a whole second of the share left the dialog
        /// does not print "within 0 seconds" — it answers the
        /// timeout, never a mismatch; one second left reads
        /// "1 second".
        #[test]
        fn no_prompt_with_no_whole_second_left() {
            let start = Instant::now();
            let mut lines = Lines::new(&["wrong\n", "CONFIRM ABC234 init\n"]);
            let mut console = Out::default();
            let mut reader = || lines.next_line();
            let mut clock = fixed_clock(&[start, start + Duration::from_millis(99_500)]);
            let err = run_init_confirmation(
                Some(start + Duration::from_secs(100)),
                &mut console,
                &mut reader,
                TEST_PHRASE,
                &mut clock,
            )
            .unwrap_err();
            assert_eq!(err.code(), "sys_tty_budget");
            assert_eq!(lines.reads, 1);
            assert!(!console.out.contains("within 0 seconds"));
            assert_eq!(console.out.matches("Type it exactly as shown").count(), 1);
            assert!(init_ceremony_prompt(TEST_PHRASE, 1, true).ends_with(" within 1 second: "));
        }
    }
}
