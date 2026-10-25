//! `pam_linux.go`'s TTY half — the physical-console ceremonies. Every
//! phrase is built from helper-owned scope; no request payload reaches
//! any prompt (upstream's invariant, kept byte-exact where the prompt
//! text itself is protocol).

use super::PeerIdentity;
use crate::sys::tty::{self, phrase};
use central_foundation::failure::Failure;
use std::io::Write;
use std::os::unix::io::{AsFd, BorrowedFd};
use std::time::Instant;

fn peer_pid(peer: PeerIdentity) -> Result<rustix::process::Pid, Failure> {
    if !peer.available() {
        return Err(Failure::denied(
            "sys_tty_console_unfit",
            "tty_ceremony: Unix peer is unavailable",
        ));
    }
    rustix::process::Pid::from_raw(peer.pid).ok_or_else(|| {
        Failure::denied(
            "sys_tty_console_unfit",
            "tty_ceremony: Unix peer is unavailable",
        )
    })
}

/// The shared ceremony body: open the peer's physical console, write the
/// preamble plus `%q`-quoted phrase, read one bounded line, exact match.
fn scoped_ceremony(
    peer: PeerIdentity,
    deadline: Option<Instant>,
    preamble: &str,
    expected: &str,
) -> Result<(), Failure> {
    let pid = peer_pid(peer)?;
    let mut console = tty::open_physical_tty(pid)?;
    console
        .write_all(format!("{preamble}Type \"{expected}\" to continue: ").as_bytes())
        .map_err(|e| {
            Failure::unavailable(
                "sys_tty_console_write",
                format!("tty_ceremony: prompt: {e}"),
            )
        })?;
    let line = tty::read_ceremony_line(&console, deadline, None::<BorrowedFd<'_>>)?;
    if !phrase::confirmation_phrase_matches(&line, expected) {
        return Err(Failure::denied(
            "sys_tty_mismatch",
            "tty_ceremony: confirmation mismatch",
        ));
    }
    Ok(())
}

/// `PerformTTYCeremony` — `CONFIRM <code>[ <target>]`.
pub fn perform_tty_ceremony(
    peer: PeerIdentity,
    deadline: Option<Instant>,
    _operation_id: &str,
    target: &str,
) -> Result<(), Failure> {
    let pid = peer_pid(peer)?;
    let mut console = tty::open_physical_tty(pid)?;
    let code = tty::random_confirmation_code()?;
    let expected = if target.is_empty() {
        format!("CONFIRM {code}")
    } else {
        format!("CONFIRM {code} {}", target.trim())
    };
    console
        .write_all(
            format!("Central privileged action. Type \"{expected}\" to continue: ").as_bytes(),
        )
        .map_err(|e| {
            Failure::unavailable(
                "sys_tty_console_write",
                format!("tty_ceremony: prompt: {e}"),
            )
        })?;
    let line = tty::read_ceremony_line(&console, deadline, None::<BorrowedFd<'_>>)?;
    if line.trim() != expected {
        return Err(Failure::denied(
            "sys_tty_mismatch",
            "tty_ceremony: confirmation mismatch",
        ));
    }
    Ok(())
}

/// `PerformInitTTYCeremony` — `CONFIRM <code> init` through the
/// scripted init dialog (one retry, bounded writes, input flush).
pub fn perform_init_tty_ceremony(
    peer: PeerIdentity,
    deadline: Option<Instant>,
) -> Result<(), Failure> {
    let pid = peer_pid(peer)?;
    let mut console = tty::open_physical_tty(pid)?;
    let code = tty::random_confirmation_code()?;
    let expected = phrase::init_confirmation_phrase(&code);
    // The read side holds its own duplicated descriptor so the console
    // can still be written between reads — the flush-and-retry path
    // needs both sides of the terminal, and Rust will not let one
    // descriptor borrow immutable and mutable at once.
    let read_fd = console.as_fd().try_clone_to_owned().map_err(|e| {
        Failure::unavailable(
            "sys_tty_console_dup",
            format!("tty_ceremony: dup console: {e}"),
        )
    })?;
    let mut read_line = move || tty::read_ceremony_line(&read_fd, deadline, None::<BorrowedFd<'_>>);
    tty::run_init_confirmation(
        deadline,
        &mut console,
        &mut read_line,
        &expected,
        &mut Instant::now,
    )
}

macro_rules! scoped_ceremonies {
    ($($name:ident => ($phrase:ident, $preamble:literal, $err:literal);)*) => {
        $(
            /// Upstream's same-named `Perform*TTYCeremony`: the distinct
            /// phrase of this one destructive act, so consent minted for
            /// any other act can never satisfy it.
            pub fn $name(
                peer: PeerIdentity,
                deadline: Option<Instant>,
                instance_id: &str,
                target_id: &str,
                operation_id: &str,
            ) -> Result<(), Failure> {
                if instance_id.is_empty() || target_id.is_empty() || operation_id.is_empty() {
                    return Err(Failure::invalid("sys_tty_scope", concat!("tty_ceremony: ", $err, " confirmation scope is incomplete")));
                }
                let expected = phrase::$phrase(instance_id, target_id, operation_id);
                scoped_ceremony(peer, deadline, $preamble, &expected)
            }
        )*
    };
}

scoped_ceremonies! {
    perform_migration_reset_tty_ceremony => (migration_reset_phrase, "Central destructive migration reset. ", "reset");
    perform_restore_apply_tty_ceremony => (restore_apply_phrase, "Central destructive restore. ", "restore");
    perform_restore_abandon_tty_ceremony => (restore_abandon_phrase, "Central irreversible restore abandonment: this restore is dead and its data is given up. ", "abandon");
    perform_wipe_tty_ceremony => (wipe_phrase, "Central irreversible protected-state wipe: all identity and trust material is destroyed. ", "wipe");
    perform_export_tty_ceremony => (export_phrase, "Central portable export: identity and key material leave this host in an encrypted bundle. ", "export");
    perform_import_tty_ceremony => (import_phrase, "Central portable import: foreign data replaces this fresh instance's whole state. ", "import");
    perform_delete_tty_ceremony => (delete_phrase, "Central backup delete: the sealed backup is destroyed permanently. ", "delete");
    perform_prune_tty_ceremony => (prune_phrase, "Central artifact prune: every body in the named plan is destroyed permanently. ", "prune");
    perform_rescue_tty_ceremony => (rescue_phrase, "Central security rescue: a denied instance is re-armed and every mutation reopens. ", "rescue");
    perform_maintenance_apply_tty_ceremony => (maintenance_apply_phrase, "Central maintenance patch: the instance's authorized dependency pin is re-recorded. ", "maintenance-apply");
}
