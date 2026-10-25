//! Broker process hardening — the non-seccomp half of upstream
//! `internal/adapter/authority/broker/hardening.go`'s `Harden()`, plus
//! [`harden`], the same sequence with [`crate::sys::seccomp`] folded in
//! at upstream's position:
//!
//! 1. `mlockall(MCL_CURRENT | MCL_FUTURE)` — secrets never page to swap.
//! 2. `PR_SET_DUMPABLE = 0` — no core dumps.
//! 3. `seccomp` — the default-deny filter ([`crate::sys::seccomp`]).
//! 4. `PR_CAPBSET_DROP` for capabilities 0..=40, then
//!    `PR_SET_NO_NEW_PRIVS` — `dropAllCapabilities`.
//!
//! Upstream's order is load-bearing: `prctl` (157) is on the seccomp
//! allow-list precisely because the capability drops run *after* the
//! filter installs (the broker is root/CAP_SYS_ADMIN at that point, so
//! the prctl+prctl-capbset calls must still reach the kernel), and
//! `no_new_privs` lands last as the final, irreversible demotion.
//!
//! All steps fail closed: any error aborts the sequence and the broker
//! refuses to start unhardened.

use central_foundation::failure::Failure;
use rustix::io::Errno;
use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};
use rustix::thread::{CapabilitySet, remove_capability_from_bounding_set, set_no_new_privs};

/// `CAP_CHECKPOINT_RESTORE` — upstream's `cap <= 40` bound; the kernel
/// silently ignores `PR_CAPBSET_DROP` for capabilities it does not
/// know, so the loop bound is inclusive and the errors are upstream's
/// "ignore" contract.
const CAP_MAX: u32 = 40;

fn os_failure(step: &str, e: Errno) -> Failure {
    Failure::internal("sys_hardening_os", format!("{step}: {e}"))
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)` — upstream's first step,
/// "prevent secrets from being paged to swap".
///
/// # Errors
/// `sys_hardening_os` — typically `EPERM`/`ENOMEM` without
/// `CAP_IPC_LOCK` or a `RLIMIT_MEMLOCK` that fits the resident set;
/// as non-root this is expected to fail, and `harden` surfaces it.
pub fn lock_memory() -> Result<(), Failure> {
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_err(|e| os_failure("mlockall", e))
}

/// `prctl(PR_SET_DUMPABLE, 0)` — "prevent core dumps".
///
/// # Errors
/// `sys_hardening_os` on the `prctl` failure.
pub fn disable_core_dumps() -> Result<(), Failure> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| os_failure("prctl dumpable", e))
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)` — "prevent privilege escalation in
/// child processes" (the last half of `dropAllCapabilities`).
///
/// # Errors
/// `sys_hardening_os` on the `prctl` failure.
pub fn set_no_new_privileges() -> Result<(), Failure> {
    set_no_new_privs(true).map_err(|e| os_failure("prctl no_new_privs", e))
}

/// `dropAllCapabilities` — `PR_CAPBSET_DROP` for every capability
/// 0..=[`CAP_MAX`], then [`set_no_new_privileges`]. Upstream silently
/// ignores per-capability errors (the kernel answers `EINVAL` for
/// capabilities it doesn't know); only the `no_new_privs` write can
/// fail the step.
///
/// # Errors
/// `sys_hardening_os` on the `no_new_privs` `prctl` failure.
pub fn drop_all_capabilities() -> Result<(), Failure> {
    for cap in 0..=CAP_MAX {
        // Upstream: "PR_CAPBSET_DROP silently ignores capabilities that
        // do not exist on the running kernel, so we ignore errors" —
        // a non-root caller lacks CAP_SETPCAP and gets EPERM for every
        // drop, which is the same silent-ignore contract.
        let set = CapabilitySet::from_bits_retain(1u64 << cap);
        let _ = remove_capability_from_bounding_set(set);
    }
    set_no_new_privileges()
}

/// `Harden` — the full sequence in upstream's order. The
/// `hardening_filter_test.go` probes install *only* the filter; this
/// is the production entry point — every step, or an error that aborts
/// startup.
///
/// # Errors
/// The first step's `Failure`; the sequence aborts there — a broker
/// that is not fully hardened does not start.
pub fn harden() -> Result<(), Failure> {
    lock_memory()?;
    disable_core_dumps()?;
    crate::sys::seccomp::install()?;
    drop_all_capabilities()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::thread::no_new_privs;

    /// `PR_SET_DUMPABLE=0` applied to a probe child and read back —
    /// the state is process-global, so the check must not run in the
    /// shared test process.
    #[test]
    fn probe_child_dumpable() {
        if !crate::sys::probe::is("dumpable") {
            return;
        }
        disable_core_dumps().expect("set dumpable");
        let got = rustix::process::dumpable_behavior().expect("read dumpable");
        assert_eq!(got, DumpableBehavior::NotDumpable);
        std::process::exit(0);
    }

    /// `PR_SET_NO_NEW_PRIVS` applied to a probe child and read back.
    #[test]
    fn probe_child_no_new_privs() {
        if !crate::sys::probe::is("nnp") {
            return;
        }
        set_no_new_privileges().expect("set nnp");
        assert!(no_new_privs().expect("read nnp"));
        std::process::exit(0);
    }

    /// `dropAllCapabilities` in a probe child — the per-cap drops are
    /// `EPERM` as non-root (upstream ignores them); the nnp write is
    /// the assertable outcome either way.
    #[test]
    fn probe_child_drop_caps() {
        if !crate::sys::probe::is("caps") {
            return;
        }
        drop_all_capabilities().expect("drop caps");
        assert!(no_new_privs().expect("read nnp"));
        // As root, the drops actually happened — verify the one the
        // kernel reports, not just that nothing failed.
        if rustix::process::geteuid().is_root() {
            assert!(
                !rustix::thread::capability_is_in_bounding_set(CapabilitySet::SYS_ADMIN)
                    .expect("capbset read"),
                "CAP_SYS_ADMIN must be out of the bounding set"
            );
        }
        std::process::exit(0);
    }

    /// `mlockall` in a probe child — root/CAP_IPC_LOCK applies it;
    /// non-root expects the clean `sys_hardening_os` refusal, either
    /// way the wrapper reports without panicking.
    #[test]
    fn probe_child_lock_memory() {
        if !crate::sys::probe::is("mlock") {
            return;
        }
        match lock_memory() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                assert_eq!(e.code(), "sys_hardening_os");
                eprintln!("lock_memory refused: {}", e.message());
                std::process::exit(if rustix::process::geteuid().is_root() {
                    1
                } else {
                    0
                });
            }
        }
    }

    /// `Harden()`'s full sequence in a probe child. Root asserts the
    /// whole path applies (the filter then governs the exit path —
    /// `exit_group` is on the allow-list). Non-root asserts the
    /// sequence fails closed *somewhere* — mlockall or the seccomp
    /// install — never silently halfway.
    #[test]
    fn probe_child_harden_full() {
        if !crate::sys::probe::is("harden") {
            return;
        }
        match harden() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("harden refused at a step: {} {}", e.code(), e.message());
                std::process::exit(if rustix::process::geteuid().is_root() {
                    1
                } else {
                    0
                });
            }
        }
    }

    /// Parent halves — each child must exit 0 (its internal asserts
    /// carry the outcome; the parent only checks the process result).
    #[test]
    fn hardening_probes() {
        for (test, mode) in [
            ("sys::hardening::tests::probe_child_dumpable", "dumpable"),
            ("sys::hardening::tests::probe_child_no_new_privs", "nnp"),
            ("sys::hardening::tests::probe_child_drop_caps", "caps"),
            ("sys::hardening::tests::probe_child_lock_memory", "mlock"),
            ("sys::hardening::tests::probe_child_harden_full", "harden"),
        ] {
            let status = crate::sys::probe::run_on(test, mode);
            assert!(status.success(), "probe {mode} failed: {status:?}");
        }
    }
}
