//! `unshare(2)`/`setns(2)` — upstream `internal/sandbox/launcher_linux.go`'s
//! `SysProcAttr.Cloneflags`/`Unshareflags` sets, expressed as a closed
//! `CLONE_NEW*` flag vocabulary.
//!
//! Upstream spawns the sandboxed process with
//! `Cloneflags: CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWCGROUP|
//! CLONE_NEWIPC|CLONE_NEWUTS` (the namespaces the child is created in)
//! and `Unshareflags: CLONE_NEWNS|CLONE_NEWNET` (what the child unshares
//! for itself pre-exec). A Rust launcher performs the same split by
//! calling [`unshare`] before spawning the worker — `unshare`'s
//! `CLONE_NEWPID` applies to the next children, matching the clone-flag
//! semantics — or enters an existing namespace with [`enter`].
//!
//! [`NamespaceFlags`] exists to keep `unshare` safe: rustix exposes the
//! call only as `unsafe fn unshare_unsafe` because `CLONE_FILES`/
//! `CLONE_FS` detach the caller's descriptor table. This module's flag
//! type admits `CLONE_NEW*` bits and nothing else, so the audited
//! wrapper (`sys::audited::unshare`) can prove that hazard unreachable.

use std::ops::BitOr;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;
use rustix::thread::{LinkNameSpaceType, UnshareFlags};

use crate::sys::audited;

/// A set of `CLONE_NEW*` namespace flags for [`unshare`]. The private
/// constructor admits only `CLONE_NEW*` bits — `CLONE_FILES`,
/// `CLONE_FS`, `CLONE_SYSVSEM` and every non-namespace flag are
/// unrepresentable — which is what makes the `unshare` call site safe.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct NamespaceFlags(UnshareFlags);

impl NamespaceFlags {
    /// No namespaces.
    pub const NONE: Self = Self(UnshareFlags::empty());
    /// `CLONE_NEWCGROUP` — cgroup namespace.
    pub const NEWCGROUP: Self = Self(UnshareFlags::NEWCGROUP);
    /// `CLONE_NEWIPC` — System V IPC / POSIX message-queue namespace.
    pub const NEWIPC: Self = Self(UnshareFlags::NEWIPC);
    /// `CLONE_NEWNET` — network namespace.
    pub const NEWNET: Self = Self(UnshareFlags::NEWNET);
    /// `CLONE_NEWNS` — mount namespace.
    pub const NEWNS: Self = Self(UnshareFlags::NEWNS);
    /// `CLONE_NEWPID` — PID namespace (applies to subsequent children).
    pub const NEWPID: Self = Self(UnshareFlags::NEWPID);
    /// `CLONE_NEWTIME` — time namespace.
    pub const NEWTIME: Self = Self(UnshareFlags::NEWTIME);
    /// `CLONE_NEWUSER` — user namespace (unprivileged gateway to the rest).
    pub const NEWUSER: Self = Self(UnshareFlags::NEWUSER);
    /// `CLONE_NEWUTS` — hostname/domainname namespace.
    pub const NEWUTS: Self = Self(UnshareFlags::NEWUTS);
    /// Every flag this type can represent — the mask `sys::audited`
    /// proves `bits()` against.
    pub const ALL: Self = Self(
        UnshareFlags::NEWCGROUP
            .union(UnshareFlags::NEWIPC)
            .union(UnshareFlags::NEWNET)
            .union(UnshareFlags::NEWNS)
            .union(UnshareFlags::NEWPID)
            .union(UnshareFlags::NEWTIME)
            .union(UnshareFlags::NEWUSER)
            .union(UnshareFlags::NEWUTS),
    );

    /// Upstream `SysProcAttr.Cloneflags` — the full isolation set a
    /// sandboxed worker is created in: PID, mount, network, cgroup,
    /// IPC and UTS namespaces.
    pub const SANDBOX_CREATE: Self = Self(
        UnshareFlags::NEWPID
            .union(UnshareFlags::NEWNS)
            .union(UnshareFlags::NEWNET)
            .union(UnshareFlags::NEWCGROUP)
            .union(UnshareFlags::NEWIPC)
            .union(UnshareFlags::NEWUTS),
    );

    /// Upstream `SysProcAttr.Unshareflags` — the namespaces the
    /// launcher unshares for itself before exec: mount and network.
    pub const SANDBOX_UNSHARE: Self = Self(UnshareFlags::NEWNS.union(UnshareFlags::NEWNET));

    /// The raw `CLONE_NEW*` bits. `pub(crate)` so only `sys::audited`
    /// can hand them to `unshare_unsafe`.
    pub(crate) const fn bits(self) -> UnshareFlags {
        self.0
    }
}

impl BitOr for NamespaceFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0.union(rhs.0))
    }
}

/// `unshare(flags)` — disassociate `flags` namespaces from the calling
/// thread. `CLONE_NEWPID` affects subsequent children only; the rest
/// take effect immediately. Needs `CAP_SYS_ADMIN` in the target
/// namespace's owning user namespace — for an unprivileged caller,
/// `NEWUSER` first, then the rest.
///
/// # Errors
/// `EPERM` without the required capability (the common non-root
/// outcome, unless a user namespace is entered first); `EINVAL` for a
/// flag combination the kernel rejects; `ENOMEM` on namespace-table
/// exhaustion.
pub fn unshare(flags: NamespaceFlags) -> Result<(), Errno> {
    audited::unshare(flags)
}

/// `setns(fd, nstype)` — reassociate the calling thread with the
/// namespace `fd` refers to (`/proc/<pid>/ns/*` or a bind mount of one).
/// `ns` pins the expected type; `None` accepts any (upstream's
/// `setns(fd, 0)` form).
///
/// # Errors
/// `EBADF` when `fd` is not a namespace descriptor; `EINVAL` when the
/// type does not match or the transition is not allowed; `EPERM`
/// without `CAP_SYS_ADMIN` over the target namespace.
pub fn enter(fd: BorrowedFd<'_>, ns: Option<LinkNameSpaceType>) -> Result<(), Errno> {
    rustix::thread::move_into_link_name_space(fd, ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flag vocabulary pins upstream's clone/unshare sets exactly:
    /// `launcher_linux.go:56-57` (Cloneflags) and `:67` (Unshareflags).
    #[test]
    fn sandbox_flag_sets_match_upstream() {
        assert_eq!(
            NamespaceFlags::SANDBOX_CREATE.bits(),
            UnshareFlags::NEWPID
                | UnshareFlags::NEWNS
                | UnshareFlags::NEWNET
                | UnshareFlags::NEWCGROUP
                | UnshareFlags::NEWIPC
                | UnshareFlags::NEWUTS
        );
        assert_eq!(
            NamespaceFlags::SANDBOX_UNSHARE.bits(),
            UnshareFlags::NEWNS | UnshareFlags::NEWNET
        );
        // Every representable flag is a CLONE_NEW* flag — the
        // unsafe-excluding property sys::audited's SAFETY proof needs.
        let non_new = UnshareFlags::FILES | UnshareFlags::FS | UnshareFlags::SYSVSEM;
        assert_eq!(NamespaceFlags::ALL.bits() & non_new, UnshareFlags::empty());
    }

    /// `unshare(NEWPID | NEWNS | NEWNET | …)` without `CAP_SYS_ADMIN`
    /// must be a clean `EPERM`, never a crash — the exact shape the
    /// launcher's privilege gate relies on. Run in a re-exec'd child:
    /// a successful unshare would mutate the shared test process.
    #[test]
    fn unshare_eperm_or_success_in_child() {
        if std::env::var_os("CENTRAL_SYS_PROBE").is_none() {
            return; // parent mode: spawned below
        }
        match unshare(NamespaceFlags::SANDBOX_CREATE) {
            // Unprivileged: the only honest refusal.
            Err(Errno::PERM) => std::process::exit(0),
            // Root or an encompassing user namespace: the call is
            // legitimate — the child just exits, taking the fresh
            // namespaces with it.
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("unshare(SANDBOX_CREATE) failed with {e}, want EPERM or success");
                std::process::exit(1);
            }
        }
    }

    /// The parent half of `unshare_eperm_or_success_in_child`: the
    /// child must exit 0 (it asserted the `EPERM`-or-success contract).
    #[test]
    fn unshare_denied_or_applied() {
        let status =
            crate::sys::probe::run("sys::namespace::tests::unshare_eperm_or_success_in_child");
        assert!(status.success(), "unshare child failed: {status:?}");
    }
}
