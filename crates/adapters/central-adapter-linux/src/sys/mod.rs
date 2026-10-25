//! `sys` — the audited Linux OS boundary of `central-adapter-linux`
//! (workflow §5.2; R5 task 4). The primitives the protected broker and
//! the sandbox launcher are built from, ported from upstream
//! `internal/adapter/authority/broker/hardening.go`,
//! `handoff_linux.go`, `protected_file_linux.go` and
//! `internal/sandbox/{envelope_linux,launcher_linux,path_resolve}.go`.
//!
//! Every call runs through `rustix` safe wrappers. The one site rustix
//! 1.1 has no safe API for — the `seccomp(2)` `SECCOMP_SET_MODE_FILTER`
//! install, plus the `unshare(2)` wrapper rustix only exposes as an
//! `unsafe fn` — lives in [`audited`], the single module this subtree
//! permits `unsafe` in; each `unsafe` block there carries a `// SAFETY:`
//! proof. Every other submodule is `forbid(unsafe_code)`, so a raw
//! syscall can only ever compile inside `audited`.
//!
//! Module map (upstream provenance):
//!
//! - [`memfd`] — sealed-memfd handoff descriptors (`handoff_linux.go`,
//!   plus the `validateProvisionedDescriptorFD`/`ReceiveDescriptor`
//!   fd-shape checks of `server.go`/`secret_bootstrap_transport_linux.go`)
//! - [`scm_rights`] — `sendmsg`/`recvmsg` descriptor passing
//! - [`peercred`] — `SO_PEERCRED` peer identity
//! - [`openat2`] — `openat2`-confined path resolution
//!   (`path_resolve.go`, `protected_file_linux.go`)
//! - [`pidfd`] — pidfd open/identify/liveness
//! - [`hardening`] — `Harden()` minus seccomp: `mlockall`,
//!   `PR_SET_DUMPABLE`, `PR_CAPBSET_DROP`, `PR_SET_NO_NEW_PRIVS`
//! - [`seccomp`] — the default-deny `sock_fprog` filter, byte-for-byte
//!   the upstream allow-list and program shape (`hardening.go`)
//! - [`cgroup`] — cgroup v2 limit writes (`envelope_linux.go`,
//!   `launcher_linux.go`)
//! - [`namespace`] — `unshare`/`setns` (`launcher_linux.go`'s clone and
//!   unshare flag sets)

/// The one audited `unsafe` site — `unsafe` is permitted inside this
/// module only (`#![allow(unsafe_code)]` at its top; the crate's
/// `unsafe_code` level is `deny` and every sibling is `forbid`). Raw
/// call sites appear only where rustix has no safe wrapper, each behind
/// a named safe wrapper with a `// SAFETY:` proof.
pub(crate) mod audited;

#[forbid(unsafe_code)]
pub mod cgroup;
#[forbid(unsafe_code)]
pub mod hardening;
#[forbid(unsafe_code)]
pub mod memfd;
#[forbid(unsafe_code)]
pub mod namespace;
#[forbid(unsafe_code)]
pub mod openat2;
#[forbid(unsafe_code)]
pub mod peercred;
#[forbid(unsafe_code)]
pub mod pidfd;
#[forbid(unsafe_code)]
pub mod scm_rights;
#[forbid(unsafe_code)]
pub mod seccomp;

/// Re-exec probe harness for the stateful-boundary tests
/// (seccomp/namespace/hardening): a `#[test]` that mutates the
/// process it runs in — installing a filter, unsharing a namespace,
/// flipping `no_new_privs` — must not run inside the shared test
/// binary. Upstream's `hardening_filter_test.go` solves the same
/// problem by re-exec'ing a probe binary per mode; this is the Rust
/// shape of that: the child test checks `CENTRAL_SYS_PROBE` and does
/// the real work only when set, and the parent test spawns the test
/// binary on exactly that test and asserts its exit status.
#[cfg(test)]
pub(crate) mod probe;
