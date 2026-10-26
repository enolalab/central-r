//! `central-adapter-linux` — the Linux platform adapter: protected-broker
//! protocol, `memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`,
//! PAM/TTY, namespaces, cgroups. One of the two audited `unsafe` sites
//! (rustix safe wrappers only — rust-engineering-workflow.md §5.2).
//!
//! The crate's `unsafe_code` lint is `deny`, not the workspace `forbid`,
//! so that `sys::audited` — the single audited `unsafe` site — can opt
//! back in. Every module below re-pins `forbid(unsafe_code)`: raw
//! syscalls can only ever compile inside `sys::audited`, behind a named
//! safe wrapper with a `// SAFETY:` proof.
//!
//! R3 pull-forwards:
//!
//! - [`workspace_seal`] — the `central-harness` `WorkspaceSealer` port
//!   (D2): `openat2`-confined ACL/seal/capture for untrusted clones.
//! - [`dev_bootstrap`] — the `central-session` `ProtectedBootstrap` port
//!   (D1): the dev-gated file-backed candidate registry standing in for
//!   the R5 protected broker.
//! - [`launcher_client`] — the production CHL1 transport: the
//!   `AF_UNIX`/`SOCK_SEQPACKET` + `SCM_RIGHTS` + `SO_PEERCRED` socket
//!   client upstream `internal/harnesslauncher/client_linux.go` carries.
//! - [`group_signals`] — the production `kill(-pgid, …)` boundary for
//!   the dev-gated `LocalExec` launcher.
//!
//! R5:
//!
//! - [`sys`] — the audited OS boundary primitives the protected broker
//!   and sandbox launcher are built from (R5 task 4).
//! - [`sandbox`] — the descriptor-bound sandbox launcher: the
//!   `central-agent` namespaced envelope, cgroup resource bounds, and
//!   the protected daemon's denial matrix (R5 task 9 / A06).

#[forbid(unsafe_code)]
pub mod backup_repository;
pub mod broker;
pub mod dev_bootstrap;
#[forbid(unsafe_code)]
pub mod dev_restore_barrier;
#[forbid(unsafe_code)]
pub mod dispatch_provision;
#[forbid(unsafe_code)]
pub mod genesis;
#[forbid(unsafe_code)]
pub mod group_signals;
pub mod helper;
#[forbid(unsafe_code)]
pub mod infra;
#[forbid(unsafe_code)]
pub mod launcher_client;
#[forbid(unsafe_code)]
pub mod lifecycle_watch;

pub mod migration_launcher;
#[forbid(unsafe_code)]
pub mod sandbox;
pub mod sys;
#[forbid(unsafe_code)]
pub mod workspace_seal;
