//! `central-adapter-linux` — the Linux platform adapter: protected-broker
//! protocol, `memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`,
//! PAM/TTY, namespaces, cgroups. One of the two audited `unsafe` sites
//! (rustix safe wrappers only — rust-engineering-workflow.md §5.2).
//!
//! R3 pull-forwards:
//!
//! - [`workspace_seal`] — the `central-harness` `WorkspaceSealer` port
//!   (D2): `openat2`-confined ACL/seal/capture for untrusted clones.
//! - [`dev_bootstrap`] — the `central-session` `ProtectedBootstrap` port
//!   (D1): the dev-gated file-backed candidate registry standing in for
//!   the R5 protected broker.

pub mod dev_bootstrap;
pub mod workspace_seal;
