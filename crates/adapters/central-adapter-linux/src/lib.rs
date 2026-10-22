//! `central-adapter-linux` — the Linux platform adapter: protected-broker
//! protocol, `memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`,
//! PAM/TTY, namespaces, cgroups. One of the two audited `unsafe` sites
//! (rustix safe wrappers only — rust-engineering-workflow.md §5.2).
//!
//! Stub crate: implementations land in this adapter's R-slice
//! (rust-application-boundaries.md §2.4).
