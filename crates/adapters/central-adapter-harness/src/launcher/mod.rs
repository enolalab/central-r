//! The `central-harness-launcher` client boundary (ADR 0036, harness
//! phase 2b spec decisions 5, 6 and 15).
//!
//! - [`protocol`] — the CHL1 v1 frame codec, byte-for-byte
//!   `cmd/central-harness-launcherd/PROTOCOL.md`. A pure codec: it
//!   performs no I/O and is shared with the `central-harness-launcherd`
//!   binary.
//! - [`client`] — [`client::HostLauncher`], the production
//!   `port::ProcessLauncher`: it maps a `port::ProcessSpec` onto the
//!   closed LAUNCH request and a launched session onto `port::Process`
//!   over an injected [`client::LauncherClient`]. The concrete
//!   `AF_UNIX`/`SOCK_SEQPACKET` + `SCM_RIGHTS` transport is an audited
//!   OS-syscall boundary and lives outside this crate
//!   (rust-application-boundaries.md §2.1).

pub mod client;
pub mod protocol;
