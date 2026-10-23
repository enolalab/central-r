//! `central-adapter-harness` — Claude Code, OpenCode, Codex, and
//! Antigravity adapters implementing `central-harness` port traits, plus
//! `gitclone` and the launcher client.
//!
//! This slice lands the adapter runtime core:
//!
//! - [`process`] — shared process-boundary helpers: the bounded NDJSON
//!   frame reader, the probe read cap, the wait-after-close exit grace,
//!   the detached kill ladder, and single-assignment result cells.
//! - [`launcher`] — the CHL1 v1 wire codec ([`launcher::protocol`], a pure
//!   codec shared with `central-harness-launcherd`) and
//!   [`launcher::client::HostLauncher`], the production
//!   `port::ProcessLauncher` mapping a `ProcessSpec` onto the closed
//!   LAUNCH request over an injected [`launcher::client::LauncherClient`].
//! - [`localexec`] — the development/test `port::ProcessLauncher`, gated
//!   by the explicit dev gate (issue #120).
//! - [`fake`] — scripted `port::Adapter`/`port::ProcessLauncher` test
//!   doubles.

pub mod antigravity;
pub mod claudecode;
pub mod codex;
pub mod fake;
pub mod gitclone;
pub mod launcher;
pub mod localexec;
pub mod opencode;
pub mod process;

/// `json` — the byte-level JSON machinery shared by the adapters:
/// raw member spans, `json.Compact`, and the duplicate-member-name
/// walk. Lifted out of `claudecode` (its upstream home) so the
/// OpenCode, Codex and Antigravity ports share it unchanged.
mod json;
