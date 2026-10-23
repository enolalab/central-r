//! `central-harness` — the ADR 0035 harness control plane: the
//! harness-session-attempt lifecycle Central supervises around one launch
//! or resume of an external coding-agent harness (Claude Code, OpenCode,
//! Codex, Antigravity) for one Run. Central never owns or alters the
//! harness's own agent loop and never handles harness credentials. Pure
//! port of `central/internal/harness` — no `sqlx`, no `tokio`, no `uuid`.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2); this
//! slice lands the pure domain modules:
//!
//! - [`domain`] — vocabularies and value types: [`domain::Kind`],
//!   [`domain::State`], [`domain::PermissionPolicy`], [`domain::Fence`],
//!   [`domain::Workspace`], [`domain::Terminal`], [`domain::Resolution`],
//!   and the [`domain::codes`] stable machine codes standing in for
//!   upstream's `errors.Is` sentinels.
//! - [`attempt`] — [`attempt::Attempt`], the per-Run aggregate with its
//!   pure mutators ([`attempt::Attempt::launch`],
//!   [`attempt::Attempt::reveal_session`], `…`) under the
//!   execution-lease fence.
//! - [`event`] — the sealed [`event::EventPayload`] vocabulary (12
//!   payload kinds), [`event::Usage`] normalization, and the
//!   [`event::Event`] envelope.
//! - [`record`] — [`record::EventRecord`], the bounded metadata persisted
//!   per event (no payload content), and [`record::record_of`].
//! - [`approval`] — [`approval::PermissionApproval`]: the durable
//!   operator permission gate with its keyed input MAC, open/decide/
//!   expire/supersede transitions.
//! - [`budget`] — [`budget::Budget`], the effective per-attempt bounds,
//!   and [`budget::sum_chain`]/[`budget::ChainCost::next`] chain-cost
//!   arithmetic.
//! - [`capability`] — [`capability::Capabilities`] adapter self-description;
//!   the [`event::UsageScope`] vocabulary it carries lives with
//!   [`event::Usage`].
//! - [`env`] — the launch-environment allowlist/denylist filter
//!   ([`env::validate_launch_env`]) enforcing ADR 0035's rule that Central
//!   never injects, relocates, or redirects harness credentials.
//! - [`recovery`] — [`recovery::attempt_id_for_step_attempt`] and
//!   [`attempt::Attempt::fail_unlaunched`] for the startup reconciler.

pub mod approval;
pub mod attempt;
pub mod budget;
pub mod capability;
pub mod domain;
pub mod env;
pub mod event;
pub mod record;
pub mod recovery;

#[cfg(test)]
pub(crate) mod testkit;
