//! The event journal's process-level components — the port of
//! `central/internal/eventjournal/app` (packet P2D06, spec-5 section 3
//! plus its OQ-1/OQ-3 defaults): the in-process transactional-outbox
//! [`publisher::Publisher`] that drains `central.event_outbox` inside
//! `central serve`, next to the scheduler's sweeper and the checkpoint
//! janitor, and the shipped [`consumers`] set.
//!
//! Capability crates never write logs directly (the workspace's
//! observability rule): the `*slog.Logger` seams upstream takes are
//! expressed here as the [`EventLog`] port the kernel's tracing-backed
//! adapter implements; `None` discards, matching upstream's nil
//! fallback only in that no record is emitted.

pub mod consumers;
pub mod publisher;

/// The structured-log seam behind the publisher's warnings and the
/// feed consumer's per-event line — upstream `*slog.Logger` (`nil`
/// falls back to `slog.Default()`; here `Option<Arc<dyn EventLog>>`
/// with `None` discarding). Field keys are static names; values are
/// pre-rendered text so the port carries no attribute-type surface.
///
/// The kernel composition installs a `tracing`-backed implementation;
/// tests capture the records verbatim.
pub trait EventLog: Send + Sync + 'static {
    /// One info-level record — the per-event feed line.
    fn info(&self, message: &'static str, fields: &[(&'static str, String)]);
    /// One warn-level record — drain/probe/GC failures and the
    /// `OUTBOX_PUBLISH_STALLED` signal.
    fn warn(&self, message: &'static str, fields: &[(&'static str, String)]);
}
