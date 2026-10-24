//! Serve-side runtime adapters — the kernel's production
//! implementations of the capability ports that upstream's
//! `cmd/central` composition wires from `time`/`context`/slog.
//!
//! [`TokioClock`] is the wall clock every composed service stamps
//! with; [`TokioTicker`] is the orchestrator and dispatcher's
//! one-shot timer; [`TokenCancel`] is the serve-stop signal each
//! spawned attempt observes; [`TracingDispatchLog`] routes the
//! dispatcher's `warn`/`info` lines into `tracing`.

use std::sync::Arc;
use std::time::Duration;

use central_harness::app::dispatcher::DispatchLog;
use central_harness::app::ports::{CancelSignal, Clock, Ticker};
use central_harness::port::PortFuture;
use time::{OffsetDateTime, SignedDuration};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Clock — upstream's `time.Now`.
// ---------------------------------------------------------------------------

/// The production wall clock — upstream `time.Now` over
/// [`OffsetDateTime::now_utc`]. Implements the harness dispatcher's
/// `app.Clock` and the execution service's `port.Clock`; both stamp
/// durable rows with the same UTC instant.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioClock;

impl Clock for TokioClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

impl central_execution::port::Clock for TokioClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

// ---------------------------------------------------------------------------
// Ticker — upstream's `time.NewTimer`.
// ---------------------------------------------------------------------------

/// The production one-shot timer — upstream `time.NewTimer`/`time.After`
/// over `tokio::time::sleep`. Re-armed per call; a dropped future is the
/// stopped timer, matching the port contract.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioTicker;

impl Ticker for TokioTicker {
    /// A non-positive duration resolves immediately — upstream's
    /// `time.NewTimer` fires at once for `d <= 0`.
    fn after<'a>(&'a self, d: SignedDuration) -> PortFuture<'a, ()> {
        let d = std::time::Duration::try_from(d).unwrap_or(Duration::ZERO);
        Box::pin(tokio::time::sleep(d))
    }
}

// ---------------------------------------------------------------------------
// CancelSignal — upstream's `ctx.Done()`.
// ---------------------------------------------------------------------------

/// The serve-stop signal — upstream `context.Context` over a
/// [`CancellationToken`]. The profile's supervisor cancels the token;
/// every in-flight attempt observes it through `cancelled()`.
#[derive(Debug, Clone)]
pub struct TokenCancel {
    token: CancellationToken,
}

impl TokenCancel {
    /// Wraps `token`. Cancelling the token cancels the signal; child
    /// tokens cancel their own signal without touching the parent.
    pub fn new(token: CancellationToken) -> Self {
        Self { token }
    }

    /// The wrapped token, for composition that also needs the
    /// `tokio_util` half (e.g. passing the same stop to a listener).
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

impl CancelSignal for TokenCancel {
    fn cancelled(&self) -> PortFuture<'_, ()> {
        let token = self.token.clone();
        Box::pin(async move { token.cancelled().await })
    }

    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

// ---------------------------------------------------------------------------
// DispatchLog — upstream's `*slog.Logger` over `tracing`.
// ---------------------------------------------------------------------------

/// Routes the dispatcher's structured `warn`/`info` lines into
/// `tracing`. Upstream's `logger.Warn(msg, fields...)` carries flat
/// `&str` key/value pairs; this sink emits them as `debug` fields so
/// the line keeps its shape under any `fmt` subscriber.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingDispatchLog;

impl DispatchLog for TracingDispatchLog {
    fn warn(&self, msg: &str, fields: &[(&str, String)]) {
        // Upstream's key/value fields ride as one compact string: the
        // dispatcher already bounds every value, and `tracing`'s
        // `debug` formatting keeps the pairs greppable without pulling
        // a `valuable` dep into the kernel.
        let rendered = render_fields(fields);
        if rendered.is_empty() {
            tracing::warn!(target: "central.harness.dispatch", "{msg}");
        } else {
            tracing::warn!(target: "central.harness.dispatch", "{msg} {rendered}");
        }
    }

    fn info(&self, msg: &str, fields: &[(&str, String)]) {
        let rendered = render_fields(fields);
        if rendered.is_empty() {
            tracing::info!(target: "central.harness.dispatch", "{msg}");
        } else {
            tracing::info!(target: "central.harness.dispatch", "{msg} {rendered}");
        }
    }
}

fn render_fields(fields: &[(&str, String)]) -> String {
    let mut out = String::new();
    for (k, v) in fields {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

// ---------------------------------------------------------------------------
// TaskEventSink — upstream `harnessMilestones`.
// ---------------------------------------------------------------------------

/// Upstream `harnessMilestones` — maps every dispatcher/orchestrator
/// [`Milestone`] onto the task event log writer. Appends are
/// best-effort: the caller logs a failure and never fails the attempt.
#[derive(Debug, Clone)]
pub struct ServeTaskEventSink {
    store: Arc<central_adapter_postgres::task::MilestoneStore>,
}

impl ServeTaskEventSink {
    /// Binds the sink to the composed milestone store.
    pub fn new(store: Arc<central_adapter_postgres::task::MilestoneStore>) -> Self {
        Self { store }
    }
}

impl central_harness::app::ports::TaskEventSink for ServeTaskEventSink {
    /// Upstream `Record` — `Append` dedups on `key`, so a repeated
    /// milestone is a no-op, including a concurrent unique-race loser.
    fn record<'a>(
        &'a self,
        m: central_harness::app::ports::Milestone,
    ) -> PortFuture<'a, Result<(), central_foundation::failure::Failure>> {
        Box::pin(async move {
            let attempt_id = if m.step_attempt_id.is_nil() {
                None
            } else {
                Some(m.step_attempt_id)
            };
            self.store
                .append(&central_adapter_postgres::task::Milestone {
                    key: m.key,
                    kind: m.kind.as_str().to_string(),
                    workspace_id: m.workspace_id,
                    task_id: m.task_id,
                    run_id: m.run_id,
                    attempt_id,
                    status: m.status,
                    reason: m.reason,
                    at: m.at,
                })
                .await
        })
    }
}

/// Convenience bundle — the four adapters serve composition hands to
/// the harness chain in one place.
#[derive(Debug, Clone)]
pub struct ServeRuntime {
    /// The shared wall clock.
    pub clock: Arc<TokioClock>,
    /// The shared timer.
    pub ticker: Arc<TokioTicker>,
    /// The dispatcher's log sink.
    pub log: Arc<TracingDispatchLog>,
}

impl ServeRuntime {
    /// Upstream's `time.Now`/`time.NewTimer`/`slog.Default` wiring.
    pub fn new() -> Self {
        Self {
            clock: Arc::new(TokioClock),
            ticker: Arc::new(TokioTicker),
            log: Arc::new(TracingDispatchLog),
        }
    }
}

impl Default for ServeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokio_clock_returns_utc_now() {
        let c = TokioClock;
        let before = OffsetDateTime::now_utc();
        let at = Clock::now(&c);
        let after = OffsetDateTime::now_utc();
        assert!(at >= before && at <= after);
        // The execution trait resolves to the same instant source.
        let exec_at = central_execution::port::Clock::now(&c);
        assert!(exec_at >= at && exec_at <= OffsetDateTime::now_utc());
    }

    #[tokio::test]
    async fn tokio_ticker_resolves_after_delay() {
        let t = TokioTicker;
        let start = std::time::Instant::now();
        t.after(SignedDuration::new(0, 5_000_000)).await;
        assert!(start.elapsed() >= Duration::from_millis(5));
        // A non-positive duration resolves immediately.
        let at = std::time::Instant::now();
        t.after(SignedDuration::ZERO).await;
        assert!(at.elapsed() < Duration::from_millis(50));
        // A dropped future is the stopped timer: nothing panics and
        // nothing resolves late on a dead receiver.
    }

    #[tokio::test]
    async fn token_cancel_observes_token_cancellation() {
        let token = CancellationToken::new();
        let signal = TokenCancel::new(token.clone());
        assert!(!signal.is_cancelled());
        token.cancel();
        assert!(signal.is_cancelled());
        signal.cancelled().await; // resolves promptly once cancelled
    }

    #[tokio::test]
    async fn token_cancel_pends_until_cancelled() {
        let token = CancellationToken::new();
        let signal = TokenCancel::new(token.clone());
        tokio::select! {
            () = signal.cancelled() => panic!("uncancelled token resolved"),
            () = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }

    #[test]
    fn tracing_dispatch_log_renders_fields() {
        assert_eq!(
            render_fields(&[("run", "r1".to_string()), ("reason", "X".to_string())]),
            "run=r1 reason=X"
        );
        assert_eq!(render_fields(&[]), "");
    }
}
