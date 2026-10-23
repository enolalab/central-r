//! The domain-facing seams over the canonical orchestration journal —
//! pure port of `central/internal/eventjournal/port/port.go`. No
//! adapter types cross this boundary; every trait is
//! `#[trait_variant::make(Send)]` with `Send + Sync + 'static` so trait
//! objects compose with multi-threaded `tokio`/`axum` handlers
//! (rust-application-boundaries.md §2.3), and every error is the
//! workspace-wide [`central_foundation::failure::Failure`].

use central_foundation::failure::Failure;

use crate::domain::RunEvent;

/// The append-only seam to the canonical per-run orchestration journal
/// (upstream `Writer`). Implementations allocate the per-run monotonic
/// `seq` inside the write transaction (spec-6 OQ-1: the run-row
/// `FOR UPDATE` lock serializes writers) and dedupe redelivery on
/// `event_id`, returning the existing row's `seq`. There is no update
/// or delete path.
///
/// The postgres adapter additionally exposes a tx-scoped append so a
/// node transition and its journal event commit atomically; that
/// method takes adapter types by design and is not part of this
/// trait.
#[trait_variant::make(Send)]
pub trait Writer: Send + Sync + 'static {
    /// Writes one event and returns its allocated per-run `seq`.
    /// Appending an `event_id` that already exists returns the
    /// existing row's `seq` (`DUPLICATE_EVENT_ID` semantics) without
    /// error.
    async fn append(&self, event: RunEvent) -> Result<i64, Failure>;
}

/// The boxed `Send` future a [`Consumer`] method returns. `Consumer` is
/// hand-written rather than `#[trait_variant::make(Send)]` exactly so it
/// stays `dyn`-compatible — the publisher's registered consumers are a
/// heterogeneous `Vec<Arc<dyn Consumer>>` — while still carrying the
/// §2.3-required explicit `+ Send` future bounds (the `ByteStream`
/// precedent in `central-artifact`).
pub type ConsumerFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Failure>> + Send + 'a>>;

/// The domain-facing delivery seam of the transactional outbox
/// (upstream `Consumer`, spec-5 section 3): the publisher drains
/// `event_outbox` rows in `(run_id, seq)` order and delivers each
/// journaled event to every registered consumer.
///
/// Delivery is AT-LEAST-ONCE. A crash between delivery and the
/// `published_at` mark redelivers the event, so every consumer MUST
/// dedupe on [`RunEvent::id`] — that is the dedup point the boundary
/// map assigns to event publication. [`consume`](Self::consume)
/// returning an error leaves the row unpublished (`publish_attempts`
/// still counts the attempt) so the next drain pass redelivers;
/// consumers must be fast, because they run inside the publisher's
/// claim transaction. Readiness recomputation is NOT an outbox
/// consumer — it stays synchronous inside the transition path;
/// consumers are feeds (journal/UI) where a lag is observable, never
/// incorrect.
pub trait Consumer: Send + Sync + 'static {
    /// Delivers one journaled event. `Ok` allows the outbox row's
    /// `published_at` mark; `Err` leaves the row unpublished for the
    /// next drain pass.
    fn consume<'a>(&'a self, event: &'a RunEvent) -> ConsumerFuture<'a>;
}

/// `Arc<dyn Consumer>` (and `Arc` of any consumer) is itself a consumer
/// — the dedup decorator wraps consumers held behind an `Arc`.
impl<T: Consumer + ?Sized> Consumer for std::sync::Arc<T> {
    fn consume<'a>(&'a self, event: &'a RunEvent) -> ConsumerFuture<'a> {
        (**self).consume(event)
    }
}
