//! The in-process transactional-outbox drain — pure port of
//! `central/internal/eventjournal/app/publisher.go` (issue #95 slice
//! 2D, packet P2D06; spec-5 section 3 plus its OQ-1 and OQ-3 defaults).
//! Every interval the kernel-side supervisor runs one sequential
//! [`Publisher::publish_once`] pass: claim a batch, deliver each event
//! to every registered consumer, mark delivered rows published, then
//! probe the backlog for the stalled signal and GC published rows past
//! their retention.
//!
//! Upstream's `Publisher.Run`/`Shutdown` (the `time.Ticker` loop and
//! done-channel wait) is a kernel `Component` concern — the capability
//! crate carries the pass itself plus the [`Publisher::stalled`]
//! flag the health/readiness surfaces read, and [`Publisher::interval`]
//! the supervisor ticks on. TICK CONTRACT: upstream `Run` calls
//! `publishOnce` once at start BEFORE the ticker begins — the
//! supervisor must run one pass at component start, then tick every
//! `interval`. Passes never overlap by construction (one
//! `&self` call); a failed pass logs and retries on the next tick — an
//! outbox error must never kill the serve process, and transitions
//! never depend on publication (spec-5 failure semantics).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use central_foundation::failure::Failure;
use time::{Duration, OffsetDateTime};

use crate::app::EventLog;
use crate::domain::RunEvent;
use crate::port::Consumer;

/// The drain cadence when [`Publisher::interval`] is unset — spec-5's
/// "~5s" in-process drain (OQ-1: no external broker, the central daemon
/// owns publication). Upstream `DefaultPublishInterval`.
pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::seconds(5);
/// Bounds one drain pass's `SKIP LOCKED` claim — a latency bound, not a
/// correctness bound: leftover rows drain on the next tick. Upstream
/// `DefaultPublishBatchSize`.
pub const DEFAULT_PUBLISH_BATCH_SIZE: u64 = 256;
/// The OQ-3 keep-published window: rows are retained for replay/debug
/// for 7 days, then the same tick GCs them (`event_outbox` carries the
/// schema's second runtime `DELETE` grant for exactly this). Upstream
/// `DefaultPublishedRetention`.
pub const DEFAULT_PUBLISHED_RETENTION: Duration = Duration::days(7);
/// The `OUTBOX_PUBLISH_STALLED` depth threshold (spec-5 failure
/// semantics). Upstream `DefaultStalledDepth`.
pub const DEFAULT_STALLED_DEPTH: u64 = 1024;
/// The `OUTBOX_PUBLISH_STALLED` age threshold (spec-5 failure
/// semantics). Upstream `DefaultStalledAge`.
pub const DEFAULT_STALLED_AGE: Duration = Duration::minutes(15);

/// The stalled-signal reason code — a warn record plus the
/// [`Publisher::stalled`] flag, deliberately NOT a journaled event: a
/// wedged or crashed publisher must be able to raise it, and journal
/// writes depend on the run-lock path the stall may itself be
/// reporting on (upstream's documented choice for spec-5's "raises
/// OUTBOX_PUBLISH_STALLED").
pub const REASON_OUTBOX_PUBLISH_STALLED: &str = "OUTBOX_PUBLISH_STALLED";

/// The pending-depth probe result — upstream's
/// `(depth int, oldest time.Time)` pair. `oldest` is `None` when the
/// backlog is empty (upstream's zero `time.Time`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnpublishedBacklog {
    /// Pending (unpublished) `event_outbox` rows.
    pub depth: u64,
    /// The oldest pending row's `created_at`; `None` when empty.
    pub oldest: Option<OffsetDateTime>,
}

/// The per-event delivery callback the store invokes once per claimed
/// row inside its claim transaction — upstream's
/// `deliver func(context.Context, Event) error` parameter, expressed
/// as a trait so the publisher's fan-out is a named seam. A `nil`-
/// equivalent cannot exist: [`Result::Err`] leaves the row unpublished
/// and counts the attempt; `Ok` marks it published.
///
/// `Send` only — the callback borrows the publisher's consumer list for
/// the length of one pass, so it carries no `'static` supertrait and
/// `drain_pending` takes it generically.
#[trait_variant::make(Send)]
pub trait EventDelivery: Send {
    /// Delivers one claimed event; the first error fails the row's
    /// delivery for this pass.
    async fn deliver(&mut self, event: &RunEvent) -> Result<(), Failure>;
}

/// The outbox surface the publisher drives each tick (upstream
/// `DrainStore`, defined consumer-side so the app crate stays free of
/// adapter types — the checkpoint janitor's `CollectStore` precedent).
/// The PostgreSQL `eventjournal` store implements it.
#[trait_variant::make(Send)]
pub trait DrainStore: Send + Sync + 'static {
    /// Claims up to `limit` unpublished rows in `(run_id, seq)` order
    /// and calls `deliver` once per event; an `Ok` delivery marks the
    /// row published, an `Err` leaves it unpublished and counts the
    /// attempt. Returns the count of rows marked published.
    async fn drain_pending<D: EventDelivery>(
        &self,
        limit: u32,
        deliver: &mut D,
    ) -> Result<u64, Failure>;

    /// The backlog probe the stall detector reads: pending depth and
    /// the oldest pending row's `created_at` (`None` when empty).
    async fn unpublished_backlog(&self) -> Result<UnpublishedBacklog, Failure>;

    /// Deletes published rows older than `cutoff` — the OQ-3 GC.
    async fn collect_published(&self, cutoff: OffsetDateTime) -> Result<u64, Failure>;
}

/// The in-process outbox drain (upstream `Publisher`). Delivery is
/// at-least-once: every consumer MUST dedupe on `event_id` — see
/// [`Consumer`]; [`crate::app::consumers::dedupe`] wraps any consumer
/// that has no dedup of its own.
///
/// A zero-valued config field resolves to its `DEFAULT_*` constant,
/// mirroring upstream's `<= 0` fallback (`u64`/`Duration` zeros are the
/// only non-positive values representable).
pub struct Publisher<S: DrainStore> {
    /// The outbox surface driven each pass.
    pub store: S,
    /// Registered consumers in delivery order.
    pub consumers: Vec<Arc<dyn Consumer>>,
    /// The structured-log sink for drain/probe/GC warnings and
    /// `OUTBOX_PUBLISH_STALLED`; `None` discards.
    pub log: Option<Arc<dyn EventLog>>,
    /// Supplies the evaluation timestamp for stall age and GC cutoff;
    /// `None` uses UTC wall time. PostgreSQL remains authoritative
    /// inside the store's own commits.
    pub now: Option<Box<dyn Fn() -> OffsetDateTime + Send + Sync>>,
    /// The pass cadence the kernel supervisor ticks on; `ZERO` uses
    /// [`DEFAULT_PUBLISH_INTERVAL`].
    pub interval: Duration,
    /// Bounds one pass's claim; `0` uses
    /// [`DEFAULT_PUBLISH_BATCH_SIZE`].
    pub batch_size: u64,
    /// The `OUTBOX_PUBLISH_STALLED` depth threshold; `0` uses
    /// [`DEFAULT_STALLED_DEPTH`].
    pub stalled_depth: u64,
    /// The `OUTBOX_PUBLISH_STALLED` age threshold; `ZERO` uses
    /// [`DEFAULT_STALLED_AGE`].
    pub stalled_age: Duration,
    /// The published-row keep window; `ZERO` uses
    /// [`DEFAULT_PUBLISHED_RETENTION`].
    pub retention: Duration,

    stalled: AtomicBool,
}

/// The fan-out [`EventDelivery`] the store invokes per claimed row —
/// upstream's bound-method `Publisher.deliver`: the first consumer
/// error fails the row's delivery (it stays unpublished for the next
/// pass — the at-least-once side of the boundary map).
struct Fanout<'a> {
    consumers: &'a [Arc<dyn Consumer>],
}

impl EventDelivery for Fanout<'_> {
    async fn deliver(&mut self, event: &RunEvent) -> Result<(), Failure> {
        for consumer in self.consumers {
            consumer.consume(event).await?;
        }
        Ok(())
    }
}

impl<S: DrainStore> Publisher<S> {
    /// Builds a publisher over `store` with no consumers, no log, and
    /// every config field at its `DEFAULT_*`-resolving zero.
    pub fn new(store: S) -> Self {
        Self {
            store,
            consumers: Vec::new(),
            log: None,
            now: None,
            interval: Duration::ZERO,
            batch_size: 0,
            stalled_depth: 0,
            stalled_age: Duration::ZERO,
            retention: Duration::ZERO,
            stalled: AtomicBool::new(false),
        }
    }

    /// Whether the last completed pass observed
    /// `OUTBOX_PUBLISH_STALLED` conditions — a flag for
    /// health/readiness surfaces, not a metric (upstream `Stalled`).
    #[must_use]
    pub fn stalled(&self) -> bool {
        self.stalled.load(Ordering::Relaxed)
    }

    fn now(&self) -> OffsetDateTime {
        self.now
            .as_ref()
            .map_or_else(OffsetDateTime::now_utc, |f| f())
    }

    fn warn(&self, message: &'static str, fields: &[(&'static str, String)]) {
        if let Some(log) = &self.log {
            log.warn(message, fields);
        }
    }

    /// Runs one drain pass then the stall probe then the GC sweep —
    /// upstream `publishOnce`. The three are independent: a drain
    /// failure still lets the stall probe fire (a persistently failing
    /// drain is exactly what the probe exists to surface) and the GC
    /// still runs. Everything the pass cannot commit is a warn; the
    /// only carried-over state is the [`Self::stalled`] flag.
    pub async fn publish_once(&self) {
        let now = self.now();

        let batch_size = if self.batch_size == 0 {
            DEFAULT_PUBLISH_BATCH_SIZE
        } else {
            self.batch_size
        };
        let limit = u32::try_from(batch_size).unwrap_or(u32::MAX);
        let mut fanout = Fanout {
            consumers: self.consumers.as_slice(),
        };
        if let Err(failure) = self.store.drain_pending(limit, &mut fanout).await {
            self.warn(
                "event outbox drain failed",
                &[("error", failure.to_string())],
            );
        }

        let stalled_depth = if self.stalled_depth == 0 {
            DEFAULT_STALLED_DEPTH
        } else {
            self.stalled_depth
        };
        let stalled_age = if self.stalled_age <= Duration::ZERO {
            DEFAULT_STALLED_AGE
        } else {
            self.stalled_age
        };
        match self.store.unpublished_backlog().await {
            Err(failure) => self.warn(
                "event outbox backlog probe failed",
                &[("error", failure.to_string())],
            ),
            Ok(backlog) => {
                // Upstream's `depth > 0 && now.Sub(oldest) >
                // stalledAge`: a pending row with no recorded oldest is
                // the zero-time case — astronomically over age —
                // hence `map_or(true, ...)`, preserving the verdict.
                let stalled = backlog.depth > stalled_depth
                    || (backlog.depth > 0
                        && backlog
                            .oldest
                            .is_none_or(|oldest| now - oldest > stalled_age));
                self.stalled.store(stalled, Ordering::Relaxed);
                if stalled {
                    self.warn(
                        REASON_OUTBOX_PUBLISH_STALLED,
                        &[
                            ("reason_code", REASON_OUTBOX_PUBLISH_STALLED.to_string()),
                            ("unpublished_depth", backlog.depth.to_string()),
                            (
                                "oldest_unpublished_age",
                                backlog.oldest.map_or_else(
                                    || "unknown".to_string(),
                                    |o| (now - o).to_string(),
                                ),
                            ),
                        ],
                    );
                }
            }
        }

        let retention = if self.retention <= Duration::ZERO {
            DEFAULT_PUBLISHED_RETENTION
        } else {
            self.retention
        };
        if let Err(failure) = self.store.collect_published(now - retention).await {
            self.warn(
                "event outbox published-row GC failed",
                &[("error", failure.to_string())],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use central_foundation::identity::{RunEventId, RunId, WorkspaceId};

    use super::*;
    use crate::testkit::block_on;

    /// One pending event paired with the outbox row's `created_at` —
    /// the age anchor the real store's `MIN(created_at)` backlog probe
    /// returns.
    #[derive(Clone)]
    struct PendingEntry {
        event: RunEvent,
        created_at: OffsetDateTime,
    }

    /// The in-memory `DrainStore` double: pending events drain through
    /// `deliver` exactly like the Postgres claim — failed deliveries
    /// stay pending and count an attempt (upstream `fakeDrainStore`).
    #[derive(Default)]
    struct FakeDrainStore {
        pending: Mutex<Vec<PendingEntry>>,
        marked: Mutex<Vec<RunEvent>>,
        attempts: Mutex<HashMap<RunEventId, u32>>,
        collected: Mutex<Vec<OffsetDateTime>>,
        drain_err: Mutex<Option<Failure>>,
        backlog_err: Mutex<Option<Failure>>,
        collect_err: Mutex<Option<Failure>>,
    }

    impl FakeDrainStore {
        fn seed(&self, events: &[RunEvent]) {
            let mut pending = self.pending.lock().unwrap();
            for event in events {
                pending.push(PendingEntry {
                    event: event.clone(),
                    created_at: OffsetDateTime::now_utc(),
                });
            }
        }

        /// Plants a pending row whose outbox `created_at` is already
        /// old — the shape a stalled backlog takes (delivered or
        /// attempted, never marked).
        fn seed_aged(&self, event: &RunEvent, created_at: OffsetDateTime) {
            self.pending.lock().unwrap().push(PendingEntry {
                event: event.clone(),
                created_at,
            });
        }

        fn pending_len(&self) -> usize {
            self.pending.lock().unwrap().len()
        }

        fn marked(&self) -> Vec<RunEvent> {
            self.marked.lock().unwrap().clone()
        }
    }

    impl DrainStore for FakeDrainStore {
        async fn drain_pending<D: EventDelivery>(
            &self,
            limit: u32,
            deliver: &mut D,
        ) -> Result<u64, Failure> {
            if let Some(failure) = self.drain_err.lock().unwrap().clone() {
                return Err(failure);
            }
            let count = {
                let pending = self.pending.lock().unwrap();
                (limit as usize).min(pending.len())
            };
            let mut delivered = 0u64;
            let mut marked_ids: HashSet<RunEventId> = HashSet::new();
            for i in 0..count {
                let entry = self.pending.lock().unwrap()[i].clone();
                *self
                    .attempts
                    .lock()
                    .unwrap()
                    .entry(entry.event.id)
                    .or_default() += 1;
                if deliver.deliver(&entry.event).await.is_err() {
                    continue;
                }
                self.marked.lock().unwrap().push(entry.event.clone());
                marked_ids.insert(entry.event.id);
                delivered += 1;
            }
            self.pending
                .lock()
                .unwrap()
                .retain(|entry| !marked_ids.contains(&entry.event.id));
            Ok(delivered)
        }

        async fn unpublished_backlog(&self) -> Result<UnpublishedBacklog, Failure> {
            if let Some(failure) = self.backlog_err.lock().unwrap().clone() {
                return Err(failure);
            }
            let pending = self.pending.lock().unwrap();
            Ok(UnpublishedBacklog {
                depth: pending.len() as u64,
                oldest: pending.iter().map(|e| e.created_at).min(),
            })
        }

        async fn collect_published(&self, cutoff: OffsetDateTime) -> Result<u64, Failure> {
            if let Some(failure) = self.collect_err.lock().unwrap().clone() {
                return Err(failure);
            }
            self.collected.lock().unwrap().push(cutoff);
            Ok(0)
        }
    }

    #[derive(Default)]
    struct RecordingConsumer {
        seen: Mutex<Vec<RunEvent>>,
        err: Mutex<Option<Failure>>,
    }

    impl Consumer for RecordingConsumer {
        fn consume<'a>(&'a self, event: &'a RunEvent) -> crate::port::ConsumerFuture<'a> {
            Box::pin(async move {
                if let Some(failure) = self.err.lock().unwrap().clone() {
                    return Err(failure);
                }
                self.seen.lock().unwrap().push(event.clone());
                Ok(())
            })
        }
    }

    impl RecordingConsumer {
        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    /// One captured log record: `(level, message, fields)`.
    type CapturedRecord = (&'static str, &'static str, Vec<(&'static str, String)>);

    /// The `EventLog` double capturing `(level, message, fields)` records
    /// — the observable surface the stalled-signal test asserts on.
    #[derive(Default)]
    struct CapturedLog {
        records: Mutex<Vec<CapturedRecord>>,
    }

    impl EventLog for CapturedLog {
        fn info(&self, message: &'static str, fields: &[(&'static str, String)]) {
            self.records
                .lock()
                .unwrap()
                .push(("info", message, fields.to_vec()));
        }

        fn warn(&self, message: &'static str, fields: &[(&'static str, String)]) {
            self.records
                .lock()
                .unwrap()
                .push(("warn", message, fields.to_vec()));
        }
    }

    impl CapturedLog {
        fn contains(&self, needle: &str) -> bool {
            let records = self.records.lock().unwrap();
            records.iter().any(|(level, message, fields)| {
                level.contains(needle)
                    || message.contains(needle)
                    || fields
                        .iter()
                        .any(|(k, v)| k.contains(needle) || v.contains(needle))
            })
        }
    }

    fn test_event(run_id: RunId, seq: i64) -> RunEvent {
        RunEvent {
            id: RunEventId::new(),
            workspace_id: WorkspaceId::new(),
            run_id,
            seq,
            node_id: None,
            attempt_id: None,
            kind: "node_declared".to_string(),
            actor: "scheduler".to_string(),
            reason_code: None,
            payload: serde_json::Value::Null,
            recorded_at: OffsetDateTime::now_utc(),
        }
    }

    // Upstream `TestPublisherUnconfigured`: `Publisher{}` with no Store
    // errors from `Run`. In Rust an unconfigured publisher is
    // unrepresentable — `Publisher::new` requires the `DrainStore` — so
    // this pins the remaining edge instead: a publisher with no
    // consumers still drains and marks (an empty fan-out is `Ok`).
    #[test]
    fn publisher_with_no_consumers_marks_rows() {
        let store = FakeDrainStore::default();
        let run = RunId::new();
        store.seed(&[test_event(run, 1)]);
        let p = Publisher::new(store);
        block_on(p.publish_once());
        assert_eq!(p.store.marked().len(), 1);
        assert_eq!(p.store.pending_len(), 0);
    }

    // One pass claims the pending batch, fans it out to every consumer,
    // and the store saw the deliveries (which is what the real store
    // marks published).
    #[test]
    fn publisher_drain_delivers_and_marks() {
        let store = FakeDrainStore::default();
        let run = RunId::new();
        store.seed(&[test_event(run, 1), test_event(run, 2)]);
        let consumer = Arc::new(RecordingConsumer::default());
        let consumer_dyn: Arc<dyn Consumer> = consumer.clone();

        let mut p = Publisher::new(store);
        p.consumers = vec![consumer_dyn];
        block_on(p.publish_once());

        assert_eq!(consumer.count(), 2);
        assert_eq!(p.store.marked().len(), 2);
        let backlog = block_on(p.store.unpublished_backlog()).unwrap();
        assert_eq!(backlog.depth, 0);
        assert!(!p.stalled(), "stalled flag set on a clean pass");
    }

    // A consumer error keeps the event unpublished for the next pass
    // while a healthy sibling row still marks — the per-row isolation
    // the drain relies on.
    #[test]
    fn publisher_consumer_failure_leaves_row_pending() {
        let store = FakeDrainStore::default();
        let run = RunId::new();
        let first = test_event(run, 1);
        let second = test_event(run, 2);
        store.seed(&[first.clone(), second.clone()]);
        let flaky = Arc::new(RecordingConsumer::default());
        *flaky.err.lock().unwrap() = Some(Failure::internal("eventjournal_test", "consumer down"));
        let ok = Arc::new(RecordingConsumer::default());

        // Two consumers: the flaky one is registered first so its error
        // fails the row's delivery entirely.
        let mut p = Publisher::new(store);
        let flaky_dyn: Arc<dyn Consumer> = flaky.clone();
        let ok_dyn: Arc<dyn Consumer> = ok.clone();
        p.consumers = vec![flaky_dyn, ok_dyn];
        block_on(p.publish_once());

        assert_eq!(
            ok.count(),
            0,
            "second consumer saw events behind a failing sibling"
        );
        assert_eq!(p.store.marked().len(), 0);
        assert_eq!(p.store.pending_len(), 2);
        assert_eq!(p.store.attempts.lock().unwrap()[&first.id], 1);
        assert_eq!(p.store.attempts.lock().unwrap()[&second.id], 1);

        // Consumer recovers: the next pass redelivers everything still
        // pending (at-least-once).
        *flaky.err.lock().unwrap() = None;
        block_on(p.publish_once());
        assert_eq!(ok.count(), 2);
    }

    // The consumer-side `event_id` dedup the at-least-once contract
    // requires: a redelivered event reaches the inner consumer once.
    #[test]
    fn dedupe_drops_redelivery() {
        let inner = Arc::new(RecordingConsumer::default());
        let deduped = crate::app::consumers::dedupe(inner.clone());
        let ev = test_event(RunId::new(), 1);

        block_on(deduped.consume(&ev)).unwrap();
        block_on(deduped.consume(&ev)).unwrap();
        assert_eq!(inner.count(), 1);
    }

    // A failed consume is not marked seen: the redelivery reaches the
    // inner consumer.
    #[test]
    fn dedupe_retries_failed_delivery() {
        let inner = Arc::new(RecordingConsumer::default());
        *inner.err.lock().unwrap() = Some(Failure::internal("eventjournal_test", "not yet"));
        let deduped = crate::app::consumers::dedupe(inner.clone());
        let ev = test_event(RunId::new(), 1);

        assert!(
            block_on(deduped.consume(&ev)).is_err(),
            "failing inner swallowed"
        );
        *inner.err.lock().unwrap() = None;
        block_on(deduped.consume(&ev)).unwrap();
        assert_eq!(inner.count(), 1);
    }

    // The `OUTBOX_PUBLISH_STALLED` surface: an over-age unpublished row
    // (kept pending by a failing consumer, the realistic stall shape)
    // flips the flag and logs the reason code; a recovered drain clears
    // it on the next pass.
    #[test]
    fn publisher_stalled_signals() {
        let store = FakeDrainStore::default();
        let run = RunId::new();
        store.seed_aged(
            &test_event(run, 1),
            OffsetDateTime::now_utc() - Duration::hours(1),
        );
        let failing = Arc::new(RecordingConsumer::default());
        *failing.err.lock().unwrap() =
            Some(Failure::internal("eventjournal_test", "consumer down"));

        let log = Arc::new(CapturedLog::default());
        let mut p = Publisher::new(store);
        let failing_dyn: Arc<dyn Consumer> = failing.clone();
        p.consumers = vec![failing_dyn];
        p.log = Some(log.clone());
        p.stalled_age = Duration::minutes(1);
        p.stalled_depth = 10;
        block_on(p.publish_once());

        assert!(
            p.stalled(),
            "stalled flag unset with an hour-old unpublished row"
        );
        assert!(
            log.contains(REASON_OUTBOX_PUBLISH_STALLED),
            "stall warn missing"
        );

        // Consumer recovers: the next pass drains the aged row and the
        // flag clears.
        *failing.err.lock().unwrap() = None;
        block_on(p.publish_once());
        assert!(!p.stalled(), "stalled flag stuck after backlog drained");
    }

    // The depth threshold fires even with a fresh oldest row.
    #[test]
    fn publisher_stalled_on_depth() {
        let store = FakeDrainStore::default();
        let run = RunId::new();
        let log = Arc::new(CapturedLog::default());
        // Four pending with batch size 1: one delivers, three remain →
        // depth 3 exceeds the threshold of 2 even though the oldest is
        // fresh.
        store.seed(&[
            test_event(run, 1),
            test_event(run, 2),
            test_event(run, 3),
            test_event(run, 4),
        ]);
        let consumer = Arc::new(RecordingConsumer::default());
        let consumer_dyn: Arc<dyn Consumer> = consumer;
        let mut p = Publisher::new(store);
        p.log = Some(log);
        p.consumers = vec![consumer_dyn];
        p.batch_size = 1;
        p.stalled_depth = 2;
        p.stalled_age = Duration::hours(1);
        block_on(p.publish_once());
        assert!(p.stalled(), "depth should exceed threshold");
    }

    // The shipped feed is idempotent by construction: redelivery logs
    // again without error — and carries the event's durable
    // coordinates.
    #[test]
    fn logging_consumer_never_fails() {
        let log = Arc::new(CapturedLog::default());
        let consumer = crate::app::consumers::LoggingConsumer {
            log: Some(log.clone()),
        };
        let ev = test_event(RunId::new(), 7);
        block_on(consumer.consume(&ev)).unwrap();
        block_on(consumer.consume(&ev)).unwrap();
        assert!(log.contains("seq"), "log line missing coordinates");
        assert!(log.contains("7"), "log line missing seq value");
        assert!(
            log.contains(&ev.id.to_string()),
            "log line missing event_id"
        );
    }
}
