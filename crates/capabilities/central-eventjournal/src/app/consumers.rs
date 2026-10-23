//! The shipped consumer set — pure port of
//! `central/internal/eventjournal/app/consumers.go` (packet P2D06):
//! [`LoggingConsumer`], the observable feed whose only job is making
//! event flow legible, and [`DedupingConsumer`] ([`dedupe`]), the
//! in-memory `event_id` dedup wrapper every consumer without its own
//! durable dedup must run under (delivery is at-least-once — spec-5
//! section 3 assigns the dedup point to event publication).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use central_foundation::identity::RunEventId;

use crate::app::EventLog;
use crate::domain::RunEvent;
use crate::port::{Consumer, ConsumerFuture};

/// The shipped feed that logs each event's durable coordinates —
/// upstream `LoggingConsumer`. Log output carries the nine durable
/// fields (`event_id`, `workspace_id`, `run_id`, `seq`, `kind`,
/// `actor`, `node_id`, `attempt_id`, `reason_code`); payload contents
/// stay out of the log (audit trail without leaking node inputs).
///
/// It is already idempotent — redelivery just logs again — so it is
/// never an error. `log: None` discards, matching upstream's
/// `slog.Default()` fallback in the only sense that matters (no panic,
/// no failure).
pub struct LoggingConsumer {
    /// The structured-log sink; `None` discards.
    pub log: Option<Arc<dyn EventLog>>,
}

impl Consumer for LoggingConsumer {
    /// Logs the event's durable coordinates — ids, seq, kind, actor,
    /// reason code — and never the payload (upstream's nine-field
    /// `run event published` line verbatim).
    fn consume<'a>(&'a self, event: &'a RunEvent) -> ConsumerFuture<'a> {
        Box::pin(async move {
            if let Some(log) = &self.log {
                log.info(
                    "run event published",
                    &[
                        ("event_id", event.id.to_string()),
                        ("workspace_id", event.workspace_id.to_string()),
                        ("run_id", event.run_id.to_string()),
                        ("seq", event.seq.to_string()),
                        ("kind", event.kind.clone()),
                        ("actor", event.actor.clone()),
                        (
                            "node_id",
                            event.node_id.map(|id| id.to_string()).unwrap_or_default(),
                        ),
                        (
                            "attempt_id",
                            event
                                .attempt_id
                                .map(|id| id.to_string())
                                .unwrap_or_default(),
                        ),
                        ("reason_code", event.reason_code.clone().unwrap_or_default()),
                    ],
                );
            }
            Ok(())
        })
    }
}

/// The in-memory dedup cap — upstream `dedupeCap` (`1 << 16`).
/// Past this many recently-seen `event_id`s the oldest are evicted;
/// duplicates may be re-delivered after eviction or restart
/// (at-least-once semantics allow it).
pub const DEDUPE_CAP: usize = 1 << 16;

/// The `event_id`-dedup wrapper every outbox consumer without a
/// durable dedup of its own must run under — upstream
/// `DedupingConsumer`. An in-memory set means duplicates may still be
/// delivered after restart; the underlying store's `publish_attempts`
/// is the counter that catches true redelivery storms (not a metric
/// here, the same as upstream).
///
/// Constructed by [`dedupe`]; `DedupingConsumer::consume` itself is
/// infallible to invoke — it simply forwards and records.
pub struct DedupingConsumer<C> {
    inner: C,
    seen: Mutex<DedupeSet>,
}

/// FIFO-ordered id set: `queue` preserves insertion order for
/// eviction, `index` gives O(1) membership.
#[derive(Default)]
struct DedupeSet {
    queue: VecDeque<RunEventId>,
    index: std::collections::HashSet<RunEventId>,
}

impl DedupeSet {
    fn insert(&mut self, id: RunEventId) {
        if self.index.insert(id) {
            self.queue.push_back(id);
            if self.queue.len() > DEDUPE_CAP
                && let Some(oldest) = self.queue.pop_front()
            {
                self.index.remove(&oldest);
            }
        }
    }
}

impl<C: Consumer> Consumer for DedupingConsumer<C> {
    /// Skips delivery when the `event_id` was already consumed
    /// successfully; otherwise forwards to the inner consumer and
    /// marks the id seen only on success (a failed delivery is
    /// redelivered on the next pass — upstream's
    /// `mark-seen-after-success` contract).
    fn consume<'a>(&'a self, event: &'a RunEvent) -> ConsumerFuture<'a> {
        Box::pin(async move {
            {
                let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
                if seen.index.contains(&event.id) {
                    return Ok(());
                }
            }
            self.inner.consume(event).await?;
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(event.id);
            Ok(())
        })
    }
}

/// Wraps `inner` with the default-cap [`DedupingConsumer`] — upstream
/// `Dedupe(inner, 0)`.
pub fn dedupe<C: Consumer>(inner: C) -> DedupingConsumer<C> {
    DedupingConsumer {
        inner,
        seen: Mutex::new(DedupeSet::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use central_foundation::failure::Failure;

    /// A consumer that counts deliveries (the dedup tests in the
    /// publisher module exercise the full redelivery path; these cover
    /// the wrapper's own contract).
    struct CountingConsumer {
        calls: Mutex<usize>,
        fail: Mutex<bool>,
    }

    impl Consumer for CountingConsumer {
        fn consume<'a>(&'a self, _event: &'a RunEvent) -> ConsumerFuture<'a> {
            Box::pin(async move {
                if *self.fail.lock().unwrap() {
                    return Err(Failure::internal("eventjournal_test", "consumer down"));
                }
                *self.calls.lock().unwrap() += 1;
                Ok(())
            })
        }
    }

    fn event(seq: i64) -> RunEvent {
        RunEvent {
            id: RunEventId::new(),
            workspace_id: central_foundation::identity::WorkspaceId::new(),
            run_id: central_foundation::identity::RunId::new(),
            seq,
            node_id: None,
            attempt_id: None,
            kind: "node_ready".to_string(),
            actor: "scheduler".to_string(),
            reason_code: None,
            payload: serde_json::Value::Null,
            recorded_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn dedupe_distinct_events_deliver() {
        let inner = CountingConsumer {
            calls: Mutex::new(0),
            fail: Mutex::new(false),
        };
        let deduped = dedupe(inner);
        block_on(deduped.consume(&event(1))).unwrap();
        block_on(deduped.consume(&event(2))).unwrap();
        assert_eq!(*deduped.inner.calls.lock().unwrap(), 2);
    }

    #[test]
    fn dedupe_set_evicts_fifo() {
        let mut set = DedupeSet::default();
        let first = RunEventId::new();
        set.insert(first);
        for _ in 0..DEDUPE_CAP {
            set.insert(RunEventId::new());
        }
        assert!(!set.index.contains(&first), "oldest id not evicted");
        assert!(set.queue.len() <= DEDUPE_CAP);
        // A re-inserted evicted id counts as unseen again.
        set.insert(first);
        assert!(set.index.contains(&first));
    }

    #[test]
    fn dedupe_failed_delivery_not_marked() {
        let inner = CountingConsumer {
            calls: Mutex::new(0),
            fail: Mutex::new(true),
        };
        let deduped = dedupe(inner);
        let ev = event(1);
        assert!(block_on(deduped.consume(&ev)).is_err());
        *deduped.inner.fail.lock().unwrap() = false;
        block_on(deduped.consume(&ev)).unwrap();
        assert_eq!(*deduped.inner.calls.lock().unwrap(), 1);
    }
}
