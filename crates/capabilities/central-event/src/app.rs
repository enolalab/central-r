//! Event Service — orchestration only
//! (rust-application-boundaries.md §2.2).
//!
//! Appends hand validated intents to the journal port, which allocates
//! Workspace-local sequences inside the caller's change-set
//! transaction; the service seals nothing itself — the domain seals at
//! the sequence the port returns. Reads validate the request and
//! delegate to the feed contract. No transaction is opened here; no
//! business rule lives here.

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;

use crate::domain::{Event, EventIntent};
use crate::port::{EventJournal, MAX_APPEND_BATCH};
use crate::query::{EventFeedPage, EventFeedRead, EventFeedRequest};

/// The event capability Service.
pub struct EventService<J: EventJournal, R: EventFeedRead> {
    journal: J,
    feed: R,
}

impl<J: EventJournal, R: EventFeedRead> EventService<J, R> {
    /// Wires the service against its ports.
    pub const fn new(journal: J, feed: R) -> Self {
        Self { journal, feed }
    }

    /// Appends a batch of validated intents inside the caller's
    /// change-set commit. Empty batches are a no-op; oversized batches
    /// fail before touching the port (≤ [`MAX_APPEND_BATCH`]).
    pub async fn append(
        &self,
        workspace_id: WorkspaceId,
        intents: Vec<EventIntent>,
    ) -> Result<Vec<Event>, Failure> {
        if intents.is_empty() {
            return Ok(Vec::new());
        }
        if intents.len() > MAX_APPEND_BATCH {
            return Err(Failure::invalid(
                crate::domain::codes::EVENT_INVALID,
                "a change set commits at most 8 events",
            ));
        }
        self.journal.append_events(workspace_id, intents).await
    }

    /// The bounded forward-only feed read (Q3).
    pub async fn feed(&self, request: &EventFeedRequest) -> Result<EventFeedPage, Failure> {
        request.validate()?;
        self.feed.read_page(request).await
    }

    /// Cursor-expiry preflight: whether committed Events exist beyond
    /// `event_sequence` in this Workspace.
    pub async fn has_events_after(
        &self,
        workspace_id: WorkspaceId,
        event_sequence: u64,
    ) -> Result<bool, Failure> {
        self.feed
            .has_events_after(workspace_id, event_sequence)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{ActorKind, EventActor, EventContext, EventPayload, StateTransition};
    use crate::query::SeekCursor;
    use central_foundation::failure::FailureKind;
    use central_foundation::identity::AggregateId;
    use time::OffsetDateTime;

    const T0: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(v) => return v,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    struct StubJournal {
        next_seq: Mutex<u64>,
    }

    impl EventJournal for StubJournal {
        async fn append_events(
            &self,
            _workspace_id: WorkspaceId,
            intents: Vec<EventIntent>,
        ) -> Result<Vec<Event>, Failure> {
            let mut seq = self.next_seq.lock().unwrap();
            intents
                .into_iter()
                .map(|intent| {
                    *seq += 1;
                    intent.seal(*seq)
                })
                .collect()
        }
    }

    struct StubFeed;

    impl EventFeedRead for StubFeed {
        async fn read_page(&self, _request: &EventFeedRequest) -> Result<EventFeedPage, Failure> {
            Ok(EventFeedPage {
                events: Vec::new(),
                next_cursor: None,
                has_more: false,
            })
        }
        async fn has_events_after(
            &self,
            _workspace_id: WorkspaceId,
            _event_sequence: u64,
        ) -> Result<bool, Failure> {
            Ok(false)
        }
    }

    fn intent() -> EventIntent {
        EventIntent {
            workspace_id: WorkspaceId::new(),
            event_type: "task.created".into(),
            aggregate_type: "task".into(),
            aggregate_id: AggregateId::new(),
            aggregate_version: 1,
            occurred_at: T0,
            correlation_id: None,
            causation_id: None,
            command_id: None,
            run_id: None,
            context: EventContext::default(),
            actor: EventActor::new("system", ActorKind::System).unwrap(),
            transition: StateTransition::new(None, "created", None).unwrap(),
            payload: EventPayload::sanitize(br#"{"type":"task.created.v1"}"#).unwrap(),
        }
    }

    #[test]
    fn append_allocates_sequences_in_order() {
        let svc = EventService::new(
            StubJournal {
                next_seq: Mutex::new(41),
            },
            StubFeed,
        );
        let ws = WorkspaceId::new();
        let events = block_on(svc.append(ws, vec![intent(), intent()])).unwrap();
        assert_eq!(events[0].sequence(), Some(42));
        assert_eq!(events[1].sequence(), Some(43));
    }

    #[test]
    fn append_rejects_oversized_batches_before_the_port() {
        let svc = EventService::new(
            StubJournal {
                next_seq: Mutex::new(0),
            },
            StubFeed,
        );
        let ws = WorkspaceId::new();
        let intents = (0..9).map(|_| intent()).collect::<Vec<_>>();
        let err = block_on(svc.append(ws, intents)).unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
        assert_eq!(block_on(svc.append(ws, Vec::new())).unwrap().len(), 0);
    }

    #[test]
    fn feed_rejects_cross_workspace_cursors_and_bad_limits() {
        let svc = EventService::new(
            StubJournal {
                next_seq: Mutex::new(0),
            },
            StubFeed,
        );
        let foreign = SeekCursor {
            workspace_id: WorkspaceId::new(),
            event_sequence: 10,
        };
        let req = EventFeedRequest {
            workspace_id: WorkspaceId::new(),
            after: Some(foreign),
            aggregate_id: None,
            run_id: None,
            limit: None,
        };
        assert_eq!(
            block_on(svc.feed(&req)).unwrap_err().code(),
            crate::domain::codes::CURSOR_WORKSPACE_MISMATCH
        );

        let req = EventFeedRequest {
            limit: Some(0),
            ..req
        };
        assert_eq!(
            block_on(svc.feed(&req)).unwrap_err().code(),
            crate::domain::codes::EVENT_INVALID
        );
    }

    #[test]
    fn cursor_wire_form_round_trips_and_is_workspace_bound() {
        let cursor = SeekCursor {
            workspace_id: WorkspaceId::new(),
            event_sequence: 42,
        };
        let encoded = cursor.encode();
        assert!(encoded.starts_with("ev1."));
        assert_eq!(SeekCursor::decode(&encoded).unwrap(), cursor);
        assert_eq!(
            SeekCursor::decode("garbage").unwrap_err().code(),
            crate::domain::codes::CURSOR_INVALID
        );
        assert_eq!(
            SeekCursor::decode("ev1.not-a-uuid.5").unwrap_err().code(),
            crate::domain::codes::CURSOR_INVALID
        );
    }
}
