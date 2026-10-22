//! The seek-paginated Workspace event feed — `EventFeedRead` (Q3,
//! `docs/events/v1.md` §7–§10, adapter-mapping §4.2).
//!
//! Forward-only seek pagination over the durable ordering key
//! `(workspace_id, event_sequence)`. A cursor encodes the last
//! delivered boundary; the next page returns strictly greater
//! sequences. There is no backward pagination and no random-access
//! offset — by contract.

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;
use serde::{Deserialize, Serialize};

use crate::domain::{Event, codes};

/// Feed page-size contract (v1.md §9): default 100, minimum 1,
/// maximum 250. Out-of-range limits are a safe invalid failure, never
/// a silent clamp.
pub const DEFAULT_FEED_LIMIT: usize = 100;
/// Hard ceiling on one feed page.
pub const MAX_FEED_LIMIT: usize = 250;

/// The typed seek cursor — the last delivered `(workspace_id,
/// event_sequence)` boundary. Workspace-bound and meaningless outside
/// its Workspace (§8): [`SeekCursor::encode`] produces the opaque wire
/// form `ev1.<workspace>.<sequence>`, and a request carrying a cursor
/// minted for a different Workspace is rejected rather than silently
/// mis-seeked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeekCursor {
    /// The Workspace the boundary belongs to.
    pub workspace_id: WorkspaceId,
    /// The highest delivered sequence. The next page returns strictly
    /// greater values — the no-skip guarantee (§10).
    pub event_sequence: u64,
}

impl SeekCursor {
    /// The opaque wire form: `ev1.<workspace_id>.<event_sequence>`.
    /// Opaque to clients, self-binding to the Workspace.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("ev1.{}.{}", self.workspace_id, self.event_sequence)
    }

    /// Parses the opaque wire form. Shape errors are `invalid` — a
    /// malformed cursor is never treated as "start from earliest".
    pub fn decode(text: &str) -> Result<Self, Failure> {
        let malformed =
            || Failure::invalid(codes::CURSOR_INVALID, "the cursor is not an ev1 boundary");
        let mut parts = text.splitn(3, '.');
        if parts.next() != Some("ev1") {
            return Err(malformed());
        }
        let workspace = parts
            .next()
            .ok_or_else(malformed)?
            .parse::<WorkspaceId>()
            .map_err(|_| malformed())?;
        let sequence = parts
            .next()
            .ok_or_else(malformed)?
            .parse::<u64>()
            .map_err(|_| malformed())?;
        Ok(Self {
            workspace_id: workspace,
            event_sequence: sequence,
        })
    }
}

/// The bounded feed request (§8 request shape): `after` cursor plus
/// `limit`. `aggregate_type`/`aggregate_id` narrow the feed to one
/// aggregate — the recovery replay path (`events_aggregate_idx`).
#[derive(Debug, Clone, PartialEq)]
pub struct EventFeedRequest {
    /// Owning Workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// Continuation boundary; `None` starts at the earliest Event.
    pub after: Option<SeekCursor>,
    /// Optional aggregate-scoped replay (recovery reconstruction).
    pub aggregate_id: Option<central_foundation::identity::AggregateId>,
    /// Optional Run-scoped feed (`events_run_idx`).
    pub run_id: Option<central_foundation::identity::RunId>,
    /// Requested page size; `None` → [`DEFAULT_FEED_LIMIT`].
    pub limit: Option<usize>,
}

impl EventFeedRequest {
    /// Validates scope, limit, and cursor binding. Returns the
    /// effective limit.
    pub fn validate(&self) -> Result<usize, Failure> {
        let limit = self.limit.unwrap_or(DEFAULT_FEED_LIMIT);
        if limit == 0 || limit > MAX_FEED_LIMIT {
            return Err(Failure::invalid(
                codes::EVENT_INVALID,
                "the feed limit must be within 1..=250",
            ));
        }
        if let Some(cursor) = &self.after
            && cursor.workspace_id != self.workspace_id
        {
            return Err(Failure::invalid(
                codes::CURSOR_WORKSPACE_MISMATCH,
                "the cursor is bound to a different workspace",
            ));
        }
        Ok(limit)
    }
}

/// One page of the feed (§8 response shape).
#[derive(Debug, Clone, PartialEq)]
pub struct EventFeedPage {
    /// The Events, `event_sequence` ascending.
    pub events: Vec<Event>,
    /// The boundary of the last delivered Event — pass it back as
    /// `after`. `None` when the page is empty.
    pub next_cursor: Option<SeekCursor>,
    /// `true` when committed Events exist beyond this page.
    pub has_more: bool,
}

/// The Q3 read contract — the only Event query path in Phase 1
/// (adapter-mapping §3.11). No offset, no backward traversal.
#[trait_variant::make(Send)]
pub trait EventFeedRead: Send + Sync + 'static {
    /// Reads one bounded page strictly after the cursor boundary.
    async fn read_page(&self, request: &EventFeedRequest) -> Result<EventFeedPage, Failure>;

    /// Preflight: whether any committed Event exists beyond the
    /// boundary — the cursor-expiry detection EXISTS check
    /// (adapter-mapping §4.3).
    async fn has_events_after(
        &self,
        workspace_id: WorkspaceId,
        event_sequence: u64,
    ) -> Result<bool, Failure>;
}
