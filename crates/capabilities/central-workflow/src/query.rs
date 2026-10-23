//! Read contract for `central-workflow`: `WorkflowGraphRead` — the
//! bounded graph page over `central.workflow_nodes` /
//! `central.workflow_edges` (b33) consumed by run-graph surfaces.
//!
//! Declaration-only: typed seek pagination over
//! `(run_id, created_at, id)` with a `(created_at, node_id)` keyset
//! cursor — never offset, never an unbounded scan. Each page carries
//! the in-edges of its nodes (every edge lands on exactly the page
//! carrying its dependent; a `prerequisite_node_id` may point outside
//! the page). `Node.spec` is the recorded `central.child-spec/v1`
//! document — leader-authored and secret-free by contract — and the
//! projection is a trusted control-plane surface; Slice 2E run views
//! define their own slimmer projections on top.
//!
//! No locks, no writes, no journaled side effects.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkflowNodeId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::domain::{Edge, Node};

/// Default page size for [`GraphPageRequest`] when `page_size` is `0`.
/// Matches the locked `max_nodes_per_run` cap so a default-capped run's
/// graph is one page.
pub const DEFAULT_GRAPH_PAGE_SIZE: u32 = 100;
/// Hard ceiling on one graph page.
pub const MAX_GRAPH_PAGE_SIZE: u32 = 250;

/// The typed keyset seek cursor for the graph page
/// (`(created_at, id)` commit order): the boundary row's `created_at`
/// plus its `node_id` tiebreaker. `None` on the request asks for the
/// head page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSeekCursor {
    /// The boundary node's `created_at`.
    pub created_at: OffsetDateTime,
    /// The boundary node's identity.
    pub node_id: WorkflowNodeId,
}

/// A run-scoped keyset page request.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphPageRequest {
    /// The owning run — mandatory isolation scope.
    pub run_id: RunId,
    /// Continuation boundary; `None` requests the head page.
    pub cursor: Option<NodeSeekCursor>,
    /// Requested page size; `0` normalizes to
    /// [`DEFAULT_GRAPH_PAGE_SIZE`], values above
    /// [`MAX_GRAPH_PAGE_SIZE`] clamp to it.
    pub page_size: u32,
}

/// Validates the mandatory run scope.
pub fn validate_graph_page_request(req: &GraphPageRequest) -> Result<(), Failure> {
    if req.run_id.is_nil() {
        return Err(Failure::invalid(
            "WORKFLOW_GRAPH_SCOPE_REQUIRED",
            "the workflow graph page requires a run scope",
        ));
    }
    Ok(())
}

/// Clamps a requested page size into `[1, MAX_GRAPH_PAGE_SIZE]`,
/// defaulting `0` to [`DEFAULT_GRAPH_PAGE_SIZE`].
#[must_use]
pub const fn normalize_graph_page_size(page_size: u32) -> u32 {
    if page_size == 0 {
        DEFAULT_GRAPH_PAGE_SIZE
    } else if page_size > MAX_GRAPH_PAGE_SIZE {
        MAX_GRAPH_PAGE_SIZE
    } else {
        page_size
    }
}

/// One bounded page of a run's graph.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphPage {
    /// One page of nodes in `(created_at, id)` order.
    pub nodes: Vec<Node>,
    /// The in-edges of the page's nodes — every edge lands on exactly
    /// the page carrying its dependent; a `prerequisite_node_id` may
    /// resolve to a node outside the page.
    pub edges: Vec<Edge>,
    /// Forward-only continuation; `None` = end of graph.
    pub next_cursor: Option<NodeSeekCursor>,
}

/// The read contract behind the bounded graph page. Implemented by
/// `central-adapter-postgres` in a single bounded round trip; consumed
/// by run-graph surfaces after the surface-appropriate authorization
/// decision.
#[trait_variant::make(Send)]
pub trait WorkflowGraphRead: Send + Sync + 'static {
    /// Reads one bounded `(created_at, id)` page of run nodes plus the
    /// in-edges attached to them.
    async fn graph_page(&self, request: &GraphPageRequest) -> Result<GraphPage, Failure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const V7_RUN: &str = "018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b";
    const V7_NODE: &str = "0190a1b2-c3d4-7e5f-9a8b-7c6d5e4f3a2b";

    fn request() -> GraphPageRequest {
        GraphPageRequest {
            run_id: RunId::parse(V7_RUN).unwrap(),
            cursor: None,
            page_size: 0,
        }
    }

    /// `page_size` clamps into the bounded range: `0` defaults,
    /// values above the ceiling clamp.
    #[test]
    fn page_size_normalizes_into_bounds() {
        assert_eq!(normalize_graph_page_size(0), 100);
        assert_eq!(normalize_graph_page_size(1), 1);
        assert_eq!(normalize_graph_page_size(64), 64);
        assert_eq!(normalize_graph_page_size(250), 250);
        assert_eq!(normalize_graph_page_size(251), 250);
        assert_eq!(normalize_graph_page_size(u32::MAX), 250);
    }

    #[test]
    fn request_validation_accepts_scoped_request() {
        validate_graph_page_request(&request()).unwrap();
    }

    /// A missing run scope fails closed — the mandatory isolation
    /// scope is never inferred.
    #[test]
    fn request_validation_rejects_missing_scope() {
        let req = GraphPageRequest {
            run_id: RunId::from_trusted_db_bytes([0; 16]),
            ..request()
        };
        let failure = validate_graph_page_request(&req).unwrap_err();
        assert_eq!(failure.code(), "WORKFLOW_GRAPH_SCOPE_REQUIRED");
    }

    /// The seek cursor round-trips its boundary `(created_at,
    /// node_id)` pair.
    #[test]
    fn seek_cursor_carries_keyset_boundary() {
        let cursor = NodeSeekCursor {
            created_at: OffsetDateTime::UNIX_EPOCH,
            node_id: WorkflowNodeId::parse(V7_NODE).unwrap(),
        };
        let mut req = request();
        req.cursor = Some(cursor);
        assert_eq!(req.cursor, Some(cursor));
    }
}
