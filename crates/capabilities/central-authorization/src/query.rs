//! Bounded read contract for `central-authorization`:
//! `ApprovalSummaryRead` (Q5) — the task-scoped summary of capability
//! grants for the approval surface.
//!
//! Query contracts (rust-application-boundaries.md §2.5) carry typed
//! seek cursors — never offsets — bounded page sizes, and a scope the
//! caller must supply. The projection is display-safe: identity texts
//! and enum vocabularies only, never policy internals or secrets.

use central_foundation::failure::Failure;
use central_foundation::identity::{ApprovalId, TaskId, WorkspaceId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::domain::codes;

/// Maximum rows one `ApprovalSummaryRead` page may carry. The upstream
/// surface shows at most ten; the bound is enforced on the request.
pub const MAX_APPROVAL_PAGE: usize = 10;
/// The default page size when the request leaves `limit` unset.
pub const DEFAULT_APPROVAL_PAGE: usize = 10;

/// Typed seek cursor over `central.approvals` ordered by
/// `(updated_at, id)` descending — the summary shows the most recently
/// decided grants first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalCursor {
    /// `updated_at` of the last row of the previous page.
    pub updated_at: OffsetDateTime,
    /// `id` tiebreaker of that row.
    pub id: ApprovalId,
}

/// The bounded request. `approver` scopes the read to one actor —
/// the summary exists to show *that* identity what it may rely on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSummaryRequest {
    /// Owning Workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// Optional Task filter (task-scoped grants surface per Task).
    pub task_id: Option<TaskId>,
    /// The actor whose grants are summarized (bounded identity text).
    pub approver: String,
    /// Continuation cursor from the previous page.
    pub cursor: Option<ApprovalCursor>,
    /// Requested page size; `None` → [`DEFAULT_APPROVAL_PAGE`], always
    /// clamped to [`MAX_APPROVAL_PAGE`].
    pub limit: Option<usize>,
}

impl ApprovalSummaryRequest {
    /// Validates scope and clamps the page bound. An unbounded request
    /// is a `FailureKind::Invalid`, never a silent full-table scan.
    pub fn validate(&self) -> Result<usize, Failure> {
        if self.approver.is_empty() || self.approver.len() > crate::domain::MAX_IDENTITY_BYTES {
            return Err(Failure::invalid(
                codes::REQUEST_INVALID,
                "the approver scope must be a bounded identity",
            ));
        }
        let limit = self.limit.unwrap_or(DEFAULT_APPROVAL_PAGE);
        if limit == 0 || limit > MAX_APPROVAL_PAGE {
            return Err(Failure::invalid(
                codes::REQUEST_INVALID,
                "the page size must be within 1..=10",
            ));
        }
        Ok(limit)
    }
}

/// One display-safe row of the summary — the fields an approval
/// surface needs to answer "what may this actor rely on, until when".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSummary {
    /// The approval row identity.
    pub approval_id: ApprovalId,
    /// `resource.effect` taxonomy identity.
    pub capability_identity: String,
    /// Canonical scope selector.
    pub scope: String,
    /// `grant` | `revoke`.
    pub action: String,
    /// `active` | `revoked` | `suspended` | `expired`.
    pub state: String,
    /// Suspend reason, when suspended (e.g. `restore_review_required`).
    pub suspend_reason: Option<String>,
    /// Auditable decision reason.
    pub reason: String,
    /// Establishing authority identity.
    pub authority_identity: String,
    /// Issuance and last-decision times.
    pub created_at: OffsetDateTime,
    /// Last decision time.
    pub updated_at: OffsetDateTime,
    /// Grant expiry — the moment it stops being reliable.
    pub expiry_at: Option<OffsetDateTime>,
}

/// One page of the summary plus the cursor for the next page — `None`
/// when the read is exhausted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSummaryPage {
    /// Rows, most recently decided first.
    pub approvals: Vec<ApprovalSummary>,
    /// Cursor for the next page; absent at the end of the feed.
    pub next_cursor: Option<ApprovalCursor>,
}

/// The Q5 read contract. Seek-paginated — there is deliberately no
/// offset parameter.
#[trait_variant::make(Send)]
pub trait ApprovalSummaryRead: Send + Sync + 'static {
    /// Reads one bounded page.
    async fn read_page(
        &self,
        request: &ApprovalSummaryRequest,
    ) -> Result<ApprovalSummaryPage, Failure>;
}
