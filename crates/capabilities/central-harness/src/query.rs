//! Read contract for `central-harness`
//! (rust-application-boundaries.md §2.3/§7.5): the attempt, event-log,
//! pending-approval and budget-usage projections the surfaces render —
//! the read side of upstream's harness store
//! (`LatestAttemptForRun`, `AttemptsForRun`, `CostForTask`, the
//! `ApprovalStore` reads) plus the `central.harness_events` keyset page.
//!
//! Declaration-only, read-only: no locks, no writes, no journaled side
//! effects; every method is scoped to one workspace. Projections return
//! the domain types [`crate::attempt::Attempt`],
//! [`crate::record::EventRecord`] and
//! [`crate::approval::PermissionApproval`] — the persisted rows carry no
//! prompt, operator-input or environment values (the prompt never
//! reaches a store row, and [`crate::record::EventRecord`] is bounded
//! metadata without payload bytes), so nothing sensitive crosses the
//! boundary. Pagination is keyset-only — typed seek cursors, never
//! `OFFSET`.

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, TaskId, WorkspaceId,
};

use crate::approval::PermissionApproval;
use crate::attempt::Attempt;
use crate::domain::codes;
use crate::port::PendingApprovalSummary;
use crate::record::EventRecord;

// ---------------------------------------------------------------------------
// AttemptSummaryRead — the run's attempt projections
// ---------------------------------------------------------------------------

/// `MaxAttemptsForRun` — bounds one [`AttemptSummaryRead::attempts_for_run`]
/// read (the chain-cost read, harness phase 3g decision 9). A run with
/// more is `INVALID_ATTEMPT`.
pub const MAX_ATTEMPTS_FOR_RUN: usize = 64;

/// The run-scoped attempt projections — upstream `Store`'s
/// `LatestAttemptForRun`/`AttemptsForRun` (task detail page and
/// chain-cost read). Implemented by `central-adapter-postgres`;
/// consumed by surfaces that hold no write port.
#[trait_variant::make(Send)]
pub trait AttemptSummaryRead: Send + Sync + 'static {
    /// Upstream `LatestAttemptForRun`: the Run's most recently prepared
    /// attempt within the workspace (`prepared_at DESC, id DESC`), or
    /// `None` — the attempt whose budget and usage the task detail
    /// shows (harness phase 3d decision 9). While an attempt is live it
    /// is also the run's live attempt (the one-live-per-run index).
    /// Nil ids are `INVALID_ATTEMPT`.
    async fn latest_attempt_for_run(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<Attempt>, Failure>;

    /// Upstream `AttemptsForRun`: every attempt of the Run within the
    /// workspace, oldest prepared first (`prepared_at, id`); a Run
    /// without attempts returns none. More than
    /// [`MAX_ATTEMPTS_FOR_RUN`] is `INVALID_ATTEMPT`. Nil ids are
    /// `INVALID_ATTEMPT`.
    async fn attempts_for_run(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Vec<Attempt>, Failure>;
}

// ---------------------------------------------------------------------------
// HarnessEventRead — the harness_events keyset page
// ---------------------------------------------------------------------------

/// Default page size for the harness event log.
pub const DEFAULT_HARNESS_EVENT_PAGE_SIZE: u32 = 100;
/// Hard ceiling on one harness event page.
pub const MAX_HARNESS_EVENT_PAGE_SIZE: u32 = 500;

/// The typed seek cursor for the harness event log — a stable
/// `(attempt_id, seq)` boundary over `central.harness_events`'s
/// primary-key order. `None` on the request asks for the head page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HarnessEventCursor {
    /// The attempt at the page boundary.
    pub attempt_id: HarnessAttemptId,
    /// The event sequence at the page boundary.
    pub seq: u64,
}

/// A workspace-scoped, bounded request for one attempt's recorded
/// event metadata, ascending in `seq`.
#[derive(Debug, Clone, PartialEq)]
pub struct HarnessEventRequest {
    /// The owning workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// The attempt whose events are read.
    pub attempt_id: HarnessAttemptId,
    /// Continuation boundary; `None` requests the head page. When set,
    /// its `attempt_id` must equal the request's — a cursor minted for
    /// another attempt is `INVALID_EVENT`.
    pub cursor: Option<HarnessEventCursor>,
    /// Requested page size; `0` normalizes to
    /// [`DEFAULT_HARNESS_EVENT_PAGE_SIZE`], anything above
    /// [`MAX_HARNESS_EVENT_PAGE_SIZE`] clamps to it.
    pub page_size: u32,
}

/// Validates workspace + attempt scope for harness event reads.
pub fn validate_harness_event_request(req: &HarnessEventRequest) -> Result<(), Failure> {
    if req.workspace_id.is_nil() {
        return Err(Failure::invalid(
            codes::INVALID_EVENT,
            "missing workspace id",
        ));
    }
    if req.attempt_id.is_nil() {
        return Err(Failure::invalid(codes::INVALID_EVENT, "missing attempt id"));
    }
    if let Some(cursor) = &req.cursor
        && cursor.attempt_id != req.attempt_id
    {
        return Err(Failure::invalid(
            codes::INVALID_EVENT,
            "event cursor belongs to another attempt",
        ));
    }
    Ok(())
}

/// Clamps a requested page size into
/// `[DEFAULT_HARNESS_EVENT_PAGE_SIZE, MAX_HARNESS_EVENT_PAGE_SIZE]`.
#[must_use]
pub const fn normalize_harness_event_page_size(v: u32) -> u32 {
    if v == 0 {
        DEFAULT_HARNESS_EVENT_PAGE_SIZE
    } else if v > MAX_HARNESS_EVENT_PAGE_SIZE {
        MAX_HARNESS_EVENT_PAGE_SIZE
    } else {
        v
    }
}

/// The bounded event-log response payload, `seq`-ascending.
/// `next_cursor` is `Some` only when a further page exists.
#[derive(Debug, Clone, PartialEq)]
pub struct HarnessEventPage {
    /// One page of recorded event metadata.
    pub records: Vec<EventRecord>,
    /// Continuation toward later events.
    pub next_cursor: Option<HarnessEventCursor>,
}

/// The seek-cursor read over `central.harness_events` — the attempt's
/// recorded event metadata in `seq` order. Rows are
/// [`EventRecord`]s — bounded metadata (kind, timing, sizes and
/// digests); the raw frame and the payload it derived from are never
/// projected.
#[trait_variant::make(Send)]
pub trait HarnessEventRead: Send + Sync + 'static {
    /// Reads one bounded page of event records for the attempt, seeking
    /// strictly after `req.cursor` when set — keyset pagination, never
    /// `OFFSET`. An out-of-range page returns empty.
    async fn read_page(&self, req: HarnessEventRequest) -> Result<HarnessEventPage, Failure>;
}

// ---------------------------------------------------------------------------
// PendingApprovalRead — the operator-gate projections
// ---------------------------------------------------------------------------

/// The read side of [`crate::port::ApprovalStore`]: the pending and
/// history projections the banner and pages render, without the
/// decision compare-and-set. Every method is scoped to one workspace.
#[trait_variant::make(Send)]
pub trait PendingApprovalRead: Send + Sync + 'static {
    /// One approval of the workspace in its current state, or
    /// `NO_PENDING_APPROVAL` when there is none — upstream
    /// `LoadApproval`.
    async fn load_approval(
        &self,
        workspace_id: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Result<PermissionApproval, Failure>;

    /// The Run's pending approval, if any — upstream
    /// `PendingApprovalForRun` (`requested_at DESC, id DESC LIMIT 1`).
    async fn pending_approval_for_run(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<PermissionApproval>, Failure>;

    /// Summarizes the workspace's pending approvals — the banner read
    /// (decision 13): how many are pending and the Task of the oldest
    /// one.
    async fn pending_approvals(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<PendingApprovalSummary, Failure>;

    /// Up to `limit` (`1..=MAX_APPROVAL_HISTORY`) of the Run's
    /// approvals, newest first — upstream `ApprovalHistory`.
    async fn approval_history(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> Result<Vec<PermissionApproval>, Failure>;
}

/// Re-export of the port bound for the approval-history read.
pub use crate::port::MAX_APPROVAL_HISTORY;

// ---------------------------------------------------------------------------
// BudgetUsageRead — the task cost-cap aggregate
// ---------------------------------------------------------------------------

/// The Task cost-cap read (harness phase 3j decision 2) — upstream
/// `Store.CostForTask`. Implemented by `central-adapter-postgres`.
#[trait_variant::make(Send)]
pub trait BudgetUsageRead: Send + Sync + 'static {
    /// The recorded cost of every attempt of every Run of the Task
    /// within the workspace, in micro-USD, saturating at `i64::MAX` —
    /// upstream `CostForTask`. A Task without attempts (or without
    /// Runs) has used 0. Only the recorded usage counts: an attempt
    /// that ended without a result frame recorded none. Nil ids are
    /// `INVALID_ATTEMPT`.
    async fn cost_for_task(&self, workspace_id: WorkspaceId, task: TaskId) -> Result<i64, Failure>;
}

// ---------------------------------------------------------------------------
// Tests — projection validation and the seek-cursor contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::codes as domain_codes;
    use crate::record::EventRecord;
    use crate::testkit::{block_on, is_code, nil_workspace_id, t0};

    fn ws() -> WorkspaceId {
        WorkspaceId::new()
    }

    fn attempt() -> HarnessAttemptId {
        HarnessAttemptId::new()
    }

    #[test]
    fn normalize_harness_event_page_size_clamps() {
        assert_eq!(
            normalize_harness_event_page_size(0),
            DEFAULT_HARNESS_EVENT_PAGE_SIZE
        );
        assert_eq!(normalize_harness_event_page_size(42), 42);
        assert_eq!(
            normalize_harness_event_page_size(u32::MAX),
            MAX_HARNESS_EVENT_PAGE_SIZE
        );
    }

    #[test]
    fn validate_harness_event_request_scopes() {
        let mut req = HarnessEventRequest {
            workspace_id: nil_workspace_id(),
            attempt_id: attempt(),
            cursor: None,
            page_size: 0,
        };
        let err = validate_harness_event_request(&req).unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_EVENT), "{err}");
        req.workspace_id = ws();
        req.attempt_id = HarnessAttemptId::from_trusted_db_bytes([0; 16]);
        let err = validate_harness_event_request(&req).unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_EVENT), "{err}");
        req.attempt_id = attempt();
        validate_harness_event_request(&req).unwrap();
        // A cursor minted for another attempt is refused.
        req.cursor = Some(HarnessEventCursor {
            attempt_id: attempt(),
            seq: 7,
        });
        let err = validate_harness_event_request(&req).unwrap_err();
        assert!(is_code(&err, domain_codes::INVALID_EVENT), "{err}");
        req.cursor = Some(HarnessEventCursor {
            attempt_id: req.attempt_id,
            seq: 7,
        });
        validate_harness_event_request(&req).unwrap();
    }

    // A minimal in-memory reader proving the query traits are
    // implementable without driver types, and exercising the
    // seek-cursor contract: strictly-after ordering, bounded pages,
    // no offset arithmetic.
    struct MemRead {
        records: Vec<EventRecord>,
        attempts: Vec<Attempt>,
        approvals: Vec<PermissionApproval>,
    }

    impl AttemptSummaryRead for MemRead {
        async fn latest_attempt_for_run(
            &self,
            workspace_id: WorkspaceId,
            run: RunId,
        ) -> Result<Option<Attempt>, Failure> {
            Ok(self
                .attempts
                .iter()
                .filter(|a| a.workspace_id == workspace_id && a.run_id == run)
                .max_by(|a, b| {
                    a.prepared_at
                        .cmp(&b.prepared_at)
                        .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
                })
                .cloned())
        }

        async fn attempts_for_run(
            &self,
            workspace_id: WorkspaceId,
            run: RunId,
        ) -> Result<Vec<Attempt>, Failure> {
            let mut out: Vec<Attempt> = self
                .attempts
                .iter()
                .filter(|a| a.workspace_id == workspace_id && a.run_id == run)
                .cloned()
                .collect();
            out.sort_by(|a, b| {
                a.prepared_at
                    .cmp(&b.prepared_at)
                    .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
            });
            if out.len() > MAX_ATTEMPTS_FOR_RUN {
                return Err(Failure::invalid(
                    domain_codes::INVALID_ATTEMPT,
                    "run has more than 64 attempts",
                ));
            }
            Ok(out)
        }
    }

    impl HarnessEventRead for MemRead {
        async fn read_page(&self, req: HarnessEventRequest) -> Result<HarnessEventPage, Failure> {
            validate_harness_event_request(&req)?;
            let limit = normalize_harness_event_page_size(req.page_size) as usize;
            let mut page: Vec<EventRecord> = self
                .records
                .iter()
                .filter(|r| r.attempt == req.attempt_id)
                .filter(|r| r.seq > req.cursor.map_or(0, |c| c.seq))
                .cloned()
                .collect();
            page.sort_by_key(|r| r.seq);
            let has_more = page.len() > limit;
            page.truncate(limit);
            let next_cursor = if has_more {
                page.last().map(|r| HarnessEventCursor {
                    attempt_id: r.attempt,
                    seq: r.seq,
                })
            } else {
                None
            };
            Ok(HarnessEventPage {
                records: page,
                next_cursor,
            })
        }
    }

    impl PendingApprovalRead for MemRead {
        async fn load_approval(
            &self,
            workspace_id: WorkspaceId,
            id: HarnessPermissionApprovalId,
        ) -> Result<PermissionApproval, Failure> {
            self.approvals
                .iter()
                .find(|a| a.workspace_id == workspace_id && a.id == id)
                .cloned()
                .ok_or_else(|| {
                    Failure::not_found(domain_codes::NO_PENDING_APPROVAL, format!("approval {id}"))
                })
        }

        async fn pending_approval_for_run(
            &self,
            workspace_id: WorkspaceId,
            run: RunId,
        ) -> Result<Option<PermissionApproval>, Failure> {
            Ok(self
                .approvals
                .iter()
                .find(|a| {
                    a.workspace_id == workspace_id
                        && a.run_id == run
                        && a.state == crate::approval::ApprovalState::Pending
                })
                .cloned())
        }

        async fn pending_approvals(
            &self,
            workspace_id: WorkspaceId,
        ) -> Result<PendingApprovalSummary, Failure> {
            let pending: Vec<&PermissionApproval> = self
                .approvals
                .iter()
                .filter(|a| {
                    a.workspace_id == workspace_id
                        && a.state == crate::approval::ApprovalState::Pending
                })
                .collect();
            Ok(PendingApprovalSummary {
                count: pending.len(),
                oldest_task_id: pending.first().map(|a| a.task_id),
            })
        }

        async fn approval_history(
            &self,
            workspace_id: WorkspaceId,
            run: RunId,
            limit: usize,
        ) -> Result<Vec<PermissionApproval>, Failure> {
            if !(1..=MAX_APPROVAL_HISTORY).contains(&limit) {
                return Err(Failure::invalid(
                    domain_codes::INVALID_APPROVAL,
                    "history needs a bounded page",
                ));
            }
            let mut out: Vec<PermissionApproval> = self
                .approvals
                .iter()
                .filter(|a| a.workspace_id == workspace_id && a.run_id == run)
                .cloned()
                .collect();
            out.truncate(limit);
            Ok(out)
        }
    }

    impl BudgetUsageRead for MemRead {
        async fn cost_for_task(
            &self,
            workspace_id: WorkspaceId,
            _task: TaskId,
        ) -> Result<i64, Failure> {
            Ok(self
                .attempts
                .iter()
                .filter(|a| a.workspace_id == workspace_id)
                .map(|a| a.usage.cost_micro_usd)
                .sum())
        }
    }

    fn rec(seq: u64) -> EventRecord {
        EventRecord {
            attempt: HarnessAttemptId::from_trusted_db_bytes([7; 16]),
            seq,
            kind: crate::event::EventKind::Message,
            at: t0(),
            raw_size: 1,
            raw_sha256: [0; 32],
            ..EventRecord::default()
        }
    }

    #[test]
    fn harness_event_read_seeks_without_offset() {
        let attempt_id = HarnessAttemptId::from_trusted_db_bytes([7; 16]);
        let reader = MemRead {
            records: (1..=7u64).map(rec).collect(),
            attempts: Vec::new(),
            approvals: Vec::new(),
        };
        let req = HarnessEventRequest {
            workspace_id: ws(),
            attempt_id,
            cursor: None,
            page_size: 3,
        };
        // Head page: seqs 1..=3 with a continuation.
        let page = block_on(reader.read_page(req.clone())).unwrap();
        assert_eq!(
            page.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let cursor = page.next_cursor.unwrap();
        assert_eq!(cursor.seq, 3);
        assert_eq!(cursor.attempt_id, attempt_id);
        // The second page seeks strictly after the cursor — no overlap,
        // no OFFSET arithmetic.
        let page = block_on(reader.read_page(HarnessEventRequest {
            cursor: Some(cursor),
            ..req.clone()
        }))
        .unwrap();
        assert_eq!(
            page.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![4, 5, 6]
        );
        // Tail page: one record, no continuation.
        let page = block_on(reader.read_page(HarnessEventRequest {
            cursor: page.next_cursor,
            ..req
        }))
        .unwrap();
        assert_eq!(
            page.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![7]
        );
        assert!(page.next_cursor.is_none());
    }
}
