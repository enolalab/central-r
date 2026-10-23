//! Read contract for `central-retry`: `AttemptHistoryRead` — the
//! attempt outcome/decision history projection over the b37 ledger
//! tables `attempt_outcomes` (the classified failure evidence behind
//! [`crate::domain::AttemptCounts`]) and `attempt_decisions` (the
//! one-row-ever operator decision for a parked ambiguous attempt,
//! spec-5's key table).
//!
//! Declaration-only: plain keyed reads — the node's outcome ledger
//! ordered by `attempt_seq` (bounded by `max_attempts_total` in
//! practice), and the single-row decision read keyed on the attempt
//! primary key. No locks, no writes, no journaled side effects; the
//! caller scope-checks the run/node through its own projection first,
//! matching the read-side convention the run views apply.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, SessionAttemptId, WorkflowNodeId};
use time::OffsetDateTime;

use crate::domain::OutcomeKind;

// ---------------------------------------------------------------------------
// attempt_outcomes projection — the classified failure ledger
// ---------------------------------------------------------------------------

/// One journaled `attempt_outcomes` row projected with its attempt's
/// `attempt_seq` — one entry of the node's classified-failure ledger.
///
/// `reason_code` and `failure_class` are carried verbatim as their
/// journaled text: both columns are unpinned in the schema, so a row
/// recorded by a build with a different vocabulary must project without
/// being re-classified or rejected — the projection is evidence, not a
/// decision.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptOutcomeView {
    /// The attempt the outcome closed.
    pub attempt_id: SessionAttemptId,
    /// The attempt's 1-based ordinal within the node — the ledger's
    /// ordering key.
    pub attempt_seq: i64,
    /// The terminal outcome kind (`succeeded` | `failed` | `cancelled`).
    pub kind: OutcomeKind,
    /// The spec-4 reason code verbatim — may name a code outside this
    /// build's [`crate::domain::ReasonCode`] set.
    pub reason_code: String,
    /// The persisted `failure_class` text verbatim — the
    /// classification the recording commit computed, never re-derived
    /// at read time.
    pub failure_class: String,
    /// The spec-5 replay-compare fingerprint recorded with the row.
    pub payload_fingerprint: [u8; 32],
    /// When the row committed.
    pub recorded_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// attempt_decisions projection — the one-row-ever operator decision
// ---------------------------------------------------------------------------

/// The closed `attempt_decisions.decision` vocabulary, pinned by
/// migration b37's `attempt_decisions_decision_check` (`resume` |
/// `rerun`). Restated here on the read side; the write-side vocabulary
/// is `central-workflow`'s (`DecisionResume`/`DecisionRerun` upstream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptDecision {
    /// `resume` — park the node for harness-native continuation.
    Resume,
    /// `rerun` — abandon the ambiguous attempt and return the node to
    /// `ready` for a fresh attempt.
    Rerun,
}

impl AttemptDecision {
    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resume => "resume",
            Self::Rerun => "rerun",
        }
    }

    /// Parses the persisted text form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "resume" => Some(Self::Resume),
            "rerun" => Some(Self::Rerun),
            _ => None,
        }
    }
}

/// The one-row-ever `attempt_decisions` record for a parked ambiguous
/// attempt (spec-5: the operator's resume-vs-rerun choice, written once
/// and replayed verbatim).
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptDecisionView {
    /// The ambiguous attempt decided — the primary key.
    pub attempt_id: SessionAttemptId,
    /// The owning run.
    pub run_id: RunId,
    /// The owning node.
    pub node_id: WorkflowNodeId,
    /// The recorded decision.
    pub decision: AttemptDecision,
    /// The spec-5 replay-compare fingerprint recorded with the row.
    pub payload_fingerprint: [u8; 32],
    /// The operator identity that recorded the decision.
    pub decided_by: String,
    /// When the decision committed.
    pub decided_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// AttemptHistoryRead
// ---------------------------------------------------------------------------

/// The read contract behind the attempt-decision history projection.
/// Implemented by `central-adapter-postgres`; consumed by the retry
/// surfaces that render or audit the journaled ledger.
#[trait_variant::make(Send)]
pub trait AttemptHistoryRead: Send + Sync + 'static {
    /// The node's journaled outcome ledger — every `attempt_outcomes`
    /// row joined to its attempt, ordered by `attempt_seq`. This is the
    /// durable evidence [`crate::port::Store::attempt_counts`]
    /// aggregates. Bounded by the node's attempt budget in practice.
    async fn list_node_outcomes(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<AttemptOutcomeView>, Failure>;

    /// The one-row-ever operator decision for a parked ambiguous
    /// attempt. `None` while the attempt is unresolved — the same
    /// probe the sweep's locked-input-3 blocker evaluates (`NOT EXISTS
    /// attempt_decisions`), so a `None` verdict here is precisely "the
    /// ambiguous attempt still blocks the timers".
    async fn load_attempt_decision(
        &self,
        attempt_id: SessionAttemptId,
    ) -> Result<Option<AttemptDecisionView>, Failure>;
}
