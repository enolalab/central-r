//! The domain-facing seams the Phase-2 Slice-2D retry/timeout machinery
//! pushes work through — the port of `central/internal/retry/port`:
//! the durable outcome ledger, the timeout sweep, and the compensation
//! execution on the store side, plus the kill-confirmation boundary,
//! the managed-compensation executor, and the clock/jitter sources that
//! keep backoff and deadline evaluation deterministic under test.
//!
//! No adapter types cross this boundary; the PostgreSQL implementation
//! lives inside the scheduler store (`central-adapter-postgres`, the
//! fenced write path — the outcome transaction must share its lock
//! order and lease re-check). Every trait is
//! `#[trait_variant::make(Send)]` with `Send + Sync + 'static` so trait
//! objects compose with multi-threaded `tokio`/`axum` handlers
//! (rust-application-boundaries.md §2.3); every error is the
//! workspace-wide [`central_foundation::failure::Failure`].
//!
//! Transactional-outbox intent (spec-5 §3): every mutating
//! [`Store`] method commits its state change AND its journal/outbox
//! event rows in ONE transaction under the run-row serialization
//! point — the `run_events` append and the `event_outbox` row the
//! publisher later drains are written atomically inside the store's
//! commit, never as a follow-up effect. The drain/publish half of the
//! outbox is `central-eventjournal`'s port, not this crate's.
//!
//! Read side note: the `not_before ≤ now` claim-eligibility gate that a
//! journaled `retry_at` arms is the scheduler claim port's condition
//! (`central-scheduler`), not a method here — this crate evaluates and
//! journals the instant; the claim path owns eligibility.
//!
//! OWNING PACKET: P2D02/P2D03/P2D04. SLICE: 2D.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, SessionAttemptId, WorkflowNodeId};
use time::{Duration, OffsetDateTime};

use crate::domain::{AttemptCounts, FailureClass, OutcomeKind};

// ---------------------------------------------------------------------------
// Store — outcome ledger, timeout sweep, compensation
// ---------------------------------------------------------------------------

/// One definite attempt outcome report arriving at the store boundary
/// (upstream `Outcome`): the spec-5 `(attempt_id, outcome_kind)`
/// idempotency key, the payload fingerprint a replay compares, and the
/// spec-4 reason code the store classifies at record time. Ambiguous
/// outcomes never reach this port — locked input 1 admits definite
/// failures only.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The `session_attempts` row the outcome closes.
    pub attempt_id: SessionAttemptId,
    /// The ledger `outcome_kind` — the closed [`OutcomeKind`]
    /// vocabulary (`succeeded` | `failed` | `cancelled`); `ambiguous`
    /// is a parked state, never an outcome.
    pub kind: OutcomeKind,
    /// The spec-4 SCREAMING_CASE code as journaled text —
    /// [`crate::domain::classify`] decides the class persisted on the
    /// row and the node transition that follows. Raw text, because a
    /// code this build predates must classify terminal rather than
    /// error. Must be non-empty on a `failed` report (the store's
    /// validation gate).
    pub reason_code: String,
    /// SHA-256 of the canonical outcome payload — the spec-5
    /// replay-compare value; exactly 32 bytes by construction
    /// (`attempt_outcomes_fingerprint_check`).
    pub fingerprint: [u8; 32],
    /// A provider `retry_after` hint, honored (bounded by the policy
    /// cap) only on `RATE_LIMITED` reports and ignored otherwise.
    pub retry_after: Option<Duration>,
}

/// What [`Store::record_outcome`] committed — or, on a deduped replay,
/// what the prior commit recorded (upstream `OutcomeResult`).
#[derive(Debug, Clone, PartialEq)]
pub struct OutcomeResult {
    /// A replay under the same key+fingerprint: the recorded row
    /// stands, no second transition or event exists.
    pub deduped: bool,
    /// The `failure_class` persisted on the outcome row.
    pub class: FailureClass,
    /// The node's state after the commit — the workflow node-state
    /// vocabulary (`ready`, `succeeded`, `failed_terminal`, ...) owned
    /// by `central-workflow`, carried here as its journaled text.
    pub node_status: String,
    /// The journaled retry instant the node's `not_before` carries when
    /// a retry was scheduled; `None` otherwise.
    pub retry_at: Option<OffsetDateTime>,
}

/// One sweep-skipped scope: a node or run carrying an unresolved
/// ambiguous descendant whose timers therefore never fired (locked
/// input 3). Typed per level — upstream reports both kinds in one
/// `[]uuid.UUID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkippedScope {
    /// A workflow node whose timer was blocked.
    Node(WorkflowNodeId),
    /// A run whose timer was blocked.
    Run(RunId),
}

/// What one [`Store::sweep_timeouts`] pass committed (upstream
/// `SweepSummary`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SweepSummary {
    /// The nodes landed `failed_terminal`/`NODE_TIMEOUT`.
    pub node_timeouts: Vec<WorkflowNodeId>,
    /// The runs landed `failed_terminal`/`WORKFLOW_TIMEOUT` after the
    /// spec-1 cancel cascade.
    pub workflow_timeouts: Vec<RunId>,
    /// The scopes the sweep skipped because an unresolved ambiguous
    /// descendant blocks their timers — locked input 3: timers never
    /// fire across it.
    pub skipped_ambiguous: Vec<SkippedScope>,
}

/// The domain-facing seam to the durable retry substrate (upstream
/// `Store`). Every mutating method commits its state change and its
/// journal events — `run_events` plus the `event_outbox` intent — in
/// ONE transaction under the run-row serialization point, and every
/// attempt-scoped write passes the lease fence (run → node → attempt →
/// live lease, the scheduler store's order).
#[trait_variant::make(Send)]
pub trait Store: Send + Sync + 'static {
    /// Durably records one definite attempt outcome: the
    /// `attempt_outcomes` key row with the classified `failure_class`,
    /// the attempt's terminal state, the lease release, the node
    /// transition, and the journaled event commit together.
    ///
    /// A retryable failure inside budget returns the node to `ready`
    /// with `not_before` = the journaled `retry_at` ([`compute_delay`]
    /// evaluated at record time, journaled verbatim); exhaustion or a
    /// terminal class lands `failed_terminal` carrying
    /// `RETRY_BUDGET_EXHAUSTED` or the class's code plus the failing
    /// `attempt_id`. A replay under the same `(attempt_id,
    /// outcome_kind)` key and fingerprint returns the recorded result
    /// with `deduped = true`; a matching key with a different
    /// fingerprint rejects with `DUPLICATE_IDEMPOTENCY_KEY`.
    ///
    /// [`compute_delay`]: crate::domain::compute_delay
    async fn record_outcome(&self, outcome: Outcome) -> Result<OutcomeResult, Failure>;

    /// Reads the node's journaled attempt consumption — per failure
    /// class and total — the [`budget_remaining`] input (spec-4
    /// decision 3: counting reads the node's `session_attempt` rows).
    ///
    /// [`budget_remaining`]: crate::domain::budget_remaining
    async fn attempt_counts(&self, node_id: WorkflowNodeId) -> Result<AttemptCounts, Failure>;

    /// The node's first dispatch instant — `MIN(claimed_at)`, the
    /// instant the node-timeout bound measures from. `None` means the
    /// node never dispatched and no node-timeout clock is running.
    async fn first_dispatch_at(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Option<OffsetDateTime>, Failure>;

    /// Evaluates the deadline bounds at `now` (spec-4 decision 5):
    /// nodes whose first dispatch plus `node_timeout_seconds` passed
    /// kill their live attempt through [`Killer`] — a confirmed kill
    /// enters [`record_outcome`](Self::record_outcome) as the definite
    /// `SESSION_WALL_CLOCK_REACHED` failure, an unconfirmed kill parks
    /// ambiguous — then land `failed_terminal`/`NODE_TIMEOUT`; runs
    /// whose deadline passed cancel running attempts, cascade
    /// non-terminal nodes cancelled, and land
    /// `failed_terminal`/`WORKFLOW_TIMEOUT`. A node or run carrying an
    /// unresolved ambiguous descendant is skipped — timers never fire
    /// across it (locked input 3).
    async fn sweep_timeouts(&self, now: OffsetDateTime) -> Result<SweepSummary, Failure>;

    /// Evaluates the node's `spec.on_terminal_failure` hook at most
    /// once, keyed on the node (spec-4 decision 6): managed kinds
    /// execute through [`CompensationExecutor`] and journal their
    /// outcome; every other value journals `compensation_requested`
    /// only. A prior journaled execution dedupes the replay, and a hook
    /// failure never reopens the terminal node.
    async fn run_compensation(&self, node_id: WorkflowNodeId) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Killer — the session kill-confirmation boundary
// ---------------------------------------------------------------------------

/// Terminates one live session attempt — the launcher/adapter cancel
/// control behind the session-timeout level of the hierarchy.
/// `Ok(true)` reports the kill is KNOWN to have taken effect: confirmed
/// makes the failure definite (`SESSION_WALL_CLOCK_REACHED`, retryable
/// through [`Store::record_outcome`]); `Ok(false)` leaves the outcome
/// unknowable and the caller parks the attempt ambiguous for an
/// operator decision (locked input 2) — never a definite failure.
#[trait_variant::make(Send)]
pub trait Killer: Send + Sync + 'static {
    /// Kills the attempt; the boolean is kill confirmation, not
    /// success — `Ok(false)` is a valid, meaningful verdict.
    async fn kill(&self, attempt_id: SessionAttemptId) -> Result<bool, Failure>;
}

// ---------------------------------------------------------------------------
// CompensationExecutor — Central-managed hooks only
// ---------------------------------------------------------------------------

/// Performs the Central-managed `on_terminal_failure` effects (spec-4
/// decision 6). Unmanaged values never reach this port — the store
/// journals `compensation_requested` for the leader/operator instead;
/// agent-authored cleanup is never auto-executed in Phase 2.
#[trait_variant::make(Send)]
pub trait CompensationExecutor: Send + Sync + 'static {
    /// Removes the node's worktree/private dir — the provisioner's free
    /// behind the port.
    async fn cleanup_workspace(&self, node_id: WorkflowNodeId) -> Result<(), Failure>;

    /// Marks the node's declared artifacts kept for inspection past the
    /// usual lifecycle.
    async fn retain_artifacts(&self, node_id: WorkflowNodeId) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Clock and Rand — deterministic evaluation seams
// ---------------------------------------------------------------------------

/// Supplies evaluation instants for the sweep and deadline predicates
/// (upstream `Clock`). PostgreSQL stays authoritative for committed
/// timestamps; the clock feeds pre-commit evaluation only.
pub trait Clock: Send + Sync + 'static {
    /// The current evaluation instant.
    fn now(&self) -> OffsetDateTime;
}

/// The default real [`Clock`]: UTC wall time (upstream `SystemClock`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Supplies the full-jitter draw [`compute_delay`] applies — a uniform
/// `[0,1)` float (upstream `Rand`). Injectable so tests pin the jitter
/// and the journaled `retry_at` stays reproducible.
///
/// [`compute_delay`]: crate::domain::compute_delay
pub trait Rand: Send + Sync + 'static {
    /// Draws the jitter sample.
    fn draw(&self) -> f64;
}

/// Any `Fn() -> f64` is a [`Rand`] — the closure form of upstream's
/// `RandFunc` adapter.
impl<F> Rand for F
where
    F: Fn() -> f64 + Send + Sync + 'static,
{
    fn draw(&self) -> f64 {
        self()
    }
}
