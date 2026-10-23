//! The Phase-2 Slice-2D retry/timeout domain — pure synchronous port of
//! `central/internal/retry/domain.go`.
//!
//! Owns the fail-closed failure-class taxonomy, the journaled backoff
//! policy, the per-class and absolute attempt budgets, the three-level
//! timeout hierarchy predicates, the compensation-hook vocabulary, and
//! the consolidated after-failure verdict ([`decide`]) that upstream
//! sequences inside `decideAfterFailureTx`. It contains no persistence,
//! transport, or scheduler types; every timestamp arrives as
//! caller-supplied durable evidence — this module never reads a clock.
//!
//! Vocabularies owned elsewhere — the outcome-kind set (the scheduler's
//! terminal attempt states, pinned by migration b37's
//! `attempt_outcomes_outcome_kind_check`) — are RESTATED here per the
//! upstream precedent; the b37 vocabulary test keeps the two sides in
//! step.
//!
//! OWNING PACKET: P2D01/P2D02/P2D03/P2D04. SLICE: 2D.

use std::collections::BTreeMap;
use std::fmt;

use time::{Duration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Reason codes — spec-4 failure semantics
// ---------------------------------------------------------------------------

/// The closed SCREAMING_CASE reason-code vocabulary spec-4's taxonomy
/// declares, plus the spec-5 idempotency codes that travel on the same
/// refusal surfaces. Every journaled attempt failure carries exactly one
/// code and the class it maps to; the class, not the code, decides
/// retryability.
///
/// Codes owned by spec 8 but classed here (spec-4 failure semantics):
/// [`Self::SessionWallClockReached`] and
/// [`Self::SessionCostCeilingReached`] classify
/// [`FailureClass::SessionTimeout`]; `CAPACITY_ADMISSION_DEFERRED` is
/// pre-attempt deferral — no attempt row exists, no outcome is
/// journaled, and it is deliberately absent below because [`classify`]
/// never sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReasonCode {
    /// `PROCESS_EXIT_NONZERO` — a harness process that exited non-zero:
    /// a definite, observed failure. Class transient.
    ProcessExitNonzero,
    /// `ADAPTER_ERROR` — a structured adapter-reported failure. Class
    /// transient.
    AdapterError,
    /// `RATE_LIMITED` — a provider rate-limit refusal; it may carry a
    /// `retry_after` hint [`compute_delay`] honors bounded by cap.
    /// Class transient.
    RateLimited,
    /// `WORKSPACE_PROVISION_FAILED` — a dispatch that failed preparing
    /// the workspace. Class dispatch_infra.
    WorkspaceProvisionFailed,
    /// `LAUNCHER_REFUSED` — a confirmed launcher refusal; nothing ran.
    /// Class dispatch_infra.
    LauncherRefused,
    /// `SESSION_WALL_CLOCK_REACHED` — a kill-confirmed session
    /// wall-clock expiry (spec-8 code, classed here). Class
    /// session_timeout.
    SessionWallClockReached,
    /// `SESSION_COST_CEILING_REACHED` — a confirmed session cost
    /// ceiling breach (spec-8 code, classed here). Class
    /// session_timeout.
    SessionCostCeilingReached,
    /// `SPEC_VALIDATION_FAILED` — a child-spec rejection. Class
    /// terminal.
    SpecValidationFailed,
    /// `BUDGET_EXHAUSTED` — a node's declared budget spent. Class
    /// terminal.
    BudgetExhausted,
    /// `WORKSPACE_UNAVAILABLE` — a workspace the node can never obtain.
    /// Class terminal.
    WorkspaceUnavailable,
    /// `CAPABILITY_MISSING` — a node no worker can ever satisfy. Class
    /// terminal.
    CapabilityMissing,
    /// `NODE_TIMEOUT` — expiry of the node's aggregate bound: first
    /// dispatch plus `node_timeout_seconds`. Class node_timeout — a
    /// bound, not a retryable class.
    NodeTimeout,
    /// `WORKFLOW_TIMEOUT` — expiry of the run's graph bound; the run
    /// lands `failed_terminal` after the spec-1 cancel cascade. Class
    /// workflow_timeout.
    WorkflowTimeout,
    /// `RETRY_BUDGET_EXHAUSTED` — the per-class or total attempt
    /// ceiling reached; the terminal reason code `node_failed_terminal`
    /// carries when no class code applies. Class terminal.
    RetryBudgetExhausted,
    /// `DUPLICATE_IDEMPOTENCY_KEY` — a reused idempotency key with a
    /// different payload fingerprint (spec-5 replay rule). Class
    /// terminal.
    DuplicateIdempotencyKey,
    /// `ARTIFACT_ALREADY_FINALIZED` — a second finalize under an
    /// existing `(attempt_id, artifact_name)` with a different checksum
    /// (spec-5). Class terminal.
    ArtifactAlreadyFinalized,
    /// `ARTIFACT_CHECKSUM_MISMATCH` — a computed checksum differing
    /// from the declared one; the finalize aborts pre-commit (spec-5).
    /// Class terminal.
    ArtifactChecksumMismatch,
}

impl ReasonCode {
    /// Every reason code in declaration order — the closed vocabulary a
    /// journaled `reason_code` must belong to to earn a retryable
    /// class.
    pub const ALL: [Self; 17] = [
        Self::ProcessExitNonzero,
        Self::AdapterError,
        Self::RateLimited,
        Self::WorkspaceProvisionFailed,
        Self::LauncherRefused,
        Self::SessionWallClockReached,
        Self::SessionCostCeilingReached,
        Self::SpecValidationFailed,
        Self::BudgetExhausted,
        Self::WorkspaceUnavailable,
        Self::CapabilityMissing,
        Self::NodeTimeout,
        Self::WorkflowTimeout,
        Self::RetryBudgetExhausted,
        Self::DuplicateIdempotencyKey,
        Self::ArtifactAlreadyFinalized,
        Self::ArtifactChecksumMismatch,
    ];

    /// The journaled SCREAMING_CASE text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExitNonzero => "PROCESS_EXIT_NONZERO",
            Self::AdapterError => "ADAPTER_ERROR",
            Self::RateLimited => "RATE_LIMITED",
            Self::WorkspaceProvisionFailed => "WORKSPACE_PROVISION_FAILED",
            Self::LauncherRefused => "LAUNCHER_REFUSED",
            Self::SessionWallClockReached => "SESSION_WALL_CLOCK_REACHED",
            Self::SessionCostCeilingReached => "SESSION_COST_CEILING_REACHED",
            Self::SpecValidationFailed => "SPEC_VALIDATION_FAILED",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
            Self::WorkspaceUnavailable => "WORKSPACE_UNAVAILABLE",
            Self::CapabilityMissing => "CAPABILITY_MISSING",
            Self::NodeTimeout => "NODE_TIMEOUT",
            Self::WorkflowTimeout => "WORKFLOW_TIMEOUT",
            Self::RetryBudgetExhausted => "RETRY_BUDGET_EXHAUSTED",
            Self::DuplicateIdempotencyKey => "DUPLICATE_IDEMPOTENCY_KEY",
            Self::ArtifactAlreadyFinalized => "ARTIFACT_ALREADY_FINALIZED",
            Self::ArtifactChecksumMismatch => "ARTIFACT_CHECKSUM_MISMATCH",
        }
    }

    /// Parses the journaled text form; `None` on anything outside the
    /// declared vocabulary — callers needing a class should use
    /// [`classify`], which fails closed instead of returning `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|code| code.as_str() == s)
    }

    /// The failure class this code maps to under the spec-4 taxonomy
    /// table — total over the declared vocabulary by construction.
    #[must_use]
    pub const fn class(self) -> FailureClass {
        match self {
            Self::ProcessExitNonzero | Self::AdapterError | Self::RateLimited => {
                FailureClass::Transient
            }
            Self::WorkspaceProvisionFailed | Self::LauncherRefused => FailureClass::DispatchInfra,
            Self::SessionWallClockReached | Self::SessionCostCeilingReached => {
                FailureClass::SessionTimeout
            }
            Self::NodeTimeout => FailureClass::NodeTimeout,
            Self::WorkflowTimeout => FailureClass::WorkflowTimeout,
            Self::SpecValidationFailed
            | Self::BudgetExhausted
            | Self::WorkspaceUnavailable
            | Self::CapabilityMissing
            | Self::RetryBudgetExhausted
            | Self::DuplicateIdempotencyKey
            | Self::ArtifactAlreadyFinalized
            | Self::ArtifactChecksumMismatch => FailureClass::Terminal,
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Failure-class taxonomy (spec-4 decision 1)
// ---------------------------------------------------------------------------

/// The retry/timeout taxonomy class an attempt failure carries.
/// Migration b37 leaves `attempt_outcomes.failure_class` an unpinned
/// string: this enum is the closed six-class vocabulary's single owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FailureClass {
    /// `transient` — definite failures of the work itself: process
    /// exit, structured adapter error, provider rate limit. Retryable.
    Transient,
    /// `dispatch_infra` — failures of the dispatch substrate:
    /// workspace provisioning, launcher refusal. Retryable.
    DispatchInfra,
    /// `session_timeout` — confirmed session-ceiling kills: wall clock
    /// or cost. Retryable.
    SessionTimeout,
    /// `terminal` — failures no retry can repair: spec, budget,
    /// workspace, capability — plus every unknown code: the taxonomy
    /// fails closed.
    Terminal,
    /// `node_timeout` — the node's aggregate bound expiring. A bound,
    /// not a retryable class: expiry is always `failed_terminal`.
    NodeTimeout,
    /// `workflow_timeout` — the run's graph bound expiring. A bound,
    /// not a retryable class: expiry cascades the run
    /// `failed_terminal`.
    WorkflowTimeout,
}

impl FailureClass {
    /// Every failure class in declaration order — the closed six-class
    /// vocabulary a journaled `failure_class` must belong to.
    pub const ALL: [Self; 6] = [
        Self::Transient,
        Self::DispatchInfra,
        Self::SessionTimeout,
        Self::Terminal,
        Self::NodeTimeout,
        Self::WorkflowTimeout,
    ];

    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::DispatchInfra => "dispatch_infra",
            Self::SessionTimeout => "session_timeout",
            Self::Terminal => "terminal",
            Self::NodeTimeout => "node_timeout",
            Self::WorkflowTimeout => "workflow_timeout",
        }
    }

    /// Parses the persisted text form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|class| class.as_str() == s)
    }

    /// Whether a failure of this class may earn a fresh attempt:
    /// transient, dispatch_infra and session_timeout retry; terminal,
    /// node_timeout and workflow_timeout never do (spec-4 table).
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::Transient | Self::DispatchInfra | Self::SessionTimeout
        )
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maps a journaled reason code to its failure class (upstream
/// `Classify`). Unknown or unclassified codes are terminal by default —
/// the taxonomy fails closed, so a new retryable class requires a spec
/// amendment, never a heuristic (spec-4 decision 1).
///
/// Only DEFINITE failures reach this function: observed process exits,
/// kill-confirmed timeouts, structured adapter errors, dispatch
/// refusals. Ambiguous attempts are operator decisions (locked input 2)
/// and never enter the retry path.
#[must_use]
pub fn classify(reason_code: &str) -> FailureClass {
    ReasonCode::parse(reason_code).map_or(FailureClass::Terminal, ReasonCode::class)
}

// ---------------------------------------------------------------------------
// Outcome-kind vocabulary (restated — see the module header)
// ---------------------------------------------------------------------------

/// The `attempt_outcomes.outcome_kind` set, restating the scheduler's
/// terminal attempt states — migration b37 pins the same list in
/// `attempt_outcomes_outcome_kind_check`. `ambiguous` is deliberately
/// absent: it is the state an outcome report resolves, never an
/// outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeKind {
    /// `succeeded`.
    Succeeded,
    /// `failed`.
    Failed,
    /// `cancelled`.
    Cancelled,
}

impl OutcomeKind {
    /// The closed outcome-kind set in pinned order.
    pub const ALL: [Self; 3] = [Self::Succeeded, Self::Failed, Self::Cancelled];

    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the persisted text form; `None` on anything else —
    /// `ambiguous` included, which is a parked state, never an outcome.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == s)
    }
}

impl fmt::Display for OutcomeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Backoff policy (spec-4 decision 2)
// ---------------------------------------------------------------------------

/// The journaled backoff parameters and the attempt budgets of spec-4
/// decisions 2–3. The zero value ([`RetryPolicy::zero`]) is fail-closed:
/// an empty `per_class_limits` and a zero `max_attempts_total` admit no
/// retry.
///
/// Durations are the signed [`time::Duration`] so the domain ports Go's
/// `time.Duration` semantics verbatim: zero is the "unset" sentinel and
/// negative values are legal inputs that clamp or participate exactly
/// as upstream.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicy {
    /// The first retry's pre-jitter delay.
    pub base_delay: Duration,
    /// Bounds every computed delay and every honored `retry_after`. A
    /// non-positive `cap` means uncapped — callers should always set it.
    pub cap: Duration,
    /// Grows the delay per attempt; below 1 it degenerates to a flat
    /// `base_delay`.
    pub multiplier: f64,
    /// Bounds attempts per retryable class; a class absent from the map
    /// has no budget.
    pub per_class_limits: BTreeMap<FailureClass, u32>,
    /// The absolute per-node ceiling so mixed failure modes cannot
    /// multiply attempts.
    pub max_attempts_total: u32,
}

impl RetryPolicy {
    /// The fail-closed empty policy: no per-class budget and no total
    /// headroom, so [`budget_remaining`] admits nothing.
    ///
    /// Distinct from [`Default`], which is the locked Phase-2 policy —
    /// upstream's `RetryPolicy{}` zero literal vs `DefaultRetryPolicy`.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            base_delay: Duration::ZERO,
            cap: Duration::ZERO,
            multiplier: 0.0,
            per_class_limits: BTreeMap::new(),
            max_attempts_total: 0,
        }
    }
}

impl Default for RetryPolicy {
    /// The locked Phase-2 defaults (spec-4 OQ-1/OQ-2): 30s base, ×2
    /// multiplier, 10m cap with full jitter; per-class limits
    /// transient=3, dispatch_infra=5, session_timeout=2 plus the
    /// absolute ceiling of 5 attempts.
    fn default() -> Self {
        Self {
            base_delay: Duration::seconds(30),
            cap: Duration::minutes(10),
            multiplier: 2.0,
            per_class_limits: [
                (FailureClass::Transient, 3),
                (FailureClass::DispatchInfra, 5),
                (FailureClass::SessionTimeout, 2),
            ]
            .into_iter()
            .collect(),
            max_attempts_total: 5,
        }
    }
}

/// The saturation value a computed delay takes when `base ×
/// multiplier^(n-1)` overflows the int64-nanosecond range — upstream's
/// `time.Duration(math.MaxInt64)`, ~292 years.
const MAX_DELAY: Duration = Duration::nanoseconds(i64::MAX);

/// Evaluates spec-4 decision 2 for one definite failure of the given
/// class: `delay_n = min(cap, base × multiplier^(n−1))` where `n` is
/// `attempt_seq` — the 1-based ordinal of the attempt that just failed —
/// followed by full jitter `uniform(0, delay_n)`. A non-retryable class
/// has no backoff and returns [`Duration::ZERO`].
///
/// `retry_after` is the provider's `RATE_LIMITED` hint (OQ-4): it
/// REPLACES the computed backoff, is still bounded by `cap`, and is
/// honored exactly — jitter is a property of computed backoff, not of
/// the hint. A negative hint clamps to 0 (immediate eligibility).
///
/// `jitter` draws the jitter sample; it must return `[0,1)` and is
/// clamped into `[0,1]` defensively so the result always lands in
/// `[0, delay]`. `None` skips jitter and returns the bounded delay
/// unchanged — the journaled `retry_at` is authoritative once
/// committed, so the draw site is the caller's choice, never a
/// recompute.
#[must_use]
pub fn compute_delay(
    policy: &RetryPolicy,
    class: FailureClass,
    attempt_seq: u32,
    retry_after: Option<Duration>,
    jitter: Option<&mut dyn FnMut() -> f64>,
) -> Duration {
    if !class.retryable() {
        return Duration::ZERO;
    }
    if let Some(hint) = retry_after {
        let mut delay = hint.max(Duration::ZERO);
        if policy.cap > Duration::ZERO && delay > policy.cap {
            delay = policy.cap;
        }
        return delay;
    }
    let seq = attempt_seq.max(1);
    let base = policy.base_delay.max(Duration::ZERO);
    let multiplier = policy.multiplier.max(1.0);
    let scaled = base.whole_nanoseconds() as f64 * multiplier.powi((seq - 1) as i32);
    let mut delay = if scaled.is_infinite() || scaled.is_nan() || scaled >= i64::MAX as f64 {
        MAX_DELAY
    } else if scaled <= 0.0 {
        Duration::ZERO
    } else {
        Duration::nanoseconds(scaled as i64)
    };
    if policy.cap > Duration::ZERO && delay > policy.cap {
        delay = policy.cap;
    }
    match jitter {
        None => delay,
        Some(draw) => {
            let sample = draw().clamp(0.0, 1.0);
            Duration::nanoseconds((sample * delay.whole_nanoseconds() as f64) as i64)
        }
    }
}

// ---------------------------------------------------------------------------
// Attempt budgets (spec-4 decision 3)
// ---------------------------------------------------------------------------

/// The node's journaled attempt consumption, read from its
/// `session_attempt` rows (spec-4 decision 3: the node, not the attempt,
/// holds durable progress). `per_class` counts the attempts each failure
/// class has produced; `total` counts every attempt the node has run.
/// The caller evaluates AFTER recording the outcome, so both counts
/// already include the just-failed attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptCounts {
    /// Attempts consumed per failure class (recorded `failed` outcomes).
    pub per_class: BTreeMap<FailureClass, u32>,
    /// Every session attempt the node has run.
    pub total: u32,
}

/// The `exhausted_by` value [`budget_remaining`] names when the absolute
/// ceiling — not any per-class limit — was reached (upstream
/// `BoundTotal`).
pub const BOUND_TOTAL: &str = "max_attempts_total";

/// The bound an exhausted budget names for the
/// `RETRY_BUDGET_EXHAUSTED` journal detail: the class's own name when
/// its per-class limit was reached, [`BOUND_TOTAL`] when the absolute
/// ceiling was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustedBound {
    /// The failing class's per-class limit was reached.
    PerClass(FailureClass),
    /// The `max_attempts_total` absolute ceiling was reached.
    Total,
}

impl ExhaustedBound {
    /// The journaled `exhausted_by` text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerClass(class) => class.as_str(),
            Self::Total => BOUND_TOTAL,
        }
    }
}

impl fmt::Display for ExhaustedBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `policy` admits one more attempt on a node whose consumed
/// counts are `counts`, for a failure of the given class (upstream
/// `BudgetRemaining` returning `(remaining, exhaustedBy)`).
///
/// `Some(bound)` names the exhausted bound for the
/// `RETRY_BUDGET_EXHAUSTED` journal detail; `None` means budget remains.
/// The per-class bound is checked first — it is the more specific bound
/// when both are spent. A retryable class with no configured limit has
/// no per-class budget; a non-positive `max_attempts_total` is no total
/// headroom at all. Both fail closed.
#[must_use]
pub fn budget_remaining(
    policy: &RetryPolicy,
    counts: &AttemptCounts,
    class: FailureClass,
) -> Option<ExhaustedBound> {
    let limit = policy.per_class_limits.get(&class).copied().unwrap_or(0);
    let used = counts.per_class.get(&class).copied().unwrap_or(0);
    if used >= limit {
        return Some(ExhaustedBound::PerClass(class));
    }
    if counts.total >= policy.max_attempts_total {
        return Some(ExhaustedBound::Total);
    }
    None
}

// ---------------------------------------------------------------------------
// Timeout hierarchy (spec-4 decision 5)
// ---------------------------------------------------------------------------

/// The three-level wall-clock hierarchy's dispatch-time composition
/// (spec-4 decision 5): session < node < workflow, so inner bounds fire
/// first and a child spec's hint may tighten, never loosen, parent
/// bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeoutHierarchy {
    /// The child spec's session ceiling hint; `None` or
    /// [`Duration::ZERO`] is unset.
    pub spec_hint: Option<Duration>,
    /// The node aggregate bound remaining at dispatch. `None` or
    /// [`Duration::ZERO`] is unset; a NEGATIVE remaining is a real
    /// bound — it reports an already-expired envelope — so it
    /// participates and yields a non-positive ceiling the dispatcher
    /// must read as "no session may start".
    pub node_remaining: Option<Duration>,
    /// The workflow graph bound remaining at dispatch; same sign rules
    /// as `node_remaining`.
    pub workflow_remaining: Option<Duration>,
}

impl TimeoutHierarchy {
    /// `min(spec_hint, node_remaining, workflow_remaining)` — the
    /// dispatch-time session bound (upstream
    /// `EffectiveSessionCeiling`). `None` or [`Duration::ZERO`] inputs
    /// are unset and never participate; when every input is unset the
    /// ceiling is unset and `None` returns.
    #[must_use]
    pub fn effective_session_ceiling(&self) -> Option<Duration> {
        [self.spec_hint, self.node_remaining, self.workflow_remaining]
            .into_iter()
            .flatten()
            .filter(|bound| !bound.is_zero())
            .reduce(|acc, bound| acc.min(bound))
    }
}

/// Whether the node's aggregate bound has passed at `now`: first
/// dispatch plus `node_timeout_seconds` (spec-4 decision 5 — measured
/// from first dispatch, so queue time never counts). A non-positive
/// `node_timeout` is an unbounded node and never expires; a `None`
/// `first_dispatch` means the node never dispatched, so no bound is
/// running. Expiry is `failed_terminal`/`NODE_TIMEOUT` regardless of
/// remaining retry budget.
#[must_use]
pub fn node_deadline_exceeded(
    first_dispatch: Option<OffsetDateTime>,
    node_timeout: Duration,
    now: OffsetDateTime,
) -> bool {
    let Some(first_dispatch) = first_dispatch else {
        return false;
    };
    if node_timeout <= Duration::ZERO {
        return false;
    }
    now >= first_dispatch + node_timeout
}

/// Whether the run's graph bound has passed at `now`: `started_at` plus
/// the workflow timeout. A non-positive `workflow_timeout` is an
/// unbounded run and never expires; a `None` `started_at` means the run
/// never started. Expiry cancels running attempts, cascades non-terminal
/// nodes cancelled per spec-1, and ends the run
/// `failed_terminal`/`WORKFLOW_TIMEOUT`.
#[must_use]
pub fn workflow_deadline_exceeded(
    started_at: Option<OffsetDateTime>,
    workflow_timeout: Duration,
    now: OffsetDateTime,
) -> bool {
    let Some(started_at) = started_at else {
        return false;
    };
    if workflow_timeout <= Duration::ZERO {
        return false;
    }
    now >= started_at + workflow_timeout
}

// ---------------------------------------------------------------------------
// The after-failure verdict (spec-4 decisions 1-5, consolidated)
// ---------------------------------------------------------------------------

/// One definite attempt failure arriving at the retry decision — the
/// evaluation input the store's outcome path builds from its journaled
/// report (upstream `decideAfterFailureTx`'s inputs).
///
/// Only definite failures exist here: observed process exits,
/// kill-confirmed timeouts, structured adapter errors, dispatch
/// refusals. Ambiguous attempts are operator decisions (locked input 2)
/// and never enter the retry path.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptFailure {
    /// The journaled spec-4 reason code — raw text, because the
    /// `attempt_outcomes.reason_code` column is unpinned and a code this
    /// build predates must still classify (terminal) rather than error.
    pub reason_code: String,
    /// The 1-based ordinal of the attempt that just failed.
    pub attempt_seq: u32,
    /// A provider `retry_after` hint, honored (bounded by the policy
    /// cap) only on `RATE_LIMITED` reports and ignored otherwise.
    pub retry_after: Option<Duration>,
}

/// The journaled history [`decide`] evaluates a failure against — read
/// under the outcome transaction's locks by the store, so the verdict
/// replays identically (spec-4 decision 3: durable progress lives on
/// the node's rows, never in memory).
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptHistory {
    /// The node's attempt consumption — per failure class and total —
    /// already including the just-failed attempt.
    pub counts: AttemptCounts,
    /// The node's first dispatch instant (`MIN(claimed_at)`) — the
    /// node-timeout bound's epoch. `None` means the node never
    /// dispatched and no bound is running.
    pub first_dispatch: Option<OffsetDateTime>,
    /// The node's aggregate bound (`node_timeout_seconds`). `None` or
    /// non-positive is unbounded.
    pub node_timeout: Option<Duration>,
    /// The evaluation instant the verdict is computed at — durable
    /// evidence supplied by the caller, never a clock read. The
    /// journaled `retry_at` is `evaluated_at + delay`.
    pub evaluated_at: OffsetDateTime,
}

/// What a definite failure earns the node (spec-4 decisions 1–5,
/// consolidated): the store commits the named transition and journals
/// the named event; nothing else may happen.
#[derive(Debug, Clone, PartialEq)]
pub enum RetryDecision {
    /// Return the node to `ready` under `not_before = retry_at` — the
    /// journaled retry instant (`evaluated_at + delay`) the claim's
    /// `not_before ≤ now` gate consumes. Authoritative once committed:
    /// a restart never recomputes or loses it.
    Retry {
        /// The journaled `attempt_retry_scheduled` instant.
        retry_at: OffsetDateTime,
    },
    /// Land the node `failed_terminal`, journaling
    /// `node_failed_terminal` with the terminal `reason_code` and
    /// `detail`, plus the failing `attempt_id`.
    FailedTerminal {
        /// The terminal reason the event carries — `NODE_TIMEOUT`,
        /// `RETRY_BUDGET_EXHAUSTED`, or the journaled failure code
        /// verbatim (an unknown code stays verbatim, never rewritten).
        reason_code: String,
        /// The event payload's `detail` — the bound verdict upstream
        /// composes inline (`node_timeout_seconds bound elapsed`,
        /// `failure class <class> is not retryable`,
        /// `exhausted_by=<bound>`).
        detail: String,
    },
}

/// The consolidated after-failure verdict (upstream's
/// `decideAfterFailureTx` decision order, made pure): the node bound
/// dominates every other decision, non-retryable classes land
/// `failed_terminal` carrying the journaled code, an exhausted budget
/// lands `RETRY_BUDGET_EXHAUSTED` naming the spent bound, and a
/// retryable failure inside budget earns a journaled `retry_at`.
///
/// `jitter_draw` is the caller's single `[0,1)` jitter sample for this
/// evaluation — a plain value because the draw site is the store's
/// injected `Rand`, and a drawn value keeps the verdict a pure function
/// of its inputs.
#[must_use]
pub fn decide(
    failure: &AttemptFailure,
    policy: &RetryPolicy,
    history: &AttemptHistory,
    jitter_draw: Option<f64>,
) -> RetryDecision {
    let class = classify(&failure.reason_code);

    // The node aggregate bound dominates every other decision: an
    // outcome arriving past it lands NODE_TIMEOUT regardless of class
    // or remaining budget (spec-4 decision 5).
    if node_deadline_exceeded(
        history.first_dispatch,
        history.node_timeout.unwrap_or(Duration::ZERO),
        history.evaluated_at,
    ) {
        return RetryDecision::FailedTerminal {
            reason_code: ReasonCode::NodeTimeout.as_str().to_owned(),
            detail: "node_timeout_seconds bound elapsed".to_owned(),
        };
    }
    if !class.retryable() {
        return RetryDecision::FailedTerminal {
            reason_code: failure.reason_code.clone(),
            detail: format!("failure class {} is not retryable", class.as_str()),
        };
    }
    if let Some(bound) = budget_remaining(policy, &history.counts, class) {
        return RetryDecision::FailedTerminal {
            reason_code: ReasonCode::RetryBudgetExhausted.as_str().to_owned(),
            detail: format!("exhausted_by={}", bound.as_str()),
        };
    }

    // The retry_after hint is honored only on RATE_LIMITED reports
    // (OQ-4); any other code ignores it outright.
    let hint = if failure.reason_code == ReasonCode::RateLimited.as_str() {
        failure.retry_after
    } else {
        None
    };
    let mut draw = jitter_draw.map(|sample| move || sample);
    let delay = compute_delay(
        policy,
        class,
        failure.attempt_seq,
        hint,
        draw.as_mut()
            .map(|sample| sample as &mut dyn FnMut() -> f64),
    );
    RetryDecision::Retry {
        retry_at: history.evaluated_at + delay,
    }
}

// ---------------------------------------------------------------------------
// Compensation hooks (spec-4 decision 6)
// ---------------------------------------------------------------------------

/// What a child spec's `on_terminal_failure` declaration resolves to.
/// Phase 2 executes only the Central-managed kinds; every other value is
/// journaled `compensation_requested` for the leader or operator —
/// agent-authored cleanup is never auto-executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompensationKind {
    /// `none` — the node declares no hook.
    None,
    /// `cleanup_workspace` — remove the node's worktree/private dir
    /// through the provisioner. Central-managed.
    CleanupWorkspace,
    /// `retain_artifacts` — mark the node's declared artifacts kept for
    /// inspection. Central-managed.
    RetainArtifacts,
    /// `unmanaged` — any other declared value: journaled
    /// `compensation_requested`, never auto-executed.
    Unmanaged,
}

impl CompensationKind {
    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CleanupWorkspace => "cleanup_workspace",
            Self::RetainArtifacts => "retain_artifacts",
            Self::Unmanaged => "unmanaged",
        }
    }

    /// Whether Central executes the kind itself (spec-4 decision 6):
    /// `cleanup_workspace` and `retain_artifacts` only.
    #[must_use]
    pub const fn managed(self) -> bool {
        matches!(self, Self::CleanupWorkspace | Self::RetainArtifacts)
    }
}

impl fmt::Display for CompensationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolves a child spec's `on_terminal_failure` value (upstream
/// `ParseCompensation`): empty is none (no hook declared), the two
/// Central-managed names map to their kinds, and anything else is
/// unmanaged — a journal-only request for the leader or operator.
#[must_use]
pub fn parse_compensation(spec_value: &str) -> CompensationKind {
    match spec_value.trim() {
        "" => CompensationKind::None,
        "cleanup_workspace" => CompensationKind::CleanupWorkspace,
        "retain_artifacts" => CompensationKind::RetainArtifacts,
        _ => CompensationKind::Unmanaged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    // -------------------------------------------------------------------
    // classify — spec-4 decision 1 taxonomy table
    // -------------------------------------------------------------------

    /// `TestClassifyKnownCodes` — every declared reason code maps to
    /// exactly the class spec-4's taxonomy table assigns; the table is
    /// total over the declared vocabulary, so each code is asserted
    /// individually rather than sampled.
    #[test]
    fn classify_known_codes() {
        let cases: [(ReasonCode, FailureClass); 17] = [
            (ReasonCode::ProcessExitNonzero, FailureClass::Transient),
            (ReasonCode::AdapterError, FailureClass::Transient),
            (ReasonCode::RateLimited, FailureClass::Transient),
            (
                ReasonCode::WorkspaceProvisionFailed,
                FailureClass::DispatchInfra,
            ),
            (ReasonCode::LauncherRefused, FailureClass::DispatchInfra),
            (
                ReasonCode::SessionWallClockReached,
                FailureClass::SessionTimeout,
            ),
            (
                ReasonCode::SessionCostCeilingReached,
                FailureClass::SessionTimeout,
            ),
            (ReasonCode::SpecValidationFailed, FailureClass::Terminal),
            (ReasonCode::BudgetExhausted, FailureClass::Terminal),
            (ReasonCode::WorkspaceUnavailable, FailureClass::Terminal),
            (ReasonCode::CapabilityMissing, FailureClass::Terminal),
            (ReasonCode::NodeTimeout, FailureClass::NodeTimeout),
            (ReasonCode::WorkflowTimeout, FailureClass::WorkflowTimeout),
            (ReasonCode::RetryBudgetExhausted, FailureClass::Terminal),
            (ReasonCode::DuplicateIdempotencyKey, FailureClass::Terminal),
            (ReasonCode::ArtifactAlreadyFinalized, FailureClass::Terminal),
            (ReasonCode::ArtifactChecksumMismatch, FailureClass::Terminal),
        ];
        for (code, want) in cases {
            assert_eq!(
                classify(code.as_str()),
                want,
                "classify({:?})",
                code.as_str()
            );
            // The typed path agrees: a declared code knows its own class.
            assert_eq!(code.class(), want, "{:?}.class()", code);
        }
    }

    /// `TestClassifyUnknownFailsClosed` — unknown, misspelled,
    /// lowercase, and empty codes are all terminal: a new retryable
    /// class requires a spec amendment, never a heuristic.
    #[test]
    fn classify_unknown_fails_closed() {
        for code in [
            "",
            "UNKNOWN_CODE",
            "process_exit_nonzero",
            "PROCES_EXIT_NONZERO",
            "CAPACITY_ADMISSION_DEFERRED",
            "WORKER_SHUTDOWN_LEASE_RELEASED",
            "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED",
            "LEASE_EXPIRED_NOT_STARTED",
        ] {
            assert_eq!(classify(code), FailureClass::Terminal, "classify({code:?})");
        }
    }

    /// `TestRetryableClasses` — the retryable predicate pinned to the
    /// spec-4 table: transient, dispatch_infra and session_timeout
    /// retry; the bounds and terminal never do.
    #[test]
    fn retryable_classes() {
        for class in FailureClass::ALL {
            let want = matches!(
                class,
                FailureClass::Transient
                    | FailureClass::DispatchInfra
                    | FailureClass::SessionTimeout
            );
            assert_eq!(class.retryable(), want, "{class:?}.retryable()");
        }
        assert_eq!(FailureClass::ALL.len(), 6, "want the closed six-class set");
    }

    // -------------------------------------------------------------------
    // compute_delay — spec-4 decision 2 backoff
    // -------------------------------------------------------------------

    /// `TestComputeDelayMonotonicToCap` — the default-policy backoff
    /// ladder with jitter pinned off: 30s x 2^(n-1) clamped at the 10m
    /// cap.
    #[test]
    fn compute_delay_monotonic_to_cap() {
        let policy = RetryPolicy::default();
        let want = [
            Duration::seconds(30),
            Duration::seconds(60),
            Duration::seconds(120),
            Duration::seconds(240),
            Duration::seconds(480),
            Duration::minutes(10), // 30s*2^5 = 960s exceeds the cap
            Duration::minutes(10),
        ];
        for (n, w) in want.iter().enumerate() {
            let seq = (n + 1) as u32;
            assert_eq!(
                compute_delay(&policy, FailureClass::Transient, seq, None, None),
                *w,
                "attempt_seq {seq}"
            );
        }
        for n in 2..=want.len() {
            let prev = compute_delay(&policy, FailureClass::Transient, (n - 1) as u32, None, None);
            let cur = compute_delay(&policy, FailureClass::Transient, n as u32, None, None);
            assert!(cur >= prev, "delay not monotonic: {cur} < {prev}");
        }
    }

    /// `TestComputeDelayJitterBounds` — full jitter lands in [0, delay]:
    /// a zero draw returns 0, a one-draw returns the whole delay, and
    /// draws outside [0,1] clamp instead of escaping the interval.
    #[test]
    fn compute_delay_jitter_bounds() {
        let policy = RetryPolicy::default();
        let base = compute_delay(&policy, FailureClass::Transient, 2, None, None);
        assert_eq!(base, Duration::seconds(60));
        assert_eq!(
            compute_delay(&policy, FailureClass::Transient, 2, None, Some(&mut || 0.0)),
            Duration::ZERO,
            "draw 0"
        );
        assert_eq!(
            compute_delay(&policy, FailureClass::Transient, 2, None, Some(&mut || 0.5)),
            Duration::seconds(30),
            "draw 0.5"
        );
        assert_eq!(
            compute_delay(&policy, FailureClass::Transient, 2, None, Some(&mut || 1.0)),
            base,
            "draw 1"
        );
        assert_eq!(
            compute_delay(
                &policy,
                FailureClass::Transient,
                2,
                None,
                Some(&mut || -0.4)
            ),
            Duration::ZERO,
            "negative draw clamps"
        );
        assert_eq!(
            compute_delay(&policy, FailureClass::Transient, 2, None, Some(&mut || 1.7)),
            base,
            "draw >1 clamps"
        );
    }

    /// `TestComputeDelayRetryAfter` — the provider hint semantics
    /// (OQ-4): it replaces the computed backoff, is honored exactly (no
    /// jitter), and stays bounded by the cap.
    #[test]
    fn compute_delay_retry_after() {
        let policy = RetryPolicy::default();
        let hint = Duration::seconds(45);
        assert_eq!(
            compute_delay(
                &policy,
                FailureClass::Transient,
                3,
                Some(hint),
                Some(&mut || 0.5)
            ),
            hint,
            "retry_after honored exactly — jitter must not apply"
        );
        assert_eq!(
            compute_delay(
                &policy,
                FailureClass::Transient,
                1,
                Some(Duration::hours(1)),
                None
            ),
            policy.cap,
            "retry_after over cap"
        );
        assert_eq!(
            compute_delay(
                &policy,
                FailureClass::Transient,
                1,
                Some(Duration::seconds(-5)),
                None
            ),
            Duration::ZERO,
            "negative retry_after clamps to 0"
        );
    }

    /// `TestComputeDelayNonRetryable` — classes outside the retryable
    /// set carry no backoff at all.
    #[test]
    fn compute_delay_non_retryable() {
        let policy = RetryPolicy::default();
        for class in [
            FailureClass::Terminal,
            FailureClass::NodeTimeout,
            FailureClass::WorkflowTimeout,
        ] {
            assert_eq!(
                compute_delay(&policy, class, 1, None, Some(&mut || 0.9)),
                Duration::ZERO,
                "compute_delay({class:?})"
            );
        }
    }

    // -------------------------------------------------------------------
    // budget_remaining — spec-4 decision 3 attempt budgets
    // -------------------------------------------------------------------

    /// `TestBudgetRemainingBounds` — each bound walked to exhaustion:
    /// the per-class limit names the class, the absolute ceiling names
    /// [`ExhaustedBound::Total`], and a policy missing a class limit
    /// fails closed.
    #[test]
    fn budget_remaining_bounds() {
        let policy = RetryPolicy::default();

        // transient=3: attempts 1-2 consumed leave headroom; 3 exhausts.
        let mut counts = AttemptCounts {
            per_class: [(FailureClass::Transient, 2)].into_iter().collect(),
            total: 2,
        };
        assert_eq!(
            budget_remaining(&policy, &counts, FailureClass::Transient),
            None,
            "transient 2/3 with total 2/5 must leave budget"
        );
        counts = AttemptCounts {
            per_class: [(FailureClass::Transient, 3)].into_iter().collect(),
            total: 3,
        };
        assert_eq!(
            budget_remaining(&policy, &counts, FailureClass::Transient),
            Some(ExhaustedBound::PerClass(FailureClass::Transient)),
            "transient 3/3 exhausted on its own bound"
        );

        // dispatch_infra=5 shares the total ceiling of 5: the total
        // bound fires only when the per-class count has not already.
        counts = AttemptCounts {
            per_class: [(FailureClass::DispatchInfra, 4)].into_iter().collect(),
            total: 5,
        };
        assert_eq!(
            budget_remaining(&policy, &counts, FailureClass::DispatchInfra),
            Some(ExhaustedBound::Total),
            "dispatch_infra 4/5 with total 5/5 exhausted on the ceiling"
        );

        // session_timeout=2: the per-class bound names the class even
        // when the total is also spent — the more specific bound is
        // reported.
        counts = AttemptCounts {
            per_class: [(FailureClass::SessionTimeout, 2)].into_iter().collect(),
            total: 5,
        };
        assert_eq!(
            budget_remaining(&policy, &counts, FailureClass::SessionTimeout),
            Some(ExhaustedBound::PerClass(FailureClass::SessionTimeout)),
            "session_timeout 2/2 exhausted on its own bound"
        );

        // A retryable class absent from the policy has no budget.
        let custom = RetryPolicy {
            per_class_limits: Default::default(),
            max_attempts_total: 5,
            ..Default::default()
        };
        assert_eq!(
            budget_remaining(&custom, &AttemptCounts::default(), FailureClass::Transient),
            Some(ExhaustedBound::PerClass(FailureClass::Transient)),
            "policy without a transient limit must fail closed"
        );
        // The zero policy admits nothing at all.
        assert_eq!(
            budget_remaining(
                &RetryPolicy::zero(),
                &AttemptCounts::default(),
                FailureClass::Transient
            ),
            Some(ExhaustedBound::PerClass(FailureClass::Transient)),
            "zero policy must fail closed"
        );
    }

    // -------------------------------------------------------------------
    // Timeout hierarchy — spec-4 decision 5
    // -------------------------------------------------------------------

    /// `TestEffectiveSessionCeiling` — the min-of-set-bounds
    /// composition: `None` is unset, the smallest set bound wins, and a
    /// negative remaining reports an already-expired envelope instead
    /// of disappearing.
    #[test]
    fn effective_session_ceiling() {
        struct Case {
            name: &'static str,
            spec_hint: Option<Duration>,
            node_remaining: Option<Duration>,
            workflow_remaining: Option<Duration>,
            want: Option<Duration>,
        }
        impl Case {
            const fn new(
                name: &'static str,
                spec_hint: Option<Duration>,
                node_remaining: Option<Duration>,
                workflow_remaining: Option<Duration>,
                want: Option<Duration>,
            ) -> Self {
                Self {
                    name,
                    spec_hint,
                    node_remaining,
                    workflow_remaining,
                    want,
                }
            }
        }
        let secs = Duration::seconds;
        let cases = [
            Case::new("all unset", None, None, None, None),
            Case::new("hint only", Some(secs(90)), None, None, Some(secs(90))),
            Case::new(
                "inner bound wins",
                Some(secs(90)),
                Some(secs(30)),
                Some(Duration::hours(1)),
                Some(secs(30)),
            ),
            Case::new(
                "workflow tightest",
                Some(secs(90)),
                Some(Duration::hours(1)),
                Some(secs(45)),
                Some(secs(45)),
            ),
            Case::new(
                "hint tightest",
                Some(secs(10)),
                Some(Duration::hours(1)),
                Some(secs(45)),
                Some(secs(10)),
            ),
            Case::new(
                "expired node participates",
                Some(secs(90)),
                Some(secs(-5)),
                Some(Duration::hours(1)),
                Some(secs(-5)),
            ),
        ];
        for case in cases {
            let hierarchy = TimeoutHierarchy {
                spec_hint: case.spec_hint,
                node_remaining: case.node_remaining,
                workflow_remaining: case.workflow_remaining,
            };
            assert_eq!(
                hierarchy.effective_session_ceiling(),
                case.want,
                "{}",
                case.name
            );
        }
    }

    /// `TestDeadlinePredicates` — unset or unstarted bounds never fire,
    /// the boundary instant itself is exceeded, and one tick before is
    /// not.
    #[test]
    fn deadline_predicates() {
        let base = datetime!(2026-10-07 12:00 UTC);
        let timeout = Duration::minutes(5);

        assert!(node_deadline_exceeded(Some(base), timeout, base + timeout));
        assert!(!node_deadline_exceeded(
            Some(base),
            timeout,
            base + timeout - Duration::seconds(1)
        ));
        assert!(!node_deadline_exceeded(
            Some(base),
            Duration::ZERO,
            base + Duration::hours(1)
        ));
        assert!(!node_deadline_exceeded(
            None,
            timeout,
            base + Duration::hours(1)
        ));

        assert!(workflow_deadline_exceeded(
            Some(base),
            timeout,
            base + timeout
        ));
        assert!(!workflow_deadline_exceeded(
            Some(base),
            timeout,
            base + timeout - Duration::seconds(1)
        ));
        assert!(!workflow_deadline_exceeded(
            Some(base),
            Duration::ZERO,
            base + Duration::hours(1)
        ));
        assert!(!workflow_deadline_exceeded(
            None,
            timeout,
            base + Duration::hours(1)
        ));
    }

    // -------------------------------------------------------------------
    // Compensation hooks — spec-4 decision 6
    // -------------------------------------------------------------------

    /// `TestParseCompensation` — empty is none, the two Central-managed
    /// names resolve, and everything else is unmanaged — journaled,
    /// never executed.
    #[test]
    fn parse_compensation_vocabulary() {
        let cases = [
            ("", CompensationKind::None),
            ("cleanup_workspace", CompensationKind::CleanupWorkspace),
            ("retain_artifacts", CompensationKind::RetainArtifacts),
            ("  cleanup_workspace  ", CompensationKind::CleanupWorkspace),
            ("run_script.sh", CompensationKind::Unmanaged),
            ("notify_leader", CompensationKind::Unmanaged),
            ("CLEANUP_WORKSPACE", CompensationKind::Unmanaged),
        ];
        for (input, want) in cases {
            assert_eq!(
                parse_compensation(input),
                want,
                "parse_compensation({input:?})"
            );
        }
        assert!(CompensationKind::CleanupWorkspace.managed());
        assert!(CompensationKind::RetainArtifacts.managed());
        assert!(!CompensationKind::None.managed());
        assert!(!CompensationKind::Unmanaged.managed());
    }

    /// `TestDefaultRetryPolicyValues` — the locked OQ-1/OQ-2 defaults:
    /// a drift in the numbers is a deliberate, reviewed change.
    #[test]
    fn default_retry_policy_values() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.base_delay, Duration::seconds(30));
        assert_eq!(policy.cap, Duration::minutes(10));
        assert!((policy.multiplier - 2.0).abs() < f64::EPSILON);
        let want_limits = [
            (FailureClass::Transient, 3),
            (FailureClass::DispatchInfra, 5),
            (FailureClass::SessionTimeout, 2),
        ];
        for (class, want) in want_limits {
            assert_eq!(policy.per_class_limits.get(&class), Some(&want));
        }
        assert_eq!(
            policy.per_class_limits.len(),
            3,
            "exactly the three retryable classes"
        );
        assert_eq!(policy.max_attempts_total, 5);
    }

    /// `TestComputeDelayDeepAttemptSequence` — the overflow path: an
    /// attempt ordinal far past the cap returns the cap, and an
    /// uncapped overflow saturates at the int64-nanosecond maximum
    /// instead of wrapping.
    #[test]
    fn compute_delay_deep_attempt_sequence() {
        let policy = RetryPolicy::default();
        assert_eq!(
            compute_delay(&policy, FailureClass::Transient, 1000, None, None),
            policy.cap
        );
        let uncapped = RetryPolicy {
            base_delay: Duration::hours(1),
            cap: Duration::ZERO,
            multiplier: 2.0,
            per_class_limits: [(FailureClass::Transient, 9)].into_iter().collect(),
            max_attempts_total: 9,
        };
        assert_eq!(
            compute_delay(&uncapped, FailureClass::Transient, 2000, None, None),
            Duration::nanoseconds(i64::MAX),
            "uncapped overflow saturates"
        );
    }

    // -------------------------------------------------------------------
    // decide — the consolidated after-failure verdict (spec-4 1-5)
    // -------------------------------------------------------------------

    fn history() -> AttemptHistory {
        AttemptHistory {
            counts: AttemptCounts::default(),
            first_dispatch: None,
            node_timeout: None,
            evaluated_at: datetime!(2026-10-07 12:00 UTC),
        }
    }

    /// A node bound already expired lands `NODE_TIMEOUT` regardless of
    /// the failure's class or remaining budget — the bound dominates
    /// every other verdict (spec-4 decision 5).
    #[test]
    fn decide_node_bound_dominates() {
        let policy = RetryPolicy::default();
        let now = datetime!(2026-10-07 12:00 UTC);
        let h = AttemptHistory {
            first_dispatch: Some(now - Duration::minutes(10)),
            node_timeout: Some(Duration::minutes(5)),
            ..history()
        };
        // Even a retryable code with an empty budget lands NODE_TIMEOUT.
        assert_eq!(
            decide(
                &AttemptFailure {
                    reason_code: "PROCESS_EXIT_NONZERO".to_owned(),
                    attempt_seq: 1,
                    retry_after: None,
                },
                &policy,
                &h,
                None,
            ),
            RetryDecision::FailedTerminal {
                reason_code: "NODE_TIMEOUT".to_owned(),
                detail: "node_timeout_seconds bound elapsed".to_owned(),
            }
        );
    }

    /// Non-retryable classes — including every unknown code — land
    /// `failed_terminal` carrying the journaled code verbatim.
    #[test]
    fn decide_non_retryable_lands_terminal_with_verbatim_code() {
        let policy = RetryPolicy::default();
        for (code, detail_class) in [
            ("SPEC_VALIDATION_FAILED", "terminal"),
            ("WORKFLOW_TIMEOUT", "workflow_timeout"),
            ("SOME_FUTURE_CODE", "terminal"),
        ] {
            assert_eq!(
                decide(
                    &AttemptFailure {
                        reason_code: code.to_owned(),
                        attempt_seq: 1,
                        retry_after: None,
                    },
                    &policy,
                    &history(),
                    None,
                ),
                RetryDecision::FailedTerminal {
                    reason_code: code.to_owned(),
                    detail: format!("failure class {detail_class} is not retryable"),
                },
                "{code}"
            );
        }
    }

    /// An exhausted budget lands `RETRY_BUDGET_EXHAUSTED` with the
    /// `exhausted_by` detail naming the spent bound.
    #[test]
    fn decide_budget_exhausted_names_bound() {
        let policy = RetryPolicy::default();
        let h = AttemptHistory {
            counts: AttemptCounts {
                per_class: [(FailureClass::Transient, 3)].into_iter().collect(),
                total: 3,
            },
            ..history()
        };
        assert_eq!(
            decide(
                &AttemptFailure {
                    reason_code: "ADAPTER_ERROR".to_owned(),
                    attempt_seq: 3,
                    retry_after: None,
                },
                &policy,
                &h,
                None,
            ),
            RetryDecision::FailedTerminal {
                reason_code: "RETRY_BUDGET_EXHAUSTED".to_owned(),
                detail: "exhausted_by=transient".to_owned(),
            }
        );

        let h = AttemptHistory {
            counts: AttemptCounts {
                per_class: [(FailureClass::DispatchInfra, 4)].into_iter().collect(),
                total: 5,
            },
            ..history()
        };
        assert_eq!(
            decide(
                &AttemptFailure {
                    reason_code: "LAUNCHER_REFUSED".to_owned(),
                    attempt_seq: 5,
                    retry_after: None,
                },
                &policy,
                &h,
                None,
            ),
            RetryDecision::FailedTerminal {
                reason_code: "RETRY_BUDGET_EXHAUSTED".to_owned(),
                detail: "exhausted_by=max_attempts_total".to_owned(),
            }
        );
    }

    /// A retryable failure inside budget schedules the journaled
    /// `retry_at = evaluated_at + delay`; `retry_after` is honored only
    /// on RATE_LIMITED reports.
    #[test]
    fn decide_retry_inside_budget() {
        let policy = RetryPolicy::default();
        let now = datetime!(2026-10-07 12:00 UTC);
        let h = AttemptHistory {
            evaluated_at: now,
            ..history()
        };

        // attempt_seq 2 → unjittered 60s; jitter pinned at the 1-draw
        // so retry_at = now + 60s.
        assert_eq!(
            decide(
                &AttemptFailure {
                    reason_code: "PROCESS_EXIT_NONZERO".to_owned(),
                    attempt_seq: 2,
                    retry_after: None,
                },
                &policy,
                &h,
                Some(1.0),
            ),
            RetryDecision::Retry {
                retry_at: now + Duration::seconds(60),
            }
        );

        // The RATE_LIMITED hint replaces the computed delay.
        assert_eq!(
            decide(
                &AttemptFailure {
                    reason_code: "RATE_LIMITED".to_owned(),
                    attempt_seq: 2,
                    retry_after: Some(Duration::seconds(45)),
                },
                &policy,
                &h,
                Some(1.0),
            ),
            RetryDecision::Retry {
                retry_at: now + Duration::seconds(45),
            }
        );

        // A hint on a non-RATE_LIMITED code is ignored, not honored.
        assert_eq!(
            decide(
                &AttemptFailure {
                    reason_code: "PROCESS_EXIT_NONZERO".to_owned(),
                    attempt_seq: 2,
                    retry_after: Some(Duration::seconds(45)),
                },
                &policy,
                &h,
                Some(1.0),
            ),
            RetryDecision::Retry {
                retry_at: now + Duration::seconds(60),
            }
        );
    }

    /// The outcome-kind vocabulary is the pinned three-value set —
    /// `ambiguous` is a parked state, never an outcome.
    #[test]
    fn outcome_kind_vocabulary() {
        assert_eq!(OutcomeKind::ALL.len(), 3);
        for (text, kind) in [
            ("succeeded", OutcomeKind::Succeeded),
            ("failed", OutcomeKind::Failed),
            ("cancelled", OutcomeKind::Cancelled),
        ] {
            assert_eq!(OutcomeKind::parse(text), Some(kind));
            assert_eq!(kind.as_str(), text);
        }
        assert_eq!(OutcomeKind::parse("ambiguous"), None);
        assert_eq!(OutcomeKind::parse(""), None);
    }
}
