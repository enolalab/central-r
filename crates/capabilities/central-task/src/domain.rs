//! Task domain — lifecycle vocabularies, aggregates, change sets, and
//! transition evaluators (ports `central/internal/task/domain.go` +
//! `contract.go`).
//!
//! Pure synchronous Rust per rust-application-boundaries.md §2.3: no
//! `async fn`, no `tokio`, no I/O traits, and no clock reads. Every
//! request carries its evaluation instant (`now`); upstream's
//! `normalizeNow` zero-time fallback is deliberately replaced by a
//! required timestamp so the domain stays deterministic.
//!
//! Upstream's typed `Failure{Class, Reason, Remediation, cause}` maps
//! onto [`Failure`]'s `kind` + stable machine `code`: `ClassInvalid` →
//! `Invalid`, `ClassConflict` → `Conflict`, `ClassDenied` → `Denied`,
//! and the sentinel causes (`ErrInvalidTransition`,
//! `ErrVersionConflict`, `ErrInvalidState`, `ErrRunMismatch`,
//! `ErrTaskNotFound`) map onto the [`codes`] constants a caller
//! compares the way upstream compares with `errors.Is`.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, TaskId, WorkspaceId};
use sha2::Digest;
use time::OffsetDateTime;

/// Stable machine codes for task-domain failures — the Rust port of
/// upstream's sentinel causes (`errors.Is` targets).
pub mod codes {
    /// Upstream `ErrTaskNotFound`.
    pub const TASK_NOT_FOUND: &str = "task_not_found";
    /// Upstream `ErrInvalidTransition` — a denied state transition.
    pub const INVALID_TRANSITION: &str = "task_invalid_transition";
    /// Upstream `ErrVersionConflict` — a stale optimistic guard.
    pub const VERSION_CONFLICT: &str = "task_version_conflict";
    /// Upstream `ErrInvalidState` — malformed input or an aggregate
    /// that violates its invariants.
    pub const INVALID_STATE: &str = "task_invalid_state";
    /// Upstream `ErrRunMismatch` — the aggregate's `current_run_id`
    /// and supplied `Run` disagree.
    pub const RUN_MISMATCH: &str = "task_run_mismatch";
    /// Invalid input carrying no upstream sentinel cause.
    pub const INVALID: &str = "task_invalid";
}

// ---------------------------------------------------------------------------
// Version sentinel
// ---------------------------------------------------------------------------

/// `NoExistingVersion` — the expected-version sentinel for create
/// commands (the row must not already exist).
pub const NO_EXISTING_VERSION: i64 = -1;

// ---------------------------------------------------------------------------
// Task and run lifecycle vocabularies
// ---------------------------------------------------------------------------

/// The parent aggregate task status (`central.tasks.status`).
///
/// The b37 CHECK admits exactly these seven values.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TaskStatus {
    /// Ready to be claimed.
    Queued,
    /// The current run is actively executing.
    Running,
    /// Blocked by approval/input/retry/reconciliation; resumable.
    Waiting,
    /// Cancellation is durable but not yet settled.
    Cancelling,
    /// Terminal: successful run completion.
    Completed,
    /// Terminal: no automatic whole-run retry.
    Failed,
    /// Terminal: after settlement.
    Cancelled,
}

impl TaskStatus {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Cancelling => "cancelling",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the canonical text; everything else is rejected.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        Ok(match text {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "waiting" => Self::Waiting,
            "cancelling" => Self::Cancelling,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => {
                return Err(Failure::invalid(
                    codes::INVALID_STATE,
                    "unknown task status",
                ));
            }
        })
    }

    /// Whether the status is terminal for a Task.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// The legal forward transitions per the Phase 0 lifecycle
    /// contract.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [TaskStatus] {
        match self {
            Self::Queued => &[Self::Running, Self::Waiting, Self::Cancelling],
            Self::Running => &[
                Self::Waiting,
                Self::Cancelling,
                Self::Completed,
                Self::Failed,
            ],
            Self::Waiting => &[
                Self::Running,
                Self::Cancelling,
                Self::Completed,
                Self::Failed,
            ],
            Self::Cancelling => &[Self::Cancelled],
            Self::Completed | Self::Failed | Self::Cancelled => &[],
        }
    }

    /// Whether `to` is a legal forward transition.
    #[must_use]
    pub fn can_transition(self, to: TaskStatus) -> bool {
        self.valid_transitions().contains(&to)
    }
}

impl serde::Serialize for TaskStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl core::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The current execution attempt status (`central.runs.status`).
///
/// `FailedTerminal` is the b37 schema-admitted value the task domain
/// never produces: upstream loads it as raw text where it is neither
/// terminal-listed nor transition-capable, which is exactly the
/// semantics preserved here (`is_terminal` is `false`,
/// `valid_transitions` is empty).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RunStatus {
    /// Awaiting claim.
    Queued,
    /// Actively executing under a claim.
    Running,
    /// Blocked; resumable.
    Waiting,
    /// Cancellation requested, not settled.
    Cancelling,
    /// Terminal: succeeded.
    Succeeded,
    /// Terminal: failed.
    Failed,
    /// Schema-admitted scheduler outcome (b37); never produced by the
    /// task domain and unreachable through its transitions.
    FailedTerminal,
    /// Terminal: cancelled.
    Cancelled,
}

impl RunStatus {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Cancelling => "cancelling",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::FailedTerminal => "failed_terminal",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the canonical text; everything else is rejected.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        Ok(match text {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "waiting" => Self::Waiting,
            "cancelling" => Self::Cancelling,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "failed_terminal" => Self::FailedTerminal,
            "cancelled" => Self::Cancelled,
            _ => {
                return Err(Failure::invalid(codes::INVALID_STATE, "unknown run status"));
            }
        })
    }

    /// Whether the status is terminal — matches the upstream predicate
    /// exactly (`succeeded`/`failed`/`cancelled` only; the
    /// schema-admitted `failed_terminal` is not in upstream's terminal
    /// list).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    /// The legal forward transitions for a run status.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [RunStatus] {
        match self {
            Self::Queued => &[Self::Running, Self::Cancelling],
            Self::Running => &[
                Self::Waiting,
                Self::Cancelling,
                Self::Succeeded,
                Self::Failed,
            ],
            Self::Waiting => &[Self::Queued, Self::Running, Self::Cancelling, Self::Failed],
            Self::Cancelling => &[Self::Cancelled],
            Self::Succeeded | Self::Failed | Self::FailedTerminal | Self::Cancelled => &[],
        }
    }

    /// Whether `to` is a legal forward transition for a run.
    #[must_use]
    pub fn can_transition(self, to: RunStatus) -> bool {
        self.valid_transitions().contains(&to)
    }
}

impl serde::Serialize for RunStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RunStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl core::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a task or run is blocked (`waiting_reason` columns).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WaitingReason {
    /// A required approval is missing.
    Approval,
    /// External/user input is required.
    ExternalInput,
    /// Retry is scheduled for a future time.
    RetryDelay,
    /// A future-capability dependency blocks execution.
    Dependency,
    /// A safe external ambiguity must be resolved.
    Reconciliation,
}

impl WaitingReason {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::ExternalInput => "external_input",
            Self::RetryDelay => "retry_delay",
            Self::Dependency => "dependency",
            Self::Reconciliation => "reconciliation",
        }
    }

    /// Parses the canonical text; everything else is rejected.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        Ok(match text {
            "approval" => Self::Approval,
            "external_input" => Self::ExternalInput,
            "retry_delay" => Self::RetryDelay,
            "dependency" => Self::Dependency,
            "reconciliation" => Self::Reconciliation,
            _ => {
                return Err(Failure::invalid(
                    codes::INVALID_STATE,
                    "unknown waiting reason",
                ));
            }
        })
    }
}

impl serde::Serialize for WaitingReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for WaitingReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl core::fmt::Display for WaitingReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the harness answers a tool permission request for this Task's
/// runs (harness phase 3c decision 3). Chosen at submission and never
/// changes; a Rerun copies it.
///
/// `Unknown` is the port of upstream's "not `Known()`" string state: a
/// persisted row or request carrying unrecognized policy text. The
/// domain fails closed on it — submit and rerun both refuse it — so no
/// path silently defaults.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionPolicy {
    /// Answer every request with a denial; the default of a Task
    /// submitted without a choice.
    Deny,
    /// Turn every request into an operator approval.
    Bridge,
    /// Run every tool without asking.
    AutoAllow,
    /// Unrecognized policy text (upstream `Known() == false`).
    Unknown,
}

/// Every declared [`PermissionPolicy`] in declaration order.
pub const PERMISSION_POLICIES: [PermissionPolicy; 3] = [
    PermissionPolicy::Deny,
    PermissionPolicy::Bridge,
    PermissionPolicy::AutoAllow,
];

impl PermissionPolicy {
    /// Canonical database text; [`PermissionPolicy::Unknown`] has no
    /// canonical form — it is the absence of one (`""`, matching what
    /// upstream's untyped string can hold).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Bridge => "bridge",
            Self::AutoAllow => "auto_allow",
            Self::Unknown => "",
        }
    }

    /// Parses policy text into the vocabulary. Unknown text maps to
    /// [`PermissionPolicy::Unknown`] rather than failing, so domain
    /// gates see the drifted value and refuse it — never a silent
    /// default (upstream `Known()` semantics).
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text {
            "deny" => Self::Deny,
            "bridge" => Self::Bridge,
            "auto_allow" => Self::AutoAllow,
            _ => Self::Unknown,
        }
    }

    /// Whether this is a declared policy. [`PermissionPolicy::Unknown`]
    /// is not.
    #[must_use]
    pub const fn known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

impl serde::Serialize for PermissionPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PermissionPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::parse(&text))
    }
}

impl core::fmt::Display for PermissionPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The harness budget the operator requested for this Task's runs at
/// submission (harness phase 3d decision 2). A zero field is unset:
/// the serve default applies to that bound when a run is claimed. The
/// budget never changes after submission: a Retry keeps it and a Rerun
/// copies it.
///
/// The serde shape matches upstream's canonical JSON field names
/// (`CostMicroUSD`, `WallClockSeconds`) so the submit-request
/// fingerprint is byte-identical to the Go encoding.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Budget {
    /// Bounds the cost the harness reports, in micro-USD.
    #[serde(rename = "CostMicroUSD")]
    pub cost_micro_usd: i64,
    /// Bounds how long one run may take, in seconds.
    #[serde(rename = "WallClockSeconds")]
    pub wall_clock_seconds: i32,
}

/// The bounds of a requested [`Budget`]: US$0.01 to US$1,000, and one
/// minute to one day. Migration b32 pins the same bounds in the
/// `tasks` CHECKs.
pub const MIN_BUDGET_COST_MICRO_USD: i64 = 10_000;
/// See [`MIN_BUDGET_COST_MICRO_USD`].
pub const MAX_BUDGET_COST_MICRO_USD: i64 = 1_000_000_000;
/// See [`MIN_BUDGET_COST_MICRO_USD`].
pub const MIN_BUDGET_WALL_CLOCK_SECONDS: i32 = 60;
/// See [`MIN_BUDGET_COST_MICRO_USD`].
pub const MAX_BUDGET_WALL_CLOCK_SECONDS: i32 = 86_400;

impl Budget {
    /// Whether neither bound is set.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    /// Accepts an unset bound or one within its range.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.cost_micro_usd != 0
            && (self.cost_micro_usd < MIN_BUDGET_COST_MICRO_USD
                || self.cost_micro_usd > MAX_BUDGET_COST_MICRO_USD)
        {
            return Err(Failure::invalid(
                codes::INVALID_STATE,
                "cost limit out of range: choose a cost limit from US$0.01 to US$1000, or leave it empty",
            ));
        }
        if self.wall_clock_seconds != 0
            && (self.wall_clock_seconds < MIN_BUDGET_WALL_CLOCK_SECONDS
                || self.wall_clock_seconds > MAX_BUDGET_WALL_CLOCK_SECONDS)
        {
            return Err(Failure::invalid(
                codes::INVALID_STATE,
                "wall clock limit out of range: choose a wall clock from 1 minute to 24 hours, or leave it empty",
            ));
        }
        Ok(())
    }
}

/// Converts a dollar amount such as `"5"`, `"0.5"` or `"2.50"` to
/// micro-USD exactly; `None` for any other shape. It does not check
/// the range: each caller (the serve default, the submit form)
/// applies its own bounds and its own message.
///
/// Shape — a plain decimal number of dollars with 1 to 7 digits and
/// at most two decimal places: no sign, exponent, separator or
/// surrounding space (`^[0-9]{1,7}(\.[0-9]{1,2})?$`).
#[must_use]
pub fn parse_budget_cost_usd(raw: &str) -> Option<i64> {
    let (whole, frac) = match raw.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (raw, None),
    };
    if whole.is_empty() || whole.len() > 7 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut cents: i64 = 0;
    if let Some(frac) = frac {
        if frac.is_empty() || frac.len() > 2 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        cents = if frac.len() == 1 {
            i64::from(frac.as_bytes()[0] - b'0') * 10
        } else {
            i64::from(frac.as_bytes()[0] - b'0') * 10 + i64::from(frac.as_bytes()[1] - b'0')
        };
    }
    let dollars: i64 = whole.parse().ok()?;
    // At most 9,999,999.99 dollars: far below i64's range.
    Some((dollars * 100 + cents) * 10_000)
}

// ---------------------------------------------------------------------------
// Aggregate shapes
// ---------------------------------------------------------------------------

/// The durable task aggregate root (`central.tasks`).
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    /// The opaque task identity.
    pub id: TaskId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The optimistic lock value for change-set CAS.
    pub version: i64,
    /// The current lifecycle status.
    pub status: TaskStatus,
    /// The active non-terminal run when present.
    pub current_run_id: Option<RunId>,
    /// The cancelled Task this Task was rerun from (`None` when
    /// submitted directly — b11 lineage).
    pub parent_task_id: Option<TaskId>,
    /// The highest persisted run index.
    pub last_run_index: i64,
    /// Terminal run failures persisted so far.
    pub retry_count: i64,
    /// When a scheduled whole-run retry becomes eligible.
    pub retry_eligible_at: Option<OffsetDateTime>,
    /// Present while [`TaskStatus::Waiting`] and a waiter is active.
    pub waiting_reason: Option<WaitingReason>,
    /// The terminal failure summary for this task state (`""` = none).
    pub failure_reason: String,
    /// The submission payload summary/reference.
    pub input: String,
    /// The user-facing label.
    pub title: String,
    /// The harness permission policy chosen at submission; never
    /// changes, a Rerun copies it.
    pub permission_policy: PermissionPolicy,
    /// The harness budget requested at submission; a zero field means
    /// the serve default. Never changes; a Rerun copies it.
    pub budget: Budget,
    /// Authoritative persistence timestamps.
    pub created_at: OffsetDateTime,
    /// Authoritative persistence timestamps.
    pub updated_at: OffsetDateTime,
}

impl Task {
    /// Whether the task status is terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}

/// The durable run aggregate (`central.runs`).
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    /// The opaque run identity.
    pub id: RunId,
    /// The owning task.
    pub task_id: TaskId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The optimistic lock value for CAS on this run.
    pub version: i64,
    /// The current run status.
    pub status: RunStatus,
    /// The run attempt number within the task (`run_index`).
    pub index: i64,
    /// Present while `status ==` [`RunStatus::Waiting`].
    pub waiting_reason: Option<WaitingReason>,
    /// The run terminal outcome (`""` = none).
    pub failure_reason: String,
    /// The opaque execution claim token (`""` = never claimed).
    pub ownership_token: String,
    /// The caller-supplied submit dedup key — spec-5's
    /// `(workspace_id, run_key)` coordinate; `None` means the submit
    /// carried no key and the partial unique index skips the row.
    pub run_key: Option<String>,
    /// The SHA-256 of the canonical submit payload the
    /// `(workspace_id, run_key)` replay compare binds.
    pub request_fingerprint: Option<[u8; 32]>,
    /// Authoritative persistence timestamps.
    pub created_at: OffsetDateTime,
    /// Authoritative persistence timestamps.
    pub updated_at: OffsetDateTime,
}

impl Run {
    /// Whether the run status is terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}

/// The logical tuple the transition functions evaluate.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskAggregate {
    /// The task row.
    pub task: Task,
    /// The current run when `task.current_run_id` names one.
    pub current_run: Option<Run>,
}

impl TaskAggregate {
    /// Ensures the aggregate invariants before evaluating a
    /// transition.
    pub fn validate_consistency(&self) -> Result<(), Failure> {
        match (self.task.current_run_id, &self.current_run) {
            (None, Some(_)) | (Some(_), None) => {
                return Err(Failure::invalid(
                    codes::RUN_MISMATCH,
                    "the current run reference and the supplied run disagree",
                ));
            }
            (Some(id), Some(run)) if run.id != id => {
                return Err(Failure::invalid(
                    codes::RUN_MISMATCH,
                    "the current run reference and the supplied run disagree",
                ));
            }
            _ => {}
        }
        let Some(run) = &self.current_run else {
            if matches!(
                self.task.status,
                TaskStatus::Running | TaskStatus::Cancelling
            ) {
                return Err(Failure::invalid(
                    codes::INVALID_STATE,
                    "a running or cancelling task keeps a current run",
                ));
            }
            if self.task.status == TaskStatus::Waiting
                && self.task.waiting_reason != Some(WaitingReason::RetryDelay)
            {
                return Err(Failure::invalid(
                    codes::INVALID_STATE,
                    "only a retry-delay wait may lack a current run",
                ));
            }
            return Ok(());
        };
        let consistent = match self.task.status {
            TaskStatus::Queued => run.status == RunStatus::Queued,
            TaskStatus::Running => run.status == RunStatus::Running,
            TaskStatus::Waiting => {
                run.status == RunStatus::Waiting
                    && self.task.waiting_reason.is_some()
                    && self.task.waiting_reason != Some(WaitingReason::RetryDelay)
            }
            TaskStatus::Cancelling => run.status == RunStatus::Cancelling,
            TaskStatus::Completed => run.status == RunStatus::Succeeded,
            TaskStatus::Failed => run.status == RunStatus::Failed,
            TaskStatus::Cancelled => run.status == RunStatus::Cancelled,
        };
        if consistent {
            Ok(())
        } else {
            Err(Failure::invalid(
                codes::INVALID_STATE,
                "the task and run statuses disagree",
            ))
        }
    }

    /// Whether this aggregate is one `cancel_unclaimed_task` accepts: a
    /// queued Task whose current Run is queued, or a cancelling Task
    /// whose current Run is cancelling — and in both cases the Run was
    /// never claimed (no ownership token; only `claim_current_run`
    /// sets one).
    #[must_use]
    pub fn unclaimed(&self) -> bool {
        match &self.current_run {
            Some(run) if run.ownership_token.is_empty() => {}
            _ => return false,
        }
        if self.validate_consistency().is_err() {
            return false;
        }
        match self.task.status {
            TaskStatus::Queued => self
                .current_run
                .as_ref()
                .is_some_and(|r| r.status == RunStatus::Queued),
            TaskStatus::Cancelling => self
                .current_run
                .as_ref()
                .is_some_and(|r| r.status == RunStatus::Cancelling),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Event intents and the optimistic change-set
// ---------------------------------------------------------------------------

/// Task/event append intents for atomic commit (`central.events`
/// `event_type`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// `task.submitted`
    TaskSubmitted,
    /// `task.claimed`
    TaskClaimed,
    /// `task.wait`
    TaskWait,
    /// `task.resumed`
    TaskResumed,
    /// `task.retry_scheduled`
    TaskRetryScheduled,
    /// `task.retry_activated`
    TaskRetryActivated,
    /// `task.completed`
    TaskCompleted,
    /// `task.failed`
    TaskFailed,
    /// `task.cancel_requested`
    TaskCancelRequested,
    /// `task.cancelled`
    TaskCancelled,
    /// `task.retry_requested`
    TaskRetryRequested,
    /// `task.run_transition`
    RunTransition,
}

impl EventKind {
    /// Canonical `event_type` text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskSubmitted => "task.submitted",
            Self::TaskClaimed => "task.claimed",
            Self::TaskWait => "task.wait",
            Self::TaskResumed => "task.resumed",
            Self::TaskRetryScheduled => "task.retry_scheduled",
            Self::TaskRetryActivated => "task.retry_activated",
            Self::TaskCompleted => "task.completed",
            Self::TaskFailed => "task.failed",
            Self::TaskCancelRequested => "task.cancel_requested",
            Self::TaskCancelled => "task.cancelled",
            Self::TaskRetryRequested => "task.retry_requested",
            Self::RunTransition => "task.run_transition",
        }
    }
}

impl serde::Serialize for EventKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EventKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(match text.as_str() {
            "task.submitted" => Self::TaskSubmitted,
            "task.claimed" => Self::TaskClaimed,
            "task.wait" => Self::TaskWait,
            "task.resumed" => Self::TaskResumed,
            "task.retry_scheduled" => Self::TaskRetryScheduled,
            "task.retry_activated" => Self::TaskRetryActivated,
            "task.completed" => Self::TaskCompleted,
            "task.failed" => Self::TaskFailed,
            "task.cancel_requested" => Self::TaskCancelRequested,
            "task.cancelled" => Self::TaskCancelled,
            "task.retry_requested" => Self::TaskRetryRequested,
            "task.run_transition" => Self::RunTransition,
            _ => return Err(serde::de::Error::custom("unknown task event kind")),
        })
    }
}

impl core::fmt::Display for EventKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The write-side payload for atomic event append.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskEventIntent {
    /// The lifecycle event kind.
    pub kind: EventKind,
    /// The task the event concerns.
    pub task_id: TaskId,
    /// The run when the event is run-scoped.
    pub run_id: Option<RunId>,
    /// The waiting reason the event carries, when any.
    pub reason: Option<WaitingReason>,
    /// Bounded safe detail text.
    pub detail: String,
    /// When the event occurred.
    pub occurred_at: OffsetDateTime,
}

/// The canonical command result the Task domain produces: the adapter
/// commits it atomically with optimistic-lock version checks.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskChangeSet {
    /// Checked against the task row with optimistic locking
    /// ([`NO_EXISTING_VERSION`] for creates).
    pub expected_task_version: i64,
    /// Optimistic guards for changed runs.
    pub run_expected_versions: std::collections::BTreeMap<RunId, i64>,
    /// The full next task snapshot.
    pub task: Task,
    /// New/updated run rows to persist.
    pub runs: Vec<Run>,
    /// Events emitted transactionally with task/run state.
    pub events: Vec<TaskEventIntent>,
}

/// The adapter-returned durability result.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitResult {
    /// The committed task row.
    pub task: Task,
    /// The committed run rows.
    pub runs: Vec<Run>,
    /// The appended event intents.
    pub events: Vec<TaskEventIntent>,
}

// ---------------------------------------------------------------------------
// Command input contracts
// ---------------------------------------------------------------------------

/// The aggregate snapshot plus version guards every mutation carries.
#[derive(Debug, Clone, PartialEq)]
pub struct MutationInput {
    /// The loaded aggregate the command evaluates against.
    pub aggregate: TaskAggregate,
    /// The task row version the caller last read
    /// ([`NO_EXISTING_VERSION`] only where a create is legal).
    pub expected_task_version: i64,
    /// The current run row version the caller last read.
    pub expected_run_version: i64,
    /// The evaluation instant — caller-supplied so the domain never
    /// reads a clock (upstream's zero-time `normalizeNow` fallback is
    /// replaced by this required field).
    pub now: OffsetDateTime,
}

/// Creates a new task and first run.
#[derive(Debug, Clone, PartialEq)]
pub struct SubmitTaskRequest {
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The user-facing label.
    pub title: String,
    /// The submission payload summary/reference.
    pub input: String,
    /// The harness permission policy: `None` means
    /// [`PermissionPolicy::Deny`] (upstream's empty policy); an
    /// unrecognized value is invalid.
    pub permission_policy: Option<PermissionPolicy>,
    /// The requested harness budget. A zero field means the serve
    /// default; a set field must be within its range.
    pub budget: Budget,
    /// The caller-chosen submit idempotency key recorded on the first
    /// run (spec-5's `(workspace_id, run_key)` coordinate). `None` (or
    /// an empty key) means the submit carries no key and persists NULL.
    pub run_key: Option<String>,
    /// The evaluation instant.
    pub now: OffsetDateTime,
}

/// Claims the queued task and its queued current run.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimCurrentRunRequest {
    /// The mutation envelope.
    pub input: MutationInput,
    /// The executor's claim token — must be non-blank.
    pub owner: String,
}

/// Moves running to waiting with a typed waiting reason.
#[derive(Debug, Clone, PartialEq)]
pub struct WaitTaskRequest {
    /// The mutation envelope.
    pub input: MutationInput,
    /// Why the task waits; required (upstream rejects `""`).
    pub reason: Option<WaitingReason>,
    /// Bounded safe detail.
    pub detail: String,
}

/// Re-queues the same non-terminal run.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeSameRunRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Resumes a Task waiting on the reconciliation of its claimed Run
/// (harness phase 3g decision 2).
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeReconciledRunRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Transitions to waiting retry-delay without destroying evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleRunRetryRequest {
    /// The mutation envelope.
    pub input: MutationInput,
    /// The wait classification recorded on the retry event.
    pub reason: Option<WaitingReason>,
    /// When the retry becomes eligible; `None` means `now`.
    pub retry_at: Option<OffsetDateTime>,
    /// The failed run's recorded failure.
    pub failure_note: String,
}

/// Creates the next run and returns the task to queued.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivateScheduledRunRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Completes a running task and run.
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteTaskRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Fails a running or waiting task (and its run, when present).
#[derive(Debug, Clone, PartialEq)]
pub struct FailTaskRequest {
    /// The mutation envelope.
    pub input: MutationInput,
    /// The terminal failure summary.
    pub reason: String,
}

/// Persists cancellation intent and transitions to cancelling.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestCancellationRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Transitions cancelling to cancelled and settles run state.
#[derive(Debug, Clone, PartialEq)]
pub struct SettleCancellationRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Cancels a Task whose current Run was never claimed (harness phase
/// 3e decisions 2 and 3).
#[derive(Debug, Clone, PartialEq)]
pub struct CancelUnclaimedTaskRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Retries a failed task, keeping prior evidence, with a new run.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryFailedTaskRequest {
    /// The mutation envelope.
    pub input: MutationInput,
}

/// Creates a brand-new Task with explicit lineage to a cancelled
/// source Task.
#[derive(Debug, Clone, PartialEq)]
pub struct RerunCancelledTaskRequest {
    /// The cancelled source aggregate.
    pub source: TaskAggregate,
    /// The source task row version the caller last read.
    pub expected_task_version: i64,
    /// The evaluation instant.
    pub now: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn assert_expected_versions(
    task: &Task,
    run: Option<&Run>,
    input: &MutationInput,
) -> Result<(), Failure> {
    if input.expected_task_version != NO_EXISTING_VERSION
        && input.expected_task_version != task.version
    {
        return Err(Failure::conflict(
            codes::VERSION_CONFLICT,
            "task version mismatch",
        ));
    }
    if let Some(run) = run
        && input.expected_run_version != NO_EXISTING_VERSION
        && input.expected_run_version != run.version
    {
        return Err(Failure::conflict(
            codes::VERSION_CONFLICT,
            "run version mismatch",
        ));
    }
    Ok(())
}

fn consistent(input: &MutationInput) -> Result<(), Failure> {
    input
        .aggregate
        .validate_consistency()
        .map_err(|e| Failure::invalid(e.code(), "invalid aggregate snapshot"))
}

fn task_events(
    task_id: TaskId,
    run_id: Option<RunId>,
    kind: EventKind,
    reason: Option<WaitingReason>,
    detail: impl Into<String>,
    now: OffsetDateTime,
) -> Vec<TaskEventIntent> {
    vec![TaskEventIntent {
        kind,
        task_id,
        run_id,
        reason,
        detail: detail.into(),
        occurred_at: now,
    }]
}

fn bump_task(mut task: Task, now: OffsetDateTime) -> Task {
    task.version += 1;
    task.updated_at = now;
    task
}

fn bump_run(mut run: Run, now: OffsetDateTime) -> Run {
    run.version += 1;
    run.updated_at = now;
    run
}

// ---------------------------------------------------------------------------
// Transition evaluators (canonical B07 lifecycle)
// ---------------------------------------------------------------------------

/// The SHA-256 of the canonical submit payload the
/// `(workspace_id, run_key)` replay compare binds (issue #122, spec
/// SR3). It is the single implementation: callers needing the
/// resume-compare value use this, never a second canonicalization.
///
/// The canonical JSON field order and names reproduce the Go encoding
/// byte-for-byte — including `Budget`'s `CostMicroUSD` /
/// `WallClockSeconds` keys — so a Go/Rust mixed deployment agrees on
/// the fingerprint for an identical request. [`go_json_escapes`]
/// rewrites `serde_json`'s raw `<`, `>`, `&`, U+2028, U+2029 output
/// into Go's `\u…` escapes so the bytes match even for HTML-unsafe
/// input.
#[must_use]
pub fn submit_request_fingerprint(req: &SubmitTaskRequest) -> [u8; 32] {
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        workspace_id: String,
        run_key: &'a str,
        title: &'a str,
        input: &'a str,
        permission_policy: &'a str,
        budget: &'a Budget,
    }
    let record = Canonical {
        workspace_id: req.workspace_id.to_string(),
        run_key: req.run_key.as_deref().unwrap_or(""),
        title: &req.title,
        input: &req.input,
        permission_policy: req.permission_policy.map_or("", PermissionPolicy::as_str),
        budget: &req.budget,
    };
    // A fixed-field struct cannot fail to serialize; an empty payload
    // keeps the function total without a panic path.
    let payload = serde_json::to_vec(&record).unwrap_or_default();
    sha2::Sha256::digest(go_json_escapes(&payload)).into()
}

/// Rewrites `serde_json` output into the byte sequence Go's
/// `json.Marshal` produces for the same payload. Field order, key
/// names, and every escape already agree — `\b`, `\f`, `\n`, `\r`,
/// `\t` shorthands, `\u00XX` for the other control bytes, raw UTF-8
/// for non-ASCII — except five characters Go always escapes inside
/// strings: `<`→`\u003c`, `>`→`\u003e`, `&`→`\u0026`, U+2028→`\u2028`,
/// U+2029→`\u2029`.
///
/// A raw byte rewrite is safe: `<`, `>` and `&` are neither JSON
/// structural characters, escape codes, nor hex digits, so each
/// occurrence in the payload is a literal string byte Go would have
/// escaped; and `serde_json` emits valid UTF-8 where `E2 80 A8` /
/// `E2 80 A9` can only ever encode U+2028 / U+2029.
fn go_json_escapes(payload: &[u8]) -> Vec<u8> {
    const U2028: [u8; 3] = [0xE2, 0x80, 0xA8];
    const U2029: [u8; 3] = [0xE2, 0x80, 0xA9];
    let mut out = Vec::with_capacity(payload.len() + 16);
    let mut i = 0;
    while i < payload.len() {
        match payload[i] {
            b'<' => {
                out.extend_from_slice(b"\\u003c");
                i += 1;
            }
            b'>' => {
                out.extend_from_slice(b"\\u003e");
                i += 1;
            }
            b'&' => {
                out.extend_from_slice(b"\\u0026");
                i += 1;
            }
            0xE2 if payload[i..].starts_with(&U2028) => {
                out.extend_from_slice(b"\\u2028");
                i += 3;
            }
            0xE2 if payload[i..].starts_with(&U2029) => {
                out.extend_from_slice(b"\\u2029");
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Creates a queued task with first queued run in one atomic
/// change-set.
pub fn submit_task(req: SubmitTaskRequest) -> Result<TaskChangeSet, Failure> {
    if req.workspace_id.is_nil() {
        return Err(Failure::invalid(
            codes::INVALID_STATE,
            "missing workspace: submit with a valid workspace identity",
        ));
    }
    let policy = req.permission_policy.unwrap_or(PermissionPolicy::Deny);
    if let PermissionPolicy::Unknown = policy {
        return Err(Failure::invalid(
            codes::INVALID_STATE,
            "unknown permission policy: submit with deny, bridge or auto_allow",
        ));
    }
    req.budget.validate()?;
    let now = req.now;
    let task_id = TaskId::new();
    let run_id = RunId::new();
    let mut run = Run {
        id: run_id,
        task_id,
        workspace_id: req.workspace_id,
        version: 0,
        status: RunStatus::Queued,
        index: 1,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: now,
        updated_at: now,
    };
    if let Some(key) = req.run_key.as_deref().filter(|k| !k.is_empty()) {
        // The (workspace_id, run_key) partial unique index is spec-5's
        // submit-run dedup coordinate; request_fingerprint binds the
        // canonical submit payload a replay compares.
        run.run_key = Some(key.to_string());
        run.request_fingerprint = Some(submit_request_fingerprint(&req));
    }
    let task = Task {
        id: task_id,
        workspace_id: req.workspace_id,
        version: 0,
        status: TaskStatus::Queued,
        current_run_id: Some(run_id),
        parent_task_id: None,
        last_run_index: 1,
        retry_count: 0,
        retry_eligible_at: None,
        waiting_reason: None,
        failure_reason: String::new(),
        input: req.input,
        title: req.title,
        permission_policy: policy,
        budget: req.budget,
        created_at: now,
        updated_at: now,
    };
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    Ok(TaskChangeSet {
        expected_task_version: NO_EXISTING_VERSION,
        run_expected_versions: [(run_id, NO_EXISTING_VERSION)].into_iter().collect(),
        task,
        runs: vec![run],
        events: task_events(
            task_id,
            Some(run_id),
            EventKind::TaskSubmitted,
            None,
            "create initial queued task",
            now,
        ),
    })
}

/// Transitions queued→running and run queued→running. The owner is
/// required: [`TaskAggregate::unclaimed`] reads an empty ownership
/// token as "never claimed", so a claim must always leave a non-blank
/// one.
pub fn claim_current_run(req: ClaimCurrentRunRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if req.owner.trim().is_empty() {
        return Err(Failure::invalid(
            codes::INVALID,
            "claim requires an owner: claim with the executor's owner token",
        ));
    }
    if req.input.aggregate.task.status != TaskStatus::Queued {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "claim requires queued task: retry only for queued tasks",
        ));
    }
    let Some(mut run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(codes::RUN_MISMATCH, "missing current run"));
    };
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    if run.status != RunStatus::Queued {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "run is not queueable: start from a queued run",
        ));
    }
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Running;
    run.status = RunStatus::Running;
    run.ownership_token = req.owner;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let mut events = task_events(
        task.id,
        Some(run.id),
        EventKind::TaskClaimed,
        None,
        "claim run",
        now,
    );
    events.push(TaskEventIntent {
        kind: EventKind::RunTransition,
        task_id: task.id,
        run_id: Some(run.id),
        reason: None,
        detail: "run_claimed".to_string(),
        occurred_at: now,
    });
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run.id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events,
    })
}

/// Moves running→waiting with a typed waiting reason.
pub fn wait_task(req: WaitTaskRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    let Some(reason) = req.reason else {
        return Err(Failure::invalid(
            codes::INVALID_STATE,
            "missing waiting reason",
        ));
    };
    if req.input.aggregate.task.status != TaskStatus::Running {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "wait requires running task: run command requires task in running state",
        ));
    }
    let Some(mut run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(codes::RUN_MISMATCH, "missing current run"));
    };
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Waiting;
    task.waiting_reason = Some(reason);
    run.status = RunStatus::Waiting;
    run.waiting_reason = Some(reason);
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let (task_id, run_id) = (task.id, run.id);
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run_id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events: task_events(
            task_id,
            Some(run_id),
            EventKind::TaskWait,
            Some(reason),
            req.detail,
            now,
        ),
    })
}

/// Re-queues the same non-terminal run.
pub fn resume_same_run(req: ResumeSameRunRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if req.input.aggregate.task.status != TaskStatus::Waiting {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "resume requires waiting task",
        ));
    }
    if req.input.aggregate.task.waiting_reason == Some(WaitingReason::RetryDelay) {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "retry-delay waits resume through ActivateScheduledRun: activate scheduled retry instead",
        ));
    }
    let Some(mut run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(codes::RUN_MISMATCH, "missing waiting run"));
    };
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Queued;
    task.waiting_reason = None;
    task.retry_eligible_at = None;
    run.status = RunStatus::Queued;
    run.waiting_reason = None;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let (task_id, run_id) = (task.id, run.id);
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run_id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events: task_events(
            task_id,
            Some(run_id),
            EventKind::TaskResumed,
            None,
            "resume same run",
            now,
        ),
    })
}

/// Moves a Task waiting on reconciliation, and its claimed Run, back
/// to running. The Run and its `ownership_token` are kept: the resumed
/// attempt continues under the same claim.
pub fn resume_reconciled_run(req: ResumeReconciledRunRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    let deny = |reason: &'static str| Failure::denied(codes::INVALID_TRANSITION, reason);
    if req.input.aggregate.task.status != TaskStatus::Waiting
        || req.input.aggregate.task.waiting_reason != Some(WaitingReason::Reconciliation)
    {
        return Err(deny("resume requires a task waiting for reconciliation"));
    }
    let Some(current) = &req.input.aggregate.current_run else {
        return Err(Failure::invalid(codes::RUN_MISMATCH, "missing waiting run"));
    };
    if current.status != RunStatus::Waiting
        || current.waiting_reason != Some(WaitingReason::Reconciliation)
    {
        return Err(deny("resume requires a run waiting for reconciliation"));
    }
    if current.ownership_token.is_empty() {
        return Err(deny("resume requires a claimed run"));
    }
    assert_expected_versions(&req.input.aggregate.task, Some(current), &req.input)?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    let mut run = current.clone();
    task.status = TaskStatus::Running;
    task.waiting_reason = None;
    run.status = RunStatus::Running;
    run.waiting_reason = None;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let mut events = task_events(
        task.id,
        Some(run.id),
        EventKind::TaskResumed,
        None,
        "resume reconciled attempt",
        now,
    );
    events.push(TaskEventIntent {
        kind: EventKind::RunTransition,
        task_id: task.id,
        run_id: Some(run.id),
        reason: None,
        detail: "run_resumed".to_string(),
        occurred_at: now,
    });
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run.id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events,
    })
}

/// Transitions to waiting retry-delay without destroying evidence.
pub fn schedule_run_retry(req: ScheduleRunRetryRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if !matches!(
        req.input.aggregate.task.status,
        TaskStatus::Running | TaskStatus::Waiting
    ) {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "retry schedule requires running or waiting task: retry schedule only applies after failure",
        ));
    }
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let Some(mut run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(
            codes::RUN_MISMATCH,
            "run expected for non-terminal retry scheduling",
        ));
    };
    let now = req.input.now;
    let retry_at = req.retry_at.unwrap_or(now);
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Waiting;
    task.waiting_reason = Some(WaitingReason::RetryDelay);
    task.retry_eligible_at = Some(retry_at);
    task.retry_count += 1;
    run.status = RunStatus::Failed;
    run.failure_reason = req.failure_note;
    task.current_run_id = None;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let (task_id, run_id) = (task.id, run.id);
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run_id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events: task_events(
            task_id,
            Some(run_id),
            EventKind::TaskRetryScheduled,
            Some(WaitingReason::RetryDelay),
            req.reason.map_or("", WaitingReason::as_str).to_string(),
            now,
        ),
    })
}

/// Creates the next run and returns the task to queued.
pub fn activate_scheduled_run(req: ActivateScheduledRunRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    let now = req.input.now;
    if req.input.aggregate.task.status != TaskStatus::Waiting {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "activation requires waiting task: activate only from retry-delay waiting",
        ));
    }
    if req.input.aggregate.task.waiting_reason != Some(WaitingReason::RetryDelay) {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "only retry-delay waits can activate next run",
        ));
    }
    if req
        .input
        .aggregate
        .task
        .retry_eligible_at
        .is_some_and(|at| at > now)
    {
        return Err(Failure::denied(
            codes::INVALID_STATE,
            "retry time has not arrived: retry with a later cursor",
        ));
    }
    if req.input.aggregate.task.current_run_id.is_some() {
        return Err(Failure::invalid(
            codes::RUN_MISMATCH,
            "retry state must not keep current run",
        ));
    }
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let mut task = req.input.aggregate.task;
    let next_run_id = RunId::new();
    let next_index = task.last_run_index + 1;
    let run = Run {
        id: next_run_id,
        task_id: task.id,
        workspace_id: task.workspace_id,
        version: 0,
        status: RunStatus::Queued,
        index: next_index,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: now,
        updated_at: now,
    };
    task.status = TaskStatus::Queued;
    task.current_run_id = Some(next_run_id);
    task.retry_eligible_at = None;
    task.waiting_reason = None;
    task.last_run_index = next_index;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let task_id = task.id;
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        // The activated Run is this change set's only write, an
        // INSERT: it names NO_EXISTING_VERSION exactly as submit_task
        // does. (Upstream emits an empty map here — the same
        // store-rejecting defect the RetryFailedTask comment records;
        // the persistence contract requires an expected version for
        // every Run the change set writes.)
        run_expected_versions: [(next_run_id, NO_EXISTING_VERSION)].into_iter().collect(),
        task,
        runs: vec![run],
        events: task_events(
            task_id,
            Some(next_run_id),
            EventKind::TaskRetryActivated,
            None,
            "create new run",
            now,
        ),
    })
}

/// Transitions running→completed and run running→succeeded.
pub fn complete_task(req: CompleteTaskRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if req.input.aggregate.task.status != TaskStatus::Running {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "complete requires running task",
        ));
    }
    let Some(mut run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(codes::RUN_MISMATCH, "missing current run"));
    };
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Completed;
    task.failure_reason = String::new();
    task.waiting_reason = None;
    run.status = RunStatus::Succeeded;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let (task_id, run_id) = (task.id, run.id);
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run_id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events: task_events(
            task_id,
            Some(run_id),
            EventKind::TaskCompleted,
            None,
            "run completed",
            now,
        ),
    })
}

/// Transitions running/waiting→failed and run to failed (if present).
pub fn fail_task(req: FailTaskRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if !matches!(
        req.input.aggregate.task.status,
        TaskStatus::Running | TaskStatus::Waiting
    ) {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "fail requires running or waiting task",
        ));
    }
    if req.input.aggregate.task.waiting_reason == Some(WaitingReason::RetryDelay) {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "retry-delay wait fails through retry scheduling",
        ));
    }
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Failed;
    task.failure_reason = req.reason.clone();
    task.waiting_reason = None;
    task.retry_eligible_at = None;
    let task = bump_task(task, now);
    let mut runs = Vec::new();
    let mut run_checks = std::collections::BTreeMap::new();
    if let Some(current) = req.input.aggregate.current_run.clone() {
        let mut run = current;
        run.status = RunStatus::Failed;
        run.failure_reason = req.reason.clone();
        run = bump_run(run, now);
        run_checks.insert(run.id, req.input.expected_run_version);
        runs.push(run);
    }
    let (task_id, run_id) = (task.id, task.current_run_id);
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: run_checks,
        task,
        runs,
        events: task_events(
            task_id,
            run_id,
            EventKind::TaskFailed,
            None,
            req.reason,
            now,
        ),
    })
}

/// Persists cancellation intent and transitions to cancelling.
pub fn request_cancellation(req: RequestCancellationRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if !matches!(
        req.input.aggregate.task.status,
        TaskStatus::Queued | TaskStatus::Running | TaskStatus::Waiting
    ) {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "task not cancellable from this status",
        ));
    }
    if req.input.aggregate.current_run.is_some()
        && req.input.aggregate.task.current_run_id.is_none()
    {
        return Err(Failure::invalid(
            codes::RUN_MISMATCH,
            "run mismatch while canceling",
        ));
    }
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Cancelling;
    let mut runs = Vec::new();
    let mut run_checks = std::collections::BTreeMap::new();
    if let Some(current) = req.input.aggregate.current_run.clone() {
        let mut run = current;
        run.status = RunStatus::Cancelling;
        run = bump_run(run, now);
        run_checks.insert(run.id, req.input.expected_run_version);
        runs.push(run);
    }
    let run_id = task.current_run_id;
    let task = bump_task(task, now);
    let task_id = task.id;
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: run_checks,
        task,
        runs,
        events: task_events(
            task_id,
            run_id,
            EventKind::TaskCancelRequested,
            None,
            "cancel requested",
            now,
        ),
    })
}

/// Transitions cancelling→cancelled and settles run state.
pub fn settle_cancellation(req: SettleCancellationRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if req.input.aggregate.task.status != TaskStatus::Cancelling {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "settle requires cancelling task",
        ));
    }
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Cancelled;
    task.waiting_reason = None;
    let mut runs = Vec::new();
    let mut run_checks = std::collections::BTreeMap::new();
    if let Some(current) = req.input.aggregate.current_run.clone() {
        let mut run = current;
        run.status = RunStatus::Cancelled;
        run = bump_run(run, now);
        run_checks.insert(run.id, req.input.expected_run_version);
        runs.push(run);
    }
    let run_id = task.current_run_id;
    let task = bump_task(task, now);
    let task_id = task.id;
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: run_checks,
        task,
        runs,
        events: task_events(
            task_id,
            run_id,
            EventKind::TaskCancelled,
            None,
            "cancel settled",
            now,
        ),
    })
}

/// Ends a Task whose current Run was never claimed cancelled in one
/// change set (harness phase 3e decisions 2 and 3): from queued it
/// records the cancel request and its settlement together; from a
/// cancelling Task left without a claimed Run it records the
/// settlement. Nothing executed, so no executor attestation is needed.
/// Every other Task, including one whose Run was claimed, is refused
/// with `Denied`.
pub fn cancel_unclaimed_task(req: CancelUnclaimedTaskRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if !req.input.aggregate.unclaimed() {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "cancel unclaimed requires a queued or cancelling task whose run was never claimed: request cancellation instead",
        ));
    }
    assert_expected_versions(
        &req.input.aggregate.task,
        req.input.aggregate.current_run.as_ref(),
        &req.input,
    )?;
    let now = req.input.now;
    let from = req.input.aggregate.task.status;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Cancelled;
    task.waiting_reason = None;
    // `unclaimed` guarantees a current run exists; the guard is kept
    // defensive so the transition stays total.
    let Some(mut run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(codes::RUN_MISMATCH, "missing current run"));
    };
    run.status = RunStatus::Cancelled;
    run.waiting_reason = None;
    let task = bump_task(task, now);
    let run = bump_run(run, now);
    let mut events = Vec::new();
    if from == TaskStatus::Queued {
        events.extend(task_events(
            task.id,
            Some(run.id),
            EventKind::TaskCancelRequested,
            None,
            "cancel requested",
            now,
        ));
    }
    events.extend(task_events(
        task.id,
        Some(run.id),
        EventKind::TaskCancelled,
        None,
        "cancelled before the run was claimed",
        now,
    ));
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        run_expected_versions: [(run.id, req.input.expected_run_version)]
            .into_iter()
            .collect(),
        task,
        runs: vec![run],
        events,
    })
}

/// Retries a failed task by keeping prior evidence and creating a new
/// run.
pub fn retry_failed_task(req: RetryFailedTaskRequest) -> Result<TaskChangeSet, Failure> {
    consistent(&req.input)?;
    if req.input.aggregate.task.status != TaskStatus::Failed {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "retry requires failed task",
        ));
    }
    if req.input.aggregate.task.current_run_id.is_none() {
        return Err(Failure::invalid(
            codes::RUN_MISMATCH,
            "retry failed task requires preserved failed run",
        ));
    }
    let Some(failed_run) = req.input.aggregate.current_run.clone() else {
        return Err(Failure::invalid(
            codes::RUN_MISMATCH,
            "retry failed task missing run",
        ));
    };
    assert_expected_versions(&req.input.aggregate.task, Some(&failed_run), &req.input)?;
    let now = req.input.now;
    let mut task = req.input.aggregate.task;
    task.status = TaskStatus::Queued;
    task.failure_reason = String::new();
    task.waiting_reason = None;
    task.retry_count += 1;
    task.current_run_id = None;
    let next_run_id = RunId::new();
    let next_index = task.last_run_index + 1;
    task.last_run_index = next_index;
    let mut run = Run {
        id: next_run_id,
        task_id: task.id,
        workspace_id: task.workspace_id,
        version: 0,
        status: RunStatus::Queued,
        index: next_index,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: now,
        updated_at: now,
    };
    run = bump_run(run, now);
    task = bump_task(task, now);
    task.current_run_id = Some(run.id);
    let (task_id, run_id) = (task.id, run.id);
    Ok(TaskChangeSet {
        expected_task_version: req.input.expected_task_version,
        task,
        runs: vec![run],
        run_expected_versions: [
            // The retry Run is the only Run this change set writes, and
            // it is an INSERT, so it must be named with
            // NO_EXISTING_VERSION — exactly as submit_task and
            // rerun_cancelled_task name the Run they create.
            //
            // Naming only the failed Run here (which this change set
            // deliberately does NOT write: it is preserved as evidence)
            // made every real Retry impossible to commit upstream. The
            // persistence contract requires an expected version for
            // every Run in the change set and reads it to choose
            // insert-vs-update, so the store rejected the change set
            // outright with "missing run expected version".
            (run_id, NO_EXISTING_VERSION),
            // The failed Run's own expected version stays recorded for
            // the optimistic guard this transition already asserted
            // through assert_expected_versions above. The store ignores
            // entries for Runs the change set does not write.
            (failed_run.id, req.input.expected_run_version),
        ]
        .into_iter()
        .collect(),
        events: task_events(
            task_id,
            Some(run_id),
            EventKind::TaskRetryRequested,
            None,
            "failed task retried",
            now,
        ),
    })
}

/// Creates a brand-new Task with explicit lineage to a cancelled
/// source Task, copying its `title` and `input`. Unlike
/// `retry_failed_task` (same Task ID, new Run) this always creates a
/// new Task ID, since a cancelled Task's terminal run is never resumed
/// under the same identity.
pub fn rerun_cancelled_task(req: RerunCancelledTaskRequest) -> Result<TaskChangeSet, Failure> {
    req.source
        .validate_consistency()
        .map_err(|e| Failure::invalid(e.code(), "invalid source aggregate snapshot"))?;
    if req.source.task.status != TaskStatus::Cancelled {
        return Err(Failure::denied(
            codes::INVALID_TRANSITION,
            "rerun requires a cancelled task",
        ));
    }
    if req.source.task.version != req.expected_task_version {
        return Err(Failure::conflict(
            codes::VERSION_CONFLICT,
            "source task version mismatch",
        ));
    }
    if !req.source.task.permission_policy.known() {
        return Err(Failure::invalid(
            codes::INVALID_STATE,
            "source task has no known permission policy: re-read the source task before retrying",
        ));
    }
    req.source.task.budget.validate()?;
    let now = req.now;
    let new_task_id = TaskId::new();
    let run_id = RunId::new();
    let run = Run {
        id: run_id,
        task_id: new_task_id,
        workspace_id: req.source.task.workspace_id,
        version: 0,
        status: RunStatus::Queued,
        index: 1,
        waiting_reason: None,
        failure_reason: String::new(),
        ownership_token: String::new(),
        run_key: None,
        request_fingerprint: None,
        created_at: now,
        updated_at: now,
    };
    let new_task = Task {
        id: new_task_id,
        workspace_id: req.source.task.workspace_id,
        parent_task_id: Some(req.source.task.id),
        version: 0,
        status: TaskStatus::Queued,
        current_run_id: Some(run_id),
        last_run_index: 1,
        retry_count: 0,
        retry_eligible_at: None,
        waiting_reason: None,
        failure_reason: String::new(),
        input: req.source.task.input.clone(),
        title: req.source.task.title.clone(),
        // The policy is copied explicitly (harness phase 3c decision
        // 3): the database default must never apply to a Rerun.
        permission_policy: req.source.task.permission_policy,
        // The budget is copied explicitly too (harness phase 3d
        // decision 2): a Rerun runs under what the operator asked for
        // the source.
        budget: req.source.task.budget,
        created_at: now,
        updated_at: now,
    };
    let new_task = bump_task(new_task, now);
    let run = bump_run(run, now);
    Ok(TaskChangeSet {
        expected_task_version: NO_EXISTING_VERSION,
        run_expected_versions: [(run_id, NO_EXISTING_VERSION)].into_iter().collect(),
        task: new_task,
        runs: vec![run],
        events: task_events(
            new_task_id,
            Some(run_id),
            EventKind::TaskSubmitted,
            None,
            format!("rerun of cancelled task {}", req.source.task.id),
            now,
        ),
    })
}

// ---------------------------------------------------------------------------
// Tests — port of internal/task/{domain_test, cancel_unclaimed_test,
// budget_test, permission_policy_test, resume_reconciled_test}.go.
// `errors.As(Failure).Class` assertions map onto `Failure::kind()`;
// `errors.Is(Err…)` assertions map onto `Failure::code()`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::failure::FailureKind;
    use central_foundation::identity::WorkspaceId;
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-07-23 12:00 UTC);

    fn submit_req(now: OffsetDateTime) -> SubmitTaskRequest {
        SubmitTaskRequest {
            workspace_id: WorkspaceId::new(),
            title: "sample task".to_string(),
            input: "input.yaml".to_string(),
            permission_policy: None,
            budget: Budget::default(),
            run_key: None,
            now,
        }
    }

    fn mutation(agg: TaskAggregate, now: OffsetDateTime) -> MutationInput {
        let mut input = MutationInput {
            aggregate: agg,
            expected_task_version: 0,
            expected_run_version: 0,
            now,
        };
        input.expected_task_version = input.aggregate.task.version;
        if let Some(run) = &input.aggregate.current_run {
            input.expected_run_version = run.version;
        }
        input
    }

    fn apply(cs: &TaskChangeSet) -> TaskAggregate {
        TaskAggregate {
            task: cs.task.clone(),
            current_run: cs.runs.first().cloned(),
        }
    }

    /// `queuedAggregate` — submit only.
    fn queued_aggregate() -> TaskAggregate {
        let cs = submit_task(submit_req(T0)).unwrap();
        apply(&cs)
    }

    /// `runningAggregate` — submit → claim("executor").
    fn running_aggregate() -> TaskAggregate {
        let agg = queued_aggregate();
        let cs = claim_current_run(ClaimCurrentRunRequest {
            input: mutation(agg, T0 + time::Duration::seconds(1)),
            owner: "executor".to_string(),
        })
        .unwrap();
        apply(&cs)
    }

    /// `cancellingAggregate` — running → request_cancellation.
    fn cancelling_aggregate() -> TaskAggregate {
        let agg = running_aggregate();
        let cs = request_cancellation(RequestCancellationRequest {
            input: mutation(agg, T0 + time::Duration::seconds(2)),
        })
        .unwrap();
        apply(&cs)
    }

    /// `cancelledAggregateFixture` — cancelling → settle.
    fn cancelled_aggregate() -> TaskAggregate {
        let agg = cancelling_aggregate();
        let cs = settle_cancellation(SettleCancellationRequest {
            input: mutation(agg, T0 + time::Duration::seconds(3)),
        })
        .unwrap();
        apply(&cs)
    }

    /// `waitingAggregate` — running → wait(reason).
    fn waiting_aggregate(reason: WaitingReason) -> TaskAggregate {
        let agg = running_aggregate();
        let cs = wait_task(WaitTaskRequest {
            input: mutation(agg, T0 + time::Duration::seconds(2)),
            reason: Some(reason),
            detail: "waiting".to_string(),
        })
        .unwrap();
        apply(&cs)
    }

    /// `reconciliationAggregate` — a claimed run waiting on
    /// reconciliation, with the fields `resume_reconciled_run` must
    /// leave untouched set to non-zero values.
    fn reconciliation_aggregate() -> TaskAggregate {
        let mut agg = waiting_aggregate(WaitingReason::Reconciliation);
        agg.task.retry_eligible_at = Some(datetime!(2026-07-28 0:00 UTC));
        agg.task.failure_reason = "previous failure".to_string();
        if let Some(run) = &mut agg.current_run {
            run.failure_reason = "previous run failure".to_string();
        }
        agg
    }

    fn resume_reconciled_request(
        a: &TaskAggregate,
        now: OffsetDateTime,
    ) -> ResumeReconciledRunRequest {
        ResumeReconciledRunRequest {
            input: mutation(a.clone(), now),
        }
    }

    // -- domain_test.go ------------------------------------------------------

    #[test]
    fn submit_task_creates_canonical_queued_run() {
        let got = submit_task(submit_req(T0)).unwrap();
        assert_eq!(got.task.status, TaskStatus::Queued);
        assert!(got.task.current_run_id.is_some());
        assert_eq!(got.task.version, 1);
        assert_eq!(got.runs.len(), 1);
        assert_eq!(got.runs[0].status, RunStatus::Queued);
        assert_eq!(got.task.id, got.runs[0].task_id);
        assert_eq!(got.runs[0].version, 1);
        assert_eq!(got.task.last_run_index, 1);
    }

    #[test]
    fn claim_current_run_success() {
        let created = submit_task(submit_req(T0)).unwrap();
        let run = created.runs[0].clone();
        let got = claim_current_run(ClaimCurrentRunRequest {
            input: MutationInput {
                aggregate: TaskAggregate {
                    task: created.task.clone(),
                    current_run: Some(run.clone()),
                },
                expected_task_version: created.task.version,
                expected_run_version: run.version,
                now: T0 + time::Duration::seconds(1),
            },
            owner: "worker-1".to_string(),
        })
        .unwrap();
        assert_eq!(got.task.status, TaskStatus::Running);
        assert_eq!(got.runs[0].status, RunStatus::Running);
        assert_eq!(got.runs[0].ownership_token, "worker-1");
    }

    #[test]
    fn wait_requires_reason_and_running_task() {
        let claimed = running_aggregate();
        let err = wait_task(WaitTaskRequest {
            input: mutation(claimed, T0 + time::Duration::seconds(2)),
            reason: None,
            detail: String::new(),
        })
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
    }

    #[test]
    fn queued_to_completed_without_running_run_rejected() {
        let agg = queued_aggregate();
        let err = complete_task(CompleteTaskRequest {
            input: mutation(agg, T0 + time::Duration::seconds(1)),
        })
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Denied);
    }

    #[test]
    fn waiting_state_allows_retry_delay_reason() {
        let claimed = running_aggregate();
        // A retry-delay wait keeps the current run attached.
        wait_task(WaitTaskRequest {
            input: mutation(claimed, T0 + time::Duration::seconds(2)),
            reason: Some(WaitingReason::RetryDelay),
            detail: "retry schedule".to_string(),
        })
        .unwrap();
    }

    #[test]
    fn resume_same_run_rejects_retry_delay() {
        let claimed = running_aggregate();
        let retry = schedule_run_retry(ScheduleRunRetryRequest {
            input: mutation(claimed, T0 + time::Duration::seconds(2)),
            failure_note: "network error".to_string(),
            retry_at: Some(T0 + time::Duration::minutes(1)),
            reason: Some(WaitingReason::RetryDelay),
        })
        .unwrap();
        // The retry-delay wait carries no current run.
        let agg = TaskAggregate {
            task: retry.task,
            current_run: None,
        };
        let mut input = mutation(agg, T0 + time::Duration::seconds(3));
        input.expected_run_version = 0;
        let err = resume_same_run(ResumeSameRunRequest { input }).unwrap_err();
        assert_eq!(err.kind(), FailureKind::Denied);
        assert!(!err.message().is_empty());
    }

    #[test]
    fn rerun_creates_new_task_with_lineage_and_copies_fields() {
        let source = cancelled_aggregate();
        let cs = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0 + time::Duration::seconds(4),
        })
        .unwrap();
        assert_ne!(cs.task.id, source.task.id);
        assert_eq!(cs.task.parent_task_id, Some(source.task.id));
        assert_eq!(cs.task.status, TaskStatus::Queued);
        assert_eq!(cs.task.title, source.task.title);
        assert_eq!(cs.task.input, source.task.input);
        assert_eq!(cs.expected_task_version, NO_EXISTING_VERSION);
        assert_eq!(cs.runs.len(), 1);
        assert_eq!(cs.runs[0].status, RunStatus::Queued);
    }

    #[test]
    fn rerun_rejects_non_cancelled_source() {
        let source = running_aggregate();
        let err = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0,
        })
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Denied);
    }

    #[test]
    fn submit_request_fingerprint_is_deterministic() {
        let req = SubmitTaskRequest {
            workspace_id: WorkspaceId::new(),
            title: "demo".to_string(),
            input: r#"{"a":1}"#.to_string(),
            run_key: Some("k1".to_string()),
            ..submit_req(T0)
        };
        let a = submit_request_fingerprint(&req);
        let b = submit_request_fingerprint(&req);
        assert_eq!(a, b);
        let changed = SubmitTaskRequest {
            title: "other".to_string(),
            ..req.clone()
        };
        assert_ne!(a, submit_request_fingerprint(&changed));
    }

    /// Byte-parity vector: SHA-256 over the canonical JSON encoding Go
    /// produces for `{Title:"demo", Input:{"a":1}, RunKey:"k1"}` with a
    /// zero workspace and unset policy/budget.
    #[test]
    fn submit_request_fingerprint_matches_go_encoding() {
        let req = SubmitTaskRequest {
            workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
            title: "demo".to_string(),
            input: r#"{"a":1}"#.to_string(),
            run_key: Some("k1".to_string()),
            ..submit_req(T0)
        };
        assert_eq!(submit_request_fingerprint(&req), GO_SUBMIT_FINGERPRINT_K1);
    }

    /// Byte-parity vector for HTML-unsafe input: Go's `json.Marshal`
    /// escapes `<`, `>`, `&`, U+2028 and U+2029 as `\u…` inside strings
    /// where `serde_json` emits the raw bytes. The expected digest is
    /// computed in-test over the hand-written Go-escaped canonical JSON
    /// — verified against real `json.Marshal` output, which hashes to
    /// `30876583823c59cc754b1525297689538898923f081c3ec1c13c8f80d7020514`.
    #[test]
    fn submit_request_fingerprint_escapes_html_unsafe_bytes_like_go() {
        let req = SubmitTaskRequest {
            workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
            title: "a<b>&c\u{2028}d\u{2029}".to_string(),
            input: r#"{"a":1}"#.to_string(),
            run_key: Some("k1".to_string()),
            ..submit_req(T0)
        };
        let canonical = concat!(
            r#"{"workspace_id":"00000000-0000-0000-0000-000000000000","#,
            r#""run_key":"k1","#,
            r#""title":"a\u003cb\u003e\u0026c\u2028d\u2029","#,
            r#""input":"{\"a\":1}","#,
            r#""permission_policy":"","#,
            r#""budget":{"CostMicroUSD":0,"WallClockSeconds":0}}"#,
        );
        let expected: [u8; 32] = sha2::Sha256::digest(canonical.as_bytes()).into();
        assert_eq!(submit_request_fingerprint(&req), expected);
    }

    /// `sha256("{"workspace_id":"00000000-0000-0000-0000-000000000000","run_key":"k1","title":"demo","input":"{\"a\":1}","permission_policy":"","budget":{"CostMicroUSD":0,"WallClockSeconds":0}}")`
    const GO_SUBMIT_FINGERPRINT_K1: [u8; 32] = [
        0x82, 0x7a, 0x09, 0x98, 0xdb, 0x94, 0xf0, 0xdb, 0xca, 0xae, 0xeb, 0xf6, 0x98, 0x4b, 0xaa,
        0x99, 0x16, 0x4d, 0xd7, 0x1f, 0xdf, 0x6e, 0x2b, 0x49, 0xb6, 0x71, 0xb6, 0x94, 0x96, 0xf7,
        0x3e, 0x21,
    ];

    // -- cancel_unclaimed_test.go --------------------------------------------

    const CANCEL_NOW: OffsetDateTime = datetime!(2026-09-29 12:00 UTC);

    fn cu_queued() -> TaskAggregate {
        let cs = submit_task(SubmitTaskRequest {
            title: "t".to_string(),
            input: "in".to_string(),
            ..submit_req(CANCEL_NOW)
        })
        .unwrap();
        apply(&cs)
    }

    fn cu_mutation(agg: TaskAggregate) -> MutationInput {
        mutation(agg, CANCEL_NOW + time::Duration::minutes(1))
    }

    fn cu_claimed() -> TaskAggregate {
        let agg = cu_queued();
        let cs = claim_current_run(ClaimCurrentRunRequest {
            input: cu_mutation(agg),
            owner: "worker".to_string(),
        })
        .unwrap();
        apply(&cs)
    }

    fn cu_cancelling(agg: TaskAggregate) -> TaskAggregate {
        let cs = request_cancellation(RequestCancellationRequest {
            input: cu_mutation(agg),
        })
        .unwrap();
        apply(&cs)
    }

    #[test]
    fn cancel_unclaimed_ends_task_cancelled_in_one_change_set() {
        for (name, agg, want_kinds) in [
            (
                "queued",
                cu_queued(),
                vec![EventKind::TaskCancelRequested, EventKind::TaskCancelled],
            ),
            (
                "cancelling",
                cu_cancelling(cu_queued()),
                vec![EventKind::TaskCancelled],
            ),
        ] {
            assert!(agg.unclaimed(), "{name}: unclaimed = false");
            let cs = cancel_unclaimed_task(CancelUnclaimedTaskRequest {
                input: cu_mutation(agg.clone()),
            })
            .unwrap();
            let before_run = agg.current_run.unwrap();
            assert_eq!(cs.task.status, TaskStatus::Cancelled, "{name}");
            assert_eq!(cs.task.version, agg.task.version + 1, "{name}");
            assert_eq!(cs.task.waiting_reason, None, "{name}");
            assert_eq!(cs.runs.len(), 1, "{name}");
            assert_eq!(cs.runs[0].status, RunStatus::Cancelled, "{name}");
            assert_eq!(cs.runs[0].version, before_run.version + 1, "{name}");
            assert_eq!(cs.runs[0].id, before_run.id, "{name}");
            assert_eq!(cs.expected_task_version, agg.task.version, "{name}");
            assert_eq!(
                cs.run_expected_versions.get(&before_run.id),
                Some(&before_run.version),
                "{name}"
            );
            assert_eq!(cs.events.len(), want_kinds.len(), "{name}");
            for (i, kind) in want_kinds.iter().enumerate() {
                assert_eq!(cs.events[i].kind, *kind, "{name} event {i}");
                assert_eq!(cs.events[i].run_id, Some(before_run.id), "{name} event {i}");
                assert_eq!(cs.events[i].task_id, agg.task.id, "{name} event {i}");
            }
            // The result is a consistent terminal aggregate.
            apply(&cs).validate_consistency().unwrap();
        }
    }

    /// A claim must record a non-blank owner token: `unclaimed` reads
    /// an empty token as "never claimed", so an ownerless claim
    /// followed by a resume would make a claimed run look unclaimed.
    #[test]
    fn claim_current_run_refuses_a_blank_owner() {
        for owner in ["", " \t\n"] {
            let agg = cu_queued();
            let err = claim_current_run(ClaimCurrentRunRequest {
                input: cu_mutation(agg),
                owner: owner.to_string(),
            })
            .unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "owner {owner:?}");
        }
    }

    #[test]
    fn cancel_unclaimed_refuses_every_other_task() {
        let waiting = || -> TaskAggregate {
            let cs = wait_task(WaitTaskRequest {
                input: cu_mutation(cu_claimed()),
                reason: Some(WaitingReason::Reconciliation),
                detail: String::new(),
            })
            .unwrap();
            apply(&cs)
        };
        let cases: Vec<(&str, TaskAggregate, FailureKind, bool)> = vec![
            ("running", cu_claimed(), FailureKind::Denied, true),
            ("waiting", waiting(), FailureKind::Denied, true),
            (
                "cancelling after a claim",
                cu_cancelling(cu_claimed()),
                FailureKind::Denied,
                true,
            ),
            (
                "queued again after a claim",
                apply(
                    &resume_same_run(ResumeSameRunRequest {
                        input: cu_mutation(waiting()),
                    })
                    .unwrap(),
                ),
                FailureKind::Denied,
                true,
            ),
            (
                "cancelled",
                apply(
                    &cancel_unclaimed_task(CancelUnclaimedTaskRequest {
                        input: cu_mutation(cu_queued()),
                    })
                    .unwrap(),
                ),
                FailureKind::Denied,
                true,
            ),
            (
                "failed",
                apply(
                    &fail_task(FailTaskRequest {
                        input: cu_mutation(cu_claimed()),
                        reason: "execution_failed".to_string(),
                    })
                    .unwrap(),
                ),
                FailureKind::Denied,
                true,
            ),
            (
                "completed",
                apply(
                    &complete_task(CompleteTaskRequest {
                        input: cu_mutation(cu_claimed()),
                    })
                    .unwrap(),
                ),
                FailureKind::Denied,
                true,
            ),
            {
                let cs = schedule_run_retry(ScheduleRunRetryRequest {
                    input: cu_mutation(cu_claimed()),
                    reason: Some(WaitingReason::RetryDelay),
                    retry_at: None,
                    failure_note: String::new(),
                })
                .unwrap();
                let agg = TaskAggregate {
                    task: cs.task,
                    current_run: None,
                };
                agg.validate_consistency().unwrap();
                assert!(agg.task.current_run_id.is_none());
                (
                    "waiting for a retry delay without a current run",
                    agg,
                    FailureKind::Denied,
                    true,
                )
            },
            {
                let mut agg = cu_queued();
                let mut run = agg.current_run.clone().unwrap();
                run.id = RunId::new();
                agg.current_run = Some(run);
                ("mismatched aggregate", agg, FailureKind::Invalid, false)
            },
        ];
        for (name, agg, class, want_invalid_transition) in cases {
            assert!(!agg.unclaimed(), "{name}: unclaimed = true");
            let err = cancel_unclaimed_task(CancelUnclaimedTaskRequest {
                input: cu_mutation(agg),
            })
            .unwrap_err();
            assert_eq!(err.kind(), class, "{name}");
            if want_invalid_transition {
                assert_eq!(err.code(), codes::INVALID_TRANSITION, "{name}");
            }
        }
    }

    #[test]
    fn cancel_unclaimed_checks_expected_versions() {
        let agg = cu_queued();
        let mut input = cu_mutation(agg.clone());
        input.expected_task_version += 1;
        let err = cancel_unclaimed_task(CancelUnclaimedTaskRequest { input }).unwrap_err();
        assert_eq!(err.code(), codes::VERSION_CONFLICT);

        let mut input = cu_mutation(agg);
        input.expected_run_version += 1;
        let err = cancel_unclaimed_task(CancelUnclaimedTaskRequest { input }).unwrap_err();
        assert_eq!(err.code(), codes::VERSION_CONFLICT);
    }

    /// `request_cancellation` is unchanged: a queued task still becomes
    /// cancelling.
    #[test]
    fn request_cancellation_of_queued_task_still_only_requests() {
        let agg = cu_cancelling(cu_queued());
        assert_eq!(agg.task.status, TaskStatus::Cancelling);
        assert_eq!(agg.current_run.unwrap().status, RunStatus::Cancelling);
    }

    // -- budget_test.go ------------------------------------------------------

    #[test]
    fn budget_validate_accepts_unset_and_in_range_bounds() {
        for b in [
            Budget::default(),
            Budget {
                cost_micro_usd: MIN_BUDGET_COST_MICRO_USD,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: MAX_BUDGET_COST_MICRO_USD,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: MIN_BUDGET_WALL_CLOCK_SECONDS,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: MAX_BUDGET_WALL_CLOCK_SECONDS,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: 2_500_000,
                wall_clock_seconds: 120,
            },
        ] {
            b.validate().unwrap();
        }
        assert_eq!(MIN_BUDGET_COST_MICRO_USD, 10_000);
        assert_eq!(MAX_BUDGET_COST_MICRO_USD, 1_000_000_000);
        assert_eq!(MIN_BUDGET_WALL_CLOCK_SECONDS, 60);
        assert_eq!(MAX_BUDGET_WALL_CLOCK_SECONDS, 86_400);
    }

    #[test]
    fn budget_validate_refuses_out_of_range_bounds() {
        for b in [
            Budget {
                cost_micro_usd: MIN_BUDGET_COST_MICRO_USD - 1,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: MAX_BUDGET_COST_MICRO_USD + 1,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: -1,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: MIN_BUDGET_WALL_CLOCK_SECONDS - 1,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: MAX_BUDGET_WALL_CLOCK_SECONDS + 1,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: -60,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: 2_500_000,
                wall_clock_seconds: 1,
            },
        ] {
            let err = b.validate().unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{b:?}");
        }
    }

    #[test]
    fn submit_records_the_requested_budget() {
        for b in [
            Budget::default(),
            Budget {
                cost_micro_usd: 500_000,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: 120,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: 2_500_000,
                wall_clock_seconds: 3600,
            },
        ] {
            let cs = submit_task(SubmitTaskRequest {
                title: "t".to_string(),
                input: "i".to_string(),
                budget: b,
                ..submit_req(T0)
            })
            .unwrap();
            assert_eq!(cs.task.budget, b);
        }
    }

    #[test]
    fn submit_rejects_an_out_of_range_budget() {
        for b in [
            Budget {
                cost_micro_usd: 9_999,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: 59,
                ..Budget::default()
            },
            Budget {
                wall_clock_seconds: 86_401,
                ..Budget::default()
            },
        ] {
            let err = submit_task(SubmitTaskRequest {
                title: "t".to_string(),
                input: "i".to_string(),
                budget: b,
                ..submit_req(T0)
            })
            .unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{b:?}");
        }
    }

    /// `bridgeCancelledAggregate` — a cancelled task submitted with
    /// bridge.
    fn bridge_cancelled_aggregate() -> TaskAggregate {
        let now = CANCEL_NOW;
        let cs = submit_task(SubmitTaskRequest {
            title: "t".to_string(),
            input: "i".to_string(),
            permission_policy: Some(PermissionPolicy::Bridge),
            ..submit_req(now)
        })
        .unwrap();
        let mut agg = apply(&cs);
        let cs = request_cancellation(RequestCancellationRequest {
            input: mutation(agg.clone(), now + time::Duration::seconds(1)),
        })
        .unwrap();
        agg = apply(&cs);
        let cs = settle_cancellation(SettleCancellationRequest {
            input: mutation(agg.clone(), now + time::Duration::seconds(2)),
        })
        .unwrap();
        apply(&cs)
    }

    #[test]
    fn rerun_copies_the_budget() {
        let mut source = bridge_cancelled_aggregate();
        source.task.budget = Budget {
            cost_micro_usd: 750_000,
            wall_clock_seconds: 900,
        };
        let cs = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0,
        })
        .unwrap();
        assert_eq!(cs.task.budget, source.task.budget);

        source.task.budget = Budget::default();
        let cs = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0,
        })
        .unwrap();
        assert!(cs.task.budget.is_zero());
    }

    #[test]
    fn rerun_refuses_a_source_with_an_out_of_range_budget() {
        let mut source = bridge_cancelled_aggregate();
        source.task.budget = Budget {
            cost_micro_usd: 1,
            ..Budget::default()
        };
        let err = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0,
        })
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
    }

    #[test]
    fn retry_keeps_the_budget() {
        let now = CANCEL_NOW;
        let want = Budget {
            cost_micro_usd: 1_000_000,
            wall_clock_seconds: 600,
        };
        let cs = submit_task(SubmitTaskRequest {
            title: "t".to_string(),
            input: "i".to_string(),
            budget: want,
            ..submit_req(now)
        })
        .unwrap();
        let mut agg = apply(&cs);
        let claimed = claim_current_run(ClaimCurrentRunRequest {
            input: mutation(agg.clone(), now + time::Duration::seconds(1)),
            owner: "w".to_string(),
        })
        .unwrap();
        agg = apply(&claimed);
        let failed = fail_task(FailTaskRequest {
            input: mutation(agg.clone(), now + time::Duration::seconds(2)),
            reason: "execution_failed".to_string(),
        })
        .unwrap();
        agg = apply(&failed);
        let retried = retry_failed_task(RetryFailedTaskRequest {
            input: mutation(agg, now + time::Duration::seconds(3)),
        })
        .unwrap();
        for (name, got) in [
            ("claim", claimed.task.budget),
            ("fail", failed.task.budget),
            ("retry", retried.task.budget),
        ] {
            assert_eq!(got, want, "{name} changed the budget");
        }
    }

    /// The one dollar parser behind both the serve default
    /// (`CENTRAL_HARNESS_MAX_COST_USD`) and the submit form: a plain
    /// decimal of 1 to 7 dollar digits and at most two decimals,
    /// converted to micro-USD exactly. It checks the shape only; each
    /// caller keeps its own range.
    #[test]
    fn parse_budget_cost_usd_shape() {
        for (raw, want) in [
            ("0", 0),
            ("0.00", 0),
            ("0.01", 10_000),
            ("0.5", 500_000),
            ("0.50", 500_000),
            ("2.5", 2_500_000),
            ("2.50", 2_500_000),
            ("5", 5_000_000),
            ("123.45", 123_450_000),
            ("1000", 1_000_000_000),
            ("1000.01", 1_000_010_000),
            ("007", 7_000_000),
            ("00.50", 500_000),
            ("0000000.01", 10_000),
            ("9999999", 9_999_999_000_000),
            ("9999999.99", 9_999_999_990_000),
        ] {
            assert_eq!(parse_budget_cost_usd(raw), Some(want), "{raw}");
        }
        for raw in [
            "",
            "5.",
            ".5",
            "1.234",
            "0.001",
            "-1",
            "+1",
            "-0.50",
            "1e3",
            "1E3",
            "0x10",
            " 5",
            "5 ",
            "5\n",
            "\n5",
            "5\t",
            "1,5",
            "1_000",
            "$5",
            "five",
            "5.0.0",
            "99999999",
            "10000000.00",
            "9223372036854775807",
        ] {
            assert_eq!(parse_budget_cost_usd(raw), None, "{raw}");
        }
    }

    // -- permission_policy_test.go -------------------------------------------

    #[test]
    fn permission_policies_are_closed() {
        let want = [
            PermissionPolicy::Deny,
            PermissionPolicy::Bridge,
            PermissionPolicy::AutoAllow,
        ];
        assert_eq!(PERMISSION_POLICIES, want);
        for p in want {
            assert!(p.known(), "{p} is not known");
            assert_eq!(PermissionPolicy::parse(p.as_str()), p);
        }
        for raw in ["", "Deny", "allow", "auto-allow", "bridge "] {
            assert!(!PermissionPolicy::parse(raw).known(), "{raw} is known");
        }
    }

    #[test]
    fn submit_defaults_the_permission_policy_to_deny() {
        let cs = submit_task(SubmitTaskRequest {
            title: "t".to_string(),
            input: "i".to_string(),
            ..submit_req(T0)
        })
        .unwrap();
        assert_eq!(cs.task.permission_policy, PermissionPolicy::Deny);
    }

    #[test]
    fn submit_records_an_explicit_permission_policy() {
        for policy in PERMISSION_POLICIES {
            let cs = submit_task(SubmitTaskRequest {
                title: "t".to_string(),
                input: "i".to_string(),
                permission_policy: Some(policy),
                ..submit_req(T0)
            })
            .unwrap();
            assert_eq!(cs.task.permission_policy, policy);
        }
    }

    #[test]
    fn submit_rejects_an_unknown_permission_policy() {
        for raw in ["allow_all", "Bridge", " deny"] {
            let err = submit_task(SubmitTaskRequest {
                title: "t".to_string(),
                input: "i".to_string(),
                permission_policy: Some(PermissionPolicy::parse(raw)),
                ..submit_req(T0)
            })
            .unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{raw}");
        }
    }

    #[test]
    fn rerun_copies_the_permission_policy() {
        let source = bridge_cancelled_aggregate();
        assert_eq!(source.task.permission_policy, PermissionPolicy::Bridge);
        let cs = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0,
        })
        .unwrap();
        assert_eq!(cs.task.permission_policy, PermissionPolicy::Bridge);
    }

    #[test]
    fn rerun_refuses_a_source_without_a_known_policy() {
        let mut source = bridge_cancelled_aggregate();
        source.task.permission_policy = PermissionPolicy::Unknown;
        let err = rerun_cancelled_task(RerunCancelledTaskRequest {
            source: source.clone(),
            expected_task_version: source.task.version,
            now: T0,
        })
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
    }

    #[test]
    fn retry_keeps_the_permission_policy() {
        let now = CANCEL_NOW;
        let cs = submit_task(SubmitTaskRequest {
            title: "t".to_string(),
            input: "i".to_string(),
            permission_policy: Some(PermissionPolicy::AutoAllow),
            ..submit_req(now)
        })
        .unwrap();
        let mut agg = apply(&cs);
        let claimed = claim_current_run(ClaimCurrentRunRequest {
            input: mutation(agg.clone(), now + time::Duration::seconds(1)),
            owner: "w".to_string(),
        })
        .unwrap();
        agg = apply(&claimed);
        let failed = fail_task(FailTaskRequest {
            input: mutation(agg.clone(), now + time::Duration::seconds(2)),
            reason: "execution_failed".to_string(),
        })
        .unwrap();
        agg = apply(&failed);
        let retried = retry_failed_task(RetryFailedTaskRequest {
            input: mutation(agg, now + time::Duration::seconds(3)),
        })
        .unwrap();
        for (name, got) in [
            ("claim", claimed.task.permission_policy),
            ("fail", failed.task.permission_policy),
            ("retry", retried.task.permission_policy),
        ] {
            assert_eq!(
                got,
                PermissionPolicy::AutoAllow,
                "{name} changed the policy"
            );
        }
    }

    // -- resume_reconciled_test.go -------------------------------------------

    #[test]
    fn resume_reconciled_moves_waiting_task_and_run_to_running() {
        let before = reconciliation_aggregate();
        let now = datetime!(2026-07-27 13:00 UTC);
        let before_run = before.current_run.clone().unwrap();

        let change = resume_reconciled_run(resume_reconciled_request(&before, now)).unwrap();
        assert_eq!(change.task.status, TaskStatus::Running);
        assert_eq!(change.task.waiting_reason, None);
        assert_eq!(change.runs.len(), 1);
        let run = &change.runs[0];
        assert_eq!(run.status, RunStatus::Running);
        assert_eq!(run.waiting_reason, None);
        assert_eq!(run.id, before_run.id);
        assert_eq!(change.task.current_run_id, before.task.current_run_id);
        assert!(!run.ownership_token.is_empty());
        assert_eq!(run.ownership_token, before_run.ownership_token);
        assert_eq!(change.task.version, before.task.version + 1);
        assert_eq!(run.version, before_run.version + 1);
        assert_eq!(change.task.updated_at, now);
        assert_eq!(run.updated_at, now);
        // Untouched fields.
        assert_eq!(change.task.retry_eligible_at, before.task.retry_eligible_at);
        assert_eq!(change.task.failure_reason, before.task.failure_reason);
        assert_eq!(change.task.last_run_index, before.task.last_run_index);
        assert_eq!(run.failure_reason, before_run.failure_reason);
        assert_eq!(run.index, before_run.index);
        assert_eq!(change.expected_task_version, before.task.version);
        assert_eq!(
            change.run_expected_versions.get(&run.id),
            Some(&before_run.version)
        );
        assert_eq!(change.events.len(), 2);
        let (first, second) = (&change.events[0], &change.events[1]);
        assert_eq!(first.kind, EventKind::TaskResumed);
        assert_eq!(first.detail, "resume reconciled attempt");
        assert_eq!(first.run_id, Some(run.id));
        assert_eq!(second.kind, EventKind::RunTransition);
        assert_eq!(second.detail, "run_resumed");
        assert_eq!(second.run_id, Some(run.id));
        for ev in &change.events {
            assert_eq!(ev.task_id, before.task.id);
            assert_eq!(ev.occurred_at, now);
        }
    }

    #[test]
    fn resume_reconciled_refuses_everything_else() {
        let now = datetime!(2026-07-27 13:00 UTC);
        let mut never_claimed = reconciliation_aggregate();
        if let Some(run) = &mut never_claimed.current_run {
            run.ownership_token = String::new();
        }
        for (name, agg) in [
            (
                "waiting approval",
                waiting_aggregate(WaitingReason::Approval),
            ),
            (
                "waiting external input",
                waiting_aggregate(WaitingReason::ExternalInput),
            ),
            ("running", running_aggregate()),
            ("cancelling", cancelling_aggregate()),
            ("queued", queued_aggregate()),
            ("never claimed", never_claimed),
        ] {
            let err = resume_reconciled_run(resume_reconciled_request(&agg, now)).unwrap_err();
            assert_eq!(err.kind(), FailureKind::Denied, "{name}");
            assert_eq!(err.code(), codes::INVALID_TRANSITION, "{name}");
        }

        for (name, bump_task_version, bump_run_version) in [
            ("stale task version", true, false),
            ("stale run version", false, true),
        ] {
            let mut req = resume_reconciled_request(&reconciliation_aggregate(), now);
            if bump_task_version {
                req.input.expected_task_version += 1;
            }
            if bump_run_version {
                req.input.expected_run_version += 1;
            }
            let err = resume_reconciled_run(req).unwrap_err();
            assert_eq!(err.code(), codes::VERSION_CONFLICT, "{name}");
        }
    }

    #[test]
    fn run_waiting_may_resume_running() {
        assert!(RunStatus::Waiting.can_transition(RunStatus::Running));
        assert!(RunStatus::Waiting.can_transition(RunStatus::Queued));
    }
}
