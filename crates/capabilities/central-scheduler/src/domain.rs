//! Scheduler domain — pure synchronous port of
//! `central/internal/scheduler/domain.go` (Phase-2 Slice 2B, b35).
//!
//! Owns the session-attempt state machine, the worker registration row
//! and its missed-beat ladder, the fencing lease record, capability
//! matching, registration refusal, the expiry-outcome split, and the
//! scheduler-domain [`Failure`] taxonomy. Migration b35 pins the same
//! vocabularies in `session_attempts_state_check`,
//! `worker_registrations_state_check`, and the two live-row partial
//! indexes — the tests below keep the two sides in step.
//!
//! It contains no persistence, transport, or adapter types: every
//! timestamp arrives as caller-supplied durable evidence and this module
//! never reads a clock.
//!
//! OWNING PACKET: P2B03/P2B04/P2B05. SLICE: 2B.

use std::fmt;

use central_foundation::failure::{Failure as FoundationFailure, FailureKind};
use central_foundation::identity::{
    HarnessAttemptId, NodeLeaseId, RunId, SessionAttemptId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use time::{Duration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Session-attempt state machine
// ---------------------------------------------------------------------------

/// The state of one session attempt inside the
/// `claimed → provisioning → started → succeeded|failed` machine with
/// the ambiguous and cancelled branches spec-2 declares. Migration b35
/// pins the same vocabulary in `session_attempts_state_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttemptState {
    /// `claimed` — the claim transaction allocated the attempt row and
    /// its lease but dispatch has not started preparing.
    Claimed,
    /// `provisioning` — dispatch is preparing the workspace and
    /// invoking the launcher.
    Provisioning,
    /// `started` — the harness session is live: `started_at` is set, so
    /// an interrupted outcome is unknowable and goes ambiguous.
    Started,
    /// `succeeded` — the terminal success state.
    Succeeded,
    /// `failed` — the terminal failure state of this attempt row; the
    /// node may still return to `ready` as a new `attempt_seq`.
    Failed,
    /// `ambiguous` — parks an attempt whose outcome is unknown for an
    /// operator decision; it is NOT terminal and never auto-relaunches.
    Ambiguous,
    /// `cancelled` — the terminal cancelled state.
    Cancelled,
}

impl AttemptState {
    /// Every state in declaration order. The set must equal migration
    /// b35's `session_attempts_state_check` list.
    pub const ALL: [Self; 7] = [
        Self::Claimed,
        Self::Provisioning,
        Self::Started,
        Self::Succeeded,
        Self::Failed,
        Self::Ambiguous,
        Self::Cancelled,
    ];

    /// The persisted/journaled text form (upstream `String()`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Provisioning => "provisioning",
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Ambiguous => "ambiguous",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the persisted text form; `None` on anything outside the
    /// declared vocabulary.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|state| state.as_str() == s)
    }

    /// Whether the state is terminal for an attempt (upstream
    /// `IsTerminal`): `succeeded`, `failed` and `cancelled` admit no
    /// transition. `ambiguous` is deliberately NON-terminal — it parks
    /// for an operator decision.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    /// Whether the state holds the node against a new claim (upstream
    /// `Live`): b35's `session_attempts_live_node_idx` pins `claimed`,
    /// `provisioning` and `started` as the states under which at most
    /// one attempt per node may exist. `ambiguous` is NOT live — an
    /// operator rerun allocates a fresh `(node_id, attempt_seq)` row
    /// while the old attempt stays ambiguous; counting it live would
    /// wedge every rerun on the index.
    #[must_use]
    pub const fn live(self) -> bool {
        matches!(self, Self::Claimed | Self::Provisioning | Self::Started)
    }

    /// The legal forward transitions for an attempt state per the
    /// spec-2 protocol (upstream `ValidTransitions`): a claimed attempt
    /// provisions, fails pre-start (e.g. `LEASE_EXPIRED_NOT_STARTED`),
    /// or releases on clean worker shutdown
    /// (`WORKER_SHUTDOWN_LEASE_RELEASED`); a provisioning attempt
    /// starts, fails definitely, or parks ambiguous on unknown outcome;
    /// a started attempt succeeds, fails, or goes ambiguous. An
    /// ambiguous attempt's only exit is operator abandonment — a rerun
    /// is a NEW `attempt_seq` row, never a state change of this one.
    /// Terminal states admit no transition.
    ///
    /// Slice 2D (spec-4 decision 5) adds the timeout-cancel edges: a
    /// provisioning or started attempt whose kill is confirmed — or
    /// that is withdrawn under the workflow deadline — closes
    /// `cancelled` instead of `failed`, because a harness-directed
    /// cancellation is not an observed failure.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [Self] {
        match self {
            Self::Claimed => &[Self::Provisioning, Self::Failed, Self::Cancelled],
            Self::Provisioning => &[
                Self::Started,
                Self::Failed,
                Self::Ambiguous,
                Self::Cancelled,
            ],
            Self::Started => &[
                Self::Succeeded,
                Self::Failed,
                Self::Ambiguous,
                Self::Cancelled,
            ],
            Self::Ambiguous => &[Self::Cancelled],
            _ => &[],
        }
    }

    /// Whether `to` is a legal forward transition (upstream
    /// `CanTransition`).
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        self.valid_transitions().contains(&to)
    }
}

impl fmt::Display for AttemptState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Worker state ladder
// ---------------------------------------------------------------------------

/// A registered worker's position on the missed-beat ladder the
/// Central-internal sweeper walks. Migration b35 pins the same
/// vocabulary in `worker_registrations_state_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WorkerState {
    /// `active` — heartbeats arrive inside the grace window.
    Active,
    /// `suspect` — [`MISSED_BEATS_SUSPECT`] beats were missed;
    /// observable only — it neither revokes leases nor blocks claims.
    Suspect,
    /// `lost` — [`MISSED_BEATS_LOST`] beats were missed; every lease
    /// the worker holds expires in one transaction.
    Lost,
    /// `deregistered` — the worker cleanly shut down; terminal for a
    /// registration row (fresh `worker_id` per process start, OQ-7).
    Deregistered,
}

impl WorkerState {
    /// Every state in declaration order. The set must equal migration
    /// b35's `worker_registrations_state_check` list.
    pub const ALL: [Self; 4] = [Self::Active, Self::Suspect, Self::Lost, Self::Deregistered];

    /// The persisted/journaled text form (upstream `String()`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspect => "suspect",
            Self::Lost => "lost",
            Self::Deregistered => "deregistered",
        }
    }

    /// Parses the persisted text form; `None` on anything outside the
    /// declared vocabulary (upstream `Known` inverted — an unrecognized
    /// persisted string fails the parse instead of producing a state).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|state| state.as_str() == s)
    }
}

impl fmt::Display for WorkerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Locked protocol constants and lease math (spec-2 OQ-5/OQ-6)
// ---------------------------------------------------------------------------

/// The only worker-protocol version Phase 2 accepts; a registering
/// worker speaking anything else is refused
/// `WORKER_REGISTRATION_REJECTED`.
pub const PROTOCOL_VERSION: i32 = 1;
/// The locked renewal cadence in seconds (OQ-5): the worker renews
/// every held lease at this interval.
pub const HEARTBEAT_INTERVAL_SEC: i64 = 15;
/// Sizes `expires_at` as beat + 3× interval (OQ-6). No maximum lease
/// lifetime exists — attempt duration ceilings are spec 4's timeout
/// hierarchy, not the lease's job.
pub const LEASE_TTL_MULTIPLIER: i64 = 3;
/// The ladder's suspect threshold (OQ-5).
pub const MISSED_BEATS_SUSPECT: u32 = 2;
/// The ladder's lost threshold (OQ-5).
pub const MISSED_BEATS_LOST: u32 = 5;

/// The locked renewal cadence (upstream `HeartbeatInterval`).
#[must_use]
pub const fn heartbeat_interval() -> Duration {
    Duration::seconds(HEARTBEAT_INTERVAL_SEC)
}

/// The locked lease lifetime (upstream `LeaseTTL`): 3 × the heartbeat
/// interval, stamped as `expires_at = now + ttl` at issue and renewal.
#[must_use]
pub const fn lease_ttl() -> Duration {
    Duration::seconds(LEASE_TTL_MULTIPLIER * HEARTBEAT_INTERVAL_SEC)
}

/// `floor((now - last_beat) / heartbeat interval)` (upstream
/// `MissedBeats`): the number of heartbeat deadlines `last_beat` has
/// silently passed. Same-host single clock — server-side timestamps are
/// authoritative and beats are evaluated on arrival, so no skew
/// correction exists; a `last_beat` at or after `now` counts as zero
/// missed.
#[must_use]
pub fn missed_beats(now: OffsetDateTime, last_beat: OffsetDateTime) -> u32 {
    let elapsed = now - last_beat;
    if elapsed <= Duration::ZERO {
        return 0;
    }
    let beats = elapsed.whole_seconds() / HEARTBEAT_INTERVAL_SEC;
    u32::try_from(beats).unwrap_or(u32::MAX)
}

/// Maps a missed-beat count to the worker state the sweeper records
/// (upstream `Ladder`): below [`MISSED_BEATS_SUSPECT`] the worker stays
/// active, at `MISSED_BEATS_SUSPECT..MISSED_BEATS_LOST-1` it is suspect
/// (observable only), and at [`MISSED_BEATS_LOST`] it is lost and all
/// its leases expire in one transaction. The ladder never marks a
/// worker deregistered — clean shutdown is the worker's own act.
#[must_use]
pub const fn ladder(missed: u32) -> WorkerState {
    if missed >= MISSED_BEATS_LOST {
        WorkerState::Lost
    } else if missed >= MISSED_BEATS_SUSPECT {
        WorkerState::Suspect
    } else {
        WorkerState::Active
    }
}

// ---------------------------------------------------------------------------
// Durable rows: worker, lease, session attempt
// ---------------------------------------------------------------------------

/// One registered worker process (upstream `Worker`): a fresh
/// `worker_id` per start (OQ-7), the harness and workspace kinds it
/// declares, its concurrency ceiling, and its ladder state. The fields
/// mirror `central.worker_registrations`; `workspace_kinds` uses the
/// v33 schema vocabulary (`'worktree'`/`'directory'`) — the names
/// spec-2 calls code/plain.
///
/// At registration the caller fills identity + capabilities only:
/// `state` is [`WorkerState::Active`], `registered_at`/`last_seen_at`
/// are `None` (the store assigns `registered_at`; `last_seen_at` is the
/// nullable column updated per heartbeat).
#[derive(Debug, Clone, PartialEq)]
pub struct Worker {
    /// The registration identity — fresh per process start.
    pub id: WorkerId,
    /// The workspace the registration is scoped to.
    pub workspace_id: WorkspaceId,
    /// The worker-protocol version the process speaks.
    pub protocol_version: i32,
    /// Declared harness kinds the worker can launch.
    pub harness_kinds: Vec<String>,
    /// Declared workspace kinds the worker can execute in.
    pub workspace_kinds: Vec<String>,
    /// The worker's live-attempt ceiling.
    pub max_concurrent_attempts: i32,
    /// The ladder state.
    pub state: WorkerState,
    /// When the row committed; `None` on a registration input (the
    /// store stamps it).
    pub registered_at: Option<OffsetDateTime>,
    /// The last heartbeat instant; `None` until the first beat (the
    /// column is nullable — a registered-never-beats worker reads as
    /// never seen, matching upstream's zero-time semantics).
    pub last_seen_at: Option<OffsetDateTime>,
}

/// The fencing-lease row of one attempt (upstream `Lease`). At most one
/// lease per node is live at a time (b35's `node_leases_live_node_idx`
/// on `released_at IS NULL`), and every lease-closing path — expiry,
/// worker-lost expiry, shutdown release, terminal release — sets
/// `released_at` in the same transaction, otherwise the partial index
/// wedges the next claim on the node. The `(attempt_id, lease_id)` pair
/// is the fencing token every durable write presents.
#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    /// The lease identity.
    pub id: NodeLeaseId,
    /// The node the lease holds.
    pub node_id: WorkflowNodeId,
    /// The attempt the lease fences.
    pub attempt_id: SessionAttemptId,
    /// The worker holding the lease.
    pub worker_id: WorkerId,
    /// When the lease was issued.
    pub issued_at: OffsetDateTime,
    /// The last renewal instant.
    pub last_heartbeat_at: OffsetDateTime,
    /// When the lease lapses (`issued`/`beat` + [`lease_ttl`]).
    pub expires_at: OffsetDateTime,
    /// The locked renewal cadence the row carries (seconds).
    pub heartbeat_interval_sec: i32,
    /// When the lease closed; `None` while live.
    pub released_at: Option<OffsetDateTime>,
}

impl Lease {
    /// Whether the lease still holds the node (upstream `Live`):
    /// `released_at IS NULL` per the partial index. A released lease is
    /// fencing-dead even if its `expires_at` has not passed.
    #[must_use]
    pub fn live(&self) -> bool {
        self.released_at.is_none()
    }

    /// Whether a still-live lease has reached `expires_at` at `now`
    /// (upstream `Expired`). A released lease is never "expired" — it
    /// is already closed.
    #[must_use]
    pub fn expired(&self, now: OffsetDateTime) -> bool {
        self.live() && now >= self.expires_at
    }
}

/// One row of the per-node attempt ledger keyed `(node_id,
/// attempt_seq)` — the claim idempotency key, so a rerun after an
/// ambiguous or failed attempt takes the next sequence instead of
/// replaying. The fields mirror `central.session_attempts`.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionAttempt {
    /// The attempt identity.
    pub id: SessionAttemptId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The owning run.
    pub run_id: RunId,
    /// The node the attempt executes.
    pub node_id: WorkflowNodeId,
    /// The 1-based ordinal within the node — the idempotency key.
    pub attempt_seq: i32,
    /// The worker that claimed the attempt.
    pub worker_id: Option<WorkerId>,
    /// The harness-attempt row the launch bound (b30 link).
    pub harness_attempt_id: Option<HarnessAttemptId>,
    /// The provisioned workspace path recorded at `provisioning`.
    pub workspace_path: Option<String>,
    /// The v33 workspace-kind vocabulary (`'worktree'`/`'directory'`).
    pub workspace_kind: String,
    /// The attempt state.
    pub state: AttemptState,
    /// The dispatch-scope reason code when the outcome parked/failed.
    pub dispatch_reason_code: Option<String>,
    /// The admission reservation id the claim journaled.
    pub reservation_id: Option<String>,
    /// The live harness session id recorded at `started`.
    pub harness_session_id: Option<String>,
    /// When the claim committed.
    pub claimed_at: OffsetDateTime,
    /// When the session went live; `None` before `started`.
    pub started_at: Option<OffsetDateTime>,
    /// When the attempt reached a closed state; `None` while open.
    pub ended_at: Option<OffsetDateTime>,
}

/// What one successful claim commits (upstream `ClaimedAttempt`): the
/// fresh session attempt, its fencing lease, and the node's harness —
/// the facts the dispatcher and launcher need without a second read.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedAttempt {
    /// The fresh `claimed` attempt row.
    pub attempt: SessionAttempt,
    /// The fencing lease issued with it.
    pub lease: Lease,
    /// The node's harness kind.
    pub harness: String,
}

// ---------------------------------------------------------------------------
// Capability match and registration refusal
// ---------------------------------------------------------------------------

/// Whether the worker may hold a lease on a node of the given harness
/// and `workspace_kind` (upstream `CapabilityMatch`): BOTH must be
/// inside the worker's declared lists (spec-2 decision 2; the spec-1
/// claim transaction enforces the match). `ws_kind` uses the v33
/// vocabulary — `'worktree'`/`'directory'`, the schema names for
/// spec-2's code/plain.
#[must_use]
pub fn capability_match(worker: &Worker, harness: &str, ws_kind: &str) -> bool {
    worker.harness_kinds.iter().any(|k| k == harness)
        && worker.workspace_kinds.iter().any(|k| k == ws_kind)
}

/// Evaluates the spec-2 handshake (upstream `RegistrationFailure`):
/// `None` accepts the registration; `Some(Failure)` refuses it.
/// Refusal grounds are a protocol-version mismatch or an empty
/// intersection between the worker's declared harness kinds and the
/// harnesses this instance can launch — registration is self-asserted
/// capability, not privilege, so an accepted worker's declarations only
/// narrow what it may claim.
#[must_use]
pub fn registration_failure(
    protocol_version: i32,
    harness_kinds: &[String],
    launchable_harnesses: &[String],
) -> Option<Failure> {
    if protocol_version != PROTOCOL_VERSION {
        return Some(Failure::new(
            FailureClass::Denied,
            REASON_WORKER_REGISTRATION_REJECTED,
        ));
    }
    if !harness_kinds
        .iter()
        .any(|kind| launchable_harnesses.contains(kind))
    {
        return Some(Failure::new(
            FailureClass::Denied,
            REASON_WORKER_REGISTRATION_REJECTED,
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// Expiry decision (spec-2 decision 6)
// ---------------------------------------------------------------------------

/// The domain verdict for one expired lease (upstream `ExpiryOutcome`):
/// where the attempt lands, where the node lands (the
/// `central-workflow` `NodeStatus` vocabulary, carried as its journaled
/// text — this crate must not import `central-workflow`), the reason
/// code, and the attempt-scope event kind (eventjournal vocabulary)
/// journaled in the same commit. The store additionally journals
/// `lease_expired`. No branch produces `failed_terminal` by itself
/// (spec-2 decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryOutcome {
    /// The state the attempt row lands in.
    pub attempt_state: AttemptState,
    /// The workflow node-status text the node lands in.
    pub node_state: &'static str,
    /// The spec-2 reason code.
    pub reason_code: &'static str,
    /// The attempt-scope `run_events` kind journaled with the commit.
    pub event_kind: &'static str,
}

/// One expired lease's committed outcome (upstream `ExpiryResult`),
/// returned by the store's `expire_leases` pass so callers can audit
/// what each expiry did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryResult {
    /// The expired lease.
    pub lease_id: NodeLeaseId,
    /// The released node.
    pub node_id: WorkflowNodeId,
    /// The affected attempt.
    pub attempt_id: SessionAttemptId,
    /// The worker that held the lease.
    pub worker_id: WorkerId,
    /// The committed outcome.
    pub outcome: ExpiryOutcome,
}

/// Applies spec-2 decision 6 to one expired lease (upstream
/// `ExpiryDecision`). `attempt_started` reports whether the attempt row
/// ever reached `started`; `via_worker_loss` marks expiry driven
/// through the lost-worker path rather than the plain sweep. A
/// never-started attempt closes `failed` (`LEASE_EXPIRED_NOT_STARTED`)
/// and its node requeues to `ready` — nothing ran, so no ambiguity is
/// possible. A started attempt parks ambiguous
/// (`ATTEMPT_AMBIGUOUS_LEASE_EXPIRED` or
/// `ATTEMPT_AMBIGUOUS_WORKER_LOST`) and its node parks
/// `attempt_ambiguous` for an operator decision.
#[must_use]
pub fn expiry_decision(attempt_started: bool, via_worker_loss: bool) -> ExpiryOutcome {
    if !attempt_started {
        return ExpiryOutcome {
            attempt_state: AttemptState::Failed,
            node_state: "ready",
            reason_code: REASON_LEASE_EXPIRED_NOT_STARTED,
            event_kind: "attempt_failed",
        };
    }
    ExpiryOutcome {
        attempt_state: AttemptState::Ambiguous,
        node_state: "attempt_ambiguous",
        reason_code: if via_worker_loss {
            REASON_ATTEMPT_AMBIGUOUS_WORKER_LOST
        } else {
            REASON_ATTEMPT_AMBIGUOUS_LEASE_EXPIRED
        },
        event_kind: "attempt_ambiguous",
    }
}

// ---------------------------------------------------------------------------
// Reason codes — spec-2 failure semantics
// ---------------------------------------------------------------------------

/// `WORKER_REGISTRATION_REJECTED` — a refused handshake:
/// protocol-version mismatch or empty capability intersection.
pub const REASON_WORKER_REGISTRATION_REJECTED: &str = "WORKER_REGISTRATION_REJECTED";
/// `LEASE_RENEWAL_STALE` — a renewal matching no live lease: expired,
/// released, or superseded; the worker must abort locally.
pub const REASON_LEASE_RENEWAL_STALE: &str = "LEASE_RENEWAL_STALE";
/// `LEASE_EXPIRED_NOT_STARTED` — a lease that lapsed before
/// `attempt_started`: the attempt closes `failed`, the node requeues.
pub const REASON_LEASE_EXPIRED_NOT_STARTED: &str = "LEASE_EXPIRED_NOT_STARTED";
/// `ATTEMPT_AMBIGUOUS_LEASE_EXPIRED` — a started attempt whose lease
/// lapsed in the sweep: `attempt_ambiguous`, operator decision.
pub const REASON_ATTEMPT_AMBIGUOUS_LEASE_EXPIRED: &str = "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED";
/// `WORKER_LOST_GRACE_EXPIRED` — a worker exceeding the missed-beat
/// grace: declared lost, all its leases expired.
pub const REASON_WORKER_LOST_GRACE_EXPIRED: &str = "WORKER_LOST_GRACE_EXPIRED";
/// `ATTEMPT_AMBIGUOUS_WORKER_LOST` — a running attempt of a lost
/// worker: `attempt_ambiguous`, operator decision.
pub const REASON_ATTEMPT_AMBIGUOUS_WORKER_LOST: &str = "ATTEMPT_AMBIGUOUS_WORKER_LOST";
/// `ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED` — a timeout sweep's kill that
/// could not be confirmed: the attempt outcome is unknowable, so the
/// attempt parks ambiguous for an operator decision (spec-4 locked
/// input 2) instead of recording a definite failure.
pub const REASON_ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED: &str = "ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED";
/// `LEASE_FENCE_STALE` — a durable write presented under an expired or
/// superseded lease.
pub const REASON_LEASE_FENCE_STALE: &str = "LEASE_FENCE_STALE";
/// `WORKER_SHUTDOWN_LEASE_RELEASED` — a clean deregistration releasing
/// a never-started attempt's lease; the node requeues.
pub const REASON_WORKER_SHUTDOWN_LEASE_RELEASED: &str = "WORKER_SHUTDOWN_LEASE_RELEASED";

// The codes below are the store's boundary refusals beyond spec-2's
// declared list: they name lookup/actuation failures, not protocol
// transitions.

/// `WORKER_NOT_FOUND` — a call naming a `worker_id` that has no
/// `worker_registrations` row.
pub const REASON_WORKER_NOT_FOUND: &str = "WORKER_NOT_FOUND";
/// `WORKER_NOT_ACTIVE` — a claim under a worker whose registration is
/// terminal on the ladder (lost or deregistered); a suspect worker may
/// still claim.
pub const REASON_WORKER_NOT_ACTIVE: &str = "WORKER_NOT_ACTIVE";
/// `INVALID_ATTEMPT_TRANSITION` — a fenced write whose attempt row is
/// in a state that admits the requested transition no longer.
pub const REASON_INVALID_ATTEMPT_TRANSITION: &str = "INVALID_ATTEMPT_TRANSITION";
/// `NODE_NOT_FOUND` — a call naming a `node_id` that has no
/// `workflow_nodes` row.
pub const REASON_NODE_NOT_FOUND: &str = "NODE_NOT_FOUND";
/// `OUTCOME_KIND_UNKNOWN` — a `record_outcome` kind outside the b37
/// `attempt_outcomes` `outcome_kind` vocabulary (spec-5, spec-4).
pub const REASON_OUTCOME_KIND_UNKNOWN: &str = "OUTCOME_KIND_UNKNOWN";
/// `OUTCOME_FINGERPRINT_INVALID` — an outcome fingerprint that is not
/// the 32-byte spec-5 replay-compare value.
pub const REASON_OUTCOME_FINGERPRINT_INVALID: &str = "OUTCOME_FINGERPRINT_INVALID";
/// `OUTCOME_REASON_MISSING` — a `failed` outcome report carrying no
/// spec-4 reason code — the taxonomy cannot classify an empty one.
pub const REASON_OUTCOME_REASON_MISSING: &str = "OUTCOME_REASON_MISSING";

// ---------------------------------------------------------------------------
// Failure
// ---------------------------------------------------------------------------

/// A stable, safe scheduler-domain error category (upstream
/// `FailureClass`). It never carries node keys, attempt payloads, or
/// other sensitive input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// `INVALID` — malformed input or a reference to a worker, lease,
    /// or attempt that does not exist.
    Invalid,
    /// `CONFLICT` — a lost-update or consistency conflict.
    Conflict,
    /// `DENIED` — a denied registration, renewal, fenced write, or
    /// state transition.
    Denied,
}

impl FailureClass {
    /// The persisted text form (upstream `FailureClass` string values).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID",
            Self::Conflict => "CONFLICT",
            Self::Denied => "DENIED",
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed scheduler-domain failure returned at store boundaries
/// (upstream `scheduler.Failure`). `reason_code` is a closed
/// machine-readable spec-2 value; `Display` deliberately excludes node
/// keys, attempt ids, and driver detail.
///
/// Upstream's `cause`/`WithCause` chain has no Rust counterpart here:
/// the port boundary error is [`FoundationFailure`], whose redacted
/// `message` carries whatever driver detail survives sanitization —
/// the adapter converts through [`From<Failure>`] at that point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The error category.
    pub class: FailureClass,
    /// The closed machine-readable reason code (upstream `ReasonCode`).
    pub reason_code: &'static str,
}

impl Failure {
    /// Builds a domain failure from a closed class and reason code.
    #[must_use]
    pub const fn new(class: FailureClass, reason_code: &'static str) -> Self {
        Self { class, reason_code }
    }
}

impl fmt::Display for Failure {
    /// `"scheduler-failure class=\"{class}\" reason_code=\"{code}\""` —
    /// upstream `Error()`'s shape, closed tokens only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scheduler-failure class={:?} reason_code={:?}",
            self.class.as_str(),
            self.reason_code
        )
    }
}

impl std::error::Error for Failure {}

/// Maps a domain failure onto the shared foundation taxonomy: `class`
/// becomes the `FailureKind`, `reason_code` the stable machine `code`,
/// and the message is the domain failure's already-redacted `Display`.
impl From<Failure> for FoundationFailure {
    fn from(failure: Failure) -> Self {
        let kind = match failure.class {
            FailureClass::Invalid => FailureKind::Invalid,
            FailureClass::Conflict => FailureKind::Conflict,
            FailureClass::Denied => FailureKind::Denied,
        };
        FoundationFailure::new(kind, failure.reason_code, failure.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `time::macros::datetime` fixed anchor — the upstream tests'
    /// `time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)`.
    fn anchor() -> OffsetDateTime {
        time::macros::datetime!(2026-10-07 12:00:00 UTC)
    }

    // -- upstream domain_test.go: TestAttemptStateTransitions ---------

    /// Pins the spec-2 attempt machine: the happy path
    /// `claimed → provisioning → started → succeeded`, the failure and
    /// ambiguous branches, and the operator-only ambiguous exit.
    #[test]
    fn attempt_state_transitions() {
        use AttemptState::*;
        let cases: &[(&str, AttemptState, AttemptState, bool)] = &[
            (
                "claimed provisions on dispatch",
                Claimed,
                Provisioning,
                true,
            ),
            ("claimed fails pre-start on expiry", Claimed, Failed, true),
            (
                "claimed releases on clean shutdown",
                Claimed,
                Cancelled,
                true,
            ),
            ("claimed never starts directly", Claimed, Started, false),
            ("claimed never succeeds", Claimed, Succeeded, false),
            (
                "claimed never goes ambiguous -- nothing ran",
                Claimed,
                Ambiguous,
                false,
            ),
            ("provisioning reaches started", Provisioning, Started, true),
            (
                "provisioning fails on definite refusal",
                Provisioning,
                Failed,
                true,
            ),
            (
                "provisioning goes ambiguous on unknown outcome",
                Provisioning,
                Ambiguous,
                true,
            ),
            (
                "provisioning cancels on confirmed timeout kill",
                Provisioning,
                Cancelled,
                true,
            ),
            (
                "provisioning never succeeds silently",
                Provisioning,
                Succeeded,
                false,
            ),
            (
                "provisioning never returns to claimed",
                Provisioning,
                Claimed,
                false,
            ),
            ("started completes", Started, Succeeded, true),
            ("started fails", Started, Failed, true),
            (
                "started goes ambiguous on lost lease",
                Started,
                Ambiguous,
                true,
            ),
            (
                "started cancels on confirmed timeout kill",
                Started,
                Cancelled,
                true,
            ),
            (
                "started never returns to provisioning",
                Started,
                Provisioning,
                false,
            ),
            ("started never reclaims", Started, Claimed, false),
            (
                "operator abandonment cancels ambiguous",
                Ambiguous,
                Cancelled,
                true,
            ),
            (
                "ambiguous never succeeds silently",
                Ambiguous,
                Succeeded,
                false,
            ),
            (
                "ambiguous never restarts -- rerun is a new attempt_seq",
                Ambiguous,
                Started,
                false,
            ),
            (
                "ambiguous never returns to claimed",
                Ambiguous,
                Claimed,
                false,
            ),
        ];
        for (name, from, to, allowed) in cases {
            assert_eq!(
                from.can_transition(*to),
                *allowed,
                "{name}: {from}.can_transition({to})"
            );
        }
    }

    // -- upstream domain_test.go: TestAttemptStateTerminalAreClosed ---

    /// Pins the terminal states — nothing leaves `succeeded`, `failed`
    /// or `cancelled` — and pins `ambiguous` as NON-terminal: it must
    /// admit an exit while never being confused for a closed state.
    #[test]
    fn attempt_state_terminal_are_closed() {
        for terminal in [
            AttemptState::Succeeded,
            AttemptState::Failed,
            AttemptState::Cancelled,
        ] {
            assert!(terminal.is_terminal(), "{terminal} should be terminal");
            for to in AttemptState::ALL {
                assert!(
                    !terminal.can_transition(to),
                    "terminal {terminal} admitted transition to {to}"
                );
            }
        }
        for open in [
            AttemptState::Claimed,
            AttemptState::Provisioning,
            AttemptState::Started,
            AttemptState::Ambiguous,
        ] {
            assert!(!open.is_terminal(), "{open} should not be terminal");
        }
        // Ambiguous is non-terminal with exactly one exit: operator
        // abandon.
        assert_eq!(
            AttemptState::Ambiguous.valid_transitions(),
            &[AttemptState::Cancelled]
        );
    }

    // -- upstream domain_test.go: TestAttemptStateLiveSet -------------

    /// Pins the b35 `session_attempts_live_node_idx` predicate: only
    /// claimed/provisioning/started hold the node. `ambiguous` is NOT
    /// live, or every rerun after operator decision would wedge on the
    /// partial unique index.
    #[test]
    fn attempt_state_live_set() {
        use AttemptState::*;
        let want = [
            (Claimed, true),
            (Provisioning, true),
            (Started, true),
            (Succeeded, false),
            (Failed, false),
            (Ambiguous, false),
            (Cancelled, false),
        ];
        for state in AttemptState::ALL {
            let expected = want
                .iter()
                .find(|(s, _)| *s == state)
                .map(|(_, live)| *live)
                .unwrap();
            assert_eq!(state.live(), expected, "{state}.live()");
        }
    }

    // -- upstream domain_test.go: TestAttemptStateVocabularyMatchesSchema

    /// Pins the exact string set migration b35 checks in
    /// `session_attempts_state_check`; both restate spec-2 and must not
    /// drift apart.
    #[test]
    fn attempt_state_vocabulary_matches_schema() {
        let want = [
            "claimed",
            "provisioning",
            "started",
            "succeeded",
            "failed",
            "ambiguous",
            "cancelled",
        ];
        let got: Vec<&str> = AttemptState::ALL
            .iter()
            .map(|state| state.as_str())
            .collect();
        assert_eq!(got, want);
        // `parse` is the strict inverse: every declared state
        // round-trips, anything else is rejected.
        for state in AttemptState::ALL {
            assert_eq!(AttemptState::parse(state.as_str()), Some(state));
        }
        assert_eq!(AttemptState::parse("busy"), None);
    }

    // -- upstream domain_test.go: TestWorkerStateVocabularyMatchesSchema

    /// Pins b35's `worker_registrations_state_check` list (and the
    /// `Known` predicate, carried by `parse` admitting nothing outside
    /// the declared set).
    #[test]
    fn worker_state_vocabulary_matches_schema() {
        let want = ["active", "suspect", "lost", "deregistered"];
        let got: Vec<&str> = WorkerState::ALL
            .iter()
            .map(|state| state.as_str())
            .collect();
        assert_eq!(got, want);
        for state in WorkerState::ALL {
            assert_eq!(WorkerState::parse(state.as_str()), Some(state));
        }
        for alien in ["busy", "dead", ""] {
            assert_eq!(
                WorkerState::parse(alien),
                None,
                "undeclared worker state {alien:?} admitted"
            );
        }
    }

    // -- upstream domain_test.go: TestLockedProtocolConstants ---------

    /// Pins the spec-2 OQ-5/OQ-6 locked numbers: 15s heartbeats, 3×
    /// interval TTL, suspect at 2, lost at 5.
    #[test]
    fn locked_protocol_constants() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(HEARTBEAT_INTERVAL_SEC, 15);
        assert_eq!(heartbeat_interval(), Duration::seconds(15));
        assert_eq!(LEASE_TTL_MULTIPLIER, 3);
        assert_eq!(lease_ttl(), Duration::seconds(45));
        assert_eq!(MISSED_BEATS_SUSPECT, 2);
        assert_eq!(MISSED_BEATS_LOST, 5);
    }

    // -- upstream domain_test.go: TestMissedBeatsFloorMath ------------

    /// Pins the `floor((now-last_beat)/interval)` contract: partial
    /// intervals do not count, exact multiples do, and a `last_beat` at
    /// or after `now` counts zero.
    #[test]
    fn missed_beats_floor_math() {
        let last_beat = anchor();
        let cases: &[(&str, Duration, u32)] = &[
            ("same instant", Duration::ZERO, 0),
            ("just under one interval", Duration::milliseconds(14_999), 0),
            ("exactly one interval", Duration::seconds(15), 1),
            ("just under two", Duration::milliseconds(29_999), 1),
            ("exactly two -- suspect boundary", Duration::seconds(30), 2),
            ("just under five", Duration::milliseconds(74_999), 4),
            ("exactly five -- lost boundary", Duration::seconds(75), 5),
            ("well past lost", Duration::minutes(2), 8),
            (
                "last_beat in the future clamps to zero",
                Duration::minutes(-1),
                0,
            ),
        ];
        for (name, elapsed, want) in cases {
            assert_eq!(
                missed_beats(last_beat + *elapsed, last_beat),
                *want,
                "{name}: missed_beats({elapsed} elapsed)"
            );
        }
    }

    // -- upstream domain_test.go: TestLadderBoundaries ----------------

    /// Pins the suspect/lost ladder at every boundary: 0-1 active, 2-4
    /// suspect, 5+ lost. The ladder never yields `deregistered` —
    /// clean shutdown is the worker's own act.
    #[test]
    fn ladder_boundaries() {
        let cases: &[(u32, WorkerState)] = &[
            (0, WorkerState::Active),
            (1, WorkerState::Active),
            (2, WorkerState::Suspect),
            (3, WorkerState::Suspect),
            (4, WorkerState::Suspect),
            (5, WorkerState::Lost),
            (6, WorkerState::Lost),
            (100, WorkerState::Lost),
        ];
        for (missed, want) in cases {
            assert_eq!(ladder(*missed), *want, "ladder({missed})");
        }
    }

    // -- upstream domain_test.go: TestCapabilityMatchMatrix -----------

    fn worker_with(harnesses: &[&str], kinds: &[&str]) -> Worker {
        Worker {
            id: WorkerId::new(),
            workspace_id: WorkspaceId::new(),
            protocol_version: PROTOCOL_VERSION,
            harness_kinds: harnesses.iter().map(|s| (*s).to_string()).collect(),
            workspace_kinds: kinds.iter().map(|s| (*s).to_string()).collect(),
            max_concurrent_attempts: 4,
            state: WorkerState::Active,
            registered_at: None,
            last_seen_at: None,
        }
    }

    /// Pins spec-2 decision 2: a worker may hold a lease only when BOTH
    /// the node's harness and `workspace_kind` are inside its declared
    /// lists.
    #[test]
    fn capability_match_matrix() {
        let worker = worker_with(&["claude-code", "codex"], &["worktree"]);
        let cases: &[(&str, &str, &str, bool)] = &[
            (
                "declared harness and workspace kind match",
                "claude-code",
                "worktree",
                true,
            ),
            ("second declared harness matches", "codex", "worktree", true),
            ("undeclared harness refuses", "gemini", "worktree", false),
            (
                "undeclared workspace kind refuses",
                "claude-code",
                "directory",
                false,
            ),
            ("both undeclared refuses", "gemini", "directory", false),
            ("empty harness refuses", "", "worktree", false),
        ];
        for (name, harness, ws_kind, want) in cases {
            assert_eq!(capability_match(&worker, harness, ws_kind), *want, "{name}");
        }
        // A worker declaring nothing matches nothing.
        let bare = worker_with(&[], &[]);
        assert!(!capability_match(&bare, "claude-code", "worktree"));
    }

    // -- upstream domain_test.go: TestRegistrationFailure -------------

    /// Pins the spec-2 handshake refusals: a protocol-version mismatch
    /// or an empty harness intersection with the launchable set rejects
    /// with `WORKER_REGISTRATION_REJECTED`; a partial intersection
    /// accepts.
    #[test]
    fn registration_failure_handshake() {
        let launchable: Vec<String> = ["claude-code", "codex"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let declared =
            |kinds: &[&str]| -> Vec<String> { kinds.iter().map(|s| (*s).to_string()).collect() };
        /// `(name, version, declared harnesses, launchable set,
        /// want_reject)` — the upstream handshake table.
        type RegCase = (&'static str, i32, Vec<String>, Vec<String>, bool);
        let cases: &[RegCase] = &[
            (
                "full intersection accepts",
                PROTOCOL_VERSION,
                declared(&["claude-code", "codex"]),
                launchable.clone(),
                false,
            ),
            (
                "partial intersection accepts",
                PROTOCOL_VERSION,
                declared(&["claude-code", "gemini"]),
                launchable.clone(),
                false,
            ),
            (
                "single-kind intersection accepts",
                PROTOCOL_VERSION,
                declared(&["codex"]),
                launchable.clone(),
                false,
            ),
            (
                "version mismatch rejects",
                PROTOCOL_VERSION + 1,
                declared(&["claude-code"]),
                launchable.clone(),
                true,
            ),
            (
                "version zero rejects",
                0,
                declared(&["claude-code"]),
                launchable.clone(),
                true,
            ),
            (
                "empty declared harnesses rejects",
                PROTOCOL_VERSION,
                vec![],
                launchable.clone(),
                true,
            ),
            (
                "empty intersection rejects",
                PROTOCOL_VERSION,
                declared(&["gemini"]),
                launchable.clone(),
                true,
            ),
            (
                "empty launchable set rejects",
                PROTOCOL_VERSION,
                declared(&["claude-code"]),
                vec![],
                true,
            ),
        ];
        for (name, version, harness_kinds, launchable, want_reject) in cases {
            match registration_failure(*version, harness_kinds, launchable) {
                Some(failure) => {
                    assert!(
                        *want_reject,
                        "{name}: registration_failure() = {failure}, want accept"
                    );
                    assert_eq!(failure.class, FailureClass::Denied, "{name}");
                    assert_eq!(
                        failure.reason_code, REASON_WORKER_REGISTRATION_REJECTED,
                        "{name}"
                    );
                }
                None => assert!(!*want_reject, "{name}: accepted, want rejection"),
            }
        }
        // Version mismatch rejects even when capabilities would
        // intersect — the handshake fails before capability evaluation
        // matters.
        assert!(registration_failure(PROTOCOL_VERSION + 1, &launchable, &launchable).is_some());
    }

    // -- upstream domain_test.go: TestExpiryDecision ------------------

    /// `(name, attempt_started, via_worker_loss, want_attempt,
    /// want_node, want_reason, want_event)` — the upstream split.
    type ExpiryCase = (
        &'static str,
        bool,
        bool,
        AttemptState,
        &'static str,
        &'static str,
        &'static str,
    );

    /// Pins spec-2 decision 6's three branches: a never-started attempt
    /// closes `failed` and requeues the node, while a started attempt
    /// parks ambiguous — under sweep or worker loss — with the node
    /// `attempt_ambiguous`. No branch produces `failed_terminal`.
    #[test]
    fn expiry_decision_branches() {
        let cases: &[ExpiryCase] = &[
            (
                "never-started sweep expiry closes failed and requeues",
                false,
                false,
                AttemptState::Failed,
                "ready",
                REASON_LEASE_EXPIRED_NOT_STARTED,
                "attempt_failed",
            ),
            (
                "never-started worker-loss expiry still closes failed",
                false,
                true,
                AttemptState::Failed,
                "ready",
                REASON_LEASE_EXPIRED_NOT_STARTED,
                "attempt_failed",
            ),
            (
                "started sweep expiry parks ambiguous",
                true,
                false,
                AttemptState::Ambiguous,
                "attempt_ambiguous",
                REASON_ATTEMPT_AMBIGUOUS_LEASE_EXPIRED,
                "attempt_ambiguous",
            ),
            (
                "started worker-loss expiry parks ambiguous",
                true,
                true,
                AttemptState::Ambiguous,
                "attempt_ambiguous",
                REASON_ATTEMPT_AMBIGUOUS_WORKER_LOST,
                "attempt_ambiguous",
            ),
        ];
        for (name, started, via_worker_loss, want_attempt, want_node, want_reason, want_event) in
            cases
        {
            let got = expiry_decision(*started, *via_worker_loss);
            assert_eq!(got.attempt_state, *want_attempt, "{name}");
            assert_eq!(got.node_state, *want_node, "{name}");
            assert_eq!(got.reason_code, *want_reason, "{name}");
            assert_eq!(got.event_kind, *want_event, "{name}");
            // Spec-2 decision 6: expiry never yields failed_terminal.
            assert_ne!(got.node_state, "failed_terminal", "{name}");
        }
    }

    // -- upstream domain_test.go: TestReasonCodeVocabulary ------------

    /// Pins every spec-2 failure-semantics code; all eight must be
    /// declared and reachable from the design.
    #[test]
    fn reason_code_vocabulary() {
        let want: [(&str, &str); 8] = [
            (
                "WORKER_REGISTRATION_REJECTED",
                REASON_WORKER_REGISTRATION_REJECTED,
            ),
            ("LEASE_RENEWAL_STALE", REASON_LEASE_RENEWAL_STALE),
            (
                "LEASE_EXPIRED_NOT_STARTED",
                REASON_LEASE_EXPIRED_NOT_STARTED,
            ),
            (
                "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED",
                REASON_ATTEMPT_AMBIGUOUS_LEASE_EXPIRED,
            ),
            (
                "WORKER_LOST_GRACE_EXPIRED",
                REASON_WORKER_LOST_GRACE_EXPIRED,
            ),
            (
                "ATTEMPT_AMBIGUOUS_WORKER_LOST",
                REASON_ATTEMPT_AMBIGUOUS_WORKER_LOST,
            ),
            ("LEASE_FENCE_STALE", REASON_LEASE_FENCE_STALE),
            (
                "WORKER_SHUTDOWN_LEASE_RELEASED",
                REASON_WORKER_SHUTDOWN_LEASE_RELEASED,
            ),
        ];
        for (literal, constant) in want {
            assert_eq!(constant, literal);
        }
    }

    // -- upstream domain_test.go: TestLeaseLiveAndExpired -------------

    fn lease(expires_at: OffsetDateTime, released_at: Option<OffsetDateTime>) -> Lease {
        Lease {
            id: NodeLeaseId::new(),
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
            worker_id: WorkerId::new(),
            issued_at: anchor(),
            last_heartbeat_at: anchor(),
            expires_at,
            heartbeat_interval_sec: HEARTBEAT_INTERVAL_SEC as i32,
            released_at,
        }
    }

    /// Pins the lease record's two predicates: `released_at IS NULL`
    /// defines live (the b35 partial index), and only a live lease can
    /// expire.
    #[test]
    fn lease_live_and_expired() {
        let now = anchor();
        let live = lease(now + lease_ttl(), None);
        assert!(live.live());
        assert!(!live.expired(now), "fresh lease should be unexpired");

        let stale = lease(now - Duration::seconds(1), None);
        assert!(stale.live());
        assert!(stale.expired(now), "live lease past expires_at expires");

        let released = lease(now + lease_ttl(), Some(now));
        assert!(!released.live(), "released lease should not be live");
        assert!(
            !released.expired(now - Duration::hours(1)),
            "released lease is closed, not expired"
        );
    }

    // -- upstream domain_test.go: TestFailureSemantics ----------------

    /// Pins the Failure contract: `Display` carries only the class and
    /// closed reason code, and the foundation mapping preserves both —
    /// the Rust equivalent of upstream's redacted `Error()` +
    /// `errors.As` round-trip. (Upstream's `WithCause` diagnostic chain
    /// maps onto the foundation failure's redacted `message` at the
    /// adapter boundary; the domain type stays `Copy`.)
    #[test]
    fn failure_semantics() {
        let failure = Failure::new(FailureClass::Denied, REASON_LEASE_FENCE_STALE);
        assert_eq!(
            failure.to_string(),
            r#"scheduler-failure class="DENIED" reason_code="LEASE_FENCE_STALE""#
        );
        let foundation: FoundationFailure = failure.into();
        assert_eq!(foundation.kind(), FailureKind::Denied);
        assert_eq!(foundation.code(), REASON_LEASE_FENCE_STALE);
        assert_eq!(foundation.message(), failure.to_string());
        // The domain failure satisfies the error interface like
        // workflow.Failure does.
        let standard: &dyn std::error::Error = &failure;
        assert!(standard.source().is_none());
    }
}
