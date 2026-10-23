//! The `Attempt` aggregate — the port of `internal/harness/attempt.go`.
//! One attempt is one launch or resume of a harness process tree for one
//! Run. All mutators are pure: they return a new `Attempt` and never
//! modify the receiver; on error they return `Err` (the Go
//! "return the zero Attempt" has no Rust analogue — an `Err` carries no
//! value).
//!
//! `version` is the persistence revision and is owned by the store:
//! [`Attempt::prepare`] sets 0, every mutator copies it unchanged, and
//! only a successful store write advances it. One event may drive several
//! mutators before a single write.

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, RunId, WorkspaceId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::budget::Budget;
use crate::domain::{
    Fence, Kind, PermissionPolicy, Resolution, ResolutionKind, State, Terminal, Workspace, codes,
    is_zero_time,
};
use crate::event::{Usage, UsageScope};

/// One harness session attempt — upstream `Attempt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attempt {
    /// The attempt's own id — also the linked execution StepAttempt id
    /// (see [`crate::recovery::attempt_id_for_step_attempt`]).
    pub id: HarnessAttemptId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The owning run.
    pub run_id: RunId,
    /// The harness adapter kind.
    pub kind: Kind,
    /// The adapter version Central launched.
    pub adapter_version: String,
    /// The harness binary's reported version, once launched.
    pub harness_version: String,
    /// The harness-owned session id, once revealed.
    pub harness_session_id: String,
    /// The attempt this one resumes, if any — Go's zero
    /// `ResumeOf` is `None` here.
    pub resume_of: Option<HarnessAttemptId>,
    /// The harness session id a resume must reveal.
    pub resume_session_id: String,
    /// The worktree and base commit.
    pub workspace: Workspace,
    /// The operator-chosen permission policy.
    pub permission: PermissionPolicy,
    /// The sandbox scope the process tree runs in, once launched.
    pub sandbox_scope_id: String,
    /// The execution-lease fence.
    pub fence: Fence,
    /// The persistence revision — owned by the store.
    pub version: i64,
    /// The lifecycle state.
    pub state: State,
    /// The pending permission request id, while awaiting one.
    pub pending_permission: String,
    /// How the session ended; set exactly on terminal states that came
    /// from an adapter terminal report.
    pub terminal: Terminal,
    /// The operator's answer; set exactly on `resolved`.
    pub resolution: Resolution,
    /// Why the attempt went ambiguous; set exactly on `ambiguous` and
    /// `resolved`.
    pub ambiguity_reason: String,
    /// The event cursor — the highest seq recorded.
    pub last_event_seq: u64,
    /// The scope-normalized cumulative usage.
    pub usage: Usage,
    /// The effective budget recorded at prepare; it never changes.
    pub budget: Budget,
    /// When the attempt was prepared.
    pub prepared_at: OffsetDateTime,
    /// The last mutator's timestamp.
    pub updated_at: OffsetDateTime,
    /// When the attempt reached a terminal state — `None` is the Go zero
    /// time.
    pub ended_at: Option<OffsetDateTime>,
}

/// Everything needed to prepare a fresh attempt — upstream
/// `PrepareInput`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrepareInput {
    /// The new attempt's id.
    pub id: HarnessAttemptId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The owning run.
    pub run_id: RunId,
    /// The harness adapter kind.
    pub kind: Kind,
    /// The adapter version.
    pub adapter_version: String,
    /// The worktree and base commit.
    pub workspace: Workspace,
    /// The operator-chosen permission policy.
    pub permission: PermissionPolicy,
    /// The execution-lease fence.
    pub fence: Fence,
    /// The effective budget the attempt runs under; it must be valid,
    /// and the attempt keeps it unchanged.
    pub budget: Budget,
    /// The prepare timestamp.
    pub at: OffsetDateTime,
}

impl Attempt {
    /// Upstream `Prepare`: creates a fresh attempt in
    /// [`State::Prepared`].
    pub fn prepare(input: PrepareInput) -> Result<Self, Failure> {
        let a = Self {
            id: input.id,
            workspace_id: input.workspace_id,
            run_id: input.run_id,
            kind: input.kind,
            adapter_version: input.adapter_version,
            harness_version: String::new(),
            harness_session_id: String::new(),
            resume_of: None,
            resume_session_id: String::new(),
            workspace: input.workspace,
            permission: input.permission,
            sandbox_scope_id: String::new(),
            fence: input.fence,
            version: 0,
            state: State::Prepared,
            pending_permission: String::new(),
            terminal: Terminal::default(),
            resolution: Resolution::default(),
            ambiguity_reason: String::new(),
            last_event_seq: 0,
            usage: Usage::default(),
            budget: input.budget,
            prepared_at: input.at,
            updated_at: input.at,
            ended_at: None,
        };
        a.checked()
    }

    /// Upstream `PrepareResume`: prepares an attempt that resumes
    /// `prev`'s harness session. Resume is general: any terminal attempt
    /// with a harness session id may be resumed, except a resolved
    /// attempt whose resolution is not resume. The new attempt must stay
    /// in `prev`'s workspace and run, and its fence may never go back
    /// below `prev`'s generation.
    pub fn prepare_resume(prev: &Attempt, input: PrepareInput) -> Result<Self, Failure> {
        if !prev.state.is_terminal() {
            return Err(Failure::conflict(
                codes::RESUME_NOT_ALLOWED,
                format!("previous attempt is {}, not terminal", prev.state.as_str()),
            ));
        }
        if prev.harness_session_id.is_empty() {
            return Err(Failure::conflict(
                codes::RESUME_NOT_ALLOWED,
                "previous attempt has no harness session id",
            ));
        }
        if prev.state == State::Resolved && prev.resolution.kind != ResolutionKind::Resume {
            return Err(Failure::conflict(
                codes::RESUME_NOT_ALLOWED,
                format!(
                    "previous attempt was resolved as {}",
                    prev.resolution.kind.as_str()
                ),
            ));
        }
        if input.workspace_id != prev.workspace_id
            || input.run_id != prev.run_id
            || input.kind != prev.kind
            || input.workspace != prev.workspace
        {
            return Err(Failure::conflict(
                codes::RESUME_NOT_ALLOWED,
                "workspace, run, kind and worktree must match the previous attempt",
            ));
        }
        if input.fence.generation < prev.fence.generation {
            return Err(Failure::conflict(
                codes::FENCE_MISMATCH,
                format!(
                    "fence generation {} is below the previous attempt's {}",
                    input.fence.generation, prev.fence.generation
                ),
            ));
        }
        let mut a = Self::prepare(input)?;
        a.resume_of = Some(prev.id);
        a.resume_session_id = prev.harness_session_id.clone();
        a.checked()
    }

    /// Upstream `Launch`: records that the harness process tree was
    /// started.
    pub fn launch(
        &self,
        fence: Fence,
        sandbox_scope_id: &str,
        harness_version: &str,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if sandbox_scope_id.is_empty() || harness_version.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "launch requires sandbox scope and harness version",
            ));
        }
        let mut next = self.move_to(State::Launching, at)?;
        next.sandbox_scope_id = sandbox_scope_id.to_string();
        next.harness_version = harness_version.to_string();
        next.checked()
    }

    /// Upstream `RevealSession`: records the harness-owned session id.
    /// Revealing the same id again while running or awaiting permission
    /// is an idempotent no-op. A resume attempt must reveal exactly the
    /// id it resumes: a harness that answered a resume with a fresh
    /// session would otherwise silently lose the history.
    pub fn reveal_session(
        &self,
        fence: Fence,
        harness_session_id: &str,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if harness_session_id.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "empty harness session id",
            ));
        }
        if !self.resume_session_id.is_empty() && harness_session_id != self.resume_session_id {
            return Err(Failure::conflict(
                codes::SESSION_MISMATCH,
                "resume revealed a different session id",
            ));
        }
        if self.state == State::Running || self.state == State::AwaitingPermission {
            if self.harness_session_id == harness_session_id {
                return Ok(self.clone());
            }
            return Err(Failure::conflict(
                codes::SESSION_MISMATCH,
                "harness session id changed",
            ));
        }
        let mut next = self.move_to(State::Running, at)?;
        next.harness_session_id = harness_session_id.to_string();
        next.checked()
    }

    /// Upstream `AwaitPermission`: records a pending harness permission
    /// request.
    pub fn await_permission(
        &self,
        fence: Fence,
        request_id: &str,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if request_id.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "empty permission request id",
            ));
        }
        let mut next = self.move_to(State::AwaitingPermission, at)?;
        next.pending_permission = request_id.to_string();
        next.checked()
    }

    /// Upstream `ResolvePermission`: clears the pending request and
    /// resumes running.
    pub fn resolve_permission(
        &self,
        fence: Fence,
        request_id: &str,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if self.state != State::AwaitingPermission {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!("cannot resolve permission in {}", self.state.as_str()),
            ));
        }
        if request_id != self.pending_permission {
            return Err(Failure::conflict(
                codes::PERMISSION_MISMATCH,
                "permission request mismatch",
            ));
        }
        let mut next = self.move_to(State::Running, at)?;
        next.pending_permission = String::new();
        next.checked()
    }

    /// Upstream `RecordProgress`: advances the event cursor. An equal seq
    /// is an idempotent no-op; a lower seq is an adapter bug. Usage is
    /// folded in separately by [`Attempt::apply_usage`].
    pub fn record_progress(
        &self,
        fence: Fence,
        seq: u64,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if !self.accepts_events() {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!("cannot record progress in {}", self.state.as_str()),
            ));
        }
        if seq == 0 || seq < self.last_event_seq {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                format!("seq {seq} after {}", self.last_event_seq),
            ));
        }
        if seq == self.last_event_seq {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.last_event_seq = seq;
        next.updated_at = at;
        next.checked()
    }

    /// Upstream `ApplyUsage`: folds a harness usage report into the
    /// attempt's scope-normalized cumulative [`Usage`]. The first report
    /// adopts its scope and a later report in another scope is rejected.
    /// A step report accumulates; a run or session_cumulative report
    /// replaces, and may never lower a counter. `estimated` is sticky
    /// once true. An empty report, or one that changes nothing, is an
    /// idempotent no-op.
    pub fn apply_usage(
        &self,
        fence: Fence,
        report: Usage,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if !self.accepts_events() {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!("cannot apply usage in {}", self.state.as_str()),
            ));
        }
        report.validate()?;
        if report == Usage::default() {
            return Ok(self.clone());
        }
        if self.usage.scope != UsageScope::Unset && self.usage.scope != report.scope {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                format!(
                    "usage scope {} after {}",
                    report.scope.as_str(),
                    self.usage.scope.as_str()
                ),
            ));
        }
        let usage = self.usage.fold(&report)?;
        if usage == self.usage {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.usage = usage;
        next.updated_at = at;
        next.checked()
    }

    fn accepts_events(&self) -> bool {
        matches!(
            self.state,
            State::Launching | State::Running | State::AwaitingPermission
        )
    }

    /// Upstream `Terminate`: records how the harness session ended.
    pub fn terminate(
        &self,
        fence: Fence,
        terminal: Terminal,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        let to = terminal.state()?;
        let mut next = self.move_to(to, at)?;
        next.terminal = terminal;
        next.pending_permission = String::new();
        next.checked()
    }

    /// Upstream `MarkAmbiguous`: records that Central lost track of the
    /// harness process after launch may have happened. Only the operator
    /// can leave this state.
    pub fn mark_ambiguous(
        &self,
        fence: Fence,
        reason: &str,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        if reason.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "ambiguity requires a reason",
            ));
        }
        let mut next = self.move_to(State::Ambiguous, at)?;
        next.ambiguity_reason = reason.to_string();
        next.pending_permission = String::new();
        next.checked()
    }

    /// Upstream `Resolve`: records the operator's answer to an ambiguous
    /// attempt.
    pub fn resolve(
        &self,
        fence: Fence,
        resolution: Resolution,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(fence, at)?;
        resolution.validate()?;
        if resolution.kind == ResolutionKind::Resume && self.harness_session_id.is_empty() {
            return Err(Failure::conflict(
                codes::RESUME_NOT_ALLOWED,
                "attempt has no harness session id to resume",
            ));
        }
        let mut next = self.move_to(State::Resolved, at)?;
        next.resolution = resolution;
        next.checked()
    }

    /// Upstream `Refence`: rotates the fence to a newly claimed, strictly
    /// greater generation.
    pub fn refence(
        &self,
        current: Fence,
        next: Fence,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        self.guard(current, at)?;
        if self.state.is_terminal() {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!("cannot refence a {} attempt", self.state.as_str()),
            ));
        }
        if next.generation <= current.generation {
            return Err(Failure::conflict(
                codes::FENCE_MISMATCH,
                format!("next generation must exceed {}", current.generation),
            ));
        }
        let mut out = self.clone();
        out.fence = next;
        out.updated_at = at;
        out.checked()
    }

    /// Upstream `Validate`: checks every aggregate invariant.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.id.is_nil() || self.workspace_id.is_nil() || self.run_id.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "attempt, workspace and run ids are required",
            ));
        }
        if self.version < 0 {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "version must be >= 0",
            ));
        }
        self.kind.validate()?;
        if self.adapter_version.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "adapter version is required",
            ));
        }
        self.workspace.validate()?;
        if !self.permission.known() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("unknown permission policy {}", self.permission.as_str()),
            ));
        }
        self.fence.validate()?;
        self.budget.validate()?;
        if !self.state.known() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("unknown state {}", self.state.as_str()),
            ));
        }
        if is_zero_time(self.prepared_at) || is_zero_time(self.updated_at) {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "timestamps are required",
            ));
        }
        // These states are reachable only through Launch, so they must
        // carry what Launch recorded; reconcile needs the sandbox scope
        // id. failed, ambiguous and resolved are also reachable straight
        // from prepared.
        if matches!(
            self.state,
            State::Launching
                | State::Running
                | State::AwaitingPermission
                | State::Succeeded
                | State::Interrupted
                | State::Killed
                | State::BudgetExhausted
        ) && (self.sandbox_scope_id.is_empty() || self.harness_version.is_empty())
        {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!(
                    "{} requires a sandbox scope id and harness version",
                    self.state.as_str()
                ),
            ));
        }
        if matches!(
            self.state,
            State::Running | State::AwaitingPermission | State::Succeeded
        ) && self.harness_session_id.is_empty()
        {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("{} requires a harness session id", self.state.as_str()),
            ));
        }
        if (self.state == State::AwaitingPermission) != (!self.pending_permission.is_empty()) {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "pending permission must be set exactly while awaiting permission",
            ));
        }
        if self.state.is_terminal() == self.ended_at.is_none() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "ended_at must be set exactly for terminal states",
            ));
        }
        if matches!(
            self.state,
            State::Succeeded
                | State::Failed
                | State::Interrupted
                | State::Killed
                | State::BudgetExhausted
        ) {
            match self.terminal.state() {
                Ok(to) if to == self.state => {}
                _ => {
                    return Err(Failure::invalid(
                        codes::INVALID_ATTEMPT,
                        format!("terminal does not match state {}", self.state.as_str()),
                    ));
                }
            }
        } else if !self.terminal.is_zero() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("terminal set on {} attempt", self.state.as_str()),
            ));
        }
        if matches!(self.state, State::Ambiguous | State::Resolved)
            != !self.ambiguity_reason.is_empty()
        {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "ambiguity reason must be set exactly for ambiguous and resolved",
            ));
        }
        if self.state == State::Resolved {
            self.resolution.validate()?;
        } else if !self.resolution.is_zero() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("resolution set on {} attempt", self.state.as_str()),
            ));
        }
        if self.resume_of.is_none() != self.resume_session_id.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "resume_of and resume_session_id must be set together",
            ));
        }
        self.usage.validate()
    }

    fn guard(&self, fence: Fence, at: OffsetDateTime) -> Result<(), Failure> {
        if fence != self.fence {
            return Err(Failure::conflict(codes::FENCE_MISMATCH, "fence mismatch"));
        }
        if is_zero_time(at) {
            return Err(Failure::invalid(codes::INVALID_ATTEMPT, "zero timestamp"));
        }
        if at < self.updated_at {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "timestamp is before the last update",
            ));
        }
        Ok(())
    }

    /// Upstream `Equal`: value equality over every field.
    /// `terminal.exit_code` is compared by value, and times at
    /// microsecond precision (PostgreSQL timestamptz), so an attempt
    /// stored and loaded again is `equal` to the one written.
    #[must_use]
    pub fn equal(&self, b: &Attempt) -> bool {
        self.id == b.id
            && self.workspace_id == b.workspace_id
            && self.run_id == b.run_id
            && self.kind == b.kind
            && self.adapter_version == b.adapter_version
            && self.harness_version == b.harness_version
            && self.harness_session_id == b.harness_session_id
            && self.resume_of == b.resume_of
            && self.resume_session_id == b.resume_session_id
            && self.workspace == b.workspace
            && self.permission == b.permission
            && self.sandbox_scope_id == b.sandbox_scope_id
            && self.fence == b.fence
            && self.version == b.version
            && self.state == b.state
            && self.pending_permission == b.pending_permission
            && self.terminal == b.terminal
            && self.resolution == b.resolution
            && self.ambiguity_reason == b.ambiguity_reason
            && self.last_event_seq == b.last_event_seq
            && self.usage == b.usage
            && self.budget == b.budget
            && equal_micros(self.prepared_at, b.prepared_at)
            && equal_micros(self.updated_at, b.updated_at)
            && option_micros(self.ended_at, b.ended_at)
    }

    fn move_to(&self, to: State, at: OffsetDateTime) -> Result<Self, Failure> {
        if !self.state.can_transition(to) {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!("{} -> {}", self.state.as_str(), to.as_str()),
            ));
        }
        let mut next = self.clone();
        next.state = to;
        next.updated_at = at;
        if to.is_terminal() {
            next.ended_at = Some(at);
        }
        Ok(next)
    }

    fn checked(self) -> Result<Self, Failure> {
        self.validate()?;
        Ok(self)
    }
}

/// Instant equality at microsecond precision — upstream `equalMicros`
/// (`a.Truncate(time.Microsecond).Equal(...)`): PostgreSQL timestamptz
/// resolution, and zone-independent.
fn equal_micros(a: OffsetDateTime, b: OffsetDateTime) -> bool {
    a.unix_timestamp_nanos() / 1_000 == b.unix_timestamp_nanos() / 1_000
}

/// `equalMicros` over optional times; `None` stands in for the Go zero
/// time.
fn option_micros(a: Option<OffsetDateTime>, b: Option<OffsetDateTime>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => equal_micros(a, b),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use central_foundation::failure::Failure;
    use central_foundation::identity::{HarnessAttemptId, RunId, WorkspaceId};
    use time::Duration;

    use super::*;
    use crate::domain::{
        Fence, Kind, PermissionPolicy, Resolution, ResolutionKind, State, Terminal, TerminalStatus,
        codes,
    };
    use crate::event::{Usage, UsageScope};
    use crate::testkit::{
        FENCE, FallibleMutation, Mutation, is_code, nil_attempt_id, nil_run_id, nil_workspace_id,
        ok, prepare_input, running, t0,
    };

    fn stale() -> Fence {
        Fence { generation: 2 }
    }

    // Ports upstream `TestPrepareValidatesInput`.
    #[test]
    fn prepare_validates_input() {
        let input = prepare_input();
        let a = ok(Attempt::prepare(prepare_input()));
        assert_eq!(a.state, State::Prepared);
        assert_eq!(a.prepared_at, t0());
        assert!(a.ended_at.is_none());
        assert_eq!(a.version, 0);
        assert_eq!(a.workspace_id, input.workspace_id);
        let mutations: [Mutation<PrepareInput>; 9] = [
            ("zero id", |i| i.id = nil_attempt_id()),
            ("zero workspace", |i| i.workspace_id = nil_workspace_id()),
            ("zero run", |i| i.run_id = nil_run_id()),
            ("bad kind", |i| i.kind = Kind::new("Claude Code")),
            ("no adapter ver", |i| i.adapter_version = String::new()),
            ("no base sha", |i| i.workspace.base_sha = String::new()),
            ("bad permission", |i| {
                i.permission = PermissionPolicy::parse("yolo")
            }),
            ("zero fence", |i| i.fence = Fence { generation: 0 }),
            ("zero timestamp", |i| i.at = crate::domain::ZERO_TIME),
        ];
        for (name, mutate) in mutations {
            let mut input = prepare_input();
            mutate(&mut input);
            let err = Attempt::prepare(input).unwrap_err();
            assert!(is_code(&err, codes::INVALID_ATTEMPT), "{name}: err = {err}");
        }
    }

    // Ports upstream `TestHappyPathToSucceeded`.
    #[test]
    fn happy_path_to_succeeded() {
        let a = running();
        let a = ok(a.await_permission(FENCE, "perm-1", t0() + Duration::seconds(3)));
        assert_eq!(a.state, State::AwaitingPermission);
        assert_eq!(a.pending_permission, "perm-1");
        let a = ok(a.resolve_permission(FENCE, "perm-1", t0() + Duration::seconds(4)));
        let a = ok(a.record_progress(FENCE, 5, t0() + Duration::seconds(5)));
        let a = ok(a.apply_usage(
            FENCE,
            Usage {
                tokens_in: 10,
                scope: UsageScope::SessionCumulative,
                ..Usage::default()
            },
            t0() + Duration::seconds(5),
        ));
        let a = ok(a.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            },
            t0() + Duration::seconds(6),
        ));
        assert_eq!(a.state, State::Succeeded);
        assert_eq!(a.ended_at, Some(t0() + Duration::seconds(6)));
        assert_eq!(a.pending_permission, "");
        assert_eq!(a.harness_session_id, "sess-1");
        assert_eq!(a.sandbox_scope_id, "scope-1");
        assert_eq!(a.harness_version, "2.1.0");
        assert_eq!(a.last_event_seq, 5);
    }

    // Ports upstream
    // `TestMutatorsRejectWrongFenceAndLeaveReceiverUnchanged`.
    #[test]
    fn mutators_reject_wrong_fence_and_leave_receiver_unchanged() {
        let a = running();
        let before = a.clone();
        let checks: [FallibleMutation<'_, Attempt>; 8] = [
            ("await", &|a| a.await_permission(stale(), "p", t0())),
            ("progress", &|a| a.record_progress(stale(), 9, t0())),
            ("terminate", &|a| {
                a.terminate(
                    stale(),
                    Terminal {
                        status: TerminalStatus::Failed,
                        ..Terminal::default()
                    },
                    t0(),
                )
            }),
            ("ambiguous", &|a| a.mark_ambiguous(stale(), "lost", t0())),
            ("apply usage", &|a| {
                a.apply_usage(
                    stale(),
                    Usage {
                        tokens_in: 5,
                        scope: UsageScope::Step,
                        ..Usage::default()
                    },
                    t0(),
                )
            }),
            ("refence", &|a| {
                a.refence(stale(), Fence { generation: 3 }, t0())
            }),
            ("reveal", &|a| a.reveal_session(stale(), "sess-1", t0())),
            ("resolve permission", &|a| {
                a.resolve_permission(stale(), "p", t0())
            }),
        ];
        for (name, call) in checks {
            let err = call(&a).unwrap_err();
            assert!(is_code(&err, codes::FENCE_MISMATCH), "{name}: err = {err}");
        }
        assert_eq!(a, before, "receiver was modified");
        // Launch on prepared and Resolve on ambiguous with a stale fence.
        let prepared = ok(Attempt::prepare(prepare_input()));
        let err = prepared.launch(stale(), "scope", "1", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::FENCE_MISMATCH),
            "launch on prepared with stale fence: {err}"
        );
        let ambiguous = ok(running().mark_ambiguous(FENCE, "lost", t0()));
        let err = ambiguous
            .resolve(
                stale(),
                Resolution {
                    kind: ResolutionKind::Abandon,
                    decided_by: "op".to_string(),
                },
                t0(),
            )
            .unwrap_err();
        assert!(
            is_code(&err, codes::FENCE_MISMATCH),
            "resolve on ambiguous with stale fence: {err}"
        );
    }

    // Ports upstream `TestInvalidTransitionsAreRejected`.
    #[test]
    fn invalid_transitions_are_rejected() {
        let prepared = ok(Attempt::prepare(prepare_input()));
        let err = prepared.reveal_session(FENCE, "s", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "prepared reveal: {err}"
        );
        let launching = ok(prepared.launch(FENCE, "scope", "1", t0()));
        for status in [TerminalStatus::Succeeded, TerminalStatus::Budget] {
            let err = launching
                .terminate(
                    FENCE,
                    Terminal {
                        status,
                        ..Terminal::default()
                    },
                    t0(),
                )
                .unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_TRANSITION),
                "launching {status}: {err}"
            );
        }
        let done = ok(running().terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Failed,
                ..Terminal::default()
            },
            t0(),
        ));
        let err = done.mark_ambiguous(FENCE, "late", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "terminal ambiguous: {err}"
        );
        let err = done.record_progress(FENCE, 99, t0()).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "terminal progress: {err}"
        );
        let err = done
            .refence(FENCE, Fence { generation: 2 }, t0())
            .unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "terminal refence: {err}"
        );
    }

    // Ports upstream `TestRevealSessionIsIdempotentForSameID`.
    #[test]
    fn reveal_session_is_idempotent_for_same_id() {
        let a = running();
        let again = ok(a.reveal_session(FENCE, "sess-1", t0() + Duration::minutes(1)));
        assert_eq!(again, a, "same-id reveal changed the attempt");
        let err = a.reveal_session(FENCE, "sess-2", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::SESSION_MISMATCH),
            "different id: {err}"
        );
        let awaiting = ok(a.await_permission(FENCE, "perm-1", t0()));
        let again = ok(awaiting.reveal_session(FENCE, "sess-1", t0() + Duration::hours(1)));
        assert_eq!(
            again, awaiting,
            "same-id reveal while awaiting permission changed the attempt"
        );
    }

    // Ports upstream `TestRevealSessionOnResumeRequiresTheResumedID`.
    #[test]
    fn reveal_session_on_resume_requires_the_resumed_id() {
        let prev = ok(running().terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            },
            t0(),
        ));
        let mut input = prepare_input();
        input.run_id = prev.run_id;
        input.kind = prev.kind.clone();
        input.workspace = prev.workspace.clone();
        let resumed = ok(Attempt::prepare_resume(&prev, input));
        let launched = ok(resumed.launch(FENCE, "scope-2", "2.1.0", t0()));
        let err = launched
            .reveal_session(FENCE, "sess-fresh", t0())
            .unwrap_err();
        assert!(
            is_code(&err, codes::SESSION_MISMATCH),
            "different id on resume: {err}"
        );
        let got = ok(launched.reveal_session(FENCE, "sess-1", t0()));
        assert_eq!(got.state, State::Running);
        assert_eq!(got.harness_session_id, "sess-1");
        // A fresh (non-resume) attempt may reveal any id.
        let fresh =
            ok(ok(Attempt::prepare(prepare_input())).launch(FENCE, "scope-3", "2.1.0", t0()));
        assert!(fresh.reveal_session(FENCE, "sess-anything", t0()).is_ok());
    }

    // Ports upstream `TestResolvePermissionRequiresMatchingRequest`.
    #[test]
    fn resolve_permission_requires_matching_request() {
        let a = ok(running().await_permission(FENCE, "perm-1", t0()));
        let err = a.resolve_permission(FENCE, "perm-2", t0()).unwrap_err();
        assert!(is_code(&err, codes::PERMISSION_MISMATCH), "{err}");
    }

    // Ports upstream `TestResolvePermissionRequiresAwaitingState`.
    #[test]
    fn resolve_permission_requires_awaiting_state() {
        let prepared = ok(Attempt::prepare(prepare_input()));
        let launched = ok(prepared.launch(FENCE, "scope", "1", t0()));
        let err = launched
            .resolve_permission(FENCE, "perm-1", t0())
            .unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "launched state: {err}"
        );
        let a = running();
        let err = a.resolve_permission(FENCE, "perm-1", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "running state: {err}"
        );
    }

    // Ports upstream `TestRecordProgressOrdering`.
    #[test]
    fn record_progress_ordering() {
        let a = ok(running().record_progress(FENCE, 3, t0()));
        let same = ok(a.record_progress(FENCE, 3, t0() + Duration::hours(1)));
        assert_eq!(same, a, "equal seq was not a no-op");
        let err = a.record_progress(FENCE, 2, t0()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "lower seq: {err}");
        let err = a.record_progress(FENCE, 0, t0()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "zero seq: {err}");
        let with_usage = ok(a.apply_usage(
            FENCE,
            Usage {
                tokens_in: 5,
                scope: UsageScope::Run,
                ..Usage::default()
            },
            t0(),
        ));
        let next = ok(with_usage.record_progress(FENCE, 4, t0()));
        assert_eq!(next.usage, with_usage.usage);
        assert_eq!(next.last_event_seq, 4);
    }

    // Ports upstream `TestApplyUsageCumulativeRules`.
    #[test]
    fn apply_usage_cumulative_rules() {
        let step = |tokens_in: i64, tokens_out: i64| Usage {
            tokens_in,
            tokens_out,
            scope: UsageScope::Step,
            ..Usage::default()
        };
        let a = ok(running().apply_usage(FENCE, step(10, 1), t0()));
        assert_eq!(a.usage, step(10, 1), "first report not adopted");
        let a = ok(a.apply_usage(
            FENCE,
            Usage {
                tokens_in: 5,
                cache_read: 2,
                cache_write: 3,
                cost_micro_usd: 7,
                scope: UsageScope::Step,
                estimated: true,
                ..Usage::default()
            },
            t0(),
        ));
        let want = Usage {
            tokens_in: 15,
            tokens_out: 1,
            cache_read: 2,
            cache_write: 3,
            cost_micro_usd: 7,
            scope: UsageScope::Step,
            estimated: true,
        };
        assert_eq!(a.usage, want, "step did not accumulate");
        let a = ok(a.apply_usage(FENCE, step(1, 0), t0()));
        assert!(a.usage.estimated, "Estimated is not sticky");
        let err = a
            .apply_usage(
                FENCE,
                Usage {
                    tokens_in: 100,
                    scope: UsageScope::Run,
                    ..Usage::default()
                },
                t0(),
            )
            .unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "scope change: {err}");

        for scope in [UsageScope::Run, UsageScope::SessionCumulative] {
            let r = ok(running().apply_usage(
                FENCE,
                Usage {
                    tokens_in: 10,
                    tokens_out: 4,
                    scope,
                    estimated: true,
                    ..Usage::default()
                },
                t0(),
            ));
            let r = ok(r.apply_usage(
                FENCE,
                Usage {
                    tokens_in: 12,
                    tokens_out: 4,
                    scope,
                    ..Usage::default()
                },
                t0(),
            ));
            let want = Usage {
                tokens_in: 12,
                tokens_out: 4,
                scope,
                estimated: true,
                ..Usage::default()
            };
            assert_eq!(r.usage, want, "{scope} did not replace (sticky estimate)");
            for (name, report) in [
                (
                    "tokens in",
                    Usage {
                        tokens_in: 11,
                        tokens_out: 4,
                        scope,
                        ..Usage::default()
                    },
                ),
                (
                    "tokens out",
                    Usage {
                        tokens_in: 12,
                        tokens_out: 3,
                        scope,
                        ..Usage::default()
                    },
                ),
                (
                    "cache read",
                    Usage {
                        tokens_in: 12,
                        tokens_out: 4,
                        cache_read: -1,
                        scope,
                        ..Usage::default()
                    },
                ),
                (
                    "zero report",
                    Usage {
                        scope,
                        ..Usage::default()
                    },
                ),
            ] {
                let err = r.apply_usage(FENCE, report, t0()).unwrap_err();
                assert!(
                    is_code(&err, codes::INVALID_EVENT),
                    "{scope} decrease {name}: {err}"
                );
            }
        }

        let r = running();
        let same = ok(r.apply_usage(FENCE, Usage::default(), t0() + Duration::hours(1)));
        assert_eq!(same, r, "an empty report changed the attempt");
        let s = ok(r.apply_usage(FENCE, step(3, 0), t0()));
        let same = ok(s.apply_usage(FENCE, step(0, 0), t0() + Duration::hours(1)));
        assert_eq!(same, s, "a report that changes nothing was not a no-op");
        let err = r
            .apply_usage(
                FENCE,
                Usage {
                    tokens_in: 1,
                    ..Usage::default()
                },
                t0(),
            )
            .unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "scopeless: {err}");
        let err = r
            .apply_usage(Fence { generation: 9 }, step(1, 0), t0())
            .unwrap_err();
        assert!(is_code(&err, codes::FENCE_MISMATCH), "stale fence: {err}");
        let done = ok(r.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            },
            t0(),
        ));
        let err = done.apply_usage(FENCE, step(1, 0), t0()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_TRANSITION), "terminal: {err}");
        let prepared = ok(Attempt::prepare(prepare_input()));
        let err = prepared.apply_usage(FENCE, step(1, 0), t0()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_TRANSITION), "prepared: {err}");
        let overflow = ok(r.apply_usage(
            FENCE,
            Usage {
                tokens_in: i64::MAX,
                scope: UsageScope::Step,
                ..Usage::default()
            },
            t0(),
        ));
        let err = overflow.apply_usage(FENCE, step(1, 0), t0()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "overflow: {err}");
    }

    // Ports upstream `TestApplyUsageCumulativeCounterDecreases`.
    #[test]
    fn apply_usage_cumulative_counter_decreases() {
        for scope in [UsageScope::Run, UsageScope::SessionCumulative] {
            let base_report = Usage {
                tokens_in: 10,
                tokens_out: 2,
                cache_read: 10,
                cache_write: 10,
                cost_micro_usd: 10,
                scope,
                estimated: false,
            };
            let cases: [(&str, Usage); 3] = [
                (
                    "cache read decrease",
                    Usage {
                        cache_read: 5,
                        ..base_report
                    },
                ),
                (
                    "cache write decrease",
                    Usage {
                        cache_write: 5,
                        ..base_report
                    },
                ),
                (
                    "cost micro usd decrease",
                    Usage {
                        cost_micro_usd: 5,
                        ..base_report
                    },
                ),
            ];
            for (name, report) in cases {
                let r = ok(running().apply_usage(FENCE, base_report, t0()));
                let err = r.apply_usage(FENCE, report, t0()).unwrap_err();
                assert!(is_code(&err, codes::INVALID_EVENT), "{scope} {name}: {err}");
            }
        }
    }

    // Ports upstream `TestTerminateMapsMaxTurnsToFailedAndKeepsStatus`.
    #[test]
    fn terminate_maps_max_turns_to_failed_and_keeps_status() {
        let a = ok(running().terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::MaxTurns,
                ..Terminal::default()
            },
            t0(),
        ));
        assert_eq!(a.state, State::Failed);
        assert_eq!(a.terminal.status, TerminalStatus::MaxTurns);
        let awaiting = ok(running().await_permission(FENCE, "p", t0()));
        let killed = ok(awaiting.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Killed,
                ..Terminal::default()
            },
            t0(),
        ));
        assert_eq!(killed.pending_permission, "");
    }

    // Ports upstream `TestAmbiguityAndResolution`.
    #[test]
    fn ambiguity_and_resolution() {
        let a = ok(running().mark_ambiguous(FENCE, "scope lost after restart", t0()));
        assert_eq!(a.state, State::Ambiguous);
        assert!(!a.state.is_terminal());
        let err = a.mark_ambiguous(FENCE, "again", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_TRANSITION),
            "double ambiguous: {err}"
        );
        let err = a
            .resolve(
                FENCE,
                Resolution {
                    kind: ResolutionKind::Resume,
                    decided_by: String::new(),
                },
                t0(),
            )
            .unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_ATTEMPT),
            "resolve without decider: {err}"
        );
        let r = ok(a.resolve(
            FENCE,
            Resolution {
                kind: ResolutionKind::Resume,
                decided_by: "operator".to_string(),
            },
            t0(),
        ));
        assert_eq!(r.state, State::Resolved);
        assert_ne!(r.ambiguity_reason, "");
        assert!(r.ended_at.is_some());
        let err = running().mark_ambiguous(FENCE, "", t0()).unwrap_err();
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "empty reason: {err}");
        // MarkAmbiguous from awaiting_permission clears the pending request.
        let awaiting = ok(running().await_permission(FENCE, "perm-9", t0()));
        let amb = ok(awaiting.mark_ambiguous(FENCE, "lost", t0()));
        assert_eq!(amb.pending_permission, "");
    }

    // Ports upstream `TestRefenceIsStrictlyMonotonic`.
    #[test]
    fn refence_is_strictly_monotonic() {
        let a = running();
        let err = a.refence(FENCE, Fence { generation: 1 }, t0()).unwrap_err();
        assert!(is_code(&err, codes::FENCE_MISMATCH), "equal: {err}");
        let next = Fence { generation: 7 };
        let b = ok(a.refence(FENCE, next, t0()));
        assert_eq!(b.fence, next, "fence not rotated");
        let err = b.await_permission(FENCE, "p", t0()).unwrap_err();
        assert!(
            is_code(&err, codes::FENCE_MISMATCH),
            "old fence still accepted"
        );
    }

    // Ports upstream `TestPrepareResumePreconditions`.
    #[test]
    fn prepare_resume_preconditions() {
        let succeeded = ok(running().terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            },
            t0(),
        ));
        let mut input = prepare_input();
        input.run_id = succeeded.run_id;
        input.kind = succeeded.kind.clone();
        input.workspace = succeeded.workspace.clone();
        let resumed = ok(Attempt::prepare_resume(&succeeded, input.clone()));
        assert_eq!(resumed.resume_of, Some(succeeded.id));
        assert_eq!(resumed.resume_session_id, "sess-1");
        assert_eq!(resumed.state, State::Prepared);
        assert_eq!(resumed.workspace_id, succeeded.workspace_id);

        let not_terminal = running();
        let err = Attempt::prepare_resume(&not_terminal, input.clone()).unwrap_err();
        assert!(
            is_code(&err, codes::RESUME_NOT_ALLOWED),
            "non-terminal: {err}"
        );
        let launching = ok(ok(Attempt::prepare(prepare_input())).launch(FENCE, "s", "1", t0()));
        let no_session = ok(launching.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Failed,
                ..Terminal::default()
            },
            t0(),
        ));
        let mut in2 = input.clone();
        in2.run_id = no_session.run_id;
        in2.kind = no_session.kind.clone();
        in2.workspace = no_session.workspace.clone();
        let err = Attempt::prepare_resume(&no_session, in2).unwrap_err();
        assert!(
            is_code(&err, codes::RESUME_NOT_ALLOWED),
            "no session id: {err}"
        );
        let ambiguous = ok(running().mark_ambiguous(FENCE, "lost", t0()));
        let rerun = ok(ambiguous.resolve(
            FENCE,
            Resolution {
                kind: ResolutionKind::Rerun,
                decided_by: "op".to_string(),
            },
            t0(),
        ));
        let mut in3 = input.clone();
        in3.run_id = rerun.run_id;
        in3.kind = rerun.kind.clone();
        in3.workspace = rerun.workspace.clone();
        let err = Attempt::prepare_resume(&rerun, in3).unwrap_err();
        assert!(
            is_code(&err, codes::RESUME_NOT_ALLOWED),
            "resolved as rerun: {err}"
        );
        let mut other = input.clone();
        other.run_id = RunId::new();
        let err = Attempt::prepare_resume(&succeeded, other).unwrap_err();
        assert!(
            is_code(&err, codes::RESUME_NOT_ALLOWED),
            "different run: {err}"
        );
    }

    // Ports upstream `TestResolveResumeRequiresHarnessSessionID`
    // (finding I2).
    #[test]
    fn resolve_resume_requires_harness_session_id() {
        let launching =
            ok(ok(Attempt::prepare(prepare_input())).launch(FENCE, "scope-1", "1.0.0", t0()));
        let ambiguous = ok(launching.mark_ambiguous(FENCE, "lost before session revealed", t0()));
        assert_eq!(ambiguous.harness_session_id, "");
        let err = ambiguous
            .resolve(
                FENCE,
                Resolution {
                    kind: ResolutionKind::Resume,
                    decided_by: "operator".to_string(),
                },
                t0(),
            )
            .unwrap_err();
        assert!(
            is_code(&err, codes::RESUME_NOT_ALLOWED),
            "resolve resume without session id: {err}"
        );
        assert!(
            ambiguous
                .resolve(
                    FENCE,
                    Resolution {
                        kind: ResolutionKind::Rerun,
                        decided_by: "operator".to_string(),
                    },
                    t0(),
                )
                .is_ok()
        );
    }

    // Ports upstream `TestValidateRejectsInconsistentAttempts`.
    #[test]
    fn validate_rejects_inconsistent_attempts() {
        let base = running();
        let mutations: [Mutation<Attempt>; 11] = [
            ("running without session", |a| {
                a.harness_session_id = String::new()
            }),
            ("pending while running", |a| {
                a.pending_permission = "p".to_string()
            }),
            ("ended while running", |a| a.ended_at = Some(t0())),
            ("terminal while running", |a| {
                a.terminal = Terminal {
                    status: TerminalStatus::Failed,
                    ..Terminal::default()
                };
            }),
            ("resolution while running", |a| {
                a.resolution = Resolution {
                    kind: ResolutionKind::Abandon,
                    decided_by: "op".to_string(),
                };
            }),
            ("reason while running", |a| {
                a.ambiguity_reason = "x".to_string()
            }),
            ("half resume link", |a| {
                a.resume_session_id = "s0".to_string()
            }),
            ("unknown state", |a| a.state = State::Unknown),
            ("bad usage", |a| {
                a.usage = Usage {
                    tokens_in: 1,
                    ..Usage::default()
                };
            }),
            ("zero workspace id", |a| a.workspace_id = nil_workspace_id()),
            ("negative version", |a| a.version = -1),
        ];
        for (name, mutate) in mutations {
            let mut a = base.clone();
            mutate(&mut a);
            assert!(a.validate().is_err(), "{name}: accepted");
        }
    }

    // Ports upstream `TestPrepareResumeRequiresSameWorkspaceAndMonotoneFence`.
    #[test]
    fn prepare_resume_requires_same_workspace_and_monotone_fence() {
        let prev = ok(running().refence(FENCE, Fence { generation: 3 }, t0()));
        let prev = ok(prev.terminate(
            Fence { generation: 3 },
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            },
            t0(),
        ));
        let mut input = prepare_input();
        input.run_id = prev.run_id;
        input.kind = prev.kind.clone();
        input.workspace = prev.workspace.clone();
        input.fence = Fence { generation: 3 };
        assert!(
            Attempt::prepare_resume(&prev, input.clone()).is_ok(),
            "equal generation"
        );
        input.fence = Fence { generation: 4 };
        assert!(
            Attempt::prepare_resume(&prev, input.clone()).is_ok(),
            "greater generation"
        );
        input.fence = Fence { generation: 2 };
        let err = Attempt::prepare_resume(&prev, input.clone()).unwrap_err();
        assert!(
            is_code(&err, codes::FENCE_MISMATCH),
            "lower generation: {err}"
        );
        input.fence = Fence { generation: 3 };
        input.workspace_id = WorkspaceId::new();
        let err = Attempt::prepare_resume(&prev, input).unwrap_err();
        assert!(
            is_code(&err, codes::RESUME_NOT_ALLOWED),
            "other workspace: {err}"
        );
    }

    // Ports upstream `TestMutatorsRejectTimestampsBeforeUpdatedAt`.
    #[test]
    fn mutators_reject_timestamps_before_updated_at() {
        let a = ok(running().await_permission(FENCE, "p", t0() + Duration::minutes(1)));
        let earlier = t0() + Duration::seconds(1);
        let checks: [FallibleMutation<'_, Attempt>; 6] = [
            ("resolve permission", &|a| {
                a.resolve_permission(FENCE, "p", earlier)
            }),
            ("progress", &|a| a.record_progress(FENCE, 9, earlier)),
            ("terminate", &|a| {
                a.terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Failed,
                        ..Terminal::default()
                    },
                    earlier,
                )
            }),
            ("ambiguous", &|a| a.mark_ambiguous(FENCE, "lost", earlier)),
            ("refence", &|a| {
                a.refence(FENCE, Fence { generation: 2 }, earlier)
            }),
            ("reveal", &|a| a.reveal_session(FENCE, "sess-1", earlier)),
        ];
        for (name, call) in checks {
            let err = call(&a).unwrap_err();
            assert!(is_code(&err, codes::INVALID_ATTEMPT), "{name}: err = {err}");
        }
        let prepared = ok(Attempt::prepare(prepare_input()));
        let err = prepared
            .launch(FENCE, "scope", "1", t0() - Duration::nanoseconds(1))
            .unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_ATTEMPT),
            "launch before prepare: {err}"
        );
        // An equal timestamp is not time travel.
        assert!(a.resolve_permission(FENCE, "p", a.updated_at).is_ok());
    }

    // Ports upstream `TestMutatorsNeverChangeVersion`.
    #[test]
    fn mutators_never_change_version() {
        let mut a = running();
        a.version = 7;
        let steps: [&dyn Fn(Attempt) -> Result<Attempt, Failure>; 7] = [
            &|a| a.await_permission(FENCE, "p", t0()),
            &|a| a.resolve_permission(FENCE, "p", t0()),
            &|a| a.record_progress(FENCE, 2, t0()),
            &|a| {
                a.apply_usage(
                    FENCE,
                    Usage {
                        tokens_in: 5,
                        scope: UsageScope::Step,
                        ..Usage::default()
                    },
                    t0(),
                )
            },
            &|a| a.refence(FENCE, Fence { generation: 2 }, t0()),
            &|a| a.mark_ambiguous(Fence { generation: 2 }, "lost", t0()),
            &|a| {
                a.resolve(
                    Fence { generation: 2 },
                    Resolution {
                        kind: ResolutionKind::Resume,
                        decided_by: "op".to_string(),
                    },
                    t0(),
                )
            },
        ];
        for (i, step) in steps.iter().enumerate() {
            a = ok(step(a));
            assert_eq!(a.version, 7, "step {i} changed version");
        }
        let mut launched = ok(Attempt::prepare(prepare_input()));
        launched.version = 3;
        let got = ok(launched.launch(FENCE, "scope", "1", t0()));
        assert_eq!(got.version, 3, "launch changed version");
    }

    // Ports upstream `TestValidateRequiresLaunchFieldsOnceLaunched`.
    #[test]
    fn validate_requires_launch_fields_once_launched() {
        let awaiting = ok(running().await_permission(FENCE, "p", t0()));
        let launched_only: [(&str, Attempt); 7] = [
            (
                "launching",
                ok(ok(Attempt::prepare(prepare_input())).launch(FENCE, "scope", "1", t0())),
            ),
            ("running", running()),
            ("awaiting_permission", awaiting),
            (
                "succeeded",
                ok(running().terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Succeeded,
                        ..Terminal::default()
                    },
                    t0(),
                )),
            ),
            (
                "interrupted",
                ok(running().terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Interrupted,
                        ..Terminal::default()
                    },
                    t0(),
                )),
            ),
            (
                "killed",
                ok(running().terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Killed,
                        ..Terminal::default()
                    },
                    t0(),
                )),
            ),
            (
                "budget_exhausted",
                ok(running().terminate(
                    FENCE,
                    Terminal {
                        status: TerminalStatus::Budget,
                        ..Terminal::default()
                    },
                    t0(),
                )),
            ),
        ];
        for (name, a) in launched_only {
            let mut no_scope = a.clone();
            no_scope.sandbox_scope_id = String::new();
            let err = no_scope.validate().unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_ATTEMPT),
                "{name} without sandbox scope: {err}"
            );
            let mut no_version = a.clone();
            no_version.harness_version = String::new();
            let err = no_version.validate().unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_ATTEMPT),
                "{name} without harness version: {err}"
            );
        }
        // failed, ambiguous and resolved are reachable straight from
        // prepared, before any launch, so they stay valid without launch
        // fields.
        let prepared = ok(Attempt::prepare(prepare_input()));
        let failed = ok(prepared.terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Failed,
                ..Terminal::default()
            },
            t0(),
        ));
        let ambiguous = ok(prepared.mark_ambiguous(FENCE, "lost before launch", t0()));
        let resolved = ok(ambiguous.resolve(
            FENCE,
            Resolution {
                kind: ResolutionKind::Abandon,
                decided_by: "op".to_string(),
            },
            t0(),
        ));
        for (name, a) in [
            ("failed", failed),
            ("ambiguous", ambiguous),
            ("resolved", resolved),
        ] {
            assert_eq!(a.sandbox_scope_id, "", "{name}: test setup launched");
            assert_eq!(a.harness_version, "", "{name}: test setup launched");
            assert!(a.validate().is_ok(), "{name} from prepared");
        }
    }

    // Ports upstream `TestEqualIsValueEqualityOverEveryField`. The
    // upstream reflect-driven "every field has a case" sweep has no Rust
    // equivalent; the table is kept field-complete by hand.
    #[test]
    fn equal_is_value_equality_over_every_field() {
        let mut base = ok(running().terminate(
            FENCE,
            Terminal {
                status: TerminalStatus::Failed,
                reason: "boom".to_string(),
                exit_code: Some(3),
            },
            t0() + Duration::seconds(1),
        ));
        base.version = 4;
        base.usage = Usage {
            tokens_in: 1,
            scope: UsageScope::Run,
            ..Usage::default()
        };

        let mut same = base.clone();
        same.terminal.exit_code = Some(3);
        same.prepared_at = base.prepared_at + Duration::nanoseconds(999);
        same.updated_at = base
            .updated_at
            .to_offset(time::UtcOffset::from_hms(1, 0, 0).unwrap());
        assert!(base.equal(&same) && same.equal(&base));

        let mutations: [Mutation<Attempt>; 27] = [
            ("ID", |a| a.id = HarnessAttemptId::new()),
            ("WorkspaceID", |a| a.workspace_id = WorkspaceId::new()),
            ("RunID", |a| a.run_id = RunId::new()),
            ("Kind", |a| a.kind = Kind::new("other")),
            ("AdapterVersion", |a| a.adapter_version = "9".to_string()),
            ("HarnessVersion", |a| a.harness_version = "9".to_string()),
            ("HarnessSessionID", |a| {
                a.harness_session_id = "other".to_string()
            }),
            ("ResumeOf", |a| a.resume_of = Some(HarnessAttemptId::new())),
            ("ResumeSessionID", |a| {
                a.resume_session_id = "other".to_string()
            }),
            ("Workspace", |a| a.workspace.base_sha = "other".to_string()),
            ("Permission", |a| a.permission = PermissionPolicy::Deny),
            ("SandboxScopeID", |a| {
                a.sandbox_scope_id = "other".to_string()
            }),
            ("Fence", |a| a.fence = Fence { generation: 9 }),
            ("Version", |a| a.version = 5),
            ("State", |a| a.state = State::Killed),
            ("PendingPermission", |a| {
                a.pending_permission = "p".to_string()
            }),
            ("Terminal", |a| a.terminal.exit_code = Some(4)),
            ("Terminal.nil", |a| a.terminal.exit_code = None),
            ("Terminal.Reason", |a| {
                a.terminal.reason = "other".to_string()
            }),
            ("Resolution", |a| a.resolution.decided_by = "op".to_string()),
            ("AmbiguityReason", |a| a.ambiguity_reason = "x".to_string()),
            ("LastEventSeq", |a| a.last_event_seq = 99),
            ("Usage", |a| a.usage.estimated = true),
            ("Budget", |a| {
                a.budget.cost_defaulted = !a.budget.cost_defaulted
            }),
            ("PreparedAt", |a| a.prepared_at += Duration::microseconds(1)),
            ("UpdatedAt", |a| a.updated_at += Duration::microseconds(1)),
            ("EndedAt", |a| a.ended_at = None),
        ];
        for (name, mutate) in mutations {
            let mut b = base.clone();
            mutate(&mut b);
            assert!(
                !base.equal(&b) && !b.equal(&base),
                "{name}: differing attempts compared equal"
            );
        }
    }

    // Ports upstream `TestPersistenceSentinelsAreDistinct`.
    #[test]
    fn persistence_sentinels_are_distinct() {
        let sentinels = [
            codes::ATTEMPT_NOT_FOUND,
            codes::VERSION_CONFLICT,
            codes::LIVE_ATTEMPT_EXISTS,
            codes::EVENT_CONFLICT,
            codes::FENCE_MISMATCH,
            codes::INVALID_ATTEMPT,
        ];
        for (i, a) in sentinels.iter().enumerate() {
            for (j, b) in sentinels.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "{a} matches {b}");
                }
            }
        }
    }
}
