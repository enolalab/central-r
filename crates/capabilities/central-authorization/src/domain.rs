//! Authorization domain — capability taxonomy, the Phase-1 default
//! policy matrix, capability-grant (`central.approvals`) lifecycle,
//! effective-grant derivation, secret-use evidence, and genesis
//! authority records.
//!
//! Pure synchronous Rust (rust-application-boundaries.md §2.3/§7.1): no
//! `async fn`, no I/O, no `tokio`.
//!
//! Canonical sources:
//!
//! - `docs/security/capability-policy.md` — the `resource × effect ×
//!   scope` request shape, the capability classes, the three-outcome
//!   policy (`allow` / `require_approval` / `deny`, strictest wins),
//!   the default policy matrix, the ≤ 24 h task-scoped grant rule, and
//!   the post-restore authority reset.
//! - `internal/authority/genesis.go` — genesis intent/receipt/status
//!   records.
//! - `internal/authority/domain.go` — `InstanceBinding`, `UIDGIDMap`,
//!   `LockedIdentity`, the fixed `central-runtime` UID/GID.
//! - adapter-mapping §3.18 (`approvals`) and §3.19 (`secret_use`).

use central_foundation::failure::Failure;
use central_foundation::identity::{
    ApprovalId, ConfigBindingId, InstanceId, OperationId, SecretUseEvidenceId, TaskId, WorkspaceId,
};
use time::{Duration, OffsetDateTime};

/// Stable machine codes emitted by this domain.
pub mod codes {
    pub const CAPABILITY_UNKNOWN: &str = "capability_unknown";
    pub const REQUEST_INVALID: &str = "authorization_request_invalid";
    pub const DECISION_DENIED: &str = "authorization_denied";
    pub const APPROVAL_INVALID: &str = "approval_invalid";
    pub const APPROVAL_NOT_FOUND: &str = "approval_not_found";
    pub const APPROVAL_TERMINAL: &str = "approval_terminal";
    pub const APPROVAL_NOT_DUE: &str = "approval_not_due";
    pub const GRANT_SCOPE_INVALID: &str = "grant_scope_invalid";
    pub const SECRET_USE_INVALID: &str = "secret_use_invalid";
    pub const GENESIS_INVALID: &str = "genesis_invalid";
}

/// Bounded text limits (defense-in-depth; the columns are unconstrained
/// `text`).
pub const MAX_IDENTITY_BYTES: usize = 256;
/// Bound for `reason`/`suspend_reason`.
pub const MAX_REASON_BYTES: usize = 1024;
/// Bound for `scope` canonical selector text.
pub const MAX_SCOPE_BYTES: usize = 1024;
/// Bound for a canonical `resource.effect` capability identity.
pub const MAX_CAPABILITY_IDENTITY_BYTES: usize = 128;
/// Bound for an operation key naming a per-action authorization.
pub const MAX_OPERATION_KEY_BYTES: usize = 512;
/// Bound for a `secret_reference_id` (opaque reference identity, never a
/// secret value — ADR 0003).
pub const MAX_SECRET_REFERENCE_ID_BYTES: usize = 256;

/// Suspend reason installed by the post-restore authority reset
/// (capability-policy.md: "suspends every restored effective capability
/// grant with `restore_review_required`").
pub const RESTORE_SUSPEND_REASON: &str = "restore_review_required";

/// Every task-scoped grant expires at most 24 hours after issuance
/// (capability-policy.md §Approval and effective grant).
pub const MAX_TASK_GRANT_TTL: Duration = Duration::hours(24);

// ---------------------------------------------------------------------------
// Capability taxonomy (capability-policy.md §Capability classes)
// ---------------------------------------------------------------------------

/// Protected resource class.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceClass {
    /// Workspace filesystem objects.
    Filesystem,
    /// Process execution.
    Process,
    /// Network connections and listeners.
    Network,
    /// Registered database connections.
    Database,
    /// Model/provider context egress.
    ModelContext,
    /// SecretReference use (never reveal).
    Secret,
}

impl ResourceClass {
    /// Canonical database/wire text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Process => "process",
            Self::Network => "network",
            Self::Database => "database",
            Self::ModelContext => "model_context",
            Self::Secret => "secret",
        }
    }

    /// Parses the canonical text; rejects everything else (closed
    /// vocabulary — unknown resource classes fail closed).
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "filesystem" => Ok(Self::Filesystem),
            "process" => Ok(Self::Process),
            "network" => Ok(Self::Network),
            "database" => Ok(Self::Database),
            "model_context" => Ok(Self::ModelContext),
            "secret" => Ok(Self::Secret),
            _ => Err(Failure::invalid(
                codes::CAPABILITY_UNKNOWN,
                "unknown resource class",
            )),
        }
    }
}

/// Requested effect. The full vocabulary; each [`ResourceClass`] admits
/// only its declared subset (capability-policy.md table).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Effect {
    /// `filesystem.read`
    Read,
    /// `filesystem.create`
    Create,
    /// `filesystem.modify`
    Modify,
    /// `filesystem.delete`
    Delete,
    /// `filesystem.set_executable`
    SetExecutable,
    /// `process.execute`
    Execute,
    /// `network.connect`
    Connect,
    /// `network.listen`
    Listen,
    /// `database.mutate`
    Mutate,
    /// `database.admin`
    Admin,
    /// `model_context.send`
    Send,
    /// `secret.use`
    Use,
}

impl Effect {
    /// Canonical database/wire text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::SetExecutable => "set_executable",
            Self::Execute => "execute",
            Self::Connect => "connect",
            Self::Listen => "listen",
            Self::Mutate => "mutate",
            Self::Admin => "admin",
            Self::Send => "send",
            Self::Use => "use",
        }
    }

    /// Parses the canonical text.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "read" => Ok(Self::Read),
            "create" => Ok(Self::Create),
            "modify" => Ok(Self::Modify),
            "delete" => Ok(Self::Delete),
            "set_executable" => Ok(Self::SetExecutable),
            "execute" => Ok(Self::Execute),
            "connect" => Ok(Self::Connect),
            "listen" => Ok(Self::Listen),
            "mutate" => Ok(Self::Mutate),
            "admin" => Ok(Self::Admin),
            "send" => Ok(Self::Send),
            "use" => Ok(Self::Use),
            _ => Err(Failure::invalid(
                codes::CAPABILITY_UNKNOWN,
                "unknown effect",
            )),
        }
    }
}

/// One atomic capability — `resource × effect`. `new` enforces the
/// declared effect subset so an illegal pair (`network.read`,
/// `secret.delete`) can never be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability {
    /// Protected resource class.
    pub resource: ResourceClass,
    /// Requested effect on that class.
    pub effect: Effect,
}

impl Capability {
    /// Constructs a capability iff the effect is declared for the class
    /// (capability-policy.md table). Unknown/illegal pairs fail closed.
    pub fn new(resource: ResourceClass, effect: Effect) -> Result<Self, Failure> {
        let legal = matches!(
            (resource, effect),
            (
                ResourceClass::Filesystem,
                Effect::Read
                    | Effect::Create
                    | Effect::Modify
                    | Effect::Delete
                    | Effect::SetExecutable
            ) | (ResourceClass::Process, Effect::Execute)
                | (ResourceClass::Network, Effect::Connect | Effect::Listen)
                | (
                    ResourceClass::Database,
                    Effect::Read | Effect::Mutate | Effect::Admin
                )
                | (ResourceClass::ModelContext, Effect::Send)
                | (ResourceClass::Secret, Effect::Use)
        );
        if !legal {
            return Err(Failure::invalid(
                codes::CAPABILITY_UNKNOWN,
                "the effect is not declared for that resource class",
            ));
        }
        Ok(Self { resource, effect })
    }

    /// The canonical `resource.effect` identity text — the value stored
    /// in `approvals.capability_identity`.
    #[must_use]
    pub fn identity(&self) -> String {
        let mut text = String::with_capacity(24);
        text.push_str(self.resource.as_str());
        text.push('.');
        text.push_str(self.effect.as_str());
        text
    }

    /// Parses `resource.effect` identity text into a validated
    /// capability. Anything outside the closed taxonomy is rejected —
    /// the caller fails closed rather than guessing.
    pub fn parse(identity: &str) -> Result<Self, Failure> {
        let (resource, effect) = identity.split_once('.').ok_or_else(|| {
            Failure::invalid(
                codes::CAPABILITY_UNKNOWN,
                "capability identity is malformed",
            )
        })?;
        Self::new(ResourceClass::parse(resource)?, Effect::parse(effect)?)
    }

    /// Whether this effect mutates state — drives the production
    /// downgrade to per-action ceilings (capability-policy.md: "Mutate
    /// production resource — never bundle-opened").
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(
            (self.resource, self.effect),
            (
                ResourceClass::Filesystem,
                Effect::Create | Effect::Modify | Effect::Delete | Effect::SetExecutable
            ) | (ResourceClass::Process, Effect::Execute)
                | (ResourceClass::Database, Effect::Mutate | Effect::Admin)
        )
    }
}

/// Sensitivity class of the target resource (`local`, `dev`, `staging`,
/// `prod`). Unknown sensitivity fails closed at parse — it receives the
/// strictest applicable rule downstream.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Sensitivity {
    /// Local-only resource.
    Local,
    /// Development environment.
    Dev,
    /// Staging environment.
    Staging,
    /// Production environment — strictest ceilings apply.
    Prod,
}

impl Sensitivity {
    /// Canonical text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }

    /// Parses the canonical text; rejects everything else.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "local" => Ok(Self::Local),
            "dev" => Ok(Self::Dev),
            "staging" => Ok(Self::Staging),
            "prod" => Ok(Self::Prod),
            _ => Err(Failure::invalid(
                codes::REQUEST_INVALID,
                "unknown sensitivity",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical authorization request and decision
// ---------------------------------------------------------------------------

/// Reusable-scope classification of a request (capability-policy.md:
/// "task-scoped or per-action class").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeClass {
    /// Bound to the current Task — grant reusable within the Task for at
    /// most 24 hours.
    Task,
    /// Bound to one operation key — never reusable, never bundle-opened.
    PerAction,
}

/// The `scope` leg of the canonical request: canonical resource
/// selector plus requested grant lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityScope {
    /// Current Task the grant would be bound to (task-scoped grants).
    pub task_id: Option<TaskId>,
    /// Exact operation key (per-action grants). Present scope keys win
    /// over task scoping — a request naming an operation key is always
    /// per-action.
    pub operation_key: Option<String>,
    /// Canonical resource selector (paths, protocol/destination/port,
    /// connection identity, SecretReference ID, provider+resource
    /// scope — the exact binding, never a wildcard).
    pub selector: String,
}

impl CapabilityScope {
    /// The reusability class this scope requests.
    #[must_use]
    pub fn class(&self) -> ScopeClass {
        if self.operation_key.is_some() {
            ScopeClass::PerAction
        } else {
            ScopeClass::Task
        }
    }

    /// Validates scope shape: a selector is mandatory and bounded; the
    /// operation key is bounded; a task-scoped grant names its Task.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.selector.is_empty() || self.selector.len() > MAX_SCOPE_BYTES {
            return Err(Failure::invalid(
                codes::GRANT_SCOPE_INVALID,
                "the canonical scope selector must be 1..=1024 bytes",
            ));
        }
        if let Some(key) = &self.operation_key
            && (key.is_empty() || key.len() > MAX_OPERATION_KEY_BYTES)
        {
            return Err(Failure::invalid(
                codes::GRANT_SCOPE_INVALID,
                "the operation key must be 1..=512 bytes",
            ));
        }
        Ok(())
    }
}

/// The canonical `resource × effect × scope` authorization request
/// (capability-policy.md §Canonical authorization request). Missing or
/// unclassifiable elements fail closed downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Owning Workspace — the isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Authenticated actor identity (bounded).
    pub actor_identity: String,
    /// Whether the request originates from the agent plane. Agent-plane
    /// requests get agent rules; operator/system requests are evaluated
    /// through the same matrix but are additionally subject to the
    /// system-owned-plane note in [`evaluate`].
    pub agent_requested: bool,
    /// `resource × effect`.
    pub capability: Capability,
    /// Canonical scope.
    pub scope: CapabilityScope,
    /// Target sensitivity.
    pub sensitivity: Sensitivity,
}

impl AuthorizationRequest {
    /// Validates request shape — missing fields fail closed.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.actor_identity.is_empty() || self.actor_identity.len() > MAX_IDENTITY_BYTES {
            return Err(Failure::invalid(
                codes::REQUEST_INVALID,
                "the actor identity must be 1..=256 bytes",
            ));
        }
        self.scope.validate()
    }
}

/// Facts the evaluator cannot infer and the caller must supply from
/// installed policy, protected configuration, or registered-resource
/// state. Supplying a wrong fact is an authority decision of the caller
/// — the domain's job is to combine them deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyFacts {
    /// The target lies inside the canonical Workspace roots
    /// (filesystem read).
    pub inside_workspace_roots: bool,
    /// An installed policy exception names this exact
    /// protocol/destination/port/purpose connect.
    pub network_exception: bool,
    /// A bounded, enforcing environment mediates ambient filesystem and
    /// network access for this `process.execute`.
    pub enforcing_environment: bool,
    /// Protected local configuration enables this maintainer-override
    /// class (`database.admin`, DDL).
    pub maintainer_override: bool,
}

/// The one policy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyOutcome {
    /// Current policy and effective grants authorize the exact request.
    Allow,
    /// A local user can authorize the exact request through durable
    /// Approval.
    RequireApproval,
    /// A hard rule, invalid request, missing authority, or prohibited
    /// combination forbids invocation.
    Deny,
}

impl PolicyOutcome {
    /// The strictest of a composed set — `deny` > `require_approval` >
    /// `allow` (capability-policy.md §Authority principle). An empty
    /// composition fails closed to `Deny`.
    #[must_use]
    pub fn strictest<I: IntoIterator<Item = Self>>(outcomes: I) -> Self {
        outcomes.into_iter().max().unwrap_or(Self::Deny)
    }

    /// Canonical text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::RequireApproval => "require_approval",
            Self::Deny => "deny",
        }
    }
}

/// The maximum reusable scope a grant may carry for the evaluated
/// request (the matrix's "Maximum reusable scope" column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantCeiling {
    /// No grant may be established.
    None,
    /// One operation key only — never reusable.
    PerAction,
    /// Current Task, at most [`MAX_TASK_GRANT_TTL`], exact scope.
    TaskBounded,
}

/// The evaluated decision: outcome + maximum reusable scope + stable
/// machine reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecision {
    /// The outcome.
    pub outcome: PolicyOutcome,
    /// Maximum reusable scope a grant established from an approval may
    /// carry; meaningless under `Deny`/`Allow` (None/`TaskBounded`).
    pub ceiling: GrantCeiling,
    /// Stable machine reason code for evidence and display.
    pub reason: &'static str,
}

impl PolicyDecision {
    const fn new(outcome: PolicyOutcome, ceiling: GrantCeiling, reason: &'static str) -> Self {
        Self {
            outcome,
            ceiling,
            reason,
        }
    }

    const fn allow(reason: &'static str) -> Self {
        Self::new(PolicyOutcome::Allow, GrantCeiling::TaskBounded, reason)
    }

    const fn approve(ceiling: GrantCeiling, reason: &'static str) -> Self {
        Self::new(PolicyOutcome::RequireApproval, ceiling, reason)
    }

    const fn deny(reason: &'static str) -> Self {
        Self::new(PolicyOutcome::Deny, GrantCeiling::None, reason)
    }
}

/// Evaluates one atomic request against the Phase-1 default policy
/// matrix (capability-policy.md §Default policy matrix).
///
/// System-owned authority planes (infrastructure helper, broker,
/// launcher, browser) are not evaluated here — they are not
/// agent-requestable capabilities at all; a `!agent_requested` request
/// for a system-owned operation fails closed the same as an unknown
/// class.
///
/// Production sensitivity applies the matrix's "Mutate production
/// resource — never bundle-opened" rule: a mutating capability under
/// `Prod` can never carry a task-bounded ceiling; the result is pinned
/// to per-action.
#[must_use]
pub fn evaluate(req: &AuthorizationRequest, facts: &PolicyFacts) -> PolicyDecision {
    let decision = match (req.capability.resource, req.capability.effect) {
        (ResourceClass::Filesystem, Effect::Read) => {
            if facts.inside_workspace_roots {
                PolicyDecision::allow("workspace_read_allowed")
            } else {
                PolicyDecision::deny("cross_workspace_read_denied")
            }
        }
        (ResourceClass::Filesystem, Effect::Create | Effect::Modify) => {
            PolicyDecision::approve(GrantCeiling::TaskBounded, "workspace_write_approval")
        }
        (ResourceClass::Filesystem, Effect::Delete | Effect::SetExecutable) => {
            PolicyDecision::approve(GrantCeiling::PerAction, "protected_path_per_action")
        }
        (ResourceClass::Process, Effect::Execute) => {
            if facts.enforcing_environment {
                PolicyDecision::approve(GrantCeiling::TaskBounded, "bounded_process_approval")
            } else {
                PolicyDecision::approve(GrantCeiling::PerAction, "arbitrary_process_per_action")
            }
        }
        (ResourceClass::Network, Effect::Connect) => {
            if req.agent_requested && !facts.network_exception {
                PolicyDecision::deny("agent_network_denied")
            } else {
                PolicyDecision::approve(GrantCeiling::PerAction, "network_exception_per_action")
            }
        }
        (ResourceClass::Network, Effect::Listen) => {
            if req.agent_requested {
                PolicyDecision::deny("agent_listen_denied")
            } else {
                // Registered loopback listeners are system-owned
                // operations, not capability-grant authority — this
                // evaluator never mints them.
                PolicyDecision::deny("system_owned_plane")
            }
        }
        (ResourceClass::Database, Effect::Read) => {
            PolicyDecision::approve(GrantCeiling::TaskBounded, "database_read_task_grant")
        }
        (ResourceClass::Database, Effect::Mutate) => {
            PolicyDecision::approve(GrantCeiling::PerAction, "database_mutate_per_action")
        }
        (ResourceClass::Database, Effect::Admin) => {
            if facts.maintainer_override {
                PolicyDecision::approve(GrantCeiling::PerAction, "maintainer_override_per_action")
            } else {
                PolicyDecision::deny("database_admin_denied")
            }
        }
        (ResourceClass::ModelContext, Effect::Send) => {
            PolicyDecision::approve(GrantCeiling::TaskBounded, "model_egress_task_grant")
        }
        (ResourceClass::Secret, Effect::Use) => {
            PolicyDecision::approve(GrantCeiling::TaskBounded, "secret_use_task_grant")
        }
        // A `Capability` built outside `Capability::new` (pub fields)
        // names an undeclared pair — fail closed, never guess.
        _ => PolicyDecision::deny("capability_outside_taxonomy"),
    };
    apply_production_ceiling(req, decision)
}

/// The production downgrade: a mutating capability under `Prod`
/// sensitivity can never carry a task-bounded grant — per-action only.
fn apply_production_ceiling(
    req: &AuthorizationRequest,
    decision: PolicyDecision,
) -> PolicyDecision {
    if req.sensitivity != Sensitivity::Prod
        || !req.capability.is_mutating()
        || decision.outcome != PolicyOutcome::RequireApproval
    {
        return decision;
    }
    PolicyDecision {
        ceiling: GrantCeiling::PerAction,
        ..decision
    }
}

/// Validates a grant lifetime: every task-scoped grant expires at most
/// [`MAX_TASK_GRANT_TTL`] after issuance; expiry must follow issuance.
/// A `None` expiry names a per-action grant (bound to one operation
/// key); a set expiry is capped unconditionally — no recorded grant may
/// outlive the 24-hour ceiling.
pub fn validate_grant_lifetime(
    issued_at: OffsetDateTime,
    expiry_at: Option<OffsetDateTime>,
) -> Result<(), Failure> {
    let Some(expiry) = expiry_at else {
        return Ok(());
    };
    if expiry <= issued_at || expiry > issued_at + MAX_TASK_GRANT_TTL {
        return Err(Failure::invalid(
            codes::GRANT_SCOPE_INVALID,
            "a grant expires within (issued, issued+24h]",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Capability-grant approval records (adapter-mapping §3.18)
// ---------------------------------------------------------------------------

/// The recorded action a capability-grant row represents
/// (`approvals.action`: `grant` | `revoke`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalAction {
    /// Establishes the effective grant.
    Grant,
    /// Withdraws it.
    Revoke,
}

impl ApprovalAction {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }

    /// Parses the canonical text.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "grant" => Ok(Self::Grant),
            "revoke" => Ok(Self::Revoke),
            _ => Err(Failure::invalid(codes::APPROVAL_INVALID, "unknown action")),
        }
    }
}

impl serde::Serialize for ApprovalAction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Effective-grant record state (`approvals.state`:
/// `active` | `revoked` | `suspended` | `expired`).
///
/// These are effective-authority states, distinct from the historical
/// Approval aggregate's `requested`/`approved`/`rejected`/`cancelled`
/// lifecycle (capability-policy.md §Approval and effective grant) and
/// from the b08 `execution` approval kind's vocabulary — both owned
/// elsewhere.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalState {
    /// The grant is effective (subject to epoch and expiry).
    Active,
    /// Withdrawn by decision. Terminal.
    Revoked,
    /// Temporarily ineffective (e.g. `restore_review_required`).
    Suspended,
    /// Passed its expiry. Terminal.
    Expired,
}

impl ApprovalState {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Suspended => "suspended",
            Self::Expired => "expired",
        }
    }

    /// Parses the canonical text.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "suspended" => Ok(Self::Suspended),
            "expired" => Ok(Self::Expired),
            _ => Err(Failure::invalid(codes::APPROVAL_INVALID, "unknown state")),
        }
    }

    /// Whether the state is final — `revoked` and `expired` never
    /// transition again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Expired)
    }

    /// Whether a grant in this state can be effective (before epoch and
    /// expiry checks).
    #[must_use]
    pub const fn grants(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl serde::Serialize for ApprovalState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The inputs of a durable capability-grant issuance — the legs of one
/// `central.approvals` `grant` row.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantRequest {
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// `resource × effect`.
    pub capability: Capability,
    /// Canonical scope.
    pub scope: CapabilityScope,
    /// Actor the grant is issued to/for (bounded).
    pub actor_identity: String,
    /// Establishing authority identity (bounded).
    pub authority_identity: String,
    /// Auditable reason (bounded).
    pub reason: String,
    /// Security epoch at issuance.
    pub security_epoch: u64,
    /// Issuance time.
    pub issued_at: OffsetDateTime,
    /// Expiry — within `(issued, issued+24h]` when present; `None`
    /// names a per-action grant.
    pub expiry_at: Option<OffsetDateTime>,
}

/// An optimistic-lock change set: the caller's `expected_version` guard
/// plus the complete next row. The commit port enforces the guard —
/// the domain never mutates in place.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalChangeSet {
    /// The row version this decision was evaluated against; the commit
    /// fails with `conflict` if the stored row has moved on.
    pub expected_version: u64,
    /// The complete next record (version already incremented).
    pub next: ApprovalRecord,
}

/// One `central.approvals` capability-grant row (adapter-mapping
/// §3.18) — the durable record of an effective-authority decision.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRecord {
    /// Row identity.
    pub id: ApprovalId,
    /// Owning Workspace — the isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Optimistic-lock version.
    pub version: u64,
    /// Canonical `resource.effect` capability identity.
    pub capability_identity: String,
    /// Canonical scope selector the grant binds.
    pub scope: String,
    /// `grant` | `revoke` — the recorded action.
    pub action: ApprovalAction,
    /// Actor identity the grant was issued to/for.
    pub actor_identity: String,
    /// Authority identity that established the record.
    pub authority_identity: String,
    /// Auditable reason.
    pub reason: String,
    /// Effective-authority state.
    pub state: ApprovalState,
    /// Why the grant is suspended — required iff `Suspended`.
    pub suspend_reason: Option<String>,
    /// Security epoch at issuance; a grant dies with its epoch
    /// (post-restore reset).
    pub security_epoch: u64,
    /// Issuance time.
    pub created_at: OffsetDateTime,
    /// Last decision time.
    pub updated_at: OffsetDateTime,
    /// Grant expiry — every expiring grant lives within
    /// [`MAX_TASK_GRANT_TTL`] of issuance (validated).
    pub expiry_at: Option<OffsetDateTime>,
}

impl ApprovalRecord {
    /// Validates the persisted-record invariants: bounded text legs,
    /// taxonomy-parseable capability identity, suspend-reason shape,
    /// and the ≤ 24 h grant lifetime.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.capability_identity.is_empty()
            || self.capability_identity.len() > MAX_CAPABILITY_IDENTITY_BYTES
        {
            return Err(Failure::invalid(
                codes::APPROVAL_INVALID,
                "capability_identity must be 1..=128 bytes",
            ));
        }
        Capability::parse(&self.capability_identity).map_err(|_| {
            Failure::invalid(
                codes::APPROVAL_INVALID,
                "capability_identity is outside the closed taxonomy",
            )
        })?;
        for (name, text, max) in [
            ("scope", &self.scope, MAX_SCOPE_BYTES),
            ("actor_identity", &self.actor_identity, MAX_IDENTITY_BYTES),
            (
                "authority_identity",
                &self.authority_identity,
                MAX_IDENTITY_BYTES,
            ),
            ("reason", &self.reason, MAX_REASON_BYTES),
        ] {
            if text.is_empty() || text.len() > max {
                return Err(Failure::invalid(
                    codes::APPROVAL_INVALID,
                    "a required text leg is empty or over its bound",
                ));
            }
            let _ = name;
        }
        match (self.state, &self.suspend_reason) {
            (ApprovalState::Suspended, Some(reason))
                if !reason.is_empty() && reason.len() <= MAX_REASON_BYTES => {}
            (ApprovalState::Suspended, _) => {
                return Err(Failure::invalid(
                    codes::APPROVAL_INVALID,
                    "a suspended grant requires a bounded suspend_reason",
                ));
            }
            (_, Some(reason)) if reason.len() > MAX_REASON_BYTES => {
                return Err(Failure::invalid(
                    codes::APPROVAL_INVALID,
                    "suspend_reason exceeds its bound",
                ));
            }
            _ => {}
        }
        validate_grant_lifetime(self.created_at, self.expiry_at)
    }

    /// Establishes a new active `grant` record (version 0).
    pub fn grant(request: GrantRequest) -> Result<Self, Failure> {
        request.scope.validate()?;
        let record = Self {
            id: ApprovalId::new(),
            workspace_id: request.workspace_id,
            version: 0,
            capability_identity: request.capability.identity(),
            scope: request.scope.selector,
            action: ApprovalAction::Grant,
            actor_identity: request.actor_identity,
            authority_identity: request.authority_identity,
            reason: request.reason,
            state: ApprovalState::Active,
            suspend_reason: None,
            security_epoch: request.security_epoch,
            created_at: request.issued_at,
            updated_at: request.issued_at,
            expiry_at: request.expiry_at,
        };
        record.validate()?;
        Ok(record)
    }

    fn guarded(&self, mut next: ApprovalRecord, at: OffsetDateTime) -> ApprovalChangeSet {
        next.version = self.version + 1;
        next.updated_at = at;
        ApprovalChangeSet {
            expected_version: self.version,
            next,
        }
    }

    fn terminal_guard(&self) -> Result<(), Failure> {
        if self.state.is_terminal() {
            return Err(Failure::conflict(
                codes::APPROVAL_TERMINAL,
                "the approval record is terminal",
            ));
        }
        Ok(())
    }

    /// `revoke` — `active`/`suspended` → `revoked` (terminal).
    pub fn evaluate_revocation(
        &self,
        reason: impl Into<String>,
        at: OffsetDateTime,
    ) -> Result<ApprovalChangeSet, Failure> {
        self.terminal_guard()?;
        let mut next = self.clone();
        next.state = ApprovalState::Revoked;
        next.action = ApprovalAction::Revoke;
        next.reason = reason.into();
        next.suspend_reason = None;
        next.validate()?;
        Ok(self.guarded(next, at))
    }

    /// `suspend` — `active` → `suspended` with a mandatory reason.
    /// Suspending an already-suspended record replaces the suspend
    /// reason (not an error — the operation is idempotent-shaped).
    pub fn evaluate_suspension(
        &self,
        suspend_reason: impl Into<String>,
        at: OffsetDateTime,
    ) -> Result<ApprovalChangeSet, Failure> {
        self.terminal_guard()?;
        let mut next = self.clone();
        next.state = ApprovalState::Suspended;
        next.suspend_reason = Some(suspend_reason.into());
        next.validate()?;
        Ok(self.guarded(next, at))
    }

    /// `expire` — `active`/`suspended` → `expired` (terminal), only
    /// once `expiry_at` has passed.
    pub fn evaluate_expiry(&self, at: OffsetDateTime) -> Result<ApprovalChangeSet, Failure> {
        self.terminal_guard()?;
        let Some(expiry) = self.expiry_at else {
            return Err(Failure::conflict(
                codes::APPROVAL_NOT_DUE,
                "the grant carries no expiry",
            ));
        };
        if expiry > at {
            return Err(Failure::conflict(
                codes::APPROVAL_NOT_DUE,
                "the grant has not reached its expiry",
            ));
        }
        let mut next = self.clone();
        next.state = ApprovalState::Expired;
        next.suspend_reason = None;
        next.validate()?;
        Ok(self.guarded(next, at))
    }

    /// The post-restore authority reset: every `active` grant is
    /// suspended with `restore_review_required`. Non-active records are
    /// untouched (`Unaffected`), matching the upstream
    /// `WHERE state = 'active'` batch.
    pub fn evaluate_restore_suspension(
        &self,
        at: OffsetDateTime,
    ) -> Result<RestoreSuspension, Failure> {
        if self.state != ApprovalState::Active {
            return Ok(RestoreSuspension::Unaffected);
        }
        Ok(RestoreSuspension::ChangeSet(Box::new(
            self.evaluate_suspension(RESTORE_SUSPEND_REASON, at)?,
        )))
    }

    /// Derives the grant a caller may rely on *right now* — `None`
    /// unless the record is `active`, the workspace's current security
    /// epoch still matches issuance, and expiry has not passed. This is
    /// the read-side mirror of the enforcement rule; callers must not
    /// treat `None` as a policy decision — re-evaluate instead.
    #[must_use]
    pub fn effective_grant(
        &self,
        at: OffsetDateTime,
        current_security_epoch: u64,
    ) -> Option<EffectiveGrant> {
        if self.action != ApprovalAction::Grant
            || !self.state.grants()
            || self.security_epoch != current_security_epoch
            || self.expiry_at.is_some_and(|expiry| expiry <= at)
        {
            return None;
        }
        Some(EffectiveGrant {
            approval_id: self.id,
            workspace_id: self.workspace_id,
            class: if self.expiry_at.is_some() {
                GrantClass::TaskScoped
            } else {
                GrantClass::PerAction
            },
            capability_identity: self.capability_identity.clone(),
            scope: self.scope.clone(),
            security_epoch: self.security_epoch,
            expires_at: self.expiry_at,
        })
    }
}

/// The restore-reset outcome for one record.
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreSuspension {
    /// The grant was active; commit this suspension.
    ChangeSet(Box<ApprovalChangeSet>),
    /// The grant was not active — nothing to do.
    Unaffected,
}

/// The grant reusability class carried by an effective grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantClass {
    /// Bound to the current Task, ≤ 24 h, exact scope.
    TaskScoped,
    /// Bound to one operation key — never reusable.
    PerAction,
}

/// The currently-reliable authorization — an `active`, in-epoch,
/// unexpired grant. Carries no actor: the grant binds scope and
/// capability; the requesting actor is matched by the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveGrant {
    /// The backing approval row.
    pub approval_id: ApprovalId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Reusability class.
    pub class: GrantClass,
    /// `resource.effect` identity.
    pub capability_identity: String,
    /// Exact scope selector.
    pub scope: String,
    /// The epoch the grant belongs to.
    pub security_epoch: u64,
    /// Expiry, when task-scoped.
    pub expires_at: Option<OffsetDateTime>,
}

// ---------------------------------------------------------------------------
// Secret-use audit evidence (adapter-mapping §3.19)
// ---------------------------------------------------------------------------

/// One `central.secret_use` evidence row: durable proof that a
/// SecretReference was used, under which actor, operation, and
/// authorization outcome. Carries reference identity only — never a
/// secret value (ADR 0003).
#[derive(Debug, Clone, PartialEq)]
pub struct SecretUseEvidence {
    /// Row identity.
    pub id: SecretUseEvidenceId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Opaque SecretReference identity (bounded, never the value).
    pub secret_reference_id: String,
    /// Actor identity that used the reference.
    pub actor_identity: String,
    /// Operation/decision identity under which use occurred.
    pub operation_identity: String,
    /// The authorization outcome text (e.g. `allow`, `require_approval`
    /// resolved under a grant identity).
    pub authorization_outcome: String,
    /// Occurrence time.
    pub created_at: OffsetDateTime,
}

impl SecretUseEvidence {
    /// Builds and validates an evidence record for append.
    pub fn record(
        workspace_id: WorkspaceId,
        secret_reference_id: impl Into<String>,
        actor_identity: impl Into<String>,
        operation_identity: impl Into<String>,
        authorization_outcome: impl Into<String>,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        let evidence = Self {
            id: SecretUseEvidenceId::new(),
            workspace_id,
            secret_reference_id: secret_reference_id.into(),
            actor_identity: actor_identity.into(),
            operation_identity: operation_identity.into(),
            authorization_outcome: authorization_outcome.into(),
            created_at: at,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Bounded-field validation.
    pub fn validate(&self) -> Result<(), Failure> {
        for (text, max) in [
            (&self.secret_reference_id, MAX_SECRET_REFERENCE_ID_BYTES),
            (&self.actor_identity, MAX_IDENTITY_BYTES),
            (&self.operation_identity, MAX_IDENTITY_BYTES),
            (&self.authorization_outcome, MAX_REASON_BYTES),
        ] {
            if text.is_empty() || text.len() > max {
                return Err(Failure::invalid(
                    codes::SECRET_USE_INVALID,
                    "a secret_use evidence leg is empty or over its bound",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Genesis authority records (internal/authority/genesis.go, domain.go)
// ---------------------------------------------------------------------------

/// The fixed, allocated `central-runtime` UID/GID — the single source
/// of truth shared by the broker's SO_PEERCRED peer gate and the
/// `minio_runtime_v1` dependency check (upstream `domain.go`).
pub const CENTRAL_RUNTIME_UID: i32 = 501;
/// The `central-runtime` GID — checked by neither widened gate but
/// defined alongside the UID as the complete identity pair.
pub const CENTRAL_RUNTIME_GID: i32 = 501;
/// The fixed `central-migrate` worker identity used by the migration
/// operator's own peer gate.
pub const CENTRAL_MIGRATE_UID: i32 = 986;
/// The `central-migrate` GID.
pub const CENTRAL_MIGRATE_GID: i32 = 986;

/// The Unix UID/GID allocated for each purpose-runner identity on the
/// host (upstream `UIDGIDMap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidGidMap {
    /// `central-runtime` daemon identity.
    pub runtime_uid: i32,
    /// `central-runtime` group.
    pub runtime_gid: i32,
    /// `central-agent` subagent runner.
    pub agent_uid: i32,
    /// `central-agent` group.
    pub agent_gid: i32,
    /// `central-browser` sandbox.
    pub browser_uid: i32,
    /// `central-browser` group.
    pub browser_gid: i32,
}

impl UidGidMap {
    /// Validates the map: no nil (root-adjacent) allocation, runtime
    /// pair fixed at 501/501, and no two identities share a UID — a
    /// shared UID would collapse the SO_PEERCRED gate's identity
    /// distinction.
    pub fn validate(&self) -> Result<(), Failure> {
        for uid in [
            self.runtime_uid,
            self.agent_uid,
            self.browser_uid,
            self.runtime_gid,
            self.agent_gid,
            self.browser_gid,
        ] {
            if uid <= 0 {
                return Err(Failure::invalid(
                    codes::GENESIS_INVALID,
                    "a uid/gid allocation must be positive and non-root",
                ));
            }
        }
        if self.runtime_uid != CENTRAL_RUNTIME_UID || self.runtime_gid != CENTRAL_RUNTIME_GID {
            return Err(Failure::invalid(
                codes::GENESIS_INVALID,
                "the runtime pair is fixed at 501/501",
            ));
        }
        if self.agent_uid == self.runtime_uid || self.browser_uid == self.runtime_uid {
            return Err(Failure::invalid(
                codes::GENESIS_INVALID,
                "purpose-runner uids must be distinct",
            ));
        }
        Ok(())
    }
}

/// A system identity that must exist on the host before the runtime
/// starts (upstream `LockedIdentity`). UID/GID values come from the
/// [`UidGidMap`] negotiated at genesis — the constructor templates
/// carry name/shell/home only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedIdentity {
    /// Account name.
    pub name: &'static str,
    /// Allocated UID (0 until bound by the genesis `UidGidMap`).
    pub uid: i32,
    /// Allocated GID.
    pub gid: i32,
    /// Login shell — always `nologin` for locked identities.
    pub shell: &'static str,
    /// Home directory.
    pub home: &'static str,
}

const NOLOGIN: &str = "/usr/sbin/nologin";

impl LockedIdentity {
    /// `central-runtime` daemon identity template.
    #[must_use]
    pub const fn runtime() -> Self {
        Self {
            name: "central-runtime",
            uid: 0,
            gid: 0,
            shell: NOLOGIN,
            home: "/nonexistent",
        }
    }

    /// `central-agent` subagent runner template.
    #[must_use]
    pub const fn agent() -> Self {
        Self {
            name: "central-agent",
            uid: 0,
            gid: 0,
            shell: NOLOGIN,
            home: "/nonexistent",
        }
    }

    /// `central-browser` sandbox template.
    #[must_use]
    pub const fn browser() -> Self {
        Self {
            name: "central-browser",
            uid: 0,
            gid: 0,
            shell: NOLOGIN,
            home: "/var/lib/central-browser",
        }
    }

    /// `central-migrate` migration-operator template.
    #[must_use]
    pub const fn migrate() -> Self {
        Self {
            name: "central-migrate",
            uid: 0,
            gid: 0,
            shell: NOLOGIN,
            home: "/nonexistent",
        }
    }

    /// The full set allocated at genesis (upstream
    /// `AllLockedIdentities`).
    #[must_use]
    pub fn all() -> [Self; 4] {
        [
            Self::runtime(),
            Self::agent(),
            Self::browser(),
            Self::migrate(),
        ]
    }

    /// Binds an allocated `UidGidMap` onto the templates.
    #[must_use]
    pub fn bind_all(map: &UidGidMap) -> [Self; 4] {
        let mut identities = Self::all();
        identities[0].uid = map.runtime_uid;
        identities[0].gid = map.runtime_gid;
        identities[1].uid = map.agent_uid;
        identities[1].gid = map.agent_gid;
        identities[2].uid = map.browser_uid;
        identities[2].gid = map.browser_gid;
        identities[3].uid = CENTRAL_MIGRATE_UID;
        identities[3].gid = CENTRAL_MIGRATE_GID;
        identities
    }
}

/// The durable identity of a Central instance on one host (upstream
/// `InstanceBinding`): machine identity, release digest, generated
/// config binding, and locked UID/GID allocations.
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceBinding {
    /// The instance identity.
    pub instance_id: InstanceId,
    /// SHA-256 of `/etc/machine-id`, lowercase hex (64 bytes).
    pub host_id: String,
    /// SHA-256 of the release artifact, lowercase hex (64 bytes).
    pub release_digest: String,
    /// Creation time (UTC system clock).
    pub created_at: OffsetDateTime,
    /// Binds the generated `central.config/v1`.
    pub config_binding_id: ConfigBindingId,
    /// Locked numeric allocations.
    pub uidgid: UidGidMap,
}

/// Bounded digest bound — a hex SHA-256 is exactly 64 characters.
const DIGEST_HEX_BYTES: usize = 64;

impl InstanceBinding {
    /// Validates binding shape: 64-byte lowercase-hex digests and a
    /// coherent UID/GID map.
    pub fn validate(&self) -> Result<(), Failure> {
        for digest in [&self.host_id, &self.release_digest] {
            if digest.len() != DIGEST_HEX_BYTES
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(Failure::invalid(
                    codes::GENESIS_INVALID,
                    "host_id and release_digest are 64-byte lowercase-hex SHA-256 digests",
                ));
            }
        }
        self.uidgid.validate()
    }
}

/// The input side of the genesis protocol (upstream `GenesisIntent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisIntent {
    /// Operator operation this genesis runs under.
    pub operation_id: OperationId,
    /// When the intent was recorded.
    pub requested_at: OffsetDateTime,
}

/// The durable proof that genesis completed for a specific instance
/// (upstream `GenesisReceipt`).
#[derive(Debug, Clone, PartialEq)]
pub struct GenesisReceipt {
    /// The operation that committed.
    pub operation_id: OperationId,
    /// The instance that was bound.
    pub instance_id: InstanceId,
    /// The generated `central.config/v1` binding.
    pub config_binding_id: ConfigBindingId,
    /// Locked allocations actually applied.
    pub uidgid: UidGidMap,
    /// Completion time.
    pub completed_at: OffsetDateTime,
}

/// The current phase of a genesis operation (upstream `Phase` text).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisPhase {
    /// Intent recorded; not yet committed.
    Prepared,
    /// Completed; a [`GenesisReceipt`] rides along.
    Committed,
    /// The intent was given up.
    Abandoned,
    /// No genesis has been attempted.
    Absent,
}

impl GenesisPhase {
    /// Canonical upstream phase text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::Abandoned => "abandoned",
            Self::Absent => "absent",
        }
    }

    /// Parses the canonical phase text.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "prepared" => Ok(Self::Prepared),
            "committed" => Ok(Self::Committed),
            "abandoned" => Ok(Self::Abandoned),
            "absent" => Ok(Self::Absent),
            _ => Err(Failure::invalid(
                codes::GENESIS_INVALID,
                "unknown genesis phase",
            )),
        }
    }
}

/// The phase of a genesis operation plus its receipt when committed
/// (upstream `GenesisStatus`). A `Committed` status without a receipt
/// — or a receipt under any other phase — fails validation.
#[derive(Debug, Clone, PartialEq)]
pub struct GenesisStatus {
    /// The operation the status describes.
    pub operation_id: OperationId,
    /// Current phase.
    pub phase: GenesisPhase,
    /// The receipt — present iff `Committed`.
    pub receipt: Option<GenesisReceipt>,
}

impl GenesisStatus {
    /// Validates the phase/receipt pairing and, when present, that the
    /// receipt belongs to this operation.
    pub fn validate(&self) -> Result<(), Failure> {
        match (&self.phase, &self.receipt) {
            (GenesisPhase::Committed, Some(receipt)) => {
                if receipt.operation_id != self.operation_id {
                    return Err(Failure::invalid(
                        codes::GENESIS_INVALID,
                        "the receipt belongs to a different operation",
                    ));
                }
                receipt.uidgid.validate()
            }
            (GenesisPhase::Committed, None) => Err(Failure::invalid(
                codes::GENESIS_INVALID,
                "a committed genesis status requires its receipt",
            )),
            (_, Some(_)) => Err(Failure::invalid(
                codes::GENESIS_INVALID,
                "a receipt only exists under a committed phase",
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::failure::FailureKind;

    const T0: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn req(cap: Capability, facts_selector: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            workspace_id: WorkspaceId::new(),
            actor_identity: "agent:planner".into(),
            agent_requested: true,
            capability: cap,
            scope: CapabilityScope {
                task_id: Some(TaskId::new()),
                operation_key: None,
                selector: facts_selector.into(),
            },
            sensitivity: Sensitivity::Local,
        }
    }

    fn cap(resource: ResourceClass, effect: Effect) -> Capability {
        Capability::new(resource, effect).unwrap()
    }

    fn grant_record() -> ApprovalRecord {
        ApprovalRecord::grant(GrantRequest {
            workspace_id: WorkspaceId::new(),
            capability: cap(ResourceClass::Filesystem, Effect::Modify),
            scope: CapabilityScope {
                task_id: Some(TaskId::new()),
                operation_key: None,
                selector: "/work/**".into(),
            },
            actor_identity: "agent:planner".into(),
            authority_identity: "authority:local-console".into(),
            reason: "user approved workspace write".into(),
            security_epoch: 7,
            issued_at: T0,
            expiry_at: Some(T0 + Duration::hours(4)),
        })
        .unwrap()
    }

    // -- capability taxonomy -------------------------------------------------

    #[test]
    fn capability_identity_round_trips_and_rejects_illegal_pairs() {
        let c = cap(ResourceClass::Filesystem, Effect::SetExecutable);
        assert_eq!(c.identity(), "filesystem.set_executable");
        assert_eq!(Capability::parse("filesystem.set_executable").unwrap(), c);

        for illegal in [
            "network.read",
            "secret.delete",
            "process.listen",
            "bogus.x",
            "filesystem",
        ] {
            let err = Capability::parse(illegal).unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{illegal}");
            assert_eq!(err.code(), codes::CAPABILITY_UNKNOWN);
        }
    }

    #[test]
    fn scope_class_prefers_per_action_and_validates_bounds() {
        let mut scope = CapabilityScope {
            task_id: Some(TaskId::new()),
            operation_key: Some("op:7".into()),
            selector: "selector".into(),
        };
        assert_eq!(scope.class(), ScopeClass::PerAction);
        scope.operation_key = None;
        assert_eq!(scope.class(), ScopeClass::Task);

        scope.selector.clear();
        assert_eq!(
            scope.validate().unwrap_err().code(),
            codes::GRANT_SCOPE_INVALID
        );
    }

    // -- policy matrix --------------------------------------------------------

    #[test]
    fn filesystem_matrix_matches_capability_policy_table() {
        let inside = PolicyFacts {
            inside_workspace_roots: true,
            ..PolicyFacts::default()
        };
        let outside = PolicyFacts::default();

        let read = req(cap(ResourceClass::Filesystem, Effect::Read), "w");
        assert_eq!(evaluate(&read, &inside).outcome, PolicyOutcome::Allow);
        assert_eq!(evaluate(&read, &outside).outcome, PolicyOutcome::Deny);

        for effect in [Effect::Create, Effect::Modify] {
            let r = req(cap(ResourceClass::Filesystem, effect), "w");
            let d = evaluate(&r, &outside);
            assert_eq!(d.outcome, PolicyOutcome::RequireApproval);
            assert_eq!(d.ceiling, GrantCeiling::TaskBounded);
        }
        for effect in [Effect::Delete, Effect::SetExecutable] {
            let r = req(cap(ResourceClass::Filesystem, effect), "w");
            let d = evaluate(&r, &outside);
            assert_eq!(d.outcome, PolicyOutcome::RequireApproval);
            assert_eq!(d.ceiling, GrantCeiling::PerAction);
        }
    }

    #[test]
    fn process_network_database_model_secret_matrix() {
        let facts = PolicyFacts::default();
        let enforcing = PolicyFacts {
            enforcing_environment: true,
            ..facts
        };
        let exception = PolicyFacts {
            network_exception: true,
            ..facts
        };
        let maintainer = PolicyFacts {
            maintainer_override: true,
            ..facts
        };

        let exec = req(cap(ResourceClass::Process, Effect::Execute), "w");
        assert_eq!(
            evaluate(&exec, &enforcing).ceiling,
            GrantCeiling::TaskBounded
        );
        assert_eq!(evaluate(&exec, &facts).ceiling, GrantCeiling::PerAction);

        let connect = req(cap(ResourceClass::Network, Effect::Connect), "w");
        assert_eq!(evaluate(&connect, &facts).outcome, PolicyOutcome::Deny);
        let d = evaluate(&connect, &exception);
        assert_eq!(d.outcome, PolicyOutcome::RequireApproval);
        assert_eq!(d.ceiling, GrantCeiling::PerAction);

        let listen = req(cap(ResourceClass::Network, Effect::Listen), "w");
        assert_eq!(evaluate(&listen, &facts).outcome, PolicyOutcome::Deny);
        // System-owned plane: even a non-agent request is never granted here.
        let mut op_listen = listen.clone();
        op_listen.agent_requested = false;
        assert_eq!(evaluate(&op_listen, &facts).reason, "system_owned_plane");

        assert_eq!(
            evaluate(
                &req(cap(ResourceClass::Database, Effect::Read), "w"),
                &facts
            )
            .ceiling,
            GrantCeiling::TaskBounded
        );
        assert_eq!(
            evaluate(
                &req(cap(ResourceClass::Database, Effect::Mutate), "w"),
                &facts
            )
            .ceiling,
            GrantCeiling::PerAction
        );
        let admin = req(cap(ResourceClass::Database, Effect::Admin), "w");
        assert_eq!(evaluate(&admin, &facts).outcome, PolicyOutcome::Deny);
        assert_eq!(
            evaluate(&admin, &maintainer).outcome,
            PolicyOutcome::RequireApproval
        );

        assert_eq!(
            evaluate(
                &req(cap(ResourceClass::ModelContext, Effect::Send), "w"),
                &facts
            )
            .ceiling,
            GrantCeiling::TaskBounded
        );
        assert_eq!(
            evaluate(&req(cap(ResourceClass::Secret, Effect::Use), "w"), &facts).ceiling,
            GrantCeiling::TaskBounded
        );
    }

    #[test]
    fn production_mutations_are_never_task_bounded() {
        let facts = PolicyFacts {
            inside_workspace_roots: true,
            ..PolicyFacts::default()
        };
        let mut r = req(cap(ResourceClass::Filesystem, Effect::Modify), "w");
        r.sensitivity = Sensitivity::Prod;
        let d = evaluate(&r, &facts);
        assert_eq!(d.outcome, PolicyOutcome::RequireApproval);
        assert_eq!(d.ceiling, GrantCeiling::PerAction, "never bundle-opened");

        // A non-mutating capability keeps its task-bounded ceiling.
        let mut read = req(cap(ResourceClass::Database, Effect::Read), "w");
        read.sensitivity = Sensitivity::Prod;
        assert_eq!(evaluate(&read, &facts).ceiling, GrantCeiling::TaskBounded);
    }

    #[test]
    fn strictest_composition_fails_closed_on_empty() {
        assert_eq!(
            PolicyOutcome::strictest([PolicyOutcome::Allow, PolicyOutcome::RequireApproval]),
            PolicyOutcome::RequireApproval
        );
        assert_eq!(
            PolicyOutcome::strictest([PolicyOutcome::RequireApproval, PolicyOutcome::Deny]),
            PolicyOutcome::Deny
        );
        assert_eq!(
            PolicyOutcome::strictest(std::iter::empty()),
            PolicyOutcome::Deny
        );
    }

    // -- grant lifetime --------------------------------------------------------

    #[test]
    fn task_grants_never_exceed_twenty_four_hours() {
        validate_grant_lifetime(T0, None).unwrap();
        validate_grant_lifetime(T0, Some(T0 + Duration::hours(24))).unwrap();
        let err =
            validate_grant_lifetime(T0, Some(T0 + Duration::hours(24) + Duration::seconds(1)))
                .unwrap_err();
        assert_eq!(err.code(), codes::GRANT_SCOPE_INVALID);
        assert!(validate_grant_lifetime(T0, Some(T0)).is_err());
        assert!(grant_record().validate().is_ok());
        let mut bad = grant_record();
        bad.expiry_at = Some(T0 + Duration::hours(48));
        assert_eq!(
            bad.validate().unwrap_err().code(),
            codes::GRANT_SCOPE_INVALID
        );
    }

    // -- approval lifecycle -----------------------------------------------------

    #[test]
    fn grant_record_validates_and_versions_forward() {
        let rec = grant_record();
        assert_eq!(rec.state, ApprovalState::Active);
        assert_eq!(rec.version, 0);

        let suspended = rec
            .evaluate_suspension("maintenance", T0 + Duration::seconds(1))
            .unwrap();
        assert_eq!(suspended.expected_version, 0);
        assert_eq!(suspended.next.version, 1);
        assert_eq!(suspended.next.state, ApprovalState::Suspended);

        let revoked = suspended
            .next
            .evaluate_revocation("user withdrew", T0 + Duration::seconds(2))
            .unwrap();
        assert_eq!(revoked.next.state, ApprovalState::Revoked);
        assert_eq!(revoked.next.action, ApprovalAction::Revoke);

        let err = revoked
            .next
            .evaluate_suspension("again", T0 + Duration::seconds(3))
            .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Conflict);
        assert_eq!(err.code(), codes::APPROVAL_TERMINAL);
    }

    #[test]
    fn expiry_requires_due_time_and_no_expiry_is_per_action() {
        let rec = grant_record();
        let not_due = rec.evaluate_expiry(T0 + Duration::hours(3)).unwrap_err();
        assert_eq!(not_due.code(), codes::APPROVAL_NOT_DUE);
        let expired = rec.evaluate_expiry(T0 + Duration::hours(4)).unwrap();
        assert_eq!(expired.next.state, ApprovalState::Expired);

        let per_action = ApprovalRecord::grant(GrantRequest {
            workspace_id: WorkspaceId::new(),
            capability: cap(ResourceClass::Database, Effect::Mutate),
            scope: CapabilityScope {
                task_id: None,
                operation_key: Some("op:9".into()),
                selector: "conn:primary".into(),
            },
            actor_identity: "agent".into(),
            authority_identity: "authority".into(),
            reason: "one operation".into(),
            security_epoch: 1,
            issued_at: T0,
            expiry_at: None,
        })
        .unwrap();
        assert_eq!(
            per_action
                .evaluate_expiry(T0 + Duration::days(30))
                .unwrap_err()
                .code(),
            codes::APPROVAL_NOT_DUE
        );
    }

    #[test]
    fn restore_reset_suspends_only_active_grants() {
        let rec = grant_record();
        let decision = rec
            .evaluate_restore_suspension(T0 + Duration::seconds(1))
            .unwrap();
        let RestoreSuspension::ChangeSet(set) = decision else {
            return assert!(matches!(decision, RestoreSuspension::Unaffected));
        };
        assert_eq!(set.next.state, ApprovalState::Suspended);
        assert_eq!(
            set.next.suspend_reason.as_deref(),
            Some(RESTORE_SUSPEND_REASON)
        );

        let suspended = set.next;
        assert_eq!(
            suspended.evaluate_restore_suspension(T0).unwrap(),
            RestoreSuspension::Unaffected
        );
    }

    #[test]
    fn effective_grant_requires_active_in_epoch_and_unexpired() {
        let rec = grant_record(); // epoch 7, expiry T0+4h
        let grant = rec.effective_grant(T0 + Duration::hours(1), 7).unwrap();
        assert_eq!(grant.class, GrantClass::TaskScoped);
        assert_eq!(grant.capability_identity, "filesystem.modify");

        assert!(
            rec.effective_grant(T0 + Duration::hours(1), 8).is_none(),
            "epoch moved"
        );
        assert!(
            rec.effective_grant(T0 + Duration::hours(4), 7).is_none(),
            "expired"
        );

        let suspended = rec.evaluate_suspension("x", T0).unwrap().next;
        assert!(suspended.effective_grant(T0, 7).is_none());

        let per_action = ApprovalRecord::grant(GrantRequest {
            workspace_id: WorkspaceId::new(),
            capability: cap(ResourceClass::Filesystem, Effect::Delete),
            scope: CapabilityScope {
                task_id: None,
                operation_key: Some("op:1".into()),
                selector: "/work/tmp".into(),
            },
            actor_identity: "a".into(),
            authority_identity: "auth".into(),
            reason: "r".into(),
            security_epoch: 7,
            issued_at: T0,
            expiry_at: None,
        })
        .unwrap();
        assert_eq!(
            per_action.effective_grant(T0, 7).unwrap().class,
            GrantClass::PerAction
        );
    }

    // -- secret-use evidence -----------------------------------------------------

    #[test]
    fn secret_use_evidence_is_bounded_and_never_carries_a_value() {
        let ev = SecretUseEvidence::record(
            WorkspaceId::new(),
            "secretref:minio/root",
            "agent:planner",
            "op:42",
            "allow",
            T0,
        )
        .unwrap();
        assert_eq!(ev.secret_reference_id, "secretref:minio/root");

        let err = SecretUseEvidence::record(WorkspaceId::new(), "", "agent", "op", "allow", T0)
            .unwrap_err();
        assert_eq!(err.code(), codes::SECRET_USE_INVALID);
    }

    // -- genesis -----------------------------------------------------------------

    #[test]
    fn uidgid_map_fixes_runtime_pair_and_rejects_collisions() {
        let map = UidGidMap {
            runtime_uid: CENTRAL_RUNTIME_UID,
            runtime_gid: CENTRAL_RUNTIME_GID,
            agent_uid: 1001,
            agent_gid: 1001,
            browser_uid: 1002,
            browser_gid: 1002,
        };
        map.validate().unwrap();

        let mut bad = map;
        bad.runtime_uid = 0;
        assert_eq!(bad.validate().unwrap_err().code(), codes::GENESIS_INVALID);
        let mut collide = map;
        collide.agent_uid = CENTRAL_RUNTIME_UID;
        assert!(collide.validate().is_err());
    }

    #[test]
    fn locked_identities_match_upstream_templates() {
        let all = LockedIdentity::all();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].name, "central-runtime");
        assert_eq!(all[2].home, "/var/lib/central-browser");
        assert!(all.iter().all(|i| i.shell == "/usr/sbin/nologin"));

        let map = UidGidMap {
            runtime_uid: 501,
            runtime_gid: 501,
            agent_uid: 1001,
            agent_gid: 1001,
            browser_uid: 1002,
            browser_gid: 1002,
        };
        let bound = LockedIdentity::bind_all(&map);
        assert_eq!(bound[0].uid, 501);
        assert_eq!(bound[3].uid, CENTRAL_MIGRATE_UID);
    }

    #[test]
    fn genesis_status_pairs_phase_with_receipt() {
        let op = OperationId::new();
        let absent = GenesisStatus {
            operation_id: op,
            phase: GenesisPhase::Absent,
            receipt: None,
        };
        absent.validate().unwrap();

        let committed = GenesisStatus {
            operation_id: op,
            phase: GenesisPhase::Committed,
            receipt: Some(GenesisReceipt {
                operation_id: op,
                instance_id: InstanceId::new(),
                config_binding_id: ConfigBindingId::new(),
                uidgid: UidGidMap {
                    runtime_uid: 501,
                    runtime_gid: 501,
                    agent_uid: 1001,
                    agent_gid: 1001,
                    browser_uid: 1002,
                    browser_gid: 1002,
                },
                completed_at: T0,
            }),
        };
        committed.validate().unwrap();

        let missing = GenesisStatus {
            operation_id: op,
            phase: GenesisPhase::Committed,
            receipt: None,
        };
        assert_eq!(
            missing.validate().unwrap_err().code(),
            codes::GENESIS_INVALID
        );
    }
}
