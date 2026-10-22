//! Workspace domain — lifecycle state machine, quota-ledger predicates,
//! and security/restore epoch transitions.
//!
//! Pure synchronous Rust (rust-application-boundaries.md §2.3/§7.1): no
//! `async fn`, no I/O, no `tokio`. `WorkspaceSnapshot` mirrors the
//! `central.workspaces` row exactly (adapter-mapping §3.1); every
//! mutation is evaluated here into a [`WorkspaceChangeSet`] the adapter
//! commits with expected-state guards, matching the domain-approved
//! change-set contract (§7.2).
//!
//! Epoch semantics follow the capability-policy post-restore authority
//! reset (capability-policy.md §Post-restore authority reset): both
//! epochs move forward only; the restore transaction installs the new
//! epoch through this domain's change set.

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;
use time::OffsetDateTime;

/// Default `quota_max_bytes` for a fresh workspace — 10 GiB, matching the
/// `central.workspaces` column default (adapter-mapping §3.1).
pub const DEFAULT_QUOTA_MAX_BYTES: u64 = 10_737_418_240;

/// `owner_principal_id` of the b20 sentinel workspace row, matching the
/// literal inserted by `migrations/0020_b20_sentinel_workspace_id.sql`.
pub const SENTINEL_OWNER_PRINCIPAL_ID: &str = "system-provisioner";

/// Upper bound on `owner_principal_id` text (defense-in-depth; the column
/// is `text` with no check constraint).
pub const MAX_OWNER_PRINCIPAL_ID_BYTES: usize = 256;

/// Stable machine codes emitted by this domain.
pub mod codes {
    pub const WORKSPACE_INVALID: &str = "workspace_invalid";
    pub const WORKSPACE_NOT_FOUND: &str = "workspace_not_found";
    pub const WORKSPACE_ALREADY_EXISTS: &str = "workspace_already_exists";
    pub const WORKSPACE_ALREADY_DELETED: &str = "workspace_already_deleted";
    pub const WORKSPACE_STATE_CONFLICT: &str = "workspace_state_conflict";
    pub const WORKSPACE_EPOCH_REGRESSED: &str = "workspace_epoch_regressed";
    pub const WORKSPACE_QUOTA_EXCEEDED: &str = "workspace_quota_exceeded";
    pub const WORKSPACE_SENTINEL_PROTECTED: &str = "workspace_sentinel_protected";
}

/// Workspace lifecycle state — `central.workspaces.state`
/// (`CHECK state IN ('active','deleted')`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkspaceState {
    /// Serving state: work may be claimed and recorded.
    Active,
    /// Terminal tombstone: the workspace accepts no new authority or work.
    Deleted,
}

impl WorkspaceState {
    /// Canonical lowercase database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deleted => "deleted",
        }
    }

    /// Parses the canonical database text; rejects anything else
    /// (closed vocabulary — fail closed on drift).
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "active" => Ok(Self::Active),
            "deleted" => Ok(Self::Deleted),
            _ => Err(Failure::invalid(
                codes::WORKSPACE_INVALID,
                "workspace state is outside the closed vocabulary",
            )),
        }
    }

    /// Whether work or authority may still be exercised in this state.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl core::fmt::Display for WorkspaceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for WorkspaceState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for WorkspaceState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// The typed durable decision snapshot for one workspace — one row of
/// `central.workspaces` (adapter-mapping §3.1). `created_at`/`updated_at`
/// are database-authoritative and ride along for projections; the
/// domain never writes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    /// Workspace identity (b20 sentinel admitted).
    pub id: WorkspaceId,
    /// Lifecycle state.
    pub state: WorkspaceState,
    /// Owning local principal identity (bounded text).
    pub owner_principal_id: String,
    /// Ready-artifact bytes currently settled against the quota ledger.
    pub quota_ready_bytes: u64,
    /// Ready-artifact count currently settled against the quota ledger.
    pub quota_ready_count: u64,
    /// Configured ready-byte ceiling (`> 0`).
    pub quota_max_bytes: u64,
    /// Post-restore authority epoch; binds sessions, grants, leases.
    pub security_epoch: u64,
    /// Restore generation epoch; bumps on every restore apply.
    pub restore_epoch: u64,
    /// Database creation timestamp.
    pub created_at: OffsetDateTime,
    /// Database last-mutation timestamp.
    pub updated_at: OffsetDateTime,
}

impl WorkspaceSnapshot {
    /// Validates the snapshot invariants the schema also pins: `state`
    /// in the closed vocabulary (by type), owner bounded and non-empty,
    /// `quota_max_bytes > 0`. The `u64` quota fields carry the schema's
    /// `>= 0` checks by construction.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.owner_principal_id.is_empty()
            || self.owner_principal_id.len() > MAX_OWNER_PRINCIPAL_ID_BYTES
        {
            return Err(Failure::invalid(
                codes::WORKSPACE_INVALID,
                "workspace owner principal id must be 1..=256 bytes",
            ));
        }
        if self.quota_max_bytes == 0 {
            return Err(Failure::invalid(
                codes::WORKSPACE_INVALID,
                "workspace quota_max_bytes must be positive",
            ));
        }
        Ok(())
    }

    /// Whether this is the b20 sentinel workspace row.
    #[must_use]
    pub fn is_sentinel(&self) -> bool {
        self.id.is_sentinel()
    }

    /// Evaluates a delete transition: `active -> deleted`.
    ///
    /// Deleting the sentinel workspace is refused outright — the local
    /// Phase-1 runtime binds every session to the sentinel row, so its
    /// tombstone would strand the instance. An already-deleted row is a
    /// rejected command (conflict), not a silent no-op: the caller sees
    /// that its guard state is stale.
    pub fn evaluate_delete(&self) -> Result<WorkspaceChangeSet, Failure> {
        if self.id.is_sentinel() {
            return Err(Failure::conflict(
                codes::WORKSPACE_SENTINEL_PROTECTED,
                "the sentinel workspace cannot be deleted",
            ));
        }
        if self.state != WorkspaceState::Active {
            return Err(Failure::conflict(
                codes::WORKSPACE_ALREADY_DELETED,
                "the workspace is already deleted",
            ));
        }
        let mut next = self.clone();
        next.state = WorkspaceState::Deleted;
        Ok(WorkspaceChangeSet {
            guard: WorkspaceGuard::from_snapshot(self),
            next,
        })
    }

    /// Evaluates a security-epoch advance. Epochs move forward only:
    /// `target > current` produces a change set; `target == current` is an
    /// approved no-op (the commit still succeeds, nothing changes —
    /// idempotent under restore replay); `target < current` fails closed.
    pub fn evaluate_security_epoch(&self, target: u64) -> Result<EpochDecision, Failure> {
        evaluate_epoch(self.security_epoch, target).map(|decision| match decision {
            EpochAdvance::Unchanged => EpochDecision::Unchanged,
            EpochAdvance::Advance => {
                let mut next = self.clone();
                next.security_epoch = target;
                EpochDecision::ChangeSet(WorkspaceChangeSet {
                    guard: WorkspaceGuard::from_snapshot(self),
                    next,
                })
            }
        })
    }

    /// Evaluates a restore-epoch advance; same forward-only rule as the
    /// security epoch.
    pub fn evaluate_restore_epoch(&self, target: u64) -> Result<EpochDecision, Failure> {
        evaluate_epoch(self.restore_epoch, target).map(|decision| match decision {
            EpochAdvance::Unchanged => EpochDecision::Unchanged,
            EpochAdvance::Advance => {
                let mut next = self.clone();
                next.restore_epoch = target;
                EpochDecision::ChangeSet(WorkspaceChangeSet {
                    guard: WorkspaceGuard::from_snapshot(self),
                    next,
                })
            }
        })
    }

    /// Quota-ledger predicate (adapter-mapping §3.1): a reservation of
    /// `additional_bytes` is admissible iff `ready + additional <= max`.
    ///
    /// The reservation itself is settled by `central-artifact`'s atomic
    /// conditional port at the database linearization point; this pure
    /// rule is the decision both sides share. A deleted workspace admits
    /// no new reservation regardless of headroom.
    pub fn evaluate_reservation(&self, additional_bytes: u64) -> Result<(), Failure> {
        if !self.state.is_live() {
            return Err(Failure::conflict(
                codes::WORKSPACE_ALREADY_DELETED,
                "the workspace does not admit reservations",
            ));
        }
        let headroom = self.quota_max_bytes.saturating_sub(self.quota_ready_bytes);
        if additional_bytes > headroom {
            return Err(Failure::conflict(
                codes::WORKSPACE_QUOTA_EXCEEDED,
                "the workspace ready-byte quota is exhausted",
            ));
        }
        Ok(())
    }

    /// Settlement arithmetic: apply `bytes`/`count` of newly-ready
    /// artifacts to the ledger. The database column-level check rejects a
    /// negative result; the domain rejects overflow before commit.
    pub fn evaluate_settlement(&self, bytes: u64, count: u64) -> Result<QuotaLedger, Failure> {
        let ledger = QuotaLedger::from_snapshot(self);
        ledger.settled(bytes, count)
    }

    /// Release arithmetic: deduct `bytes`/`count` of released reservation
    /// from the ledger. Releasing more than is ready is a conflict — the
    /// schema's `>= 0` checks make it uncommittable anyway.
    pub fn evaluate_release(&self, bytes: u64, count: u64) -> Result<QuotaLedger, Failure> {
        let ledger = QuotaLedger::from_snapshot(self);
        ledger.released(bytes, count)
    }
}

/// Forward-only epoch evaluation shared by both epoch columns.
enum EpochAdvance {
    Unchanged,
    Advance,
}

fn evaluate_epoch(current: u64, target: u64) -> Result<EpochAdvance, Failure> {
    match target.cmp(&current) {
        core::cmp::Ordering::Less => Err(Failure::conflict(
            codes::WORKSPACE_EPOCH_REGRESSED,
            "workspace epochs move forward only",
        )),
        core::cmp::Ordering::Equal => Ok(EpochAdvance::Unchanged),
        core::cmp::Ordering::Greater => Ok(EpochAdvance::Advance),
    }
}

/// Result of an epoch-advance evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochDecision {
    /// The target equals the installed epoch — nothing to commit.
    Unchanged,
    /// An approved change set advancing the epoch.
    ChangeSet(WorkspaceChangeSet),
}

/// The quota-ledger projection of a snapshot — the three counters the
/// capacity ports read and mutate atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLedger {
    /// Ready-artifact bytes settled against the quota.
    pub ready_bytes: u64,
    /// Ready-artifact count settled against the quota.
    pub ready_count: u64,
    /// Configured ready-byte ceiling.
    pub max_bytes: u64,
}

impl QuotaLedger {
    /// Projects the ledger from a snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &WorkspaceSnapshot) -> Self {
        Self {
            ready_bytes: snapshot.quota_ready_bytes,
            ready_count: snapshot.quota_ready_count,
            max_bytes: snapshot.quota_max_bytes,
        }
    }

    /// Whether `additional_bytes` fits under the ceiling.
    #[must_use]
    pub fn admits(&self, additional_bytes: u64) -> bool {
        additional_bytes <= self.max_bytes.saturating_sub(self.ready_bytes)
    }

    /// The ledger after settling `bytes`/`count` of newly-ready work.
    /// Overflow is a conflict — the schema's `>= 0` checks cannot express
    /// an upper overflow, so the domain owns it.
    pub fn settled(&self, bytes: u64, count: u64) -> Result<Self, Failure> {
        let next = Self {
            ready_bytes: self
                .ready_bytes
                .checked_add(bytes)
                .ok_or_else(quota_overflow)?,
            ready_count: self
                .ready_count
                .checked_add(count)
                .ok_or_else(quota_overflow)?,
            max_bytes: self.max_bytes,
        };
        Ok(next)
    }

    /// The ledger after releasing `bytes`/`count` of reservation.
    /// Underflow is a conflict — it would violate the `>= 0` checks.
    pub fn released(&self, bytes: u64, count: u64) -> Result<Self, Failure> {
        let underflow = || {
            Failure::conflict(
                codes::WORKSPACE_QUOTA_EXCEEDED,
                "release exceeds the ready quota ledger",
            )
        };
        Ok(Self {
            ready_bytes: self.ready_bytes.checked_sub(bytes).ok_or_else(underflow)?,
            ready_count: self.ready_count.checked_sub(count).ok_or_else(underflow)?,
            max_bytes: self.max_bytes,
        })
    }
}

fn quota_overflow() -> Failure {
    Failure::conflict(
        codes::WORKSPACE_QUOTA_EXCEEDED,
        "the quota ledger cannot represent the settlement",
    )
}

/// The optimistic-concurrency guard a [`WorkspaceChangeSet`] commits
/// under. `workspaces` has no `version` column; the guard pins the
/// mutable columns the domain's decision depended on (state + epochs) so
/// a concurrent mutation surfaces as a conflict instead of a silent
/// overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceGuard {
    /// The row must not exist (create).
    Absent,
    /// The row must currently carry exactly these facts.
    Present {
        /// Expected lifecycle state.
        state: WorkspaceState,
        /// Expected security epoch.
        security_epoch: u64,
        /// Expected restore epoch.
        restore_epoch: u64,
    },
}

impl WorkspaceGuard {
    /// The guard pinning a loaded snapshot's decision-relevant columns.
    #[must_use]
    pub fn from_snapshot(snapshot: &WorkspaceSnapshot) -> Self {
        Self::Present {
            state: snapshot.state,
            security_epoch: snapshot.security_epoch,
            restore_epoch: snapshot.restore_epoch,
        }
    }
}

/// A domain-approved workspace mutation with its concurrency guard —
/// the unit [`crate::port::WorkspaceStore::commit_change_set`] commits
/// atomically. `next` is the full intended row; `updated_at` is ignored
/// by the adapter, which stamps database time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceChangeSet {
    /// Expected current facts (or required absence) at commit time.
    pub guard: WorkspaceGuard,
    /// The next durable row state.
    pub next: WorkspaceSnapshot,
}

/// Command input for workspace creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceCommand {
    /// Fresh workspace identity (or the sentinel id for provisioning).
    pub workspace_id: WorkspaceId,
    /// Owning principal identity.
    pub owner_principal_id: String,
    /// Ready-byte ceiling; `None` installs [`DEFAULT_QUOTA_MAX_BYTES`].
    pub quota_max_bytes: Option<u64>,
}

/// Evaluates a create command: validates inputs, builds the `active`
/// snapshot with zeroed quota ledger and epochs, guarded on absence.
///
/// The sentinel workspace is provisioned by migration `0020_b20`; this
/// path exists for post-install workspaces and for idempotent
/// provisioning replays (the adapter's `Absent` guard maps a duplicate
/// insert to [`codes::WORKSPACE_ALREADY_EXISTS`] conflict).
pub fn evaluate_create(
    cmd: CreateWorkspaceCommand,
    now: OffsetDateTime,
) -> Result<WorkspaceChangeSet, Failure> {
    let quota_max_bytes = cmd.quota_max_bytes.unwrap_or(DEFAULT_QUOTA_MAX_BYTES);
    let snapshot = WorkspaceSnapshot {
        id: cmd.workspace_id,
        state: WorkspaceState::Active,
        owner_principal_id: cmd.owner_principal_id,
        quota_ready_bytes: 0,
        quota_ready_count: 0,
        quota_max_bytes,
        security_epoch: 0,
        restore_epoch: 0,
        created_at: now,
        updated_at: now,
    };
    snapshot.validate()?;
    Ok(WorkspaceChangeSet {
        guard: WorkspaceGuard::Absent,
        next: snapshot,
    })
}

/// The Phase-1 sentinel provisioning command: the fixed b20 identity,
/// the `system-provisioner` owner, the default quota ceiling.
#[must_use]
pub fn sentinel_create_command() -> CreateWorkspaceCommand {
    CreateWorkspaceCommand {
        workspace_id: WorkspaceId::sentinel(),
        owner_principal_id: SENTINEL_OWNER_PRINCIPAL_ID.to_string(),
        quota_max_bytes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-10-21 12:00 UTC);

    fn snapshot() -> WorkspaceSnapshot {
        WorkspaceSnapshot {
            id: WorkspaceId::new(),
            state: WorkspaceState::Active,
            owner_principal_id: "local-operator".to_string(),
            quota_ready_bytes: 100,
            quota_ready_count: 2,
            quota_max_bytes: 1_000,
            security_epoch: 3,
            restore_epoch: 1,
            created_at: NOW,
            updated_at: NOW,
        }
    }

    fn sentinel_snapshot() -> WorkspaceSnapshot {
        WorkspaceSnapshot {
            id: WorkspaceId::sentinel(),
            owner_principal_id: SENTINEL_OWNER_PRINCIPAL_ID.to_string(),
            quota_max_bytes: DEFAULT_QUOTA_MAX_BYTES,
            ..snapshot()
        }
    }

    #[test]
    fn state_vocabulary_is_closed_and_canonical() {
        assert_eq!(WorkspaceState::Active.as_str(), "active");
        assert_eq!(WorkspaceState::Deleted.as_str(), "deleted");
        assert_eq!(
            WorkspaceState::parse("active").unwrap(),
            WorkspaceState::Active
        );
        assert_eq!(
            WorkspaceState::parse("deleted").unwrap(),
            WorkspaceState::Deleted
        );
        for bad in ["", "Active", "archived", "suspended", " deleted"] {
            assert!(WorkspaceState::parse(bad).is_err(), "admitted {bad:?}");
        }
        assert!(WorkspaceState::Active.is_live());
        assert!(!WorkspaceState::Deleted.is_live());
    }

    #[test]
    fn validate_enforces_owner_bound_and_positive_ceiling() {
        let mut s = snapshot();
        assert!(s.validate().is_ok());

        s.owner_principal_id.clear();
        assert_eq!(s.validate().unwrap_err().code(), codes::WORKSPACE_INVALID);

        s.owner_principal_id = "x".repeat(MAX_OWNER_PRINCIPAL_ID_BYTES + 1);
        assert_eq!(s.validate().unwrap_err().code(), codes::WORKSPACE_INVALID);

        s.owner_principal_id = "ok".to_string();
        s.quota_max_bytes = 0;
        assert_eq!(s.validate().unwrap_err().code(), codes::WORKSPACE_INVALID);
    }

    #[test]
    fn create_builds_active_zeroed_snapshot_guarded_on_absence() {
        let cmd = CreateWorkspaceCommand {
            workspace_id: WorkspaceId::new(),
            owner_principal_id: "local-operator".to_string(),
            quota_max_bytes: None,
        };
        let set = evaluate_create(cmd, NOW).unwrap();
        assert_eq!(set.guard, WorkspaceGuard::Absent);
        assert_eq!(set.next.state, WorkspaceState::Active);
        assert_eq!(set.next.quota_ready_bytes, 0);
        assert_eq!(set.next.quota_ready_count, 0);
        assert_eq!(set.next.quota_max_bytes, DEFAULT_QUOTA_MAX_BYTES);
        assert_eq!(set.next.security_epoch, 0);
        assert_eq!(set.next.restore_epoch, 0);
        assert_eq!(set.next.created_at, NOW);
    }

    #[test]
    fn create_rejects_invalid_inputs() {
        let base = CreateWorkspaceCommand {
            workspace_id: WorkspaceId::new(),
            owner_principal_id: "local-operator".to_string(),
            quota_max_bytes: None,
        };
        let mut cmd = base.clone();
        cmd.owner_principal_id.clear();
        assert!(evaluate_create(cmd, NOW).is_err());

        let mut cmd = base;
        cmd.quota_max_bytes = Some(0);
        assert!(evaluate_create(cmd, NOW).is_err());
    }

    #[test]
    fn sentinel_create_command_matches_the_b20_row() {
        let cmd = sentinel_create_command();
        assert_eq!(cmd.workspace_id, WorkspaceId::sentinel());
        assert_eq!(cmd.owner_principal_id, SENTINEL_OWNER_PRINCIPAL_ID);
        let set = evaluate_create(cmd, NOW).unwrap();
        assert_eq!(set.next.quota_max_bytes, DEFAULT_QUOTA_MAX_BYTES);
    }

    #[test]
    fn delete_transitions_active_to_deleted_under_guard() {
        let s = snapshot();
        let set = s.evaluate_delete().unwrap();
        assert_eq!(set.guard, WorkspaceGuard::from_snapshot(&s));
        assert_eq!(set.next.state, WorkspaceState::Deleted);
        // Only the state changed.
        assert_eq!(set.next.owner_principal_id, s.owner_principal_id);
        assert_eq!(set.next.security_epoch, s.security_epoch);
    }

    #[test]
    fn delete_rejects_already_deleted_and_sentinel() {
        let mut s = snapshot();
        s.state = WorkspaceState::Deleted;
        assert_eq!(
            s.evaluate_delete().unwrap_err().code(),
            codes::WORKSPACE_ALREADY_DELETED
        );

        let sentinel = sentinel_snapshot();
        assert_eq!(
            sentinel.evaluate_delete().unwrap_err().code(),
            codes::WORKSPACE_SENTINEL_PROTECTED
        );
    }

    #[test]
    fn epochs_move_forward_only() {
        let s = snapshot();

        // Advance produces a guarded change set.
        let decision = s.evaluate_security_epoch(4).unwrap();
        let EpochDecision::ChangeSet(set) = decision else {
            return assert!(
                matches!(decision, EpochDecision::ChangeSet(_)),
                "expected a change set"
            );
        };
        assert_eq!(set.next.security_epoch, 4);
        assert_eq!(set.next.restore_epoch, s.restore_epoch);
        assert_eq!(
            set.guard,
            WorkspaceGuard::Present {
                state: WorkspaceState::Active,
                security_epoch: 3,
                restore_epoch: 1,
            }
        );

        // Equal is an approved no-op (idempotent restore replay).
        assert_eq!(
            s.evaluate_security_epoch(3).unwrap(),
            EpochDecision::Unchanged
        );
        assert_eq!(
            s.evaluate_restore_epoch(1).unwrap(),
            EpochDecision::Unchanged
        );

        // Regression fails closed.
        assert_eq!(
            s.evaluate_security_epoch(2).unwrap_err().code(),
            codes::WORKSPACE_EPOCH_REGRESSED
        );
        assert_eq!(
            s.evaluate_restore_epoch(0).unwrap_err().code(),
            codes::WORKSPACE_EPOCH_REGRESSED
        );

        let decision = s.evaluate_restore_epoch(9).unwrap();
        assert!(matches!(
            decision,
            EpochDecision::ChangeSet(WorkspaceChangeSet {
                next: WorkspaceSnapshot {
                    restore_epoch: 9,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn reservation_admits_within_headroom_only() {
        let s = snapshot(); // ready 100 / max 1000
        assert!(s.evaluate_reservation(900).is_ok());
        assert!(s.evaluate_reservation(0).is_ok());
        assert_eq!(
            s.evaluate_reservation(901).unwrap_err().code(),
            codes::WORKSPACE_QUOTA_EXCEEDED
        );
        assert_eq!(
            s.evaluate_reservation(u64::MAX).unwrap_err().code(),
            codes::WORKSPACE_QUOTA_EXCEEDED
        );

        let mut deleted = snapshot();
        deleted.state = WorkspaceState::Deleted;
        assert_eq!(
            deleted.evaluate_reservation(1).unwrap_err().code(),
            codes::WORKSPACE_ALREADY_DELETED
        );
    }

    #[test]
    fn quota_ledger_arithmetic_is_total_and_guarded() {
        let ledger = QuotaLedger::from_snapshot(&snapshot());
        assert!(ledger.admits(900));
        assert!(!ledger.admits(901));

        let settled = ledger.settled(50, 3).unwrap();
        assert_eq!(settled.ready_bytes, 150);
        assert_eq!(settled.ready_count, 5);

        let released = settled.released(150, 5).unwrap();
        assert_eq!(released.ready_bytes, 0);
        assert_eq!(released.ready_count, 0);
        assert_eq!(released.max_bytes, 1_000);

        // Underflow and overflow both fail as conflicts.
        assert_eq!(
            ledger.released(101, 0).unwrap_err().code(),
            codes::WORKSPACE_QUOTA_EXCEEDED
        );
        assert_eq!(
            ledger.settled(u64::MAX, 0).unwrap_err().code(),
            codes::WORKSPACE_QUOTA_EXCEEDED
        );
    }
}
