//! `internal/backup/recovery.go` — the C01 durable backup operation:
//! `BackupPhase`, the closed failure-reason vocabulary,
//! `BackupAcceptedFacts`, `BackupOperation` with `Accept`/`Advance`/
//! `Fail`, `BackupSealProposal` and `DumpEvidence`.

use central_foundation::failure::Failure;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::domain::TargetIdentity;
use crate::wire::{is_v7, is_zero_time, valid_sha256_fingerprint};

use super::capacity::MAXIMUM_SEAL_ROOT_MANIFEST_BYTES;

fn invalid_backup() -> Failure {
    Failure::invalid("backup_recovery", "invalid recovery backup operation")
}

/// `BackupTargetLockProtocol`.
pub const BACKUP_TARGET_LOCK_PROTOCOL: &str = "central.target-exclusive/v1";
/// `BackupInventoryBoundary`.
pub const BACKUP_INVENTORY_BOUNDARY: &str = "central.ready-artifact-inventory/v1";
/// `BackupDumpToolVersion` — the pinned `pg_dump` version.
pub const BACKUP_DUMP_TOOL_VERSION: &str = "pg_dump-16.14";
/// `BackupChecksumManifest`.
pub const BACKUP_CHECKSUM_MANIFEST: &str = "central.sha256/v1";
/// `BackupRootSealScheme`.
pub const BACKUP_ROOT_SEAL_SCHEME: &str = "central.broker-hmac/v1";
/// `BackupServiceIdentity`.
pub const BACKUP_SERVICE_IDENTITY: &str = "central-backup-worker/v1";
/// `BackupDatabaseSchemaVersion` — the sealed schema identity (b37).
pub const BACKUP_DATABASE_SCHEMA_VERSION: &str = "central.schema-manifest/v1";

/// `PinnedBackupConfiguration` — the exact, fixed database-connection
/// configuration every real backup worker's
/// `AcceptedFacts.ConfigFingerprint` is derived from
/// (`internal/adapter/postgres/backup/accepted_facts.go`). SC-DEF-50:
/// the C02 probe's `ConfigDigest` binds to this exact value.
pub const PINNED_BACKUP_CONFIGURATION: &str = concat!(
    "central.local-postgres/v1\u{0}127.0.0.1\u{0}55432\u{0}central\u{0}central_runtime\u{0}",
    "pg_dump-16.14"
);

/// `RecoveryBootstrapRegistrationTable` — the one `central` relation
/// `central_runtime` is deliberately never granted privileges on
/// (migrate b26). A real backup's `pg_dump` must pass this to
/// `--exclude-table` (SC-DEF-52).
pub const RECOVERY_BOOTSTRAP_REGISTRATION_TABLE: &str = "central.recovery_bootstrap_registrations";

/// `BackupPhase` — the C01 durable operation lifecycle. Once admitted,
/// an ordinary backup never resumes after interruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupPhase {
    /// `planned`.
    #[default]
    Planned,
    /// `admitted`.
    Admitted,
    /// `dumping`.
    Dumping,
    /// `inventory`.
    Inventory,
    /// `sealing`.
    Sealing,
    /// `sealed`.
    Sealed,
    /// `failed`.
    Failed,
}

impl BackupPhase {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Admitted => "admitted",
            Self::Dumping => "dumping",
            Self::Inventory => "inventory",
            Self::Sealing => "sealing",
            Self::Sealed => "sealed",
            Self::Failed => "failed",
        }
    }

    /// `ValidTransitions`.
    #[must_use]
    pub fn valid_transitions(self) -> &'static [BackupPhase] {
        match self {
            Self::Planned => &[Self::Admitted],
            Self::Admitted => &[Self::Dumping, Self::Failed],
            Self::Dumping => &[Self::Inventory, Self::Failed],
            Self::Inventory => &[Self::Sealing, Self::Failed],
            Self::Sealing => &[Self::Sealed, Self::Failed],
            _ => &[],
        }
    }

    /// `CanTransition`.
    #[must_use]
    pub fn can_transition(self, next: BackupPhase) -> bool {
        self.valid_transitions().contains(&next)
    }

    /// `IsTerminal`.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Sealed | Self::Failed)
    }

    /// `IsResumable` — intentionally false from admission onwards:
    /// verification can be retried separately, but an interrupted
    /// ordinary backup needs a new operation and consistent point.
    #[must_use]
    pub const fn is_resumable(self) -> bool {
        matches!(self, Self::Planned)
    }
}

/// The closed, locator-free backup failure vocabulary persisted in the
/// protected operation (`BackupFailure*` constants).
pub mod backup_failure {
    /// Continuity guard lost after acceptance.
    pub const CONTINUITY_LOST: &str = "BACKUP_CONTINUITY_LOST";
    /// Repository bind refused.
    pub const REPOSITORY_BIND: &str = "BACKUP_REPOSITORY_BIND_FAILED";
    /// `pg_dump` did not start.
    pub const DUMP_START: &str = "BACKUP_DUMP_START_FAILED";
    /// Dump copy failed.
    pub const DUMP_WRITE: &str = "BACKUP_DUMP_WRITE_FAILED";
    /// A ready artifact body disagreed with its sealed metadata after
    /// every retry.
    pub const CORRUPTED_UNRECOVERABLE_BODY: &str = "BACKUP_CORRUPTED_UNRECOVERABLE_BODY";
    /// Chunk write refused.
    pub const INVENTORY_WRITE: &str = "BACKUP_INVENTORY_WRITE_FAILED";
    /// Manifest write refused.
    pub const MANIFEST_WRITE: &str = "BACKUP_MANIFEST_WRITE_FAILED";
    /// The seal proposal itself was invalid.
    pub const SEAL_PROPOSAL: &str = "BACKUP_SEAL_PROPOSAL_INVALID";
    /// The broker seal call failed.
    pub const SEAL: &str = "BACKUP_SEAL_FAILED";
    /// The broker's seal companion did not bind the proposal.
    pub const SEAL_RESPONSE: &str = "BACKUP_SEAL_RESPONSE_INVALID";
    /// Publication outcome unknown.
    pub const SEAL_PUBLICATION: &str = "BACKUP_SEAL_PUBLICATION_UNKNOWN";
}

/// `validBackupFailureReason`.
#[must_use]
pub fn valid_backup_failure_reason(reason: &str) -> bool {
    use backup_failure::*;
    matches!(
        reason,
        CONTINUITY_LOST
            | REPOSITORY_BIND
            | DUMP_START
            | DUMP_WRITE
            | CORRUPTED_UNRECOVERABLE_BODY
            | INVENTORY_WRITE
            | MANIFEST_WRITE
            | SEAL_PROPOSAL
            | SEAL
            | SEAL_RESPONSE
            | SEAL_PUBLICATION
    )
}

/// `BackupAcceptedFacts` — the locator-free, immutable inputs captured
/// by the trusted backup environment while it owns the exact target
/// and repository capabilities. `database_time` is the accepted point
/// and must come from the target database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupAcceptedFacts {
    /// The accepted consistent point (target database time).
    pub database_time: time::OffsetDateTime,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// `sha256:`-prefixed pinned-config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: Uuid,
    /// Repository binding identity.
    pub repository_binding_id: Uuid,
    /// Fixed [`BACKUP_TARGET_LOCK_PROTOCOL`].
    pub target_lock_protocol: String,
    /// `sha256:`-prefixed target-lock proof.
    pub target_lock_proof: String,
    /// Fixed [`BACKUP_INVENTORY_BOUNDARY`].
    pub inventory_boundary: String,
    /// Fixed [`BACKUP_DATABASE_SCHEMA_VERSION`].
    pub database_schema_version: String,
    /// Fixed [`BACKUP_DUMP_TOOL_VERSION`].
    pub tool_version: String,
    /// Fixed [`BACKUP_CHECKSUM_MANIFEST`].
    pub checksum_manifest: String,
    /// Fixed [`BACKUP_SERVICE_IDENTITY`].
    pub service_identity: String,
}

impl Default for BackupAcceptedFacts {
    /// The unset shape `Validate` refuses and `planned` operations carry.
    fn default() -> Self {
        Self {
            database_time: crate::wire::zero_time(),
            target_fingerprint: String::new(),
            config_fingerprint: String::new(),
            payload_epoch_id: uuid::Uuid::nil(),
            repository_binding_id: uuid::Uuid::nil(),
            target_lock_protocol: String::new(),
            target_lock_proof: String::new(),
            inventory_boundary: String::new(),
            database_schema_version: String::new(),
            tool_version: String::new(),
            checksum_manifest: String::new(),
            service_identity: String::new(),
        }
    }
}

/// `NewBackupAcceptedFacts` — closes the versioned fields so adapters
/// cannot widen the installed C01 format.
pub fn new_backup_accepted_facts(
    database_time: time::OffsetDateTime,
    target_fingerprint: &str,
    config_fingerprint: &str,
    payload_epoch_id: Uuid,
    repository_binding_id: Uuid,
    target_lock_proof: &str,
) -> Result<BackupAcceptedFacts, Failure> {
    let facts = BackupAcceptedFacts {
        database_time: database_time.to_offset(time::UtcOffset::UTC),
        target_fingerprint: target_fingerprint.to_owned(),
        config_fingerprint: config_fingerprint.to_owned(),
        payload_epoch_id,
        repository_binding_id,
        target_lock_protocol: BACKUP_TARGET_LOCK_PROTOCOL.into(),
        target_lock_proof: target_lock_proof.into(),
        inventory_boundary: BACKUP_INVENTORY_BOUNDARY.into(),
        database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
        tool_version: BACKUP_DUMP_TOOL_VERSION.into(),
        checksum_manifest: BACKUP_CHECKSUM_MANIFEST.into(),
        service_identity: BACKUP_SERVICE_IDENTITY.into(),
    };
    facts.validate()?;
    Ok(facts)
}

impl BackupAcceptedFacts {
    /// `Validate`.
    pub fn validate(&self) -> Result<(), Failure> {
        if is_zero_time(self.database_time)
            || !valid_sha256_fingerprint(&self.target_fingerprint)
            || !valid_sha256_fingerprint(&self.config_fingerprint)
            || !is_v7(self.payload_epoch_id)
            || self.repository_binding_id.is_nil()
            || self.target_lock_protocol != BACKUP_TARGET_LOCK_PROTOCOL
            || !valid_sha256_fingerprint(&self.target_lock_proof)
            || self.inventory_boundary != BACKUP_INVENTORY_BOUNDARY
            || self.database_schema_version != BACKUP_DATABASE_SCHEMA_VERSION
            || self.tool_version != BACKUP_DUMP_TOOL_VERSION
            || self.checksum_manifest != BACKUP_CHECKSUM_MANIFEST
            || self.service_identity != BACKUP_SERVICE_IDENTITY
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid accepted backup facts",
            ));
        }
        Ok(())
    }
}

/// `BackupOperation` — the durable C01 command snapshot. The accepted
/// point is set exactly once, at the transition that begins
/// exclusive-target mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOperation {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Backup identity.
    pub backup_id: Uuid,
    /// Target identity the operation binds.
    pub target: TargetIdentity,
    /// Accepted-point trusted facts (empty until `Admitted`).
    pub accepted_facts: BackupAcceptedFacts,
    /// Journal CAS fence.
    pub revision: u64,
    /// Current lifecycle phase.
    pub phase: BackupPhase,
    /// Closed failure reason (`failed` phase only).
    pub failure_reason: String,
    /// Creation time (UTC).
    pub created_at: time::OffsetDateTime,
    /// Accepted consistent point (target database time).
    pub accepted_at: time::OffsetDateTime,
    /// Last update (UTC).
    pub updated_at: time::OffsetDateTime,
}

/// `NewBackupOperation`.
pub fn new_backup_operation(
    operation_id: Uuid,
    backup_id: Uuid,
    target: TargetIdentity,
    created_at: time::OffsetDateTime,
) -> Result<BackupOperation, Failure> {
    if operation_id.is_nil() || backup_id.is_nil() || !target.is_valid() || is_zero_time(created_at)
    {
        return Err(invalid_backup());
    }
    let created_at = created_at.to_offset(time::UtcOffset::UTC);
    Ok(BackupOperation {
        operation_id,
        backup_id,
        target,
        accepted_facts: BackupAcceptedFacts::default(),
        revision: 1,
        phase: BackupPhase::Planned,
        failure_reason: String::new(),
        created_at,
        accepted_at: crate::wire::zero_time(),
        updated_at: created_at,
    })
}

impl BackupOperation {
    /// `Validate` — the complete persisted shape a journal accepts.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.operation_id.is_nil()
            || self.backup_id.is_nil()
            || !self.target.is_valid()
            || self.revision == 0
            || is_zero_time(self.created_at)
            || is_zero_time(self.updated_at)
            || self.updated_at < self.created_at
        {
            return Err(invalid_backup());
        }
        match self.phase {
            BackupPhase::Planned => {
                if !is_zero_time(self.accepted_at)
                    || self.accepted_facts != BackupAcceptedFacts::default()
                    || !self.failure_reason.is_empty()
                {
                    return Err(invalid_backup());
                }
            }
            BackupPhase::Admitted
            | BackupPhase::Dumping
            | BackupPhase::Inventory
            | BackupPhase::Sealing
            | BackupPhase::Sealed => {
                if self.accepted_facts.validate().is_err()
                    || is_zero_time(self.accepted_at)
                    || self.accepted_at
                        != self
                            .accepted_facts
                            .database_time
                            .to_offset(time::UtcOffset::UTC)
                    || self.accepted_at < self.created_at
                    || self.updated_at < self.accepted_at
                    || !self.failure_reason.is_empty()
                {
                    return Err(invalid_backup());
                }
            }
            BackupPhase::Failed => {
                if self.accepted_facts.validate().is_err()
                    || is_zero_time(self.accepted_at)
                    || self.accepted_at
                        != self
                            .accepted_facts
                            .database_time
                            .to_offset(time::UtcOffset::UTC)
                    || self.accepted_at < self.created_at
                    || self.updated_at < self.accepted_at
                    || !valid_backup_failure_reason(&self.failure_reason)
                {
                    return Err(invalid_backup());
                }
            }
        }
        Ok(())
    }

    /// `Accept` — records the trusted offline consistent point in the
    /// same protected transition that moves `planned` to `admitted`.
    /// Deliberately separate from [`BackupOperation::advance`] so
    /// generic phase progression cannot fabricate accepted facts.
    pub fn accept(&self, facts: BackupAcceptedFacts) -> Result<Self, Failure> {
        if self.validate().is_err()
            || self.phase != BackupPhase::Planned
            || facts.validate().is_err()
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery backup admission",
            ));
        }
        let accepted_at = facts.database_time.to_offset(time::UtcOffset::UTC);
        if accepted_at < self.created_at {
            return Err(Failure::invalid(
                "backup_recovery",
                "recovery backup accepted point moved backwards",
            ));
        }
        let mut next = self.clone();
        next.phase = BackupPhase::Admitted;
        next.revision += 1;
        next.accepted_at = accepted_at;
        next.accepted_facts = facts;
        next.updated_at = accepted_at;
        Ok(next)
    }

    /// `Advance` — the one-way operation state transition. Only
    /// admission can establish a consistent point; terminal
    /// operations cannot be reopened.
    pub fn advance(&self, next: BackupPhase, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.validate().is_err() || is_zero_time(at) {
            return Err(invalid_backup());
        }
        if next == BackupPhase::Failed || !self.phase.can_transition(next) {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery backup operation transition",
            ));
        }
        if at < self.updated_at {
            return Err(Failure::invalid(
                "backup_recovery",
                "recovery backup operation timestamp moved backwards",
            ));
        }
        let mut next_operation = self.clone();
        next_operation.phase = next;
        next_operation.revision += 1;
        next_operation.updated_at = at.to_offset(time::UtcOffset::UTC);
        if next == BackupPhase::Admitted {
            return Err(Failure::invalid(
                "backup_recovery",
                "recovery backup admission requires trusted facts",
            ));
        } else if is_zero_time(self.accepted_at) {
            return Err(Failure::invalid(
                "backup_recovery",
                "recovery backup operation advanced without accepted point",
            ));
        }
        Ok(next_operation)
    }

    /// `Fail` — persists one closed terminal reason.
    pub fn fail(&self, reason: &str, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.validate().is_err()
            || !self.phase.can_transition(BackupPhase::Failed)
            || !valid_backup_failure_reason(reason)
            || is_zero_time(at)
            || at < self.updated_at
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery backup failure",
            ));
        }
        let mut next = self.clone();
        next.phase = BackupPhase::Failed;
        next.failure_reason = reason.to_owned();
        next.revision += 1;
        next.updated_at = at.to_offset(time::UtcOffset::UTC);
        Ok(next)
    }
}

/// `DumpEvidence` — the bounded, non-secret result of copying a
/// `pg_dump` output into the recovery repository. The root inventory
/// binds its digest before a broker seal can make the backup
/// restorable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DumpEvidence {
    /// Dump byte length.
    pub size: i64,
    /// SHA-256 of the dump bytes.
    pub digest: [u8; 32],
}

impl DumpEvidence {
    /// `Validate` — a PostgreSQL custom archive always has a header;
    /// an empty stream must never let a SHA-256 of zero bytes enter a
    /// sealed manifest.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.size <= 0 || self.digest == [0u8; 32] {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery dump evidence",
            ));
        }
        Ok(())
    }
}

/// `BackupSealProposal` — the complete non-secret input to the
/// broker's seal commit. A broker HMAC or journal receipt is
/// deliberately absent: that material stays in protected state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSealProposal {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Backup identity.
    pub backup_id: Uuid,
    /// Target identity the seal binds.
    pub target: TargetIdentity,
    /// Accepted consistent point.
    pub accepted_at: time::OffsetDateTime,
    /// Repository binding identity.
    pub repository_binding_id: Uuid,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// `sha256:`-prefixed config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: Uuid,
    /// The exact canonical seal-root manifest bytes.
    pub root_manifest_json: Vec<u8>,
    /// SHA-256 of `root_manifest_json`.
    pub manifest_digest: [u8; 32],
    /// SHA-256 of the ordered file-tree evidence.
    pub file_tree_digest: [u8; 32],
    /// Proposal time.
    pub proposed_at: time::OffsetDateTime,
}

impl BackupSealProposal {
    /// `Validate` — re-parses the manifest bytes and binds every
    /// identity the broker will seal against.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid =
            || Failure::invalid("backup_recovery", "invalid recovery backup seal proposal");
        let invalid_manifest = || {
            Failure::invalid(
                "backup_recovery",
                "invalid recovery backup seal proposal manifest",
            )
        };
        if self.operation_id.is_nil()
            || self.backup_id.is_nil()
            || !self.target.is_valid()
            || is_zero_time(self.accepted_at)
            || is_zero_time(self.proposed_at)
            || self.proposed_at < self.accepted_at
            || self.repository_binding_id.is_nil()
            || !valid_sha256_fingerprint(&self.target_fingerprint)
            || !valid_sha256_fingerprint(&self.config_fingerprint)
            || !is_v7(self.payload_epoch_id)
            || self.root_manifest_json.is_empty()
            || self.root_manifest_json.len() as u64 > MAXIMUM_SEAL_ROOT_MANIFEST_BYTES
            || self.manifest_digest == [0u8; 32]
            || self.file_tree_digest == [0u8; 32]
        {
            return Err(invalid());
        }
        let references = super::manifest::parse_seal_root_references(&self.root_manifest_json)
            .map_err(|_| invalid_manifest())?;
        if Sha256::digest(&self.root_manifest_json).as_slice() != self.manifest_digest
            || references.operation_id != self.operation_id
            || references.backup_id != self.backup_id
            || references.repository_binding_id != self.repository_binding_id
            || references.accepted_facts.database_time != self.accepted_at
            || references.accepted_facts.target_fingerprint != self.target_fingerprint
            || references.accepted_facts.config_fingerprint != self.config_fingerprint
            || references.accepted_facts.payload_epoch_id != self.payload_epoch_id
        {
            return Err(invalid_manifest());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        }
    }

    fn facts(at: time::OffsetDateTime) -> BackupAcceptedFacts {
        new_backup_accepted_facts(
            at,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            &format!("sha256:{}", "c".repeat(64)),
        )
        .unwrap()
    }

    #[test]
    fn accepted_facts_require_pinned_versions() {
        let at = datetime!(2026-03-01 12:00:00 UTC);
        assert!(
            new_backup_accepted_facts(
                at,
                "not-a-digest",
                &format!("sha256:{}", "b".repeat(64)),
                uuid::Uuid::now_v7(),
                uuid::Uuid::now_v7(),
                &format!("sha256:{}", "c".repeat(64)),
            )
            .is_err()
        );
        // A v4 payload epoch is refused — only v7 is admitted.
        let mut f = facts(at);
        f.payload_epoch_id = uuid::Uuid::new_v4();
        assert!(f.validate().is_err());
    }

    #[test]
    fn operation_lifecycle() {
        let created = datetime!(2026-03-01 12:00:00 UTC);
        let op = new_backup_operation(Uuid::now_v7(), Uuid::now_v7(), target(), created).unwrap();
        assert_eq!(op.phase, BackupPhase::Planned);
        assert!(op.validate().is_ok());
        // A planned operation cannot advance without accepted facts.
        assert!(op.advance(BackupPhase::Dumping, created).is_err());
        // Nil/empty subjects are refused at construction.
        assert!(new_backup_operation(Uuid::nil(), Uuid::now_v7(), target(), created).is_err());
        assert!(
            new_backup_operation(
                Uuid::now_v7(),
                Uuid::now_v7(),
                TargetIdentity::default(),
                created
            )
            .is_err()
        );
        // Accepted point cannot precede creation.
        assert!(op.accept(facts(created - time::Duration::SECOND)).is_err());
        let admitted = op.accept(facts(created)).unwrap();
        assert_eq!(admitted.phase, BackupPhase::Admitted);
        assert_eq!(admitted.revision, 2);
        assert!(admitted.validate().is_ok());
        // admitted → sealing directly is not a transition.
        assert!(admitted.advance(BackupPhase::Sealing, created).is_err());
        let dumping = admitted.advance(BackupPhase::Dumping, created).unwrap();
        let inventory = dumping.advance(BackupPhase::Inventory, created).unwrap();
        let sealing = inventory.advance(BackupPhase::Sealing, created).unwrap();
        let sealed = sealing.advance(BackupPhase::Sealed, created).unwrap();
        assert!(sealed.phase.is_terminal());
        assert!(!sealed.phase.is_resumable());
        // Terminal operations cannot be reopened.
        assert!(sealed.advance(BackupPhase::Failed, created).is_err());
        // A terminal failure carries a closed reason.
        let failed = dumping.fail(backup_failure::DUMP_WRITE, created).unwrap();
        assert!(failed.validate().is_ok());
        assert!(dumping.fail("BOGUS_REASON", created).is_err());
        // Timestamps must not move backwards.
        assert!(
            dumping
                .advance(BackupPhase::Inventory, created - time::Duration::HOUR)
                .is_err()
        );
    }

    #[test]
    fn dump_evidence_needs_a_header_and_digest() {
        assert!(
            DumpEvidence {
                size: 0,
                digest: [1u8; 32]
            }
            .validate()
            .is_err()
        );
        assert!(
            DumpEvidence {
                size: 10,
                digest: [0u8; 32]
            }
            .validate()
            .is_err()
        );
        assert!(
            DumpEvidence {
                size: 10,
                digest: [1u8; 32]
            }
            .validate()
            .is_ok()
        );
    }
}
