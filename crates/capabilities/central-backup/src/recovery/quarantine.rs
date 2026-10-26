//! `internal/backup/recovery.go` quarantine half — the five typed
//! findings, the reason↔comparison bijection that makes their
//! evidence shapes mutually exclusive, and `ValidateFor` binding a
//! finding to an operation that admits inventory verification.

use central_foundation::failure::Failure;
use uuid::Uuid;

use crate::wire::is_zero_time;

use super::operation::RestoreOperation;

fn invalid_finding() -> Failure {
    Failure::invalid("backup_recovery", "invalid recovery quarantine finding")
}

/// `QuarantineReason` — the closed discrepancy vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// `missing_body` — object-store reread found no object.
    MissingBody,
    /// `checksum_mismatch` — body digest disagreed (length agreed).
    ChecksumMismatch,
    /// `size_mismatch` — body length disagreed before any digest.
    SizeMismatch,
    /// `unexpected_artifact` — a restored ready row with no sealed
    /// inventory entry.
    UnexpectedArtifact,
    /// `metadata_mismatch` — restored row absent or its recorded
    /// columns drifted from the sealed entry.
    MetadataMismatch,
}

impl QuarantineReason {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingBody => "missing_body",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::SizeMismatch => "size_mismatch",
            Self::UnexpectedArtifact => "unexpected_artifact",
            Self::MetadataMismatch => "metadata_mismatch",
        }
    }
}

/// `QuarantineObservationSource` — WHICH comparison observed the
/// evidence a finding carries. Load-bearing, not decoration: without
/// it the expected/observed pairs are ambiguous by construction (an
/// absent restored row and a missing body carry the identical shape).
/// Five comparisons, five reasons, one each — a bijection on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineObservationSource {
    /// `inventory_row` — sealed entry vs restored `central.artifacts`
    /// row; the only comparison that reads restored metadata.
    InventoryRow,
    /// `restored_scan` — a restored ready row with no sealed entry.
    RestoredScan,
    /// `object_presence` — the recovery object-store reread answering
    /// not-found; observes existence, never bytes.
    ObjectPresence,
    /// `object_length` — the retrieved body's byte length vs sealed.
    ObjectLength,
    /// `object_digest` — SHA-256 of streamed bytes vs sealed checksum;
    /// reached only after length agreed.
    ObjectDigest,
}

impl QuarantineObservationSource {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventoryRow => "inventory_row",
            Self::RestoredScan => "restored_scan",
            Self::ObjectPresence => "object_presence",
            Self::ObjectLength => "object_length",
            Self::ObjectDigest => "object_digest",
        }
    }

    /// `Valid` — adapters persisting or rereading a finding refuse a
    /// value the closed vocabulary does not contain.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        true
    }
}

/// `QuarantineSourceFor` — the single comparison that can raise the
/// given reason, or `None` for an out-of-vocabulary reason. The
/// persisted projection uses it to keep the stored column and the
/// stored reason from drifting across a backfill or replay.
#[must_use]
pub const fn quarantine_source_for(
    reason: QuarantineReason,
) -> Option<QuarantineObservationSource> {
    Some(match reason {
        QuarantineReason::MissingBody => QuarantineObservationSource::ObjectPresence,
        QuarantineReason::ChecksumMismatch => QuarantineObservationSource::ObjectDigest,
        QuarantineReason::SizeMismatch => QuarantineObservationSource::ObjectLength,
        QuarantineReason::UnexpectedArtifact => QuarantineObservationSource::RestoredScan,
        QuarantineReason::MetadataMismatch => QuarantineObservationSource::InventoryRow,
    })
}

/// `QuarantineFinding` — safe, bounded recovery evidence for one
/// artifact: no object key, filename, repository path, or body.
/// Resolution is intentionally absent — a complete later inventory
/// pass reconciles the durable finding; a caller can never clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineFinding {
    /// Finding identity.
    pub quarantine_id: Uuid,
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound artifact.
    pub artifact_id: Uuid,
    /// Closed reason.
    pub reason: QuarantineReason,
    /// The one comparison that can raise `reason`.
    pub observation_source: QuarantineObservationSource,
    /// Sealed checksum, when the comparison carries it.
    pub expected_checksum: Option<[u8; 32]>,
    /// Observed checksum, when the comparison carries it.
    pub observed_checksum: Option<[u8; 32]>,
    /// Sealed size, when the comparison carries it.
    pub expected_size: Option<i64>,
    /// Observed size, when the comparison carries it.
    pub observed_size: Option<i64>,
    /// Creation instant.
    pub created_at: time::OffsetDateTime,
}

/// `metadataRowAbsent` — expected row missing entirely.
fn metadata_row_absent(f: &QuarantineFinding) -> bool {
    f.expected_checksum.is_some()
        && f.expected_size.is_some()
        && f.observed_checksum.is_none()
        && f.observed_size.is_none()
}

/// `metadataColumnsDrift` — restored row present and disagreeing:
/// every carried column is an expected/observed pair whose two sides
/// actually differ, and at least one pair is present.
fn metadata_columns_drift(f: &QuarantineFinding) -> bool {
    if f.expected_checksum.is_none() != f.observed_checksum.is_none()
        || f.expected_size.is_none() != f.observed_size.is_none()
    {
        return false;
    }
    if f.expected_checksum.is_none() && f.expected_size.is_none() {
        return false;
    }
    if let (Some(expected), Some(observed)) = (f.expected_checksum, f.observed_checksum)
        && expected == observed
    {
        return false;
    }
    if let (Some(expected), Some(observed)) = (f.expected_size, f.observed_size)
        && expected == observed
    {
        return false;
    }
    true
}

impl QuarantineFinding {
    /// `ValidateFor` — the source gate runs for EVERY reason ahead of
    /// the per-reason evidence rules, which is what makes the five
    /// shapes mutually exclusive.
    pub fn validate_for(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        if operation.validate().is_err()
            || !operation.admits_inventory_verification()
            || self.quarantine_id.is_nil()
            || self.operation_id != operation.operation_id
            || self.artifact_id.is_nil()
            || is_zero_time(self.created_at)
            || self.created_at < operation.started_at
            || self.expected_size.is_some_and(|size| size < 0)
            || self.observed_size.is_some_and(|size| size < 0)
        {
            return Err(invalid_finding());
        }
        if quarantine_source_for(self.reason) != Some(self.observation_source) {
            return Err(invalid_finding());
        }
        match self.reason {
            QuarantineReason::MissingBody => {
                if self.expected_checksum.is_none()
                    || self.expected_size.is_none()
                    || self.observed_checksum.is_some()
                    || self.observed_size.is_some()
                {
                    return Err(invalid_finding());
                }
            }
            QuarantineReason::ChecksumMismatch => {
                if self.expected_checksum.is_none()
                    || self.observed_checksum.is_none()
                    || self.expected_checksum == self.observed_checksum
                    || self.expected_size.is_some()
                    || self.observed_size.is_some()
                {
                    return Err(invalid_finding());
                }
            }
            QuarantineReason::SizeMismatch => {
                if self.expected_size.is_none()
                    || self.observed_size.is_none()
                    || self.expected_size == self.observed_size
                    || self.expected_checksum.is_some()
                    || self.observed_checksum.is_some()
                {
                    return Err(invalid_finding());
                }
            }
            QuarantineReason::UnexpectedArtifact => {
                if self.expected_checksum.is_some()
                    || self.expected_size.is_some()
                    || (self.observed_checksum.is_none() && self.observed_size.is_none())
                {
                    return Err(invalid_finding());
                }
            }
            QuarantineReason::MetadataMismatch => {
                if !metadata_row_absent(self) && !metadata_columns_drift(self) {
                    return Err(invalid_finding());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
    use crate::domain::TargetIdentity;
    use crate::recovery::operation::{RestoreTicket, new_restore_operation};
    use time::macros::datetime;

    fn verifying_operation() -> RestoreOperation {
        let now = datetime!(2026-03-01 12:30:00 UTC);
        let ticket = RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: TargetIdentity {
                system_id: "sys".into(),
                database_oid: "16384".into(),
                database: "central".into(),
                config_hash: "cfg".into(),
                epoch: 1,
            },
            target_fingerprint: format!("sha256:{}", "a".repeat(64)),
            manifest_digest: format!("sha256:{}", "b".repeat(64)),
            security_epoch: 1,
            restore_epoch: 1,
            config_fingerprint: format!("sha256:{}", "c".repeat(64)),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: format!("sha256:{}", "d".repeat(64)),
            tool_version: "pg_dump-16.14".into(),
            hidden_nonce: b"n".to_vec(),
            issued_at: now - time::Duration::HOUR,
            expires_at: now + time::Duration::HOUR,
            hmac: String::new(),
        };
        new_restore_operation(&ticket, now)
            .unwrap()
            .record_database_replaced(now)
            .unwrap()
            .begin_verification(now)
            .unwrap()
    }

    fn finding(operation: &RestoreOperation, reason: QuarantineReason) -> QuarantineFinding {
        QuarantineFinding {
            quarantine_id: Uuid::now_v7(),
            operation_id: operation.operation_id,
            artifact_id: Uuid::now_v7(),
            reason,
            observation_source: quarantine_source_for(reason).unwrap(),
            expected_checksum: None,
            observed_checksum: None,
            expected_size: None,
            observed_size: None,
            created_at: operation.updated_at,
        }
    }

    #[test]
    fn each_reason_admits_exactly_its_shape() {
        let operation = verifying_operation();
        // missing_body: full expectation, nothing observed.
        let mut f = finding(&operation, QuarantineReason::MissingBody);
        f.expected_checksum = Some([1u8; 32]);
        f.expected_size = Some(10);
        assert!(f.validate_for(&operation).is_ok());
        // Its shape under checksum_mismatch's label refuses (source gate).
        f.reason = QuarantineReason::ChecksumMismatch;
        assert!(f.validate_for(&operation).is_err());
        // checksum_mismatch: differing digests, no sizes.
        let mut f = finding(&operation, QuarantineReason::ChecksumMismatch);
        f.expected_checksum = Some([1u8; 32]);
        f.observed_checksum = Some([2u8; 32]);
        assert!(f.validate_for(&operation).is_ok());
        f.observed_checksum = Some([1u8; 32]);
        assert!(f.validate_for(&operation).is_err()); // equal → refused
        // size_mismatch: differing sizes, no checksums.
        let mut f = finding(&operation, QuarantineReason::SizeMismatch);
        f.expected_size = Some(10);
        f.observed_size = Some(11);
        assert!(f.validate_for(&operation).is_ok());
        f.observed_size = Some(10);
        assert!(f.validate_for(&operation).is_err());
        // unexpected_artifact: observed side only, at least one column.
        let mut f = finding(&operation, QuarantineReason::UnexpectedArtifact);
        assert!(f.validate_for(&operation).is_err());
        f.observed_size = Some(5);
        assert!(f.validate_for(&operation).is_ok());
        // metadata_mismatch: row absent OR columns drift.
        let mut f = finding(&operation, QuarantineReason::MetadataMismatch);
        f.expected_checksum = Some([1u8; 32]);
        f.expected_size = Some(10);
        assert!(f.validate_for(&operation).is_ok()); // absent row
        f.observed_checksum = Some([2u8; 32]);
        f.observed_size = Some(11);
        assert!(f.validate_for(&operation).is_ok()); // drifted columns
        f.observed_checksum = Some([1u8; 32]); // no divergence left
        assert!(f.validate_for(&operation).is_err());
    }

    #[test]
    fn finding_requires_inventory_verification_state() {
        let now = datetime!(2026-03-01 12:30:00 UTC);
        let ticket = RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: TargetIdentity {
                system_id: "s".into(),
                database_oid: "1".into(),
                database: "d".into(),
                config_hash: "c".into(),
                epoch: 1,
            },
            target_fingerprint: "sha256:aaaa".into(),
            manifest_digest: "sha256:bbbb".into(),
            security_epoch: 1,
            restore_epoch: 1,
            config_fingerprint: "sha256:cccc".into(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: format!("sha256:{}", "d".repeat(64)),
            tool_version: "t".into(),
            hidden_nonce: b"n".to_vec(),
            issued_at: now - time::Duration::HOUR,
            expires_at: now + time::Duration::HOUR,
            hmac: String::new(),
        };
        let applying = new_restore_operation(&ticket, now).unwrap();
        let mut f = QuarantineFinding {
            quarantine_id: Uuid::now_v7(),
            operation_id: applying.operation_id,
            artifact_id: Uuid::now_v7(),
            reason: QuarantineReason::MissingBody,
            observation_source: QuarantineObservationSource::ObjectPresence,
            expected_checksum: Some([1u8; 32]),
            observed_checksum: None,
            expected_size: Some(1),
            observed_size: None,
            created_at: now,
        };
        assert!(f.validate_for(&applying).is_err());
        // Wrong operation binding refuses.
        f.operation_id = Uuid::now_v7();
        assert!(f.validate_for(&applying).is_err());
    }
}
