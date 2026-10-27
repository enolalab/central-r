//! `restored_inventory.go` — [`RestoredInventoryVerifier`] merge-compares
//! the exact sealed inventory with restored PostgreSQL metadata, then
//! rereads every expected body through the recovery object-store
//! identity. Raw ready keys remain inside this adapter.

use std::sync::Arc;

use central_artifact::port::ObjectRef;
use central_backup::backup::capacity::RecoveryProfile;
use central_backup::backup::inventory::InventoryEntry;
use central_backup::port::RecoveryInventorySource;
use central_backup::recovery::operation::RestoreOperation;
use central_backup::recovery::quarantine::{
    QuarantineFinding, QuarantineObservationSource, QuarantineReason,
};
use central_foundation::failure::{Failure, FailureKind};
use sha2::Digest as _;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::backup::{
    RawReadyRow, ReadyArtifactObjectReader, ReadyArtifactRecord, is_zero_time, truncate_micros,
};
use crate::error::SqlxContext as _;
use crate::store_support::BlockingConn;

/// `ErrRestoredInventory` is deliberately locator-free.
fn restored_inventory_unavailable() -> Failure {
    Failure::unavailable(
        "recovery_restored_inventory",
        "recovery restored inventory is unavailable",
    )
}

/// `RestoredInventoryVerifier` — see module docs. `read` on `objects`
/// must map a missing object to [`FailureKind::NotFound`] (the
/// `missing_body` finding depends on that classification).
pub struct RestoredInventoryVerifier {
    repository: Arc<dyn RecoveryInventorySource>,
    conn: BlockingConn,
    objects: Arc<dyn ReadyArtifactObjectReader>,
    profile: RecoveryProfile,
}

impl RestoredInventoryVerifier {
    /// `NewRestoredInventoryVerifier`.
    ///
    /// # Errors
    /// `recovery_restored_inventory` when the profile is invalid or the
    /// bridge runtime cannot be built.
    pub fn new(
        repository: Arc<dyn RecoveryInventorySource>,
        conn: PgConnection,
        objects: Arc<dyn ReadyArtifactObjectReader>,
        profile: RecoveryProfile,
    ) -> Result<Self, Failure> {
        if profile.validate().is_err() {
            return Err(restored_inventory_unavailable());
        }
        Ok(Self {
            repository,
            conn: BlockingConn::new(conn)?,
            objects,
            profile,
        })
    }

    /// `openRuntimeConnectionFromSealedPassfile` composition shape —
    /// `operationScopedInventoryVerifier` only has a connect future, and
    /// a `PgConnection` must be made on the same runtime that will drive
    /// it ([`BlockingConn::new_connecting`]'s reactor-binding rule).
    ///
    /// # Errors
    /// `recovery_restored_inventory` when the profile is invalid or the
    /// bridge runtime cannot be built; whatever `connect` returns
    /// otherwise.
    pub fn new_connecting<F, Fut>(
        connect: F,
        repository: Arc<dyn RecoveryInventorySource>,
        objects: Arc<dyn ReadyArtifactObjectReader>,
        profile: RecoveryProfile,
    ) -> Result<Self, Failure>
    where
        F: FnOnce() -> Fut,
        Fut: core::future::Future<Output = Result<PgConnection, Failure>>,
    {
        if profile.validate().is_err() {
            return Err(restored_inventory_unavailable());
        }
        Ok(Self {
            repository,
            conn: BlockingConn::new_connecting(connect)?,
            objects,
            profile,
        })
    }

    /// `VerifyInventory` — the merge walk: sealed inventory entries
    /// against restored ready rows in artifact-ID order, then a body
    /// reread for every exact match. Findings carry the observation
    /// source naming which comparison ran.
    ///
    /// # Errors
    /// `recovery_restored_inventory` on any invalid input, unreadable
    /// metadata/body, or bound violation; never the underlying
    /// PostgreSQL or object-store error.
    pub fn verify_inventory(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Vec<QuarantineFinding>, Failure> {
        if operation.validate().is_err() || !operation.admits_inventory_verification() {
            return Err(restored_inventory_unavailable());
        }
        let expected = self
            .repository
            .read_verified_inventory(operation.backup_id, &self.profile)
            .map_err(|_| restored_inventory_unavailable())?;
        if expected.len() as u64 > self.profile.max_record_count
            || !canonical_inventory_entries(&expected)
        {
            return Err(restored_inventory_unavailable());
        }
        let observed = self.read_restored_ready_metadata()?;
        let at = truncate_micros(time::OffsetDateTime::now_utc());
        if is_zero_time(at) || at < truncate_micros(operation.started_at) {
            return Err(restored_inventory_unavailable());
        }
        let mut findings: Vec<QuarantineFinding> = Vec::new();
        let (mut expected_index, mut observed_index) = (0usize, 0usize);
        while expected_index < expected.len() || observed_index < observed.len() {
            if observed_index >= observed.len()
                || (expected_index < expected.len()
                    && expected[expected_index].artifact_id.to_string()
                        < observed[observed_index].artifact_id.to_string())
            {
                // Sealed entry, no restored row: the inventory-row
                // comparison's absent verdict.
                let finding = new_restored_inventory_finding(
                    operation,
                    expected[expected_index].artifact_id,
                    QuarantineReason::MetadataMismatch,
                    QuarantineObservationSource::InventoryRow,
                    Some(&expected[expected_index]),
                    None,
                    at,
                )?;
                findings.push(finding);
                expected_index += 1;
            } else if expected_index >= expected.len()
                || observed[observed_index].artifact_id.to_string()
                    < expected[expected_index].artifact_id.to_string()
            {
                // Restored ready row with no sealed entry: the scan's
                // own observation.
                let entry = observed[observed_index].inventory_entry();
                let finding = new_restored_inventory_finding(
                    operation,
                    entry.artifact_id,
                    QuarantineReason::UnexpectedArtifact,
                    QuarantineObservationSource::RestoredScan,
                    None,
                    Some(&entry),
                    at,
                )?;
                findings.push(finding);
                observed_index += 1;
            } else {
                let want = expected[expected_index];
                let record = &observed[observed_index];
                let got = record.inventory_entry();
                if want != got {
                    // The same inventory-row comparison, drift verdict.
                    let finding = new_restored_inventory_finding(
                        operation,
                        want.artifact_id,
                        QuarantineReason::MetadataMismatch,
                        QuarantineObservationSource::InventoryRow,
                        Some(&want),
                        Some(&got),
                        at,
                    )?;
                    findings.push(finding);
                } else if let Some(finding) =
                    self.verify_body(operation, &want, &record.ready_key, at)?
                {
                    findings.push(finding);
                }
                expected_index += 1;
                observed_index += 1;
            }
            if findings.len() as u64 > self.profile.max_record_count {
                return Err(restored_inventory_unavailable());
            }
        }
        Ok(findings)
    }

    /// `readRestoredReadyMetadata` — the same `ready`/no-delete-intent
    /// predicate as the C01 source, scanned in artifact-ID order with
    /// each row re-validated and its key re-derived.
    fn read_restored_ready_metadata(&self) -> Result<Vec<ReadyArtifactRecord>, Failure> {
        let limit = i64::try_from(self.profile.max_record_count).unwrap_or(i64::MAX);
        self.conn.run(|conn| {
            Box::pin(async move {
                let rows = sqlx::query_as!(
                    RawReadyRow,
                    "SELECT workspace_id, id, size, checksum_value,
                        content_generation, ready_key
                    FROM central.artifacts
                    WHERE state='ready' AND delete_intent_at IS NULL
                    ORDER BY id ASC",
                )
                .fetch_all(&mut *conn)
                .await
                .ctx("recovery: read restored ready metadata")?;
                if rows.len() as i64 > limit {
                    return Err(restored_inventory_unavailable());
                }
                let mut records: Vec<ReadyArtifactRecord> = Vec::with_capacity(rows.len());
                for row in &rows {
                    let record = ReadyArtifactRecord::from_raw(row)?;
                    if let Some(previous) = records.last()
                        && previous.artifact_id >= record.artifact_id
                    {
                        return Err(restored_inventory_unavailable());
                    }
                    records.push(record);
                }
                Ok::<Vec<ReadyArtifactRecord>, Failure>(records)
            })
        })
    }

    /// `verifyBody` — the object-presence/-length/-digest comparisons,
    /// in that order.
    fn verify_body(
        &self,
        operation: &RestoreOperation,
        expected: &InventoryEntry,
        ready_key: &str,
        at: time::OffsetDateTime,
    ) -> Result<Option<QuarantineFinding>, Failure> {
        let (body, info) = match self.objects.read(&ObjectRef {
            key: ready_key.to_owned(),
        }) {
            Ok(pair) => pair,
            Err(failure) if failure.kind() == FailureKind::NotFound => {
                // The object-presence comparison: the store holds no
                // object at all.
                return new_restored_inventory_finding(
                    operation,
                    expected.artifact_id,
                    QuarantineReason::MissingBody,
                    QuarantineObservationSource::ObjectPresence,
                    Some(expected),
                    None,
                    at,
                )
                .map(Some);
            }
            Err(_) => return Err(restored_inventory_unavailable()),
        };
        let mut body = body;
        if info.size != expected.size {
            // Upstream `_ = body.Close()` — released before the refusal.
            let _ = body.close();
            let observed = InventoryEntry {
                artifact_id: expected.artifact_id,
                checksum: expected.checksum,
                size: info.size,
            };
            return new_restored_inventory_finding(
                operation,
                expected.artifact_id,
                QuarantineReason::SizeMismatch,
                QuarantineObservationSource::ObjectLength,
                Some(expected),
                Some(&observed),
                at,
            )
            .map(Some);
        }
        // `io.Copy(hasher, io.LimitReader(body, size+1))` — `Sha256` is
        // a `Digest`, not an `io::Write`, so the copy runs as an explicit
        // bounded read loop (the same cap upstream's LimitReader sets).
        let limit = u64::try_from(expected.size)
            .ok()
            .and_then(|size| size.checked_add(1))
            .unwrap_or(u64::MAX);
        let bytes_read = {
            let mut limited = std::io::Read::take(&mut body, limit);
            let mut hasher = sha2::Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 8192];
            let read_result = loop {
                match std::io::Read::read(&mut limited, &mut buffer) {
                    Ok(0) => break Ok(total),
                    Ok(n) => {
                        hasher.update(&buffer[..n]);
                        total += n as u64;
                    }
                    Err(error) => break Err(error),
                }
            };
            if read_result.is_err() {
                let _ = body.close();
                return Err(restored_inventory_unavailable());
            }
            let observed_digest: [u8; 32] = hasher.finalize().into();
            if body.close().is_err() {
                return Err(restored_inventory_unavailable());
            }
            let bytes_read = i64::try_from(total).map_err(|_| restored_inventory_unavailable())?;
            if bytes_read == expected.size && observed_digest != expected.checksum {
                // The object-digest comparison, reached only once the
                // length agreed.
                let observed = InventoryEntry {
                    artifact_id: expected.artifact_id,
                    checksum: observed_digest,
                    size: bytes_read,
                };
                return new_restored_inventory_finding(
                    operation,
                    expected.artifact_id,
                    QuarantineReason::ChecksumMismatch,
                    QuarantineObservationSource::ObjectDigest,
                    Some(expected),
                    Some(&observed),
                    at,
                )
                .map(Some);
            }
            bytes_read
        };
        if bytes_read != expected.size {
            // The same object-length comparison, on the streamed bytes.
            let observed = InventoryEntry {
                artifact_id: expected.artifact_id,
                checksum: expected.checksum,
                size: bytes_read,
            };
            return new_restored_inventory_finding(
                operation,
                expected.artifact_id,
                QuarantineReason::SizeMismatch,
                QuarantineObservationSource::ObjectLength,
                Some(expected),
                Some(&observed),
                at,
            )
            .map(Some);
        }
        Ok(None)
    }
}

/// `canonicalInventoryEntries` — strictly ascending, valid entries.
fn canonical_inventory_entries(entries: &[InventoryEntry]) -> bool {
    for (index, entry) in entries.iter().enumerate() {
        if entry.validate().is_err()
            || (index > 0
                && entries[index - 1].artifact_id.to_string() >= entry.artifact_id.to_string())
        {
            return false;
        }
    }
    true
}

/// `newRestoredInventoryFinding` — builds one finding; the source is
/// passed by each call site so the field records which comparison this
/// verifier actually ran, then `validate_for` refuses any reason the
/// comparison cannot raise.
fn new_restored_inventory_finding(
    operation: &RestoreOperation,
    artifact_id: Uuid,
    reason: QuarantineReason,
    source: QuarantineObservationSource,
    expected: Option<&InventoryEntry>,
    observed: Option<&InventoryEntry>,
    at: time::OffsetDateTime,
) -> Result<QuarantineFinding, Failure> {
    let mut finding = QuarantineFinding {
        quarantine_id: Uuid::now_v7(),
        operation_id: operation.operation_id,
        artifact_id,
        reason,
        observation_source: source,
        expected_checksum: expected.map(|e| e.checksum),
        observed_checksum: observed.map(|e| e.checksum),
        expected_size: expected.map(|e| e.size),
        observed_size: observed.map(|e| e.size),
        created_at: at,
    };
    match reason {
        QuarantineReason::ChecksumMismatch => {
            finding.expected_size = None;
            finding.observed_size = None;
        }
        QuarantineReason::SizeMismatch => {
            finding.expected_checksum = None;
            finding.observed_checksum = None;
        }
        QuarantineReason::MetadataMismatch => {
            if let (Some(expected), Some(observed)) = (expected, observed) {
                if expected.checksum == observed.checksum {
                    finding.expected_checksum = None;
                    finding.observed_checksum = None;
                }
                if expected.size == observed.size {
                    finding.expected_size = None;
                    finding.observed_size = None;
                }
            }
        }
        _ => {}
    }
    if finding.validate_for(operation).is_err() {
        return Err(restored_inventory_unavailable());
    }
    Ok(finding)
}
