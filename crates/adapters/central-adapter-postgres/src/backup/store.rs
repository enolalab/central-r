//! `ready_artifact_source.go` — the production C01 bridge from
//! authoritative PostgreSQL metadata to a separately credentialed object
//! body stream. Raw ready keys remain inside this infrastructure adapter
//! and never enter the backup domain or its immutable inventory.

use std::sync::Arc;

use central_artifact::port::{ObjectInfo, ObjectRef};
use central_backup::backup::inventory::InventoryEntry;
use central_backup::backup::operation::{BackupOperation, BackupPhase};
use central_backup::port::{
    MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES, ReadClose, ReadyArtifactCursor, ReadyArtifactPage,
    ReadyArtifactSource as ReadyArtifactSourcePort,
};
use central_foundation::failure::Failure;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::SqlxContext as _;
use crate::store_support::BlockingConn;

/// `ErrReadyArtifactSource` is deliberately locator-free. Neither a
/// PostgreSQL error nor an object-store error is wrapped across this
/// recovery boundary, because both may contain a database target, bucket,
/// or raw object key.
fn ready_artifact_source_unavailable() -> Failure {
    Failure::unavailable(
        "recovery_ready_artifact_source",
        "recovery ready Artifact source is unavailable",
    )
}

/// `readyArtifactObjectReader` is intentionally narrower than the general
/// B10 object-store port. A C01 source supplied with the
/// `minio_backup_v1` identity can only read an already-derived ready
/// reference; it cannot upload, promote, list, delete, or accept a
/// caller-provided key.
///
/// The seam is synchronous like upstream's `io.ReadCloser`: the
/// composition root owns any async→sync bridging when it adapts the S3
/// store (the body stream must implement [`ReadClose`]).
pub trait ReadyArtifactObjectReader: Send + Sync {
    /// `Read` — opens the derived ready object for a bounded read.
    ///
    /// # Errors
    /// Implementation-defined [`Failure`]; a missing object must surface
    /// as [`central_foundation::failure::FailureKind::NotFound`] so the
    /// restored-inventory verifier can raise `missing_body` rather than
    /// fail the pass.
    fn read(&self, reference: &ObjectRef) -> Result<(Box<dyn ReadClose>, ObjectInfo), Failure>;
}

/// `ReadyArtifactSource` implements
/// [`central_backup::port::ReadyArtifactSource`].
pub struct ReadyArtifactSource {
    conn: BlockingConn,
    objects: Arc<dyn ReadyArtifactObjectReader>,
}

impl ReadyArtifactSource {
    /// `NewReadyArtifactSource` — refuses a missing object seam.
    ///
    /// # Errors
    /// `recovery_ready_artifact_source` when the bridge runtime cannot
    /// be built.
    pub fn new(
        conn: PgConnection,
        objects: Arc<dyn ReadyArtifactObjectReader>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            conn: BlockingConn::new(conn)?,
            objects,
        })
    }
}

impl ReadyArtifactSourcePort for ReadyArtifactSource {
    /// `ListReadyArtifacts` — one metadata page in artifact-ID order,
    /// `LIMIT limit+1` for the complete flag; every row is re-validated
    /// and its ready key re-derived (never trusted as stored).
    fn list_ready_artifacts(
        &self,
        operation: &BackupOperation,
        after: ReadyArtifactCursor,
        limit: usize,
    ) -> Result<ReadyArtifactPage, Failure> {
        if operation.validate().is_err()
            || operation.phase != BackupPhase::Inventory
            || limit == 0
            || limit > MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES
        {
            return Err(ready_artifact_source_unavailable());
        }
        let fetch = i64::try_from(limit)
            .ok()
            .and_then(|v| v.checked_add(1))
            .unwrap_or(i64::MAX);
        let records = self.conn.run(|conn| {
            Box::pin(async move {
                let rows = sqlx::query_as!(
                    RawReadyRow,
                    "SELECT workspace_id, id, size, checksum_value,
                        content_generation, ready_key
                    FROM central.artifacts
                    WHERE state='ready' AND delete_intent_at IS NULL AND id > $1::uuid
                    ORDER BY id ASC LIMIT $2",
                    after.artifact_id,
                    fetch,
                )
                .fetch_all(&mut *conn)
                .await
                .ctx("backup: list ready artifacts")?;
                rows.iter()
                    .map(ReadyArtifactRecord::from_raw)
                    .collect::<Result<Vec<_>, _>>()
            })
        })?;
        if records.len() > limit + 1 {
            return Err(ready_artifact_source_unavailable());
        }
        let complete = records.len() <= limit;
        let mut records = records;
        if !complete {
            records.truncate(limit);
        }
        let mut page = ReadyArtifactPage {
            entries: Vec::with_capacity(records.len()),
            next_cursor: ReadyArtifactCursor::default(),
            complete,
        };
        for (index, record) in records.iter().enumerate() {
            if index > 0 && records[index - 1].artifact_id >= record.artifact_id {
                return Err(ready_artifact_source_unavailable());
            }
            page.entries.push(record.inventory_entry());
        }
        if !complete {
            let Some(last) = records.last() else {
                return Err(ready_artifact_source_unavailable());
            };
            page.next_cursor.artifact_id = last.artifact_id;
        }
        Ok(page)
    }

    /// `OpenReadyArtifact` — re-reads the row, requires the stored
    /// projection to equal the caller's sealed entry exactly, verifies
    /// the store's reported size, then returns the body stream.
    fn open_ready_artifact(
        &self,
        operation: &BackupOperation,
        entry: &InventoryEntry,
    ) -> Result<Box<dyn ReadClose>, Failure> {
        if operation.validate().is_err()
            || operation.phase != BackupPhase::Inventory
            || entry.validate().is_err()
        {
            return Err(ready_artifact_source_unavailable());
        }
        let artifact_id = entry.artifact_id;
        let record = self.conn.run(|conn| {
            Box::pin(async move {
                let row = sqlx::query_as!(
                    RawReadyRow,
                    "SELECT workspace_id, id, size, checksum_value,
                        content_generation, ready_key
                    FROM central.artifacts
                    WHERE id=$1::uuid AND state='ready' AND delete_intent_at IS NULL",
                    artifact_id,
                )
                .fetch_one(&mut *conn)
                .await
                .ctx("backup: open ready artifact")?;
                ReadyArtifactRecord::from_raw(&row)
            })
        })?;
        if record.inventory_entry() != *entry {
            return Err(ready_artifact_source_unavailable());
        }
        let (body, info) = self
            .objects
            .read(&ObjectRef {
                key: record.ready_key.clone(),
            })
            .map_err(|_| ready_artifact_source_unavailable())?;
        if info.size != entry.size {
            // Upstream `_ = body.Close()` — the stream is released before
            // the refusal; a close failure does not replace it.
            let _ = body.close();
            return Err(ready_artifact_source_unavailable());
        }
        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// `readyArtifactRecord` — shared with `recovery::restored_inventory`.
// ---------------------------------------------------------------------------

/// The raw row shape both `ReadyArtifactSource` and the restored
/// inventory verifier scan. `checksum_value`/`content_generation`/
/// `ready_key` are schema-nullable; a NULL on a `ready` row is corrupt
/// for this read and refuses (`scanReadyArtifact`).
pub(crate) struct RawReadyRow {
    pub(crate) workspace_id: uuid::Uuid,
    pub(crate) id: uuid::Uuid,
    pub(crate) size: i64,
    pub(crate) checksum_value: Option<Vec<u8>>,
    pub(crate) content_generation: Option<uuid::Uuid>,
    pub(crate) ready_key: Option<String>,
}

/// `readyArtifactRecord` — a validated ready row whose stored key was
/// re-derived, never trusted.
#[derive(Debug, Clone)]
pub struct ReadyArtifactRecord {
    /// Workspace identity.
    pub workspace_id: Uuid,
    /// Artifact identity.
    pub artifact_id: Uuid,
    /// Sealed body size.
    pub size: i64,
    /// Sealed body checksum.
    pub checksum: [u8; 32],
    /// Content generation.
    pub content_generation: Uuid,
    /// The derived-and-verified ready key (adapter-internal).
    pub ready_key: String,
}

impl ReadyArtifactRecord {
    /// `scanReadyArtifact` — all upstream shape checks: non-nil UUIDs,
    /// nonnegative size, 32-byte nonzero checksum, and the stored
    /// `ready_key` must equal the canonical derivation.
    pub(crate) fn from_raw(row: &RawReadyRow) -> Result<Self, Failure> {
        let checksum: [u8; 32] = row
            .checksum_value
            .as_deref()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(ready_artifact_source_unavailable)?;
        let (Some(content_generation), Some(ready_key)) =
            (row.content_generation, row.ready_key.as_deref())
        else {
            return Err(ready_artifact_source_unavailable());
        };
        if row.workspace_id.is_nil()
            || row.id.is_nil()
            || content_generation.is_nil()
            || row.size < 0
            || checksum == [0u8; 32]
        {
            return Err(ready_artifact_source_unavailable());
        }
        let expected_key = format!(
            "v1/ready/{}/{}/{}",
            row.workspace_id, row.id, content_generation
        );
        if ready_key != expected_key {
            return Err(ready_artifact_source_unavailable());
        }
        Ok(Self {
            workspace_id: row.workspace_id,
            artifact_id: row.id,
            size: row.size,
            checksum,
            content_generation,
            ready_key: ready_key.to_owned(),
        })
    }

    /// `inventoryEntry` — the locator-free projection.
    #[must_use]
    pub fn inventory_entry(&self) -> InventoryEntry {
        InventoryEntry {
            artifact_id: self.artifact_id,
            checksum: self.checksum,
            size: self.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawReadyRow {
        RawReadyRow {
            workspace_id: Uuid::now_v7(),
            id: Uuid::now_v7(),
            size: 42,
            checksum_value: Some(vec![7u8; 32]),
            content_generation: Some(Uuid::now_v7()),
            ready_key: None,
        }
    }

    fn canonical_key(raw: &RawReadyRow) -> String {
        format!(
            "v1/ready/{}/{}/{}",
            raw.workspace_id,
            raw.id,
            raw.content_generation.unwrap()
        )
    }

    #[test]
    fn record_requires_the_derived_key() {
        let mut fixture = raw();
        fixture.ready_key = Some(canonical_key(&fixture));
        let record = ReadyArtifactRecord::from_raw(&fixture).unwrap();
        assert_eq!(record.size, 42);
        assert_eq!(record.checksum, [7u8; 32]);
        // A stored-but-wrong key refuses — the derivation is the check.
        let tampered = RawReadyRow {
            ready_key: Some("v1/ready/other".into()),
            ..raw()
        };
        assert!(ReadyArtifactRecord::from_raw(&tampered).is_err());
        // Zero checksum refuses.
        let mut bad = RawReadyRow {
            checksum_value: Some(vec![0; 32]),
            ..raw()
        };
        bad.ready_key = Some(canonical_key(&bad));
        assert!(ReadyArtifactRecord::from_raw(&bad).is_err());
        // NULL evidence refuses.
        for null in [
            RawReadyRow {
                checksum_value: None,
                ..raw()
            },
            RawReadyRow {
                ready_key: None,
                ..raw()
            },
            RawReadyRow {
                content_generation: None,
                ..raw()
            },
        ] {
            assert!(ReadyArtifactRecord::from_raw(&null).is_err());
        }
    }
}
