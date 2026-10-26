//! `internal/backup/inventory.go` seal-root half — the canonical
//! `central.backup-seal-root/v1` manifest the broker seal binds.
//!
//! Field order on the wire reproduces Go `json.Marshal` struct order
//! exactly (serde declaration order ≙ Go declaration order); the
//! `accepted_point` timestamp is `time.RFC3339Nano`. Parsing re-encodes
//! and requires byte equality.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::wire::{
    decode_canonical, hex_encode, parse_rfc3339_utc, parse_sha256, rfc3339_nano, wire_failure,
};

use super::inventory::{
    DATABASE_DUMP_LOGICAL_REF, InventoryChunk, MAXIMUM_INVENTORY_CHUNK_ENTRIES,
    inventory_chunk_identity,
};
use super::operation::{
    BACKUP_ROOT_SEAL_SCHEME, BackupAcceptedFacts, BackupOperation, BackupPhase, DumpEvidence,
};

/// `sealRootSchemaVersion`.
pub const SEAL_ROOT_SCHEMA: &str = "central.backup-seal-root/v1";
/// `sealRootOutcome`.
pub const SEAL_ROOT_OUTCOME: &str = "sealed";

fn seal_failure(message: &'static str) -> Failure {
    wire_failure("backup_recovery", message)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRootChunkWire {
    ordinal: u32,
    chunk_identity: String,
    digest_sha256: String,
    entry_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedPointWire {
    database_time: String,
    target_lock_protocol: String,
    target_lock_proof_sha256: String,
    inventory_boundary: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseDumpWire {
    logical_reference: String,
    size: i64,
    digest_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealOutcomeWire {
    scheme: String,
    outcome: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRootWire {
    schema_version: String,
    backup_id: String,
    operation_id: String,
    repository_binding_id: String,
    target_fingerprint_sha256: String,
    config_fingerprint_sha256: String,
    payload_epoch_id: String,
    accepted_point: AcceptedPointWire,
    database_dump: DatabaseDumpWire,
    chunks: Vec<SealRootChunkWire>,
    tool_version: String,
    database_schema_version: String,
    checksum_manifest_version: String,
    service_identity: String,
    sealing: SealOutcomeWire,
}

/// `SealRootChunkReference` — the bounded chunk facts read before the
/// repository opens the immutable chunk bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealRootChunkReference {
    /// Contiguous ordinal.
    pub ordinal: u32,
    /// Declared chunk digest.
    pub digest: [u8; 32],
    /// Declared entry count.
    pub entry_count: usize,
}

/// `SealRootReferences` — the bounded metadata read before the
/// repository opens the exact immutable chunks.
#[derive(Debug, Clone)]
pub struct SealRootReferences {
    /// Backup identity.
    pub backup_id: Uuid,
    /// Operation identity.
    pub operation_id: Uuid,
    /// Repository binding.
    pub repository_binding_id: Uuid,
    /// Trusted accepted-point facts.
    pub accepted_facts: BackupAcceptedFacts,
    /// Bound dump evidence.
    pub dump: DumpEvidence,
    /// Per-chunk references.
    pub chunks: Vec<SealRootChunkReference>,
}

/// `SealRootManifest` — the canonical `central.backup-seal-root/v1`
/// value bound by the broker seal.
#[derive(Debug, Clone)]
pub struct SealRootManifest {
    /// Backup identity.
    pub backup_id: Uuid,
    /// Operation identity.
    pub operation_id: Uuid,
    /// Repository binding.
    pub repository_binding_id: Uuid,
    /// Trusted accepted-point facts.
    pub accepted_facts: BackupAcceptedFacts,
    /// Bound dump evidence.
    pub dump: DumpEvidence,
    /// Canonically ordered chunks.
    pub chunks: Vec<InventoryChunk>,
    /// SHA-256 over [`SealRootManifest::canonical_json`].
    pub digest: [u8; 32],
}

/// `canonicalInventoryChunks` — sorted, contiguous-ordinal, verified.
pub fn canonical_inventory_chunks(
    chunks: &[InventoryChunk],
) -> Result<Vec<InventoryChunk>, Failure> {
    let mut canonical = chunks.to_vec();
    canonical.sort_by_key(|c| c.ordinal);
    for (index, chunk) in canonical.iter().enumerate() {
        if chunk.ordinal != index as u32 {
            return Err(seal_failure(
                "recovery inventory chunk ordinals are not contiguous",
            ));
        }
        chunk.verify()?;
    }
    Ok(canonical)
}

/// `NewSealRootManifest` — verifies every immutable component and
/// binds it to the protected operation. Zero chunks is legitimate; a
/// non-empty dump is required.
pub fn new_seal_root_manifest(
    operation: &BackupOperation,
    dump: DumpEvidence,
    chunks: &[InventoryChunk],
) -> Result<SealRootManifest, Failure> {
    if operation.validate().is_err()
        || !matches!(
            operation.phase,
            BackupPhase::Inventory | BackupPhase::Sealing
        )
        || dump.validate().is_err()
    {
        return Err(seal_failure("invalid recovery seal root"));
    }
    let mut manifest = SealRootManifest {
        backup_id: operation.backup_id,
        operation_id: operation.operation_id,
        repository_binding_id: operation.accepted_facts.repository_binding_id,
        accepted_facts: operation.accepted_facts.clone(),
        dump,
        chunks: canonical_inventory_chunks(chunks)?,
        digest: [0u8; 32],
    };
    manifest.digest = Sha256::digest(manifest.canonical_payload()?).into();
    Ok(manifest)
}

impl SealRootManifest {
    fn canonical_payload(&self) -> Result<Vec<u8>, Failure> {
        if self.backup_id.is_nil()
            || self.operation_id.is_nil()
            || self.repository_binding_id.is_nil()
            || self.repository_binding_id != self.accepted_facts.repository_binding_id
            || self.accepted_facts.validate().is_err()
            || self.dump.validate().is_err()
        {
            return Err(seal_failure("invalid recovery seal root"));
        }
        let canonical = canonical_inventory_chunks(&self.chunks)?;
        if canonical.len() != self.chunks.len() {
            return Err(seal_failure("invalid recovery seal root chunks"));
        }
        for (a, b) in canonical.iter().zip(&self.chunks) {
            if a.digest != b.digest {
                return Err(seal_failure(
                    "recovery seal root chunks are not canonically ordered",
                ));
            }
        }
        let wire = SealRootWire {
            schema_version: SEAL_ROOT_SCHEMA.into(),
            backup_id: self.backup_id.to_string(),
            operation_id: self.operation_id.to_string(),
            repository_binding_id: self.repository_binding_id.to_string(),
            target_fingerprint_sha256: self.accepted_facts.target_fingerprint.clone(),
            config_fingerprint_sha256: self.accepted_facts.config_fingerprint.clone(),
            payload_epoch_id: self.accepted_facts.payload_epoch_id.to_string(),
            accepted_point: AcceptedPointWire {
                database_time: rfc3339_nano(self.accepted_facts.database_time),
                target_lock_protocol: self.accepted_facts.target_lock_protocol.clone(),
                target_lock_proof_sha256: self.accepted_facts.target_lock_proof.clone(),
                inventory_boundary: self.accepted_facts.inventory_boundary.clone(),
            },
            database_dump: DatabaseDumpWire {
                logical_reference: DATABASE_DUMP_LOGICAL_REF.into(),
                size: self.dump.size,
                digest_sha256: hex_encode(&self.dump.digest),
            },
            chunks: self
                .chunks
                .iter()
                .map(|chunk| SealRootChunkWire {
                    ordinal: chunk.ordinal,
                    chunk_identity: inventory_chunk_identity(chunk.ordinal),
                    digest_sha256: hex_encode(&chunk.digest),
                    entry_count: chunk.entries.len(),
                })
                .collect(),
            tool_version: self.accepted_facts.tool_version.clone(),
            database_schema_version: self.accepted_facts.database_schema_version.clone(),
            checksum_manifest_version: self.accepted_facts.checksum_manifest.clone(),
            service_identity: self.accepted_facts.service_identity.clone(),
            sealing: SealOutcomeWire {
                scheme: BACKUP_ROOT_SEAL_SCHEME.into(),
                outcome: SEAL_ROOT_OUTCOME.into(),
            },
        };
        serde_json::to_vec(&wire).map_err(|_| seal_failure("invalid recovery seal root"))
    }

    /// `CanonicalJSON` — the exact bytes the broker seal binds.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        self.canonical_payload()
    }

    /// `Verify` — recompute the root digest.
    pub fn verify(&self) -> Result<(), Failure> {
        if Sha256::digest(self.canonical_payload()?).as_slice() != self.digest {
            return Err(seal_failure("recovery seal root digest mismatch"));
        }
        Ok(())
    }
}

/// `ParseSealRootManifest` — binds stored root bytes to the actual
/// stored chunks. The obsolete `central.backup-inventory-root/v1`
/// schema is rejected, not accepted as a weaker legacy authority.
pub fn parse_seal_root_manifest(
    payload: &[u8],
    chunks: &[InventoryChunk],
) -> Result<SealRootManifest, Failure> {
    let references = parse_seal_root_references(payload)?;
    if references.chunks.len() != chunks.len() {
        return Err(seal_failure("invalid recovery seal root"));
    }
    for (reference, chunk) in references.chunks.iter().zip(chunks) {
        if reference.ordinal != chunk.ordinal
            || reference.entry_count != chunk.entries.len()
            || reference.digest != chunk.digest
        {
            return Err(seal_failure("recovery seal root chunk mismatch"));
        }
    }
    let mut manifest = SealRootManifest {
        backup_id: references.backup_id,
        operation_id: references.operation_id,
        repository_binding_id: references.repository_binding_id,
        accepted_facts: references.accepted_facts,
        dump: references.dump,
        chunks: canonical_inventory_chunks(chunks)?,
        digest: [0u8; 32],
    };
    match manifest.canonical_json() {
        Ok(canonical) if canonical == payload => {
            manifest.digest = Sha256::digest(payload).into();
            Ok(manifest)
        }
        _ => Err(seal_failure("recovery seal root is not canonical")),
    }
}

/// `ParseSealRootReferences` — the bounded read before chunks open.
pub fn parse_seal_root_references(payload: &[u8]) -> Result<SealRootReferences, Failure> {
    let wire: SealRootWire = decode_canonical(payload)
        .map_err(|_| seal_failure("invalid recovery seal root encoding"))?;
    if wire.schema_version != SEAL_ROOT_SCHEMA
        || wire.database_dump.logical_reference != DATABASE_DUMP_LOGICAL_REF
        || wire.sealing.scheme != BACKUP_ROOT_SEAL_SCHEME
        || wire.sealing.outcome != SEAL_ROOT_OUTCOME
    {
        return Err(seal_failure("invalid recovery seal root encoding"));
    }
    match serde_json::to_vec(&wire) {
        Ok(canonical) if canonical == payload => {}
        _ => return Err(seal_failure("recovery seal root is not canonical")),
    }
    let backup_id = Uuid::parse_str(&wire.backup_id);
    let operation_id = Uuid::parse_str(&wire.operation_id);
    let repository_binding_id = Uuid::parse_str(&wire.repository_binding_id);
    let payload_epoch_id = Uuid::parse_str(&wire.payload_epoch_id);
    let database_time = parse_rfc3339_utc(&wire.accepted_point.database_time);
    let dump_digest = parse_sha256(&wire.database_dump.digest_sha256);
    let (
        Ok(backup_id),
        Ok(operation_id),
        Ok(repository_binding_id),
        Ok(payload_epoch_id),
        Ok(database_time),
        Ok(dump_digest),
    ) = (
        backup_id,
        operation_id,
        repository_binding_id,
        payload_epoch_id,
        database_time,
        dump_digest,
    )
    else {
        return Err(seal_failure("invalid recovery seal root identity"));
    };
    let facts = BackupAcceptedFacts {
        database_time,
        target_fingerprint: wire.target_fingerprint_sha256,
        config_fingerprint: wire.config_fingerprint_sha256,
        payload_epoch_id,
        repository_binding_id,
        target_lock_protocol: wire.accepted_point.target_lock_protocol,
        target_lock_proof: wire.accepted_point.target_lock_proof_sha256,
        inventory_boundary: wire.accepted_point.inventory_boundary,
        database_schema_version: wire.database_schema_version,
        tool_version: wire.tool_version,
        checksum_manifest: wire.checksum_manifest_version,
        service_identity: wire.service_identity,
    };
    let dump = DumpEvidence {
        size: wire.database_dump.size,
        digest: dump_digest,
    };
    if facts.validate().is_err() || dump.validate().is_err() {
        return Err(seal_failure("invalid recovery seal root facts"));
    }
    let mut references = SealRootReferences {
        backup_id,
        operation_id,
        repository_binding_id,
        accepted_facts: facts,
        dump,
        chunks: Vec::with_capacity(wire.chunks.len()),
    };
    for (index, reference) in wire.chunks.iter().enumerate() {
        if reference.ordinal != index as u32
            || reference.chunk_identity != inventory_chunk_identity(reference.ordinal)
            || reference.entry_count == 0
            || reference.entry_count > MAXIMUM_INVENTORY_CHUNK_ENTRIES
        {
            return Err(seal_failure("invalid recovery seal root chunk reference"));
        }
        references.chunks.push(SealRootChunkReference {
            ordinal: reference.ordinal,
            digest: parse_sha256(&reference.digest_sha256)?,
            entry_count: reference.entry_count,
        });
    }
    Ok(references)
}

/// PostgreSQL engine/dump compatibility (restore admission):
/// the dump's recorded tool family must match the target engine's
/// major version line. `pg_dump-16.14` restores only into a `16.x`
/// engine. Pinned-tool and engine majors that differ are refused as
/// `RESTORE_MEDIA_INVALID` by the caller — this predicate is the
/// pure check.
#[must_use]
pub fn postgres_version_compatible(dump_tool_version: &str, engine_version: &str) -> bool {
    let dump_major = dump_tool_version
        .strip_prefix("pg_dump-")
        .and_then(|rest| rest.split('.').next());
    let engine_major = engine_version.split('.').next();
    matches!((dump_major, engine_major), (Some(d), Some(e)) if !d.is_empty() && !e.is_empty() && d == e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::inventory::{InventoryEntry, new_inventory_chunk};
    use crate::backup::operation::{new_backup_accepted_facts, new_backup_operation};
    use crate::domain::TargetIdentity;
    use time::macros::datetime;

    fn admitted_operation() -> BackupOperation {
        let created = datetime!(2026-03-01 12:00:00 UTC);
        let target = TargetIdentity {
            system_id: "sys".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        };
        let facts = new_backup_accepted_facts(
            created,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
            Uuid::now_v7(),
            Uuid::now_v7(),
            &format!("sha256:{}", "c".repeat(64)),
        )
        .unwrap();
        new_backup_operation(Uuid::now_v7(), Uuid::now_v7(), target, created)
            .unwrap()
            .accept(facts)
            .unwrap()
            .advance(BackupPhase::Dumping, created)
            .unwrap()
            .advance(BackupPhase::Inventory, created)
            .unwrap()
    }

    fn chunk(ordinal: u32) -> InventoryChunk {
        new_inventory_chunk(
            ordinal,
            vec![InventoryEntry {
                artifact_id: Uuid::from_bytes([ordinal as u8 + 1; 16]),
                checksum: [ordinal as u8 + 2; 32],
                size: 100,
            }],
        )
        .unwrap()
    }

    fn dump() -> DumpEvidence {
        DumpEvidence {
            size: 4096,
            digest: [7u8; 32],
        }
    }

    #[test]
    fn seal_root_round_trip() {
        let operation = admitted_operation();
        let manifest = new_seal_root_manifest(&operation, dump(), &[chunk(0), chunk(1)]).unwrap();
        assert!(manifest.verify().is_ok());
        let payload = manifest.canonical_json().unwrap();
        // Strict parse binds every chunk.
        let parsed = parse_seal_root_manifest(&payload, &[chunk(0), chunk(1)]).unwrap();
        assert_eq!(parsed.digest, manifest.digest);
        // A wrong chunk count or digest refuses.
        assert!(parse_seal_root_manifest(&payload, &[chunk(0)]).is_err());
        let mut wrong = chunk(1);
        wrong.digest = [9u8; 32];
        assert!(parse_seal_root_manifest(&payload, &[chunk(0), wrong]).is_err());
        // Bounded references parse without chunks.
        let references = parse_seal_root_references(&payload).unwrap();
        assert_eq!(references.chunks.len(), 2);
        assert_eq!(references.dump, dump());
        assert_eq!(references.backup_id, operation.backup_id);
        // Trailing/unknown JSON refuses.
        let mut trailing = payload.clone();
        trailing.extend_from_slice(b" ");
        assert!(parse_seal_root_references(&trailing).is_err());
    }

    #[test]
    fn seal_root_rejects_wrong_phase_and_dump() {
        let operation = admitted_operation();
        // Zero chunks is legitimate.
        let empty = new_seal_root_manifest(&operation, dump(), &[]).unwrap();
        assert!(empty.verify().is_ok());
        // A failed/terminal operation cannot mint a root.
        let planned = new_backup_operation(
            Uuid::now_v7(),
            Uuid::now_v7(),
            operation.target.clone(),
            operation.created_at,
        )
        .unwrap();
        assert!(new_seal_root_manifest(&planned, dump(), &[]).is_err());
        // A zero digest dump is refused.
        assert!(
            new_seal_root_manifest(
                &operation,
                DumpEvidence {
                    size: 1,
                    digest: [0u8; 32]
                },
                &[]
            )
            .is_err()
        );
        // Non-contiguous ordinals refuse.
        assert!(new_seal_root_manifest(&operation, dump(), &[chunk(1)]).is_err());
    }

    #[test]
    fn postgres_major_lines_must_match() {
        assert!(postgres_version_compatible("pg_dump-16.14", "16.3"));
        assert!(postgres_version_compatible("pg_dump-16.14", "16"));
        assert!(!postgres_version_compatible("pg_dump-16.14", "15.9"));
        assert!(!postgres_version_compatible("pg_dump-16.14", "17.0"));
        assert!(!postgres_version_compatible("other", "16.3"));
        assert!(!postgres_version_compatible("pg_dump-16.14", ""));
    }
}
