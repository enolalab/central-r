//! `internal/backup/inventory.go` — the bounded, canonical
//! `central.backup-inventory/v1` chunk unit.
//!
//! A chunk is immutable, carries only opaque artifact IDs, sizes, and
//! checksums — never a live object key, backend locator, filename, or
//! body. Entries sort by opaque artifact UUID so two equivalent scans
//! yield byte-identical payload and digest. Canonical bytes reproduce
//! Go's `json.Marshal` struct-field order exactly (serde field order
//! ≙ Go declaration order); parsing re-encodes and demands
//! byte-equality so a stored entry cannot be reinterpreted under a
//! looser JSON parser.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::wire::{decode_canonical, hex_encode, parse_sha256, wire_failure};

/// `inventoryChunkSchemaVersion`.
pub const INVENTORY_CHUNK_SCHEMA: &str = "central.backup-inventory/v1";
/// `databaseDumpLogicalRef`.
pub const DATABASE_DUMP_LOGICAL_REF: &str = "central.database-dump/v1";
/// `MaximumInventoryChunkEntries`.
pub const MAXIMUM_INVENTORY_CHUNK_ENTRIES: usize = 1_000;

fn inventory_failure(message: &'static str) -> Failure {
    wire_failure("backup_recovery", message)
}

/// `inventoryChunkIdentity` — `central.backup-inventory-chunk/v1:%08d`.
#[must_use]
pub fn inventory_chunk_identity(ordinal: u32) -> String {
    format!("central.backup-inventory-chunk/v1:{ordinal:08}")
}

/// `InventoryEntry` — the recovery-safe projection of one ready
/// artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Opaque artifact identity.
    pub artifact_id: Uuid,
    /// Sealed body checksum.
    pub checksum: [u8; 32],
    /// Body byte length.
    pub size: i64,
}

impl InventoryEntry {
    /// `Validate` — refuses nil IDs, negative sizes, and zero digests.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.artifact_id.is_nil() || self.size < 0 || self.checksum == [0u8; 32] {
            return Err(inventory_failure("invalid recovery inventory entry"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryEntryWire {
    artifact_id: String,
    checksum_sha256: String,
    size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryChunkWire {
    schema_version: String,
    ordinal: u32,
    entries: Vec<InventoryEntryWire>,
}

/// `InventoryChunk` — one canonical, checksum-protected, immutable
/// inventory unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryChunk {
    /// Contiguous chunk ordinal (0-based within the manifest).
    pub ordinal: u32,
    /// Entries sorted by `artifact_id` string.
    pub entries: Vec<InventoryEntry>,
    /// SHA-256 over [`InventoryChunk::canonical_json`].
    pub digest: [u8; 32],
}

/// `NewInventoryChunk` — canonicalizes and validates a bounded page.
pub fn new_inventory_chunk(
    ordinal: u32,
    entries: Vec<InventoryEntry>,
) -> Result<InventoryChunk, Failure> {
    if entries.is_empty() || entries.len() > MAXIMUM_INVENTORY_CHUNK_ENTRIES {
        return Err(inventory_failure("invalid recovery inventory chunk length"));
    }
    let mut canonical = entries;
    for entry in &canonical {
        entry.validate()?;
    }
    canonical.sort_by_key(|entry| entry.artifact_id.to_string());
    for pair in canonical.windows(2) {
        if pair[0].artifact_id == pair[1].artifact_id {
            return Err(inventory_failure("duplicate recovery inventory artifact"));
        }
    }
    let mut chunk = InventoryChunk {
        ordinal,
        entries: canonical,
        digest: [0u8; 32],
    };
    chunk.digest = Sha256::digest(chunk.canonical_payload()?).into();
    Ok(chunk)
}

impl InventoryChunk {
    fn canonical_payload(&self) -> Result<Vec<u8>, Failure> {
        if self.entries.is_empty() || self.entries.len() > MAXIMUM_INVENTORY_CHUNK_ENTRIES {
            return Err(inventory_failure("invalid recovery inventory chunk length"));
        }
        let mut wire = InventoryChunkWire {
            schema_version: INVENTORY_CHUNK_SCHEMA.to_owned(),
            ordinal: self.ordinal,
            entries: Vec::with_capacity(self.entries.len()),
        };
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if index > 0
                && self.entries[index - 1].artifact_id.to_string() >= entry.artifact_id.to_string()
            {
                return Err(inventory_failure(
                    "recovery inventory entries are not canonically ordered",
                ));
            }
            wire.entries.push(InventoryEntryWire {
                artifact_id: entry.artifact_id.to_string(),
                checksum_sha256: hex_encode(&entry.checksum),
                size: entry.size,
            });
        }
        serde_json::to_vec(&wire).map_err(|_| inventory_failure("invalid recovery inventory chunk"))
    }

    /// `CanonicalJSON` — the exact bytes covered by `digest`.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        self.canonical_payload()
    }

    /// `Verify` — recompute the digest before the chunk may join a
    /// seal or a restore verification.
    pub fn verify(&self) -> Result<(), Failure> {
        if Sha256::digest(self.canonical_payload()?).as_slice() != self.digest {
            return Err(inventory_failure(
                "recovery inventory chunk digest mismatch",
            ));
        }
        Ok(())
    }
}

/// `ParseInventoryChunk` — accepts only the exact canonical wire
/// representation.
pub fn parse_inventory_chunk(payload: &[u8]) -> Result<InventoryChunk, Failure> {
    let wire: InventoryChunkWire = decode_canonical(payload)
        .map_err(|_| inventory_failure("invalid recovery inventory chunk encoding"))?;
    if wire.schema_version != INVENTORY_CHUNK_SCHEMA {
        return Err(inventory_failure("invalid recovery inventory chunk schema"));
    }
    let mut entries = Vec::with_capacity(wire.entries.len());
    for encoded in &wire.entries {
        let artifact_id = Uuid::parse_str(&encoded.artifact_id)
            .map_err(|_| inventory_failure("invalid recovery inventory artifact identity"))?;
        entries.push(InventoryEntry {
            artifact_id,
            checksum: parse_sha256(&encoded.checksum_sha256)?,
            size: encoded.size,
        });
    }
    let chunk = new_inventory_chunk(wire.ordinal, entries)?;
    match chunk.canonical_json() {
        Ok(canonical) if canonical == payload => Ok(chunk),
        _ => Err(inventory_failure(
            "recovery inventory chunk is not canonical",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id_byte: u8) -> InventoryEntry {
        InventoryEntry {
            artifact_id: Uuid::from_bytes([id_byte; 16]),
            checksum: [id_byte.wrapping_add(1); 32],
            size: id_byte as i64 + 1,
        }
    }

    #[test]
    fn chunk_canonicalizes_and_verifies() {
        // Unsorted input is sorted by artifact UUID string.
        let chunk = new_inventory_chunk(0, vec![entry(3), entry(1), entry(2)]).unwrap();
        let ordered: Vec<_> = chunk
            .entries
            .iter()
            .map(|e| e.artifact_id.to_string())
            .collect();
        let mut sorted = ordered.clone();
        sorted.sort();
        assert_eq!(ordered, sorted);
        assert!(chunk.verify().is_ok());
        // Round-trip strictness.
        let payload = chunk.canonical_json().unwrap();
        let parsed = parse_inventory_chunk(&payload).unwrap();
        assert_eq!(parsed, chunk);
        // Noncanonical whitespace refuses — a stored chunk cannot be
        // reinterpreted under a looser JSON parser.
        let mut tampered = payload.clone();
        tampered.insert(1, b' ');
        assert!(parse_inventory_chunk(&tampered).is_err());
        // Entries out of canonical order refuse.
        let reversed = new_inventory_chunk;
        let mut unsorted = payload.clone();
        // swap the two middle entry objects wholesale
        let text = String::from_utf8(unsorted.clone()).unwrap();
        let entry_start = text.find("[{").unwrap() + 1;
        let entry_end = text.rfind("}]").unwrap() + 1;
        let mid = text[entry_start..entry_end].find("},{").unwrap() + entry_start;
        let swapped = format!(
            "{}[{}]{}{}",
            &text[..entry_start - 1],
            &text[mid + 3..entry_end - 1],
            "},{",
            &text[entry_start..mid],
        );
        unsorted = swapped.into_bytes();
        unsorted.push(b'}');
        assert!(parse_inventory_chunk(&unsorted).is_err());
        let _ = reversed;
        // Unknown field refuses.
        let with_extra = payload[..payload.len() - 1].to_vec();
        let mut with_extra = with_extra;
        with_extra.extend_from_slice(b",\"extra\":1}");
        assert!(parse_inventory_chunk(&with_extra).is_err());
        // Trailing value refuses.
        let mut trailing = payload.clone();
        trailing.extend_from_slice(b"{}");
        assert!(parse_inventory_chunk(&trailing).is_err());
    }

    #[test]
    fn chunk_bounds_and_identity() {
        assert_eq!(
            inventory_chunk_identity(42),
            "central.backup-inventory-chunk/v1:00000042"
        );
        assert!(new_inventory_chunk(0, vec![]).is_err());
        let duplicate = entry(1);
        assert!(new_inventory_chunk(0, vec![duplicate, duplicate]).is_err());
        let oversized = vec![entry(1); MAXIMUM_INVENTORY_CHUNK_ENTRIES + 1];
        assert!(new_inventory_chunk(0, oversized).is_err());
        let bad = InventoryEntry {
            artifact_id: Uuid::nil(),
            ..entry(1)
        };
        assert!(bad.validate().is_err());
    }
}
