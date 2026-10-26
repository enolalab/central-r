//! `internal/backup/repository_metadata.go` +
//! `repository_seal.go` — the repository binding and the repository
//! manifest genesis initializes (R5 task 13). Only the values genesis
//! writes are ported: `NewRepositoryBinding`, `NewRepositoryManifest`
//! (empty entry set), the canonical-JSON encoders and their strict
//! parsers. The seal companions, inventory pages and backup bindings
//! are the R6 backup slice's, exactly as upstream splits the files.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const INVALID_BINDING: &str = "invalid recovery repository binding";
const INVALID_MANIFEST: &str = "invalid recovery repository manifest";

/// `repositoryBindingSchemaVersion`.
pub const REPOSITORY_BINDING_SCHEMA: &str = "central.backup-repository-binding/v1";
/// `RepositoryManifestSchema`.
pub const REPOSITORY_MANIFEST_SCHEMA: &str = "central.backup-repository-manifest/v1";
/// `MaximumSealedBackups`.
pub const MAXIMUM_SEALED_BACKUPS: usize = 16;

fn invalid_binding(message: &str) -> Failure {
    Failure::invalid("backup_repository_binding", message.to_owned())
}

fn invalid_manifest(message: &str) -> Failure {
    Failure::invalid("backup_repository_manifest", message.to_owned())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn parse_sha256(raw: &str) -> Option<[u8; 32]> {
    let raw = raw.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibble(raw[i * 2])? << 4) | nibble(raw[i * 2 + 1])?;
    }
    Some(out)
}

/// `validOpaqueRepositoryIdentity`.
fn valid_opaque_repository_identity(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || value.contains(['/', '\\', '\0']) {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// `decodeCanonicalJSON` — strict field set and a single JSON value.
fn decode_canonical<'a, T: Deserialize<'a>>(payload: &'a [u8]) -> Result<T, Failure> {
    let mut de = serde_json::Deserializer::from_slice(payload);
    let value = serde::de::Deserialize::deserialize(&mut de)
        .map_err(|e| Failure::invalid("backup_canonical_json", e.to_string()))?;
    // `decoder.Decode(&trailing) == io.EOF` upstream: only whitespace
    // may follow the single value.
    de.end()
        .map_err(|_| Failure::invalid("backup_canonical_json", "trailing data after JSON value"))?;
    Ok(value)
}

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn parse_rfc3339(raw: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).ok()
}

/// `time.Time.IsZero` — January 1, year 1, midnight UTC.
fn is_zero_time(t: time::OffsetDateTime) -> bool {
    t.year() == 1
        && t.month() == time::Month::January
        && t.day() == 1
        && t.hour() == 0
        && t.minute() == 0
        && t.second() == 0
        && t.nanosecond() == 0
}

// ---------------------------------------------------------------------------
// RepositoryBinding (repository_metadata.go)
// ---------------------------------------------------------------------------

/// `repositoryBindingWire` — the binding's canonical JSON shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryBindingWire {
    schema_version: String,
    binding_id: String,
    instance_id: String,
    owner_uid: u32,
    owner_gid: u32,
    device_major: u64,
    device_minor: u64,
    root_inode: u64,
    mount_id: u64,
    created_at: String,
    creation_nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    immutable_digest_sha256: String,
}

/// `RepositoryBinding` — the repository's durable identity, bound to
/// one instance and one filesystem mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryBinding {
    pub binding_id: Uuid,
    pub instance_id: String,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub device_major: u64,
    pub device_minor: u64,
    pub root_inode: u64,
    pub mount_id: u64,
    pub created_at: time::OffsetDateTime,
    pub creation_nonce: [u8; 32],
    pub immutable_digest: [u8; 32],
}

impl RepositoryBinding {
    fn wire(&self, include_digest: bool) -> RepositoryBindingWire {
        RepositoryBindingWire {
            schema_version: REPOSITORY_BINDING_SCHEMA.to_owned(),
            binding_id: self.binding_id.to_string(),
            instance_id: self.instance_id.clone(),
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            device_major: self.device_major,
            device_minor: self.device_minor,
            root_inode: self.root_inode,
            mount_id: self.mount_id,
            created_at: rfc3339(self.created_at),
            creation_nonce: hex_encode(&self.creation_nonce),
            immutable_digest_sha256: if include_digest {
                hex_encode(&self.immutable_digest)
            } else {
                String::new()
            },
        }
    }

    fn canonical_payload(&self, include_digest: bool) -> Result<Vec<u8>, Failure> {
        if self.binding_id.is_nil()
            || !valid_opaque_repository_identity(&self.instance_id)
            || self.root_inode == 0
            || self.mount_id == 0
            || is_zero_time(self.created_at)
            || self.creation_nonce == [0u8; 32]
        {
            return Err(invalid_binding(INVALID_BINDING));
        }
        serde_json::to_vec(&self.wire(include_digest)).map_err(|_| invalid_binding(INVALID_BINDING))
    }

    /// `Verify` — the digest over the digest-less canonical payload.
    pub fn verify(&self) -> Result<(), Failure> {
        let payload = self.canonical_payload(false)?;
        if self.immutable_digest == [0u8; 32]
            || Sha256::digest(&payload).as_slice() != self.immutable_digest
        {
            return Err(invalid_binding(INVALID_BINDING));
        }
        Ok(())
    }

    /// `CanonicalJSON` — the bytes `binding.json` carries.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        self.verify()?;
        serde_json::to_vec(&self.wire(true)).map_err(|_| invalid_binding(INVALID_BINDING))
    }
}

/// `NewRepositoryBinding`.
#[allow(clippy::too_many_arguments)]
pub fn new_repository_binding(
    binding_id: Uuid,
    instance_id: &str,
    owner_uid: u32,
    owner_gid: u32,
    device_major: u64,
    device_minor: u64,
    root_inode: u64,
    mount_id: u64,
    created_at: time::OffsetDateTime,
    creation_nonce: [u8; 32],
) -> Result<RepositoryBinding, Failure> {
    let mut binding = RepositoryBinding {
        binding_id,
        instance_id: instance_id.to_owned(),
        owner_uid,
        owner_gid,
        device_major,
        device_minor,
        root_inode,
        mount_id,
        created_at,
        creation_nonce,
        immutable_digest: [0u8; 32],
    };
    let payload = binding.canonical_payload(false)?;
    binding.immutable_digest = Sha256::digest(&payload).into();
    Ok(binding)
}

/// `ParseRepositoryBinding` — strict decode plus canonical round-trip.
pub fn parse_repository_binding(payload: &[u8]) -> Result<RepositoryBinding, Failure> {
    let wire: RepositoryBindingWire = decode_canonical(payload)
        .map_err(|_| invalid_binding("invalid recovery repository binding encoding"))?;
    if wire.schema_version != REPOSITORY_BINDING_SCHEMA {
        return Err(invalid_binding(
            "invalid recovery repository binding encoding",
        ));
    }
    let binding_id = Uuid::parse_str(&wire.binding_id).ok();
    let created_at = parse_rfc3339(&wire.created_at);
    let nonce = parse_sha256(&wire.creation_nonce);
    let digest = parse_sha256(&wire.immutable_digest_sha256);
    let (Some(binding_id), Some(created_at), Some(nonce), Some(digest)) =
        (binding_id, created_at, nonce, digest)
    else {
        return Err(invalid_binding(
            "invalid recovery repository binding encoding",
        ));
    };
    let binding = RepositoryBinding {
        binding_id,
        instance_id: wire.instance_id,
        owner_uid: wire.owner_uid,
        owner_gid: wire.owner_gid,
        device_major: wire.device_major,
        device_minor: wire.device_minor,
        root_inode: wire.root_inode,
        mount_id: wire.mount_id,
        created_at,
        creation_nonce: nonce,
        immutable_digest: digest,
    };
    match binding.canonical_json() {
        Ok(canonical) if canonical == payload => Ok(binding),
        _ => Err(invalid_binding(
            "recovery repository binding is not canonical",
        )),
    }
}

// ---------------------------------------------------------------------------
// RepositoryManifest (repository_seal.go)
// ---------------------------------------------------------------------------

/// `repositoryManifestEntryWire`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryManifestEntryWire {
    backup_id: String,
    accepted_at: String,
    root_manifest_digest_sha256: String,
    seal_companion_digest_sha256: String,
    file_tree_digest_sha256: String,
}

/// `repositoryManifestWire`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryManifestWire {
    schema_version: String,
    root_binding_id: String,
    revision: u64,
    sealed_backups: Vec<RepositoryManifestEntryWire>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    manifest_digest_sha256: String,
}

/// `RepositoryManifestEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryManifestEntry {
    pub backup_id: Uuid,
    pub accepted_at: time::OffsetDateTime,
    pub root_manifest_digest: [u8; 32],
    pub seal_companion_digest: [u8; 32],
    pub file_tree_digest: [u8; 32],
}

/// `RepositoryManifest` — the sealed-backup index; genesis publishes
/// the revision-0 empty form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryManifest {
    pub root_binding_id: Uuid,
    pub revision: u64,
    pub sealed_backups: Vec<RepositoryManifestEntry>,
    pub digest: [u8; 32],
}

impl RepositoryManifest {
    fn canonical_payload(&self, include_digest: bool) -> Result<Vec<u8>, Failure> {
        if self.root_binding_id.is_nil() || self.sealed_backups.len() > MAXIMUM_SEALED_BACKUPS {
            return Err(invalid_manifest(INVALID_MANIFEST));
        }
        let mut wire = RepositoryManifestWire {
            schema_version: REPOSITORY_MANIFEST_SCHEMA.to_owned(),
            root_binding_id: self.root_binding_id.to_string(),
            revision: self.revision,
            sealed_backups: Vec::with_capacity(self.sealed_backups.len()),
            manifest_digest_sha256: String::new(),
        };
        for (i, entry) in self.sealed_backups.iter().enumerate() {
            if entry.backup_id.is_nil()
                || is_zero_time(entry.accepted_at)
                || entry.root_manifest_digest == [0u8; 32]
                || entry.seal_companion_digest == [0u8; 32]
                || entry.file_tree_digest == [0u8; 32]
                || (i > 0
                    && !(self.sealed_backups[i - 1].accepted_at < entry.accepted_at
                        || (self.sealed_backups[i - 1].accepted_at == entry.accepted_at
                            && self.sealed_backups[i - 1].backup_id.to_string().as_str()
                                < entry.backup_id.to_string().as_str())))
            {
                return Err(invalid_manifest(
                    "invalid recovery repository manifest entry",
                ));
            }
            wire.sealed_backups.push(RepositoryManifestEntryWire {
                backup_id: entry.backup_id.to_string(),
                accepted_at: rfc3339(entry.accepted_at),
                root_manifest_digest_sha256: hex_encode(&entry.root_manifest_digest),
                seal_companion_digest_sha256: hex_encode(&entry.seal_companion_digest),
                file_tree_digest_sha256: hex_encode(&entry.file_tree_digest),
            });
        }
        if include_digest {
            wire.manifest_digest_sha256 = hex_encode(&self.digest);
        }
        serde_json::to_vec(&wire).map_err(|_| invalid_manifest(INVALID_MANIFEST))
    }

    /// `CanonicalJSON`.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        let payload = self.canonical_payload(false)?;
        if self.digest == [0u8; 32] || Sha256::digest(&payload).as_slice() != self.digest {
            return Err(invalid_manifest(INVALID_MANIFEST));
        }
        self.canonical_payload(true)
    }
}

/// `NewRepositoryManifest` — sorts the entries before digesting,
/// exactly as upstream.
pub fn new_repository_manifest(
    binding_id: Uuid,
    revision: u64,
    entries: Vec<RepositoryManifestEntry>,
) -> Result<RepositoryManifest, Failure> {
    let mut manifest = RepositoryManifest {
        root_binding_id: binding_id,
        revision,
        sealed_backups: entries,
        digest: [0u8; 32],
    };
    manifest.sealed_backups.sort_by(|a, b| {
        a.accepted_at
            .cmp(&b.accepted_at)
            .then_with(|| a.backup_id.to_string().cmp(&b.backup_id.to_string()))
    });
    let payload = manifest.canonical_payload(false)?;
    manifest.digest = Sha256::digest(&payload).into();
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn binding_canonical_round_trip() {
        let binding = new_repository_binding(
            Uuid::now_v7(),
            "instance-1",
            501,
            501,
            8,
            1,
            4242,
            77,
            datetime!(2026-01-02 03:04:05.123456789 UTC),
            [7u8; 32],
        )
        .unwrap();
        let payload = binding.canonical_json().unwrap();
        let parsed = parse_repository_binding(&payload).unwrap();
        assert_eq!(parsed, binding);
        // Strict: unknown field, trailing data, wrong schema all refuse.
        assert!(parse_repository_binding(br#"{"schema_version":"x"}"#.as_slice()).is_err());
        let mut trailing = payload.clone();
        trailing.extend_from_slice(b" {}");
        assert!(parse_repository_binding(&trailing).is_err());
    }

    #[test]
    fn manifest_revision_zero_canonical() {
        let manifest = new_repository_manifest(Uuid::now_v7(), 0, Vec::new()).unwrap();
        let payload = manifest.canonical_json().unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(wire["schema_version"], REPOSITORY_MANIFEST_SCHEMA);
        assert_eq!(wire["revision"], 0);
        assert_eq!(wire["sealed_backups"], serde_json::json!([]));
        assert!(wire["manifest_digest_sha256"].as_str().unwrap().len() == 64);
    }
}
