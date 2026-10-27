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
/// `backupBindingSchemaVersion`.
pub const BACKUP_BINDING_SCHEMA: &str = "central.backup-binding/v1";
/// `RepositoryManifestSchema`.
pub const REPOSITORY_MANIFEST_SCHEMA: &str = "central.backup-repository-manifest/v1";
/// `MaximumSealedBackups`.
pub const MAXIMUM_SEALED_BACKUPS: usize = 16;
/// `BackupSealCompanionSchema`.
pub const BACKUP_SEAL_COMPANION_SCHEMA: &str = "central.backup-seal/v1";
/// `BackupSealHMACDomain`.
pub const BACKUP_SEAL_HMAC_DOMAIN: &str = "slice-c-backup-seal-v1";
/// `BackupSealKeyVersion`.
pub const BACKUP_SEAL_KEY_VERSION: &str = "hmac-fingerprint-v1";
/// `BackupRepositoryAttestationSchema`.
pub const REPOSITORY_ATTESTATION_SCHEMA: &str = "central.backup-repository-attestation/v1";

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

/// `parseSHA256` — exactly 64 lowercase hex chars; the re-encode
/// check rejects uppercase/mixed input exactly as upstream.
fn parse_sha256(raw: &str) -> Option<[u8; 32]> {
    let raw = raw.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibble(raw[i * 2])? << 4) | nibble(raw[i * 2 + 1])?;
    }
    if hex_encode(&out).as_bytes() != raw {
        return None;
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
    // `x.Format(time.RFC3339Nano)` upstream — the shared wire helper
    // (fractional seconds when nonzero, `Z` suffix), not the `time`
    // crate's `Rfc3339` descriptor which truncates sub-second
    // precision and would silently change every canonical digest.
    crate::wire::rfc3339_nano(t)
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
// BackupBinding (repository_metadata.go) — the per-backup `binding.json`.
// ---------------------------------------------------------------------------

const INVALID_BACKUP_BINDING: &str = "invalid recovery backup binding";

fn invalid_backup_binding(message: &str) -> Failure {
    Failure::invalid("backup_repository_binding", message.to_owned())
}

/// `backupBindingWire`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupBindingWire {
    schema_version: String,
    repository_binding_id: String,
    backup_id: String,
    operation_id: String,
    target_fingerprint_sha256: String,
    config_fingerprint_sha256: String,
    payload_epoch_id: String,
    accepted_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    immutable_digest_sha256: String,
}

/// `BackupBinding` — ties a create-only backup directory to the
/// protected accepted operation before the first dump byte is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupBinding {
    /// Repository binding identity this backup belongs to.
    pub repository_binding_id: Uuid,
    /// Backup identity.
    pub backup_id: Uuid,
    /// Operation identity.
    pub operation_id: Uuid,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// `sha256:`-prefixed pinned-config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: Uuid,
    /// Accepted consistent point (target database time).
    pub accepted_at: time::OffsetDateTime,
    /// `sha256` over the digest-less canonical payload.
    pub immutable_digest: [u8; 32],
}

impl BackupBinding {
    fn wire(&self, include_digest: bool) -> BackupBindingWire {
        BackupBindingWire {
            schema_version: BACKUP_BINDING_SCHEMA.to_owned(),
            repository_binding_id: self.repository_binding_id.to_string(),
            backup_id: self.backup_id.to_string(),
            operation_id: self.operation_id.to_string(),
            target_fingerprint_sha256: self.target_fingerprint.clone(),
            config_fingerprint_sha256: self.config_fingerprint.clone(),
            payload_epoch_id: self.payload_epoch_id.to_string(),
            accepted_at: rfc3339(self.accepted_at),
            immutable_digest_sha256: if include_digest {
                hex_encode(&self.immutable_digest)
            } else {
                String::new()
            },
        }
    }

    fn canonical_payload(&self, include_digest: bool) -> Result<Vec<u8>, Failure> {
        if self.repository_binding_id.is_nil()
            || self.backup_id.is_nil()
            || self.operation_id.is_nil()
            || !crate::wire::valid_sha256_fingerprint(&self.target_fingerprint)
            || !crate::wire::valid_sha256_fingerprint(&self.config_fingerprint)
            || !crate::wire::is_v7(self.payload_epoch_id)
            || is_zero_time(self.accepted_at)
        {
            return Err(invalid_backup_binding(INVALID_BACKUP_BINDING));
        }
        serde_json::to_vec(&self.wire(include_digest))
            .map_err(|_| invalid_backup_binding(INVALID_BACKUP_BINDING))
    }

    /// `Verify` — the digest over the digest-less canonical payload.
    pub fn verify(&self) -> Result<(), Failure> {
        let payload = self.canonical_payload(false)?;
        if self.immutable_digest == [0u8; 32]
            || Sha256::digest(&payload).as_slice() != self.immutable_digest
        {
            return Err(invalid_backup_binding(INVALID_BACKUP_BINDING));
        }
        Ok(())
    }

    /// `CanonicalJSON` — the bytes `backups/<id>/binding.json` carries.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        self.verify()?;
        serde_json::to_vec(&self.wire(true))
            .map_err(|_| invalid_backup_binding(INVALID_BACKUP_BINDING))
    }
}

/// `NewBackupBinding` — the immutable binding derived only from the
/// accepted protected operation; a `Planned` operation can never bind.
pub fn new_backup_binding(
    operation: &crate::backup::operation::BackupOperation,
) -> Result<BackupBinding, Failure> {
    if operation.validate().is_err()
        || operation.phase == crate::backup::operation::BackupPhase::Planned
        || operation.accepted_facts.validate().is_err()
    {
        return Err(invalid_backup_binding(INVALID_BACKUP_BINDING));
    }
    let facts = &operation.accepted_facts;
    let mut binding = BackupBinding {
        repository_binding_id: facts.repository_binding_id,
        backup_id: operation.backup_id,
        operation_id: operation.operation_id,
        target_fingerprint: facts.target_fingerprint.clone(),
        config_fingerprint: facts.config_fingerprint.clone(),
        payload_epoch_id: facts.payload_epoch_id,
        accepted_at: operation.accepted_at.to_offset(time::UtcOffset::UTC),
        immutable_digest: [0u8; 32],
    };
    let payload = binding.canonical_payload(false)?;
    binding.immutable_digest = Sha256::digest(&payload).into();
    Ok(binding)
}

/// `ParseBackupBinding` — strict decode plus canonical round-trip.
pub fn parse_backup_binding(payload: &[u8]) -> Result<BackupBinding, Failure> {
    let wire: BackupBindingWire = decode_canonical(payload)
        .map_err(|_| invalid_backup_binding("invalid recovery backup binding encoding"))?;
    if wire.schema_version != BACKUP_BINDING_SCHEMA {
        return Err(invalid_backup_binding(
            "invalid recovery backup binding encoding",
        ));
    }
    let repository_binding_id = Uuid::parse_str(&wire.repository_binding_id).ok();
    let backup_id = Uuid::parse_str(&wire.backup_id).ok();
    let operation_id = Uuid::parse_str(&wire.operation_id).ok();
    let payload_epoch_id = Uuid::parse_str(&wire.payload_epoch_id).ok();
    let accepted_at = parse_rfc3339(&wire.accepted_at);
    let digest = parse_sha256(&wire.immutable_digest_sha256);
    let (
        Some(repository_binding_id),
        Some(backup_id),
        Some(operation_id),
        Some(payload_epoch_id),
        Some(accepted_at),
        Some(digest),
    ) = (
        repository_binding_id,
        backup_id,
        operation_id,
        payload_epoch_id,
        accepted_at,
        digest,
    )
    else {
        return Err(invalid_backup_binding(
            "invalid recovery backup binding encoding",
        ));
    };
    let binding = BackupBinding {
        repository_binding_id,
        backup_id,
        operation_id,
        target_fingerprint: wire.target_fingerprint_sha256,
        config_fingerprint: wire.config_fingerprint_sha256,
        payload_epoch_id,
        accepted_at,
        immutable_digest: digest,
    };
    match binding.canonical_json() {
        Ok(canonical) if canonical == payload => Ok(binding),
        _ => Err(invalid_backup_binding(
            "recovery backup binding is not canonical",
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

/// `ParseRepositoryManifest` — strict decode, entry parsing, sorted
/// re-derivation, digest equality, and byte-for-byte canonical
/// round-trip; nothing else is a valid `repository-manifest.json`.
pub fn parse_repository_manifest(payload: &[u8]) -> Result<RepositoryManifest, Failure> {
    let wire: RepositoryManifestWire = decode_canonical(payload)
        .map_err(|_| invalid_manifest("invalid recovery repository manifest encoding"))?;
    if wire.schema_version != REPOSITORY_MANIFEST_SCHEMA {
        return Err(invalid_manifest(
            "invalid recovery repository manifest encoding",
        ));
    }
    let binding_id = Uuid::parse_str(&wire.root_binding_id)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| invalid_manifest("invalid recovery repository manifest encoding"))?;
    let mut entries = Vec::with_capacity(wire.sealed_backups.len());
    for entry in &wire.sealed_backups {
        let backup_id = Uuid::parse_str(&entry.backup_id).ok();
        let accepted_at = parse_rfc3339(&entry.accepted_at);
        let root_digest = parse_sha256(&entry.root_manifest_digest_sha256);
        let companion_digest = parse_sha256(&entry.seal_companion_digest_sha256);
        let tree_digest = parse_sha256(&entry.file_tree_digest_sha256);
        let (
            Some(backup_id),
            Some(accepted_at),
            Some(root_digest),
            Some(companion_digest),
            Some(tree_digest),
        ) = (
            backup_id,
            accepted_at,
            root_digest,
            companion_digest,
            tree_digest,
        )
        else {
            return Err(invalid_manifest(
                "invalid recovery repository manifest encoding",
            ));
        };
        entries.push(RepositoryManifestEntry {
            backup_id,
            accepted_at,
            root_manifest_digest: root_digest,
            seal_companion_digest: companion_digest,
            file_tree_digest: tree_digest,
        });
    }
    let declared = parse_sha256(&wire.manifest_digest_sha256)
        .ok_or_else(|| invalid_manifest("invalid recovery repository manifest encoding"))?;
    let manifest = new_repository_manifest(binding_id, wire.revision, entries)?;
    if manifest.digest != declared {
        return Err(invalid_manifest(
            "invalid recovery repository manifest encoding",
        ));
    }
    match manifest.canonical_json() {
        Ok(canonical) if canonical == payload => Ok(manifest),
        _ => Err(invalid_manifest(
            "recovery repository manifest is not canonical",
        )),
    }
}

// ---------------------------------------------------------------------------
// BackupRepositoryAttestation (repository_attestation.go)
// ---------------------------------------------------------------------------

const INVALID_ATTESTATION: &str = "invalid recovery repository attestation";

fn invalid_attestation(message: &str) -> Failure {
    Failure::invalid("backup_repository_attestation", message.to_owned())
}

/// `backupRepositoryAttestationWire`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRepositoryAttestationWire {
    schema_version: String,
    launch_evidence_id: String,
    operation_id: String,
    backup_id: String,
    repository_binding_id: String,
    root_manifest_digest_sha256: String,
    seal_companion_digest_sha256: String,
    file_tree_digest_sha256: String,
    repository_manifest_digest_sha256: String,
    repository_revision: u64,
    attested_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    immutable_digest_sha256: String,
}

/// `BackupRepositoryAttestation` — the locator-free result of a
/// trusted helper re-reading the sealed repository after the backup
/// worker and all of its descendants have been reaped. It is the only
/// repository evidence accepted by the broker's terminal seal
/// transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRepositoryAttestation {
    /// Launch evidence identity.
    pub launch_evidence_id: Uuid,
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound backup.
    pub backup_id: Uuid,
    /// Repository binding.
    pub repository_binding_id: Uuid,
    /// Seal-root manifest digest.
    pub root_manifest_digest: [u8; 32],
    /// Seal companion digest.
    pub seal_companion_digest: [u8; 32],
    /// File-tree digest.
    pub file_tree_digest: [u8; 32],
    /// Repository manifest digest.
    pub repository_manifest_digest: [u8; 32],
    /// Repository revision.
    pub repository_revision: u64,
    /// Attestation instant (UTC).
    pub attested_at: time::OffsetDateTime,
    /// `sha256` over the digest-less canonical payload.
    pub immutable_digest: [u8; 32],
}

impl BackupRepositoryAttestation {
    fn wire(&self, include_digest: bool) -> BackupRepositoryAttestationWire {
        BackupRepositoryAttestationWire {
            schema_version: REPOSITORY_ATTESTATION_SCHEMA.to_owned(),
            launch_evidence_id: self.launch_evidence_id.to_string(),
            operation_id: self.operation_id.to_string(),
            backup_id: self.backup_id.to_string(),
            repository_binding_id: self.repository_binding_id.to_string(),
            root_manifest_digest_sha256: hex_encode(&self.root_manifest_digest),
            seal_companion_digest_sha256: hex_encode(&self.seal_companion_digest),
            file_tree_digest_sha256: hex_encode(&self.file_tree_digest),
            repository_manifest_digest_sha256: hex_encode(&self.repository_manifest_digest),
            repository_revision: self.repository_revision,
            attested_at: rfc3339(self.attested_at),
            immutable_digest_sha256: if include_digest {
                hex_encode(&self.immutable_digest)
            } else {
                String::new()
            },
        }
    }

    fn canonical_payload(&self, include_digest: bool) -> Result<Vec<u8>, Failure> {
        if self.launch_evidence_id.is_nil()
            || self.operation_id.is_nil()
            || self.backup_id.is_nil()
            || self.repository_binding_id.is_nil()
            || self.root_manifest_digest == [0u8; 32]
            || self.seal_companion_digest == [0u8; 32]
            || self.file_tree_digest == [0u8; 32]
            || self.repository_manifest_digest == [0u8; 32]
            || self.repository_revision == 0
            || is_zero_time(self.attested_at)
        {
            return Err(invalid_attestation(INVALID_ATTESTATION));
        }
        serde_json::to_vec(&self.wire(include_digest))
            .map_err(|_| invalid_attestation(INVALID_ATTESTATION))
    }

    /// `Verify`.
    pub fn verify(&self) -> Result<(), Failure> {
        let payload = self.canonical_payload(false)?;
        if self.immutable_digest == [0u8; 32]
            || Sha256::digest(&payload).as_slice() != self.immutable_digest
        {
            return Err(invalid_attestation(INVALID_ATTESTATION));
        }
        Ok(())
    }

    /// `CanonicalJSON`.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        self.verify()?;
        serde_json::to_vec(&self.wire(true)).map_err(|_| invalid_attestation(INVALID_ATTESTATION))
    }

    /// `Publication` — the seal publication this attestation carries.
    pub fn publication(&self) -> Result<BackupSealPublication, Failure> {
        self.verify()?;
        Ok(BackupSealPublication {
            operation_id: self.operation_id,
            backup_id: self.backup_id,
            repository_binding_id: self.repository_binding_id,
            root_manifest_digest: self.root_manifest_digest,
            seal_companion_digest: self.seal_companion_digest,
            file_tree_digest: self.file_tree_digest,
            repository_manifest_digest: self.repository_manifest_digest,
            repository_revision: self.repository_revision,
        })
    }

    /// `Binds` — the attestation names exactly this companion, and it
    /// cannot predate the seal it claims.
    #[must_use]
    pub fn binds(&self, companion: &BackupSealCompanion) -> bool {
        match self.publication() {
            Ok(publication) => {
                publication.binds(companion) && self.attested_at >= companion.sealed_at
            }
            Err(_) => false,
        }
    }
}

/// `NewBackupRepositoryAttestation`.
pub fn new_backup_repository_attestation(
    launch_evidence_id: Uuid,
    publication: &BackupSealPublication,
    attested_at: time::OffsetDateTime,
) -> Result<BackupRepositoryAttestation, Failure> {
    if launch_evidence_id.is_nil() || publication.validate().is_err() || is_zero_time(attested_at) {
        return Err(invalid_attestation(INVALID_ATTESTATION));
    }
    let mut attestation = BackupRepositoryAttestation {
        launch_evidence_id,
        operation_id: publication.operation_id,
        backup_id: publication.backup_id,
        repository_binding_id: publication.repository_binding_id,
        root_manifest_digest: publication.root_manifest_digest,
        seal_companion_digest: publication.seal_companion_digest,
        file_tree_digest: publication.file_tree_digest,
        repository_manifest_digest: publication.repository_manifest_digest,
        repository_revision: publication.repository_revision,
        attested_at: attested_at.to_offset(time::UtcOffset::UTC),
        immutable_digest: [0u8; 32],
    };
    let payload = attestation.canonical_payload(false)?;
    attestation.immutable_digest = Sha256::digest(&payload).into();
    Ok(attestation)
}

/// `ParseBackupRepositoryAttestation` — strict decode plus canonical
/// round-trip.
pub fn parse_backup_repository_attestation(
    payload: &[u8],
) -> Result<BackupRepositoryAttestation, Failure> {
    let wire: BackupRepositoryAttestationWire = decode_canonical(payload)
        .map_err(|_| invalid_attestation("invalid recovery repository attestation encoding"))?;
    if wire.schema_version != REPOSITORY_ATTESTATION_SCHEMA {
        return Err(invalid_attestation(
            "invalid recovery repository attestation encoding",
        ));
    }
    let launch_id = Uuid::parse_str(&wire.launch_evidence_id).ok();
    let operation_id = Uuid::parse_str(&wire.operation_id).ok();
    let backup_id = Uuid::parse_str(&wire.backup_id).ok();
    let binding_id = Uuid::parse_str(&wire.repository_binding_id).ok();
    let root_digest = parse_sha256(&wire.root_manifest_digest_sha256);
    let companion_digest = parse_sha256(&wire.seal_companion_digest_sha256);
    let tree_digest = parse_sha256(&wire.file_tree_digest_sha256);
    let index_digest = parse_sha256(&wire.repository_manifest_digest_sha256);
    let attested_at = parse_rfc3339(&wire.attested_at);
    let digest = parse_sha256(&wire.immutable_digest_sha256);
    let (
        Some(launch_id),
        Some(operation_id),
        Some(backup_id),
        Some(binding_id),
        Some(root_digest),
        Some(companion_digest),
        Some(tree_digest),
        Some(index_digest),
        Some(attested_at),
        Some(digest),
    ) = (
        launch_id,
        operation_id,
        backup_id,
        binding_id,
        root_digest,
        companion_digest,
        tree_digest,
        index_digest,
        attested_at,
        digest,
    )
    else {
        return Err(invalid_attestation(
            "invalid recovery repository attestation encoding",
        ));
    };
    let attestation = BackupRepositoryAttestation {
        launch_evidence_id: launch_id,
        operation_id,
        backup_id,
        repository_binding_id: binding_id,
        root_manifest_digest: root_digest,
        seal_companion_digest: companion_digest,
        file_tree_digest: tree_digest,
        repository_manifest_digest: index_digest,
        repository_revision: wire.repository_revision,
        attested_at,
        immutable_digest: digest,
    };
    match attestation.canonical_json() {
        Ok(canonical) if canonical == payload => Ok(attestation),
        _ => Err(invalid_attestation(
            "recovery repository attestation is not canonical",
        )),
    }
}

// ---------------------------------------------------------------------------
// BackupFileTreeEvidence / BackupSealCompanion / BackupSealPublication
// (repository_seal.go)
// ---------------------------------------------------------------------------

const INVALID_SEAL_COMPANION: &str = "invalid recovery seal companion";

fn invalid_seal_companion(message: &str) -> Failure {
    Failure::invalid("backup_seal_companion", message.to_owned())
}

/// `BackupFileTreeEvidence` — binds the ordered immutable files present
/// before the broker seal. The digest covers canonical logical
/// identities, sizes, and checksums; it carries no repository pathname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupFileTreeEvidence {
    /// SHA-256 over the canonical file-tree encoding.
    pub digest: [u8; 32],
}

impl BackupFileTreeEvidence {
    /// `Validate`.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.digest == [0u8; 32] {
            return Err(invalid_seal_companion(
                "invalid recovery file-tree evidence",
            ));
        }
        Ok(())
    }
}

/// `BackupSealPublication` — the locator-free receipt for the exact
/// companion and root index revision durably synchronized after the
/// broker commit. It is later consumed by the broker's dedicated
/// terminal completion transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSealPublication {
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound backup.
    pub backup_id: Uuid,
    /// Repository binding.
    pub repository_binding_id: Uuid,
    /// Digest of the seal-root manifest the entry binds.
    pub root_manifest_digest: [u8; 32],
    /// Digest of the exact companion JSON.
    pub seal_companion_digest: [u8; 32],
    /// Digest of the immutable file tree.
    pub file_tree_digest: [u8; 32],
    /// Digest of the published repository manifest revision.
    pub repository_manifest_digest: [u8; 32],
    /// Published repository manifest revision.
    pub repository_revision: u64,
}

impl BackupSealPublication {
    /// `Validate`.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.operation_id.is_nil()
            || self.backup_id.is_nil()
            || self.repository_binding_id.is_nil()
            || self.root_manifest_digest == [0u8; 32]
            || self.seal_companion_digest == [0u8; 32]
            || self.file_tree_digest == [0u8; 32]
            || self.repository_manifest_digest == [0u8; 32]
            || self.repository_revision == 0
        {
            return Err(invalid_seal_companion("invalid recovery seal publication"));
        }
        Ok(())
    }

    /// `Binds` — the publication receipt names exactly the broker
    /// companion it claims to have synchronized.
    #[must_use]
    pub fn binds(&self, companion: &BackupSealCompanion) -> bool {
        self.validate().is_ok()
            && companion.verify().is_ok()
            && self.operation_id == companion.operation_id
            && self.backup_id == companion.backup_id
            && self.repository_binding_id == companion.repository_binding_id
            && self.root_manifest_digest == companion.root_manifest_digest
            && self.seal_companion_digest == companion.digest
            && self.file_tree_digest == companion.file_tree_digest
    }
}

/// `backupSealCompanionWire` — the companion's canonical JSON shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSealCompanionWire {
    schema_version: String,
    authority_envelope_id: String,
    hmac_domain: String,
    key_version: String,
    backup_id: String,
    operation_id: String,
    repository_binding_id: String,
    target_fingerprint_sha256: String,
    config_fingerprint_sha256: String,
    payload_epoch_id: String,
    root_manifest_digest_sha256: String,
    file_tree_digest_sha256: String,
    sealed_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    hmac_sha256: String,
}

/// `BackupSealCompanion` — the repository copy of the broker-owned
/// final seal. Its HMAC is integrity evidence, not a reusable
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSealCompanion {
    /// `sha256:`-prefixed authority envelope identity.
    pub authority_envelope_id: String,
    /// Bound backup.
    pub backup_id: Uuid,
    /// Bound operation.
    pub operation_id: Uuid,
    /// Repository binding.
    pub repository_binding_id: Uuid,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// `sha256:`-prefixed config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: Uuid,
    /// Seal-root manifest digest.
    pub root_manifest_digest: [u8; 32],
    /// Immutable file-tree digest.
    pub file_tree_digest: [u8; 32],
    /// Seal instant (UTC).
    pub sealed_at: time::OffsetDateTime,
    /// Broker integrity HMAC (lowercase hex, no prefix).
    pub hmac: String,
    /// `sha256` over the canonical JSON — set by [`Self::verify`] or
    /// [`parse_backup_seal_companion`].
    pub digest: [u8; 32],
}

impl BackupSealCompanion {
    fn wire(&self, include_hmac: bool) -> BackupSealCompanionWire {
        BackupSealCompanionWire {
            schema_version: BACKUP_SEAL_COMPANION_SCHEMA.to_owned(),
            authority_envelope_id: self.authority_envelope_id.clone(),
            hmac_domain: BACKUP_SEAL_HMAC_DOMAIN.to_owned(),
            key_version: BACKUP_SEAL_KEY_VERSION.to_owned(),
            backup_id: self.backup_id.to_string(),
            operation_id: self.operation_id.to_string(),
            repository_binding_id: self.repository_binding_id.to_string(),
            target_fingerprint_sha256: self.target_fingerprint.clone(),
            config_fingerprint_sha256: self.config_fingerprint.clone(),
            payload_epoch_id: self.payload_epoch_id.to_string(),
            root_manifest_digest_sha256: hex_encode(&self.root_manifest_digest),
            file_tree_digest_sha256: hex_encode(&self.file_tree_digest),
            sealed_at: rfc3339(self.sealed_at),
            hmac_sha256: if include_hmac {
                self.hmac.clone()
            } else {
                String::new()
            },
        }
    }

    /// `validateShape`.
    fn validate_shape(&self, require_hmac: bool) -> Result<(), Failure> {
        if !crate::wire::valid_sha256_fingerprint(&self.authority_envelope_id)
            || self.backup_id.is_nil()
            || self.operation_id.is_nil()
            || self.repository_binding_id.is_nil()
            || !crate::wire::valid_sha256_fingerprint(&self.target_fingerprint)
            || !crate::wire::valid_sha256_fingerprint(&self.config_fingerprint)
            || !crate::wire::is_v7(self.payload_epoch_id)
            || self.root_manifest_digest == [0u8; 32]
            || self.file_tree_digest == [0u8; 32]
            || is_zero_time(self.sealed_at)
        {
            return Err(invalid_seal_companion(INVALID_SEAL_COMPANION));
        }
        if require_hmac && parse_sha256(&self.hmac).is_none() {
            return Err(invalid_seal_companion(INVALID_SEAL_COMPANION));
        }
        Ok(())
    }

    /// `HMACPayload` — the exact canonical value the broker
    /// authenticated (the companion without its HMAC field).
    pub fn hmac_payload(&self) -> Result<Vec<u8>, Failure> {
        self.validate_shape(false)?;
        serde_json::to_vec(&self.wire(false))
            .map_err(|_| invalid_seal_companion(INVALID_SEAL_COMPANION))
    }

    /// `CanonicalJSON` — the bytes the repository copy carries.
    pub fn canonical_json(&self) -> Result<Vec<u8>, Failure> {
        self.validate_shape(true)?;
        serde_json::to_vec(&self.wire(true))
            .map_err(|_| invalid_seal_companion(INVALID_SEAL_COMPANION))
    }

    /// `Verify` — the digest must equal `sha256` over the canonical
    /// JSON (which includes the HMAC field).
    pub fn verify(&self) -> Result<(), Failure> {
        let payload = self.canonical_json()?;
        if self.digest == [0u8; 32] || Sha256::digest(&payload).as_slice() != self.digest {
            return Err(invalid_seal_companion(INVALID_SEAL_COMPANION));
        }
        Ok(())
    }
}

/// `ParseBackupSealCompanion` — strict decode plus canonical
/// round-trip; the digest is recomputed from the exact payload bytes.
pub fn parse_backup_seal_companion(payload: &[u8]) -> Result<BackupSealCompanion, Failure> {
    let wire: BackupSealCompanionWire = decode_canonical(payload)
        .map_err(|_| invalid_seal_companion("invalid recovery seal companion encoding"))?;
    if wire.schema_version != BACKUP_SEAL_COMPANION_SCHEMA
        || wire.hmac_domain != BACKUP_SEAL_HMAC_DOMAIN
        || wire.key_version != BACKUP_SEAL_KEY_VERSION
    {
        return Err(invalid_seal_companion(
            "invalid recovery seal companion encoding",
        ));
    }
    let backup_id = Uuid::parse_str(&wire.backup_id).ok();
    let operation_id = Uuid::parse_str(&wire.operation_id).ok();
    let repository_binding_id = Uuid::parse_str(&wire.repository_binding_id).ok();
    let payload_epoch_id = Uuid::parse_str(&wire.payload_epoch_id).ok();
    let root_digest = parse_sha256(&wire.root_manifest_digest_sha256);
    let tree_digest = parse_sha256(&wire.file_tree_digest_sha256);
    let sealed_at = parse_rfc3339(&wire.sealed_at);
    let (
        Some(backup_id),
        Some(operation_id),
        Some(repository_binding_id),
        Some(payload_epoch_id),
        Some(root_digest),
        Some(tree_digest),
        Some(sealed_at),
    ) = (
        backup_id,
        operation_id,
        repository_binding_id,
        payload_epoch_id,
        root_digest,
        tree_digest,
        sealed_at,
    )
    else {
        return Err(invalid_seal_companion(
            "invalid recovery seal companion encoding",
        ));
    };
    let mut companion = BackupSealCompanion {
        authority_envelope_id: wire.authority_envelope_id,
        backup_id,
        operation_id,
        repository_binding_id,
        target_fingerprint: wire.target_fingerprint_sha256,
        config_fingerprint: wire.config_fingerprint_sha256,
        payload_epoch_id,
        root_manifest_digest: root_digest,
        file_tree_digest: tree_digest,
        sealed_at,
        hmac: wire.hmac_sha256,
        digest: [0u8; 32],
    };
    match companion.canonical_json() {
        Ok(canonical) if canonical == payload => {
            companion.digest = Sha256::digest(payload).into();
            Ok(companion)
        }
        _ => Err(invalid_seal_companion(
            "recovery seal companion is not canonical",
        )),
    }
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
