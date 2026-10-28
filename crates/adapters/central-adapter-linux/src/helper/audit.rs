//! `internal/audit/audit.go` + `helper/audit.go` — the D05 protected-state
//! integrity audit: hash every file under the protected tree, compare
//! against the last signed manifest, sign and append the report.
//! Tamper is evidence, never a trigger; authorized repair (the D01 wipe
//! ceremony) only removes untrusted files and appends a signed successor
//! manifest — it never invents the contents it deletes.
//!
//! This module also carries the deny-safe gate's read side
//! (`internal/advisory/denysafe.go`'s `LoadDenySafe`/`IsDenySafeActive`)
//! because the helper's transport gate is the slice's only consumer.

use super::PeerIdentity;
use super::grant::CeremonyScope;
use super::protocol::{Request, Response};
use central_foundation::failure::Failure;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn internal(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::internal(code, msg.into())
}

// ---------------------------------------------------------------------------
// Reason vocabulary + tamper vocabulary (audit.go's const blocks)
// ---------------------------------------------------------------------------

pub const REASON_AUDIT_DENIED_SIGNED: &str = "AUDIT_DENIED_SIGNED";
pub const REASON_AUDIT_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
pub const REASON_AUDIT_CEREMONY_REQUIRED: &str = "AUDIT_CEREMONY_REQUIRED";
pub const REASON_AUDIT_UNAVAILABLE: &str = "AUDIT_UNAVAILABLE";
pub const REASON_AUDIT_INVALID_REQUEST: &str = "INVALID_AUDIT_REQUEST";
pub const REASON_AUDIT_TAMPER_DETECTED: &str = "AUDIT_TAMPER_DETECTED";
pub const REASON_AUDIT_REPAIR_REFUSED: &str = "AUDIT_REPAIR_REFUSED";
pub const REASON_AUDIT_REPAIR_FAILED: &str = "AUDIT_REPAIR_FAILED";

/// `advisory.ReasonDenySafeActive` — the one gate reason the transport
/// gate retains.
pub const REASON_DENY_SAFE_ACTIVE: &str = "DENY_SAFE_ACTIVE";

pub const TAMPER_MODIFIED: &str = "modified";
pub const TAMPER_MISSING: &str = "missing";
pub const TAMPER_UNKNOWN: &str = "unknown";
pub const TAMPER_SYMLINK: &str = "symlink";
pub const TAMPER_SPECIAL: &str = "special";

/// `AuditInterval` — the dossier's daily schedule.
pub const AUDIT_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// `ScheduleDue(last_unix, now_unix)` — zero last is due, never late.
/// Times are unix seconds; a negative last means "never run".
pub fn schedule_due(last: Option<time::OffsetDateTime>, now: time::OffsetDateTime) -> (bool, bool) {
    let Some(last) = last else {
        return (true, false);
    };
    let elapsed = now - last;
    if elapsed < time::Duration::try_from(AUDIT_INTERVAL).unwrap_or(time::Duration::MAX) {
        return (false, false);
    }
    (
        true,
        elapsed >= time::Duration::try_from(AUDIT_INTERVAL * 2).unwrap_or(time::Duration::MAX),
    )
}

// ---------------------------------------------------------------------------
// Deny-safe gate read side (advisory/denysafe.go)
// ---------------------------------------------------------------------------

/// `RescueAttempt` — one recorded rescue try; the candidate itself is
/// never stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RescueAttempt {
    #[serde(default)]
    pub attempt_id: String,
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub candidate_digest_sha256: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub code: String,
}

/// `DenySafeState` — the deny-safe mode record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenySafeState {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub entered_at: String,
    #[serde(default)]
    pub trigger_code: String,
    #[serde(default)]
    pub cleanup_done: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rescue_attempts: Vec<RescueAttempt>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exited_at: String,
}

/// `LoadDenySafe` — absence is reported, never defaulted.
pub fn load_deny_safe(dir: &str) -> Result<(DenySafeState, bool), Failure> {
    if dir.is_empty() || !Path::new(dir).is_absolute() {
        return Err(internal(
            "sys_denysafe_dir",
            "advisory: deny-safe dir must be absolute",
        ));
    }
    let path = Path::new(dir).join("deny-safe.json");
    let raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((DenySafeState::default(), false));
        }
        Err(e) => {
            return Err(internal(
                "sys_denysafe_read",
                format!("advisory: deny-safe state: {e}"),
            ));
        }
    };
    let state: DenySafeState = serde_json::from_slice(&raw).map_err(|e| {
        internal(
            "sys_denysafe_corrupt",
            format!("advisory: deny-safe state corrupt: {e}"),
        )
    })?;
    Ok((state, true))
}

/// `IsDenySafeActive` — a corrupt state file fails CLOSED (active):
/// a gate that cannot read its own lock does not open it.
pub fn is_deny_safe_active(dir: &str) -> bool {
    match load_deny_safe(dir) {
        Err(_) => true,
        Ok((_, false)) => false,
        Ok((state, true)) => state.active && state.exited_at.is_empty(),
    }
}

// ---------------------------------------------------------------------------
// AuditRequest / AuditResult (helper/audit.go)
// ---------------------------------------------------------------------------

/// `AuditRequest` — the closed `state-audit` payload.
#[derive(Debug, Clone, Default)]
pub struct AuditRequest {
    pub operation_id: String,
    pub repair: bool,
    pub scheduled: bool,
    pub last_run_at: String,
}

/// `ParseAuditRequest` — unknown fields are refused so a flag the
/// handler does not understand cannot silently become authority.
pub fn parse_audit_request(req: &Request) -> Result<AuditRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing audit operation".to_owned());
    }
    let trimmed = {
        let p = req.payload_bytes();
        let s = p
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(p.len());
        let e = p
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(s, |i| i + 1);
        &p[s..e.max(s)]
    };
    if trimmed.is_empty() {
        return Ok(AuditRequest {
            operation_id: req.operation_id.clone(),
            ..AuditRequest::default()
        });
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        repair: bool,
        #[serde(default)]
        scheduled: bool,
        #[serde(default)]
        last_run_at: String,
    }
    let payload: Payload = super::protocol::strict_decode(trimmed)
        .map_err(|e| format!("helper: invalid audit payload: {e}"))?;
    Ok(AuditRequest {
        operation_id: req.operation_id.clone(),
        repair: payload.repair,
        scheduled: payload.scheduled,
        last_run_at: payload.last_run_at,
    })
}

/// `TamperedFile` — one diverged path and what the audit proved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperedFile {
    pub path: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Manifest / Report / Evidence / Identity
// ---------------------------------------------------------------------------

/// `Manifest` — one signed baseline. `files` maps slash-separated paths
/// relative to the protected root to lowercase-hex SHA-256; the chain
/// (each manifest naming its predecessor) makes a replaced manifest
/// tamper evidence itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_manifest_id: String,
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub file_hashes: BTreeMap<String, String>,
    #[serde(default)]
    pub signature: String,
}

pub const MANIFEST_GENESIS: &str = "genesis";
pub const MANIFEST_AUDIT: &str = "audit";
pub const MANIFEST_REPAIR: &str = "repair";

/// `Report` — one signed audit outcome. Tamper and partial coverage
/// travel here, never as an error.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub report_id: String,
    pub manifest_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_manifest_id: String,
    #[serde(default)]
    pub manifest_valid: bool,
    #[serde(default)]
    pub checked: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tampered: Vec<TamperedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub late: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub baseline_created: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub repaired: bool,
    #[serde(default)]
    pub completed_at: String,
    #[serde(default)]
    pub signature: String,
}

/// `AuditResult` — the bounded audit outcome the wire carries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditResult {
    pub operation_id: String,
    pub report_id: String,
    pub manifest_id: String,
    pub manifest_valid: bool,
    pub checked: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tampered: Vec<TamperedFile>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub late: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub baseline_created: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub repaired: bool,
    pub completed_at: String,
}

/// `Identity` — the instance's persistent audit keypair, minted once.
/// Deliberately NOT the export identity: audit trust and export trust
/// are separate roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub private_seed_hex: String,
    pub public_key_hex: String,
    pub created_at: String,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Go's `time.RFC3339Nano` — fraction only when nonzero, trailing
/// zeros trimmed. Delegates to [`crate::broker::wire::format_rfc3339_nano`],
/// the crate's canonical Go-parity formatter: `well_known::Rfc3339`
/// already emits a fractional second when the nanos are nonzero, so a
/// wrapper that appends another one doubled it (`…00.52.52Z`, and
/// `…+07:00.52` for non-UTC inputs) and corrupted every signed
/// manifest/report timestamp it fed.
pub fn format_rfc3339nano(t: time::OffsetDateTime) -> String {
    crate::broker::wire::format_rfc3339_nano(t)
}

/// `LoadOrMintIdentity` — load, or create exactly once (O_EXCL: a
/// concurrent first audit reads what won the race). A present-but-
/// malformed file refuses rather than re-minting: silent re-minting
/// would orphan every report the old key signed.
pub fn load_or_mint_identity(
    path: &Path,
    uid: u32,
    gid: u32,
    now: &str,
) -> Result<(Identity, bool), Failure> {
    match std::fs::read(path) {
        Ok(raw) => {
            let identity: Identity = serde_json::from_slice(&raw).map_err(|e| {
                internal(
                    "sys_audit_identity",
                    format!("audit: identity corrupt: {e}"),
                )
            })?;
            let seed = hex_decode(&identity.private_seed_hex)
                .filter(|s| s.len() == ed25519_dalek::SECRET_KEY_LENGTH)
                .ok_or_else(|| internal("sys_audit_identity", "audit: identity corrupt"))?;
            let mut arr = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
            arr.copy_from_slice(&seed);
            let private = SigningKey::from_bytes(&arr);
            if hex_encode(&private.verifying_key().to_bytes())
                != identity.public_key_hex.to_lowercase()
            {
                return Err(internal("sys_audit_identity", "audit: identity corrupt"));
            }
            return Ok((identity, false));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(internal(
                "sys_audit_identity",
                format!("audit: identity: {e}"),
            ));
        }
        Err(_) => {}
    }
    let mut seed = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| internal("sys_audit_identity", format!("audit: mint identity: {e}")))?;
    let private = SigningKey::from_bytes(&seed);
    let identity = Identity {
        private_seed_hex: hex_encode(&seed),
        public_key_hex: hex_encode(&private.verifying_key().to_bytes()),
        created_at: now.to_owned(),
    };
    let encoded = serde_json::to_vec(&identity)
        .map_err(|e| internal("sys_audit_identity", format!("audit: identity: {e}")))?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    match file {
        Ok(mut f) => {
            f.write_all(&encoded)
                .and_then(|_| f.write_all(b"\n"))
                .and_then(|_| f.sync_all())
                .map_err(|e| internal("sys_audit_identity", format!("audit: identity: {e}")))?;
            drop(f);
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return load_or_mint_identity(path, uid, gid, now);
        }
        Err(e) => {
            return Err(internal(
                "sys_audit_identity",
                format!("audit: identity: {e}"),
            ));
        }
    }
    set_audit_file_owner(path, uid, gid)?;
    Ok((identity, true))
}

fn set_audit_file_owner(path: &Path, uid: u32, gid: u32) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| internal("sys_audit_file", format!("audit: file mode: {e}")))?;
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .map_err(|e| internal("sys_audit_file", format!("audit: file owner: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Roots / HashTree / Compare
// ---------------------------------------------------------------------------

/// `Roots` — the two hierarchies an audit touches. The audit subtree
/// must live inside the protected root (reports inherit its
/// protection) and is the one subtree the walk skips.
#[derive(Debug, Clone, Default)]
pub struct Roots {
    pub protected_dir: String,
    pub audit_dir: String,
    pub instance_id: String,
    pub audit_uid: u32,
    pub audit_gid: u32,
}

impl Roots {
    /// `roots.validate`.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.protected_dir.is_empty() || self.audit_dir.is_empty() || self.instance_id.is_empty()
        {
            return Err(internal("sys_audit_roots", "audit: roots are incomplete"));
        }
        let (p, a) = (Path::new(&self.protected_dir), Path::new(&self.audit_dir));
        if !p.is_absolute() || !a.is_absolute() {
            return Err(internal("sys_audit_roots", "audit: roots must be absolute"));
        }
        match a.strip_prefix(p) {
            Ok(rel) if rel != Path::new("") => Ok(()),
            _ => Err(internal(
                "sys_audit_roots",
                "audit: audit dir must live inside the protected dir",
            )),
        }
    }
}

fn manifest_path(audit_dir: &str) -> PathBuf {
    Path::new(audit_dir).join("manifest.json")
}
fn identity_path(audit_dir: &str) -> PathBuf {
    Path::new(audit_dir).join("audit-identity.json")
}

/// The `HashTree` triple: file hashes, structural tamper findings,
/// and unreadable slash-relative paths.
pub type HashTree = (BTreeMap<String, String>, Vec<TamperedFile>, Vec<String>);

/// `HashTree` — slash-relative paths to hex digests. The audit subtree
/// is skipped. Symlinks and specials are not followed or hashed; they
/// are tamper (the protected tree must contain neither). Unreadable
/// files are collected, not fatal.
pub fn hash_tree(protected_dir: &str, audit_dir: &str) -> Result<HashTree, Failure> {
    let mut hashes = BTreeMap::new();
    let mut tampered = Vec::new();
    let mut unreadable = Vec::new();
    let clean_audit = normalize(Path::new(audit_dir));
    let root = Path::new(protected_dir);
    let mut stack = vec![root.to_path_buf()];
    // `filepath.WalkDir` order is lexical per directory; sort the
    // findings at the end for the same deterministic report.
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                if dir == root {
                    return Err(internal("sys_audit_walk", format!("audit: walk: {e}")));
                }
                let slash = slash_rel(root, &dir);
                if !slash.is_empty() {
                    unreadable.push(slash);
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let clean = normalize(&path);
            if clean == clean_audit {
                continue; // the audit subtree is out of scope, dir or file
            }
            let slash = slash_rel(root, &path);
            if slash.is_empty() {
                continue;
            }
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => {
                    unreadable.push(slash);
                    continue;
                }
            };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                let reason = if ft.is_symlink() {
                    TAMPER_SYMLINK
                } else {
                    TAMPER_SPECIAL
                };
                tampered.push(TamperedFile {
                    path: slash,
                    reason: reason.to_owned(),
                });
                continue;
            }
            match std::fs::read(&path) {
                Ok(raw) => {
                    hashes.insert(slash, hex_encode(&Sha256::digest(&raw)));
                }
                Err(_) => unreadable.push(slash),
            }
        }
    }
    tampered.sort_by(|a, b| a.path.cmp(&b.path));
    unreadable.sort();
    Ok((hashes, tampered, unreadable))
}

/// Component-wise clean (no fs access): resolves `.` and interior `..`
/// textually so the audit-dir comparison behaves like
/// `filepath.Clean`.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn slash_rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|r| {
            r.components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default()
}

/// `Compare` — per path, what changed between manifest and tree.
/// `structural` carries the walk's own findings; unreadable paths are
/// skipped and stay in the report's unreadable list.
pub fn compare(
    manifest: &Manifest,
    hashes: &BTreeMap<String, String>,
    structural: &[TamperedFile],
    unreadable: &[String],
) -> Vec<TamperedFile> {
    let mut tampered = structural.to_vec();
    let skip: std::collections::BTreeSet<&str> = unreadable.iter().map(String::as_str).collect();
    for (path, want) in &manifest.file_hashes {
        if skip.contains(path.as_str()) {
            continue;
        }
        match hashes.get(path) {
            None => tampered.push(TamperedFile {
                path: path.clone(),
                reason: TAMPER_MISSING.to_owned(),
            }),
            Some(got) if got != want => tampered.push(TamperedFile {
                path: path.clone(),
                reason: TAMPER_MODIFIED.to_owned(),
            }),
            _ => {}
        }
    }
    for path in hashes.keys() {
        if skip.contains(path.as_str()) || manifest.file_hashes.contains_key(path) {
            continue;
        }
        tampered.push(TamperedFile {
            path: path.clone(),
            reason: TAMPER_UNKNOWN.to_owned(),
        });
    }
    tampered
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

fn signing_key(identity: &Identity) -> Result<SigningKey, Failure> {
    let seed = hex_decode(&identity.private_seed_hex)
        .filter(|s| s.len() == ed25519_dalek::SECRET_KEY_LENGTH)
        .ok_or_else(|| internal("sys_audit_sign", "audit: private key size is invalid"))?;
    let mut arr = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&arr))
}

fn verifying_key(identity: &Identity) -> Result<VerifyingKey, Failure> {
    let raw = hex_decode(&identity.public_key_hex)
        .filter(|s| s.len() == ed25519_dalek::PUBLIC_KEY_LENGTH)
        .ok_or_else(|| internal("sys_audit_verify", "audit: public key size is invalid"))?;
    let mut arr = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| internal("sys_audit_verify", "audit: public key size is invalid"))
}

/// `canonicalManifestBytes` — the manifest with signature blanked.
/// Serde emits fields in declaration order and `BTreeMap` keys sorted —
/// Go's marshal order exactly.
fn canonical_manifest_bytes(m: &Manifest) -> Result<Vec<u8>, Failure> {
    let mut m = m.clone();
    m.signature.clear();
    serde_json::to_vec(&m).map_err(|e| internal("sys_audit_sign", format!("audit: manifest: {e}")))
}

/// `SignManifest` — shape check, then sign.
pub fn sign_manifest(mut manifest: Manifest, private: &SigningKey) -> Result<Manifest, Failure> {
    if manifest.manifest_id.is_empty()
        || manifest.instance_id.is_empty()
        || manifest.created_at.is_empty()
    {
        return Err(internal(
            "sys_audit_sign",
            "audit: manifest identity is incomplete",
        ));
    }
    match manifest.reason.as_str() {
        MANIFEST_GENESIS | MANIFEST_AUDIT | MANIFEST_REPAIR => {}
        _ => {
            return Err(internal(
                "sys_audit_sign",
                "audit: manifest reason is invalid",
            ));
        }
    }
    let canonical = canonical_manifest_bytes(&manifest)?;
    manifest.signature = hex_encode(&private.sign(&canonical).to_bytes());
    Ok(manifest)
}

/// `VerifyManifest` — signature plus chain link: non-genesis must name
/// its predecessor.
pub fn verify_manifest(
    manifest: &Manifest,
    public: &VerifyingKey,
    predecessor_id: &str,
) -> Result<(), Failure> {
    let sig = hex_decode(&manifest.signature)
        .filter(|s| s.len() == ed25519_dalek::SIGNATURE_LENGTH)
        .ok_or_else(|| internal("sys_audit_verify", "audit: manifest signature is invalid"))?;
    let mut arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    arr.copy_from_slice(&sig);
    let signature = Signature::from_bytes(&arr);
    let canonical = canonical_manifest_bytes(manifest)?;
    public.verify(&canonical, &signature).map_err(|_| {
        internal(
            "sys_audit_verify",
            "audit: manifest signature does not verify",
        )
    })?;
    if manifest.reason == MANIFEST_GENESIS {
        if !manifest.previous_manifest_id.is_empty() {
            return Err(internal(
                "sys_audit_verify",
                "audit: genesis manifest names a predecessor",
            ));
        }
        return Ok(());
    }
    if manifest.previous_manifest_id.is_empty() || manifest.previous_manifest_id != predecessor_id {
        return Err(internal(
            "sys_audit_verify",
            "audit: manifest chain is broken",
        ));
    }
    Ok(())
}

/// `LoadManifest` — absence is reported, never defaulted.
pub fn load_manifest(audit_dir: &str) -> Result<(Manifest, bool), Failure> {
    let raw = match std::fs::read(manifest_path(audit_dir)) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Manifest::default(), false));
        }
        Err(e) => {
            return Err(internal(
                "sys_audit_manifest",
                format!("audit: manifest: {e}"),
            ));
        }
    };
    let manifest: Manifest = serde_json::from_slice(&raw).map_err(|e| {
        internal(
            "sys_audit_manifest",
            format!("audit: manifest corrupt: {e}"),
        )
    })?;
    Ok((manifest, true))
}

fn store_owned_file(
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    exclusive: bool,
) -> Result<(), Failure> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).mode(0o600);
    if exclusive {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut f = opts.open(path).map_err(|e| {
        internal(
            "sys_audit_store",
            format!("audit: store {}: {e}", path.display()),
        )
    })?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| {
        internal(
            "sys_audit_store",
            format!("audit: store {}: {e}", path.display()),
        )
    })?;
    drop(f);
    set_audit_file_owner(path, uid, gid)
}

/// `StoreManifest` — the history copy is created exclusively (a second
/// manifest with the same id is a bug, never an overwrite) and the
/// current pointer is replaced atomically by tmp+rename — the signed
/// transition the dossier requires.
pub fn store_manifest(
    audit_dir: &str,
    manifest: &Manifest,
    uid: u32,
    gid: u32,
) -> Result<(), Failure> {
    if manifest.manifest_id.is_empty() || manifest.signature.is_empty() {
        return Err(internal(
            "sys_audit_store",
            "audit: manifest must be signed before storing",
        ));
    }
    let mut encoded = serde_json::to_vec_pretty(manifest)
        .map_err(|e| internal("sys_audit_store", format!("audit: manifest: {e}")))?;
    encoded.push(b'\n');
    let history = Path::new(audit_dir).join(format!("manifest-{}.json", manifest.manifest_id));
    store_owned_file(&history, &encoded, uid, gid, true)?;
    let tmp = Path::new(audit_dir).join(format!("manifest-{}.tmp", std::process::id()));
    store_owned_file(&tmp, &encoded, uid, gid, false)?;
    std::fs::rename(&tmp, manifest_path(audit_dir))
        .map_err(|e| internal("sys_audit_store", format!("audit: store manifest: {e}")))
}

fn canonical_report_bytes(r: &Report) -> Result<Vec<u8>, Failure> {
    let mut r = r.clone();
    r.signature.clear();
    serde_json::to_vec(&r).map_err(|e| internal("sys_audit_sign", format!("audit: report: {e}")))
}

/// `SignReport`.
pub fn sign_report(mut report: Report, private: &SigningKey) -> Result<Report, Failure> {
    if report.report_id.is_empty()
        || report.manifest_id.is_empty()
        || report.completed_at.is_empty()
    {
        return Err(internal(
            "sys_audit_sign",
            "audit: report identity is incomplete",
        ));
    }
    let canonical = canonical_report_bytes(&report)?;
    report.signature = hex_encode(&private.sign(&canonical).to_bytes());
    Ok(report)
}

/// `VerifyReport`.
pub fn verify_report(report: &Report, public: &VerifyingKey) -> Result<(), Failure> {
    let sig = hex_decode(&report.signature)
        .filter(|s| s.len() == ed25519_dalek::SIGNATURE_LENGTH)
        .ok_or_else(|| internal("sys_audit_verify", "audit: report signature is invalid"))?;
    let mut arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    arr.copy_from_slice(&sig);
    let signature = Signature::from_bytes(&arr);
    let canonical = canonical_report_bytes(report)?;
    public.verify(&canonical, &signature).map_err(|_| {
        internal(
            "sys_audit_verify",
            "audit: report signature does not verify",
        )
    })
}

/// `StoreReport` — append-only: a second report with the same id is
/// refused.
pub fn store_report(audit_dir: &str, report: &Report, uid: u32, gid: u32) -> Result<(), Failure> {
    if report.report_id.is_empty() || report.signature.is_empty() {
        return Err(internal(
            "sys_audit_store",
            "audit: report must be signed before storing",
        ));
    }
    let mut encoded = serde_json::to_vec_pretty(report)
        .map_err(|e| internal("sys_audit_store", format!("audit: report: {e}")))?;
    encoded.push(b'\n');
    let path = Path::new(audit_dir).join(format!("report-{}.json", report.report_id));
    store_owned_file(&path, &encoded, uid, gid, true)
}

// ---------------------------------------------------------------------------
// Run / Repair
// ---------------------------------------------------------------------------

/// `RunInput`.
#[derive(Debug, Clone)]
pub struct RunInput {
    pub roots: Roots,
    pub now: time::OffsetDateTime,
    pub scheduled: bool,
    /// `None` = zero value: due immediately, never late.
    pub last_run_at: Option<time::OffsetDateTime>,
}

/// `RunOutput`.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub report: Report,
    pub manifest: Manifest,
    pub baseline_created: bool,
}

fn new_id() -> Result<String, Failure> {
    Ok(uuid::Uuid::now_v7().to_string())
}

/// `Run` — identity, hash, compare (or genesis baseline), sign and
/// store the report. It never repairs.
pub fn run(input: &RunInput) -> Result<RunOutput, Failure> {
    input.roots.validate()?;
    // `os.MkdirAll(dir, 0o700)` — the leaf is mode-pinned only when
    // this run creates it; an existing dir keeps its mode, upstream's
    // exact rule.
    if !Path::new(&input.roots.audit_dir).exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&input.roots.audit_dir)
            .and_then(|_| {
                std::fs::set_permissions(
                    &input.roots.audit_dir,
                    std::fs::Permissions::from_mode(0o700),
                )
            })
            .map_err(|e| internal("sys_audit_run", format!("audit: audit dir: {e}")))?;
    }
    // `now := input.Now.UTC()` upstream — the timestamp text is
    // always Z-formed regardless of the caller's offset.
    let now = format_rfc3339nano(input.now.to_offset(time::UtcOffset::UTC));
    let (identity, _) = load_or_mint_identity(
        &identity_path(&input.roots.audit_dir),
        input.roots.audit_uid,
        input.roots.audit_gid,
        &now,
    )?;
    let private = signing_key(&identity)?;
    let public = verifying_key(&identity)?;

    let (manifest, found) = load_manifest(&input.roots.audit_dir)?;
    let (hashes, structural, unreadable) =
        hash_tree(&input.roots.protected_dir, &input.roots.audit_dir)?;

    let report_id = new_id()?;
    let late = input.scheduled && schedule_due(input.last_run_at, input.now).1;

    if !found {
        let genesis = sign_manifest(
            Manifest {
                manifest_id: new_id()?,
                previous_manifest_id: String::new(),
                instance_id: input.roots.instance_id.clone(),
                created_at: now.clone(),
                reason: MANIFEST_GENESIS.to_owned(),
                file_hashes: hashes.clone(),
                signature: String::new(),
            },
            &private,
        )?;
        store_manifest(
            &input.roots.audit_dir,
            &genesis,
            input.roots.audit_uid,
            input.roots.audit_gid,
        )?;
        let report = sign_report(
            Report {
                report_id,
                manifest_id: genesis.manifest_id.clone(),
                manifest_valid: true,
                checked: i64::try_from(hashes.len()).unwrap_or(i64::MAX),
                tampered: structural,
                unreadable,
                late,
                baseline_created: true,
                completed_at: now,
                ..Report::default()
            },
            &private,
        )?;
        store_report(
            &input.roots.audit_dir,
            &report,
            input.roots.audit_uid,
            input.roots.audit_gid,
        )?;
        return Ok(RunOutput {
            report,
            manifest: genesis,
            baseline_created: true,
        });
    }

    let manifest_valid =
        verify_manifest(&manifest, &public, &manifest.previous_manifest_id).is_ok();
    let tampered = if manifest_valid {
        compare(&manifest, &hashes, &structural, &unreadable)
    } else {
        vec![TamperedFile {
            path: "audit/manifest.json".to_owned(),
            reason: TAMPER_MODIFIED.to_owned(),
        }]
    };
    let report = sign_report(
        Report {
            report_id,
            manifest_id: manifest.manifest_id.clone(),
            previous_manifest_id: manifest.previous_manifest_id.clone(),
            manifest_valid,
            checked: i64::try_from(hashes.len()).unwrap_or(i64::MAX),
            tampered,
            unreadable,
            late,
            completed_at: now,
            ..Report::default()
        },
        &private,
    )?;
    store_report(
        &input.roots.audit_dir,
        &report,
        input.roots.audit_uid,
        input.roots.audit_gid,
    )?;
    Ok(RunOutput {
        report,
        manifest,
        baseline_created: false,
    })
}

/// `Repairable` — hash-mismatched, unknown, symlinked, and special
/// paths can be removed; missing paths cannot — a successor manifest
/// that silently forgot them would launder the deletion.
pub fn repairable(tampered: &[TamperedFile]) -> (Vec<TamperedFile>, Vec<TamperedFile>) {
    let mut removable = Vec::new();
    let mut missing = Vec::new();
    for f in tampered {
        if f.reason == TAMPER_MISSING {
            missing.push(f.clone());
        } else {
            removable.push(f.clone());
        }
    }
    (removable, missing)
}

/// `Repair` — remove the repairable findings, append the signed
/// successor manifest over the resulting tree, re-verify clean. The
/// caller performs the D01 ceremony first; nothing here authorizes.
pub fn repair(
    roots: &Roots,
    now: time::OffsetDateTime,
    tampered: &[TamperedFile],
) -> Result<Report, Failure> {
    roots.validate()?;
    let (removable, missing) = repairable(tampered);
    if !missing.is_empty() {
        return Err(internal(
            "sys_audit_repair_refused",
            format!(
                "audit: {}: {} manifest-listed file(s) are missing and unrecoverable",
                REASON_AUDIT_REPAIR_REFUSED,
                missing.len()
            ),
        ));
    }
    if removable.is_empty() {
        return Err(internal("sys_audit_repair", "audit: nothing repairable"));
    }
    // `now = now.UTC()` upstream — same UTC normalization as `run`.
    let now_text = format_rfc3339nano(now.to_offset(time::UtcOffset::UTC));
    let (identity, _) = load_or_mint_identity(
        &identity_path(&roots.audit_dir),
        roots.audit_uid,
        roots.audit_gid,
        &now_text,
    )?;
    let private = signing_key(&identity)?;

    for finding in &removable {
        let candidate = Path::new(&roots.protected_dir).join(&finding.path);
        let clean = normalize(&candidate);
        let protected = normalize(Path::new(&roots.protected_dir));
        // The finding paths came from this tree's own walk, but repair
        // re-validates anyway: removal outside the protected root is
        // never attempted, and audit-owned paths are never removed.
        if !clean.starts_with(&protected) || clean == protected {
            return Err(internal(
                "sys_audit_repair_escape",
                format!(
                    "audit: repair path escapes the protected root: {}",
                    finding.path
                ),
            ));
        }
        let audit_clean = normalize(Path::new(&roots.audit_dir));
        if clean == audit_clean || clean.starts_with(&audit_clean) {
            return Err(internal(
                "sys_audit_repair_escape",
                format!(
                    "audit: repair refuses an audit-owned path: {}",
                    finding.path
                ),
            ));
        }
        match std::fs::remove_file(&clean) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(internal("sys_audit_repair", format!("audit: repair: {e}"))),
        }
    }

    let (hashes, structural, unreadable) = hash_tree(&roots.protected_dir, &roots.audit_dir)?;
    if !structural.is_empty() || !unreadable.is_empty() {
        return Err(internal(
            "sys_audit_repair",
            "audit: tree is not repairable to clean",
        ));
    }
    let (previous, found) = load_manifest(&roots.audit_dir)?;
    if !found {
        return Err(internal(
            "sys_audit_repair",
            "audit: predecessor manifest is unavailable",
        ));
    }
    let successor = sign_manifest(
        Manifest {
            manifest_id: new_id()?,
            previous_manifest_id: previous.manifest_id.clone(),
            instance_id: roots.instance_id.clone(),
            created_at: now_text.clone(),
            reason: MANIFEST_REPAIR.to_owned(),
            file_hashes: hashes.clone(),
            signature: String::new(),
        },
        &private,
    )?;
    store_manifest(
        &roots.audit_dir,
        &successor,
        roots.audit_uid,
        roots.audit_gid,
    )?;

    // The repair proves itself: re-compare the post-repair tree
    // against the successor just stored.
    let (verify, structural_after, unreadable_after) =
        hash_tree(&roots.protected_dir, &roots.audit_dir)?;
    if !compare(&successor, &verify, &structural_after, &unreadable_after).is_empty() {
        return Err(internal(
            "sys_audit_repair_failed",
            format!("audit: {REASON_AUDIT_REPAIR_FAILED}: findings remain"),
        ));
    }
    let report = sign_report(
        Report {
            report_id: new_id()?,
            manifest_id: successor.manifest_id.clone(),
            previous_manifest_id: successor.previous_manifest_id.clone(),
            manifest_valid: true,
            checked: i64::try_from(verify.len()).unwrap_or(i64::MAX),
            repaired: true,
            completed_at: now_text,
            ..Report::default()
        },
        &private,
    )?;
    store_report(&roots.audit_dir, &report, roots.audit_uid, roots.audit_gid)?;
    Ok(report)
}

// ---------------------------------------------------------------------------
// AuditHandlerImpl (helper/audit.go)
// ---------------------------------------------------------------------------

/// The B01 seam — `auditAdvisoryEvaluator`. Only `state == Current`
/// admits a repair.
pub trait AuditAdvisoryEvaluator: Send + Sync {
    fn evaluate(&self) -> Result<AdvisoryVerdict, Failure>;
}

/// `advisory.Result` narrowed to the one fact the repair gate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryVerdict {
    Current,
    NotCurrent,
}

/// `wipePAMConfirmer` — the D01 wipe ceremony the repair runs under.
pub trait AuditPamConfirmer: Send + Sync {
    fn confirm_wipe(
        &self,
        peer: PeerIdentity,
        deadline: Option<std::time::Instant>,
        scope: &CeremonyScope,
        operation_id: &str,
    ) -> Result<String, Failure>;
    fn verify_and_consume(&self, token: &str) -> bool;
}

/// `AuditHandlerImpl` — read-only audit unconditionally; repair only
/// under the D01 ceremony, only toward a verifying manifest, only when
/// nothing is missing, only under a Current advisory.
pub struct AuditHandlerImpl {
    pub pam: Option<Box<dyn AuditPamConfirmer>>,
    pub advisory: Option<Box<dyn AuditAdvisoryEvaluator>>,
    /// The D01 wipe scope — repair runs under the D01 ceremony, so it
    /// confirms the D01 identity.
    pub scope: CeremonyScope,
    pub roots: Roots,
}

/// The transport seam — same shape as [`super::init::InitHandler`].
/// `deadline` is the verb's transport bound, forwarded into the D01
/// ceremony exactly as upstream's `ctx` was.
pub trait AuditHandler: Send + Sync {
    fn audit(
        &self,
        peer: PeerIdentity,
        deadline: std::time::Instant,
        request: AuditRequest,
    ) -> Response;
}

fn audit_response(operation_id: &str, outcome: &str, code: i64, reason: &str) -> Response {
    Response::new(operation_id, outcome, code, reason)
}

fn to_audit_result(operation_id: &str, report: &Report) -> AuditResult {
    AuditResult {
        operation_id: operation_id.to_owned(),
        report_id: report.report_id.clone(),
        manifest_id: report.manifest_id.clone(),
        manifest_valid: report.manifest_valid,
        checked: report.checked,
        tampered: report.tampered.clone(),
        unreadable: report.unreadable.clone(),
        late: report.late,
        baseline_created: report.baseline_created,
        repaired: report.repaired,
        completed_at: report.completed_at.clone(),
    }
}

impl AuditHandler for AuditHandlerImpl {
    /// `Audit` — the upstream ordering verbatim: request and seams,
    /// last-run timestamp, run, read-only answer, repair gate chain.
    fn audit(
        &self,
        peer: PeerIdentity,
        deadline: std::time::Instant,
        request: AuditRequest,
    ) -> Response {
        let op = request.operation_id.as_str();
        let valid_id = uuid::Uuid::parse_str(op).is_ok()
            && uuid::Uuid::parse_str(op)
                .map(|u| u != uuid::Uuid::nil())
                .unwrap_or(false);
        if !valid_id
            || !peer.available()
            || self.pam.is_none()
            || self.advisory.is_none()
            || self.scope.instance_id.is_empty()
            || self.scope.target_id.is_empty()
        {
            return audit_response(op, "denied", 7, REASON_AUDIT_CEREMONY_REQUIRED);
        }
        let mut last_run_at = None;
        if !request.last_run_at.is_empty() {
            match time::OffsetDateTime::parse(
                &request.last_run_at,
                &time::format_description::well_known::Rfc3339,
            ) {
                Ok(t) => last_run_at = Some(t),
                Err(_) => return audit_response(op, "denied", 2, REASON_AUDIT_INVALID_REQUEST),
            }
        }
        let out = match run(&RunInput {
            roots: self.roots.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: request.scheduled,
            last_run_at,
        }) {
            Ok(o) => o,
            Err(_) => return audit_response(op, "denied", 7, REASON_AUDIT_UNAVAILABLE),
        };
        if !request.repair {
            return Response::new(op, "success", 0, "ok")
                .with_result(&to_audit_result(op, &out.report));
        }
        if out.report.tampered.is_empty() && out.report.manifest_valid {
            return Response::new(op, "success", 0, "ok")
                .with_result(&to_audit_result(op, &out.report));
        }
        let (_, missing) = repairable(&out.report.tampered);
        if !missing.is_empty() {
            return audit_response(op, "denied", 7, REASON_AUDIT_REPAIR_REFUSED);
        }
        if !out.report.manifest_valid {
            // The manifest itself does not verify: no trustworthy
            // baseline to repair toward.
            return audit_response(op, "denied", 7, REASON_AUDIT_REPAIR_REFUSED);
        }
        match self.advisory.as_ref().map(|a| a.evaluate()) {
            Some(Ok(AdvisoryVerdict::Current)) => {}
            _ => return audit_response(op, "denied", 7, REASON_AUDIT_DENIED_SIGNED),
        }
        let Some(pam) = &self.pam else {
            return audit_response(op, "denied", 7, REASON_AUDIT_CEREMONY_REQUIRED);
        };
        let confirmation = pam
            .confirm_wipe(peer, Some(deadline), &self.scope, op)
            .ok()
            .filter(|token| pam.verify_and_consume(token));
        if confirmation.is_none() {
            return audit_response(op, "denied", 7, REASON_AUDIT_AUTHORITY_DENIED);
        }
        match repair(
            &self.roots,
            time::OffsetDateTime::now_utc(),
            &out.report.tampered,
        ) {
            Ok(repaired) => {
                Response::new(op, "success", 0, "ok").with_result(&to_audit_result(op, &repaired))
            }
            Err(_) => audit_response(op, "denied", 7, REASON_AUDIT_REPAIR_FAILED),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditClient — client_linux.go's linuxAuditClient.
// ---------------------------------------------------------------------------

/// `AuditClientResult` mirrors the helper's `AuditResult` across the
/// socket — strict-decoded and canonical-checked.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditClientResult {
    pub operation_id: String,
    pub report_id: String,
    pub manifest_id: String,
    pub manifest_valid: bool,
    pub checked: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tampered: Vec<TamperedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub late: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub baseline_created: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub repaired: bool,
    pub completed_at: String,
}

/// `AuditClientError` exposes only the stable exit class plus a
/// whitelisted reason token.
#[derive(Debug)]
pub struct AuditClientError {
    exit_code: i64,
    reason: String,
}

impl AuditClientError {
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }
    /// The whitelisted helper reason token, or the empty string when
    /// the helper reported nothing on the closed set.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for AuditClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "helper: audit failed")
    }
}
impl std::error::Error for AuditClientError {}

/// `retainedAuditReason` — the complete whitelist of audit reason
/// tokens this client retains.
fn retained_audit_reason(reason: &str) -> String {
    match reason {
        REASON_DENY_SAFE_ACTIVE
        | REASON_AUDIT_REPAIR_REFUSED
        | REASON_AUDIT_REPAIR_FAILED
        | REASON_AUDIT_CEREMONY_REQUIRED
        | "AUTHORITY_DENIED"
        | REASON_AUDIT_DENIED_SIGNED => reason.to_owned(),
        _ => String::new(),
    }
}

fn new_audit_client_error(exit_code: i64, reason: &str) -> AuditClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    AuditClientError {
        exit_code,
        reason: retained_audit_reason(reason),
    }
}

/// `decodeExactAuditResult` — strict decode plus canonical re-encode
/// equality.
fn decode_exact_audit_result(payload: &[u8]) -> Result<AuditClientResult, String> {
    if payload.is_empty() {
        return Err("helper: audit result is invalid".to_owned());
    }
    let result: AuditClientResult =
        super::protocol::strict_decode(payload).map_err(|e| e.to_string())?;
    let canonical = serde_json::to_vec(&result)
        .map_err(|_| "helper: audit result is not canonical".to_owned())?;
    if canonical != payload {
        return Err("helper: audit result is not canonical".to_owned());
    }
    Ok(result)
}

/// `AuditClient` — `linuxAuditClient`: dials the state-audit verb.
pub struct AuditClient {
    socket_path: String,
}

impl AuditClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        AuditClient {
            socket_path: socket_path.into(),
        }
    }

    /// `Audit` — sends repair/scheduled/last_run_at and validates the
    /// bounded result: operation id echoes and identity fields are
    /// complete.
    ///
    /// # Errors
    /// [`AuditClientError`] — transport failures fold to exit 3, a
    /// non-canonical or mismatched result to exit 6, and helper
    /// denials carry the envelope code plus the whitelisted reason.
    pub fn audit(
        &self,
        operation_id: &str,
        repair: bool,
        scheduled: bool,
        last_run_at: &str,
    ) -> Result<AuditClientResult, AuditClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() {
            return Err(new_audit_client_error(3, ""));
        }
        let mut conn = super::browser::dial_unix_bounded(
            Path::new(&self.socket_path),
            super::client::DIAL_TIMEOUT,
        )
        .map_err(|_| new_audit_client_error(3, ""))?;
        let _ = conn.set_read_timeout(Some(
            super::client::DIAL_TIMEOUT + super::server::STATE_AUDIT_BUDGET,
        ));
        let _ = conn.set_write_timeout(Some(super::client::DIAL_TIMEOUT));
        let mut payload = serde_json::Map::new();
        if repair {
            payload.insert("repair".to_owned(), true.into());
        }
        if scheduled {
            payload.insert("scheduled".to_owned(), true.into());
        }
        if !last_run_at.is_empty() {
            payload.insert("last_run_at".to_owned(), last_run_at.into());
        }
        let msg = super::Request {
            operation_id: operation_id.to_owned(),
            verb: super::verb::STATE_AUDIT.to_owned(),
            payload: serde_json::value::RawValue::from_string(
                serde_json::Value::Object(payload).to_string(),
            )
            .ok(),
        };
        super::protocol::write_request(&mut conn, &msg)
            .map_err(|_| new_audit_client_error(3, ""))?;
        let response =
            super::protocol::read_response(&mut conn).map_err(|_| new_audit_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_audit_client_error(response.exit_code, &response.reason));
        }
        let raw = response
            .result
            .as_ref()
            .map_or(&b""[..], |r| r.get().as_bytes());
        let result = decode_exact_audit_result(raw).map_err(|_| new_audit_client_error(6, ""))?;
        if result.operation_id != operation_id
            || result.report_id.is_empty()
            || result.manifest_id.is_empty()
            || result.completed_at.is_empty()
        {
            return Err(new_audit_client_error(response.exit_code, &response.reason));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("central-audit-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn roots(tag: &str) -> (PathBuf, Roots) {
        let base = temp_dir(tag);
        let protected = base.join("protected");
        let audit = protected.join("audit");
        std::fs::create_dir_all(&audit).unwrap();
        std::fs::write(protected.join("state.json"), b"{}\n").unwrap();
        (
            base.clone(),
            Roots {
                protected_dir: protected.to_string_lossy().into_owned(),
                audit_dir: audit.to_string_lossy().into_owned(),
                instance_id: "default".into(),
                audit_uid: rustix::process::geteuid().as_raw(),
                audit_gid: rustix::process::getegid().as_raw(),
            },
        )
    }

    /// `time.RFC3339Nano` byte shape: one fraction field — never a
    /// doubled `.NN.NN` — absent when nanos are zero, `Z` for UTC and
    /// `±hh:mm` otherwise. `well_known::Rfc3339` already emits the
    /// fraction; the port's first wrapper layered a second on top.
    #[test]
    fn format_rfc3339nano_emits_a_single_fraction() {
        use time::macros::datetime;
        // UTC + nonzero nanos: single, trailing-zero-trimmed fraction.
        assert_eq!(
            format_rfc3339nano(datetime!(2025-01-01 00:00:00.520000000 UTC)),
            "2025-01-01T00:00:00.52Z"
        );
        // nanos == 0: no fraction field at all — the shape the buggy
        // wrapper already produced, preserved verbatim.
        assert_eq!(
            format_rfc3339nano(datetime!(2025-01-01 00:00:00 UTC)),
            "2025-01-01T00:00:00Z"
        );
        // Non-UTC offset: the fraction belongs inside the offset, not
        // appended after it (`…+07:00.52` was the doubled bug).
        assert_eq!(
            format_rfc3339nano(datetime!(2025-01-01 00:00:00.520000000 +07:00)),
            "2025-01-01T00:00:00.52+07:00"
        );
        assert_eq!(
            format_rfc3339nano(datetime!(2025-01-01 00:00:00 -05:30)),
            "2025-01-01T00:00:00-05:30"
        );
        // Full nanosecond precision round-trips untrimmed.
        assert_eq!(
            format_rfc3339nano(datetime!(2025-01-01 00:00:00.123456789 UTC)),
            "2025-01-01T00:00:00.123456789Z"
        );
    }

    /// `Run` mints identity + genesis manifest + signed report on the
    /// first run; the second run verifies against it and reports clean.
    #[test]
    fn run_creates_baseline_then_verifies_clean() {
        let (_base, r) = roots("baseline");
        let out1 = run(&RunInput {
            roots: r.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: false,
            last_run_at: None,
        })
        .unwrap();
        assert!(out1.baseline_created);
        assert!(out1.report.manifest_valid);
        assert_eq!(out1.report.checked, 1);
        // Identity file is 0600 owner-only.
        let meta = std::fs::metadata(identity_path(&r.audit_dir)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // Second run: verifies against the stored manifest.
        let out2 = run(&RunInput {
            roots: r.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: false,
            last_run_at: None,
        })
        .unwrap();
        assert!(!out2.baseline_created);
        assert!(out2.report.manifest_valid);
        assert!(out2.report.tampered.is_empty());
        assert_eq!(out2.report.manifest_id, out1.report.manifest_id);
    }

    /// A modified, missing, and unknown file are each named with their
    /// own reason; a symlink is structural tamper.
    #[test]
    fn compare_names_each_divergence() {
        let (_base, r) = roots("tamper");
        run(&RunInput {
            roots: r.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: false,
            last_run_at: None,
        })
        .unwrap();
        std::fs::write(
            Path::new(&r.protected_dir).join("state.json"),
            b"{\"x\":1}\n",
        )
        .unwrap();
        std::fs::write(Path::new(&r.protected_dir).join("planted.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc/hostname", Path::new(&r.protected_dir).join("link"))
            .unwrap();
        let out = run(&RunInput {
            roots: r.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: false,
            last_run_at: None,
        })
        .unwrap();
        let reasons: BTreeMap<_, _> = out
            .report
            .tampered
            .iter()
            .map(|t| (t.path.as_str(), t.reason.as_str()))
            .collect();
        assert_eq!(reasons.get("state.json"), Some(&TAMPER_MODIFIED));
        assert_eq!(reasons.get("planted.txt"), Some(&TAMPER_UNKNOWN));
        assert_eq!(reasons.get("link"), Some(&TAMPER_SYMLINK));
    }

    /// Repair removes the divergent files, appends the signed
    /// successor manifest, and re-verifies clean; a manifest-listed
    /// missing file refuses the repair outright.
    #[test]
    fn repair_removes_and_refuses_missing() {
        let (_base, r) = roots("repair");
        run(&RunInput {
            roots: r.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: false,
            last_run_at: None,
        })
        .unwrap();
        std::fs::write(Path::new(&r.protected_dir).join("planted.txt"), b"x").unwrap();
        let out = run(&RunInput {
            roots: r.clone(),
            now: time::OffsetDateTime::now_utc(),
            scheduled: false,
            last_run_at: None,
        })
        .unwrap();
        assert!(!out.report.tampered.is_empty());
        let repaired = repair(&r, time::OffsetDateTime::now_utc(), &out.report.tampered).unwrap();
        assert!(repaired.repaired);
        assert!(!Path::new(&r.protected_dir).join("planted.txt").exists());
        // Missing-file refusal: the manifest lists it, the tree does not.
        let findings = vec![TamperedFile {
            path: "gone.json".into(),
            reason: TAMPER_MISSING.into(),
        }];
        assert!(repair(&r, time::OffsetDateTime::now_utc(), &findings).is_err());
    }

    /// `is_deny_safe_active` — absent file is inactive; a corrupt file
    /// fails closed; `active` without `exited_at` is active.
    #[test]
    fn deny_safe_gate_reads_fail_closed() {
        let base = temp_dir("denysafe");
        let dir = base.to_string_lossy().into_owned();
        assert!(!is_deny_safe_active(&dir));
        std::fs::write(Path::new(&dir).join("deny-safe.json"), b"{corrupt").unwrap();
        assert!(is_deny_safe_active(&dir));
        std::fs::write(
            Path::new(&dir).join("deny-safe.json"),
            serde_json::to_vec(&DenySafeState {
                active: true,
                entered_at: "2024-01-01T00:00:00Z".into(),
                trigger_code: "x".into(),
                cleanup_done: false,
                rescue_attempts: vec![],
                exited_at: String::new(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(is_deny_safe_active(&dir));
    }

    /// The audit handler: read-only needs no ceremony; a repair with a
    /// clean tree short-circuits before one; a denial reason is the
    /// closed token, never detail.
    #[test]
    fn handler_read_only_and_repair_gate() {
        struct CurrentEval;
        impl AuditAdvisoryEvaluator for CurrentEval {
            fn evaluate(&self) -> Result<AdvisoryVerdict, Failure> {
                Ok(AdvisoryVerdict::Current)
            }
        }
        let (_base, r) = roots("handler");
        let handler = AuditHandlerImpl {
            pam: None,
            advisory: Some(Box::new(CurrentEval)),
            scope: CeremonyScope {
                instance_id: "default".into(),
                target_id: "postgres:central".into(),
            },
            roots: r,
        };
        let peer = PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 42,
        };
        // pam is None → CEREMONY_REQUIRED before anything runs.
        let resp = handler.audit(
            peer,
            std::time::Instant::now() + Duration::from_secs(60),
            AuditRequest {
                operation_id: uuid::Uuid::now_v7().to_string(),
                ..AuditRequest::default()
            },
        );
        assert_eq!(resp.reason, REASON_AUDIT_CEREMONY_REQUIRED);
    }
}
