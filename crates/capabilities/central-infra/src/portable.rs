//! Portable export/import domain — upstream `internal/portable/bundle.go`
//! and `internal/portable/import.go`. This module owns the vocabulary and
//! the pure policy: reason tokens, the `bx1` token shape and its signed
//! projection, the HKDF-SHA256 bundle-key derivation, manifest and
//! restore-plan types, and the evidence bodies. Archive framing, chunked
//! AES-256-GCM, and every filesystem touch live in
//! `central-adapter-linux::helper::portable`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Reason vocabulary — upstream `internal/portable/bundle.go` constants.
// ---------------------------------------------------------------------------

/// `ReasonExportSelfVerifyFailed`.
pub const REASON_EXPORT_SELF_VERIFY_FAILED: &str = "EXPORT_VERIFY_SELF_FAILED";
/// `ReasonExportNoBackup`.
pub const REASON_EXPORT_NO_BACKUP: &str = "BACKUP_NO_ADMISSIBLE_BACKUP";
/// `ReasonExportBackupAmbiguous`.
pub const REASON_EXPORT_BACKUP_AMBIGUOUS: &str = "BACKUP_CANDIDATE_AMBIGUOUS";
/// `ReasonExportBackupUnsealed`.
pub const REASON_EXPORT_BACKUP_UNSEALED: &str = "EXPORT_BACKUP_UNSEALED";
/// `ReasonExportOutInvalid`.
pub const REASON_EXPORT_OUT_INVALID: &str = "EXPORT_OUT_INVALID";
/// `ReasonExportIdentityFailed`.
pub const REASON_EXPORT_IDENTITY_FAILED: &str = "EXPORT_IDENTITY_FAILED";
/// `ReasonExportCeremonyRequired`.
pub const REASON_EXPORT_CEREMONY_REQUIRED: &str = "EXPORT_CEREMONY_REQUIRED";
/// `ReasonExportAuthorityDenied`.
pub const REASON_EXPORT_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
/// `ReasonExportUnavailable`.
pub const REASON_EXPORT_UNAVAILABLE: &str = "EXPORT_UNAVAILABLE";
/// `ReasonExportInvalidRequest`.
pub const REASON_EXPORT_INVALID_REQUEST: &str = "INVALID_EXPORT_REQUEST";
/// `ReasonImportTokenInvalid`.
pub const REASON_IMPORT_TOKEN_INVALID: &str = "IMPORT_TOKEN_INVALID";
/// `ReasonImportBundleMismatch`.
pub const REASON_IMPORT_BUNDLE_MISMATCH: &str = "IMPORT_BUNDLE_MISMATCH";
/// `ReasonImportTargetInit`.
pub const REASON_IMPORT_TARGET_INIT: &str = "IMPORT_TARGET_INITIALIZED";
/// `ReasonImportConfirmFailed`.
pub const REASON_IMPORT_CONFIRM_FAILED: &str = "IMPORT_CONFIRM_FAILED";
/// `ReasonImportAuthorityDenied`.
pub const REASON_IMPORT_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
/// `ReasonImportCeremonyRequired`.
pub const REASON_IMPORT_CEREMONY_REQUIRED: &str = "IMPORT_CEREMONY_REQUIRED";
/// `ReasonImportUnavailable`.
pub const REASON_IMPORT_UNAVAILABLE: &str = "IMPORT_UNAVAILABLE";
/// `ReasonImportInvalidRequest`.
pub const REASON_IMPORT_INVALID_REQUEST: &str = "INVALID_IMPORT_REQUEST";

/// `ExportPurpose` — the fixed v1 purpose tag. Later purposes are new
/// values, never flag-invented strings.
pub const EXPORT_PURPOSE: &str = "full-instance-export";
/// `TokenExpiryDefault` — 30 days in hours (86400s * 30).
pub const TOKEN_EXPIRY_SECONDS: i64 = 30 * 24 * 60 * 60;
/// `ChunkSize` — one authenticated-encryption segment's plaintext bound;
/// bundles stream and never load fully into memory.
pub const CHUNK_SIZE: usize = 1 << 20;
/// The HKDF `info` tag binding the DEK to the bx1 format version.
pub const DEK_INFO: &[u8] = b"bx1-dek/v1";
/// The chunked stream's magic header bytes.
pub const CHUNKED_MAGIC: &[u8; 8] = b"BX1GCM01";
/// The import work-area plan file the restore engine consumes.
pub const RESTORE_PLAN_FILE_NAME: &str = "restore-plan.json";
/// The fresh-target marker staged protected-state bootstrap writes.
pub const IMPORT_MARKER_FILE_NAME: &str = "import.json";

// ---------------------------------------------------------------------------
// HKDF-SHA256 — `hkdfSHA256` + `DeriveBundleKey`.
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

/// `hkdfSHA256` — RFC 5869 extract-then-expand; `okm_len` bounds output.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Option<Vec<u8>> {
    if okm_len == 0 || okm_len > 255 * 32 {
        return None;
    }
    let zero_salt;
    let salt = if salt.is_empty() {
        zero_salt = [0u8; 32];
        &zero_salt[..]
    } else {
        salt
    };
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(salt).ok()?;
    mac.update(ikm);
    // PRK, the chaining block, and the over-long OKM tail are all key
    // material — scrub them on drop (Go parity plus hardening).
    let prk = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let mut okm = Zeroizing::new(Vec::with_capacity(okm_len));
    let mut prev: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut i: u8 = 1;
    while okm.len() < okm_len {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&prk).ok()?;
        mac.update(&prev[..]);
        mac.update(info);
        mac.update(&[i]);
        prev = Zeroizing::new(mac.finalize().into_bytes().to_vec());
        okm.extend_from_slice(&prev);
        if i == 255 {
            break;
        }
        i = i.wrapping_add(1);
    }
    Some(okm[..okm_len].to_vec())
}

/// `DeriveBundleKey` — DEK = HKDF-SHA256(salt="", ikm=N, info="bx1-dek/v1", 32).
/// Possession of the token (which carries N) equals decryption capability.
pub fn derive_bundle_key(nonce: &[u8]) -> Option<[u8; 32]> {
    if nonce.len() != 32 {
        return None;
    }
    let okm = Zeroizing::new(hkdf_sha256(&[], nonce, DEK_INFO, 32)?);
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Some(key)
}

// ---------------------------------------------------------------------------
// Manifest + archive vocabulary.
// ---------------------------------------------------------------------------

/// `ManifestFile` — one staged file inside the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Archive-relative slash path.
    pub path: String,
    /// Byte length.
    pub size: i64,
    /// Lowercase hex SHA-256 of the contents.
    pub sha256: String,
}

/// `ExportManifest` — the bundle's first tar entry (`manifest.json`),
/// covered by the token's bundle SHA-256.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportManifest {
    /// Freshly minted per export.
    pub bundle_id: String,
    /// Source instance id.
    pub instance_id: String,
    /// RFC 3339 issue timestamp.
    pub created_at: String,
    /// Always [`EXPORT_PURPOSE`].
    pub purpose: String,
    /// Staged file inventory (excluding `manifest.json`).
    pub files: Vec<ManifestFile>,
    /// `backup/bodies/*` count from the staged tree.
    pub body_count: i64,
}

// ---------------------------------------------------------------------------
// bx1 token — `Bx1Token`, `IssueBx1Token`, `VerifyBx1Token`.
// ---------------------------------------------------------------------------

/// `Bx1Token` — the independent integrity token carried beside the
/// bundle. The nonce is the bundle-DEK preimage; the public key pins the
/// instance export identity out of band (import takes `--trust-key`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bx1Token {
    /// Minted per export.
    pub token_id: String,
    /// Lowercase hex SHA-256 of the encrypted bundle.
    pub bundle_sha256: String,
    /// RFC 3339(nano) issue timestamp.
    pub issued_at: String,
    /// RFC 3339(nano) expiry timestamp.
    pub expires_at: String,
    /// Source instance id.
    pub instance_id: String,
    /// Always [`EXPORT_PURPOSE`].
    pub purpose: String,
    /// Base64-raw-URL-encoded 32-byte DEK preimage.
    pub nonce_b64: String,
    /// Lowercase hex Ed25519 verifying key.
    pub public_key_hex: String,
    /// Lowercase hex Ed25519 signature over the JCS-canonical unsigned
    /// projection (`omitempty` upstream).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_hex: String,
}

/// `bx1Unsigned` — the signed projection: every field but the signature.
#[derive(Serialize)]
struct Bx1Unsigned<'a> {
    token_id: &'a str,
    bundle_sha256: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
    instance_id: &'a str,
    purpose: &'a str,
    nonce_b64: &'a str,
    public_key_hex: &'a str,
}

impl Bx1Token {
    fn unsigned(&self) -> Bx1Unsigned<'_> {
        Bx1Unsigned {
            token_id: &self.token_id,
            bundle_sha256: &self.bundle_sha256,
            issued_at: &self.issued_at,
            expires_at: &self.expires_at,
            instance_id: &self.instance_id,
            purpose: &self.purpose,
            nonce_b64: &self.nonce_b64,
            public_key_hex: &self.public_key_hex,
        }
    }

    /// `json.Marshal(token.unsigned())` → `jcs.Transform`.
    fn unsigned_canonical(&self) -> Option<Vec<u8>> {
        let marshaled = serde_json::to_vec(&self.unsigned()).ok()?;
        let value: serde_json::Value = serde_json::from_slice(&marshaled).ok()?;
        central_foundation::jcs::canonicalize(&value).ok()
    }
}

/// The domain-level token failures — the three upstream sentinels map
/// onto `IMPORT_TOKEN_INVALID` / `IMPORT_BUNDLE_MISMATCH` at the handler
/// boundary (upstream: `ErrBundleMismatch`→mismatch, else→invalid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// `ErrTokenInvalid` — structure, trust pin, signature, nonce, or
    /// digest field failure.
    Invalid(&'static str),
    /// `ErrTokenExpired` — `now` is at or past `expires_at`.
    Expired,
    /// `ErrBundleMismatch` — the bundle digest does not match the token.
    BundleMismatch,
}

/// `IssueBx1Token` — signs a token over the bundle digest. `ttl` bounds
/// the token's life; the signature covers the JCS-canonical unsigned
/// bytes. `seed` is the 32-byte Ed25519 seed.
#[allow(clippy::too_many_arguments)]
pub fn issue_bx1_token(
    seed: &[u8; 32],
    token_id: &str,
    bundle_sha256: &str,
    instance_id: &str,
    purpose: &str,
    now: OffsetDateTime,
    ttl_seconds: i64,
    nonce: &[u8],
) -> Option<Bx1Token> {
    if nonce.len() != 32 {
        return None;
    }
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key();
    let mut token = Bx1Token {
        token_id: token_id.to_owned(),
        bundle_sha256: bundle_sha256.to_owned(),
        issued_at: format_rfc3339_nano(now),
        expires_at: format_rfc3339_nano(now + time::Duration::seconds(ttl_seconds)),
        instance_id: instance_id.to_owned(),
        purpose: purpose.to_owned(),
        nonce_b64: b64_url_raw_encode(nonce),
        public_key_hex: hex_encode(&public.to_bytes()),
        signature_hex: String::new(),
    };
    let canonical = token.unsigned_canonical()?;
    let signature: Signature = signing.sign(&canonical);
    token.signature_hex = hex_encode(&signature.to_bytes());
    Some(token)
}

/// `VerifyBx1Token` — structure, trust-key pin, expiry, signature, then
/// bundle-digest binding, in that order. `now` is injected for tests.
pub fn verify_bx1_token(
    token: &Bx1Token,
    trust_key_hex: &str,
    bundle_sha256: &str,
    now: OffsetDateTime,
) -> Result<(), TokenError> {
    if token.signature_hex.is_empty()
        || token.nonce_b64.is_empty()
        || token.bundle_sha256.is_empty()
        || token.public_key_hex.is_empty()
        || token.token_id.is_empty()
    {
        return Err(TokenError::Invalid("missing field"));
    }
    if !token.public_key_hex.eq_ignore_ascii_case(trust_key_hex) {
        return Err(TokenError::Invalid("trust key mismatch"));
    }
    let public = hex_decode(&token.public_key_hex).ok_or(TokenError::Invalid("public key"))?;
    if public.len() != 32 {
        return Err(TokenError::Invalid("public key"));
    }
    let signature = hex_decode(&token.signature_hex).ok_or(TokenError::Invalid("signature"))?;
    if signature.len() != 64 {
        return Err(TokenError::Invalid("signature"));
    }
    let expires = parse_rfc3339(&token.expires_at).ok_or(TokenError::Invalid("expiry"))?;
    if now >= expires {
        return Err(TokenError::Expired);
    }
    let canonical = token
        .unsigned_canonical()
        .ok_or(TokenError::Invalid("canonical"))?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&public);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature);
    let verifying = VerifyingKey::from_bytes(&pk).map_err(|_| TokenError::Invalid("public key"))?;
    let signature = Signature::from_bytes(&sig);
    verifying
        .verify(&canonical, &signature)
        .map_err(|_| TokenError::Invalid("signature mismatch"))?;
    if !token.bundle_sha256.eq_ignore_ascii_case(bundle_sha256) {
        return Err(TokenError::BundleMismatch);
    }
    if b64_url_raw_decode(&token.nonce_b64).is_none() {
        return Err(TokenError::Invalid("nonce"));
    }
    Ok(())
}

/// `time.RFC3339Nano` — RFC 3339 with sub-second precision only when the
/// time carries it (Go trims a zero fraction; `time`'s `Rfc3339` always
/// emits one, so zero-fraction times are rewritten without the fraction).
pub fn format_rfc3339_nano(t: OffsetDateTime) -> String {
    let formatted = t.format(&Rfc3339).unwrap_or_default();
    if t.nanosecond() == 0 {
        if let Some(stripped) = formatted.strip_suffix(".000000000Z") {
            return format!("{stripped}Z");
        }
        if let Some(stripped) = formatted.strip_suffix(".000000000+00:00") {
            return format!("{stripped}+00:00");
        }
    }
    formatted
}

/// `time.Parse(time.RFC3339Nano, s)` — accepts fractional or whole-second
/// RFC 3339 strings.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

// ---------------------------------------------------------------------------
// Restore plan + evidence — `RestorePlan`, `ExportEvidence`,
// `ImportEvidence`.
// ---------------------------------------------------------------------------

/// `RestorePlan` — `restore-plan.json`, staged in the persistent import
/// work area; the restore engine consumes it verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePlan {
    /// The imported bundle's id.
    pub bundle_id: String,
    /// The source instance id (upstream field name is `instance_id`).
    pub instance_id: String,
    /// Always empty upstream — serialized as `""`.
    pub token_id: String,
    /// `db/backup/<rel>` path of the staged dump, empty when none.
    pub dump_path: String,
    /// Lowercase hex SHA-256 of the staged dump.
    pub dump_sha256: String,
    /// Staged dump byte length.
    pub dump_bytes: i64,
    /// Body inventory (non-dump `backup/` files).
    pub bodies: Vec<ManifestFile>,
    /// Manifest's declared body count.
    pub expected_body_count: i64,
    /// RFC 3339 staging timestamp.
    pub staged_at: String,
}

/// `ExportEvidence` — the `slice-d-export.json` artifact body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEvidence {
    /// Ceremony-bound operation.
    pub operation_id: String,
    /// Exported bundle id.
    pub bundle_id: String,
    /// Source sealed backup id.
    pub backup_id: String,
    /// Source instance id.
    pub instance_id: String,
    /// Lowercase hex SHA-256 of the encrypted bundle.
    pub bundle_sha256: String,
    /// Issued `bx1` token id.
    pub token_id: String,
    /// True when the export identity was minted by this operation.
    pub identity_created: bool,
    /// Lowercase hex Ed25519 export verifying key.
    pub public_key_hex: String,
    /// Staged body count.
    pub body_count: i64,
    /// Encrypted bundle byte length.
    pub bundle_bytes: i64,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// `ImportEvidence` — the `slice-d-import.json` artifact body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportEvidence {
    /// Ceremony-bound operation.
    pub operation_id: String,
    /// Imported bundle id.
    pub bundle_id: String,
    /// Source sealed backup id (empty — the bundle does not carry it).
    pub backup_id: String,
    /// The instance that produced the bundle.
    pub source_instance_id: String,
    /// The fresh target instance id.
    pub target_instance_id: String,
    /// The spent `bx1` token id.
    pub token_id: String,
    /// Lowercase hex SHA-256 of the encrypted bundle.
    pub bundle_sha256: String,
    /// Staged body count.
    pub body_count: i64,
    /// Lowercase hex SHA-256 of the staged dump (empty when no dump).
    pub staged_dump_sha256: String,
    /// Lowercase hex SHA-256 of `restore-plan.json`.
    pub restore_plan_sha256: String,
    /// True only after a valid engine receipt.
    pub data_plane_restored: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

// ---------------------------------------------------------------------------
// Encoders — local hex + base64-raw-URL (no `hex`/`base64` crates in the
// workspace; upstream uses std `encoding/hex` + `base64.RawURLEncoding`).
// ---------------------------------------------------------------------------

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// `hex.EncodeToString`.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

/// `hex.DecodeString` — accepts upper and lower case like Go.
#[must_use]
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `base64.RawURLEncoding.EncodeToString`.
#[must_use]
pub fn b64_url_raw_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64_URL[(n >> 18) as usize & 63] as char);
        out.push(B64_URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64_URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_URL[n as usize & 63] as char);
        }
    }
    out
}

/// `base64.RawURLEncoding.DecodeString` — strict no-padding decode.
#[must_use]
pub fn b64_url_raw_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => u64::from(c - b'A'),
            b'a'..=b'z' => u64::from(c - b'a' + 26),
            b'0'..=b'9' => u64::from(c - b'0' + 52),
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    // Residual bits must be zero and a valid 6-bit remainder (Go rejects
    // a dangling single sextet and non-zero trailing bits).
    if nbits >= 6 || (nbits > 0 && (bits & ((1 << nbits) - 1)) != 0) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    /// RFC 5869 test case 1 — the upstream `bundle_test.go` vector.
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0b_u8; 22];
        let salt = hex_decode("000102030405060708090a0b0c").unwrap_or_default();
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9").unwrap_or_default();
        let okm = hkdf_sha256(&salt, &ikm, &info, 42).unwrap_or_default();
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_empty_salt_zeroes() {
        // RFC 5869: empty salt means HashLen zero octets — the same as an
        // explicit 32-byte zero salt.
        let a = hkdf_sha256(&[], b"ikm", b"info", 32).unwrap_or_default();
        let b = hkdf_sha256(&[0u8; 32], b"ikm", b"info", 32).unwrap_or_default();
        assert_eq!(a, b);
        assert!(hkdf_sha256(&[], b"ikm", b"info", 0).is_none());
        assert!(hkdf_sha256(&[], b"ikm", b"info", 255 * 32 + 1).is_none());
    }

    #[test]
    fn derive_bundle_key_bounds() {
        assert!(derive_bundle_key(&[0u8; 31]).is_none());
        assert!(derive_bundle_key(&[0u8; 33]).is_none());
        let key = derive_bundle_key(&[0x42; 32]).unwrap_or_default();
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32]);
    }

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn issued() -> Bx1Token {
        let nonce = [9u8; 32];
        issue_bx1_token(
            &seed(),
            "tok-1",
            &hex_encode(&[0xaa; 32]),
            "inst-1",
            EXPORT_PURPOSE,
            datetime!(2025-01-02 03:04:05 UTC),
            TOKEN_EXPIRY_SECONDS,
            &nonce,
        )
        .unwrap_or_default()
    }

    #[test]
    fn token_issue_verify_round_trip() {
        let token = issued();
        let bundle_sha = hex_encode(&[0xaa; 32]);
        let trust = token.public_key_hex.clone();
        verify_bx1_token(
            &token,
            &trust,
            &bundle_sha,
            datetime!(2025-01-03 00:00:00 UTC),
        )
        .expect("verify");
    }

    #[test]
    fn token_verify_rejects_in_upstream_order() {
        let bundle_sha = hex_encode(&[0xaa; 32]);
        let token = issued();
        let trust = token.public_key_hex.clone();
        let now = datetime!(2025-01-03 00:00:00 UTC);
        // Trust key mismatch → Invalid before signature is even checked.
        let mut bad = token.clone();
        assert_eq!(
            verify_bx1_token(&bad, &hex_encode(&[0x11; 32]), &bundle_sha, now),
            Err(TokenError::Invalid("trust key mismatch"))
        );
        // Expired → Expired (after pin/signature structural checks).
        assert_eq!(
            verify_bx1_token(
                &token,
                &trust,
                &bundle_sha,
                datetime!(2025-02-02 03:04:05 UTC)
            ),
            Err(TokenError::Expired)
        );
        // Tampered unsigned field → signature mismatch.
        bad = token.clone();
        bad.instance_id = "other".to_owned();
        assert_eq!(
            verify_bx1_token(&bad, &trust, &bundle_sha, now),
            Err(TokenError::Invalid("signature mismatch"))
        );
        // Forged signature over a re-signed (different key) projection →
        // still a signature mismatch under the pinned key.
        bad = token.clone();
        let other = SigningKey::from_bytes(&[8u8; 32]);
        bad.signature_hex = hex_encode(
            &other
                .sign(&bad.unsigned_canonical().unwrap_or_default())
                .to_bytes(),
        );
        assert_eq!(
            verify_bx1_token(&bad, &trust, &bundle_sha, now),
            Err(TokenError::Invalid("signature mismatch"))
        );
        // Bundle digest mismatch → BundleMismatch.
        assert_eq!(
            verify_bx1_token(&token, &trust, &hex_encode(&[0xbb; 32]), now),
            Err(TokenError::BundleMismatch)
        );
        // Missing field → Invalid.
        bad = token.clone();
        bad.nonce_b64 = String::new();
        assert_eq!(
            verify_bx1_token(&bad, &trust, &bundle_sha, now),
            Err(TokenError::Invalid("missing field"))
        );
        // Malformed nonce → Invalid after digest check.
        bad = token.clone();
        bad.nonce_b64 = "%%%".to_owned();
        bad.signature_hex = hex_encode(
            &SigningKey::from_bytes(&seed())
                .sign(&bad.unsigned_canonical().unwrap_or_default())
                .to_bytes(),
        );
        assert_eq!(
            verify_bx1_token(&bad, &trust, &bundle_sha, now),
            Err(TokenError::Invalid("nonce"))
        );
    }

    #[test]
    fn hex_and_b64_round_trip() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_decode("DEADbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
        let raw = b"hello, bx1";
        assert_eq!(
            b64_url_raw_decode(&b64_url_raw_encode(raw)).as_deref(),
            Some(&raw[..])
        );
        // RawURLEncoding: no padding; `-`/`_` alphabet only.
        let enc = b64_url_raw_encode(&[0xfb, 0xff, 0xfe]);
        assert_eq!(enc, "-__-");
        assert_eq!(b64_url_raw_decode(&enc), Some(vec![0xfb, 0xff, 0xfe]));
        assert_eq!(b64_url_raw_decode("abcd="), None);
        assert_eq!(b64_url_raw_decode("a"), None);
    }

    #[test]
    fn rfc3339_nano_trims_zero_fraction() {
        assert_eq!(
            format_rfc3339_nano(datetime!(2025-01-02 03:04:05 UTC)),
            "2025-01-02T03:04:05Z"
        );
        let t =
            parse_rfc3339("2025-01-02T03:04:05.123456789Z").unwrap_or_else(OffsetDateTime::now_utc);
        assert_eq!(format_rfc3339_nano(t), "2025-01-02T03:04:05.123456789Z");
        assert!(parse_rfc3339("not a time").is_none());
    }
}
