//! `internal/portable/bundle.go`'s token half — the BX1 integrity
//! token, its Ed25519/JCS issue+verify ladder, the HKDF-SHA256 bundle
//! key derivation, the instance `export-identity.json`, and the
//! protected-subset trust-material scan.
//!
//! Custody invariants (unchanged from upstream):
//!
//! - The token is the *independent* integrity record beside the
//!   bundle: `nonce_b64` is the bundle-DEK preimage (possession of the
//!   token equals decryption capability — documented operator
//!   knowledge), `public_key_hex` pins the instance export identity
//!   out of band (import takes `--trust-key` and compares).
//! - The signature is Ed25519 over the JCS-canonical **unsigned**
//!   record — never the transport JSON.
//! - `export-identity.json` is the only private material this file
//!   touches: it lives `0600` under the instance state root, is minted
//!   once via `O_EXCL` (a racing first export loads the winner), and a
//!   present-but-corrupt file refuses rather than re-minting — a
//!   silent re-mint would orphan every token the old key signed.
//! - [`scan_protected_subset`] is the deny-list guard that runs after
//!   staging and before archiving: trust-material file *names* and
//!   secret-marker *content* both abort the export.
//! - The bundle encryption stream and tar layer stay in the portable
//!   bundle slice — this module carries only the token, identity, key
//!   derivation, and scan guard (upstream's secrets-adjacent surface).

use std::path::Path;

use central_foundation::failure::Failure;
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::durable;
use super::signing::{sign_canonical_json, verify_canonical_json_hex};
use super::wire;

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_export_token", msg)
}

/// `ErrTokenInvalid` — upstream's sentinel; carried as the `Failure`
/// code so `errors.Is`-equivalent checks (`e.code() ==`) discriminate.
pub const ERR_TOKEN_INVALID: &str = "portable: token invalid";
/// `ErrTokenExpired`.
pub const ERR_TOKEN_EXPIRED: &str = "portable: token expired";
/// `ErrBundleMismatch`.
pub const ERR_BUNDLE_MISMATCH: &str = "portable: bundle does not match token";

/// `ExportPurpose` — the fixed v1 purpose tag.
pub const EXPORT_PURPOSE: &str = "full-instance-export";
/// `TokenExpiryDefault` — how long a token stays spendable.
pub const TOKEN_EXPIRY_DEFAULT: time::Duration = time::Duration::days(30);

/// `Bx1Token` — the independent integrity token, carried beside the
/// bundle. Upstream's field names exactly; `signature_hex` omits when
/// empty (`omitempty`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bx1Token {
    /// Token identity.
    pub token_id: String,
    /// The bundle's SHA-256 (lowercase hex).
    pub bundle_sha256: String,
    /// RFC3339Nano issue time (upstream stores the formatted string).
    pub issued_at: String,
    /// RFC3339Nano expiry.
    pub expires_at: String,
    /// Instance identity.
    pub instance_id: String,
    /// Fixed purpose tag (`full-instance-export`).
    pub purpose: String,
    /// Raw-URL-safe-base64 bundle-DEK preimage (32 bytes decoded).
    pub nonce_b64: String,
    /// Hex Ed25519 public key of the export identity.
    pub public_key_hex: String,
    /// Hex Ed25519 signature over the canonical unsigned record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_hex: String,
}

/// `bx1Unsigned` — the signed projection: every field but the
/// signature, in upstream's field order and names.
fn unsigned_token(t: &Bx1Token) -> serde_json::Value {
    serde_json::json!({
        "token_id": t.token_id,
        "bundle_sha256": t.bundle_sha256,
        "issued_at": t.issued_at,
        "expires_at": t.expires_at,
        "instance_id": t.instance_id,
        "purpose": t.purpose,
        "nonce_b64": t.nonce_b64,
        "public_key_hex": t.public_key_hex,
    })
}

/// `IssueBx1Token` — sign a token over the bundle digest. `now` and
/// `ttl` bound the token's life; the signature covers the
/// JCS-canonical unsigned bytes. The signing key stays inside the
/// caller's custody — this signs with a borrow, never stores it.
///
/// # Errors
/// `broker_export_token` invalid when the nonce is not 32 bytes.
#[allow(clippy::too_many_arguments)] // upstream IssueBx1Token's 8-arg signature
pub fn issue_bx1_token(
    signing_key: &ed25519_dalek::SigningKey,
    token_id: &str,
    bundle_sha256: &str,
    instance_id: &str,
    purpose: &str,
    now: OffsetDateTime,
    ttl: time::Duration,
    nonce: &[u8],
) -> Result<Bx1Token, Failure> {
    // The `ed25519.PrivateKeySize == 64` check upstream performs is
    // type-level here: `SigningKey` is always a valid key.
    if nonce.len() != 32 {
        return Err(Failure::invalid(
            "broker_export_token",
            format!("portable: nonce must be 32 bytes, got {}", nonce.len()),
        ));
    }
    let mut token = Bx1Token {
        token_id: token_id.to_owned(),
        bundle_sha256: bundle_sha256.to_owned(),
        issued_at: wire::format_rfc3339_nano(now.to_offset(time::UtcOffset::UTC)),
        expires_at: wire::format_rfc3339_nano((now + ttl).to_offset(time::UtcOffset::UTC)),
        instance_id: instance_id.to_owned(),
        purpose: purpose.to_owned(),
        nonce_b64: wire::b64_url_raw_encode(nonce),
        public_key_hex: wire::hex_encode(signing_key.verifying_key().as_bytes()),
        signature_hex: String::new(),
    };
    token.signature_hex = sign_canonical_json(signing_key, &unsigned_token(&token))?;
    Ok(token)
}

/// `VerifyBx1Token` — structure, trust-key pin, expiry, signature,
/// bundle-digest binding, nonce decode — in upstream's exact order.
/// `errors.Is` surfaces map to `Failure` codes [`ERR_TOKEN_INVALID`],
/// [`ERR_TOKEN_EXPIRED`], [`ERR_BUNDLE_MISMATCH`].
///
/// # Errors
/// Token-invalid failures carry `ERR_TOKEN_INVALID`; expiry
/// `ERR_TOKEN_EXPIRED`; bundle mismatch `ERR_BUNDLE_MISMATCH`.
pub fn verify_bx1_token(
    token: &Bx1Token,
    trust_key_hex: &str,
    bundle_sha256: &str,
    now: OffsetDateTime,
) -> Result<(), Failure> {
    let invalid =
        |detail: &str| Failure::denied(ERR_TOKEN_INVALID, format!("{ERR_TOKEN_INVALID}: {detail}"));
    if token.signature_hex.is_empty()
        || token.nonce_b64.is_empty()
        || token.bundle_sha256.is_empty()
        || token.public_key_hex.is_empty()
        || token.token_id.is_empty()
    {
        return Err(invalid("missing field"));
    }
    if !token.public_key_hex.eq_ignore_ascii_case(trust_key_hex) {
        return Err(invalid("trust key mismatch"));
    }
    let public_raw = wire::hex_decode(&token.public_key_hex)
        .filter(|p| p.len() == ed25519_dalek::PUBLIC_KEY_LENGTH)
        .ok_or_else(|| invalid("public key"))?;
    drop(public_raw); // length+encoding verified; the verify below re-derives it.
    let signature_raw = wire::hex_decode(&token.signature_hex)
        .filter(|s| s.len() == ed25519_dalek::Signature::BYTE_SIZE)
        .ok_or_else(|| invalid("signature"))?;
    drop(signature_raw);
    let expires = time::OffsetDateTime::parse(
        &token.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| invalid("expiry"))?;
    if now >= expires {
        return Err(Failure::denied(ERR_TOKEN_EXPIRED, ERR_TOKEN_EXPIRED));
    }
    verify_canonical_json_hex(
        &token.public_key_hex,
        &token.signature_hex,
        &unsigned_token(token),
    )
    .map_err(|_| invalid("signature mismatch"))?;
    if !token.bundle_sha256.eq_ignore_ascii_case(bundle_sha256) {
        return Err(Failure::denied(ERR_BUNDLE_MISMATCH, ERR_BUNDLE_MISMATCH));
    }
    if wire::b64_url_raw_decode(&token.nonce_b64).is_none() {
        return Err(invalid("nonce"));
    }
    Ok(())
}

/// `hkdfSHA256` — RFC 5869 extract-then-expand, upstream's vendored
/// re-implementation. `okm_len` must be in `1..=255*32`.
fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    if okm_len == 0 || okm_len > 255 * 32 {
        return Err(Failure::invalid(
            "broker_export_token",
            format!("portable: hkdf length {okm_len} out of range"),
        ));
    }
    let zero_salt = [0u8; 32];
    let salt = salt.filter(|s| !s.is_empty()).unwrap_or(&zero_salt);
    let mut mac = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(salt)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA-256 accepts any key length"));
    mac.update(ikm);
    let prk = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let mut okm = Zeroizing::new(Vec::new());
    let mut prev = Zeroizing::new(Vec::<u8>::new());
    let mut i = 1u8;
    while okm.len() < okm_len {
        let mut mac = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&prk[..])
            .unwrap_or_else(|_| unreachable!("HMAC-SHA-256 accepts any key length"));
        mac.update(&prev[..]);
        mac.update(info);
        mac.update(&[i]);
        *prev = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&prev[..]);
        if i == 255 {
            break;
        }
        i += 1;
    }
    okm.truncate(okm_len);
    Ok(okm)
}

/// `DeriveBundleKey` — the bundle data-encryption key from the token
/// nonce: `DEK = HKDF-SHA256(salt="", ikm=N, info="bx1-dek/v1", 32)`.
/// Possession of the token (which carries `N`) equals decryption
/// capability — documented operator knowledge, not a hidden property.
///
/// # Errors
/// `broker_export_token` invalid unless `nonce` is exactly 32 bytes.
pub fn derive_bundle_key(nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
    if nonce.len() != 32 {
        return Err(Failure::invalid(
            "broker_export_token",
            format!("portable: nonce must be 32 bytes, got {}", nonce.len()),
        ));
    }
    hkdf_sha256(None, nonce, b"bx1-dek/v1", 32)
}

// ---------------------------------------------------------------------------
// ExportIdentity — the instance's persistent export keypair
// ---------------------------------------------------------------------------

/// `ExportIdentity` — minted once on first export, lives `0600` under
/// the state root. Wiping the instance destroys it, which is correct:
/// a new instance is a new export identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportIdentity {
    /// Hex Ed25519 seed — the only private material this file persists.
    pub private_seed_hex: String,
    /// Hex Ed25519 public key.
    pub public_key_hex: String,
    /// RFC3339Nano creation time.
    pub created_at: String,
}

/// `LoadOrMintExportIdentity` — load the identity or create it exactly
/// once (`O_EXCL`: concurrent first exports race, one wins, the other
/// loads what won). A present-but-malformed file refuses rather than
/// re-minting. Returns `(identity, created)`.
///
/// # Errors
/// `broker_export_token` on IO failure or a corrupt persisted identity
/// (bad seed length, public key not matching the seed).
pub fn load_or_mint_export_identity(
    path: &Path,
    uid: u32,
    gid: u32,
    now: OffsetDateTime,
) -> Result<(ExportIdentity, bool), Failure> {
    match durable::read_file(path) {
        Ok(raw) => {
            let identity: ExportIdentity = serde_json::from_slice(&raw)
                .map_err(|e| internal(format!("portable: export identity corrupt: {e}")))?;
            let seed = wire::hex_decode(&identity.private_seed_hex)
                .filter(|s| s.len() == 32)
                .ok_or_else(|| internal("portable: export identity corrupt"))?;
            let seed_arr: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| internal("portable: export identity corrupt"))?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
            let derived_pub = wire::hex_encode(key.verifying_key().as_bytes());
            if derived_pub != identity.public_key_hex.to_lowercase() {
                return Err(internal("portable: export identity corrupt"));
            }
            Ok((identity, false))
        }
        Err(rustix::io::Errno::NOENT) => {
            let mut seed = Zeroizing::new([0u8; 32]);
            rustix::rand::getrandom(&mut seed[..], rustix::rand::GetRandomFlags::empty())
                .map_err(|e| internal(format!("portable: identity key gen: {e}")))?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let identity = ExportIdentity {
                private_seed_hex: wire::hex_encode(&seed[..]),
                public_key_hex: wire::hex_encode(key.verifying_key().as_bytes()),
                created_at: wire::format_rfc3339_nano(now.to_offset(time::UtcOffset::UTC)),
            };
            let mut encoded = serde_json::to_vec(&identity)
                .map_err(|e| internal(format!("portable: marshal identity: {e}")))?;
            encoded.push(b'\n');
            use std::io::Write as _;
            let mut file = match durable::open_exclusive(path, 0o600) {
                Ok(f) => f,
                // A racing creator won — adopt the established identity
                // (upstream's `IsExist` → recursive reload).
                Err(rustix::io::Errno::EXIST) => {
                    return load_or_mint_export_identity(path, uid, gid, now);
                }
                Err(e) => {
                    return Err(internal(format!("portable: write identity: {e}")));
                }
            };
            file.write_all(&encoded)
                .and_then(|()| file.sync_all())
                .map_err(|e| internal(format!("portable: write identity: {e}")))?;
            // `os.Chmod(0600)` then `os.Chown(uid, gid)` — ownership
            // follows the state root (instance UID); failures fail the
            // export rather than leaving a root-owned key in instance
            // space. `fchmod` on the open fd: path `fchmodat` is not on
            // the broker's seccomp allow-list (ADR 0044).
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
                .map_err(|e| internal(format!("portable: secure identity: {e}")))?;
            drop(file);
            rustix::fs::chown(
                path,
                Some(rustix::process::Uid::from_raw(uid)),
                Some(rustix::process::Gid::from_raw(gid)),
            )
            .map_err(|e| internal(format!("portable: chown identity: {e}")))?;
            Ok((identity, true))
        }
        Err(e) => Err(internal(format!("portable: read identity: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// ScanProtectedSubset — the staged-copy trust-material guard
// ---------------------------------------------------------------------------

/// Upstream `deniedNames` — refused file-name substrings (lowercased
/// basename match).
const DENIED_NAMES: &[&str] = &[
    "export-identity.json",
    "tls-authority.json",
    "ceremony-mode",
    "grants",
    ".key",
    "passfile",
    ".pem",
];

/// Upstream `deniedContent` — refused content markers.
const DENIED_CONTENT: &[&str] = &["PRIVATE KEY", "ca_key", "leaf_key", "private_seed_hex"];

/// `ScanProtectedSubset` — reject trust material in the staged
/// protected-state copy: denied names and secret markers in content.
/// Runs after staging and before archiving; the first flagged path
/// aborts the export.
///
/// # Errors
/// `broker_export_token` when any file name or file content matches a
/// deny marker, or the tree cannot be walked.
pub fn scan_protected_subset(root: &Path) -> Result<(), Failure> {
    scan_dir(root)
}

fn scan_dir(dir: &Path) -> Result<(), Failure> {
    let entries = super::durable::read_dir(dir)
        .map_err(|e| internal(format!("portable: scan {}: {e}", dir.display())))?;
    // Sorted for deterministic first-error behavior.
    let mut names: Vec<_> = entries;
    names.sort_by(|a, b| a.name.cmp(&b.name));
    for entry in names {
        let path = dir.join(&entry.name);
        let base = entry.name.to_string_lossy().to_ascii_lowercase();
        for denied_name in DENIED_NAMES {
            if base.contains(denied_name) {
                return Err(internal(format!(
                    "portable: protected subset carries trust file {}",
                    path.display()
                )));
            }
        }
        if entry.file_type.is_dir() {
            scan_dir(&path)?;
            continue;
        }
        if !entry.file_type.is_file() {
            continue;
        }
        let Ok(raw) = durable::read_file(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&raw);
        for marker in DENIED_CONTENT {
            if text.contains(marker) {
                return Err(internal(format!(
                    "portable: protected subset file {} carries secret marker",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use std::fs;
    use time::Duration;

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn digest() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn issue_verify_round_trip() {
        let nonce = [7u8; 32];
        let token = issue_bx1_token(
            &key(),
            "tok-1",
            &digest(),
            "inst-1",
            EXPORT_PURPOSE,
            now(),
            TOKEN_EXPIRY_DEFAULT,
            &nonce,
        )
        .unwrap();
        assert_eq!(token.purpose, EXPORT_PURPOSE);
        // Raw URL-safe base64: no padding, URL alphabet.
        assert!(!token.nonce_b64.contains('='));
        assert_eq!(wire::b64_url_raw_decode(&token.nonce_b64).unwrap(), nonce);
        assert_eq!(token.public_key_hex.len(), 64);
        assert_eq!(token.signature_hex.len(), 128);
        verify_bx1_token(&token, &token.public_key_hex, &digest(), now()).unwrap();
        // Trust key comparison is case-insensitive (upstream EqualFold).
        verify_bx1_token(
            &token,
            &token.public_key_hex.to_uppercase(),
            &digest(),
            now(),
        )
        .unwrap();
    }

    #[test]
    fn verify_ladder_order_and_codes() {
        let nonce = [9u8; 32];
        let token = issue_bx1_token(
            &key(),
            "tok-2",
            &digest(),
            "inst-1",
            EXPORT_PURPOSE,
            now(),
            TOKEN_EXPIRY_DEFAULT,
            &nonce,
        )
        .unwrap();
        // Expired.
        let err = verify_bx1_token(
            &token,
            &token.public_key_hex,
            &digest(),
            now() + Duration::days(31),
        )
        .unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_EXPIRED);
        // Trust key mismatch.
        let err = verify_bx1_token(&token, &"00".repeat(32), &digest(), now()).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_INVALID);
        assert!(err.message().contains("trust key"));
        // Bundle digest mismatch.
        let err =
            verify_bx1_token(&token, &token.public_key_hex, &"00".repeat(32), now()).unwrap_err();
        assert_eq!(err.code(), ERR_BUNDLE_MISMATCH);
        // Tampered signature fails the ladder.
        let mut tampered = token.clone();
        tampered.instance_id = "other".to_owned();
        let err = verify_bx1_token(&tampered, &token.public_key_hex, &digest(), now()).unwrap_err();
        assert_eq!(err.code(), ERR_TOKEN_INVALID);
        // Missing field.
        let mut empty = token.clone();
        empty.signature_hex = String::new();
        let err = verify_bx1_token(&empty, &token.public_key_hex, &digest(), now()).unwrap_err();
        assert!(err.message().contains("missing field"));
    }

    #[test]
    fn derive_bundle_key_is_rfc5869_hkdf() {
        // RFC 5869 test case A.1 for HKDF-SHA256 has salt=13 zero bytes;
        // our empty-salt path fills 32 zeros — verify extract+expand
        // against a direct two-step computation instead.
        let nonce = [0xabu8; 32];
        let key1 = derive_bundle_key(&nonce).unwrap();
        assert_eq!(key1.len(), 32);
        // Deterministic and bound to the nonce.
        assert_eq!(derive_bundle_key(&nonce).unwrap(), key1);
        assert_ne!(derive_bundle_key(&[0xbbu8; 32]).unwrap(), key1);
        assert!(derive_bundle_key(&[0u8; 31]).is_err());
        // Independent check: PRK = HMAC(0*32, nonce); OKM =
        // HMAC(PRK, "" || info || 0x01).
        let mut mac = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(&nonce);
        let prk = mac.finalize().into_bytes();
        let mut mac2 = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&prk[..]).unwrap();
        mac2.update(b"bx1-dek/v1");
        mac2.update(&[1u8]);
        let expected = mac2.finalize().into_bytes();
        assert_eq!(&key1[..], &expected[..]);
    }

    #[test]
    fn identity_mints_once_and_refuses_corrupt() {
        let dir = TempDir::new("export-id");
        let path = dir.join("export-identity.json");
        let euid = rustix::process::geteuid().as_raw();
        let egid = rustix::process::getegid().as_raw();
        let (id1, created1) = load_or_mint_export_identity(&path, euid, egid, now()).unwrap();
        assert!(created1);
        let (id2, created2) = load_or_mint_export_identity(&path, euid, egid, now()).unwrap();
        assert!(!created2);
        assert_eq!(id1, id2);
        // Mode is 0600.
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Public key really derives from the seed.
        let seed = wire::hex_decode(&id1.private_seed_hex).unwrap();
        let k = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
        assert_eq!(
            id1.public_key_hex,
            wire::hex_encode(k.verifying_key().as_bytes())
        );
        // Corrupt file refuses rather than re-minting.
        fs::write(
            &path,
            br#"{"private_seed_hex":"00","public_key_hex":"x","created_at":"t"}"#,
        )
        .unwrap();
        assert!(load_or_mint_export_identity(&path, euid, egid, now()).is_err());
    }

    #[test]
    fn scan_protected_subset_flags_names_and_content() {
        let dir = TempDir::new("subset");
        fs::write(dir.join("config.json"), b"{}").unwrap();
        fs::write(dir.join("instance.json"), b"{}").unwrap();
        assert!(scan_protected_subset(&dir).is_ok());
        // Denied name.
        fs::write(dir.join("tls-authority.json"), b"{}").unwrap();
        assert!(scan_protected_subset(&dir).is_err());
        fs::remove_file(dir.join("tls-authority.json")).unwrap();
        // Denied content marker in an innocuously-named file.
        fs::write(
            dir.join("notes.json"),
            b"{\"x\": \"-----BEGIN PRIVATE KEY-----\"}",
        )
        .unwrap();
        assert!(scan_protected_subset(&dir).is_err());
        fs::remove_file(dir.join("notes.json")).unwrap();
        // Nested dir recursion.
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("sub").join("id.pem"), b"x").unwrap();
        assert!(scan_protected_subset(&dir).is_err());
        assert!(scan_protected_subset(&dir).is_err());
    }
}
