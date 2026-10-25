//! `SigningService` + `Ed25519Signer` — the port of upstream
//! `signing.go`: the broker's persistent HMAC-SHA-256 fingerprint key
//! and the ephemeral Ed25519 signer the journal's committed records
//! carry.
//!
//! The HMAC key is *persistent* — created once under the protected root
//! as `hmac-fingerprint.key` (`0600`, link count 1, owned by the broker
//! user) and reloaded across restarts, so issued proofs and records stay
//! verifiable after a crash. The Ed25519 key is ephemeral by upstream
//! design: signatures prove "this broker instance signed this record",
//! never a durable identity.

use std::path::Path;

use central_foundation::failure::Failure;

use super::durable::{
    self, FINGERPRINT_KEY_FILENAME, PRIVATE_FILE_MODE, ensure_private_root, sync_dir,
};
use super::wire::hmac_fingerprint;
use zeroize::Zeroizing;

/// `fingerprintKeySize` — 32-byte HMAC key.
const FINGERPRINT_KEY_SIZE: usize = 32;

/// `SigningService` — HMAC-based fingerprinting used by the journal,
/// proof, payload-epoch, and lifecycle protocols.
pub struct SigningService {
    fingerprint_key: Zeroizing<Vec<u8>>,
}

impl SigningService {
    /// `NewSigningService` — a fixed-key service for isolated unit tests.
    /// Broker services must use [`Self::new_persistent`] instead.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fingerprint_key: Zeroizing::new(b"central-fingerprint-key-v1".to_vec()),
        }
    }

    /// A service over an already-validated key — the read-only
    /// `ActivePayloadEpochSource` composition, which loads the persistent
    /// key through the strict path rather than creating it.
    #[must_use]
    pub(crate) fn from_key(key: Vec<u8>) -> Self {
        Self {
            fingerprint_key: Zeroizing::new(key),
        }
    }

    /// A copy of the fingerprint key for composing a second service
    /// over the same identity (the persistent `ProofService` shares the
    /// key the `Service` HMACs under).
    pub(crate) fn key_copy(&self) -> Vec<u8> {
        (*self.fingerprint_key).clone()
    }

    /// `newPersistentSigningService` — atomically creates or loads the
    /// broker's HMAC key. The broker normally runs as root; requiring the
    /// effective user to own the root and key preserves that boundary
    /// while allowing unprivileged tests.
    pub fn new_persistent(root: &Path) -> Result<Self, Failure> {
        ensure_private_root(root)?;
        let key_path = root.join(FINGERPRINT_KEY_FILENAME);
        let key = load_or_create_fingerprint_key(root, &key_path)?;
        Ok(Self {
            fingerprint_key: Zeroizing::new(key),
        })
    }

    /// `HMACFingerprint` — hex HMAC-SHA-256 over `domain|data`.
    #[must_use]
    pub fn fingerprint(&self, domain: &str, data: &[u8]) -> String {
        hmac_fingerprint(&self.fingerprint_key, domain, data)
    }
}

impl Default for SigningService {
    fn default() -> Self {
        Self::new()
    }
}

/// `loadOrCreateFingerprintKey` — open the existing key (strict shape
/// checks) or create it via a `0600` temp file published by `link(2)`
/// so a racing creator never overwrites an established key.
fn load_or_create_fingerprint_key(root: &Path, key_path: &Path) -> Result<Vec<u8>, Failure> {
    match load_fingerprint_key(key_path) {
        Ok(key) => return Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Failure::internal(
                "broker_signing_os",
                format!("broker: load signing key: {e}"),
            ));
        }
    }

    // Create in a unique temp file, then `link` into place — the link
    // fails with EEXIST when a peer already published, in which case we
    // re-load and adopt theirs (upstream's `os.ErrExist →
    // loadFingerprintKey` retry).
    let tmp = {
        let mut name = [0u8; 8];
        rustix::rand::getrandom(&mut name, rustix::rand::GetRandomFlags::empty())
            .map_err(|e| Failure::internal("broker_signing_os", format!("tmp entropy: {e}")))?;
        root.join(format!(
            ".hmac-fingerprint-key-{}",
            crate::broker::wire::hex_encode(&name)
        ))
    };
    let publish = (|| -> Result<Vec<u8>, Failure> {
        let mut file = durable::open_exclusive(&tmp, PRIVATE_FILE_MODE).map_err(|e| {
            Failure::internal(
                "broker_signing_os",
                format!("broker: create signing key: {e}"),
            )
        })?;
        let mut key = vec![0u8; FINGERPRINT_KEY_SIZE];
        let mut filled = 0usize;
        while filled < FINGERPRINT_KEY_SIZE {
            filled +=
                rustix::rand::getrandom(&mut key[filled..], rustix::rand::GetRandomFlags::empty())
                    .map_err(|e| {
                        Failure::internal(
                            "broker_signing_os",
                            format!("broker: generate signing key: {e}"),
                        )
                    })?;
        }
        use std::io::Write as _;
        file.write_all(&key)
            .and_then(|()| file.sync_all())
            .map_err(|e| {
                Failure::internal(
                    "broker_signing_os",
                    format!("broker: write signing key: {e}"),
                )
            })?;
        drop(file);
        match durable::hard_link(&tmp, key_path) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                // A racing creator won — adopt the established key.
                let _ = durable::remove_file(&tmp);
                return load_fingerprint_key(key_path).map_err(|e| {
                    Failure::internal(
                        "broker_signing_os",
                        format!("broker: load signing key: {e}"),
                    )
                });
            }
            Err(e) => {
                return Err(Failure::internal(
                    "broker_signing_os",
                    format!("broker: publish signing key: {e}"),
                ));
            }
        }
        Ok(key)
    })();
    let _ = durable::remove_file(&tmp);
    let key = publish?;
    sync_dir(root)?;
    Ok(key)
}

/// `loadFingerprintKey` — `lstat` shape checks (regular, not symlink,
/// exact `0600`, owner-owned, link count 1) then read; 32 bytes or
/// corrupt. `newfstatat` goes through [`durable::lstat`] —
/// `fs::symlink_metadata` emits `statx`, which the hardened broker's
/// filter does not allow (ADR 0044).
fn load_fingerprint_key(key_path: &Path) -> std::io::Result<Vec<u8>> {
    let meta = durable::lstat(key_path)?;
    if !rustix::fs::FileType::from_raw_mode(meta.st_mode).is_file()
        || rustix::fs::FileType::from_raw_mode(meta.st_mode).is_symlink()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker: signing key is not a regular file",
        ));
    }
    if meta.st_mode & 0o777 != PRIVATE_FILE_MODE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "broker: insecure signing key permissions {:04o}",
                (meta.st_mode & 0o777)
            ),
        ));
    }
    if meta.st_uid != rustix::process::geteuid().as_raw() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker: signing key is not owned by the broker user",
        ));
    }
    if meta.st_nlink != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker: signing key has an invalid link count",
        ));
    }
    let key = durable::read_file(key_path).map_err(std::io::Error::from)?;
    if key.len() != FINGERPRINT_KEY_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("broker: corrupt signing key length {}", key.len()),
        ));
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Ed25519Signer — external verifiability for journal entries
// ---------------------------------------------------------------------------

/// `Ed25519Signer` — an ephemeral Ed25519 key pair that signs authority
/// transition payloads (upstream `NewEd25519Signer`). The key never
/// persists: signatures prove "a broker signed", not "this broker".
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// `NewEd25519Signer` — a fresh key pair from the OS RNG.
    ///
    /// # Errors
    /// `broker_signing_os` when the entropy source fails.
    pub fn new() -> Result<Self, Failure> {
        let mut seed = [0u8; 32];
        rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty()).map_err(|e| {
            Failure::internal("broker_signing_os", format!("broker: ed25519 key gen: {e}"))
        })?;
        Ok(Self {
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }

    /// `Sign` — the hex-encoded Ed25519 signature over `data`.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> String {
        use ed25519_dalek::Signer as _;
        super::wire::hex_encode(&self.key.sign(data).to_bytes())
    }

    /// `PublicKeyHex` — the hex-encoded public half.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        super::wire::hex_encode(self.key.verifying_key().as_bytes())
    }

    /// The raw signing key for composed signing sites (the BX1 export
    /// token's JCS payload). Key material stays inside the broker
    /// boundary — this hands out a borrow, never a copy into ordinary
    /// storage. Only the tests and the R6 export-issuing call site use
    /// it today.
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// Canonical-JSON signing + verification — the signed-record signature
// vocabulary (the BX1 export token's JCS unsigned form)
// ---------------------------------------------------------------------------

/// Sign the JCS-canonical form of `value` and return the hex Ed25519
/// signature — the single call sites that must produce "signature over
/// canonical JSON bytes" (BX1 signs the canonical unsigned token
/// object).
pub(crate) fn sign_canonical_json(
    key: &ed25519_dalek::SigningKey,
    value: &serde_json::Value,
) -> Result<String, Failure> {
    use ed25519_dalek::Signer as _;
    let canonical = central_foundation::jcs::canonicalize(value).map_err(|e| {
        Failure::invalid(
            "broker_signing",
            format!("broker: canonicalize signed payload: {e}"),
        )
    })?;
    Ok(super::wire::hex_encode(&key.sign(&canonical).to_bytes()))
}

/// Verify an Ed25519 signature given hex-encoded public key and
/// signature — upstream's `ed25519.Verify` + strict decode ladder
/// (each malformed input is denied, not silently skipped).
pub(crate) fn verify_ed25519_hex(
    public_key_hex: &str,
    signature_hex: &str,
    data: &[u8],
) -> Result<(), Failure> {
    let invalid =
        |what: &str| Failure::invalid("broker_signing", format!("broker: invalid ed25519 {what}"));
    let public_raw =
        super::wire::hex_decode(public_key_hex).ok_or_else(|| invalid("public key encoding"))?;
    let public_array: [u8; 32] = public_raw
        .try_into()
        .map_err(|_| invalid("public key length"))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public_array)
        .map_err(|_| invalid("public key"))?;
    let signature_raw =
        super::wire::hex_decode(signature_hex).ok_or_else(|| invalid("signature encoding"))?;
    let signature_array: [u8; 64] = signature_raw
        .try_into()
        .map_err(|_| invalid("signature length"))?;
    use ed25519_dalek::Verifier as _;
    verifying
        .verify(
            data,
            &ed25519_dalek::Signature::from_bytes(&signature_array),
        )
        .map_err(|_| {
            Failure::denied(
                "broker_signing",
                "broker: ed25519 signature verification failed",
            )
        })
}

/// Verify an Ed25519 signature over the JCS-canonical form of `value` —
/// the consumer-side counterpart of [`sign_canonical_json`].
pub(crate) fn verify_canonical_json_hex(
    public_key_hex: &str,
    signature_hex: &str,
    value: &serde_json::Value,
) -> Result<(), Failure> {
    let canonical = central_foundation::jcs::canonicalize(value).map_err(|e| {
        Failure::invalid(
            "broker_signing",
            format!("broker: canonicalize signed payload: {e}"),
        )
    })?;
    verify_ed25519_hex(public_key_hex, signature_hex, &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn persistent_key_survives_restart() {
        let dir = std::env::temp_dir().join(format!("central-signing-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a = SigningService::new_persistent(&dir).unwrap();
        let fa = a.fingerprint("test", b"abc");
        let b = SigningService::new_persistent(&dir).unwrap();
        assert_eq!(fa, b.fingerprint("test", b"abc"));
        let mode = fs::metadata(dir.join(FINGERPRINT_KEY_FILENAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn insecure_key_rejected() {
        let dir = std::env::temp_dir().join(format!("central-signing-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key = dir.join(FINGERPRINT_KEY_FILENAME);
        fs::write(&key, [0u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SigningService::new_persistent(&dir).is_err());
        // Wrong length, right mode — still corrupt.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&key, [0u8; 31]).unwrap();
        assert!(SigningService::new_persistent(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn canonical_json_sign_and_verify() {
        let signer = Ed25519Signer::new().unwrap();
        let value = serde_json::json!({"b": 2, "a": [1, {"x": true}]});
        let signature = sign_canonical_json(signer.signing_key(), &value).unwrap();
        assert_eq!(signature.len(), 128);
        // The same object with different key order canonicalizes
        // identically — the signature verifies across serializations.
        let reordered = serde_json::json!({"a": [1, {"x": true}], "b": 2});
        verify_canonical_json_hex(signer.public_key_hex().as_str(), &signature, &reordered)
            .unwrap();
        // Tampered payload refuses.
        let tampered = serde_json::json!({"a": [1, {"x": false}], "b": 2});
        assert!(
            verify_canonical_json_hex(signer.public_key_hex().as_str(), &signature, &tampered)
                .is_err()
        );
    }

    #[test]
    fn verify_rejects_malformed_inputs() {
        let signer = Ed25519Signer::new().unwrap();
        let signature =
            sign_canonical_json(signer.signing_key(), &serde_json::json!({"k": "v"})).unwrap();
        assert!(verify_ed25519_hex("zz", &signature, b"x").is_err());
        assert!(verify_ed25519_hex("abcd", &signature, b"x").is_err());
        assert!(
            verify_ed25519_hex(
                &signer.public_key_hex(),
                &signature[..signature.len() - 2],
                b"x"
            )
            .is_err()
        );
        assert!(verify_ed25519_hex(&signer.public_key_hex(), &signature, b"other").is_err());
    }
}
