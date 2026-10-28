//! Dependency attestation — the port of upstream
//! `internal/adapter/dependencyprepare/attestation.go`,
//! `attestation_signer.go` and `attestation_key_linux.go`.
//!
//! * [`AttestationVerifier`] admits a DSSE envelope signed by a key in
//!   the lock's trust policy. It decides nothing about what an envelope
//!   may say: every call supplies the full [`AttestationExpectation`]
//!   (predicate, exact OCI subject, binding materials).
//! * [`AttestationSigner`] holds the private half of one trusted ed25519
//!   key and emits DSSE-shaped envelopes. The signature covers the DSSE
//!   pre-authentication encoding, so the payload type is bound too.
//! * [`AttestationService`] signs every required predicate over an equal
//!   OCI result and verifies each envelope it produced against the same
//!   expectation promotion will enforce.
//! * [`load_attestation_signer`] reads the operator's key file under the
//!   no-follow, regular-file, owner-only discipline; the key lives in the
//!   operator's state directory, never in the repository, a lock, or a
//!   result. Key *generation* (upstream `GenerateAttestationKey`, an
//!   operator tool) is not part of this port.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use central_infra::domain::{
    ATTESTATION_PAYLOAD_TYPE, ATTESTATION_SCHEMA, AttestationFact, REQUIRED_ATTESTATION_PREDICATES,
    codes, valid_operation_id, validate_attestation_facts,
};
use central_infra::prepare::{
    AttestationExpectation, AttestationMaterials, AttestationStatement, AttestationSubject,
    AttestationTrustPolicy, SignedAttestation, new_attestation_statement, prepare_codes,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::OpDeadline;
use crate::broker::wire::{b64_decode, b64_encode, hex_decode, hex_encode};

/// `AttestationKeyEnv` — overrides where the signing key is read from.
pub const ATTESTATION_KEY_ENV: &str = "CENTRAL_DEPENDENCY_ATTESTATION_KEY";

const ATTESTATION_KEY_SCHEMA: &str = "central.local-dependency-attestation-key/v1";
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// `port.Attestor` — generates and verifies the bound attestations once,
/// and only once, an equal OCI result exists.
pub trait Attestor: Send + Sync {
    /// `Attest`.
    ///
    /// # Errors
    /// `ATTESTATION_INVALID` (and friends) when any envelope cannot be
    /// signed, or does not verify against its own expectation.
    fn attest(
        &self,
        deadline: OpDeadline,
        subject: &AttestationSubject,
        materials: &AttestationMaterials,
    ) -> Result<Vec<AttestationFact>, Failure>;
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure::invalid(codes::ATTESTATION_INVALID, message)
}

fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(data)))
}

/// `dsseSignedBytes` — the DSSE pre-authentication encoding. The payload
/// type is inside the signed bytes, so an envelope cannot be relabelled
/// after signing.
fn dsse_signed_bytes(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

#[derive(Debug, Serialize, Deserialize)]
struct SigBlock {
    #[serde(rename = "keyid", default)]
    key_id: String,
    #[serde(default)]
    sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    #[serde(default)]
    payload: String,
    #[serde(rename = "payloadType", default)]
    payload_type: String,
    #[serde(default)]
    signatures: Vec<SigBlock>,
}

fn parse_envelope(raw: &[u8]) -> Result<Envelope, String> {
    let envelope: Envelope =
        serde_json::from_slice(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    if envelope.payload.is_empty() {
        return Err("missing payload".to_owned());
    }
    if envelope.signatures.is_empty() {
        return Err("missing signatures".to_owned());
    }
    Ok(envelope)
}

/// `AttestationVerifier` — admits dependency attestations signed by a key
/// in the lock's trust policy.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    policy: AttestationTrustPolicy,
}

impl AttestationVerifier {
    /// `NewAttestationVerifier`.
    #[must_use]
    pub fn new(policy: AttestationTrustPolicy) -> Self {
        Self { policy }
    }

    /// `Verify` — admits one envelope against `expect` and returns the
    /// verification fact recorded in the prepared manifest. Fails closed
    /// on an under-specified expectation, an untrusted/revoked/invalid
    /// signature, the wrong payload type, schema or predicate, a subject
    /// that is not the exact OCI layout, or differing materials.
    ///
    /// # Errors
    /// `ATTESTATION_INVALID`, `ATTESTATION_REVOKED` or `OCI_MISMATCH`.
    pub fn verify(
        &self,
        raw: &[u8],
        expect: &AttestationExpectation,
    ) -> Result<AttestationFact, Failure> {
        expect.validate()?;
        if raw.is_empty() {
            return Err(invalid("dependencyprepare: attestation payload is empty"));
        }
        let envelope = parse_envelope(raw).map_err(|e| {
            invalid(format!(
                "dependencyprepare: invalid attestation: attestation envelope: {e}"
            ))
        })?;
        if envelope.payload_type != ATTESTATION_PAYLOAD_TYPE {
            return Err(invalid(format!(
                "dependencyprepare: invalid attestation: payload type {:?} != {:?}",
                envelope.payload_type, ATTESTATION_PAYLOAD_TYPE
            )));
        }
        let payload = b64_decode(&envelope.payload).ok_or_else(|| {
            invalid("dependencyprepare: invalid attestation: decode payload: illegal base64 data")
        })?;
        let key_id = self.verify_envelope_signature(&envelope, &payload)?;

        let statement: AttestationStatement = serde_json::from_slice(&payload).map_err(|e| {
            invalid(format!(
                "dependencyprepare: invalid attestation: invalid payload JSON: {e}"
            ))
        })?;
        if statement.schema != ATTESTATION_SCHEMA {
            return Err(invalid(format!(
                "dependencyprepare: invalid attestation: attestation schema {:?} != {:?}",
                statement.schema, ATTESTATION_SCHEMA
            )));
        }
        if statement.predicate != expect.predicate {
            return Err(invalid(format!(
                "dependencyprepare: invalid attestation: attestation predicate {} != expected {}",
                statement.predicate, expect.predicate
            )));
        }
        if statement.subject != expect.subject {
            return Err(Failure::invalid(
                codes::OCI_MISMATCH,
                format!(
                    "dependencyprepare: OCI mismatch: attestation subject {:?} != expected {:?}",
                    statement.subject, expect.subject
                ),
            ));
        }
        if statement.materials != expect.materials {
            return Err(invalid(
                "dependencyprepare: invalid attestation: attestation materials do not bind the expected lock, source, bases, builders, invocation and operation",
            ));
        }
        Ok(AttestationFact {
            predicate: statement.predicate,
            schema: statement.schema,
            key_id,
            envelope_digest: sha256_hex(raw),
            subject_digest: statement.subject.index_digest,
        })
    }

    /// Requires every signature block to name a trusted, unrevoked key
    /// and to verify, and returns the first signer. Stopping at the first
    /// block would let an attacker append blocks that are never examined.
    fn verify_envelope_signature(
        &self,
        envelope: &Envelope,
        payload: &[u8],
    ) -> Result<String, Failure> {
        self.policy.validate().map_err(|e| {
            invalid(format!(
                "dependencyprepare: invalid attestation: trust policy: {}",
                e.message()
            ))
        })?;
        let signed = dsse_signed_bytes(&envelope.payload_type, payload);
        let mut signer = String::new();
        for block in &envelope.signatures {
            let Some(key) = self.policy.keys.iter().find(|k| k.key_id == block.key_id) else {
                return Err(invalid(format!(
                    "dependencyprepare: invalid attestation: attestation signed by unknown key {:?}",
                    block.key_id
                )));
            };
            if key.revoked {
                return Err(Failure::invalid(
                    prepare_codes::ATTESTATION_REVOKED,
                    format!(
                        "dependencyprepare: attestation key revoked: {:?}",
                        block.key_id
                    ),
                ));
            }
            let verifying = hex_decode(&key.public_key)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
                .ok_or_else(|| {
                    invalid(format!(
                        "dependencyprepare: invalid attestation: key {:?}: bad public key",
                        key.key_id
                    ))
                })?;
            let signature = b64_decode(&block.sig)
                .and_then(|b| <[u8; 64]>::try_from(b).ok())
                .map(|b| Signature::from_bytes(&b))
                .ok_or_else(|| {
                    invalid(format!(
                        "dependencyprepare: invalid attestation: key {:?}: decode signature",
                        block.key_id
                    ))
                })?;
            if verifying.verify(&signed, &signature).is_err() {
                return Err(invalid(format!(
                    "dependencyprepare: invalid attestation: attestation signature from key {:?} is invalid",
                    block.key_id
                )));
            }
            if signer.is_empty() {
                signer.clone_from(&block.key_id);
            }
        }
        if signer.is_empty() {
            return Err(invalid(
                "dependencyprepare: invalid attestation: attestation has no valid signatures",
            ));
        }
        Ok(signer)
    }
}

/// `AttestationSigner` — produces the attestations this capability
/// verifies. Holds the private half of one trusted key.
pub struct AttestationSigner {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for AttestationSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl AttestationSigner {
    /// `NewAttestationSigner` — from a 64-byte ed25519 private key
    /// (seed ‖ public), Go's `ed25519.PrivateKey` layout. A key whose two
    /// halves disagree is corrupt and refused.
    ///
    /// # Errors
    /// `ATTESTATION_INVALID` for an empty key ID, wrong length, or
    /// inconsistent halves.
    pub fn from_private_key(key_id: &str, private: &[u8]) -> Result<Self, Failure> {
        if key_id.is_empty() {
            return Err(invalid(
                "dependencyprepare: invalid attestation: signer has no key ID",
            ));
        }
        let bytes: [u8; 64] = private.try_into().map_err(|_| {
            invalid(format!(
                "dependencyprepare: invalid attestation: signer key {key_id:?} has {} bytes, want 64",
                private.len()
            ))
        })?;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(&bytes[..32]).unwrap_or([0; 32]));
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().to_bytes()[..] != bytes[32..] {
            return Err(invalid(format!(
                "dependencyprepare: invalid attestation: signer key {key_id:?} halves disagree"
            )));
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            key,
        })
    }

    /// `KeyID`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// `PublicKeyHex` — the encoding a lock's trust policy records.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.key.verifying_key().to_bytes())
    }

    /// `Sign` — one DSSE-shaped envelope over `statement`.
    ///
    /// # Errors
    /// `ATTESTATION_INVALID` for a wrong schema or an unbound subject or
    /// materials; `internal` if marshalling fails.
    pub fn sign(&self, statement: &AttestationStatement) -> Result<SignedAttestation, Failure> {
        if statement.schema != ATTESTATION_SCHEMA {
            return Err(invalid(format!(
                "dependencyprepare: invalid attestation: statement schema {:?} != {:?}",
                statement.schema, ATTESTATION_SCHEMA
            )));
        }
        statement.subject.validate()?;
        statement.materials.validate()?;
        let payload = serde_json::to_vec(statement).map_err(|e| {
            Failure::internal(
                codes::ATTESTATION_INVALID,
                format!("dependencyprepare: marshal attestation statement: {e}"),
            )
        })?;
        let signature = self
            .key
            .sign(&dsse_signed_bytes(ATTESTATION_PAYLOAD_TYPE, &payload));
        let envelope = serde_json::to_vec(&Envelope {
            payload: b64_encode(&payload),
            payload_type: ATTESTATION_PAYLOAD_TYPE.to_owned(),
            signatures: vec![SigBlock {
                key_id: self.key_id.clone(),
                sig: b64_encode(&signature.to_bytes()),
            }],
        })
        .map_err(|e| {
            Failure::internal(
                codes::ATTESTATION_INVALID,
                format!("dependencyprepare: marshal attestation envelope: {e}"),
            )
        })?;
        Ok(SignedAttestation {
            predicate: statement.predicate,
            envelope,
        })
    }
}

/// `AttestationService` — both sides of attestation. A signer that emits
/// something the verifier would reject fails here rather than at promotion.
#[derive(Debug)]
pub struct AttestationService {
    signer: AttestationSigner,
    verifier: AttestationVerifier,
    artifact_dir: Option<PathBuf>,
}

impl AttestationService {
    /// `NewAttestationService` — refuses a signer whose key is not in the
    /// lock's attestation trust policy.
    ///
    /// # Errors
    /// `ATTESTATION_INVALID` for an invalid policy or an untrusted key.
    pub fn new(signer: AttestationSigner, policy: AttestationTrustPolicy) -> Result<Self, Failure> {
        policy.validate().map_err(|e| {
            invalid(format!(
                "dependencyprepare: invalid attestation: attestation trust: {}",
                e.message()
            ))
        })?;
        let trusted = policy
            .keys
            .iter()
            .any(|k| k.key_id == signer.key_id() && k.public_key == signer.public_key_hex());
        if !trusted {
            return Err(invalid(format!(
                "dependencyprepare: invalid attestation: signing key {:?} is not in the lock's attestation trust policy",
                signer.key_id()
            )));
        }
        Ok(Self {
            signer,
            verifier: AttestationVerifier::new(policy),
            artifact_dir: None,
        })
    }

    /// `WithArtifactDir` — retain the exact verified envelopes under
    /// `<dir>/<opID>/attestations/`. Without it nothing is kept.
    #[must_use]
    pub fn with_artifact_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.artifact_dir = Some(dir.into());
        self
    }

    fn persist_envelopes(
        &self,
        operation_id: &str,
        envelopes: &[SignedAttestation],
    ) -> Result<(), Failure> {
        let Some(root) = &self.artifact_dir else {
            return Ok(());
        };
        valid_operation_id(operation_id).map_err(|e| invalid(e.message().to_owned()))?;
        let dir = root.join(operation_id).join("attestations");
        let io = |what: &str, e: std::io::Error| {
            invalid(format!(
                "dependencyprepare: invalid attestation: {what}: {e}"
            ))
        };
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| io("create attestation artifact dir", e))?;
        for signed in envelopes {
            let path = dir.join(format!("{}.json", signed.predicate));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| io(&format!("persist {} envelope", signed.predicate), e))?;
            std::io::Write::write_all(&mut file, &signed.envelope)
                .map_err(|e| io(&format!("persist {} envelope", signed.predicate), e))?;
        }
        Ok(())
    }
}

impl Attestor for AttestationService {
    /// `Attest` — signs and verifies the complete set of required
    /// predicates for one subject and returns the facts recorded in the
    /// candidate manifest.
    ///
    /// What this establishes, exactly: each statement is the same binding
    /// (subject plus materials) distinguished only by its predicate label,
    /// so a verified `sbom` fact is evidence that the lock, source
    /// archive, commit, bases, both builder identities and the invocation
    /// were signed over this layout by a trusted key. It is not a package
    /// inventory, and `license-report` is not a license inventory.
    fn attest(
        &self,
        deadline: OpDeadline,
        subject: &AttestationSubject,
        materials: &AttestationMaterials,
    ) -> Result<Vec<AttestationFact>, Failure> {
        subject.validate()?;
        materials.validate()?;
        let mut facts = Vec::with_capacity(REQUIRED_ATTESTATION_PREDICATES.len());
        let mut envelopes = Vec::with_capacity(REQUIRED_ATTESTATION_PREDICATES.len());
        for predicate in REQUIRED_ATTESTATION_PREDICATES {
            deadline.check()?;
            let statement =
                new_attestation_statement(predicate, subject.clone(), materials.clone())?;
            let signed = self.signer.sign(&statement)?;
            let fact = self.verifier.verify(
                &signed.envelope,
                &AttestationExpectation {
                    predicate,
                    subject: subject.clone(),
                    materials: materials.clone(),
                },
            )?;
            facts.push(fact);
            envelopes.push(signed);
        }
        validate_attestation_facts(&facts, &subject.index_digest)?;
        self.persist_envelopes(&materials.operation_id, &envelopes)?;
        Ok(facts)
    }
}

/// `AttestationKeyPath` — the environment override if set, otherwise the
/// XDG state root the rest of Central's dev trust material uses. The key
/// is deliberately outside the repository and the work directory.
#[must_use]
pub fn attestation_key_path() -> PathBuf {
    if let Some(over) = std::env::var_os(ATTESTATION_KEY_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(over);
    }
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(
            || {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                    .join(".local")
                    .join("state")
            },
            PathBuf::from,
        );
    state_home
        .join("central")
        .join("dev-trust")
        .join("dependency-attestation-key.json")
}

#[derive(Deserialize)]
struct KeyFile {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    private_key: String,
}

/// `LoadAttestationSigner` — reads the signing key at `path` with
/// `openat2` `NO_MAGICLINKS` + `O_NOFOLLOW`, requires a regular file, and
/// refuses a key readable by any account other than its owner.
///
/// # Errors
/// `ATTESTATION_INVALID` for an unreadable, misshapen, wrong-schema,
/// over-permissive, or self-inconsistent key file.
pub fn load_attestation_signer(path: &Path) -> Result<AttestationSigner, Failure> {
    use std::os::fd::OwnedFd;
    let fd: OwnedFd = rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| {
        invalid(format!(
            "dependencyprepare: open attestation signing key: {e}"
        ))
    })?;
    let file = fs::File::from(fd);
    let meta = file.metadata().map_err(|e| {
        invalid(format!(
            "dependencyprepare: stat attestation signing key: {e}"
        ))
    })?;
    if !meta.is_file() {
        return Err(invalid(
            "dependencyprepare: attestation signing key is not a regular file",
        ));
    }
    {
        use std::os::unix::fs::PermissionsExt as _;
        let perm = meta.permissions().mode() & 0o777;
        if perm & 0o077 != 0 {
            return Err(invalid(format!(
                "dependencyprepare: attestation signing key is readable beyond its owner (mode {perm:04o})"
            )));
        }
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE_BYTES)
        .read_to_end(&mut data)
        .map_err(|e| {
            invalid(format!(
                "dependencyprepare: read attestation signing key: {e}"
            ))
        })?;
    let key_file: KeyFile = serde_json::from_slice(&data).map_err(|e| {
        invalid(format!(
            "dependencyprepare: decode attestation signing key: {e}"
        ))
    })?;
    if key_file.schema != ATTESTATION_KEY_SCHEMA {
        return Err(invalid(format!(
            "dependencyprepare: invalid attestation: signing key schema {:?} != {:?}",
            key_file.schema, ATTESTATION_KEY_SCHEMA
        )));
    }
    let private = Zeroizing::new(b64_decode(&key_file.private_key).ok_or_else(|| {
        invalid("dependencyprepare: invalid attestation: decode signing key: illegal base64 data")
    })?);
    let signer = AttestationSigner::from_private_key(&key_file.key_id, &private)?;
    if !key_file.public_key.is_empty()
        && !key_file
            .public_key
            .eq_ignore_ascii_case(&signer.public_key_hex())
    {
        return Err(invalid(format!(
            "dependencyprepare: invalid attestation: signing key {:?} does not match its recorded public key",
            key_file.key_id
        )));
    }
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::domain::AttestationPredicate;
    use central_infra::prepare::TrustedKey;

    const SEED: [u8; 32] = [7; 32];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SEED)
    }

    fn private_bytes() -> Vec<u8> {
        let key = signing_key();
        let mut out = SEED.to_vec();
        out.extend_from_slice(&key.verifying_key().to_bytes());
        out
    }

    fn signer() -> AttestationSigner {
        AttestationSigner::from_private_key("k1", &private_bytes()).expect("signer")
    }

    fn policy_for(signer: &AttestationSigner) -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            keys: vec![TrustedKey {
                key_id: signer.key_id().to_owned(),
                public_key: signer.public_key_hex(),
                expires_at: None,
                revoked: false,
            }],
        }
    }

    fn subject() -> AttestationSubject {
        AttestationSubject {
            name: "minio".to_owned(),
            index_digest: "sha256:i".to_owned(),
            manifest_digest: "sha256:m".to_owned(),
            config_digest: "sha256:c".to_owned(),
        }
    }

    fn materials() -> AttestationMaterials {
        AttestationMaterials {
            lock_digest: "sha256:a".to_owned(),
            source_archive_digest: "sha256:b".to_owned(),
            source_commit: "c".repeat(40),
            base_identities: vec!["scratch".to_owned()],
            builder_identity_a: "sha256:x".to_owned(),
            builder_identity_b: "sha256:y".to_owned(),
            invocation_digest: "sha256:i".to_owned(),
            operation_id: "prepare-1".to_owned(),
        }
    }

    fn expect(predicate: AttestationPredicate) -> AttestationExpectation {
        AttestationExpectation {
            predicate,
            subject: subject(),
            materials: materials(),
        }
    }

    fn signed(predicate: AttestationPredicate) -> Vec<u8> {
        let stmt = new_attestation_statement(predicate, subject(), materials()).expect("stmt");
        signer().sign(&stmt).expect("sign").envelope
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-pp-att-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn attest_signs_and_verifies_every_required_predicate() {
        let s = signer();
        let svc = AttestationService::new(
            AttestationSigner::from_private_key("k1", &private_bytes()).expect("s"),
            policy_for(&s),
        )
        .expect("svc");
        let facts = svc
            .attest(OpDeadline::NONE, &subject(), &materials())
            .expect("attest");
        assert_eq!(facts.len(), REQUIRED_ATTESTATION_PREDICATES.len());
        assert!(
            facts
                .iter()
                .all(|f| f.key_id == "k1" && f.subject_digest == "sha256:i")
        );
    }

    #[test]
    fn service_refuses_a_signer_outside_the_trust_policy() {
        let s = signer();
        let mut policy = policy_for(&s);
        policy.keys[0].key_id = "other".to_owned();
        assert!(AttestationService::new(signer(), policy).is_err());
    }

    #[test]
    fn verify_refuses_wrong_predicate_subject_and_materials() {
        let v = AttestationVerifier::new(policy_for(&signer()));
        let raw = signed(AttestationPredicate::Sbom);
        assert!(v.verify(&raw, &expect(AttestationPredicate::Sbom)).is_ok());
        assert!(
            v.verify(&raw, &expect(AttestationPredicate::LicenseReport))
                .is_err()
        );
        let mut e = expect(AttestationPredicate::Sbom);
        e.subject.index_digest = "sha256:other".to_owned();
        assert_eq!(
            v.verify(&raw, &e).expect_err("subject").code(),
            codes::OCI_MISMATCH
        );
        let mut e = expect(AttestationPredicate::Sbom);
        e.materials.operation_id = "prepare-2".to_owned();
        assert!(v.verify(&raw, &e).is_err());
    }

    #[test]
    fn verify_refuses_untrusted_revoked_and_tampered_envelopes() {
        let s = signer();
        let raw = signed(AttestationPredicate::Sbom);
        let mut revoked = policy_for(&s);
        revoked.keys[0].revoked = true;
        let err = AttestationVerifier::new(revoked)
            .verify(&raw, &expect(AttestationPredicate::Sbom))
            .expect_err("revoked");
        assert_eq!(err.code(), prepare_codes::ATTESTATION_REVOKED);

        let mut unknown = policy_for(&s);
        unknown.keys[0].key_id = "someone-else".to_owned();
        assert!(
            AttestationVerifier::new(unknown)
                .verify(&raw, &expect(AttestationPredicate::Sbom))
                .is_err()
        );

        let mut env: Envelope = serde_json::from_slice(&raw).expect("env");
        env.payload_type = "text/plain".to_owned();
        let relabelled = serde_json::to_vec(&env).expect("json");
        let v = AttestationVerifier::new(policy_for(&s));
        assert!(
            v.verify(&relabelled, &expect(AttestationPredicate::Sbom))
                .is_err()
        );

        let mut env: Envelope = serde_json::from_slice(&raw).expect("env");
        let mut payload = b64_decode(&env.payload).expect("b64");
        payload[10] ^= 1;
        env.payload = b64_encode(&payload);
        let tampered = serde_json::to_vec(&env).expect("json");
        assert!(
            v.verify(&tampered, &expect(AttestationPredicate::Sbom))
                .is_err()
        );
    }

    #[test]
    fn every_signature_block_must_verify() {
        let s = signer();
        let raw = signed(AttestationPredicate::Sbom);
        let mut env: Envelope = serde_json::from_slice(&raw).expect("env");
        env.signatures.push(SigBlock {
            key_id: "k1".to_owned(),
            sig: b64_encode(&[0u8; 64]),
        });
        let two = serde_json::to_vec(&env).expect("json");
        assert!(
            AttestationVerifier::new(policy_for(&s))
                .verify(&two, &expect(AttestationPredicate::Sbom))
                .is_err()
        );
    }

    #[test]
    fn verify_refuses_empty_and_unbound_input() {
        let v = AttestationVerifier::new(policy_for(&signer()));
        assert!(v.verify(b"", &expect(AttestationPredicate::Sbom)).is_err());
        assert!(
            v.verify(b"{}", &expect(AttestationPredicate::Sbom))
                .is_err()
        );
        let mut e = expect(AttestationPredicate::Sbom);
        e.subject.name.clear();
        assert!(v.verify(&signed(AttestationPredicate::Sbom), &e).is_err());
    }

    #[test]
    fn signer_refuses_inconsistent_halves_and_bad_lengths() {
        let mut bad = private_bytes();
        bad[40] ^= 1;
        assert!(AttestationSigner::from_private_key("k", &bad).is_err());
        assert!(AttestationSigner::from_private_key("k", &[0u8; 10]).is_err());
        assert!(AttestationSigner::from_private_key("", &private_bytes()).is_err());
    }

    #[test]
    fn envelopes_are_retained_only_with_an_artifact_dir() {
        let s = signer();
        let root = tmp("persist");
        let svc = AttestationService::new(signer(), policy_for(&s))
            .expect("svc")
            .with_artifact_dir(&root);
        svc.attest(OpDeadline::NONE, &subject(), &materials())
            .expect("attest");
        let dir = root.join("prepare-1").join("attestations");
        for p in REQUIRED_ATTESTATION_PREDICATES {
            assert!(dir.join(format!("{p}.json")).is_file(), "{p}");
        }
        let _ = fs::remove_dir_all(&root);
    }

    fn key_file_json(public: &str) -> String {
        serde_json::json!({
            "schema": ATTESTATION_KEY_SCHEMA,
            "label": "t",
            "key_id": "k1",
            "public_key": public,
            "private_key": b64_encode(&private_bytes()),
        })
        .to_string()
    }

    #[test]
    fn key_loader_enforces_owner_only_regular_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmp("key");
        let path = dir.join("key.json");
        let public = signer().public_key_hex();
        fs::write(&path, key_file_json(&public)).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = load_attestation_signer(&path).expect_err("perm");
        assert!(err.message().contains("readable beyond its owner"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(load_attestation_signer(&path).expect("load").key_id(), "k1");

        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(load_attestation_signer(&link).is_err());

        fs::write(&path, key_file_json(&"00".repeat(32))).expect("write");
        assert!(
            load_attestation_signer(&path)
                .expect_err("mismatch")
                .message()
                .contains("recorded public key")
        );
        fs::write(
            &path,
            key_file_json("").replace(ATTESTATION_KEY_SCHEMA, "bogus"),
        )
        .expect("write");
        assert!(load_attestation_signer(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
