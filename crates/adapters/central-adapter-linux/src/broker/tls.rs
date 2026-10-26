//! `TlsAuthority` — the port of upstream `tls_authority.go` +
//! `tls_persistent.go`: the broker-owned local Ed25519 CA that signs
//! `127.0.0.1` server-auth leaves for the protected transport.
//!
//! Custody rules (unchanged from upstream):
//!
//! - The CA private key and active leaf private key exist only inside
//!   this type (memory) and in `tls-authority.json` under the private
//!   broker root (`0600`, owner-checked, link count 1, ≤ 64 KiB,
//!   atomically renamed into place). Private material is never returned
//!   through any RPC or projection.
//! - `rekey` publishes a complete replacement state file *before* the
//!   in-memory authority is swapped — a failed publish leaves the prior
//!   authority live.
//! - Reload re-validates the persisted chain: CA parses and is a CA
//!   certificate, the leaf's signature verifies under the CA public
//!   key, and each persisted private key matches its certificate's
//!   public key. A corrupt or tampered state file refuses startup rather
//!   than silently minting a new authority.
//!
//! One deliberate deviation from upstream: Go's `SignLeaf` assigns
//! `req.PublicKey` (the *caller's public* key bytes) into a field typed
//! `ed25519.PrivateKey`; the real leaf private key is installed only by
//! `GenerateAndSignLeaf`. That upstream state cannot be persisted
//! (`persistentStateLocked` refuses a 32-byte "private key"), so this
//! port models it honestly as `leaf_key: None` — `persist` refuses an
//! incomplete authority in exactly the same state.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use central_foundation::failure::Failure;
use central_infra::port::{LeafCertificate, LeafSignRequest};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ED25519, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::FromDer as _;
use zeroize::Zeroize as _;

use super::durable::{self, PRIVATE_FILE_MODE, ensure_private_root, validate_owner};
use super::wire::{b64, sha256_hex};

const TLS_AUTHORITY_STATE_FILENAME: &str = "tls-authority.json";
const MAX_TLS_AUTHORITY_STATE_BYTES: u64 = 64 << 10;
const CA_COMMON_NAME: &str = "Central Local CA";
const LEAF_COMMON_NAME: &str = "127.0.0.1";
const CA_VALIDITY_DAYS: i64 = 365;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// DER prefix of an Ed25519 SubjectPublicKeyInfo:
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING 0x00 <key> }`.
const ED25519_SPKI_DER_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SIGALG_OID: &str = "1.3.101.112";

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_tls", msg)
}

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("broker_tls", msg)
}

/// `tlsAuthorityState` — the persisted JSON record. Field names and the
/// base64 `[]byte` encoding match upstream byte-for-byte. The record
/// holds private PKCS#8 material: it is scrubbed on drop so freed heap
/// does not retain the keys.
#[derive(Serialize, Deserialize)]
struct TlsAuthorityState {
    #[serde(with = "b64")]
    ca_key: Vec<u8>,
    #[serde(with = "b64")]
    ca_cert: Vec<u8>,
    #[serde(with = "b64")]
    leaf_key: Vec<u8>,
    #[serde(with = "b64")]
    leaf_cert: Vec<u8>,
}

impl Drop for TlsAuthorityState {
    fn drop(&mut self) {
        self.ca_key.zeroize();
        self.leaf_key.zeroize();
    }
}

struct AuthorityState {
    ca_key: KeyPair,
    ca_cert_der: Vec<u8>,
    /// Signing-side params (DN/usages/key-id method) feeding
    /// `Issuer::from_params` — rebuilt from the persisted certificate
    /// on reload so a restarted authority signs identically.
    ca_params: CertificateParams,
    leaf_key: Option<KeyPair>,
    leaf_cert_der: Option<Vec<u8>>,
}

impl AuthorityState {
    /// `persistentStateLocked` — refuse to snapshot an authority that
    /// lacks broker-owned leaf key material (upstream's
    /// incomplete-state refusal; see the module doc).
    fn persistent_state(&self) -> Result<TlsAuthorityState, Failure> {
        let leaf_key = self
            .leaf_key
            .as_ref()
            .ok_or_else(|| internal("broker: TLS authority is incomplete"))?;
        let leaf_cert = self
            .leaf_cert_der
            .as_ref()
            .ok_or_else(|| internal("broker: TLS authority is incomplete"))?;
        Ok(TlsAuthorityState {
            ca_key: self.ca_key.serialize_der(),
            ca_cert: self.ca_cert_der.clone(),
            leaf_key: leaf_key.serialize_der(),
            leaf_cert: leaf_cert.clone(),
        })
    }
}

/// `DefaultTLSAuthority` — the broker's local certificate authority.
pub struct TlsAuthority {
    inner: Mutex<AuthorityState>,
    /// `statePath` — `None` only for the isolated in-memory seam.
    state_path: Option<PathBuf>,
}

impl TlsAuthority {
    /// `NewTLSAuthority` — a fresh self-signed CA, no leaf yet.
    pub fn new() -> Result<Self, Failure> {
        Ok(Self {
            inner: Mutex::new(new_authority_state()?),
            state_path: None,
        })
    }

    /// `NewPersistentTLSAuthority` — load the durable authority under
    /// `root`, or mint CA + active leaf and publish them atomically.
    /// A present-but-unloadable state file refuses startup — only a
    /// missing file mints fresh.
    pub fn new_persistent(root: &Path) -> Result<Self, Failure> {
        ensure_private_root(root)?;
        let state_path = root.join(TLS_AUTHORITY_STATE_FILENAME);
        match durable::lstat(&state_path) {
            Ok(_) => {
                let state = load_tls_authority_state(&state_path)?;
                let authority = authority_from_state(state)?;
                return Ok(Self {
                    inner: Mutex::new(authority),
                    state_path: Some(state_path),
                });
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => {
                return Err(internal(format!(
                    "broker: inspect persistent TLS authority state: {e}"
                )));
            }
        }

        let authority = Self {
            inner: Mutex::new(new_authority_state()?),
            state_path: Some(state_path),
        };
        // A persistent authority is only usable with a broker-owned
        // active leaf — generate before publishing so a restart never
        // observes a half authority. `generate_and_sign_leaf` performs
        // the publish itself.
        authority.generate_and_sign_leaf()?;
        Ok(authority)
    }

    /// `SignLeaf` — sign a server-auth leaf over the caller's raw
    /// 32-byte Ed25519 public key. The leaf *certificate* becomes the
    /// active leaf; because the broker does not hold the private half,
    /// `leaf_key` becomes `None` — upstream's 32-byte `leafKey` state —
    /// and `persist` refuses until `generate_and_sign_leaf` installs
    /// broker-owned material again.
    pub fn sign_leaf(&self, req: &LeafSignRequest) -> Result<LeafCertificate, Failure> {
        let mut guard = lock(&self.inner)?;
        let der = sign_leaf_der(
            &guard.ca_params,
            &guard.ca_key,
            &req.public_key,
            req.not_after,
        )?;
        let fingerprint = sha256_hex(&der);
        guard.leaf_cert_der = Some(der.clone());
        guard.leaf_key = None;
        Ok(LeafCertificate {
            raw: der,
            fingerprint,
        })
    }

    /// `GenerateAndSignLeaf` — mint a broker-owned leaf key pair, sign
    /// it for the full validity window, then persist. This is the only
    /// path that installs broker-held leaf private material.
    pub fn generate_and_sign_leaf(&self) -> Result<(), Failure> {
        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| internal(format!("broker: generate leaf key: {e}")))?;
        let not_after =
            (OffsetDateTime::now_utc() + Duration::days(CA_VALIDITY_DAYS)).unix_timestamp();
        let mut guard = lock(&self.inner)?;
        let der = sign_leaf_der(
            &guard.ca_params,
            &guard.ca_key,
            leaf_key.public_key_raw(),
            not_after,
        )?;
        guard.leaf_cert_der = Some(der);
        guard.leaf_key = Some(leaf_key);
        if let Some(path) = &self.state_path {
            let state = guard.persistent_state()?;
            save_tls_authority_state(path, &state)?;
        }
        Ok(())
    }

    /// `CAFingerprint` — SHA-256 hex of the CA certificate DER.
    pub fn ca_fingerprint(&self) -> Result<String, Failure> {
        Ok(sha256_hex(&lock(&self.inner)?.ca_cert_der))
    }

    /// `LeafFingerprint` — SHA-256 hex of the active leaf DER; an error
    /// when no leaf has been signed (upstream's `no active leaf`).
    pub fn leaf_fingerprint(&self) -> Result<String, Failure> {
        let guard = lock(&self.inner)?;
        let leaf = guard
            .leaf_cert_der
            .as_ref()
            .ok_or_else(|| internal("broker: no active leaf certificate"))?;
        Ok(sha256_hex(leaf))
    }

    /// `CAPEM` — PEM-encoded CA certificate.
    pub fn ca_pem(&self) -> Result<Vec<u8>, Failure> {
        Ok(pem_encode("CERTIFICATE", &lock(&self.inner)?.ca_cert_der))
    }

    /// `LeafPEM` — PEM-encoded active leaf, or `None` when no
    /// broker-owned leaf is installed (upstream returns nil).
    pub fn leaf_pem(&self) -> Result<Option<Vec<u8>>, Failure> {
        let guard = lock(&self.inner)?;
        match (&guard.leaf_cert_der, &guard.leaf_key) {
            (Some(der), Some(_)) => Ok(Some(pem_encode("CERTIFICATE", der))),
            _ => Ok(None),
        }
    }

    /// `Rekey` — mint a complete replacement authority, persist it
    /// atomically, and only then swap the in-memory state. A publish
    /// failure leaves the prior authority live.
    pub fn rekey(&self) -> Result<(), Failure> {
        let state_path = self
            .state_path
            .as_ref()
            .ok_or_else(|| internal("broker: persistent TLS rekey is unavailable"))?
            .clone();
        let mut candidate = new_authority_state()?;
        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| internal(format!("broker: generate leaf key: {e}")))?;
        let not_after =
            (OffsetDateTime::now_utc() + Duration::days(CA_VALIDITY_DAYS)).unix_timestamp();
        candidate.leaf_cert_der = Some(sign_leaf_der(
            &candidate.ca_params,
            &candidate.ca_key,
            leaf_key.public_key_raw(),
            not_after,
        )?);
        candidate.leaf_key = Some(leaf_key);
        let state = candidate.persistent_state()?;
        save_tls_authority_state(&state_path, &state)?;
        // Publish succeeded — the swap is now safe.
        *lock(&self.inner)? = candidate;
        Ok(())
    }
}

/// Mutex guard helper — a poisoned lock is an internal failure, never a
/// panic.
fn lock(
    inner: &Mutex<AuthorityState>,
) -> Result<std::sync::MutexGuard<'_, AuthorityState>, Failure> {
    inner
        .lock()
        .map_err(|_| internal("broker: TLS authority lock poisoned"))
}

/// The shared leaf-signing path: `x509.Certificate` template parity —
/// serial 2, CN `127.0.0.1`, SAN IP `127.0.0.1`, `DigitalSignature`
/// key usage, `ServerAuth` EKU, caller-supplied `NotAfter`, no basic
/// constraints.
fn sign_leaf_der(
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
    leaf_public_key_raw: &[u8],
    not_after_unix: i64,
) -> Result<Vec<u8>, Failure> {
    if leaf_public_key_raw.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(invalid("broker: leaf public key must be raw ed25519"));
    }
    let not_after = OffsetDateTime::from_unix_timestamp(not_after_unix)
        .map_err(|_| invalid("broker: leaf not_after out of range"))?;
    let mut spki_der = Vec::with_capacity(ED25519_SPKI_DER_PREFIX.len() + 32);
    spki_der.extend_from_slice(&ED25519_SPKI_DER_PREFIX);
    spki_der.extend_from_slice(leaf_public_key_raw);
    let public_key = SubjectPublicKeyInfo::from_der(&spki_der)
        .map_err(|e| invalid(format!("broker: leaf public key: {e}")))?;

    let mut params = CertificateParams::default();
    params.serial_number = Some(SerialNumber::from_slice(&[2]));
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, LEAF_COMMON_NAME);
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = not_after;
    params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let issuer = Issuer::from_params(ca_params, ca_key);
    let cert = params
        .signed_by(&public_key, &issuer)
        .map_err(|e| internal(format!("broker: sign leaf: {e}")))?;
    Ok(cert.der().to_vec())
}

/// `NewTLSAuthority`'s CA minting — Ed25519 self-signed root, CN
/// `Central Local CA`, serial 1, ~365-day validity, `KeyCertSign` usage,
/// `basicConstraints CA:true` (upstream `IsCA + BasicConstraintsValid`).
fn new_authority_state() -> Result<AuthorityState, Failure> {
    let ca_key = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| internal(format!("broker: generate CA key: {e}")))?;
    let mut ca_params = CertificateParams::default();
    ca_params.serial_number = Some(SerialNumber::from_slice(&[1]));
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    ca_params.not_before = OffsetDateTime::now_utc();
    ca_params.not_after = OffsetDateTime::now_utc() + Duration::days(CA_VALIDITY_DAYS);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| internal(format!("broker: self-sign CA: {e}")))?;
    Ok(AuthorityState {
        ca_key,
        ca_cert_der: cert.der().to_vec(),
        ca_params,
        leaf_key: None,
        leaf_cert_der: None,
    })
}

/// The serve listener's broker-owned TLS material (B06): the active
/// leaf certificate, its private key, and the CA certificate — DER
/// only, exported out of the validated persisted state.
pub struct ServeMaterialExport {
    /// The active leaf certificate DER.
    pub leaf_cert_der: Vec<u8>,
    /// The leaf's PKCS#8 private key (zeroized on drop).
    pub leaf_key_pkcs8: PrivatePkcs8KeyDer<'static>,
    /// The CA certificate DER.
    pub ca_cert_der: Vec<u8>,
}

/// Load-only export for `central serve`: reads
/// `tls-authority.json` under `state_root` (the broker protected root),
/// re-validates the full persisted chain via [`authority_from_state`]
/// (CA shape, leaf signature, both key/cert matches), and exports the
/// DER the listener needs. Unlike [`TlsAuthority::new_persistent`] this
/// never mints — a missing state file is `broker_tls` internal, a
/// corrupt one refuses, so serve cannot silently run on a half
/// authority. The file's `0600`/owner/link-count custody checks still
/// apply, which is why only a process sharing the broker's uid may
/// take this path (dev/loopback compositions); everyone else uses the
/// provisioned `CENTRAL_TLS_ROOT` bundle (kernel `serve_tls`).
///
/// # Errors
/// `broker_tls` failures on custody, decode, or chain-validation
/// violations.
pub fn load_serve_material(state_root: &Path) -> Result<ServeMaterialExport, Failure> {
    let state = load_tls_authority_state(&state_root.join(TLS_AUTHORITY_STATE_FILENAME))?;
    let export = ServeMaterialExport {
        leaf_cert_der: state.leaf_cert.clone(),
        leaf_key_pkcs8: PrivatePkcs8KeyDer::from(state.leaf_key.clone()),
        ca_cert_der: state.ca_cert.clone(),
    };
    // The export is only released after the persisted chain validates
    // — `authority_from_state` consumes (and zeroizes) the state.
    let _ = authority_from_state(state)?;
    Ok(export)
}

/// `tlsAuthorityFromState` — re-validate the persisted authority: all
/// four fields present, CA parses and carries `CA:true`, leaf parses and
/// verifies under the CA public key, and each private key matches its
/// certificate's public key. Any mismatch refuses startup.
fn authority_from_state(state: TlsAuthorityState) -> Result<AuthorityState, Failure> {
    let corrupt = || invalid("broker: corrupt persistent TLS authority state");
    if state.ca_key.is_empty()
        || state.leaf_key.is_empty()
        || state.ca_cert.is_empty()
        || state.leaf_cert.is_empty()
    {
        return Err(corrupt());
    }
    let ca_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(state.ca_key.clone()));
    let ca_key =
        KeyPair::from_der_and_sign_algo(&ca_key_der, &PKCS_ED25519).map_err(|_| corrupt())?;
    let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(state.leaf_key.clone()));
    let leaf_key =
        KeyPair::from_der_and_sign_algo(&leaf_key_der, &PKCS_ED25519).map_err(|_| corrupt())?;

    let (_rem, ca_cert) = x509_parser::certificate::X509Certificate::from_der(&state.ca_cert)
        .map_err(|_| invalid("broker: invalid persistent TLS CA certificate"))?;
    let is_ca = ca_cert
        .basic_constraints()
        .map_err(|_| invalid("broker: invalid persistent TLS CA certificate"))?
        .is_some_and(|bc| bc.value.ca);
    if !is_ca {
        return Err(invalid("broker: invalid persistent TLS CA certificate"));
    }
    let (_rem, leaf_cert) = x509_parser::certificate::X509Certificate::from_der(&state.leaf_cert)
        .map_err(|e| {
        invalid(format!(
            "broker: invalid persistent TLS leaf certificate: {e}"
        ))
    })?;
    // `leafCert.CheckSignatureFrom(caCert)` — Ed25519 signature over the
    // leaf's TBS, verified under the CA's public key.
    verify_cert_signature(&leaf_cert, &ca_cert).map_err(|e| {
        invalid(format!(
            "broker: persistent TLS leaf is not signed by local CA: {e}"
        ))
    })?;
    // `caKey.Public().Equal(caCert.PublicKey)` / leaf equivalent.
    if ca_key.public_key_raw() != ca_cert.public_key().subject_public_key.data.as_ref() {
        return Err(invalid(
            "broker: persistent TLS CA key does not match certificate",
        ));
    }
    if leaf_key.public_key_raw() != leaf_cert.public_key().subject_public_key.data.as_ref() {
        return Err(invalid(
            "broker: persistent TLS leaf key does not match certificate",
        ));
    }
    let ca_params = ca_params_from_cert(&ca_cert)?;
    Ok(AuthorityState {
        ca_key,
        // Public certificate DER — cloned out of the zeroizing state
        // record (certificate bytes are public; only key material is
        // scrubbed on drop).
        ca_cert_der: state.ca_cert.clone(),
        ca_params,
        leaf_key: Some(leaf_key),
        leaf_cert_der: Some(state.leaf_cert.clone()),
    })
}

/// Ed25519 `CheckSignatureFrom`: the signature algorithm must be
/// Ed25519, then verify `cert.tbs` under `issuer`'s raw public key.
fn verify_cert_signature(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    issuer: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), Failure> {
    if cert.signature_algorithm.algorithm.to_id_string() != ED25519_SIGALG_OID {
        return Err(invalid("broker: certificate is not ed25519-signed"));
    }
    let public: [u8; 32] = issuer
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| invalid("broker: issuer public key is not ed25519"))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public)
        .map_err(|_| invalid("broker: issuer public key is invalid"))?;
    let signature: [u8; 64] = cert
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| invalid("broker: certificate signature length"))?;
    use ed25519_dalek::Verifier as _;
    verifying
        .verify(
            cert.tbs_certificate.as_ref(),
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| invalid("broker: certificate signature does not verify"))
}

/// Rebuild the signing-side params for `Issuer::from_params` from the
/// persisted CA certificate — same subject DN (the `CommonName`
/// attribute this authority always mints), `KeyCertSign` usage, default
/// SHA-256 key-id method — so a reloaded authority signs leaves
/// indistinguishably from a freshly minted one.
fn ca_params_from_cert(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<CertificateParams, Failure> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    for attr in cert.tbs_certificate.subject.iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            dn.push(DnType::CommonName, cn);
        }
    }
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    Ok(params)
}

/// `loadTLSAuthorityState` — `lstat` shape checks (regular, not
/// symlink, exact `0600`, owner, link count 1, `0 < size ≤ 64 KiB`),
/// then read + JSON decode.
fn load_tls_authority_state(path: &Path) -> Result<TlsAuthorityState, Failure> {
    let meta = durable::lstat(path).map_err(|e| {
        internal(format!(
            "broker: inspect persistent TLS authority state: {e}"
        ))
    })?;
    if !rustix::fs::FileType::from_raw_mode(meta.st_mode).is_file()
        || rustix::fs::FileType::from_raw_mode(meta.st_mode).is_symlink()
        || meta.st_mode & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(Failure::denied(
            "broker_tls_denied",
            "broker: insecure persistent TLS authority state",
        ));
    }
    validate_owner(&meta, "persistent TLS authority state")?;
    if meta.st_nlink != 1
        || meta.st_size == 0
        || meta.st_size > MAX_TLS_AUTHORITY_STATE_BYTES as i64
    {
        return Err(invalid("broker: invalid persistent TLS authority state"));
    }
    let data = durable::read_file(path)
        .map_err(|e| internal(format!("broker: read persistent TLS authority state: {e}")))?;
    serde_json::from_slice(&data).map_err(|e| {
        invalid(format!(
            "broker: decode persistent TLS authority state: {e}"
        ))
    })
}

/// `saveTLSAuthorityState` — marshal, bound-check, `.tls-authority-*.tmp`
/// at `0600` + fsync + close, atomic rename, dir-sync.
fn save_tls_authority_state(path: &Path, state: &TlsAuthorityState) -> Result<(), Failure> {
    let data = serde_json::to_vec(state).map_err(|e| {
        internal(format!(
            "broker: encode persistent TLS authority state: {e}"
        ))
    })?;
    if data.is_empty() || data.len() as u64 > MAX_TLS_AUTHORITY_STATE_BYTES {
        return Err(internal("broker: encode persistent TLS authority state"));
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = {
        let mut name = [0u8; 8];
        rustix::rand::getrandom(&mut name, rustix::rand::GetRandomFlags::empty())
            .map_err(|e| internal(format!("broker: tmp name entropy: {e}")))?;
        dir.join(format!(
            ".tls-authority-{}.tmp",
            super::wire::hex_encode(&name)
        ))
    };
    let result = (|| -> Result<(), Failure> {
        use std::io::Write as _;
        let mut file = durable::open_exclusive(&tmp, PRIVATE_FILE_MODE).map_err(|e| {
            internal(format!(
                "broker: create persistent TLS authority state: {e}"
            ))
        })?;
        file.write_all(&data)
            .and_then(|()| file.sync_all())
            .map_err(|e| internal(format!("broker: write persistent TLS authority state: {e}")))?;
        drop(file);
        super::durable::rename_replace(&tmp, path)
    })();
    if result.is_err() {
        let _ = durable::remove_file(&tmp);
    }
    result?;
    super::durable::sync_dir(dir)
}

/// `pem.EncodeToMemory(&pem.Block{Type: tag, Bytes: der})` — 64-column
/// base64 lines between the BEGIN/END markers.
fn pem_encode(tag: &str, der: &[u8]) -> Vec<u8> {
    const LINE: usize = 64;
    let b64 = super::wire::b64_encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(tag);
    out.push_str("-----\n");
    let mut i = 0;
    while i < b64.len() {
        let end = usize::min(i + LINE, b64.len());
        out.push_str(&b64[i..end]);
        out.push('\n');
        i = end;
    }
    out.push_str("-----END ");
    out.push_str(tag);
    out.push_str("-----\n");
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// central_infra::port::TlsAuthority — the async port boundary
// ---------------------------------------------------------------------------

impl central_infra::port::TlsAuthority for TlsAuthority {
    async fn sign_leaf(&self, request: LeafSignRequest) -> Result<LeafCertificate, Failure> {
        Self::sign_leaf(self, &request)
    }
    async fn ca_fingerprint(&self) -> Result<String, Failure> {
        Self::ca_fingerprint(self)
    }
    async fn leaf_fingerprint(&self) -> Result<String, Failure> {
        Self::leaf_fingerprint(self)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("central-tls-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// PEM body → DER for test verification.
    fn pem_decode(pem: &[u8]) -> Vec<u8> {
        let text = String::from_utf8(pem.to_vec()).unwrap();
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        super::super::wire::b64_decode(&body).unwrap()
    }

    #[test]
    fn new_authority_has_ca_no_leaf() {
        let authority = TlsAuthority::new().unwrap();
        assert_eq!(authority.ca_fingerprint().unwrap().len(), 64);
        assert!(authority.leaf_fingerprint().is_err());
        assert!(authority.leaf_pem().unwrap().is_none());
    }

    #[test]
    fn sign_leaf_issues_server_auth_cert() {
        let authority = TlsAuthority::new().unwrap();
        let leaf_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let not_after = (OffsetDateTime::now_utc() + Duration::days(30)).unix_timestamp();
        let cert = authority
            .sign_leaf(&LeafSignRequest {
                public_key: leaf_key.public_key_raw().to_vec(),
                not_after,
            })
            .unwrap();
        assert_eq!(cert.fingerprint, authority.leaf_fingerprint().unwrap());
        let (_rem, parsed) =
            x509_parser::certificate::X509Certificate::from_der(&cert.raw).unwrap();
        // SAN 127.0.0.1, server-auth EKU, signature verifies under the CA.
        let sans = parsed.subject_alternative_name().unwrap().unwrap();
        assert!(sans.value.general_names.iter().any(|n| matches!(
            n,
            x509_parser::extensions::GeneralName::IPAddress(b) if *b == [127, 0, 0, 1]
        )));
        let ca_der = pem_decode(&authority.ca_pem().unwrap());
        let (_r, ca) = x509_parser::certificate::X509Certificate::from_der(&ca_der).unwrap();
        verify_cert_signature(&parsed, &ca).unwrap();
        // Public-key-signed leaf leaves no broker-held leaf key.
        assert!(authority.leaf_pem().unwrap().is_none());
        // Wrong-length public keys refuse before signing.
        assert!(
            authority
                .sign_leaf(&LeafSignRequest {
                    public_key: vec![0u8; 31],
                    not_after,
                })
                .is_err()
        );
    }

    #[test]
    fn persistent_authority_survives_restart_and_rekeys_durably() {
        let dir = temp_dir("persist");
        let authority = TlsAuthority::new_persistent(&dir).unwrap();
        let ca_fp = authority.ca_fingerprint().unwrap();
        let leaf_fp = authority.leaf_fingerprint().unwrap();
        assert!(dir.join(TLS_AUTHORITY_STATE_FILENAME).exists());
        assert_eq!(
            fs::metadata(dir.join(TLS_AUTHORITY_STATE_FILENAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Restart: identical fingerprints.
        let reloaded = TlsAuthority::new_persistent(&dir).unwrap();
        assert_eq!(ca_fp, reloaded.ca_fingerprint().unwrap());
        assert_eq!(leaf_fp, reloaded.leaf_fingerprint().unwrap());
        assert!(reloaded.leaf_pem().unwrap().is_some());
        // Rekey replaces both, durably.
        reloaded.rekey().unwrap();
        assert_ne!(ca_fp, reloaded.ca_fingerprint().unwrap());
        let restarted = TlsAuthority::new_persistent(&dir).unwrap();
        assert_eq!(
            restarted.ca_fingerprint().unwrap(),
            reloaded.ca_fingerprint().unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_state_refuses_restart() {
        let dir = temp_dir("corrupt");
        let authority = TlsAuthority::new_persistent(&dir).unwrap();
        drop(authority);
        // Tamper with the persisted leaf cert — signature checks must
        // refuse the state, not mint a fresh authority.
        let path = dir.join(TLS_AUTHORITY_STATE_FILENAME);
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let leaf_cert =
            super::super::wire::b64_decode(state["leaf_cert"].as_str().unwrap()).unwrap();
        let mut tampered = leaf_cert;
        tampered[10] ^= 0xff;
        state["leaf_cert"] = serde_json::Value::String(super::super::wire::b64_encode(&tampered));
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(TlsAuthority::new_persistent(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn insecure_state_file_rejected() {
        let dir = temp_dir("insecure");
        let authority = TlsAuthority::new_persistent(&dir).unwrap();
        drop(authority);
        let path = dir.join(TLS_AUTHORITY_STATE_FILENAME);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(TlsAuthority::new_persistent(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_and_sign_leaf_installs_broker_owned_material() {
        let dir = temp_dir("genleaf");
        let authority = TlsAuthority::new_persistent(&dir).unwrap();
        // Sign an external key → the broker no longer holds the leaf key.
        let foreign = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        authority
            .sign_leaf(&LeafSignRequest {
                public_key: foreign.public_key_raw().to_vec(),
                not_after: (OffsetDateTime::now_utc() + Duration::days(1)).unix_timestamp(),
            })
            .unwrap();
        assert!(authority.leaf_pem().unwrap().is_none());
        // Regenerating installs broker-owned material again and persists.
        authority.generate_and_sign_leaf().unwrap();
        assert!(authority.leaf_pem().unwrap().is_some());
        let reloaded = TlsAuthority::new_persistent(&dir).unwrap();
        assert_eq!(
            authority.leaf_fingerprint().unwrap(),
            reloaded.leaf_fingerprint().unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
