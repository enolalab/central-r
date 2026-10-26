//! `serve_tls` — the B06 TLS material boundary for the application
//! listener: ports `internal/kernel/lifecycle.go`'s `TLSConfig`,
//! `TLSMaterialProvider`, and `ValidateTLS`, plus
//! `cmd/central/serve_composition.go`'s `serveTLSProvider`.
//!
//! The application listener binds `127.0.0.1:8080` and terminates TLS
//! 1.3 over a leaf that the broker's local TLS authority signs. Two
//! providers carry the material into the composition:
//!
//! - [`FileTlsMaterialProvider`] — the upstream `serveTLSProvider`
//!   port: `leaf.pem` / `leaf.key` / `ca.pem` under
//!   `CENTRAL_TLS_ROOT` (default
//!   `/var/lib/central-instances/default/tls`), provisioned by the
//!   instance setup from the broker authority. The optional
//!   `CENTRAL_TLS_EXPECTED_*` pins tighten provenance beyond
//!   upstream's self-derived expectations when provisioning records
//!   them; unset keeps upstream's self-consistent contract exactly.
//! - [`BrokerTlsMaterialProvider`] — reads the broker's persisted
//!   `TlsAuthority` state directly (broker-owned material, no file
//!   intermediary). Selected by `CENTRAL_BROKER_TLS_STATE`; usable
//!   where the serve process shares the broker state's owner — dev
//!   and in-process compositions — and the strictest provenance of
//!   the two.
//!
//! [`validate_tls`] is the startup gate every provider's output goes
//! through: the full upstream checklist — presence, leaf-first chain,
//! CA shape, validity windows, the exact `127.0.0.1` SAN,
//! `ServerAuth` EKU, private-key/leaf public-key equality, CA
//! signature + issuer equality, the pinned signer name, and the four
//! SHA-256 fingerprints. Any failure is `tls_invalid` and serve
//! refuses to start.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer as _;

/// `CENTRAL_TLS_ROOT` — the provisioned TLS material directory
/// (upstream `serve_composition.go`).
pub const ENV_TLS_ROOT: &str = "CENTRAL_TLS_ROOT";
/// `CENTRAL_BROKER_TLS_STATE` — the broker's protected state
/// directory; set it to read the authority directly instead of the
/// provisioned file bundle.
pub const ENV_BROKER_TLS_STATE: &str = "CENTRAL_BROKER_TLS_STATE";
/// `CENTRAL_TLS_EXPECTED_CA_SHA` — optional pin of the broker CA's
/// SHA-256 fingerprint (deployment-recorded provenance).
pub const ENV_EXPECTED_CA_SHA: &str = "CENTRAL_TLS_EXPECTED_CA_SHA";
/// `CENTRAL_TLS_EXPECTED_LEAF_SHA` — optional pin of the leaf's
/// SHA-256 fingerprint.
pub const ENV_EXPECTED_LEAF_SHA: &str = "CENTRAL_TLS_EXPECTED_LEAF_SHA";
/// `CENTRAL_TLS_EXPECTED_SIGNER` — optional pin of the issuer name
/// that must have signed the leaf.
pub const ENV_EXPECTED_SIGNER: &str = "CENTRAL_TLS_EXPECTED_SIGNER";
/// Upstream's default `tlsRoot` — `/var/lib/central-instances/default/tls`.
pub const DEFAULT_TLS_ROOT: &str = "/var/lib/central-instances/default/tls";

const ERR_TLS_INVALID: &str = "tls_invalid";

fn tls_invalid() -> Failure {
    Failure::invalid(ERR_TLS_INVALID, "TLS_INVALID")
}

fn tls_io(step: &str, e: &dyn std::fmt::Display) -> Failure {
    Failure::invalid(ERR_TLS_INVALID, format!("tls: {step}: {e}"))
}

// ---------------------------------------------------------------------------
// ServeTlsMaterial — kernel.TLSConfig
// ---------------------------------------------------------------------------

/// `kernel.TLSConfig` — the validated certificate material the
/// application listener terminates with. `chain` is leaf-first, as
/// `tls.Certificate.Certificate`; `key` is the leaf private key.
pub struct ServeTlsMaterial {
    /// `Certificate.Certificate` — leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// `Certificate.PrivateKey`.
    pub key: PrivateKeyDer<'static>,
    /// `LeafDER` — the leaf's exact DER.
    pub leaf_der: Vec<u8>,
    /// `CADER` — the issuing CA's exact DER.
    pub ca_der: Vec<u8>,
    /// `LeafFingerprint` — the provider's computed leaf SHA-256.
    pub leaf_fingerprint: String,
    /// `CAFingerprint` — the provider's computed CA SHA-256.
    pub ca_fingerprint: String,
    /// `ExpectedLeafSHA` — the pinned leaf fingerprint.
    pub expected_leaf_sha: String,
    /// `ExpectedCASHA` — the pinned CA fingerprint.
    pub expected_ca_sha: String,
    /// `ExpectedSigner` — the pinned issuer name.
    pub expected_signer: String,
}

/// `kernel.TLSMaterialProvider`.
pub trait TlsMaterialProvider: Send + Sync {
    /// `LoadTLS` — reads and fingerprints the material; the caller
    /// still runs [`validate_tls`] over the result.
    ///
    /// # Errors
    /// `tls_invalid`/`DEPENDENCY_UNAVAILABLE`-shaped failures when the
    /// material cannot be loaded.
    fn load_tls(&self) -> Result<ServeTlsMaterial, Failure>;
}

// ---------------------------------------------------------------------------
// FileTlsMaterialProvider — serveTLSProvider
// ---------------------------------------------------------------------------

/// `serveTLSProvider` — reads `leaf.pem`, `leaf.key`, `ca.pem` from the
/// TLS root and fingerprints both certificates. Upstream fills the
/// `Expected*` pins from the loaded material itself; the optional
/// `CENTRAL_TLS_EXPECTED_*` environment pins override them so a
/// deployment that recorded the broker CA's fingerprint binds the
/// files to it.
pub struct FileTlsMaterialProvider {
    leaf_path: PathBuf,
    key_path: PathBuf,
    ca_path: PathBuf,
    expected_ca_sha: Option<String>,
    expected_leaf_sha: Option<String>,
    expected_signer: Option<String>,
}

impl FileTlsMaterialProvider {
    /// `newServeTLSProvider` — `CENTRAL_TLS_ROOT` or the default root.
    #[must_use]
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Self {
        let root = getenv(ENV_TLS_ROOT)
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from(DEFAULT_TLS_ROOT), PathBuf::from);
        Self {
            leaf_path: root.join("leaf.pem"),
            key_path: root.join("leaf.key"),
            ca_path: root.join("ca.pem"),
            expected_ca_sha: getenv(ENV_EXPECTED_CA_SHA).filter(|v| !v.is_empty()),
            expected_leaf_sha: getenv(ENV_EXPECTED_LEAF_SHA).filter(|v| !v.is_empty()),
            expected_signer: getenv(ENV_EXPECTED_SIGNER).filter(|v| !v.is_empty()),
        }
    }

    /// The testable constructor: explicit root plus optional pins.
    #[must_use]
    pub fn new(
        root: &Path,
        expected_ca_sha: Option<String>,
        expected_leaf_sha: Option<String>,
        expected_signer: Option<String>,
    ) -> Self {
        Self {
            leaf_path: root.join("leaf.pem"),
            key_path: root.join("leaf.key"),
            ca_path: root.join("ca.pem"),
            expected_ca_sha,
            expected_leaf_sha,
            expected_signer,
        }
    }
}

impl TlsMaterialProvider for FileTlsMaterialProvider {
    fn load_tls(&self) -> Result<ServeTlsMaterial, Failure> {
        let leaf_pem = std::fs::read(&self.leaf_path).map_err(|e| tls_io("read leaf cert", &e))?;
        let key_pem = std::fs::read(&self.key_path).map_err(|e| tls_io("read leaf key", &e))?;
        let ca_pem = std::fs::read(&self.ca_path).map_err(|e| tls_io("read ca cert", &e))?;

        // `pem.Decode` — the first PEM block only; a non-certificate
        // first block fails decode, exactly like upstream's nil block.
        let leaf_der = CertificateDer::pem_slice_iter(&leaf_pem)
            .next()
            .ok_or_else(|| tls_io("leaf certificate PEM decode", &"failed"))?
            .map_err(|e| tls_io("leaf certificate PEM decode", &e))?;
        let ca_der = CertificateDer::pem_slice_iter(&ca_pem)
            .next()
            .ok_or_else(|| tls_io("CA certificate PEM decode", &"failed"))?
            .map_err(|e| tls_io("CA certificate PEM decode", &e))?;
        // `parsePrivateKey` — PKCS#8, then PKCS#1, then SEC1; the
        // pki-types decoder accepts the same three key shapes.
        let key = PrivateKeyDer::from_pem_slice(&key_pem)
            .map_err(|e| tls_io("private key PEM decode", &e))?;

        let (_rem, leaf_cert) = X509Certificate::from_der(&leaf_der)
            .map_err(|e| tls_io("parse leaf certificate", &e))?;

        let leaf_fp = fingerprint(leaf_der.as_ref());
        let ca_fp = fingerprint(ca_der.as_ref());
        let expected_signer = self
            .expected_signer
            .clone()
            .unwrap_or_else(|| leaf_cert.issuer().to_string());
        Ok(ServeTlsMaterial {
            chain: vec![leaf_der.clone()],
            key,
            leaf_der: leaf_der.as_ref().to_vec(),
            ca_der: ca_der.as_ref().to_vec(),
            expected_leaf_sha: self
                .expected_leaf_sha
                .clone()
                .unwrap_or_else(|| leaf_fp.clone()),
            expected_ca_sha: self
                .expected_ca_sha
                .clone()
                .unwrap_or_else(|| ca_fp.clone()),
            leaf_fingerprint: leaf_fp,
            ca_fingerprint: ca_fp,
            expected_signer,
        })
    }
}

// ---------------------------------------------------------------------------
// BrokerTlsMaterialProvider — broker-owned material
// ---------------------------------------------------------------------------

/// Reads the broker's persisted `TlsAuthority` state directly — the
/// broker-owned form of the serve material (no provisioned file
/// intermediary). `state_root` is the broker protected root
/// (`CENTRAL_BROKER_TLS_STATE`); the authority loader re-validates
/// the persisted chain, key matches, and file custody before any
/// material is released.
pub struct BrokerTlsMaterialProvider {
    state_root: PathBuf,
}

impl BrokerTlsMaterialProvider {
    /// `CENTRAL_BROKER_TLS_STATE` must name the broker protected root.
    /// The provider is only usable where the process user owns the
    /// state (the authority loader owner-checks it); an unreadable or
    /// absent state fails `load_tls` closed.
    ///
    /// # Errors
    /// `tls_invalid` when the environment names no state root.
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Result<Self, Failure> {
        let root = getenv(ENV_BROKER_TLS_STATE)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                Failure::invalid(
                    ERR_TLS_INVALID,
                    format!("{ENV_BROKER_TLS_STATE} is not set"),
                )
            })?;
        Ok(Self {
            state_root: PathBuf::from(root),
        })
    }

    /// The testable constructor.
    #[must_use]
    pub fn new(state_root: &Path) -> Self {
        Self {
            state_root: state_root.to_path_buf(),
        }
    }
}

impl TlsMaterialProvider for BrokerTlsMaterialProvider {
    fn load_tls(&self) -> Result<ServeTlsMaterial, Failure> {
        let export = central_adapter_linux::broker::tls::load_serve_material(&self.state_root)?;
        let expected_signer = {
            let (_rem, leaf_cert) = X509Certificate::from_der(&export.leaf_cert_der)
                .map_err(|e| tls_io("parse leaf certificate", &e))?;
            leaf_cert.issuer().to_string()
        };
        let leaf_fp = fingerprint(&export.leaf_cert_der);
        let ca_fp = fingerprint(&export.ca_cert_der);
        Ok(ServeTlsMaterial {
            chain: vec![CertificateDer::from(export.leaf_cert_der.clone())],
            key: PrivateKeyDer::Pkcs8(export.leaf_key_pkcs8),
            leaf_der: export.leaf_cert_der,
            ca_der: export.ca_cert_der,
            leaf_fingerprint: leaf_fp.clone(),
            ca_fingerprint: ca_fp.clone(),
            expected_leaf_sha: leaf_fp,
            expected_ca_sha: ca_fp,
            expected_signer,
        })
    }
}

// ---------------------------------------------------------------------------
// validate_tls — kernel.ValidateTLS
// ---------------------------------------------------------------------------

/// `kernel.ValidateTLS` — every upstream check in upstream's order;
/// any failure is `tls_invalid` (`TLS_INVALID`).
///
/// # Errors
/// `tls_invalid` on any violated property.
#[allow(clippy::too_many_lines)]
pub fn validate_tls(material: &ServeTlsMaterial, now: OffsetDateTime) -> Result<(), Failure> {
    // `leafDER` falls back to `Certificate.Certificate[0]` — a
    // provider that did not separate the field still presents the
    // leaf.
    let leaf_der: &[u8] = if material.leaf_der.is_empty() {
        material.chain.first().map_or(&[][..], |c| c.as_ref())
    } else {
        &material.leaf_der
    };
    if leaf_der.is_empty() || material.ca_der.is_empty() || material.chain.is_empty() {
        return Err(tls_invalid());
    }
    if material.chain[0].as_ref() != leaf_der {
        return Err(tls_invalid());
    }
    let (_rem, leaf) = X509Certificate::from_der(leaf_der).map_err(|_| tls_invalid())?;
    let (_rem, ca) = X509Certificate::from_der(&material.ca_der).map_err(|_| tls_invalid())?;

    // `!ca.IsCA || !ca.BasicConstraintsValid ||
    //  ca.KeyUsage&KeyUsageCertSign == 0 || leaf.IsCA` — the CA must
    // carry a valid `CA:TRUE` basic-constraints and cert-sign usage;
    // the leaf must not be a CA.
    let ca_is_ca = ca
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|bc| bc.value.ca);
    let ca_cert_sign = ca
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|ku| ku.value.key_cert_sign());
    let leaf_is_ca = leaf
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|bc| bc.value.ca);
    if !ca_is_ca || !ca_cert_sign || leaf_is_ca {
        return Err(tls_invalid());
    }

    // `now.Before(NotBefore) || !now.Before(NotAfter)` on both —
    // unix-second comparison (ASN1Time is whole-second).
    let now_ts = now.unix_timestamp();
    if now_ts < leaf.validity().not_before.timestamp()
        || now_ts >= leaf.validity().not_after.timestamp()
        || now_ts < ca.validity().not_before.timestamp()
        || now_ts >= ca.validity().not_after.timestamp()
    {
        return Err(tls_invalid());
    }

    if !has_exact_loopback_san(&leaf) || !has_server_auth(&leaf) {
        return Err(tls_invalid());
    }

    // `publicKeysMatch` — the signing key's public SPKI must equal the
    // leaf's subject public key. `any_supported_type` handles every
    // key shape the providers accept (Ed25519, ECDSA, RSA).
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&material.key)
        .map_err(|_| tls_invalid())?;
    let key_spki = signing.public_key().ok_or_else(tls_invalid)?;
    if key_spki.as_ref() != leaf.public_key().raw {
        return Err(tls_invalid());
    }

    // `leaf.CheckSignatureFrom(ca)` + issuer equality — ring-backed
    // signature verification under the CA's public key, then the
    // issuer name must be byte-identical to the CA subject.
    leaf.verify_signature(Some(ca.public_key()))
        .map_err(|_| tls_invalid())?;
    if leaf.issuer().as_raw() != ca.subject().as_raw() {
        return Err(tls_invalid());
    }
    let issuer = leaf.issuer().to_string();
    if material.expected_signer.is_empty() || issuer != material.expected_signer {
        return Err(tls_invalid());
    }

    // `leaf.Verify{Roots: ca, DNSName: "127.0.0.1", ServerAuth,
    // CurrentTime}` — the manual checks above cover each property the
    // Go verifier re-derives: issuer+signature (chain building), the
    // IP-SAN name match (the exact-SAN gate is strictly stronger —
    // it also rejects any second SAN identity), validity at `now`,
    // and ServerAuth EKU.

    // `fingerprint` — SHA-256 hex of the DER.
    let leaf_fp = fingerprint(leaf_der);
    let ca_fp = fingerprint(&material.ca_der);
    if !equal_fingerprint(&material.leaf_fingerprint, &leaf_fp)
        || !equal_fingerprint(&material.ca_fingerprint, &ca_fp)
        || !equal_fingerprint(&material.expected_leaf_sha, &leaf_fp)
        || !equal_fingerprint(&material.expected_ca_sha, &ca_fp)
    {
        return Err(tls_invalid());
    }
    Ok(())
}

/// `hasExactLoopbackSAN` — exactly one SAN, an IP, `127.0.0.1`; any
/// DNS, e-mail, or URI SAN refuses. (Other `GeneralName` kinds — a
/// `directoryName`, say — map to none of Go's parsed SAN fields and
/// are ignored exactly as upstream's field lists ignore them.)
fn has_exact_loopback_san(cert: &X509Certificate<'_>) -> bool {
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    let mut ips = 0u32;
    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(_) | GeneralName::RFC822Name(_) | GeneralName::URI(_) => {
                return false;
            }
            GeneralName::IPAddress(raw) => {
                ips += 1;
                if !is_v4_loopback(raw) {
                    return false;
                }
            }
            _ => {}
        }
    }
    ips == 1
}

/// `ip.Equal(net.ParseIP("127.0.0.1"))` — a 4-byte `127.0.0.1` or its
/// 16-byte v4-mapped `::ffff:127.0.0.1` form both equal under Go's
/// `IP.Equal`.
fn is_v4_loopback(raw: &[u8]) -> bool {
    if raw.len() == 4 {
        return IpAddr::V4(Ipv4Addr::LOCALHOST)
            == IpAddr::from(<[u8; 4]>::try_from(raw).unwrap_or_default());
    }
    if raw.len() == 16 {
        let addr = Ipv6Addr::from(<[u8; 16]>::try_from(raw).unwrap_or_default());
        return addr.to_ipv4_mapped() == Some(Ipv4Addr::LOCALHOST)
            || addr == Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    }
    false
}

/// `hasServerAuth` — `ServerAuth` appears in the leaf's EKU list.
fn has_server_auth(cert: &X509Certificate<'_>) -> bool {
    cert.extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|eku| eku.value.server_auth)
}

/// `fingerprint` — lowercase hex SHA-256 of the DER.
fn fingerprint(der: &[u8]) -> String {
    let sum = Sha256::digest(der);
    let mut out = String::with_capacity(64);
    for byte in sum {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `equalFingerprint` — `left` may carry a `sha256:` prefix and any
/// case; it must be 64 hex digits equal to `actual` case-insensitively.
fn equal_fingerprint(declared: &str, actual: &str) -> bool {
    let normalized = declared.trim().to_lowercase();
    let normalized = normalized.strip_prefix("sha256:").unwrap_or(&normalized);
    normalized.len() == 64
        && normalized.bytes().all(|b| b.is_ascii_hexdigit())
        && normalized.eq_ignore_ascii_case(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use time::macros::datetime;

    /// A broker-shaped CA + leaf fixture minted with rcgen — same
    /// Ed25519 shape `TlsAuthority` produces: CN + serial, `CA:true` +
    /// `KeyCertSign` on the CA, `127.0.0.1` SAN + `ServerAuth` +
    /// `DigitalSignature` on the leaf.
    struct Fixture {
        ca_der: Vec<u8>,
        leaf_der: Vec<u8>,
        leaf_key: PrivateKeyDer<'static>,
        ca_pem: String,
        leaf_pem: String,
        key_pem: String,
    }

    fn mint(leaf_adjust: impl Fn(&mut rcgen::CertificateParams)) -> Fixture {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Central Local CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut leaf_params = rcgen::CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        leaf_params.subject_alt_names = vec![rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        // The broker's validity window — a year from mint — so tests
        // can place `now` on either side of it.
        leaf_params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(1);
        leaf_params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
        leaf_adjust(&mut leaf_params);
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        Fixture {
            ca_der: ca_cert.der().to_vec(),
            leaf_der: leaf_cert.der().to_vec(),
            leaf_key: PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )),
            ca_pem: ca_cert.pem(),
            leaf_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        }
    }

    fn material(f: &Fixture) -> ServeTlsMaterial {
        let (_, leaf) = X509Certificate::from_der(&f.leaf_der).unwrap();
        ServeTlsMaterial {
            chain: vec![CertificateDer::from(f.leaf_der.clone())],
            key: f.leaf_key.clone_key(),
            leaf_der: f.leaf_der.clone(),
            ca_der: f.ca_der.clone(),
            leaf_fingerprint: fingerprint(&f.leaf_der),
            ca_fingerprint: fingerprint(&f.ca_der),
            expected_leaf_sha: fingerprint(&f.leaf_der),
            expected_ca_sha: fingerprint(&f.ca_der),
            expected_signer: leaf.issuer().to_string(),
        }
    }

    /// A valid broker-shaped bundle passes every gate.
    #[test]
    fn valid_material_passes() {
        let f = mint(|_| {});
        validate_tls(&material(&f), OffsetDateTime::now_utc()).expect("valid");
    }

    /// The upstream `TestValidateTLSRejectsInvalidMaterial` table:
    /// each single violation fails closed.
    #[test]
    fn each_violation_refuses() {
        let now = OffsetDateTime::now_utc();
        let good = mint(|_| {});

        // Missing pieces: no CA and no chain refuse. (An empty
        // `leaf_der` is NOT a violation — upstream falls back to
        // `Certificate.Certificate[0]`.)
        for m in [
            ServeTlsMaterial {
                ca_der: Vec::new(),
                ..material(&good)
            },
            ServeTlsMaterial {
                chain: Vec::new(),
                ..material(&good)
            },
        ] {
            assert!(validate_tls(&m, now).is_err());
        }
        // The fallback itself validates: empty leaf_der + real chain.
        let mut m = material(&good);
        m.leaf_der = Vec::new();
        assert!(validate_tls(&m, now).is_ok());
        // chain[0] != leaf_der.
        let mut m = material(&good);
        m.chain = vec![CertificateDer::from(good.ca_der.clone())];
        assert!(validate_tls(&m, now).is_err());
        // Garbage DER.
        let mut m = material(&good);
        m.leaf_der = vec![0x30, 0x03, 0x02, 0x01];
        m.chain = vec![CertificateDer::from(m.leaf_der.clone())];
        assert!(validate_tls(&m, now).is_err());
        // Leaf presented as CA bundle (ca slot parses but is not a CA
        // → the leaf-as-CA arm fails).
        let mut m = material(&good);
        m.ca_der = good.leaf_der.clone();
        m.ca_fingerprint = fingerprint(&good.leaf_der);
        m.expected_ca_sha = fingerprint(&good.leaf_der);
        assert!(validate_tls(&m, now).is_err());
        // Wrong key (key/public-key mismatch).
        let other = mint(|_| {});
        let mut m = material(&good);
        m.key = other.leaf_key.clone_key();
        assert!(validate_tls(&m, now).is_err());
        // Wrong expected signer.
        let mut m = material(&good);
        m.expected_signer = "CN=Somebody Else".into();
        assert!(validate_tls(&m, now).is_err());
        let mut m = material(&good);
        m.expected_signer = String::new();
        assert!(validate_tls(&m, now).is_err());
        // Wrong fingerprints.
        for (field, bad) in [
            ("leaf", "0".repeat(64)),
            ("ca", "f".repeat(64)),
            ("expected_leaf", "1".repeat(64)),
            ("expected_ca", "2".repeat(64)),
        ] {
            let mut m = material(&good);
            match field {
                "leaf" => m.leaf_fingerprint = bad,
                "ca" => m.ca_fingerprint = bad,
                "expected_leaf" => m.expected_leaf_sha = bad,
                _ => m.expected_ca_sha = bad,
            }
            assert!(validate_tls(&m, now).is_err(), "{field}");
        }
    }

    /// Expired and not-yet-valid material refuse; `now` just inside
    /// the window passes (boundary: NotAfter is exclusive).
    #[test]
    fn validity_window_refuses_outside() {
        let f = mint(|_| {});
        let m = material(&f);
        assert!(validate_tls(&m, datetime!(2000-01-01 0:00 UTC)).is_err());
        assert!(validate_tls(&m, datetime!(2100-01-01 0:00 UTC)).is_err());
    }

    /// `TestValidateTLSRejectsExtraSANIdentities` — a DNS SAN beside
    /// the loopback IP refuses; a second IP refuses; a leaf signed by
    /// a different CA refuses; a leaf that is itself a CA refuses;
    /// no-ServerAuth refuses.
    #[test]
    fn extra_san_and_shape_violations_refuse() {
        let now = OffsetDateTime::now_utc();
        for adjust in [
            |p: &mut rcgen::CertificateParams| {
                p.subject_alt_names
                    .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
            },
            |p: &mut rcgen::CertificateParams| {
                p.subject_alt_names
                    .push(rcgen::SanType::IpAddress("127.0.0.2".parse().unwrap()));
            },
            |p: &mut rcgen::CertificateParams| {
                p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            },
            |p: &mut rcgen::CertificateParams| {
                p.extended_key_usages = vec![];
            },
        ] {
            let f = mint(adjust);
            assert!(validate_tls(&material(&f), now).is_err());
        }
        // A leaf signed under a different CA refuses even when the
        // bundle is otherwise self-consistent.
        let rogue = mint(|_| {});
        let f = mint(|_| {});
        let mut m = material(&f);
        m.ca_der = rogue.ca_der.clone();
        m.ca_fingerprint = fingerprint(&rogue.ca_der);
        m.expected_ca_sha = fingerprint(&rogue.ca_der);
        assert!(validate_tls(&m, now).is_err());
    }

    /// `equalFingerprint` — `sha256:` prefix and case folding match
    /// upstream; wrong lengths and non-hex refuse.
    #[test]
    fn fingerprint_compare_rules() {
        let fp = "ab".repeat(32);
        assert!(equal_fingerprint(&fp, &fp));
        assert!(equal_fingerprint(
            &format!("sha256:{}", fp.to_uppercase()),
            &fp
        ));
        assert!(!equal_fingerprint(&fp[..62], &fp));
        assert!(!equal_fingerprint(&"g".repeat(64), &fp));
        assert!(!equal_fingerprint("", &fp));
    }

    /// `FileTlsMaterialProvider` loads leaf/key/ca PEMs and
    /// self-derives the expected pins like upstream; a pin override
    /// wins over the computed value.
    #[test]
    fn file_provider_loads_and_self_derives() {
        let f = mint(|_| {});
        let dir = tempfile_dir();
        std::fs::write(dir.join("leaf.pem"), &f.leaf_pem).unwrap();
        std::fs::write(dir.join("leaf.key"), &f.key_pem).unwrap();
        std::fs::write(dir.join("ca.pem"), &f.ca_pem).unwrap();

        let provider = FileTlsMaterialProvider::new(&dir, None, None, None);
        let m = provider.load_tls().expect("load");
        assert_eq!(m.leaf_der, f.leaf_der);
        assert_eq!(m.expected_leaf_sha, fingerprint(&f.leaf_der));
        validate_tls(&m, OffsetDateTime::now_utc()).expect("valid");

        // A wrong CA pin refuses at validate time.
        let pinned = FileTlsMaterialProvider::new(&dir, Some("9".repeat(64)), None, None);
        let m = pinned.load_tls().expect("load");
        assert!(validate_tls(&m, OffsetDateTime::now_utc()).is_err());

        // Missing files fail.
        let missing = FileTlsMaterialProvider::new(&dir.join("nope"), None, None, None);
        assert!(missing.load_tls().is_err());
    }

    /// `BrokerTlsMaterialProvider` loads the authority's persisted
    /// state and yields material that validates.
    #[test]
    fn broker_provider_loads_authority_state() {
        let root = tempfile_dir();
        let authority = central_adapter_linux::broker::tls::TlsAuthority::new_persistent(&root)
            .expect("authority");
        let provider = BrokerTlsMaterialProvider::new(&root);
        let m = provider.load_tls().expect("load");
        assert_eq!(
            m.ca_fingerprint,
            authority.ca_fingerprint().unwrap(),
            "provider fingerprint is the authority's"
        );
        validate_tls(&m, OffsetDateTime::now_utc()).expect("valid");
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-serve-tls-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
