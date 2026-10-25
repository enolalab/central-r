//! `xdg.rs` — signed, safe XDG projections.
//!
//! The broker produces read-only configuration/diagnostic views for
//! consumers that live outside its custody boundary — the central
//! runtime, task agents, and the operator CLI — which read them from
//! XDG directories (`$XDG_CONFIG_HOME`, `$XDG_RUNTIME_DIR`). Because
//! those consumers cannot authenticate the broker socket, integrity is
//! carried in-band: every projection is Ed25519-signed over its
//! JCS-canonical unsigned form by the broker's signer, and consumers
//! verify the signature plus the generation floor before trusting a
//! byte.
//!
//! Custody invariants:
//!
//! - **No secrets ever cross.** The view body is denied outright (at
//!   both sign and verify time) when any key or string value carries a
//!   secret marker — private-key blocks, `ca_key`/`leaf_key`/
//!   `private_seed_hex`, password/token/credential keys. A view that
//!   fails the scan is refused, never silently signed. [`redact_view`]
//!   exists for building views: it replaces sensitive-keyed values
//!   with `"[redacted]"`, but the signer still enforces the scan — a
//!   redaction miss is a denial, not a leak.
//! - **Generation-bound.** A projection carries a monotonic
//!   `generation`; verification takes a `min_generation` floor and
//!   rejects older projections so a stale, correctly-signed file
//!   cannot roll a consumer back after rotation.
//! - **Signature domain.** The signature covers the JCS-canonical
//!   bytes of the unsigned record (`kind`, `recipient`, `generation`,
//!   `issued_at`, `view`) — never the transport representation.
//! - **Filesystem shape.** Projections publish `0644` (consumers run
//!   under other UIDs by design) via tmp-write, fsync, rename, and a
//!   directory fsync; loading bounds the file at 64 KiB before decode.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::signing::{Ed25519Signer, sign_canonical_json, verify_canonical_json_hex};
use super::wire;

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_xdg", msg)
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_xdg", msg)
}

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("broker_xdg", msg)
}

/// `central.projected-config/v1` — the safe runtime/agent
/// configuration view.
pub const PROJECTED_CONFIG_KIND: &str = "central.projected-config/v1";

/// `central.projected-diagnostic/v1` — the safe diagnostic view.
pub const PROJECTED_DIAGNOSTIC_KIND: &str = "central.projected-diagnostic/v1";

/// Bound on a serialized projection — same ceiling upstream gives the
/// TLS authority state file.
pub const MAX_PROJECTION_BYTES: usize = 64 << 10;

/// The projection's intended reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// The central runtime process.
    Runtime,
    /// A task agent inside a workspace.
    Agent,
    /// The operator CLI.
    Operator,
}

impl Recipient {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Agent => "agent",
            Self::Operator => "operator",
        }
    }
}

/// `XdgProjection` — one signed projection record. `signature_hex`
/// signs the JCS-canonical form of every other field (the `bx1Unsigned`
/// pattern: the signature signs the *record*, not a transport blob).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdgProjection {
    /// `central.projected-config/v1` | `central.projected-diagnostic/v1`.
    pub kind: String,
    /// `runtime` | `agent` | `operator`.
    pub recipient: String,
    /// Monotonic projection generation.
    pub generation: u64,
    /// RFC3339Nano issue time.
    #[serde(with = "wire::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// The safe view body — arbitrary JSON that passed the marker scan.
    pub view: serde_json::Value,
    /// Ed25519 signature over the canonical unsigned record.
    pub signature_hex: String,
}

impl XdgProjection {
    /// The unsigned record — every field but `signature_hex` — as a
    /// `serde_json::Value` for canonical signing/verification.
    fn unsigned(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "recipient": self.recipient,
            "generation": self.generation,
            "issued_at": wire::format_rfc3339_nano(self.issued_at),
            "view": self.view,
        })
    }
}

/// Secret markers refused anywhere inside a view — key names and
/// string content alike. The content list mirrors upstream
/// `ScanProtectedSubset`'s `deniedContent`; the key list refuses the
/// *key vocabulary* a credential would need.
const DENIED_KEY_MARKERS: &[&str] = &[
    "private_key",
    "secret",
    "password",
    "token",
    "credential",
    "ca_key",
    "leaf_key",
    "private_seed_hex",
    "seed",
    "api_key",
];

/// The literal placeholder `redact_view` writes and the marker scan
/// accepts under a sensitive key.
const REDACTED: &str = "[redacted]";

const DENIED_CONTENT_MARKERS: &[&str] = &["PRIVATE KEY", "ca_key", "leaf_key", "private_seed_hex"];

fn key_is_denied(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    DENIED_KEY_MARKERS.iter().any(|m| lower.contains(m))
}

fn value_has_denied_content(v: &str) -> bool {
    DENIED_CONTENT_MARKERS.iter().any(|m| v.contains(m))
}

/// `assert_view_safe` — the recursive marker scan every view passes
/// before signing and every verified projection passes before a
/// consumer trusts it. Returns `denied` naming nothing sensitive —
/// the refusal mentions only *where* in the shape the marker sat.
pub fn assert_view_safe(view: &serde_json::Value) -> Result<(), Failure> {
    match view {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                // A denied key is admitted only when its value is the
                // literal redaction placeholder — every other payload
                // under a sensitive name refuses.
                if key_is_denied(k) && v != &serde_json::Value::String(REDACTED.to_owned()) {
                    return Err(denied("broker: projection view carries a secret marker"));
                }
                assert_view_safe(v)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for v in items {
                assert_view_safe(v)?;
            }
            Ok(())
        }
        serde_json::Value::String(s) => {
            if value_has_denied_content(s) {
                return Err(denied("broker: projection view carries a secret marker"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `redact_view` — build a safe view from a wider config value by
/// replacing every sensitive-keyed value with `"[redacted]"`,
/// recursively. Signing still runs the marker scan afterwards: the
/// redactor is a convenience, not the guard.
#[must_use]
pub fn redact_view(view: &serde_json::Value) -> serde_json::Value {
    match view {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if key_is_denied(k) {
                    out.insert(k.clone(), serde_json::Value::String(REDACTED.to_owned()));
                } else {
                    out.insert(k.clone(), redact_view(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_view).collect())
        }
        serde_json::Value::String(s) if value_has_denied_content(s) => {
            serde_json::Value::String(REDACTED.to_owned())
        }
        other => other.clone(),
    }
}

/// `XdgSigner` — issues and verifies signed projections with the
/// broker's Ed25519 signer.
pub struct XdgSigner {
    signer: Arc<Ed25519Signer>,
}

impl XdgSigner {
    /// Wrap the broker signer.
    #[must_use]
    pub fn new(signer: Arc<Ed25519Signer>) -> Self {
        Self { signer }
    }

    /// The hex public key consumers pin as the trust key.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.signer.public_key_hex()
    }

    /// `issue` — refuse unsafe views, then sign the canonical unsigned
    /// record.
    pub fn issue(
        &self,
        kind: &str,
        recipient: Recipient,
        generation: u64,
        view: serde_json::Value,
        issued_at: OffsetDateTime,
    ) -> Result<XdgProjection, Failure> {
        if kind != PROJECTED_CONFIG_KIND && kind != PROJECTED_DIAGNOSTIC_KIND {
            return Err(invalid("broker: unknown projection kind"));
        }
        if generation == 0 {
            return Err(invalid("broker: projection generation required"));
        }
        assert_view_safe(&view)?;
        let mut projection = XdgProjection {
            kind: kind.to_owned(),
            recipient: recipient.as_str().to_owned(),
            generation,
            issued_at,
            view,
            signature_hex: String::new(),
        };
        projection.signature_hex =
            sign_canonical_json(self.signer.signing_key(), &projection.unsigned())?;
        Ok(projection)
    }

    /// `verify` — shape, generation floor, marker scan, then the
    /// canonical signature. Order mirrors upstream's verify ladders:
    /// the cheap shape checks precede the signature verification.
    pub fn verify(&self, projection: &XdgProjection, min_generation: u64) -> Result<(), Failure> {
        verify_projection(projection, &self.public_key_hex(), min_generation)
    }
}

/// `verify` — signature and generation verification against a caller-
/// supplied trust key (the hex Ed25519 public key the consumer pinned).
/// A wrong trust key is a denial, same as a bad signature.
pub fn verify_projection(
    projection: &XdgProjection,
    trust_key_hex: &str,
    min_generation: u64,
) -> Result<(), Failure> {
    if projection.kind != PROJECTED_CONFIG_KIND && projection.kind != PROJECTED_DIAGNOSTIC_KIND {
        return Err(denied("broker: unknown projection kind"));
    }
    match projection.recipient.as_str() {
        "runtime" | "agent" | "operator" => {}
        _ => return Err(denied("broker: unknown projection recipient")),
    }
    if projection.generation == 0 || projection.generation < min_generation {
        return Err(denied("broker: projection generation below floor"));
    }
    if projection.signature_hex.is_empty() {
        return Err(denied("broker: projection unsigned"));
    }
    // Marker scan BEFORE signature verification: a signed view carrying
    // secret markers is refused regardless of who signed it.
    assert_view_safe(&projection.view)?;
    verify_canonical_json_hex(
        trust_key_hex,
        &projection.signature_hex,
        &projection.unsigned(),
    )
}

/// `write_projection` — tmp `0644` write, fsync, rename, dir fsync.
/// `0644` not `0600`: the projection's consumers are other UIDs by
/// design, and the marker scan guarantees nothing secret is in it.
pub fn write_projection(path: &Path, projection: &XdgProjection) -> Result<(), Failure> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let data = serde_json::to_vec_pretty(projection)
        .map_err(|e| internal(format!("broker: marshal projection: {e}")))?;
    if data.len() > MAX_PROJECTION_BYTES {
        return Err(internal("broker: projection exceeds bound"));
    }
    let tmp = {
        let mut p = path.as_os_str().to_owned();
        p.push(".tmp");
        PathBuf::from(p)
    };
    let write_result = (|| -> Result<(), Failure> {
        use std::os::unix::fs::PermissionsExt as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .custom_flags(libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| internal(format!("broker: write {}: {e}", tmp.display())))?;
        file.write_all(&data)
            .and_then(|()| file.sync_all())
            .map_err(|e| internal(format!("broker: write {}: {e}", tmp.display())))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
            .map_err(|e| internal(format!("broker: secure {}: {e}", tmp.display())))?;
        fs::rename(&tmp, path)
            .map_err(|e| internal(format!("broker: publish {}: {e}", path.display())))?;
        let dir = path
            .parent()
            .ok_or_else(|| internal("broker: projection path has no parent"))?;
        super::durable::sync_dir(dir)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

/// `load_and_verify` — read a projection file (≤ 64 KiB), decode it
/// strictly, and run [`verify_projection`].
pub fn load_and_verify(
    path: &Path,
    trust_key_hex: &str,
    min_generation: u64,
) -> Result<XdgProjection, Failure> {
    let data = fs::read(path).map_err(|e| internal(format!("broker: read projection: {e}")))?;
    if data.is_empty() || data.len() > MAX_PROJECTION_BYTES {
        return Err(invalid("broker: projection size out of bounds"));
    }
    let projection: XdgProjection = serde_json::from_slice(&data)
        .map_err(|e| invalid(format!("broker: decode projection: {e}")))?;
    verify_projection(&projection, trust_key_hex, min_generation)?;
    Ok(projection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;

    fn signer() -> XdgSigner {
        XdgSigner::new(Arc::new(Ed25519Signer::new().unwrap()))
    }

    fn view() -> serde_json::Value {
        serde_json::json!({
            "instance": {"id": "inst-1", "listen": "127.0.0.1:7749"},
            "features": {"backup": true, "restore": true},
        })
    }

    #[test]
    fn issue_verify_round_trip() {
        let s = signer();
        let p = s
            .issue(
                PROJECTED_CONFIG_KIND,
                Recipient::Runtime,
                3,
                view(),
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        assert_eq!(p.recipient, "runtime");
        s.verify(&p, 3).unwrap();
        s.verify(&p, 1).unwrap(); // newer-than-floor is fine
        // Stale floor denies.
        assert!(s.verify(&p, 4).is_err());
        // Foreign key denies.
        let other = Ed25519Signer::new().unwrap();
        assert!(verify_projection(&p, &other.public_key_hex(), 1).is_err());
    }

    #[test]
    fn tamper_breaks_signature() {
        let s = signer();
        let mut p = s
            .issue(
                PROJECTED_CONFIG_KIND,
                Recipient::Agent,
                1,
                view(),
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        p.generation = 99;
        assert!(s.verify(&p, 1).is_err());
        let mut p2 = s
            .issue(
                PROJECTED_CONFIG_KIND,
                Recipient::Agent,
                1,
                view(),
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        p2.view["features"]["backup"] = serde_json::Value::Bool(false);
        assert!(s.verify(&p2, 1).is_err());
    }

    #[test]
    fn secret_markers_refuse_signing_and_verification() {
        let s = signer();
        for bad in [
            serde_json::json!({"tls": {"private_key": "x"}}),
            serde_json::json!({"nested": [{"db_password": "x"}]}),
            serde_json::json!({"note": "-----BEGIN PRIVATE KEY-----"}),
            serde_json::json!({"blob": "ca_key material"}),
        ] {
            assert!(
                s.issue(
                    PROJECTED_CONFIG_KIND,
                    Recipient::Runtime,
                    1,
                    bad,
                    OffsetDateTime::now_utc(),
                )
                .is_err()
            );
        }
        // A signed projection cannot be smuggled past the verify scan:
        // craft one by signing directly (bypassing issue's refusal).
        let bad_view = serde_json::json!({"x": "leaf_key bytes"});
        let mut p = XdgProjection {
            kind: PROJECTED_CONFIG_KIND.to_owned(),
            recipient: "operator".to_owned(),
            generation: 1,
            issued_at: OffsetDateTime::now_utc(),
            view: bad_view,
            signature_hex: String::new(),
        };
        p.signature_hex = sign_canonical_json(s.signer.signing_key(), &p.unsigned()).unwrap();
        // Well-formed signature over an unsafe view still denies.
        assert!(s.verify(&p, 1).is_err());
    }

    #[test]
    fn redact_view_produces_signable_view() {
        let s = signer();
        let raw = serde_json::json!({
            "listen": "127.0.0.1:7749",
            "db_password": "hunter2",
            "nested": {"api_key": "k", "keep": "v"},
            "leaf": "-----BEGIN PRIVATE KEY-----\nxxx"
        });
        let safe = redact_view(&raw);
        assert_eq!(safe["db_password"], serde_json::json!("[redacted]"));
        assert_eq!(safe["nested"]["api_key"], serde_json::json!("[redacted]"));
        assert_eq!(safe["nested"]["keep"], serde_json::json!("v"));
        s.issue(
            PROJECTED_CONFIG_KIND,
            Recipient::Operator,
            2,
            safe,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    }

    #[test]
    fn write_load_round_trip_and_stale_floor() {
        let dir = TempDir::new("xdg");
        let s = signer();
        let p = s
            .issue(
                PROJECTED_DIAGNOSTIC_KIND,
                Recipient::Operator,
                7,
                view(),
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        let path = dir.join("central.projected-diagnostic.v1.json");
        write_projection(&path, &p).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let loaded = load_and_verify(&path, &s.public_key_hex(), 7).unwrap();
        assert_eq!(loaded, p);
        // Wrong trust key refuses the same bytes.
        let other = Ed25519Signer::new().unwrap();
        assert!(load_and_verify(&path, &other.public_key_hex(), 1).is_err());
        // Stale floor refuses.
        assert!(load_and_verify(&path, &s.public_key_hex(), 8).is_err());
        // Corrupt file refuses.
        fs::write(&path, b"{}").unwrap();
        assert!(load_and_verify(&path, &s.public_key_hex(), 1).is_err());
    }

    #[test]
    fn generation_zero_and_unknown_kind_refuse() {
        let s = signer();
        assert!(
            s.issue(
                PROJECTED_CONFIG_KIND,
                Recipient::Runtime,
                0,
                view(),
                OffsetDateTime::now_utc(),
            )
            .is_err()
        );
        assert!(
            s.issue(
                "central.evil/v1",
                Recipient::Runtime,
                1,
                view(),
                OffsetDateTime::now_utc(),
            )
            .is_err()
        );
    }
}
