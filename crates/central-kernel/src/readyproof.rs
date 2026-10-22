//! The supervisor ready proof — ports `internal/kernel/readyproof.go`.
//!
//! [`ReadyProof`] is the opaque supervisor status message that authorizes a
//! single serve launch to proceed with browser open. It binds the launch
//! ID, a 256-bit nonce, and the expiry at which the proof must be revoked.
//!
//! A proof is issued only after the listeners are bound, migration and
//! epoch checks pass, the serving-data pool is ready, and a dedicated
//! non-borrowable `central_runtime` control connection holds the target
//! shared lock for the entire serve profile (the listener/TLS/control-lock
//! stages land with the R3 serve composition). The nonce is redacted in
//! every formatted and serialized representation; `launch_id` and
//! `expires_at` are safe to expose because they are an opaque
//! broker-assigned identifier and an absolute timestamp.

use std::fmt;

use central_foundation::failure::Failure;
use serde::{Serialize, Serializer};
use time::OffsetDateTime;

use crate::BoxFuture;

/// The opaque supervisor status message authorizing one serve launch.
///
/// The `nonce` field is public only so adapters and tests can carry the
/// exact value; it is never rendered by [`fmt::Display`] or [`Serialize`].
#[derive(Debug, Clone)]
pub struct ReadyProof {
    /// Opaque broker-assigned launch identifier.
    pub launch_id: String,
    /// The runtime generation admitted for this launch (equals
    /// `launch_id` for kernel-issued proofs).
    pub runtime_generation: String,
    /// 256-bit proof nonce. Never formatted or serialized.
    pub nonce: [u8; 32],
    /// Absolute expiry at which the proof must be revoked.
    pub expires_at: OffsetDateTime,
}

impl ReadyProof {
    /// Reports whether two proofs share the same `launch_id`,
    /// `runtime_generation`, and `nonce` using a constant-time nonce
    /// comparison. `expires_at` is intentionally not considered; callers
    /// compare it separately via [`Self::is_expired`].
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        if self.launch_id != other.launch_id || self.runtime_generation != other.runtime_generation
        {
            return false;
        }
        // XOR-fold over all 32 bytes: no early exit, no data-dependent
        // branching — the Rust port of `crypto/subtle.ConstantTimeCompare`.
        let mut diff = 0u8;
        for (left, right) in self.nonce.iter().zip(other.nonce.iter()) {
            diff |= left ^ right;
        }
        diff == 0
    }

    /// Reports whether the proof is expired relative to `reference`. The
    /// comparison never formats the nonce.
    #[must_use]
    pub fn is_expired(&self, reference: OffsetDateTime) -> bool {
        self.expires_at <= reference
    }
}

impl fmt::Display for ReadyProof {
    /// Redacted representation suitable for logs and diagnostics; never
    /// contains the nonce.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ready_proof:{}:generation={}:exp={}:redacted",
            self.launch_id,
            self.runtime_generation,
            self.expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        )
    }
}

impl Serialize for ReadyProof {
    /// Opaque JSON representation: `{launch_id, runtime_generation,
    /// expires_at, redacted}` — the nonce is never serialized.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Rendered<'a> {
            launch_id: &'a str,
            runtime_generation: &'a str,
            expires_at: String,
            redacted: bool,
        }
        Rendered {
            launch_id: &self.launch_id,
            runtime_generation: &self.runtime_generation,
            expires_at: self
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            redacted: true,
        }
        .serialize(serializer)
    }
}

/// Builds a fresh proof for `launch_id` expiring `ttl` after `now`.
///
/// Rejects an empty launch ID and a non-positive TTL — the composition
/// root must never publish a proof it cannot bind or one that is already
/// expired.
///
/// # Errors
/// [`central_foundation::failure::FailureKind::Invalid`] on an empty
/// launch ID or non-positive TTL.
pub fn new_ready_proof(
    launch_id: &str,
    now: OffsetDateTime,
    ttl: std::time::Duration,
) -> Result<ReadyProof, Failure> {
    if launch_id.is_empty() {
        return Err(Failure::invalid(
            "kernel_launch_id_required",
            "kernel: launch ID is required",
        ));
    }
    if ttl.is_zero() {
        return Err(Failure::invalid(
            "kernel_proof_ttl_invalid",
            "kernel: ready proof TTL must be positive",
        ));
    }
    let ttl = time::Duration::try_from(ttl).map_err(|_| {
        Failure::invalid(
            "kernel_proof_ttl_invalid",
            "kernel: ready proof TTL is outside the representable range",
        )
    })?;
    let nonce: [u8; 32] = rand::random();
    Ok(ReadyProof {
        launch_id: launch_id.to_string(),
        runtime_generation: launch_id.to_string(),
        nonce,
        expires_at: now + ttl,
    })
}

/// Generates the broker-assigned runtime launch ID
/// (`central-runtime-<unix-nanos>-<128-bit nonce>`).
#[must_use]
pub fn new_runtime_launch_id(now: OffsetDateTime) -> String {
    let nonce: [u8; 16] = rand::random();
    let mut hex = String::with_capacity(32);
    for byte in nonce {
        // Single-byte formatting keeps this dependency-free.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("central-runtime-{}-{hex}", now.unix_timestamp_nanos())
}

// ---------------------------------------------------------------------------
// Typed failure contracts
// ---------------------------------------------------------------------------

/// Classifies a kernel readiness failure for safe mapping to CLI exit
/// codes and operations-health reason classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReadyFailureClass {
    /// The proof expired before browser open.
    Expired = 1,
    /// The proof was revoked due to shutdown, control-lock loss, epoch
    /// mismatch, or terminal component failure.
    Revoked = 2,
    /// The presented proof did not match the currently issued proof.
    Mismatch = 3,
}

impl ReadyFailureClass {
    /// Safe, stable reason code (matches upstream `String()`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "READY_EXPIRED",
            Self::Revoked => "READY_REVOKED",
            Self::Mismatch => "READY_MISMATCH",
        }
    }
}

impl fmt::Display for ReadyFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed kernel readiness failure returned to the helper browser-open
/// path, the bootstrap-show path, and operations health. It carries only
/// an opaque class, a safe reason, remediation copy, and an optional
/// source error kept solely for downcast/source matching — the formatted
/// representation never renders the source, so a cause that happens to
/// contain secret material cannot leak through it.
#[derive(Debug)]
pub struct ReadyFailure {
    class: ReadyFailureClass,
    reason: String,
    remediation: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl ReadyFailure {
    /// Builds a readiness failure. `reason` and `remediation` must
    /// already be redacted, bounded operator copy.
    pub fn new(
        class: ReadyFailureClass,
        reason: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            class,
            reason: reason.into(),
            remediation: remediation.into(),
            source: None,
        }
    }

    /// The sentinel-equivalent constructors: callers classify through
    /// [`Self::class`] the same way upstream callers match
    /// `errors.Is(err, ErrReadyExpired/Revoked/Mismatch)` sentinels.
    pub fn expired() -> Self {
        Self::new(
            ReadyFailureClass::Expired,
            "kernel: ready proof expired",
            "",
        )
    }
    /// See [`Self::expired`].
    pub fn revoked() -> Self {
        Self::new(
            ReadyFailureClass::Revoked,
            "kernel: ready proof revoked",
            "",
        )
    }
    /// See [`Self::expired`].
    pub fn mismatch() -> Self {
        Self::new(
            ReadyFailureClass::Mismatch,
            "kernel: ready proof mismatch",
            "",
        )
    }

    /// Returns a copy of `self` with `source` attached for
    /// [`std::error::Error::source`] matching. The source is never
    /// formatted.
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The failure class.
    #[must_use]
    pub const fn class(&self) -> ReadyFailureClass {
        self.class
    }

    /// The redacted reason copy.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The bounded remediation copy (may be empty).
    #[must_use]
    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

impl fmt::Display for ReadyFailure {
    /// `kernel:{CLASS}` or `kernel:{CLASS}:{remediation}` — never
    /// contains the nonce, the cause text, or any derivable substring.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.remediation.is_empty() {
            write!(f, "kernel:{}", self.class)
        } else {
            write!(f, "kernel:{}:{}", self.class, self.remediation)
        }
    }
}

impl std::error::Error for ReadyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

// ---------------------------------------------------------------------------
// Ready-proof publication port
// ---------------------------------------------------------------------------

/// Kernel-owned port that transfers the short-lived proof to the
/// privileged helper boundary. Implementations must store it only in
/// protected state. The lifecycle mirrors upstream
/// `kernel.ReadyProofPublisher`:
///
/// - [`begin_startup`](Self::begin_startup) serializes this process's
///   entire proof lifecycle; it is taken before singleton admission and
///   remains held until [`revoke_if_generation`](Self::revoke_if_generation)
///   or [`abort_startup`](Self::abort_startup) releases it.
/// - [`revoke`](Self::revoke) removes any previously published proof; the
///   kernel calls it only after admission to the deployment singleton
///   while the `begin_startup` guard is still held.
/// - [`revoke_if_generation`](Self::revoke_if_generation) removes the
///   proof only when the currently published runtime generation equals
///   the supplied value, so a fenced-out predecessor cannot erase its
///   successor; it also releases the `begin_startup` guard.
/// - [`abort_startup`](Self::abort_startup) releases a `begin_startup`
///   guard without deleting a proof, used when admission or startup
///   fails before publication.
///
/// The trait is kernel-owned and object-safe; the helper-side adapter
/// (a protected-state adapter, not `central-adapter-postgres`) supplies
/// the concrete implementation when the R5 boundary lands.
pub trait ReadyProofPublisher: Send + 'static {
    /// Takes the startup-serialization guard.
    fn begin_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>>;
    /// Publishes `proof` to protected state.
    fn publish(&mut self, proof: ReadyProof) -> BoxFuture<'_, Result<(), Failure>>;
    /// Removes any previously published proof regardless of generation.
    fn revoke(&mut self) -> BoxFuture<'_, Result<(), Failure>>;
    /// Removes the proof only when `generation` matches the currently
    /// published runtime generation; releases the startup guard.
    fn revoke_if_generation(&mut self, generation: String) -> BoxFuture<'_, Result<(), Failure>>;
    /// Releases the startup guard without deleting a published proof.
    fn abort_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn fixed_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        nonce
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

    // Canonical B06 boundary test: String/JSON/ReadyFailure-wrapped
    // representations never contain the nonce while still exposing the
    // safe LaunchID and ExpiresAt.
    #[test]
    fn ready_proof_never_formats_plaintext() {
        let nonce = fixed_nonce();
        let leak = hex_encode(&nonce);
        let proof = ReadyProof {
            launch_id: "launch-abc".to_string(),
            runtime_generation: "launch-abc".to_string(),
            nonce,
            expires_at: datetime!(2026-07-22 12:00:00 UTC),
        };

        let rendered = proof.to_string();
        assert!(!rendered.contains(&leak), "Display leaked nonce");
        assert!(!rendered.contains(String::from_utf8_lossy(&nonce).as_ref()));
        assert!(rendered.contains("launch-abc"), "Display dropped launch id");
        assert!(rendered.contains("redacted"));

        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains(&leak), "Serialize leaked nonce: {json}");
        assert!(json.contains("\"launch_id\":\"launch-abc\""));
        assert!(json.contains("\"runtime_generation\":\"launch-abc\""));
        assert!(json.contains("\"redacted\":true"));
    }

    #[test]
    fn ready_proof_expiry_and_constant_time_equal() {
        let nonce = fixed_nonce();
        let future = datetime!(2099-01-01 0:00:00 UTC);
        let past = datetime!(2000-01-01 0:00:00 UTC);
        let reference = datetime!(2026-07-22 0:00:00 UTC);

        let expired = ReadyProof {
            launch_id: "l".into(),
            runtime_generation: "l".into(),
            nonce,
            expires_at: past,
        };
        let current = ReadyProof {
            expires_at: future,
            ..expired.clone()
        };
        assert!(expired.is_expired(reference));
        assert!(!current.is_expired(reference));
        // Boundary: expires exactly at reference counts as expired.
        let at_reference = ReadyProof {
            expires_at: reference,
            ..expired.clone()
        };
        assert!(at_reference.is_expired(reference));

        assert!(current.equal(&current.clone()));
        let other = ReadyProof {
            nonce: [0u8; 32],
            ..current.clone()
        };
        assert!(!current.equal(&other));
        let other_launch = ReadyProof {
            launch_id: "different".into(),
            ..current.clone()
        };
        assert!(!current.equal(&other_launch));
    }

    #[test]
    fn ready_failure_is_stable_and_never_formats_source() {
        let leak = "0102030405";

        struct Sensitive(String);
        impl fmt::Display for Sensitive {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "sensitive:{}", self.0)
            }
        }
        impl std::error::Error for Sensitive {}
        impl fmt::Debug for Sensitive {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        let failure = ReadyFailure::new(
            ReadyFailureClass::Expired,
            "ready proof expired",
            "restart serve",
        )
        .with_source(Sensitive(leak.to_string()));
        let rendered = failure.to_string();
        assert!(!rendered.contains(leak));
        assert_eq!(rendered, "kernel:READY_EXPIRED:restart serve");
        assert_eq!(failure.class(), ReadyFailureClass::Expired);
        assert!(std::error::Error::source(&failure).is_some());

        let bare = ReadyFailure::expired();
        assert_eq!(bare.to_string(), "kernel:READY_EXPIRED");
        assert!(std::error::Error::source(&bare).is_none());
    }

    #[test]
    fn new_ready_proof_validates_inputs() {
        let now = datetime!(2026-07-22 12:00:00 UTC);
        assert!(new_ready_proof("", now, std::time::Duration::from_secs(300)).is_err());
        assert!(new_ready_proof("l", now, std::time::Duration::ZERO).is_err());
        let proof = new_ready_proof("l", now, std::time::Duration::from_secs(300)).unwrap();
        assert_eq!(proof.launch_id, "l");
        assert_eq!(proof.runtime_generation, "l");
        assert_eq!(proof.expires_at, now + time::Duration::minutes(5));
        assert!(!proof.is_expired(now));
    }

    #[test]
    fn runtime_launch_id_shape() {
        let now = datetime!(2026-07-22 12:00:00 UTC);
        let id = new_runtime_launch_id(now);
        assert!(id.starts_with("central-runtime-"));
        assert!(id.contains(&now.unix_timestamp_nanos().to_string()));
        // Suffix is 32 lowercase hex chars (128-bit nonce).
        let suffix = id.rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(suffix.chars().all(|c| !c.is_ascii_uppercase()));
        assert_ne!(new_runtime_launch_id(now), new_runtime_launch_id(now));
    }
}
