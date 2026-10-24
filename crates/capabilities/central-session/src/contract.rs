//! `central-session` contracts — the opaque bootstrap verifier, candidate
//! binding, request identity, pre-auth CSRF pair, and the typed failure
//! contract consumed by the session service, the `ProtectedBootstrap`
//! implementations, the PostgreSQL adapter, the transport, and the kernel.
//! Port of upstream `internal/session/contract.go`.
//!
//! Design boundary: the transport holds plaintext only request-scoped,
//! long enough to derive the versioned verifier through the narrow
//! fingerprint path. Domain, controller, helper, logs, Events, and
//! database errors receive only the opaque representations declared in
//! this file. The `Display`, `Debug`, and `Failure` `Error` paths of
//! every type in this file are audited to never contain plaintext,
//! digest, or credential material.
//!
//! Upstream divergence notes:
//!
//! - Upstream compares digests with `crypto/subtle.ConstantTimeCompare`.
//!   `subtle` is not a workspace dependency, so this crate carries
//!   [`ct_eq`], a constant-time comparison over fixed 32-byte inputs
//!   (every comparison site operates on `[u8; 32]` pairs — the input
//!   lengths are equal by construction and never secret-dependent).
//! - Upstream's `errors.Is`/`errors.As` traversal is modelled by
//!   [`Failure::is_sentinel`] + [`Failure::as_failure`]; `errors.Join`
//!   maps to [`Joined`]. `FailureClass` maps the Go `int` zero value
//!   ("UNKNOWN") to `None` so an untyped adapter failure keeps
//!   upstream's non-`Failure` shape.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use zeroize::Zeroizing;

/// `ct_eq` — constant-time equality over equal-length byte slices.
/// Returns `false` immediately when the lengths differ (every call site
/// compares fixed 32-byte digests/hashes, so the length is public).
#[must_use]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `BootstrapVerifierVersion` — the fingerprint algorithm version bound
/// to a [`BootstrapVerifier`]. The version is safe to expose in logs and
/// diagnostics; the digest is not.
pub type BootstrapVerifierVersion = u8;

/// `BootstrapVerifierV1` — the current SHA-256 fingerprint version.
pub const BOOTSTRAP_VERIFIER_V1: BootstrapVerifierVersion = 1;

/// `BootstrapVerifier` — the opaque, versioned verifier derived from a
/// presented bootstrap token. The transport holds the plaintext only
/// long enough to derive the verifier through the narrow fingerprint
/// path; domain, controller, helper, logs, Events, and database errors
/// receive only opaque representations of this value.
#[derive(Clone)]
pub struct BootstrapVerifier {
    version: BootstrapVerifierVersion,
    digest: Zeroizing<[u8; 32]>,
}

impl BootstrapVerifier {
    /// `NewBootstrapVerifier` — constructs a verifier from a versioned
    /// digest. The caller (the narrow fingerprint path) is responsible
    /// for ensuring the digest is the only representation of the
    /// plaintext that escapes the request scope.
    #[must_use]
    pub fn new(version: BootstrapVerifierVersion, digest: [u8; 32]) -> Self {
        Self {
            version,
            digest: Zeroizing::new(digest),
        }
    }

    /// The fingerprint algorithm version. Safe to log.
    #[must_use]
    pub const fn version(&self) -> BootstrapVerifierVersion {
        self.version
    }

    /// The verifier digest. Reachable only by code that already owns the
    /// verifier (the session store comparison path and the broker
    /// activator that matches it against registered evidence). It never
    /// appears in logs, Events, or database errors.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// `IsZero` — whether the verifier is the zero value. Used to detect
    /// missing verifiers without formatting the digest.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.version == 0 && *self.digest == [0u8; 32]
    }

    /// `DigestEqual` — whether the verifier's digest equals `stored`
    /// (the persisted verifier hash) using a constant-time comparison.
    /// A wrong-length `stored` is a mismatch. It never formats either
    /// side.
    #[must_use]
    pub fn digest_equal(&self, stored: &[u8]) -> bool {
        ct_eq(self.digest(), stored)
    }

    /// `Equal` — whether two verifiers carry the same version and digest
    /// using a constant-time comparison. It never formats either digest.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self.version == other.version && ct_eq(&self.digest[..], &other.digest[..])
    }
}

impl fmt::Display for BootstrapVerifier {
    /// Redacted representation suitable for logs and diagnostics. It
    /// never contains the digest or any derivable substring.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bootstrap_verifier:v{}:redacted", self.version)
    }
}

impl fmt::Debug for BootstrapVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// `CandidateBinding` — the broker-issued identity of the current
/// bootstrap candidate: its UUID, the generation monotonic counter, and
/// the candidate digest. The broker accepts activation only when all
/// three match the registered evidence exactly.
///
/// `candidate_id` and `generation` are safe to expose in diagnostics
/// because they are opaque broker-assigned identifiers unrelated to
/// plaintext. The `digest` is redacted in every formatted
/// representation.
#[derive(Clone)]
pub struct CandidateBinding {
    /// Opaque broker-assigned candidate identity — canonical UUID text.
    pub candidate_id: String,
    /// Monotonic generation counter.
    pub generation: u64,
    /// The registered candidate digest — redacted everywhere.
    pub digest: Zeroizing<[u8; 32]>,
}

impl CandidateBinding {
    /// `Equal` — whether two bindings identify the same candidate using
    /// a constant-time digest comparison.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self.candidate_id == other.candidate_id
            && self.generation == other.generation
            && ct_eq(&self.digest[..], &other.digest[..])
    }

    /// Upstream `validCandidateBinding` — the shape the broker/dev
    /// registry requires before it stores evidence: a non-empty
    /// candidate id, a positive generation, and a non-zero digest.
    /// (The PostgreSQL store additionally requires `candidate_id` to
    /// parse as a UUID — upstream `validCandidate`.)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.candidate_id.is_empty() && self.generation > 0 && *self.digest != [0u8; 32]
    }
}

impl fmt::Display for CandidateBinding {
    /// Redacted representation. The digest is never formatted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "candidate_binding:{}:gen={}:redacted",
            self.candidate_id, self.generation
        )
    }
}

impl fmt::Debug for CandidateBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// `RequestIdentity` — the request-scoped caller identity that the
/// session capability binds to a bootstrap exchange. It records only
/// the loopback peer identity and the exact validated `Origin`; no
/// token, cookie, credential, or digest value is reachable from this
/// type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdentity {
    /// Loopback peer uid.
    pub peer_uid: u32,
    /// Loopback peer pid.
    pub peer_pid: i32,
    /// Exact raw `Origin` validated by the transport guard.
    pub origin: String,
}

impl RequestIdentity {
    /// `Equal` — whether two identities reference the same peer and
    /// origin.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self == other
    }
}

impl fmt::Display for RequestIdentity {
    /// Safe diagnostic representation. Peer identity is already part of
    /// the broker's caller fingerprint (see the authority domain) and
    /// is safe to log; no secret material is included. This is also the
    /// `principal_identity` text persisted on session rows, so the
    /// format is a wire contract (`internal/session/contract.go`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "request_identity:peer={}:{}:origin={}",
            self.peer_uid, self.peer_pid, self.origin
        )
    }
}

/// `PreAuthCSRF` — the unauthenticated double-submit CSRF material
/// issued before bootstrap exchange. `value` is the cookie/header value
/// presented by the browser (transport-scoped, never persisted); `hash`
/// is `SHA-256(value)`, the form persisted in PostgreSQL session rows
/// and compared on subsequent state-changing requests.
///
/// Both `value` and `hash` are redacted in every formatted
/// representation, and `value` is zeroized on drop. Accessors are
/// exposed only for the narrow transport validation path and the
/// session store comparison path.
#[derive(Clone)]
pub struct PreAuthCSRF {
    value: Zeroizing<[u8; 32]>,
    hash: [u8; 32],
}

impl PreAuthCSRF {
    /// `NewPreAuthCSRF` — constructs a pre-auth CSRF pair from the
    /// presented value and its persisted hash.
    #[must_use]
    pub fn new(value: [u8; 32], hash: [u8; 32]) -> Self {
        Self {
            value: Zeroizing::new(value),
            hash,
        }
    }

    /// The zero pair — upstream `PreAuthCSRF{}`.
    #[must_use]
    pub fn zero() -> Self {
        Self::new([0u8; 32], [0u8; 32])
    }

    /// The presented cookie/header value. Reachable only by code that
    /// already owns the CSRF pair. Never appears in logs, Events, or
    /// database errors.
    #[must_use]
    pub fn value(&self) -> [u8; 32] {
        *self.value
    }

    /// The persisted hash form. Reachable by the session store for row
    /// comparison; never formatted.
    #[must_use]
    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Whether the pair is the zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self.value == [0u8; 32] && self.hash == [0u8; 32]
    }

    /// `Equal` — whether two CSRF pairs share the same value and hash
    /// using constant-time comparisons.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        ct_eq(&self.value[..], &other.value[..]) && ct_eq(&self.hash[..], &other.hash[..])
    }
}

impl fmt::Display for PreAuthCSRF {
    /// Redacted representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("preauth_csrf:redacted")
    }
}

impl fmt::Debug for PreAuthCSRF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Typed failure contracts
// ---------------------------------------------------------------------------

/// `FailureClass` — classifies a session capability failure for safe
/// mapping to CLI exit codes, HTTP status, and diagnostics. The kernel
/// maps each class to its concrete exit code; the class itself never
/// carries plaintext.
///
/// The Go `int` zero value — which `String()` renders `"UNKNOWN"` — is
/// modelled by `Option<FailureClass>` (`None`), so the five variants
/// are exactly upstream's declared set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// `ClassCSRFInvalid` — a missing, mismatched, or replayed CSRF
    /// value. The request must be rejected without mutation.
    CsrfInvalid,
    /// `ClassBootstrapInvalid` — an invalid, consumed, expired, or
    /// replaced bootstrap token. The response must not hint whether a
    /// particular token existed.
    BootstrapInvalid,
    /// `ClassBootstrapThrottled` — the per-generation
    /// five-failures-per-60-seconds throttle has been reached. The
    /// response carries a bounded `Retry-After`.
    BootstrapThrottled,
    /// `ClassSessionInvalidated` — an expired, restarted, or
    /// epoch-invalidated session. Recovery requires a fresh bootstrap
    /// token.
    SessionInvalidated,
    /// `ClassAuthorityDenied` — the broker refused candidate activation
    /// or the helper refused browser open.
    AuthorityDenied,
}

impl FailureClass {
    /// Upstream `FailureClass.String()` — a safe, stable reason code
    /// that never contains plaintext.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CsrfInvalid => "CSRF_INVALID",
            Self::BootstrapInvalid => "BOOTSTRAP_INVALID",
            Self::BootstrapThrottled => "BOOTSTRAP_THROTTLED",
            Self::SessionInvalidated => "SESSION_INVALIDATED",
            Self::AuthorityDenied => "AUTHORITY_DENIED",
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `Sentinel` — the declared sentinel errors (`ErrCSRFInvalid`,
/// `ErrBootstrapInvalid`, `ErrBootstrapConsumed`, `ErrBootstrapExpired`,
/// `ErrBootstrapThrottled`, `ErrSessionInvalidated`, `ErrAuthorityDenied`).
/// They appear only inside a [`Failure`]'s `cause` so callers can match
/// via [`Failure::is_sentinel`] without depending on the struct fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sentinel {
    /// `session: pre-auth csrf invalid`
    CsrfInvalid,
    /// `session: bootstrap token invalid`
    BootstrapInvalid,
    /// `session: bootstrap token already consumed`
    BootstrapConsumed,
    /// `session: bootstrap token expired`
    BootstrapExpired,
    /// `session: bootstrap throttle exceeded`
    BootstrapThrottled,
    /// `session: session invalidated by restart or epoch change`
    SessionInvalidated,
    /// `session: authority denied candidate activation`
    AuthorityDenied,
}

impl Sentinel {
    /// The [`FailureClass`] this sentinel classifies into — the
    /// upstream sentinel→class mapping (consumed and expired are both
    /// `ClassBootstrapInvalid`).
    #[must_use]
    pub const fn class(self) -> FailureClass {
        match self {
            Self::CsrfInvalid => FailureClass::CsrfInvalid,
            Self::BootstrapInvalid | Self::BootstrapConsumed | Self::BootstrapExpired => {
                FailureClass::BootstrapInvalid
            }
            Self::BootstrapThrottled => FailureClass::BootstrapThrottled,
            Self::SessionInvalidated => FailureClass::SessionInvalidated,
            Self::AuthorityDenied => FailureClass::AuthorityDenied,
        }
    }
}

impl fmt::Display for Sentinel {
    /// The upstream sentinel `Error()` text — safe, stable, secret-free.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CsrfInvalid => "session: pre-auth csrf invalid",
            Self::BootstrapInvalid => "session: bootstrap token invalid",
            Self::BootstrapConsumed => "session: bootstrap token already consumed",
            Self::BootstrapExpired => "session: bootstrap token expired",
            Self::BootstrapThrottled => "session: bootstrap throttle exceeded",
            Self::SessionInvalidated => "session: session invalidated by restart or epoch change",
            Self::AuthorityDenied => "session: authority denied candidate activation",
        })
    }
}

impl Error for Sentinel {}

/// `Joined` — the `errors.Join` carrier: several causes attached to one
/// [`Failure`]. Its `Display` concatenates each error's text on its own
/// line (upstream `errors.Join` semantics); a [`Failure`] never formats
/// its cause chain, so this text can surface only if a caller unwraps
/// and formats the `Joined` deliberately.
pub struct Joined(pub Vec<Box<dyn Error + Send + Sync>>);

impl fmt::Debug for Joined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Joined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl Error for Joined {}

/// `Failure` — the typed session failure contract returned by the
/// session capability through ports and across the transport boundary.
/// It carries only an opaque class, safe reason, remediation copy, safe
/// detail keys, and an optional cause for sentinel matching.
///
/// `class` is `None` for untyped failures — upstream's plain
/// `fmt.Errorf` adapter returns (e.g. `databaseFailure`), which are not
/// `session.Failure` values at all. In this port every error crossing a
/// session port is a `Failure`, so `None` is the untyped slot: its
/// `Display` prints the raw safe `reason` (matching the upstream
/// non-`Failure` `Error()` shape) rather than a `session:CLASS` line.
///
/// Plaintext tokens, digests, nonces, credentials, connection strings,
/// and raw database errors never appear in any `Failure` field, and the
/// `Display`/`Debug` paths never format `cause`. Adapters that receive
/// a sensitive error must convert it into a `Failure` before crossing
/// the capability boundary.
pub struct Failure {
    /// The failure classification — `None` for untyped adapter errors
    /// (the `errors.As` miss of upstream's plain returns).
    pub class: Option<FailureClass>,
    /// The safe reason text.
    pub reason: String,
    /// The operator-safe remediation copy; empty when none.
    pub remediation: String,
    /// Safe key/value diagnostics (e.g. `retry_after_seconds`).
    pub safe_details: BTreeMap<String, String>,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl Failure {
    /// Builds a typed failure. `reason` and `remediation` must already
    /// be redacted — they are the text the transport may surface.
    #[must_use]
    pub fn new(
        class: FailureClass,
        reason: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            class: Some(class),
            reason: reason.into(),
            remediation: remediation.into(),
            safe_details: BTreeMap::new(),
            cause: None,
        }
    }

    /// Builds an untyped failure — upstream's non-`Failure` adapter
    /// error (`fmt.Errorf("session store: %s", op)`).
    #[must_use]
    pub fn untyped(reason: impl Into<String>) -> Self {
        Self {
            class: None,
            reason: reason.into(),
            remediation: String::new(),
            safe_details: BTreeMap::new(),
            cause: None,
        }
    }

    /// `WithCause` — returns a copy of `self` with `cause` set to the
    /// given error. Intended for adapter authors that need to attach a
    /// sentinel so callers can match via [`Failure::is_sentinel`]. The
    /// cause is never formatted by `Display`.
    #[must_use]
    pub fn with_cause(mut self, cause: impl Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// `errors.Is` — whether `sentinel` appears anywhere in this
    /// failure's cause chain (`with_cause` attachments and [`Joined`]
    /// members are all walked).
    #[must_use]
    pub fn is_sentinel(&self, sentinel: Sentinel) -> bool {
        fn walk(e: &(dyn Error + 'static), sentinel: Sentinel) -> bool {
            if let Some(s) = e.downcast_ref::<Sentinel>()
                && *s == sentinel
            {
                return true;
            }
            if let Some(j) = e.downcast_ref::<Joined>() {
                return j.0.iter().any(|c| walk(&**c, sentinel));
            }
            if let Some(f) = e.downcast_ref::<Failure>() {
                return f.is_sentinel(sentinel);
            }
            e.source().is_some_and(|s| walk(s, sentinel))
        }
        self.cause.as_deref().is_some_and(|c| walk(c, sentinel))
    }

    /// `errors.As(err, &Failure)` — always `Some(self)` since the port
    /// error type is `Failure`; provided so ported call sites keep the
    /// upstream shape.
    #[must_use]
    pub const fn as_failure(&self) -> Option<&Self> {
        Some(self)
    }
}

impl fmt::Display for Failure {
    /// Upstream `Failure.Error()`: `session:{class}:{remediation}` when
    /// remediation is present, `session:{class}` otherwise; a `class` of
    /// `None` is the untyped slot and prints the raw safe `reason`
    /// (upstream's plain-error shape). Never formats `cause` — plaintext
    /// or digest material attached there cannot leak through here.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.class {
            Some(class) if !self.remediation.is_empty() => {
                write!(f, "session:{}:{}", class, self.remediation)
            }
            Some(class) => write!(f, "session:{}", class),
            None => f.write_str(&self.reason),
        }
    }
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Error for Failure {
    /// `Unwrap` — the optional cause so sentinel matching can reach the
    /// declared sentinels. The cause is a session [`Sentinel`], another
    /// `Failure`, a [`Joined`] set, or an opaque carrier value (carriers
    /// may be attached internally for redaction auditing, but
    /// [`Failure::is_sentinel`] treats them as terminal).
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_deref().map(|e| e as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len() * 2);
        for b in input {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// `mockSensitiveErr` — an upstream error whose text contains
    /// secret material; `Failure`'s `Display` must never reach into a
    /// cause's formatted representation.
    #[derive(Debug)]
    struct MockSensitiveErr {
        leak: String,
    }

    impl fmt::Display for MockSensitiveErr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "sensitive:{}", self.leak)
        }
    }

    impl Error for MockSensitiveErr {}

    /// `TestBootstrapVerifierNeverFormatsPlaintext` — the canonical B06
    /// boundary test: the verifier's `Display`/`Debug` and
    /// `Failure`-wrapped representations never contain the digest or
    /// any substring derivable from it.
    #[test]
    fn bootstrap_verifier_never_formats_plaintext() {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let hex_leak = hex_encode(&secret);
        let raw_leak = String::from_utf8_lossy(&secret).into_owned();

        let v = BootstrapVerifier::new(BOOTSTRAP_VERIFIER_V1, secret);
        for out in [v.to_string(), format!("{v:?}")] {
            assert!(!out.contains(&hex_leak), "leaked digest in {out:?}");
            assert!(!out.contains(&raw_leak), "leaked raw digest in {out:?}");
        }

        // Failure-wrapped representation: `Display` must not pull the
        // digest into its formatted string even when an opaque carrier
        // is attached as the cause.
        let f = Failure::new(
            FailureClass::BootstrapInvalid,
            "verifier mismatch",
            "request a fresh bootstrap token",
        )
        .with_cause(MockSensitiveErr {
            leak: hex_leak.clone(),
        });
        assert!(!f.to_string().contains(&hex_leak));
    }

    /// `TestBootstrapVerifierEqualIsConstantTimeAndNeverFormats`.
    #[test]
    fn bootstrap_verifier_equal_and_zero() {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let mut b = a;
        b[31] ^= 0xff;

        let v1 = BootstrapVerifier::new(BOOTSTRAP_VERIFIER_V1, a);
        let v2 = BootstrapVerifier::new(BOOTSTRAP_VERIFIER_V1, a);
        let v3 = BootstrapVerifier::new(BOOTSTRAP_VERIFIER_V1, b);
        let v4 = BootstrapVerifier::new(2, a);

        assert!(v1.equal(&v2));
        assert!(!v1.equal(&v3));
        assert!(!v1.equal(&v4));
        assert!(BootstrapVerifier::new(0, [0u8; 32]).is_zero());
        assert!(!v1.is_zero());
    }

    /// `TestCandidateBindingRedactsDigest`.
    #[test]
    fn candidate_binding_redacts_digest() {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = 0xa0u8.wrapping_add(i as u8);
        }
        let hex_leak = hex_encode(&secret);
        let binding = CandidateBinding {
            candidate_id: "cand-123".to_string(),
            generation: 7,
            digest: Zeroizing::new(secret),
        };
        for out in [binding.to_string(), format!("{binding:?}")] {
            assert!(!out.contains(&hex_leak), "leaked digest in {out:?}");
            assert!(out.contains("cand-123"), "dropped candidate id: {out:?}");
            assert!(out.contains("gen=7"), "dropped generation: {out:?}");
        }
    }

    /// `TestPreAuthCSRFRedactsValueAndHash`.
    #[test]
    fn preauth_csrf_redacts_value_and_hash() {
        let mut value = [0u8; 32];
        for (i, b) in value.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = 0xc0u8.wrapping_add(i as u8);
        }
        let value_leak = hex_encode(&value);
        let hash_leak = hex_encode(&hash);

        let p = PreAuthCSRF::new(value, hash);
        for out in [p.to_string(), format!("{p:?}")] {
            assert!(!out.contains(&value_leak), "leaked value in {out:?}");
            assert!(!out.contains(&hash_leak), "leaked hash in {out:?}");
        }
        assert_eq!(p.value(), value);
        assert_eq!(p.hash(), hash);
    }

    /// `TestRequestIdentityFormatsSafeIdentifiers`.
    #[test]
    fn request_identity_formats_safe_identifiers() {
        let r = RequestIdentity {
            peer_uid: 1000,
            peer_pid: 4242,
            origin: "https://127.0.0.1:8080".to_string(),
        };
        let out = r.to_string();
        assert!(out.contains("1000"));
        assert!(out.contains("4242"));
        assert!(out.contains("https://127.0.0.1:8080"));
    }

    /// `TestFailureNeverCarriesPlaintext`.
    #[test]
    fn failure_never_carries_plaintext() {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = 0x10u8.wrapping_add(i as u8);
        }
        let hex_leak = hex_encode(&secret);

        let mut f = Failure::new(
            FailureClass::BootstrapInvalid,
            "verifier mismatch",
            "request a fresh bootstrap token",
        );
        f.safe_details
            .insert("attempt".to_string(), "3".to_string());
        let f = f.with_cause(MockSensitiveErr {
            leak: hex_leak.clone(),
        });

        let target = f.as_failure().unwrap();
        assert_eq!(target.class, Some(FailureClass::BootstrapInvalid));
        assert_eq!(
            target.safe_details.get("attempt").map(String::as_str),
            Some("3")
        );
        assert!(!f.to_string().contains(&hex_leak));
    }

    /// `TestBootstrapFailureSentinelsAreStable` — each sentinel
    /// satisfies `is_sentinel` against itself when attached as a cause.
    #[test]
    fn bootstrap_failure_sentinels_are_stable() {
        for s in [
            Sentinel::CsrfInvalid,
            Sentinel::BootstrapInvalid,
            Sentinel::BootstrapConsumed,
            Sentinel::BootstrapExpired,
            Sentinel::BootstrapThrottled,
            Sentinel::SessionInvalidated,
            Sentinel::AuthorityDenied,
        ] {
            let f = Failure::untyped("opaque").with_cause(s);
            assert!(f.is_sentinel(s), "sentinel {s} not reachable");
        }
        let f = Failure::new(FailureClass::CsrfInvalid, "pre-auth csrf missing", "reload")
            .with_cause(Sentinel::CsrfInvalid);
        assert!(f.is_sentinel(Sentinel::CsrfInvalid));
    }

    /// The `Joined` cause — upstream `errors.Join(ErrAuthorityDenied,
    /// err)`: `is_sentinel` reaches each member.
    #[test]
    fn joined_cause_is_walked() {
        let inner = Failure::untyped("session store: activate");
        let f = Failure::new(
            FailureClass::AuthorityDenied,
            "broker refused candidate activation",
            "request a fresh bootstrap token",
        )
        .with_cause(Joined(vec![
            Box::new(Sentinel::AuthorityDenied),
            Box::new(inner),
        ]));
        assert!(f.is_sentinel(Sentinel::AuthorityDenied));
        assert!(!f.is_sentinel(Sentinel::BootstrapInvalid));
    }

    /// Untyped failures display the raw safe reason (upstream's
    /// non-`Failure` `Error()` shape), typed failures the
    /// `session:{class}` contract.
    #[test]
    fn display_shapes() {
        assert_eq!(
            Failure::new(
                FailureClass::BootstrapInvalid,
                "verifier mismatch",
                "request a fresh bootstrap token"
            )
            .to_string(),
            "session:BOOTSTRAP_INVALID:request a fresh bootstrap token"
        );
        assert_eq!(
            Failure::new(FailureClass::CsrfInvalid, "missing", "").to_string(),
            "session:CSRF_INVALID"
        );
        assert_eq!(
            Failure::untyped("session store: validate session").to_string(),
            "session store: validate session"
        );
        assert_eq!(
            FailureClass::BootstrapThrottled.as_str(),
            "BOOTSTRAP_THROTTLED"
        );
        assert_eq!(
            Sentinel::BootstrapConsumed.class(),
            FailureClass::BootstrapInvalid
        );
        assert_eq!(
            Sentinel::SessionInvalidated.to_string(),
            "session: session invalidated by restart or epoch change"
        );
    }
}
