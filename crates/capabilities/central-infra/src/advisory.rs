//! `central-infra::advisory` — the B01 signed release-security advisory
//! domain: the strict-JSON surface, the Ed25519/JCS/SHA-256 verifier, the
//! compatibility/validity evaluation, and the evaluation pipeline the
//! helper runs before any mutating verb.
//!
//! Upstream map:
//!
//! - `internal/advisory/domain.go` — [`State`], [`Code`], [`Outcome`],
//!   [`ReleaseTrust`], [`TimeWitness`], [`CompatibilityMatrix`],
//!   [`DenyPolicy`], [`HostFacts`], [`Snapshot`], [`VerifiedBundle`],
//!   [`Receipt`], [`Admission`], [`Verifier`], and the sentinel codes.
//! - `internal/advisory/verify.go` — [`Verifier::verify_snapshot`] and
//!   [`Verifier::evaluate_verified`].
//! - `internal/advisory/strictjson.go` — [`strict_decode`] and
//!   [`StrictError`].
//! - `internal/advisory/release_key.go` — the compiled v2 trust root and
//!   [`new_production_verifier`].
//! - `internal/advisory/denysafe.go` (pure parts) — the candidate
//!   envelope functions [`snapshot_from_envelope`], [`digest_candidate`],
//!   [`discard_candidate`], and [`evaluate_candidate`]. The deny-safe
//!   state record itself lives in `central-adapter-linux` (filesystem),
//!   reusing `helper::audit`'s already-ported `DenySafeState`.
//! - `internal/advisory/app/evaluate_service.go` —
//!   [`EvaluationService::evaluate`].
//!
//! The signature payload is the JCS-canonical form of the *inner* bundle
//! member produced by [`central_foundation::jcs::canonicalize`] — never a
//! re-serialization — digested with SHA-256 and verified under the exact
//! `central.security-advisory/v1|bundle|SHA-256:<hex>` message upstream
//! signs. Ed25519 verification reproduces Go's `ed25519.Verify`
//! strictness (top-three-bits S check, `A`/`R` curve-point decode,
//! canonical `S < L`) — the same checks `config/view.rs` landed for the
//! authenticated config view — without the stronger small-order rejection
//! `ed25519-dalek`'s strict verifier would add.

use std::collections::HashSet;
use std::fmt;

use central_foundation::failure::{Failure, FailureKind};
use ed25519_dalek::{Signature, VerifyingKey};
// Method-resolution import only — `VerifyingKey::verify` is provided by
// the `signature` crate's `Verifier` trait; the alias avoids colliding
// with this module's own `Verifier`.
use ed25519_dalek::Verifier as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::authority::InstanceBinding;
use crate::authority::wire::{b64_decode, hex_encode};
use crate::port::{
    ActiveBundleSource, AdvisoryClock, DenySafeStore, HostFactsCollector, TimeWitnessStore,
    TransitionRecorder,
};

// ---------------------------------------------------------------------------
// Outcome vocabulary — upstream `advisory.State` / `advisory.Code` /
// `advisory.Result`
// ---------------------------------------------------------------------------

/// `advisory.State` — the closed admission vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// `current` — the advisory verified and admits the operation.
    Current,
    /// `stale` — the advisory verified but no longer admits (expired or
    /// host mismatch).
    Stale,
    /// `denied` — the advisory refused admission.
    Denied,
    /// `hard_expired` — the advisory is beyond its seven-day hard expiry;
    /// the service enters deny-safe mode.
    HardExpired,
}

impl State {
    /// The upstream string value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Denied => "denied",
            Self::HardExpired => "hard_expired",
        }
    }
}

/// `advisory.Code` — the closed machine reason vocabulary. `Unset` is the
/// Go zero value (`""`) a `current` outcome carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// `""` — Go's zero `Code`; every `Current` outcome carries it.
    Unset,
    /// `INVALID_ADVISORY`.
    Invalid,
    /// `SIGNATURE_INVALID`.
    SignatureInvalid,
    /// `ADVISORY_EXPIRED`.
    Expired,
    /// `ADVISORY_HARD_EXPIRED`.
    HardExpired,
    /// `ADVISORY_HOST_MISMATCH`.
    HostMismatch,
    /// `EMERGENCY_DENY`.
    EmergencyDeny,
    /// `ADVISORY_SOURCE_UNAVAILABLE`.
    SourceUnavailable,
    /// `ADVISORY_EVIDENCE_UNAVAILABLE`.
    EvidenceUnavailable,
}

impl Code {
    /// The upstream string value (`""` for [`Code::Unset`]).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unset => "",
            Self::Invalid => "INVALID_ADVISORY",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::Expired => "ADVISORY_EXPIRED",
            Self::HardExpired => "ADVISORY_HARD_EXPIRED",
            Self::HostMismatch => "ADVISORY_HOST_MISMATCH",
            Self::EmergencyDeny => "EMERGENCY_DENY",
            Self::SourceUnavailable => "ADVISORY_SOURCE_UNAVAILABLE",
            Self::EvidenceUnavailable => "ADVISORY_EVIDENCE_UNAVAILABLE",
        }
    }
}

/// `advisory.Result` — the evaluation verdict. Named `Outcome` because
/// `Result` is taken by `std`; upstream's `result` identifier maps here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The admission state.
    pub state: State,
    /// The machine code ([`Code::Unset`] for `current`).
    pub code: Code,
    /// The failing compatibility check (HostMismatch only).
    pub check: String,
    /// Operator remediation hint — no upstream code path sets it today;
    /// carried for struct parity.
    pub remediation: String,
}

impl Outcome {
    /// `Result{State: s, Code: c}` — the two-field construction every
    /// upstream deny path uses.
    #[must_use]
    pub fn new(state: State, code: Code) -> Self {
        Self {
            state,
            code,
            ..Self::default()
        }
    }

    /// `Result{State: Current}` — the acceptance a verified, in-window,
    /// host-matching evaluation produces.
    #[must_use]
    pub fn current() -> Self {
        Self::new(State::Current, Code::Unset)
    }

    /// `Result{State: Denied, Code: c}`.
    #[must_use]
    pub fn denied(code: Code) -> Self {
        Self::new(State::Denied, code)
    }
}

impl Default for Outcome {
    /// Go's zero `Result` is `{State: ""}` — represented as `Denied`+`Unset`
    /// so an accidentally-defaulted outcome can never admit.
    fn default() -> Self {
        Self {
            state: State::Denied,
            code: Code::Unset,
            check: String::new(),
            remediation: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain types — upstream `advisory.*` structs
// ---------------------------------------------------------------------------

/// `advisory.ReleaseTrust` — the release-authority trust root a verifier
/// is pinned to.
#[derive(Debug, Clone)]
pub struct ReleaseTrust {
    /// The `key_id` a bundle must name.
    pub key_id: String,
    /// The signing protocol identity (recorded; the signed-message prefix
    /// is fixed — see [`Verifier::verify_snapshot`]).
    pub protocol: String,
    /// The Ed25519 public key.
    pub public_key: [u8; 32],
    /// The binding's expected public-key digest (set only on the
    /// [`new_production_verifier`] path).
    pub release_authority_digest: String,
}

/// `advisory.TimeWitness` — the anti-rollback witness the store persists.
/// `None` fields are Go's `time.Time` zero values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeWitness {
    /// `issued_at` of the last durably accepted bundle.
    pub last_accepted_at: Option<OffsetDateTime>,
    /// `issued_at` of the last accepted bundle (same value upstream
    /// writes twice).
    pub last_issued_at: Option<OffsetDateTime>,
}

/// `advisory.CompatibilityMatrix` — the per-fact version pins a bundle
/// carries. Empty pins admit any host value.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompatibilityMatrix {
    /// `/etc/os-release` `VERSION_ID` pin.
    pub os_release: String,
    /// `/proc/sys/kernel/osrelease` pin.
    pub kernel: String,
    /// Docker client version pin.
    pub docker: String,
    /// Docker Compose version pin.
    pub compose: String,
    /// `psql` client version pin.
    pub psql: String,
}

/// `advisory.DenyPolicy` — the emergency-deny block.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DenyPolicy {
    /// Emergency deny flag — evaluated before every other acceptance
    /// check.
    pub emergency: bool,
    /// Operator-facing reason (not consulted by evaluation).
    pub reason: String,
}

/// `advisory.HostFacts` — the collected host environment versions.
/// Empty fields are "unknown": they never admit a known-incompatible
/// host (the check fires only when *both* sides are non-empty).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// `/etc/os-release` `VERSION_ID`.
    pub os_release: String,
    /// Kernel release.
    pub kernel: String,
    /// Docker client version.
    pub docker: String,
    /// Compose version.
    pub compose: String,
    /// `psql` version.
    pub psql: String,
}

/// `advisory.Snapshot` — the raw installed bundle the adapter loaded.
/// `bundle` carries the *whole envelope* bytes (upstream `source.go`'s
/// round-trip contract); `signature` is the base64 string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The selector's generation identity.
    pub generation_id: String,
    /// The selector's SHA-256 digest of the envelope bytes.
    pub selector_digest: String,
    /// The whole `envelope.json` byte content.
    pub bundle: Vec<u8>,
    /// The base64 signature text (not decoded).
    pub signature: Vec<u8>,
}

/// `advisory.VerifiedBundle` — a snapshot that passed signature, schema,
/// and shape verification, with the canonical bytes and parsed fields.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    /// The source snapshot.
    pub snapshot: Snapshot,
    /// JCS-canonical bytes of the inner `bundle` member.
    pub canonical: Vec<u8>,
    /// Lowercase hex SHA-256 of `canonical`.
    pub digest: String,
    /// The bundle's `key_id`.
    pub key_id: String,
    /// The bundle's `issued_at`.
    pub issued_at: OffsetDateTime,
    /// The bundle's `expires_at`.
    pub expires_at: OffsetDateTime,
    /// The bundle's compatibility pins.
    pub compatibility: CompatibilityMatrix,
    /// The bundle's emergency-deny block.
    pub emergency_deny: DenyPolicy,
}

/// `advisory.Receipt` — the durable-evidence identity the recorder
/// returns; the admission binds its `id`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Receipt {
    /// Journal entry identity.
    pub id: String,
    /// Journal stream sequence.
    pub sequence: u64,
}

/// `advisory` — `ErrNonCurrentAdmission`'s code.
pub const ERR_NON_CURRENT_ADMISSION: &str = "advisory.non_current_admission";
/// `advisory` — `ErrSourceUnavailable`'s code.
pub const ERR_SOURCE_UNAVAILABLE: &str = "advisory.source_unavailable";
/// `advisory` — `ErrWitnessNotFound`'s code: the one `TimeWitnessStore::load`
/// failure [`EvaluationService::evaluate`] treats as a legitimate zero
/// witness (first acceptance ever) instead of a denial.
pub const WITNESS_NOT_FOUND_CODE: &str = "advisory.witness_not_found";
/// `advisory` — `ErrReleaseAuthorityMismatch`'s code.
pub const ERR_RELEASE_AUTHORITY_MISMATCH: &str = "advisory.release_authority_mismatch";

/// `advisory.Admission` — the opaque admission token. Constructible only
/// from a `Current` outcome with a non-empty receipt id (or via
/// [`Admission::from_receipt`] when a receipt is already known-good);
/// non-current outcomes can never produce one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admission {
    receipt_id: String,
}

impl Admission {
    /// `NewAdmission` — refuses non-current outcomes and empty receipt
    /// ids with `ErrNonCurrentAdmission`.
    ///
    /// # Errors
    /// [`ERR_NON_CURRENT_ADMISSION`] when `outcome` is not `Current` or
    /// `receipt_id` is empty.
    pub fn new(outcome: &Outcome, receipt_id: impl Into<String>) -> Result<Self, Failure> {
        let receipt_id = receipt_id.into();
        if outcome.state != State::Current || receipt_id.is_empty() {
            return Err(Failure::denied(
                ERR_NON_CURRENT_ADMISSION,
                "advisory: admission requires current result",
            ));
        }
        Ok(Self { receipt_id })
    }

    /// `NewAdmissionFromReceipt` — for a receipt already known valid
    /// (upstream panics on empty; Rust returns `None`).
    #[must_use]
    pub fn from_receipt(receipt_id: impl Into<String>) -> Option<Self> {
        let receipt_id = receipt_id.into();
        if receipt_id.is_empty() {
            return None;
        }
        Some(Self { receipt_id })
    }

    /// `ReceiptID` — the journaled evidence identity.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// `IsZero` — no receipt was ever bound.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.receipt_id.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Strict JSON — upstream `advisory/strictjson.go` `StrictDecode`
// ---------------------------------------------------------------------------

const STRICT_MAX_DEPTH: usize = 32;
const STRICT_MAX_MEMBERS: usize = 1000;
const STRICT_MAX_STRING: usize = 16 * 1024;

/// `strictjson.go`'s error vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictError {
    /// `ErrStrictTooDeep` — nesting beyond 32 containers.
    TooDeep,
    /// `ErrStrictTooManyMembers` — an object with more than 1000 members.
    TooManyMembers,
    /// `ErrStrictStringTooLong` — a string over 16 KiB decoded.
    StringTooLong,
    /// `ErrStrictDuplicateKey` — a repeated member name in one frame.
    DuplicateKey,
    /// `ErrStrictInvalidUTF8` — invalid UTF-8 input.
    InvalidUtf8,
    /// `ErrStrictTrailingGarbage` — a complete second JSON token after the
    /// first top-level value.
    TrailingGarbage,
    /// `ErrStrictNonCanonicalNumber` — a number containing `e`, `E`, or
    /// `+` (I-JSON canonical-number rule).
    NonCanonicalNumber,
    /// Any other malformed input (upstream's bare `json.Token` errors:
    /// unexpected delimiters, truncated input, syntax violations).
    Malformed,
}

impl fmt::Display for StrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooDeep => "strict json: depth exceeds maximum",
            Self::TooManyMembers => "strict json: too many object members",
            Self::StringTooLong => "strict json: string exceeds maximum length",
            Self::DuplicateKey => "strict json: duplicate object key",
            Self::InvalidUtf8 => "strict json: invalid UTF-8 in string",
            Self::TrailingGarbage => "strict json: trailing data after first value",
            Self::NonCanonicalNumber => "strict json: non-canonical number (I-JSON)",
            Self::Malformed => "strict json: malformed input",
        };
        f.write_str(text)
    }
}

impl std::error::Error for StrictError {}

/// One strict-decoder frame — upstream `strictFrame` (`keys`, `nextKey`,
/// `members`). `keys` uses raw decoded bytes: the upfront UTF-8 check
/// plus valid escape decoding make byte-compare identical to Go's string
/// compare.
#[derive(Default)]
struct StrictFrame {
    keys: HashSet<Vec<u8>>,
    next_key: bool,
    members: usize,
}

/// `StrictDecode` — validates `raw` as strict JSON exactly as upstream's
/// token-walk does: the UTF-8 gate, the depth/member/string bounds,
/// duplicate-key detection within each object frame, the I-JSON number
/// rule, and the single-top-level-value rule whose acceptance edge is
/// "one more complete token" (trailing *malformed* bytes are accepted,
/// trailing *valid* tokens refuse). Empty input is valid — callers parse
/// again and fail there, matching upstream.
///
/// The walk is recursive descent rather than a token loop, but the
/// `frames` stack reproduces upstream's `nextKey` accounting exactly —
/// including the quirk that strings inside arrays alternate key/value
/// roles for member counting and duplicate detection.
///
/// # Errors
/// [`StrictError`] describing the first violation.
pub fn strict_decode(raw: &[u8]) -> Result<(), StrictError> {
    if std::str::from_utf8(raw).is_err() {
        return Err(StrictError::InvalidUtf8);
    }
    let mut walker = StrictWalker {
        raw,
        pos: 0,
        frames: Vec::new(),
    };
    walker.skip_ws();
    if walker.pos == raw.len() {
        return Ok(());
    }
    walker.value(0)?;
    // Upstream's `firstValueComplete` branch: exactly one more `Token()`
    // attempt decides — a complete second token refuses, EOF or a
    // malformed tail accepts.
    match walker.lex_one() {
        Lex::Token => Err(StrictError::TrailingGarbage),
        Lex::Eof | Lex::Malformed => Ok(()),
    }
}

enum Lex {
    Token,
    Eof,
    Malformed,
}

struct StrictWalker<'a> {
    raw: &'a [u8],
    pos: usize,
    frames: Vec<StrictFrame>,
}

impl StrictWalker<'_> {
    fn skip_ws(&mut self) {
        while matches!(self.raw.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.raw.get(self.pos).copied()
    }

    /// The parent's `nextKey = true` assignment upstream runs when a `}`
    /// or `]` closes a nested container.
    fn mark_parent_value(&mut self) {
        if let Some(f) = self.frames.last_mut() {
            f.next_key = true;
        }
    }

    /// The `bool`/`json.Number`/`nil` token arms: a completed scalar sets
    /// the innermost frame's `nextKey = true`.
    fn note_scalar(&mut self) {
        if let Some(f) = self.frames.last_mut() {
            f.next_key = true;
        }
    }

    /// The `case string:` arm: a decoded string at a key position is
    /// duplicate-checked and member-counted; at a value position it only
    /// flips `nextKey`. Length was already enforced by `string()`.
    fn note_string(&mut self, decoded: Vec<u8>) -> Result<(), StrictError> {
        if let Some(f) = self.frames.last_mut() {
            if f.next_key {
                if !f.keys.insert(decoded) {
                    return Err(StrictError::DuplicateKey);
                }
                f.members += 1;
                f.next_key = false;
            } else {
                f.next_key = true;
            }
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<(), StrictError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                if depth + 1 > STRICT_MAX_DEPTH {
                    return Err(StrictError::TooDeep);
                }
                self.frames.push(StrictFrame {
                    next_key: true,
                    ..StrictFrame::default()
                });
                self.object(depth + 1)
            }
            Some(b'[') => {
                self.pos += 1;
                if depth + 1 > STRICT_MAX_DEPTH {
                    return Err(StrictError::TooDeep);
                }
                self.frames.push(StrictFrame {
                    next_key: false,
                    ..StrictFrame::default()
                });
                self.array(depth + 1)
            }
            Some(b'"') => {
                let s = self.string()?;
                self.note_string(s)
            }
            Some(b't') => {
                self.literal(b"true")?;
                self.note_scalar();
                Ok(())
            }
            Some(b'f') => {
                self.literal(b"false")?;
                self.note_scalar();
                Ok(())
            }
            Some(b'n') => {
                self.literal(b"null")?;
                self.note_scalar();
                Ok(())
            }
            Some(b'-' | b'0'..=b'9') => {
                let lit = self.number()?;
                if lit.iter().any(|b| matches!(b, b'e' | b'E' | b'+')) {
                    return Err(StrictError::NonCanonicalNumber);
                }
                self.note_scalar();
                Ok(())
            }
            _ => Err(StrictError::Malformed),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), StrictError> {
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return self.close_object();
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(StrictError::Malformed);
            }
            let key = self.string()?;
            // The key position always carries nextKey = true upstream, so
            // the key arm runs unconditionally here.
            if let Some(f) = self.frames.last_mut() {
                if !f.keys.insert(key) {
                    return Err(StrictError::DuplicateKey);
                }
                f.members += 1;
                f.next_key = false;
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(StrictError::Malformed);
            }
            self.pos += 1;
            self.value(depth)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return self.close_object();
                }
                _ => return Err(StrictError::Malformed),
            }
        }
    }

    /// The `case '}'` arm: member bound is checked only on object close.
    fn close_object(&mut self) -> Result<(), StrictError> {
        let frame = self.frames.pop().unwrap_or_default();
        if frame.members > STRICT_MAX_MEMBERS {
            return Err(StrictError::TooManyMembers);
        }
        self.mark_parent_value();
        Ok(())
    }

    fn array(&mut self, depth: usize) -> Result<(), StrictError> {
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.frames.pop();
            self.mark_parent_value();
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    self.frames.pop();
                    self.mark_parent_value();
                    return Ok(());
                }
                _ => return Err(StrictError::Malformed),
            }
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), StrictError> {
        if self.raw.len() >= self.pos + lit.len()
            && &self.raw[self.pos..self.pos + lit.len()] == lit
        {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(StrictError::Malformed)
        }
    }

    /// A Go-decoder string token: full escape handling (lone surrogates
    /// decode to U+FFFD like Go's `getu4`), the decoded-length bound, and
    /// rejection of raw control bytes.
    fn string(&mut self) -> Result<Vec<u8>, StrictError> {
        if self.peek() != Some(b'"') {
            return Err(StrictError::Malformed);
        }
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return Err(StrictError::Malformed),
                Some(b'"') => {
                    self.pos += 1;
                    if out.len() > STRICT_MAX_STRING {
                        return Err(StrictError::StringTooLong);
                    }
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/') => {
                            out.push(self.raw[self.pos]);
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            out.push(0x08);
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            out.push(0x0C);
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            out.push(b'\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push(b'\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push(b'\t');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            let cp = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&cp) {
                                // High surrogate: pair with a following
                                // `\uXXXX` low surrogate when present,
                                // else U+FFFD — Go's exact rule.
                                if self.raw.len() >= self.pos + 6
                                    && &self.raw[self.pos..self.pos + 2] == b"\\u"
                                {
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                        char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER)
                                    } else {
                                        char::REPLACEMENT_CHARACTER
                                    }
                                } else {
                                    char::REPLACEMENT_CHARACTER
                                }
                            } else if (0xDC00..0xE000).contains(&cp) {
                                char::REPLACEMENT_CHARACTER
                            } else {
                                char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER)
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(StrictError::Malformed),
                    }
                }
                // Raw control bytes inside a string are invalid JSON.
                Some(0x00..=0x1F) => return Err(StrictError::Malformed),
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
            if out.len() > STRICT_MAX_STRING {
                return Err(StrictError::StringTooLong);
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, StrictError> {
        if self.raw.len() < self.pos + 4 {
            return Err(StrictError::Malformed);
        }
        let mut v = 0u32;
        for &b in &self.raw[self.pos..self.pos + 4] {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(StrictError::Malformed),
            };
            v = (v << 4) | u32::from(d);
        }
        self.pos += 4;
        Ok(v)
    }

    /// A JSON number literal under Go's grammar. Returns the literal —
    /// the caller applies the `eE+` I-JSON rejection.
    fn number(&mut self) -> Result<Vec<u8>, StrictError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(StrictError::Malformed),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(StrictError::Malformed);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(StrictError::Malformed);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(self.raw[start..self.pos].to_vec())
    }

    /// Upstream's post-value `dec.Token()` probe: is there one more
    /// *complete* token? `{`/`[` return a `Delim` immediately (complete),
    /// `}`/`]`/`,`/`:` are syntax errors in value position, strings,
    /// literals, and numbers must lex fully.
    fn lex_one(&mut self) -> Lex {
        self.skip_ws();
        match self.peek() {
            None => Lex::Eof,
            Some(b'{' | b'[') => Lex::Token,
            Some(b'"') => match self.string() {
                Ok(_) => Lex::Token,
                Err(_) => Lex::Malformed,
            },
            Some(b't') => {
                if self.try_literal(b"true") {
                    Lex::Token
                } else {
                    Lex::Malformed
                }
            }
            Some(b'f') => {
                if self.try_literal(b"false") {
                    Lex::Token
                } else {
                    Lex::Malformed
                }
            }
            Some(b'n') => {
                if self.try_literal(b"null") {
                    Lex::Token
                } else {
                    Lex::Malformed
                }
            }
            Some(b'-' | b'0'..=b'9') => match self.number() {
                Ok(_) => Lex::Token,
                Err(_) => Lex::Malformed,
            },
            _ => Lex::Malformed,
        }
    }

    fn try_literal(&mut self, lit: &[u8]) -> bool {
        if self.raw.len() >= self.pos + lit.len()
            && &self.raw[self.pos..self.pos + lit.len()] == lit
        {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier — upstream `advisory/verify.go`
// ---------------------------------------------------------------------------

/// `maxBundleSize`.
const MAX_BUNDLE_SIZE: usize = 1 << 20;

/// `allowedBundleKeys`.
const ALLOWED_BUNDLE_KEYS: [&str; 6] = [
    "schema_version",
    "key_id",
    "issued_at",
    "expires_at",
    "compatibility",
    "emergency_deny",
];

/// `envelope` — the outer `{bundle, signature}` member view. Unknown
/// fields are ignored, matching upstream's plain `json.Unmarshal`.
#[derive(Deserialize)]
struct EnvelopeView<'a> {
    #[serde(borrow)]
    bundle: Option<&'a serde_json::value::RawValue>,
    #[serde(default)]
    signature: Option<String>,
}

/// `advisory.Verifier` — verifies signed snapshots against a pinned
/// [`ReleaseTrust`], then evaluates verified bundles for admission.
pub struct Verifier {
    trust: ReleaseTrust,
}

impl Verifier {
    /// `NewVerifierForTesting` — a verifier pinned to an arbitrary trust
    /// root; the production constructor is [`Verifier::production`].
    #[must_use]
    pub fn for_testing(trust: ReleaseTrust) -> Self {
        Self { trust }
    }

    /// `Trust()` — the pinned trust root.
    #[must_use]
    pub fn trust(&self) -> &ReleaseTrust {
        &self.trust
    }

    /// `VerifySnapshot` — the full fail-closed verification chain in
    /// upstream's exact order: size → strict → envelope parse → inner
    /// strict → typed bundle → allowed keys → schema → JCS → SHA-256 →
    /// signature → key_id → timestamps. Any failure produces a `denied`
    /// [`Outcome`] and no bundle.
    #[must_use]
    pub fn verify_snapshot(&self, snapshot: &Snapshot) -> (Option<VerifiedBundle>, Outcome) {
        if snapshot.bundle.len() > MAX_BUNDLE_SIZE {
            return (None, Outcome::denied(Code::Invalid));
        }
        if strict_decode(&snapshot.bundle).is_err() {
            return (None, Outcome::denied(Code::Invalid));
        }
        let Ok(env) = serde_json::from_slice::<EnvelopeView<'_>>(&snapshot.bundle) else {
            return (None, Outcome::denied(Code::Invalid));
        };
        // `signature` is parsed for shape only — verification uses
        // `snapshot.signature`, which the source read from the same field.
        let _ = &env.signature;
        let Some(bundle_raw) = env.bundle else {
            return (None, Outcome::denied(Code::Invalid));
        };
        if strict_decode(bundle_raw.get().as_bytes()).is_err() {
            return (None, Outcome::denied(Code::Invalid));
        }
        let Ok(bundle_value) = serde_json::from_str::<serde_json::Value>(bundle_raw.get()) else {
            return (None, Outcome::denied(Code::Invalid));
        };
        // `json.Unmarshal` into `bundleJSON` + the raw-map allowed-keys
        // pass. A JSON `null` member value unmarshal is a no-op (zero
        // struct, empty map); any other non-object is a type error.
        let mut bundle = ParsedBundle::default();
        match &bundle_value {
            serde_json::Value::Object(m) => {
                if bundle.extract(m).is_err() {
                    return (None, Outcome::denied(Code::Invalid));
                }
            }
            serde_json::Value::Null => {}
            _ => return (None, Outcome::denied(Code::Invalid)),
        }
        if let serde_json::Value::Object(m) = &bundle_value {
            for key in m.keys() {
                if !ALLOWED_BUNDLE_KEYS.contains(&key.as_str()) {
                    return (None, Outcome::denied(Code::Invalid));
                }
            }
        }
        if bundle.schema_version != 1 {
            return (None, Outcome::denied(Code::Invalid));
        }

        let Ok(canonical) = central_foundation::jcs::canonicalize(&bundle_value) else {
            return (None, Outcome::denied(Code::Invalid));
        };
        let sum = Sha256::digest(&canonical);
        // The protocol prefix is the fixed literal upstream signs — not
        // `trust.protocol` — see `verify.go`'s message construction.
        let message = format!(
            "central.security-advisory/v1|bundle|SHA-256:{}",
            hex_encode(&sum)
        );

        let Ok(sig_text) = std::str::from_utf8(&snapshot.signature) else {
            return (None, Outcome::denied(Code::SignatureInvalid));
        };
        let Some(sig_bytes) = b64_decode(sig_text) else {
            return (None, Outcome::denied(Code::SignatureInvalid));
        };
        if sig_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return (None, Outcome::denied(Code::SignatureInvalid));
        }
        let Ok(sig_array) = <&[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return (None, Outcome::denied(Code::SignatureInvalid));
        };
        if !go_ed25519_verify(&self.trust.public_key, message.as_bytes(), sig_array) {
            return (None, Outcome::denied(Code::SignatureInvalid));
        }

        if bundle.key_id != self.trust.key_id {
            return (None, Outcome::denied(Code::Invalid));
        }
        let Ok(issued_at) = OffsetDateTime::parse(
            &bundle.issued_at,
            &time::format_description::well_known::Rfc3339,
        ) else {
            return (None, Outcome::denied(Code::Invalid));
        };
        let Ok(expires_at) = OffsetDateTime::parse(
            &bundle.expires_at,
            &time::format_description::well_known::Rfc3339,
        ) else {
            return (None, Outcome::denied(Code::Invalid));
        };

        (
            Some(VerifiedBundle {
                snapshot: snapshot.clone(),
                canonical,
                digest: crate::authority::wire::hex_encode(&sum),
                key_id: bundle.key_id,
                issued_at,
                expires_at,
                compatibility: bundle.compatibility,
                emergency_deny: bundle.emergency_deny,
            }),
            Outcome::current(),
        )
    }

    /// `EvaluateVerified` — the admission evaluation in upstream's exact
    /// order: emergency deny → future-issued → witness regression →
    /// hard expiry (`expires_at + 7d`) → soft expiry → per-fact
    /// compatibility (both-sides-non-empty compare, `stale` on
    /// mismatch).
    #[must_use]
    pub fn evaluate_verified(
        &self,
        bundle: &VerifiedBundle,
        facts: &HostFacts,
        witness: &TimeWitness,
        now: OffsetDateTime,
    ) -> Outcome {
        if bundle.emergency_deny.emergency {
            return Outcome::denied(Code::EmergencyDeny);
        }
        if bundle.issued_at > now {
            return Outcome::denied(Code::Invalid);
        }
        if let Some(last) = witness.last_accepted_at
            && last > bundle.issued_at
        {
            return Outcome::denied(Code::Invalid);
        }
        let hard_expiry = bundle.expires_at + time::Duration::days(7);
        if now > hard_expiry {
            return Outcome::new(State::HardExpired, Code::HardExpired);
        }
        if now > bundle.expires_at {
            return Outcome::new(State::Stale, Code::Expired);
        }
        let checks: [(&str, &str, &str); 5] = [
            (
                "os_release",
                &facts.os_release,
                &bundle.compatibility.os_release,
            ),
            ("kernel", &facts.kernel, &bundle.compatibility.kernel),
            ("docker", &facts.docker, &bundle.compatibility.docker),
            ("compose", &facts.compose, &bundle.compatibility.compose),
            ("psql", &facts.psql, &bundle.compatibility.psql),
        ];
        for (name, fact, pin) in checks {
            if !fact.is_empty() && !pin.is_empty() && fact != pin {
                return Outcome {
                    state: State::Stale,
                    code: Code::HostMismatch,
                    check: name.to_owned(),
                    remediation: String::new(),
                };
            }
        }
        Outcome::current()
    }
}

/// `bundleJSON` — the typed view of the inner bundle. `extract`
/// reproduces `json.Unmarshal` type strictness: a present member of the
/// wrong JSON type fails, an absent member keeps the zero value, unknown
/// members are tolerated here and refused by the allowed-keys pass.
#[derive(Default)]
struct ParsedBundle {
    schema_version: i64,
    key_id: String,
    issued_at: String,
    expires_at: String,
    compatibility: CompatibilityMatrix,
    emergency_deny: DenyPolicy,
}

impl ParsedBundle {
    fn extract(&mut self, map: &serde_json::Map<String, serde_json::Value>) -> Result<(), ()> {
        if let Some(v) = map.get("schema_version") {
            self.schema_version = v.as_i64().ok_or(())?;
        }
        if let Some(v) = map.get("key_id") {
            self.key_id = v.as_str().ok_or(())?.to_owned();
        }
        if let Some(v) = map.get("issued_at") {
            self.issued_at = v.as_str().ok_or(())?.to_owned();
        }
        if let Some(v) = map.get("expires_at") {
            self.expires_at = v.as_str().ok_or(())?.to_owned();
        }
        if let Some(v) = map.get("compatibility") {
            self.compatibility = parse_compatibility(v)?;
        }
        if let Some(v) = map.get("emergency_deny") {
            self.emergency_deny = parse_deny_policy(v)?;
        }
        Ok(())
    }
}

/// `json.Unmarshal` of `CompatibilityMatrix` — `null` keeps the zero
/// value; non-object fails; known members must be strings; unknown
/// members are ignored.
fn parse_compatibility(v: &serde_json::Value) -> Result<CompatibilityMatrix, ()> {
    let mut out = CompatibilityMatrix::default();
    match v {
        serde_json::Value::Null => Ok(out),
        serde_json::Value::Object(m) => {
            for (name, slot) in [
                ("os_release", &mut out.os_release),
                ("kernel", &mut out.kernel),
                ("docker", &mut out.docker),
                ("compose", &mut out.compose),
                ("psql", &mut out.psql),
            ] {
                if let Some(val) = m.get(name) {
                    *slot = val.as_str().ok_or(())?.to_owned();
                }
            }
            Ok(out)
        }
        _ => Err(()),
    }
}

/// `json.Unmarshal` of `DenyPolicy` — same rules as
/// [`parse_compatibility`]; `emergency` must be a bool, `reason` a
/// string.
fn parse_deny_policy(v: &serde_json::Value) -> Result<DenyPolicy, ()> {
    let mut out = DenyPolicy::default();
    match v {
        serde_json::Value::Null => Ok(out),
        serde_json::Value::Object(m) => {
            if let Some(val) = m.get("emergency") {
                out.emergency = val.as_bool().ok_or(())?;
            }
            if let Some(val) = m.get("reason") {
                out.reason = val.as_str().ok_or(())?.to_owned();
            }
            Ok(out)
        }
        _ => Err(()),
    }
}

/// `ed25519.Verify` — Go's exact refusal shape (Go 1.26
/// `crypto/internal/fips140/ed25519.verifyWithDom` plus the
/// `NewPublicKey` decode), mirroring the `config/view.rs` checks the
/// R5 T2 review pinned:
///
/// - `signature[63] & 0xE0 != 0` — the top three bits of the S scalar
///   must be clear (Go's first check, before the message hash).
/// - `A` (the public key) must decode to a curve point — Go
///   `edwards25519.Point.SetBytes`, reached through dalek's
///   `CompressedEdwardsY::decompress` (exposed by
///   `VerifyingKey::from_bytes`). Both decoders accept the
///   non-canonical encodings of *valid* points — unreduced field
///   elements (`y ≥ p`, i.e. `x + p` of a canonical encoding) and
///   `x = 0` with the sign bit set — so this is a Go-parity decode,
///   not a canonicality check: adding one would deny encodings
///   upstream accepts.
/// - `R` (the first signature half) must decompress — old-Go's
///   `NewIdentityPoint().SetBytes(sig[:32])`. The FIPS verifier
///   dropped the explicit decode as redundant: the equation below
///   byte-compares `sig[:32]` against the *canonical* re-encoding of
///   the recomputed point (`bytes.Equal(sig[:32], R.Bytes())` — dalek
///   performs the same compare on `CompressedEdwardsY`), which can
///   only match a decompressible encoding. Kept here for the
///   old-Go check order; it is outcome-identical either way, and it
///   is what refuses non-decompressible `R` bytes before the hash.
/// - `S < L` canonically — `Scalar::from_canonical_bytes` inside
///   `verify`, matching `SetCanonicalBytes`.
///
/// Non-canonical-but-decompressible `R` (`y ≥ p`) is refused exactly
/// as upstream refuses it: not by a decode rejection — both decoders
/// accept it — but by the canonical byte-compare inside `verify`.
///
/// `ed25519-dalek`'s `verify_strict` is deliberately *not* used: it adds
/// a small-order-R/A rejection Go never performs, which would deny
/// signatures upstream accepts.
fn go_ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    if signature[63] & 0xE0 != 0 {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let Ok(r_bytes) = <&[u8; 32]>::try_from(&signature[..32]) else {
        return false;
    };
    if VerifyingKey::from_bytes(r_bytes).is_err() {
        return false;
    }
    key.verify(message, &Signature::from_bytes(signature))
        .is_ok()
}

// ---------------------------------------------------------------------------
// Release key — upstream `advisory/release_key.go`
// ---------------------------------------------------------------------------

/// `productionReleaseAuthorityPublicKeyBase64` — the public half of the
/// v2 release-signing key. Safe to commit: an Ed25519 public key
/// discloses nothing about the private key, which lives only in the
/// maintainer's custody file (ADR 0039 — the v1 id is retired).
pub const PRODUCTION_RELEASE_AUTHORITY_PUBLIC_KEY_BASE64: &str =
    "qvXtNCLuEhrZ2x3nwaXICuq4RytGkhRVEU3DZtkZdRA=";

/// The decoded form of
/// [`PRODUCTION_RELEASE_AUTHORITY_PUBLIC_KEY_BASE64`]. Upstream decodes
/// the base64 constant and panics on corruption; Rust embeds the bytes
/// directly (no fallible construction, nothing to panic over) and a test
/// pins the two constants equal.
const PRODUCTION_RELEASE_AUTHORITY_PUBLIC_KEY: [u8; 32] = [
    0xaa, 0xf5, 0xed, 0x34, 0x22, 0xee, 0x12, 0x1a, 0xd9, 0xdb, 0x1d, 0xe7, 0xc1, 0xa5, 0xc8, 0x0a,
    0xea, 0xb8, 0x47, 0x2b, 0x46, 0x92, 0x14, 0x55, 0x11, 0x4d, 0xc3, 0x66, 0xd9, 0x19, 0x75, 0x10,
];

/// The v2 key id a production bundle must carry.
pub const PRODUCTION_KEY_ID: &str = "central-release-authority/v2";
/// The advisory signing protocol identity.
pub const PRODUCTION_PROTOCOL: &str = "central.security-advisory/v1";

/// `productionTrust` — the compiled trust root.
fn production_trust() -> ReleaseTrust {
    ReleaseTrust {
        key_id: PRODUCTION_KEY_ID.to_owned(),
        protocol: PRODUCTION_PROTOCOL.to_owned(),
        public_key: PRODUCTION_RELEASE_AUTHORITY_PUBLIC_KEY,
        release_authority_digest: String::new(),
    }
}

/// `ProductionReleaseAuthorityDigestForTesting` — hex SHA-256 of the
/// compiled public key: the exact value a real
/// `InstanceBinding.release_digest` must carry for
/// [`new_production_verifier`] to accept it. Exists only as a test seam.
#[must_use]
pub fn production_release_authority_digest_for_testing() -> String {
    crate::authority::wire::hex_encode(&Sha256::digest(production_trust().public_key))
}

/// `NewProductionVerifier` — verifies the binding's `release_digest`
/// pins the compiled public key before returning a verifier.
///
/// # Errors
/// [`ERR_RELEASE_AUTHORITY_MISMATCH`] when the digests disagree.
pub fn new_production_verifier(binding: &InstanceBinding) -> Result<Verifier, Failure> {
    let mut trust = production_trust();
    trust.release_authority_digest = binding.release_digest.clone();
    let digest = crate::authority::wire::hex_encode(&Sha256::digest(trust.public_key));
    if digest != binding.release_digest {
        return Err(Failure::denied(
            ERR_RELEASE_AUTHORITY_MISMATCH,
            "advisory: release authority digest mismatch",
        ));
    }
    Ok(Verifier { trust })
}

impl Verifier {
    /// `NewProductionVerifierFromCompiledTrust` — the production
    /// construction path: the compile-time embedded key with no binding
    /// and no genesis dependency (upstream explains why the binding
    /// cross-check is not the B01 requirement: `release_digest` pins the
    /// helper *binary's* own release digest, an unrelated supply-chain
    /// check nothing populates today).
    #[must_use]
    pub fn production() -> Self {
        Self {
            trust: production_trust(),
        }
    }
}

// ---------------------------------------------------------------------------
// Candidate helpers — upstream `advisory/denysafe.go`'s pure functions
// ---------------------------------------------------------------------------

/// `MaxCandidateAdvisoryBytes` — the operator-carried candidate bound;
/// matches the installed-envelope bound.
pub const MAX_CANDIDATE_ADVISORY_BYTES: usize = 1 << 20;

/// `SnapshotFromEnvelope` — parses operator-carried candidate bytes into
/// the [`Snapshot`] [`Verifier::verify_snapshot`] consumes: strict JSON,
/// non-empty `bundle`/`signature`, size bound. The selector binding is
/// not enforced (only installed bundles carry one); `generation_id` is
/// the fixed `"candidate"` label and `selector_digest` the raw-bytes
/// SHA-256.
///
/// # Errors
/// [`ERR_SOURCE_UNAVAILABLE`] for every refusal — the same failure
/// classification upstream wraps.
pub fn snapshot_from_envelope(raw: &[u8]) -> Result<Snapshot, Failure> {
    let unavailable =
        |msg: &str| Failure::unavailable(ERR_SOURCE_UNAVAILABLE, format!("advisory: {msg}"));
    if raw.is_empty() || raw.len() > MAX_CANDIDATE_ADVISORY_BYTES {
        return Err(unavailable("candidate size is out of bounds"));
    }
    if strict_decode(raw).is_err() {
        return Err(unavailable("candidate is not strict JSON"));
    }
    let Ok(env) = serde_json::from_slice::<EnvelopeView<'_>>(raw) else {
        return Err(unavailable("candidate does not parse"));
    };
    let signature = env.signature.unwrap_or_default();
    if signature.is_empty() || env.bundle.is_none_or(|b| b.get().is_empty()) {
        return Err(unavailable("candidate envelope is incomplete"));
    }
    let sum = Sha256::digest(raw);
    Ok(Snapshot {
        generation_id: "candidate".to_owned(),
        selector_digest: crate::authority::wire::hex_encode(&sum),
        bundle: raw.to_vec(),
        signature: signature.into_bytes(),
    })
}

/// `DigestCandidate` — the hex SHA-256 a rescue-attempt record binds to.
#[must_use]
pub fn digest_candidate(raw: &[u8]) -> String {
    crate::authority::wire::hex_encode(&Sha256::digest(raw))
}

/// `DiscardCandidate` — zeroes a candidate buffer after use.
pub fn discard_candidate(raw: &mut [u8]) {
    raw.fill(0);
}

/// `CandidateFacts` — the read-only host-facts seam
/// [`evaluate_candidate`] needs.
pub trait CandidateFacts: Send + Sync {
    /// `Collect`.
    ///
    /// # Errors
    /// Any collection failure — the caller substitutes the zero
    /// [`HostFacts`].
    fn collect(&self) -> Result<HostFacts, Failure>;
}

/// `CandidateWitness` — the read-only witness seam. Candidate
/// evaluation never advances the witness.
pub trait CandidateWitness: Send + Sync {
    /// `Load`.
    ///
    /// # Errors
    /// [`WITNESS_NOT_FOUND_CODE`] for a genuinely absent witness; any
    /// other error for an untrusted one.
    fn load(&self) -> Result<TimeWitness, Failure>;
}

/// `EvaluateCandidate` — the B01 pipeline over operator-carried bytes:
/// parse → signature verify → compatibility evaluate. Records nothing,
/// advances nothing — the deny-safe attempt record (not the advisory
/// journal) is where the outcome lands.
#[must_use]
pub fn evaluate_candidate(
    verifier: &Verifier,
    facts: &dyn CandidateFacts,
    witness: &dyn CandidateWitness,
    now: OffsetDateTime,
    raw: &[u8],
) -> (Option<VerifiedBundle>, Outcome) {
    let Ok(snapshot) = snapshot_from_envelope(raw) else {
        return (None, Outcome::denied(Code::Invalid));
    };
    let (bundle, outcome) = verifier.verify_snapshot(&snapshot);
    let Some(bundle) = bundle else {
        return (None, outcome);
    };
    let loaded = match witness.load() {
        Ok(w) => w,
        Err(f) if f.kind() == FailureKind::NotFound && f.code() == WITNESS_NOT_FOUND_CODE => {
            TimeWitness::default()
        }
        Err(_) => return (None, Outcome::denied(Code::Invalid)),
    };
    let collected = facts.collect().unwrap_or_default();
    let outcome = verifier.evaluate_verified(&bundle, &collected, &loaded, now);
    if outcome.state != State::Current {
        return (None, outcome);
    }
    (Some(bundle), outcome)
}

// ---------------------------------------------------------------------------
// EvaluationService — upstream `advisory/app/evaluate_service.go`
// ---------------------------------------------------------------------------

/// The `err` member of upstream `Evaluate`'s triple return. Carries the
/// denial [`Outcome`] the caller must still honor (always
/// `Denied`/`EvidenceUnavailable` on the record paths, the real outcome
/// on the admission-construction path) plus the persistence failure.
#[derive(Debug)]
pub struct EvaluationError {
    /// The outcome the caller must treat as the result — never `Current`
    /// on the evidence-failure paths.
    pub outcome: Outcome,
    /// The underlying witness/recorder/admission failure.
    pub source: Failure,
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for EvaluationError {}

/// `app.Service` — the single funnel every B01 evaluation flows
/// through: load → verify → witness → facts → evaluate → advance →
/// record → deny-safe → admit. Fields are upstream's public `Service`
/// fields; `deny_safe` replaces `DenySafeDir`/`DenySafeUID`/`DenySafeGID`
/// with a port because the domain cannot touch the filesystem (the
/// adapter's `DenySafeFileStore` carries the uid/gid).
///
/// The ports are generic parameters — `trait_variant` async traits are
/// not dyn-compatible, and the `Arc<T>` blanket impls in `crate::port`
/// mean both owned and shared values compose.
pub struct EvaluationService<S, F, C, W, R, D>
where
    S: ActiveBundleSource,
    F: HostFactsCollector,
    C: AdvisoryClock,
    W: TimeWitnessStore,
    R: TransitionRecorder,
    D: DenySafeStore,
{
    /// `port.ActiveBundleSource`.
    pub source: S,
    /// `port.HostFactsCollector`.
    pub facts: F,
    /// `port.Clock`.
    pub clock: C,
    /// `port.TimeWitnessStore`.
    pub witness: W,
    /// `port.TransitionRecorder`.
    pub recorder: R,
    /// `advisory.Verifier`.
    pub verifier: Verifier,
    /// The deny-safe entry port — `None` disables recording (tests,
    /// hosts without helper state), matching upstream's empty
    /// `DenySafeDir`.
    pub deny_safe: Option<D>,
}

impl<S, F, C, W, R, D> EvaluationService<S, F, C, W, R, D>
where
    S: ActiveBundleSource,
    F: HostFactsCollector,
    C: AdvisoryClock,
    W: TimeWitnessStore,
    R: TransitionRecorder,
    D: DenySafeStore,
{
    /// `Evaluate` — upstream's exact sequence, including which failures
    /// record evidence (source/verify/witness-load/refused outcomes and
    /// every evaluated outcome) and which evidence failure codes
    /// `EvidenceUnavailable` without admitting.
    ///
    /// # Errors
    /// [`EvaluationError`] when witness-advance or evidence-record fails
    /// — the returned `outcome` is the `Denied`/`EvidenceUnavailable`
    /// the caller must honor (or the real outcome on the
    /// admission-construction edge).
    pub async fn evaluate(&self) -> Result<(Outcome, Admission), EvaluationError> {
        let snapshot = match self.source.load_active().await {
            Ok(s) => s,
            Err(_) => {
                let outcome = Outcome::denied(Code::SourceUnavailable);
                self.recorder
                    .record(&outcome, None, &HostFacts::default())
                    .await
                    .map_err(|f| EvaluationError {
                        outcome: Outcome::denied(Code::EvidenceUnavailable),
                        source: f,
                    })?;
                return Ok((outcome, Admission::default()));
            }
        };

        let (bundle, outcome) = self.verifier.verify_snapshot(&snapshot);
        let Some(bundle) = bundle else {
            self.recorder
                .record(&outcome, None, &HostFacts::default())
                .await
                .map_err(|f| EvaluationError {
                    outcome: Outcome::denied(Code::EvidenceUnavailable),
                    source: f,
                })?;
            return Ok((outcome, Admission::default()));
        };

        let witness = match self.witness.load().await {
            Ok(w) => w,
            Err(f) if f.kind() == FailureKind::NotFound && f.code() == WITNESS_NOT_FOUND_CODE => {
                TimeWitness::default()
            }
            Err(_) => {
                let outcome = Outcome::denied(Code::Invalid);
                self.recorder
                    .record(&outcome, Some(&bundle), &HostFacts::default())
                    .await
                    .map_err(|f| EvaluationError {
                        outcome: Outcome::denied(Code::EvidenceUnavailable),
                        source: f,
                    })?;
                return Ok((outcome, Admission::default()));
            }
        };

        let facts = self.facts.collect().await.unwrap_or_default();

        let outcome = self
            .verifier
            .evaluate_verified(&bundle, &facts, &witness, self.clock.now());

        if outcome.state == State::Current {
            // The witness advances to the accepted bundle's own
            // issued_at — never the wall clock — so a re-evaluation of an
            // unchanged bundle compares equal rather than tripping the
            // regression check.
            let advanced = TimeWitness {
                last_accepted_at: Some(bundle.issued_at),
                last_issued_at: Some(bundle.issued_at),
            };
            self.witness
                .advance(&advanced)
                .await
                .map_err(|f| EvaluationError {
                    outcome: Outcome::denied(Code::EvidenceUnavailable),
                    source: f,
                })?;
        }

        let receipt = self
            .recorder
            .record(&outcome, Some(&bundle), &facts)
            .await
            .map_err(|f| EvaluationError {
                outcome: Outcome::denied(Code::EvidenceUnavailable),
                source: f,
            })?;

        // Hard-expired is the only state that enters deny-safe mode, and
        // this service is the only place that observes it. The entry is
        // best-effort: the refusal itself is the primary protection.
        if outcome.state == State::HardExpired
            && let Some(deny_safe) = &self.deny_safe
        {
            let _ = deny_safe
                .enter(outcome.code.as_str(), self.clock.now())
                .await;
        }

        if outcome.state == State::Current {
            let admission = Admission::new(&outcome, receipt.id).map_err(|f| EvaluationError {
                outcome: outcome.clone(),
                source: f,
            })?;
            return Ok((outcome, admission));
        }
        Ok((outcome, Admission::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::wire::b64_encode;
    use ed25519_dalek::Signer;
    use std::sync::{Arc, Mutex};
    use time::macros::datetime;

    // -- helpers ----------------------------------------------------------

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(v) => return v,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    const TEST_KEY_ID: &str = "test-key/v1";
    /// Deterministic test seed — never a production key.
    const TEST_SEED: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x01, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED,
        0xFE, 0x0F,
    ];
    /// A second key — the "wrong signer" fixture.
    const OTHER_SEED: [u8; 32] = [0x42; 32];

    fn signing_key(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(seed)
    }

    fn test_trust() -> ReleaseTrust {
        ReleaseTrust {
            key_id: TEST_KEY_ID.to_owned(),
            protocol: PRODUCTION_PROTOCOL.to_owned(),
            public_key: signing_key(&TEST_SEED).verifying_key().to_bytes(),
            release_authority_digest: String::new(),
        }
    }

    fn test_verifier() -> Verifier {
        Verifier::for_testing(test_trust())
    }

    fn bundle_json(
        issued_at: &str,
        expires_at: &str,
        compatibility: serde_json::Value,
        emergency: bool,
    ) -> String {
        serde_json::json!({
            "schema_version": 1,
            "key_id": TEST_KEY_ID,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "compatibility": compatibility,
            "emergency_deny": {"emergency": emergency, "reason": ""},
        })
        .to_string()
    }

    /// Signs `bundle_json` the way upstream `jcs.Transform` + `ed25519.Sign`
    /// does and wraps it in the `{bundle, signature}` envelope
    /// `VerifySnapshot` unwraps.
    fn signed_snapshot(bundle_json: &str, signing: &ed25519_dalek::SigningKey) -> Snapshot {
        let value: serde_json::Value = serde_json::from_str(bundle_json).expect("bundle json");
        let canonical = central_foundation::jcs::canonicalize(&value).expect("canonicalize");
        let sum = Sha256::digest(&canonical);
        let message = format!(
            "central.security-advisory/v1|bundle|SHA-256:{}",
            crate::authority::wire::hex_encode(&sum)
        );
        let signature = signing.sign(message.as_bytes());
        let signature_b64 = b64_encode(&signature.to_bytes());
        let envelope = format!("{{\"bundle\":{bundle_json},\"signature\":\"{signature_b64}\"}}");
        Snapshot {
            bundle: envelope.into_bytes(),
            signature: signature_b64.into_bytes(),
            ..Snapshot::default()
        }
    }

    fn signed_snapshot_default(bundle_json: &str) -> Snapshot {
        signed_snapshot(bundle_json, &signing_key(&TEST_SEED))
    }

    const VALID_BUNDLE: &str = concat!(
        r#"{"schema_version":1,"key_id":"test-key/v1","#,
        r#""issued_at":"2025-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","#,
        r#""compatibility":{},"emergency_deny":{"emergency":false,"reason":""}}"#
    );

    fn verified_bundle(snapshot: &Snapshot) -> VerifiedBundle {
        let (bundle, outcome) = test_verifier().verify_snapshot(snapshot);
        assert_eq!(
            outcome.state,
            State::Current,
            "fixture must verify: {outcome:?}"
        );
        bundle.expect("bundle")
    }

    const NOW: OffsetDateTime = datetime!(2025-06-01 00:00 UTC);

    // -- verify_snapshot --------------------------------------------------

    #[test]
    fn verify_snapshot_valid_bundle() {
        let snapshot = signed_snapshot_default(VALID_BUNDLE);
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert_eq!(outcome, Outcome::current());
        let bundle = bundle.expect("bundle");
        assert_eq!(bundle.key_id, TEST_KEY_ID);
        assert_eq!(bundle.issued_at, datetime!(2025-01-01 00:00 UTC));
        assert_eq!(bundle.expires_at, datetime!(2099-01-01 00:00 UTC));
        assert!(!bundle.digest.is_empty());
        assert!(!bundle.canonical.is_empty());
    }

    #[test]
    fn verify_snapshot_rejects_over_max_size() {
        let mut snapshot = signed_snapshot_default(VALID_BUNDLE);
        snapshot.bundle = vec![b' '; MAX_BUNDLE_SIZE + 1];
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::Invalid);
    }

    #[test]
    fn verify_snapshot_rejects_invalid_signature() {
        let snapshot = signed_snapshot(VALID_BUNDLE, &signing_key(&OTHER_SEED));
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::SignatureInvalid);
    }

    /// The Go-parity malleation: setting S's top three bits must refuse —
    /// the check `5cda281` pinned for the config view applies here too.
    #[test]
    fn verify_snapshot_rejects_noncanonical_s_scalar() {
        let mut snapshot = signed_snapshot_default(VALID_BUNDLE);
        let mut sig =
            b64_decode(std::str::from_utf8(&snapshot.signature).expect("utf8")).expect("b64");
        sig[63] |= 0xE0;
        snapshot.signature = b64_encode(&sig).into_bytes();
        // The envelope's own signature member must be re-written to the
        // same malleated value — the verifier reads snapshot.signature.
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.code, Code::SignatureInvalid);
    }

    /// An `R` value that does not decompress to a curve point must
    /// refuse rather than panic — the second decode check Go performs.
    #[test]
    fn verify_snapshot_rejects_undecodable_r() {
        let mut snapshot = signed_snapshot_default(VALID_BUNDLE);
        let mut sig =
            b64_decode(std::str::from_utf8(&snapshot.signature).expect("utf8")).expect("b64");
        // A non-canonical point encoding: 2^255-19 + 19 = p is not a
        // field element; p+1 in little-endian is definitely invalid.
        for b in &mut sig[..32] {
            *b = 0xFF;
        }
        snapshot.signature = b64_encode(&sig).into_bytes();
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.code, Code::SignatureInvalid);
    }

    /// A non-canonical-but-decompressible `R` — `y = p` little-endian
    /// (`0xED 0xFF…0xFF 0x7F`), which reduces to the valid `y = 0`
    /// point — must refuse. Both Go's `SetBytes` and dalek's
    /// `decompress` *accept* the encoding, so the refusal comes from
    /// the recomputed-R canonical byte-compare inside `verify` —
    /// upstream's exact mechanism, pinned here so a laxer equation
    /// check (point equality instead of byte equality) cannot slip in.
    #[test]
    fn verify_snapshot_rejects_noncanonical_r_encoding() {
        let mut noncanonical_r = [0xFFu8; 32];
        noncanonical_r[0] = 0xED;
        noncanonical_r[31] = 0x7F;
        // The premise: `y = p` decompresses (it is a non-canonical
        // encoding of a valid point, not a non-point), so an
        // all-0xFF-style test would not isolate the canonicality gap.
        assert!(
            VerifyingKey::from_bytes(&noncanonical_r).is_ok(),
            "y = p must decompress for this test to isolate byte-compare rejection"
        );
        let mut snapshot = signed_snapshot_default(VALID_BUNDLE);
        let mut sig =
            b64_decode(std::str::from_utf8(&snapshot.signature).expect("utf8")).expect("b64");
        sig[..32].copy_from_slice(&noncanonical_r);
        snapshot.signature = b64_encode(&sig).into_bytes();
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.code, Code::SignatureInvalid);
    }

    #[test]
    fn verify_snapshot_rejects_wrong_key_id() {
        let bundle_json = VALID_BUNDLE.replace("test-key/v1", "test-key/other");
        let snapshot = signed_snapshot_default(&bundle_json);
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::Invalid);
    }

    /// A bundle signed under the retired v1 id must deny under v2 trust —
    /// the production path's key-id check, pinned.
    #[test]
    fn verify_snapshot_refuses_v1_key_id_under_v2_trust() {
        let verifier = Verifier::production();
        let bundle_json = VALID_BUNDLE.replace("test-key/v1", "central-release-authority/v1");
        // Sign with the test key — v2 verification never runs: the
        // signature itself must already fail.
        let snapshot = signed_snapshot_default(&bundle_json);
        let (bundle, outcome) = verifier.verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.state, State::Denied);
        // The v2 public key can't verify a test-key signature.
        assert_eq!(outcome.code, Code::SignatureInvalid);
        assert_eq!(verifier.trust().key_id, PRODUCTION_KEY_ID);
    }

    #[test]
    fn verify_snapshot_rejects_malformed_base64() {
        let mut snapshot = signed_snapshot_default(VALID_BUNDLE);
        snapshot.signature = b"!!not-base64!!".to_vec();
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.code, Code::SignatureInvalid);
    }

    #[test]
    fn verify_snapshot_rejects_wrong_signature_size() {
        for bad in [&b64_encode(&[0xAA; 63]), &b64_encode(&[0xAA; 65])] {
            let mut snapshot = signed_snapshot_default(VALID_BUNDLE);
            snapshot.signature = bad.clone().into_bytes();
            let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
            assert!(bundle.is_none(), "size must refuse");
            assert_eq!(outcome.code, Code::SignatureInvalid);
        }
    }

    #[test]
    fn verify_snapshot_rejects_unknown_bundle_field() {
        let bundle_json = VALID_BUNDLE.replace(
            r#""emergency_deny""#,
            r#""unexpected":true,"emergency_deny""#,
        );
        let snapshot = signed_snapshot_default(&bundle_json);
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.code, Code::Invalid);
    }

    #[test]
    fn verify_snapshot_rejects_unsupported_schema() {
        let bundle_json = VALID_BUNDLE.replace(r#""schema_version":1"#, r#""schema_version":2"#);
        let snapshot = signed_snapshot_default(&bundle_json);
        let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
        assert!(bundle.is_none());
        assert_eq!(outcome.code, Code::Invalid);
    }

    #[test]
    fn verify_snapshot_rejects_bad_timestamps() {
        for field in ["issued_at", "expires_at"] {
            let bundle_json = VALID_BUNDLE.replace(
                &format!(r#""{field}":"2"#),
                &format!(r#""{field}":"not-a-time"#),
            );
            let snapshot = signed_snapshot_default(&bundle_json);
            let (bundle, outcome) = test_verifier().verify_snapshot(&snapshot);
            assert!(bundle.is_none(), "{field} must parse");
            assert_eq!(outcome.code, Code::Invalid);
        }
    }

    #[test]
    fn verify_snapshot_rejects_non_object_bundle() {
        // `bundle` must be a JSON object or `null`; a string member is a
        // typed-unmarshal error upstream.
        for raw in [
            r#"{"bundle":"e30=","signature":"e30="}"#,
            r#"{"bundle":[1,2],"signature":"e30="}"#,
            r#"{"bundle":1.5,"signature":"e30="}"#,
        ] {
            let snapshot = Snapshot {
                bundle: raw.as_bytes().to_vec(),
                signature: b"e30=".to_vec(),
                ..Snapshot::default()
            };
            let (_, outcome) = test_verifier().verify_snapshot(&snapshot);
            assert_eq!(outcome.state, State::Denied, "{raw}");
            assert_eq!(outcome.code, Code::Invalid);
        }
    }

    // -- strict_decode ----------------------------------------------------

    #[test]
    fn strict_decode_accepts_valid() {
        strict_decode(br#"{"a":1,"b":[true,null,"x"],"c":{"d":{}}}"#).expect("valid");
        strict_decode(b"{}").expect("empty object");
        strict_decode(b"[]").expect("empty array");
        strict_decode(b"").expect("empty input is valid upstream");
        strict_decode(b"5").expect("bare number");
    }

    #[test]
    fn strict_decode_rejects_duplicate_key() {
        assert_eq!(
            strict_decode(br#"{"a":1,"a":2}"#),
            Err(StrictError::DuplicateKey)
        );
        // Nested frame duplicates are independent.
        strict_decode(br#"{"a":{"b":1},"b":2}"#).expect("different frames");
        assert_eq!(
            strict_decode(br#"{"a":{"x":1,"x":2}}"#),
            Err(StrictError::DuplicateKey)
        );
        // Escaped-key equality: "\u0061" IS the key "a".
        assert_eq!(
            strict_decode(br#"{"a":1,"a":2}"#),
            Err(StrictError::DuplicateKey)
        );
    }

    #[test]
    fn strict_decode_too_deep() {
        let mut nested = String::new();
        for _ in 0..33 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..33 {
            nested.push('}');
        }
        assert_eq!(strict_decode(nested.as_bytes()), Err(StrictError::TooDeep));
        // Exactly 32 containers deep is admitted.
        let mut ok = String::new();
        for _ in 0..32 {
            ok.push_str("{\"a\":");
        }
        ok.push('1');
        for _ in 0..32 {
            ok.push('}');
        }
        strict_decode(ok.as_bytes()).expect("32 deep ok");
    }

    #[test]
    fn strict_decode_too_many_members() {
        let mut obj = String::from("{");
        for i in 0..1001 {
            if i > 0 {
                obj.push(',');
            }
            obj.push_str(&format!("\"k{i}\":0"));
        }
        obj.push('}');
        assert_eq!(
            strict_decode(obj.as_bytes()),
            Err(StrictError::TooManyMembers)
        );
        let mut ok = String::from("{");
        for i in 0..1000 {
            if i > 0 {
                ok.push(',');
            }
            ok.push_str(&format!("\"k{i}\":0"));
        }
        ok.push('}');
        strict_decode(ok.as_bytes()).expect("1000 members ok");
    }

    #[test]
    fn strict_decode_string_too_long() {
        let long = format!("\"{}\"", "x".repeat(STRICT_MAX_STRING + 1));
        assert_eq!(
            strict_decode(long.as_bytes()),
            Err(StrictError::StringTooLong)
        );
        let ok = format!("\"{}\"", "x".repeat(STRICT_MAX_STRING));
        strict_decode(ok.as_bytes()).expect("16KiB string ok");
        // The bound applies to keys too.
        let obj = format!("{{\"{}\":0}}", "k".repeat(STRICT_MAX_STRING + 1));
        assert_eq!(
            strict_decode(obj.as_bytes()),
            Err(StrictError::StringTooLong)
        );
    }

    #[test]
    fn strict_decode_trailing_garbage() {
        assert_eq!(strict_decode(b"{}{}"), Err(StrictError::TrailingGarbage));
        assert_eq!(strict_decode(b"{} 5"), Err(StrictError::TrailingGarbage));
        assert_eq!(
            strict_decode(b"{} \"x\""),
            Err(StrictError::TrailingGarbage)
        );
        assert_eq!(strict_decode(b"{} true"), Err(StrictError::TrailingGarbage));
        // Malformed tails are *accepted* — Go's Token() error means the
        // single-value contract held.
        strict_decode(b"{} xyz").expect("malformed tail accepted");
        strict_decode(b"{} }").expect("stray closer accepted");
        strict_decode(b"{} \"unterminated").expect("bad tail accepted");
        strict_decode(b"{} 5e").expect("incomplete number tail accepted");
    }

    #[test]
    fn strict_decode_rejects_invalid_utf8() {
        assert_eq!(
            strict_decode(b"{\"a\":\"\xFF\"}"),
            Err(StrictError::InvalidUtf8)
        );
    }

    #[test]
    fn strict_decode_rejects_noncanonical_numbers() {
        for raw in [b"1e5" as &[u8], b"1E5", b"1e+5", b"1.5e-3"] {
            assert_eq!(
                strict_decode(raw),
                Err(StrictError::NonCanonicalNumber),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
        // A leading `+` never becomes a number token upstream — the Go
        // scanner rejects it before the I-JSON arm — so it is Malformed,
        // not NonCanonicalNumber.
        assert_eq!(strict_decode(b"+5"), Err(StrictError::Malformed));
        strict_decode(b"1.5").expect("decimal ok");
        strict_decode(b"-0").expect("neg zero ok");
    }

    /// Upstream's token-walk quirk: strings inside an *array* alternate
    /// key/value roles — `["a","b","a"]` counts `"a"` twice in one frame
    /// and the third lands on the key arm → duplicate.
    #[test]
    fn strict_decode_array_alternation_quirk() {
        assert_eq!(
            strict_decode(br#"["a","b","c","b"]"#),
            Err(StrictError::DuplicateKey)
        );
        strict_decode(br#"["a","b"]"#).expect("two strings alternate");
        // Even-index positions are values, odd-index positions are keys —
        // `["a","a"]` is accepted because the second "a" is a *fresh* key.
        strict_decode(br#"["a","a"]"#).expect("even index is a value");
        assert_eq!(
            strict_decode(br#"["a","a","a","a"]"#),
            Err(StrictError::DuplicateKey)
        );
        // A non-string token still leaves nextKey = true: the next string
        // lands on the key arm, and its first insert is fresh.
        strict_decode(br#"["a",1,"a"]"#).expect("scalar leaves key arm fresh");
    }

    #[test]
    fn strict_decode_malformed_inputs() {
        for raw in [
            b"{\"a\" 1}" as &[u8], // missing colon
            b"{\"a\":1 \"b\":2}",  // missing comma
            b"{\"a\":1,}",         // trailing comma
            b"{,}",                // comma first
            b"{",                  // truncated object
            b"[1 2]",              // missing comma
            b"[1,",                // truncated array
            b"]",                  // stray closer
            b"}",                  // stray closer
            b"tru",                // bad literal
            b"01",                 // leading zero
            b"-",                  // bare minus
            b"5.",                 // trailing dot
            b"\"a\x01b\"",         // raw control in string
            b"\"\\x\"",            // bad escape
        ] {
            assert!(
                strict_decode(raw).is_err(),
                "{:?} must refuse",
                String::from_utf8_lossy(raw)
            );
        }
    }

    // -- evaluate_verified ------------------------------------------------

    /// A bundle whose only deviations from `VALID_BUNDLE` are the named
    /// timestamps — still signed correctly by the test key.
    fn bundle_times(issued_at: &str, expires_at: &str) -> VerifiedBundle {
        verified_bundle(&signed_snapshot_default(&bundle_json(
            issued_at,
            expires_at,
            serde_json::json!({}),
            false,
        )))
    }

    #[test]
    fn evaluate_verified_rejects_future_issue_time() {
        let bundle = bundle_times("2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW,
        );
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::Invalid);
    }

    #[test]
    fn evaluate_verified_expiry_boundary() {
        let bundle = bundle_times("2025-01-01T00:00:00Z", "2025-06-01T00:00:00Z");
        // now == expires_at → still current (upstream compares After).
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW,
        );
        assert_eq!(outcome.state, State::Current);
        // now > expires_at → stale.
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW + time::Duration::seconds(1),
        );
        assert_eq!(outcome.state, State::Stale);
        assert_eq!(outcome.code, Code::Expired);
    }

    #[test]
    fn evaluate_verified_hard_expiry() {
        let bundle = bundle_times("2025-01-01T00:00:00Z", "2025-05-24T00:00:00Z");
        // expires + 7d = 2025-05-31 → now > hard expiry.
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            datetime!(2025-06-01 00:00:01 UTC),
        );
        assert_eq!(outcome.state, State::HardExpired);
        assert_eq!(outcome.code, Code::HardExpired);
    }

    #[test]
    fn evaluate_verified_emergency_deny() {
        let bundle = verified_bundle(&signed_snapshot_default(&bundle_json(
            "2025-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            serde_json::json!({}),
            true,
        )));
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW,
        );
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::EmergencyDeny);
    }

    /// Emergency deny is checked first — a hard-expired emergency bundle
    /// reports EmergencyDeny, not HardExpired.
    #[test]
    fn evaluate_verified_emergency_precedes_hard_expiry() {
        let bundle = verified_bundle(&signed_snapshot_default(&bundle_json(
            "2025-01-01T00:00:00Z",
            "2025-02-01T00:00:00Z",
            serde_json::json!({}),
            true,
        )));
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW,
        );
        assert_eq!(outcome.code, Code::EmergencyDeny);
    }

    #[test]
    fn evaluate_verified_host_mismatch_table() {
        for check in ["os_release", "kernel", "docker", "compose", "psql"] {
            let pin = serde_json::json!({check: "expected-1"});
            let bundle = verified_bundle(&signed_snapshot_default(&bundle_json(
                "2025-01-01T00:00:00Z",
                "2099-01-01T00:00:00Z",
                pin,
                false,
            )));
            let mut facts = HostFacts::default();
            match check {
                "os_release" => facts.os_release = "different-1".into(),
                "kernel" => facts.kernel = "different-1".into(),
                "docker" => facts.docker = "different-1".into(),
                "compose" => facts.compose = "different-1".into(),
                "psql" => facts.psql = "different-1".into(),
                _ => {}
            }
            let outcome =
                test_verifier().evaluate_verified(&bundle, &facts, &TimeWitness::default(), NOW);
            assert_eq!(outcome.state, State::Stale, "{check}");
            assert_eq!(outcome.code, Code::HostMismatch);
            assert_eq!(outcome.check, check);
        }
    }

    #[test]
    fn evaluate_verified_matching_facts_current() {
        let pin = serde_json::json!({
            "os_release": "24.04",
            "kernel": "6.8.0",
            "docker": "27.0",
            "compose": "2.29",
            "psql": "16.4",
        });
        let bundle = verified_bundle(&signed_snapshot_default(&bundle_json(
            "2025-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            pin,
            false,
        )));
        let facts = HostFacts {
            os_release: "24.04".into(),
            kernel: "6.8.0".into(),
            docker: "27.0".into(),
            compose: "2.29".into(),
            psql: "16.4".into(),
        };
        let outcome =
            test_verifier().evaluate_verified(&bundle, &facts, &TimeWitness::default(), NOW);
        assert_eq!(outcome.state, State::Current);
        // Unknown facts (empty) never trip a non-empty pin — upstream
        // semantics — and empty pins never trip known facts.
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW,
        );
        assert_eq!(outcome.state, State::Current);
    }

    #[test]
    fn evaluate_verified_regressed_witness() {
        let bundle = verified_bundle(&signed_snapshot_default(VALID_BUNDLE));
        let witness = TimeWitness {
            last_accepted_at: Some(datetime!(2025-02-01 00:00 UTC)),
            last_issued_at: Some(datetime!(2025-02-01 00:00 UTC)),
        };
        let outcome =
            test_verifier().evaluate_verified(&bundle, &HostFacts::default(), &witness, NOW);
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::Invalid);
        // Equal witness timestamps are NOT a regression.
        let witness = TimeWitness {
            last_accepted_at: Some(datetime!(2025-01-01 00:00 UTC)),
            last_issued_at: Some(datetime!(2025-01-01 00:00 UTC)),
        };
        let outcome =
            test_verifier().evaluate_verified(&bundle, &HostFacts::default(), &witness, NOW);
        assert_eq!(outcome.state, State::Current);
        // No prior witness → current.
        let outcome = test_verifier().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            NOW,
        );
        assert_eq!(outcome.state, State::Current);
    }

    // -- release key ------------------------------------------------------

    #[test]
    fn production_verifier_accepts_matching_digest() {
        let binding = InstanceBinding {
            release_digest: production_release_authority_digest_for_testing(),
            ..fixture_binding()
        };
        new_production_verifier(&binding).expect("matching digest");
    }

    #[test]
    fn production_verifier_rejects_mismatched_digest() {
        let binding = InstanceBinding {
            release_digest: "beef".repeat(16),
            ..fixture_binding()
        };
        let err = new_production_verifier(&binding)
            .err()
            .expect("mismatched digest must refuse");
        assert_eq!(err.code(), ERR_RELEASE_AUTHORITY_MISMATCH);
    }

    /// The compiled trust's key, protocol, and digest are pinned to the
    /// upstream `packaging/install/advisory-bundle.json` fixture's
    /// signing identity — including the base64↔bytes equivalence the
    /// upstream panic guard enforced.
    #[test]
    fn production_trust_is_pinned() {
        let trust = production_trust();
        assert_eq!(trust.key_id, "central-release-authority/v2");
        assert_eq!(trust.protocol, "central.security-advisory/v1");
        let decoded = b64_decode(PRODUCTION_RELEASE_AUTHORITY_PUBLIC_KEY_BASE64).expect("b64");
        assert_eq!(decoded.as_slice(), &PRODUCTION_RELEASE_AUTHORITY_PUBLIC_KEY);
        assert_eq!(
            crate::authority::wire::hex_encode(&trust.public_key),
            "aaf5ed3422ee121ad9db1de7c1a5c80aeab8472b46921455114dc366d9197510"
        );
        assert_eq!(
            production_release_authority_digest_for_testing(),
            "bef5edef6abe9a1f437ffa3630508b2d78f420e49142dc752ff8a5664969057d"
        );
    }

    fn fixture_binding() -> InstanceBinding {
        use central_foundation::identity::{ConfigBindingId, InstanceId};
        InstanceBinding {
            instance_id: InstanceId::new(),
            host_id: "host".into(),
            release_digest: String::new(),
            created_at: NOW,
            config_binding_id: ConfigBindingId::new(),
            uid_gid: crate::authority::UidGidMap {
                runtime_uid: 0,
                runtime_gid: 0,
                agent_uid: 0,
                agent_gid: 0,
                browser_uid: 0,
                browser_gid: 0,
            },
        }
    }

    // -- upstream signed fixture parity ------------------------------------

    /// The real `packaging/install/advisory-bundle.json` — signed offline
    /// with the v2 release key — must verify `Current` under
    /// `Verifier::production()`. This is the byte-exact upstream vector:
    /// the JCS canonical digest and the Ed25519 signature were produced
    /// by Go code, so agreement proves the whole verify chain.
    #[test]
    fn packaged_bundle_verifies_against_pinned_trust() {
        let raw = include_bytes!("testdata/advisory-bundle.json");
        strict_decode(raw).expect("packaged bundle is strict JSON");
        let snapshot = snapshot_from_envelope(raw).expect("envelope");
        let (bundle, outcome) = Verifier::production().verify_snapshot(&snapshot);
        assert_eq!(
            outcome.state,
            State::Current,
            "packaged bundle state: {outcome:?}"
        );
        let bundle = bundle.expect("bundle");
        assert_eq!(bundle.key_id, "central-release-authority/v2");
        // Pinned JCS-canonical digest — computed once against upstream's
        // own jcs.Transform of the same bytes.
        assert_eq!(
            bundle.digest,
            "725c16b82837f2488ced40c153f634293f558fb8692e825327b292df2968d351"
        );
        assert_eq!(bundle.issued_at, datetime!(2026-10-02 12:54:36 UTC));
        assert_eq!(bundle.expires_at, datetime!(2026-12-31 12:54:36 UTC));
        // All compatibility pins are empty and emergency deny is unset —
        // the packaged fixture's required shape.
        assert_eq!(bundle.compatibility, CompatibilityMatrix::default());
        assert!(!bundle.emergency_deny.emergency);
        // The inner bundle's canonical form is byte-pinned too.
        assert_eq!(
            std::str::from_utf8(&bundle.canonical).expect("utf8"),
            "{\"compatibility\":{\"compose\":\"\",\"docker\":\"\",\"kernel\":\"\",\"os_release\":\"\",\"psql\":\"\"},\"emergency_deny\":{\"emergency\":false,\"reason\":\"\"},\"expires_at\":\"2026-12-31T12:54:36Z\",\"issued_at\":\"2026-10-02T12:54:36Z\",\"key_id\":\"central-release-authority/v2\",\"schema_version\":1}"
        );
        // Evaluation against the packaged window: in-window → current;
        // past expiry → stale; past hard expiry → hard_expired.
        let outcome = Verifier::production().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            datetime!(2026-11-01 00:00 UTC),
        );
        assert_eq!(outcome.state, State::Current);
        let outcome = Verifier::production().evaluate_verified(
            &bundle,
            &HostFacts::default(),
            &TimeWitness::default(),
            datetime!(2027-01-01 00:00 UTC),
        );
        assert_eq!(outcome.state, State::Stale);
        assert_eq!(outcome.code, Code::Expired);
    }

    // -- candidate helpers -------------------------------------------------

    #[test]
    fn snapshot_from_envelope_refuses_garbage() {
        for raw in [
            &b""[..],
            b"not json",
            br#"{"bundle":"e30="}"#,
            br#"{"signature":"e30="}"#,
        ] {
            assert!(snapshot_from_envelope(raw).is_err(), "{raw:?}");
        }
        let oversized = vec![b' '; MAX_CANDIDATE_ADVISORY_BYTES + 1];
        assert!(snapshot_from_envelope(&oversized).is_err());
    }

    #[test]
    fn snapshot_from_envelope_carries_whole_envelope() {
        let snapshot = signed_snapshot_default(VALID_BUNDLE);
        let parsed = snapshot_from_envelope(&snapshot.bundle).expect("parse");
        assert_eq!(parsed.generation_id, "candidate");
        assert_eq!(parsed.bundle, snapshot.bundle);
        assert_eq!(parsed.signature, snapshot.signature);
        assert_eq!(parsed.selector_digest, digest_candidate(&snapshot.bundle));
    }

    struct CountingWitness {
        loads: Mutex<usize>,
        err: Option<Failure>,
    }
    impl CandidateWitness for CountingWitness {
        fn load(&self) -> Result<TimeWitness, Failure> {
            *self.loads.lock().unwrap() += 1;
            match &self.err {
                Some(f) => Err(f.clone()),
                None => Ok(TimeWitness::default()),
            }
        }
    }
    struct CountingFacts {
        collects: Mutex<usize>,
    }
    impl CandidateFacts for CountingFacts {
        fn collect(&self) -> Result<HostFacts, Failure> {
            *self.collects.lock().unwrap() += 1;
            Ok(HostFacts::default())
        }
    }

    /// An unverifiable candidate never reaches the witness or facts —
    /// the refusal happens at parse/verify, before any state is
    /// consulted.
    #[test]
    fn evaluate_candidate_refuses_invalid_without_touching_witness() {
        let witness = CountingWitness {
            loads: Mutex::new(0),
            err: None,
        };
        let facts = CountingFacts {
            collects: Mutex::new(0),
        };
        let (bundle, outcome) =
            evaluate_candidate(&test_verifier(), &facts, &witness, NOW, br#"{"nope":true}"#);
        assert!(bundle.is_none());
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(*witness.loads.lock().unwrap(), 0);
        assert_eq!(*facts.collects.lock().unwrap(), 0);
    }

    #[test]
    fn evaluate_candidate_current_round_trip() {
        let witness = CountingWitness {
            loads: Mutex::new(0),
            err: None,
        };
        let facts = CountingFacts {
            collects: Mutex::new(0),
        };
        let snapshot = signed_snapshot_default(VALID_BUNDLE);
        let (bundle, outcome) =
            evaluate_candidate(&test_verifier(), &facts, &witness, NOW, &snapshot.bundle);
        assert_eq!(outcome.state, State::Current);
        assert!(bundle.is_some());
        assert_eq!(*witness.loads.lock().unwrap(), 1);
        assert_eq!(*facts.collects.lock().unwrap(), 1);
    }

    #[test]
    fn discard_candidate_zeroes() {
        let mut raw = vec![0xAB; 16];
        discard_candidate(&mut raw);
        assert!(raw.iter().all(|b| *b == 0));
    }

    // -- Admission ---------------------------------------------------------

    #[test]
    fn admission_requires_current_and_receipt() {
        for state in [State::Stale, State::Denied, State::HardExpired] {
            let outcome = Outcome::new(state, Code::Unset);
            assert!(Admission::new(&outcome, "r1").is_err(), "{state:?}");
        }
        let current = Outcome::current();
        assert!(Admission::new(&current, "").is_err());
        let admission = Admission::new(&current, "receipt-1").expect("admission");
        assert_eq!(admission.receipt_id(), "receipt-1");
        assert!(!admission.is_zero());
        assert!(Admission::default().is_zero());
        assert!(Admission::from_receipt("").is_none());
        assert!(Admission::from_receipt("r").is_some());
        // Codes are distinct machine strings.
        let codes: std::collections::HashSet<_> = [
            Code::Invalid,
            Code::SignatureInvalid,
            Code::Expired,
            Code::HardExpired,
            Code::HostMismatch,
            Code::EmergencyDeny,
            Code::SourceUnavailable,
            Code::EvidenceUnavailable,
        ]
        .iter()
        .copied()
        .map(Code::as_str)
        .collect();
        assert_eq!(codes.len(), 8);
    }

    // -- EvaluationService -------------------------------------------------

    struct StubSource {
        snapshot: Result<Snapshot, Failure>,
    }
    impl ActiveBundleSource for StubSource {
        async fn load_active(&self) -> Result<Snapshot, Failure> {
            self.snapshot.clone()
        }
    }

    struct StubFacts {
        facts: Result<HostFacts, Failure>,
    }
    impl HostFactsCollector for StubFacts {
        async fn collect(&self) -> Result<HostFacts, Failure> {
            self.facts.clone()
        }
    }

    struct FixedClock(OffsetDateTime);
    impl AdvisoryClock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    struct StubWitness {
        loaded: Mutex<TimeWitness>,
        load_err: Option<Failure>,
        advanced: Mutex<Vec<TimeWitness>>,
        advance_err: Option<Failure>,
    }
    impl StubWitness {
        fn ok() -> Self {
            Self {
                loaded: Mutex::new(TimeWitness::default()),
                load_err: None,
                advanced: Mutex::new(Vec::new()),
                advance_err: None,
            }
        }
    }
    impl TimeWitnessStore for StubWitness {
        async fn load(&self) -> Result<TimeWitness, Failure> {
            match &self.load_err {
                Some(f) => Err(f.clone()),
                None => Ok(*self.loaded.lock().unwrap()),
            }
        }
        async fn advance(&self, witness: &TimeWitness) -> Result<(), Failure> {
            match &self.advance_err {
                Some(f) => Err(f.clone()),
                None => {
                    self.advanced.lock().unwrap().push(*witness);
                    Ok(())
                }
            }
        }
    }

    struct StubRecorder {
        receipt: Receipt,
        calls: Mutex<Vec<(Outcome, bool, HostFacts)>>,
        err: Option<Failure>,
    }
    impl StubRecorder {
        fn ok() -> Self {
            Self {
                receipt: Receipt {
                    id: "receipt-1".into(),
                    sequence: 1,
                },
                calls: Mutex::new(Vec::new()),
                err: None,
            }
        }
    }
    impl TransitionRecorder for StubRecorder {
        async fn record(
            &self,
            outcome: &Outcome,
            bundle: Option<&VerifiedBundle>,
            facts: &HostFacts,
        ) -> Result<Receipt, Failure> {
            self.calls
                .lock()
                .unwrap()
                .push((outcome.clone(), bundle.is_some(), facts.clone()));
            match &self.err {
                Some(f) => Err(f.clone()),
                None => Ok(self.receipt.clone()),
            }
        }
    }

    struct SpyDenySafe {
        entries: Mutex<Vec<(String, OffsetDateTime)>>,
    }
    impl DenySafeStore for SpyDenySafe {
        async fn enter(&self, trigger_code: &str, now: OffsetDateTime) -> Result<(), Failure> {
            self.entries
                .lock()
                .unwrap()
                .push((trigger_code.to_owned(), now));
            Ok(())
        }
    }

    struct ServiceFixture {
        source: Arc<StubSource>,
        facts: Arc<StubFacts>,
        witness: Arc<StubWitness>,
        recorder: Arc<StubRecorder>,
        deny_safe: Arc<SpyDenySafe>,
    }

    impl ServiceFixture {
        #[allow(clippy::type_complexity)]
        fn service(
            &self,
        ) -> EvaluationService<
            Arc<StubSource>,
            Arc<StubFacts>,
            Arc<FixedClock>,
            Arc<StubWitness>,
            Arc<StubRecorder>,
            Arc<SpyDenySafe>,
        > {
            EvaluationService {
                source: self.source.clone(),
                facts: self.facts.clone(),
                clock: Arc::new(FixedClock(NOW)),
                witness: self.witness.clone(),
                recorder: self.recorder.clone(),
                verifier: test_verifier(),
                deny_safe: Some(self.deny_safe.clone()),
            }
        }
        fn new(snapshot: Result<Snapshot, Failure>) -> Self {
            Self {
                source: Arc::new(StubSource { snapshot }),
                facts: Arc::new(StubFacts {
                    facts: Ok(HostFacts::default()),
                }),
                witness: Arc::new(StubWitness::ok()),
                recorder: Arc::new(StubRecorder::ok()),
                deny_safe: Arc::new(SpyDenySafe {
                    entries: Mutex::new(Vec::new()),
                }),
            }
        }
    }

    #[test]
    fn service_source_failure_denies_and_records() {
        let fx = ServiceFixture::new(Err(Failure::internal("t", "gone")));
        let err = block_on(fx.service().evaluate());
        let (outcome, admission) = err.expect("no eval error");
        assert_eq!(outcome.code, Code::SourceUnavailable);
        assert_eq!(outcome.state, State::Denied);
        assert!(admission.is_zero());
        let calls = fx.recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.code, Code::SourceUnavailable);
        assert!(!calls[0].1, "no bundle on source failure");
    }

    #[test]
    fn service_invalid_signature_denies_before_facts() {
        let snapshot = signed_snapshot(VALID_BUNDLE, &signing_key(&OTHER_SEED));
        let fx = ServiceFixture::new(Ok(snapshot));
        let (outcome, admission) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.code, Code::SignatureInvalid);
        assert!(admission.is_zero());
        let calls = fx.recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].1, "no bundle evidence on verify failure");
    }

    #[test]
    fn service_expired_is_stale() {
        // NOW is 2025-06-01: expired 2025-05-30 but still inside the
        // seven-day hard-expiry grace (hard edge 2025-06-06).
        let bundle = bundle_json(
            "2025-01-01T00:00:00Z",
            "2025-05-30T00:00:00Z",
            serde_json::json!({}),
            false,
        );
        let fx = ServiceFixture::new(Ok(signed_snapshot_default(&bundle)));
        let (outcome, _) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Stale);
        assert_eq!(outcome.code, Code::Expired);
        assert!(fx.witness.advanced.lock().unwrap().is_empty());
    }

    #[test]
    fn service_current_admits_with_receipt_and_advances() {
        let fx = ServiceFixture::new(Ok(signed_snapshot_default(VALID_BUNDLE)));
        let (outcome, admission) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Current);
        assert_eq!(admission.receipt_id(), "receipt-1");
        // The witness advanced to the bundle's issued_at — never the
        // wall clock.
        let advanced = fx.witness.advanced.lock().unwrap();
        assert_eq!(advanced.len(), 1);
        assert_eq!(
            advanced[0].last_accepted_at,
            Some(datetime!(2025-01-01 00:00 UTC))
        );
        assert_eq!(
            advanced[0].last_issued_at,
            Some(datetime!(2025-01-01 00:00 UTC))
        );
        // Evidence carries the verified bundle.
        let calls = fx.recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1);
    }

    /// A missing witness is the legitimate first acceptance; a corrupt
    /// one denies — and is never advanced.
    #[test]
    fn service_missing_witness_admits() {
        let mut fx = ServiceFixture::new(Ok(signed_snapshot_default(VALID_BUNDLE)));
        fx.witness = Arc::new(StubWitness {
            load_err: Some(Failure::not_found(WITNESS_NOT_FOUND_CODE, "not written")),
            ..StubWitness::ok()
        });
        let (outcome, admission) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Current);
        assert_eq!(admission.receipt_id(), "receipt-1");
    }

    #[test]
    fn service_corrupt_witness_denies_never_advances() {
        let mut fx = ServiceFixture::new(Ok(signed_snapshot_default(VALID_BUNDLE)));
        fx.witness = Arc::new(StubWitness {
            load_err: Some(Failure::internal("t", "corrupt")),
            ..StubWitness::ok()
        });
        let (outcome, admission) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::Invalid);
        assert!(admission.is_zero());
        assert!(fx.witness.advanced.lock().unwrap().is_empty());
        let calls = fx.recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.code, Code::Invalid);
        assert!(calls[0].1, "bundle evidence on corrupt witness");
    }

    #[test]
    fn service_recorder_failure_is_evidence_unavailable() {
        let mut fx = ServiceFixture::new(Ok(signed_snapshot_default(VALID_BUNDLE)));
        fx.recorder = Arc::new(StubRecorder {
            err: Some(Failure::internal("t", "journal down")),
            ..StubRecorder::ok()
        });
        let err = block_on(fx.service().evaluate()).expect_err("evidence failure");
        assert_eq!(err.outcome.code, Code::EvidenceUnavailable);
        assert_eq!(err.outcome.state, State::Denied);
    }

    /// A witness-advance failure denies rather than admitting — the
    /// receipt is never even requested.
    #[test]
    fn service_advance_failure_is_evidence_unavailable() {
        let mut fx = ServiceFixture::new(Ok(signed_snapshot_default(VALID_BUNDLE)));
        fx.witness = Arc::new(StubWitness {
            advance_err: Some(Failure::internal("t", "read-only fs")),
            ..StubWitness::ok()
        });
        let err = block_on(fx.service().evaluate()).expect_err("evidence failure");
        assert_eq!(err.outcome.code, Code::EvidenceUnavailable);
        assert!(fx.recorder.calls.lock().unwrap().is_empty());
    }

    /// The fail-closed requirement: a host whose collected facts
    /// mismatch the advisory's pins refuses *before* any admission — the
    /// outcome is `stale`/`ADVISORY_HOST_MISMATCH` and no admission
    /// object exists to pass downstream.
    #[test]
    fn service_unsupported_host_refused_before_admission() {
        let compat = serde_json::json!({
            "os_release": "22.04",
            "kernel": "",
            "docker": "",
            "compose": "",
            "psql": "",
        });
        let bundle = bundle_json(
            "2025-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            compat,
            false,
        );
        let mut fx = ServiceFixture::new(Ok(signed_snapshot_default(&bundle)));
        fx.facts = Arc::new(StubFacts {
            facts: Ok(HostFacts {
                os_release: "24.04".into(),
                ..HostFacts::default()
            }),
        });
        let (outcome, admission) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Stale);
        assert_eq!(outcome.code, Code::HostMismatch);
        assert_eq!(outcome.check, "os_release");
        assert!(admission.is_zero());
        assert!(fx.witness.advanced.lock().unwrap().is_empty());
    }

    #[test]
    fn service_emergency_deny_denies() {
        let bundle_json = VALID_BUNDLE.replace(r#""emergency":false"#, r#""emergency":true"#);
        let fx = ServiceFixture::new(Ok(signed_snapshot_default(&bundle_json)));
        let (outcome, _) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Denied);
        assert_eq!(outcome.code, Code::EmergencyDeny);
    }

    /// Hard-expired enters deny-safe with the result's code — the one
    /// funnel upstream guarantees.
    #[test]
    fn service_hard_expired_enters_deny_safe() {
        // NOW is 2025-06-01: expires 2025-05-20, hard edge 2025-05-27 —
        // already past, so this is a hard expiry.
        let bundle = bundle_json(
            "2025-01-01T00:00:00Z",
            "2025-05-20T00:00:00Z",
            serde_json::json!({}),
            false,
        );
        let fx = ServiceFixture::new(Ok(signed_snapshot_default(&bundle)));
        let (outcome, _) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::HardExpired);
        let entries = fx.deny_safe.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, Code::HardExpired.as_str());
    }

    #[test]
    fn service_current_does_not_enter_deny_safe() {
        let fx = ServiceFixture::new(Ok(signed_snapshot_default(VALID_BUNDLE)));
        let (outcome, _) = block_on(fx.service().evaluate()).expect("ok");
        assert_eq!(outcome.state, State::Current);
        assert!(fx.deny_safe.entries.lock().unwrap().is_empty());
    }
}
