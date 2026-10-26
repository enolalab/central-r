//! The `dependencyprepare` domain — port of upstream
//! `internal/dependencyprepare/lock.go`, `release.go`, and the
//! `domain.go` surface the shared [`crate::domain`] module does not
//! already carry (results, build/load requests, attestation
//! statements, prepared manifests, and the receipt record).
//!
//! The lock and its two build recipes are embedded verbatim from
//! upstream `assets/`; every verification upstream performs on them is
//! performed here before any side effect may be scheduled:
//!
//! 1. `strict_validate_json` — UTF-8, single top-level object, no
//!    duplicate depth-1 keys, no trailing data, 1 MiB ceiling.
//! 2. [`Lock::verify_digest`] — JCS-canonical SHA-256 of the raw lock.
//! 3. [`Lock::verify_identities`] — the pinned PostgreSQL OCI triple
//!    and the pinned MinIO commit/archive digest.
//! 4. [`Lock::verify_recipe_digest`] — JCS-canonical digest of the
//!    embedded recipes, in their fixed order.
//! 5. [`Lock::validate_shipped_fetch_capabilities`] — the embedded lock
//!    may never carry a test-only fetch posture.
//! 6. [`Lock::validate_b03_modes`] — the locked mode inventories must
//!    satisfy the B03 prepared-set rule.
//!
//! Like the rest of the domain, this module is pure synchronous Rust:
//! no I/O beyond reading a caller-supplied lock file, no adapter types.
//! All failures arrive as [`Failure`] with [`codes`] machine strings.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use central_foundation::failure::Failure;
use central_foundation::jcs;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::authority::wire::{hex_decode, null_to_default};
use crate::domain::{
    ATTESTATION_SCHEMA, AttestationFact, AttestationPredicate, BUILT_IMAGE_REPOSITORY,
    ComparisonFact, ManifestSource, OciInventory, PREPARED_RECEIPT_SCHEMA, PreparePhase,
    PreparedDependencySet, PreparedMode, REQUIRED_ATTESTATION_PREDICATES, ServiceMode,
    StoredEnvelope, codes, digest_fields, sha256_prefixed, valid_canonical_digest,
};

// ===========================================================================
// Machine codes added by this module (upstream `dependencyprepare`
// sentinel errors that had no home in domain.rs's table).
// ===========================================================================

/// Lock/release/result codes. Where the upstream sentinel maps onto a
/// code already in [`crate::domain::codes`] the domain constant is used.
pub mod prepare_codes {
    /// `dependencyprepare.ErrLockSchemaMismatch`.
    pub const LOCK_SCHEMA_MISMATCH: &str = "LOCK_SCHEMA_MISMATCH";
    /// `dependencyprepare.ErrLockInvalidJSON`.
    pub const LOCK_INVALID_JSON: &str = "LOCK_INVALID_JSON";
    /// `dependencyprepare.ErrLockUnknownField`.
    pub const LOCK_UNKNOWN_FIELD: &str = "LOCK_UNKNOWN_FIELD";
    /// `dependencyprepare.ErrLockHelperDigestMismatch`.
    pub const LOCK_HELPER_DIGEST_MISMATCH: &str = "LOCK_HELPER_DIGEST_MISMATCH";
    /// `dependencyprepare.ErrLockDuplicateKey`.
    pub const LOCK_DUPLICATE_KEY: &str = "LOCK_DUPLICATE_KEY";
    /// `dependencyprepare.ErrLockDigestMismatch`.
    pub const LOCK_DIGEST_MISMATCH: &str = "LOCK_DIGEST_MISMATCH";
    /// `dependencyprepare.ErrLockIdentityMismatch`.
    pub const LOCK_IDENTITY_MISMATCH: &str = "LOCK_IDENTITY_MISMATCH";
    /// `dependencyprepare.ErrLockRecipeDigestMismatch`.
    pub const LOCK_RECIPE_DIGEST_MISMATCH: &str = "LOCK_RECIPE_DIGEST_MISMATCH";
    /// `dependencyprepare.ErrLockHelperDigestUnset`.
    pub const LOCK_HELPER_DIGEST_UNSET: &str = "LOCK_HELPER_DIGEST_UNSET";
    /// `dependencyprepare.ErrLockInvalidFetchCapability`.
    pub const LOCK_INVALID_FETCH_CAPABILITY: &str = "LOCK_INVALID_FETCH_CAPABILITY";
    /// `dependencyprepare.ErrLockInvalidRetryPolicy`.
    pub const LOCK_INVALID_RETRY_POLICY: &str = "LOCK_INVALID_RETRY_POLICY";
    /// `dependencyprepare.ErrAttestationEmptyKeyID`.
    pub const ATTESTATION_EMPTY_KEY_ID: &str = "ATTESTATION_EMPTY_KEY_ID";
    /// `dependencyprepare.ErrAttestationInvalidKeyHex`.
    pub const ATTESTATION_INVALID_KEY_HEX: &str = "ATTESTATION_INVALID_KEY_HEX";
    /// `dependencyprepare.ErrAttestationExpired`.
    pub const ATTESTATION_EXPIRED: &str = "ATTESTATION_EXPIRED";
    /// `dependencyprepare.ErrAttestationRevoked`.
    pub const ATTESTATION_REVOKED: &str = "ATTESTATION_REVOKED";
    /// `dependencyprepare.ErrAttestationSmallOrderKey`.
    pub const ATTESTATION_SMALL_ORDER_KEY: &str = "ATTESTATION_SMALL_ORDER_KEY";
    /// `dependencyprepare.ErrInvalidResult`.
    pub const RESULT_INVALID: &str = "RESULT_INVALID";
    /// `dependencyprepare.ErrInvalidImageLoad`.
    pub const IMAGE_LOAD_INVALID: &str = "IMAGE_LOAD_INVALID";
    /// `dependencyprepare.ErrPreparedIdentityDrift`.
    pub const PREPARED_IDENTITY_DRIFT: &str = "PREPARED_IDENTITY_DRIFT";
    /// `dependencyprepare.ErrBuilderIsolation`.
    pub const BUILDER_ISOLATION: &str = "BUILDER_ISOLATION";
    /// `dependencyprepare.ErrReleaseUnreadable`.
    pub const RELEASE_UNREADABLE: &str = "RELEASE_UNREADABLE";
    /// `dependencyprepare.ErrReleaseInvalid`.
    pub const RELEASE_INVALID: &str = "RELEASE_INVALID";
    /// `dependencyprepare.ErrReleaseUntrusted`.
    pub const RELEASE_UNTRUSTED: &str = "RELEASE_UNTRUSTED";
    /// `dependencyprepare.ErrReleaseLockMismatch`.
    pub const RELEASE_LOCK_MISMATCH: &str = "RELEASE_LOCK_MISMATCH";
    /// `dependencyprepare.ErrExportFailed`.
    pub const RELEASE_EXPORT_FAILED: &str = "RELEASE_EXPORT_FAILED";
    /// `dependencyprepare.ErrExportDirUnusable`.
    pub const RELEASE_EXPORT_DIR_UNUSABLE: &str = "RELEASE_EXPORT_DIR_UNUSABLE";
}

// ===========================================================================
// Embedded assets — byte-identical copies of upstream
// internal/dependencyprepare/assets/.
// ===========================================================================

const LOCKED_ASSETS_JSON: &[u8] = include_bytes!("assets/dependency-lock.json");
const MINIO_BUILD_RECIPE_JSON: &[u8] = include_bytes!("assets/minio-build-recipe.json");
const POSTGRESQL_BUILD_RECIPE_JSON: &[u8] = include_bytes!("assets/postgresql-build-recipe.json");

/// `lockSchema` — the only schema string the lock may declare.
pub const LOCK_SCHEMA: &str = "central.local-dependency-lock/v1";

/// `unsetDigest` is the all-zero placeholder a lock field carries while
/// its value has not been decided yet. It is never a legitimate digest,
/// so any check that would otherwise compare against it must refuse
/// instead.
pub const UNSET_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// `lockedRecipes` — the fixed, ordered set of build recipes covered by
/// the lock's `recipe_digest`. Both order and names are inputs to the
/// digest, so changing either requires recomputing `recipe_digest`.
const LOCKED_RECIPES: [(&str, &[u8]); 2] = [
    ("assets/minio-build-recipe.json", MINIO_BUILD_RECIPE_JSON),
    (
        "assets/postgresql-build-recipe.json",
        POSTGRESQL_BUILD_RECIPE_JSON,
    ),
];

/// `expectedPostgreSQL` — the pinned published OCI identity for the
/// PostgreSQL selector.
#[must_use]
pub fn expected_postgresql() -> OciArtifact {
    OciArtifact {
        index_sha256: "sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"
            .to_owned(),
        manifest_sha256: "sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28"
            .to_owned(),
        config_sha256: "sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e"
            .to_owned(),
    }
}

/// `expectedMinIO` — the digest of the archive the locked commit's own
/// endpoint serves (`https://github.com/minio/minio/archive/<commit>.tar.gz`,
/// 24232282 bytes, wrapper directory `minio-<commit>/`). See upstream's
/// comment: the tag-era value hashed neither archive and killed every
/// real fetch on `ErrFetchDigest`.
#[must_use]
pub fn expected_minio() -> GitArtifact {
    GitArtifact {
        commit: "9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a".to_owned(),
        archive_sha256: "sha256:45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841"
            .to_owned(),
    }
}

// ===========================================================================
// lock.go — types
// ===========================================================================

/// `Lock` — the embedded dependency lock. `raw` is the exact bytes the
/// file carried; the canonical hash is always computed over them, never
/// over a re-serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lock {
    /// `central.local-dependency-lock/v1`.
    pub schema: String,
    /// Still `unsetDigest` in the embedded asset: nothing produces a
    /// helper release digest yet, and [`Lock::verify_release_digest`]
    /// refuses while it is unset so the placeholder can never be
    /// mistaken for a verified value.
    pub helper_release_digest: String,
    /// Per-selector pinned acquisition identities.
    pub fetches: FetchRules,
    /// The per-selector fetch policy: endpoint, exact redirect chain,
    /// address and TLS posture, byte ceiling, and deadline.
    pub fetch_capability: BTreeMap<String, FetchCapability>,
    /// Pinned BuildKit frontend/exporter/base.
    pub buildkit: BuildKitPins,
    /// Bounded retry policy.
    pub retry: RetryPolicy,
    /// Digest of the embedded build recipes.
    pub recipe_digest: String,
    /// The set of keys whose signatures admit a dependency attestation.
    pub attestation_trust: AttestationTrustPolicy,
    /// The mode → OCI inventory table the lock fixes.
    #[serde(default, deserialize_with = "null_to_default")]
    pub modes: Vec<LockedMode>,

    /// The exact bytes the lock was parsed from.
    #[serde(skip)]
    raw: Vec<u8>,
}

/// `FetchRules` — the pinned identity of each selector's acquisition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRules {
    /// The published OCI triple PostgreSQL must resolve to.
    pub postgresql: OciArtifact,
    /// The pinned MinIO commit and archive digest.
    pub minio: GitArtifact,
}

/// `FetchCapability` is the whole of what an acquisition is permitted
/// to do for one selector: one scheme, one host, one port, one path
/// prefix, one exact redirect chain, one address policy, one TLS
/// policy, one byte ceiling and one deadline.
///
/// It is in the lock because that is the only place a fetch policy can
/// be audited. Before it existed the policy was spread across the
/// adapter as literals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchCapability {
    /// Only `https`.
    pub scheme: String,
    /// The permitted host.
    pub host: String,
    /// The permitted port.
    pub port: i64,
    /// The permitted path prefix (must be absolute).
    pub path_prefix: String,
    /// The ordered, exact redirect chain.
    #[serde(default, deserialize_with = "null_to_default")]
    pub redirect_chain: Vec<FetchHop>,
    /// `public-unicast` or (test-only) `any`.
    pub address_policy: String,
    /// `system-roots` or (test-only) `insecure-test-only`.
    pub tls_policy: TlsFetchMode,
    /// Response byte ceiling.
    pub max_bytes: i64,
    /// Per-fetch budget in milliseconds.
    pub deadline_ms: i64,
}

/// `FetchHop` — one permitted redirect. The chain is ordered and
/// exact: hop n of a response must match hop n of the chain, and a
/// chain of length k admits exactly k redirects, never k+1.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchHop {
    /// Only `https`.
    pub scheme: String,
    /// The permitted host.
    pub host: String,
    /// The permitted port.
    pub port: i64,
    /// The permitted path prefix.
    pub path_prefix: String,
}

/// `TLSFetchMode` — the closed set of TLS postures a fetch may take.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsFetchMode {
    /// `system-roots` — verify the server against the host trust
    /// store. The only value the shipped lock may carry.
    #[default]
    #[serde(rename = "system-roots")]
    SystemRoots,
    /// `insecure-test-only` — disables verification. Admissible only
    /// from a lock a test constructed; the adapter's
    /// verification-skipping switch is gated on this value rather than
    /// being unconditionally available.
    #[serde(rename = "insecure-test-only")]
    InsecureTestOnly,
}

/// `AddressPolicyPublicUnicast` refuses to connect to a resolved
/// address that is loopback, private, link-local, multicast, or
/// unspecified.
pub const ADDRESS_POLICY_PUBLIC_UNICAST: &str = "public-unicast";
/// `AddressPolicyAny` permits any address and, like
/// [`TlsFetchMode::InsecureTestOnly`], may not appear in the shipped
/// lock.
pub const ADDRESS_POLICY_ANY: &str = "any";

impl FetchCapability {
    /// `FetchCapability.Validate` — the structural shape of one
    /// capability. It is deliberately not the shipped-lock posture
    /// check; that lives in
    /// [`Lock::validate_shipped_fetch_capabilities`].
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_FETCH_CAPABILITY,
                format!("dependencyprepare: {msg}"),
            )
        };
        if self.scheme != "https" {
            return Err(invalid(&format!(
                "fetch capability scheme must be https, got {:?}",
                self.scheme
            )));
        }
        if self.host.is_empty() {
            return Err(invalid("fetch capability names no host"));
        }
        if self.port <= 0 || self.port > 65535 {
            return Err(invalid(&format!(
                "fetch capability port {} is out of range",
                self.port
            )));
        }
        if !self.path_prefix.starts_with('/') {
            return Err(invalid(&format!(
                "fetch capability path prefix {:?} is not absolute",
                self.path_prefix
            )));
        }
        for (i, hop) in self.redirect_chain.iter().enumerate() {
            if hop.scheme != "https" {
                return Err(invalid(&format!(
                    "redirect hop {i} scheme must be https, got {:?}",
                    hop.scheme
                )));
            }
            if hop.host.is_empty()
                || hop.port <= 0
                || hop.port > 65535
                || !hop.path_prefix.starts_with('/')
            {
                return Err(invalid(&format!("redirect hop {i} is incomplete")));
            }
        }
        match self.address_policy.as_str() {
            ADDRESS_POLICY_PUBLIC_UNICAST | ADDRESS_POLICY_ANY => {}
            _ => {
                return Err(invalid(&format!(
                    "unknown address policy {:?}",
                    self.address_policy
                )));
            }
        }
        // `TlsFetchMode` is a closed serde enum; an unspellable value
        // cannot reach here, so only the shipped-vs-test posture needs
        // a runtime check and that lives in
        // `validate_shipped_fetch_capabilities`.
        if self.max_bytes <= 0 {
            return Err(invalid("fetch capability names no byte ceiling"));
        }
        if self.deadline_ms <= 0 {
            return Err(invalid("fetch capability names no deadline"));
        }
        Ok(())
    }

    /// `Deadline` — the capability's per-fetch budget.
    #[must_use]
    pub fn deadline(&self) -> Duration {
        Duration::from_millis(self.deadline_ms.max(0) as u64)
    }
}

/// `OCIArtifact` — the pinned published identity triple.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciArtifact {
    /// OCI index digest.
    pub index_sha256: String,
    /// Platform manifest digest.
    pub manifest_sha256: String,
    /// Image config digest.
    pub config_sha256: String,
}

/// `GitArtifact` — the pinned source identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitArtifact {
    /// The exact upstream commit.
    pub commit: String,
    /// SHA-256 of the `.tar.gz` the commit's archive endpoint serves.
    pub archive_sha256: String,
}

/// `BuildKitPins` — the pinned build tooling identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildKitPins {
    /// `docker/dockerfile:1.10.0`.
    pub frontend_version: String,
    /// The pinned exporter version.
    pub exporter_version: String,
    /// The build's `FROM` ref (`scratch`).
    pub base_ref: String,
}

/// `RetryPolicy` — the bounded fetch/build retry shape. A retry loop
/// is the one place a terminal failure can be turned into an
/// unbounded one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum total attempts (>= 1).
    pub max_attempts: i64,
    /// Wait before each attempt after the first, in milliseconds.
    #[serde(default, deserialize_with = "null_to_default")]
    pub backoff_ms: Vec<i64>,
}

impl RetryPolicy {
    /// `RetryPolicy.Validate` — bounds the retry policy.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_RETRY_POLICY,
                format!("dependencyprepare: {msg}"),
            )
        };
        if self.max_attempts < 1 {
            return Err(invalid("retry policy admits no attempts"));
        }
        if self.max_attempts > self.backoff_ms.len() as i64 + 1 {
            return Err(invalid(&format!(
                "retry policy allows {} attempts but names {} backoffs",
                self.max_attempts,
                self.backoff_ms.len()
            )));
        }
        for (i, ms) in self.backoff_ms.iter().enumerate() {
            if *ms < 0 {
                return Err(invalid(&format!("backoff {i} is negative")));
            }
        }
        Ok(())
    }

    /// `Backoff` — the wait before attempt n (1-based). Attempt 1
    /// never waits.
    #[must_use]
    pub fn backoff(&self, attempt: i64) -> Duration {
        let index = attempt - 2;
        if index < 0 || index >= self.backoff_ms.len() as i64 {
            return Duration::ZERO;
        }
        Duration::from_millis(self.backoff_ms[index as usize].max(0) as u64)
    }
}

/// `AttestationTrustPolicy` — the set of keys whose signatures admit a
/// dependency attestation. The anchor shipped in
/// `assets/dependency-lock.json` is explicitly development/local-only;
/// an installed, production, or online instance must be given its own
/// anchor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationTrustPolicy {
    /// The trusted key set.
    #[serde(default, deserialize_with = "null_to_default")]
    pub keys: Vec<TrustedKey>,
}

/// `TrustedKey` — one trust anchor entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKey {
    /// The key's identifier.
    pub key_id: String,
    /// Hex-encoded ed25519 public key.
    pub public_key: String,
    /// Optional RFC 3339 expiry.
    pub expires_at: Option<String>,
    /// Whether the key is retired (still refused at verify time, kept
    /// visible in the lock's history).
    #[serde(default)]
    pub revoked: bool,
}

/// `smallOrderPublicKeys` — the hex encodings of every ed25519 point
/// whose order divides 8, both sign bits included. Signatures under
/// such a key prove nothing, so one can never stand in as a trust
/// anchor. The all-zero placeholder the lock shipped with is one of
/// them.
fn is_small_order_public_key(hex_key: &str) -> bool {
    matches!(
        hex_key.to_ascii_lowercase().as_str(),
        "0000000000000000000000000000000000000000000000000000000000000000"
            | "0000000000000000000000000000000000000000000000000000000000000080"
            | "0100000000000000000000000000000000000000000000000000000000000000"
            | "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
            | "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"
            | "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
            | "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
            | "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    )
}

impl AttestationTrustPolicy {
    /// `AttestationTrustPolicy.Validate` — checks every key's
    /// structural shape (present ID, correctly sized and decodable
    /// hex, not a known small-order point) and expiry.
    ///
    /// A revoked key is deliberately NOT rejected here (ADR 0030): a
    /// lock retiring one key must not make every other key in the same
    /// trust policy unusable. The refusal a revoked key must still
    /// produce happens at the point it would actually be used to
    /// verify a signature — the attestation verifier — so an
    /// attestation it signed is never trusted, while a sibling key's
    /// signatures still are.
    ///
    /// `now` is the instant expiry is evaluated against; production
    /// callers pass `OffsetDateTime::now_utc()`.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), Failure> {
        for (i, key) in self.keys.iter().enumerate() {
            if key.key_id.is_empty() {
                return Err(Failure::invalid(
                    prepare_codes::ATTESTATION_EMPTY_KEY_ID,
                    format!(
                        "dependencyprepare: attestation key ID must not be empty: key index {i}"
                    ),
                ));
            }
            if key.public_key.len() != 64 {
                return Err(Failure::invalid(
                    prepare_codes::ATTESTATION_INVALID_KEY_HEX,
                    format!(
                        "dependencyprepare: attestation public key is not valid hex-encoded ed25519 key: key {:?} has incorrect hex length (got {}, want 64)",
                        key.key_id,
                        key.public_key.len()
                    ),
                ));
            }
            if hex_decode(&key.public_key).is_none() {
                return Err(Failure::invalid(
                    prepare_codes::ATTESTATION_INVALID_KEY_HEX,
                    format!(
                        "dependencyprepare: attestation public key is not valid hex-encoded ed25519 key: key {:?}",
                        key.key_id
                    ),
                ));
            }
            if is_small_order_public_key(&key.public_key) {
                return Err(Failure::invalid(
                    prepare_codes::ATTESTATION_SMALL_ORDER_KEY,
                    format!(
                        "dependencyprepare: attestation public key is a small-order ed25519 point: key {:?}",
                        key.key_id
                    ),
                ));
            }
            // Upstream checks `ExpiresAt != nil && *ExpiresAt != ""`.
            if let Some(expires_at) = &key.expires_at
                && !expires_at.is_empty()
            {
                let expiry = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| {
                    Failure::invalid(
                        codes::ATTESTATION_INVALID,
                        format!(
                            "dependencyprepare: attestation key {:?} has invalid expires_at",
                            key.key_id
                        ),
                    )
                })?;
                if now > expiry {
                    return Err(Failure::invalid(
                        prepare_codes::ATTESTATION_EXPIRED,
                        format!(
                            "dependencyprepare: attestation key has expired: {expires_at:?} expired at {expires_at}"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// `Validate` at the current instant — the production entry point.
    pub fn validate(&self) -> Result<(), Failure> {
        self.validate_at(OffsetDateTime::now_utc())
    }
}

/// `LockedMode` — one mode → inventory entry in the lock's `modes`
/// table. Distinct from [`crate::domain::PreparedMode`]: the lock's
/// JSON is lowercase-keyed while the manifest form rides Go's untagged
/// PascalCase convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedMode {
    /// The Compose service mode.
    pub mode: ServiceMode,
    /// Its locked OCI identity.
    pub inventory: OciInventory,
}

/// `allowedLockKeys` — the closed set of top-level lock fields.
const ALLOWED_LOCK_KEYS: [&str; 9] = [
    "schema",
    "helper_release_digest",
    "fetches",
    "fetch_capability",
    "buildkit",
    "retry",
    "recipe_digest",
    "attestation_trust",
    "modes",
];

// ===========================================================================
// lock.go — loading and verification
// ===========================================================================

/// `LoadLock` — parses the embedded lock and applies every check
/// upstream runs before the lock may be trusted: strict JSON, mode
/// table validity, embedded-recipe digest, shipped fetch postures, and
/// the retry bound.
pub fn load_lock() -> Result<Lock, Failure> {
    let lock = parse_lock(LOCKED_ASSETS_JSON)?;
    lock.validate_b03_modes()?;
    lock.verify_recipe_digest()?;
    // The shipped lock's fetch policy is checked here rather than in
    // `parse_lock`: `parse_lock_file` parses arbitrary lock files, and
    // a test lock is allowed the local-server postures the embedded
    // one may never carry.
    lock.validate_shipped_fetch_capabilities()?;
    lock.retry.validate()?;
    Ok(lock)
}

/// `ParseLockFile` — parses an arbitrary lock file and validates its
/// mode table. It deliberately does not compare `recipe_digest`
/// against the embedded recipes: the recipes it would be compared
/// against are always the embedded ones, so enforcing it here would
/// reject every externally supplied lock rather than catching a real
/// divergence.
pub fn parse_lock_file(path: &Path) -> Result<Lock, Failure> {
    let data = fs::read(path).map_err(|e| {
        Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            format!("dependencyprepare: reading lock file: {e}"),
        )
    })?;
    let lock = parse_lock(&data)?;
    lock.validate_b03_modes()?;
    Ok(lock)
}

/// `parseLock` — strict-validate, then bind the closed top-level field
/// set and the declared schema.
fn parse_lock(raw: &[u8]) -> Result<Lock, Failure> {
    strict_validate_json(raw)?;

    let raw_fields: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(raw).map_err(|e| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_JSON,
                format!("dependencyprepare: lock is not valid JSON: {e}"),
            )
        })?;

    for key in raw_fields.keys() {
        if !ALLOWED_LOCK_KEYS.contains(&key.as_str()) {
            return Err(Failure::invalid(
                prepare_codes::LOCK_UNKNOWN_FIELD,
                format!("dependencyprepare: lock contains unknown field: {key:?}"),
            ));
        }
    }

    let Some(schema) = raw_fields.get("schema") else {
        return Err(Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            "dependencyprepare: lock is not valid JSON: schema field is missing",
        ));
    };
    let Some(schema_str) = schema.as_str() else {
        return Err(Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            "dependencyprepare: lock is not valid JSON: schema field is not a string",
        ));
    };
    if schema_str != LOCK_SCHEMA {
        return Err(Failure::invalid(
            prepare_codes::LOCK_SCHEMA_MISMATCH,
            format!(
                "dependencyprepare: lock schema mismatch: expected {LOCK_SCHEMA:?}, got {schema_str:?}"
            ),
        ));
    }

    let mut lock: Lock = serde_json::from_slice(raw).map_err(|e| {
        Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            format!("dependencyprepare: lock is not valid JSON: {e}"),
        )
    })?;
    lock.raw = raw.to_vec();
    Ok(lock)
}

/// `strictValidateJSON` — the lock's own parser contract: at most
/// 1 MiB, valid UTF-8, exactly one top-level value, no duplicate
/// depth-1 keys, and nothing after the first value.
///
/// The depth-1 key tracking reproduces upstream's token-parity rule
/// exactly: every string token toggles `in_key` at any depth, `}`
/// resets it, `]` does not. The parity quirk is part of the contract —
/// a byte-identical lock parses identically on both implementations.
fn strict_validate_json(raw: &[u8]) -> Result<(), Failure> {
    const MAX_LOCK_BYTES: usize = 1 << 20;
    if raw.len() > MAX_LOCK_BYTES {
        return Err(Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            format!("dependencyprepare: lock size {} exceeds 1 MiB", raw.len()),
        ));
    }
    if std::str::from_utf8(raw).is_err() {
        return Err(Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            "dependencyprepare: lock is not valid JSON: invalid UTF-8",
        ));
    }

    let text = std::str::from_utf8(raw).map_err(|_| {
        Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            "dependencyprepare: lock is not valid JSON: invalid UTF-8",
        )
    })?;
    let mut pos = 0usize;
    let mut depth = 0i32;
    let mut in_key = false;
    let mut first_done = false;
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    let invalid = |msg: &str| {
        Failure::invalid(
            prepare_codes::LOCK_INVALID_JSON,
            format!("dependencyprepare: lock is not valid JSON: {msg}"),
        )
    };

    // One JSON token, upstream `dec.Token()` shape. Strings and
    // delimiters matter to the dup/parity rule; numbers and literals
    // are consumed and classified as scalars.
    fn next_token(text: &str, pos: &mut usize) -> Result<JsonToken, String> {
        let bytes = text.as_bytes();
        while *pos < bytes.len() && matches!(bytes[*pos], b' ' | b'\t' | b'\n' | b'\r') {
            *pos += 1;
        }
        if *pos >= bytes.len() {
            return Ok(JsonToken::Eof);
        }
        match bytes[*pos] {
            b'{' => {
                *pos += 1;
                Ok(JsonToken::OpenObject)
            }
            b'}' => {
                *pos += 1;
                Ok(JsonToken::CloseObject)
            }
            b'[' => {
                *pos += 1;
                Ok(JsonToken::OpenArray)
            }
            b']' => {
                *pos += 1;
                Ok(JsonToken::CloseArray)
            }
            b':' | b',' => {
                *pos += 1;
                next_token(text, pos)
            }
            b'"' => {
                *pos += 1;
                let mut out = String::new();
                loop {
                    if *pos >= bytes.len() {
                        return Err("unterminated string".to_owned());
                    }
                    let c = bytes[*pos];
                    match c {
                        b'"' => {
                            *pos += 1;
                            return Ok(JsonToken::Str(out));
                        }
                        b'\\' => {
                            *pos += 1;
                            if *pos >= bytes.len() {
                                return Err("unterminated escape".to_owned());
                            }
                            let esc = bytes[*pos];
                            match esc {
                                b'"' | b'\\' | b'/' => out.push(esc as char),
                                b'b' => out.push('\u{0008}'),
                                b'f' => out.push('\u{000C}'),
                                b'n' => out.push('\n'),
                                b'r' => out.push('\r'),
                                b't' => out.push('\t'),
                                b'u' => {
                                    let end = (*pos + 5).min(bytes.len());
                                    if *pos + 5 > bytes.len() {
                                        return Err("short unicode escape".to_owned());
                                    }
                                    for digit in &bytes[*pos + 1..end] {
                                        if !digit.is_ascii_hexdigit() {
                                            return Err("bad unicode escape".to_owned());
                                        }
                                    }
                                    // The exact decoded scalar is
                                    // irrelevant to the depth/parity
                                    // rule — surrogate halves need not
                                    // combine for it.
                                    out.push('\u{FFFD}');
                                    *pos += 4;
                                }
                                _ => return Err("bad escape".to_owned()),
                            }
                            *pos += 1;
                        }
                        _ => {
                            // Consume the UTF-8 scalar starting at pos.
                            let rest = &text[*pos..];
                            let ch = rest.chars().next().ok_or("truncated utf-8")?;
                            out.push(ch);
                            *pos += ch.len_utf8();
                        }
                    }
                }
            }
            b't' => {
                if text[*pos..].starts_with("true") {
                    *pos += 4;
                    Ok(JsonToken::Scalar)
                } else {
                    Err("invalid literal".to_owned())
                }
            }
            b'f' => {
                if text[*pos..].starts_with("false") {
                    *pos += 5;
                    Ok(JsonToken::Scalar)
                } else {
                    Err("invalid literal".to_owned())
                }
            }
            b'n' => {
                if text[*pos..].starts_with("null") {
                    *pos += 4;
                    Ok(JsonToken::Scalar)
                } else {
                    Err("invalid literal".to_owned())
                }
            }
            b'-' | b'0'..=b'9' => {
                while *pos < bytes.len()
                    && matches!(bytes[*pos], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    *pos += 1;
                }
                Ok(JsonToken::Scalar)
            }
            _ => Err("unexpected character".to_owned()),
        }
    }

    enum JsonToken {
        Eof,
        OpenObject,
        CloseObject,
        OpenArray,
        CloseArray,
        Str(String),
        Scalar,
    }

    loop {
        if first_done {
            match next_token(text, &mut pos) {
                Ok(JsonToken::Eof) => return Ok(()),
                Ok(_) => {
                    return Err(invalid("trailing data after first value"));
                }
                Err(e) => {
                    let _ = e;
                    return Ok(());
                }
            }
        }
        // The strict validator is a gate, not the parser — serde_json
        // rejects malformed structure after this returns Ok. Upstream
        // accepts EOF at any depth here; the real decode fails next.
        match next_token(text, &mut pos) {
            Err(e) => return Err(invalid(&e)),
            Ok(JsonToken::Eof) => return Ok(()),
            Ok(JsonToken::OpenObject) => depth += 1,
            Ok(JsonToken::CloseObject) => {
                depth -= 1;
                if depth == 0 {
                    first_done = true;
                }
                in_key = false;
            }
            Ok(JsonToken::OpenArray) => depth += 1,
            Ok(JsonToken::CloseArray) => depth -= 1,
            Ok(JsonToken::Str(s)) => {
                if depth == 1 && !in_key && !seen_keys.insert(s.clone()) {
                    return Err(Failure::invalid(
                        prepare_codes::LOCK_DUPLICATE_KEY,
                        format!("dependencyprepare: lock contains duplicate key: {s:?}"),
                    ));
                }
                in_key = !in_key;
            }
            Ok(JsonToken::Scalar) => in_key = false,
        }
        if depth < 0 {
            return Err(invalid("unexpected closing delimiter"));
        }
    }
}

impl Lock {
    /// `ValidateB03Modes` — the locked mode table must satisfy the same
    /// prepared-set rule the store enforces.
    pub fn validate_b03_modes(&self) -> Result<(), Failure> {
        let mut set = PreparedDependencySet {
            modes: Vec::with_capacity(self.modes.len()),
        };
        for mode in &self.modes {
            set.modes.push(PreparedMode {
                mode: mode.mode,
                inventory: mode.inventory.clone(),
            });
        }
        set.validate_b03()
    }

    /// `VerifyReleaseDigest` — the helper release digest is either the
    /// lock's value or a refusal; the all-zero placeholder can never be
    /// admitted.
    pub fn verify_release_digest(&self, actual_digest: &str) -> Result<(), Failure> {
        if self.helper_release_digest == UNSET_DIGEST {
            return Err(Failure::invalid(
                prepare_codes::LOCK_HELPER_DIGEST_UNSET,
                format!(
                    "dependencyprepare: lock helper release digest is unset: refusing to admit helper release digest {actual_digest} against an undecided lock value"
                ),
            ));
        }
        if self.helper_release_digest != actual_digest {
            return Err(Failure::invalid(
                prepare_codes::LOCK_HELPER_DIGEST_MISMATCH,
                format!(
                    "dependencyprepare: helper release digest mismatch: lock expects {} but helper release digest is {actual_digest}",
                    self.helper_release_digest
                ),
            ));
        }
        Ok(())
    }

    /// `RawJSON` — the exact bytes the lock was parsed from.
    #[must_use]
    pub fn raw_json(&self) -> &[u8] {
        &self.raw
    }

    /// `CanonicalHash` — JCS-canonical SHA-256 of the raw lock bytes.
    /// The digest is always computed over the stored bytes, never over
    /// a re-serialization, so whitespace or key-order edits produce a
    /// different input to canonicalization exactly as upstream's
    /// `jcs.Transform(l.raw)` does.
    pub fn canonical_hash(&self) -> Result<String, Failure> {
        let value: serde_json::Value = serde_json::from_slice(&self.raw).map_err(|e| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_JSON,
                format!("dependencyprepare: canonical hash: {e}"),
            )
        })?;
        let canonical = jcs::canonicalize(&value).map_err(|e| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_JSON,
                format!("dependencyprepare: canonical hash: {e}"),
            )
        })?;
        Ok(sha256_prefixed(&canonical))
    }

    /// `VerifyDigest` — the JCS-canonical digest of the raw lock must
    /// equal `expected_digest`.
    pub fn verify_digest(&self, expected_digest: &str) -> Result<(), Failure> {
        let actual = self.canonical_hash().map_err(|e| {
            Failure::invalid(
                e.code(),
                format!("dependencyprepare: verify digest: {}", e.message()),
            )
        })?;
        if actual != expected_digest {
            return Err(Failure::invalid(
                prepare_codes::LOCK_DIGEST_MISMATCH,
                format!(
                    "dependencyprepare: lock digest mismatch: expected {expected_digest}, got {actual}"
                ),
            ));
        }
        Ok(())
    }

    /// `VerifyRecipeDigest` — the lock's recorded `recipe_digest`
    /// against the recipes compiled into this binary. Only `load_lock`
    /// calls it.
    pub fn verify_recipe_digest(&self) -> Result<(), Failure> {
        let actual = recipe_digest()?;
        if self.recipe_digest != actual {
            return Err(Failure::invalid(
                prepare_codes::LOCK_RECIPE_DIGEST_MISMATCH,
                format!(
                    "dependencyprepare: lock recipe digest mismatch: lock records {} but the embedded recipes hash to {actual}",
                    self.recipe_digest
                ),
            ));
        }
        Ok(())
    }

    /// `VerifyIdentities` — the lock's pinned fetch identities must be
    /// exactly the expected PostgreSQL OCI triple and MinIO
    /// commit/archive pair. Any drift is a refusal before any side
    /// effect.
    pub fn verify_identities(&self) -> Result<(), Failure> {
        if self.fetches.postgresql != expected_postgresql() {
            return Err(Failure::invalid(
                prepare_codes::LOCK_IDENTITY_MISMATCH,
                "dependencyprepare: lock identity mismatch: postgresql identity does not match expected",
            ));
        }
        if self.fetches.minio != expected_minio() {
            return Err(Failure::invalid(
                prepare_codes::LOCK_IDENTITY_MISMATCH,
                "dependencyprepare: lock identity mismatch: minio identity does not match expected",
            ));
        }
        Ok(())
    }

    /// `FetchCapabilityFor` — the validated capability for a selector.
    /// A selector with no entry has no permitted endpoint at all,
    /// which is a refusal rather than a default.
    pub fn fetch_capability_for(&self, selector: &str) -> Result<FetchCapability, Failure> {
        let Some(capability) = self.fetch_capability.get(selector) else {
            return Err(Failure::invalid(
                prepare_codes::LOCK_INVALID_FETCH_CAPABILITY,
                format!(
                    "dependencyprepare: fetch capability is invalid: the lock grants no fetch capability for {selector:?}"
                ),
            ));
        };
        capability.validate()?;
        Ok(capability.clone())
    }

    /// `ValidateShippedFetchCapabilities` — refuses the test-only
    /// postures in the embedded lock. They exist so a test can point a
    /// fetch at a local server; a lock that shipped with either would
    /// be a fetch policy that verifies nothing.
    pub fn validate_shipped_fetch_capabilities(&self) -> Result<(), Failure> {
        for (selector, capability) in &self.fetch_capability {
            capability.validate().map_err(|e| {
                Failure::invalid(
                    e.code(),
                    format!("fetch capability {selector:?}: {}", e.message()),
                )
            })?;
            if capability.tls_policy != TlsFetchMode::SystemRoots {
                return Err(Failure::invalid(
                    prepare_codes::LOCK_INVALID_FETCH_CAPABILITY,
                    format!(
                        "dependencyprepare: fetch capability is invalid: shipped fetch capability {selector:?} must verify against system roots"
                    ),
                ));
            }
            if capability.address_policy != ADDRESS_POLICY_PUBLIC_UNICAST {
                return Err(Failure::invalid(
                    prepare_codes::LOCK_INVALID_FETCH_CAPABILITY,
                    format!(
                        "dependencyprepare: fetch capability is invalid: shipped fetch capability {selector:?} must refuse non-public addresses"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// `MinioRecipe` — the embedded MinIO build recipe bytes.
    #[must_use]
    pub fn minio_recipe(&self) -> &'static [u8] {
        MINIO_BUILD_RECIPE_JSON
    }

    /// `PostgresRecipe` — the embedded PostgreSQL build recipe bytes.
    #[must_use]
    pub fn postgres_recipe(&self) -> &'static [u8] {
        POSTGRESQL_BUILD_RECIPE_JSON
    }
}

/// `RecipeDigest` — the digest of the compiled-in build recipes. Each
/// recipe is JCS-canonicalized before hashing so that whitespace or
/// key-order edits to an asset file do not churn the digest, and each
/// per-recipe line is bound to that recipe's name and position in
/// `LOCKED_RECIPES`.
pub fn recipe_digest() -> Result<String, Failure> {
    let mut lines = String::new();
    for (name, body) in LOCKED_RECIPES {
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_JSON,
                format!("dependencyprepare: recipe digest: {name}: {e}"),
            )
        })?;
        let canonical = jcs::canonicalize(&value).map_err(|e| {
            Failure::invalid(
                prepare_codes::LOCK_INVALID_JSON,
                format!("dependencyprepare: recipe digest: {name}: {e}"),
            )
        })?;
        lines.push_str(&format!("{name}:{}\n", sha256_prefixed(&canonical)));
    }
    Ok(sha256_prefixed(lines.as_bytes()))
}

// ===========================================================================
// domain.go — Result and operator-summary surface
// ===========================================================================

/// `OperationBudget` — the deadline one prepare operation may consume.
pub const OPERATION_BUDGET: Duration = Duration::from_secs(20 * 60);

/// `Result` — the whole of what one prepare operation reports. No
/// path, URL, command line, or build output may ever be carried on
/// this struct: everything is a phase name, a count, or a duration.
#[derive(Debug, Clone, PartialEq)]
pub struct PrepareResult {
    /// The operation's exit code.
    pub exit_code: i32,
    /// The terminal reason, `CODE: detail` form.
    pub reason: String,
    /// The operation identifier.
    pub operation_id: String,
    /// The settled candidate's receipt.
    pub receipt_id: String,
    /// The coarse phase the operation ended in.
    pub phase: PreparePhase,
    /// Whether a `--resume` of this operation is the next move.
    pub resume_required: bool,
    /// Candidates reused from an earlier operation.
    pub reused: i64,
    /// Candidates acquired this operation.
    pub acquired: i64,
    /// The derived operator next action.
    pub safe_next_action: SafeNextAction,
    /// Bounded per-phase timings.
    pub stage_timings: Vec<StageTiming>,
    /// The result-facing counter projection.
    pub counters: ResourceCounters,
    /// The operation's measured elapsed milliseconds.
    pub elapsed_ms: i64,
    /// The admission receipt this operation ran under.
    pub admission_id: String,
    /// The selector being prepared.
    pub selector: String,
    /// The operation deadline.
    pub deadline: OffsetDateTime,
    /// The operation creation instant.
    pub created_at: OffsetDateTime,
}

/// `NewResult` — refuses an unnamed operation or an unknown phase.
pub fn new_result(operation_id: &str, phase: PreparePhase) -> Result<PrepareResult, Failure> {
    if operation_id.is_empty() {
        return Err(Failure::invalid(
            prepare_codes::RESULT_INVALID,
            "dependencyprepare: invalid result",
        ));
    }
    Ok(PrepareResult {
        exit_code: 0,
        reason: String::new(),
        operation_id: operation_id.to_owned(),
        receipt_id: String::new(),
        phase,
        resume_required: false,
        reused: 0,
        acquired: 0,
        safe_next_action: SafeNextAction::None,
        stage_timings: Vec::new(),
        counters: ResourceCounters::default(),
        elapsed_ms: 0,
        admission_id: String::new(),
        selector: String::new(),
        deadline: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    })
}

/// `SafeNextAction` — the closed enum of actions an operator may
/// safely take next. It exists so an unspellable instruction cannot
/// reach an operator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafeNextAction {
    /// `""` — a completed prepare names no next action.
    #[default]
    #[serde(rename = "")]
    None,
    /// `RESUME_REQUIRED`.
    #[serde(rename = "RESUME_REQUIRED")]
    Resume,
    /// `PREPARATION_REQUIRED`.
    #[serde(rename = "PREPARATION_REQUIRED")]
    Prepare,
    /// `TERMINAL_FAILURE`.
    #[serde(rename = "TERMINAL_FAILURE")]
    Terminal,
}

impl SafeNextAction {
    /// The upstream `SafeNextAction` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Resume => "RESUME_REQUIRED",
            Self::Prepare => "PREPARATION_REQUIRED",
            Self::Terminal => "TERMINAL_FAILURE",
        }
    }

    /// `SafeNextAction.IsValid` — the closed-set membership test.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(
            self,
            Self::None | Self::Resume | Self::Prepare | Self::Terminal
        )
    }
}

impl fmt::Display for SafeNextAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SafeNextAction {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(Self::None),
            "RESUME_REQUIRED" => Ok(Self::Resume),
            "PREPARATION_REQUIRED" => Ok(Self::Prepare),
            "TERMINAL_FAILURE" => Ok(Self::Terminal),
            _ => Err(Failure::invalid(
                prepare_codes::RESULT_INVALID,
                "dependencyprepare: invalid result",
            )),
        }
    }
}

/// `retryablePrepareReasons` — the terminal reason codes for which
/// running `central local prepare` again is the correct next move:
/// the operation stopped before it committed anything, and the cause
/// is a condition of the host or the network rather than a fact about
/// the inputs.
///
/// Everything absent from this set is terminal on purpose. A build
/// whose two halves disagreed, an attestation that did not verify, an
/// identity that drifted from the lock, or a promotion the authority
/// refused are all statements about the inputs; repeating the
/// operation cannot change them.
const RETRYABLE_PREPARE_REASONS: [&str; 14] = [
    "CAPACITY_UNAVAILABLE",
    "CAPACITY_CHECK_FAILED",
    "FETCH_FAILED",
    // The image store could not answer, or cannot key an image by
    // manifest digest, or would not import one. All three are
    // conditions of this host's Docker daemon and its data root.
    // Deliberately absent: LOAD_UNRESOLVABLE — that one says the host
    // imported the build and then resolved the promoted reference to
    // different content, which no repetition changes.
    "IMAGE_STORE_UNSUPPORTED",
    "LOAD_FAILED",
    "BUILD_ONE_FAILED",
    "BUILD_TWO_FAILED",
    "DEADLINE_EXCEEDED",
    "CONTEXT_CANCELLED",
    "RECORD_FAILED",
    "NO_SELECTORS",
    "PREPARATION_REQUIRED",
    "SELECTOR_NOT_PREPARED",
    "DEPENDENCIES_NOT_READY",
];

/// `reasonCode` — the machine-readable code from a `CODE: detail`
/// reason string; only the code is classified.
#[must_use]
pub fn reason_code(reason: &str) -> &str {
    match reason.split_once(':') {
        Some((code, _)) => code.trim(),
        None => reason.trim(),
    }
}

/// `SafeNextActionFor` — derives the one action an operator may safely
/// take next from the result itself. A completed prepare names no next
/// action at all: before this existed the success path emitted
/// `PREPARATION_REQUIRED` — a finished preparation telling the
/// operator to run the preparation.
#[must_use]
pub fn safe_next_action_for(result: &PrepareResult) -> SafeNextAction {
    if result.resume_required {
        return SafeNextAction::Resume;
    }
    match result.phase {
        PreparePhase::Ready => return SafeNextAction::None,
        PreparePhase::Skipped => return SafeNextAction::Prepare,
        _ => {}
    }
    if RETRYABLE_PREPARE_REASONS.contains(&reason_code(&result.reason)) {
        return SafeNextAction::Prepare;
    }
    SafeNextAction::Terminal
}

/// `WithSafeNextAction` — stamps a result with the action derived from
/// it, applied where a result leaves the prepare service so no caller
/// has to restate the rule.
#[must_use]
pub fn with_safe_next_action(mut result: PrepareResult) -> PrepareResult {
    result.safe_next_action = safe_next_action_for(&result);
    result
}

/// `MaxStageTimings` — bounds the per-phase timings a result may
/// carry. The state machine re-enters phases on resume, so the
/// sequence is not bounded by the number of phases; a result is a
/// fixed-size operator summary, not a log.
pub const MAX_STAGE_TIMINGS: usize = 24;

/// `MaxProgressEvents` — bounds a single operation's progress stream.
/// A prepare runs for up to twenty minutes on the root helper's side
/// of the socket, and an unbounded reporter there is a way to stall
/// it.
pub const MAX_PROGRESS_EVENTS: usize = 256;

/// `AppendStageTiming` — records one finished phase, dropping anything
/// past the cap rather than growing without bound. Only the phase name
/// is recorded; a stage timing may never name a directory, an image,
/// or a command.
pub fn append_stage_timing(timings: &mut Vec<StageTiming>, phase: PreparePhase, elapsed: Duration) {
    if timings.len() >= MAX_STAGE_TIMINGS {
        return;
    }
    timings.push(StageTiming {
        phase: phase.as_str().to_owned(),
        duration_ms: elapsed.as_secs_f64() * 1000.0,
    });
}

/// `StageTiming` — one finished phase and how long it took.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StageTiming {
    /// The phase name.
    pub phase: String,
    /// Milliseconds.
    pub duration_ms: f64,
}

/// `ResourceCounters` — the result-facing counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCounters {
    /// Fetches performed.
    pub fetched: i64,
    /// Builds performed.
    pub built: i64,
    /// OCI comparisons performed.
    pub compared: i64,
    /// Staged artifacts.
    pub staged: i64,
    /// Bytes read.
    pub bytes_read: i64,
}

/// `ProgressEvent` — one bounded progress record.
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressEvent {
    /// The phase the event reports.
    pub phase: PreparePhase,
    /// When it was emitted.
    pub at: OffsetDateTime,
    /// Elapsed operation time.
    pub elapsed: Duration,
    /// The counters safe to show an operator.
    pub safe_counters: SafeCounters,
}

/// `SafeCounters` — the progress-stream counters. `build_count` exists
/// on the wire view but never reaches a result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeCounters {
    /// Fetches performed.
    pub fetched: i64,
    /// Builds performed.
    pub built: i64,
    /// OCI comparisons performed.
    pub compared: i64,
    /// Staged artifacts.
    pub staged: i64,
    /// Bytes read.
    pub bytes_read: i64,
    /// Build invocations (progress-only).
    pub build_count: i64,
}

impl SafeCounters {
    /// `Resources` — the result-facing projection of the counters a
    /// progress stream carries.
    #[must_use]
    pub fn resources(&self) -> ResourceCounters {
        ResourceCounters {
            fetched: self.fetched,
            built: self.built,
            compared: self.compared,
            staged: self.staged,
            bytes_read: self.bytes_read,
        }
    }
}

// ===========================================================================
// domain.go — BuildRequest / ImageLoadRequest
// ===========================================================================

/// `BuildRequest` — one hermetic build invocation. The `no_*` flags
/// are the isolation posture the builder must honor; `NewBuildRequest`
/// sets them all and no caller may clear them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    /// The selector being built.
    pub selector: String,
    /// The exact recipe bytes.
    pub recipe: Vec<u8>,
    /// First isolated builder root.
    pub root_a: String,
    /// Second isolated builder root.
    pub root_b: String,
    /// Whether the build may reach the network after the base import.
    pub network_after_import: bool,
    /// No default caches.
    pub no_default_caches: bool,
    /// No host mounts.
    pub no_host_mounts: bool,
    /// No Docker socket.
    pub no_docker_socket: bool,
    /// No secrets.
    pub no_secrets: bool,
    /// No SSH forwards.
    pub no_ssh: bool,
    /// No privileged mode.
    pub no_privileged: bool,
    /// No plugins.
    pub no_plugins: bool,
    /// No external cache.
    pub no_external_cache: bool,
}

impl BuildRequest {
    /// `ContextDir` — the one place the build-context convention is
    /// written down: the caller stages already-fetched,
    /// already-verified source here, and the builder reads it from
    /// here.
    #[must_use]
    pub fn context_dir(&self) -> PathBuf {
        if self.root_b.is_empty() {
            return PathBuf::new();
        }
        Path::new(&self.root_b).join("context")
    }

    /// `ExportPath` — the OCI export the build writes, mirroring
    /// `context_dir` so the load step has one derivation.
    #[must_use]
    pub fn export_path(&self) -> PathBuf {
        if self.root_b.is_empty() {
            return PathBuf::new();
        }
        Path::new(&self.root_b).join("oci-output.tar")
    }

    /// `InvocationDigest` — identifies one build invocation: the
    /// selector, the exact recipe bytes, and the isolation flags
    /// actually requested. Two builds that differ in any of those are
    /// not the same invocation.
    #[must_use]
    pub fn invocation_digest(&self) -> String {
        let recipe_hex = sha256_prefixed(&self.recipe);
        digest_fields(
            "central.build-invocation/v1",
            &[
                self.selector.as_str(),
                recipe_hex.as_str(),
                format!("network_after_import={}", self.network_after_import).as_str(),
                format!("no_default_caches={}", self.no_default_caches).as_str(),
                format!("no_host_mounts={}", self.no_host_mounts).as_str(),
                format!("no_docker_socket={}", self.no_docker_socket).as_str(),
                format!("no_secrets={}", self.no_secrets).as_str(),
                format!("no_ssh={}", self.no_ssh).as_str(),
                format!("no_privileged={}", self.no_privileged).as_str(),
                format!("no_plugins={}", self.no_plugins).as_str(),
                format!("no_external_cache={}", self.no_external_cache).as_str(),
            ],
        )
    }
}

/// `NewBuildRequest` — refuses an unbound request before any isolation
/// flags exist.
pub fn new_build_request(
    selector: &str,
    recipe: &[u8],
    root_a: &str,
    root_b: &str,
    network_after_import: bool,
) -> Result<BuildRequest, Failure> {
    if selector.is_empty() || recipe.is_empty() || root_a.is_empty() || root_b.is_empty() {
        return Err(Failure::invalid(
            codes::BUILD_REQUEST_INVALID,
            "dependencyprepare: invalid build request",
        ));
    }
    Ok(BuildRequest {
        selector: selector.to_owned(),
        recipe: recipe.to_vec(),
        root_a: root_a.to_owned(),
        root_b: root_b.to_owned(),
        network_after_import,
        no_default_caches: true,
        no_host_mounts: true,
        no_docker_socket: true,
        no_secrets: true,
        no_ssh: true,
        no_privileged: true,
        no_plugins: true,
        no_external_cache: true,
    })
}

/// `BuilderIdentity` — the descriptor-bound identity recorded for a
/// builder root. It is a digest so that evidence never carries a raw
/// path.
#[must_use]
pub fn builder_identity(root: &str) -> String {
    digest_fields("central.builder-root/v1", &[root])
}

/// `ImageLoadRequest` — asks for one proven build's export to be made
/// resolvable in the host's local image store. `proven` is not a hint:
/// it is the identity the load is required to produce, and the only
/// identity a caller is allowed to pass is one the two-build
/// comparison has already proven equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLoadRequest {
    /// The selector being loaded.
    pub selector: String,
    /// The proven build's `BuildRequest::export_path()`.
    pub export: String,
    /// The proven OCI identity.
    pub proven: OciInventory,
}

impl ImageLoadRequest {
    /// `Reference` — the local reference the loaded image must answer
    /// to: the same string `infralifecycle.ImageReference` renders for
    /// the built mode, and what B03's receipt inspection runs
    /// `docker image inspect` against.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}@{}", BUILT_IMAGE_REPOSITORY, self.proven.manifest_digest)
    }

    /// `PinnedReference` — the second name the load must leave behind:
    /// the proven content under a name derived from its own manifest
    /// digest, in the conventional `sha256-<hex>` tag encoding.
    ///
    /// It exists because a repository-and-tag name is a mutable
    /// pointer: re-pointing the only tag that held a manifest makes
    /// `docker image inspect <repo>@<digest>` answer "No such image".
    /// This name cannot collide with a different build — it is the
    /// content's own digest — so retention is explicit rather than
    /// accidental.
    #[must_use]
    pub fn pinned_reference(&self) -> String {
        format!(
            "{}:sha256-{}",
            BUILT_IMAGE_REPOSITORY,
            self.proven.manifest_digest.trim_start_matches("sha256:")
        )
    }

    /// `Validate` — refuses a load that could not possibly satisfy
    /// the receipt, before any host state is touched. The manifest
    /// digest is checked for shape and not merely for presence: it
    /// is interpolated into an image reference that becomes an
    /// argument to a subprocess, so anything but a canonical sha256
    /// digest is refused here rather than at the process boundary.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| {
            Failure::invalid(
                prepare_codes::IMAGE_LOAD_INVALID,
                format!("dependencyprepare: {msg}"),
            )
        };
        if self.selector.is_empty() {
            return Err(invalid("invalid image load request: no selector"));
        }
        if self.export.is_empty() {
            return Err(invalid("invalid image load request: no export path"));
        }
        if !Path::new(&self.export).is_absolute() {
            return Err(invalid(
                "invalid image load request: export path must be absolute",
            ));
        }
        valid_canonical_digest(&self.proven.manifest_digest)
            .map_err(|_| invalid("invalid image load request: manifest digest is not canonical"))?;
        if self.proven.index_digest.is_empty() || self.proven.config_digest.is_empty() {
            return Err(invalid(
                "invalid image load request: proven inventory is incomplete",
            ));
        }
        Ok(())
    }
}

/// `LoadedImage` — what the host's image store actually reported after
/// a load: the reference that was inspected and the image ID it
/// resolved to. It is an observation, never an assertion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedImage {
    /// The reference inspected.
    pub reference: String,
    /// The image ID it resolved to.
    pub image_id: String,
}

/// `ValidateLoadedImage` — refuses a load whose observed identity is
/// not the proven one. A load that merely "succeeded" is not evidence
/// of anything: on a host whose image store cannot key an image by
/// manifest digest, `docker load` prints success and the digest
/// reference still resolves to nothing.
///
/// Nothing observed is interpolated into the returned reason until it
/// has been checked to be a canonical digest — the observed identity
/// is whatever the host's image store printed, unbounded, and only the
/// expected reference and a digest-shaped observation may be quoted.
pub fn validate_loaded_image(got: &LoadedImage, proven: &OciInventory) -> Result<(), Failure> {
    valid_canonical_digest(&proven.manifest_digest).map_err(|_| {
        Failure::invalid(
            codes::IMAGE_UNRESOLVABLE,
            "dependencyprepare: loaded image is not resolvable as its proven identity: proven manifest digest is not canonical",
        )
    })?;
    let want = format!("{}@{}", BUILT_IMAGE_REPOSITORY, proven.manifest_digest);
    valid_canonical_digest(&got.image_id).map_err(|_| {
        Failure::invalid(
            codes::IMAGE_UNRESOLVABLE,
            format!(
                "dependencyprepare: loaded image is not resolvable as its proven identity: reference {want:?} did not resolve to a canonical image digest"
            ),
        )
    })?;
    if got.reference != want {
        return Err(Failure::invalid(
            codes::IMAGE_UNRESOLVABLE,
            format!(
                "dependencyprepare: loaded image is not resolvable as its proven identity: the image was resolved by a reference other than {want:?}"
            ),
        ));
    }
    if got.image_id != proven.manifest_digest {
        return Err(Failure::invalid(
            codes::IMAGE_UNRESOLVABLE,
            format!(
                "dependencyprepare: loaded image is not resolvable as its proven identity: reference {want:?} resolved to {:?}, expected the proven manifest digest {:?}",
                got.image_id, proven.manifest_digest
            ),
        ));
    }
    Ok(())
}

// ===========================================================================
// domain.go — attestation statements and the prepared manifest
// ===========================================================================

/// `AttestationSubject` — binds an attestation to one exact canonical
/// OCI layout. All four fields are required: a subject that names only
/// an index digest leaves the platform manifest and config unbound.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationSubject {
    /// The subject name.
    pub name: String,
    /// OCI index digest.
    pub index_digest: String,
    /// Platform manifest digest.
    pub manifest_digest: String,
    /// Image config digest.
    pub config_digest: String,
}

/// `SubjectFromInventory` — the attestation subject for a built
/// layout.
#[must_use]
pub fn subject_from_inventory(name: &str, inv: &OciInventory) -> AttestationSubject {
    AttestationSubject {
        name: name.to_owned(),
        index_digest: inv.index_digest.clone(),
        manifest_digest: inv.manifest_digest.clone(),
        config_digest: inv.config_digest.clone(),
    }
}

impl AttestationSubject {
    /// `Validate` — every field present.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| {
            Failure::invalid(
                codes::ATTESTATION_INVALID,
                format!("dependencyprepare: {msg}"),
            )
        };
        if self.name.is_empty() {
            return Err(invalid("invalid attestation: subject name is empty"));
        }
        if self.index_digest.is_empty() {
            return Err(invalid(
                "invalid attestation: subject index digest is empty",
            ));
        }
        if self.manifest_digest.is_empty() {
            return Err(invalid(
                "invalid attestation: subject manifest digest is empty",
            ));
        }
        if self.config_digest.is_empty() {
            return Err(invalid(
                "invalid attestation: subject config digest is empty",
            ));
        }
        Ok(())
    }
}

/// `AttestationMaterials` — the binding the design requires every
/// attestation to carry alongside its subject: the lock, source
/// archive, bases, both builder identities, the invocation, and the
/// operation. Builder identities are descriptor-bound digests, never
/// paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationMaterials {
    /// JCS-canonical digest of the lock.
    pub lock_digest: String,
    /// SHA-256 of the source archive.
    pub source_archive_digest: String,
    /// The pinned source commit.
    pub source_commit: String,
    /// Base image identities (base ref, published index).
    #[serde(default, deserialize_with = "null_to_default")]
    pub base_identities: Vec<String>,
    /// First builder identity digest.
    pub builder_identity_a: String,
    /// Second builder identity digest.
    pub builder_identity_b: String,
    /// The build invocation digest.
    pub invocation_digest: String,
    /// The prepare operation identifier.
    pub operation_id: String,
}

impl AttestationMaterials {
    /// `Validate` — the full binding must be present and the two
    /// builder identities distinct.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| {
            Failure::invalid(
                codes::ATTESTATION_INVALID,
                format!("dependencyprepare: {msg}"),
            )
        };
        if self.lock_digest.is_empty() {
            return Err(invalid(
                "invalid attestation: materials lock digest is empty",
            ));
        }
        if self.source_archive_digest.is_empty() {
            return Err(invalid(
                "invalid attestation: materials source archive digest is empty",
            ));
        }
        if self.source_commit.is_empty() {
            return Err(invalid(
                "invalid attestation: materials source commit is empty",
            ));
        }
        if self.base_identities.is_empty() {
            return Err(invalid(
                "invalid attestation: materials carry no base identities",
            ));
        }
        if self.builder_identity_a.is_empty() || self.builder_identity_b.is_empty() {
            return Err(invalid(
                "invalid attestation: materials do not name both builder identities",
            ));
        }
        if self.builder_identity_a == self.builder_identity_b {
            return Err(invalid(&format!(
                "invalid attestation: both builder identities are {:?}",
                self.builder_identity_a
            )));
        }
        if self.invocation_digest.is_empty() {
            return Err(invalid(
                "invalid attestation: materials invocation digest is empty",
            ));
        }
        if self.operation_id.is_empty() {
            return Err(invalid(
                "invalid attestation: materials operation ID is empty",
            ));
        }
        for (i, base) in self.base_identities.iter().enumerate() {
            if base.is_empty() {
                return Err(invalid(&format!(
                    "invalid attestation: materials base identity {i} is empty"
                )));
            }
        }
        Ok(())
    }
}

/// `AttestationStatement` — the signed payload of one attestation
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationStatement {
    /// `central.local-dependency-attestation/v1`.
    pub schema: String,
    /// The predicate this statement attests.
    pub predicate: AttestationPredicate,
    /// The exact canonical OCI layout.
    pub subject: AttestationSubject,
    /// The full materials binding.
    pub materials: AttestationMaterials,
}

/// `NewAttestationStatement` — builds a complete, self-consistent
/// statement. It refuses to build an under-bound one, so a signer
/// cannot emit an envelope a strict verifier would then have to
/// reject. Upstream's unknown-predicate refusal is unrepresentable
/// here — `AttestationPredicate` is a closed enum — so the checks that
/// remain are the subject and materials bindings.
pub fn new_attestation_statement(
    predicate: AttestationPredicate,
    subject: AttestationSubject,
    materials: AttestationMaterials,
) -> Result<AttestationStatement, Failure> {
    subject.validate()?;
    materials.validate()?;
    Ok(AttestationStatement {
        schema: ATTESTATION_SCHEMA.to_owned(),
        predicate,
        subject,
        materials,
    })
}

/// `AttestationExpectation` — everything a verifier must already know
/// before it may admit an envelope. There is no partial verification:
/// an expectation that does not validate is refused rather than
/// silently narrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationExpectation {
    /// The predicate expected.
    pub predicate: AttestationPredicate,
    /// The expected subject.
    pub subject: AttestationSubject,
    /// The expected materials.
    pub materials: AttestationMaterials,
}

impl AttestationExpectation {
    /// `Validate` — an expectation that does not validate admits
    /// nothing. The predicate is a closed enum, so the checks that
    /// remain are the subject and materials bindings.
    pub fn validate(&self) -> Result<(), Failure> {
        self.subject.validate().map_err(|e| {
            Failure::invalid(e.code(), format!("expectation subject: {}", e.message()))
        })?;
        self.materials.validate().map_err(|e| {
            Failure::invalid(e.code(), format!("expectation materials: {}", e.message()))
        })?;
        Ok(())
    }
}

/// `SignedAttestation` — one envelope together with the predicate it
/// carries. `envelope` is a `[]byte` upstream — Base64 on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The predicate carried.
    pub predicate: AttestationPredicate,
    /// The DSSE envelope bytes.
    #[serde(with = "crate::authority::wire::b64_lenient")]
    pub envelope: Vec<u8>,
}

/// `PreparedManifest` — the immutable, integrity-protected candidate
/// manifest. Its JSON field names for selector, phase, created_at,
/// candidate_id and dependency_set are deliberately the ones the
/// pre-schema manifest already used, so a manifest written by an
/// earlier build still decodes here.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PreparedManifest {
    /// `central.prepared-dependencies/v1`, or empty on a legacy
    /// record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema: String,
    /// The candidate identifier.
    #[serde(default)]
    pub candidate_id: String,
    /// The settling operation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    /// The selector prepared.
    #[serde(default)]
    pub selector: String,
    /// The phase the manifest froze at; absent on a legacy record.
    #[serde(default)]
    pub phase: PreparePhase,
    /// Creation time text.
    #[serde(default)]
    pub created_at: String,
    /// The lock's canonical digest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lock_digest: String,
    /// The config binding.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_binding: String,
    /// The helper release digest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub helper_release: String,
    /// The advisory lineage.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub advisory_lineage: String,
    /// The promotion receipt.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub promotion_receipt_id: String,
    /// The prepared modes; absent on a legacy record.
    #[serde(default)]
    pub dependency_set: PreparedDependencySet,
    /// The comparison evidence; absent on a legacy record.
    #[serde(default)]
    pub comparison: ComparisonFact,
    /// The attestation facts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<AttestationFact>,
    /// `build` or `release`; absent reads as `build` (upstream's
    /// empty `Source` and its `omitempty` both land on `Build`).
    #[serde(default)]
    pub source: ManifestSource,
    /// The verified DSSE envelopes persisted for later audit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envelopes: Vec<StoredEnvelope>,
}

impl PreparedManifest {
    /// `EffectiveSource` — an empty `source` reads as `build`:
    /// manifests written before the field existed are builds. The
    /// port folds the empty value into [`ManifestSource::Build`], so
    /// the effective source is the field itself.
    #[must_use]
    pub fn effective_source(&self) -> ManifestSource {
        self.source
    }

    /// `IsLegacy` — a manifest written before the schema field
    /// existed. Such a manifest carries a dependency set and nothing
    /// else, and cannot be treated as evidence that comparison or
    /// attestation ever ran.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.schema.is_empty()
    }
}

/// `ValidateManifestSource` — enforces the envelope rule: release
/// manifests carry exactly the three required envelopes (one per
/// predicate, non-empty); build manifests carry none.
pub fn validate_manifest_source(manifest: &PreparedManifest) -> Result<(), Failure> {
    match manifest.effective_source() {
        ManifestSource::Build => {
            if !manifest.envelopes.is_empty() {
                return Err(Failure::invalid(
                    codes::CANDIDATE_INVALID,
                    format!(
                        "dependencyprepare: invalid candidate: build manifest carries {} envelopes",
                        manifest.envelopes.len()
                    ),
                ));
            }
            Ok(())
        }
        ManifestSource::Release => {
            if manifest.envelopes.len() != REQUIRED_ATTESTATION_PREDICATES.len() {
                return Err(Failure::invalid(
                    codes::CANDIDATE_INVALID,
                    format!(
                        "dependencyprepare: invalid candidate: release manifest carries {} envelopes, want {}",
                        manifest.envelopes.len(),
                        REQUIRED_ATTESTATION_PREDICATES.len()
                    ),
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for envelope in &manifest.envelopes {
                // `AttestationPredicate` is a closed enum, so
                // upstream's `IsValid` disjunct is unrepresentable
                // here; the serde boundary already refused unspellable
                // values.
                if !seen.insert(envelope.predicate) || envelope.envelope.is_empty() {
                    return Err(Failure::invalid(
                        codes::CANDIDATE_INVALID,
                        format!(
                            "dependencyprepare: invalid candidate: release manifest envelope {:?} is invalid",
                            envelope.predicate.as_str()
                        ),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// `PreparedReceiptRecord` — names one manifest digest, one operation
/// settlement, and one active-selector generation. It is the durable
/// form of `Receipt` and the record B03 consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedReceiptRecord {
    /// `central.dependency-preparation-receipt/v1`.
    pub schema: String,
    /// The candidate receipt.
    pub receipt_id: String,
    /// The manifest digest.
    pub manifest_digest: String,
    /// The settling operation.
    pub operation_id: String,
    /// The active-selector generation.
    pub selector_generation: String,
    /// The admission receipt.
    pub admission_receipt_id: String,
    /// When the receipt settled.
    pub settled_at: String,
}

impl PreparedReceiptRecord {
    /// `Validate` — every binding present; a receipt that names no
    /// operation can never exercise the "names one operation
    /// settlement" property.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |msg: &str| {
            Failure::invalid(
                codes::CANDIDATE_INVALID,
                format!("dependencyprepare: {msg}"),
            )
        };
        if self.schema != PREPARED_RECEIPT_SCHEMA {
            return Err(invalid(&format!(
                "invalid candidate: receipt schema {:?} != {:?}",
                self.schema, PREPARED_RECEIPT_SCHEMA
            )));
        }
        if self.receipt_id.is_empty() {
            return Err(invalid("invalid candidate: receipt names no candidate"));
        }
        if self.manifest_digest.is_empty() {
            return Err(invalid(
                "invalid candidate: receipt names no manifest digest",
            ));
        }
        if self.selector_generation.is_empty() {
            return Err(invalid(
                "invalid candidate: receipt names no selector generation",
            ));
        }
        if self.operation_id.is_empty() {
            return Err(invalid("invalid candidate: receipt names no operation"));
        }
        if self.admission_receipt_id.is_empty() {
            return Err(invalid("invalid candidate: receipt names no admission"));
        }
        Ok(())
    }
}

// ===========================================================================
// release.go — the operator-delivered release shape
// ===========================================================================

/// `ReleaseSchemaVersion` — the only `schema_version` a release file
/// may declare.
pub const RELEASE_SCHEMA_VERSION: &str = "central.release/v1";

/// `ReleaseFileName` — the release's own manifest file.
pub const RELEASE_FILE_NAME: &str = "release.json";
/// `MinioTarName` — the staged MinIO image tarball.
pub const MINIO_TAR_NAME: &str = "image.tar";
/// `InfraTarName` — the staged infra image tarball.
pub const INFRA_TAR_NAME: &str = "image.tar";
/// `ComparisonFileName` — the release's recorded comparison fact.
pub const COMPARISON_FILE_NAME: &str = "comparison.json";
/// `MaxReleaseFileBytes`.
pub const MAX_RELEASE_FILE_BYTES: u64 = 64 << 10;
/// `MaxEnvelopeBytes`.
pub const MAX_ENVELOPE_BYTES: u64 = 1 << 20;
/// `MaxComparisonBytes`.
pub const MAX_COMPARISON_BYTES: u64 = 64 << 10;
/// `MaxMinioTarBytes`.
pub const MAX_MINIO_TAR_BYTES: u64 = 1 << 30;
/// `MaxInfraTarBytes`.
pub const MAX_INFRA_TAR_BYTES: u64 = 2 << 30;
/// `MaxReleaseTarMembers`.
pub const MAX_RELEASE_TAR_MEMBERS: u64 = 64;

/// `ReleaseInfraModes` — the lock modes served by the release's infra
/// tarball: the central-local-infra image's modes, which pin one
/// image.
pub const RELEASE_INFRA_MODES: [ServiceMode; 4] = [
    ServiceMode::PostgresFsInit,
    ServiceMode::MinioFsInit,
    ServiceMode::MinioProvision,
    ServiceMode::PostgresThroughputProvision,
];

/// `ReleaseEvidence` — a release whose envelopes verified: the facts
/// to freeze into the manifest plus the staged artifacts to load.
#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseEvidence {
    /// The verified attestation facts.
    pub facts: Vec<AttestationFact>,
    /// The verified subject.
    pub subject: AttestationSubject,
    /// The full verified MinIO inventory (with layers): the receipt's
    /// MinIO entry and the loader's `proven` value.
    pub inventory: OciInventory,
    /// The verified comparison fact.
    pub comparison: ComparisonFact,
    /// The staged MinIO tarball path.
    pub minio_tar: String,
    /// The staged infra tarball path.
    pub infra_tar: String,
    /// The verified envelopes by predicate.
    pub envelopes: BTreeMap<AttestationPredicate, Vec<u8>>,
    /// How many release bytes the import staged: the only byte figure
    /// the import's progress counters may carry.
    pub staged_bytes: i64,
}

/// `ReleaseTrustMaterials` — the trust-relevant attestation materials
/// extracted from the lock. Producer-local fields stay empty: import
/// verification overlays them from inside each verified envelope.
pub fn release_trust_materials(lock: &Lock) -> Result<AttestationMaterials, Failure> {
    let lock_digest = lock.canonical_hash().map_err(|e| {
        Failure::invalid(
            e.code(),
            format!("release trust materials: {}", e.message()),
        )
    })?;
    Ok(AttestationMaterials {
        lock_digest,
        source_archive_digest: lock.fetches.minio.archive_sha256.clone(),
        source_commit: lock.fetches.minio.commit.clone(),
        base_identities: vec![
            lock.buildkit.base_ref.clone(),
            lock.fetches.postgresql.index_sha256.clone(),
        ],
        ..AttestationMaterials::default()
    })
}

/// `ReleaseFile` — the parsed `release.json`: the release's claimed
/// lock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFile {
    /// `central.release/v1`.
    pub schema_version: String,
    /// The lock the release claims.
    pub lock_digest: String,
}

/// `ParseReleaseFile` — strict-decode `release.json` and validate it.
pub fn parse_release_file(raw: &[u8]) -> Result<ReleaseFile, Failure> {
    let rf: ReleaseFile = serde_json::from_slice(raw).map_err(|e| {
        Failure::invalid(
            prepare_codes::RELEASE_INVALID,
            format!("dependencyprepare: release invalid: release.json: {e}"),
        )
    })?;
    rf.validate()?;
    Ok(rf)
}

impl ReleaseFile {
    /// `Validate` — the release file's schema version and lock digest
    /// shape.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.schema_version != RELEASE_SCHEMA_VERSION {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: release.json schema {:?}",
                    self.schema_version
                ),
            ));
        }
        if !self.lock_digest.starts_with("sha256:")
            || self.lock_digest.len() != "sha256:".len() + 64
        {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                "dependencyprepare: release invalid: release.json lock digest",
            ));
        }
        Ok(())
    }
}

/// `ReleasePaths` — the staged (root-owned) copies. Every later step
/// reads these, never the operator DIR.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReleasePaths {
    /// The staging root.
    pub root: String,
    /// Staged `release.json`.
    pub release_file: String,
    /// Staged MinIO tarball.
    pub minio_tar: String,
    /// Staged envelopes by predicate.
    pub envelopes: BTreeMap<AttestationPredicate, String>,
    /// Staged comparison file.
    pub comparison_file: String,
    /// Staged infra tarball.
    pub infra_tar: String,
    /// Total staged bytes.
    pub staged_bytes: i64,
}

/// `EnvelopeFileName` — the staged name for one predicate's envelope.
#[must_use]
pub fn envelope_file_name(predicate: AttestationPredicate) -> String {
    format!("attestation-{}.json", predicate.as_str())
}

// ===========================================================================
// Tests — ported from upstream lock_test.go, domain_test.go,
// release_test.go, safe_result_test.go, imageload_test.go.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The verified JCS-canonical digest of the embedded lock —
    /// cross-checked against upstream's `gowebpki/jcs` Transform over
    /// the byte-identical asset (D6 parity).
    const LOCK_DIGEST_EXPECTED: &str =
        "sha256:3cf008228ca25686882cfe69e78ae57836f4b52b18bd5e05a04c3838aee6e02e";

    fn parsed_lock() -> Lock {
        parse_lock(LOCKED_ASSETS_JSON).expect("embedded lock parses")
    }

    // ---- lock_test.go ------------------------------------------------

    #[test]
    fn shipped_lock_is_valid() {
        let lock = load_lock().expect("LoadLock");
        assert_eq!(lock.schema, LOCK_SCHEMA);
        assert_eq!(lock.helper_release_digest, UNSET_DIGEST);
        assert!(lock.fetch_capability.contains_key("minio"));
        assert!(lock.fetch_capability.contains_key("gomodules"));
        assert_eq!(lock.modes.len(), 7);
    }

    #[test]
    fn shipped_lock_matches_pinned_digest() {
        // D6: the JCS-canonical digest of the embedded lock is the
        // identity every advisory, release and manifest binds. This
        // expectation is the upstream-recorded value; a canonicalizer
        // that disagrees fails here.
        let lock = parsed_lock();
        let digest = lock.canonical_hash().expect("canonical hash");
        assert_eq!(digest, LOCK_DIGEST_EXPECTED);
        lock.verify_digest(LOCK_DIGEST_EXPECTED).unwrap();
    }

    #[test]
    fn shipped_lock_recipe_digest_matches() {
        let lock = parsed_lock();
        lock.verify_recipe_digest().unwrap();
        let digest = recipe_digest().unwrap();
        assert_eq!(lock.recipe_digest, digest);
    }

    #[test]
    fn shipped_lock_identities_match_pinned() {
        parsed_lock().verify_identities().unwrap();
    }

    #[test]
    fn shipped_lock_release_digest_unset_refuses() {
        let lock = parsed_lock();
        let err = lock
            .verify_release_digest(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_HELPER_DIGEST_UNSET);
    }

    #[test]
    fn verify_digest_refuses_mismatch() {
        let lock = parsed_lock();
        let err = lock.verify_digest(UNSET_DIGEST).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_DIGEST_MISMATCH);
    }

    #[test]
    fn verify_identities_refuses_postgresql_drift() {
        let mut lock = parsed_lock();
        lock.fetches.postgresql.config_sha256 = UNSET_DIGEST.to_owned();
        let err = lock.verify_identities().unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_IDENTITY_MISMATCH);
    }

    #[test]
    fn verify_identities_refuses_minio_drift() {
        let mut lock = parsed_lock();
        lock.fetches.minio.commit = "0".repeat(40);
        let err = lock.verify_identities().unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_IDENTITY_MISMATCH);
    }

    #[test]
    fn verify_identities_refuses_minio_archive_drift() {
        let mut lock = parsed_lock();
        lock.fetches.minio.archive_sha256 = UNSET_DIGEST.to_owned();
        let err = lock.verify_identities().unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_IDENTITY_MISMATCH);
    }

    #[test]
    fn parse_refuses_trailing_data() {
        let mut raw = LOCKED_ASSETS_JSON.to_vec();
        raw.extend_from_slice(b" {}");
        let err = parse_lock(&raw).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_INVALID_JSON);
    }

    #[test]
    fn parse_refuses_duplicate_top_level_key() {
        let raw = br#"{"schema":"x","schema":"y"}"#.as_slice();
        let err = parse_lock(raw).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_DUPLICATE_KEY);
    }

    #[test]
    fn parse_refuses_unknown_field() {
        let raw = br#"{"schema":"x","bogus":1}"#.as_slice();
        let err = parse_lock(raw).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_UNKNOWN_FIELD);
    }

    #[test]
    fn parse_refuses_schema_mismatch() {
        let raw = br#"{"schema":"other/v9"}"#.as_slice();
        let err = parse_lock(raw).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_SCHEMA_MISMATCH);
    }

    #[test]
    fn parse_refuses_invalid_utf8() {
        let raw = b"\xff\xfe".as_slice();
        let err = parse_lock(raw).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_INVALID_JSON);
    }

    #[test]
    fn parse_refuses_oversize() {
        let raw = vec![b' '; (1 << 20) + 1];
        let err = parse_lock(&raw).unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_INVALID_JSON);
    }

    #[test]
    fn retry_policy_bounds_hold() {
        let mut p = RetryPolicy {
            max_attempts: 0,
            backoff_ms: vec![],
        };
        assert_eq!(
            p.validate().unwrap_err().code(),
            prepare_codes::LOCK_INVALID_RETRY_POLICY
        );
        p = RetryPolicy {
            max_attempts: 3,
            backoff_ms: vec![1],
        };
        assert!(p.validate().is_err());
        p = RetryPolicy {
            max_attempts: 3,
            backoff_ms: vec![1000, 5000],
        };
        p.validate().unwrap();
        assert_eq!(p.backoff(1), Duration::ZERO);
        assert_eq!(p.backoff(2), Duration::from_millis(1000));
        assert_eq!(p.backoff(3), Duration::from_millis(5000));
        assert_eq!(p.backoff(4), Duration::ZERO);
    }

    #[test]
    fn shipped_fetch_capabilities_are_production_posture() {
        let lock = parsed_lock();
        lock.validate_shipped_fetch_capabilities().unwrap();
        for cap in lock.fetch_capability.values() {
            assert_eq!(cap.tls_policy, TlsFetchMode::SystemRoots);
            assert_eq!(cap.address_policy, ADDRESS_POLICY_PUBLIC_UNICAST);
        }
    }

    #[test]
    fn fetch_capability_for_unknown_selector_refuses() {
        let lock = parsed_lock();
        let err = lock.fetch_capability_for("nosuch").unwrap_err();
        assert_eq!(err.code(), prepare_codes::LOCK_INVALID_FETCH_CAPABILITY);
    }

    #[test]
    fn fetch_capability_validate_refuses_bad_shape() {
        let mut cap = FetchCapability {
            scheme: "http".to_owned(),
            ..FetchCapability::default()
        };
        assert_eq!(
            cap.validate().unwrap_err().code(),
            prepare_codes::LOCK_INVALID_FETCH_CAPABILITY
        );
        cap.scheme = "https".to_owned();
        cap.host = "h".to_owned();
        cap.port = 443;
        cap.path_prefix = "/p".to_owned();
        cap.address_policy = ADDRESS_POLICY_ANY.to_owned();
        cap.max_bytes = 1;
        cap.deadline_ms = 1;
        cap.validate().unwrap();
        cap.address_policy = "bogus".to_owned();
        assert!(cap.validate().is_err());
    }

    #[test]
    fn attestation_trust_policy_rejects_small_order_and_bad_hex() {
        let good = "95bf1446040b21139aa1dae2a19d6072f19516bb4b1ed710fac6300ba7521a59";
        let mut policy = AttestationTrustPolicy {
            keys: vec![TrustedKey {
                key_id: "k".to_owned(),
                public_key: "00".repeat(32),
                expires_at: None,
                revoked: false,
            }],
        };
        assert_eq!(
            policy.validate().unwrap_err().code(),
            prepare_codes::ATTESTATION_SMALL_ORDER_KEY
        );
        policy.keys[0].public_key = "zz".repeat(32);
        assert_eq!(
            policy.validate().unwrap_err().code(),
            prepare_codes::ATTESTATION_INVALID_KEY_HEX
        );
        policy.keys[0].public_key = "aa".repeat(10);
        assert_eq!(
            policy.validate().unwrap_err().code(),
            prepare_codes::ATTESTATION_INVALID_KEY_HEX
        );
        policy.keys[0].public_key = good.to_owned();
        policy.keys[0].expires_at = Some("2020-01-01T00:00:00Z".to_owned());
        assert_eq!(
            policy.validate().unwrap_err().code(),
            prepare_codes::ATTESTATION_EXPIRED
        );
        // A revoked-but-otherwise-valid key still validates: the
        // refusal happens at verify time (ADR 0030).
        policy.keys[0].expires_at = None;
        policy.keys[0].revoked = true;
        policy.validate().unwrap();
    }

    #[test]
    fn shipped_trust_anchor_validates() {
        let lock = parsed_lock();
        lock.attestation_trust.validate().unwrap();
    }

    // ---- domain_test.go: result / safe_next_action -------------------

    fn result_with(reason: &str, phase: PreparePhase) -> PrepareResult {
        let mut r = new_result("op-1", phase).unwrap();
        r.reason = reason.to_owned();
        r
    }

    #[test]
    fn safe_next_action_mapping() {
        let mut r = result_with("", PreparePhase::Ready);
        assert_eq!(safe_next_action_for(&r), SafeNextAction::None);
        r = result_with("", PreparePhase::Skipped);
        assert_eq!(safe_next_action_for(&r), SafeNextAction::Prepare);
        r = result_with("FETCH_FAILED: boom", PreparePhase::Failed);
        assert_eq!(safe_next_action_for(&r), SafeNextAction::Prepare);
        r = result_with("BUILD_MISMATCH: a!=b", PreparePhase::Failed);
        assert_eq!(safe_next_action_for(&r), SafeNextAction::Terminal);
        r.resume_required = true;
        assert_eq!(safe_next_action_for(&r), SafeNextAction::Resume);
        let stamped = with_safe_next_action(result_with("", PreparePhase::Failed));
        assert_eq!(stamped.safe_next_action, SafeNextAction::Terminal);
    }

    #[test]
    fn append_stage_timing_bounds() {
        let mut t = Vec::new();
        append_stage_timing(&mut t, PreparePhase::Acquiring, Duration::from_millis(42));
        assert_eq!(t[0].phase, "acquiring");
        assert_eq!(t[0].duration_ms, 42.0);
        for _ in 0..MAX_STAGE_TIMINGS + 4 {
            append_stage_timing(&mut t, PreparePhase::Failed, Duration::ZERO);
        }
        assert_eq!(t.len(), MAX_STAGE_TIMINGS);
    }

    #[test]
    fn safe_counters_project() {
        let c = SafeCounters {
            fetched: 1,
            built: 2,
            compared: 3,
            staged: 4,
            bytes_read: 5,
            build_count: 9,
        };
        let r = c.resources();
        assert_eq!(r.built, 2);
        assert_eq!(r.bytes_read, 5);
    }

    // ---- domain_test.go: build/load requests -------------------------

    #[test]
    fn build_request_conventions() {
        let req = new_build_request("minio", b"{}", "/a", "/b", false).unwrap();
        assert_eq!(req.context_dir(), Path::new("/b").join("context"));
        assert_eq!(req.export_path(), Path::new("/b").join("oci-output.tar"));
        assert!(req.no_docker_socket && req.no_secrets && req.no_privileged);
        assert_ne!(req.invocation_digest(), "");
        assert_ne!(builder_identity("/a"), builder_identity("/a2"),);
        assert_eq!(builder_identity("/a"), builder_identity("/a"));
        // Every flag participates in the invocation digest.
        let mut altered = req.clone();
        altered.no_docker_socket = false;
        assert_ne!(req.invocation_digest(), altered.invocation_digest());
    }

    #[test]
    fn build_request_refuses_unbound() {
        assert!(new_build_request("", b"{}", "/a", "/b", false).is_err());
        assert!(new_build_request("minio", b"", "/a", "/b", false).is_err());
        assert!(new_build_request("minio", b"{}", "", "/b", false).is_err());
        assert!(new_build_request("minio", b"{}", "/a", "", false).is_err());
    }

    #[test]
    fn image_load_request_references() {
        let inv = OciInventory {
            index_digest: format!("sha256:{}", "1".repeat(64)),
            manifest_digest: format!("sha256:{}", "2".repeat(64)),
            config_digest: format!("sha256:{}", "3".repeat(64)),
            layers: vec![],
        };
        let req = ImageLoadRequest {
            selector: "minio".to_owned(),
            export: "/tmp/x/oci-output.tar".to_owned(),
            proven: inv.clone(),
        };
        req.validate().unwrap();
        assert_eq!(
            req.reference(),
            format!("central-minio@sha256:{}", "2".repeat(64))
        );
        assert_eq!(
            req.pinned_reference(),
            format!("central-minio:sha256-{}", "2".repeat(64))
        );
        let got = LoadedImage {
            reference: req.reference(),
            image_id: inv.manifest_digest.clone(),
        };
        validate_loaded_image(&got, &inv).unwrap();
        // Wrong reference shape.
        let bad = LoadedImage {
            reference: "central-minio:latest".to_owned(),
            image_id: inv.manifest_digest.clone(),
        };
        assert_eq!(
            validate_loaded_image(&bad, &inv).unwrap_err().code(),
            codes::IMAGE_UNRESOLVABLE
        );
        // Digest drift.
        let drift = LoadedImage {
            reference: req.reference(),
            image_id: format!("sha256:{}", "9".repeat(64)),
        };
        assert!(validate_loaded_image(&drift, &inv).is_err());
        // Non-digest image ID is refused before it can be quoted.
        let junk = LoadedImage {
            reference: req.reference(),
            image_id: "sha256:XYZnothex".to_owned(),
        };
        assert!(validate_loaded_image(&junk, &inv).is_err());
        // Request validation.
        let mut r2 = req.clone();
        r2.export = "relative/path".to_owned();
        assert_eq!(
            r2.validate().unwrap_err().code(),
            prepare_codes::IMAGE_LOAD_INVALID
        );
        r2.export = "/abs".to_owned();
        r2.proven.manifest_digest = "not-a-digest".to_owned();
        assert!(r2.validate().is_err());
    }

    // ---- domain_test.go: attestation binding -------------------------

    fn materials() -> AttestationMaterials {
        AttestationMaterials {
            lock_digest: "sha256:a".to_owned(),
            source_archive_digest: "sha256:b".to_owned(),
            source_commit: "c".repeat(40),
            base_identities: vec!["scratch".to_owned()],
            builder_identity_a: "sha256:x".to_owned(),
            builder_identity_b: "sha256:y".to_owned(),
            invocation_digest: "sha256:i".to_owned(),
            operation_id: "op".to_owned(),
        }
    }

    #[test]
    fn attestation_statement_binding() {
        let subject = subject_from_inventory(
            "central-minio",
            &OciInventory {
                index_digest: "i".to_owned(),
                manifest_digest: "m".to_owned(),
                config_digest: "c".to_owned(),
                layers: vec![],
            },
        );
        let stmt =
            new_attestation_statement(AttestationPredicate::Sbom, subject.clone(), materials())
                .unwrap();
        assert_eq!(stmt.schema, "central.local-dependency-attestation/v1");
        // Distinct builders are required.
        let mut bad = materials();
        bad.builder_identity_b = bad.builder_identity_a.clone();
        assert!(
            new_attestation_statement(AttestationPredicate::Sbom, subject.clone(), bad).is_err()
        );
        // Empty subject refused.
        let empty = AttestationSubject::default();
        assert!(new_attestation_statement(AttestationPredicate::Sbom, empty, materials()).is_err());
        // Expectation validates the same binding.
        let expectation = AttestationExpectation {
            predicate: AttestationPredicate::Sbom,
            subject,
            materials: materials(),
        };
        expectation.validate().unwrap();
    }

    // ---- domain_test.go: manifest/receipt ----------------------------

    fn manifest_with(source: ManifestSource, envelopes: Vec<StoredEnvelope>) -> PreparedManifest {
        PreparedManifest {
            schema: crate::domain::PREPARED_MANIFEST_SCHEMA.to_owned(),
            source,
            envelopes,
            phase: PreparePhase::Ready,
            ..PreparedManifest::default()
        }
    }

    #[test]
    fn manifest_source_envelope_rule() {
        // Build manifest carries no envelopes.
        validate_manifest_source(&manifest_with(ManifestSource::Build, vec![])).unwrap();
        let bad_build = manifest_with(
            ManifestSource::Build,
            vec![StoredEnvelope {
                predicate: AttestationPredicate::Sbom,
                envelope: b"{}".to_vec(),
            }],
        );
        assert_eq!(
            validate_manifest_source(&bad_build).unwrap_err().code(),
            codes::CANDIDATE_INVALID
        );
        // Empty source reads as build.
        assert_eq!(
            PreparedManifest::default().effective_source(),
            ManifestSource::Build
        );
        // Release manifest needs exactly the three predicates.
        let envs: Vec<StoredEnvelope> = REQUIRED_ATTESTATION_PREDICATES
            .iter()
            .map(|p| StoredEnvelope {
                predicate: *p,
                envelope: b"env".to_vec(),
            })
            .collect();
        validate_manifest_source(&manifest_with(ManifestSource::Release, envs)).unwrap();
        let short = manifest_with(ManifestSource::Release, vec![]);
        assert!(validate_manifest_source(&short).is_err());
        let dup = manifest_with(
            ManifestSource::Release,
            vec![
                StoredEnvelope {
                    predicate: AttestationPredicate::Sbom,
                    envelope: b"e".to_vec(),
                },
                StoredEnvelope {
                    predicate: AttestationPredicate::Sbom,
                    envelope: b"e".to_vec(),
                },
                StoredEnvelope {
                    predicate: AttestationPredicate::Sbom,
                    envelope: b"e".to_vec(),
                },
            ],
        );
        assert!(validate_manifest_source(&dup).is_err());
    }

    #[test]
    fn receipt_record_validate() {
        let mut r = PreparedReceiptRecord {
            schema: PREPARED_RECEIPT_SCHEMA.to_owned(),
            receipt_id: "r".to_owned(),
            manifest_digest: "m".to_owned(),
            operation_id: "op".to_owned(),
            selector_generation: "g".to_owned(),
            admission_receipt_id: "a".to_owned(),
            settled_at: "t".to_owned(),
        };
        r.validate().unwrap();
        r.operation_id.clear();
        assert_eq!(r.validate().unwrap_err().code(), codes::CANDIDATE_INVALID);
    }

    // ---- release_test.go ----------------------------------------------

    #[test]
    fn release_file_parse_and_validate() {
        let rf = parse_release_file(
            br#"{"schema_version":"central.release/v1","lock_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#,
        )
        .unwrap();
        assert_eq!(rf.schema_version, RELEASE_SCHEMA_VERSION);
        assert_eq!(
            parse_release_file(br#"{"schema_version":"x","lock_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#)
                .unwrap_err()
                .code(),
            prepare_codes::RELEASE_INVALID
        );
        assert_eq!(
            parse_release_file(
                br#"{"schema_version":"central.release/v1","lock_digest":"sha256:short"}"#
            )
            .unwrap_err()
            .code(),
            prepare_codes::RELEASE_INVALID
        );
        assert_eq!(
            parse_release_file(br#"{"schema_version":"central.release/v1","lock_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","extra":1}"#)
                .unwrap_err()
                .code(),
            prepare_codes::RELEASE_INVALID
        );
    }

    #[test]
    fn release_infra_modes_match_shipped_lock() {
        // Upstream pins this against the embedded lock: a lock
        // evolution that changes the infra-mode set fails loudly here.
        let lock = parsed_lock();
        let locked_modes: Vec<ServiceMode> = lock.modes.iter().map(|m| m.mode).collect();
        for mode in RELEASE_INFRA_MODES {
            assert!(locked_modes.contains(&mode), "lock carries {mode:?}");
        }
    }

    #[test]
    fn release_trust_materials_from_lock() {
        let lock = parsed_lock();
        let materials = release_trust_materials(&lock).unwrap();
        assert_eq!(materials.lock_digest, lock.canonical_hash().unwrap());
        assert_eq!(
            materials.source_archive_digest,
            lock.fetches.minio.archive_sha256
        );
        assert_eq!(materials.source_commit, lock.fetches.minio.commit);
        assert_eq!(
            materials.base_identities,
            vec![
                lock.buildkit.base_ref.clone(),
                lock.fetches.postgresql.index_sha256.clone()
            ]
        );
    }

    #[test]
    fn envelope_file_names() {
        assert_eq!(
            envelope_file_name(AttestationPredicate::Sbom),
            "attestation-sbom.json"
        );
        assert_eq!(
            envelope_file_name(AttestationPredicate::SlsaProvenance),
            "attestation-slsa-provenance.json"
        );
    }
}
