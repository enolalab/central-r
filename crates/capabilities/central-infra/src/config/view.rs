//! Signed view envelopes and authority consumption — port of upstream
//! `internal/config/view.go` and `view_instrumentation.go`.
//!
//! A `central.view-signature/v1` envelope binds one canonical
//! configuration payload to one instance, one generation, one signing
//! key, and one timestamp. Ed25519 verification happens exactly once
//! and only after the keyring lookup and digest binding have already
//! narrowed the candidate key — the message is the canonical unsigned
//! envelope, a single `\x00` separator, then the raw config payload.

use std::cell::RefCell;
use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::FormatItem;
use time::macros::utc_datetime;
use time::{PrimitiveDateTime, UtcDateTime};

use central_foundation::identity::{ConfigBindingId, InstanceId};

use super::schema::{
    ProviderBudget, ProviderProfile, hex_encode, parse_validated_canonical, validate_fingerprint,
};
use super::strict_json::{
    CONFIG_DOCUMENT_LIMITS, VIEW_SIGNATURE_LIMITS, canonical_json, validate_strict_json,
};
use super::{Error, ErrorKind};

const VIEW_SIGNATURE_SCHEMA: &str = "central.view-signature/v1";
const VIEW_SIGNING_KEY_PREFIX: &str = "central.view-signing/v1:";
const SIGNED_AT_FORMAT: &[FormatItem<'static>] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
);
const SIGNATURE_BYTES: usize = ed25519_dalek::SIGNATURE_LENGTH;
const PUBLIC_KEY_BYTES: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Go `time.Time{}` — the never-valid sentinel `signedAt.IsZero()`
/// guards against.
const GO_ZERO_TIME: UtcDateTime = utc_datetime!(0001-01-01 00:00);

/// The compatibility-shaped runtime policy projection extracted from a
/// signed provider profile — upstream `RuntimeProviderPolicy`. Secret
/// references and purposes are omitted. `ProfileSignature` is a
/// non-secret canonical digest needed to bind durable B09 admission
/// evidence. Field names serialize PascalCase because the authority
/// side-channel marshals this struct for a Go-facing contract.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeProviderPolicy {
    #[serde(rename = "ProfileSignature")]
    pub profile_signature: String,
    #[serde(rename = "Provider")]
    pub provider: String,
    #[serde(rename = "Model")]
    pub model: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Method")]
    pub method: String,
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "PolicyRevision")]
    pub policy_revision: String,
    #[serde(rename = "ToolRevision")]
    pub tool_revision: String,
    #[serde(rename = "PriceDataRevision")]
    pub price_data_revision: String,
    #[serde(rename = "ProtectedPaths")]
    pub protected_paths: Vec<String>,
    #[serde(rename = "DefaultBudget")]
    pub default_budget: ProviderBudget,
    #[serde(rename = "HardBudget")]
    pub hard_budget: ProviderBudget,
    #[serde(rename = "InputTokenPriceMicros")]
    pub input_token_price_micros: u64,
    #[serde(rename = "OutputTokenPriceMicros")]
    pub output_token_price_micros: u64,
    #[serde(rename = "LocalGrantTTLSeconds")]
    pub local_grant_ttl_seconds: u64,
}

/// A parsed `central.view-signature/v1` envelope.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ViewSignature {
    pub schema_version: String,
    pub instance_id: String,
    pub config_binding_id: String,
    pub authoritative_config_digest: String,
    pub view_generation: u64,
    pub signing_key_id: String,
    pub signed_at: String,
    pub signature: String,
}

/// The unsigned envelope fields covered by the Ed25519 signature —
/// `unsignedViewSignature`. The `signature` field is excluded.
#[derive(Serialize)]
struct UnsignedViewSignature {
    schema_version: String,
    instance_id: String,
    config_binding_id: String,
    authoritative_config_digest: String,
    view_generation: u64,
    signing_key_id: String,
    signed_at: String,
}

/// The exact member set of one view-signature envelope — upstream's
/// `want` map in `parseViewSignature`.
const ENVELOPE_FIELDS: &[&str] = &[
    "schema_version",
    "instance_id",
    "config_binding_id",
    "authoritative_config_digest",
    "view_generation",
    "signing_key_id",
    "signed_at",
    "signature",
];

/// One trusted Ed25519 signing key, identified by its derived key ID.
/// `id` must equal [`derive_signing_key_id`] of `public` — the keyring
/// refuses a mismatch, same as upstream.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    pub id: String,
    pub public: [u8; PUBLIC_KEY_BYTES],
}

/// An immutable lookup of trusted signing keys by derived key ID.
#[derive(Debug, Clone, Default)]
pub struct VerificationKeyring {
    keys: HashMap<String, VerificationKey>,
}

impl VerificationKeyring {
    /// Upstream `NewVerificationKeyring`: rejects zero public keys, IDs
    /// that do not match the derived key ID, and duplicates.
    pub fn new(keys: Vec<VerificationKey>) -> Result<Self, Error> {
        let mut by_id = HashMap::with_capacity(keys.len());
        for key in &keys {
            if key.public == [0u8; PUBLIC_KEY_BYTES] {
                return Err(Error::redacted(ErrorKind::Keyring));
            }
            let derived = derive_signing_key_id(&key.public);
            if key.id != derived {
                return Err(Error::redacted(ErrorKind::Keyring));
            }
            if by_id.contains_key(&key.id) {
                return Err(Error::redacted(ErrorKind::Keyring));
            }
            by_id.insert(key.id.clone(), key.clone());
        }
        Ok(Self { keys: by_id })
    }

    /// Returns the key for `signing_key_id` without performing external
    /// work.
    #[must_use]
    pub fn lookup(&self, signing_key_id: &str) -> Option<VerificationKey> {
        self.keys.get(signing_key_id).cloned()
    }
}

/// `deriveSigningKeyID` — `"central.view-signing/v1:" + hex(sha256(key))`.
/// The prefix is prepended to the hex digest; it is not hashed in.
#[must_use]
pub fn derive_signing_key_id(public: &[u8; PUBLIC_KEY_BYTES]) -> String {
    let digest: [u8; 32] = Sha256::digest(public).into();
    format!("{VIEW_SIGNING_KEY_PREFIX}{}", hex_encode(&digest))
}

/// Selector metadata authenticated by a verified view — upstream
/// `VerifiedViewMetadata`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedViewMetadata {
    pub instance_id: InstanceId,
    pub config_binding_id: ConfigBindingId,
    pub generation: u64,
    pub signing_key_id: String,
    pub signed_at: UtcDateTime,
}

/// The immutable, minimum projection of a verified view. Exactly the
/// six upstream accessors exist — `Generation`, `SignedAt`,
/// `SelectorMetadata`, `RootIDs`, `ProviderPolicy`, and
/// `B09ProviderAuthority` — and every collection returned is a
/// defensive copy.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct VerifiedView {
    generation: u64,
    signing_key_id: String,
    signed_at: UtcDateTime,
    instance_id: InstanceId,
    binding_id: ConfigBindingId,
    config_digest: [u8; 32],
    root_ids: Vec<String>,
    provider_policy: RuntimeProviderPolicy,
    provider_profile: ProviderProfile,
}

impl VerifiedView {
    /// The authenticated view generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The authenticated signing time.
    #[must_use]
    pub fn signed_at(&self) -> UtcDateTime {
        self.signed_at
    }

    /// A value copy of authenticated selector metadata.
    #[must_use]
    pub fn selector_metadata(&self) -> VerifiedViewMetadata {
        VerifiedViewMetadata {
            instance_id: self.instance_id,
            config_binding_id: self.binding_id,
            generation: self.generation,
            signing_key_id: self.signing_key_id.clone(),
            signed_at: self.signed_at,
        }
    }

    /// A defensive copy of authenticated workspace root IDs.
    #[must_use]
    pub fn root_ids(&self) -> Vec<String> {
        self.root_ids.clone()
    }

    /// A defensive copy of the authenticated provider policy.
    #[must_use]
    pub fn provider_policy(&self) -> RuntimeProviderPolicy {
        self.provider_policy.clone()
    }

    /// Creates the narrow authority projection for provider planning
    /// from an authenticated, signed configuration view — upstream
    /// `VerifiedView.B09ProviderAuthority`.
    pub fn b09_provider_authority(&self) -> Result<B09ProviderAuthority, Error> {
        if self.generation == 0 || self.signed_at == GO_ZERO_TIME || self.root_ids.is_empty() {
            return Err(Error::redacted(ErrorKind::Semantic));
        }
        if self.provider_profile.validate_signed().is_err()
            || self.provider_profile.signature != self.provider_policy.profile_signature
        {
            return Err(Error::redacted(ErrorKind::Semantic));
        }
        for (i, root) in self.root_ids.iter().enumerate() {
            if root.is_empty() || (i > 0 && self.root_ids[i - 1] >= *root) {
                return Err(Error::redacted(ErrorKind::Semantic));
            }
        }
        Ok(B09ProviderAuthority {
            profile: self.provider_profile.clone(),
            root_ids: self.root_ids.clone(),
            generation: self.generation,
            signed_at: self.signed_at,
            config_digest: self.config_digest,
        })
    }
}

/// JSON projection of [`VerifiedView`] — deliberately opaque (`{}`), so
/// no authority field can escape through serialization.
impl Serialize for VerifiedView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        serializer.serialize_map(Some(0))?.end()
    }
}

/// The adapter-neutral authority used to plan a B09 provider turn —
/// upstream `B09ProviderAuthority`. It can only be obtained from a
/// [`VerifiedView`]; its private state prevents callers from assembling
/// a profile or root allowlist by hand. Returned slices and profiles
/// are defensive copies.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct B09ProviderAuthority {
    profile: ProviderProfile,
    root_ids: Vec<String>,
    generation: u64,
    signed_at: UtcDateTime,
    config_digest: [u8; 32],
}

impl B09ProviderAuthority {
    /// Verifies that this authority still contains complete signed
    /// provider provenance and a non-empty, canonical root allowlist.
    pub fn validate(&self) -> Result<(), Error> {
        if self.generation == 0
            || self.signed_at == GO_ZERO_TIME
            || self.config_digest == [0u8; 32]
            || self.root_ids.is_empty()
        {
            return Err(Error::redacted(ErrorKind::Semantic));
        }
        if self.profile.validate_signed().is_err() {
            return Err(Error::redacted(ErrorKind::Semantic));
        }
        for (i, root) in self.root_ids.iter().enumerate() {
            if root.is_empty() || (i > 0 && self.root_ids[i - 1] >= *root) {
                return Err(Error::redacted(ErrorKind::Semantic));
            }
        }
        Ok(())
    }

    /// The authenticated profile copy for the planner and broker
    /// boundary.
    #[must_use]
    pub fn provider_profile(&self) -> ProviderProfile {
        self.profile.clone()
    }

    /// The authenticated provider-profile digest, decoded from the
    /// signed profile carried by this authority. Callers cannot supply
    /// a replacement value.
    pub fn profile_signature(&self) -> Result<[u8; 32], Error> {
        self.validate()?;
        hex_decode_32(&self.profile.signature).ok_or_else(|| Error::redacted(ErrorKind::Semantic))
    }

    /// The only credential selector authenticated by the signed
    /// provider profile. Callers must not replace it with a persisted
    /// or caller-supplied reference.
    #[must_use]
    pub fn secret_ref(&self) -> &str {
        &self.profile.secret_ref
    }

    /// A defensive copy of the authenticated workspace root allowlist.
    #[must_use]
    pub fn root_ids(&self) -> Vec<String> {
        self.root_ids.clone()
    }

    /// Whether `root_id` is in the authenticated root allowlist.
    #[must_use]
    pub fn allows_root(&self, root_id: &str) -> bool {
        self.root_ids.iter().any(|allowed| allowed == root_id)
    }

    /// The authenticated view generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The authenticated view signing time.
    #[must_use]
    pub fn signed_at(&self) -> UtcDateTime {
        self.signed_at
    }

    /// The authenticated configuration digest.
    #[must_use]
    pub fn config_digest(&self) -> &[u8; 32] {
        &self.config_digest
    }
}

/// Verification stages, recorded for the order tests — upstream
/// `verificationEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerificationEvent {
    KeyLookup,
    ConfigDigest,
    MessageConstruction,
    Ed25519Verify,
}

thread_local! {
    static VERIFICATION_EVENTS: RefCell<Vec<VerificationEvent>> = const { RefCell::new(Vec::new()) };
}

fn observe_verification_event(event: VerificationEvent) {
    VERIFICATION_EVENTS.with(|events| events.borrow_mut().push(event));
}

/// Drains the thread-local verification-event record — the Rust port of
/// upstream's `verificationObserver` spy (which only tests install).
#[cfg(test)]
pub(crate) fn drain_verification_events() -> Vec<VerificationEvent> {
    VERIFICATION_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

/// Upstream `ParseViewSignature` — strictly parses one canonical
/// view-signature envelope, validating the signature encoding too.
pub fn parse_view_signature(raw: &[u8]) -> Result<ViewSignature, Error> {
    parse_view_signature_inner(raw, true)
}

fn parse_view_signature_inner(
    raw: &[u8],
    validate_signature: bool,
) -> Result<ViewSignature, Error> {
    validate_strict_json(raw, VIEW_SIGNATURE_LIMITS).map_err(Error::redacted)?;
    let fields: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| Error::redacted(ErrorKind::Envelope))?;
    let Some(object) = fields.as_object() else {
        return Err(Error::redacted(ErrorKind::Envelope));
    };
    if object.len() != ENVELOPE_FIELDS.len()
        || !ENVELOPE_FIELDS
            .iter()
            .all(|name| object.contains_key(*name))
    {
        return Err(Error::redacted(ErrorKind::Envelope));
    }
    canonical_json(raw).map_err(Error::redacted)?;

    let view: ViewSignature =
        serde_json::from_slice(raw).map_err(|_| Error::redacted(ErrorKind::Envelope))?;
    if view.schema_version != VIEW_SIGNATURE_SCHEMA || view.view_generation == 0 {
        return Err(Error::redacted(ErrorKind::Envelope));
    }
    match InstanceId::parse(&view.instance_id) {
        Ok(id) if id.to_string() == view.instance_id => {}
        _ => return Err(Error::redacted(ErrorKind::Envelope)),
    }
    if ConfigBindingId::parse(&view.config_binding_id).is_err() {
        return Err(Error::redacted(ErrorKind::Envelope));
    }
    if validate_fingerprint(&view.authoritative_config_digest).is_err() {
        return Err(Error::redacted(ErrorKind::Envelope));
    }
    if view.signing_key_id.is_empty() || view.signing_key_id.len() > 128 {
        return Err(Error::redacted(ErrorKind::Envelope));
    }
    parse_signed_at(&view.signed_at)?;
    if validate_signature {
        decode_raw_signature(&view.signature)?;
    }
    Ok(view)
}

/// Upstream `VerifyView` — the single Ed25519 verification boundary.
///
/// This is a pure static and cryptographic boundary. It validates the
/// typed configuration, envelope/config instance equality, digest, key
/// identity, and signature, but it does not consult an authoritative
/// [`super::schema::BindingCatalog`] or claim that opaque binding IDs
/// have been checked for external purpose/instance ownership. Callers
/// that need that authority step must explicitly call
/// [`super::schema::validate_with_binding_catalog`] later.
pub fn verify_view(
    config_raw: &[u8],
    signature_raw: &[u8],
    keyring: &VerificationKeyring,
) -> Result<VerifiedView, Error> {
    let view = parse_view_signature_inner(signature_raw, false)?;

    let unsigned = UnsignedViewSignature {
        schema_version: view.schema_version.clone(),
        instance_id: view.instance_id.clone(),
        config_binding_id: view.config_binding_id.clone(),
        authoritative_config_digest: view.authoritative_config_digest.clone(),
        view_generation: view.view_generation,
        signing_key_id: view.signing_key_id.clone(),
        signed_at: view.signed_at.clone(),
    };
    let unsigned_value =
        serde_json::to_value(&unsigned).map_err(|_| Error::redacted(ErrorKind::Envelope))?;
    let unsigned_envelope = central_foundation::jcs::canonicalize(&unsigned_value)
        .map_err(|_| Error::redacted(ErrorKind::Envelope))?;

    if config_raw.len() > CONFIG_DOCUMENT_LIMITS.max_bytes {
        return Err(Error::redacted(ErrorKind::Limit));
    }
    validate_strict_json(config_raw, CONFIG_DOCUMENT_LIMITS).map_err(Error::redacted)?;
    canonical_json(config_raw).map_err(Error::redacted)?;

    observe_verification_event(VerificationEvent::KeyLookup);
    let key = keyring
        .lookup(&view.signing_key_id)
        .ok_or_else(|| Error::redacted(ErrorKind::Keyring))?;
    if derive_signing_key_id(&key.public) != view.signing_key_id {
        return Err(Error::redacted(ErrorKind::Keyring));
    }

    observe_verification_event(VerificationEvent::ConfigDigest);
    let config_digest: [u8; 32] = Sha256::digest(config_raw).into();
    if hex_encode(&config_digest) != view.authoritative_config_digest {
        return Err(Error::redacted(ErrorKind::Digest));
    }

    let signature_bytes = decode_raw_signature(&view.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);

    observe_verification_event(VerificationEvent::MessageConstruction);
    let mut message = unsigned_envelope;
    message.push(0);
    message.extend_from_slice(config_raw);

    observe_verification_event(VerificationEvent::Ed25519Verify);
    let verifying_key =
        VerifyingKey::from_bytes(&key.public).map_err(|_| Error::redacted(ErrorKind::Signature))?;
    if verifying_key.verify(&message, &signature).is_err() {
        return Err(Error::redacted(ErrorKind::Signature));
    }

    let cfg = parse_validated_canonical(config_raw)?;
    if cfg.instance_id.to_string() != view.instance_id {
        return Err(Error::redacted(ErrorKind::Semantic));
    }
    let instance_id =
        InstanceId::parse(&view.instance_id).map_err(|_| Error::redacted(ErrorKind::Envelope))?;
    let binding_id = ConfigBindingId::parse(&view.config_binding_id)
        .map_err(|_| Error::redacted(ErrorKind::Envelope))?;
    let signed_at = parse_signed_at(&view.signed_at)?;

    let root_ids: Vec<String> = cfg
        .paths
        .workspace_roots
        .iter()
        .map(|root| root.root_id.clone())
        .collect();
    let provider_policy = RuntimeProviderPolicy {
        profile_signature: cfg.provider.signature.clone(),
        provider: cfg.provider.provider.clone(),
        model: cfg.provider.model.clone(),
        destination: cfg.provider.destination.clone(),
        method: cfg.provider.method.clone(),
        path: cfg.provider.path.clone(),
        policy_revision: cfg.provider.policy_revision.clone(),
        tool_revision: cfg.provider.tool_revision.clone(),
        price_data_revision: cfg.provider.price_data_revision.clone(),
        protected_paths: cfg.provider.protected_paths.clone(),
        default_budget: cfg.provider.default_budget,
        hard_budget: cfg.provider.hard_budget,
        input_token_price_micros: cfg.provider.input_token_price_micros,
        output_token_price_micros: cfg.provider.output_token_price_micros,
        local_grant_ttl_seconds: cfg.provider.local_grant_ttl_seconds,
    };

    Ok(VerifiedView {
        generation: view.view_generation,
        signing_key_id: view.signing_key_id.clone(),
        signed_at,
        instance_id,
        binding_id,
        config_digest,
        root_ids,
        provider_policy,
        provider_profile: cfg.provider,
    })
}

/// Upstream `parseSignedAt`: fixed 27-byte layout, every non-separator
/// position must be a digit, then parse plus a re-format canonicality
/// check.
fn parse_signed_at(value: &str) -> Result<UtcDateTime, Error> {
    const LAYOUT_LEN: usize = 27;
    const SEPARATORS: &[(usize, u8)] = &[
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (26, b'Z'),
    ];
    let bytes = value.as_bytes();
    if bytes.len() != LAYOUT_LEN {
        return Err(Error::redacted(ErrorKind::Timestamp));
    }
    for (i, &b) in bytes.iter().enumerate() {
        match SEPARATORS.iter().find(|(pos, _)| *pos == i) {
            Some((_, want)) => {
                if b != *want {
                    return Err(Error::redacted(ErrorKind::Timestamp));
                }
            }
            None => {
                if !b.is_ascii_digit() {
                    return Err(Error::redacted(ErrorKind::Timestamp));
                }
            }
        }
    }
    let naive = PrimitiveDateTime::parse(value, &SIGNED_AT_FORMAT)
        .map_err(|_| Error::redacted(ErrorKind::Timestamp))?;
    let parsed = naive.assume_utc();
    let formatted = parsed
        .format(&SIGNED_AT_FORMAT)
        .map_err(|_| Error::redacted(ErrorKind::Timestamp))?;
    if formatted != value {
        return Err(Error::redacted(ErrorKind::Timestamp));
    }
    Ok(parsed.into())
}

/// Upstream `decodeRawSignature`: base64 RawStdEncoding decode, exactly
/// 64 bytes, and the input must be the canonical encoding of itself.
fn decode_raw_signature(value: &str) -> Result<[u8; SIGNATURE_BYTES], Error> {
    let decoded =
        base64_raw_std_decode(value).ok_or_else(|| Error::redacted(ErrorKind::Envelope))?;
    let array: [u8; SIGNATURE_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| Error::redacted(ErrorKind::Envelope))?;
    if base64_raw_std_encode(&array) != value {
        return Err(Error::redacted(ErrorKind::Envelope));
    }
    Ok(array)
}

const BASE64_STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64.RawStdEncoding.EncodeToString (standard alphabet, no padding).
pub(crate) fn base64_raw_std_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let (b0, b1, b2) = (
            chunk[0] as u32,
            *chunk.get(1).unwrap_or(&0) as u32,
            *chunk.get(2).unwrap_or(&0) as u32,
        );
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64_STD_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(BASE64_STD_ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(BASE64_STD_ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64_STD_ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// base64.RawStdEncoding.DecodeString — standard alphabet, no padding,
/// trailing sextet padding bits must be zero (same canonical check
/// `RawStdEncoding` performs).
fn base64_raw_std_decode(value: &str) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in bytes {
        let v = decode_char(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 && acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// Lowercase hex decode into a fixed 32-byte digest — the
/// `ProfileSignature` decode path (upstream `hex.DecodeString` +
/// length check).
fn hex_decode_32(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    //! Ports of upstream `view_order_test.go` (instrumented ordering)
    //! and `view_authority_test.go` (B09 authority consumption).

    use super::*;
    use crate::config::testutil::{
        COMPLETE_CONFIG_FIXTURE, INSTRUMENTATION_ENVELOPE, SIGNED_NONCANONICAL_ENVELOPE,
        VIEW_VECTOR_KEY_ID, VIEW_VECTOR_PUBLIC, valid_config,
    };
    use crate::config::{ErrorKind, VerificationKey, VerificationKeyring};

    fn vector_keyring() -> VerificationKeyring {
        VerificationKeyring::new(vec![VerificationKey {
            id: VIEW_VECTOR_KEY_ID.to_owned(),
            public: VIEW_VECTOR_PUBLIC,
        }])
        .expect("keyring")
    }

    #[test]
    fn verify_view_rejects_bad_config_before_any_crypto_or_keyring_work() {
        let keys = vector_keyring();
        let cases: Vec<(&str, Vec<u8>, &str, ErrorKind)> = vec![
            (
                "oversized",
                [valid_config(), vec![b' '; CONFIG_DOCUMENT_LIMITS.max_bytes]].concat(),
                INSTRUMENTATION_ENVELOPE,
                ErrorKind::Limit,
            ),
            (
                "structurally invalid",
                b"not json".to_vec(),
                INSTRUMENTATION_ENVELOPE,
                ErrorKind::InvalidSyntax,
            ),
            (
                "non-JCS",
                [b" ".as_ref(), valid_config().as_slice()].concat(),
                INSTRUMENTATION_ENVELOPE,
                ErrorKind::Semantic,
            ),
            (
                "signed non-JCS",
                [b" ".as_ref(), valid_config().as_slice()].concat(),
                SIGNED_NONCANONICAL_ENVELOPE,
                ErrorKind::Semantic,
            ),
        ];
        for (name, raw, envelope, want) in cases {
            drain_verification_events();
            let result = verify_view(&raw, envelope.as_bytes(), &keys);
            assert!(result.is_err(), "{name}: VerifyView unexpectedly succeeded");
            assert_eq!(
                result.err().map(|e| e.kind()),
                Some(want),
                "{name}: VerifyView error kind"
            );
            assert!(
                drain_verification_events().is_empty(),
                "{name}: verification events for rejected config, want none"
            );
        }
    }

    #[test]
    fn verify_view_crypto_and_lookup_order_is_observable() {
        let keys = vector_keyring();
        drain_verification_events();
        let result = verify_view(
            COMPLETE_CONFIG_FIXTURE,
            INSTRUMENTATION_ENVELOPE.as_bytes(),
            &keys,
        );
        assert!(
            result.is_err(),
            "VerifyView unexpectedly accepted the intentionally unsigned envelope"
        );
        assert_eq!(
            drain_verification_events(),
            vec![
                VerificationEvent::KeyLookup,
                VerificationEvent::ConfigDigest,
                VerificationEvent::MessageConstruction,
                VerificationEvent::Ed25519Verify,
            ],
            "verification event order"
        );
    }

    #[test]
    fn b09_provider_authority_secret_ref_uses_authenticated_profile() {
        let authority = B09ProviderAuthority {
            profile: ProviderProfile {
                secret_ref: "openai_api_key".to_owned(),
                ..empty_profile()
            },
            root_ids: vec![],
            generation: 0,
            signed_at: GO_ZERO_TIME,
            config_digest: [0u8; 32],
        };
        assert_eq!(authority.secret_ref(), "openai_api_key");
    }

    #[test]
    fn b09_provider_authority_profile_signature_uses_authenticated_profile() {
        let budget = |n: u64, s: u64| ProviderBudget {
            request_bytes: n,
            response_bytes: n,
            input_tokens: n,
            output_tokens: n,
            tool_calls_per_step: n,
            tool_calls_per_run: n,
            wall_time_seconds: n,
            spend_micros: s,
        };
        let mut profile = ProviderProfile {
            provider: "openai-responses".to_owned(),
            model: "gpt-5.6".to_owned(),
            destination: "https://api.openai.com:443/v1/responses".to_owned(),
            method: "POST".to_owned(),
            path: "/v1/responses".to_owned(),
            policy_revision: "policy".to_owned(),
            tool_revision: "tool".to_owned(),
            price_data_revision: "price".to_owned(),
            secret_ref: "openai_api_key".to_owned(),
            purpose: "provider_api_key_v1".to_owned(),
            protected_paths: vec![],
            default_budget: budget(1, 2),
            hard_budget: budget(2, 4),
            input_token_price_micros: 1,
            output_token_price_micros: 1,
            local_grant_ttl_seconds: 1,
            signature: String::new(),
        };
        profile.signature = profile.canonical_digest();
        let authority = B09ProviderAuthority {
            profile: profile.clone(),
            root_ids: vec!["root".to_owned()],
            generation: 1,
            signed_at: UtcDateTime::UNIX_EPOCH,
            config_digest: Sha256::digest(b"config").into(),
        };
        let got = authority.profile_signature().expect("profile_signature");
        let want = hex_decode_32(&profile.signature).expect("decode want");
        assert_eq!(got, want);
    }

    fn empty_profile() -> ProviderProfile {
        ProviderProfile {
            provider: String::new(),
            model: String::new(),
            destination: String::new(),
            method: String::new(),
            path: String::new(),
            policy_revision: String::new(),
            tool_revision: String::new(),
            price_data_revision: String::new(),
            secret_ref: String::new(),
            purpose: String::new(),
            protected_paths: vec![],
            default_budget: ProviderBudget {
                request_bytes: 0,
                response_bytes: 0,
                input_tokens: 0,
                output_tokens: 0,
                tool_calls_per_step: 0,
                tool_calls_per_run: 0,
                wall_time_seconds: 0,
                spend_micros: 0,
            },
            hard_budget: ProviderBudget {
                request_bytes: 0,
                response_bytes: 0,
                input_tokens: 0,
                output_tokens: 0,
                tool_calls_per_step: 0,
                tool_calls_per_run: 0,
                wall_time_seconds: 0,
                spend_micros: 0,
            },
            input_token_price_micros: 0,
            output_token_price_micros: 0,
            local_grant_ttl_seconds: 0,
            signature: String::new(),
        }
    }
}
