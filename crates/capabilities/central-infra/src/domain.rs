//! The `central-infra` domain — port of upstream
//! `internal/infralifecycle` (B03 lifecycle state machine),
//! `internal/secretbootstrap` (B04/B05/B10 secret-binding domain and
//! the MinIO least-privilege policy contracts), and the
//! `internal/dependencyprepare` vocabulary the lifecycle and
//! dependency-store ports carry (B02).
//!
//! Everything here is pure synchronous Rust: no async, no I/O, no
//! adapter types. The MinIO policy functions render byte-exact IAM
//! documents and SHA-256 policy digests that the external provisioner
//! cross-checks — they are production contracts, not test scaffolding.
//!
//! Domain failures arrive as [`central_foundation::failure::Failure`]
//! carrying [`codes`] values; `Failure::message` is already redacted —
//! no secret, path, or credential material ever crosses this module.
//!
//! Upstream keeps these in three packages; the Rust port keeps them
//! together because `infralifecycle` and `secretbootstrap` already
//! share the authority boundary, and `central-infra` may not import
//! `central-authorization` under the approved dependency graph —
//! the required `dependencyprepare` value types are therefore modeled
//! here rather than imported.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use central_foundation::failure::Failure;
use central_foundation::identity::{
    DurableLeaseId, HandoffReceiptId, HandoffReservationId, LifecycleProofId, OperationId,
    ProtectedGenerationId, SecretBindingId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::authority::wire::{
    self, ct_eq, format_rfc3339_nano, hex_decode, hex_encode, hmac_sha256, is_go_zero_time,
};
use crate::authority::{CENTRAL_MIGRATE_GID, CENTRAL_MIGRATE_UID, CENTRAL_RUNTIME_UID};

// ---------------------------------------------------------------------------
// Failure codes — the stable machine vocabulary riding `Failure::code`.
// Where upstream fixes the wire token verbatim (the `B04_*` reason
// strings) the constant carries it exactly.
// ---------------------------------------------------------------------------

/// Machine codes carried by [`Failure::code`] across this domain.
/// `B04_*` values are upstream's closed reason strings — they ride the
/// wire verbatim and must not be renamed.
pub mod codes {
    /// `secretbootstrap.ErrUnknownPurpose`.
    pub const UNKNOWN_PURPOSE: &str = "UNKNOWN_PURPOSE";
    /// `secretbootstrap.ErrCrossServicePurpose`.
    pub const CROSS_SERVICE_PURPOSE: &str = "CROSS_SERVICE_PURPOSE";
    /// `secretbootstrap.ErrNotMaterializable`.
    pub const NOT_MATERIALIZABLE: &str = "NOT_MATERIALIZABLE";
    /// `secretbootstrap.ErrBindingDenied`.
    pub const BINDING_DENIED: &str = "BINDING_DENIED";
    /// `secretbootstrap.ErrReceiptConsumed`.
    pub const RECEIPT_CONSUMED: &str = "RECEIPT_CONSUMED";
    /// `secretbootstrap.ErrReceiptExpired`.
    pub const RECEIPT_EXPIRED: &str = "RECEIPT_EXPIRED";
    /// `secretbootstrap.ErrReceiptNotFound`.
    pub const RECEIPT_NOT_FOUND: &str = "RECEIPT_NOT_FOUND";
    /// `secretbootstrap.ErrFencingConflict`.
    pub const FENCING_CONFLICT: &str = "FENCING_CONFLICT";
    /// `secretbootstrap.ErrCutoverRequired` — wire-verbatim reason.
    pub const B04_CUTOVER_REPAIR_REQUIRED: &str = "B04_CUTOVER_REPAIR_REQUIRED";
    /// `secretbootstrap.ErrStateRepairRequired` — wire-verbatim reason.
    pub const B04_PROTECTED_STATE_REPAIR_REQUIRED: &str = "B04_PROTECTED_STATE_REPAIR_REQUIRED";
    /// `secretbootstrap.ReasonB04HandoffDenied` — wire-verbatim reason.
    pub const B04_HANDOFF_DENIED: &str = "B04_HANDOFF_DENIED";
    /// `secretbootstrap.ReasonB04HandoffCleanupRequired` — wire-verbatim.
    pub const B04_HANDOFF_CLEANUP_REQUIRED: &str = "B04_HANDOFF_CLEANUP_REQUIRED";
    /// `secretbootstrap.ReasonB04BindingRevoked` — wire-verbatim.
    pub const B04_BINDING_REVOKED: &str = "B04_BINDING_REVOKED";
    /// A `secretbootstrap.Binding`/request/handoff validation failure.
    pub const BOOTSTRAP_INVALID: &str = "BOOTSTRAP_INVALID";
    /// A `MigrationLaunchBinding` validation failure.
    pub const MIGRATION_LAUNCH_INVALID: &str = "MIGRATION_LAUNCH_INVALID";
    /// A MinIO policy bucket/scope rejection.
    pub const MINIO_POLICY_INVALID: &str = "MINIO_POLICY_INVALID";
    /// `infralifecycle` binding/evidence validation failure.
    pub const LIFECYCLE_INVALID: &str = "LIFECYCLE_INVALID";
    /// `dependencyprepare.ErrInvalidCandidate` and candidate-side rejects.
    pub const CANDIDATE_INVALID: &str = "CANDIDATE_INVALID";
    /// `dependencyprepare.ErrInvalidAdmissionBinding`.
    pub const ADMISSION_BINDING_INVALID: &str = "ADMISSION_BINDING_INVALID";
    /// `dependencyprepare.ErrInvalidOCIInventory`.
    pub const OCI_INVENTORY_INVALID: &str = "OCI_INVENTORY_INVALID";
    /// `dependencyprepare.ErrInvalidPhase`.
    pub const PREPARE_PHASE_INVALID: &str = "PREPARE_PHASE_INVALID";
    /// `dependencyprepare.ErrOCIMismatch`.
    pub const OCI_MISMATCH: &str = "OCI_MISMATCH";
    /// `dependencyprepare.ErrMissingServiceMode`.
    pub const MISSING_SERVICE_MODE: &str = "MISSING_SERVICE_MODE";
    /// `dependencyprepare.ErrInvalidServiceMode`.
    pub const INVALID_SERVICE_MODE: &str = "INVALID_SERVICE_MODE";
    /// `dependencyprepare.ErrAttestationInvalid`.
    pub const ATTESTATION_INVALID: &str = "ATTESTATION_INVALID";
    /// `dependencyprepare.ErrUnknownSelector`.
    pub const UNKNOWN_SELECTOR: &str = "UNKNOWN_SELECTOR";
    /// `dependencyprepare.ErrSharedBuilderRoots`.
    pub const SHARED_BUILDER_ROOTS: &str = "SHARED_BUILDER_ROOTS";
    /// `dependencyprepare.ErrInvalidBuildRequest`.
    pub const BUILD_REQUEST_INVALID: &str = "BUILD_REQUEST_INVALID";
    /// `dependencyprepare.ErrInvalidOperationID`.
    pub const OPERATION_ID_INVALID: &str = "OPERATION_ID_INVALID";
    /// `dependencyprepare.ErrImageUnresolvable`.
    pub const IMAGE_UNRESOLVABLE: &str = "IMAGE_UNRESOLVABLE";
}

// ===========================================================================
// B02 dependency-prepare vocabulary
// ===========================================================================

/// The coarse operator-facing phase of a dependency-prepare operation
/// (upstream `dependencyprepare.Phase`). The fine-grained journal
/// phases live at [`crate::authority::PrepareOperationPhase`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PreparePhase {
    /// `pending`.
    #[default]
    Pending,
    /// `acquiring`.
    Acquiring,
    /// `building`.
    Building,
    /// `staging`.
    Staging,
    /// `ready`.
    Ready,
    /// `failed`.
    Failed,
    /// `skipped`.
    Skipped,
}

/// Every [`PreparePhase`], in upstream declaration order.
pub const ALL_PREPARE_PHASES: [PreparePhase; 7] = [
    PreparePhase::Pending,
    PreparePhase::Acquiring,
    PreparePhase::Building,
    PreparePhase::Staging,
    PreparePhase::Ready,
    PreparePhase::Failed,
    PreparePhase::Skipped,
];

impl PreparePhase {
    /// The upstream phase string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Acquiring => "acquiring",
            Self::Building => "building",
            Self::Staging => "staging",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

impl fmt::Display for PreparePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PreparePhase {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for phase in ALL_PREPARE_PHASES {
            if phase.as_str() == s {
                return Ok(phase);
            }
        }
        Err(Failure::invalid(
            codes::PREPARE_PHASE_INVALID,
            "dependencyprepare: invalid phase",
        ))
    }
}

/// How one selector's image is obtained (upstream
/// `dependencyprepare.AcquisitionKind`). The design spec fixes both:
/// MinIO is built from the locked source archive by two independent
/// hermetic builders; PostgreSQL is admitted as the accepted published
/// `16.14-bookworm` OCI identity chain and is never built here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcquisitionKind {
    /// `built` — two independent hermetic builds compared for equality.
    Built,
    /// `published` — the accepted published OCI identity chain.
    Published,
}

impl AcquisitionKind {
    /// The upstream `AcquisitionKind` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Published => "published",
        }
    }
}

/// `AcquisitionKindFor` — how a selector is acquired. The selector set
/// is closed: the lock names exactly these two, and a selector nobody
/// has decided an acquisition path for is refused rather than
/// defaulted into the build path.
pub fn acquisition_kind_for(selector: &str) -> Result<AcquisitionKind, Failure> {
    match selector {
        "minio" => Ok(AcquisitionKind::Built),
        "postgresql" => Ok(AcquisitionKind::Published),
        _ => Err(Failure::invalid(
            codes::UNKNOWN_SELECTOR,
            "dependencyprepare: unknown selector",
        )),
    }
}

/// `ServiceModeForSelector` — maps a prepared selector to the B03
/// Compose mode whose OCI identity that selector's acquisition
/// establishes.
pub fn service_mode_for_selector(selector: &str) -> Result<ServiceMode, Failure> {
    match selector {
        "minio" => Ok(ServiceMode::Minio),
        "postgresql" => Ok(ServiceMode::Postgres),
        _ => Err(Failure::invalid(
            codes::UNKNOWN_SELECTOR,
            "dependencyprepare: unknown selector",
        )),
    }
}

/// One of the closed B03 Compose modes (upstream
/// `dependencyprepare.ServiceMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceMode {
    /// `postgres-fs-init` — one-shot PostgreSQL filesystem init.
    PostgresFsInit,
    /// `minio-fs-init` — one-shot MinIO filesystem init.
    MinioFsInit,
    /// `postgres` — the PostgreSQL daemon (upstream `PostgresDaemon`).
    #[serde(rename = "postgres")]
    Postgres,
    /// `minio` — the MinIO daemon (upstream `MinioDaemon`).
    #[serde(rename = "minio")]
    Minio,
    /// `postgres-provision` — the PostgreSQL provisioner (upstream
    /// `PostgresProv`; left the required set under ADR 0026).
    #[serde(rename = "postgres-provision")]
    PostgresProvision,
    /// `minio-provision` — the MinIO provisioner (upstream `MinioProv`).
    #[serde(rename = "minio-provision")]
    MinioProvision,
    /// `postgres-throughput-provision` — C02's on-demand
    /// admission-probe candidate (upstream `PostgresThroughputProv`):
    /// not part of B03's steady-state bring-up requirement, prepared
    /// and consumed only when C02's throughput gate runs.
    #[serde(rename = "postgres-throughput-provision")]
    PostgresThroughputProvision,
}

/// Every [`ServiceMode`] `isKnownServiceMode` accepts, in upstream
/// declaration order.
pub const ALL_SERVICE_MODES: [ServiceMode; 7] = [
    ServiceMode::PostgresFsInit,
    ServiceMode::MinioFsInit,
    ServiceMode::Postgres,
    ServiceMode::Minio,
    ServiceMode::PostgresProvision,
    ServiceMode::MinioProvision,
    ServiceMode::PostgresThroughputProvision,
];

/// The closed set of modes B03 requires before it can use a prepared
/// dependency receipt (upstream `ValidateB03`'s `required` slice).
/// `PostgresProvision` left this set under ADR 0026.
pub const B03_REQUIRED_SERVICE_MODES: [ServiceMode; 5] = [
    ServiceMode::PostgresFsInit,
    ServiceMode::MinioFsInit,
    ServiceMode::Postgres,
    ServiceMode::Minio,
    ServiceMode::MinioProvision,
];

impl ServiceMode {
    /// The upstream mode string — the Compose service name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostgresFsInit => "postgres-fs-init",
            Self::MinioFsInit => "minio-fs-init",
            Self::Postgres => "postgres",
            Self::Minio => "minio",
            Self::PostgresProvision => "postgres-provision",
            Self::MinioProvision => "minio-provision",
            Self::PostgresThroughputProvision => "postgres-throughput-provision",
        }
    }

    /// `isKnownServiceMode` — a recognized-identity check, not a
    /// per-set requirement. [`PreparedDependencySet::validate_b03`]'s
    /// own `required` list is what demands a mode's presence.
    #[must_use]
    pub const fn is_known(self) -> bool {
        // `ServiceMode` is a closed enum: every variant is known. The
        // method exists so the upstream check's name and intent stay
        // visible at the validation site rather than dissolving into
        // a tautology.
        true
    }
}

impl fmt::Display for ServiceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ServiceMode {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for mode in ALL_SERVICE_MODES {
            if mode.as_str() == s {
                return Ok(mode);
            }
        }
        Err(Failure::invalid(
            codes::INVALID_SERVICE_MODE,
            "dependencyprepare: invalid service mode",
        ))
    }
}

/// One OCI image layer (upstream `dependencyprepare.OCILayer`).
/// Upstream's fields carry no JSON tags — Go marshals them PascalCase
/// and decodes case-insensitively, so the renames keep the wire form
/// byte-faithful.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciLayer {
    /// Layer digest.
    #[serde(rename = "Digest")]
    pub digest: String,
    /// Layer media type.
    #[serde(rename = "MediaType")]
    pub media_type: String,
    /// Layer size in bytes.
    #[serde(rename = "Size")]
    pub size: i64,
    /// Layer annotations; a nil map arrives as `null`.
    #[serde(default, deserialize_with = "wire::null_to_default")]
    #[serde(rename = "Annotations")]
    pub annotations: BTreeMap<String, String>,
}

/// A complete canonical OCI layout identity (upstream
/// `dependencyprepare.OCIInventory`). The three digests are the
/// identity chain every comparison, attestation, and load check binds.
/// `layers` serializes as `[]` when empty; Go emits `null` for a nil
/// slice and the deserializer accepts both.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciInventory {
    /// OCI index digest.
    pub index_digest: String,
    /// Platform manifest digest.
    pub manifest_digest: String,
    /// Image config digest.
    pub config_digest: String,
    /// Ordered layer list.
    #[serde(default, deserialize_with = "wire::null_to_default")]
    pub layers: Vec<OciLayer>,
}

/// `NewOCIInventory` — refuses an inventory with an empty identity
/// chain.
pub fn new_oci_inventory(
    index_digest: String,
    manifest_digest: String,
    config_digest: String,
) -> Result<OciInventory, Failure> {
    if index_digest.is_empty() || manifest_digest.is_empty() || config_digest.is_empty() {
        return Err(Failure::invalid(
            codes::OCI_INVENTORY_INVALID,
            "dependencyprepare: invalid OCI inventory",
        ));
    }
    Ok(OciInventory {
        index_digest,
        manifest_digest,
        config_digest,
        layers: Vec::new(),
    })
}

/// `validCanonicalDigest` — admits only `sha256:` followed by 64
/// lowercase hex digits. It is interpolated into image references that
/// become subprocess arguments, so anything but a canonical digest is
/// refused here rather than at the process boundary.
pub fn valid_canonical_digest(digest: &str) -> Result<(), Failure> {
    let Some(hex_part) = digest.strip_prefix("sha256:") else {
        return Err(Failure::invalid(
            codes::OCI_INVENTORY_INVALID,
            "dependencyprepare: not a sha256 digest",
        ));
    };
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Failure::invalid(
            codes::OCI_INVENTORY_INVALID,
            "dependencyprepare: not a 64-character lowercase hex sha256 digest",
        ));
    }
    Ok(())
}

/// `digestFields` — hashes a length-prefixed encoding of its fields so
/// that no value can be shifted across a field boundary to forge a
/// matching digest. Returns `sha256:<hex>`.
pub fn digest_fields(domain: &str, fields: &[&str]) -> String {
    let mut text = String::with_capacity(domain.len() + 2 + fields.len() * 16);
    text.push_str(domain);
    text.push('\n');
    for field in fields {
        text.push_str(&format!("{}:{}\n", field.len(), field));
    }
    let digest = Sha256::digest(text.as_bytes());
    format!("sha256:{}", hex_encode(&digest))
}

/// `hexSum` — `sha256:<hex>` of `data`.
pub fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(data)))
}

/// `SelectorToken` — the token an [`AdmissionBinding`] must carry to
/// promote a candidate for `selector`. Deriving the token from the
/// selector is what stops an admission taken for one selector from
/// settling another.
pub fn selector_token(selector: &str) -> String {
    sha256_prefixed(selector.as_bytes())
}

/// `InventoryDigest` — the ordered identity of one OCI inventory: the
/// digest triple followed by every layer's digest, media type, size
/// and annotations in canonical order.
pub fn inventory_digest(inventory: &OciInventory) -> String {
    let mut fields: Vec<String> = vec![
        inventory.index_digest.clone(),
        inventory.manifest_digest.clone(),
        inventory.config_digest.clone(),
    ];
    for layer in &inventory.layers {
        fields.push(layer.digest.clone());
        fields.push(layer.media_type.clone());
        fields.push(layer.size.to_string());
        for (key, value) in &layer.annotations {
            fields.push(format!("{key}={value}"));
        }
    }
    let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
    digest_fields("central.oci-inventory/v1", &refs)
}

/// A B03 mode bound to its immutable OCI identity (upstream
/// `dependencyprepare.PreparedMode`). Upstream carries no JSON tags —
/// Go marshals PascalCase, so the renames keep the wire form
/// byte-faithful inside `dependency_set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedMode {
    /// The Compose service mode.
    #[serde(rename = "Mode")]
    pub mode: ServiceMode,
    /// Its proven OCI identity.
    #[serde(rename = "Inventory")]
    pub inventory: OciInventory,
}

/// The dependency set carried by a receipt (upstream
/// `dependencyprepare.PreparedDependencySet`, untagged → `Modes`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedDependencySet {
    /// One entry per prepared mode; a nil slice arrives as `null`.
    #[serde(default, deserialize_with = "wire::null_to_default")]
    #[serde(rename = "Modes")]
    pub modes: Vec<PreparedMode>,
}

impl PreparedDependencySet {
    /// `ValidateB03` — requires exactly one complete identity for each
    /// mode in [`B03_REQUIRED_SERVICE_MODES`]. Entries for any mode
    /// `is_known` rejects are refused outright; duplicates are refused;
    /// a mode whose OCI identity chain is incomplete is refused.
    pub fn validate_b03(&self) -> Result<(), Failure> {
        let mut seen = BTreeSet::new();
        for prepared in &self.modes {
            // `ServiceMode` is a closed enum, so `is_known` can only be
            // false for a deserialized impossibility; the check is kept
            // explicit to mirror upstream's two-part rule.
            if !prepared.mode.is_known() || !seen.insert(prepared.mode) {
                return Err(Failure::invalid(
                    codes::INVALID_SERVICE_MODE,
                    "dependencyprepare: invalid service mode",
                ));
            }
            if prepared.inventory.index_digest.is_empty()
                || prepared.inventory.manifest_digest.is_empty()
                || prepared.inventory.config_digest.is_empty()
            {
                return Err(Failure::invalid(
                    codes::INVALID_SERVICE_MODE,
                    "dependencyprepare: mode has incomplete OCI identity",
                ));
            }
        }
        for mode in B03_REQUIRED_SERVICE_MODES {
            if !seen.contains(&mode) {
                return Err(Failure::invalid(
                    codes::MISSING_SERVICE_MODE,
                    "dependencyprepare: missing required service mode",
                ));
            }
        }
        Ok(())
    }

    /// `Lookup` — the complete OCI identity prepared for `mode`,
    /// independent of `validate_b03`. C02's throughput gate uses this
    /// for `postgres-throughput-provision`, which `validate_b03`
    /// never requires and never rejects if present.
    pub fn lookup(&self, mode: ServiceMode) -> Result<&OciInventory, Failure> {
        for prepared in &self.modes {
            if prepared.mode != mode {
                continue;
            }
            if prepared.inventory.index_digest.is_empty()
                || prepared.inventory.manifest_digest.is_empty()
                || prepared.inventory.config_digest.is_empty()
            {
                return Err(Failure::invalid(
                    codes::INVALID_SERVICE_MODE,
                    "dependencyprepare: mode has incomplete OCI identity",
                ));
            }
            return Ok(&prepared.inventory);
        }
        Err(Failure::invalid(
            codes::MISSING_SERVICE_MODE,
            "dependencyprepare: missing required service mode",
        ))
    }
}

/// One of the three artifacts the design requires after (and only
/// after) an equal OCI result exists (upstream
/// `dependencyprepare.AttestationPredicate`). The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttestationPredicate {
    /// `sbom`.
    #[serde(rename = "sbom")]
    Sbom,
    /// `license-report`.
    #[serde(rename = "license-report")]
    LicenseReport,
    /// `slsa-provenance`.
    #[serde(rename = "slsa-provenance")]
    SlsaProvenance,
}

/// `RequiredAttestationPredicates` — the ordered, complete set that a
/// promotion requires. Missing any one of them blocks candidate
/// staging.
pub const REQUIRED_ATTESTATION_PREDICATES: [AttestationPredicate; 3] = [
    AttestationPredicate::Sbom,
    AttestationPredicate::LicenseReport,
    AttestationPredicate::SlsaProvenance,
];

/// `AttestationSchema` — the schema every dependency attestation
/// payload must declare. It is checked before any field of the
/// payload is trusted.
pub const ATTESTATION_SCHEMA: &str = "central.local-dependency-attestation/v1";

/// `AttestationPayloadType` — the only accepted DSSE payload type. It
/// is part of the issuer check, not decoration.
pub const ATTESTATION_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Schemas of the two durable settlement records (upstream
/// `PreparedManifestSchema`/`PreparedReceiptSchema`).
pub const PREPARED_MANIFEST_SCHEMA: &str = "central.prepared-dependencies/v1";
/// See [`PREPARED_MANIFEST_SCHEMA`].
pub const PREPARED_RECEIPT_SCHEMA: &str = "central.dependency-preparation-receipt/v1";

/// The repository name the MinIO server image built here is known by
/// in the host's local image store (ADR 0024 Decision 1, upstream
/// `BuiltImageRepository`).
pub const BUILT_IMAGE_REPOSITORY: &str = "central-minio";

/// The registry-qualified repository of the externally delivered
/// `central-local-infra` image, pulled by digest from GHCR (upstream
/// `InfraImageRepository`).
pub const INFRA_IMAGE_REPOSITORY: &str = "ghcr.io/enolalab/central-local-infra";

impl AttestationPredicate {
    /// The upstream predicate string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sbom => "sbom",
            Self::LicenseReport => "license-report",
            Self::SlsaProvenance => "slsa-provenance",
        }
    }
}

impl fmt::Display for AttestationPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AttestationPredicate {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for predicate in REQUIRED_ATTESTATION_PREDICATES {
            if predicate.as_str() == s {
                return Ok(predicate);
            }
        }
        Err(Failure::invalid(
            codes::ATTESTATION_INVALID,
            "dependencyprepare: invalid attestation",
        ))
    }
}

/// The verification evidence recorded in the prepared manifest: which
/// predicate was verified, under which schema, by which key, over
/// which envelope and subject (upstream
/// `dependencyprepare.AttestationFact`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFact {
    /// The verified predicate.
    pub predicate: AttestationPredicate,
    /// The schema the payload declared.
    pub schema: String,
    /// The verifying key identity.
    pub key_id: String,
    /// The envelope digest.
    pub envelope_digest: String,
    /// The bound subject digest.
    pub subject_digest: String,
}

impl AttestationFact {
    /// `Validate` — the fact must name a known predicate, declare the
    /// fixed schema, name a key, and carry both digests.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.schema != ATTESTATION_SCHEMA {
            return Err(Failure::invalid(
                codes::ATTESTATION_INVALID,
                "dependencyprepare: attestation fact schema mismatch",
            ));
        }
        if self.key_id.is_empty() {
            return Err(Failure::invalid(
                codes::ATTESTATION_INVALID,
                "dependencyprepare: attestation fact names no key",
            ));
        }
        if self.envelope_digest.is_empty() || self.subject_digest.is_empty() {
            return Err(Failure::invalid(
                codes::ATTESTATION_INVALID,
                "dependencyprepare: attestation fact carries no envelope or subject digest",
            ));
        }
        Ok(())
    }
}

/// `ValidateAttestationFacts` — requires exactly one verified fact
/// per required predicate, all bound to the same subject digest.
pub fn validate_attestation_facts(
    facts: &[AttestationFact],
    subject_digest: &str,
) -> Result<(), Failure> {
    if subject_digest.is_empty() {
        return Err(Failure::invalid(
            codes::ATTESTATION_INVALID,
            "dependencyprepare: no subject digest to bind attestation facts to",
        ));
    }
    let mut seen = BTreeSet::new();
    for fact in facts {
        fact.validate()?;
        if !seen.insert(fact.predicate) {
            return Err(Failure::invalid(
                codes::ATTESTATION_INVALID,
                "dependencyprepare: duplicate fact for predicate",
            ));
        }
        if fact.subject_digest != subject_digest {
            return Err(Failure::invalid(
                codes::ATTESTATION_INVALID,
                "dependencyprepare: attestation fact binds a different subject",
            ));
        }
    }
    for predicate in REQUIRED_ATTESTATION_PREDICATES {
        if !seen.contains(&predicate) {
            return Err(Failure::invalid(
                codes::ATTESTATION_INVALID,
                "dependencyprepare: missing attestation for predicate",
            ));
        }
    }
    Ok(())
}

/// The two-build equality proof recorded in a candidate manifest:
/// which comparator ran, over which ordered inventory, and whether
/// the layouts were equal (upstream `dependencyprepare.ComparisonFact`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonFact {
    /// The comparator identity.
    pub comparator: String,
    /// Whether the two layouts proved equal.
    pub equal: bool,
    /// The index digest both builds produced.
    pub index_digest: String,
    /// The ordered inventory digest compared.
    pub inventory_digest: String,
}

impl ComparisonFact {
    /// `Validate` — a fact is only evidence when the comparator is
    /// named, the comparison proved equality, and a layout identity
    /// is carried.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.comparator.is_empty() {
            return Err(Failure::invalid(
                codes::OCI_MISMATCH,
                "dependencyprepare: comparison names no comparator",
            ));
        }
        if !self.equal {
            return Err(Failure::invalid(
                codes::OCI_MISMATCH,
                "dependencyprepare: comparison did not prove equality",
            ));
        }
        if self.index_digest.is_empty() || self.inventory_digest.is_empty() {
            return Err(Failure::invalid(
                codes::OCI_MISMATCH,
                "dependencyprepare: comparison carries no layout identity",
            ));
        }
        Ok(())
    }
}

/// What produced a candidate: a local two-build prepare (`build`) or a
/// verified release import (`release`) — upstream
/// `dependencyprepare.ManifestSource`. `None`/empty reads as `build`:
/// manifests written before the field existed are builds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ManifestSource {
    /// `build` — a local two-build prepare.
    #[default]
    Build,
    /// `release` — a verified release import.
    Release,
}

/// One verified DSSE envelope persisted beside the manifest so a
/// later audit can re-verify contents, not just digests (upstream
/// `dependencyprepare.StoredEnvelope`; `envelope` is `[]byte` —
/// Base64 on the JSON wire, `null` for a nil slice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEnvelope {
    /// The carried predicate.
    pub predicate: AttestationPredicate,
    /// The verified envelope bytes.
    #[serde(with = "wire::b64_lenient")]
    pub envelope: Vec<u8>,
}

/// A staged dependency-prepare candidate (upstream
/// `dependencyprepare.Candidate`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidate {
    /// The staged candidate identity.
    pub id: String,
    /// The owning operation.
    pub operation_id: String,
    /// The prepared selector.
    pub selector: String,
    /// The candidate phase.
    pub phase: PreparePhase,
    /// Bytes of source the acquisition actually read — the only byte
    /// figure a progress event may carry.
    pub source_bytes: i64,
    /// The prepared dependency set frozen into the manifest.
    pub dependency_set: PreparedDependencySet,
    /// The two-build equality proof frozen into the manifest.
    pub comparison: ComparisonFact,
    /// The verified attestation facts frozen into the manifest.
    pub attestations: Vec<AttestationFact>,
    /// What produced the candidate.
    pub source: ManifestSource,
    /// The persisted DSSE envelopes (release candidates only).
    pub envelopes: Vec<StoredEnvelope>,
}

impl Candidate {
    /// `IsZero` — the unset candidate.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.id.is_empty() && self.selector.is_empty()
    }
}

/// `NewCandidate` — refuses a candidate with no selector.
pub fn new_candidate(selector: &str) -> Result<Candidate, Failure> {
    if selector.is_empty() {
        return Err(Failure::invalid(
            codes::CANDIDATE_INVALID,
            "dependencyprepare: invalid candidate",
        ));
    }
    Ok(Candidate {
        selector: selector.to_string(),
        phase: PreparePhase::Pending,
        ..Candidate::default()
    })
}

/// The dependency receipt a promoted candidate settles into (upstream
/// `dependencyprepare.Receipt`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyReceipt {
    /// The receipt identity (the candidate ID).
    pub id: String,
    /// The settled manifest digest.
    pub manifest_digest: String,
    /// The settling operation.
    pub operation_id: String,
    /// The active-selector generation.
    pub selector_generation: String,
    /// The dependency set the receipt promotes.
    pub dependency_set: PreparedDependencySet,
}

impl DependencyReceipt {
    /// `ValidateB03` — an active receipt must carry the complete B03
    /// dependency set.
    pub fn validate_b03(&self) -> Result<(), Failure> {
        self.dependency_set.validate_b03()
    }
}

/// `ReceiptForCandidate` — derives the receipt from a staged
/// candidate whose dependency set validates.
pub fn receipt_for_candidate(candidate: &Candidate) -> Result<DependencyReceipt, Failure> {
    if candidate.id.is_empty() || candidate.selector.is_empty() {
        return Err(Failure::invalid(
            codes::CANDIDATE_INVALID,
            "dependencyprepare: invalid candidate",
        ));
    }
    candidate.dependency_set.validate_b03().map_err(|_| {
        Failure::invalid(
            codes::CANDIDATE_INVALID,
            "dependencyprepare: invalid candidate",
        )
    })?;
    Ok(DependencyReceipt {
        id: candidate.id.clone(),
        dependency_set: candidate.dependency_set.clone(),
        ..DependencyReceipt::default()
    })
}

/// The token binding an admission receipt to the selector it may
/// promote (upstream `dependencyprepare.AdmissionBinding`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionBinding {
    /// The admission receipt being bound.
    pub admission_receipt_id: String,
    /// `selector_token(selector)` — required at promotion.
    pub selector_token: String,
}

impl AdmissionBinding {
    /// `IsZero` — the unset binding.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.admission_receipt_id.is_empty() && self.selector_token.is_empty()
    }
}

/// `NewAdmissionBinding` — refuses a binding with either field empty.
pub fn new_admission_binding(
    admission_receipt_id: &str,
    selector_token: &str,
) -> Result<AdmissionBinding, Failure> {
    if admission_receipt_id.is_empty() || selector_token.is_empty() {
        return Err(Failure::invalid(
            codes::ADMISSION_BINDING_INVALID,
            "dependencyprepare: invalid admission binding",
        ));
    }
    Ok(AdmissionBinding {
        admission_receipt_id: admission_receipt_id.to_string(),
        selector_token: selector_token.to_string(),
    })
}

/// `ValidOperationID` — admits only an identifier that is a single
/// safe path component. An operation ID arrives from the operator
/// (`--resume=<id>`), crosses the helper socket, and is then joined
/// into the root-owned journal directory to name a file the state
/// machine trusts as an authoritative record — so `../attacker`
/// would have made any `*.json` on the host a forgeable record.
pub fn valid_operation_id(id: &str) -> Result<(), Failure> {
    if id.is_empty() {
        return Err(Failure::invalid(
            codes::OPERATION_ID_INVALID,
            "dependencyprepare: operation ID must not be empty",
        ));
    }
    if id == "." || id == ".." || id.contains('/') || id.contains('\0') {
        return Err(Failure::invalid(
            codes::OPERATION_ID_INVALID,
            "dependencyprepare: operation ID is not a single safe path component",
        ));
    }
    Ok(())
}

/// `ValidateIndependentBuilds` — refuses two build requests that
/// share any root. The design spec requires the two builders not to
/// share a root, cache, output, or daemon-default builder; without
/// it the comparison step proves nothing, because two builds under
/// one state root would agree even for a nondeterministic build.
pub fn validate_independent_builds(
    one_roots: (&str, &str),
    two_roots: (&str, &str),
) -> Result<(), Failure> {
    let roots = [one_roots.0, one_roots.1, two_roots.0, two_roots.1];
    if roots.iter().any(|r| r.is_empty()) {
        return Err(Failure::invalid(
            codes::BUILD_REQUEST_INVALID,
            "dependencyprepare: every build needs both roots",
        ));
    }
    for (i, a) in roots.iter().enumerate() {
        for b in roots.iter().skip(i + 1) {
            if a == b {
                return Err(Failure::invalid(
                    codes::SHARED_BUILDER_ROOTS,
                    "dependencyprepare: builds share a root",
                ));
            }
        }
    }
    Ok(())
}

// ===========================================================================
// B03 infrastructure lifecycle (upstream internal/infralifecycle)
// ===========================================================================

/// The current state of a lifecycle operation (upstream
/// `infralifecycle.Phase`) — the journaled state machine every
/// `up`/`down` transition is recorded through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    /// `started`.
    Started,
    /// `verified` — admission verified, bootstrap ensured.
    Verified,
    /// `fs_initialized`.
    FsInitialized,
    /// `daemons_started`.
    DaemonsStarted,
    /// `containers_healthy`.
    ContainersHealthy,
    /// `postgres_provisioned`.
    PostgresProvisioned,
    /// `minio_provisioned`.
    MinioProvisioned,
    /// `semantic_verified`.
    SemanticVerified,
    /// `receipt_prepared`.
    ReceiptPrepared,
    /// `receipt_selector_switched`.
    ReceiptSelectorSwitched,
    /// `completed` — terminal.
    Completed,
    /// `failed` — terminal.
    Failed,
    /// `cancelled` — terminal.
    Cancelled,
}

/// Every [`LifecyclePhase`], in upstream declaration order.
pub const ALL_LIFECYCLE_PHASES: [LifecyclePhase; 13] = [
    LifecyclePhase::Started,
    LifecyclePhase::Verified,
    LifecyclePhase::FsInitialized,
    LifecyclePhase::DaemonsStarted,
    LifecyclePhase::ContainersHealthy,
    LifecyclePhase::PostgresProvisioned,
    LifecyclePhase::MinioProvisioned,
    LifecyclePhase::SemanticVerified,
    LifecyclePhase::ReceiptPrepared,
    LifecyclePhase::ReceiptSelectorSwitched,
    LifecyclePhase::Completed,
    LifecyclePhase::Failed,
    LifecyclePhase::Cancelled,
];

impl LifecyclePhase {
    /// `IsTerminal` — a final state from which the operation cannot
    /// transition further.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// The upstream phase string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Verified => "verified",
            Self::FsInitialized => "fs_initialized",
            Self::DaemonsStarted => "daemons_started",
            Self::ContainersHealthy => "containers_healthy",
            Self::PostgresProvisioned => "postgres_provisioned",
            Self::MinioProvisioned => "minio_provisioned",
            Self::SemanticVerified => "semantic_verified",
            Self::ReceiptPrepared => "receipt_prepared",
            Self::ReceiptSelectorSwitched => "receipt_selector_switched",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for LifecyclePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LifecyclePhase {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for phase in ALL_LIFECYCLE_PHASES {
            if phase.as_str() == s {
                return Ok(phase);
            }
        }
        Err(Failure::invalid(
            codes::LIFECYCLE_INVALID,
            "infralifecycle: invalid phase",
        ))
    }
}

/// Binds a bootstrap handoff to the lifecycle operation that
/// currently owns the B03 lock (upstream
/// `infralifecycle.B04LifecycleEvidence`). Its values are opaque
/// broker-verifiable tokens; they never contain paths or secret
/// material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct B04LifecycleEvidence {
    /// The bound instance.
    pub instance_id: String,
    /// The owning lifecycle operation.
    pub operation_id: String,
    /// The lifecycle lock fencing token.
    pub fencing_token: u64,
    /// Proof the topology was stopped.
    pub stopped_topology_proof: String,
    /// Proof the mount was released.
    pub mount_release_proof: String,
    /// The binding evidence.
    pub binding_evidence: String,
    /// Evidence expiry.
    pub expires_at: Option<OffsetDateTime>,
}

impl B04LifecycleEvidence {
    /// `Validate` — every B04 authority proof must be present before
    /// a production bootstrap handoff can be attempted.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.instance_id.is_empty()
            || self.operation_id.is_empty()
            || self.fencing_token == 0
            || self.stopped_topology_proof.is_empty()
            || self.mount_release_proof.is_empty()
            || self.binding_evidence.is_empty()
            || self.expires_at.is_none()
        {
            return Err(Failure::invalid(
                codes::LIFECYCLE_INVALID,
                "infralifecycle: incomplete B04 lifecycle evidence",
            ));
        }
        Ok(())
    }
}

/// The durable binding for an infrastructure lifecycle (upstream
/// `infralifecycle.Binding`). It carries the instance identity,
/// config binding, and receipt identifiers needed to correlate a
/// lifecycle operation across runs. It must NOT include the runtime
/// boot observation (`BootID`), which is carried separately in
/// [`Observation`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleBinding {
    /// The bound instance.
    pub instance_id: String,
    /// The `central.config/v1` binding.
    pub config_binding: String,
    /// The admission receipt.
    pub admission_id: String,
    /// The promoted dependency receipt.
    pub receipt_id: String,
    /// The compose model digest.
    pub model_digest: String,
    /// The payload epoch.
    pub payload_epoch: String,
    /// Bootstrap artifact fingerprints.
    pub bootstrap_fingerprints: Vec<String>,
    /// B04 authority evidence for the bootstrap handoff.
    pub b04: B04LifecycleEvidence,
}

impl LifecycleBinding {
    /// `Validate` — required binding fields must be present.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.instance_id.is_empty() {
            return Err(Failure::invalid(
                codes::LIFECYCLE_INVALID,
                "infralifecycle: binding missing instance id",
            ));
        }
        if self.config_binding.is_empty() {
            return Err(Failure::invalid(
                codes::LIFECYCLE_INVALID,
                "infralifecycle: binding missing config binding",
            ));
        }
        if self.receipt_id.is_empty() {
            return Err(Failure::invalid(
                codes::LIFECYCLE_INVALID,
                "infralifecycle: binding missing receipt id",
            ));
        }
        if self.payload_epoch.is_empty() {
            return Err(Failure::invalid(
                codes::LIFECYCLE_INVALID,
                "infralifecycle: binding missing payload epoch",
            ));
        }
        Ok(())
    }
}

/// Runtime information observed during a lifecycle operation, such as
/// the boot identifier and started container IDs (upstream
/// `infralifecycle.Observation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// The host boot identifier — observed, never binding-persisted.
    pub boot_id: String,
    /// Started container IDs by service mode.
    pub container_start_ids: BTreeMap<ServiceMode, String>,
}

/// A durable lifecycle operation record created by
/// [`crate::port::LifecyclePort::begin`] and carried through all
/// subsequent lifecycle transitions (upstream
/// `infralifecycle.Operation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleOperation {
    /// The operation identity.
    pub id: String,
    /// Identifies the unsettled `up` operation that a `down`
    /// operation is settling; empty for ordinary operations.
    pub linked_operation_id: String,
    /// The current journaled phase.
    pub phase: LifecyclePhase,
    /// The binding the operation is for.
    pub binding: LifecycleBinding,
    /// The latest runtime observation.
    pub observation: Observation,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
}

/// The caller-supplied parameters for starting a new lifecycle `up`
/// or `down` operation (upstream `infralifecycle.Request`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleRequest {
    /// The bound instance.
    pub instance_id: String,
    /// The `central.config/v1` binding.
    pub config_binding: String,
    /// The admission receipt.
    pub admission_id: String,
    /// The promoted dependency receipt.
    pub receipt_id: String,
    /// The compose model digest.
    pub model_digest: String,
    /// The payload epoch.
    pub payload_epoch: String,
    /// Bootstrap artifact fingerprints.
    pub bootstrap_fingerprints: Vec<String>,
}

/// The caller-supplied parameters for reading the current lifecycle
/// status of an instance binding (upstream
/// `infralifecycle.StatusRequest`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleStatusRequest {
    /// The bound instance.
    pub instance_id: String,
    /// The `central.config/v1` binding.
    pub config_binding: String,
}

/// The outcome of a lifecycle operation, carrying the final phase
/// and any error information (upstream `infralifecycle.Result`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleResult {
    /// The operation identity.
    pub operation_id: String,
    /// The settled receipt.
    pub receipt_id: String,
    /// The instance fingerprint.
    pub instance_fingerprint: String,
    /// The final phase.
    pub phase: LifecyclePhase,
    /// The operator-facing state.
    pub state: String,
    /// The machine reason.
    pub reason: String,
    /// The safe next action.
    pub safe_next_action: String,
    /// The process exit code the CLI should surface.
    pub exit_code: i32,
    /// The compose model digest.
    pub model_digest: String,
}

/// A receipt whose content has been semantically verified against
/// the expected topology state (upstream
/// `infralifecycle.SemanticReceipt`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticReceipt {
    /// The verified receipt.
    pub receipt_id: String,
    /// Its digest.
    pub digest: String,
    /// Whether semantic verification passed.
    pub verified: bool,
}

/// A point-in-time view of the infrastructure topology (upstream
/// `infralifecycle.Snapshot`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologySnapshot {
    /// The binding inspected.
    pub binding: LifecycleBinding,
    /// Container state by service mode.
    pub services: BTreeMap<ServiceMode, String>,
    /// Whether every service is healthy.
    pub healthy: bool,
    /// Operator-safe description.
    pub description: String,
}

// ===========================================================================
// B04/B05/B10 secret bootstrap (upstream internal/secretbootstrap)
// ===========================================================================

/// The closed twelve-purpose registry (upstream
/// `secretbootstrap.Purpose`). Every secret-binding purpose in the
/// system is named here; an unregistered purpose cannot be bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Purpose {
    /// `postgres_server_admin_v1`.
    PostgresServerAdmin,
    /// `postgres_runtime_v1`.
    PostgresRuntime,
    /// `postgres_outbox_v1`.
    PostgresOutbox,
    /// `postgres_migration_v1` — delivered only to the verified
    /// `central-migrate` descriptor peer.
    PostgresMigration,
    /// `minio_root_v1` — the canonical B04 alias [`MINIO_ROOT`].
    MinioRoot,
    /// `minio_runtime_v1` — the Artifact runtime principal.
    MinioRuntime,
    /// `minio_backup_v1`.
    MinioBackup,
    /// `minio_restore_v1` — ADR 0017 read-only.
    MinioRestore,
    /// `minio_import_v1` — ADR 0034, the one recovery credential that
    /// writes.
    MinioImport,
    /// `application_tls_v1`.
    ApplicationTls,
    /// `bootstrap_v1`.
    Bootstrap,
    /// `workspace_database_v1`.
    WorkspaceDatabase,
}

/// Every registered [`Purpose`] (`AllPurposes`), in upstream order.
pub const ALL_PURPOSES: [Purpose; 12] = [
    Purpose::PostgresServerAdmin,
    Purpose::PostgresRuntime,
    Purpose::PostgresOutbox,
    Purpose::PostgresMigration,
    Purpose::MinioRoot,
    Purpose::MinioRuntime,
    Purpose::MinioBackup,
    Purpose::MinioRestore,
    Purpose::MinioImport,
    Purpose::ApplicationTls,
    Purpose::Bootstrap,
    Purpose::WorkspaceDatabase,
];

/// `MinioRoot` — the canonical B04 alias for [`Purpose::MinioRoot`].
pub const MINIO_ROOT: Purpose = Purpose::MinioRoot;

/// `MaxSecretBytes` — the upper bound on a protected generation's
/// secret material.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// The only peer permitted to receive a B10 `minio_runtime_v1`
/// descriptor in the provisioner role: the `minio-provision`
/// provisioner, which the B03 compose policy pins to `1000:1000`
/// (upstream `MinioProvisionerUID`).
pub const MINIO_PROVISIONER_UID: u32 = 1000;
/// See [`MINIO_PROVISIONER_UID`].
pub const MINIO_PROVISIONER_GID: u32 = 1000;

/// `MinioRuntimeStagingPrefix` — the staging key prefix a
/// `minio_runtime_v1` principal streams bodies into, reads back to
/// verify, and cleans up under. One of the credential's two key roles.
pub const MINIO_RUNTIME_STAGING_PREFIX: &str = "v1/staging/";

/// `MinioRuntimeReadyPrefix` — the ready-object key prefix. The
/// runtime principal may create ready objects — promotion is a
/// client-side create-only PUT, never a server-side copy — but may
/// never delete one.
pub const MINIO_RUNTIME_READY_PREFIX: &str = "v1/ready/";

/// `MinioBackupThroughputFixtureKey` — the one reserved `v1/system`
/// object the backup identity may read for C02's bounded throughput
/// measurement.
pub const MINIO_BACKUP_THROUGHPUT_FIXTURE_KEY: &str = "v1/system/backup-throughput-fixture-v1";

/// `MinioBackupKeyScope` — the backup credential's closed scope:
/// the ready prefix plus the throughput fixture key.
pub const MINIO_BACKUP_KEY_SCOPE: &str = "v1/ready/ v1/system/backup-throughput-fixture-v1";

/// `MinioRestoreKeyScope` — the ready prefix alone.
pub const MINIO_RESTORE_KEY_SCOPE: &str = "v1/ready/";

/// `MinioImportKeyScope` — the ready prefix alone.
pub const MINIO_IMPORT_KEY_SCOPE: &str = "v1/ready/";

impl Purpose {
    /// The upstream purpose string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostgresServerAdmin => "postgres_server_admin_v1",
            Self::PostgresRuntime => "postgres_runtime_v1",
            Self::PostgresOutbox => "postgres_outbox_v1",
            Self::PostgresMigration => "postgres_migration_v1",
            Self::MinioRoot => "minio_root_v1",
            Self::MinioRuntime => "minio_runtime_v1",
            Self::MinioBackup => "minio_backup_v1",
            Self::MinioRestore => "minio_restore_v1",
            Self::MinioImport => "minio_import_v1",
            Self::ApplicationTls => "application_tls_v1",
            Self::Bootstrap => "bootstrap_v1",
            Self::WorkspaceDatabase => "workspace_database_v1",
        }
    }

    /// `Materializable` — true only for purposes the broker may
    /// materialize a credential for: `minio_root_v1` and the three
    /// ADR 0019 §4 rotate-then-sync service roles
    /// (`postgres_migration_v1`, `postgres_runtime_v1`,
    /// `postgres_outbox_v1`) whose live PostgreSQL password the root
    /// helper syncs via `BindMaterializedSecret` after each rotation.
    #[must_use]
    pub const fn materializable(self) -> bool {
        matches!(
            self,
            Self::MinioRoot
                | Self::PostgresMigration
                | Self::PostgresRuntime
                | Self::PostgresOutbox
        )
    }

    /// `ValidateDependency` — the closed service/target/identity
    /// binding for the four descriptor-deliverable purposes. Every
    /// other purpose has no dependency binding and is refused.
    ///
    /// `minio_runtime_v1` (ADR 0013 / SB-G3 Task 11a): the OUTBOUND
    /// (broker → runtime) direction accepts either the
    /// `minio-provision` identity that originally delivered the
    /// credential, or Central's own runtime identity
    /// ([`CENTRAL_RUNTIME_UID`]) — the same constant the broker
    /// server's `isMinioRuntimeOutboundPeer` compares against. The
    /// runtime branch checks UID only, exactly mirroring the
    /// UID-only gate: checking GID here too would leave this gate
    /// stricter than the transport's, and ADR 0013 requires the two
    /// independent gates to accept exactly the same peer set.
    /// Service and target stay fixed either way: they describe the
    /// credential's origin and delivery mechanism, not the requester.
    pub fn validate_dependency(
        self,
        service: &str,
        target: &str,
        uid: u32,
        gid: u32,
    ) -> Result<(), Failure> {
        match self {
            Self::MinioRoot => {
                if service != "minio"
                    || target != "/run/secrets/minio-root-password"
                    || uid != 1000
                    || gid != 1000
                {
                    return Err(Failure::denied(
                        codes::CROSS_SERVICE_PURPOSE,
                        "secretbootstrap: minio_root_v1 requires minio /run/secrets/minio-root-password 1000:1000",
                    ));
                }
                Ok(())
            }
            Self::PostgresMigration => {
                if service != "central-migrate"
                    || target != "scm_rights"
                    || uid != CENTRAL_MIGRATE_UID
                    || gid != CENTRAL_MIGRATE_GID
                {
                    return Err(Failure::denied(
                        codes::CROSS_SERVICE_PURPOSE,
                        "secretbootstrap: postgres_migration_v1 requires the verified central-migrate descriptor peer",
                    ));
                }
                Ok(())
            }
            Self::MinioRuntime => {
                if service != "minio-provision" || target != "sealed_memfd" {
                    return Err(Failure::denied(
                        codes::CROSS_SERVICE_PURPOSE,
                        "secretbootstrap: minio_runtime_v1 requires the registered minio-provision descriptor peer",
                    ));
                }
                let is_provisioner = uid == MINIO_PROVISIONER_UID && gid == MINIO_PROVISIONER_GID;
                let is_runtime = uid == CENTRAL_RUNTIME_UID;
                if !is_provisioner && !is_runtime {
                    return Err(Failure::denied(
                        codes::CROSS_SERVICE_PURPOSE,
                        "secretbootstrap: minio_runtime_v1 requires the registered minio-provision descriptor peer or Central's own runtime identity",
                    ));
                }
                Ok(())
            }
            _ => Err(Failure::denied(
                codes::CROSS_SERVICE_PURPOSE,
                "secretbootstrap: purpose has no dependency binding",
            )),
        }
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Purpose {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for purpose in ALL_PURPOSES {
            if purpose.as_str() == s {
                return Ok(purpose);
            }
        }
        Err(Failure::invalid(
            codes::UNKNOWN_PURPOSE,
            "secretbootstrap: unknown purpose",
        ))
    }
}

impl Serialize for Purpose {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Purpose {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// `MinioRuntimeKeyPrefixes` — the closed pair of key roles a
/// `minio_runtime_v1` principal is scoped to, in canonical order.
///
/// It exists so that there is exactly one statement of that scope.
/// The IAM policy below, the descriptor request's declared scope, and
/// the broker's minting gate all read it, so the authority that is
/// *granted* and the authority that is *declared* cannot drift apart.
/// Both roles are required: promotion is a client-side create-only
/// PUT and verification reads the ready body back, so a staging-only
/// principal cannot complete the Artifact lifecycle.
pub const MINIO_RUNTIME_KEY_PREFIXES: [&str; 2] =
    [MINIO_RUNTIME_STAGING_PREFIX, MINIO_RUNTIME_READY_PREFIX];

/// `MinioRuntimeKeyScope` — that pair rendered as the single canonical
/// scope string a descriptor request declares and a durable runtime
/// binding records.
pub const MINIO_RUNTIME_KEY_SCOPE: &str = "v1/staging/ v1/ready/";

/// The closed B10 broker protocol request for the Artifact runtime
/// principal (upstream `secretbootstrap.MinioRuntimeUseRequest`).
/// Every field participates in authorization and it carries no
/// plaintext credential: the credential itself is delivered
/// out-of-band as one sealed descriptor.
///
/// The request is scoped to exactly one instance bucket and one
/// provisioning operation receipt, so a descriptor minted for one
/// operation can never be replayed against another bucket, prefix,
/// or receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinioRuntimeUseRequest {
    /// The owning instance.
    pub instance_id: String,
    /// The provisioning operation.
    pub operation_id: String,
    /// The provisioning receipt.
    pub receipt_id: String,
    /// The opaque generation.
    pub opaque_generation: String,
    /// The scoped bucket.
    pub bucket: String,
    /// The declared key scope — must equal
    /// [`MINIO_RUNTIME_KEY_SCOPE`].
    pub key_prefix: String,
    /// The service (`minio-provision`).
    pub service: String,
    /// The target (`sealed_memfd`).
    pub target: String,
    /// Peer UID.
    pub uid: u32,
    /// Peer GID.
    pub gid: u32,
    /// Must be [`Purpose::MinioRuntime`].
    pub purpose: Purpose,
    /// Lifecycle fencing token — nonzero.
    pub fencing_token: u64,
    /// Request deadline — must be set and unexpired.
    pub deadline: OffsetDateTime,
}

impl MinioRuntimeUseRequest {
    /// `Validate` — rejects every altered or incomplete B10 runtime
    /// binding before a `minio_runtime_v1` descriptor can be minted.
    /// `now` is injected so the deadline check is deterministic.
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), Failure> {
        for value in [
            &self.instance_id,
            &self.operation_id,
            &self.receipt_id,
            &self.opaque_generation,
            &self.bucket,
        ] {
            if value.is_empty() {
                return Err(Failure::invalid(
                    codes::BOOTSTRAP_INVALID,
                    "secretbootstrap: minio runtime request has missing identity",
                ));
            }
        }
        // The declared scope must be exactly the credential's two key
        // roles — the same pair the runtime policy grants. A
        // whole-bucket scope, a single role on its own, or any other
        // prefix is never a legal runtime descriptor scope.
        if self.purpose != Purpose::MinioRuntime || self.key_prefix != MINIO_RUNTIME_KEY_SCOPE {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: invalid minio runtime binding",
            ));
        }
        if self.fencing_token == 0 || is_go_zero_time(self.deadline) || now >= self.deadline {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: invalid minio runtime binding",
            ));
        }
        self.purpose
            .validate_dependency(&self.service, &self.target, self.uid, self.gid)
    }
}

/// Reports only opaque principal and policy fingerprints (upstream
/// `secretbootstrap.MinioRuntimeUseResult`). It never carries the
/// runtime access key, secret, or the rendered policy document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinioRuntimeUseResult {
    /// Echoed operation identity.
    pub operation_id: String,
    /// The consumed receipt.
    pub receipt_id: String,
    /// Opaque principal fingerprint.
    pub principal_fingerprint: String,
    /// Opaque policy fingerprint.
    pub policy_fingerprint: String,
}

// ---------------------------------------------------------------------------
// MinIO IAM policy documents — byte-exact cross-repo contracts
// ---------------------------------------------------------------------------

const POLICY_VERSION: &str = "2012-10-17";
const ACTION_GET_OBJECT: &str = "s3:GetObject";
const ACTION_PUT_OBJECT: &str = "s3:PutObject";
const ACTION_DELETE_OBJECT: &str = "s3:DeleteObject";

#[derive(Serialize)]
#[serde(rename = "Statement")]
struct MinioPolicyStatement {
    #[serde(rename = "Effect")]
    effect: &'static str,
    #[serde(rename = "Action")]
    action: Vec<&'static str>,
    #[serde(rename = "Resource")]
    resource: Vec<String>,
}

#[derive(Serialize)]
struct MinioPolicyDocument {
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "Statement")]
    statement: Vec<MinioPolicyStatement>,
}

/// The bucket-name guard shared by both policy renderers: refuses an
/// empty-or-whitespace bucket and any bucket containing `/`, `*`,
/// `"`, or `\` — the characters that would break the ARN scope or
/// widen the grant.
fn validate_minio_bucket(bucket: &str, what: &str) -> Result<(), Failure> {
    if bucket.trim().is_empty() || bucket.contains(['/', '*', '"', '\\']) {
        return Err(Failure::invalid(
            codes::MINIO_POLICY_INVALID,
            match what {
                "runtime" => "secretbootstrap: invalid runtime policy bucket",
                _ => "secretbootstrap: invalid recovery policy bucket",
            },
        ));
    }
    Ok(())
}

/// `MinioRuntimePolicy` — the least-privilege IAM policy document for
/// the Artifact runtime principal scoped to exactly one bucket,
/// rendered byte-for-byte as upstream emits it.
///
/// The grants are deliberately narrow, and each omission is
/// load-bearing:
///
/// - **No `s3:ListBucket`, anywhere.** The runtime never enumerates
///   objects, and readiness is never inferred from object existence,
///   so listing would only ever be a way to discover other
///   Workspaces' opaque keys.
/// - **No `s3:DeleteObject` under the ready prefix.** It removes one
///   specific capability — delete-then-recreate under the same key —
///   and it bounds what a compromised runtime can destroy.
/// - **No admin action of any kind**, and no resource outside this
///   one bucket's two key roles.
///
/// Overwrite protection is client-side only: withholding
/// `s3:DeleteObject` does not prevent a ready object from being
/// replaced by a plain PUT. A real server-side immutability mechanism
/// exists — bucket versioning plus Object Lock in compliance mode on
/// the ready prefix — but it is a bucket-provisioning step blocked on
/// an externally built, digest-locked provisioner image. Until that
/// lands, ready-object immutability is a known gap, not a property
/// this policy delivers.
pub fn minio_runtime_policy(bucket: &str) -> Result<String, Failure> {
    validate_minio_bucket(bucket, "runtime")?;
    let [staging_prefix, ready_prefix] = MINIO_RUNTIME_KEY_PREFIXES;
    let staging = format!("arn:aws:s3:::{bucket}/{staging_prefix}*");
    let ready = format!("arn:aws:s3:::{bucket}/{ready_prefix}*");
    let document = MinioPolicyDocument {
        version: POLICY_VERSION,
        statement: vec![
            // Staging is the working area: the runtime streams a body
            // in, reads it back to verify it, and removes it after a
            // rejection or an expiry.
            MinioPolicyStatement {
                effect: "Allow",
                action: vec![ACTION_PUT_OBJECT, ACTION_GET_OBJECT, ACTION_DELETE_OBJECT],
                resource: vec![staging],
            },
            // Ready objects may be created and read back; they may
            // never be deleted by this principal.
            MinioPolicyStatement {
                effect: "Allow",
                action: vec![ACTION_PUT_OBJECT, ACTION_GET_OBJECT],
                resource: vec![ready],
            },
        ],
    };
    serde_json::to_string(&document).map_err(|_| {
        Failure::internal(
            codes::MINIO_POLICY_INVALID,
            "secretbootstrap: runtime policy marshal failed",
        )
    })
}

/// `MinioRecoveryKeyScope` — the closed, space-separated object-key
/// scope declaration for each Slice C recovery credential. Rejects
/// every unrelated purpose rather than falling back to the broader
/// runtime scope.
pub fn minio_recovery_key_scope(purpose: Purpose) -> Result<&'static str, Failure> {
    match purpose {
        Purpose::MinioBackup => Ok(MINIO_BACKUP_KEY_SCOPE),
        Purpose::MinioRestore => Ok(MINIO_RESTORE_KEY_SCOPE),
        Purpose::MinioImport => Ok(MINIO_IMPORT_KEY_SCOPE),
        _ => Err(Failure::invalid(
            codes::MINIO_POLICY_INVALID,
            "secretbootstrap: purpose has no recovery MinIO scope",
        )),
    }
}

/// `MinioRecoveryPolicy` — the exact least-privilege policy for one
/// Slice C/D recovery purpose. It must be cross-checked
/// byte-for-byte by the external provisioner before a broker accepts
/// a descriptor for any of the four purposes.
///
/// ADR 0017 (option B): [`Purpose::MinioRestore`] is read-only. Its
/// only consumer, `VerifyInventory`, reads restored object bodies to
/// compare against the sealed inventory; it never writes one.
/// Granting `PutObject` released a write capability with no
/// demonstrated consumer, so it is removed rather than merely
/// time-boxed — a credential that cannot write cannot be misused by a
/// caller reaching it through a path nobody anticipated.
///
/// ADR 0034: [`Purpose::MinioImport`] is the one recovery credential
/// that writes — it uploads foreign bodies to the ready prefix, then
/// reads them back for post-import verification.
pub fn minio_recovery_policy(purpose: Purpose, bucket: &str) -> Result<String, Failure> {
    validate_minio_bucket(bucket, "recovery")?;
    minio_recovery_key_scope(purpose)?;
    let actions: Vec<&'static str> = if purpose == Purpose::MinioImport {
        vec![ACTION_PUT_OBJECT, ACTION_GET_OBJECT]
    } else {
        vec![ACTION_GET_OBJECT]
    };
    let mut resources = vec![format!(
        "arn:aws:s3:::{bucket}/{MINIO_RUNTIME_READY_PREFIX}*"
    )];
    if purpose == Purpose::MinioBackup {
        resources.push(format!(
            "arn:aws:s3:::{bucket}/{MINIO_BACKUP_THROUGHPUT_FIXTURE_KEY}"
        ));
    }
    let document = MinioPolicyDocument {
        version: POLICY_VERSION,
        statement: vec![MinioPolicyStatement {
            effect: "Allow",
            action: actions,
            resource: resources,
        }],
    };
    serde_json::to_string(&document).map_err(|_| {
        Failure::internal(
            codes::MINIO_POLICY_INVALID,
            "secretbootstrap: recovery policy marshal failed",
        )
    })
}

/// `MinioRecoveryPolicyDigest` — the immutable `sha256:<hex>` digest
/// of the exact policy bytes generated above. Callers must derive
/// authority from this function, never from a policy digest supplied
/// by configuration or an external peer.
pub fn minio_recovery_policy_digest(purpose: Purpose, bucket: &str) -> Result<String, Failure> {
    let policy = minio_recovery_policy(purpose, bucket)?;
    Ok(sha256_prefixed(policy.as_bytes()))
}

// ---------------------------------------------------------------------------
// Generation / Binding
// ---------------------------------------------------------------------------

/// One generation of protected key material bound to a purpose
/// (upstream `secretbootstrap.Generation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    /// The generation identity.
    pub generation_id: ProtectedGenerationId,
    /// The purpose it serves.
    pub purpose: Purpose,
    /// The owning instance.
    pub instance_id: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Digest of the generation value — never the value itself.
    pub value_digest: String,
}

/// A secret binding between a purpose and a protected generation
/// (upstream `secretbootstrap.Binding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBinding {
    /// The bound purpose.
    pub purpose: Purpose,
    /// The owning instance.
    pub instance_id: String,
    /// The bound generation.
    pub generation_id: ProtectedGenerationId,
    /// The workspace the binding serves; empty for instance-scoped
    /// purposes.
    pub workspace_id: String,
    /// The reference a workspace-scoped secret is stored under.
    pub secret_ref: String,
    /// The binding identity.
    pub binding_id: SecretBindingId,
}

impl SecretBinding {
    /// `Validate` — the purpose must be registered and
    /// materializable, the identities non-nil, and a workspace-scoped
    /// binding must carry its `secret_ref`.
    ///
    /// The nil-UUID rejections upstream performs are enforced here by
    /// construction (`*_id` newtypes cannot be nil) — the `is_nil`
    /// checks below cover only a corrupted-row reconstruction through
    /// `from_trusted_db_bytes`.
    pub fn validate(&self) -> Result<(), Failure> {
        if !self.purpose.materializable() {
            return Err(Failure::denied(
                codes::NOT_MATERIALIZABLE,
                "secretbootstrap: purpose is declaration-only",
            ));
        }
        if self.instance_id.is_empty() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: binding missing instance id",
            ));
        }
        if self.generation_id.is_nil() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: binding missing generation id",
            ));
        }
        if self.binding_id.is_nil() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: binding missing binding id",
            ));
        }
        if self.purpose != Purpose::MinioRoot
            && !self.workspace_id.is_empty()
            && self.secret_ref.is_empty()
        {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: workspace binding requires SecretRef",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AdoptRequest
// ---------------------------------------------------------------------------

/// The B04 adoption request importing a legacy B03 protected
/// generation into the registry (upstream
/// `secretbootstrap.AdoptRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptRequest {
    /// The adopting instance.
    pub instance_id: String,
    /// The adopted purpose.
    pub purpose: Purpose,
    /// The legacy generation being imported; `None` when adopting a
    /// fresh generation (upstream `uuid.Nil`).
    pub legacy_generation_id: Option<ProtectedGenerationId>,
    /// The adopting operation.
    pub operation_id: OperationId,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
}

impl AdoptRequest {
    /// `Validate` — instance, registered purpose, and operation
    /// identity are all required.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.instance_id.is_empty() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: adopt request missing instance id",
            ));
        }
        if self.operation_id.is_nil() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: adopt request missing operation id",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HandoffRequest / HandoffReceipt / HandoffOperation
// ---------------------------------------------------------------------------

/// The one-use materialization request (upstream
/// `secretbootstrap.HandoffRequest`): resolve a receipt and write the
/// bound dependency credential to the authorized target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffRequest {
    /// The binding being materialized.
    pub binding_id: SecretBindingId,
    /// Calling peer's UID.
    pub peer_uid: u32,
    /// Calling peer's PID.
    pub peer_pid: i32,
    /// The requesting operation.
    pub operation_id: OperationId,
    /// The consumed one-use receipt.
    pub receipt_id: HandoffReceiptId,
    /// Receipt HMAC.
    pub receipt_hmac: String,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// The purpose served.
    pub purpose: Purpose,
    /// Dependency service.
    pub service: String,
    /// Authorized materialization target.
    pub target: String,
    /// Target file owner UID.
    pub uid: u32,
    /// Target file owner GID.
    pub gid: u32,
}

impl HandoffRequest {
    /// `Validate` — binding, operation, receipt, HMAC, peer identity,
    /// and the purpose's closed dependency binding are all required.
    ///
    /// `peer_uid` is not checked against its zero value: `0` is root,
    /// and every production caller of this handoff (the helper daemon
    /// materializing the B04 MinIO secret) is itself a root process —
    /// SC-DEF-16 found treating a legitimate root peer as "no
    /// identity at all", which no real root-run caller could ever
    /// pass. `peer_pid` has no such ambiguity: `0` is never a real
    /// process's PID.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.binding_id.is_nil() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: handoff request missing binding id",
            ));
        }
        if self.operation_id.is_nil() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: handoff request missing operation id",
            ));
        }
        if self.receipt_id.is_nil() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: handoff request missing receipt id",
            ));
        }
        if self.receipt_hmac.is_empty() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: handoff request missing receipt hmac",
            ));
        }
        if self.peer_pid == 0 {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: handoff request missing peer identity",
            ));
        }
        self.purpose
            .validate_dependency(&self.service, &self.target, self.uid, self.gid)
    }
}

/// The durable state of a one-use handoff receipt (upstream
/// `secretbootstrap.HandoffReceiptState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffReceiptState {
    /// `issued` — minted, not yet consumed.
    Issued,
    /// `reserved` — bound to a reservation.
    Reserved,
    /// `acknowledged` — consumed by the authorized peer.
    Acknowledged,
    /// `invalidated` — revoked before use.
    Invalidated,
}

impl HandoffReceiptState {
    /// The upstream state string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Reserved => "reserved",
            Self::Acknowledged => "acknowledged",
            Self::Invalidated => "invalidated",
        }
    }
}

/// The durable receipt record (upstream
/// `secretbootstrap.HandoffReceipt`) — consumed atomically by
/// `MaterializeDependency`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffReceipt {
    /// The receipt identity.
    pub receipt_id: HandoffReceiptId,
    /// The requesting operation.
    pub operation_id: OperationId,
    /// The bound binding.
    pub binding_id: SecretBindingId,
    /// The purpose served.
    pub purpose: Purpose,
    /// Dependency service.
    pub service: String,
    /// Authorized materialization target.
    pub target: String,
    /// Target owner UID.
    pub uid: u32,
    /// Target owner GID.
    pub gid: u32,
    /// Peer UID.
    pub peer_uid: u32,
    /// Peer PID.
    pub peer_pid: i32,
    /// Receipt HMAC.
    pub hmac: String,
    /// Current state.
    pub state: HandoffReceiptState,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Issue time.
    pub issued_at: OffsetDateTime,
}

/// The canonical handoff-operation state machine (upstream
/// `secretbootstrap.HandoffOperationState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffOperationState {
    /// `issued`.
    Issued,
    /// `reserved`.
    Reserved,
    /// `write_started`.
    WriteStarted,
    /// `broker_closed`.
    BrokerClosed,
    /// `helper_acknowledged`.
    HelperAcknowledged,
    /// `acknowledged` — terminal.
    Acknowledged,
    /// `reconciliation_required` — a durable gap needs settling.
    ReconciliationRequired,
    /// `invalidated` — terminal.
    Invalidated,
    /// `failed` — terminal.
    Failed,
}

impl HandoffOperationState {
    /// `IsTerminal` — acknowledged, invalidated, or failed.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Acknowledged | Self::Invalidated | Self::Failed)
    }

    /// `IsTransitionable` — not terminal.
    #[must_use]
    pub const fn is_transitionable(self) -> bool {
        !self.is_terminal()
    }

    /// `ValidTransitions` — the legal next states from this state.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [Self] {
        match self {
            Self::Issued => &[Self::Reserved, Self::ReconciliationRequired],
            Self::Reserved => &[Self::WriteStarted, Self::ReconciliationRequired],
            Self::WriteStarted => &[Self::BrokerClosed, Self::ReconciliationRequired],
            Self::BrokerClosed => &[Self::HelperAcknowledged, Self::ReconciliationRequired],
            Self::HelperAcknowledged => &[Self::Acknowledged, Self::ReconciliationRequired],
            Self::ReconciliationRequired => &[Self::Acknowledged, Self::Invalidated, Self::Failed],
            _ => &[],
        }
    }

    /// `CanTransition` — whether `to` is a legal transition from
    /// this state.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        self.valid_transitions().contains(&to)
    }

    /// The upstream state string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Reserved => "reserved",
            Self::WriteStarted => "write_started",
            Self::BrokerClosed => "broker_closed",
            Self::HelperAcknowledged => "helper_acknowledged",
            Self::Acknowledged => "acknowledged",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::Invalidated => "invalidated",
            Self::Failed => "failed",
        }
    }
}

/// The durable operation record for a handoff (upstream
/// `secretbootstrap.HandoffOperation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffOperation {
    /// The operation identity.
    pub operation_id: OperationId,
    /// The receipt it materializes.
    pub receipt_id: HandoffReceiptId,
    /// The bound binding.
    pub binding_id: SecretBindingId,
    /// The purpose served.
    pub purpose: Purpose,
    /// Current state.
    pub state: HandoffOperationState,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last transition time.
    pub updated_at: OffsetDateTime,
    /// Record HMAC.
    pub hmac: String,
    /// How a reconciliation settled.
    pub resolved_action: String,
}

// ---------------------------------------------------------------------------
// LifecycleProof / HandoffReservation / DurableLease
// ---------------------------------------------------------------------------

/// The broker-signed lifecycle proof (upstream
/// `secretbootstrap.LifecycleProof`, SC-DEF-12): the durable record a
/// B04 adoption verifies the caller's stopped-topology /
/// mount-release / binding tokens against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleProof {
    /// The proof identity.
    pub proof_id: LifecycleProofId,
    /// The bound instance.
    pub instance_id: String,
    /// The owning operation.
    pub operation_id: OperationId,
    /// The lifecycle lock.
    pub lock_id: String,
    /// Stopped-topology proof present.
    pub stopped_proof: bool,
    /// Mount-release proof present.
    pub mount_release_proof: bool,
    /// Bootstrap fingerprint.
    pub bootstrap_fingerprint: String,
    /// Provisioning receipt.
    pub provisioning_receipt: String,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Opaque stopped-topology token (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stopped_proof_token: String,
    /// Opaque mount-release token (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mount_release_token: String,
    /// Opaque binding-evidence token (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub binding_evidence_token: String,
    /// Issue time.
    #[serde(with = "wire::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// Expiry.
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Broker HMAC over the canonical record.
    pub hmac: String,
}

/// A bounded handoff reservation (upstream
/// `secretbootstrap.HandoffReservation`): pins one receipt's service,
/// target, owner identity, and fencing token until expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffReservation {
    /// The reservation identity.
    pub reservation_id: HandoffReservationId,
    /// The requesting operation.
    pub operation_id: OperationId,
    /// The bound binding.
    pub binding_id: SecretBindingId,
    /// The purpose served.
    pub purpose: Purpose,
    /// Dependency service.
    pub service: String,
    /// Authorized materialization target.
    pub target: String,
    /// Target owner UID.
    pub uid: u32,
    /// Target owner GID.
    pub gid: u32,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Reservation expiry.
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Broker HMAC over the record.
    pub hmac: String,
}

/// A durable secret-binding lease (upstream
/// `secretbootstrap.DurableLease`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableLease {
    /// The lease identity.
    pub lease_id: DurableLeaseId,
    /// The bound binding.
    pub binding_id: SecretBindingId,
    /// The operation holding the lease.
    pub holder_op_id: OperationId,
    /// Lease expiry.
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Creation time.
    #[serde(with = "wire::rfc3339")]
    pub created_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// ProtectedBindingState / Outcome / reason codes
// ---------------------------------------------------------------------------

/// The durable state of a protected binding (upstream
/// `secretbootstrap.ProtectedBindingState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedBindingState {
    /// `prepared`.
    Prepared,
    /// `active`.
    Active,
    /// `retired` — terminal.
    Retired,
    /// `revoked` — terminal.
    Revoked,
    /// `deleted` — terminal.
    Deleted,
    /// `tombstone` — terminal.
    Tombstone,
}

impl ProtectedBindingState {
    /// `IsTerminal` — retired, revoked, deleted, or tombstone.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Retired | Self::Revoked | Self::Deleted | Self::Tombstone
        )
    }

    /// The upstream state string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Deleted => "deleted",
            Self::Tombstone => "tombstone",
        }
    }
}

/// The closed outcome vocabulary of a secret-bootstrap operation
/// (upstream `secretbootstrap.Outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapOutcome {
    /// `adopted`.
    Adopted,
    /// `already_adopted`.
    AlreadyAdopted,
    /// `materialized`.
    Materialized,
    /// `denied`.
    Denied,
    /// `revoked`.
    Revoked,
    /// `deleted`.
    Deleted,
}

impl BootstrapOutcome {
    /// The upstream outcome string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adopted => "adopted",
            Self::AlreadyAdopted => "already_adopted",
            Self::Materialized => "materialized",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::Deleted => "deleted",
        }
    }
}

// ---------------------------------------------------------------------------
// MigrationLaunchBinding — broker-minted launch binding for central-migrate
// ---------------------------------------------------------------------------

/// `MigrationLaunchBindingHMACDomain` — the domain separator the
/// broker's B05 launch-binding HMAC is computed under.
pub const MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN: &str = "b05-launch-binding";

/// The canonical-payload schema version (upstream's fixed
/// `"b05-migration-launch-binding/v1"`).
const MIGRATION_LAUNCH_PAYLOAD_VERSION: &str = "b05-migration-launch-binding/v1";

/// A broker-generated, one-use launch binding that authorizes the
/// `central-migrate` helper to perform a single migration-mode
/// operation (upstream `secretbootstrap.MigrationLaunchBinding`). The
/// binding is sealed with HMAC and carries a CLOEXEC requirement: the
/// descriptor is invalidated after exec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationLaunchBinding {
    /// The broker-issued launch evidence token.
    pub launch_evidence_id: String,
    /// The authorized operation.
    pub operation_id: OperationId,
    /// The protected lease binding.
    pub binding_id: SecretBindingId,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Broker-generated one-use nonce (Base64 on the wire — upstream
    /// `[]byte`; `null` for a nil slice).
    #[serde(with = "wire::b64_lenient")]
    pub nonce: Vec<u8>,
    /// Verified peer UID — must be [`CENTRAL_MIGRATE_UID`].
    pub peer_uid: u32,
    /// Verified peer GID — must be [`CENTRAL_MIGRATE_GID`].
    pub peer_gid: u32,
    /// Verified peer PID — nonzero.
    pub peer_pid: i32,
    /// Fixed path to the `central-migrate` binary.
    pub executable: String,
    /// Must be `"migrate"`.
    pub mode: String,
    /// `/proc/<pid>/stat` starttime (field 22).
    pub process_start: String,
    /// Binding deadline.
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
    /// Creation time.
    #[serde(with = "wire::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Broker-signed HMAC over the canonical payload.
    pub hmac: String,
}

/// `migrationLaunchBindingCanonicalPayload` — the deterministic JSON
/// the HMAC signs. Field order is the byte contract; the struct's
/// declaration order is upstream's.
#[derive(Serialize)]
struct MigrationLaunchCanonical<'a> {
    version: &'static str,
    launch_evidence_id: &'a str,
    operation_id: String,
    binding_id: String,
    fencing_token: u64,
    nonce: String,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    executable: &'a str,
    mode: &'a str,
    process_start: &'a str,
    deadline: String,
    created_at: String,
}

impl MigrationLaunchBinding {
    /// `CanonicalPayload` — the deterministic byte representation
    /// used for HMAC computation. All identity fields are included so
    /// any tampering invalidates the signature: UUID text form, hex
    /// nonce, RFC 3339Nano UTC timestamps, and every identity field.
    #[must_use]
    pub fn canonical_payload(&self) -> Vec<u8> {
        let payload = MigrationLaunchCanonical {
            version: MIGRATION_LAUNCH_PAYLOAD_VERSION,
            launch_evidence_id: &self.launch_evidence_id,
            operation_id: self.operation_id.to_string(),
            binding_id: self.binding_id.to_string(),
            fencing_token: self.fencing_token,
            nonce: hex_encode(&self.nonce),
            peer_uid: self.peer_uid,
            peer_gid: self.peer_gid,
            peer_pid: self.peer_pid,
            executable: &self.executable,
            mode: &self.mode,
            process_start: &self.process_start,
            deadline: format_rfc3339_nano(self.deadline.to_offset(time::UtcOffset::UTC)),
            created_at: format_rfc3339_nano(self.created_at.to_offset(time::UtcOffset::UTC)),
        };
        // serde_json cannot fail to serialize this struct — all
        // fields are primitives — matching upstream's infallible
        // json.Marshal of the payload.
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// `VerifyHMAC` — whether `hmac` was computed over this binding's
    /// complete canonical payload using the broker's B05
    /// launch-binding HMAC key: `HMAC-SHA256(key, domain | "|" |
    /// payload)` compared in constant time.
    #[must_use]
    pub fn verify_hmac(&self, key: &[u8]) -> bool {
        let Some(provided) = hex_decode(&self.hmac) else {
            return false;
        };
        let mut message = Vec::with_capacity(
            MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN.len() + 1 + self.canonical_payload().len(),
        );
        message.extend_from_slice(MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN.as_bytes());
        message.push(b'|');
        message.extend_from_slice(&self.canonical_payload());
        let computed = hmac_sha256(key, &message);
        ct_eq(&computed, &provided)
    }

    /// `Validate` — every field of the binding is checked before the
    /// migrate worker may be launched under it. `now` is injected so
    /// the deadline check is deterministic.
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), Failure> {
        if self.launch_evidence_id.is_empty() {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing launch evidence id",
            ));
        }
        if self.binding_id.is_nil() || self.fencing_token == 0 {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing protected lease binding",
            ));
        }
        if self.operation_id.is_nil() {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing operation id",
            ));
        }
        if self.mode != "migrate" {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: mode must be \"migrate\"",
            ));
        }
        if self.nonce.is_empty() {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing nonce",
            ));
        }
        if self.peer_uid != CENTRAL_MIGRATE_UID || self.peer_gid != CENTRAL_MIGRATE_GID {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: peer must be 986:986",
            ));
        }
        if self.peer_pid <= 0 {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: invalid peer pid",
            ));
        }
        if self.executable.is_empty() {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing executable",
            ));
        }
        if self.process_start.is_empty() {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing process start time",
            ));
        }
        if now > self.deadline {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: deadline expired",
            ));
        }
        if self.hmac.is_empty() {
            return Err(Failure::invalid(
                codes::MIGRATION_LAUNCH_INVALID,
                "migration launch binding: missing HMAC",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::wire;
    use time::macros::datetime;

    // ---------------------------------------------------------------
    // Purpose registry (secretbootstrap domain_test.go)
    // ---------------------------------------------------------------

    /// Ports `TestAllPurposesRegistry` — the closed registry has
    /// exactly twelve purposes and the materializable set is exactly
    /// the four descriptor-deliverable purposes.
    #[test]
    fn all_purposes_registry() {
        assert_eq!(ALL_PURPOSES.len(), 12);
        let materializable: Vec<Purpose> = ALL_PURPOSES
            .iter()
            .copied()
            .filter(|p| p.materializable())
            .collect();
        assert_eq!(
            materializable,
            vec![
                // AllPurposes() declaration order, filtered.
                Purpose::PostgresRuntime,
                Purpose::PostgresOutbox,
                Purpose::PostgresMigration,
                Purpose::MinioRoot,
            ],
            "exactly four purposes are materializable"
        );
        for purpose in ALL_PURPOSES {
            assert_eq!(
                purpose.as_str().parse::<Purpose>().unwrap(),
                purpose,
                "{}: as_str/FromStr round-trip",
                purpose.as_str()
            );
        }
        assert!("bogus".parse::<Purpose>().is_err());
        assert_eq!(
            "bogus".parse::<Purpose>().unwrap_err().code(),
            codes::UNKNOWN_PURPOSE
        );
        assert_eq!(MINIO_ROOT, Purpose::MinioRoot);
        assert_eq!(MAX_SECRET_BYTES, 64 * 1024);
    }

    /// Ports the `ValidateDependency` test matrix.
    #[test]
    fn purpose_validate_dependency_matrix() {
        // minio_root_v1 — exact tuple only.
        assert!(
            Purpose::MinioRoot
                .validate_dependency("minio", "/run/secrets/minio-root-password", 1000, 1000)
                .is_ok()
        );
        for (service, target, uid, gid) in [
            ("other", "/run/secrets/minio-root-password", 1000, 1000),
            ("minio", "/other/path", 1000, 1000),
            ("minio", "/run/secrets/minio-root-password", 0, 1000),
            ("minio", "/run/secrets/minio-root-password", 1000, 0),
            ("minio", "/run/secrets/minio-root-password", 1001, 1001),
        ] {
            assert!(
                Purpose::MinioRoot
                    .validate_dependency(service, target, uid, gid)
                    .is_err(),
                "minio_root accepted {service}/{target}/{uid}:{gid}"
            );
        }

        // postgres_migration_v1 — the verified central-migrate peer.
        assert!(
            Purpose::PostgresMigration
                .validate_dependency("central-migrate", "scm_rights", 986, 986)
                .is_ok()
        );
        for (service, target, uid, gid) in [
            ("minio", "scm_rights", 986, 986),
            ("central-migrate", "/run/secrets/x", 986, 986),
            ("central-migrate", "scm_rights", 0, 986),
            ("central-migrate", "scm_rights", 986, 0),
            ("central-migrate", "scm_rights", 1000, 1000),
        ] {
            assert!(
                Purpose::PostgresMigration
                    .validate_dependency(service, target, uid, gid)
                    .is_err(),
                "postgres_migration accepted {service}/{target}/{uid}:{gid}"
            );
        }

        // minio_runtime_v1 — provisioner 1000:1000 OR runtime UID 501
        // with ANY gid (the UID-only outbound gate).
        assert!(
            Purpose::MinioRuntime
                .validate_dependency("minio-provision", "sealed_memfd", 1000, 1000)
                .is_ok()
        );
        assert!(
            Purpose::MinioRuntime
                .validate_dependency("minio-provision", "sealed_memfd", 501, 0)
                .is_ok(),
            "runtime peer is UID-only — any GID"
        );
        assert!(
            Purpose::MinioRuntime
                .validate_dependency("minio-provision", "sealed_memfd", 501, 999)
                .is_ok()
        );
        for (service, target, uid, gid) in [
            ("minio", "sealed_memfd", 1000, 1000),
            ("minio-provision", "/run/secrets/x", 1000, 1000),
            ("minio-provision", "sealed_memfd", 0, 1000),
            ("minio-provision", "sealed_memfd", 1000, 0),
            ("minio-provision", "sealed_memfd", 1001, 1001),
            ("minio-provision", "sealed_memfd", 0, 0),
        ] {
            assert!(
                Purpose::MinioRuntime
                    .validate_dependency(service, target, uid, gid)
                    .is_err(),
                "minio_runtime accepted {service}/{target}/{uid}:{gid}"
            );
        }

        // Every other purpose has no dependency binding.
        for purpose in ALL_PURPOSES {
            if matches!(
                purpose,
                Purpose::MinioRoot | Purpose::PostgresMigration | Purpose::MinioRuntime
            ) {
                continue;
            }
            assert_eq!(
                purpose
                    .validate_dependency("minio", "/run/secrets/x", 0, 0)
                    .unwrap_err()
                    .code(),
                codes::CROSS_SERVICE_PURPOSE,
                "{} must not have a dependency binding",
                purpose.as_str()
            );
        }
    }

    /// Ports the `MinioRuntimeUseRequest.Validate` test matrix.
    #[test]
    fn minio_runtime_use_request_validation() {
        let now = datetime!(2026-03-04 05:00:00 UTC);
        let valid = MinioRuntimeUseRequest {
            instance_id: "instance-1".to_string(),
            operation_id: "operation-1".to_string(),
            receipt_id: "receipt-1".to_string(),
            opaque_generation: "generation-1".to_string(),
            bucket: "central-artifacts".to_string(),
            key_prefix: MINIO_RUNTIME_KEY_SCOPE.to_string(),
            service: "minio-provision".to_string(),
            target: "sealed_memfd".to_string(),
            uid: MINIO_PROVISIONER_UID,
            gid: MINIO_PROVISIONER_GID,
            purpose: Purpose::MinioRuntime,
            fencing_token: 7,
            deadline: datetime!(2026-03-04 06:00:00 UTC),
        };
        assert!(valid.validate(now).is_ok());

        // The widened runtime peer: 501 with any GID.
        assert!(
            MinioRuntimeUseRequest {
                uid: CENTRAL_RUNTIME_UID,
                gid: 0,
                ..valid.clone()
            }
            .validate(now)
            .is_ok()
        );

        let cases: Vec<MinioRuntimeUseRequest> = vec![
            MinioRuntimeUseRequest {
                instance_id: String::new(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                operation_id: String::new(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                receipt_id: String::new(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                opaque_generation: String::new(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                bucket: String::new(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                purpose: Purpose::MinioRoot,
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                key_prefix: "v1/staging/".to_string(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                key_prefix: "v1/".to_string(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                fencing_token: 0,
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                deadline: datetime!(1-01-01 0:00:00 UTC),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                deadline: datetime!(2026-03-04 04:00:00 UTC),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                deadline: now,
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                uid: 1001,
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                gid: 1001,
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                service: "minio".to_string(),
                ..valid.clone()
            },
            MinioRuntimeUseRequest {
                target: "file".to_string(),
                ..valid.clone()
            },
        ];
        for (i, case) in cases.iter().enumerate() {
            assert!(
                case.validate(now).is_err(),
                "case {i} must be rejected: {case:?}"
            );
        }
    }

    // ---------------------------------------------------------------
    // MinIO policies (minio_runtime_policy_test.go +
    // minio_recovery_policy_test.go) — byte-exact contracts.
    // ---------------------------------------------------------------

    /// Ports `TestRuntimePolicyResourcesMatchTheDeclaredKeyScope`:
    /// every key role the policy grants a resource for must appear in
    /// the declared scope, and every role in the declared scope must
    /// appear in the policy — the two statements cannot drift.
    #[test]
    fn runtime_policy_resources_match_declared_key_scope() {
        const BUCKET: &str = "central-artifacts";
        let raw = minio_runtime_policy(BUCKET).unwrap();
        let document: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let mut granted = BTreeSet::new();
        for statement in document["Statement"].as_array().unwrap() {
            for resource in statement["Resource"].as_array().unwrap() {
                let resource = resource.as_str().unwrap();
                let prefix = resource
                    .strip_prefix(&format!("arn:aws:s3:::{BUCKET}/"))
                    .unwrap()
                    .trim_end_matches('*');
                granted.insert(prefix.to_string());
            }
        }
        let declared: BTreeSet<String> = MINIO_RUNTIME_KEY_PREFIXES
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            granted, declared,
            "granted resource prefixes must equal the declared scope"
        );
        assert_eq!(declared.len(), 2, "exactly staging and ready");

        // The canonical scope string names both roles and neither alone.
        for prefix in MINIO_RUNTIME_KEY_PREFIXES {
            assert!(MINIO_RUNTIME_KEY_SCOPE.contains(prefix));
            assert_ne!(MINIO_RUNTIME_KEY_SCOPE, prefix);
        }
        assert_eq!(MINIO_RUNTIME_KEY_SCOPE, "v1/staging/ v1/ready/");

        // Exact byte contract: staging Put/Get/Delete, ready Put/Get,
        // no ListBucket anywhere, no DeleteObject on ready.
        assert_eq!(
            raw,
            "{\"Version\":\"2012-10-17\",\"Statement\":[\
{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\",\"s3:DeleteObject\"],\"Resource\":[\"arn:aws:s3:::central-artifacts/v1/staging/*\"]},\
{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::central-artifacts/v1/ready/*\"]}]}"
        );
        assert!(!raw.contains("ListBucket"));
        assert!(minio_runtime_policy("bad/bucket").is_err());
        assert!(minio_runtime_policy("  ").is_err());
        assert!(minio_runtime_policy("wild*card").is_err());
        assert!(minio_runtime_policy("quote\"bucket").is_err());
        assert!(minio_runtime_policy("back\\slash").is_err());
    }

    /// Ports `TestMinioRecoveryPoliciesAreBothReadOnlyOverDistinctScopes`
    /// and `TestMinioRecoveryPolicyExactCrossRepoContractAndDigest` —
    /// the exact JSON bytes and pinned SHA-256 digests.
    #[test]
    fn recovery_policies_exact_contract_and_digest() {
        const BUCKET: &str = "central-artifacts-v1";
        let cases: [(Purpose, &str, &str); 3] = [
            (
                Purpose::MinioBackup,
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::central-artifacts-v1/v1/ready/*\",\"arn:aws:s3:::central-artifacts-v1/v1/system/backup-throughput-fixture-v1\"]}]}",
                "sha256:aa5f63fdf5b13e4bc2effd1a972a7c2ed6771faee3b56bc2fca7d822ad7d38b1",
            ),
            (
                Purpose::MinioRestore,
                // ADR 0017 (option B): no s3:PutObject.
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::central-artifacts-v1/v1/ready/*\"]}]}",
                "sha256:79ec56cee096807d98ca968500e2b5bd16ac948c008a2c83ab5cbfc5e338e6dc",
            ),
            (
                Purpose::MinioImport,
                // ADR 0034: the one recovery credential that writes.
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::central-artifacts-v1/v1/ready/*\"]}]}",
                "sha256:46919b32f24986496167605fb6fb7b859f78aa8b4cd4aa9f36b859e3cc6f18f7",
            ),
        ];
        for (purpose, want_policy, want_digest) in cases {
            let policy = minio_recovery_policy(purpose, BUCKET).unwrap();
            assert_eq!(
                policy,
                want_policy,
                "{}: exact cross-repo policy contract",
                purpose.as_str()
            );
            assert_eq!(
                minio_recovery_policy_digest(purpose, BUCKET).unwrap(),
                want_digest,
                "{}: pinned digest",
                purpose.as_str()
            );
            assert!(!policy.contains("ListBucket"));
        }
        // Both backup and restore are read-only (ADR 0017 option B).
        for purpose in [Purpose::MinioBackup, Purpose::MinioRestore] {
            let policy = minio_recovery_policy(purpose, BUCKET).unwrap();
            assert!(
                !policy.contains("PutObject"),
                "{}: must be read-only",
                purpose.as_str()
            );
        }
    }

    /// Ports `TestMinioRecoveryKeyScope` and the runtime/malformed-bucket
    /// rejections.
    #[test]
    fn recovery_scope_and_bucket_rejections() {
        assert_eq!(
            minio_recovery_key_scope(Purpose::MinioBackup).unwrap(),
            "v1/ready/ v1/system/backup-throughput-fixture-v1"
        );
        assert_eq!(
            minio_recovery_key_scope(Purpose::MinioRestore).unwrap(),
            "v1/ready/"
        );
        assert_eq!(
            minio_recovery_key_scope(Purpose::MinioImport).unwrap(),
            "v1/ready/"
        );
        for purpose in ALL_PURPOSES {
            if matches!(
                purpose,
                Purpose::MinioBackup | Purpose::MinioRestore | Purpose::MinioImport
            ) {
                continue;
            }
            assert!(
                minio_recovery_key_scope(purpose).is_err(),
                "{} must not have a recovery scope",
                purpose.as_str()
            );
        }
        assert!(minio_recovery_policy(Purpose::MinioRuntime, "central-artifacts-v1").is_err());
        assert!(minio_recovery_policy(Purpose::MinioBackup, "bad/bucket").is_err());
        assert!(minio_recovery_policy(Purpose::MinioBackup, "").is_err());
    }

    // ---------------------------------------------------------------
    // SecretBinding / AdoptRequest / HandoffRequest validation
    // ---------------------------------------------------------------

    /// Ports the `Binding.Validate` test matrix.
    #[test]
    fn secret_binding_validation() {
        let valid = SecretBinding {
            purpose: Purpose::MinioRoot,
            instance_id: "instance-1".to_string(),
            generation_id: ProtectedGenerationId::new(),
            workspace_id: String::new(),
            secret_ref: String::new(),
            binding_id: SecretBindingId::new(),
        };
        assert!(valid.validate().is_ok());

        // Non-materializable purposes are declaration-only.
        let non_materializable = SecretBinding {
            purpose: Purpose::MinioRuntime,
            ..valid.clone()
        };
        assert_eq!(
            non_materializable.validate().unwrap_err().code(),
            codes::NOT_MATERIALIZABLE
        );

        let missing_instance = SecretBinding {
            instance_id: String::new(),
            ..valid.clone()
        };
        assert!(missing_instance.validate().is_err());

        // A workspace-scoped materializable binding requires SecretRef.
        let workspace_missing_ref = SecretBinding {
            purpose: Purpose::PostgresRuntime,
            workspace_id: "workspace-1".to_string(),
            secret_ref: String::new(),
            ..valid.clone()
        };
        assert!(workspace_missing_ref.validate().is_err());
        let workspace_ok = SecretBinding {
            purpose: Purpose::PostgresRuntime,
            workspace_id: "workspace-1".to_string(),
            secret_ref: "ref-1".to_string(),
            ..valid.clone()
        };
        assert!(workspace_ok.validate().is_ok());
        // minio_root_v1 is exempt from the SecretRef rule.
        let root_workspace = SecretBinding {
            workspace_id: "workspace-1".to_string(),
            secret_ref: String::new(),
            ..valid.clone()
        };
        assert!(root_workspace.validate().is_ok());
    }

    /// Ports the `AdoptRequest.Validate` test matrix.
    #[test]
    fn adopt_request_validation() {
        let valid = AdoptRequest {
            instance_id: "instance-1".to_string(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 3,
        };
        assert!(valid.validate().is_ok());
        let no_instance = AdoptRequest {
            instance_id: String::new(),
            ..valid.clone()
        };
        assert!(no_instance.validate().is_err());
        let with_legacy = AdoptRequest {
            legacy_generation_id: Some(ProtectedGenerationId::new()),
            ..valid.clone()
        };
        assert!(with_legacy.validate().is_ok());
    }

    /// Ports the `HandoffRequest.Validate` test matrix — including
    /// SC-DEF-16: peer UID 0 (root) is a legitimate caller.
    #[test]
    fn handoff_request_validation() {
        let valid = HandoffRequest {
            binding_id: SecretBindingId::new(),
            peer_uid: 0,
            peer_pid: 4321,
            operation_id: OperationId::new(),
            receipt_id: HandoffReceiptId::new(),
            receipt_hmac: "deadbeef".to_string(),
            fencing_token: 9,
            purpose: Purpose::MinioRoot,
            service: "minio".to_string(),
            target: "/run/secrets/minio-root-password".to_string(),
            uid: 1000,
            gid: 1000,
        };
        assert!(
            valid.validate().is_ok(),
            "root peer (uid 0) is a real caller — SC-DEF-16"
        );
        for case in [
            HandoffRequest {
                peer_pid: 0,
                ..valid.clone()
            },
            HandoffRequest {
                receipt_hmac: String::new(),
                ..valid.clone()
            },
            HandoffRequest {
                service: "other".to_string(),
                ..valid.clone()
            },
            HandoffRequest {
                purpose: Purpose::MinioRuntime,
                ..valid.clone()
            },
        ] {
            assert!(case.validate().is_err(), "must reject {case:?}");
        }
    }

    /// Ports the `HandoffOperationState` transition-matrix test.
    #[test]
    fn handoff_operation_state_machine() {
        // The legal path: issued → reserved → write_started →
        // broker_closed → helper_acknowledged → acknowledged.
        let path = [
            HandoffOperationState::Issued,
            HandoffOperationState::Reserved,
            HandoffOperationState::WriteStarted,
            HandoffOperationState::BrokerClosed,
            HandoffOperationState::HelperAcknowledged,
            HandoffOperationState::Acknowledged,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition(pair[1]),
                "{:?} must transition to {:?}",
                pair[0],
                pair[1]
            );
        }
        // Every non-terminal state may fall into reconciliation.
        for state in path[..5].iter() {
            assert!(state.can_transition(HandoffOperationState::ReconciliationRequired));
            assert!(state.is_transitionable());
        }
        // Reconciliation settles into exactly the three terminals.
        for terminal in [
            HandoffOperationState::Acknowledged,
            HandoffOperationState::Invalidated,
            HandoffOperationState::Failed,
        ] {
            assert!(HandoffOperationState::ReconciliationRequired.can_transition(terminal));
            assert!(terminal.is_terminal());
            assert!(!terminal.is_transitionable());
            assert!(terminal.valid_transitions().is_empty());
        }
        // No skipping: issued cannot jump to write_started, terminals
        // cannot transition at all.
        assert!(!HandoffOperationState::Issued.can_transition(HandoffOperationState::WriteStarted));
        assert!(!HandoffOperationState::Acknowledged.can_transition(HandoffOperationState::Issued));
        assert_eq!(
            HandoffOperationState::WriteStarted.as_str(),
            "write_started"
        );
        assert_eq!(
            HandoffOperationState::ReconciliationRequired.as_str(),
            "reconciliation_required"
        );
    }

    /// Ports the `ProtectedBindingState` terminal-set test.
    #[test]
    fn protected_binding_state_terminals() {
        assert!(!ProtectedBindingState::Prepared.is_terminal());
        assert!(!ProtectedBindingState::Active.is_terminal());
        for state in [
            ProtectedBindingState::Retired,
            ProtectedBindingState::Revoked,
            ProtectedBindingState::Deleted,
            ProtectedBindingState::Tombstone,
        ] {
            assert!(state.is_terminal());
        }
    }

    // ---------------------------------------------------------------
    // MigrationLaunchBinding (B05) — canonical payload, HMAC, validate
    // ---------------------------------------------------------------

    fn valid_launch_binding() -> MigrationLaunchBinding {
        MigrationLaunchBinding {
            launch_evidence_id: "evidence-1".to_string(),
            operation_id: OperationId::new(),
            binding_id: SecretBindingId::new(),
            fencing_token: 7,
            nonce: b"nonce-bytes".to_vec(),
            peer_uid: CENTRAL_MIGRATE_UID,
            peer_gid: CENTRAL_MIGRATE_GID,
            peer_pid: 4242,
            executable: "/usr/libexec/central-migrate".to_string(),
            mode: "migrate".to_string(),
            process_start: "123456789".to_string(),
            deadline: datetime!(2026-03-04 06:00:00 UTC),
            created_at: datetime!(2026-03-04 05:00:00 UTC),
            hmac: "00".repeat(32),
        }
    }

    /// Ports `TestMigrationLaunchBindingCanonicalPayload*`: the
    /// payload is deterministic, carries the fixed version, and any
    /// identity-field change invalidates it.
    #[test]
    fn migration_launch_binding_canonical_payload() {
        let binding = valid_launch_binding();
        let payload = binding.canonical_payload();
        let text = String::from_utf8(payload.clone()).unwrap();

        // Fixed version and all identity fields present.
        assert!(text.contains("\"version\":\"b05-migration-launch-binding/v1\""));
        assert!(text.contains(&format!("\"operation_id\":\"{}\"", binding.operation_id)));
        assert!(text.contains(&format!("\"binding_id\":\"{}\"", binding.binding_id)));
        assert!(text.contains(&format!(
            "\"nonce\":\"{}\"",
            wire::hex_encode(&binding.nonce)
        )));
        assert!(text.contains("\"deadline\":\"2026-03-04T06:00:00Z\""));

        // Deterministic.
        assert_eq!(binding.canonical_payload(), payload);

        // Any field change produces a different payload — no field can
        // be shifted across a boundary to forge a matching signature.
        for altered in [
            MigrationLaunchBinding {
                launch_evidence_id: "evidence-2".to_string(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                operation_id: OperationId::new(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                binding_id: SecretBindingId::new(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                fencing_token: 8,
                ..binding.clone()
            },
            MigrationLaunchBinding {
                nonce: b"other".to_vec(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                peer_uid: 0,
                ..binding.clone()
            },
            MigrationLaunchBinding {
                peer_pid: 1,
                ..binding.clone()
            },
            MigrationLaunchBinding {
                executable: "/tmp/fake".to_string(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                mode: "other".to_string(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                process_start: "999".to_string(),
                ..binding.clone()
            },
            MigrationLaunchBinding {
                deadline: datetime!(2026-03-04 07:00:00 UTC),
                ..binding.clone()
            },
        ] {
            assert_ne!(
                altered.canonical_payload(),
                payload,
                "altered binding must produce a different payload: {altered:?}"
            );
        }
    }

    /// Ports `TestMigrationLaunchBindingVerifyHMAC*`: a binding whose
    /// HMAC was computed over `domain|payload` verifies; any altered
    /// field or key fails, and a malformed HMAC fails safely.
    #[test]
    fn migration_launch_binding_hmac() {
        let key = b"test-hmac-key";
        let binding = valid_launch_binding();

        // Compute a valid HMAC the way the broker does.
        let mut message = MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN.as_bytes().to_vec();
        message.push(b'|');
        message.extend_from_slice(&binding.canonical_payload());
        let mut signed = MigrationLaunchBinding {
            hmac: wire::hex_encode(&wire::hmac_sha256(key, &message)),
            ..binding.clone()
        };
        assert!(signed.verify_hmac(key));

        // Wrong key, tampered field, and malformed hex all fail.
        assert!(!signed.verify_hmac(b"other-key"));
        signed.peer_pid = 99;
        assert!(!signed.verify_hmac(key));
        signed.peer_pid = 4242;
        signed.hmac = "not-hex".to_string();
        assert!(!signed.verify_hmac(key));
        signed.hmac = "00".repeat(31); // truncated
        assert!(!signed.verify_hmac(key));
    }

    /// Ports the `MigrationLaunchBinding.Validate` test matrix.
    #[test]
    fn migration_launch_binding_validate() {
        let now = datetime!(2026-03-04 05:30:00 UTC);
        let valid = valid_launch_binding();
        assert!(valid.validate(now).is_ok());

        for case in [
            MigrationLaunchBinding {
                launch_evidence_id: String::new(),
                ..valid.clone()
            },
            MigrationLaunchBinding {
                fencing_token: 0,
                ..valid.clone()
            },
            MigrationLaunchBinding {
                mode: "other".to_string(),
                ..valid.clone()
            },
            MigrationLaunchBinding {
                nonce: Vec::new(),
                ..valid.clone()
            },
            MigrationLaunchBinding {
                peer_uid: 0,
                ..valid.clone()
            },
            MigrationLaunchBinding {
                peer_gid: 0,
                ..valid.clone()
            },
            MigrationLaunchBinding {
                peer_pid: 0,
                ..valid.clone()
            },
            MigrationLaunchBinding {
                peer_pid: -1,
                ..valid.clone()
            },
            MigrationLaunchBinding {
                executable: String::new(),
                ..valid.clone()
            },
            MigrationLaunchBinding {
                process_start: String::new(),
                ..valid.clone()
            },
            MigrationLaunchBinding {
                deadline: datetime!(2026-03-04 05:00:00 UTC),
                ..valid.clone()
            },
            MigrationLaunchBinding {
                hmac: String::new(),
                ..valid.clone()
            },
        ] {
            assert!(case.validate(now).is_err(), "must reject {case:?}");
        }
    }

    /// The serde shape is a durable-record contract: `nonce` is
    /// Base64, the IDs are UUID text, timestamps RFC 3339.
    #[test]
    fn migration_launch_binding_serde_shape() {
        let binding = valid_launch_binding();
        let json = serde_json::to_value(&binding).unwrap();
        assert_eq!(
            json["nonce"],
            serde_json::Value::String(wire::b64_encode(&binding.nonce))
        );
        assert_eq!(json["peer_uid"], serde_json::json!(986));
        assert_eq!(json["mode"], serde_json::json!("migrate"));
        let decoded: MigrationLaunchBinding = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, binding);
    }

    // ---------------------------------------------------------------
    // B02 dependency vocabulary
    // ---------------------------------------------------------------

    #[test]
    fn service_modes_and_selectors() {
        assert_eq!(ALL_SERVICE_MODES.len(), 7);
        for mode in ALL_SERVICE_MODES {
            assert_eq!(mode.as_str().parse::<ServiceMode>().unwrap(), mode);
        }
        assert_eq!(ServiceMode::Postgres.as_str(), "postgres");
        assert_eq!(
            ServiceMode::PostgresProvision.as_str(),
            "postgres-provision"
        );
        assert_eq!(
            ServiceMode::PostgresThroughputProvision.as_str(),
            "postgres-throughput-provision"
        );
        assert_eq!(
            acquisition_kind_for("minio").unwrap(),
            AcquisitionKind::Built
        );
        assert_eq!(
            acquisition_kind_for("postgresql").unwrap(),
            AcquisitionKind::Published
        );
        assert_eq!(
            acquisition_kind_for("bogus").unwrap_err().code(),
            codes::UNKNOWN_SELECTOR
        );
        assert_eq!(
            service_mode_for_selector("minio").unwrap(),
            ServiceMode::Minio
        );
        assert_eq!(
            service_mode_for_selector("postgresql").unwrap(),
            ServiceMode::Postgres
        );
    }

    fn complete_prepared_set() -> PreparedDependencySet {
        let inventory = || {
            new_oci_inventory(
                "sha256:index".to_string(),
                "sha256:manifest".to_string(),
                "sha256:config".to_string(),
            )
            .unwrap()
        };
        PreparedDependencySet {
            modes: B03_REQUIRED_SERVICE_MODES
                .iter()
                .map(|&mode| PreparedMode {
                    mode,
                    inventory: inventory(),
                })
                .collect(),
        }
    }

    /// Ports `ValidateB03` — the required set, duplicate rejection,
    /// and incomplete-identity rejection.
    #[test]
    fn prepared_dependency_set_validate_b03() {
        assert!(complete_prepared_set().validate_b03().is_ok());

        // Missing one required mode.
        let missing = PreparedDependencySet {
            modes: complete_prepared_set()
                .modes
                .into_iter()
                .filter(|m| m.mode != ServiceMode::MinioProvision)
                .collect(),
        };
        assert_eq!(
            missing.validate_b03().unwrap_err().code(),
            codes::MISSING_SERVICE_MODE
        );

        // A duplicate mode is invalid.
        let mut dup = complete_prepared_set();
        let extra = dup.modes[0].clone();
        dup.modes.push(extra);
        assert_eq!(
            dup.validate_b03().unwrap_err().code(),
            codes::INVALID_SERVICE_MODE
        );

        // Incomplete OCI identity.
        let mut incomplete = complete_prepared_set();
        incomplete.modes[0].inventory.manifest_digest.clear();
        assert_eq!(
            incomplete.validate_b03().unwrap_err().code(),
            codes::INVALID_SERVICE_MODE
        );

        // Extra known modes are admitted (postgres-throughput-provision).
        let mut with_extra = complete_prepared_set();
        with_extra.modes.push(PreparedMode {
            mode: ServiceMode::PostgresThroughputProvision,
            inventory: new_oci_inventory(
                "sha256:a".to_string(),
                "sha256:b".to_string(),
                "sha256:c".to_string(),
            )
            .unwrap(),
        });
        assert!(with_extra.validate_b03().is_ok());
    }

    /// Ports `Lookup` — mode identity lookup independent of B03's
    /// required set.
    #[test]
    fn prepared_dependency_set_lookup() {
        let set = complete_prepared_set();
        assert_eq!(
            set.lookup(ServiceMode::Postgres).unwrap().index_digest,
            "sha256:index"
        );
        assert_eq!(
            set.lookup(ServiceMode::PostgresProvision)
                .unwrap_err()
                .code(),
            codes::MISSING_SERVICE_MODE
        );
    }

    /// Ports `ValidateAttestationFacts` — exactly one verified fact
    /// per required predicate, all bound to the same subject.
    #[test]
    fn attestation_facts_validation() {
        let fact = |predicate| AttestationFact {
            predicate,
            schema: ATTESTATION_SCHEMA.to_string(),
            key_id: "key-1".to_string(),
            envelope_digest: "sha256:e".to_string(),
            subject_digest: "sha256:subject".to_string(),
        };
        let complete: Vec<AttestationFact> = REQUIRED_ATTESTATION_PREDICATES
            .iter()
            .map(|&p| fact(p))
            .collect();
        assert!(validate_attestation_facts(&complete, "sha256:subject").is_ok());
        assert!(validate_attestation_facts(&complete, "").is_err());
        // Missing a predicate.
        assert!(validate_attestation_facts(&complete[..2], "sha256:subject").is_err());
        // Duplicate predicate.
        let mut dup = complete.clone();
        dup.push(fact(AttestationPredicate::Sbom));
        assert!(validate_attestation_facts(&dup, "sha256:subject").is_err());
        // Wrong subject binding.
        let mut wrong = complete.clone();
        wrong[0].subject_digest = "sha256:other".to_string();
        assert!(validate_attestation_facts(&wrong, "sha256:subject").is_err());
        // Wrong schema.
        let mut bad_schema = complete;
        bad_schema[0].schema = "other/v1".to_string();
        assert!(validate_attestation_facts(&bad_schema, "sha256:subject").is_err());
        assert_eq!(ATTESTATION_PAYLOAD_TYPE, "application/vnd.in-toto+json");
    }

    /// Ports `ReceiptForCandidate`, `NewAdmissionBinding`,
    /// `SelectorToken`, `ValidOperationID`, and
    /// `ValidateIndependentBuilds`.
    #[test]
    fn dependency_records_and_guards() {
        // Receipt derivation: a valid candidate produces its receipt.
        let mut candidate = new_candidate("minio").unwrap();
        assert!(!candidate.is_zero());
        assert_eq!(candidate.phase, PreparePhase::Pending);
        candidate.id = "candidate-1".to_string();
        candidate.dependency_set = complete_prepared_set();
        let receipt = receipt_for_candidate(&candidate).unwrap();
        assert_eq!(receipt.id, "candidate-1");
        assert!(receipt.validate_b03().is_ok());
        // An empty candidate cannot settle.
        assert!(receipt_for_candidate(&Candidate::default()).is_err());
        // A candidate with an incomplete set cannot settle.
        let mut bad = candidate.clone();
        bad.dependency_set = PreparedDependencySet::default();
        assert!(receipt_for_candidate(&bad).is_err());

        // Admission binding + selector token.
        let binding = new_admission_binding("admission-1", &selector_token("minio")).unwrap();
        assert!(!binding.is_zero());
        assert!(binding.selector_token.starts_with("sha256:"));
        assert_eq!(selector_token("minio"), sha256_prefixed(b"minio"));
        assert!(new_admission_binding("", "tok").is_err());
        assert!(new_admission_binding("a", "").is_err());
        assert!(AdmissionBinding::default().is_zero());

        // Operation ID path safety.
        assert!(valid_operation_id("op-123").is_ok());
        for id in ["", ".", "..", "../etc", "a/b", "a\0b"] {
            assert!(
                valid_operation_id(id).is_err(),
                "operation id {id:?} must be rejected"
            );
        }

        // Independent-build roots.
        assert!(validate_independent_builds(("/a", "/b"), ("/c", "/d")).is_ok());
        assert_eq!(
            validate_independent_builds(("/a", "/b"), ("/c", "/b"))
                .unwrap_err()
                .code(),
            codes::SHARED_BUILDER_ROOTS
        );
        assert_eq!(
            validate_independent_builds(("/a", ""), ("/c", "/d"))
                .unwrap_err()
                .code(),
            codes::BUILD_REQUEST_INVALID
        );
        // A build may share roots with itself? No — all four roots
        // must be pairwise distinct (upstream compares every pair).
        assert!(validate_independent_builds(("/a", "/b"), ("/a", "/c")).is_err());
    }

    /// Ports the `PreparePhase`, `ComparisonFact`, `OciInventory`, and
    /// digest-helpers coverage.
    #[test]
    fn prepare_vocabulary_and_digests() {
        for phase in ALL_PREPARE_PHASES {
            assert_eq!(phase.as_str().parse::<PreparePhase>().unwrap(), phase);
        }
        assert!("bogus".parse::<PreparePhase>().is_err());

        // Canonical digest guard.
        assert!(
            valid_canonical_digest(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_ok()
        );
        for digest in [
            "md5:deadbeef",
            "sha256:short",
            "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        ] {
            assert!(valid_canonical_digest(digest).is_err());
        }

        // Comparison fact.
        let fact = ComparisonFact {
            comparator: "cmp".to_string(),
            equal: true,
            index_digest: "sha256:i".to_string(),
            inventory_digest: "sha256:d".to_string(),
        };
        assert!(fact.validate().is_ok());
        assert!(
            ComparisonFact {
                equal: false,
                ..fact.clone()
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            ComparisonFact {
                comparator: String::new(),
                ..fact.clone()
            }
            .validate()
            .unwrap_err()
            .code(),
            codes::OCI_MISMATCH
        );

        // Inventory digest is order-sensitive and boundary-safe.
        let inventory = OciInventory {
            index_digest: "sha256:i".to_string(),
            manifest_digest: "sha256:m".to_string(),
            config_digest: "sha256:c".to_string(),
            layers: vec![OciLayer {
                digest: "sha256:l".to_string(),
                media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
                size: 42,
                annotations: BTreeMap::from([("k".to_string(), "v".to_string())]),
            }],
        };
        let digest = inventory_digest(&inventory);
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
        assert_eq!(inventory_digest(&inventory), digest);
        let mut shifted = inventory.clone();
        shifted.layers[0].size = 43;
        assert_ne!(inventory_digest(&shifted), digest);
        // digest_fields: field values cannot be shifted across the
        // boundary ("ab","c" != "a","bc").
        assert_ne!(
            digest_fields("d", &["ab", "c"]),
            digest_fields("d", &["a", "bc"])
        );

        // OCI inventory constructor + serde (PascalCase layer fields).
        assert!(new_oci_inventory("".into(), "m".into(), "c".into()).is_err());
        let json = serde_json::to_value(&inventory).unwrap();
        assert_eq!(json["layers"][0]["Digest"], "sha256:l");
        assert_eq!(json["index_digest"], "sha256:i");
    }

    // ---------------------------------------------------------------
    // B03 lifecycle
    // ---------------------------------------------------------------

    /// Ports `TestPhase*` (infralifecycle domain_test.go): the closed
    /// phase set, terminality, and string round-trip.
    #[test]
    fn lifecycle_phase_terminality() {
        assert_eq!(ALL_LIFECYCLE_PHASES.len(), 13);
        let terminals = [
            LifecyclePhase::Completed,
            LifecyclePhase::Failed,
            LifecyclePhase::Cancelled,
        ];
        for phase in ALL_LIFECYCLE_PHASES {
            assert_eq!(
                phase.is_terminal(),
                terminals.contains(&phase),
                "{}: terminality",
                phase.as_str()
            );
            assert_eq!(phase.as_str().parse::<LifecyclePhase>().unwrap(), phase);
        }
        assert!("bogus".parse::<LifecyclePhase>().is_err());
        assert_eq!(LifecyclePhase::FsInitialized.as_str(), "fs_initialized");
        assert_eq!(
            LifecyclePhase::ReceiptSelectorSwitched.as_str(),
            "receipt_selector_switched"
        );
    }

    /// Ports `TestBindingValidate*` and `TestBindingExcludesBootID`:
    /// the binding carries the durable identity fields and must NOT
    /// include the runtime boot observation, which lives in
    /// [`Observation`] separately.
    #[test]
    fn lifecycle_binding_validate_and_no_boot_id() {
        let valid = LifecycleBinding {
            instance_id: "instance-1".to_string(),
            config_binding: "cfg-1".to_string(),
            admission_id: "adm-1".to_string(),
            receipt_id: "rcpt-1".to_string(),
            model_digest: "sha256:m".to_string(),
            payload_epoch: "epoch-1".to_string(),
            bootstrap_fingerprints: vec![],
            b04: B04LifecycleEvidence::default(),
        };
        assert!(valid.validate().is_ok());
        for case in [
            LifecycleBinding {
                instance_id: String::new(),
                ..valid.clone()
            },
            LifecycleBinding {
                config_binding: String::new(),
                ..valid.clone()
            },
            LifecycleBinding {
                receipt_id: String::new(),
                ..valid.clone()
            },
            LifecycleBinding {
                payload_epoch: String::new(),
                ..valid.clone()
            },
        ] {
            assert!(case.validate().is_err());
        }
        // BootID lives only on the observation — the binding has no
        // such field (compile-time property, asserted by construction
        // here for parity with the upstream test's reflection check).
        let observation = Observation {
            boot_id: "boot-1".to_string(),
            container_start_ids: BTreeMap::new(),
        };
        assert_eq!(observation.boot_id, "boot-1");
    }

    /// Ports `TestB04LifecycleEvidenceValidate`: every proof field
    /// must be present before a production handoff can be attempted.
    #[test]
    fn b04_lifecycle_evidence_validate() {
        let valid = B04LifecycleEvidence {
            instance_id: "i".to_string(),
            operation_id: "o".to_string(),
            fencing_token: 1,
            stopped_topology_proof: "s".to_string(),
            mount_release_proof: "m".to_string(),
            binding_evidence: "b".to_string(),
            expires_at: Some(datetime!(2026-03-04 06:00:00 UTC)),
        };
        assert!(valid.validate().is_ok());
        for case in [
            B04LifecycleEvidence {
                instance_id: String::new(),
                ..valid.clone()
            },
            B04LifecycleEvidence {
                operation_id: String::new(),
                ..valid.clone()
            },
            B04LifecycleEvidence {
                fencing_token: 0,
                ..valid.clone()
            },
            B04LifecycleEvidence {
                stopped_topology_proof: String::new(),
                ..valid.clone()
            },
            B04LifecycleEvidence {
                mount_release_proof: String::new(),
                ..valid.clone()
            },
            B04LifecycleEvidence {
                binding_evidence: String::new(),
                ..valid.clone()
            },
            B04LifecycleEvidence {
                expires_at: None,
                ..valid.clone()
            },
        ] {
            assert!(case.validate().is_err(), "incomplete evidence must reject");
        }
    }

    /// Purpose is a typed, closed enum: serde renders the exact
    /// upstream purpose string and parse rejects everything else.
    #[test]
    fn purpose_serde() {
        let json = serde_json::to_value(Purpose::MinioRuntime).unwrap();
        assert_eq!(json, serde_json::json!("minio_runtime_v1"));
        assert_eq!(
            serde_json::from_value::<Purpose>(serde_json::json!("postgres_outbox_v1")).unwrap(),
            Purpose::PostgresOutbox
        );
        assert!(serde_json::from_value::<Purpose>(serde_json::json!("root")).is_err());
    }
}
