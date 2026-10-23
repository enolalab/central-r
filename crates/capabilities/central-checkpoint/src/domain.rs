//! Checkpoint domain — immutable verified continuation evidence.
//!
//! Two layers, one file, per the owning contracts:
//!
//! 1. **Phase-1 record** (`central.checkpoints`, adapter-mapping §3.20 +
//!    b08, `docs/runtime/checkpoints.md`): the continuation-envelope
//!    payload schema, the size policy (256 KiB default, 1 MiB hard
//!    maximum), the SHA-256 checksum binding, immutability, the ordered
//!    compatibility verification, and the CM-1 migration rule.
//! 2. **b36 readiness** (upstream `internal/checkpoint/domain.go`):
//!    the subtree-anchored `resume_checkpoints` record vocabulary —
//!    boundary legality (spec D2), format/graph-schema compatibility
//!    (D3), the digest-bound resume token, the idempotency fingerprint,
//!    and retention-class GC selection (D5).
//!
//! Pure synchronous Rust (rust-application-boundaries.md §2.3/§7.1):
//! no `async fn`, no I/O.

use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, CheckpointId, ResumeCheckpointId, RunId, SessionAttemptId, StepAttemptId, StepId,
    TaskId, WorkflowNodeId, WorkspaceId,
};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};

/// Stable machine codes emitted by this domain.
pub mod codes {
    pub const CHECKPOINT_INVALID: &str = "checkpoint_invalid";
    pub const PAYLOAD_TOO_LARGE: &str = "checkpoint_payload_too_large";
    pub const UNSANITIZED_PAYLOAD: &str = "checkpoint_unsanitized_payload";
    pub const UNKNOWN_PAYLOAD_FIELD: &str = "checkpoint_unknown_payload_field";
    pub const CHECKSUM_MISMATCH: &str = "checkpoint_checksum_mismatch";
    pub const OWNERSHIP_MISSING: &str = "checkpoint_ownership_missing";
    pub const SCHEMA_INCOMPATIBLE: &str = "checkpoint_schema_incompatible";
    pub const PRODUCER_UNKNOWN: &str = "checkpoint_producer_unknown";
    pub const AGENT_REVISION_MISMATCH: &str = "checkpoint_agent_revision_mismatch";
    pub const POLICY_MISMATCH: &str = "checkpoint_policy_fingerprint_mismatch";
    pub const ARTIFACT_MISSING: &str = "checkpoint_artifact_missing";
    pub const EVIDENCE_INCONSISTENT: &str = "checkpoint_evidence_inconsistent";
    pub const BOUNDARY_ILLEGAL: &str = "CHECKPOINT_BOUNDARY_ILLEGAL";
    pub const RESUME_TOKEN_STALE: &str = "RESUME_TOKEN_STALE";
    pub const FORMAT_INCOMPATIBLE: &str = "CHECKPOINT_INCOMPATIBLE";
    pub const WORKSPACE_DIGEST_MISMATCH: &str = "WORKSPACE_DIGEST_MISMATCH";
    /// Spec-3's preflight check-4 verdict: a `finalized_artifacts`
    /// entry that no longer resolves `ready` (upstream
    /// `ReasonCheckpointArtifactMissing`). Distinct from the Phase-1
    /// compatibility check-7 code [`ARTIFACT_MISSING`] above — the two
    /// layers carry different vocabularies by design.
    pub const RESUME_ARTIFACT_MISSING: &str = "CHECKPOINT_ARTIFACT_MISSING";
    pub const RESUME_REQUIRES_OPERATOR: &str = "RESUME_REQUIRES_OPERATOR_DECISION";
    pub const DUPLICATE_IDEMPOTENCY: &str = "DUPLICATE_IDEMPOTENCY_KEY";
    pub const MIGRATION_UNSUPPORTED: &str = "checkpoint_migration_unsupported";
    pub const NOT_FOUND: &str = "checkpoint_not_found";
}

// ---------------------------------------------------------------------------
// Size policy (checkpoints.md §Size policy)
// ---------------------------------------------------------------------------

/// Default inline continuation-state bound — 256 KiB. State at or
/// below it is stored inline unconditionally.
pub const DEFAULT_INLINE_PAYLOAD_LIMIT: usize = 256 * 1024;

/// Phase-1 hard maximum inline payload — 1 MiB (`MaxCheckpointPayloadBytes`,
/// `checkpoints_payload_b08_check`: `octet_length(payload) <= 1048576`).
/// Installed policy may choose a lower value; a value above it is
/// rejected, and payload above it requires an Artifact reference.
pub const MAX_CHECKPOINT_PAYLOAD_BYTES: usize = 1 << 20;

/// Validates an installed inline limit: any value at or below the hard
/// maximum is legal; anything above is a contract violation.
pub fn validate_inline_limit(installed: usize) -> Result<(), Failure> {
    if installed == 0 || installed > MAX_CHECKPOINT_PAYLOAD_BYTES {
        return Err(Failure::invalid(
            codes::CHECKPOINT_INVALID,
            "the installed inline limit must be within 1..=1048576",
        ));
    }
    Ok(())
}

/// Bound for producer identity/version text.
pub const MAX_PRODUCER_TEXT_BYTES: usize = 128;
/// Bound for a fingerprint string (`sha256:<64 hex>` = 71 chars).
pub const MAX_FINGERPRINT_BYTES: usize = 128;

/// Keys that must never appear in a checkpoint payload — the upstream
/// `sensitivePayloadKeys` denylist, matched case-insensitively at every
/// level.
const SENSITIVE_PAYLOAD_KEYS: [&str; 10] = [
    "access_token",
    "api_key",
    "api_token",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "secret_key",
    "token",
];

// ---------------------------------------------------------------------------
// Payload schema — the upstream checkpointPayloadSchema
// ---------------------------------------------------------------------------

/// A fixed allowlist node in the payload schema: a leaf accepts only
/// scalars/arrays-of-scalars… mirroring upstream, a `leaf` accepts any
/// non-object value; an `Object` node recurses over a declared key set
/// where every member must be a declared child (strict allowlist —
/// `UNKNOWN_PAYLOAD_FIELD` on anything else, matching upstream
/// `sanitizeObject`).
enum Schema {
    Leaf,
    Object(&'static [(&'static str, Schema)]),
}

const METADATA_SCHEMA: Schema = Schema::Object(&[
    ("producer_version", Schema::Leaf),
    ("schema_version", Schema::Leaf),
    ("source", Schema::Leaf),
    ("sequence", Schema::Leaf),
]);

const CONTINUATION_SCHEMA: Schema = Schema::Object(&[
    ("state", Schema::Leaf),
    ("cursor", Schema::Leaf),
    ("sequence", Schema::Leaf),
    ("summary", Schema::Leaf),
    ("metadata", METADATA_SCHEMA),
]);

/// The Phase-1 continuation-envelope schema — upstream
/// `checkpointPayloadSchema` verbatim.
const CHECKPOINT_PAYLOAD_SCHEMA: Schema = Schema::Object(&[
    ("schema_version", Schema::Leaf),
    ("producer_version", Schema::Leaf),
    ("continuation", CONTINUATION_SCHEMA),
    ("metadata", METADATA_SCHEMA),
]);

fn sanitize_against(
    object: &serde_json::Map<String, serde_json::Value>,
    schema: &Schema,
) -> Result<(), Failure> {
    let Schema::Object(children) = schema else {
        return Err(Failure::internal(
            codes::CHECKPOINT_INVALID,
            "the schema root is malformed",
        ));
    };
    for (key, value) in object {
        let normalized = key.to_lowercase();
        if SENSITIVE_PAYLOAD_KEYS.contains(&normalized.as_str()) {
            return Err(Failure::invalid(
                codes::UNSANITIZED_PAYLOAD,
                "the payload carries a denied sensitive key",
            ));
        }
        let child = children.iter().find(|(name, _)| *name == key.as_str());
        let Some((_, child_schema)) = child else {
            return Err(Failure::invalid(
                codes::UNKNOWN_PAYLOAD_FIELD,
                "the payload carries an undeclared field",
            ));
        };
        match (value, child_schema) {
            (serde_json::Value::Object(child_object), Schema::Object(_)) => {
                sanitize_against(child_object, child_schema)?;
            }
            (serde_json::Value::Array(items), Schema::Object(_)) => {
                // Upstream: an array under an object-typed slot must
                // contain objects conforming to that schema.
                for item in items {
                    let item = item.as_object().ok_or_else(|| {
                        Failure::invalid(
                            codes::UNKNOWN_PAYLOAD_FIELD,
                            "a payload array carries a non-object member",
                        )
                    })?;
                    sanitize_against(item, child_schema)?;
                }
            }
            (serde_json::Value::Object(_), Schema::Leaf)
            | (serde_json::Value::Array(_), Schema::Leaf) => {
                return Err(Failure::invalid(
                    codes::UNKNOWN_PAYLOAD_FIELD,
                    "a leaf field carries a structured value",
                ));
            }
            (_, Schema::Leaf) => {}
            (_, Schema::Object(_)) => {
                return Err(Failure::invalid(
                    codes::UNKNOWN_PAYLOAD_FIELD,
                    "an object field carries a scalar value",
                ));
            }
        }
    }
    Ok(())
}

/// A validated, canonicalized continuation payload — the
/// `checkpoints.payload` bytes (jsonb-compatible object, ≤ the
/// installed inline limit, strict schema allowlist, sensitive keys
/// denied). Constructed only through [`CheckpointPayload::sanitize`]
/// or [`CheckpointPayload::from_canonical`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPayload(Vec<u8>);

impl CheckpointPayload {
    /// Sanitizes producer bytes: complete JSON object, strict
    /// continuation schema, sensitive keys denied, canonical
    /// re-encode, size re-check. Rejects totally — never truncates.
    pub fn sanitize(raw: &[u8], installed_limit: usize) -> Result<Self, Failure> {
        validate_inline_limit(installed_limit)?;
        if raw.is_empty() || raw.len() > installed_limit {
            return Err(Failure::invalid(
                codes::PAYLOAD_TOO_LARGE,
                "the payload exceeds the installed inline limit",
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| {
            Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the payload is not a complete JSON document",
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the payload is not a JSON object",
            )
        })?;
        sanitize_against(object, &CHECKPOINT_PAYLOAD_SCHEMA)?;
        let encoded = serde_json::to_vec(object).map_err(|_| {
            Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the payload cannot be canonically re-encoded",
            )
        })?;
        if encoded.len() > installed_limit {
            return Err(Failure::invalid(
                codes::PAYLOAD_TOO_LARGE,
                "the canonical payload exceeds the installed inline limit",
            ));
        }
        Ok(Self(encoded))
    }

    /// Rehydrates a stored payload — re-validates because a row whose
    /// stored bytes do not equal their canonical form is corrupt (the
    /// upstream bytes-equal read rule).
    pub fn from_canonical(raw: &[u8], installed_limit: usize) -> Result<Self, Failure> {
        Self::sanitize(raw, installed_limit)
    }

    /// The canonical payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The payload's declared `schema_version` leaf, when present.
    #[must_use]
    pub fn declared_schema_version(&self) -> Option<u64> {
        serde_json::from_slice::<serde_json::Value>(&self.0)
            .ok()?
            .get("schema_version")?
            .as_u64()
    }
}

/// The SHA-256 checksum binding a Checkpoint to its exact payload —
/// `checkpoints.checksum bytea` constrained to 32 bytes.
pub fn payload_checksum(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

// ---------------------------------------------------------------------------
// checkpoint_kind — the closed baseline vocabulary
// ---------------------------------------------------------------------------

/// The closed `checkpoint_kind` vocabulary (`§3.20` CHECK:
/// `run_start | run_complete | step_boundary | external_effect |
/// recovery`). The column dropped `NOT NULL` in b08, but a domain
/// record always names its kind.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CheckpointKind {
    /// Run start boundary.
    RunStart,
    /// Run completion boundary — the run-history record.
    RunComplete,
    /// A safe boundary between logical steps.
    StepBoundary,
    /// A boundary around a completed external effect.
    ExternalEffect,
    /// A recovery/reconciliation boundary.
    Recovery,
}

impl CheckpointKind {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunStart => "run_start",
            Self::RunComplete => "run_complete",
            Self::StepBoundary => "step_boundary",
            Self::ExternalEffect => "external_effect",
            Self::Recovery => "recovery",
        }
    }

    /// Parses the canonical text; everything else is rejected.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "run_start" => Ok(Self::RunStart),
            "run_complete" => Ok(Self::RunComplete),
            "step_boundary" => Ok(Self::StepBoundary),
            "external_effect" => Ok(Self::ExternalEffect),
            "recovery" => Ok(Self::Recovery),
            _ => Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "unknown checkpoint kind",
            )),
        }
    }
}

impl serde::Serialize for CheckpointKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CheckpointKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// The Phase-1 Checkpoint record
// ---------------------------------------------------------------------------

/// One immutable `central.checkpoints` row (§3.20 + b08 columns) —
/// verified continuation evidence. Nothing about it changes after
/// commit (checkpoints.md §Envelope: "prior evidence is immutable and
/// is never rewritten, extended, or merged").
///
/// Persisted/in-memory split: `policy_fingerprint`,
/// `agent_revision_fingerprint`, and `source_checkpoint_id` are
/// **in-memory-only legs** — `central.checkpoints` has no columns for
/// them, upstream's writer (`queryInsertCheckpoint`,
/// `persistCheckpoints`) stores no such value, and the payload-schema
/// allowlist excludes them (their envelope content is the
/// checkpoint.md compatibility contract, evaluated against
/// caller-supplied facts at preflight, not a persisted column). The
/// Task-7 adapter must not invent columns for them; a record reloaded
/// from the table simply cannot supply them.
#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    /// Immutable identity.
    pub id: CheckpointId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Parent Task (b08 `NOT NULL` via the run backfill).
    pub task_id: TaskId,
    /// Parent Run — the resume unit.
    pub run_id: RunId,
    /// Producing Step, when step-bound.
    pub step_id: Option<StepId>,
    /// Producing StepAttempt, when known.
    pub step_attempt_id: Option<StepAttemptId>,
    /// Row version — `0` at insert; immutable evidence never bumps it.
    pub version: u64,
    /// The boundary kind (`checkpoints.checkpoint_kind` — the column
    /// went nullable in b08; a domain record always names its kind).
    pub kind: CheckpointKind,
    /// Producer identity (the component that wrote the evidence).
    pub producer_id: String,
    /// Producer version.
    pub producer_version: String,
    /// Envelope schema version — matches the payload's declared
    /// `schema_version` (validated).
    pub schema_version: u64,
    /// Policy version the record was written under
    /// (`checkpoints.policy_version bigint NOT NULL`; upstream writes
    /// the literal `1` — [`CURRENT_POLICY_VERSION`]).
    pub policy_version: u64,
    /// Effective-policy fingerprint the checkpoint was validated
    /// under — opaque `sha256:`-style text, never raw policy content.
    /// **In-memory only** — see the struct-level persistence note.
    pub policy_fingerprint: String,
    /// AgentDefinition revision the run's snapshot carried — opaque
    /// fingerprint text. **In-memory only** — same note.
    pub agent_revision_fingerprint: String,
    /// The sanitized continuation payload.
    pub payload: CheckpointPayload,
    /// SHA-256 over `payload` — binds the record to exact content.
    pub checksum: [u8; 32],
    /// The b08-nullable `metadata jsonb` column — upstream's writer
    /// leaves it `NULL` (the doc-level fingerprints deliberately do
    /// NOT ride here; see the struct-level persistence note).
    pub metadata: Option<serde_json::Value>,
    /// When the evidence was recorded.
    pub recorded_at: OffsetDateTime,
    /// Row creation (database-authoritative on commit; carried for the
    /// domain model).
    pub created_at: OffsetDateTime,
    /// Whether resume may consume this record.
    pub resume_compatible: bool,
    /// Whether the record passed full validation at write.
    pub validated: bool,
    /// Retention eligibility — GC may not collect before this.
    pub eligible_after: OffsetDateTime,
    /// Legal hold — GC never collects while set.
    pub legal_hold: bool,
    /// CM-1 lineage: the source Checkpoint this record migrated from.
    /// `None` for original writes. **In-memory only** — same note.
    pub source_checkpoint_id: Option<CheckpointId>,
}

/// The `policy_version` every record of this build writes — the
/// literal upstream `queryInsertCheckpoint` fixes at `1`.
pub const CURRENT_POLICY_VERSION: u64 = 1;

/// Defense-in-depth bound for the nullable `metadata jsonb` leg —
/// the column is unconstrained, matching the 64 KiB class of bound
/// upstream applies to evidence payloads.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;

/// The schema-version vocabulary this build reads and writes. Phase-1
/// writers record `1`; readers accept exactly it (check 3 of the
/// ordered compatibility verification — anything else is a
/// structured-incompatibility failure, not a silent replay).
pub const CURRENT_SCHEMA_VERSION: u64 = 1;

/// Facts the ordered compatibility verification cannot infer — the
/// caller gathers them from durable state at preflight. Every leg maps
/// to one ordered check of checkpoints.md §Compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityFacts {
    /// Check 2 — the claiming executor holds the persisted ownership
    /// lease for the Run.
    pub lease_held: bool,
    /// Check 3 — the runtime reader version; the checkpoint's declared
    /// `schema_version` must equal [`CURRENT_SCHEMA_VERSION`] *and*
    /// this reader version (Phase-1 has exactly one recognized pair).
    pub reader_schema_version: u64,
    /// Check 4 — the producer identity+version is a known, accepted
    /// writer.
    pub producer_known: bool,
    /// Check 5 — the recorded AgentDefinition revision fingerprint
    /// matches the Run's snapshot exactly.
    pub agent_revision_matches: bool,
    /// Check 6 — the recorded policy fingerprint matches the current
    /// effective policy (or a supported migration path applies —
    /// evaluated by [`Checkpoint::evaluate_migration`], not here).
    pub policy_fingerprint_matches: bool,
    /// Check 7 — every referenced Artifact is present, ready, verified.
    pub artifacts_ready: bool,
    /// Check 8 — recorded completed work and operation evidence agree
    /// with durable state.
    pub evidence_consistent: bool,
}

impl Checkpoint {
    /// Validates the persisted-record invariants: bounded producer and
    /// fingerprint text, payload/checksum binding, declared schema
    /// agreement, and kind vocabulary.
    pub fn validate(&self) -> Result<(), Failure> {
        for text in [&self.producer_id, &self.producer_version] {
            if text.is_empty() || text.len() > MAX_PRODUCER_TEXT_BYTES {
                return Err(Failure::invalid(
                    codes::CHECKPOINT_INVALID,
                    "producer identity/version must be 1..=128 bytes",
                ));
            }
        }
        for fp in [&self.policy_fingerprint, &self.agent_revision_fingerprint] {
            if fp.is_empty() || fp.len() > MAX_FINGERPRINT_BYTES {
                return Err(Failure::invalid(
                    codes::CHECKPOINT_INVALID,
                    "a compatibility fingerprint must be 1..=128 bytes",
                ));
            }
        }
        if payload_checksum(self.payload.as_bytes()) != self.checksum {
            return Err(Failure::invalid(
                codes::CHECKSUM_MISMATCH,
                "the recorded checksum does not match the payload",
            ));
        }
        if self.payload.declared_schema_version() != Some(self.schema_version) {
            return Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the column schema_version disagrees with the payload declaration",
            ));
        }
        if let Some(metadata) = &self.metadata {
            let serialized = serde_json::to_vec(metadata).map_err(|_| {
                Failure::invalid(
                    codes::CHECKPOINT_INVALID,
                    "the metadata cannot be canonically encoded",
                )
            })?;
            if serialized.len() > MAX_METADATA_BYTES {
                return Err(Failure::invalid(
                    codes::CHECKPOINT_INVALID,
                    "the metadata exceeds its bound",
                ));
            }
        }
        Ok(())
    }

    /// The ordered pre-resume compatibility verification
    /// (checkpoints.md §Compatibility): every check must pass, and the
    /// first failure produces its structured reason and stops.
    /// Check 1 (checksum) is re-verified inside; the remaining legs are
    /// caller-supplied facts.
    pub fn verify_compatibility(&self, facts: &CompatibilityFacts) -> Result<(), Failure> {
        // 1. Checksum — recompute over the envelope.
        if payload_checksum(self.payload.as_bytes()) != self.checksum {
            return Err(Failure::denied(
                codes::CHECKSUM_MISMATCH,
                "the checkpoint checksum does not match its payload",
            ));
        }
        // 2. Ownership lease.
        if !facts.lease_held {
            return Err(Failure::denied(
                codes::OWNERSHIP_MISSING,
                "the claiming executor holds no ownership lease for the run",
            ));
        }
        // 3. Schema and reader range.
        if self.schema_version != CURRENT_SCHEMA_VERSION
            || facts.reader_schema_version != CURRENT_SCHEMA_VERSION
        {
            return Err(Failure::denied(
                codes::SCHEMA_INCOMPATIBLE,
                "the schema or reader version is outside the recognized range",
            ));
        }
        // 4. Producer.
        if !facts.producer_known {
            return Err(Failure::denied(
                codes::PRODUCER_UNKNOWN,
                "the producer is unknown or unaccepted",
            ));
        }
        // 5. AgentDefinition revision.
        if !facts.agent_revision_matches {
            return Err(Failure::denied(
                codes::AGENT_REVISION_MISMATCH,
                "the agent definition revision no longer matches the run snapshot",
            ));
        }
        // 6. Policy fingerprint — stale authority is blocked (R24).
        if !facts.policy_fingerprint_matches {
            return Err(Failure::denied(
                codes::POLICY_MISMATCH,
                "the policy fingerprint no longer matches the effective policy",
            ));
        }
        // 7. Artifact readiness.
        if !facts.artifacts_ready {
            return Err(Failure::denied(
                codes::ARTIFACT_MISSING,
                "a referenced artifact is absent or not ready",
            ));
        }
        // 8. Operation evidence.
        if !facts.evidence_consistent {
            return Err(Failure::denied(
                codes::EVIDENCE_INCONSISTENT,
                "the recorded work disagrees with durable state",
            ));
        }
        Ok(())
    }

    /// CM-1 — a supported migration path transforms this record's
    /// continuation state into a new envelope (new schema version,
    /// fingerprints, fresh checksum) while this source is preserved
    /// unchanged. `migration_path_registered` is the producer-declared
    /// path check: without one the result is a structured
    /// incompatibility, never silent data loss.
    ///
    /// The returned record is a new immutable row — the caller appends
    /// it and must pass the full compatibility verification before
    /// resume.
    pub fn evaluate_migration(&self, request: MigrationRequest) -> Result<Checkpoint, Failure> {
        if !request.migration_path_registered {
            return Err(Failure::denied(
                codes::MIGRATION_UNSUPPORTED,
                "no registered migration path covers this checkpoint",
            ));
        }
        let migrated = Self {
            id: CheckpointId::new(),
            workspace_id: self.workspace_id,
            task_id: self.task_id,
            run_id: self.run_id,
            step_id: self.step_id,
            step_attempt_id: self.step_attempt_id,
            version: 0,
            kind: self.kind,
            producer_id: self.producer_id.clone(),
            producer_version: request.producer_version,
            schema_version: request.new_schema_version,
            policy_version: self.policy_version,
            policy_fingerprint: request.new_policy_fingerprint,
            agent_revision_fingerprint: request.new_agent_revision_fingerprint,
            checksum: payload_checksum(request.new_payload.as_bytes()),
            payload: request.new_payload,
            metadata: self.metadata.clone(),
            recorded_at: request.at,
            created_at: request.at,
            resume_compatible: false,
            validated: true,
            eligible_after: request.eligible_after,
            legal_hold: self.legal_hold,
            source_checkpoint_id: Some(self.id),
        };
        migrated.validate()?;
        Ok(migrated)
    }
}

/// The legs of a CM-1 migration: the producer-declared path marker
/// plus the new envelope's content and fingerprints. The source
/// checkpoint's identity, anchor, kind, and legal-hold state carry
/// over; the source row itself is preserved unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct MigrationRequest {
    /// A producer-declared migration path covers `(source schema,
    /// revision, fingerprint)` → the new combination. `false` fails as
    /// incompatible without touching either side.
    pub migration_path_registered: bool,
    /// The transformed continuation payload (already sanitized).
    pub new_payload: CheckpointPayload,
    /// The new envelope schema version.
    pub new_schema_version: u64,
    /// The new effective-policy fingerprint.
    pub new_policy_fingerprint: String,
    /// The new AgentDefinition revision fingerprint.
    pub new_agent_revision_fingerprint: String,
    /// The migrating producer's version.
    pub producer_version: String,
    /// Migration instant — the new record's recorded/created time.
    pub at: OffsetDateTime,
    /// The new record's retention eligibility.
    pub eligible_after: OffsetDateTime,
}

/// The write-side construction recipe — everything except the
/// assigned identity, checksum (derived), and row metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointIntent {
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Parent Task.
    pub task_id: TaskId,
    /// Parent Run.
    pub run_id: RunId,
    /// Producing Step.
    pub step_id: Option<StepId>,
    /// Producing StepAttempt.
    pub step_attempt_id: Option<StepAttemptId>,
    /// Boundary kind.
    pub kind: CheckpointKind,
    /// Producer identity + version.
    pub producer_id: String,
    /// Producer version.
    pub producer_version: String,
    /// Envelope schema version.
    pub schema_version: u64,
    /// Effective-policy fingerprint — in-memory-only leg (see
    /// [`Checkpoint`]'s persistence note).
    pub policy_fingerprint: String,
    /// AgentDefinition revision fingerprint — in-memory-only leg.
    pub agent_revision_fingerprint: String,
    /// Sanitized continuation payload.
    pub payload: CheckpointPayload,
    /// The nullable `metadata` column — `None` matches upstream's
    /// writer.
    pub metadata: Option<serde_json::Value>,
    /// Retention eligibility.
    pub eligible_after: OffsetDateTime,
    /// Legal hold.
    pub legal_hold: bool,
    /// Migration lineage.
    pub source_checkpoint_id: Option<CheckpointId>,
}

impl CheckpointIntent {
    /// Seals the intent into an immutable, checksum-bound, validated
    /// record.
    pub fn seal(self, at: OffsetDateTime) -> Result<Checkpoint, Failure> {
        let checkpoint = Checkpoint {
            id: CheckpointId::new(),
            workspace_id: self.workspace_id,
            task_id: self.task_id,
            run_id: self.run_id,
            step_id: self.step_id,
            step_attempt_id: self.step_attempt_id,
            version: 0,
            kind: self.kind,
            producer_id: self.producer_id,
            producer_version: self.producer_version,
            schema_version: self.schema_version,
            policy_version: CURRENT_POLICY_VERSION,
            policy_fingerprint: self.policy_fingerprint,
            agent_revision_fingerprint: self.agent_revision_fingerprint,
            checksum: payload_checksum(self.payload.as_bytes()),
            payload: self.payload,
            metadata: self.metadata,
            recorded_at: at,
            created_at: at,
            resume_compatible: false,
            validated: true,
            eligible_after: self.eligible_after,
            legal_hold: self.legal_hold,
            source_checkpoint_id: self.source_checkpoint_id,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

// ===========================================================================
// b36 readiness — the subtree-anchored resume-checkpoint domain
// (upstream internal/checkpoint/domain.go, spec D1–D5)
// ===========================================================================

/// The only resume-checkpoint record schema this build reads and
/// writes (spec D1/D3 — `central.checkpoint/v1`).
pub const RESUME_FORMAT_VERSION: &str = "central.checkpoint/v1";

/// The child-spec/graph schema the subtree was validated under —
/// restates `internal/workflow.ChildSpecVersion`; the drift test below
/// pins the literal.
pub const GRAPH_SCHEMA_VERSION: &str = "central.child-spec/v1";

/// The closed session-attempt state vocabulary (restates
/// `internal/scheduler.AttemptState`, pinned by v35's
/// `session_attempts_state_check`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptState {
    /// Claimed by a worker; no outcome yet.
    Claimed,
    /// Provisioning its environment.
    Provisioning,
    /// Invoke window open.
    Started,
    /// Terminal success.
    Succeeded,
    /// Terminal failure.
    Failed,
    /// Parked with unknown outcome — non-terminal, `ended_at` NULL; the
    /// exact anchor state resume exists to serve.
    Ambiguous,
    /// Terminal cancellation.
    Cancelled,
}

impl AttemptState {
    /// Canonical vocabulary text (v35-pinned).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Provisioning => "provisioning",
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Ambiguous => "ambiguous",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the closed vocabulary.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "claimed" => Ok(Self::Claimed),
            "provisioning" => Ok(Self::Provisioning),
            "started" => Ok(Self::Started),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "ambiguous" => Ok(Self::Ambiguous),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "attempt state outside the session-attempt vocabulary",
            )),
        }
    }

    /// The live set (spec D2): states under which an attempt holds its
    /// node — `claimed`, `provisioning`, `started`. `ambiguous` is
    /// deliberately NOT live: it parks the outcome with `ended_at`
    /// NULL, which is exactly why `ended_at` must never be the
    /// quiescence predicate.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Claimed | Self::Provisioning | Self::Started)
    }
}

/// The closed workflow-node status vocabulary (restates
/// `internal/workflow.NodeStatus`, pinned by v33's
/// `workflow_nodes_state_check`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeStatus {
    /// Declared, never scheduled.
    Declared,
    /// Dependencies satisfied, dispatchable.
    Ready,
    /// Claim issued to a worker.
    Dispatched,
    /// Attempt in its invoke window.
    Running,
    /// Terminal success.
    Succeeded,
    /// Terminal failure.
    FailedTerminal,
    /// Parked on an ambiguous attempt.
    AttemptAmbiguous,
    /// Terminal cancellation.
    Cancelled,
}

impl NodeStatus {
    /// Canonical vocabulary text (v33-pinned).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Ready => "ready",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::FailedTerminal => "failed_terminal",
            Self::AttemptAmbiguous => "attempt_ambiguous",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the closed vocabulary.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "declared" => Ok(Self::Declared),
            "ready" => Ok(Self::Ready),
            "dispatched" => Ok(Self::Dispatched),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed_terminal" => Ok(Self::FailedTerminal),
            "attempt_ambiguous" => Ok(Self::AttemptAmbiguous),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "node state outside the workflow-node vocabulary",
            )),
        }
    }

    /// The in-flight set (spec D2): `dispatched`/`running` — the node
    /// sits between claim and a journaled attempt outcome even if the
    /// observed attempt row is stale.
    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(self, Self::Dispatched | Self::Running)
    }
}

/// Whether a checkpoint write is legal at the observed anchor state
/// (spec D2). Quiescence is defined on the ANCHOR ATTEMPT: legal
/// exactly when the attempt is not live — the complement of v35's live
/// vocabulary. The node leg must additionally not sit in its invoke
/// window, and a subtree artifact mid-finalization refuses regardless.
/// Unrecognized states refuse closed — a state outside the pinned
/// vocabularies cannot be proven quiescent.
pub fn boundary_legal(
    attempt_state: &str,
    node_state: &str,
    artifact_finalizing: bool,
) -> Result<(), Failure> {
    let illegal = |detail: &'static str| Failure::denied(codes::BOUNDARY_ILLEGAL, detail);
    if artifact_finalizing {
        return Err(illegal("a subtree artifact is mid-finalization"));
    }
    let attempt = AttemptState::parse(attempt_state)
        .map_err(|_| illegal("anchor attempt state is outside the session-attempt vocabulary"))?;
    if attempt.is_live() {
        return Err(illegal("anchor attempt is in its claim-to-outcome window"));
    }
    let node = NodeStatus::parse(node_state)
        .map_err(|_| illegal("anchor node state is outside the workflow-node vocabulary"))?;
    if node.is_in_flight() {
        return Err(illegal(
            "anchor node is between claim and a journaled outcome",
        ));
    }
    Ok(())
}

/// Whether this build can read a checkpoint recorded under the given
/// format and graph-schema versions (spec D3 check 2). The detail
/// carries the observed-vs-expected pair verbatim — upstream
/// `Compatible` — so the `resume_failed` journal is actionable.
pub fn resume_format_compatible(format: &str, graph_schema: &str) -> Result<(), Failure> {
    if format == RESUME_FORMAT_VERSION && graph_schema == GRAPH_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Failure::denied(
            codes::FORMAT_INCOMPATIBLE,
            format!(
                "format_version={format:?} graph_schema_version={graph_schema:?} \
                 (want {RESUME_FORMAT_VERSION:?} / {GRAPH_SCHEMA_VERSION:?})"
            ),
        ))
    }
}

/// The closed retention-class vocabulary (spec D5, pinned by v36's
/// `resume_checkpoints_gc_class_check`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GcClass {
    /// Deletable once a newer same-anchor checkpoint exists or
    /// `expires_at` passes.
    Supersedeable,
    /// The run-completion record — retained for the run-history window.
    RunTerminal,
    /// Operator-pinned; GC never collects.
    Pinned,
}

impl GcClass {
    /// Canonical database text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supersedeable => "supersedeable",
            Self::RunTerminal => "run_terminal",
            Self::Pinned => "pinned",
        }
    }

    /// Every declared class in declaration order — upstream
    /// `GCClasses()`. The ordered list is itself spec vocabulary
    /// (`supersedeable` first, least retentive).
    pub const ALL: [Self; 3] = [Self::Supersedeable, Self::RunTerminal, Self::Pinned];

    /// Parses the canonical text.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "supersedeable" => Ok(Self::Supersedeable),
            "run_terminal" => Ok(Self::RunTerminal),
            "pinned" => Ok(Self::Pinned),
            _ => Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "unknown gc class",
            )),
        }
    }
}

/// The run-history retention window for `run_terminal` records —
/// spec OQ-1: 30 days.
pub const RUN_TERMINAL_RETENTION: Duration = Duration::days(30);
/// Newest supersedeable records GC preserves per anchor — spec OQ-1.
pub const SUPERSEDEABLE_KEEP_LATEST: usize = 3;

/// One durable `resume_checkpoints` record (v36) — the Phase-2
/// subtree-anchored resume evidence. `(run_id, node_id)` is the anchor
/// whose subtree the snapshot covers; `attempt_id` is the anchor
/// session attempt whose harness session and workspace the record
/// carries; `event_watermark` is the `run_events` seq the snapshot is
/// consistent at.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeCheckpoint {
    /// Immutable identity.
    pub id: ResumeCheckpointId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Anchor Run.
    pub run_id: RunId,
    /// Anchor workflow node.
    pub node_id: WorkflowNodeId,
    /// Anchor session attempt.
    pub attempt_id: SessionAttemptId,
    /// Caller-supplied idempotency coordinate — dedupe on
    /// `(attempt_id, checkpoint_seq)`, never a server-side counter.
    pub checkpoint_seq: i64,
    /// Record format version (`central.checkpoint/v1`).
    pub format_version: String,
    /// Graph schema the subtree validated under.
    pub graph_schema_version: String,
    /// `run_events` consistency watermark.
    pub event_watermark: i64,
    /// Harness session the attempt held.
    pub harness_session_id: Option<String>,
    /// Workspace content digest at the watermark.
    pub workspace_digest: Option<String>,
    /// Workspace path evidence.
    pub workspace_path: Option<String>,
    /// Subtree node keys completed at the watermark — resume input.
    pub completed_nodes: Vec<String>,
    /// Finalized artifact references — resume input.
    pub finalized_artifacts: Vec<ArtifactId>,
    /// Subtree nodes live at the watermark — resume treats them as
    /// ambiguous.
    pub in_flight_nodes: Vec<String>,
    /// Retention class.
    pub gc_class: GcClass,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Optional retention expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Persisted token-binding digest — must equal
    /// [`ResumeCheckpoint::digest`].
    pub content_digest: String,
}

/// Length-prefixes a field for the shared digest encoding — identical
/// framing for [`ResumeCheckpoint::digest`] and
/// [`ResumeCheckpoint::fingerprint`] so the two can never drift in
/// encoding (the upstream `hashFields` contract).
fn hash_fields<'a>(fields: impl Iterator<Item = &'a str>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.finalize().into()
}

impl ResumeCheckpoint {
    fn sorted<T: Ord + ToString, I: Iterator<Item = T>>(items: I) -> Vec<String> {
        let mut strings: Vec<String> = items.map(|i| i.to_string()).collect();
        strings.sort();
        strings
    }

    /// The immutable fields the content digest binds — identity,
    /// anchor, versions, watermark, session/workspace evidence, and the
    /// three inventories (sorted: they are sets). GC bookkeeping is
    /// deliberately excluded — pinning or expiry must never stale a
    /// live token.
    fn digest_fields(&self) -> Vec<String> {
        let mut fields = vec![
            self.id.to_string(),
            self.workspace_id.to_string(),
            self.run_id.to_string(),
            self.node_id.to_string(),
            self.attempt_id.to_string(),
            self.format_version.clone(),
            self.graph_schema_version.clone(),
            self.event_watermark.to_string(),
            self.harness_session_id.clone().unwrap_or_default(),
            self.workspace_digest.clone().unwrap_or_default(),
            self.workspace_path.clone().unwrap_or_default(),
        ];
        fields.extend(Self::sorted(self.completed_nodes.iter()));
        fields.extend(Self::sorted(self.finalized_artifacts.iter()));
        fields.extend(Self::sorted(self.in_flight_nodes.iter()));
        fields
    }

    /// The canonical `sha256:<hex>` content digest. The write path
    /// stores it in `content_digest`; the resume token binds a prefix
    /// of it — recomputing at preflight binds the token to the record's
    /// content, not just its id.
    #[must_use]
    pub fn digest(&self) -> String {
        let sum = hash_fields(self.digest_fields().iter().map(String::as_str));
        format!("sha256:{}", hex_lower(&sum))
    }

    /// The idempotency fingerprint fields (spec-5 OQ-2): anchor,
    /// caller-supplied sequence, retention class, versions, evidence,
    /// inventories — everything a retry resolves identically. Excluded
    /// on purpose: row id, watermark, and GC bookkeeping.
    fn fingerprint_fields(&self) -> Vec<String> {
        let mut fields = vec![
            self.workspace_id.to_string(),
            self.run_id.to_string(),
            self.node_id.to_string(),
            self.attempt_id.to_string(),
            self.checkpoint_seq.to_string(),
            self.format_version.clone(),
            self.graph_schema_version.clone(),
            self.harness_session_id.clone().unwrap_or_default(),
            self.workspace_digest.clone().unwrap_or_default(),
            self.workspace_path.clone().unwrap_or_default(),
            self.gc_class.as_str().to_string(),
        ];
        fields.extend(Self::sorted(self.completed_nodes.iter()));
        fields.extend(Self::sorted(self.finalized_artifacts.iter()));
        fields.extend(Self::sorted(self.in_flight_nodes.iter()));
        fields
    }

    /// The raw 32-byte payload fingerprint stored by the
    /// `(attempt_id, checkpoint_seq)` dedupe compare. A retried write
    /// resolving different bound fields conflicts as
    /// `DUPLICATE_IDEMPOTENCY_KEY`.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        hash_fields(self.fingerprint_fields().iter().map(String::as_str))
    }

    /// The opaque resume token: `ckpt.<id>.<digest-prefix>`. The
    /// `ckpt.` domain prefix keeps it greppable; the 32-hex-char prefix
    /// (128 bits) binds it to content per spec D3.
    #[must_use]
    pub fn encode_token(&self) -> String {
        let digest = self.digest();
        let hex = digest.trim_start_matches("sha256:");
        format!("ckpt.{}.{}", self.id, &hex[..TOKEN_DIGEST_PREFIX_LEN])
    }

    /// Whether a decoded token digest prefix equals this record's
    /// digest prefix — the store's post-resolve staleness check.
    #[must_use]
    pub fn token_matches(&self, digest_prefix: &str) -> bool {
        self.digest()
            .trim_start_matches("sha256:")
            .starts_with(digest_prefix)
    }
}

/// Hex chars of the digest prefix the resume token carries.
const TOKEN_DIGEST_PREFIX_LEN: usize = 32;

/// A decoded resume token: the checkpoint identity plus the embedded
/// digest prefix, shape-validated only — resolving and comparing are
/// the caller's job (a resolved row whose prefix differs is
/// `RESUME_TOKEN_STALE`, never a decode error).
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedToken {
    /// The checkpoint identity the token names.
    pub checkpoint_id: ResumeCheckpointId,
    /// The embedded lowercase-hex digest prefix (≤ 64 chars).
    pub digest_prefix: String,
}

/// Parses `ckpt.<id>.<digest-prefix>` — the opaque resume token.
/// Malformed input is `RESUME_TOKEN_STALE` (the upstream rule: a stale
/// or forged token is a stale token, not a crash).
pub fn decode_resume_token(token: &str) -> Result<DecodedToken, Failure> {
    let stale = |detail: &'static str| Failure::invalid(codes::RESUME_TOKEN_STALE, detail);
    let mut segments = token.splitn(3, '.');
    if segments.next() != Some("ckpt") {
        return Err(stale("the token is not a ckpt triple"));
    }
    let id = segments
        .next()
        .ok_or_else(|| stale("the token carries no checkpoint id"))?
        .parse::<ResumeCheckpointId>()
        .map_err(|_| stale("the token carries an invalid checkpoint id"))?;
    let digest = segments
        .next()
        .ok_or_else(|| stale("the token carries no digest"))?;
    if digest.is_empty()
        || digest.len() > 64
        || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        || digest != digest.to_lowercase()
    {
        return Err(stale("the token digest is not lowercase hex"));
    }
    Ok(DecodedToken {
        checkpoint_id: id,
        digest_prefix: digest.to_string(),
    })
}

/// Selects the checkpoint ids GC may delete among `candidates` at `now`
/// (spec D5) — pure selection; the caller deletes and journals
/// `checkpoint_gc_collected` per id.
///
/// - `pinned` is never collected, whatever `expires_at` says;
/// - `run_terminal` collects once `created_at` ages past
///   [`RUN_TERMINAL_RETENTION`];
/// - `supersedeable` collects when `expires_at` has passed, or when a
///   newer same-anchor `(run_id, node_id)` checkpoint pushes it past
///   [`SUPERSEDEABLE_KEEP_LATEST`].
///
/// Candidates must carry every row of the anchors under consideration;
/// rows of anchors not represented are unaffected. The result is
/// sorted by id for a deterministic commit order.
#[must_use]
pub fn gc_pick(candidates: &[ResumeCheckpoint], now: OffsetDateTime) -> Vec<ResumeCheckpointId> {
    use std::collections::BTreeMap;

    let mut supersedeable: BTreeMap<(RunId, WorkflowNodeId), Vec<&ResumeCheckpoint>> =
        BTreeMap::new();
    let mut out: Vec<ResumeCheckpointId> = Vec::new();
    for c in candidates {
        match c.gc_class {
            GcClass::Pinned => {}
            GcClass::RunTerminal => {
                if !(c.created_at + RUN_TERMINAL_RETENTION > now) {
                    out.push(c.id);
                }
            }
            GcClass::Supersedeable => {
                if c.expires_at.is_some_and(|e| e <= now) {
                    out.push(c.id);
                    continue;
                }
                supersedeable
                    .entry((c.run_id, c.node_id))
                    .or_default()
                    .push(c);
            }
        }
    }
    for (_, mut group) in supersedeable {
        // Newest-first; created_at then id keeps the order total and
        // deterministic on a shared timestamp.
        group.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        out.extend(group.iter().skip(SUPERSEDEABLE_KEEP_LATEST).map(|c| c.id));
    }
    out.sort();
    out
}

/// Lowercase-hex encodes a digest — the `sha256:` digest text.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::failure::FailureKind;
    use central_foundation::identity::SessionAttemptId;

    const T0: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn payload_bytes() -> &'static [u8] {
        br#"{"schema_version":1,"producer_version":"1.0","continuation":{"state":"ready","cursor":"c","sequence":1,"summary":"s","metadata":{"source":"x"}},"metadata":{"sequence":1}}"#
    }

    fn checkpoint() -> Checkpoint {
        CheckpointIntent {
            workspace_id: WorkspaceId::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: None,
            step_attempt_id: None,
            kind: CheckpointKind::StepBoundary,
            producer_id: "central-executor".into(),
            producer_version: "1.0".into(),
            schema_version: 1,
            policy_fingerprint: "sha256:pol".into(),
            agent_revision_fingerprint: "sha256:agent".into(),
            payload: CheckpointPayload::sanitize(payload_bytes(), DEFAULT_INLINE_PAYLOAD_LIMIT)
                .unwrap(),
            metadata: None,
            eligible_after: T0 + Duration::days(90),
            legal_hold: false,
            source_checkpoint_id: None,
        }
        .seal(T0)
        .unwrap()
    }

    fn all_good() -> CompatibilityFacts {
        CompatibilityFacts {
            lease_held: true,
            reader_schema_version: CURRENT_SCHEMA_VERSION,
            producer_known: true,
            agent_revision_matches: true,
            policy_fingerprint_matches: true,
            artifacts_ready: true,
            evidence_consistent: true,
        }
    }

    // -- payload -----------------------------------------------------------------

    #[test]
    fn payload_enforces_strict_schema_and_canonical_encoding() {
        let p = CheckpointPayload::sanitize(payload_bytes(), DEFAULT_INLINE_PAYLOAD_LIMIT).unwrap();
        let text = String::from_utf8(p.as_bytes().to_vec()).unwrap();
        assert!(text.starts_with(r#"{"continuation":{"cursor":"#));
        assert_eq!(p.declared_schema_version(), Some(1));

        for raw in [
            &b"not json"[..],
            br#"{"schema_version":1} trailing"#,
            br#"[1]"#,
            br#"{"unknown_field":1}"#,
            br#"{"schema_version":1,"secret":"x"}"#,
            br#"{"schema_version":{"deep":1}}"#,
            br#"{"continuation":"scalar"}"#,
        ] {
            assert!(
                CheckpointPayload::sanitize(raw, DEFAULT_INLINE_PAYLOAD_LIMIT).is_err(),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn size_policy_bounds_installed_limit() {
        validate_inline_limit(DEFAULT_INLINE_PAYLOAD_LIMIT).unwrap();
        validate_inline_limit(MAX_CHECKPOINT_PAYLOAD_BYTES).unwrap();
        assert!(validate_inline_limit(0).is_err());
        assert!(validate_inline_limit(MAX_CHECKPOINT_PAYLOAD_BYTES + 1).is_err());

        let big = format!(
            r#"{{"schema_version":1,"producer_version":"{}"}}"#,
            "x".repeat(300 * 1024)
        );
        // exceeds default, fits hard max? — no, schema rejects 'x' as leaf? it is a leaf — allowed.
        assert_eq!(
            CheckpointPayload::sanitize(big.as_bytes(), DEFAULT_INLINE_PAYLOAD_LIMIT)
                .unwrap_err()
                .code(),
            codes::PAYLOAD_TOO_LARGE
        );
        CheckpointPayload::sanitize(big.as_bytes(), MAX_CHECKPOINT_PAYLOAD_BYTES).unwrap();
    }

    // -- record --------------------------------------------------------------------

    #[test]
    fn kind_vocabulary_is_closed() {
        for (text, kind) in [
            ("run_start", CheckpointKind::RunStart),
            ("run_complete", CheckpointKind::RunComplete),
            ("step_boundary", CheckpointKind::StepBoundary),
            ("external_effect", CheckpointKind::ExternalEffect),
            ("recovery", CheckpointKind::Recovery),
        ] {
            assert_eq!(CheckpointKind::parse(text).unwrap(), kind);
            assert_eq!(kind.as_str(), text);
        }
        assert!(CheckpointKind::parse("other").is_err());
    }

    #[test]
    fn record_carries_persistable_b08_columns() {
        let c = checkpoint();
        // `policy_version` — the literal upstream `queryInsertCheckpoint`
        // fixes at 1; `metadata` — the b08-nullable column upstream
        // leaves NULL.
        assert_eq!(c.policy_version, CURRENT_POLICY_VERSION);
        assert!(c.metadata.is_none());

        let mut with_metadata = c.clone();
        with_metadata.metadata = Some(serde_json::json!({"source": "test"}));
        with_metadata.validate().unwrap();

        let mut oversized = c;
        oversized.metadata = Some(serde_json::json!({
            "blob": "x".repeat(MAX_METADATA_BYTES)
        }));
        assert_eq!(
            oversized.validate().unwrap_err().code(),
            codes::CHECKPOINT_INVALID
        );
    }

    #[test]
    fn checksum_binds_payload_exactly() {
        let c = checkpoint();
        c.validate().unwrap();
        assert_eq!(payload_checksum(c.payload.as_bytes()), c.checksum);

        let mut forged = c.clone();
        forged.checksum[0] ^= 0xff;
        assert_eq!(
            forged.validate().unwrap_err().code(),
            codes::CHECKSUM_MISMATCH
        );
    }

    #[test]
    fn compatibility_checks_run_in_order_and_first_failure_wins() {
        let c = checkpoint();
        c.verify_compatibility(&all_good()).unwrap();

        type Case = (fn(&mut CompatibilityFacts), &'static str);
        let cases: [Case; 7] = [
            (
                |f: &mut CompatibilityFacts| f.lease_held = false,
                codes::OWNERSHIP_MISSING,
            ),
            (
                |f: &mut CompatibilityFacts| f.reader_schema_version = 99,
                codes::SCHEMA_INCOMPATIBLE,
            ),
            (
                |f: &mut CompatibilityFacts| f.producer_known = false,
                codes::PRODUCER_UNKNOWN,
            ),
            (
                |f: &mut CompatibilityFacts| f.agent_revision_matches = false,
                codes::AGENT_REVISION_MISMATCH,
            ),
            (
                |f: &mut CompatibilityFacts| f.policy_fingerprint_matches = false,
                codes::POLICY_MISMATCH,
            ),
            (
                |f: &mut CompatibilityFacts| f.artifacts_ready = false,
                codes::ARTIFACT_MISSING,
            ),
            (
                |f: &mut CompatibilityFacts| f.evidence_consistent = false,
                codes::EVIDENCE_INCONSISTENT,
            ),
        ];
        for (mutate, code) in cases {
            let mut facts = all_good();
            mutate(&mut facts);
            let err = c.verify_compatibility(&facts).unwrap_err();
            assert_eq!(err.code(), code);
        }

        // Checksum is check 1 — a corrupted record fails before any fact.
        let mut forged = checkpoint();
        forged.checksum[0] ^= 0xff;
        assert_eq!(
            forged.verify_compatibility(&all_good()).unwrap_err().code(),
            codes::CHECKSUM_MISMATCH
        );
    }

    #[test]
    fn migration_preserves_source_and_records_lineage() {
        let source = checkpoint();
        let new_payload =
            CheckpointPayload::sanitize(payload_bytes(), DEFAULT_INLINE_PAYLOAD_LIMIT).unwrap();
        let migrated = source
            .evaluate_migration(MigrationRequest {
                migration_path_registered: true,
                new_payload,
                new_schema_version: 1,
                new_policy_fingerprint: "sha256:pol2".into(),
                new_agent_revision_fingerprint: "sha256:agent".into(),
                producer_version: "2.0".into(),
                at: T0 + Duration::hours(1),
                eligible_after: T0 + Duration::days(90),
            })
            .unwrap();
        assert_eq!(migrated.source_checkpoint_id, Some(source.id));
        assert_eq!(migrated.producer_version, "2.0");
        assert_ne!(migrated.id, source.id);
        assert!(source.source_checkpoint_id.is_none(), "source preserved");

        let err = source
            .evaluate_migration(MigrationRequest {
                migration_path_registered: false,
                new_payload: CheckpointPayload::sanitize(
                    payload_bytes(),
                    DEFAULT_INLINE_PAYLOAD_LIMIT,
                )
                .unwrap(),
                new_schema_version: 1,
                new_policy_fingerprint: "sha256:x".into(),
                new_agent_revision_fingerprint: "sha256:y".into(),
                producer_version: "2.0".into(),
                at: T0,
                eligible_after: T0,
            })
            .unwrap_err();
        assert_eq!(err.code(), codes::MIGRATION_UNSUPPORTED);
    }

    // -- b36: boundary legality --------------------------------------------------------

    #[test]
    fn boundary_legal_matches_spec_d2() {
        for (attempt, node, fin, legal) in [
            ("succeeded", "succeeded", false, true),
            ("ambiguous", "attempt_ambiguous", false, true),
            ("failed", "failed_terminal", false, true),
            ("cancelled", "cancelled", false, true),
            ("claimed", "dispatched", false, false),
            ("provisioning", "ready", false, false),
            ("started", "running", false, false),
            ("succeeded", "running", false, false), // node in invoke window
            ("succeeded", "declared", true, false), // artifact mid-finalization
            ("bogus", "succeeded", false, false),
            ("succeeded", "bogus", false, false),
        ] {
            let result = boundary_legal(attempt, node, fin);
            assert_eq!(result.is_ok(), legal, "{attempt}/{node}/fin={fin}");
            if let Err(f) = result {
                assert_eq!(f.code(), codes::BOUNDARY_ILLEGAL);
                assert_eq!(f.kind(), FailureKind::Denied);
            }
        }
    }

    #[test]
    fn resume_format_compatibility_is_exact() {
        resume_format_compatible(RESUME_FORMAT_VERSION, GRAPH_SCHEMA_VERSION).unwrap();
        for (f, g) in [
            ("other", GRAPH_SCHEMA_VERSION),
            (RESUME_FORMAT_VERSION, "other"),
            ("", ""),
        ] {
            assert_eq!(
                resume_format_compatible(f, g).unwrap_err().code(),
                codes::FORMAT_INCOMPATIBLE
            );
        }
    }

    // -- b36: token + digest -------------------------------------------------------------

    fn resume(seq: i64) -> ResumeCheckpoint {
        let row = ResumeCheckpoint {
            id: ResumeCheckpointId::new(),
            workspace_id: WorkspaceId::new(),
            run_id: RunId::new(),
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
            checkpoint_seq: seq,
            format_version: RESUME_FORMAT_VERSION.into(),
            graph_schema_version: GRAPH_SCHEMA_VERSION.into(),
            event_watermark: 10,
            harness_session_id: Some("hs-1".into()),
            workspace_digest: Some("sha256:dd".into()),
            workspace_path: Some("/w".into()),
            completed_nodes: vec!["n2".into(), "n1".into()],
            finalized_artifacts: vec![ArtifactId::new()],
            in_flight_nodes: vec!["n3".into()],
            gc_class: GcClass::Supersedeable,
            created_at: T0,
            expires_at: None,
            content_digest: String::new(),
        };
        let digest = row.digest();
        ResumeCheckpoint {
            content_digest: digest,
            ..row
        }
    }

    #[test]
    fn token_round_trips_and_binds_content() {
        let row = resume(1);
        let token = row.encode_token();
        assert!(token.starts_with("ckpt."));
        let decoded = decode_resume_token(&token).unwrap();
        assert_eq!(decoded.checkpoint_id, row.id);
        assert!(row.token_matches(&decoded.digest_prefix));

        // Content drift breaks the match — the upstream staleness rule.
        let mut drifted = row.clone();
        drifted.event_watermark = 99;
        assert!(!drifted.token_matches(&decoded.digest_prefix));

        for bad in ["", "x.y.z", "ckpt.not-uuid.ab12", "ckpt..", "ckpt.a.AB12"] {
            assert_eq!(
                decode_resume_token(bad).unwrap_err().code(),
                codes::RESUME_TOKEN_STALE,
                "{bad}"
            );
        }
    }

    #[test]
    fn fingerprint_is_order_invariant_and_content_sensitive() {
        let a = resume(3);
        let mut b = a.clone();
        b.completed_nodes.reverse();
        b.in_flight_nodes.reverse();
        assert_eq!(
            a.fingerprint(),
            b.fingerprint(),
            "set order must not matter"
        );

        b.completed_nodes.push("extra".into());
        assert_ne!(a.fingerprint(), b.fingerprint());
        // GC bookkeeping is excluded from the fingerprint AND the digest.
        let mut c = a.clone();
        c.gc_class = GcClass::Pinned;
        c.expires_at = Some(T0 + Duration::days(1));
        assert_ne!(a.fingerprint(), c.fingerprint(), "gc_class is bound");
        assert_eq!(
            a.digest(),
            c.digest(),
            "gc bookkeeping never stales a token"
        );
    }

    // -- b36: GC -------------------------------------------------------------------------

    #[test]
    fn gc_pick_respects_classes_and_keep_latest() {
        let ws = WorkspaceId::new();
        let run = RunId::new();
        let node = WorkflowNodeId::new();
        let anchor = |seq: i64, class: GcClass, created: OffsetDateTime| {
            let mut r = resume(seq);
            r.workspace_id = ws;
            r.run_id = run;
            r.node_id = node;
            r.gc_class = class;
            r.created_at = created;
            r
        };
        let mut candidates = vec![];
        // 5 supersedeable on one anchor → oldest 2 collected.
        for i in 0..5 {
            candidates.push(anchor(i, GcClass::Supersedeable, T0 + Duration::minutes(i)));
        }
        // Pinned — never collected even when expired.
        let mut pinned = anchor(10, GcClass::Pinned, T0 - Duration::days(365));
        pinned.expires_at = Some(T0 - Duration::days(1));
        candidates.push(pinned.clone());
        // run_terminal inside and past the 30-day window.
        candidates.push(anchor(11, GcClass::RunTerminal, T0 - Duration::days(20)));
        candidates.push(anchor(12, GcClass::RunTerminal, T0 - Duration::days(31)));
        // Expired supersedeable — collected regardless of keep-latest.
        let mut expired = anchor(13, GcClass::Supersedeable, T0 + Duration::days(10));
        expired.expires_at = Some(T0 - Duration::days(1));
        let expired_id = expired.id;
        candidates.push(expired);

        let picks = gc_pick(&candidates, T0);
        assert_eq!(picks.len(), 4);
        assert!(picks.contains(&candidates[0].id)); // oldest supersedeable
        assert!(picks.contains(&candidates[1].id)); // second-oldest
        assert!(picks.contains(&candidates[7].id)); // aged run_terminal
        assert!(picks.contains(&expired_id));
        assert!(!picks.contains(&pinned.id));
    }

    // -- upstream domain_test.go: TestGCClassVocabularyIsClosedAndOrdered ----------

    #[test]
    fn gc_class_vocabulary_is_closed_and_ordered() {
        assert_eq!(
            GcClass::ALL,
            [
                GcClass::Supersedeable,
                GcClass::RunTerminal,
                GcClass::Pinned
            ],
            "ALL is the spec's declaration order — supersedeable first"
        );
        for class in GcClass::ALL {
            assert_eq!(GcClass::parse(class.as_str()).unwrap(), class);
        }
        assert!(GcClass::parse("other").is_err());
    }

    // -- upstream domain_test.go: TestReasonCodesAreClosedSpecVocabulary -----------

    #[test]
    fn resume_reason_codes_are_closed_spec_vocabulary() {
        let spec3: [&str; 7] = [
            codes::BOUNDARY_ILLEGAL,
            codes::RESUME_TOKEN_STALE,
            codes::FORMAT_INCOMPATIBLE,
            codes::WORKSPACE_DIGEST_MISMATCH,
            codes::RESUME_ARTIFACT_MISSING,
            codes::RESUME_REQUIRES_OPERATOR,
            codes::DUPLICATE_IDEMPOTENCY,
        ];
        for (index, code) in spec3.iter().enumerate() {
            // Spec-3 codes are SCREAMING_CASE and pairwise distinct.
            assert_eq!(*code, code.to_uppercase(), "{code}");
            assert!(!spec3[..index].contains(code), "duplicate code {code}");
        }
    }

    // -- upstream domain_test.go: TestDigestIsCanonicalOverInventoryOrder ----------

    #[test]
    fn digest_is_canonical_over_inventory_order() {
        let mut a = resume(1);
        let mut b = a.clone();
        b.completed_nodes.reverse();
        b.finalized_artifacts.reverse();
        b.in_flight_nodes.reverse();
        assert_eq!(a.digest(), b.digest(), "set order must not matter");
        a.completed_nodes.push("extra".into());
        assert_ne!(a.digest(), b.digest());
    }
}
