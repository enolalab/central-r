//! Artifact domain — pure synchronous port of
//! `central/internal/artifact/domain.go` (the B10 lifecycle), plus the
//! workspace-scoped two-phase deletion/tombstone transitions
//! (`docs/artifacts/lifecycle.md`, adapter-mapping §3.9–§3.10) and the
//! content-policy delivery/preview disposition evaluator
//! (`docs/artifacts/content-policy.md`) that upstream implements outside
//! this package.
//!
//! It contains no persistence, transport, or object-storage
//! implementation. All functions return new values; callers persist
//! approved transitions atomically through the artifact application and
//! adapter boundaries. This module never depends on `sqlx`, `aws-sdk-s3`,
//! `tokio`, or `uuid` — all UUID work goes through
//! `central_foundation::identity` and it never reads a clock: every
//! timestamp arrives as caller-supplied durable evidence.

use std::fmt;

use central_foundation::failure::{Failure as FoundationFailure, FailureKind};
use central_foundation::identity::{
    ArtifactId, ArtifactTombstoneId, ContentGeneration, RunId, StagingGeneration, StepAttemptId,
    StepId, TaskId, ToolCallAttemptId, WorkspaceId,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Failure
// ---------------------------------------------------------------------------

/// A stable, safe Artifact-domain error category. It is never combined
/// with body bytes, raw names, object-store locators, or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// `INVALID` — caller input is malformed.
    Invalid,
    /// `CONFLICT` — request conflicts with current durable state.
    Conflict,
    /// `DENIED` — the workspace/artifact chain does not match.
    Denied,
}

impl FailureClass {
    /// The persisted upstream text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID",
            Self::Conflict => "CONFLICT",
            Self::Denied => "DENIED",
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed Artifact-domain failure returned at invariant boundaries.
///
/// `reason` is a closed machine-readable value; `Display` deliberately
/// excludes selectors, bodies, keys, and other sensitive input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The error category.
    pub class: FailureClass,
    /// The closed machine-readable reason (upstream `Reason`).
    pub reason: &'static str,
}

impl Failure {
    /// Builds a domain failure from a closed class and reason.
    #[must_use]
    pub const fn new(class: FailureClass, reason: &'static str) -> Self {
        Self { class, reason }
    }
}

impl fmt::Display for Failure {
    /// `"artifact: {class} ({reason})"` — closed tokens only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "artifact: {} ({})", self.class, self.reason)
    }
}

impl std::error::Error for Failure {}

/// Maps a domain failure onto the shared foundation taxonomy:
/// `class` becomes the `FailureKind`, `reason` the stable machine `code`,
/// and the message is the domain failure's already-redacted `Display`.
impl From<Failure> for FoundationFailure {
    fn from(failure: Failure) -> Self {
        let kind = match failure.class {
            FailureClass::Invalid => FailureKind::Invalid,
            FailureClass::Conflict => FailureKind::Conflict,
            FailureClass::Denied => FailureKind::Denied,
        };
        FoundationFailure::new(kind, failure.reason, failure.to_string())
    }
}

// ---------------------------------------------------------------------------
// Limits: the B09 required-report class (distinct from any generic body cap)
// ---------------------------------------------------------------------------

/// The B09 required-Markdown-report size class: 1 MiB default. This class
/// is intentionally distinct from the much larger generic Artifact body
/// ceiling used elsewhere in the capability, which bounds any
/// object-store body regardless of required-report policy.
pub const DEFAULT_REQUIRED_REPORT_MAX_BYTES: i64 = 1 << 20;

/// The B09 required-Markdown-report hard maximum: 10 MiB.
pub const HARD_REQUIRED_REPORT_MAX_BYTES: i64 = 10 << 20;

/// The raw-body bound one inline preview may render: 128 KiB.
///
/// Deliberately far smaller than [`DEFAULT_REQUIRED_REPORT_MAX_BYTES`]:
/// HTML escaping expands every HTML-significant byte up to 5x
/// (`&` → `&amp;`), so bounding the raw read to 128 KiB keeps the
/// worst-case escaped body comfortably under the transport's buffered
/// response cap. A larger body previews as a visibly-flagged truncation,
/// never a rejection — the full content remains downloadable.
/// (`artifactPreviewMaxBytes` in upstream `ServeArtifactPreview`.)
pub const ARTIFACT_PREVIEW_MAX_BYTES: i64 = 128 * 1024;

/// The installed size ceiling snapshot for one required report Artifact.
/// It must never exceed [`HARD_REQUIRED_REPORT_MAX_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Installed per-artifact body ceiling in bytes.
    pub max_bytes: i64,
}

impl Default for Limits {
    /// The B10 default required-report limit.
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_REQUIRED_REPORT_MAX_BYTES,
        }
    }
}

impl Limits {
    /// Reports a [`Failure`] when `max_bytes` is not a positive value
    /// within the hard required-report ceiling.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.max_bytes <= 0 || self.max_bytes > HARD_REQUIRED_REPORT_MAX_BYTES {
            return Err(Failure::new(FailureClass::Invalid, "INVALID_LIMITS"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic reservation identity
// ---------------------------------------------------------------------------

/// Domain separator for the derived ArtifactId (upstream
/// `derivedUUID("central.b10.reservation-artifact-id/v1", input, 7)`).
const RESERVATION_ARTIFACT_ID_DOMAIN: &str = "central.b10.reservation-artifact-id/v1";
/// Domain separator for the derived StagingGeneration (upstream
/// `derivedUUID("central.b10.reservation-staging-generation/v1", input, 4)`).
const RESERVATION_STAGING_GENERATION_DOMAIN: &str = "central.b10.reservation-staging-generation/v1";

/// The first 16 bytes of `SHA-256(domain || "\x00" || input)` — upstream
/// `derivedUUID`'s preimage, byte for byte.
fn derived_digest_prefix(domain: &str, input: &str) -> [u8; 16] {
    let mut preimage = Vec::with_capacity(domain.len() + 1 + input.len());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(input.as_bytes());
    let sum: [u8; 32] = Sha256::digest(&preimage).into();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&sum[..16]);
    raw
}

/// Projects one stable operation identity onto the [`ArtifactId`] and
/// [`StagingGeneration`] a Reserve command for it must always use —
/// upstream `DeriveReservationIdentity`, deterministic and byte-for-byte
/// identical.
///
/// It exists because Reserve's durable receipt is keyed on the caller's
/// idempotency key but *fingerprinted* over the reservation's full
/// canonical content — which includes both of these identities. A caller
/// that mints them randomly per call derives a different fingerprint on
/// every attempt under the same operation identity, and its intended
/// replay is rejected as an idempotency conflict for the receipt's whole
/// retention window, defeating the "replay with the exact command
/// identity returns the durable prior result" crash-recovery contract.
///
/// Only a caller that genuinely has a stable, collision-resistant
/// operation identity may use this: the derived values are a pure
/// function of that identity, so two distinct reservations sharing one
/// operation identity would collide on the same Artifact. A caller
/// without such an identity must keep minting fresh random values, which
/// remains correct.
///
/// The derived ArtifactId is UUIDv7-shaped and the StagingGeneration
/// UUIDv4-shaped because the persisted columns and their parsers require
/// exactly those versions. The v7 timestamp prefix is necessarily
/// pseudo-random here — a deterministic function of a non-temporal input
/// cannot carry a real timestamp — which costs some index locality on
/// the Artifact primary key and buys the replay contract. Row ordering
/// for reconciliation is taken from `created_at`, never from this id, so
/// nothing else depends on the lost ordering.
///
/// The upstream error arms for the derived parses are unreachable here:
/// the digest constructors force the version nibble, so a nil identity
/// is impossible by construction.
pub fn derive_reservation_identity(
    operation_id: &str,
) -> Result<(ArtifactId, StagingGeneration), Failure> {
    if operation_id.is_empty() {
        return Err(Failure::new(
            FailureClass::Invalid,
            "INVALID_OPERATION_IDENTITY",
        ));
    }
    Ok((
        ArtifactId::from_v7_digest_bytes(derived_digest_prefix(
            RESERVATION_ARTIFACT_ID_DOMAIN,
            operation_id,
        )),
        StagingGeneration::from_v4_digest_bytes(derived_digest_prefix(
            RESERVATION_STAGING_GENERATION_DOMAIN,
            operation_id,
        )),
    ))
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The closed B10 lifecycle state — the seven persisted values of
/// `central.artifacts.state` plus `rejected` (adapter-mapping §3.9,
/// `artifacts_state_b10_check`).
///
/// `DeletePending`, `Deleted`, and `Quarantined` have no B10 command
/// surface: `DeletePending`/`Deleted` are driven only by the two-phase
/// deletion transitions below, and `Quarantined` is the restore-time
/// holding state no artifact-domain command produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// `reserved` — reservation admitted; no body byte staged yet.
    Reserved,
    /// `staging` — a producer is streaming to the unique staging key.
    Staging,
    /// `verifying` — staged body verified; promotion/finalize pending.
    Verifying,
    /// `ready` — immutable verified body at its ready key.
    Ready,
    /// `rejected` — terminally rejected staging generation.
    Rejected,
    /// `delete_pending` — durable delete intent before object deletion.
    DeletePending,
    /// `deleted` — terminal tombstoned state; never becomes ready again.
    Deleted,
    /// `quarantined` — post-restore integrity quarantine.
    Quarantined,
}

impl State {
    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Staging => "staging",
            Self::Verifying => "verifying",
            Self::Ready => "ready",
            Self::Rejected => "rejected",
            Self::DeletePending => "delete_pending",
            Self::Deleted => "deleted",
            Self::Quarantined => "quarantined",
        }
    }

    /// Parses the persisted form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reserved" => Some(Self::Reserved),
            "staging" => Some(Self::Staging),
            "verifying" => Some(Self::Verifying),
            "ready" => Some(Self::Ready),
            "rejected" => Some(Self::Rejected),
            "delete_pending" => Some(Self::DeletePending),
            "deleted" => Some(Self::Deleted),
            "quarantined" => Some(Self::Quarantined),
            _ => None,
        }
    }

    /// Reports whether `self` may move to `next` under the B10 command
    /// matrix. Ready and Rejected are terminal; the deletion states are
    /// driven only by the two-phase deletion functions, never through
    /// this table.
    fn can_transition_to(self, next: State) -> bool {
        match self {
            Self::Reserved => matches!(next, Self::Staging | Self::Rejected),
            Self::Staging => matches!(next, Self::Verifying | Self::Rejected),
            Self::Verifying => matches!(next, Self::Ready | Self::Rejected),
            _ => false,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The closed sensitivity classification persisted at reservation time
/// (`central.artifacts.sensitivity`). It is derived only from trusted
/// producer context and policy — never from Task text, filenames, or
/// declared media types — and never changes after reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    /// `unrestricted` — preview-eligible when content allows.
    Unrestricted,
    /// `restricted` — download-only; never inline-previewed.
    Restricted,
    /// `sensitive` — download-only with the generic binary fallback
    /// type; never inline-previewed.
    Sensitive,
}

impl Sensitivity {
    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Restricted => "restricted",
            Self::Sensitive => "sensitive",
        }
    }

    /// Parses the persisted form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "unrestricted" => Some(Self::Unrestricted),
            "restricted" => Some(Self::Restricted),
            "sensitive" => Some(Self::Sensitive),
            _ => None,
        }
    }
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Selects inline-preview vs. attachment-download delivery semantics,
/// persisted at reservation time (`central.artifacts.disposition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// `inline` — sanitized inline preview.
    Inline,
    /// `attachment` — download-only.
    Attachment,
}

impl Disposition {
    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Attachment => "attachment",
        }
    }

    /// Parses the persisted form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inline" => Some(Self::Inline),
            "attachment" => Some(Self::Attachment),
            _ => None,
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Artifact: the pure lifecycle snapshot
// ---------------------------------------------------------------------------

/// The pure lifecycle snapshot a caller evaluates a command against. It
/// carries no adapter-specific representation and no raw object-store
/// locator beyond its own opaque derived keys.
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// This artifact.
    pub artifact_id: ArtifactId,
    /// Current lifecycle state.
    pub state: State,
    /// Optimistic-concurrency version.
    pub version: i64,
    /// The one-time staging generation bound at Reserve.
    pub staging_generation: StagingGeneration,
    /// The derived opaque staging key (`v1/staging/...`).
    pub staging_key: String,
    /// The one-time content generation bound at Promotion (`None` until
    /// promoted — upstream's zero `ContentGeneration`).
    pub content_generation: Option<ContentGeneration>,
    /// The derived opaque ready key (`v1/ready/...`), empty until
    /// promoted.
    pub ready_key: String,
    /// The installed limits snapshot in force since reservation.
    pub limits: Limits,
    /// Verified full-body size recorded by Verified.
    pub verified_size: i64,
    /// Verified full-body SHA-256 recorded by Verified.
    pub verified_checksum: [u8; 32],
    /// Object-version (or ETag) evidence bound to the verified ready
    /// object at finalization, where the store exposes it. Empty when
    /// the store exposes no version evidence — it is never itself proof
    /// of readiness; size and checksum always are.
    pub ready_object_version: String,
    /// Durable producer chain the reservation was made against;
    /// `central.artifacts` requires them as foreign-keyed state from the
    /// moment a row is created.
    pub task_id: TaskId,
    /// Producer chain: run.
    pub run_id: RunId,
    /// Producer chain: step.
    pub step_id: StepId,
    /// Producer chain: step attempt.
    pub step_attempt_id: StepAttemptId,
    /// Optional tool-call attempt (`None` = no associated Tool call —
    /// upstream's zero `ToolCallAttemptID`).
    pub tool_call_attempt_id: Option<ToolCallAttemptId>,
    /// Producer identity.
    pub producer_id: String,
    /// Optional required-output role.
    pub required_role: String,
    /// Persisted sensitivity classification.
    pub sensitivity: Sensitivity,
    /// Persisted delivery disposition.
    pub disposition: Disposition,
    /// Durable delete intent recorded by `mark_delete_pending`; `None`
    /// means no delete intent and delivery may proceed.
    pub delete_intent_at: Option<OffsetDateTime>,
    /// Durable deletion completion recorded by `complete_deletion`;
    /// `None` while the record is not deleted.
    pub deleted_at: Option<OffsetDateTime>,
}

/// The opaque staging key:
/// `v1/staging/<workspace-opaque-id>/<artifact-opaque-id>/<staging-generation>`.
fn staging_key(
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
    generation: StagingGeneration,
) -> String {
    format!("v1/staging/{workspace_id}/{artifact_id}/{generation}")
}

/// The opaque ready key:
/// `v1/ready/<workspace-opaque-id>/<artifact-opaque-id>/<content-generation>`.
fn ready_key_for(
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
    generation: ContentGeneration,
) -> String {
    format!("v1/ready/{workspace_id}/{artifact_id}/{generation}")
}

/// Reports whether the caller-declared selector matches `current`'s own
/// identity. It fails closed on a nil selector so a caller/adapter bug
/// can never operate on unrelated `current` state supplied by mistake,
/// and it is the sole gate against cross-workspace command chains.
fn chain_matches(workspace_id: WorkspaceId, artifact_id: ArtifactId, current: &Artifact) -> bool {
    !workspace_id.is_nil()
        && !artifact_id.is_nil()
        && workspace_id == current.workspace_id
        && artifact_id == current.artifact_id
}

// ---------------------------------------------------------------------------
// CommandIdentity
// ---------------------------------------------------------------------------

/// The closed set of B10 lifecycle commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandStage {
    /// `reserve`.
    Reserve,
    /// `begin_upload`.
    BeginUpload,
    /// `verify`.
    Verify,
    /// `promote`.
    Promote,
    /// `finalize`.
    Finalize,
    /// `reject`.
    Reject,
}

impl CommandStage {
    /// The persisted text form (`artifact_command_receipts.command_kind`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserve => "reserve",
            Self::BeginUpload => "begin_upload",
            Self::Verify => "verify",
            Self::Promote => "promote",
            Self::Finalize => "finalize",
            Self::Reject => "reject",
        }
    }
}

impl fmt::Display for CommandStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The stable, stage-scoped identity used to detect an exact replay
/// before any new transition, quota effect, or completion contribution.
/// Only the fields relevant to its originating stage are populated; a
/// caller must compare the whole value, never a single field, to decide
/// a replay match.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandIdentity {
    /// Originating lifecycle command.
    pub stage: CommandStage,
    /// Workspace the command operates on.
    pub workspace_id: WorkspaceId,
    /// Artifact the command operates on.
    pub artifact_id: ArtifactId,
    /// Expected durable version the command was evaluated against.
    pub expected_version: i64,
    /// Staging generation bound into the command (`None` when the stage
    /// does not carry it — upstream's zero `StagingGeneration`).
    pub staging_generation: Option<StagingGeneration>,
    /// Content generation bound into the command (`None` when the stage
    /// does not carry it).
    pub content_generation: Option<ContentGeneration>,
    /// Ready key bound into promote/finalize commands.
    pub ready_key: String,
    /// Verified size bound into finalize commands.
    pub verified_size: i64,
    /// Verified checksum bound into finalize commands.
    pub verified_checksum: [u8; 32],
    /// Caller idempotency key (reserve only).
    pub idempotency_key: String,
    /// SHA-256 over the canonical command content (reserve only).
    pub fingerprint: [u8; 32],
    /// Populated only by Verify/Reject: the closed reason the rejection
    /// was driven by. It binds the command identity to that exact cause,
    /// so a rejection for one reason is never an idempotent replay of a
    /// rejection for another at the same expected version. Empty when
    /// the command was not a rejection.
    pub failure_code: String,
}

impl CommandIdentity {
    /// Whether two identities are the exact same command — an exact
    /// replay rather than a merely similar one.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self == other
    }
}

/// Binds a Reserve command to the exact inputs it may admit or replay.
/// Any workspace, artifact, generation, limits, or idempotency-key
/// change is a distinct command.
///
/// The canonical payload is upstream `reserveFingerprint`'s JSON struct
/// byte for byte: fields in declaration order, compact separators, the
/// two optional fields (`tool_call_attempt_id`, `required_role`)
/// omitted exactly like Go's `,omitempty` when empty, and Go
/// `encoding/json` string escaping — `\"`, `\\`, `\n`, `\r`, `\t`,
/// `\u00xx` for other control characters (never `\b`/`\f`), and
/// `&`/`<`/`>`/U+2028/U+2029 — so a fingerprint computed here
/// equals one the Go implementation would have produced for the same
/// reservation.
fn reserve_fingerprint(input: &ReserveInput<'_>) -> [u8; 32] {
    let mut canonical = Vec::with_capacity(512);
    canonical.push(b'{');
    let mut first = true;
    let workspace = input.workspace_id.to_string();
    push_json_field(&mut canonical, &mut first, "workspace_id", &workspace);
    let artifact = input.artifact_id.to_string();
    push_json_field(&mut canonical, &mut first, "artifact_id", &artifact);
    let generation = input.staging_generation.to_string();
    push_json_field(
        &mut canonical,
        &mut first,
        "staging_generation",
        &generation,
    );
    push_json_i64_field(
        &mut canonical,
        &mut first,
        "max_bytes",
        input.limits.max_bytes,
    );
    push_json_field(
        &mut canonical,
        &mut first,
        "idempotency_key",
        input.idempotency_key,
    );
    let task = input.task_id.to_string();
    push_json_field(&mut canonical, &mut first, "task_id", &task);
    let run = input.run_id.to_string();
    push_json_field(&mut canonical, &mut first, "run_id", &run);
    let step = input.step_id.to_string();
    push_json_field(&mut canonical, &mut first, "step_id", &step);
    let step_attempt = input.step_attempt_id.to_string();
    push_json_field(&mut canonical, &mut first, "step_attempt_id", &step_attempt);
    push_json_field(&mut canonical, &mut first, "producer_id", input.producer_id);
    // `tool_call_attempt_id` and `required_role` complete the
    // reservation's canonical content. Both are optional — not every
    // reservation originates inside a Tool call, and not every Artifact
    // is a required output — so both are omitted when empty, matching
    // how upstream's `,omitempty` drops them.
    //
    // They belong here because they are genuinely part of what a
    // reservation is: two reservations that agree on everything else but
    // disagree on which required-output role they satisfy are different
    // commands, and must not replay one another.
    let tool_call_attempt = input
        .tool_call_attempt_id
        .map_or(String::new(), |id| id.to_string());
    if !tool_call_attempt.is_empty() {
        push_json_field(
            &mut canonical,
            &mut first,
            "tool_call_attempt_id",
            &tool_call_attempt,
        );
    }
    if !input.required_role.is_empty() {
        push_json_field(
            &mut canonical,
            &mut first,
            "required_role",
            input.required_role,
        );
    }
    canonical.push(b'}');
    Sha256::digest(&canonical).into()
}

/// Writes one `"name":"value"` pair, honoring the running `first` flag.
fn push_json_field(buf: &mut Vec<u8>, first: &mut bool, name: &str, value: &str) {
    if !*first {
        buf.push(b',');
    }
    *first = false;
    push_json_string(buf, name);
    buf.push(b':');
    push_json_string(buf, value);
}

/// Writes one `"name":<int>` pair, honoring the running `first` flag.
fn push_json_i64_field(buf: &mut Vec<u8>, first: &mut bool, name: &str, value: i64) {
    if !*first {
        buf.push(b',');
    }
    *first = false;
    push_json_string(buf, name);
    buf.push(b':');
    buf.extend_from_slice(value.to_string().as_bytes());
}

/// Writes `value` as a Go `encoding/json` string literal: the exact
/// escaping `json.Marshal` applies — `\u003c`, `\u003e`, `\u0026` (its
/// always-on HTMLEscape), `\u2028`/`\u2029`, `\u00xx` for control
/// characters including `\u0008`/`\u000c` (Go has no `\b`/`\f`
/// shortcuts), and the `\n`/`\r`/`\t` shortcuts. Rust `&str` input is
/// always valid UTF-8, so Go's invalid-UTF-8 → `\ufffd` arm is
/// unreachable by construction.
fn push_json_string(buf: &mut Vec<u8>, value: &str) {
    buf.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\n' => buf.extend_from_slice(b"\\n"),
            '\r' => buf.extend_from_slice(b"\\r"),
            '\t' => buf.extend_from_slice(b"\\t"),
            '<' => buf.extend_from_slice(b"\\u003c"),
            '>' => buf.extend_from_slice(b"\\u003e"),
            '&' => buf.extend_from_slice(b"\\u0026"),
            '\u{2028}' => buf.extend_from_slice(b"\\u2028"),
            '\u{2029}' => buf.extend_from_slice(b"\\u2029"),
            c if (c as u32) < 0x20 => {
                buf.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut encoded = [0u8; 4];
                buf.extend_from_slice(c.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    buf.push(b'"');
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// Classifies a terminal or ambiguous B10 lifecycle result for the
/// owning B08 StepAttempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeKind {
    /// `ready` — the required Artifact reached the ready state and may
    /// contribute to B08 completion.
    Ready,
    /// `retryable` — a known non-delivery or transient dependency
    /// failure occurred; only a new Artifact reservation and staging
    /// generation may retry.
    Retryable,
    /// `terminal` — an integrity, limit, policy, or secret-disclosure
    /// failure occurred; it is never retried.
    Terminal,
    /// `reconciliation` — an ambiguous object-store result occurred
    /// after acceptance; B08's reconciliation path owns it.
    Reconciliation,
}

impl OutcomeKind {
    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
            Self::Reconciliation => "reconciliation",
        }
    }
}

impl fmt::Display for OutcomeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed, safe classification returned to B08 for a required
/// Artifact. `failure_code` is a closed reason code; it never carries
/// body bytes, raw names, object-store locators, or secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The outcome classification.
    pub kind: OutcomeKind,
    /// The closed failure code (empty for a successful outcome).
    pub failure_code: String,
}

/// Known upload non-delivery: the body certainly never landed, so the
/// reservation is released immediately rather than waiting for the
/// staging-lifetime sweep.
pub const FAILURE_CODE_UPLOAD_NON_DELIVERY: &str = "UPLOAD_NON_DELIVERY";
/// A reserved record with no begun upload that reached the installed
/// staging lifetime.
pub const FAILURE_CODE_RESERVATION_EXPIRED: &str = "RESERVATION_LIFETIME_EXPIRED";
/// A staging record with no active claim that reached the installed
/// staging lifetime.
pub const FAILURE_CODE_STAGING_EXPIRED: &str = "STAGING_LIFETIME_EXPIRED";
/// Body size exceeded the installed required-report limits.
pub const FAILURE_CODE_SIZE_LIMIT_EXCEEDED: &str = "SIZE_LIMIT_EXCEEDED";
/// Missing or invalid full-body SHA-256 checksum.
pub const FAILURE_CODE_CHECKSUM_INVALID: &str = "INVALID_CHECKSUM";
/// Suspected secret disclosure in the staged body.
pub const FAILURE_CODE_SECRET_DISCLOSURE: &str = "SECRET_DISCLOSURE";
/// Bounded content-policy rejection other than suspected secret
/// disclosure.
pub const FAILURE_CODE_CONTENT_POLICY: &str = "CONTENT_POLICY_REJECTED";
/// Bounded content-policy rejection for an unsupported media type.
pub const FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE: &str = "UNSUPPORTED_MEDIA_TYPE";

/// Reports whether `reason` is one of the closed content-policy
/// rejection codes Verified may act on. A Classifier that returns
/// anything else has violated its port contract, and Verified fails
/// closed rather than guessing why a body was rejected.
#[must_use]
pub fn classifier_rejection_admitted(reason: &str) -> bool {
    matches!(
        reason,
        FAILURE_CODE_SECRET_DISCLOSURE
            | FAILURE_CODE_CONTENT_POLICY
            | FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE
    )
}

/// Maps a closed rejection reason to the [`Outcome`] B08 consumes. It is
/// the single place the retryable/terminal split for a rejected Artifact
/// is decided, so a durable replay reconstructs exactly the Outcome the
/// original command produced.
///
/// Expiry and known non-delivery are retryable: a replacement must use a
/// new Artifact and staging generation. Limit, integrity, and policy
/// causes are terminal and are never retried. An unrecognised reason
/// fails closed.
pub fn rejection_outcome(reason: &str) -> Result<Outcome, Failure> {
    let kind = match reason {
        FAILURE_CODE_UPLOAD_NON_DELIVERY
        | FAILURE_CODE_RESERVATION_EXPIRED
        | FAILURE_CODE_STAGING_EXPIRED => OutcomeKind::Retryable,
        FAILURE_CODE_SIZE_LIMIT_EXCEEDED
        | FAILURE_CODE_CHECKSUM_INVALID
        | FAILURE_CODE_SECRET_DISCLOSURE
        | FAILURE_CODE_CONTENT_POLICY
        | FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE => OutcomeKind::Terminal,
        _ => {
            return Err(Failure::new(
                FailureClass::Invalid,
                "INVALID_REJECTION_REASON",
            ));
        }
    };
    Ok(Outcome {
        kind,
        failure_code: reason.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Reserve
// ---------------------------------------------------------------------------

/// The caller-supplied selector, generation, and limits snapshot for a
/// fresh Artifact reservation.
#[derive(Debug, Clone)]
pub struct ReserveInput<'a> {
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Fresh artifact identity.
    pub artifact_id: ArtifactId,
    /// Fresh one-time staging generation.
    pub staging_generation: StagingGeneration,
    /// Installed limits snapshot.
    pub limits: Limits,
    /// Caller idempotency key.
    pub idempotency_key: &'a str,
    /// Producer chain — required: `central.artifacts` persists it as
    /// foreign-keyed state from the moment the row is created.
    pub task_id: TaskId,
    /// Producer chain: run (required).
    pub run_id: RunId,
    /// Producer chain: step (required).
    pub step_id: StepId,
    /// Producer chain: step attempt (required).
    pub step_attempt_id: StepAttemptId,
    /// Optional tool-call attempt (`None` is valid — not every Step
    /// attempt has a tool call).
    pub tool_call_attempt_id: Option<ToolCallAttemptId>,
    /// Producer identity (required, non-empty).
    pub producer_id: &'a str,
    /// Optional required-output role.
    pub required_role: &'a str,
}

/// The pure outcome of [`reserve`]: a new reserved Artifact and its
/// replay identity.
#[derive(Debug, Clone)]
pub struct ReserveResult {
    /// The newly reserved artifact snapshot.
    pub artifact: Artifact,
    /// The reserve command identity.
    pub identity: CommandIdentity,
}

/// Derives the opaque staging key for a fresh Artifact and admits it in
/// the reserved state. It performs no I/O and never accepts a
/// caller-controlled key or path fragment.
pub fn reserve(input: &ReserveInput<'_>) -> Result<ReserveResult, Failure> {
    if input.workspace_id.is_nil()
        || input.artifact_id.is_nil()
        || input.staging_generation.is_nil()
        || input.task_id.is_nil()
        || input.run_id.is_nil()
        || input.step_id.is_nil()
        || input.step_attempt_id.is_nil()
        || input.producer_id.is_empty()
    {
        return Err(Failure::new(FailureClass::Invalid, "INVALID_RESERVE_INPUT"));
    }
    input.limits.validate()?;
    let artifact = Artifact {
        workspace_id: input.workspace_id,
        artifact_id: input.artifact_id,
        state: State::Reserved,
        version: 1,
        staging_generation: input.staging_generation,
        staging_key: staging_key(
            input.workspace_id,
            input.artifact_id,
            input.staging_generation,
        ),
        content_generation: None,
        ready_key: String::new(),
        limits: input.limits,
        verified_size: 0,
        verified_checksum: [0; 32],
        ready_object_version: String::new(),
        task_id: input.task_id,
        run_id: input.run_id,
        step_id: input.step_id,
        step_attempt_id: input.step_attempt_id,
        tool_call_attempt_id: input.tool_call_attempt_id,
        producer_id: input.producer_id.to_owned(),
        required_role: input.required_role.to_owned(),
        // The persisted reservation-time defaults — the insert fixes
        // 'restricted'/'attachment' until trusted classification says
        // otherwise (content-policy.md: uncertainty is restricted).
        sensitivity: Sensitivity::Restricted,
        disposition: Disposition::Attachment,
        delete_intent_at: None,
        deleted_at: None,
    };
    Ok(ReserveResult {
        artifact,
        identity: CommandIdentity {
            stage: CommandStage::Reserve,
            workspace_id: input.workspace_id,
            artifact_id: input.artifact_id,
            expected_version: 0,
            staging_generation: Some(input.staging_generation),
            content_generation: None,
            ready_key: String::new(),
            verified_size: 0,
            verified_checksum: [0; 32],
            idempotency_key: input.idempotency_key.to_owned(),
            fingerprint: reserve_fingerprint(input),
            failure_code: String::new(),
        },
    })
}

// ---------------------------------------------------------------------------
// BeginUpload
// ---------------------------------------------------------------------------

/// Binds the BeginUpload command to a caller-declared selector, the
/// current durable snapshot, and its expected version.
#[derive(Debug, Clone)]
pub struct BeginUploadInput {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
}

/// The pure outcome of [`begin_upload`].
#[derive(Debug, Clone)]
pub struct BeginUploadResult {
    /// The artifact snapshot after the transition.
    pub artifact: Artifact,
    /// The begin-upload command identity.
    pub identity: CommandIdentity,
}

/// Records the reserved-to-staging transition before any object body
/// byte is written. It never itself performs streaming I/O.
pub fn begin_upload(input: &BeginUploadInput) -> Result<BeginUploadResult, Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if !input.current.state.can_transition_to(State::Staging) {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }
    let mut next = input.current.clone();
    next.state = State::Staging;
    next.version += 1;
    Ok(BeginUploadResult {
        identity: CommandIdentity {
            stage: CommandStage::BeginUpload,
            workspace_id: next.workspace_id,
            artifact_id: next.artifact_id,
            expected_version: input.expected,
            staging_generation: Some(next.staging_generation),
            content_generation: None,
            ready_key: String::new(),
            verified_size: 0,
            verified_checksum: [0; 32],
            idempotency_key: String::new(),
            fingerprint: [0; 32],
            failure_code: String::new(),
        },
        artifact: next,
    })
}

// ---------------------------------------------------------------------------
// Verified
// ---------------------------------------------------------------------------

/// Carries the full-body size, SHA-256 checksum, and secret-disclosure
/// classification decision computed by the caller after reading the
/// staged object. [`verified`] itself performs no I/O.
#[derive(Debug, Clone)]
pub struct VerifiedInput<'a> {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
    /// Recomputed full-body size.
    pub size: i64,
    /// Recomputed full-body SHA-256.
    pub checksum: [u8; 32],
    /// The Classifier's suspected-secret decision. It takes precedence
    /// over `rejection_code` so a body suspected of disclosing a secret
    /// always rejects with [`FAILURE_CODE_SECRET_DISCLOSURE`], whatever
    /// else the Classifier also reported.
    pub secret_disclosure: bool,
    /// The Classifier's content-policy rejection reason for a cause
    /// other than secret disclosure. It must be one of the closed codes
    /// [`classifier_rejection_admitted`] accepts; anything else fails
    /// closed.
    ///
    /// Carrying it here — rather than letting the caller act on it after
    /// the verify transition has already committed — is what makes a
    /// policy rejection atomic with verification: a rejected body never
    /// reaches the verifying state at all, so it can never strand a
    /// reservation that no later pass revisits.
    pub rejection_code: &'a str,
}

/// The pure outcome of [`verified`]. A successful body still in progress
/// carries `outcome: None`; a rejected body carries a terminal `Outcome`
/// and the Rejected state.
#[derive(Debug, Clone)]
pub struct VerifiedResult {
    /// The artifact snapshot after the transition.
    pub artifact: Artifact,
    /// The verify command identity.
    pub identity: CommandIdentity,
    /// `Some` only for a rejection — the outcome B08 consumes.
    pub outcome: Option<Outcome>,
}

/// Applies the B10 verification invariants: size within the installed
/// Limits, a present 32-byte checksum, and no suspected secret
/// disclosure. Any failure rejects the Artifact and releases it from
/// further promotion; it never overwrites a rejected record with a later
/// retry.
pub fn verified(input: &VerifiedInput<'_>) -> Result<VerifiedResult, Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if input.current.state != State::Staging {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }

    let mut next = input.current.clone();
    next.version += 1;

    let mut identity = CommandIdentity {
        stage: CommandStage::Verify,
        workspace_id: next.workspace_id,
        artifact_id: next.artifact_id,
        expected_version: input.expected,
        staging_generation: Some(next.staging_generation),
        content_generation: None,
        ready_key: String::new(),
        verified_size: 0,
        verified_checksum: [0; 32],
        idempotency_key: String::new(),
        fingerprint: [0; 32],
        failure_code: String::new(),
    };

    // Every rejecting branch binds its own closed reason into the
    // command identity, exactly as `CommandIdentity::failure_code`
    // documents. Leaving it unset on any of them would let an accepted
    // verify and a rejection — or two rejections for different reasons —
    // share one identity at the same expected version, so the second
    // would replay the first's durable result instead of being refused.
    if input.size <= 0 || input.size > input.current.limits.max_bytes {
        next.state = State::Rejected;
        identity.failure_code = FAILURE_CODE_SIZE_LIMIT_EXCEEDED.to_owned();
        return Ok(VerifiedResult {
            artifact: next,
            identity,
            outcome: Some(Outcome {
                kind: OutcomeKind::Terminal,
                failure_code: FAILURE_CODE_SIZE_LIMIT_EXCEEDED.to_owned(),
            }),
        });
    }
    if input.checksum == [0; 32] {
        next.state = State::Rejected;
        identity.failure_code = FAILURE_CODE_CHECKSUM_INVALID.to_owned();
        return Ok(VerifiedResult {
            artifact: next,
            identity,
            outcome: Some(Outcome {
                kind: OutcomeKind::Terminal,
                failure_code: FAILURE_CODE_CHECKSUM_INVALID.to_owned(),
            }),
        });
    }
    if input.secret_disclosure || !input.rejection_code.is_empty() {
        // Suspected secret disclosure keeps its own specific code
        // whatever else the Classifier reported alongside it.
        let reason = if input.secret_disclosure {
            FAILURE_CODE_SECRET_DISCLOSURE
        } else {
            input.rejection_code
        };
        if !classifier_rejection_admitted(reason) {
            return Err(Failure::new(
                FailureClass::Invalid,
                "INVALID_CLASSIFIER_REJECTION",
            ));
        }
        let outcome = rejection_outcome(reason)?;
        next.state = State::Rejected;
        identity.failure_code = reason.to_owned();
        return Ok(VerifiedResult {
            artifact: next,
            identity,
            outcome: Some(outcome),
        });
    }

    next.state = State::Verifying;
    next.verified_size = input.size;
    next.verified_checksum = input.checksum;
    Ok(VerifiedResult {
        artifact: next,
        identity,
        outcome: None,
    })
}

// ---------------------------------------------------------------------------
// Reject
// ---------------------------------------------------------------------------

/// Binds the Reject command to a caller-declared selector, the current
/// durable snapshot, its expected version, and one closed rejection
/// reason. [`reject`] performs no I/O.
#[derive(Debug, Clone)]
pub struct RejectInput<'a> {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
    /// One of the closed `FAILURE_CODE_*` values [`rejection_outcome`]
    /// admits. It is never caller-formatted text.
    pub reason: &'a str,
}

/// The pure outcome of [`reject`]: the Artifact reaches Rejected and
/// carries the Outcome its reason maps to.
#[derive(Debug, Clone)]
pub struct RejectResult {
    /// The artifact snapshot after the transition.
    pub artifact: Artifact,
    /// The reject command identity.
    pub identity: CommandIdentity,
    /// The outcome B08 consumes.
    pub outcome: Outcome,
}

/// Drives the already-legal reserved-or-staging to rejected transition
/// for a cause that is known before (or instead of) verification: a
/// known upload non-delivery, or a reserved/staging record that reached
/// the installed staging lifetime.
///
/// It is deliberately distinct from [`verified`], whose rejections all
/// describe evidence computed from a fully staged body. Requiring
/// reserved or staging keeps a finalizable verifying record — and an
/// already terminal one — outside this command entirely; it adds no edge
/// to the state machine. Persisting the result is what releases the
/// reservation, exactly once.
pub fn reject(input: &RejectInput<'_>) -> Result<RejectResult, Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if input.current.state != State::Reserved && input.current.state != State::Staging {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }
    let outcome = rejection_outcome(input.reason)?;

    let mut next = input.current.clone();
    next.state = State::Rejected;
    next.version += 1;

    Ok(RejectResult {
        artifact: next.clone(),
        identity: CommandIdentity {
            stage: CommandStage::Reject,
            workspace_id: next.workspace_id,
            artifact_id: next.artifact_id,
            expected_version: input.expected,
            staging_generation: Some(next.staging_generation),
            content_generation: None,
            ready_key: String::new(),
            verified_size: 0,
            verified_checksum: [0; 32],
            idempotency_key: String::new(),
            fingerprint: [0; 32],
            failure_code: input.reason.to_owned(),
        },
        outcome,
    })
}

// ---------------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------------

/// Binds the Promotion command to a fresh, caller-minted
/// [`ContentGeneration`]. It never reuses a generation already assigned
/// to the current Artifact.
#[derive(Debug, Clone)]
pub struct PromotionInput {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
    /// Fresh one-time content generation.
    pub content_generation: ContentGeneration,
}

/// The pure outcome of [`promotion`]. The state remains Verifying: only
/// [`finalize`], after a second verification, moves it to Ready.
#[derive(Debug, Clone)]
pub struct PromotionResult {
    /// The artifact snapshot after the transition.
    pub artifact: Artifact,
    /// The promote command identity.
    pub identity: CommandIdentity,
}

/// Derives the opaque ready key for a fresh [`ContentGeneration`]. It
/// rejects reuse of an already-assigned ready key, matching the
/// immutable, non-overwriting promotion invariant.
pub fn promotion(input: &PromotionInput) -> Result<PromotionResult, Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if input.current.state != State::Verifying {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }
    if input.content_generation.is_nil() {
        return Err(Failure::new(
            FailureClass::Invalid,
            "INVALID_CONTENT_GENERATION",
        ));
    }
    if !input.current.ready_key.is_empty() {
        return Err(Failure::new(
            FailureClass::Conflict,
            "READY_KEY_ALREADY_ASSIGNED",
        ));
    }

    let mut next = input.current.clone();
    next.version += 1;
    next.content_generation = Some(input.content_generation);
    next.ready_key = ready_key_for(
        next.workspace_id,
        next.artifact_id,
        input.content_generation,
    );

    Ok(PromotionResult {
        identity: CommandIdentity {
            stage: CommandStage::Promote,
            workspace_id: next.workspace_id,
            artifact_id: next.artifact_id,
            expected_version: input.expected,
            staging_generation: None,
            content_generation: Some(input.content_generation),
            ready_key: next.ready_key.clone(),
            verified_size: 0,
            verified_checksum: [0; 32],
            idempotency_key: String::new(),
            fingerprint: [0; 32],
            failure_code: String::new(),
        },
        artifact: next,
    })
}

// ---------------------------------------------------------------------------
// Finalize
// ---------------------------------------------------------------------------

/// Binds the Finalize command to the verified size/checksum produced by
/// Verified. Finalize requires a prior Promotion (a present ready key
/// and content generation).
#[derive(Debug, Clone)]
pub struct FinalizeInput {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
    /// Caller-supplied promoted-object size, checked against recorded
    /// verified evidence.
    pub size: i64,
    /// Caller-supplied promoted-object checksum, checked against
    /// recorded verified evidence.
    pub checksum: [u8; 32],
    /// Object-version evidence the caller observed for the promoted
    /// object. Optional — a store that exposes no version evidence
    /// finalizes with an empty value — and deliberately not part of the
    /// Finalize command identity: it is evidence bound to the ready
    /// object, never a component of replay identity.
    pub ready_object_version: String,
}

/// The pure outcome of [`finalize`]: the Artifact reaches Ready with
/// immutable integrity evidence, or the command fails closed.
#[derive(Debug, Clone)]
pub struct FinalizeResult {
    /// The artifact snapshot after the transition.
    pub artifact: Artifact,
    /// The finalize command identity.
    pub identity: CommandIdentity,
    /// The ready outcome B08 consumes.
    pub outcome: Outcome,
}

/// Atomically records the ready transition once the caller-supplied
/// size and checksum exactly match the evidence Verified already
/// recorded. No preceding step may complete a required output; only
/// Finalize's success carries [`OutcomeKind::Ready`].
pub fn finalize(input: &FinalizeInput) -> Result<FinalizeResult, Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if !input.current.state.can_transition_to(State::Ready) {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }
    // A `Some(nil)` content generation — reachable only through a
    // corrupted `from_trusted_db_bytes` snapshot — is a missing
    // promotion, matching upstream's `ContentGeneration.IsZero()` gate.
    if input.current.ready_key.is_empty()
        || input
            .current
            .content_generation
            .is_none_or(|generation| generation.is_nil())
    {
        return Err(Failure::new(FailureClass::Invalid, "MISSING_PROMOTION"));
    }

    let mut identity = new_finalize_identity(&input.current, input.size, &input.checksum)?;
    identity.expected_version = input.expected;

    let mut next = input.current.clone();
    next.state = State::Ready;
    next.version += 1;
    if !input.ready_object_version.is_empty() {
        next.ready_object_version
            .clone_from(&input.ready_object_version);
    }

    Ok(FinalizeResult {
        artifact: next,
        identity,
        outcome: Outcome {
            kind: OutcomeKind::Ready,
            failure_code: String::new(),
        },
    })
}

/// Binds the Finalize command to the exact verified integrity evidence
/// Verified already recorded on `current`. A mismatched size or checksum
/// fails closed as a conflict before any finalization effect: it never
/// lets a caller-supplied value stand in for previously verified
/// evidence.
pub fn new_finalize_identity(
    current: &Artifact,
    size: i64,
    checksum: &[u8; 32],
) -> Result<CommandIdentity, Failure> {
    if size <= 0 || *checksum == [0; 32] {
        return Err(Failure::new(
            FailureClass::Invalid,
            "INVALID_FINALIZE_IDENTITY",
        ));
    }
    if current.verified_size != size || current.verified_checksum != *checksum {
        return Err(Failure::new(
            FailureClass::Conflict,
            "FINALIZE_IDENTITY_MISMATCH",
        ));
    }
    Ok(CommandIdentity {
        stage: CommandStage::Finalize,
        workspace_id: current.workspace_id,
        artifact_id: current.artifact_id,
        expected_version: 0,
        staging_generation: None,
        content_generation: current.content_generation,
        ready_key: current.ready_key.clone(),
        verified_size: size,
        verified_checksum: *checksum,
        idempotency_key: String::new(),
        fingerprint: [0; 32],
        failure_code: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Two-phase workspace-scoped deletion & tombstone
// (docs/artifacts/lifecycle.md §Delete intent and tombstone;
// adapter-mapping §3.9 artifacts / §3.10 artifact_tombstones)
// ---------------------------------------------------------------------------

/// Durable non-body evidence that a delete intent and outcome occurred —
/// the `central.artifact_tombstones` row (§3.10). It preserves safe
/// lineage only: it grants no body access, is append-only, and prevents
/// object-key and content-generation reuse so a deleted body cannot be
/// resurrected at the same key.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactTombstone {
    /// Fresh tombstone identity.
    pub id: ArtifactTombstoneId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// The deleted artifact.
    pub artifact_id: ArtifactId,
    /// The object key whose body was deleted (the ready key when
    /// assigned, else the staging key).
    pub object_key: String,
    /// The artifact's one-time staging generation, retained so it can
    /// never be reused.
    pub staging_generation: StagingGeneration,
    /// The verified body's checksum algorithm (`Some("sha256")` when
    /// verified evidence existed — matches the artifacts row's
    /// `checksum_algorithm` convention).
    pub checksum_algorithm: Option<String>,
    /// The verified body's SHA-256 when verified evidence existed.
    pub checksum_value: Option<[u8; 32]>,
    /// The artifact's size at deletion (the verified body size).
    pub size_at_deletion: i64,
    /// The closed deletion reason — durable, never caller-freeform
    /// markup.
    pub deletion_reason: String,
}

/// The `checksum_algorithm` value every SHA-256-verified body records —
/// the same literal the verification update writes (`'sha256'`).
pub const CHECKSUM_ALGORITHM_SHA256: &str = "sha256";

/// Binds RequestArtifactDeletion to a caller-declared selector, the
/// current durable snapshot, its expected version, and the durable
/// delete-intent timestamp.
#[derive(Debug, Clone)]
pub struct MarkDeletePendingInput {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
    /// The database-derived delete-intent timestamp. The domain never
    /// reads a clock; the caller supplies durable time.
    pub delete_intent_at: OffsetDateTime,
}

/// Records explicit workspace-scoped delete intent *before* any
/// object-store deletion: a ready Artifact enters `delete_pending`, new
/// delivery is prevented, and new finalization is blocked. Delete intent
/// wins any uncommitted finalization — the version-and-state check in
/// the commit path is what makes this durable.
///
/// Requires [`State::Ready`]: only a ready Artifact holds a retained
/// body this command is responsible for deleting. Non-ready records are
/// released through rejection and staging cleanup instead.
pub fn mark_delete_pending(input: &MarkDeletePendingInput) -> Result<Artifact, Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if input.current.state != State::Ready {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }
    let mut next = input.current.clone();
    next.state = State::DeletePending;
    next.version += 1;
    next.delete_intent_at = Some(input.delete_intent_at);
    Ok(next)
}

/// Binds SettleArtifactDeletion to a caller-declared selector, the
/// current durable snapshot, its expected version, a fresh tombstone
/// identity, the closed deletion reason, and the durable completion
/// timestamp.
#[derive(Debug, Clone)]
pub struct CompleteDeletionInput<'a> {
    /// Caller-declared workspace selector.
    pub workspace_id: WorkspaceId,
    /// Caller-declared artifact selector.
    pub artifact_id: ArtifactId,
    /// The current durable snapshot.
    pub current: Artifact,
    /// Expected durable version.
    pub expected: i64,
    /// Fresh tombstone identity minted by the caller.
    pub tombstone_id: ArtifactTombstoneId,
    /// The closed deletion reason persisted on the tombstone — required
    /// non-empty (`artifact_tombstones.deletion_reason` is `NOT NULL`).
    pub deletion_reason: &'a str,
    /// The database-derived deletion-completion timestamp.
    pub deleted_at: OffsetDateTime,
}

/// Records known object deletion after the external delete operation:
/// the Artifact enters `deleted` — terminal and irreversible — and the
/// immutable [`ArtifactTombstone`] preserving safe lineage is returned
/// alongside it for atomic insert in the same commit.
///
/// Accepts [`State::DeletePending`] (the normal settle path after
/// [`mark_delete_pending`]) or [`State::Ready`] (a direct metadata mark
/// where an operator path deletes a retained body in one step — the
/// upstream prune journal's `state = 'deleted'` mark). Every other state
/// fails closed as `INVALID_TRANSITION`. A non-empty `deletion_reason`
/// is always required.
///
/// A deletion retry operates on the same artifact and tombstone identity
/// and is idempotent: the version guard plus the
/// `artifact_tombstones_artifact_id_unique` constraint make a repeated
/// settle return the prior result rather than writing a second
/// tombstone.
pub fn complete_deletion(
    input: &CompleteDeletionInput<'_>,
) -> Result<(Artifact, ArtifactTombstone), Failure> {
    if !chain_matches(input.workspace_id, input.artifact_id, &input.current) {
        return Err(Failure::new(
            FailureClass::Denied,
            "WORKSPACE_CHAIN_MISMATCH",
        ));
    }
    if input.current.version != input.expected {
        return Err(Failure::new(FailureClass::Conflict, "VERSION_CONFLICT"));
    }
    if input.current.state != State::DeletePending && input.current.state != State::Ready {
        return Err(Failure::new(FailureClass::Conflict, "INVALID_TRANSITION"));
    }
    if input.deletion_reason.is_empty() {
        return Err(Failure::new(
            FailureClass::Invalid,
            "INVALID_DELETION_REASON",
        ));
    }
    if input.tombstone_id.is_nil() {
        return Err(Failure::new(
            FailureClass::Invalid,
            "INVALID_TOMBSTONE_IDENTITY",
        ));
    }

    let current = &input.current;
    let verified_body = current.verified_checksum != [0; 32];
    let tombstone = ArtifactTombstone {
        id: input.tombstone_id,
        workspace_id: current.workspace_id,
        artifact_id: current.artifact_id,
        // The body being destroyed lives at the ready key when one was
        // assigned; otherwise the tombstone preserves the staging key so
        // neither key shape can be resurrected.
        object_key: if current.ready_key.is_empty() {
            current.staging_key.clone()
        } else {
            current.ready_key.clone()
        },
        staging_generation: current.staging_generation,
        checksum_algorithm: verified_body.then(|| CHECKSUM_ALGORITHM_SHA256.to_owned()),
        checksum_value: verified_body.then_some(current.verified_checksum),
        size_at_deletion: current.verified_size,
        deletion_reason: input.deletion_reason.to_owned(),
    };

    let mut next = input.current.clone();
    next.state = State::Deleted;
    next.version += 1;
    next.deleted_at = Some(input.deleted_at);
    Ok((next, tombstone))
}

// ---------------------------------------------------------------------------
// Content-policy delivery & preview disposition
// (docs/artifacts/content-policy.md §Disposition, §Preview allowlist,
// §Inspection and preview hard bounds)
// ---------------------------------------------------------------------------

/// The detected-content preview allowlist (R2 scope): bounded escaped
/// plain text, Markdown, and JSON only. Everything else — HTML, SVG,
/// PDF, office documents, archives, scripts, executables, images, and
/// unknown or contradictory content — is download-only.
const PREVIEW_ALLOWLIST: [&str; 3] = ["text/plain", "text/markdown", "application/json"];

/// The explicit fallback `Content-Type` for download-only delivery —
/// never sniffed, never widened.
pub const FALLBACK_MEDIA_TYPE: &str = "application/octet-stream";

/// The pure content-policy decision for one delivery request: the
/// disposition the transport must use, the explicit `Content-Type` it
/// must set (detected classification or the octet-stream fallback —
/// never the producer-declared type and never sniffed), and the raw
/// preview bound with its truncation flag.
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryPolicyDecision<'a> {
    /// The effective disposition. [`Disposition::Inline`] only when
    /// every preview condition held *and* the caller requested it;
    /// [`Disposition::Attachment`] in every other case.
    pub disposition: Disposition,
    /// The explicit `Content-Type` the delivery must set. The detected
    /// type when the content is allowlisted and not `Sensitive`;
    /// [`FALLBACK_MEDIA_TYPE`] otherwise.
    pub media_type: &'a str,
    /// Whether the body cleared the preview gate (unrestricted
    /// sensitivity + allowlisted detected type) — independent of the
    /// requested disposition.
    pub preview_permitted: bool,
    /// The raw preview read bound ([`ARTIFACT_PREVIEW_MAX_BYTES`]).
    pub preview_max_bytes: i64,
    /// Whether the preview is a truncated prefix of the body
    /// (`verified_size` over the bound). Always `false` when the
    /// decision is not inline.
    pub preview_truncated: bool,
}

/// Evaluates the delivery/preview disposition policy over a ready
/// Artifact's durable classification evidence.
///
/// Rules (`content-policy.md`): the baseline and default disposition is
/// attachment. Inline preview is permitted only when *all* of the
/// following hold — the detected content is on the preview allowlist,
/// the Artifact is `Unrestricted` (a `Restricted` or `Sensitive`
/// Artifact is never inline-previewed regardless of detected media
/// type), and the caller requested inline delivery. Any failure falls
/// back to `Attachment`: allowlisted non-sensitive content keeps its
/// detected explicit type; unallowlisted, undetected, or `Sensitive`
/// content takes the `application/octet-stream` fallback so the
/// download is always explicit and `nosniff`-safe. A preview larger
/// than [`ARTIFACT_PREVIEW_MAX_BYTES`] renders as a visibly-flagged
/// truncation, never a rejection.
#[must_use]
pub fn evaluate_delivery_policy<'a>(
    detected_media_type: Option<&'a str>,
    sensitivity: Sensitivity,
    requested_disposition: Disposition,
    verified_size: i64,
) -> DeliveryPolicyDecision<'a> {
    let allowlisted = detected_media_type.is_some_and(|t| PREVIEW_ALLOWLIST.contains(&t));
    let preview_permitted = matches!(sensitivity, Sensitivity::Unrestricted) && allowlisted;
    if preview_permitted && requested_disposition == Disposition::Inline {
        return DeliveryPolicyDecision {
            disposition: Disposition::Inline,
            // `allowlisted` proves `detected_media_type` is `Some`.
            media_type: detected_media_type.unwrap_or(FALLBACK_MEDIA_TYPE),
            preview_permitted: true,
            preview_max_bytes: ARTIFACT_PREVIEW_MAX_BYTES,
            preview_truncated: verified_size > ARTIFACT_PREVIEW_MAX_BYTES,
        };
    }
    let media_type = if allowlisted && !matches!(sensitivity, Sensitivity::Sensitive) {
        // Download-only delivery still sets the explicit detected type —
        // the policy's `nosniff` + attachment disposition is what makes
        // it safe, not hiding the classification.
        detected_media_type.unwrap_or(FALLBACK_MEDIA_TYPE)
    } else {
        FALLBACK_MEDIA_TYPE
    };
    DeliveryPolicyDecision {
        disposition: Disposition::Attachment,
        media_type,
        preview_permitted,
        preview_max_bytes: ARTIFACT_PREVIEW_MAX_BYTES,
        preview_truncated: false,
    }
}

// ---------------------------------------------------------------------------
// Tests — port of `domain_test.go`, `fingerprint_coverage_test.go`, plus
// two-phase deletion and content-policy coverage.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors upstream `requireFailureClass`: only the closed class is
    // asserted — never reason text beyond the codes the domain owns.
    #[track_caller]
    fn require_failure_class(err: Result<impl fmt::Debug, Failure>, want: FailureClass) {
        // `unwrap_err` reports the unexpected Ok value on failure —
        // unwraps are allowed in test code per clippy.toml.
        let failure = err.unwrap_err();
        assert_eq!(failure.class, want, "expected class {want:?}");
    }

    /// Upstream `validReserveInput`: fresh identities and a complete
    /// required producer chain.
    fn valid_reserve_input() -> ReserveInput<'static> {
        ReserveInput {
            workspace_id: WorkspaceId::new(),
            artifact_id: ArtifactId::new(),
            staging_generation: StagingGeneration::new(),
            limits: Limits::default(),
            idempotency_key: "",
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            tool_call_attempt_id: None,
            producer_id: "test-producer",
            required_role: "",
        }
    }

    fn reserved_artifact() -> Artifact {
        reserve(&valid_reserve_input()).unwrap().artifact
    }

    fn staging_artifact() -> Artifact {
        let current = reserved_artifact();
        begin_upload(&BeginUploadInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
        })
        .unwrap()
        .artifact
    }

    fn verifying_artifact() -> Artifact {
        let current = staging_artifact();
        verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: 128,
            checksum: Sha256::digest(b"required report body").into(),
            secret_disclosure: false,
            rejection_code: "",
        })
        .unwrap()
        .artifact
    }

    fn promoted_artifact() -> Artifact {
        let current = verifying_artifact();
        promotion(&PromotionInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            content_generation: ContentGeneration::new(),
        })
        .unwrap()
        .artifact
    }

    fn ready_artifact() -> Artifact {
        let current = promoted_artifact();
        finalize(&FinalizeInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: current.verified_size,
            checksum: current.verified_checksum,
            ready_object_version: String::new(),
        })
        .unwrap()
        .artifact
    }

    // -----------------------------------------------------------------
    // Step 1 brief tests (verbatim intent)
    // -----------------------------------------------------------------

    #[test]
    fn reserve_derives_opaque_staging_key() {
        let input = valid_reserve_input();
        let (workspace_id, artifact_id, generation) = (
            input.workspace_id,
            input.artifact_id,
            input.staging_generation,
        );

        let got = reserve(&input).unwrap();
        let want = format!("v1/staging/{workspace_id}/{artifact_id}/{generation}");
        assert_eq!(got.artifact.staging_key, want);
        assert_eq!(got.artifact.state, State::Reserved);
        assert_eq!(got.artifact.task_id, input.task_id);
        assert_eq!(got.artifact.run_id, input.run_id);
        assert_eq!(got.artifact.step_id, input.step_id);
        assert_eq!(got.artifact.step_attempt_id, input.step_attempt_id);
        assert_eq!(got.artifact.producer_id, input.producer_id);
    }

    #[test]
    fn finalize_identity_requires_verified_size_and_checksum() {
        let current = promoted_artifact();
        let mismatched: [u8; 32] = Sha256::digest(b"a different body").into();
        require_failure_class(
            new_finalize_identity(&current, current.verified_size, &mismatched),
            FailureClass::Conflict,
        );
    }

    // -----------------------------------------------------------------
    // Limits
    // -----------------------------------------------------------------

    #[test]
    fn default_limits_uses_report_class_not_generic_body_limit() {
        let limits = Limits::default();
        assert_eq!(limits.max_bytes, DEFAULT_REQUIRED_REPORT_MAX_BYTES);
        assert_eq!(DEFAULT_REQUIRED_REPORT_MAX_BYTES, 1 << 20);
        assert_eq!(HARD_REQUIRED_REPORT_MAX_BYTES, 10 << 20);
    }

    #[test]
    fn reserve_rejects_limits_above_hard_max() {
        let mut input = valid_reserve_input();
        input.limits = Limits {
            max_bytes: HARD_REQUIRED_REPORT_MAX_BYTES + 1,
        };
        require_failure_class(reserve(&input), FailureClass::Invalid);
    }

    #[test]
    fn reserve_rejects_zero_limits() {
        let mut input = valid_reserve_input();
        input.limits = Limits { max_bytes: 0 };
        require_failure_class(reserve(&input), FailureClass::Invalid);
    }

    // -----------------------------------------------------------------
    // Reserve: identity and replay
    // -----------------------------------------------------------------

    #[test]
    fn reserve_rejects_zero_identity() {
        let nil = WorkspaceId::from_trusted_db_bytes([0; 16]);
        let input = ReserveInput {
            workspace_id: nil,
            artifact_id: nil_to_artifact(),
            staging_generation: nil_to_staging(),
            limits: Limits::default(),
            idempotency_key: "",
            task_id: nil_to_task(),
            run_id: nil_to_run(),
            step_id: nil_to_step(),
            step_attempt_id: nil_to_step_attempt(),
            tool_call_attempt_id: None,
            producer_id: "",
            required_role: "",
        };
        require_failure_class(reserve(&input), FailureClass::Invalid);
    }

    // Nil sentinels for zero-value inputs — Go's zero `identity.*ID`.
    fn nil_to_artifact() -> ArtifactId {
        ArtifactId::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_staging() -> StagingGeneration {
        StagingGeneration::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_content() -> ContentGeneration {
        ContentGeneration::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_task() -> TaskId {
        TaskId::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_run() -> RunId {
        RunId::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_step() -> StepId {
        StepId::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_step_attempt() -> StepAttemptId {
        StepAttemptId::from_trusted_db_bytes([0; 16])
    }
    fn nil_to_tombstone() -> ArtifactTombstoneId {
        ArtifactTombstoneId::from_trusted_db_bytes([0; 16])
    }

    /// A test-case mutator applied to a base `ReserveInput`.
    type InputMutator = fn(&mut ReserveInput<'static>);

    /// Each of Task/Run/Step/StepAttempt/ProducerID is independently
    /// required: zeroing any single one must still fail closed as the
    /// same INVALID_RESERVE_INPUT case.
    #[test]
    fn reserve_rejects_missing_producer_chain() {
        let cases: [(&str, InputMutator); 5] = [
            ("task_id", |i| i.task_id = nil_to_task()),
            ("run_id", |i| i.run_id = nil_to_run()),
            ("step_id", |i| i.step_id = nil_to_step()),
            ("step_attempt_id", |i| {
                i.step_attempt_id = nil_to_step_attempt()
            }),
            ("producer_id", |i| i.producer_id = ""),
        ];
        for (name, zero) in cases {
            let mut input = valid_reserve_input();
            zero(&mut input);
            assert!(
                reserve(&input).is_err_and(|f| f.class == FailureClass::Invalid),
                "missing {name} must fail closed as INVALID_RESERVE_INPUT"
            );
        }
    }

    /// ToolCallAttemptID and RequiredRole remain optional: a Reserve
    /// with the full required producer chain but no Tool call or
    /// required role must still succeed.
    #[test]
    fn reserve_accepts_zero_optional_fields() {
        let mut input = valid_reserve_input();
        input.tool_call_attempt_id = None;
        input.required_role = "";
        let got = reserve(&input).unwrap();
        assert!(got.artifact.tool_call_attempt_id.is_none());
        assert_eq!(got.artifact.required_role, "");
    }

    #[test]
    fn reserve_exact_replay_is_deterministic() {
        let mut input = valid_reserve_input();
        input.idempotency_key = "reserve-request-1";
        let first = reserve(&input).unwrap();
        let second = reserve(&input).unwrap();
        assert_eq!(first.artifact.staging_key, second.artifact.staging_key);
        assert!(first.identity.equal(&second.identity));
    }

    #[test]
    fn reserve_differs_by_idempotency_key() {
        let mut base = valid_reserve_input();
        base.idempotency_key = "key-a";
        let mut other = base.clone();
        other.idempotency_key = "key-b";

        let first = reserve(&base).unwrap();
        let second = reserve(&other).unwrap();
        assert!(!first.identity.equal(&second.identity));
    }

    /// A Reserve replay against the same Workspace/Artifact/staging
    /// generation but a different producer chain is a distinct command:
    /// the fingerprint binds the producer chain as part of the command's
    /// own identity.
    #[test]
    fn reserve_differs_by_producer_chain() {
        let mut base = valid_reserve_input();
        base.idempotency_key = "same-idempotency-key";
        let mut other = base.clone();
        other.producer_id = "a-different-producer";

        let first = reserve(&base).unwrap();
        let second = reserve(&other).unwrap();
        assert!(!first.identity.equal(&second.identity));
    }

    // -----------------------------------------------------------------
    // BeginUpload
    // -----------------------------------------------------------------

    #[test]
    fn begin_upload_transitions_reserved_to_staging() {
        let current = reserved_artifact();
        let got = begin_upload(&BeginUploadInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
        })
        .unwrap();
        assert_eq!(got.artifact.state, State::Staging);
        assert_eq!(got.artifact.version, current.version + 1);
    }

    #[test]
    fn begin_upload_rejects_invalid_workspace_chain() {
        let current = reserved_artifact();
        require_failure_class(
            begin_upload(&BeginUploadInput {
                workspace_id: WorkspaceId::new(), // deliberately mismatched
                artifact_id: current.artifact_id,
                current,
                expected: 1,
            }),
            FailureClass::Denied,
        );
    }

    #[test]
    fn begin_upload_rejects_stale_expected_version() {
        let current = reserved_artifact();
        require_failure_class(
            begin_upload(&BeginUploadInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version + 1,
                current,
            }),
            FailureClass::Conflict,
        );
    }

    #[test]
    fn begin_upload_rejects_invalid_transition_from_ready() {
        let mut current = reserved_artifact();
        current.state = State::Ready; // simulate an already-terminal record
        let version = current.version;
        require_failure_class(
            begin_upload(&BeginUploadInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                current,
                expected: version,
            }),
            FailureClass::Conflict,
        );
    }

    // -----------------------------------------------------------------
    // Verified
    // -----------------------------------------------------------------

    #[test]
    fn verified_transitions_to_verifying_on_valid_body() {
        let current = staging_artifact();
        let checksum: [u8; 32] = Sha256::digest(b"required report body").into();
        let got = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: 128,
            checksum,
            secret_disclosure: false,
            rejection_code: "",
        })
        .unwrap();
        assert_eq!(got.artifact.state, State::Verifying);
        assert!(got.outcome.is_none());
        assert_eq!(got.artifact.verified_size, 128);
        assert_eq!(got.artifact.verified_checksum, checksum);
    }

    #[test]
    fn verified_rejects_over_limit_body_with_terminal_outcome() {
        let current = staging_artifact();
        let got = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: current.limits.max_bytes + 1,
            checksum: Sha256::digest(b"oversized").into(),
            secret_disclosure: false,
            rejection_code: "",
        })
        .unwrap();
        assert_eq!(got.artifact.state, State::Rejected);
        let outcome = got.outcome.unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Terminal);
        assert_eq!(outcome.failure_code, FAILURE_CODE_SIZE_LIMIT_EXCEEDED);
    }

    #[test]
    fn verified_rejects_zero_checksum_with_terminal_outcome() {
        let current = staging_artifact();
        let got = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: 10,
            checksum: [0; 32],
            secret_disclosure: false,
            rejection_code: "",
        })
        .unwrap();
        assert_eq!(got.artifact.state, State::Rejected);
        let outcome = got.outcome.unwrap();
        assert_eq!(outcome.failure_code, FAILURE_CODE_CHECKSUM_INVALID);
    }

    #[test]
    fn verified_rejects_suspected_secret_disclosure() {
        let current = staging_artifact();
        let got = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: 10,
            checksum: Sha256::digest(b"x").into(),
            secret_disclosure: true,
            rejection_code: "",
        })
        .unwrap();
        assert_eq!(got.artifact.state, State::Rejected);
        let outcome = got.outcome.unwrap();
        assert_eq!(outcome.failure_code, FAILURE_CODE_SECRET_DISCLOSURE);
    }

    /// The classifier's own closed reason drives the same atomic
    /// verify-time rejection secret disclosure already did — a policy
    /// rejection never reaches the verifying state.
    #[test]
    fn verified_rejects_a_classifier_content_policy_code() {
        for reason in [
            FAILURE_CODE_CONTENT_POLICY,
            FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE,
        ] {
            let current = staging_artifact();
            let got = verified(&VerifiedInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                current: current.clone(),
                expected: current.version,
                size: 10,
                checksum: Sha256::digest(b"x").into(),
                secret_disclosure: false,
                rejection_code: reason,
            })
            .unwrap();
            assert_eq!(got.artifact.state, State::Rejected, "{reason}");
            let outcome = got.outcome.unwrap();
            assert_eq!(outcome.kind, OutcomeKind::Terminal, "{reason}");
            assert_eq!(outcome.failure_code, reason);
            // The command identity binds the cause, so a rejection for
            // one reason is never an idempotent replay of another.
            assert_eq!(got.identity.failure_code, reason);
        }
    }

    /// The specific code is never lost: a body suspected of disclosing a
    /// secret rejects as SECRET_DISCLOSURE even when the classifier also
    /// reported a different policy code.
    #[test]
    fn verified_keeps_secret_disclosure_specific() {
        let current = staging_artifact();
        let got = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: 10,
            checksum: Sha256::digest(b"x").into(),
            secret_disclosure: true,
            rejection_code: FAILURE_CODE_CONTENT_POLICY,
        })
        .unwrap();
        assert_eq!(
            got.outcome.unwrap().failure_code,
            FAILURE_CODE_SECRET_DISCLOSURE
        );
    }

    #[test]
    fn verified_fails_closed_on_an_unknown_classifier_code() {
        let current = staging_artifact();
        let err = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: 10,
            checksum: Sha256::digest(b"x").into(),
            secret_disclosure: false,
            rejection_code: "MADE_UP_REASON",
        });
        require_failure_class(err, FailureClass::Invalid);
        assert!(!classifier_rejection_admitted("MADE_UP_REASON"));
    }

    #[test]
    fn verified_rejects_invalid_transition_from_reserved() {
        let current = reserved_artifact(); // still Reserved, never staged
        require_failure_class(
            verified(&VerifiedInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version,
                size: 1,
                checksum: Sha256::digest(b"x").into(),
                secret_disclosure: false,
                rejection_code: "",
                current,
            }),
            FailureClass::Conflict,
        );
    }

    // -----------------------------------------------------------------
    // Promotion
    // -----------------------------------------------------------------

    #[test]
    fn promotion_derives_opaque_ready_key() {
        let current = verifying_artifact();
        let content_generation = ContentGeneration::new();
        let got = promotion(&PromotionInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            content_generation,
        })
        .unwrap();
        let want = format!(
            "v1/ready/{}/{}/{}",
            current.workspace_id, current.artifact_id, content_generation
        );
        assert_eq!(got.artifact.ready_key, want);
        // Promotion does not itself flip the state to ready; Finalize
        // does, after a second verification confirms the promoted object.
        assert_eq!(got.artifact.state, State::Verifying);
    }

    #[test]
    fn promotion_rejects_ready_key_reuse() {
        let current = verifying_artifact();
        let promoted = promotion(&PromotionInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            content_generation: ContentGeneration::new(),
        })
        .unwrap();
        let second = promotion(&PromotionInput {
            workspace_id: promoted.artifact.workspace_id,
            artifact_id: promoted.artifact.artifact_id,
            expected: promoted.artifact.version,
            content_generation: ContentGeneration::new(),
            current: promoted.artifact,
        });
        require_failure_class(second, FailureClass::Conflict);
    }

    #[test]
    fn promotion_rejects_invalid_workspace_chain() {
        let current = verifying_artifact();
        require_failure_class(
            promotion(&PromotionInput {
                workspace_id: WorkspaceId::new(),
                artifact_id: current.artifact_id,
                expected: current.version,
                content_generation: ContentGeneration::new(),
                current,
            }),
            FailureClass::Denied,
        );
    }

    // -----------------------------------------------------------------
    // Finalize
    // -----------------------------------------------------------------

    #[test]
    fn finalize_transitions_verifying_to_ready() {
        let current = promoted_artifact();
        let got = finalize(&FinalizeInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: current.verified_size,
            checksum: current.verified_checksum,
            ready_object_version: String::new(),
        })
        .unwrap();
        assert_eq!(got.artifact.state, State::Ready);
        assert_eq!(got.outcome.kind, OutcomeKind::Ready);
    }

    #[test]
    fn finalize_rejects_invalid_transition_from_reserved() {
        let current = reserved_artifact();
        require_failure_class(
            finalize(&FinalizeInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version,
                size: 1,
                checksum: Sha256::digest(b"x").into(),
                ready_object_version: String::new(),
                current,
            }),
            FailureClass::Conflict,
        );
    }

    #[test]
    fn finalize_rejects_missing_promotion() {
        let current = verifying_artifact(); // verified but never promoted
        require_failure_class(
            finalize(&FinalizeInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version,
                size: current.verified_size,
                checksum: current.verified_checksum,
                ready_object_version: String::new(),
                current,
            }),
            FailureClass::Invalid,
        );
    }

    #[test]
    fn finalize_rejects_nil_content_generation_as_missing_promotion() {
        // A `Some(nil)` content generation is only reachable through a
        // corrupted `from_trusted_db_bytes` snapshot; the ready key stays
        // assigned so only the nil-generation gate can fire.
        let mut current = promoted_artifact();
        current.content_generation = Some(nil_to_content());
        let failure = finalize(&FinalizeInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            expected: current.version,
            size: current.verified_size,
            checksum: current.verified_checksum,
            ready_object_version: String::new(),
            current,
        })
        .unwrap_err();
        assert_eq!(failure.class, FailureClass::Invalid);
        assert_eq!(failure.reason, "MISSING_PROMOTION");
    }

    #[test]
    fn finalize_identity_rejects_zero_evidence() {
        let current = promoted_artifact();
        require_failure_class(
            new_finalize_identity(&current, 0, &[0; 32]),
            FailureClass::Invalid,
        );
    }

    #[test]
    fn finalize_identity_accepts_matching_evidence() {
        let current = promoted_artifact();
        let got =
            new_finalize_identity(&current, current.verified_size, &current.verified_checksum)
                .unwrap();
        assert_eq!(got.artifact_id, current.artifact_id);
        assert_eq!(got.ready_key, current.ready_key);
    }

    // -----------------------------------------------------------------
    // Opaque generation identities
    // -----------------------------------------------------------------

    #[test]
    fn staging_generation_round_trip() {
        let generation = StagingGeneration::new();
        let parsed = StagingGeneration::parse(&generation.to_string()).unwrap();
        assert_eq!(parsed, generation);
    }

    #[test]
    fn staging_generation_rejects_wrong_uuid_version() {
        // Artifact IDs are UUIDv7; a staging generation must be UUIDv4
        // and reject a v7 value even though both are syntactically valid.
        let wrong = ArtifactId::new().to_string();
        assert!(StagingGeneration::parse(&wrong).is_err());
    }

    #[test]
    fn content_generation_round_trip() {
        let generation = ContentGeneration::new();
        let parsed = ContentGeneration::parse(&generation.to_string()).unwrap();
        assert_eq!(parsed, generation);
    }

    // -----------------------------------------------------------------
    // Reject
    // -----------------------------------------------------------------

    #[test]
    fn reject_moves_reserved_and_staging_to_rejected_with_retryable_outcome() {
        let cases: [(&str, Artifact, &str); 3] = [
            (
                "reserved reservation expiry",
                reserved_artifact(),
                FAILURE_CODE_RESERVATION_EXPIRED,
            ),
            (
                "staging lifetime expiry",
                staging_artifact(),
                FAILURE_CODE_STAGING_EXPIRED,
            ),
            (
                "known upload non-delivery",
                staging_artifact(),
                FAILURE_CODE_UPLOAD_NON_DELIVERY,
            ),
        ];
        for (name, current, reason) in cases {
            let got = reject(&RejectInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version,
                reason,
                current: current.clone(),
            })
            .unwrap();
            assert_eq!(got.artifact.state, State::Rejected, "{name}");
            assert_eq!(got.artifact.version, current.version + 1, "{name}");
            // A replacement requires a new Artifact and staging
            // generation: that is the definition of retryable.
            assert_eq!(got.outcome.kind, OutcomeKind::Retryable, "{name}");
            assert_eq!(got.outcome.failure_code, reason, "{name}");
            assert_eq!(got.identity.stage, CommandStage::Reject, "{name}");
            assert_eq!(got.identity.expected_version, current.version, "{name}");
            assert_eq!(got.identity.failure_code, reason, "{name}");
        }
    }

    #[test]
    fn reject_carries_terminal_reasons_as_terminal() {
        let current = staging_artifact();
        for reason in [
            FAILURE_CODE_SIZE_LIMIT_EXCEEDED,
            FAILURE_CODE_CHECKSUM_INVALID,
            FAILURE_CODE_SECRET_DISCLOSURE,
        ] {
            let got = reject(&RejectInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version,
                reason,
                current: current.clone(),
            })
            .unwrap();
            assert_eq!(got.outcome.kind, OutcomeKind::Terminal, "{reason}");
        }
    }

    #[test]
    fn reject_refuses_a_reason_outside_the_closed_vocabulary() {
        let current = staging_artifact();
        for reason in ["", "boom", "s3://bucket/key", "SIZE_LIMIT_EXCEEDED "] {
            require_failure_class(
                reject(&RejectInput {
                    workspace_id: current.workspace_id,
                    artifact_id: current.artifact_id,
                    expected: current.version,
                    reason,
                    current: current.clone(),
                }),
                FailureClass::Invalid,
            );
        }
    }

    #[test]
    fn reject_refuses_a_mismatched_chain_or_version() {
        let current = staging_artifact();
        require_failure_class(
            reject(&RejectInput {
                workspace_id: WorkspaceId::new(),
                artifact_id: current.artifact_id,
                expected: current.version,
                reason: FAILURE_CODE_STAGING_EXPIRED,
                current: current.clone(),
            }),
            FailureClass::Denied,
        );

        require_failure_class(
            reject(&RejectInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                expected: current.version + 1,
                reason: FAILURE_CODE_STAGING_EXPIRED,
                current,
            }),
            FailureClass::Conflict,
        );
    }

    #[test]
    fn reject_refuses_an_already_terminal_or_finalizable_record() {
        // verifying is finalizable and rejected/ready are terminal: none
        // of them may be driven through the expiry/non-delivery
        // rejection command.
        let staging = staging_artifact();
        for state in [State::Verifying, State::Ready, State::Rejected] {
            let mut current = staging.clone();
            current.state = state;
            let version = current.version;
            require_failure_class(
                reject(&RejectInput {
                    workspace_id: current.workspace_id,
                    artifact_id: current.artifact_id,
                    expected: version,
                    reason: FAILURE_CODE_STAGING_EXPIRED,
                    current,
                }),
                FailureClass::Conflict,
            );
        }
    }

    // -----------------------------------------------------------------
    // fingerprint_coverage_test.go port
    // -----------------------------------------------------------------

    fn base_reserve_input() -> ReserveInput<'static> {
        ReserveInput {
            workspace_id: WorkspaceId::new(),
            artifact_id: ArtifactId::new(),
            staging_generation: StagingGeneration::new(),
            limits: Limits::default(),
            idempotency_key: "operation-1",
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            tool_call_attempt_id: None,
            producer_id: "b09-report-materializer",
            required_role: "final_report",
        }
    }

    fn reserve_identity(input: &ReserveInput<'_>) -> CommandIdentity {
        reserve(input).unwrap().identity
    }

    /// The canonical reserve encoding covers both `required_role` and
    /// `tool_call_attempt_id`: two reservations differing only in one of
    /// them must not replay one another.
    #[test]
    fn reserve_fingerprint_covers_required_role_and_tool_call_attempt() {
        let base = base_reserve_input();
        let baseline = reserve_identity(&base).fingerprint;

        let mut different_role = base.clone();
        different_role.required_role = "interim_report";
        assert_ne!(
            reserve_identity(&different_role).fingerprint,
            baseline,
            "two reservations for different required-output roles shared one fingerprint"
        );

        let mut with_tool_call = base.clone();
        with_tool_call.tool_call_attempt_id = Some(ToolCallAttemptId::new());
        assert_ne!(
            reserve_identity(&with_tool_call).fingerprint,
            baseline,
            "a reservation inside a Tool call shared a fingerprint with one that did not"
        );

        let mut other_tool_call = base.clone();
        other_tool_call.tool_call_attempt_id = Some(ToolCallAttemptId::new());
        assert_ne!(
            reserve_identity(&other_tool_call).fingerprint,
            reserve_identity(&with_tool_call).fingerprint,
            "two reservations from different Tool-call attempts shared one fingerprint"
        );
    }

    /// Guards against the two additions having been made by replacing
    /// rather than extending the canonical encoding.
    #[test]
    fn reserve_fingerprint_still_covers_the_original_fields() {
        let base = base_reserve_input();
        let baseline = reserve_identity(&base).fingerprint;

        let cases: [(&str, InputMutator); 10] = [
            ("declared limit", |i| {
                i.limits = Limits {
                    max_bytes: Limits::default().max_bytes / 2,
                };
            }),
            ("idempotency key", |i| i.idempotency_key = "operation-2"),
            ("producer", |i| i.producer_id = "someone-else"),
            ("task", |i| i.task_id = TaskId::new()),
            ("run", |i| i.run_id = RunId::new()),
            ("step", |i| i.step_id = StepId::new()),
            ("step attempt", |i| i.step_attempt_id = StepAttemptId::new()),
            ("artifact", |i| i.artifact_id = ArtifactId::new()),
            ("staging generation", |i| {
                i.staging_generation = StagingGeneration::new();
            }),
            ("owning workspace id", |i| {
                i.workspace_id = WorkspaceId::new()
            }),
        ];
        for (name, mutate) in cases {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            assert_ne!(
                reserve_identity(&mutated).fingerprint,
                baseline,
                "a reservation differing in its {name} shared the baseline fingerprint"
            );
        }
    }

    /// An accepted verify and a SIZE_LIMIT_EXCEEDED rejection at the
    /// same expected version must never share one identity — the
    /// rejection binds its cause so it cannot replay the acceptance's
    /// durable result.
    #[test]
    fn verified_binds_every_rejection_reason_into_its_identity() {
        let (ws, id) = (WorkspaceId::new(), ArtifactId::new());
        let current = Artifact {
            workspace_id: ws,
            artifact_id: id,
            state: State::Staging,
            version: 2,
            limits: Limits::default(),
            staging_generation: StagingGeneration::new(),
            staging_key: String::new(),
            content_generation: None,
            ready_key: String::new(),
            verified_size: 0,
            verified_checksum: [0; 32],
            ready_object_version: String::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            tool_call_attempt_id: None,
            producer_id: "test-producer".to_owned(),
            required_role: String::new(),
            sensitivity: Sensitivity::Restricted,
            disposition: Disposition::Attachment,
            delete_intent_at: None,
            deleted_at: None,
        };
        let body = b"an accepted report body";
        let checksum: [u8; 32] = Sha256::digest(body).into();
        let verify = |input: VerifiedInput<'_>| -> CommandIdentity {
            let mut input = input;
            input.workspace_id = ws;
            input.artifact_id = id;
            input.expected = current.version;
            input.current = current.clone();
            verified(&input).unwrap().identity
        };

        let accepted = verify(VerifiedInput {
            workspace_id: ws,
            artifact_id: id,
            current: current.clone(),
            expected: current.version,
            size: i64::try_from(body.len()).unwrap(),
            checksum,
            secret_disclosure: false,
            rejection_code: "",
        });
        assert!(accepted.failure_code.is_empty());

        let oversize = verify(VerifiedInput {
            workspace_id: ws,
            artifact_id: id,
            current: current.clone(),
            expected: current.version,
            size: current.limits.max_bytes + 1,
            checksum,
            secret_disclosure: false,
            rejection_code: "",
        });
        assert_eq!(oversize.failure_code, FAILURE_CODE_SIZE_LIMIT_EXCEEDED);

        let bad_checksum = verify(VerifiedInput {
            workspace_id: ws,
            artifact_id: id,
            current: current.clone(),
            expected: current.version,
            size: i64::try_from(body.len()).unwrap(),
            checksum: [0; 32],
            secret_disclosure: false,
            rejection_code: "",
        });
        assert_eq!(bad_checksum.failure_code, FAILURE_CODE_CHECKSUM_INVALID);

        let disclosure = verify(VerifiedInput {
            workspace_id: ws,
            artifact_id: id,
            current: current.clone(),
            expected: current.version,
            size: i64::try_from(body.len()).unwrap(),
            checksum,
            secret_disclosure: true,
            rejection_code: "",
        });
        assert_eq!(disclosure.failure_code, FAILURE_CODE_SECRET_DISCLOSURE);

        // All four are distinct commands at the same expected version —
        // the property that stops any of them replaying another's
        // durable result.
        let identities = [accepted, oversize, bad_checksum, disclosure];
        for (i, a) in identities.iter().enumerate() {
            for b in &identities[i + 1..] {
                assert!(
                    !a.equal(b),
                    "two verify results shared one command identity"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Deterministic reservation identity
    // -----------------------------------------------------------------

    /// `derive_reservation_identity` is byte-for-byte identical to
    /// upstream `DeriveReservationIdentity`: these expected identities
    /// are the upstream algorithm's output computed independently
    /// (SHA-256 of `"<domain>\x00<operation>"` truncated to 16 bytes,
    /// version/variant forced).
    #[test]
    fn derive_reservation_identity_matches_upstream_vectors() {
        let (artifact, staging) = derive_reservation_identity("op-1").unwrap();
        assert_eq!(
            artifact,
            ArtifactId::parse("1442ca0d-2c53-7012-a8ae-33312c9778f4").unwrap()
        );
        assert_eq!(
            staging,
            StagingGeneration::parse("0714ac99-1c43-4557-b835-ad641b544a5e").unwrap()
        );

        let (artifact, staging) = derive_reservation_identity("task-42").unwrap();
        assert_eq!(
            artifact,
            ArtifactId::parse("08edba8a-40ee-774a-966d-bedb63136de7").unwrap()
        );
        assert_eq!(
            staging,
            StagingGeneration::parse("726c6ba9-b378-4132-a75f-5f251ed4fb3b").unwrap()
        );
    }

    #[test]
    fn derive_reservation_identity_is_deterministic_and_domain_separated() {
        let first = derive_reservation_identity("same-op").unwrap();
        let second = derive_reservation_identity("same-op").unwrap();
        assert_eq!(first, second);
        // The two outputs share a preimage family but the domain
        // separators keep them independent.
        assert_ne!(first.0.as_bytes(), first.1.as_bytes());
        assert_ne!(
            derive_reservation_identity("op-a").unwrap().0,
            derive_reservation_identity("op-b").unwrap().0
        );
    }

    #[test]
    fn derive_reservation_identity_rejects_empty_operation_id() {
        require_failure_class(derive_reservation_identity(""), FailureClass::Invalid);
    }

    // -----------------------------------------------------------------
    // Reserve fingerprint byte parity with upstream encoding/json
    // -----------------------------------------------------------------

    /// The canonical fingerprint payload is byte-for-byte Go
    /// `encoding/json` — proven by hashing the exact expected JSON text.
    #[test]
    fn reserve_fingerprint_matches_upstream_canonical_encoding() {
        let input = ReserveInput {
            workspace_id: WorkspaceId::parse("018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b").unwrap(),
            artifact_id: ArtifactId::parse("019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a").unwrap(),
            staging_generation: StagingGeneration::parse("550e8400-e29b-41d4-a716-446655440000")
                .unwrap(),
            limits: Limits::default(),
            idempotency_key: "operation-1",
            task_id: TaskId::parse("019fdc8d-e33a-7000-8000-000000000001").unwrap(),
            run_id: RunId::parse("019fdc8d-e33a-7000-8000-000000000002").unwrap(),
            step_id: StepId::parse("019fdc8d-e33a-7000-8000-000000000003").unwrap(),
            step_attempt_id: StepAttemptId::parse("019fdc8d-e33a-7000-8000-000000000004").unwrap(),
            tool_call_attempt_id: None,
            producer_id: "b09-report-materializer",
            required_role: "final_report",
        };
        // The exact upstream canonical payload for this input — Go's
        // field order plus `,omitempty` dropping only
        // `tool_call_attempt_id`.
        const CANONICAL: &str = concat!(
            r#"{"workspace_id":"018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b","#,
            r#""artifact_id":"019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a","#,
            r#""staging_generation":"550e8400-e29b-41d4-a716-446655440000","#,
            r#""max_bytes":1048576,"idempotency_key":"operation-1","#,
            r#""task_id":"019fdc8d-e33a-7000-8000-000000000001","#,
            r#""run_id":"019fdc8d-e33a-7000-8000-000000000002","#,
            r#""step_id":"019fdc8d-e33a-7000-8000-000000000003","#,
            r#""step_attempt_id":"019fdc8d-e33a-7000-8000-000000000004","#,
            r#""producer_id":"b09-report-materializer","required_role":"final_report"}"#
        );
        let expected: [u8; 32] = Sha256::digest(CANONICAL.as_bytes()).into();
        assert_eq!(reserve_fingerprint(&input), expected);

        // With a tool-call attempt the same shape holds.
        let mut with_tool_call = input;
        with_tool_call.tool_call_attempt_id =
            Some(ToolCallAttemptId::parse("019fdc8d-e33a-7000-8000-000000000005").unwrap());
        const CANONICAL_TOOL_CALL: &str = concat!(
            r#"{"workspace_id":"018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b","#,
            r#""artifact_id":"019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a","#,
            r#""staging_generation":"550e8400-e29b-41d4-a716-446655440000","#,
            r#""max_bytes":1048576,"idempotency_key":"operation-1","#,
            r#""task_id":"019fdc8d-e33a-7000-8000-000000000001","#,
            r#""run_id":"019fdc8d-e33a-7000-8000-000000000002","#,
            r#""step_id":"019fdc8d-e33a-7000-8000-000000000003","#,
            r#""step_attempt_id":"019fdc8d-e33a-7000-8000-000000000004","#,
            r#""producer_id":"b09-report-materializer","#,
            r#""tool_call_attempt_id":"019fdc8d-e33a-7000-8000-000000000005","#,
            r#""required_role":"final_report"}"#
        );
        let expected: [u8; 32] = Sha256::digest(CANONICAL_TOOL_CALL.as_bytes()).into();
        assert_eq!(reserve_fingerprint(&with_tool_call), expected);
    }

    /// Go's `json.Marshal` always applies HTMLEscape: `&`, `<`, `>` and
    /// U+2028/U+2029 are escaped in string values — the encoder must
    /// reproduce that or fingerprints would diverge from Go-written
    /// receipts.
    #[test]
    fn reserve_fingerprint_escapes_like_go_encoding_json() {
        let mut input = valid_reserve_input();
        input.idempotency_key = "a&b<c>d";
        input.producer_id = "p<&>";
        let fingerprint = reserve_fingerprint(&input);
        // Independently re-derive the expected canonical payload: Go's
        // always-on HTMLEscape must appear as < > & — anything else
        // would diverge from a Go-written receipt fingerprint.
        let canonical = format!(
            "{{\"workspace_id\":\"{}\",\"artifact_id\":\"{}\",\"staging_generation\":\"{}\",\"max_bytes\":1048576,\"idempotency_key\":\"a\\u0026b\\u003cc\\u003ed\",\"task_id\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"step_attempt_id\":\"{}\",\"producer_id\":\"p\\u003c\\u0026\\u003e\"}}",
            input.workspace_id,
            input.artifact_id,
            input.staging_generation,
            input.task_id,
            input.run_id,
            input.step_id,
            input.step_attempt_id,
        );
        let expected: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        assert_eq!(fingerprint, expected);
    }

    // -----------------------------------------------------------------
    // Failure → foundation conversion
    // -----------------------------------------------------------------

    #[test]
    fn failure_converts_to_foundation_failure() {
        let failure = Failure::new(FailureClass::Conflict, "VERSION_CONFLICT");
        assert_eq!(failure.to_string(), "artifact: CONFLICT (VERSION_CONFLICT)");
        let foundation: FoundationFailure = failure.into();
        assert_eq!(foundation.kind(), FailureKind::Conflict);
        assert_eq!(foundation.code(), "VERSION_CONFLICT");
    }

    // -----------------------------------------------------------------
    // Two-phase deletion & tombstone
    // -----------------------------------------------------------------

    const T_INTENT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;
    const T_DELETED: OffsetDateTime = match OffsetDateTime::from_unix_timestamp(60) {
        Ok(t) => t,
        Err(_) => unreachable!(),
    };

    fn mark_input(current: &Artifact) -> MarkDeletePendingInput {
        MarkDeletePendingInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            delete_intent_at: T_INTENT,
        }
    }

    fn complete_input<'a>(current: &Artifact, reason: &'a str) -> CompleteDeletionInput<'a> {
        CompleteDeletionInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            tombstone_id: ArtifactTombstoneId::new(),
            deletion_reason: reason,
            deleted_at: T_DELETED,
        }
    }

    #[test]
    fn mark_delete_pending_transitions_ready_and_sets_delete_intent() {
        let current = ready_artifact();
        let got = mark_delete_pending(&mark_input(&current)).unwrap();
        assert_eq!(got.state, State::DeletePending);
        assert_eq!(got.version, current.version + 1);
        assert_eq!(got.delete_intent_at, Some(T_INTENT));
    }

    #[test]
    fn mark_delete_pending_requires_ready() {
        for state in [
            State::Reserved,
            State::Staging,
            State::Verifying,
            State::Rejected,
            State::DeletePending,
            State::Deleted,
            State::Quarantined,
        ] {
            let mut current = staging_artifact();
            current.state = state;
            let version = current.version;
            require_failure_class(
                mark_delete_pending(&MarkDeletePendingInput {
                    workspace_id: current.workspace_id,
                    artifact_id: current.artifact_id,
                    current,
                    expected: version,
                    delete_intent_at: T_INTENT,
                }),
                FailureClass::Conflict,
            );
        }
    }

    #[test]
    fn mark_delete_pending_refuses_mismatched_chain_or_version() {
        let current = ready_artifact();
        require_failure_class(
            mark_delete_pending(&MarkDeletePendingInput {
                workspace_id: WorkspaceId::new(),
                ..mark_input(&current)
            }),
            FailureClass::Denied,
        );
        require_failure_class(
            mark_delete_pending(&MarkDeletePendingInput {
                expected: current.version + 1,
                ..mark_input(&current)
            }),
            FailureClass::Conflict,
        );
    }

    #[test]
    fn complete_deletion_settles_delete_pending_and_builds_tombstone() {
        let pending = mark_delete_pending(&mark_input(&ready_artifact())).unwrap();
        let (got, tombstone) =
            complete_deletion(&complete_input(&pending, "operator_delete")).unwrap();

        assert_eq!(got.state, State::Deleted);
        assert_eq!(got.version, pending.version + 1);
        assert_eq!(got.deleted_at, Some(T_DELETED));

        assert_eq!(tombstone.workspace_id, pending.workspace_id);
        assert_eq!(tombstone.artifact_id, pending.artifact_id);
        // The deleted body lived at the ready key; the tombstone
        // preserves it so the key is never reused.
        assert_eq!(tombstone.object_key, pending.ready_key);
        assert_eq!(tombstone.staging_generation, pending.staging_generation);
        assert_eq!(
            tombstone.checksum_algorithm.as_deref(),
            Some(CHECKSUM_ALGORITHM_SHA256)
        );
        assert_eq!(tombstone.checksum_value, Some(pending.verified_checksum));
        assert_eq!(tombstone.size_at_deletion, pending.verified_size);
        assert_eq!(tombstone.deletion_reason, "operator_delete");
    }

    #[test]
    fn complete_deletion_accepts_ready_with_reason() {
        // The direct metadata mark: a retained body may be deleted in
        // one step where an operator path supplies the reason.
        let current = ready_artifact();
        let (got, tombstone) = complete_deletion(&complete_input(&current, "pruned")).unwrap();
        assert_eq!(got.state, State::Deleted);
        assert_eq!(tombstone.deletion_reason, "pruned");
    }

    #[test]
    fn complete_deletion_refuses_non_ready_non_pending_states() {
        for state in [
            State::Reserved,
            State::Staging,
            State::Verifying,
            State::Rejected,
            State::Deleted,
            State::Quarantined,
        ] {
            let mut current = staging_artifact();
            current.state = state;
            let version = current.version;
            require_failure_class(
                complete_deletion(&CompleteDeletionInput {
                    workspace_id: current.workspace_id,
                    artifact_id: current.artifact_id,
                    current,
                    expected: version,
                    tombstone_id: ArtifactTombstoneId::new(),
                    deletion_reason: "reason",
                    deleted_at: T_DELETED,
                }),
                FailureClass::Conflict,
            );
        }
    }

    #[test]
    fn complete_deletion_requires_reason_and_tombstone_identity() {
        let pending = mark_delete_pending(&mark_input(&ready_artifact())).unwrap();
        require_failure_class(
            complete_deletion(&CompleteDeletionInput {
                deletion_reason: "",
                ..complete_input(&pending, "")
            }),
            FailureClass::Invalid,
        );
        require_failure_class(
            complete_deletion(&CompleteDeletionInput {
                tombstone_id: nil_to_tombstone(),
                ..complete_input(&pending, "reason")
            }),
            FailureClass::Invalid,
        );
    }

    #[test]
    fn complete_deletion_refuses_mismatched_chain_or_version() {
        let pending = mark_delete_pending(&mark_input(&ready_artifact())).unwrap();
        require_failure_class(
            complete_deletion(&CompleteDeletionInput {
                workspace_id: WorkspaceId::new(),
                ..complete_input(&pending, "reason")
            }),
            FailureClass::Denied,
        );
        require_failure_class(
            complete_deletion(&CompleteDeletionInput {
                expected: pending.version + 1,
                ..complete_input(&pending, "reason")
            }),
            FailureClass::Conflict,
        );
    }

    #[test]
    fn tombstone_uses_staging_key_when_no_ready_key_exists() {
        // A delete-pending record that never reached promotion
        // preserves its staging key so neither key shape is reused.
        let mut pending = mark_delete_pending(&mark_input(&ready_artifact())).unwrap();
        pending.ready_key.clear();
        pending.content_generation = None;
        let (_, tombstone) = complete_deletion(&complete_input(&pending, "cleanup")).unwrap();
        assert_eq!(tombstone.object_key, pending.staging_key);
    }

    // -----------------------------------------------------------------
    // Delivery/preview disposition policy
    // -----------------------------------------------------------------

    #[test]
    fn delivery_policy_permits_inline_preview_for_allowlisted_unrestricted() {
        for media_type in ["text/plain", "text/markdown", "application/json"] {
            let decision = evaluate_delivery_policy(
                Some(media_type),
                Sensitivity::Unrestricted,
                Disposition::Inline,
                4096,
            );
            assert_eq!(decision.disposition, Disposition::Inline, "{media_type}");
            assert_eq!(decision.media_type, media_type);
            assert!(decision.preview_permitted);
            assert_eq!(decision.preview_max_bytes, ARTIFACT_PREVIEW_MAX_BYTES);
            assert!(!decision.preview_truncated);
        }
    }

    #[test]
    fn delivery_policy_flags_truncated_preview_over_the_bound() {
        let decision = evaluate_delivery_policy(
            Some("text/markdown"),
            Sensitivity::Unrestricted,
            Disposition::Inline,
            ARTIFACT_PREVIEW_MAX_BYTES + 1,
        );
        assert_eq!(decision.disposition, Disposition::Inline);
        assert!(decision.preview_truncated);
        assert_eq!(ARTIFACT_PREVIEW_MAX_BYTES, 128 * 1024);
    }

    #[test]
    fn delivery_policy_download_only_for_unallowlisted_or_unknown_content() {
        for detected in [
            Some("text/html"),
            Some("image/png"),
            Some("application/pdf"),
            Some("application/octet-stream"),
            None,
        ] {
            let decision = evaluate_delivery_policy(
                detected,
                Sensitivity::Unrestricted,
                Disposition::Inline,
                10,
            );
            assert_eq!(
                decision.disposition,
                Disposition::Attachment,
                "{detected:?}"
            );
            assert_eq!(decision.media_type, FALLBACK_MEDIA_TYPE, "{detected:?}");
            assert!(!decision.preview_permitted, "{detected:?}");
        }
    }

    #[test]
    fn delivery_policy_never_previews_restricted_or_sensitive() {
        for sensitivity in [Sensitivity::Restricted, Sensitivity::Sensitive] {
            let decision = evaluate_delivery_policy(
                Some("text/markdown"),
                sensitivity,
                Disposition::Inline,
                10,
            );
            assert_eq!(
                decision.disposition,
                Disposition::Attachment,
                "{sensitivity:?}"
            );
            assert!(!decision.preview_permitted, "{sensitivity:?}");
        }
        // Sensitive content also loses its detected type to the binary
        // fallback; restricted keeps the explicit detected type for the
        // download-only delivery.
        let sensitive = evaluate_delivery_policy(
            Some("text/markdown"),
            Sensitivity::Sensitive,
            Disposition::Inline,
            10,
        );
        assert_eq!(sensitive.media_type, FALLBACK_MEDIA_TYPE);
        let restricted = evaluate_delivery_policy(
            Some("text/markdown"),
            Sensitivity::Restricted,
            Disposition::Inline,
            10,
        );
        assert_eq!(restricted.media_type, "text/markdown");
    }

    #[test]
    fn delivery_policy_honours_attachment_request_on_allowlisted_content() {
        let decision = evaluate_delivery_policy(
            Some("application/json"),
            Sensitivity::Unrestricted,
            Disposition::Attachment,
            10,
        );
        // The caller asked for a download: the allowlist permits a
        // preview but the disposition stays attachment with the
        // explicit detected type.
        assert_eq!(decision.disposition, Disposition::Attachment);
        assert_eq!(decision.media_type, "application/json");
        assert!(decision.preview_permitted);
        assert!(!decision.preview_truncated);
    }
}
