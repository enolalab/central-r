//! `internal/destructive` — D01 (wipe + reseed) and D04 (delete + prune)
//! domain: the refusal vocabulary, the crash-safe intent/result/checkpoint
//! records, the plan and batch types, and the pure batching/validation/
//! orchestration rules. Filesystem and process seams live in
//! `central-adapter-linux`'s helper — this module is pure data and logic,
//! exactly like upstream's own pure half (`BatchPrunePlan`,
//! `ValidatePruneCandidate`, `ApplyPruneBatches`, `RewriteConfigForInstance`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use central_foundation::identity::InstanceId;

// ---------------------------------------------------------------------------
// Refusal vocabulary — verbatim upstream tokens; never invent a new one.
// ---------------------------------------------------------------------------

/// `ReasonWipeDeniedSigned` — the signed advisory refused before ceremony.
pub const REASON_WIPE_DENIED_SIGNED: &str = "WIPE_DENIED_SIGNED";
/// `ReasonWipeCheckpointFailed` — the C01 checkpoint is not sealed.
pub const REASON_WIPE_CHECKPOINT_FAILED: &str = "WIPE_CHECKPOINT_FAILED";
/// `ReasonWipeAppArmorRefused` — confinement could not be cleared. The
/// upstream spelling (`WIPE_APARMOR_REFUSED`) is kept verbatim.
pub const REASON_WIPE_APPARMOR_REFUSED: &str = "WIPE_APARMOR_REFUSED";
/// `ReasonWipeTargetInvalid` — the selection is not the installed root.
pub const REASON_WIPE_TARGET_INVALID: &str = "WIPE_TARGET_INVALID";
/// `ReasonWipeTargetLive` — the runtime root exists; `local down` first.
pub const REASON_WIPE_TARGET_LIVE: &str = "WIPE_TARGET_LIVE";
/// `ReasonWipeReseedFailed` — any step after destruction began failed.
pub const REASON_WIPE_RESEED_FAILED: &str = "WIPE_RESEED_FAILED";
/// `ReasonWipeCeremonyRequired` — no confirmer can run this ceremony.
pub const REASON_WIPE_CEREMONY_REQUIRED: &str = "WIPE_CEREMONY_REQUIRED";
/// `ReasonWipeAuthorityDenied` — the ceremony did not produce a token.
pub const REASON_WIPE_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
/// `ReasonWipeUnavailable` — the verb is closed in this composition.
pub const REASON_WIPE_UNAVAILABLE: &str = "WIPE_UNAVAILABLE";
/// `ReasonWipeInvalidRequest` — the request itself is malformed.
pub const REASON_WIPE_INVALID_REQUEST: &str = "INVALID_WIPE_REQUEST";

/// `ReasonDeleteDeniedSigned`.
pub const REASON_DELETE_DENIED_SIGNED: &str = "DELETE_DENIED_SIGNED";
/// `ReasonDeleteAuthorityDenied`.
pub const REASON_DELETE_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
/// `ReasonDeleteCeremonyRequired`.
pub const REASON_DELETE_CEREMONY_REQUIRED: &str = "DELETE_CEREMONY_REQUIRED";
/// `ReasonDeleteUnavailable`.
pub const REASON_DELETE_UNAVAILABLE: &str = "DELETE_UNAVAILABLE";
/// `ReasonDeleteInvalidRequest`.
pub const REASON_DELETE_INVALID_REQUEST: &str = "INVALID_DELETE_REQUEST";
/// `ReasonDeleteNoBackup` — zero sealed candidates for an implicit pick.
pub const REASON_DELETE_NO_BACKUP: &str = "BACKUP_NO_ADMISSIBLE_BACKUP";
/// `ReasonDeleteBackupAmbiguous` — several sealed candidates, no id.
pub const REASON_DELETE_BACKUP_AMBIGUOUS: &str = "BACKUP_CANDIDATE_AMBIGUOUS";
/// `ReasonDeleteRetentionTooYoung` — inside the retention floor.
pub const REASON_DELETE_RETENTION_TOO_YOUNG: &str = "DELETE_RETENTION_TOO_YOUNG";
/// `ReasonDeleteReferenced` — an operation still references the backup.
pub const REASON_DELETE_REFERENCED: &str = "DELETE_REFERENCED";
/// `ReasonDeleteEngineFailed` — the tree removal or record write failed.
pub const REASON_DELETE_ENGINE_FAILED: &str = "DELETE_ENGINE_FAILED";

/// `ReasonPruneDeniedSigned`.
pub const REASON_PRUNE_DENIED_SIGNED: &str = "PRUNE_DENIED_SIGNED";
/// `ReasonPruneAuthorityDenied`.
pub const REASON_PRUNE_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
/// `ReasonPruneCeremonyRequired`.
pub const REASON_PRUNE_CEREMONY_REQUIRED: &str = "PRUNE_CEREMONY_REQUIRED";
/// `ReasonPruneUnavailable`.
pub const REASON_PRUNE_UNAVAILABLE: &str = "PRUNE_UNAVAILABLE";
/// `ReasonPruneInvalidRequest`.
pub const REASON_PRUNE_INVALID_REQUEST: &str = "INVALID_PRUNE_REQUEST";
/// `ReasonPrunePlanStale` — a body changed between plan and apply.
pub const REASON_PRUNE_PLAN_STALE: &str = "PRUNE_PLAN_STALE";
/// `ReasonPruneEngineFailed`.
pub const REASON_PRUNE_ENGINE_FAILED: &str = "PRUNE_ENGINE_FAILED";

/// `DefaultRetentionDays` — the dossier's 30-day retention floor.
/// Installed policy may tighten it (raise it); nothing may loosen it.
pub const DEFAULT_RETENTION_DAYS: i32 = 30;

/// `PruneBatchSize` — the checkpoint unit: `prune_log` rows and
/// tombstones commit one batch at a time, so a crash resumes at a batch
/// boundary instead of replaying the whole plan.
pub const PRUNE_BATCH_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// D01 — AppArmor, target, intent, result, evidence, reseed.
// ---------------------------------------------------------------------------

/// `ProductionAppArmorAttrCurrent` — the kernel's confinement report for
/// the reading process.
pub const APPARMOR_ATTR_CURRENT: &str = "/proc/self/attr/current";
/// `ProductionAppArmorProfile` — the sandbox launcher's installed
/// profile. D01 defines this path: no in-repo convention existed.
pub const APPARMOR_PROFILE: &str = "/etc/apparmor.d/central-sandbox-launcher";

/// `AppArmorState` — what the handler found and did about the sandbox
/// launcher's confinement. It is evidence, recorded on every wipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppArmorState {
    /// `not_confined`: the helper is unconfined and no launcher profile
    /// file exists — the Docker-host shape. Nothing was done.
    #[serde(rename = "not_confined")]
    NotConfined,
    /// `profile_removed`: a launcher profile existed, was deactivated
    /// with `apparmor_parser -R`, its file removed, and the helper
    /// re-verified unconfined.
    #[serde(rename = "profile_removed")]
    ProfileRemoved,
}

impl AppArmorState {
    /// The upstream string value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfined => "not_confined",
            Self::ProfileRemoved => "profile_removed",
        }
    }
}

/// `WipeTarget` — a validated wipe selection: the operator-named
/// canonical path resolved to exactly the installed instance's state
/// root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WipeTarget {
    /// The strict instance-id base name.
    pub instance_id: String,
    /// The canonical state-root path.
    pub state_root: String,
}

/// `WipeIntent` — the crash record, written to the instances parent
/// (which survives the wipe) after the ceremony and before any
/// destruction. A stale intent beside a missing instance dir is a
/// crashed wipe; the next wipe invocation completes the reseed half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeIntent {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The instance being destroyed.
    pub instance_id: String,
    /// The sealed C01 checkpoint backup id.
    pub checkpoint_backup_id: String,
    /// The state root already validated for destruction.
    pub state_root: String,
    /// The broker protected instance dir.
    pub broker_instance_dir: String,
    /// RFC 3339 start timestamp.
    pub started_at: String,
    /// The operator config the reseed half rebinds. The old state root
    /// is gone by the time a resume needs it, so the intent carries it;
    /// the file is root-only 0600 like the state it came from.
    pub config_json: String,
}

/// `WipeResult` — the terminal audit record, written beside the intent.
/// The intent is removed only after the result is durably written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeResultRecord {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The wiped instance.
    pub instance_id: String,
    /// The reseeded instance identity.
    pub new_instance_id: String,
    /// The sealed C01 checkpoint backup id.
    pub checkpoint_backup_id: String,
    /// What the AppArmor seam observed/did.
    pub apparmor: AppArmorState,
    /// Whether this run completed a crashed predecessor's reseed half.
    pub resumed_after_crash: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
    /// The terminal machine reason ("ok").
    pub reason: String,
}

/// `WipeEvidence` — the `slice-d-wipe-reseed.json` artifact body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeEvidence {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The wiped instance.
    pub wiped_instance_id: String,
    /// The reseeded instance identity.
    pub new_instance_id: String,
    /// The sealed C01 checkpoint backup id.
    pub checkpoint_backup_id: String,
    /// What the AppArmor seam observed/did.
    pub apparmor: AppArmorState,
    /// Whether the run completed a crashed predecessor.
    pub resumed_after_crash: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// `ReseedInput` — everything the skeleton rebuild needs. All paths are
/// absolute and clean; ownership is explicit (production: instance dirs
/// owned by the central-runtime UID, broker dirs by root).
#[derive(Debug, Clone)]
pub struct ReseedInput {
    /// The instances parent (`<root>/<instance-id>` state roots).
    pub instances_root: String,
    /// The protected parent (`<parent>/<instance-id>/protected` roots).
    pub protected_parent: String,
    /// The strict new instance id.
    pub new_instance_id: String,
    /// The JCS-canonical rebound config document.
    pub config_bytes: Vec<u8>,
    /// Owner of the instance state tree.
    pub instance_uid: u32,
    /// Group of the instance state tree.
    pub instance_gid: u32,
    /// Owner of the broker protected tree.
    pub broker_uid: u32,
    /// Group of the broker protected tree.
    pub broker_gid: u32,
}

/// The wipe intent file name under the instances root —
/// `wipe-<operation-id>.intent.json`.
#[must_use]
pub fn wipe_intent_file_name(operation_id: &str) -> String {
    format!("wipe-{operation_id}.intent.json")
}

/// The wipe result file name under the instances root —
/// `wipe-<operation-id>.result.json`.
#[must_use]
pub fn wipe_result_file_name(operation_id: &str) -> String {
    format!("wipe-{operation_id}.result.json")
}

/// Whether a directory entry name is a wipe intent file —
/// `wipe-*.intent.json`, at least `"wipe-" + ".intent.json"` long.
#[must_use]
pub fn is_wipe_intent_file_name(name: &str) -> bool {
    name.len() > 5 + ".intent.json".len()
        && name.starts_with("wipe-")
        && name.ends_with(".intent.json")
}

/// `validWipeTargetSyntax` — checks the selection's shape without
/// touching the filesystem: absolute, clean, directly under the
/// instances root, naming a strict instance id.
#[must_use]
pub fn valid_wipe_target_syntax(operator_path: &str, instances_root: &str) -> bool {
    let path = std::path::Path::new(operator_path);
    if !path.is_absolute() || !is_clean_abs(operator_path) {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    if parent != std::path::Path::new(instances_root) {
        return false;
    }
    let Some(base) = path.file_name().and_then(|b| b.to_str()) else {
        return false;
    };
    InstanceId::parse(base).is_ok_and(|parsed| parsed.to_string() == base)
}

/// `filepath.Clean(path) == path` for an absolute path: no `.`/`..`
/// segments, no duplicate separators, no trailing separator.
fn is_clean_abs(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    if path.len() > 1 && path.ends_with('/') {
        return false;
    }
    let mut prev_sep = false;
    for (i, segment) in path.split('/').enumerate() {
        if i == 0 {
            continue;
        }
        if segment.is_empty() {
            // An interior empty segment means `//` (or a trailing `/`,
            // handled above).
            let _ = prev_sep;
            return false;
        }
        if segment == "." || segment == ".." {
            return false;
        }
        prev_sep = true;
    }
    true
}

/// `wipeResumeRequestMatches` — binds a resume request to its crash
/// intent. The target is gone by definition here, so symlink resolution
/// would fail; instead the request must name exactly
/// `instancesRoot/<intent-instance-id>` (parent byte-identical, base a
/// strict instance-id match).
#[must_use]
pub fn wipe_resume_request_matches(
    operator_path: &str,
    instances_root: &str,
    intent: &WipeIntent,
) -> bool {
    if !valid_wipe_target_syntax(operator_path, instances_root) {
        return false;
    }
    std::path::Path::new(operator_path)
        .file_name()
        .and_then(|b| b.to_str())
        == Some(intent.instance_id.as_str())
        && intent.state_root == operator_path
}

/// `RewriteConfigForInstance` — rebinds a parsed operator config to a
/// new instance identity: the instance id and the three derived paths
/// move; everything else carries over. The output must re-parse or the
/// wipe is refused before anything is destroyed.
pub fn rewrite_config_for_instance(
    raw: &[u8],
    new_id: InstanceId,
    new_state_root: &str,
) -> Result<Vec<u8>, WipeDomainError> {
    let mut cfg = crate::config::parse(raw)
        .map_err(|_| WipeDomainError::Reseed("source config".to_owned()))?;
    cfg.instance_id = new_id;
    cfg.paths.authoritative_state_root = new_state_root.to_owned();
    cfg.paths.instance_data_root = format!("{new_state_root}/data");
    cfg.paths.backup_repository_root = format!("{new_state_root}/backups");
    let marshaled =
        serde_json::to_vec(&cfg).map_err(|_| WipeDomainError::Reseed("encode".to_owned()))?;
    let value: serde_json::Value = serde_json::from_slice(&marshaled)
        .map_err(|_| WipeDomainError::Reseed("encode".to_owned()))?;
    let out = central_foundation::jcs::canonicalize(&value)
        .map_err(|_| WipeDomainError::Reseed("canonicalize".to_owned()))?;
    crate::config::parse(&out)
        .map_err(|_| WipeDomainError::Reseed("rewritten config does not parse".to_owned()))?;
    Ok(out)
}

/// The domain-level wipe failures: each maps to one refusal reason at
/// the handler boundary. Details are locator-free diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WipeDomainError {
    /// `ErrTargetInvalid` — the selection is not the installed root.
    TargetInvalid(String),
    /// `ErrTargetLive` — the ephemeral runtime root exists.
    TargetLive(String),
    /// `ErrAppArmorRefused` — confinement could not be cleared.
    AppArmorRefused(String),
    /// `ErrReseedFailed` — a post-destruction step failed.
    Reseed(String),
    /// `ErrIntentCorrupt` — a wipe intent record is corrupt.
    IntentCorrupt(String),
}

impl WipeDomainError {
    /// The refusal reason this failure maps to.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::TargetInvalid(_) => REASON_WIPE_TARGET_INVALID,
            Self::TargetLive(_) => REASON_WIPE_TARGET_LIVE,
            Self::AppArmorRefused(_) => REASON_WIPE_APPARMOR_REFUSED,
            Self::Reseed(_) => REASON_WIPE_RESEED_FAILED,
            Self::IntentCorrupt(_) => REASON_WIPE_RESEED_FAILED,
        }
    }
}

impl std::fmt::Display for WipeDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetInvalid(d) => write!(f, "destructive: wipe target is invalid: {d}"),
            Self::TargetLive(d) => {
                write!(
                    f,
                    "destructive: instance is live; run local down first: {d}"
                )
            }
            Self::AppArmorRefused(d) => {
                write!(
                    f,
                    "destructive: apparmor confinement cannot be cleared: {d}"
                )
            }
            Self::Reseed(d) => write!(f, "destructive: reseed failed: {d}"),
            Self::IntentCorrupt(d) => write!(f, "destructive: wipe intent record is corrupt: {d}"),
        }
    }
}

impl std::error::Error for WipeDomainError {}

// ---------------------------------------------------------------------------
// D04 — delete record + evidence, prune candidates, batches, journal.
// ---------------------------------------------------------------------------

/// `DeleteRecord` — the journaled proof of one `backup delete`. The
/// journal file is the audit trail; unlike prune bodies, a deleted
/// sealed backup gets no artifact tombstone (`artifact_tombstones` is
/// artifact-keyed and a sealed tree is not an artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteRecord {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The deleted sealed backup id.
    pub backup_id: String,
    /// The proven retention age at delete time.
    pub retention_age_days: i32,
    /// The proven reference count (always 0 on success).
    pub reference_count: i32,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// The delete journal file name under the journal dir —
/// `delete-<operation-id>.result.json`.
#[must_use]
pub fn delete_record_file_name(operation_id: &str) -> String {
    format!("delete-{operation_id}.result.json")
}

/// `DeleteEvidence` — the D04 evidence artifact both delete and
/// prune-apply write (`slice-d-delete-prune.json`). Identities and
/// counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteEvidence {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// Which verb wrote the evidence (`delete` / `prune-apply`).
    pub verb: String,
    /// The applied plan id (prune-apply only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plan_id: String,
    /// The deleted backup id (delete only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backup_id: String,
    /// Bodies deleted by the run.
    pub bodies_deleted: i64,
    /// Batches completed by the run.
    pub batches_done: i64,
    /// Whether the apply resumed a crashed predecessor.
    #[serde(default)]
    pub resumed_after_crash: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// `PruneCandidate` — one artifact body eligible for deletion: old
/// enough and unreferenced at plan time. `retention_age_days` and
/// `reference_count` are the proof the checks produced, journaled
/// verbatim into `prune_log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneCandidate {
    /// Artifact identity.
    pub artifact_id: Uuid,
    /// Workspace identity.
    pub workspace_id: Uuid,
    /// The ready object key.
    pub object_key: String,
    /// The artifact's one-time staging generation.
    pub staging_generation: Uuid,
    /// Body size.
    pub size: i64,
    /// Proven retention age at plan time.
    pub retention_age_days: i32,
    /// Proven reference count at plan time.
    pub reference_count: i32,
}

/// `PrunePlan` — the read-only output of `backup prune plan`: the
/// eligible set frozen at plan time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunePlan {
    /// Minted plan identity.
    pub plan_id: Uuid,
    /// The retention floor this plan proved.
    pub retention_days: i32,
    /// The frozen eligible bodies.
    pub bodies: Vec<PruneCandidate>,
}

/// `PruneBatch` — one checkpoint unit of an apply run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneBatch {
    /// Plan identity.
    pub plan_id: Uuid,
    /// Zero-based batch ordinal.
    pub batch_seq: i32,
    /// The batch's bodies.
    pub bodies: Vec<PruneCandidate>,
}

/// `BatchPrunePlan` — splits bodies into batches of [`PRUNE_BATCH_SIZE`].
/// `batch_seq` counts from zero; an empty plan yields no batches, never
/// a degenerate empty batch.
#[must_use]
pub fn batch_prune_plan(plan: &PrunePlan) -> Vec<PruneBatch> {
    if plan.bodies.is_empty() {
        return Vec::new();
    }
    plan.bodies
        .chunks(PRUNE_BATCH_SIZE)
        .enumerate()
        .map(|(i, chunk)| PruneBatch {
            plan_id: plan.plan_id,
            batch_seq: i32::try_from(i).unwrap_or(i32::MAX),
            bodies: chunk.to_vec(),
        })
        .collect()
}

/// `PruneRowState` — the `prune_log` state vocabulary, mirroring the
/// b29 CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneRowState {
    /// `pending`.
    Pending,
    /// `applying`.
    Applying,
    /// `done`.
    Done,
}

impl PruneRowState {
    /// The upstream string value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applying => "applying",
            Self::Done => "done",
        }
    }
}

/// `ResumeBatches` — the batches an apply run must still execute given
/// the per-batch states already journaled: `done` batches are skipped,
/// `applying` batches are re-executed (per-body tombstone presence makes
/// the re-execution idempotent), `pending` batches execute in order.
#[must_use]
pub fn resume_batches(
    batches: &[PruneBatch],
    journaled: &HashMap<i32, PruneRowState>,
) -> Vec<PruneBatch> {
    batches
        .iter()
        .filter(|b| journaled.get(&b.batch_seq) != Some(&PruneRowState::Done))
        .cloned()
        .collect()
}

/// `ValidatePruneCandidate` — refuses a body that does not satisfy the
/// delete preconditions: retention age at or above the floor, zero
/// references, and a sane identity triple. The engine runs this over
/// every body at apply time as well as plan time, so a plan built
/// elsewhere cannot smuggle a young or referenced body past the checks.
pub fn validate_prune_candidate(
    body: &PruneCandidate,
    retention_days: i32,
) -> Result<(), PruneValidationError> {
    if body.artifact_id.is_nil()
        || body.workspace_id.is_nil()
        || body.object_key.is_empty()
        || body.staging_generation.is_nil()
    {
        return Err(PruneValidationError::IncompleteIdentity);
    }
    if body.size < 0 {
        return Err(PruneValidationError::NegativeSize);
    }
    if body.retention_age_days < retention_days {
        return Err(PruneValidationError::TooYoung);
    }
    if body.reference_count != 0 {
        return Err(PruneValidationError::Referenced);
    }
    Ok(())
}

/// The closed validation-failure vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneValidationError {
    /// Identity triple incomplete or nil.
    IncompleteIdentity,
    /// Negative body size.
    NegativeSize,
    /// Below the retention floor.
    TooYoung,
    /// Still referenced.
    Referenced,
}

impl std::fmt::Display for PruneValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IncompleteIdentity => "destructive: prune body identity is incomplete",
            Self::NegativeSize => "destructive: prune body size is negative",
            Self::TooYoung => "destructive: DELETE_RETENTION_TOO_YOUNG",
            Self::Referenced => "destructive: DELETE_REFERENCED",
        })
    }
}

impl std::error::Error for PruneValidationError {}

/// `PruneInventory` — the read port the plan verb and the apply
/// re-check need: retention-aged, reference-counted bodies. Production
/// queries central PG; tests substitute a fixture.
pub trait PruneInventory: Send + Sync {
    /// `ListPruneEligible`.
    fn list_prune_eligible(
        &self,
        retention_days: i32,
    ) -> Result<Vec<PruneCandidate>, PruneEngineError>;
    /// `ReproveBody` — re-runs the eligibility proof for one body
    /// immediately before its deletion.
    fn reprove_body(
        &self,
        artifact_id: Uuid,
        workspace_id: Uuid,
        retention_days: i32,
    ) -> Result<PruneCandidate, PruneEngineError>;
}

/// `PruneJournal` — the write port for `prune_log` rows, tombstones,
/// and the artifact metadata transition. Production runs as
/// `central_migration` in one transaction per call; the metadata mark
/// is `state='deleted'` (the spec's `pruned` mark without a b30
/// CHECK-widen migration — terminal semantics are identical, and no
/// un-prune exists in either design).
pub trait PruneJournal: Send + Sync {
    /// `MarkBatchApplying` — journals the batch's rows as `applying`.
    fn mark_batch_applying(&self, batch: &PruneBatch) -> Result<(), PruneEngineError>;
    /// `RecordBodyDeleted` — atomically persists the tombstone, the
    /// artifact `deleted` transition, and the `prune_log` settlement
    /// for one body — the one-transaction-per-body boundary.
    fn record_body_deleted(
        &self,
        batch: &PruneBatch,
        body: &PruneCandidate,
        tombstone_id: Uuid,
    ) -> Result<(), PruneEngineError>;
    /// `MarkBatchDone` — the batch's terminal mark.
    fn mark_batch_done(&self, plan_id: Uuid, batch_seq: i32) -> Result<(), PruneEngineError>;
    /// `BatchStates` — every journaled batch state for the plan.
    fn batch_states(&self, plan_id: Uuid) -> Result<HashMap<i32, PruneRowState>, PruneEngineError>;
    /// `HasTombstone` — the tombstone-existence probe resume consults.
    fn has_tombstone(
        &self,
        workspace_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<bool, PruneEngineError>;
}

/// `PruneBodyStore` — deletes one sealed body from object storage.
/// Bodies are deleted only after their metadata commits (ADR 0005).
pub trait PruneBodyStore: Send + Sync {
    /// `DeleteBody`.
    fn delete_body(&self, object_key: &str) -> Result<(), PruneEngineError>;
}

/// `PruneEngine` — the composed D04 execution port: inventory, journal,
/// and body store behind one seam so a composition without PG/MinIO
/// refuses explicitly instead of running degraded.
pub trait PruneEngine: PruneInventory + PruneJournal + PruneBodyStore {}

impl<T> PruneEngine for T where T: PruneInventory + PruneJournal + PruneBodyStore {}

/// The engine call's failure: locator-free, and `stale` marks the one
/// reason that maps to `PRUNE_PLAN_STALE` rather than
/// `PRUNE_ENGINE_FAILED` (`ErrPrunePlanStale`, upstream).
#[derive(Debug)]
pub struct PruneEngineError {
    /// The wrapped failure's message (locator-free).
    pub message: String,
    /// `errors.Is(err, ErrPrunePlanStale)`.
    pub stale: bool,
}

impl PruneEngineError {
    /// A non-stale engine failure.
    #[must_use]
    pub fn engine(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            stale: false,
        }
    }

    /// `ErrPrunePlanStale` — the apply refusal: a body changed between
    /// plan and apply (in practice it gained a reference; age only
    /// grows, so aging out is impossible).
    #[must_use]
    pub fn stale(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            stale: true,
        }
    }
}

impl std::fmt::Display for PruneEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PruneEngineError {}

/// `ApplyPruneBatches` — executes the non-done batches of a plan: mark
/// applying, delete each body (metadata commit → body → tombstone
/// recorded by the journal's transaction; ADR 0005), mark done.
/// Tombstone presence skips a body already deleted by an interrupted
/// run, which is what makes resume idempotent. A body whose re-proof
/// fails stops the run as `stale`: completed batches stay done.
pub fn apply_prune_batches(
    engine: &dyn PruneEngine,
    plan: &PrunePlan,
    retention_days: i32,
) -> Result<(i64, i64), PruneEngineError> {
    let batches = batch_prune_plan(plan);
    let states = engine.batch_states(plan.plan_id)?;
    let mut bodies_deleted: i64 = 0;
    let mut batches_done: i64 = 0;
    for batch in resume_batches(&batches, &states) {
        engine.mark_batch_applying(&batch)?;
        for body in &batch.bodies {
            let reproved =
                engine.reprove_body(body.artifact_id, body.workspace_id, retention_days)?;
            if let Err(e) = validate_prune_candidate(&reproved, retention_days) {
                return Err(PruneEngineError::stale(format!("destructive: {e}")));
            }
            if engine.has_tombstone(body.workspace_id, body.artifact_id)? {
                continue;
            }
            let tombstone_id = Uuid::now_v7();
            engine.record_body_deleted(&batch, &reproved, tombstone_id)?;
            engine.delete_body(&body.object_key)?;
            bodies_deleted += 1;
        }
        engine.mark_batch_done(plan.plan_id, batch.batch_seq)?;
        batches_done += 1;
    }
    Ok((bodies_deleted, batches_done))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(seq: u8) -> PruneCandidate {
        PruneCandidate {
            artifact_id: Uuid::now_v7(),
            workspace_id: Uuid::now_v7(),
            object_key: format!("obj/{seq}"),
            staging_generation: Uuid::now_v7(),
            size: 10,
            retention_age_days: 90,
            reference_count: 0,
        }
    }

    /// `BatchPrunePlan`: 100-per batch, seq from zero, no empty batch.
    #[test]
    fn batch_prune_plan_splits_at_100() {
        let plan = PrunePlan {
            plan_id: Uuid::now_v7(),
            retention_days: 30,
            bodies: (0..250).map(candidate).collect(),
        };
        let batches = batch_prune_plan(&plan);
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].bodies.len(), 100);
        assert_eq!(batches[1].bodies.len(), 100);
        assert_eq!(batches[2].bodies.len(), 50);
        assert_eq!(batches[2].batch_seq, 2);
        let empty = PrunePlan {
            plan_id: Uuid::now_v7(),
            retention_days: 30,
            bodies: vec![],
        };
        assert!(batch_prune_plan(&empty).is_empty());
    }

    /// `ResumeBatches` skips done, replays applying + pending.
    #[test]
    fn resume_batches_skips_done_only() {
        let plan = PrunePlan {
            plan_id: Uuid::now_v7(),
            retention_days: 30,
            bodies: (0..250).map(candidate).collect(),
        };
        let batches = batch_prune_plan(&plan);
        let mut journaled = HashMap::new();
        journaled.insert(0, PruneRowState::Done);
        journaled.insert(1, PruneRowState::Applying);
        let pending = resume_batches(&batches, &journaled);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].batch_seq, 1);
        assert_eq!(pending[1].batch_seq, 2);
    }

    /// `ValidatePruneCandidate` enforces every precondition.
    #[test]
    fn validate_prune_candidate_refuses_each_violation() {
        let good = candidate(1);
        assert!(validate_prune_candidate(&good, 30).is_ok());
        let mut nil_art = good.clone();
        nil_art.artifact_id = Uuid::nil();
        assert_eq!(
            validate_prune_candidate(&nil_art, 30),
            Err(PruneValidationError::IncompleteIdentity)
        );
        let mut empty_key = good.clone();
        empty_key.object_key = String::new();
        assert_eq!(
            validate_prune_candidate(&empty_key, 30),
            Err(PruneValidationError::IncompleteIdentity)
        );
        let mut neg = good.clone();
        neg.size = -1;
        assert_eq!(
            validate_prune_candidate(&neg, 30),
            Err(PruneValidationError::NegativeSize)
        );
        let mut young = good.clone();
        young.retention_age_days = 29;
        assert_eq!(
            validate_prune_candidate(&young, 30),
            Err(PruneValidationError::TooYoung)
        );
        let mut referenced = good.clone();
        referenced.reference_count = 1;
        assert_eq!(
            validate_prune_candidate(&referenced, 30),
            Err(PruneValidationError::Referenced)
        );
    }

    /// In-memory engine recording the exact call order — proves
    /// reprove → tombstone-check → record → delete per body and
    /// applying → done per batch (ADR 0005 ordering).
    #[derive(Default)]
    struct FakeEngine {
        calls: std::sync::Mutex<Vec<String>>,
        tombstoned: std::sync::Mutex<std::collections::HashSet<(Uuid, Uuid)>>,
        states: std::sync::Mutex<HashMap<i32, PruneRowState>>,
        candidates: Vec<PruneCandidate>,
        fail_reprove: bool,
    }

    impl FakeEngine {
        fn log(&self, s: String) {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).push(s);
        }
    }

    impl PruneInventory for FakeEngine {
        fn list_prune_eligible(
            &self,
            _retention_days: i32,
        ) -> Result<Vec<PruneCandidate>, PruneEngineError> {
            Ok(self.candidates.clone())
        }
        fn reprove_body(
            &self,
            artifact_id: Uuid,
            workspace_id: Uuid,
            _retention_days: i32,
        ) -> Result<PruneCandidate, PruneEngineError> {
            self.log(format!("reprove:{artifact_id}"));
            if self.fail_reprove {
                return Ok(PruneCandidate {
                    artifact_id,
                    workspace_id,
                    reference_count: 1,
                    ..candidate(0)
                });
            }
            self.candidates
                .iter()
                .find(|c| c.artifact_id == artifact_id)
                .cloned()
                .ok_or_else(|| PruneEngineError::engine("not found"))
        }
    }

    impl PruneJournal for FakeEngine {
        fn mark_batch_applying(&self, batch: &PruneBatch) -> Result<(), PruneEngineError> {
            self.log(format!("applying:{}", batch.batch_seq));
            self.states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(batch.batch_seq, PruneRowState::Applying);
            Ok(())
        }
        fn record_body_deleted(
            &self,
            _batch: &PruneBatch,
            body: &PruneCandidate,
            _tombstone_id: Uuid,
        ) -> Result<(), PruneEngineError> {
            self.log(format!("record:{}", body.artifact_id));
            self.tombstoned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert((body.workspace_id, body.artifact_id));
            Ok(())
        }
        fn mark_batch_done(&self, _plan_id: Uuid, batch_seq: i32) -> Result<(), PruneEngineError> {
            self.log(format!("done:{batch_seq}"));
            self.states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(batch_seq, PruneRowState::Done);
            Ok(())
        }
        fn batch_states(
            &self,
            _plan_id: Uuid,
        ) -> Result<HashMap<i32, PruneRowState>, PruneEngineError> {
            Ok(self
                .states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone())
        }
        fn has_tombstone(
            &self,
            workspace_id: Uuid,
            artifact_id: Uuid,
        ) -> Result<bool, PruneEngineError> {
            self.log(format!("has_tombstone:{artifact_id}"));
            Ok(self
                .tombstoned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(workspace_id, artifact_id)))
        }
    }

    impl PruneBodyStore for FakeEngine {
        fn delete_body(&self, object_key: &str) -> Result<(), PruneEngineError> {
            self.log(format!("delete:{object_key}"));
            Ok(())
        }
    }

    /// `ApplyPruneBatches` deletes every body once, ordering ADR 0005.
    #[test]
    fn apply_prune_batches_orders_metadata_before_body() {
        let bodies: Vec<PruneCandidate> = (0..3).map(candidate).collect();
        let plan = PrunePlan {
            plan_id: Uuid::now_v7(),
            retention_days: 30,
            bodies: bodies.clone(),
        };
        let engine = FakeEngine {
            candidates: bodies.clone(),
            ..FakeEngine::default()
        };
        let (deleted, done) = apply_prune_batches(&engine, &plan, 30).unwrap();
        assert_eq!((deleted, done), (3, 1));
        let calls = engine.calls.lock().unwrap_or_else(|e| e.into_inner());
        // Per body: reprove → has_tombstone → record → delete.
        for body in &bodies {
            let r = calls
                .iter()
                .position(|c| *c == format!("reprove:{}", body.artifact_id))
                .unwrap();
            let t = calls
                .iter()
                .position(|c| *c == format!("has_tombstone:{}", body.artifact_id))
                .unwrap();
            let m = calls
                .iter()
                .position(|c| *c == format!("record:{}", body.artifact_id))
                .unwrap();
            let d = calls
                .iter()
                .position(|c| *c == format!("delete:{}", body.object_key))
                .unwrap();
            assert!(r < t && t < m && m < d, "order violated: {calls:?}");
        }
        assert_eq!(calls.first().map(String::as_str), Some("applying:0"));
        assert_eq!(calls.last().map(String::as_str), Some("done:0"));
    }

    /// Re-running an apply skips done batches and tombstoned bodies —
    /// a body is never double-deleted.
    #[test]
    fn apply_prune_batches_resume_never_double_deletes() {
        let bodies: Vec<PruneCandidate> = (0..2).map(candidate).collect();
        let plan = PrunePlan {
            plan_id: Uuid::now_v7(),
            retention_days: 30,
            bodies: bodies.clone(),
        };
        let engine = FakeEngine {
            candidates: bodies.clone(),
            ..FakeEngine::default()
        };
        let (a, _) = apply_prune_batches(&engine, &plan, 30).unwrap();
        assert_eq!(a, 2);
        // Second run: batch is done, nothing re-executes.
        let (b, done) = apply_prune_batches(&engine, &plan, 30).unwrap();
        assert_eq!((b, done), (0, 0));
        let calls = engine.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.iter().filter(|c| c.starts_with("delete:")).count(), 2);
    }

    /// A body that gains a reference between plan and apply stops the
    /// run as `stale` — never deleted.
    #[test]
    fn apply_prune_batches_stale_plan_refuses() {
        let bodies: Vec<PruneCandidate> = (0..1).map(candidate).collect();
        let plan = PrunePlan {
            plan_id: Uuid::now_v7(),
            retention_days: 30,
            bodies: bodies.clone(),
        };
        let engine = FakeEngine {
            candidates: bodies,
            fail_reprove: true,
            ..FakeEngine::default()
        };
        let err = apply_prune_batches(&engine, &plan, 30).unwrap_err();
        assert!(err.stale);
        let calls = engine.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!calls.iter().any(|c| c.starts_with("delete:")));
    }

    /// `valid_wipe_target_syntax` admits only a strict direct child.
    #[test]
    fn wipe_target_syntax_rules() {
        let id = InstanceId::new().to_string();
        let root = "/var/lib/central-protected/v1/instances";
        assert!(valid_wipe_target_syntax(&format!("{root}/{id}"), root));
        // Relative, unclean, wrong parent, non-id base — all refused.
        assert!(!valid_wipe_target_syntax(&format!("{root}//{id}"), root));
        assert!(!valid_wipe_target_syntax(&format!("{root}/a/{id}"), root));
        assert!(!valid_wipe_target_syntax(&format!("{root}/{id}/"), root));
        assert!(!valid_wipe_target_syntax(
            &format!("{root}/not-an-id"),
            root
        ));
        assert!(!valid_wipe_target_syntax("relative/path", root));
        assert!(!valid_wipe_target_syntax(&format!("{root}/{id}"), "/other"));
    }

    /// `wipe_resume_request_matches` binds only the exact intent path.
    #[test]
    fn wipe_resume_request_matches_intent_exactly() {
        let id = InstanceId::new().to_string();
        let root = "/var/lib/central-protected/v1/instances";
        let path = format!("{root}/{id}");
        let intent = WipeIntent {
            operation_id: "op".to_owned(),
            instance_id: id.clone(),
            checkpoint_backup_id: "b".to_owned(),
            state_root: path.clone(),
            broker_instance_dir: String::new(),
            started_at: String::new(),
            config_json: String::new(),
        };
        assert!(wipe_resume_request_matches(&path, root, &intent));
        let mut other = intent.clone();
        other.instance_id = InstanceId::new().to_string();
        assert!(!wipe_resume_request_matches(&path, root, &other));
    }

    /// `rewrite_config_for_instance` rebinds identity + paths, keeps
    /// the rest, and emits re-parsable canonical JSON.
    #[test]
    fn rewrite_config_rebinds_instance() {
        let cfg = crate::config::testutil::valid_config();
        let new_id = InstanceId::new();
        let out = rewrite_config_for_instance(&cfg, new_id, "/new/root").unwrap();
        let parsed = crate::config::parse(&out).unwrap();
        assert_eq!(parsed.instance_id, new_id);
        assert_eq!(parsed.paths.authoritative_state_root, "/new/root");
        assert_eq!(parsed.paths.instance_data_root, "/new/root/data");
        assert_eq!(parsed.paths.backup_repository_root, "/new/root/backups");
        // Canonical output is byte-stable.
        let out2 = rewrite_config_for_instance(&out, new_id, "/new/root").unwrap();
        assert_eq!(out, out2);
        assert!(rewrite_config_for_instance(b"{}", new_id, "/new/root").is_err());
    }
}
