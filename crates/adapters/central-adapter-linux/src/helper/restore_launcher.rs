//! `cmd/central/restore_engine_launcher.go` +
//! `restore_capacity_reserve_launch.go` +
//! `restore_resolvers.go`'s verify-candidate half — the root helper's
//! `central-restore` process launcher and the reserve allocation that
//! must physically exist before a verify engine is released.
//!
//! The launcher runs the root recovery engine as a direct child of
//! the root helper. It passes exactly the fixed descriptor contract
//! and no path, credential, connection string, or configuration: the
//! engine's whole world is the protected root, the recovery
//! repository, the four capacity role roots, the launch gate, and two
//! opaque identities.
//!
//! Ordering is the design's, structural rather than conventional:
//!
//!  1. `bind_and_run` `Start`s the child so this process — the real
//!     kernel parent — learns its PID, reads `/proc` for the
//!     executable and process-start the broker re-derives, and binds
//!     that identity through `restore_issue_launch` *before* the
//!     child can complete its first daemon call.
//!  2. The gate pipe (child fd 9) is written only after the bind
//!     durably succeeded; a bind failure closes it unwritten, which
//!     the child's blocking read observes as EOF — an explicit denial
//!     it fails closed on.
//!  3. The verify launch's reserve allocation runs in exactly that
//!     post-bind, pre-release window: frame `0xc3` admits only a peer
//!     the launch record names, and the engine's admission must never
//!     observe a half-written reserve. Apply/resume pass no
//!     allocator: they spend the reserve the verify launch created.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use central_backup::backup::capacity::{RoleRoots, default_recovery_profile};
use central_backup::recovery::refusal::RestoreRefusalReason;
use central_foundation::failure::Failure;
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use time::OffsetDateTime;
use uuid::Uuid;

use super::restore::{
    RESTORE_CEREMONY_DEADLINE, RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS,
    RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP, RestoreEngineLauncher, RestoreEngineReceipt,
    RestoreVerifyReceipt, RestoreVerifyRunner, new_restore_refusal,
};
use crate::backup::repository::{self, Repository};
use crate::broker::daemon::ProductionInstanceComposition;
use crate::broker::restore_capacity::allocation::ReserveAllocator;
use crate::broker::restore_capacity::helper::ReserveHelperAuthority;
use crate::broker::restore_capacity::reserve_frame::{
    AllocationConfirmation, ReserveClient, ReserveSetRequest,
};
use crate::broker::restore_capacity::sweep::{ReleaseTrigger, SweepCaller};
use crate::broker::restore_capacity::{RESERVE_ROLES, ReserveRole};
use crate::broker::restore_launch::{
    RESTORE_ENGINE_EXECUTABLE_PATH, RestoreLaunchClientEvidence, RestoreLaunchIssuer,
};

/// `restoreEngineReceiptLimit`.
const RESTORE_ENGINE_RECEIPT_LIMIT: usize = 4096;
/// `restoreEngineSchema`.
const RESTORE_ENGINE_SCHEMA: &str = "central.restore-engine-receipt/v1";
/// `restoreLaunchGateReleaseByte` — the one byte `bind_and_run`
/// writes to release its child once the bind has durably succeeded.
/// It must name the exact same value as `central-restore`'s own
/// release byte — the two sides intentionally share no common
/// constants package, so this duplication is deliberate and must be
/// kept in lockstep by hand.
const RESTORE_LAUNCH_GATE_RELEASE_BYTE: u8 = 0x01;
/// `restoreEngineInheritedDescriptorCount` — exactly the
/// protected-root, repository and four capacity-role-root descriptors
/// every launcher maps before calling `bind_and_run`, which then
/// appends the gate read end. In fixed order: fd 3 protected root,
/// fd 4 repository, fds 5–8 role roots in [`RESERVE_ROLES`] order,
/// fd 9 launch gate. Import launches append one more descriptor at
/// fd 10.
const RESTORE_ENGINE_INHERITED_DESCRIPTOR_COUNT: usize = 6;
/// `restoreLaunchGateMessageSize` — the release byte plus the
/// 16-byte reserve-set identity (all-zero for apply/resume, which
/// allocate nothing).
const RESTORE_LAUNCH_GATE_MESSAGE_SIZE: usize = 1 + 16;
/// `restoreVerifyEngineMediaWalks` — how many full SHA-256 walks of
/// the dump and every artifact body a verify child performs inside
/// its own window: exactly one, in `RestoreVerifier::verify`. The
/// launcher's own walk in [`reserve_set_request`] is deliberately not
/// counted: it runs before this window opens, in the privileged
/// process, so the helper sizes a physical reserve from evidence it
/// read itself rather than from figures the engine supplied.
const RESTORE_VERIFY_ENGINE_MEDIA_WALKS: u64 = 1;
/// The closed environment every engine launch runs under — nothing
/// the operator or a parent unit set can reach the engine or the
/// `pg_restore` process it spawns.
const ENGINE_ENVIRONMENT: [&str; 4] = [
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C",
    "LC_ALL=C",
    "TZ=UTC",
];

fn denied() -> Failure {
    Failure::internal("restore_engine_launch", "restore engine launch denied")
}

fn run_failed() -> Failure {
    Failure::internal("restore_engine_launch", "restore engine run failed")
}

fn receipt_unavailable() -> Failure {
    Failure::internal(
        "restore_engine_launch",
        "restore engine receipt unavailable",
    )
}

/// `reportRestoreCapacityReserveSweepFailure` — the one place a sweep
/// or publish failure is surfaced. It writes to stderr and returns:
/// neither is a reason to refuse a recovery.
fn report_sweep_failure(site: &str, err: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "central: restore capacity reserve sweep ({site}): {err}"
    );
}

// ---------------------------------------------------------------------------
// MinIO preparer seams — `restore_minio_composition.go` /
// `import_minio_composition.go`. The restore-side production
// preparer lives in `helper/minio_provision.rs`
// (`ProductionRestoreMinioPreparer`, the real chain the ported
// `ProductionInstanceComposition` now feeds). The import writer is
// still uncomposed — `import_minio` stays `None` and the import
// launch refuses at the exact rung upstream's nil check sits.
// ---------------------------------------------------------------------------

/// `restoreMinioCredentialPreparer` — mints the operation-bound,
/// read-only MinIO identity `VerifyInventory` needs. Only
/// `launch_restore` (apply/resume) reads it; verify never runs
/// `VerifyInventory` and never touches this seam.
pub trait RestoreMinioCredentialPreparer: Send + Sync {
    /// `PrepareRestoreMinio`.
    fn prepare_restore_minio(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), Failure>;
}

/// `importMinioCredentialPreparer` — the `minio_import_v1` writer the
/// import launch mints.
pub trait ImportMinioCredentialPreparer: Send + Sync {
    /// `PrepareImportMinio`.
    fn prepare_import_minio(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), Failure>;
}

/// `restoreMinioHandoffExpiry` — the operation's absolute expiry on
/// its own minted-at timestamp: the UUIDv7's embedded millisecond
/// clock plus `RestoreOperationAbsoluteLifetime`'s 8h, the same bound
/// the capacity reserve set fixes the whole operation to. A fresh
/// resume mints the identical request and lands on the already-bound
/// fast path instead of being refused as a mismatched replay.
fn restore_minio_handoff_expiry(operation_id: Uuid) -> Result<OffsetDateTime, Failure> {
    if operation_id.is_nil() || operation_id.get_version_num() != 7 {
        return Err(Failure::internal(
            "restore_engine_launch",
            "restore MinIO handoff expiry requires a UUIDv7 operation identity",
        ));
    }
    let bytes = operation_id.as_bytes();
    let millis = i64::from(bytes[0]) << 40
        | i64::from(bytes[1]) << 32
        | i64::from(bytes[2]) << 24
        | i64::from(bytes[3]) << 16
        | i64::from(bytes[4]) << 8
        | i64::from(bytes[5]);
    let minted_at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|_| denied())?;
    Ok(minted_at + crate::broker::restore_capacity::RESERVE_ABSOLUTE_LIFETIME)
}

/// `importMinioHandoffExpiry` — the same operation-absolute expiry
/// for the import writer (ADR 0034 pins the identical bound).
fn import_minio_handoff_expiry(operation_id: Uuid) -> Result<OffsetDateTime, Failure> {
    restore_minio_handoff_expiry(operation_id)
}

// ---------------------------------------------------------------------------
// Descriptor opens — `openRestoreEngineRoot`,
// `openRestoreEngineRepository`, `openRestoreEngineRoleRoots`,
// `openImportStagingDir`.
// ---------------------------------------------------------------------------

/// `openRestoreEngineRoot` — the protected root the engine uses as
/// its broker state. Ownership is checked here, in the helper, so
/// the engine never has to trust a pathname it was handed.
fn open_restore_engine_root(path: &Path) -> Result<OwnedFd, Failure> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| {
        Failure::internal(
            "restore_engine_launch",
            "restore engine protected root unavailable",
        )
    })?;
    let st = fstat(&fd).map_err(|_| {
        Failure::internal(
            "restore_engine_launch",
            "restore engine protected root unavailable",
        )
    })?;
    if st.st_uid != 0 || st.st_gid != 0 || st.st_mode & 0o777 != 0o700 {
        return Err(Failure::internal(
            "restore_engine_launch",
            "restore engine protected root unavailable",
        ));
    }
    Ok(fd)
}

/// `openRestoreEngineRepository` — opens the recovery repository and
/// confirms its immutable binding names this instance before the
/// descriptor is handed on.
fn open_restore_engine_repository(root: &Path, instance_id: &str) -> Result<OwnedFd, Failure> {
    let fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| {
        Failure::internal(
            "restore_engine_launch",
            "restore engine repository unavailable",
        )
    })?;
    let binding = repository::inspect_repository_descriptor(&fd).map_err(|_| {
        Failure::internal(
            "restore_engine_launch",
            "restore engine repository unavailable",
        )
    })?;
    if !instance_id.is_empty() && binding.instance_id != instance_id {
        return Err(Failure::internal(
            "restore_engine_launch",
            "restore engine repository unavailable",
        ));
    }
    Ok(fd)
}

/// `restoreEngineRoleRootPath` maps one capacity role onto its host
/// directory. It is the launcher's single mapping, so no second
/// switch statement can point a descriptor at a different directory
/// than the one the helper's own allocator measured and allocated
/// beneath.
fn role_root_path(roots: &RoleRoots, role: ReserveRole) -> &str {
    role.root(roots)
}

/// `openRestoreEngineRoleRoots` opens the four capacity-role host
/// directories in [`RESERVE_ROLES`] order as the inherited fds 5–8.
///
/// The predicate is deliberately the one the helper's own allocator
/// applies to the same directories (a directory, with a non-zero
/// `st_dev`, reached without following a symlink) and deliberately
/// *not* [`open_restore_engine_root`]'s `root:root 0700` predicate.
/// The protected root is state this codebase creates and owns; a
/// capacity role root is a service data directory — PostgreSQL's data
/// directory is chowned by the container that runs it — so requiring
/// 0700 root:root here would refuse every production host while
/// telling the operator their disk was at fault. What must agree is
/// the helper and the engine: they measure the same descriptor for
/// the same device, and a fingerprint mismatch between them is a
/// refusal the frozen consumer already makes.
fn open_restore_engine_role_roots(roots: &RoleRoots) -> Result<Vec<OwnedFd>, Failure> {
    let unavailable = || {
        Failure::internal(
            "restore_engine_launch",
            "restore engine capacity role root unavailable",
        )
    };
    let mut files = Vec::with_capacity(RESERVE_ROLES.len());
    for role in RESERVE_ROLES {
        let path = role_root_path(roots, role);
        if path.is_empty() || !path.starts_with('/') {
            return Err(unavailable());
        }
        let fd = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| unavailable())?;
        let st = fstat(&fd).map_err(|_| unavailable())?;
        if !FileType::from_raw_mode(st.st_mode).is_dir() || st.st_dev == 0 {
            return Err(unavailable());
        }
        files.push(fd);
    }
    Ok(files)
}

/// `openImportStagingDir` opens the staged work dir for exactly one
/// import operation: `<parent>/import-<op>`, derived here, never
/// accepted. The directory must be root-owned `0700` like every other
/// inherited root; anything else — including a missing staging —
/// denies the launch.
fn open_import_staging_dir(parent: &Path, operation_id: Uuid) -> Result<OwnedFd, Failure> {
    let unavailable = || {
        Failure::internal(
            "restore_engine_launch",
            "restore engine import staging unavailable",
        )
    };
    if parent.as_os_str().is_empty()
        || !parent.is_absolute()
        || operation_id.is_nil()
        || operation_id.get_version_num() != 7
    {
        return Err(unavailable());
    }
    let work = parent.join(format!("import-{operation_id}"));
    if work.parent() != Some(parent) {
        return Err(unavailable());
    }
    let fd = open(
        &work,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| unavailable())?;
    let st = fstat(&fd).map_err(|_| unavailable())?;
    if st.st_uid != 0 || st.st_gid != 0 || st.st_mode & 0o777 != 0o700 {
        return Err(unavailable());
    }
    Ok(fd)
}

// ---------------------------------------------------------------------------
// `restore_capacity_reserve_launch.go` — the allocation call site.
// ---------------------------------------------------------------------------

/// `restoreCapacityReserveSetRequest` derives the sealed figures one
/// reserve set records from the repository descriptor this helper
/// already opened and validated. Every value is read from the sealed
/// recovery evidence: nothing an operator, a helper request, or the
/// engine could name reaches it.
fn reserve_set_request(
    repository_fd: &OwnedFd,
    backup_id: Uuid,
) -> Result<ReserveSetRequest, Failure> {
    let binding = repository::inspect_repository_descriptor(repository_fd)
        .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
    let repository = Repository::read_only_from_descriptor(repository_fd, &binding)
        .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
    let evidence = repository
        .verify_backup(backup_id, &default_recovery_profile())
        .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
    if evidence.backup_id != backup_id
        || evidence.repository_binding_id != binding.binding_id
        || evidence.dump.size <= 0
    {
        return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(ReserveSetRequest {
        backup_id,
        repository_binding_id: evidence.repository_binding_id,
        dump_bytes: evidence.dump.size as u64,
        object_bytes: evidence.object_bytes,
        artifact_count: evidence.artifact_count,
    })
}

/// `allocateRestoreCapacityReserve` is the helper's allocation call
/// site. The ordering is the design's and is structural, not
/// conventional:
///
///  1. `plan` measures the four role roots from held descriptors and
///     applies every refusal that can be decided before anything is
///     written. It has no physical effect, so a refusal here needs no
///     release.
///  2. The set record is created (frame `0xc3` kind 1) and then one
///     member intent per role (kind 2), *before* any physical object
///     exists.
///  3. `allocate` creates and fallocates one object per device,
///     re-measures, and releases everything it created on any
///     refusal.
///  4. Each role's allocation is confirmed (kind 3), which is the
///     only thing that moves a member from intent to allocated, and
///     the daemon proves the object for itself before it does.
///
/// It returns the set identity it created even when it then fails, so
/// the caller can fire `verify_failed_before_binding` against it. A
/// failure before the set exists returns [`Uuid::nil`], and there is
/// nothing to release.
fn allocate_restore_capacity_reserve(
    writer: &ReserveClient,
    roots: &RoleRoots,
    request: &ReserveSetRequest,
) -> (Uuid, Result<(), Failure>) {
    let unavailable = || RestoreRefusalReason::EngineUnavailable.into_failure();
    if request.backup_id.is_nil() || request.repository_binding_id.is_nil() {
        return (Uuid::nil(), Err(unavailable()));
    }
    let Some(demand) = central_backup::backup::capacity::restore_capacity_demands(
        request.dump_bytes,
        request.object_bytes,
        request.artifact_count,
    ) else {
        return (Uuid::nil(), Err(unavailable()));
    };
    let allocator = match ReserveAllocator::new(roots.clone()) {
        Ok(a) => a,
        Err(e) => return (Uuid::nil(), Err(e)),
    };
    let plan = match allocator.plan(&demand, OffsetDateTime::now_utc()) {
        Ok(p) => p,
        Err(e) => return (Uuid::nil(), Err(e)),
    };
    let outcome = (|plan: &crate::broker::restore_capacity::allocation::ReservePlan<'_>| {
        let set_id = match writer.create_reserve_set(request) {
            Ok(id) => id,
            Err(e) => return (Uuid::nil(), Err(e)),
        };
        if set_id.is_nil() {
            return (Uuid::nil(), Err(unavailable()));
        }
        let intents = plan.member_intents();
        if intents.len() != RESERVE_ROLES.len() {
            return (set_id, Err(unavailable()));
        }
        let mut complete = false;
        for intent in &intents {
            match writer.create_reserve_member(set_id, intent) {
                Ok(done) => complete = done,
                Err(e) => return (set_id, Err(e)),
            }
        }
        if !complete {
            // The daemon's own answer from the durable records, not
            // this process's count: a set it does not consider
            // complete must never be allocated against.
            return (set_id, Err(unavailable()));
        }
        let allocations = match plan.allocate() {
            Ok(a) => a,
            Err(e) => return (set_id, Err(e)),
        };
        let mut allocated = false;
        for allocation in &allocations {
            let confirmation = AllocationConfirmation {
                role: allocation.role,
                observed_free_bytes: allocation.observed_free_bytes,
                observed_at: allocation.observed_at,
            };
            match writer.confirm_reserve_allocation(set_id, &confirmation) {
                Ok(done) => allocated = done,
                Err(e) => return (set_id, Err(e)),
            }
        }
        if !allocated {
            return (set_id, Err(unavailable()));
        }
        (set_id, Ok(()))
    })(&plan);
    plan.close();
    outcome
}

// ---------------------------------------------------------------------------
// Receipt decoders — bounded, schema-matched, locator-free.
// ---------------------------------------------------------------------------

/// `decodeRestoreEngineRefusal` decodes the bounded, locator-free
/// refusal receipt `central-restore` emits when apply/resume is
/// refused. It is a separate function from
/// [`decode_restore_engine_receipt`], not a relaxation of it: the
/// success decoder's `deny_unknown_fields` rejects any document
/// carrying `reason`, so the two shapes cannot be confused. This is
/// the only place a reason is trusted, and it performs the identical
/// schema/mode/operation-identity match the success decoder performs.
fn decode_restore_engine_refusal(
    raw: &[u8],
    mode: &str,
    operation_id: Uuid,
) -> Result<RestoreRefusalReason, Failure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RefusalWire {
        schema_version: String,
        mode: String,
        operation_id: String,
        reason: String,
    }
    if raw.is_empty() || raw.len() > RESTORE_ENGINE_RECEIPT_LIMIT {
        return Err(receipt_unavailable());
    }
    let document: RefusalWire = serde_json::from_slice(raw).map_err(|_| receipt_unavailable())?;
    if document.schema_version != RESTORE_ENGINE_SCHEMA
        || document.mode != mode
        || document.operation_id != operation_id.to_string()
    {
        return Err(receipt_unavailable());
    }
    RestoreRefusalReason::from_wire(&document.reason).ok_or_else(receipt_unavailable)
}

/// `decodeRestoreEngineReceipt` accepts exactly one bounded canonical
/// document for the exact mode and operation. Unknown fields,
/// trailing bytes, and a substituted operation are all failures, not
/// warnings.
fn decode_restore_engine_receipt(
    raw: &[u8],
    mode: &str,
    operation_id: Uuid,
) -> Result<RestoreEngineReceipt, Failure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReceiptWire {
        schema_version: String,
        mode: String,
        operation_id: String,
        #[allow(dead_code)]
        backup_id: String,
        phase: String,
        checkpoint: String,
        #[allow(dead_code)]
        expires_at: String,
    }
    if raw.is_empty() || raw.len() > RESTORE_ENGINE_RECEIPT_LIMIT {
        return Err(receipt_unavailable());
    }
    let document: ReceiptWire = serde_json::from_slice(raw).map_err(|_| receipt_unavailable())?;
    if document.schema_version != RESTORE_ENGINE_SCHEMA
        || document.mode != mode
        || document.operation_id != operation_id.to_string()
        || document.phase.is_empty()
        || document.checkpoint.is_empty()
    {
        return Err(receipt_unavailable());
    }
    Ok(RestoreEngineReceipt {
        operation_id: document.operation_id,
        phase: document.phase,
        checkpoint: document.checkpoint,
    })
}

/// `decodeRestoreVerifyEngineRefusal` is verify's own refusal
/// decoder. It has no operation identity to match against: a failed
/// verify never minted one, so nothing this caller supplied could be
/// substituted through it. Schema and mode are still required, and —
/// since its wire carries neither a phase nor a checkpoint field —
/// a genuine completed-verify or apply/resume receipt is rejected
/// here just as this document would be rejected by
/// [`decode_restore_verify_engine_receipt`].
fn decode_restore_verify_engine_refusal(raw: &[u8]) -> Result<RestoreRefusalReason, Failure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RefusalWire {
        schema_version: String,
        mode: String,
        reason: String,
    }
    if raw.is_empty() || raw.len() > RESTORE_ENGINE_RECEIPT_LIMIT {
        return Err(receipt_unavailable());
    }
    let document: RefusalWire = serde_json::from_slice(raw).map_err(|_| receipt_unavailable())?;
    if document.schema_version != RESTORE_ENGINE_SCHEMA || document.mode != "verify" {
        return Err(receipt_unavailable());
    }
    RestoreRefusalReason::from_wire(&document.reason).ok_or_else(receipt_unavailable)
}

/// `restoreVerifyEngineReceipt` — the safe, non-mutating verify
/// result the engine reports. Unlike the apply/resume receipt it has
/// no phase or checkpoint: verify never advances an operation to a
/// phase, so a genuine verify receipt cannot carry either field.
#[derive(Debug, Clone)]
pub struct RestoreVerifyEngineReceipt {
    pub operation_id: String,
    pub backup_id: String,
    pub expires_at: String,
}

/// `decodeRestoreVerifyEngineReceipt` is verify's own decoder,
/// deliberately separate from [`decode_restore_engine_receipt`] and
/// with its own required-field set. A receipt bearing a phase or
/// checkpoint is an apply/resume receipt, never a verify one, so it
/// is refused outright rather than partially trusted.
fn decode_restore_verify_engine_receipt(
    raw: &[u8],
    backup_id: Uuid,
) -> Result<RestoreVerifyEngineReceipt, Failure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReceiptWire {
        schema_version: String,
        mode: String,
        operation_id: String,
        backup_id: String,
        #[serde(default)]
        phase: Option<String>,
        #[serde(default)]
        checkpoint: Option<String>,
        expires_at: String,
    }
    if raw.is_empty() || raw.len() > RESTORE_ENGINE_RECEIPT_LIMIT {
        return Err(receipt_unavailable());
    }
    let document: ReceiptWire = serde_json::from_slice(raw).map_err(|_| receipt_unavailable())?;
    if document.schema_version != RESTORE_ENGINE_SCHEMA
        || document.mode != "verify"
        || document.phase.as_deref().is_some_and(|p| !p.is_empty())
        || document
            .checkpoint
            .as_deref()
            .is_some_and(|c| !c.is_empty())
    {
        // A phase or checkpoint is an apply/resume shape wearing a
        // verify label; refuse it rather than accept it as a degraded
        // verify.
        return Err(receipt_unavailable());
    }
    let Ok(operation_id) = Uuid::parse_str(&document.operation_id) else {
        return Err(receipt_unavailable());
    };
    if operation_id.is_nil()
        || operation_id.get_version_num() != 7
        || operation_id.to_string() != document.operation_id
    {
        // The verify receipt's operation identity is minted inside
        // issuance, so — unlike apply/resume — there is nothing this
        // caller supplied to match it against. It is validated for
        // shape only.
        return Err(receipt_unavailable());
    }
    if document.backup_id != backup_id.to_string() || document.expires_at.is_empty() {
        return Err(receipt_unavailable());
    }
    if OffsetDateTime::parse(
        &document.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .is_err()
    {
        return Err(receipt_unavailable());
    }
    Ok(RestoreVerifyEngineReceipt {
        operation_id: document.operation_id,
        backup_id: document.backup_id,
        expires_at: document.expires_at,
    })
}

/// `decodeRestoreImportEngineReceipt` trusts only the terminal
/// vocabulary: the exact schema, mode, and operation identity plus
/// phase `imported` and checkpoint `plan_consumed` — the only success
/// words an import run emits. Anything else, including a
/// restore-shaped receipt with a real phase, is unavailable rather
/// than trusted.
fn decode_restore_import_engine_receipt(
    raw: &[u8],
    operation_id: Uuid,
) -> Result<RestoreEngineReceipt, Failure> {
    let receipt = decode_restore_engine_receipt(raw, "import", operation_id)?;
    if receipt.phase != "imported" || receipt.checkpoint != "plan_consumed" {
        return Err(receipt_unavailable());
    }
    Ok(receipt)
}

/// `restoreEngineReceiptPhaseIsTerminal` — the one decision the
/// post-receipt sweep hangs on: only a terminal phase releases. The
/// spellings are the domain's.
fn receipt_phase_is_terminal(phase: &str) -> bool {
    phase == "ready" || phase == "abandoned"
}

// ---------------------------------------------------------------------------
// `productionRestoreEngineLauncher`.
// ---------------------------------------------------------------------------

/// `restoreVerifyLauncher` is the seam
/// [`ProductionRestoreVerifyRunner`] depends on, narrowed to the one
/// method it needs.
pub trait RestoreVerifyLauncher: Send + Sync {
    /// `LaunchRestoreVerify`.
    fn launch_restore_verify(
        &self,
        deadline: Instant,
        backup_id: Uuid,
    ) -> Result<RestoreVerifyEngineReceipt, Failure>;
}

/// `restoreVerifyArgv` — the exact, single-argument invocation shape
/// `central-restore verify` expects: the mode plus the one backup
/// identity being verified.
fn restore_verify_argv(backup_id: Uuid) -> [String; 2] {
    ["verify".to_owned(), backup_id.to_string()]
}

/// `restoreImportArgv` — the whole import command line: the launcher's
/// own executable literal plus the two words above it. It shares
/// nothing with the apply/resume argv builder because import takes
/// one identity, not two: there is no authorization record for
/// foreign data.
fn restore_import_argv(operation_id: Uuid) -> [String; 2] {
    ["import".to_owned(), operation_id.to_string()]
}

/// `restoreApplyEngineDeadline` bounds one destructive run. It is
/// not a number of its own: the helper's transport budget for
/// restore-apply and restore-resume is the ceremony's share plus the
/// engine's, and the engine runs *under* that transport context, so
/// an engine budget larger than what the transport leaves is not a
/// longer run — it is a SIGKILL partway through `pg_restore`. This
/// function therefore takes what the transport leaves: the published
/// transport budget minus the published ceremony share. A nonsense
/// derivation fails closed to zero, which `launch_restore` refuses
/// rather than launching under.
fn restore_apply_engine_deadline() -> Duration {
    let transport = super::server::restore_apply_deadline();
    transport.saturating_sub(RESTORE_CEREMONY_DEADLINE)
}

/// `restoreVerifyEngineDeadline` bounds one non-mutating verify run.
/// The derivation is the profile's own admitted envelope: the media
/// this profile calls supported, at the floor throughput this profile
/// calls supported, times [`RESTORE_VERIFY_ENGINE_MEDIA_WALKS`], plus
/// a margin, clamped to the profile's maximum.
fn restore_verify_engine_deadline() -> Duration {
    default_recovery_profile()
        .media_verification_deadline(RESTORE_VERIFY_ENGINE_MEDIA_WALKS)
        .map(|d| d.unsigned_abs())
        .unwrap_or(Duration::ZERO)
}

/// `restoreImportEngineDeadline` — the import run's share of the
/// import transport budget: transport minus ceremony minus staging.
/// The import verb's budgets are unported in this slice, so the
/// derivation yields zero and `launch_restore_import` refuses —
/// upstream's fail-closed arm, not a made-up figure.
fn restore_import_engine_deadline() -> Duration {
    Duration::ZERO
}

/// `productionRestoreEngineLauncher` runs the root recovery engine
/// as a direct child of the root helper.
pub struct ProductionRestoreEngineLauncher {
    protected_root: PathBuf,
    backup_repository_root: PathBuf,
    instance_id: String,
    /// `l.deadline` — the apply/resume engine share.
    deadline: Duration,
    launch_issuer: RestoreLaunchIssuer,
    /// `roleRoots` — the four capacity-role host directories this
    /// launcher opens and hands the engine as fds 5–8, and the same
    /// value the helper's own reserve allocator measures and
    /// allocates beneath. One value, two consumers, so the engine's
    /// descriptors and the helper's allocation can never name
    /// different directories.
    role_roots: RoleRoots,
    /// `reserveWriter` — frame `0xc3`, the helper's protected write
    /// path for the reserve set and its four member records.
    reserve_writer: ReserveClient,
    /// `reserveHelper` — the narrow in-process view of the reserve's
    /// protected state the sweep and the inspection publisher run
    /// over. `None` when its own construction failed — a verify
    /// launch refuses rather than launching an engine whose admission
    /// can never be judged; the post-terminal sweep skips instead of
    /// failing a restore that already completed.
    reserve_helper: std::sync::Mutex<Option<ReserveHelperAuthority>>,
    /// `minio` provisions the operation-bound, read-only MinIO
    /// identity `VerifyInventory` needs. Only `launch_restore`
    /// (apply/resume) reads it; `launch_restore_verify` never runs
    /// `VerifyInventory` and never touches this field. Production
    /// composes `ProductionRestoreMinioPreparer`; `launch_restore`
    /// still checks `None` itself and refuses before doing anything
    /// destructive, so a construction that tolerated the preparer
    /// failing narrows only apply/resume — the rung upstream's own
    /// nil check sits on.
    minio: Option<Box<dyn RestoreMinioCredentialPreparer>>,
    /// ADR 0034's import-launch collaborators, read only by
    /// `launch_restore_import`.
    import_deadline: Duration,
    import_staging_parent: PathBuf,
    import_minio: Option<Box<dyn ImportMinioCredentialPreparer>>,
}

impl ProductionRestoreEngineLauncher {
    /// `newProductionRestoreEngineLauncher`.
    ///
    /// # Errors
    /// Returns `Err` when the protected root or repository root cannot
    /// resolve — upstream fails the helper's composition identically.
    pub fn new_production(
        composition: &ProductionInstanceComposition,
        broker_socket: &Path,
    ) -> Result<Self, Failure> {
        let protected_root = crate::broker::daemon::production_broker_root_at(
            composition,
            crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES,
            0,
            0,
        )
        .map_err(|_| denied())?;
        let backup_repository_root =
            Path::new(&composition.authoritative_state_root).join("backups");
        if backup_repository_root.as_os_str().is_empty() || !backup_repository_root.is_absolute() {
            return Err(denied());
        }
        // `newProductionRestoreCapacityReserveHelper` tolerates its
        // own construction failing rather than propagating: before
        // this policy existed, the constructor's error took down every
        // helper verb — including backup — on exactly the condition
        // ("the disk is full") the reserve feature exists to survive.
        // `launch_restore_verify` already refuses outright when
        // `reserve_helper` is `None`, so tolerating the failure here
        // narrows only the verify path plus the post-terminal sweep.
        let reserve_helper = match ReserveHelperAuthority::new(
            &protected_root,
            composition.role_roots.clone(),
            SweepCaller::HelperRestoreLauncher,
        ) {
            Ok(authority) => Some(authority),
            Err(e) => {
                report_sweep_failure("restore-launcher-startup", e.message());
                None
            }
        };
        let reserve_helper = std::sync::Mutex::new(reserve_helper);
        Ok(Self {
            protected_root,
            backup_repository_root,
            instance_id: composition.instance_id.clone(),
            deadline: restore_apply_engine_deadline(),
            launch_issuer: RestoreLaunchIssuer::new(broker_socket.to_string_lossy().into_owned()),
            role_roots: composition.role_roots.clone(),
            reserve_writer: ReserveClient::new(broker_socket.to_path_buf()),
            reserve_helper,
            // `newProductionRestoreMinioPreparer` — the real
            // provisioner chain: active dependency receipt → pinned
            // image → exact compose model → broker rendezvous →
            // scoped policy digest → operation-bound handoff →
            // container run + strict receipt. Upstream fails the
            // launcher when it cannot be composed, so its error
            // propagates here identically.
            minio: Some(Box::new(
                crate::helper::minio_provision::ProductionRestoreMinioPreparer::new_production(
                    composition,
                    broker_socket,
                )?,
            )),
            import_deadline: restore_import_engine_deadline(),
            // `filepath.Dir(AuthoritativeStateRoot)`: the
            // instances-parent directory. `Path::parent` returns
            // `None` for `/` where `filepath.Dir` returns `/`
            // itself — an unreachable input on a validated
            // absolute composition root, mirrored anyway.
            import_staging_parent: {
                let root = Path::new(&composition.authoritative_state_root);
                match root.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
                    Some(_) => PathBuf::from("."),
                    None => root.to_path_buf(),
                }
            },
            import_minio: None,
        })
    }

    /// `bindAndRun` is `command.run()` split into its two halves
    /// around the one step ADR 0015 requires in between: `spawn` so
    /// this process — the actual kernel parent — learns the child's
    /// real PID, then a bind that hands that PID, its resolved
    /// executable, and its process-start identity to the broker
    /// before the child can possibly complete its own first daemon
    /// call, then `wait`. A bind failure kills the child's whole
    /// process group rather than letting an unbound engine run on.
    ///
    /// The gate pipe closes the scheduling gap: the child's own first
    /// action is an unconditional blocking read of fd 9, appended
    /// here as the last mapped descriptor. Nothing is ever written to
    /// it until the bind has durably succeeded, so the child cannot
    /// reach its first daemon call before that point regardless of
    /// scheduling. A bind failure closes the write end without
    /// writing anything, which the child's blocking read observes as
    /// EOF — an explicit denial the child itself fails closed on.
    ///
    /// `allocate` is the one step that legitimately runs between the
    /// launch record being durably issued and the child being
    /// released: the reserve allocation a `restore verify` launch
    /// performs. It returns the reserve set identity it created,
    /// carried to the child in the gate's release message. Apply and
    /// resume pass `None` — they allocate nothing, and spend a
    /// reserve the verify launch already created.
    ///
    /// It runs *after* `issue_restore_launch` because frame `0xc3`'s
    /// predicate needs the launch record this helper's PID is
    /// recorded on, and *before* the gate is released because the
    /// engine's first daemon call must not be able to observe a
    /// half-written reserve.
    ///
    /// Returns the child's captured stdout on every path after
    /// `spawn` — `central-restore`'s receipt is its only channel back
    /// to this launcher (stderr is discarded), so a refusal still
    /// attempts to publish a bounded, locator-free reason there.
    /// `(empty, Err)` is a pre-spawn denial; `(bytes, Err)` a
    /// post-spawn failure the caller's refusal decoders get first
    /// sight of.
    #[allow(clippy::too_many_arguments)]
    fn bind_and_run(
        &self,
        command: &mut Command,
        mode: &str,
        launch_deadline: OffsetDateTime,
        run_deadline: Instant,
        mut fd_map: Vec<(RawFd, i32)>,
        allocate: Option<&dyn Fn() -> (Uuid, Result<(), Failure>)>,
        import_staging: Option<OwnedFd>,
        held_fds: Vec<OwnedFd>,
    ) -> (Vec<u8>, Result<(), Failure>) {
        // Exactly the protected-root, repository and four
        // capacity-role-root descriptors every launcher maps before
        // calling this function: the gate must land at the fixed fd
        // `central-restore`'s launch gate reads from, never at
        // whatever number an unexpected map shape would produce.
        if fd_map.len() != RESTORE_ENGINE_INHERITED_DESCRIPTOR_COUNT {
            return (Vec::new(), Err(denied()));
        }
        // The import staging descriptor travels only on import
        // launches, and only after the gate: the gate must stay fd 9
        // for every mode, and a restore launch carrying staging (or an
        // import launch missing it) is a composition defect that
        // denies rather than mis-describes.
        if (mode == "import") == import_staging.is_none() {
            return (Vec::new(), Err(denied()));
        }
        let Ok((gate_read, mut gate_write)) = std::io::pipe() else {
            return (Vec::new(), Err(denied()));
        };
        fd_map.push((gate_read.as_raw_fd(), 9));
        if let Some(staging) = &import_staging {
            fd_map.push((staging.as_raw_fd(), 10));
        }
        crate::sys::audited::restore_engine_command(command, &fd_map, std::process::id());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => return (Vec::new(), Err(denied())),
        };
        // The child holds its own copy of the read end across
        // fork+exec; this process's copy must close so `gate_write`'s
        // eventual close is the only thing that can ever signal EOF
        // to the child. `held_fds` drops here for the same reason:
        // the parent keeps no copy of any descriptor the child now
        // owns at its fixed number.
        drop(gate_read);
        drop(held_fds);
        drop(import_staging);

        /// `killRestoreEngineProcessGroup` — a bind failure kills the
        /// whole process group rather than letting an unbound engine
        /// run on, then reaps and captures whatever the child
        /// published before dying.
        // Drain stdout concurrently with `wait`: a child that writes
        // more than the pipe buffer while the parent waits would
        // deadlock both ends — upstream's `cmd.Output()` drains on a
        // goroutine for the same reason. The reader still bounds what
        // it keeps at the receipt limit.
        fn drain_stdout(child: &mut std::process::Child) -> std::thread::JoinHandle<Vec<u8>> {
            let mut stdout = child.stdout.take();
            std::thread::spawn(move || {
                let mut out = Vec::new();
                if let Some(stdout) = stdout.as_mut() {
                    let _ = stdout
                        .take((RESTORE_ENGINE_RECEIPT_LIMIT + 1) as u64)
                        .read_to_end(&mut out);
                }
                out
            })
        }

        fn kill_and_reap(child: &mut std::process::Child) -> Vec<u8> {
            let reader = drain_stdout(child);
            #[allow(clippy::cast_possible_wrap)]
            if let Some(pgid) = rustix::process::Pid::from_raw(child.id() as i32) {
                let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
            }
            let _ = child.wait();
            reader.join().unwrap_or_default()
        }

        #[allow(clippy::cast_possible_wrap)]
        let pid = child.id() as i32;
        let bind = (|command_pid: i32| -> Result<(), Failure> {
            let (executable, process_start) =
                crate::broker::migration_launch::verify_peer_process(command_pid)
                    .map_err(|_| denied())?;
            self.launch_issuer
                .issue_restore_launch(&RestoreLaunchClientEvidence {
                    pid: command_pid,
                    process_start,
                    executable,
                    mode: mode.to_owned(),
                    expires_at: launch_deadline,
                })
        })(pid);
        if let Err(e) = bind {
            drop(gate_write);
            let out = kill_and_reap(&mut child);
            // A launch refused specifically because a prior binding is
            // still alive (ADR 0015's single-flight restriction)
            // carries a typed, sanitized [`RestoreRefusalReason`] all
            // the way from the broker's `issue`; surface it instead of
            // collapsing it into the generic denial.
            if RestoreRefusalReason::from_wire(e.code()).is_some() {
                return (out, Err(e));
            }
            return (out, Err(denied()));
        }

        // The bind is now durably recorded with the broker, so frame
        // `0xc3` will admit this helper: allocate the reserve, if this
        // launch mode allocates one. A failure here is a launch
        // failure — the child must not be released into an admission
        // it cannot pass — and the gate is denied exactly as a bind
        // failure denies it, which the child observes as EOF and fails
        // closed on.
        let mut reserve_set_id = Uuid::nil();
        if let Some(allocate) = allocate {
            let (allocated, result) = allocate();
            reserve_set_id = allocated;
            if let Err(e) = result {
                drop(gate_write);
                let out = kill_and_reap(&mut child);
                if RestoreRefusalReason::from_wire(e.code()).is_some() {
                    return (out, Err(e));
                }
                return (
                    out,
                    Err(RestoreRefusalReason::CapacityInsufficient.into_failure()),
                );
            }
        }

        // Release the child, and hand it the reserve set its admission
        // will be judged against in the same message.
        let mut release = [0u8; RESTORE_LAUNCH_GATE_MESSAGE_SIZE];
        release[0] = RESTORE_LAUNCH_GATE_RELEASE_BYTE;
        release[1..].copy_from_slice(reserve_set_id.as_bytes());
        if gate_write.write_all(&release).is_err() {
            drop(gate_write);
            let out = kill_and_reap(&mut child);
            return (out, Err(denied()));
        }
        drop(gate_write);

        // `exec.CommandContext`'s cancel: the engine's own share of
        // the verb's budget, enforced by a watchdog that kills the
        // child's whole process group — never mid-pipe through the
        // parent. The pidfd liveness check keeps the signal from ever
        // landing on a recycled pid.
        let watchdog_deadline = run_deadline;
        let watchdog_pid = child.id();
        let _ = std::thread::Builder::new()
            .name("restore-engine-deadline".to_owned())
            .spawn(move || {
                let now = Instant::now();
                if watchdog_deadline > now {
                    std::thread::sleep(watchdog_deadline - now);
                }
                #[allow(clippy::cast_possible_wrap)]
                let Some(raw_pid) = rustix::process::Pid::from_raw(watchdog_pid as i32) else {
                    return;
                };
                let Ok(pidfd) = crate::sys::pidfd::open(raw_pid) else {
                    return;
                };
                if crate::sys::pidfd::alive(&pidfd).unwrap_or(false) {
                    let _ = crate::sys::pidfd::send_signal(&pidfd, rustix::process::Signal::KILL);
                    let _ =
                        rustix::process::kill_process_group(raw_pid, rustix::process::Signal::KILL);
                }
            });
        let reader = drain_stdout(&mut child);
        let status = child.wait();
        let out = reader.join().unwrap_or_default();
        match status {
            Ok(s) if s.success() => (out, Ok(())),
            _ => (out, Err(run_failed())),
        }
    }

    /// `LaunchRestore`.
    fn launch_restore_inner(
        &self,
        deadline: Instant,
        mode: &str,
        operation_id: Uuid,
        authorization_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure> {
        if (mode != "apply" && mode != "resume")
            || operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || authorization_id.is_nil()
            || authorization_id.get_version_num() != 7
            || operation_id == authorization_id
        {
            return Err(denied());
        }
        // The same refusal `launch_restore_verify` makes for the same
        // reason: the budget is now profile-derived, so a profile that
        // cannot produce one must not silently yield a zero-duration
        // timeout below, which would SIGKILL `pg_restore` immediately
        // and leave the target half-restored.
        if self.deadline.is_zero() {
            return Err(denied());
        }
        // The engine must never start on a budget it did not get in
        // full: if the transport deadline has less than `l.deadline`
        // left, the child is silently killed partway through — on a
        // target that has already been dropped, with the ticket
        // consumed and the phase left at `applying`. That is the wedge
        // whose only exit is the irreversible abandonment ceremony.
        // Refusing here converts that into an ordinary recoverable
        // refusal on an untouched target: `RESTORE_CAPACITY_
        // INSUFFICIENT`, and the operator can simply run the verb
        // again.
        let parent_remaining = deadline.saturating_duration_since(Instant::now());
        if parent_remaining < self.deadline {
            return Err(RestoreRefusalReason::CapacityInsufficient.into_failure());
        }
        let protected_fd = open_restore_engine_root(&self.protected_root)?;
        let repository_fd =
            open_restore_engine_repository(&self.backup_repository_root, &self.instance_id)?;
        let role_root_files = open_restore_engine_role_roots(&self.role_roots)?;

        // `minioExpiresAt` is fixed for the whole operation, never per
        // launch, so apply and any later resume mint the identical
        // handoff request and the second one always lands on the
        // already-bound fast path instead of being refused as a
        // mismatched replay.
        //
        // `self.minio` is checked here, not earlier:
        // `launch_restore_verify` never reads this field, so a
        // composition problem narrows only apply/resume — and it is
        // checked only after the three descriptors above have already
        // opened successfully, so a launch whose protected root or
        // repository is itself unavailable still reports that specific
        // cause rather than a generic one that happens to run first.
        let Some(minio) = &self.minio else {
            return Err(denied());
        };
        let minio_expires_at = restore_minio_handoff_expiry(operation_id).map_err(|_| denied())?;
        if let Err(e) = minio.prepare_restore_minio(deadline, operation_id, minio_expires_at) {
            if RestoreRefusalReason::from_wire(e.code()).is_some() {
                return Err(e);
            }
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }

        let run_deadline = Instant::now() + self.deadline.min(parent_remaining);
        let mut command = Command::new(RESTORE_ENGINE_EXECUTABLE_PATH);
        command
            .arg(mode)
            .arg(operation_id.to_string())
            .arg(authorization_id.to_string());
        command.env_clear();
        for entry in ENGINE_ENVIRONMENT {
            let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
            command.env(key, value);
        }
        command.stdin(Stdio::null());
        command.stderr(Stdio::null());
        command.stdout(Stdio::piped());
        // The map order is the fixed contract: fd 3 protected root,
        // fd 4 repository, fds 5–8 the four role roots in
        // [`RESERVE_ROLES`] order.
        let mut fd_map = vec![
            (protected_fd.as_raw_fd(), 3),
            (repository_fd.as_raw_fd(), 4),
        ];
        let mut held = vec![protected_fd, repository_fd];
        for (index, file) in role_root_files.into_iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            fd_map.push((file.as_raw_fd(), 5 + index as i32));
            held.push(file);
        }
        // `runCtx.Deadline()`'s `ok` check upstream: the wall-clock
        // expiry the launch record carries must be explicit, never a
        // zero `OffsetDateTime` that `validate_peer` treats as already
        // elapsed.
        let remaining = run_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(denied());
        }
        let launch_deadline = OffsetDateTime::now_utc()
            + time::Duration::try_from(remaining).map_err(|_| denied())?;
        let (out, run) = self.bind_and_run(
            &mut command,
            mode,
            launch_deadline,
            run_deadline,
            fd_map,
            // `None`: apply and resume allocate nothing. The reserve
            // they spend was allocated by the `restore verify` launch
            // that issued their ticket.
            None,
            None,
            held,
        );
        if let Err(e) = run {
            // A typed [`RestoreRefusalReason`] from `bind_and_run`
            // itself (today, only "another restore launch is already
            // bound") is decided before the child could ever have
            // written a receipt, so it takes priority over the stdout
            // decode below, which would otherwise always miss on an
            // empty buffer and fall through to the generic failure.
            if RestoreRefusalReason::from_wire(e.code()).is_some() {
                return Err(e);
            }
            // A non-zero exit does not by itself mean nothing can be
            // trusted: `central-restore`'s receipt is its only channel
            // back to this launcher (stderr is discarded), so a
            // refusal still attempts to publish a bounded,
            // locator-free reason on stdout. Only a receipt that
            // passes every check [`decode_restore_engine_refusal`]
            // applies is trusted; anything else falls back to the
            // generic failure.
            if let Ok(reason) = decode_restore_engine_refusal(&out, mode, operation_id) {
                return Err(reason.into_failure());
            }
            return Err(run_failed());
        }
        let receipt = decode_restore_engine_receipt(&out, mode, operation_id)?;
        // SC-DEF-86: the sweep's third named call site. A terminal
        // receipt means the operation reached an outcome nothing
        // further will protect, so the reserve the verify allocated
        // must be released now — not at the next helper restart or
        // the next verify, which is when the two pre-existing call
        // sites would get to it. The sweep re-checks its guards
        // against the durable record, so a set still covered by a
        // live bound launch is retained; and a sweep that cannot run
        // is reported, never fatal to a restore that already
        // completed.
        if receipt_phase_is_terminal(&receipt.phase)
            && let Ok(helper) = self.reserve_helper.lock()
            && let Some(helper) = helper.as_ref()
            && let Err((_, e)) = helper.sweep_and_publish(OffsetDateTime::now_utc())
        {
            report_sweep_failure("restore-launcher-terminal-receipt", e.message());
        }
        Ok(receipt)
    }

    /// `releaseReserveAfterFailedVerify` fires the caller-known
    /// `verify_failed_before_binding` trigger. It is deliberately
    /// given the caller's deadline rather than the run deadline: the
    /// run window is elapsed by the time a failed verify reaches
    /// here, and a release that cannot run is the outcome this call
    /// site exists to prevent.
    ///
    /// The trigger is a request, not an instruction: `release`
    /// re-checks its guard against the durable record, so a set the
    /// gate has already committed, or one still protected by a live
    /// launch, is retained and reported rather than freed.
    fn release_reserve_after_failed_verify(&self, set_id: Uuid) {
        if set_id.is_nil() {
            return;
        }
        let Ok(helper) = self.reserve_helper.lock() else {
            return;
        };
        let Some(helper) = helper.as_ref() else {
            return;
        };
        let now = OffsetDateTime::now_utc();
        match helper.release(set_id, ReleaseTrigger::VerifyFailed, now) {
            Ok(report) | Err((report, _)) => {
                if let Err(e) = helper.publish_inspection_digest(&report, now) {
                    report_sweep_failure("restore-launcher-verify-failed-publish", e.message());
                }
            }
        }
    }
}

/// `SharedRestoreEngineLauncher` — one `Arc` handle on the
/// production launcher presented as the `Box<dyn RestoreEngineLauncher>`
/// [`super::restore::RestoreApplyAuthorizationHandler::with_engine`]
/// consumes. Upstream hands the single
/// `*productionRestoreEngineLauncher` to the one apply/resume handler
/// *and* to the verify runner; the `Arc` clones are the Rust shape of
/// that sharing.
pub struct SharedRestoreEngineLauncher(pub Arc<ProductionRestoreEngineLauncher>);

impl RestoreEngineLauncher for SharedRestoreEngineLauncher {
    fn launch_restore(
        &self,
        deadline: Instant,
        mode: &str,
        operation_id: Uuid,
        authorization_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure> {
        self.0
            .launch_restore(deadline, mode, operation_id, authorization_id)
    }

    fn launch_restore_import(
        &self,
        deadline: Instant,
        operation_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure> {
        self.0.launch_restore_import(deadline, operation_id)
    }
}

impl RestoreEngineLauncher for ProductionRestoreEngineLauncher {
    /// `LaunchRestore` — the destructive `central-restore apply` /
    /// `central-restore resume` run for exactly one authorized
    /// operation.
    fn launch_restore(
        &self,
        deadline: Instant,
        mode: &str,
        operation_id: Uuid,
        authorization_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure> {
        self.launch_restore_inner(deadline, mode, operation_id, authorization_id)
    }

    /// `LaunchRestoreImport` runs `central-restore import` for
    /// exactly one staged import operation. It mirrors
    /// `launch_restore`'s shape with three import differences: the
    /// MinIO preparation mints the `minio_import_v1` writer (not the
    /// read-only restore reader), the staged work dir travels as a
    /// seventh descriptor after the gate (fd 10), and nothing is
    /// swept afterwards because no capacity reserve is ever
    /// allocated for an import.
    fn launch_restore_import(
        &self,
        deadline: Instant,
        operation_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure> {
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(denied());
        }
        if self.import_deadline.is_zero() {
            return Err(denied());
        }
        // The same never-start-short check `launch_restore` documents
        // at length: the transport budget is the ceremony's share plus
        // the staging share plus this run, so a staging phase that
        // overran its share refuses here, recoverably, on an
        // unrestored target — and the operator's re-run resumes from
        // the staged plan instead of re-staging.
        let parent_remaining = deadline.saturating_duration_since(Instant::now());
        if parent_remaining < self.import_deadline {
            return Err(RestoreRefusalReason::CapacityInsufficient.into_failure());
        }
        let protected_fd = open_restore_engine_root(&self.protected_root)?;
        let repository_fd =
            open_restore_engine_repository(&self.backup_repository_root, &self.instance_id)?;
        let role_root_files = open_restore_engine_role_roots(&self.role_roots)?;
        // `import_minio` is checked here, after the descriptors, for
        // the same narrowing reason `launch_restore` documents for
        // `minio`: a composition problem here must narrow only the
        // import launch.
        let Some(import_minio) = &self.import_minio else {
            return Err(denied());
        };
        let minio_expires_at = import_minio_handoff_expiry(operation_id).map_err(|_| denied())?;
        if let Err(e) = import_minio.prepare_import_minio(deadline, operation_id, minio_expires_at)
        {
            if RestoreRefusalReason::from_wire(e.code()).is_some() {
                return Err(e);
            }
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }

        let run_deadline = Instant::now() + self.import_deadline.min(parent_remaining);
        let argv = restore_import_argv(operation_id);
        let mut command = Command::new(RESTORE_ENGINE_EXECUTABLE_PATH);
        command.arg(&argv[0]).arg(&argv[1]);
        command.env_clear();
        for entry in ENGINE_ENVIRONMENT {
            let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
            command.env(key, value);
        }
        command.stdin(Stdio::null());
        command.stderr(Stdio::null());
        command.stdout(Stdio::piped());
        let mut fd_map = vec![
            (protected_fd.as_raw_fd(), 3),
            (repository_fd.as_raw_fd(), 4),
        ];
        let mut held = vec![protected_fd, repository_fd];
        for (index, file) in role_root_files.into_iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            fd_map.push((file.as_raw_fd(), 5 + index as i32));
            held.push(file);
        }
        let remaining = run_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(denied());
        }
        let launch_deadline = OffsetDateTime::now_utc()
            + time::Duration::try_from(remaining).map_err(|_| denied())?;
        let staging = open_import_staging_dir(&self.import_staging_parent, operation_id)?;
        let (out, run) = self.bind_and_run(
            &mut command,
            "import",
            launch_deadline,
            run_deadline,
            fd_map,
            // `None`: an import allocates no capacity reserve. The
            // target is fresh by the pre-ceremony gate, so there is no
            // live database whose replacement needs a survival
            // reserve.
            None,
            Some(staging),
            held,
        );
        if let Err(e) = run {
            if RestoreRefusalReason::from_wire(e.code()).is_some() {
                return Err(e);
            }
            if let Ok(reason) = decode_restore_engine_refusal(&out, "import", operation_id) {
                return Err(reason.into_failure());
            }
            return Err(run_failed());
        }
        decode_restore_import_engine_receipt(&out, operation_id)
    }
}

impl RestoreVerifyLauncher for ProductionRestoreEngineLauncher {
    /// `LaunchRestoreVerify` runs the root engine's non-mutating
    /// verify path. It is a separate method from `launch_restore`,
    /// not an overload of it: verify's argv carries one opaque
    /// identity where apply/resume carry two, its receipt has no
    /// phase or checkpoint, and its receipt's operation identity is
    /// minted inside issuance rather than matched against anything
    /// this caller supplied.
    fn launch_restore_verify(
        &self,
        deadline: Instant,
        backup_id: Uuid,
    ) -> Result<RestoreVerifyEngineReceipt, Failure> {
        if backup_id.is_nil() || backup_id.get_version_num() != 7 {
            return Err(denied());
        }
        let protected_fd = open_restore_engine_root(&self.protected_root)?;
        let repository_fd =
            open_restore_engine_repository(&self.backup_repository_root, &self.instance_id)?;
        let role_root_files = open_restore_engine_role_roots(&self.role_roots)?;
        {
            let helper = self.reserve_helper.lock().map_err(|_| denied())?;
            if helper.is_none() {
                // A verify launch whose reserve cannot be allocated or
                // reconciled can only ever reach the admission
                // inspector with nothing to tell it. Refuse before
                // spawning anything.
                return Err(denied());
            }
            // The sweep's second named call site: before allocating a
            // fresh reserve. A host that came back from a crash frees
            // what nothing claims here, rather than meeting the
            // single-live-set refusal on the next line. A sweep that
            // could not run at all is not a reason to refuse a
            // recovery: the allocation below applies every cap for
            // itself.
            if let Some(authority) = helper.as_ref()
                && let Err((_, e)) = authority.sweep_and_publish(OffsetDateTime::now_utc())
            {
                report_sweep_failure("restore-launcher", e.message());
            }
        }
        // The sealed figures the reserve set records and the demand
        // arithmetic is derived from. They come from the repository
        // descriptor this helper already opened and validated, never
        // from a caller.
        //
        // It runs *before* the run deadline is derived below, and
        // that placement is load-bearing rather than incidental:
        // reading them verifies the sealed media, which SHA-256s the
        // whole dump and every artifact body, and
        // `restore_verify_engine_deadline` bounds the child's own run
        // plus the allocation — a window sized for the child's single
        // walk, not for this one too.
        let reserve_request = reserve_set_request(&repository_fd, backup_id)?;

        let verify_budget = restore_verify_engine_deadline();
        if verify_budget.is_zero() {
            // The profile could not produce a bound. Refuse rather
            // than launch a child this process cannot promise to
            // stop.
            return Err(denied());
        }
        let parent_remaining = deadline.saturating_duration_since(Instant::now());
        let run_deadline = Instant::now() + verify_budget.min(parent_remaining);
        let run_args = restore_verify_argv(backup_id);
        let mut command = Command::new(RESTORE_ENGINE_EXECUTABLE_PATH);
        command.arg(&run_args[0]).arg(&run_args[1]);
        command.env_clear();
        for entry in ENGINE_ENVIRONMENT {
            let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
            command.env(key, value);
        }
        command.stdin(Stdio::null());
        command.stderr(Stdio::null());
        command.stdout(Stdio::piped());
        let mut fd_map = vec![
            (protected_fd.as_raw_fd(), 3),
            (repository_fd.as_raw_fd(), 4),
        ];
        let mut held = vec![protected_fd, repository_fd];
        for (index, file) in role_root_files.into_iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            fd_map.push((file.as_raw_fd(), 5 + index as i32));
            held.push(file);
        }
        // `runCtx.Deadline()`'s `ok` check upstream: never pass a zero
        // deadline through to `bind_and_run`'s launch record.
        let remaining = run_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(denied());
        }
        let launch_deadline = OffsetDateTime::now_utc()
            + time::Duration::try_from(remaining).map_err(|_| denied())?;
        // `reserve_set_id` escapes the closure so a verify that
        // failed *after* allocating can name the set it stranded. It
        // is `Uuid::nil()` for a verify that failed before or during
        // allocation with nothing created.
        let reserve_set_id = std::cell::Cell::new(Uuid::nil());
        let allocate = || -> (Uuid, Result<(), Failure>) {
            let (set_id, result) = allocate_restore_capacity_reserve(
                &self.reserve_writer,
                &self.role_roots,
                &reserve_request,
            );
            reserve_set_id.set(set_id);
            (set_id, result)
        };
        let (out, run) = self.bind_and_run(
            &mut command,
            "verify",
            launch_deadline,
            run_deadline,
            fd_map,
            Some(&allocate),
            None,
            held,
        );
        if let Err(e) = run {
            // The `verify_failed_before_binding` trigger, fired from
            // the one party that knows the verification failed. It
            // runs after `wait` has returned, which is what lets the
            // trigger's own launch-liveness guard hold: an engine
            // that is still running protects its own reserve.
            self.release_reserve_after_failed_verify(reserve_set_id.get());
            if RestoreRefusalReason::from_wire(e.code()).is_some() {
                return Err(e);
            }
            if let Ok(reason) = decode_restore_verify_engine_refusal(&out) {
                return Err(reason.into_failure());
            }
            return Err(run_failed());
        }
        match decode_restore_verify_engine_receipt(&out, backup_id) {
            Ok(receipt) => Ok(receipt),
            Err(e) => {
                // The engine exited zero but published nothing this
                // launcher will trust, so no ticket reaches the
                // operator and the reserve it may have allocated has
                // nothing left to protect.
                self.release_reserve_after_failed_verify(reserve_set_id.get());
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `restore_resolvers.go` + `productionRestoreVerifyRunner` — the
// helper-side resolution of the single admissible sealed backup.
// ---------------------------------------------------------------------------

/// `restoreVerifyCandidateSource` enumerates every sealed backup the
/// recovery repository holds. The set genuinely grows past one on a
/// host that has been running for a while, which is precisely the
/// case the resolver decision accepted the cost of.
pub trait RestoreVerifyCandidateSource: Send + Sync {
    /// `AdmissibleRestoreBackups`.
    fn admissible_restore_backups(&self) -> Result<Vec<Uuid>, Failure>;
}

/// `resolveSingleRestoreBackupCandidate` — resolve the single
/// candidate, and refuse to guess. When exactly one candidate
/// matches, the verb proceeds against it. When none matches, the
/// verb refuses. When more than one matches, the verb refuses and
/// does NOT choose — never the newest, never the first, never the
/// most likely.
fn resolve_single_restore_backup_candidate(
    source: &dyn RestoreVerifyCandidateSource,
) -> Result<Uuid, Failure> {
    let candidates = source.admissible_restore_backups()?;
    match candidates.len() {
        0 => Err(new_restore_refusal(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP)),
        1 => {
            let candidate = candidates[0];
            // The engine's argv accepts a canonical UUIDv7 and nothing
            // else, and a repository index that offered anything else
            // is not one this launcher will act on.
            if candidate.is_nil() || candidate.get_version_num() != 7 {
                return Err(new_restore_refusal(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP));
            }
            Ok(candidate)
        }
        _ => Err(new_restore_refusal(
            RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS,
        )),
    }
}

/// `repositoryRestoreVerifyCandidates` — the production source: the
/// recovery repository's own canonical sealed-backup index, read
/// through the same helper-opened, binding-validated descriptor the
/// verify launcher itself uses. Nothing an operator or a helper
/// request could name reaches it.
pub struct RepositoryRestoreVerifyCandidates {
    pub root: PathBuf,
    pub instance_id: String,
}

impl RestoreVerifyCandidateSource for RepositoryRestoreVerifyCandidates {
    fn admissible_restore_backups(&self) -> Result<Vec<Uuid>, Failure> {
        if self.root.as_os_str().is_empty() {
            // `errRestoreRepositoryRootUnconfigured` — deliberately
            // NOT a restore refusal, so it collapses to the generic
            // denial rather than the operator-facing "there is
            // nothing to restore".
            return Err(Failure::internal(
                "restore_engine_launch",
                "restore repository root is not configured",
            ));
        }
        let fd = open_restore_engine_repository(&self.root, &self.instance_id)?;
        let binding = repository::inspect_repository_descriptor(&fd)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        let repository = Repository::read_only_from_descriptor(&fd, &binding)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        repository
            .sealed_backup_ids()
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())
    }
}

/// `productionRestoreVerifyRunner` — the privileged body of the
/// restore-verify helper verb: it resolves the single admissible
/// sealed backup and launches the root engine against it.
pub struct ProductionRestoreVerifyRunner {
    launcher: Arc<dyn RestoreVerifyLauncher>,
    candidates: Box<dyn RestoreVerifyCandidateSource>,
}

impl ProductionRestoreVerifyRunner {
    /// The composition in `runHelperDaemon`.
    #[must_use]
    pub fn new(
        launcher: Arc<dyn RestoreVerifyLauncher>,
        candidates: Box<dyn RestoreVerifyCandidateSource>,
    ) -> Self {
        Self {
            launcher,
            candidates,
        }
    }
}

impl RestoreVerifyRunner for ProductionRestoreVerifyRunner {
    /// `RunRestoreVerify`.
    fn run_restore_verify(&self, deadline: Instant) -> Result<RestoreVerifyReceipt, Failure> {
        let backup_id = resolve_single_restore_backup_candidate(self.candidates.as_ref())?;
        let receipt = self.launcher.launch_restore_verify(deadline, backup_id)?;
        let expires_at = OffsetDateTime::parse(
            &receipt.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| {
            Failure::internal(
                "restore_engine_launch",
                "restore verify receipt unavailable",
            )
        })?;
        Ok(RestoreVerifyReceipt {
            ticket_id: receipt.operation_id,
            backup_id: receipt.backup_id,
            expires_at,
        })
    }
}
