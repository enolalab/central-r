//! `restore_capacity_reserve_sweep_linux.go` — reconciliation, sweep,
//! and release: the only thing in this design that gives
//! multi-gigabyte reserves back.
//!
//! Every earlier task in this plan takes capacity: the helper measures
//! and physically allocates, the daemon records and gates, the engine
//! draws and spends receipts. Nothing anywhere releases. A crash
//! between any two of those steps, an abandoned attempt, an expired
//! set, or a device identity change all leave 4 GiB per device held by
//! nothing, on a machine the operator has already accepted as damaged.
//! This file is the other half.
//!
//! # Where this runs, and why
//!
//! **The sweep runs in the root helper (`central --helper`), never
//! inside the hardened broker daemon.** Its single enumeration
//! primitive, `getdents64`, is what held it out of the daemon's
//! seccomp filter; since ADR 0029 admitted the syscall the placement
//! is held by `TestReserveEnumerationIsNotReachableFromDaemonDispatch`
//! and by the single-chokepoint enumeration probe
//! (`sweep_names` is the only `Dir::read_from` in this package).
//!
//! # The two rules this file must not get backwards
//!
//! - **A record that cannot be parsed is retained and reported, never
//!   treated as absent.** Only a demonstrable not-found permits the
//!   "absent" reading. An unreadable record also suppresses object
//!   deletion for the whole pass.
//! - **Abandonment releases only when no live bound launch record
//!   exists for the operation** — freeing the cushion out from under a
//!   live `pg_restore` is the failure ADR 0016 exists to prevent. The
//!   liveness reader is peerless and read-only (`inspect_liveness`)
//!   precisely because a sweep has neither a peer credential nor any
//!   business advancing `issued → active`.
//!
//! # The bind with the admission gate
//!
//! The gate decided that absolute expiry bounds *entry* into the
//! destructive window, not continuation of one already entered: a
//! committed set past its expiry is still admitted while its operation
//! applies. This file is the other half of that decision: the only
//! state in which the gate admits an expired set is
//! `phase == applying`, and that is precisely the state in which this
//! sweep refuses to release on expiry.

use std::collections::HashSet;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_foundation::failure::Failure;
use time::OffsetDateTime;
use uuid::Uuid;

use central_backup::backup::capacity::RoleRoots;
use central_backup::recovery::operation::{RestoreOperation, RestorePhase};

use crate::broker::recovery_journal::{self, RecoveryJournalStore};
use crate::broker::restore_launch::RestoreLaunchStore;
use crate::broker::wire;

use super::receipt::{self, ReceiptStore};
use super::store::{ReserveMemberRecord, ReserveSetRecord, ReserveStore};
use super::store_path::{self, ReserveDeviceStore};
use super::{RESERVE_ROLES, ReserveState};

// --- the named call sites ----------------------------------------------------

/// `RestoreCapacityReserveSweepCaller` — names, exhaustively, the root
/// binaries that may hold this sweep's deletion path. Both admitted
/// values are inside `central --helper`: the root helper daemon, the
/// same process that runs the allocator and issues the restore launch
/// record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepCaller {
    /// `central --helper`'s own startup reconciliation pass: the pass
    /// that recovers from a crash.
    HelperStartup,
    /// The same process's restore-launch path, which runs the sweep
    /// around an engine's life: before allocating a fresh reserve, and
    /// after the engine it launched has exited.
    HelperRestoreLauncher,
}

impl SweepCaller {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HelperStartup => "central-helper-startup",
            Self::HelperRestoreLauncher => "central-helper-restore-launcher",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "central-helper-startup" => Some(Self::HelperStartup),
            "central-helper-restore-launcher" => Some(Self::HelperRestoreLauncher),
            _ => None,
        }
    }
}

/// `RestoreCapacityReserveReleaseTrigger` — the design's closed
/// release-trigger set. Six values and no seventh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReleaseTrigger {
    /// A verification that failed before the set was ever bound.
    /// Caller-fired: only the party that ran the verification knows.
    VerifyFailed,
    /// The 20-minute receipt window lapsing over a set that was never
    /// committed — a different clock from the set's absolute expiry.
    ReceiptWindowLapsed,
    /// Helper abandonment of an unbound set: no receipt was spent over
    /// it and no live bound launch record exists for it. "Unbound"
    /// means *not committed by the gate*: since "verify allocates"
    /// this also covers a set bound to an operation whose ticket has
    /// expired without `Begin` ever running.
    HelperAbandonment,
    /// The protected restore operation reaching a terminal outcome —
    /// ready or abandoned. The one trigger that overrides launch
    /// liveness.
    TerminalOutcome,
    /// The sweep's own discovery: a reserve object with no live record
    /// behind it, an orphaned member record, a pointer whose target is
    /// gone or released. Minted only by `sweep` — `release` refuses
    /// it, so a caller cannot label an arbitrary release as
    /// "reconciliation" and bypass another trigger's guard.
    Reconciliation,
    /// The set's absolute expiry, **except** while its operation is
    /// applying.
    AbsoluteExpiry,
}

impl ReleaseTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifyFailed => "verify_failed_before_binding",
            Self::ReceiptWindowLapsed => "receipt_window_lapsed_unbound",
            Self::HelperAbandonment => "helper_abandonment_unbound",
            Self::TerminalOutcome => "terminal_restore_outcome",
            Self::Reconciliation => "reconciliation",
            Self::AbsoluteExpiry => "absolute_expiry",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "verify_failed_before_binding" => Self::VerifyFailed,
            "receipt_window_lapsed_unbound" => Self::ReceiptWindowLapsed,
            "helper_abandonment_unbound" => Self::HelperAbandonment,
            "terminal_restore_outcome" => Self::TerminalOutcome,
            "reconciliation" => Self::Reconciliation,
            "absolute_expiry" => Self::AbsoluteExpiry,
            _ => return None,
        })
    }
}

/// `RestoreCapacityReserveSweepItem` — what one outcome is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SweepItem {
    Set,
    Member,
    OperationIndex,
    SpendPointer,
    Object,
    Device,
}
impl SweepItem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Member => "member",
            Self::OperationIndex => "operation_index",
            Self::SpendPointer => "spend_pointer",
            Self::Object => "object",
            Self::Device => "device",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "set" => Self::Set,
            "member" => Self::Member,
            "operation_index" => Self::OperationIndex,
            "spend_pointer" => Self::SpendPointer,
            "object" => Self::Object,
            "device" => Self::Device,
            _ => return None,
        })
    }
}

/// `RestoreCapacityReserveSweepAction` — what the sweep did about one
/// item. "Reported" is a first-class outcome rather than an absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SweepAction {
    Released,
    Retained,
    Reported,
}
impl SweepAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Retained => "retained",
            Self::Reported => "reported",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "released" => Self::Released,
            "retained" => Self::Retained,
            "reported" => Self::Reported,
            _ => return None,
        })
    }
}

/// `RestoreCapacityReserveSweepCondition` — why an item was retained
/// or reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SweepCondition {
    /// The two corruption classes. Both retain; they are separate
    /// values only so a report can say which one was seen.
    UnrecognizedSchema,
    RecordUnreadable,
    /// The protection conditions.
    OperationApplying,
    OperationUnreadable,
    LaunchLive,
    LaunchUnreadable,
    SetCommitted,
    SetLive,
    /// The issuing-ticket conditions — the window "verify allocates"
    /// opened: a set bound to an operation whose `Begin` has not run.
    TicketIssued,
    TicketUnreadable,
    /// The device and store conditions.
    DeviceAbsent,
    StoreAbsent,
    /// The object conditions.
    ObjectClaimed,
    ObjectUnclaimed,
    ObjectSuppressed,
    /// The pointer conditions.
    PointerTargetMissing,
    PointerTargetReleased,
    PointerTargetLive,
    /// Anything in a swept directory this design did not put there.
    /// Retained and reported, never removed.
    UnrecognizedEntry,
}
impl SweepCondition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnrecognizedSchema => "record_unrecognized_schema",
            Self::RecordUnreadable => "record_unreadable",
            Self::OperationApplying => "operation_applying",
            Self::OperationUnreadable => "operation_unreadable",
            Self::LaunchLive => "launch_record_live",
            Self::LaunchUnreadable => "launch_record_unreadable",
            Self::SetCommitted => "set_committed",
            Self::SetLive => "set_live",
            Self::TicketIssued => "issuing_ticket_unconsumed",
            Self::TicketUnreadable => "issuing_ticket_unreadable",
            Self::DeviceAbsent => "device_absent",
            Self::StoreAbsent => "store_absent",
            Self::ObjectClaimed => "object_claimed_by_live_record",
            Self::ObjectUnclaimed => "object_without_live_record",
            Self::ObjectSuppressed => "object_sweep_suppressed_by_unreadable_record",
            Self::PointerTargetMissing => "pointer_target_missing",
            Self::PointerTargetReleased => "pointer_target_released",
            Self::PointerTargetLive => "pointer_target_live",
            Self::UnrecognizedEntry => "unrecognized_entry",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "record_unrecognized_schema" => Self::UnrecognizedSchema,
            "record_unreadable" => Self::RecordUnreadable,
            "operation_applying" => Self::OperationApplying,
            "operation_unreadable" => Self::OperationUnreadable,
            "launch_record_live" => Self::LaunchLive,
            "launch_record_unreadable" => Self::LaunchUnreadable,
            "set_committed" => Self::SetCommitted,
            "set_live" => Self::SetLive,
            "issuing_ticket_unconsumed" => Self::TicketIssued,
            "issuing_ticket_unreadable" => Self::TicketUnreadable,
            "device_absent" => Self::DeviceAbsent,
            "store_absent" => Self::StoreAbsent,
            "object_claimed_by_live_record" => Self::ObjectClaimed,
            "object_without_live_record" => Self::ObjectUnclaimed,
            "object_sweep_suppressed_by_unreadable_record" => Self::ObjectSuppressed,
            "pointer_target_missing" => Self::PointerTargetMissing,
            "pointer_target_released" => Self::PointerTargetReleased,
            "pointer_target_live" => Self::PointerTargetLive,
            "unrecognized_entry" => Self::UnrecognizedEntry,
            _ => return None,
        })
    }
}

/// `RestoreCapacityReserveSweepOutcome` — one decision about one item.
/// `key` never carries a filesystem path.
#[derive(Debug, Clone)]
pub struct SweepOutcome {
    pub item: SweepItem,
    pub key: String,
    pub action: SweepAction,
    pub trigger: Option<ReleaseTrigger>,
    pub condition: Option<SweepCondition>,
    /// The reserve object's allocated bytes at the moment it was
    /// unlinked — `st_blocks`, not `st_size`: a hole-punched object
    /// has a size and no blocks, and it is the blocks that were being
    /// held.
    pub bytes: u64,
}

/// `RestoreCapacityReserveSweepReport` — one pass's whole result.
#[derive(Debug, Clone)]
pub struct SweepReport {
    pub caller: Option<SweepCaller>,
    pub outcomes: Vec<SweepOutcome>,
    /// The physical capacity this pass gave back.
    pub bytes_released: u64,
    /// False when any set or member record could not be read for a
    /// reason other than "does not exist". While it is false no
    /// reserve object is unlinked at all.
    pub records_intact: bool,
}

impl SweepReport {
    fn empty() -> Self {
        Self {
            caller: None,
            outcomes: Vec::new(),
            bytes_released: 0,
            records_intact: true,
        }
    }
    fn push(
        &mut self,
        item: SweepItem,
        key: impl Into<String>,
        action: SweepAction,
        trigger: Option<ReleaseTrigger>,
        condition: Option<SweepCondition>,
        bytes: u64,
    ) {
        self.outcomes.push(SweepOutcome {
            item,
            key: key.into(),
            action,
            trigger,
            condition,
            bytes,
        });
    }
    /// `Released` — the report's read side.
    pub fn released(&self) -> Vec<&SweepOutcome> {
        self.with_action(SweepAction::Released)
    }
    pub fn retained(&self) -> Vec<&SweepOutcome> {
        self.with_action(SweepAction::Retained)
    }
    pub fn reported(&self) -> Vec<&SweepOutcome> {
        self.with_action(SweepAction::Reported)
    }
    fn with_action(&self, action: SweepAction) -> Vec<&SweepOutcome> {
        self.outcomes
            .iter()
            .filter(|o| o.action == action)
            .collect()
    }
}

// --- sentinels ----------------------------------------------------------------

const CODE_CALLER: &str = "broker_restore_reserve_sweep_caller";
const CODE_UNAVAILABLE: &str = "broker_restore_reserve_sweep_unavailable";
const CODE_TRIGGER_REFUSED: &str = "broker_restore_reserve_sweep_trigger_refused";
const CODE_SET_UNREADABLE: &str = "broker_restore_reserve_sweep_set_unreadable";

#[allow(dead_code)] // reserved for the constructor's caller-validation leg
fn caller_refused() -> Failure {
    Failure::denied(
        CODE_CALLER,
        "broker: restore capacity reserve sweep caller is not one of the named root call sites",
    )
}
/// `errRestoreCapacityReserveSweepUnavailable` — the generic
/// construction/enumeration refusal.
pub(crate) fn sweep_unavailable(detail: impl Into<String>) -> Failure {
    Failure::internal(CODE_UNAVAILABLE, detail.into())
}
fn trigger_refused() -> Failure {
    Failure::denied(
        CODE_TRIGGER_REFUSED,
        "broker: restore capacity reserve release trigger does not apply to this set",
    )
}
fn set_unreadable() -> Failure {
    Failure::internal(
        CODE_SET_UNREADABLE,
        "broker: restore capacity reserve release could not read the named set's record",
    )
}

#[allow(dead_code)] // classification for the helper-side release call sites
pub(crate) fn is_trigger_refused(f: &Failure) -> bool {
    f.code() == CODE_TRIGGER_REFUSED
}
#[allow(dead_code)] // classification for the helper-side release call sites
pub(crate) fn is_set_unreadable(f: &Failure) -> bool {
    f.code() == CODE_SET_UNREADABLE
}

// --- the one enumeration chokepoint -------------------------------------------

/// `restoreCapacityReserveSweepStore` — the whole of what the sweep
/// needs from one device's reserve store: the device identity, the
/// held directory descriptor to enumerate and stat through, and the
/// unlink. Deliberately a third, narrower seam rather than a widening
/// of either sibling: the sweep must not be able to create a reserve
/// object.
pub trait SweepStore {
    fn st_dev(&self) -> u64;
    fn dir_fd(&self) -> BorrowedFd<'_>;
    fn remove(&self, fingerprint: &str) -> Result<(), Failure>;
}

impl SweepStore for ReserveDeviceStore {
    fn st_dev(&self) -> u64 {
        ReserveDeviceStore::st_dev(self)
    }
    fn dir_fd(&self) -> BorrowedFd<'_> {
        ReserveDeviceStore::dir_fd(self)
    }
    fn remove(&self, fingerprint: &str) -> Result<(), Failure> {
        ReserveDeviceStore::remove(self, fingerprint)
    }
}

/// `restoreCapacityReserveSweepOpener` — resolves one device's store
/// beneath an already-held role-root descriptor, with no create
/// parameter: a store directory the sweep had to create is proof there
/// was nothing to sweep.
type SweepOpener = Box<dyn Fn(BorrowedFd<'_>) -> Result<Box<dyn SweepStore>, Failure> + Send>;

fn open_sweep_store(role_root: BorrowedFd<'_>) -> Result<Box<dyn SweepStore>, Failure> {
    Ok(Box::new(store_path::open_device_store(role_root, false)?))
}

/// `restoreCapacityReserveSweepNames` — the sweep's **one** directory
/// enumeration (`getdents64`), and the reason this whole engine lives
/// in the root helper rather than in the hardened daemon. The
/// directory is re-opened as `"."` from the held descriptor rather
/// than dup'ed, for the same reason `object_count` does it: a dup
/// shares the file description, so a second enumeration would resume
/// from the offset the first one left behind.
fn sweep_names(dir: BorrowedFd<'_>) -> Result<Vec<String>, Failure> {
    use rustix::fs::{Mode, OFlags};
    let fd: OwnedFd = rustix::fs::openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| sweep_unavailable(format!("open sweep directory: {e}")))?;
    let mut entries = rustix::fs::Dir::read_from(&fd)
        .map_err(|e| sweep_unavailable(format!("read sweep directory: {e}")))?;
    let mut names = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|e| sweep_unavailable(format!("read dir entry: {e}")))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    Ok(names)
}

/// `restoreCapacityReserveSweepDirNames` — enumerate one
/// protected-state record directory by path (the store's own field,
/// never re-derived), opened `O_NOFOLLOW` before anything is read.
fn sweep_dir_names(path: &Path) -> Result<Vec<String>, Failure> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| sweep_unavailable(format!("open record directory: {e}")))?;
    sweep_names(fd.as_fd())
}

const RECORD_SUFFIX: &str = ".json";
/// `.lock` and `.recovery-journal-` — the infrastructure entries the
/// per-file flock pattern leaves beside a record. Skipped silently
/// rather than reported: a lock file exists beside every record ever
/// written. The lock file is also deliberately never unlinked, even
/// when its record is: unlinking a file another process holds an flock
/// on does not release that lock.
const LOCK_SUFFIX: &str = ".lock";
const TEMP_PREFIX: &str = ".recovery-journal-";

/// `restoreCapacityReserveSweepClassifyEntry` — sort one directory
/// entry into a record this design wrote, infrastructure to ignore, or
/// something else.
fn classify_entry(name: &str) -> (bool, bool) {
    if name.ends_with(LOCK_SUFFIX) || name.starts_with(TEMP_PREFIX) {
        return (false, true);
    }
    let Some(stem) = name.strip_suffix(RECORD_SUFFIX) else {
        return (false, false);
    };
    if stem.len() != 64
        || !stem
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return (false, false);
    }
    (true, false)
}

/// `restoreCapacityReserveSweepRecordCondition` — map a record read
/// failure onto the condition to report. **Every** value it can return
/// retains: the caller must never branch on which class it was to
/// decide whether to delete.
fn record_condition(e: &Failure) -> SweepCondition {
    if super::is_reserve_ambiguous(e) || receipt::is_receipt_ambiguous(e) {
        SweepCondition::UnrecognizedSchema
    } else {
        SweepCondition::RecordUnreadable
    }
}

/// `restoreCapacityReserveSweepAbsent` — the *only* read failure that
/// permits treating a record as not there.
fn sweep_absent(e: &Failure) -> bool {
    super::is_reserve_not_found(e) || receipt::is_receipt_not_found(e)
}

/// `restoreCapacityReserveSweepClaim` — one physical reserve object,
/// named the way every identity decision in this design names one:
/// `st_dev` authoritative, fingerprint as the naming key.
type SweepClaim = (u64, String);

fn claim_of(st_dev: u64, fingerprint: &str) -> SweepClaim {
    (st_dev, fingerprint.to_string())
}

// --- the sweeper ---------------------------------------------------------------

/// `restoreCapacityGateAllocatedBytes` — `st_blocks × 512`, the
/// allocated-block count the release accounting and the admission gate
/// share. `None` on overflow.
pub(crate) fn gate_allocated_bytes(blocks: i64) -> Option<u64> {
    u64::try_from(blocks).ok()?.checked_mul(512)
}

/// `RestoreCapacityReserveSweeper` — the reconciliation, sweep, and
/// release engine. Constructed only for one of the named callers. The
/// stores are `Arc`ed so the helper authority can hand the same
/// `ReserveStore` to the inspection publisher without a self-referential
/// struct — upstream's Go pointers, with shared ownership spelled out.
pub struct ReserveSweeper {
    caller: SweepCaller,
    reserves: Arc<ReserveStore>,
    receipts: Arc<ReceiptStore>,
    launches: Arc<RestoreLaunchStore>,
    journal: Arc<RecoveryJournalStore>,
    roots: RoleRoots,
    open_store: SweepOpener,
}

impl ReserveSweeper {
    /// `NewRestoreCapacityReserveSweeper` — build the sweep for one
    /// named root call site. `pub(crate)` because its parameters name
    /// the crate-private stores; the public constructor-facing path is
    /// `ReserveHelperAuthority`, which builds them from a root path.
    pub(crate) fn new(
        caller: SweepCaller,
        reserves: Arc<ReserveStore>,
        receipts: Arc<ReceiptStore>,
        launches: Arc<RestoreLaunchStore>,
        journal: Arc<RecoveryJournalStore>,
        roots: RoleRoots,
    ) -> Result<Self, Failure> {
        for role in RESERVE_ROLES {
            if role.root(&roots).is_empty() {
                return Err(sweep_unavailable(
                    "broker: restore capacity reserve role roots are incomplete",
                ));
            }
        }
        Ok(Self {
            caller,
            reserves,
            receipts,
            launches,
            journal,
            roots,
            open_store: Box::new(open_sweep_store),
        })
    }

    /// `Sweep` — one whole reconciliation pass: evaluate every reserve
    /// set against the four sweep-discovered release triggers, release
    /// the ones that fire, unlink every reserve object no live record
    /// claims, and unlink the two pointer families whose targets are
    /// gone.
    ///
    /// It never returns an error for a condition it can report. The
    /// error return is reserved for "this engine could not run at
    /// all" — and even then the partial report travels with it,
    /// upstream's `(report, err)` pair.
    pub fn sweep(&self, now: OffsetDateTime) -> Result<SweepReport, (SweepReport, Failure)> {
        let mut report = SweepReport::empty();
        if wire::is_go_zero_time(now) {
            return Err((report, sweep_unavailable("sweep called with no clock")));
        }
        report.caller = Some(self.caller);
        self.sweep_sets(&mut report, now)
            .map_err(|e| (report.clone(), e))?;
        let claims = self
            .sweep_members(&mut report, now)
            .map_err(|e| (report.clone(), e))?;
        self.sweep_objects(&mut report, &claims)
            .map_err(|e| (report.clone(), e))?;
        self.sweep_pointers(&mut report)
            .map_err(|e| (report.clone(), e))?;
        Ok(report)
    }

    /// `Release` — the caller-fired half of the trigger set: the two
    /// facts the sweep cannot discover for itself, plus the four it
    /// can, applied to one named set.
    ///
    /// Every trigger carries its own guard and the guard is checked
    /// here, against the durable record, rather than trusted from the
    /// caller. `Reconciliation` is refused outright: it is `sweep`'s
    /// own trigger, and admitting it here would give a caller a label
    /// with no guard behind it.
    ///
    /// A successful release then runs the object and pointer sweep, so
    /// the physical capacity is given back on this call. A set whose
    /// own record cannot be read is retained and reported, but
    /// `release` additionally returns `set_unreadable`: a caller that
    /// checks only the error must not learn nothing from a call that
    /// could not evaluate the trigger it was asked to fire.
    pub fn release(
        &self,
        set_id: Uuid,
        trigger: ReleaseTrigger,
        now: OffsetDateTime,
    ) -> Result<SweepReport, (SweepReport, Failure)> {
        let mut report = SweepReport::empty();
        if set_id.is_nil() || wire::is_go_zero_time(now) {
            return Err((
                report,
                sweep_unavailable("release called with invalid arguments"),
            ));
        }
        if trigger == ReleaseTrigger::Reconciliation {
            return Err((report, trigger_refused()));
        }
        report.caller = Some(self.caller);
        let set = match self.reserves.read_set(set_id) {
            Ok(set) => set,
            Err(e) if sweep_absent(&e) => return Err((report, trigger_refused())),
            Err(e) => {
                // Both corruption classes: retained and reported,
                // never released. The error return (rather than nil)
                // is what keeps that legible to a caller that checks
                // only err.
                report.records_intact = false;
                report.push(
                    SweepItem::Set,
                    set_id.to_string(),
                    SweepAction::Retained,
                    None,
                    Some(record_condition(&e)),
                    0,
                );
                return Err((report, set_unreadable()));
            }
        };
        if set.state == ReserveState::Released {
            // Release is idempotent, exactly as the store's own
            // `release_set` is.
            report.push(
                SweepItem::Set,
                set.set_id.to_string(),
                SweepAction::Released,
                Some(trigger),
                None,
                0,
            );
        } else {
            match self.trigger_guard_holds(&set, trigger, now) {
                (false, condition) => {
                    report.push(
                        SweepItem::Set,
                        set.set_id.to_string(),
                        SweepAction::Retained,
                        None,
                        condition,
                        0,
                    );
                    return Err((report, trigger_refused()));
                }
                (true, _) => self.release_set(&mut report, &set, trigger, now),
            }
        }
        let claims = self
            .sweep_members(&mut report, now)
            .map_err(|e| (report.clone(), e))?;
        self.sweep_objects(&mut report, &claims)
            .map_err(|e| (report.clone(), e))?;
        self.sweep_pointers(&mut report)
            .map_err(|e| (report.clone(), e))?;
        Ok(report)
    }

    // --- phase 1: the set records ------------------------------------

    /// `sweepSets` — evaluate every readable set record against the
    /// sweep-discovered triggers.
    fn sweep_sets(&self, report: &mut SweepReport, now: OffsetDateTime) -> Result<(), Failure> {
        let names = sweep_dir_names(self.reserves.sets_dir())?;
        for name in names {
            let (record, ignore) = classify_entry(&name);
            if ignore {
                continue;
            }
            if !record {
                report.push(
                    SweepItem::Set,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::UnrecognizedEntry),
                    0,
                );
                continue;
            }
            let path = self.reserves.sets_dir().join(&name);
            let set = match self.reserves.read_set_at_path(&path) {
                Ok(set) => set,
                Err(e) if sweep_absent(&e) => continue,
                Err(e) => {
                    // The retain-never-delete rule, on both corruption
                    // classes. It also suppresses the object sweep for
                    // the whole pass.
                    report.records_intact = false;
                    report.push(
                        SweepItem::Set,
                        name,
                        SweepAction::Retained,
                        None,
                        Some(record_condition(&e)),
                        0,
                    );
                    continue;
                }
            };
            if set.state == ReserveState::Released {
                continue;
            }
            let (trigger, condition, fire) = self.evaluate_set(&set, now);
            let (Some(trigger), true) = (trigger, fire) else {
                report.push(
                    SweepItem::Set,
                    set.set_id.to_string(),
                    SweepAction::Retained,
                    None,
                    condition,
                    0,
                );
                continue;
            };
            self.release_set(report, &set, trigger, now);
        }
        Ok(())
    }

    /// `evaluateSet` — decide which of the four sweep-discovered
    /// triggers, if any, fires for one set.
    ///
    /// The order is load-bearing:
    ///
    /// 1. A terminal restore outcome releases unconditionally — a
    ///    ready or abandoned operation cannot still be applying.
    /// 2. The protection guard: unreadable operation, applying
    ///    operation, or a live bound launch record retains whatever
    ///    else is true.
    /// 3. Absolute expiry.
    /// 4. The issuing-ticket window, for a set bound to an operation
    ///    that has not begun.
    /// 5. The two unbound-only triggers, which never apply to a set
    ///    the gate has already committed.
    fn evaluate_set(
        &self,
        set: &ReserveSetRecord,
        now: OffsetDateTime,
    ) -> (Option<ReleaseTrigger>, Option<SweepCondition>, bool) {
        let (operation, present, readable) = self.operation_state(set.operation_id);
        if present && readable && operation.as_ref().is_some_and(|o| o.is_terminal()) {
            return (Some(ReleaseTrigger::TerminalOutcome), None, true);
        }
        if let (condition, true) =
            self.set_is_protected(set, operation.as_ref(), present, readable, now)
        {
            return (None, condition, false);
        }
        if now >= set.absolute_expires_at {
            return (Some(ReleaseTrigger::AbsoluteExpiry), None, true);
        }
        // Rules 3 and 5. A bound set whose operation record does not
        // exist is one whose `Begin` has not run: the ticket is the
        // only thing standing between the reserve and a sweep.
        //
        // It sits *after* the absolute-expiry release deliberately —
        // an unreadable ticket record retains, but must not retain
        // forever, and the set's own 8-hour expiry is what bounds it —
        // and *ahead of* the `set_committed` check: a **committed**
        // set whose operation record is absent and whose issuing
        // ticket has lapsed is released here, by rule 5. That is the
        // fail-safe direction (`Begin` never leaves a committed set
        // without first writing the operation record, so the case is
        // unreachable on a healthy host) and is deliberate.
        if !set.operation_id.is_nil() && !present {
            return match self.issuing_ticket_live(set.operation_id, now) {
                Err(_) => (None, Some(SweepCondition::TicketUnreadable), false),
                Ok(true) => (None, Some(SweepCondition::TicketIssued), false),
                Ok(false) => (Some(ReleaseTrigger::HelperAbandonment), None, true),
            };
        }
        if set.state == ReserveState::Verified {
            return (None, Some(SweepCondition::SetCommitted), false);
        }
        let (spent, lapsed) = self.spend_windows(set, now);
        if spent && lapsed {
            return (Some(ReleaseTrigger::ReceiptWindowLapsed), None, true);
        }
        if !spent {
            // Nothing was ever spent over this set and no live bound
            // launch record covers it: the helper that created it is
            // gone.
            return (Some(ReleaseTrigger::HelperAbandonment), None, true);
        }
        (None, Some(SweepCondition::SetLive), false)
    }

    /// `setIsProtected` — the one guard that stands between this sweep
    /// and freeing the cushion out from under a live `pg_restore`.
    ///
    /// An operation record that exists but cannot be read protects —
    /// "cannot tell" must never resolve toward deletion. An operation
    /// record that does not exist at all does not protect: there is no
    /// protected operation for a destructive run to be happening
    /// under, and the gate refuses without one.
    fn set_is_protected(
        &self,
        set: &ReserveSetRecord,
        operation: Option<&RestoreOperation>,
        present: bool,
        readable: bool,
        now: OffsetDateTime,
    ) -> (Option<SweepCondition>, bool) {
        if present && !readable {
            return (Some(SweepCondition::OperationUnreadable), true);
        }
        if present && readable && operation.is_some_and(|o| o.phase == RestorePhase::Applying) {
            return (Some(SweepCondition::OperationApplying), true);
        }
        match self.launch_is_live_for(set, now) {
            Err(_) => (Some(SweepCondition::LaunchUnreadable), true),
            Ok(true) => (Some(SweepCondition::LaunchLive), true),
            Ok(false) => (None, false),
        }
    }

    /// `triggerGuardHolds` — re-check a caller-fired trigger's own
    /// precondition against the durable record. Shares
    /// `set_is_protected` with the sweep-discovered path, so a caller
    /// cannot reach through `release` a release the sweep would
    /// refuse.
    fn trigger_guard_holds(
        &self,
        set: &ReserveSetRecord,
        trigger: ReleaseTrigger,
        now: OffsetDateTime,
    ) -> (bool, Option<SweepCondition>) {
        let (operation, present, readable) = self.operation_state(set.operation_id);
        if trigger == ReleaseTrigger::TerminalOutcome {
            if present && readable && operation.as_ref().is_some_and(|o| o.is_terminal()) {
                return (true, None);
            }
            if present && !readable {
                return (false, Some(SweepCondition::OperationUnreadable));
            }
            if present {
                return (false, Some(SweepCondition::OperationApplying));
            }
            return (false, Some(SweepCondition::SetLive));
        }
        if let (condition, true) =
            self.set_is_protected(set, operation.as_ref(), present, readable, now)
        {
            return (false, condition);
        }
        match trigger {
            ReleaseTrigger::AbsoluteExpiry => {
                if now < set.absolute_expires_at {
                    (false, Some(SweepCondition::SetLive))
                } else {
                    (true, None)
                }
            }
            ReleaseTrigger::VerifyFailed => {
                // "before binding": a set the gate has committed was
                // bound, and a set whose members are provisionally
                // consumed has had receipts spent over it.
                if set.state != ReserveState::Intent && set.state != ReserveState::Allocated {
                    (false, Some(SweepCondition::SetCommitted))
                } else {
                    (true, None)
                }
            }
            ReleaseTrigger::ReceiptWindowLapsed => {
                if set.state == ReserveState::Verified {
                    return (false, Some(SweepCondition::SetCommitted));
                }
                let (spent, lapsed) = self.spend_windows(set, now);
                if !spent || !lapsed {
                    (false, Some(SweepCondition::SetLive))
                } else {
                    (true, None)
                }
            }
            ReleaseTrigger::HelperAbandonment => {
                if set.state == ReserveState::Verified {
                    return (false, Some(SweepCondition::SetCommitted));
                }
                let (spent, _) = self.spend_windows(set, now);
                if spent {
                    (false, Some(SweepCondition::SetLive))
                } else {
                    (true, None)
                }
            }
            _ => (false, Some(SweepCondition::SetLive)),
        }
    }

    /// `releaseSet` — advance the set and all four of its member
    /// records to released, attributing the trigger that caused it.
    /// Every write is the store's own idempotent release, so a set
    /// already released costs nothing.
    fn release_set(
        &self,
        report: &mut SweepReport,
        set: &ReserveSetRecord,
        trigger: ReleaseTrigger,
        now: OffsetDateTime,
    ) {
        if self.reserves.release_set(set.set_id, now).is_err() {
            report.records_intact = false;
            report.push(
                SweepItem::Set,
                set.set_id.to_string(),
                SweepAction::Retained,
                None,
                Some(SweepCondition::RecordUnreadable),
                0,
            );
            return;
        }
        report.push(
            SweepItem::Set,
            set.set_id.to_string(),
            SweepAction::Released,
            Some(trigger),
            None,
            0,
        );
        for role in RESERVE_ROLES {
            let key = format!("{}/{}", set.set_id, role.as_str());
            match self.reserves.release_member(set.set_id, role, now) {
                Ok(_) => report.push(
                    SweepItem::Member,
                    key,
                    SweepAction::Released,
                    Some(trigger),
                    None,
                    0,
                ),
                Err(e) if sweep_absent(&e) => continue,
                Err(e) => {
                    report.records_intact = false;
                    report.push(
                        SweepItem::Member,
                        key,
                        SweepAction::Retained,
                        None,
                        Some(record_condition(&e)),
                        0,
                    );
                }
            }
        }
    }

    // --- phase 2: the member records, and the claims they carry ------

    /// `sweepMembers` — read every member record and build the set of
    /// physical reserve objects a live record still claims. Runs
    /// *after* the set phase, so a set released on this pass no longer
    /// protects its objects on this pass.
    ///
    /// An unreadable member record claims — conservatively, since its
    /// fingerprint cannot be read, the claim is recorded as the
    /// whole-pass suppression rather than as a specific object — and
    /// an unreadable *set* behind a readable member does the same.
    fn sweep_members(
        &self,
        report: &mut SweepReport,
        now: OffsetDateTime,
    ) -> Result<HashSet<SweepClaim>, Failure> {
        let mut claims = HashSet::new();
        let names = sweep_dir_names(self.reserves.members_dir())?;
        for name in names {
            let (record, ignore) = classify_entry(&name);
            if ignore {
                continue;
            }
            if !record {
                report.push(
                    SweepItem::Member,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::UnrecognizedEntry),
                    0,
                );
                continue;
            }
            let path = self.reserves.members_dir().join(&name);
            let member = match self.reserves.read_member_at_path(&path) {
                Ok(member) => member,
                Err(e) if sweep_absent(&e) => continue,
                Err(e) => {
                    report.records_intact = false;
                    report.push(
                        SweepItem::Member,
                        name,
                        SweepAction::Retained,
                        None,
                        Some(record_condition(&e)),
                        0,
                    );
                    continue;
                }
            };
            let key = format!("{}/{}", member.set_id, member.role.as_str());
            if member.state == ReserveState::Released {
                continue;
            }
            match self.reserves.read_set(member.set_id) {
                Ok(set) if set.state != ReserveState::Released => {
                    claims.insert(claim_of(member.st_dev, &member.device_fingerprint));
                    report.push(
                        SweepItem::Member,
                        key,
                        SweepAction::Retained,
                        None,
                        Some(SweepCondition::SetLive),
                        0,
                    );
                }
                Ok(_) => {
                    // A released set: the member follows its set into
                    // released so a later pass need not re-derive it.
                    self.release_orphan_member(report, &member, &key, now);
                }
                Err(e) if sweep_absent(&e) => {
                    // An orphan whose set record is demonstrably gone:
                    // same disposition.
                    self.release_orphan_member(report, &member, &key, now);
                }
                Err(e) => {
                    // The set is there and cannot be read: retain,
                    // report, suppress.
                    report.records_intact = false;
                    claims.insert(claim_of(member.st_dev, &member.device_fingerprint));
                    report.push(
                        SweepItem::Member,
                        key,
                        SweepAction::Retained,
                        None,
                        Some(record_condition(&e)),
                        0,
                    );
                }
            }
        }
        Ok(claims)
    }

    /// The released-set/orphan leg of `sweep_members`: release the
    /// member record so a later pass does not re-derive it.
    fn release_orphan_member(
        &self,
        report: &mut SweepReport,
        member: &ReserveMemberRecord,
        key: &str,
        now: OffsetDateTime,
    ) {
        match self
            .reserves
            .release_member(member.set_id, member.role, now)
        {
            Ok(_) => report.push(
                SweepItem::Member,
                key.to_string(),
                SweepAction::Released,
                Some(ReleaseTrigger::Reconciliation),
                None,
                0,
            ),
            Err(e) => {
                report.records_intact = false;
                report.push(
                    SweepItem::Member,
                    key.to_string(),
                    SweepAction::Retained,
                    None,
                    Some(record_condition(&e)),
                    0,
                );
            }
        }
    }

    // --- phase 3: the device-keyed object store ------------------------

    /// `sweepObjects` — walk each device's reserve store and unlink
    /// every object no live record claims.
    ///
    /// A role root that cannot be opened, and a store directory that
    /// cannot be resolved beneath one, are each their own reported
    /// condition rather than an error or a silent skip: on a
    /// disaster-recovery host a device that is simply gone is one of
    /// the more likely things an operator needs to be told.
    ///
    /// Devices are visited once each, keyed by the store's own
    /// `st_dev`, because the four role roots on a single-disk host
    /// resolve to one store.
    fn sweep_objects(
        &self,
        report: &mut SweepReport,
        claims: &HashSet<SweepClaim>,
    ) -> Result<(), Failure> {
        use rustix::fs::{Mode, OFlags};
        let mut visited: HashSet<u64> = HashSet::with_capacity(RESERVE_ROLES.len());
        for role in RESERVE_ROLES {
            let path = role.root(&self.roots);
            let root = if path.is_empty() {
                None
            } else {
                rustix::fs::open(
                    path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok()
            };
            let Some(root) = root else {
                report.push(
                    SweepItem::Device,
                    role.as_str(),
                    SweepAction::Reported,
                    None,
                    Some(SweepCondition::DeviceAbsent),
                    0,
                );
                continue;
            };
            let store = match (self.open_store)(root.as_fd()) {
                Ok(store) => store,
                Err(_) => {
                    report.push(
                        SweepItem::Device,
                        role.as_str(),
                        SweepAction::Reported,
                        None,
                        Some(SweepCondition::StoreAbsent),
                        0,
                    );
                    continue;
                }
            };
            if !visited.insert(store.st_dev()) {
                continue;
            }
            self.sweep_device_store(report, store.as_ref(), claims);
        }
        Ok(())
    }

    fn sweep_device_store(
        &self,
        report: &mut SweepReport,
        store: &dyn SweepStore,
        claims: &HashSet<SweepClaim>,
    ) {
        let names = match sweep_names(store.dir_fd()) {
            Ok(names) => names,
            Err(_) => {
                report.push(
                    SweepItem::Device,
                    "",
                    SweepAction::Reported,
                    None,
                    Some(SweepCondition::StoreAbsent),
                    0,
                );
                return;
            }
        };
        for name in names {
            if !store_path::is_object_name(&name) {
                // Something else dropped into the store directory. The
                // sweep owns exactly the names this package's resolver
                // mints, so this is reported and left alone.
                report.push(
                    SweepItem::Object,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::UnrecognizedEntry),
                    0,
                );
                continue;
            }
            let Some(fingerprint) = name.strip_suffix(store_path::OBJECT_SUFFIX) else {
                continue;
            };
            let stat = rustix::fs::statat(
                store.dir_fd(),
                name.as_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            );
            let Ok(stat) = stat else {
                report.push(
                    SweepItem::Object,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::RecordUnreadable),
                    0,
                );
                continue;
            };
            // A reserve object is a single-linked regular file on the
            // store's own device. Ownership is not re-asserted here:
            // the resolver proved the store directory is root:root
            // 0700 before handing this descriptor back.
            if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
                || stat.st_dev != store.st_dev()
                || stat.st_nlink != 1
            {
                report.push(
                    SweepItem::Object,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::UnrecognizedEntry),
                    0,
                );
                continue;
            }
            if claims.contains(&claim_of(store.st_dev(), fingerprint)) {
                report.push(
                    SweepItem::Object,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::ObjectClaimed),
                    0,
                );
                continue;
            }
            if !report.records_intact {
                // The retain-never-delete rule reaching the physical
                // layer: a record this build could not parse may be
                // the claim on this exact object.
                report.push(
                    SweepItem::Object,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::ObjectSuppressed),
                    0,
                );
                continue;
            }
            let bytes = gate_allocated_bytes(stat.st_blocks).unwrap_or(0);
            match store.remove(fingerprint) {
                Ok(()) => {
                    report.bytes_released += bytes;
                    report.push(
                        SweepItem::Object,
                        name,
                        SweepAction::Released,
                        Some(ReleaseTrigger::Reconciliation),
                        Some(SweepCondition::ObjectUnclaimed),
                        bytes,
                    );
                }
                Err(_) => report.push(
                    SweepItem::Object,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::RecordUnreadable),
                    0,
                ),
            }
        }
    }

    // --- phase 4: the two inherited pointer families --------------------

    /// `sweepPointers` — release the operation→set index and the
    /// (set, role)→spent-receipt pointer whose targets are gone or
    /// released. Neither can strand a physical reserve, but an
    /// unswept accumulation of them is a durable-state leak, and this
    /// sweep is the only thing positioned to close it.
    ///
    /// The unrecognized-schema rule applies identically: a pointer
    /// this build cannot parse is retained and reported, never
    /// deleted, because it may name a set that is in fact live.
    fn sweep_pointers(&self, report: &mut SweepReport) -> Result<(), Failure> {
        self.sweep_pointer_directory(
            report,
            SweepItem::OperationIndex,
            self.reserves.operations_dir(),
            |path| {
                self.reserves
                    .read_operation_index_at_path(path)
                    .map(|record| (record.set_id, record.operation_id.to_string()))
            },
        )?;
        self.sweep_pointer_directory(
            report,
            SweepItem::SpendPointer,
            self.receipts.spends_dir(),
            |path| {
                self.receipts.read_spend_at_path(path).map(|record| {
                    (
                        record.set_id,
                        format!("{}/{}", record.set_id, record.role.as_str()),
                    )
                })
            },
        )?;
        Ok(())
    }

    fn sweep_pointer_directory(
        &self,
        report: &mut SweepReport,
        item: SweepItem,
        dir: &Path,
        read: impl Fn(&Path) -> Result<(Uuid, String), Failure>,
    ) -> Result<(), Failure> {
        let names = sweep_dir_names(dir)?;
        for name in names {
            let (record, ignore) = classify_entry(&name);
            if ignore {
                continue;
            }
            if !record {
                report.push(
                    item,
                    name,
                    SweepAction::Retained,
                    None,
                    Some(SweepCondition::UnrecognizedEntry),
                    0,
                );
                continue;
            }
            let path: PathBuf = dir.join(&name);
            let (set_id, key) = match read(&path) {
                Ok(v) => v,
                Err(e) if sweep_absent(&e) => continue,
                Err(e) => {
                    report.push(
                        item,
                        name,
                        SweepAction::Retained,
                        None,
                        Some(record_condition(&e)),
                        0,
                    );
                    continue;
                }
            };
            let condition = match self.reserves.read_set(set_id) {
                Ok(set) if set.state != ReserveState::Released => {
                    report.push(
                        item,
                        key,
                        SweepAction::Retained,
                        None,
                        Some(SweepCondition::PointerTargetLive),
                        0,
                    );
                    continue;
                }
                Ok(_) => SweepCondition::PointerTargetReleased,
                Err(e) if sweep_absent(&e) => SweepCondition::PointerTargetMissing,
                Err(e) => {
                    // The set exists and cannot be parsed. It may be
                    // live; the pointer stays.
                    report.push(
                        item,
                        key,
                        SweepAction::Retained,
                        None,
                        Some(record_condition(&e)),
                        0,
                    );
                    continue;
                }
            };
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    report.push(
                        item,
                        key,
                        SweepAction::Retained,
                        None,
                        Some(SweepCondition::RecordUnreadable),
                        0,
                    );
                    continue;
                }
            }
            report.push(
                item,
                key,
                SweepAction::Released,
                Some(ReleaseTrigger::Reconciliation),
                Some(condition),
                0,
            );
        }
        Ok(())
    }

    // --- the facts the triggers are decided from -------------------------

    /// `operationState` — whether the protected restore operation
    /// behind a set exists on disk at all, and if so whether it could
    /// be read. The distinction matters and the journal's own `read`
    /// cannot make it: it collapses "no such file" and "corrupt
    /// record" into one error. An operation that does not exist cannot
    /// have a destructive run happening under it; an operation that
    /// exists and cannot be read is exactly the case where this sweep
    /// must not guess.
    fn operation_state(&self, operation_id: Uuid) -> (Option<RestoreOperation>, bool, bool) {
        if operation_id.is_nil() || !self.journal.restore_operation_present(operation_id) {
            return (None, false, false);
        }
        match self.journal.read(operation_id) {
            Ok(operation) => (Some(operation), true, true),
            Err(_) => (None, true, false),
        }
    }

    /// `issuingTicketLive` — is the ticket that bound this set to its
    /// operation still one an operator could consume?
    ///
    /// The three answers are distinct on purpose:
    ///
    /// - carry demonstrably absent: no ticket was ever minted for this
    ///   operation — not live, no error.
    /// - carry or ticket present and unreadable: an error, which
    ///   retains. The set's absolute expiry is what stops that
    ///   retention being permanent.
    /// - readable: live iff still `issued` and unexpired.
    fn issuing_ticket_live(
        &self,
        operation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, Failure> {
        let carry = match self.journal.read_ticket_launch(operation_id) {
            Ok(carry) => carry,
            Err(e) if e.code() == recovery_journal::TICKET_LAUNCH_NOT_FOUND_CODE => {
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let ticket = self.journal.read_ticket_record(carry.ticket_id)?;
        if ticket.ticket.operation_id != operation_id || ticket.state != "issued" {
            return Ok(false);
        }
        Ok(now < ticket.ticket.expires_at)
    }

    /// `launchIsLiveFor` — the abandonment guard: is there a live
    /// bound launch record for the operation this set protects? Goes
    /// through `inspect_liveness`, never `validate_peer`: a sweep has
    /// no peer credential to offer and no business advancing the
    /// record from issued to active.
    ///
    /// The launch record carries no operation id, so the binding is
    /// made through the launch evidence identity both the record and
    /// the set carry.
    fn launch_is_live_for(
        &self,
        set: &ReserveSetRecord,
        now: OffsetDateTime,
    ) -> Result<bool, Failure> {
        let liveness = self.launches.inspect_liveness(now)?;
        if !liveness.bound || liveness.launch_evidence_id != set.launch_evidence_id {
            return Ok(false);
        }
        Ok(liveness.engine_live && !liveness.deadline_passed)
    }

    /// `spendWindows` — whether any receipt was ever spent over this
    /// set, and whether every such spend's own window has lapsed. The
    /// window is the receipt's 20 minutes, read from the ledger's
    /// (set, role) spend pointer rather than from the member record:
    /// `attach_member_receipt` refuses replacement, so a member
    /// permanently names its *first* receipt, which on the retry path
    /// may never have been presented at all.
    fn spend_windows(&self, set: &ReserveSetRecord, now: OffsetDateTime) -> (bool, bool) {
        let mut spent = false;
        let mut all_lapsed = true;
        for role in RESERVE_ROLES {
            match self.receipts.read_spend(set.set_id, role) {
                Ok(spend) => {
                    spent = true;
                    if now < spend.expires_at {
                        all_lapsed = false;
                    }
                }
                Err(e) if sweep_absent(&e) => continue,
                Err(_) => {
                    // A spend record that exists and cannot be read is
                    // not evidence that nothing was spent. Treat the
                    // set as spent and in force: the conservative
                    // direction is to retain.
                    return (true, false);
                }
            }
        }
        (spent, all_lapsed)
    }
}

// ---------------------------------------------------------------------------
// Tests — vocabulary round-trips, gate_allocated_bytes, classify_entry.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The six-trigger closed release set: every wire string round-trips,
    /// and no seventh value parses.
    #[test]
    fn release_trigger_vocabulary_is_closed() {
        for trigger in [
            ReleaseTrigger::VerifyFailed,
            ReleaseTrigger::ReceiptWindowLapsed,
            ReleaseTrigger::HelperAbandonment,
            ReleaseTrigger::TerminalOutcome,
            ReleaseTrigger::Reconciliation,
            ReleaseTrigger::AbsoluteExpiry,
        ] {
            assert_eq!(ReleaseTrigger::from_str(trigger.as_str()), Some(trigger));
        }
        assert_eq!(ReleaseTrigger::from_str("caller_arbitrary"), None);
        assert_eq!(ReleaseTrigger::from_str(""), None);
    }

    /// The two named helper call sites round-trip; unnamed callers
    /// cannot be expressed.
    #[test]
    fn sweep_caller_vocabulary_is_closed() {
        for caller in [
            SweepCaller::HelperStartup,
            SweepCaller::HelperRestoreLauncher,
        ] {
            assert_eq!(SweepCaller::from_str(caller.as_str()), Some(caller));
        }
        assert_eq!(SweepCaller::from_str("central-serve"), None);
    }

    /// Every item/action/condition wire string round-trips.
    #[test]
    fn sweep_outcome_vocabularies_round_trip() {
        for item in [
            SweepItem::Set,
            SweepItem::Member,
            SweepItem::OperationIndex,
            SweepItem::SpendPointer,
            SweepItem::Object,
            SweepItem::Device,
        ] {
            assert_eq!(SweepItem::from_str(item.as_str()), Some(item));
        }
        for action in [
            SweepAction::Released,
            SweepAction::Retained,
            SweepAction::Reported,
        ] {
            assert_eq!(SweepAction::from_str(action.as_str()), Some(action));
        }
        for condition in [
            SweepCondition::UnrecognizedSchema,
            SweepCondition::RecordUnreadable,
            SweepCondition::OperationApplying,
            SweepCondition::OperationUnreadable,
            SweepCondition::LaunchLive,
            SweepCondition::LaunchUnreadable,
            SweepCondition::SetCommitted,
            SweepCondition::SetLive,
            SweepCondition::TicketIssued,
            SweepCondition::TicketUnreadable,
            SweepCondition::DeviceAbsent,
            SweepCondition::StoreAbsent,
            SweepCondition::ObjectClaimed,
            SweepCondition::ObjectUnclaimed,
            SweepCondition::ObjectSuppressed,
            SweepCondition::PointerTargetMissing,
            SweepCondition::PointerTargetReleased,
            SweepCondition::PointerTargetLive,
            SweepCondition::UnrecognizedEntry,
        ] {
            assert_eq!(
                SweepCondition::from_str(condition.as_str()),
                Some(condition)
            );
        }
        assert_eq!(SweepCondition::from_str("operator_choice"), None);
    }

    /// `gate_allocated_bytes` — `st_blocks × 512`, `None` on overflow
    /// or a negative block count.
    #[test]
    fn allocated_bytes_scales_blocks() {
        assert_eq!(gate_allocated_bytes(0), Some(0));
        assert_eq!(gate_allocated_bytes(1), Some(512));
        assert_eq!(gate_allocated_bytes(-1), None);
        assert_eq!(gate_allocated_bytes(i64::MAX), None);
    }

    /// `classify_entry` sorts record names, infrastructure, and
    /// foreign entries into their three buckets.
    #[test]
    fn directory_entries_classify() {
        let record = format!("{}.json", "a".repeat(64));
        assert_eq!(classify_entry(&record), (true, false));
        assert_eq!(classify_entry(&format!("{record}.lock")), (false, true));
        assert_eq!(classify_entry(".recovery-journal-abc"), (false, true));
        assert_eq!(classify_entry("not-a-record.json"), (false, false));
        assert_eq!(
            classify_entry(&format!("{}.json", "A".repeat(64))),
            (false, false)
        );
        assert_eq!(classify_entry("stray.txt"), (false, false));
    }
}
