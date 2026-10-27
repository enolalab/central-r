//! `restore_capacity_reserve_allocation_linux.go` — helper-side
//! allocation for the restore capacity reserve gate.
//!
//! Before a destructive `pg_restore` may run, enough disk must be
//! *physically* reserved on each of the four capacity roles' devices,
//! so the restore cannot die of `ENOSPC` part-way through on a machine
//! the operator has already accepted as damaged. This is the half that
//! runs in the root helper: it resolves each role's device from a held
//! descriptor, refuses unsupported or ambiguous ones, physically
//! allocates the reserve object, re-measures, and reports what it
//! observed.
//!
//! Two orderings from the design are structural:
//!
//! - **Intent before allocate.** The member intent record is written
//!   from the helper's measurements *before* any physical object
//!   exists, so a process that dies between the two leaves a durably
//!   discoverable intent record and no orphaned object. Allocation is
//!   two phases — [`ReserveAllocator::plan`] (measure, refuse, report
//!   intents) and [`ReservePlan::allocate`] (create, `fallocate`,
//!   re-measure) — rather than one call: the frame-`0xc3` writes
//!   belong between them.
//! - **`st_dev` is authoritative; the fingerprint is a naming key.**
//!   Every identity decision turns on `st_dev`. A fingerprint match is
//!   never accepted as a substitute.

use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use central_foundation::failure::Failure;
use time::OffsetDateTime;

use central_backup::backup::capacity::{
    FREE_FLOOR_BYTES, RestoreCapacityDemand, RoleRoots, SURVIVAL_RESERVE_BYTES,
    restore_admission_margin,
};

use crate::sys::audited;

use super::store::ReserveMemberIntent;
use super::store_path::{self, ReserveDeviceStore};
use super::{RESERVE_ROLES, ReserveRole};

/// `restoreCapacityReserveObjectBytes` — the per-device reserve: exactly
/// [`SURVIVAL_RESERVE_BYTES`], the same domain constant the ordinary
/// backup admission path already reserves against.
pub const RESERVE_OBJECT_BYTES: u64 = SURVIVAL_RESERVE_BYTES;

/// `restoreCapacityReserveMaxObjectsPerHost` — at most one object per
/// device, four roles at most: a structural ceiling, not a tunable.
pub const MAX_OBJECTS_PER_HOST: usize = RESERVE_ROLES.len();

/// `restoreCapacityReserveMaxHostBytes` — derived from the two caps
/// above (4 × 4 GiB = 16 GiB), not written down independently.
pub const MAX_HOST_BYTES: u64 = MAX_OBJECTS_PER_HOST as u64 * RESERVE_OBJECT_BYTES;

// --- Refusal sentinels ------------------------------------------------------
// Upstream discriminates with `errors.Is`; the port keeps each refusal a
// distinct `Failure` code so the same `is_*` classification is possible.

const CODE_FS: &str = "broker_restore_reserve_filesystem";
const CODE_AMBIGUOUS: &str = "broker_restore_reserve_device_ambiguous";
const CODE_FLOOR: &str = "broker_restore_reserve_floor";
const CODE_CAP: &str = "broker_restore_reserve_cap";
const CODE_LIVE_SET: &str = "broker_restore_reserve_live_set";
const CODE_ROLE_ROOT: &str = "broker_restore_reserve_role_root";
const CODE_PLAN_STATE: &str = "broker_restore_reserve_plan_state";
const CODE_EXTENT: &str = "broker_restore_reserve_extent";

fn fs_refused() -> Failure {
    Failure::denied(
        CODE_FS,
        "broker: restore capacity reserve role root is on an unsupported filesystem",
    )
}
fn ambiguous() -> Failure {
    Failure::denied(
        CODE_AMBIGUOUS,
        "broker: restore capacity reserve role roots disagree about device identity",
    )
}
fn floor() -> Failure {
    Failure::denied(
        CODE_FLOOR,
        "broker: restore capacity reserve would breach the free floor",
    )
}
fn cap() -> Failure {
    Failure::denied(
        CODE_CAP,
        "broker: restore capacity reserve exceeds a host cap",
    )
}
fn live_set() -> Failure {
    Failure::denied(
        CODE_LIVE_SET,
        "broker: a restore capacity reserve set is already live for this instance",
    )
}
fn role_root() -> Failure {
    Failure::denied(
        CODE_ROLE_ROOT,
        "broker: restore capacity reserve role root is unusable",
    )
}
fn plan_state() -> Failure {
    Failure::denied(
        CODE_PLAN_STATE,
        "broker: restore capacity reserve plan is not in an allocatable state",
    )
}
fn extent() -> Failure {
    Failure::denied(
        CODE_EXTENT,
        "broker: invalid restore capacity reserve extent",
    )
}

#[allow(dead_code)] // classified upstream for the helper-side call site
pub(crate) fn is_floor(f: &Failure) -> bool {
    f.code() == CODE_FLOOR
}
#[allow(dead_code)] // classified upstream for the helper-side call site
pub(crate) fn is_cap(f: &Failure) -> bool {
    f.code() == CODE_CAP
}
#[allow(dead_code)] // classified upstream for the helper-side call site
pub(crate) fn is_live_set(f: &Failure) -> bool {
    f.code() == CODE_LIVE_SET
}
#[allow(dead_code)]
pub(crate) fn is_ambiguous(f: &Failure) -> bool {
    f.code() == CODE_AMBIGUOUS
}

// --- measurement ------------------------------------------------------------

/// `restoreCapacityReserveSupportedFilesystem` — the design's
/// allowlist: ext4 and XFS only, checked before any allocation,
/// failing closed on everything else. ext2/ext3 share
/// `EXT4_SUPER_MAGIC`; the kernel reports one magic for the whole
/// family and no finer distinction is available from `statfs`.
fn supported_filesystem(fs_type: i64) -> bool {
    const EXT4_SUPER_MAGIC: i64 = 0xEF53;
    const XFS_SUPER_MAGIC: i64 = 0x584D_5342;
    fs_type == EXT4_SUPER_MAGIC || fs_type == XFS_SUPER_MAGIC
}

/// `restoreCapacityReserveMeasurement` — one role root's reading,
/// taken from a held descriptor.
#[derive(Debug, Clone)]
pub(crate) struct Measurement {
    pub role: ReserveRole,
    pub st_dev: u64,
    pub fingerprint: String,
    pub free_bytes: u64,
}

/// `restoreCapacityReserveDevice` — one physical device the reserve
/// must cover, after the four roles collapse onto the devices they
/// actually share.
#[derive(Debug, Clone)]
pub(crate) struct ReserveDevice {
    pub st_dev: u64,
    pub fingerprint: String,
    /// `AnchorRole` — the role whose held root descriptor this
    /// device's store resolves beneath: the first role in
    /// `RESERVE_ROLES` order on this `st_dev`. A deterministic
    /// function of `st_dev` and the fixed role order, which is what
    /// lets the gate and the sweep re-derive the identical location
    /// without being told.
    pub anchor_role: ReserveRole,
    pub roles: Vec<ReserveRole>,
    pub free_bytes: u64,
    pub planned_bytes: u64,
}

/// `restoreCapacityReserveRoleDemand` — map the domain's per-role
/// restore plan onto this package's role vocabulary. The arithmetic
/// itself stays in `restore_capacity_demands`; this is a lookup.
pub(crate) fn role_demand(demand: &RestoreCapacityDemand, role: ReserveRole) -> u64 {
    match role {
        ReserveRole::PostgresData => demand.postgres_data_bytes,
        ReserveRole::PostgresWal => demand.postgres_wal_bytes,
        ReserveRole::PostgresTemp => demand.postgres_temp_bytes,
        ReserveRole::ObjectData => demand.object_data_bytes,
    }
}

pub(crate) fn add_bytes(left: u64, right: u64) -> Option<u64> {
    left.checked_add(right)
}

/// `restoreCapacityReserveCollapse` — group the four measurements onto
/// devices, refusing both directions of identity disagreement:
/// same-fingerprint-different-`st_dev` (two devices on one store name)
/// and same-`st_dev`-different-fingerprint (one device under two store
/// names). Only one is imaginable as an honest kernel report — which
/// is precisely why the other must not be silently absorbed.
pub(crate) fn collapse(
    measurements: &[Measurement],
    demand: &RestoreCapacityDemand,
) -> Result<Vec<ReserveDevice>, Failure> {
    if measurements.len() != RESERVE_ROLES.len() {
        return Err(role_root());
    }
    let mut by_dev: HashMap<u64, usize> = HashMap::with_capacity(measurements.len());
    let mut by_fingerprint: HashMap<&str, u64> = HashMap::with_capacity(measurements.len());
    let mut devices: Vec<ReserveDevice> = Vec::with_capacity(measurements.len());
    let mut seen_roles: HashMap<ReserveRole, ()> = HashMap::with_capacity(measurements.len());
    for m in measurements {
        if m.st_dev == 0 || !store_path::valid_fingerprint(&m.fingerprint) {
            return Err(role_root());
        }
        if seen_roles.insert(m.role, ()).is_some() {
            return Err(role_root());
        }
        // Same fingerprint must mean same st_dev.
        if by_fingerprint
            .get(m.fingerprint.as_str())
            .is_some_and(|&existing| existing != m.st_dev)
        {
            return Err(ambiguous());
        }
        by_fingerprint.insert(m.fingerprint.as_str(), m.st_dev);
        match by_dev.get(&m.st_dev) {
            None => {
                by_dev.insert(m.st_dev, devices.len());
                devices.push(ReserveDevice {
                    st_dev: m.st_dev,
                    fingerprint: m.fingerprint.clone(),
                    anchor_role: m.role,
                    roles: vec![m.role],
                    free_bytes: m.free_bytes,
                    planned_bytes: 0,
                });
            }
            Some(&index) => {
                // ...and same st_dev must mean same fingerprint.
                if devices[index].fingerprint != m.fingerprint {
                    return Err(ambiguous());
                }
                devices[index].roles.push(m.role);
                // The conservative reading wins: two roles on one
                // device may report different free bytes only if
                // something moved between the two fstatfs calls; the
                // smaller figure is the safe one to plan on.
                if m.free_bytes < devices[index].free_bytes {
                    devices[index].free_bytes = m.free_bytes;
                }
            }
        }
    }
    for device in &mut devices {
        let mut planned = 0u64;
        for role in &device.roles {
            planned = add_bytes(planned, role_demand(demand, *role)).ok_or_else(floor)?;
        }
        device.planned_bytes = planned;
    }
    Ok(devices)
}

/// `restoreCapacityReserveRequiredFree` — `FREE_FLOOR + margin +
/// reserve`, all overflow-checked. `restore_admission_margin` is the
/// domain's own 1.25 admission margin.
fn required_free(planned_bytes: u64, reserve_bytes: u64) -> Result<u64, Failure> {
    let margin = restore_admission_margin(planned_bytes).ok_or_else(floor)?;
    let required = add_bytes(FREE_FLOOR_BYTES, margin).ok_or_else(floor)?;
    add_bytes(required, reserve_bytes).ok_or_else(floor)
}

/// `restoreCapacityReservePreAllocationFloor` — the design's precheck:
/// `free >= SURVIVAL_RESERVE + FREE_FLOOR + margin(planned_device)`.
pub(crate) fn pre_allocation_floor(free_bytes: u64, planned_bytes: u64) -> Result<(), Failure> {
    let required = required_free(planned_bytes, RESERVE_OBJECT_BYTES)?;
    if free_bytes < required {
        return Err(floor());
    }
    Ok(())
}

/// `restoreCapacityReservePostAllocationFloor` — the re-measurement
/// check. The survival reserve is no longer free once its object
/// exists — that is the entire point of allocating it — so the post
/// condition drops that term and requires the *remaining* free space
/// to still clear floor plus margin on the planned restore.
pub(crate) fn post_allocation_floor(free_bytes: u64, planned_bytes: u64) -> Result<(), Failure> {
    let required = required_free(planned_bytes, 0)?;
    if free_bytes < required {
        return Err(floor());
    }
    Ok(())
}

/// `restoreCapacityReserveHostCaps` — the two per-host ceilings: at
/// most four reserve objects, at most 16 GiB in total. Fed a census of
/// the objects already present in each device's store directory plus
/// the ones this call is creating — not merely this call's own count.
pub(crate) fn host_caps(objects: usize, total_bytes: u64) -> Result<(), Failure> {
    if objects == 0 || objects > MAX_OBJECTS_PER_HOST {
        return Err(cap());
    }
    if total_bytes > MAX_HOST_BYTES {
        return Err(cap());
    }
    Ok(())
}

/// `restoreCapacityReserveCapError` — wrap the cap refusal with the
/// store directory (or directories) and object count that tripped the
/// cap: until the sweep clears foreign-fingerprint leftovers, a bare
/// sentinel leaves an operator with no clue what to remove or where to
/// look. Directories are read back through `/proc/self/fd/<DirFD>` —
/// the held descriptor the resolver already validated — rather than
/// reconstructed from a role root and the store's literal name, which
/// would re-derive the resolver's path a second time.
fn cap_error(objects: usize, total_bytes: u64, stores: &[&dyn ReserveObjectStore]) -> Failure {
    let mut dirs: Vec<String> = Vec::with_capacity(stores.len());
    for store in stores {
        if let Ok(path) =
            std::fs::read_link(format!("/proc/self/fd/{}", store.dir_fd().as_raw_fd()))
        {
            dirs.push(path.display().to_string());
        }
    }
    let description = if dirs.is_empty() {
        "<unresolved restore capacity reserve store directory>".to_string()
    } else {
        dirs.join(", ")
    };
    Failure::denied(
        CODE_CAP,
        format!(
            "broker: restore capacity reserve exceeds a host cap: {description} holds \
             {objects} reserve objects ({total_bytes} bytes); the host cap is \
             {MAX_OBJECTS_PER_HOST} objects / {MAX_HOST_BYTES} bytes"
        ),
    )
}

/// `restoreCapacityReserveTotalBytes` — deliberately only an overflow
/// guard, not a second copy of the object-count cap.
fn total_bytes(devices: usize) -> Option<u64> {
    (devices as u64).checked_mul(RESERVE_OBJECT_BYTES)
}

// --- allocator ---------------------------------------------------------------

/// `RestoreCapacityReserveAllocation` — one role's completed
/// helper-side observation, the shape the member intent record is
/// written from.
///
/// `reserved_bytes` is the *device's* reserve, not a per-role share:
/// roles sharing an `st_dev` are backed by one object of exactly
/// `RESERVE_OBJECT_BYTES`. `st_dev` travels with every allocation — a
/// consumer summing `reserved_bytes` across roles must dedupe by
/// `st_dev` first or it counts one object up to four times.
#[derive(Debug, Clone)]
pub struct ReserveAllocation {
    pub role: ReserveRole,
    pub device_fingerprint: String,
    pub st_dev: u64,
    pub reserved_bytes: u64,
    pub observed_free_bytes: u64,
    pub observed_at: OffsetDateTime,
}

impl ReserveAllocation {
    /// `MemberIntent` — the record-store/frame shape of this
    /// observation, so no caller restates the field mapping.
    pub fn member_intent(&self) -> ReserveMemberIntent {
        ReserveMemberIntent {
            role: self.role,
            device_fingerprint: self.device_fingerprint.clone(),
            st_dev: self.st_dev,
            reserved_bytes: self.reserved_bytes,
            observed_free_bytes: self.observed_free_bytes,
            observed_at: self.observed_at,
        }
    }
}

/// `restoreCapacityReserveObjectStore` — the whole of what `allocate`
/// needs from a device's reserve store: the device identity to
/// re-check, the directory descriptor to fsync, the census the host
/// caps consume, and create/remove.
///
/// [`ReserveDeviceStore`] is the only implementation production ever
/// sees — `plan` wires [`store_path::open_device_store`] in and
/// nothing else assigns the field. The trait exists so the
/// release-and-fail rollback can be exercised by an ordinary user: the
/// real store insists on a root:root directory and a root-owned
/// object, which no unprivileged process can produce.
pub trait ReserveObjectStore {
    fn st_dev(&self) -> u64;
    fn dir_fd(&self) -> BorrowedFd<'_>;
    fn object_count(&self) -> Result<usize, Failure>;
    fn create(&self, fingerprint: &str) -> Result<std::fs::File, Failure>;
    fn remove(&self, fingerprint: &str) -> Result<(), Failure>;
}

impl ReserveObjectStore for ReserveDeviceStore {
    fn st_dev(&self) -> u64 {
        self.st_dev()
    }
    fn dir_fd(&self) -> BorrowedFd<'_> {
        ReserveDeviceStore::dir_fd(self)
    }
    fn object_count(&self) -> Result<usize, Failure> {
        self.object_count()
    }
    fn create(&self, fingerprint: &str) -> Result<std::fs::File, Failure> {
        ReserveDeviceStore::create(self, fingerprint)
    }
    fn remove(&self, fingerprint: &str) -> Result<(), Failure> {
        ReserveDeviceStore::remove(self, fingerprint)
    }
}

/// `restoreCapacityReserveStoreOpener`.
type StoreOpener =
    Box<dyn Fn(BorrowedFd<'_>, bool) -> Result<Box<dyn ReserveObjectStore>, Failure> + Send>;

/// `openRestoreCapacityReserveStore` — production's opener.
fn open_reserve_store(
    role_root: BorrowedFd<'_>,
    create: bool,
) -> Result<Box<dyn ReserveObjectStore>, Failure> {
    Ok(Box::new(store_path::open_device_store(role_root, create)?))
}

/// `RestoreCapacityReserveAllocator` — the root helper's allocation
/// capability, bound to one instance's four capacity-role directories.
///
/// It holds the single-live-set slot for this process: claimed by
/// `plan`, released by `close` on a plan that never allocated. A plan
/// that allocated keeps it until close — that is what makes "one live
/// reserve set per instance" observable rather than aspirational.
pub struct ReserveAllocator {
    roots: RoleRoots,
    live: AtomicBool,
}

impl ReserveAllocator {
    /// `NewRestoreCapacityReserveAllocator` — bind an allocator to the
    /// four capacity-role host directories. It takes
    /// [`RoleRoots`] — the same domain-owned shape `infralifecycle`
    /// resolves and `Service::role_roots` hands back — rather than
    /// four strings, so no conversion exists anywhere for a role to be
    /// mapped to the wrong directory in.
    pub fn new(roots: RoleRoots) -> Result<Self, Failure> {
        for role in RESERVE_ROLES {
            if role.root(&roots).is_empty() {
                return Err(Failure::denied(
                    CODE_ROLE_ROOT,
                    "broker: restore capacity reserve role roots are incomplete",
                ));
            }
        }
        Ok(Self {
            roots,
            live: AtomicBool::new(false),
        })
    }

    /// `Plan` — measure the four role roots, apply every refusal that
    /// can be decided before anything is written, and return the
    /// member intents the helper must persist through frame `0xc3`
    /// *before* calling [`ReservePlan::allocate`].
    ///
    /// Everything refused is refused with no physical effect at all:
    /// no store directory is created, no object exists.
    pub fn plan(
        &self,
        demand: &RestoreCapacityDemand,
        now: OffsetDateTime,
    ) -> Result<ReservePlan<'_>, Failure> {
        if self.live.swap(true, Ordering::SeqCst) {
            return Err(live_set());
        }
        let plan = ReservePlan {
            allocator: self,
            roots: Mutex::new(HashMap::with_capacity(RESERVE_ROLES.len())),
            devices: Mutex::new(Vec::new()),
            measurements: Mutex::new(Vec::new()),
            observed_at: now,
            open_store: Box::new(open_reserve_store),
            state: Mutex::new(PlanState {
                closed: false,
                allocated: false,
            }),
        };
        if let Err(e) = plan.measure(demand) {
            plan.close();
            return Err(e);
        }
        Ok(plan)
    }
}

/// `RestoreCapacityReservePlan` — a measured, refused-or-admitted
/// reserve proposal that has not yet allocated anything. It holds one
/// open descriptor per role root: every later resolution and
/// re-measurement runs against those held descriptors rather than
/// re-walking the path strings.
pub struct ReservePlan<'a> {
    allocator: &'a ReserveAllocator,
    roots: Mutex<HashMap<ReserveRole, OwnedFd>>,
    devices: Mutex<Vec<ReserveDevice>>,
    measurements: Mutex<Vec<Measurement>>,
    observed_at: OffsetDateTime,
    open_store: StoreOpener,
    state: Mutex<PlanState>,
}

struct PlanState {
    closed: bool,
    allocated: bool,
}

/// A poisoned plan lock is `plan_state()`: a previous panic while the
/// mutex was held is exactly the "the plan's lifecycle cannot be
/// trusted" case, and it fails closed like every other one.
fn plan_lock<'a, T>(
    mutex: &'a std::sync::Mutex<T>,
) -> Result<std::sync::MutexGuard<'a, T>, Failure> {
    mutex.lock().map_err(|_| plan_state())
}

impl<'a> ReservePlan<'a> {
    fn measure(&self, demand: &RestoreCapacityDemand) -> Result<(), Failure> {
        let mut measurements = Vec::with_capacity(RESERVE_ROLES.len());
        let mut roots = plan_lock(&self.roots)?;
        for role in RESERVE_ROLES {
            let path = role.root(&self.allocator.roots);
            if path.is_empty() {
                return Err(role_root());
            }
            // `O_NOFOLLOW` refuses a role root that is itself a
            // symlink; the descriptor is then held for the whole life
            // of the plan, so every subsequent fstat/fstatfs/openat2 is
            // anchored to this exact directory.
            let root = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| role_root())?;
            let measurement = measure_root(&root, role)?;
            roots.insert(role, root);
            measurements.push(measurement);
        }
        drop(roots);
        let devices = collapse(&measurements, demand)?;
        // The cap applied to what this call alone would create. The
        // whole check is applied again in `allocate` against the
        // census: the objects already on each device are only
        // countable once the store directory is resolved, and
        // resolving it on the create path is a physical effect a plan
        // must not have.
        let total = total_bytes(devices.len()).ok_or_else(cap)?;
        host_caps(devices.len(), total)?;
        // The precheck runs here as well as immediately before each
        // allocation: a plan that could never clear the floor must be
        // refused before the helper writes intent records for it.
        for device in &devices {
            pre_allocation_floor(device.free_bytes, device.planned_bytes)?;
        }
        *plan_lock(&self.measurements)? = measurements;
        *plan_lock(&self.devices)? = devices;
        Ok(())
    }

    /// `MemberIntents` — the four per-role intent records carrying the
    /// pre-allocation observation; what frame `0xc3` persists before
    /// `allocate` runs.
    pub fn member_intents(&self) -> Vec<ReserveMemberIntent> {
        self.observations()
            .iter()
            .map(ReserveAllocation::member_intent)
            .collect()
    }

    fn observations(&self) -> Vec<ReserveAllocation> {
        // `unwrap_or_else(into_inner)`: a poisoned lock still yields
        // its contents, and an empty observation set is the
        // conservative answer anyway.
        let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        let by_dev: HashMap<u64, &ReserveDevice> = devices.iter().map(|d| (d.st_dev, d)).collect();
        self.measurements
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|m| {
                by_dev.get(&m.st_dev).map(|device| ReserveAllocation {
                    role: m.role,
                    device_fingerprint: device.fingerprint.clone(),
                    st_dev: device.st_dev,
                    reserved_bytes: RESERVE_OBJECT_BYTES,
                    observed_free_bytes: m.free_bytes,
                    observed_at: self.observed_at,
                })
            })
            .collect()
    }

    /// `Allocate` — physically reserve one object per device,
    /// re-measure, and report the post-allocation observation per
    /// role.
    ///
    /// The failure discipline is the design's: any refusal after the
    /// first object exists releases every object this call created
    /// before returning. A partial reserve is worse than none — it
    /// holds capacity nothing will ever release until the sweep,
    /// while the caller has been told the allocation failed.
    pub fn allocate(&self) -> Result<Vec<ReserveAllocation>, Failure> {
        let mut state = plan_lock(&self.state)?;
        if state.closed || state.allocated || plan_lock(&self.devices)?.is_empty() {
            return Err(plan_state());
        }

        struct Held {
            store: Box<dyn ReserveObjectStore>,
            fingerprint: String,
        }
        let mut created: Vec<Held> = Vec::new();
        let release = |created: Vec<Held>| {
            for entry in created {
                let _ = entry.store.remove(&entry.fingerprint);
            }
        };

        let mut free_after: HashMap<u64, u64> = HashMap::new();
        // `existing_objects` accumulates the reserve objects this call
        // did not create, device by device, so the host caps apply to
        // what the host will actually be holding rather than to this
        // call's own bookkeeping.
        let mut existing_objects = 0usize;
        let roots = plan_lock(&self.roots)?;
        let devices = plan_lock(&self.devices)?;
        for device in devices.iter() {
            let root = roots.get(&device.anchor_role).ok_or_else(role_root)?;
            // Re-measure immediately before allocating rather than
            // trusting the plan-time reading: the precheck runs
            // against what the device looks like now.
            let current = measure_root(root, device.anchor_role).inspect_err(|_| {
                release(std::mem::take(&mut created));
            })?;
            if current.st_dev != device.st_dev || current.fingerprint != device.fingerprint {
                release(std::mem::take(&mut created));
                return Err(ambiguous());
            }
            if let Err(e) = pre_allocation_floor(current.free_bytes, device.planned_bytes) {
                release(std::mem::take(&mut created));
                return Err(e);
            }

            let store = match (self.open_store)(root.as_fd(), true) {
                Ok(store) => store,
                Err(e) => {
                    release(std::mem::take(&mut created));
                    return Err(e);
                }
            };
            if store.st_dev() != device.st_dev {
                release(std::mem::take(&mut created));
                return Err(ambiguous());
            }
            // The caps, against the census rather than this call's own
            // count — before the object is created, so a host already
            // at its ceiling is refused without adding to what it
            // holds.
            let existing = match store.object_count() {
                Ok(n) => n,
                Err(e) => {
                    release(std::mem::take(&mut created));
                    return Err(e);
                }
            };
            existing_objects += existing;
            let objects = created.len() + existing_objects + 1;
            let Some(host_bytes) = total_bytes(objects) else {
                let e = cap_error(objects, 0, &[store.as_ref()]);
                release(std::mem::take(&mut created));
                return Err(e);
            };
            if host_caps(objects, host_bytes).is_err() {
                let e = cap_error(objects, host_bytes, &[store.as_ref()]);
                release(std::mem::take(&mut created));
                return Err(e);
            }
            let object = match store.create(&device.fingerprint) {
                Ok(object) => object,
                Err(e) => {
                    release(std::mem::take(&mut created));
                    return Err(e);
                }
            };
            created.push(Held {
                store,
                fingerprint: device.fingerprint.clone(),
            });
            if let Err(e) = allocate_extent(&object, RESERVE_OBJECT_BYTES) {
                release(std::mem::take(&mut created));
                return Err(e);
            }
            // A reserve that does not survive a crash is not a
            // reserve. fsync the object, then the store directory
            // that now names it.
            if let Err(e) = rustix::fs::fsync(&object) {
                release(std::mem::take(&mut created));
                return Err(Failure::internal(
                    "broker_restore_reserve_os",
                    format!("broker: fsync reserve object: {e}"),
                ));
            }
            drop(object);
            let dir_fd = created.last().ok_or_else(plan_state)?.store.dir_fd();
            if let Err(e) = rustix::fs::fsync(dir_fd) {
                release(std::mem::take(&mut created));
                return Err(Failure::internal(
                    "broker_restore_reserve_os",
                    format!("broker: fsync reserve store dir: {e}"),
                ));
            }

            // Re-measure after the allocation and release-and-fail on
            // a floor breach — a precheck alone cannot see a
            // concurrent writer that consumed the headroom between
            // the reading and the fallocate.
            let after = match measure_root(root, device.anchor_role) {
                Ok(after) => after,
                Err(e) => {
                    release(std::mem::take(&mut created));
                    return Err(e);
                }
            };
            if after.st_dev != device.st_dev {
                release(std::mem::take(&mut created));
                return Err(ambiguous());
            }
            if let Err(e) = post_allocation_floor(after.free_bytes, device.planned_bytes) {
                release(std::mem::take(&mut created));
                return Err(e);
            }
            free_after.insert(device.st_dev, after.free_bytes);
        }

        let held_refs: Vec<&dyn ReserveObjectStore> =
            created.iter().map(|h| h.store.as_ref()).collect();
        let total = total_bytes(created.len() + existing_objects);
        let Some(total) = total else {
            let e = cap_error(created.len() + existing_objects, 0, &held_refs);
            release(std::mem::take(&mut created));
            return Err(e);
        };
        if host_caps(created.len() + existing_objects, total).is_err() {
            let e = cap_error(created.len() + existing_objects, total, &held_refs);
            release(std::mem::take(&mut created));
            return Err(e);
        }
        // `devices`/`roots` guards must end before `observations()`
        // re-locks them; `created` drops its store descriptors here
        // exactly as upstream's `store.Close()` loop does.
        drop(created);
        drop(roots);
        drop(devices);

        state.allocated = true;
        let mut observations = self.observations();
        for observation in &mut observations {
            if let Some(free) = free_after.get(&observation.st_dev) {
                observation.observed_free_bytes = *free;
            }
            observation.observed_at = OffsetDateTime::now_utc();
        }
        Ok(observations)
    }

    /// `Close` — drop every descriptor this plan holds and, if it
    /// never allocated, release the single-live-set slot. Idempotent.
    ///
    /// A plan that *did* allocate keeps the slot: the reserve is live,
    /// and releasing it is the sweep's job — a second unaudited
    /// release path does not exist here.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return;
        }
        state.closed = true;
        self.roots.lock().unwrap_or_else(|e| e.into_inner()).clear();
        if !state.allocated {
            self.allocator.live.store(false, Ordering::SeqCst);
        }
    }
}

impl<'a> Drop for ReservePlan<'a> {
    fn drop(&mut self) {
        self.close();
    }
}

/// `restoreCapacityReserveMeasure` — read one role root from a held
/// descriptor: `fstat` for `st_dev` (the authoritative identity),
/// `fstatfs` for the filesystem type, `f_fsid`, and free space.
pub(crate) fn measure_root<Fd: AsFd>(root: Fd, role: ReserveRole) -> Result<Measurement, Failure> {
    let stat = rustix::fs::fstat(&root).map_err(|_| role_root())?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() || stat.st_dev == 0 {
        return Err(role_root());
    }
    let filesystem = rustix::fs::fstatfs(&root).map_err(|_| role_root())?;
    if filesystem.f_bsize <= 0 {
        return Err(role_root());
    }
    // The allowlist is checked before anything else this measurement
    // feeds, and before any allocation anywhere: an unsupported
    // filesystem is not a capacity question, it is a "do not touch
    // this device" answer.
    if !supported_filesystem(filesystem.f_type as i64) {
        return Err(fs_refused());
    }
    let fsid = audited::statfs_fsid(&root).map_err(|_| role_root())?;
    let fingerprint = store_path::device_fingerprint(fsid).map_err(|_| role_root())?;
    let block_size = u64::try_from(filesystem.f_bsize).map_err(|_| role_root())?;
    let free_bytes = filesystem
        .f_bavail
        .checked_mul(block_size)
        .ok_or_else(role_root)?;
    Ok(Measurement {
        role,
        st_dev: stat.st_dev,
        fingerprint,
        free_bytes,
    })
}

/// `restoreCapacityReserveAllocateExtent` — the physical reservation:
/// `fallocate(2)` with mode 0, which allocates real blocks rather than
/// extending a sparse file. On ext4 and XFS — the only two filesystems
/// this path admits — that is metadata-only.
///
/// `fallocate(2)` is syscall 285 on x86-64 and is NOT on the broker
/// daemon's seccomp allow-list, which is correct: this function runs
/// in the root *helper*, which is not the hardened process. If a later
/// task ever moves allocation into the daemon, the filter test is what
/// will say so.
fn allocate_extent(object: &std::fs::File, size: u64) -> Result<(), Failure> {
    if size == 0 || size > i64::MAX as u64 {
        return Err(extent());
    }
    rustix::fs::fallocate(object, rustix::fs::FallocateFlags::empty(), 0, size).map_err(|e| {
        if e == rustix::io::Errno::NOSPC {
            floor()
        } else {
            Failure::internal(
                "broker_restore_reserve_os",
                format!("broker: fallocate reserve object: {e}"),
            )
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use central_backup::backup::capacity::{FREE_FLOOR_BYTES, restore_admission_margin};

    /// `testFingerprint` — resolver-minted, never hand-written.
    /// `seed` lands in `f_fsid.val[0]`; a distinct multiplier feeds
    /// `val[1]` so two seeds never collide.
    fn test_fingerprint(seed: i32) -> String {
        let fsid = ((seed as u32 as u64) << 32) | (seed.wrapping_mul(7) as u32 as u64);
        store_path::device_fingerprint(fsid).unwrap()
    }

    fn measurement(role: ReserveRole, st_dev: u64, seed: i32, free: u64) -> Measurement {
        Measurement {
            role,
            st_dev,
            fingerprint: test_fingerprint(seed),
            free_bytes: free,
        }
    }

    /// `TestRestoreCapacityReserveFilesystemAllowlist` — the closed
    /// allowlist admits exactly ext4 and XFS.
    #[test]
    fn filesystem_allowlist() {
        assert!(supported_filesystem(0xEF53), "ext4");
        assert!(supported_filesystem(0x584D_5342), "xfs");
        for (name, magic) in [
            ("tmpfs", 0x0102_1994i64),
            ("overlay", 0x794C_7630),
            ("btrfs", 0x9123_683E),
            ("nfs", 0x6969),
        ] {
            assert!(!supported_filesystem(magic), "{name} must refuse");
        }
    }

    /// `TestRestoreCapacityReserveMeasureRefusesUnsupportedFilesystem`
    /// — tmpfs is a filesystem this allocator must refuse.
    #[test]
    fn measure_refuses_unsupported_filesystem() {
        let dir = TempDir::new("measure-refuse");
        let fd = std::fs::File::open(&*dir).unwrap();
        let filesystem = rustix::fs::fstatfs(&fd).unwrap();
        if supported_filesystem(filesystem.f_type as i64) {
            eprintln!("SKIP: test temp dir is not on a refused filesystem");
            return;
        }
        assert_eq!(
            measure_root(&fd, ReserveRole::PostgresData)
                .unwrap_err()
                .code(),
            CODE_FS
        );
    }

    /// `TestRestoreCapacityReserveMeasureAcceptsSupportedFilesystem` —
    /// a real directory on ext4/XFS measures cleanly, or the test
    /// skips on a host without one.
    #[test]
    fn measure_accepts_supported_filesystem() {
        let Some(dir) = supported_temp_dir() else {
            eprintln!("SKIP: no ext4/xfs candidate directory available");
            return;
        };
        let fd = std::fs::File::open(&*dir).unwrap();
        let m = measure_root(&fd, ReserveRole::PostgresData).unwrap();
        assert_eq!(m.role, ReserveRole::PostgresData);
        assert_ne!(m.st_dev, 0);
        assert!(store_path::valid_fingerprint(&m.fingerprint));
        assert!(m.free_bytes > 0);
    }

    /// `supportedTempDir`'s scratch directory on a supported
    /// filesystem — removed on drop like `TempDir`, but rooted
    /// beneath the first ext4/XFS candidate this host offers.
    pub(crate) struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        pub(crate) fn supported(tag: &str) -> Option<Self> {
            for candidate in [
                std::env::var("CENTRAL_RESERVE_TEST_DIR").unwrap_or_default(),
                "/var/tmp".to_owned(),
                std::env::temp_dir().to_string_lossy().to_string(),
                std::env::var("HOME").unwrap_or_default(),
            ] {
                if candidate.is_empty() {
                    continue;
                }
                let Ok(fd) = std::fs::File::open(&candidate) else {
                    continue;
                };
                let Ok(filesystem) = rustix::fs::fstatfs(&fd) else {
                    continue;
                };
                if !supported_filesystem(filesystem.f_type) {
                    continue;
                }
                let dir = std::path::PathBuf::from(&candidate).join(format!(
                    "central-reserve-{tag}-{}-{}",
                    std::process::id(),
                    uuid::Uuid::new_v4()
                ));
                std::fs::create_dir_all(&dir).unwrap();
                return Some(Self(dir));
            }
            None
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for ScratchDir {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    /// `supportedTempDir` — `None` when no ext4/XFS candidate exists;
    /// callers then skip rather than asserting on a filesystem the
    /// design refuses anyway.
    pub(crate) fn supported_temp_dir() -> Option<ScratchDir> {
        ScratchDir::supported("measure")
    }

    /// `roleRootsIn` — four role-root directories beneath one scratch
    /// root, all on the same device, as upstream's fixture places them.
    pub(crate) fn role_roots_in(base: &std::path::Path) -> RoleRoots {
        let roots = RoleRoots {
            postgres_data: base.join("postgres-data").to_string_lossy().to_string(),
            postgres_wal: base.join("postgres-wal").to_string_lossy().to_string(),
            postgres_temp: base.join("postgres-temp").to_string_lossy().to_string(),
            object_data: base.join("object-data").to_string_lossy().to_string(),
        };
        for role in RESERVE_ROLES {
            std::fs::create_dir_all(role.root(&roots)).unwrap();
        }
        roots
    }

    /// `TestRestoreCapacityReserveDeviceFingerprintRefusesZeroFsid` —
    /// a zero fsid is not a device.
    #[test]
    fn device_fingerprint_refuses_zero_fsid() {
        assert!(store_path::device_fingerprint(0).is_err());
    }

    /// `TestRestoreCapacityReserveCollapseRefusesFingerprintCollapse` —
    /// one store name, two devices.
    #[test]
    fn collapse_refuses_fingerprint_collapse() {
        let shared = test_fingerprint(7);
        let m = |role: ReserveRole, st_dev: u64, fingerprint: String| Measurement {
            role,
            st_dev,
            fingerprint,
            free_bytes: 1 << 40,
        };
        let measurements = vec![
            m(ReserveRole::PostgresData, 10, shared.clone()),
            m(ReserveRole::PostgresWal, 11, shared),
            m(ReserveRole::PostgresTemp, 12, test_fingerprint(3)),
            m(ReserveRole::ObjectData, 13, test_fingerprint(4)),
        ];
        assert_eq!(
            collapse(&measurements, &RestoreCapacityDemand::default())
                .unwrap_err()
                .code(),
            CODE_AMBIGUOUS
        );
    }

    /// `TestRestoreCapacityReserveCollapseRefusesSplitFingerprintOnOneDevice`
    /// — one device, two store names.
    #[test]
    fn collapse_refuses_split_fingerprint_on_one_device() {
        let measurements = vec![
            measurement(ReserveRole::PostgresData, 10, 1, 1 << 40),
            measurement(ReserveRole::PostgresWal, 10, 2, 1 << 40),
            measurement(ReserveRole::PostgresTemp, 12, 3, 1 << 40),
            measurement(ReserveRole::ObjectData, 13, 4, 1 << 40),
        ];
        assert_eq!(
            collapse(&measurements, &RestoreCapacityDemand::default())
                .unwrap_err()
                .code(),
            CODE_AMBIGUOUS
        );
    }

    /// `TestRestoreCapacityReserveCollapseSharesOneObjectPerDevice` —
    /// four roles on one device produce exactly one reserve object,
    /// anchored at the first role in the fixed order, with the four
    /// roles' demands summed onto it.
    #[test]
    fn collapse_shares_one_object_per_device() {
        let fingerprint = test_fingerprint(9);
        let measurements: Vec<Measurement> = RESERVE_ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| Measurement {
                role: *role,
                st_dev: 42,
                fingerprint: fingerprint.clone(),
                free_bytes: (1 << 40) + index as u64,
            })
            .collect();
        let demand = RestoreCapacityDemand {
            postgres_data_bytes: 1,
            postgres_wal_bytes: 2,
            postgres_temp_bytes: 4,
            object_data_bytes: 8,
        };
        let devices = collapse(&measurements, &demand).unwrap();
        assert_eq!(devices.len(), 1, "one object per device");
        assert_eq!(devices[0].anchor_role, ReserveRole::PostgresData);
        assert_eq!(devices[0].planned_bytes, 15);
        assert_eq!(devices[0].free_bytes, 1 << 40, "smallest reading wins");
    }

    /// `TestRestoreCapacityReserveCollapseKeepsDistinctDevicesApart`.
    #[test]
    fn collapse_keeps_distinct_devices_apart() {
        let measurements: Vec<Measurement> = RESERVE_ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| measurement(*role, 100 + index as u64, index as i32 + 1, 1 << 40))
            .collect();
        let devices = collapse(&measurements, &RestoreCapacityDemand::default()).unwrap();
        assert_eq!(devices.len(), RESERVE_ROLES.len());
    }

    /// `TestRestoreCapacityReservePreAllocationFloor` — the boundary
    /// is admitted exactly and refused one byte short.
    #[test]
    fn pre_allocation_floor_boundary() {
        let planned = 8u64 << 30;
        let margin = restore_admission_margin(planned).unwrap();
        let required = SURVIVAL_RESERVE_BYTES + FREE_FLOOR_BYTES + margin;
        assert!(pre_allocation_floor(required, planned).is_ok());
        assert_eq!(
            pre_allocation_floor(required - 1, planned)
                .unwrap_err()
                .code(),
            CODE_FLOOR
        );
    }

    /// `TestRestoreCapacityReservePostAllocationFloor` — the
    /// post-condition drops the survival term the object now occupies.
    #[test]
    fn post_allocation_floor_boundary() {
        let planned = 8u64 << 30;
        let margin = restore_admission_margin(planned).unwrap();
        let required = FREE_FLOOR_BYTES + margin;
        assert!(post_allocation_floor(required, planned).is_ok());
        assert_eq!(
            post_allocation_floor(required - 1, planned)
                .unwrap_err()
                .code(),
            CODE_FLOOR
        );
    }

    /// `TestRestoreCapacityReserveFloorRefusesOverflowingDemand` —
    /// overflow is a floor refusal, never a wrap or panic.
    #[test]
    fn floor_refuses_overflowing_demand() {
        assert_eq!(
            pre_allocation_floor(u64::MAX, u64::MAX).unwrap_err().code(),
            CODE_FLOOR
        );
    }

    /// `TestRestoreCapacityReserveHostCaps` — the two ceilings, the
    /// boundary, and the zero-object refusal.
    #[test]
    fn host_caps_boundaries() {
        assert_eq!(MAX_HOST_BYTES, 16 << 30, "16 GiB");
        assert_eq!(RESERVE_OBJECT_BYTES, SURVIVAL_RESERVE_BYTES);
        assert!(host_caps(MAX_OBJECTS_PER_HOST, MAX_HOST_BYTES).is_ok());
        assert_eq!(
            host_caps(MAX_OBJECTS_PER_HOST + 1, MAX_HOST_BYTES)
                .unwrap_err()
                .code(),
            CODE_CAP
        );
        assert_eq!(
            host_caps(MAX_OBJECTS_PER_HOST, MAX_HOST_BYTES + 1)
                .unwrap_err()
                .code(),
            CODE_CAP
        );
        assert_eq!(host_caps(0, 0).unwrap_err().code(), CODE_CAP);
    }

    /// `TestRestoreCapacityReserveObjectNameRefusesForeignFingerprints`
    /// — `object_name` mints only resolver-shaped names and
    /// `is_object_name` recognizes exactly those.
    #[test]
    fn object_name_refuses_foreign_fingerprints() {
        let fingerprint = test_fingerprint(1);
        let name = store_path::object_name(&fingerprint).unwrap();
        assert!(store_path::is_object_name(&name));
        for bad in [
            "",
            "fs-zzzz",
            "not-a-fingerprint",
            &format!("{fingerprint}.bak"),
            "fs-0123456789abcdef0123456789abcdef", // 32 hex but no suffix
        ] {
            assert!(store_path::object_name(bad).is_err() || !store_path::is_object_name(bad));
        }
        // A foreign fingerprint never names an object.
        assert!(store_path::object_name("../fs-0123456789abcdef0123456789abcdef").is_err());
    }

    /// `TestRestoreCapacityReserveAllocatorRefusesSecondLiveSet` — the
    /// single-live-set cap's in-process half: while one plan is live a
    /// second is refused before any measurement runs.
    #[test]
    fn allocator_refuses_second_live_set() {
        let scratch = TempDir::new("live-set");
        let roots = role_roots_in(&scratch);
        let allocator = ReserveAllocator::new(roots).unwrap();
        // Hold the live slot without a measured plan: the flag is the
        // cap, the plan is what sits beneath it.
        allocator.live.store(true, Ordering::SeqCst);
        let e = allocator
            .plan(&RestoreCapacityDemand::default(), OffsetDateTime::now_utc())
            .err()
            .expect("a second live plan must refuse");
        assert_eq!(e.code(), CODE_LIVE_SET);
        allocator.live.store(false, Ordering::SeqCst);
    }

    /// `TestRestoreCapacityReservePlanReportsOneMemberIntentPerRole` —
    /// a measured plan reports exactly four member intents, one per
    /// role, carrying the device's own identity.
    #[test]
    fn plan_reports_one_member_intent_per_role() {
        let Some(scratch) = ScratchDir::supported("plan-intents") else {
            eprintln!("SKIP: no ext4/xfs candidate directory available");
            return;
        };
        let roots = role_roots_in(&scratch);
        let allocator = ReserveAllocator::new(roots).unwrap();
        let now = OffsetDateTime::now_utc();
        let demand = RestoreCapacityDemand {
            postgres_data_bytes: 1 << 20,
            postgres_wal_bytes: 2 << 20,
            postgres_temp_bytes: 4 << 20,
            object_data_bytes: 8 << 20,
        };
        let plan = allocator.plan(&demand, now).unwrap();
        let intents = plan.member_intents();
        assert_eq!(intents.len(), RESERVE_ROLES.len());
        for role in RESERVE_ROLES {
            let intent = intents.iter().find(|i| i.role == role).unwrap();
            assert_ne!(intent.st_dev, 0);
            assert!(store_path::valid_fingerprint(&intent.device_fingerprint));
            assert_eq!(intent.reserved_bytes, RESERVE_OBJECT_BYTES);
            assert!(intent.observed_free_bytes > 0);
        }
        plan.close();
        // A closed, never-allocated plan releases the live slot:
        // the next plan is refused by measurement or succeeds on its
        // own merits, never by the stale flag.
        drop(plan);
        let plan2 = allocator.plan(&demand, now).unwrap();
        plan2.close();
    }

    /// `TestRestoreCapacityReservePlanRefusesFloorBreachBeforeAllocating`
    /// — a demand no real device can clear is refused before anything
    /// is created.
    #[test]
    fn plan_refuses_floor_breach_before_allocating() {
        let Some(scratch) = ScratchDir::supported("floor-breach") else {
            eprintln!("SKIP: no ext4/xfs candidate directory available");
            return;
        };
        let roots = role_roots_in(&scratch);
        let allocator = ReserveAllocator::new(roots.clone()).unwrap();
        let demand = RestoreCapacityDemand {
            postgres_data_bytes: 1 << 62,
            ..Default::default()
        };
        let e = allocator
            .plan(&demand, OffsetDateTime::now_utc())
            .err()
            .expect("a floor-breaching demand must refuse");
        assert_eq!(e.code(), CODE_FLOOR);
        for role in RESERVE_ROLES {
            assert_eq!(
                std::fs::read_dir(role.root(&roots)).unwrap().count(),
                0,
                "refused plan left entries under a role root"
            );
        }
    }

    /// `TestRestoreCapacityReserveObjectStatAssertions` — the
    /// `st_blocks × 512` contract `gate_allocated_bytes` pins and the
    /// negative-block refusal.
    #[test]
    fn gate_allocated_bytes_contract() {
        use super::super::sweep::gate_allocated_bytes;
        assert_eq!(gate_allocated_bytes(0), Some(0));
        assert_eq!(gate_allocated_bytes(2), Some(1024));
        assert_eq!(gate_allocated_bytes(-1), None);
        assert_eq!(gate_allocated_bytes(i64::MAX), None);
    }
}
