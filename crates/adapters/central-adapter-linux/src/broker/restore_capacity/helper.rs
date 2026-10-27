//! `restore_capacity_reserve_helper_linux.go` — the root helper's
//! narrow view of the restore capacity reserve's protected state.
//!
//! # Why this exists rather than `Service::new_with_role_roots`
//!
//! The sweep (`ReserveSweeper`) and the inspection publisher
//! (`ReserveStore::publish_inspection_digest`) both run inside
//! `central --helper`, never inside the hardened daemon: the sweep's
//! placement is held by the no-enumeration-from-daemon-dispatch test,
//! and the publisher is the helper-side half of the bridge the
//! daemon's frame `0xc5` reads back with a single openat.
//!
//! Until this constructor existed, the only way to build either was
//! `Service::new` — whose one production caller is the broker daemon
//! composition, at `CentralRuntimeUID`, after `harden()`. Wiring the
//! helper's call sites through it would have made a root helper
//! process construct, and take ownership of, the daemon's whole
//! authority surface as a side effect of wanting four record
//! directories. That answers the ownership question — which process
//! owns the daemon's protected material — in the wrong direction.
//!
//! So this constructor provides exactly what the two capabilities
//! read, and nothing else:
//!
//! - the persistent signing service, because every record the sweep
//!   reads is HMAC-signed with it and every record it writes must be
//!   signed the same way. It *adopts* the key the daemon already
//!   created; it creates one only on a root that has none, which is
//!   the same behaviour `Service::new` has and is not a new authority;
//! - the protected file backend and the recovery journal, which the
//!   launch store and the sweep's operation-state reader are built
//!   over;
//! - the restore launch store, for the launch-liveness guard that
//!   stands between the sweep and freeing a cushion out from under a
//!   live `pg_restore`;
//! - the reserve record store and the receipt ledger, the two capacity
//!   stores;
//! - `RoleRoots`, which is how the sweep reaches each device's store.
//!
//! It provides no TLS authority, no signer, no nonce store, no secret
//! bootstrap, no proof service, no provisioning store, no bootstrap
//! session, no MinIO runtime binding, no payload epoch store, no
//! throughput journal, and no migration/backup/throughput launch
//! store. `Service` stays genuinely daemon-only.
//!
//! It is emphatically not a `Service` and cannot serve a frame: it has
//! no handoff service, no listener, and no peer predicate. Every
//! method below is an in-process protected-state operation performed
//! by the root helper on its own behalf.

use std::path::Path;
use std::sync::Arc;

use central_foundation::failure::Failure;
use time::OffsetDateTime;
use uuid::Uuid;

use central_backup::backup::capacity::RoleRoots;

use crate::broker::protected_file::ProtectedFileBackend;
use crate::broker::recovery_journal::RecoveryJournalStore;
use crate::broker::restore_launch::RestoreLaunchStore;
use crate::broker::signing::SigningService;

use super::RESERVE_ROLES;
use super::receipt::ReceiptStore;
use super::store::ReserveStore;
use super::sweep::{ReleaseTrigger, ReserveSweeper, SweepCaller, SweepReport};

const HELPER_UNAVAILABLE_CODE: &str = "broker_restore_reserve_helper_unavailable";
fn helper_unavailable() -> Failure {
    Failure::internal(
        HELPER_UNAVAILABLE_CODE,
        "broker: restore capacity reserve helper authority unavailable",
    )
}

/// `RestoreCapacityReserveHelperAuthority` — the narrow helper view
/// over one protected root and the four capacity-role host
/// directories, for one of the two named `central --helper` call
/// sites.
pub struct ReserveHelperAuthority {
    #[allow(dead_code)] // carried for parity with upstream's field
    caller: SweepCaller,
    sweeper: ReserveSweeper,
    reserves: Arc<ReserveStore>,
}

impl ReserveHelperAuthority {
    /// `NewRestoreCapacityReserveHelperAuthority` — build the view for
    /// one named caller. An unnamed caller cannot be expressed: the
    /// type only admits the two named call sites, which is the
    /// structural form of the requirement that the sweep's call sites
    /// be named explicitly rather than left as "any root-owned
    /// invocation".
    pub fn new(
        root_path: &Path,
        role_roots: RoleRoots,
        caller: SweepCaller,
    ) -> Result<Self, Failure> {
        if root_path.as_os_str().is_empty() {
            return Err(helper_unavailable());
        }
        for role in RESERVE_ROLES {
            if role.root(&role_roots).is_empty() {
                return Err(helper_unavailable());
            }
        }
        let signing = Arc::new(SigningService::new_persistent(root_path)?);
        let backend = ProtectedFileBackend::new(root_path.to_path_buf());
        let journal = Arc::new(RecoveryJournalStore::new(
            root_path,
            signing.clone(),
            backend,
        )?);
        let launches = Arc::new(RestoreLaunchStore::new(
            root_path,
            signing.clone(),
            journal.clone(),
        )?);
        let reserves = Arc::new(ReserveStore::new(root_path, signing.clone())?);
        let receipts = Arc::new(ReceiptStore::new(root_path, signing.clone())?);
        let sweeper = ReserveSweeper::new(
            caller,
            reserves.clone(),
            receipts,
            launches,
            journal,
            role_roots,
        )?;
        Ok(Self {
            caller,
            sweeper,
            reserves,
        })
    }

    /// `Sweep` — one whole reconciliation pass. See
    /// `ReserveSweeper::sweep`. The partial report travels with the
    /// error, exactly as upstream's `(report, err)` pair.
    pub fn sweep(&self, now: OffsetDateTime) -> Result<SweepReport, (SweepReport, Failure)> {
        self.sweeper.sweep(now)
    }

    /// `Release` — fire one caller-known release trigger against one
    /// named set. Every trigger's guard is re-checked against the
    /// durable record, so naming a trigger is a request, not an
    /// instruction.
    pub fn release(
        &self,
        set_id: Uuid,
        trigger: ReleaseTrigger,
        now: OffsetDateTime,
    ) -> Result<SweepReport, (SweepReport, Failure)> {
        self.sweeper.release(set_id, trigger, now)
    }

    /// `PublishInspectionDigest` — write the bucketed, locator-free
    /// digest the hardened daemon serves on frame `0xc5`. It belongs
    /// beside the sweep, in this process, because the sweep's own
    /// findings are half of what the digest carries and the daemon
    /// cannot enumerate the reserve store for itself.
    pub fn publish_inspection_digest(
        &self,
        report: &SweepReport,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        self.reserves.publish_inspection_digest(report, now)
    }

    /// `SweepAndPublish` — the pairing both wired call sites perform:
    /// one reconciliation pass, then the digest that makes its
    /// findings visible to the daemon's read-only inspection frame.
    /// The publish runs even when the sweep reported unreadable
    /// records — a pass that found corruption is exactly the pass an
    /// operator most needs published — but not when the sweep could
    /// not run at all, because there would be no findings to describe.
    pub fn sweep_and_publish(
        &self,
        now: OffsetDateTime,
    ) -> Result<SweepReport, (SweepReport, Failure)> {
        let report = self.sweep(now)?;
        if let Err(publish_err) = self.publish_inspection_digest(&report, now) {
            return Err((report, publish_err));
        }
        Ok(report)
    }
}
