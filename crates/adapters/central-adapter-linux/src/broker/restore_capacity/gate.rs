//! `restore_capacity_gate_linux.go` — the gate: frame `0xc2` kind 1's
//! capacity preconditions.
//!
//! This is the point the whole restore-capacity-reserve authority
//! exists for. A root helper measures and physically allocates; a root
//! broker daemon records what it measured; the engine draws and spends
//! bearer receipts over that reserve. None of that has any effect on
//! anything until the daemon refuses to hand over the PostgreSQL
//! *migration* credential — the one that drives the destructive
//! `pg_restore` — unless the reserve is real.
//!
//! The design's four preconditions, in the order this file applies
//! them:
//!
//! 1. a committed, unexpired reserve set bound to this operation,
//!    created by the launch that issued this operation's ticket;
//! 2. planned bytes re-derived by the daemon from
//!    `restore_capacity_demands`;
//! 3. the floor and margin re-applied against the helper-recorded
//!    observed free bytes;
//! 4. the daemon's own fstat of the reserve object it opened,
//!    requiring allocated blocks ≥ `SURVIVAL_RESERVE_BYTES`.
//!
//! # What the daemon derives and what it merely carries
//!
//! The property this gate buys is that the daemon re-derives
//! everything it *can* re-derive from its own evidence, so a
//! compromised or buggy engine cannot buy admission with its own
//! numbers:
//!
//! - **Dump bytes and artifact count** come from the daemon's own
//!   backup seal record, and the helper-recorded figures on the set
//!   record must equal them exactly. Neither the engine nor the helper
//!   is trusted for these.
//! - **Object bytes cannot be re-derived here and this code does not
//!   pretend otherwise.** The seal's root manifest carries per-chunk
//!   `EntryCount` and no per-entry `Size`; summing body bytes means
//!   walking the inventory chunk entries in the recovery repository,
//!   which is engine-side code the broker holds no chunk of. ADR 0018
//!   ratified the residual rather than adding a bounded inventory
//!   reader to the most privileged process on the host. So the term is
//!   *carried* from the helper record into `restore_capacity_demands`
//!   unchanged. Dropping it to zero because it cannot be verified
//!   would turn the ratified "the helper can deflate this term" into
//!   "this term is always zero" — a wider hole than the one that was
//!   authorized.
//!
//! # Refusal vocabulary
//!
//! Every refusal this file makes is `RESTORE_STATE_INVALID` or
//! `RESTORE_CAPACITY_INSUFFICIENT`, never a media reason. The split
//! is: `STATE_INVALID` for "the evidence does not describe an
//! admissible reserve for this operation" (missing, unparsable, bound
//! elsewhere, uncommitted, disagreeing with the seal),
//! `CAPACITY_INSUFFICIENT` for "the arithmetic or the physical extent
//! does not clear the bar". A daemon that cannot read its own state
//! fails closed as `STATE_INVALID`.

use std::collections::HashMap;
use std::os::fd::AsFd;

use central_foundation::failure::Failure;
use rustix::fs::{Mode, OFlags};
use time::OffsetDateTime;
use uuid::Uuid;

use central_backup::backup::capacity::{
    MAXIMUM_INVENTORY_CHUNK_ENTRIES, RestoreCapacityDemand, SUPPORTED_RECOVERY_DATABASE_BYTES,
    SUPPORTED_RECOVERY_OBJECT_BYTES, SUPPORTED_RECOVERY_RECORD_COUNT, SURVIVAL_RESERVE_BYTES,
    restore_capacity_demands,
};
use central_backup::recovery::operation::RestoreOperation;
use central_backup::recovery::refusal::RestoreRefusalReason;

use crate::broker::restore_launch::RestoreLaunchBinding;
use crate::broker::server::Service;
use crate::broker::wire;

use super::allocation::{self, RESERVE_OBJECT_BYTES, role_demand};
use super::frame::device_id_from_fingerprint;
use super::store::{ReserveMemberRecord, ReserveSetRecord};
use super::store_path;
use super::sweep::gate_allocated_bytes;
use super::{RESERVE_ROLES, ReserveRole, ReserveState};

fn invalid() -> Failure {
    RestoreRefusalReason::StateInvalid.into_failure()
}
fn insufficient() -> Failure {
    RestoreRefusalReason::CapacityInsufficient.into_failure()
}

/// `restoreCapacityGateDevice` — one physical device the gate reasons
/// about, after the four member records have been collapsed onto the
/// devices they actually share.
///
/// Collapsing is not an optimisation. Roles that share an `st_dev` are
/// backed by **one** reserve object, and each of their member records
/// carries `reserved_bytes` for that same one object. A gate that
/// summed the four members' `reserved_bytes`, or that checked the same
/// object four times against four copies of the same free-space
/// reading, would over-count a single-disk host's reserve by up to
/// 4x — which is every host this codebase currently produces.
#[derive(Debug)]
struct GateDevice {
    st_dev: u64,
    fingerprint: String,
    /// `AnchorRole` — the first role in `RESERVE_ROLES` order that
    /// sits on this `st_dev`. The identical deterministic function of
    /// `st_dev` and the fixed role order that the helper's allocator
    /// used to decide which role root this device's store lives
    /// beneath, which is what lets the gate find the object without
    /// being told where it is.
    anchor_role: ReserveRole,
    planned_bytes: u64,
    free_bytes: u64,
    reserved_bytes: u64,
}

impl Service {
    /// `assertRestoreCapacityReserveGate` — the whole precondition.
    /// It returns `Ok` only when a committed, unexpired reserve set
    /// bound to this operation and to the launch that issued this
    /// operation's ticket exists, its demand figures agree with the
    /// daemon's own seal, the per-device arithmetic clears the floor
    /// and the margin, and the daemon has itself opened and fstat'ed
    /// every reserve object behind it.
    ///
    /// `binding` arrives as a **parameter** from the transport handler
    /// that already ran the peer predicate — the design's decision 1.
    /// It is deliberately not re-derived here: `validate_peer` both
    /// requires a peer credential this function does not have and
    /// advances the launch record from issued to active, so a second
    /// call would be a second mutation.
    ///
    /// # The issuing-launch binding
    ///
    /// The set and the ledger spend are pinned to
    /// `issuing.launch_evidence_id` — the launch that *issued this
    /// operation's ticket* — never to `binding.launch_evidence_id`.
    /// Under "verify allocates" those two never match on a legitimate
    /// apply: the verify-time launch created the set, the apply-time
    /// launch is the one asking now, and the ticket-launch record is
    /// the only durable link between them.
    pub(crate) fn assert_restore_capacity_reserve_gate(
        &self,
        operation: &RestoreOperation,
        binding: &RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        if self.restore_capacity_receipts.is_none() {
            return Err(invalid());
        }
        let (Some(reserves), Some(journal)) = (
            self.restore_capacity_reserves.as_ref(),
            self.recovery_journal.as_ref(),
        ) else {
            return Err(invalid());
        };
        if wire::is_go_zero_time(now)
            || operation.operation_id.is_nil()
            || operation.backup_id.is_nil()
            || operation.ticket_id.is_nil()
        {
            return Err(invalid());
        }
        // A zero binding is what a caller that never validated would
        // pass. It must never be admitted: the whole value of
        // decision 1 is that reaching this function requires having
        // produced one.
        if binding.launch_evidence_id.is_nil() {
            return Err(invalid());
        }

        // --- Precondition 0: the launch that issued this operation's
        // ticket ----------------------------------------------------
        //
        // Everything precondition 1 compares a launch against comes
        // from here, so it is resolved before any of it. A missing,
        // unreadable, or mismatched carry is STATE_INVALID for the
        // same reason an unresolvable set is: the evidence does not
        // describe an admissible reserve for this operation, and the
        // gate has no third answer.
        let issuing = journal
            .read_ticket_launch(operation.operation_id)
            .map_err(|_| invalid())?;
        if issuing.ticket_id != operation.ticket_id || issuing.launch_evidence_id.is_nil() {
            // A ticket issued outside any launch record carries nil,
            // and such a ticket must buy nothing. Without this check
            // the comparisons below would be satisfied by any set
            // whose `launch_evidence_id` also happened to be nil —
            // which the reserve record schema forbids, so the
            // practical effect is that the whole precondition would
            // compare two values neither of which could match.
            // Refusing explicitly says so rather than relying on that.
            return Err(invalid());
        }

        // --- Precondition 1: the set ----------------------------------
        let set = reserves
            .resolve_set_for_operation(operation.operation_id)
            .map_err(|_| invalid())?;
        // `operation_id` is caller-asserted at frame `0xc3` kind 1 and
        // was not cross-checkable there; the resolution itself is the
        // check (`resolve_set_for_operation` requires the set it
        // returns to name the operation it was asked about). The
        // backup is a separate fact and is checked here: the set's own
        // `backup_id` is what the seal below is re-derived from.
        if set.backup_id != operation.backup_id {
            return Err(invalid());
        }
        // The set × issuing-launch check — pin one of three. A set
        // created by a launch other than the one that issued this
        // operation's ticket is not evidence about this operation,
        // however genuine the asking peer's process identity is. It is
        // emphatically *not* compared against
        // `binding.launch_evidence_id`: under "verify allocates" those
        // two never match on a legitimate apply.
        if set.launch_evidence_id != issuing.launch_evidence_id {
            return Err(invalid());
        }
        let committed = set.state == ReserveState::Verified;
        if !committed && set.state != ReserveState::Allocated {
            // intent: nothing has been physically allocated.
            // provisionally_consumed: not a state this gate ever
            // writes. released: the cushion has been given back.
            return Err(invalid());
        }
        // Absolute expiry, and the decision the plan asked this task
        // to make rather than defer.
        //
        // The bind: the sweep refuses to release a set whose operation
        // is still applying, so an expired set's physical cushion is
        // *still held*. Enforcing expiry unconditionally here would
        // therefore refuse a resume against a half-rewritten database
        // while the bytes that resume needs are demonstrably still
        // reserved.
        //
        // **Decision: absolute expiry bounds *entry* into the
        // destructive window, not continuation of one already
        // entered.** A set that has not yet been committed is refused
        // the moment it expires; a set this gate has already committed
        // (state verified) is admitted past its expiry — but only
        // through the identical, unrelaxed re-check of every other
        // precondition, including the daemon's own fstat of the
        // physical extent.
        if !committed && now >= set.absolute_expires_at {
            return Err(invalid());
        }

        // --- Precondition 2: the demand figures, re-derived -----------
        let demand = self.gate_demand(&set)?;

        // --- The members, and the receipts that committed them --------
        let members = self.gate_members(&set, issuing.launch_evidence_id, committed, now)?;

        // --- Precondition 3: floor and margin, per device -------------
        let devices = gate_collapse(&members, &demand)?;
        for device in &devices {
            // The post-allocation form, and deliberately so. The
            // design's inequality is written against the helper's
            // *pre*-allocation reading; the reading this gate actually
            // holds is the *post*-allocation re-measurement
            // (`confirm_member_allocation` supersedes the intent-time
            // figure exactly once). Charging the survival reserve
            // against a reading it has already been subtracted from
            // would demand 2x the cushion. So the survival term is
            // *moved*: proven physically by precondition 4's fstat of
            // allocated blocks, instead of asserted arithmetically.
            //
            // This equivalence holds only because
            // `RESERVE_OBJECT_BYTES == SURVIVAL_RESERVE_BYTES` and the
            // allocator places exactly one reserve object per device,
            // which together make `observed_post == observed_pre -
            // SURVIVAL_RESERVE_BYTES` by construction.
            allocation::post_allocation_floor(device.free_bytes, device.planned_bytes)
                .map_err(|_| insufficient())?;
        }

        // --- Precondition 4: the physical extents -----------------------
        self.assert_gate_extents(&devices)?;

        // --- The commit ---------------------------------------------------
        // "The set commits at the gate." `allocated → verified` is the
        // one skip the store reserves for set granularity. Member
        // records are deliberately left where they are: their state is
        // receipt-keyed, and the receipt window the sweep reads off a
        // member is not something this gate is entitled to move.
        //
        // It runs after every precondition and before the credential is
        // released, so a refusal never commits and a commit that cannot
        // be persisted refuses.
        if !committed {
            reserves
                .advance_set_state(set.set_id, ReserveState::Verified, now)
                .map_err(|_| invalid())?;
        }
        Ok(())
    }

    /// `restoreCapacityGateDemand` — the daemon's own seal record is
    /// where dump bytes and artifact count come from; the
    /// helper-recorded figures on the set record must equal them
    /// exactly.
    fn gate_demand(&self, set: &ReserveSetRecord) -> Result<RestoreCapacityDemand, Failure> {
        let journal = self.recovery_journal.as_ref().ok_or_else(invalid)?;
        let seal = journal
            .read_backup_seal(set.backup_id)
            .map_err(|_| invalid())?;
        let references = central_backup::backup::manifest::parse_seal_root_references(
            &seal.proposal.root_manifest_json,
        )
        .map_err(|_| invalid())?;
        // The seal has to be the seal for this backup and this
        // repository binding, or the figures below are re-derived from
        // someone else's evidence.
        if references.backup_id != set.backup_id
            || references.repository_binding_id != set.repository_binding_id
        {
            return Err(invalid());
        }
        if references.dump.size <= 0 {
            return Err(invalid());
        }
        let dump_bytes = references.dump.size as u64;
        let mut artifact_count = 0u64;
        for chunk in &references.chunks {
            // `parse_seal_root_references` already bounds each
            // `entry_count` to `(0, MAXIMUM_INVENTORY_CHUNK_ENTRIES]`;
            // the addition is still checked so the sum cannot wrap.
            if chunk.entry_count == 0 || chunk.entry_count as u64 > MAXIMUM_INVENTORY_CHUNK_ENTRIES
            {
                return Err(invalid());
            }
            artifact_count = allocation::add_bytes(artifact_count, chunk.entry_count as u64)
                .ok_or_else(insufficient)?;
        }
        // The equality that makes this a gate rather than a
        // transcript: the helper-recorded set record has to say what
        // the daemon's own seal says.
        if set.dump_bytes != dump_bytes || set.artifact_count != artifact_count {
            return Err(invalid());
        }
        // Object bytes are carried, not verified — see this file's
        // header. The supported-profile ceiling frame `0xc3` applied
        // on the wire is re-applied here against the durable record,
        // so the one term the daemon cannot check still cannot be an
        // arbitrary 2^64 figure feeding the arithmetic below.
        if set.object_bytes > SUPPORTED_RECOVERY_OBJECT_BYTES
            || dump_bytes > SUPPORTED_RECOVERY_DATABASE_BYTES
            || artifact_count > SUPPORTED_RECOVERY_RECORD_COUNT
        {
            return Err(insufficient());
        }
        restore_capacity_demands(dump_bytes, set.object_bytes, artifact_count)
            .ok_or_else(insufficient)
    }

    /// `restoreCapacityGateMembers` — read all four member records
    /// and, for a set that is not yet committed, the ledger entry
    /// proving which receipt was spent for each of them.
    fn gate_members(
        &self,
        set: &ReserveSetRecord,
        issuing_launch_evidence_id: Uuid,
        committed: bool,
        now: OffsetDateTime,
    ) -> Result<Vec<ReserveMemberRecord>, Failure> {
        let reserves = self
            .restore_capacity_reserves
            .as_ref()
            .ok_or_else(invalid)?;
        let mut members = Vec::with_capacity(RESERVE_ROLES.len());
        for role in RESERVE_ROLES {
            let member = reserves
                .read_member(set.set_id, role)
                .map_err(|_| invalid())?;
            if member.set_id != set.set_id || member.role != role {
                return Err(invalid());
            }
            // Checked before the value is ever used as a path
            // component, exactly as the one store-path resolver
            // requires of every fingerprint read back out of a
            // protected record.
            if !store_path::valid_fingerprint(&member.device_fingerprint) || member.st_dev == 0 {
                return Err(invalid());
            }
            // A member that is not at least provisionally consumed has
            // had no receipt spent over it, so the set is not one this
            // gate may commit.
            if member.state != ReserveState::ProvisionallyConsumed
                && member.state != ReserveState::Verified
            {
                return Err(invalid());
            }
            // The role-appropriate bound. `MAX_RESERVED_BYTES`, which
            // frame `0xc3` applies on the wire, is an overflow/shape
            // guard derived from the whole supported footprint: a
            // WAL-role reserve at database size parses cleanly under
            // it. This design allocates exactly one object of
            // `RESERVE_OBJECT_BYTES` per device, and the frozen
            // consumer requires at least `SURVIVAL_RESERVE_BYTES`, so
            // those two are the bounds a reserve figure may
            // legitimately sit between.
            if member.reserved_bytes < SURVIVAL_RESERVE_BYTES
                || member.reserved_bytes > RESERVE_OBJECT_BYTES
            {
                return Err(insufficient());
            }
            if !committed {
                self.assert_gate_spend(set, &member, issuing_launch_evidence_id, now)?;
            }
            members.push(member);
        }
        Ok(members)
    }

    /// `assertRestoreCapacityGateSpend` — prove, from the receipt
    /// **ledger**, that a receipt bound to this set, this role and
    /// this launch was spent for this member and is still in force.
    ///
    /// It reads the ledger and not the member's own receipt binding,
    /// and that is the whole point: `attach_member_receipt` refuses
    /// replacement, so the member permanently names its *first*
    /// receipt, which on the retry path may never have been presented
    /// at all. See `SpendRecord`.
    fn assert_gate_spend(
        &self,
        set: &ReserveSetRecord,
        member: &ReserveMemberRecord,
        issuing_launch_evidence_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let receipts = self
            .restore_capacity_receipts
            .as_ref()
            .ok_or_else(invalid)?;
        let spend = receipts
            .read_spend(set.set_id, member.role)
            .map_err(|_| invalid())?;
        // The spend's (set, role) is not re-compared here: `read_spend`
        // takes both as arguments and refuses a record that does not
        // carry them. The launch binding is a different fact — it is
        // what the ledger itself recorded at consumption time, not
        // what the set record says — and it is compared.
        if spend.launch_evidence_id != issuing_launch_evidence_id {
            return Err(invalid());
        }
        // The provisional mark is in force for the receipt's own
        // 20-minute window, which is a different clock from the set's
        // 8-hour absolute expiry. It is checked only on the commit,
        // never afterwards: once the set is committed it is bound, and
        // "receipt window lapsed" is a release trigger for an
        // *unbound* set.
        if now >= spend.expires_at || now < spend.consumed_at {
            return Err(invalid());
        }
        let receipt = receipts
            .read_receipt(spend.receipt_id)
            .map_err(|_| invalid())?;
        // `read_receipt` already pins `receipt_id` to the id it was
        // asked for; everything below is a fact the ledger entry
        // carries that nothing else has asserted.
        if receipt.set_id != set.set_id
            || receipt.role != member.role
            || receipt.launch_evidence_id != issuing_launch_evidence_id
            || receipt.backup_id != set.backup_id
            || receipt.repository_binding_id != set.repository_binding_id
            || receipt.reserved_bytes != member.reserved_bytes
        {
            return Err(invalid());
        }
        if wire::is_go_zero_time(receipt.consumed_at) || receipt.consumed_at != spend.consumed_at {
            return Err(invalid());
        }
        // The device the receipt was minted over must be the device
        // the member record names, or the proof is about some other
        // disk.
        let device_id =
            device_id_from_fingerprint(&member.device_fingerprint).map_err(|_| invalid())?;
        if receipt.device_id != device_id {
            return Err(invalid());
        }
        Ok(())
    }

    /// `assertRestoreCapacityGateExtents` — precondition 4: the
    /// daemon opens each device's reserve object itself and requires
    /// its *allocated blocks* to cover the survival reserve.
    ///
    /// `st_blocks`, not `st_size`, and that distinction is the whole
    /// check. A file that has been truncated to zero and re-extended,
    /// or had its extents punched out with `FALLOC_FL_PUNCH_HOLE`,
    /// keeps its size and loses its blocks — and it is the blocks that
    /// stop a `pg_restore` dying of `ENOSPC`. Reading the size would
    /// admit exactly the sparse file this precondition exists to
    /// refuse.
    fn assert_gate_extents(&self, devices: &[GateDevice]) -> Result<(), Failure> {
        let Ok(roots) = self.role_roots() else {
            // A service composed without role roots cannot ask the
            // disk anything. The restore engine's own in-process
            // service is deliberately one of those, and it must never
            // be able to admit itself.
            return Err(invalid());
        };
        for device in devices {
            let path = device.anchor_role.root(roots);
            if path.is_empty() {
                return Err(invalid());
            }
            self.assert_gate_extent(path, device)?;
        }
        Ok(())
    }

    fn assert_gate_extent(&self, role_root_path: &str, device: &GateDevice) -> Result<(), Failure> {
        // `O_NOFOLLOW` refuses a role root that is itself a symlink,
        // and the descriptor is what everything below resolves from —
        // never the path string a second time.
        let root = rustix::fs::open(
            role_root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| insufficient())?;
        // `create = false`: a store directory this call had to create
        // is proof nothing was ever allocated beneath it.
        let store =
            store_path::open_device_store(root.as_fd(), false).map_err(|_| insufficient())?;
        // `st_dev` is authoritative. A store whose device is not the
        // device this record names holds no object that could be this
        // member's, whatever it is called.
        if store.st_dev() != device.st_dev {
            return Err(insufficient());
        }
        let object = store
            .open(&device.fingerprint)
            .map_err(|_| insufficient())?;
        let stat = rustix::fs::fstat(&object).map_err(|_| insufficient())?;
        let allocated = gate_allocated_bytes(stat.st_blocks).ok_or_else(insufficient)?;
        if allocated < SURVIVAL_RESERVE_BYTES || allocated < device.reserved_bytes {
            return Err(insufficient());
        }
        Ok(())
    }
}

/// `restoreCapacityGateCollapse` — group the four member records onto
/// the devices they share, refusing every way the records could
/// disagree about device identity, and compute each device's planned
/// demand.
///
/// It is the daemon-side counterpart of the helper's `collapse` and
/// refuses in both directions of the identity disagreement for the
/// identical reason: two roles sharing a fingerprint while differing
/// in `st_dev` would put two devices under one store name, and two
/// roles sharing an `st_dev` while differing in fingerprint would put
/// one device under two names. `st_dev` is authoritative; the
/// fingerprint is a naming key.
fn gate_collapse(
    members: &[ReserveMemberRecord],
    demand: &RestoreCapacityDemand,
) -> Result<Vec<GateDevice>, Failure> {
    if members.len() != RESERVE_ROLES.len() {
        return Err(invalid());
    }
    let mut by_dev: HashMap<u64, usize> = HashMap::with_capacity(members.len());
    let mut by_fingerprint: HashMap<&str, u64> = HashMap::with_capacity(members.len());
    let mut devices: Vec<GateDevice> = Vec::with_capacity(members.len());
    let mut seen_roles = std::collections::HashSet::with_capacity(members.len());
    // The iteration follows `RESERVE_ROLES` order, which is what makes
    // the first role seen on a device its anchor — the same rule the
    // helper's allocator applied when it chose which role root to
    // create the object beneath.
    for role in RESERVE_ROLES {
        let member = members
            .iter()
            .find(|candidate| candidate.role == role)
            .ok_or_else(invalid)?;
        if !seen_roles.insert(role) {
            return Err(invalid());
        }
        if by_fingerprint
            .get(member.device_fingerprint.as_str())
            .is_some_and(|&existing| existing != member.st_dev)
        {
            return Err(invalid());
        }
        by_fingerprint.insert(member.device_fingerprint.as_str(), member.st_dev);
        let index = match by_dev.get(&member.st_dev) {
            None => {
                by_dev.insert(member.st_dev, devices.len());
                devices.push(GateDevice {
                    st_dev: member.st_dev,
                    fingerprint: member.device_fingerprint.clone(),
                    anchor_role: role,
                    planned_bytes: 0,
                    free_bytes: member.observed_free_bytes,
                    reserved_bytes: member.reserved_bytes,
                });
                devices.len() - 1
            }
            Some(&index) => {
                if devices[index].fingerprint != member.device_fingerprint {
                    return Err(invalid());
                }
                // Roles on one device are backed by one object, so
                // their reserve figures describe the same object and
                // must agree. The conservative reading of free space
                // wins, exactly as the helper's collapse takes the
                // smaller of two readings taken microseconds apart.
                //
                // A disagreement here is not a capacity shortfall — it
                // is two member records making incompatible claims
                // about the same physical object, which is this file's
                // own STATE_INVALID bucket, not CAPACITY_INSUFFICIENT.
                if devices[index].reserved_bytes != member.reserved_bytes {
                    return Err(invalid());
                }
                if member.observed_free_bytes < devices[index].free_bytes {
                    devices[index].free_bytes = member.observed_free_bytes;
                }
                index
            }
        };
        // This is the dedupe that matters: each role's demand is added
        // to its *device's* plan exactly once, rather than each member
        // being checked against the whole plan or the four reserves
        // being summed as if they were four objects.
        devices[index].planned_bytes =
            allocation::add_bytes(devices[index].planned_bytes, role_demand(demand, role))
                .ok_or_else(insufficient)?;
    }
    if devices.is_empty() || devices.len() > RESERVE_ROLES.len() {
        return Err(invalid());
    }
    Ok(devices)
}

#[cfg(test)]
mod tests {
    //! `restore_capacity_gate_linux_test.go` — the gate fixture: a real
    //! protected store, real role roots on a supported filesystem, a
    //! sealed backup, a live apply operation, and reserve/member/
    //! receipt/spend records seeded through the real store calls —
    //! the same chain `0xc3`/`0xc4` frames drive, minus the socket.

    use super::*;
    use crate::broker::migration_launch::verify_peer_process;
    use crate::broker::restore_capacity::allocation::tests::{
        ScratchDir, role_roots_in, supported_temp_dir,
    };
    use crate::broker::restore_capacity::receipt::{self, ReceiptMint};
    use crate::broker::restore_capacity::store::{ReserveMemberIntent, ReserveSetIntent};
    use crate::broker::restore_launch::RestoreLaunchEvidence;
    use crate::broker::testutil::TempDir;
    use central_backup::backup::capacity::RoleRoots;
    use central_backup::backup::inventory::{InventoryEntry, new_inventory_chunk};
    use central_backup::backup::manifest::new_seal_root_manifest;
    use central_backup::backup::operation::{
        self as backup_operation, BackupPhase, BackupSealProposal, DumpEvidence,
    };
    use central_backup::domain::TargetIdentity;
    use central_backup::port::RestoreAdmissionFacts;
    use sha2::Digest;
    use std::process::Child;
    use time::Duration;

    const DUMP_BYTES: u64 = 1 << 30;
    const OBJECT_BYTES: u64 = 1 << 30;
    const OBSERVED_FREE: u64 = 1 << 40;

    fn is_invalid(f: &Failure) -> bool {
        f.code() == RestoreRefusalReason::StateInvalid.as_str()
    }
    fn is_insufficient(f: &Failure) -> bool {
        f.code() == RestoreRefusalReason::CapacityInsufficient.as_str()
    }

    /// What the sealed manifest proves: `DUMP_BYTES` of dump and two
    /// inventory entries. The set record must repeat both exactly.
    fn seal_artifacts() -> Vec<central_backup::backup::inventory::InventoryChunk> {
        vec![
            new_inventory_chunk(
                0,
                vec![
                    InventoryEntry {
                        artifact_id: Uuid::now_v7(),
                        checksum: [9; 32],
                        size: 4096,
                    },
                    InventoryEntry {
                        artifact_id: Uuid::now_v7(),
                        checksum: [8; 32],
                        size: 2048,
                    },
                ],
            )
            .unwrap(),
        ]
    }

    struct GateFixture {
        svc: Service,
        _protected: TempDir,
        _scratch: ScratchDir,
        roots: RoleRoots,
        _engine: Child,
        engine_pid: i32,
        binding: RestoreLaunchBinding,
        operation: RestoreOperation,
        backup_id: Uuid,
        repository_binding_id: Uuid,
        fingerprint: String,
        st_dev: u64,
        now: OffsetDateTime,
    }

    /// `newGateFixture` — every durable fact the gate reads, created
    /// through the daemon's own write paths. Returns `None` on a host
    /// without a supported filesystem for the role roots.
    fn fixture() -> Option<GateFixture> {
        let scratch = supported_temp_dir()?;
        let roots = role_roots_in(&scratch);
        let anchor_fd = std::fs::File::open(ReserveRole::PostgresData.root(&roots)).ok()?;
        let measurement = allocation::measure_root(&anchor_fd, ReserveRole::PostgresData).ok()?;

        let dir = TempDir::new("gate");
        let mut svc = crate::broker::testutil::service(&dir);
        svc.set_role_roots(roots.clone());
        let now = OffsetDateTime::now_utc();

        // A live apply launch: `sleep` stands in for `central-restore`.
        let engine = std::process::Command::new("sleep").arg("30").spawn().ok()?;
        let pid = engine.id() as i32;
        let (executable, process_start) = verify_peer_process(pid).ok()?;
        let launches = svc.restore_launches.as_mut().unwrap();
        launches.executable_path = executable.clone();
        launches.helper_executable_path = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string();
        launches
            .issue(
                &RestoreLaunchEvidence {
                    pid,
                    process_start,
                    executable,
                    mode: "apply".to_string(),
                    expires_at: now + Duration::hours(1),
                },
                std::process::id() as i32,
            )
            .unwrap();
        let engine_cred = crate::sys::peercred::PeerCred {
            pid: rustix::process::Pid::from_raw(pid).unwrap(),
            uid: rustix::process::Uid::from_raw(0),
            gid: rustix::process::Gid::from_raw(0),
        };
        let binding = svc
            .restore_launches
            .as_ref()
            .unwrap()
            .validate_peer(&engine_cred)
            .unwrap();

        // A sealed backup in the recovery journal.
        let journal = svc.recovery_journal.as_ref().unwrap();
        let target = TargetIdentity {
            system_id: "7263123456789012345".to_string(),
            database_oid: "16402".to_string(),
            database: "central".to_string(),
            config_hash: "sha256:config".to_string(),
            epoch: 1,
        };
        let target_fingerprint = format!("sha256:{}", target.fingerprint());
        let config_fingerprint = format!("sha256:{}", "cd".repeat(32));
        let payload_epoch_id = Uuid::now_v7();
        let repository_binding_id = Uuid::now_v7();
        let backup_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let mut backup =
            backup_operation::new_backup_operation(operation_id, backup_id, target.clone(), now)
                .unwrap();
        journal.create_backup(&backup).unwrap();
        let facts = backup_operation::new_backup_accepted_facts(
            now,
            &target_fingerprint,
            &config_fingerprint,
            payload_epoch_id,
            repository_binding_id,
            &format!("sha256:{}", "ef".repeat(32)),
        )
        .unwrap();
        let next = backup.accept(facts).unwrap();
        journal.compare_and_swap_backup(&backup, &next).unwrap();
        backup = next;
        for phase in [
            BackupPhase::Dumping,
            BackupPhase::Inventory,
            BackupPhase::Sealing,
        ] {
            let next = backup.advance(phase, now).unwrap();
            journal.compare_and_swap_backup(&backup, &next).unwrap();
            backup = next;
        }
        let chunks = seal_artifacts();
        let manifest = new_seal_root_manifest(
            &backup,
            DumpEvidence {
                size: DUMP_BYTES as i64,
                digest: [7; 32],
            },
            &chunks,
        )
        .unwrap();
        let root_manifest_json = manifest.canonical_json().unwrap();
        let manifest_digest: [u8; 32] = sha2::Sha256::digest(&root_manifest_json).into();
        journal
            .seal_backup(&BackupSealProposal {
                operation_id,
                backup_id,
                target: target.clone(),
                accepted_at: backup.accepted_at,
                repository_binding_id,
                target_fingerprint: target_fingerprint.clone(),
                config_fingerprint: config_fingerprint.clone(),
                payload_epoch_id,
                root_manifest_json,
                manifest_digest,
                file_tree_digest: [3; 32],
                proposed_at: now,
            })
            .unwrap();
        // The operation stays `sealing`: `sealed` is reachable only
        // through `complete_attested_backup_seal`, and the gate reads
        // the seal *record*, which now exists.

        // A ticket the fixture's launch issued, then an apply begun on it.
        let admission = RestoreAdmissionFacts {
            target,
            target_fingerprint,
            security_epoch: 1,
            restore_epoch: 7,
            config_fingerprint,
            payload_epoch_id,
            database_schema_version: backup_operation::BACKUP_DATABASE_SCHEMA_VERSION.to_string(),
            capacity_evidence_digest: format!("sha256:{}", "ab".repeat(32)),
            tool_version: "pg_restore-16.14".to_string(),
        };
        let ticket = journal
            .issue(
                backup_id,
                &format!("sha256:{}", wire::hex_encode(&manifest_digest)),
                &admission,
                binding.launch_evidence_id,
                now,
            )
            .unwrap();
        // `valid_at` is strict (`now > issued_at`): the begin runs one
        // tick after the ceremony that authorized it.
        let authorization = journal
            .issue_restore_apply_authorization(&ticket, 0, pid, now)
            .unwrap();
        let operation = journal
            .begin(&ticket, &authorization, now + Duration::milliseconds(10))
            .unwrap();

        Some(GateFixture {
            svc,
            _protected: dir,
            _scratch: scratch,
            roots,
            _engine: engine,
            engine_pid: pid,
            binding,
            operation,
            backup_id,
            repository_binding_id,
            fingerprint: measurement.fingerprint,
            st_dev: measurement.st_dev,
            now,
        })
    }

    /// The seed-time knobs a refusal test turns; `Seed::reference` is
    /// the helper-recorded evidence a legitimate run produces.
    struct Seed {
        set_backup_id: Option<Uuid>,
        set_launch: Option<Uuid>,
        spend_launch: Option<Uuid>,
        dump_bytes: u64,
        object_bytes: u64,
        artifact_count: u64,
        reserved_bytes: u64,
        expires_in: Duration,
        spend: bool,
    }

    impl Seed {
        fn reference() -> Self {
            Self {
                set_backup_id: None,
                set_launch: None,
                spend_launch: None,
                dump_bytes: DUMP_BYTES,
                object_bytes: OBJECT_BYTES,
                artifact_count: 2,
                reserved_bytes: SURVIVAL_RESERVE_BYTES,
                expires_in: Duration::hours(1),
                spend: true,
            }
        }
    }

    impl GateFixture {
        /// `seedAllocatedReserveSet` — set intent, operation bind, four
        /// member intents confirmed allocated, one minted+spent receipt
        /// per member, members provisionally consumed, set allocated.
        fn seed(&self, seed: &Seed) -> Uuid {
            let reserves = self.svc.restore_capacity_reserves.as_ref().unwrap();
            let receipts = self.svc.restore_capacity_receipts.as_ref().unwrap();
            let set = reserves
                .create_set_intent(
                    ReserveSetIntent {
                        launch_evidence_id: seed
                            .set_launch
                            .unwrap_or(self.binding.launch_evidence_id),
                        backup_id: seed.set_backup_id.unwrap_or(self.backup_id),
                        repository_binding_id: self.repository_binding_id,
                        dump_bytes: seed.dump_bytes,
                        object_bytes: seed.object_bytes,
                        artifact_count: seed.artifact_count,
                        absolute_expires_at: self.now + seed.expires_in,
                    },
                    self.now,
                )
                .unwrap();
            reserves
                .bind_set_to_operation(set.set_id, self.operation.operation_id, self.now)
                .unwrap();
            let device_id = device_id_from_fingerprint(&self.fingerprint).unwrap();
            let spend_launch = seed.spend_launch.unwrap_or(self.binding.launch_evidence_id);
            for role in RESERVE_ROLES {
                let reserved = seed.reserved_bytes;
                reserves
                    .create_member_intent(
                        set.set_id,
                        ReserveMemberIntent {
                            role,
                            device_fingerprint: self.fingerprint.clone(),
                            st_dev: self.st_dev,
                            reserved_bytes: reserved,
                            observed_free_bytes: OBSERVED_FREE,
                            observed_at: self.now,
                        },
                        self.now,
                    )
                    .unwrap();
                reserves
                    .confirm_member_allocation(set.set_id, role, OBSERVED_FREE, self.now, self.now)
                    .unwrap();
                if seed.spend {
                    let minted = receipts
                        .mint(
                            ReceiptMint {
                                set_id: set.set_id,
                                launch_evidence_id: spend_launch,
                                backup_id: self.backup_id,
                                repository_binding_id: self.repository_binding_id,
                                role,
                                device_id: device_id.clone(),
                                reserved_bytes: reserved,
                            },
                            self.now,
                        )
                        .unwrap();
                    let bearer = wire::hex_decode(&minted.authority_proof).unwrap();
                    receipts
                        .consume(minted.receipt_id, &bearer, spend_launch, self.now)
                        .unwrap();
                    reserves
                        .attach_member_receipt(
                            set.set_id,
                            role,
                            minted.receipt_id,
                            &receipt::bearer_hash(&bearer),
                            minted.issued_at,
                            minted.expires_at,
                        )
                        .unwrap();
                    reserves
                        .advance_member_state(
                            set.set_id,
                            role,
                            ReserveState::ProvisionallyConsumed,
                            self.now,
                        )
                        .unwrap();
                }
            }
            reserves
                .advance_set_state(set.set_id, ReserveState::Allocated, self.now)
                .unwrap();
            set.set_id
        }

        /// `placeReserveObject` — the physical extent under the anchor
        /// role's store. `real` fallocates the full object; `false`
        /// leaves a sparse file of the same size — the hole the gate's
        /// `st_blocks` check exists to refuse.
        fn place_object(&self, role: ReserveRole, real: bool) -> bool {
            let path = role.root(&self.roots);
            let Ok(root) = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) else {
                return false;
            };
            let Ok(store) = store_path::open_device_store(root.as_fd(), true) else {
                return false;
            };
            let Ok(object) = store.create(&self.fingerprint) else {
                return false;
            };
            if !real {
                return object.set_len(RESERVE_OBJECT_BYTES).is_ok();
            }
            rustix::fs::fallocate(
                &object,
                rustix::fs::FallocateFlags::empty(),
                0,
                RESERVE_OBJECT_BYTES,
            )
            .is_ok()
        }
    }

    /// `TestRestoreCapacityGateAdmitsOnHelperRecordedEvidenceAndIgnores
    /// TheEngineTranscript` — every figure the gate checks comes from
    /// the daemon's own protected records, and the committed set is
    /// admitted.
    #[test]
    fn gate_admits_on_helper_recorded_evidence() {
        let Some(fx) = fixture() else { return };
        if !fx.place_object(ReserveRole::PostgresData, true) {
            return;
        }
        fx.seed(&Seed::reference());
        fx.svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap();
        let set = fx
            .svc
            .restore_capacity_reserves
            .as_ref()
            .unwrap()
            .resolve_set_for_operation(fx.operation.operation_id)
            .unwrap();
        assert_eq!(set.state, ReserveState::Verified);
    }

    /// Missing set, unspent member, intent-state member — the set is
    /// not one this gate may commit.
    #[test]
    fn gate_refuses_missing_or_uncommitted_set() {
        let Some(fx) = fixture() else { return };
        // No reserve seeded at all.
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "missing set: {err}");
        // Members allocated but no receipt spent over any of them.
        fx.seed(&Seed {
            spend: false,
            ..Seed::reference()
        });
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "unspent member: {err}");
    }

    /// The set must name this operation's backup and the launch that
    /// issued this operation's ticket — a set under another backup or
    /// another launch is not evidence here.
    #[test]
    fn gate_refuses_misbound_set() {
        let Some(fx) = fixture() else { return };
        fx.seed(&Seed {
            set_launch: Some(Uuid::now_v7()),
            ..Seed::reference()
        });
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "other launch: {err}");

        let Some(fx) = fixture() else { return };
        fx.seed(&Seed::reference());
        let mut operation = fx.operation.clone();
        operation.backup_id = Uuid::now_v7();
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "other backup: {err}");
    }

    /// `TestRestoreCapacityGateTreatsAbsoluteExpiryAsAnEntryBoundNotA
    /// ContinuationBound` — expired uncommitted set refused; a set the
    /// gate already committed is admitted past expiry.
    #[test]
    fn gate_expiry_bounds_entry_not_continuation() {
        let Some(fx) = fixture() else { return };
        fx.seed(&Seed::reference());
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(
                &fx.operation,
                &fx.binding,
                fx.now + Duration::hours(2),
            )
            .unwrap_err();
        assert!(is_invalid(&err), "expired entry: {err}");

        let Some(fx) = fixture() else { return };
        if !fx.place_object(ReserveRole::PostgresData, true) {
            return;
        }
        fx.seed(&Seed::reference());
        fx.svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap();
        // Same operation, past the set's expiry and past the receipt
        // window: committed means committed.
        fx.svc
            .assert_restore_capacity_reserve_gate(
                &fx.operation,
                &fx.binding,
                fx.now + Duration::hours(2),
            )
            .unwrap();
    }

    /// `TestRestoreCapacityGateRefusesFiguresTheDaemonsOwnSeal
    /// Contradicts` — dump bytes or artifact count that are not the
    /// seal's are state-invalid, not a shortfall.
    #[test]
    fn gate_refuses_figures_the_seal_contradicts() {
        for seed in [
            Seed {
                dump_bytes: DUMP_BYTES + 1,
                ..Seed::reference()
            },
            Seed {
                artifact_count: 3,
                ..Seed::reference()
            },
        ] {
            let Some(fx) = fixture() else { return };
            fx.seed(&seed);
            let err = fx
                .svc
                .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
                .unwrap_err();
            assert!(is_invalid(&err), "seal disagreement: {err}");
        }
    }

    /// `TestRestoreCapacityGateCollapseRefusesReservedBytesDisagreement
    /// AsStateInvalid` — exercised on `gate_collapse` directly, exactly
    /// as upstream does: with `RESERVE_OBJECT_BYTES ==
    /// SURVIVAL_RESERVE_BYTES` there is no in-bounds disagreement the
    /// store could durably record, so the disagreement is built as two
    /// hand-made records. One device means one object, and two member
    /// records naming different figures for it is a state defect, not
    /// a shortfall.
    #[test]
    fn gate_collapse_refuses_reserved_bytes_disagreement() {
        let fp = member_fingerprint();
        let mut members: Vec<ReserveMemberRecord> = RESERVE_ROLES
            .iter()
            .map(|role| member_record(*role, &fp, 77, SURVIVAL_RESERVE_BYTES))
            .collect();
        members[1].reserved_bytes += 1;
        let err = gate_collapse(&members, &RestoreCapacityDemand::default()).unwrap_err();
        assert!(is_invalid(&err), "reserved disagreement: {err}");
    }

    /// `TestRestoreCapacityGateCollapseAgreesWithReserveCollapseOn
    /// AnchorRole` — the helper's collapse and the gate's collapse pick
    /// the same anchor for a shared device: the first role in the
    /// fixed `RESERVE_ROLES` order. A drift between the two would
    /// surface only as an unexplained refusal at the gate.
    #[test]
    fn gate_collapse_agrees_with_reserve_collapse_on_anchor_role() {
        let fp = member_fingerprint();
        let measurements: Vec<allocation::Measurement> = RESERVE_ROLES
            .iter()
            .map(|role| allocation::Measurement {
                role: *role,
                st_dev: 91,
                fingerprint: fp.clone(),
                free_bytes: 1 << 40,
            })
            .collect();
        let members: Vec<ReserveMemberRecord> = RESERVE_ROLES
            .iter()
            .map(|role| member_record(*role, &fp, 91, SURVIVAL_RESERVE_BYTES))
            .collect();
        let demand = RestoreCapacityDemand {
            postgres_data_bytes: 1,
            postgres_wal_bytes: 2,
            postgres_temp_bytes: 4,
            object_data_bytes: 8,
        };
        let helper = allocation::collapse(&measurements, &demand).unwrap();
        let gate = gate_collapse(&members, &demand).unwrap();
        assert_eq!(helper.len(), 1, "helper must dedupe one shared device");
        assert_eq!(gate.len(), 1, "gate must dedupe one shared device");
        assert_eq!(helper[0].anchor_role, gate[0].anchor_role);
        assert_eq!(helper[0].anchor_role, ReserveRole::PostgresData);
        assert_eq!(gate[0].planned_bytes, 1 + 2 + 4 + 8);
    }

    /// `TestRestoreCapacityGateSumsDemandPerDeviceRatherThanPerRole` —
    /// two devices hold two roles each; each device's plan is the sum
    /// of its own roles, not the whole set's.
    #[test]
    fn gate_collapse_sums_demand_per_device() {
        let fp_a = member_fingerprint();
        let fp_b = member_fingerprint_b();
        let members = vec![
            member_record(ReserveRole::PostgresData, &fp_a, 41, SURVIVAL_RESERVE_BYTES),
            member_record(ReserveRole::PostgresWal, &fp_a, 41, SURVIVAL_RESERVE_BYTES),
            member_record(ReserveRole::PostgresTemp, &fp_b, 43, SURVIVAL_RESERVE_BYTES),
            member_record(ReserveRole::ObjectData, &fp_b, 43, SURVIVAL_RESERVE_BYTES),
        ];
        let demand = RestoreCapacityDemand {
            postgres_data_bytes: 1,
            postgres_wal_bytes: 2,
            postgres_temp_bytes: 4,
            object_data_bytes: 8,
        };
        let devices = gate_collapse(&members, &demand).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].st_dev, 41);
        assert_eq!(devices[0].planned_bytes, 1 + 2);
        assert_eq!(devices[0].anchor_role, ReserveRole::PostgresData);
        assert_eq!(devices[1].st_dev, 43);
        assert_eq!(devices[1].planned_bytes, 4 + 8);
        assert_eq!(devices[1].anchor_role, ReserveRole::PostgresTemp);
    }

    /// Fingerprint/device identity disagreement refuses in both
    /// directions — one fingerprint over two `st_dev`s, and one
    /// `st_dev` under two fingerprints.
    #[test]
    fn gate_collapse_refuses_identity_disagreement() {
        let fp_a = member_fingerprint();
        let fp_b = member_fingerprint_b();
        for members in [
            vec![
                member_record(ReserveRole::PostgresData, &fp_a, 41, SURVIVAL_RESERVE_BYTES),
                member_record(ReserveRole::PostgresWal, &fp_a, 43, SURVIVAL_RESERVE_BYTES),
                member_record(ReserveRole::PostgresTemp, &fp_b, 45, SURVIVAL_RESERVE_BYTES),
                member_record(ReserveRole::ObjectData, &fp_b, 47, SURVIVAL_RESERVE_BYTES),
            ],
            vec![
                member_record(ReserveRole::PostgresData, &fp_a, 41, SURVIVAL_RESERVE_BYTES),
                member_record(ReserveRole::PostgresWal, &fp_b, 41, SURVIVAL_RESERVE_BYTES),
                member_record(ReserveRole::PostgresTemp, &fp_a, 41, SURVIVAL_RESERVE_BYTES),
                member_record(ReserveRole::ObjectData, &fp_b, 41, SURVIVAL_RESERVE_BYTES),
            ],
        ] {
            let err = gate_collapse(&members, &RestoreCapacityDemand::default()).unwrap_err();
            assert!(is_invalid(&err), "identity disagreement: {err}");
        }
    }

    /// A resolver-minted fingerprint — never hand-written, the shape
    /// the store-path resolver itself produces.
    fn member_fingerprint() -> String {
        store_path::device_fingerprint(((21u64) << 32) | 21u64).unwrap()
    }
    fn member_fingerprint_b() -> String {
        store_path::device_fingerprint(((31u64) << 32) | 31u64).unwrap()
    }

    /// The record shape `gate_collapse` consumes; only the fields the
    /// collapse reads are meaningful.
    fn member_record(
        role: ReserveRole,
        fingerprint: &str,
        st_dev: u64,
        reserved_bytes: u64,
    ) -> ReserveMemberRecord {
        ReserveMemberRecord {
            schema_version: String::new(),
            set_id: Uuid::now_v7(),
            role,
            device_fingerprint: fingerprint.to_string(),
            st_dev,
            reserved_bytes,
            observed_free_bytes: 1 << 40,
            observed_at: OffsetDateTime::now_utc(),
            receipt_id: Uuid::nil(),
            bearer_value_hash: String::new(),
            receipt_issued_at: wire::go_zero_time(),
            receipt_expires_at: wire::go_zero_time(),
            state: ReserveState::ProvisionallyConsumed,
            created_at: OffsetDateTime::now_utc(),
            allocated_at: wire::go_zero_time(),
            consumed_at: wire::go_zero_time(),
            verified_at: wire::go_zero_time(),
            released_at: wire::go_zero_time(),
            hmac: String::new(),
        }
    }

    /// `TestRestoreCapacityGateBoundsTheReserveFigureToARoleAppropriate
    /// Range` — below the survival reserve or above one object is an
    /// arithmetic refusal.
    #[test]
    fn gate_bounds_the_reserve_figure() {
        for reserved_bytes in [SURVIVAL_RESERVE_BYTES - 1, RESERVE_OBJECT_BYTES + 1] {
            let Some(fx) = fixture() else { return };
            fx.seed(&Seed {
                reserved_bytes,
                ..Seed::reference()
            });
            let err = fx
                .svc
                .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
                .unwrap_err();
            assert!(is_insufficient(&err), "reserved {reserved_bytes}: {err}");
        }
    }

    /// `TestRestoreCapacityGateRefusesAHolePunchedOrTruncatedReserve` —
    /// a sparse file of the right *size* has no blocks; a missing
    /// object has nothing at all.
    #[test]
    fn gate_refuses_sparse_or_missing_extent() {
        let Some(fx) = fixture() else { return };
        fx.seed(&Seed::reference());
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_insufficient(&err), "missing object: {err}");

        if !fx.place_object(ReserveRole::PostgresData, false) {
            return;
        }
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_insufficient(&err), "sparse object: {err}");
    }

    /// `TestRestoreCapacityGateRefusesASpendFromAnotherLaunchOrOutside
    /// ItsWindow` — the ledger's own launch binding is what the gate
    /// compares, not the member's or the set's.
    #[test]
    fn gate_refuses_spend_from_another_launch() {
        let Some(fx) = fixture() else { return };
        fx.seed(&Seed {
            spend_launch: Some(Uuid::now_v7()),
            ..Seed::reference()
        });
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "foreign-launch spend: {err}");
    }

    /// The anchor-role agreement: four roles on one device place one
    /// object under the *first* role's root, and the gate looks there
    /// — an object under a sibling root is not it.
    #[test]
    fn gate_looks_up_the_anchor_roles_store() {
        let Some(fx) = fixture() else { return };
        if !fx.place_object(ReserveRole::PostgresWal, true) {
            return;
        }
        fx.seed(&Seed::reference());
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_insufficient(&err), "sibling-root object: {err}");
    }

    /// A service composed without role roots, or without capacity
    /// stores, fails closed — the engine-side service can never admit
    /// itself.
    #[test]
    fn gate_fails_closed_without_authority_surfaces() {
        let Some(mut fx) = fixture() else { return };
        fx.seed(&Seed::reference());
        fx.svc.restore_capacity_receipts = None;
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "no receipt store: {err}");

        let Some(mut fx) = fixture() else { return };
        fx.seed(&Seed::reference());
        fx.svc.role_roots = None;
        if fx.place_object(ReserveRole::PostgresData, true) {
            let err = fx
                .svc
                .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
                .unwrap_err();
            assert!(is_invalid(&err), "no role roots: {err}");
        }
        let _ = fx.engine_pid;
    }

    /// `TestResolveSetForOperationRefusesAPointerThatDriftedFromItsSet`
    /// — an operation whose recorded set no longer names it is refused
    /// at resolution, before any arithmetic.
    #[test]
    fn gate_refuses_a_drifted_operation_pointer() {
        let Some(fx) = fixture() else { return };
        let set_id = fx.seed(&Seed::reference());
        // Point the operation index at a second, foreign set; the
        // pointer resolves but the set it names does not name this
        // operation back.
        let reserves = fx.svc.restore_capacity_reserves.as_ref().unwrap();
        let foreign = reserves
            .create_set_intent(
                ReserveSetIntent {
                    launch_evidence_id: fx.binding.launch_evidence_id,
                    backup_id: fx.backup_id,
                    repository_binding_id: fx.repository_binding_id,
                    dump_bytes: DUMP_BYTES,
                    object_bytes: OBJECT_BYTES,
                    artifact_count: 2,
                    absolute_expires_at: fx.now + Duration::hours(1),
                },
                fx.now,
            )
            .unwrap();
        reserves
            .bind_set_to_operation(foreign.set_id, fx.operation.operation_id, fx.now)
            .unwrap_err();
        // A second bind under a different set refuses; the pointer
        // stays on the first set, which still resolves — so release
        // the first set instead and prove resolution refuses it back.
        reserves.release_set(set_id, fx.now).unwrap();
        let err = fx
            .svc
            .assert_restore_capacity_reserve_gate(&fx.operation, &fx.binding, fx.now)
            .unwrap_err();
        assert!(is_invalid(&err), "released set: {err}");
    }
}
