//! `restore_capacity_reserve_object{,_linux}.go` — the daemon's
//! read-only view of the physical reserve.
//!
//! Frame `0xc3`'s allocation confirmation (kind 3) advances a member
//! from intent to allocated. The advance's whole value is that it is
//! evidence: an allocated member is what the receipt draw requires and
//! what the admission gate will admit a destructive restore against.
//! So the daemon does not take the helper's word for it — before it
//! writes the advance, it opens the reserve object the member record
//! names and requires it to be there.
//!
//! The view is deliberately narrower than the helper's allocator-side
//! store: this process can prove a reserve object is present and is
//! structurally unable to mint one, unlink one, or enumerate the
//! directory (`ReserveDeviceStore::open` opens one name; nothing here
//! calls `object_count`, `create`, or `remove`).
//!
//! What it deliberately does NOT do is check the object's size or
//! allocated block count. Confirming the extent is the one the design
//! requires is the admission gate's job, which opens the same object
//! through the same resolver; duplicating a weaker version here would
//! put two answers to one question in the tree.

use rustix::fs::{Mode, OFlags};
use uuid::Uuid;

use crate::broker::server::Service;

use super::reserve_frame::ReserveRefusal;
use super::store::ReserveMemberRecord;
use super::{RESERVE_ROLES, ReserveRole, store_path};

/// `restoreCapacityReserveObjectPresent` — is the reserve object one
/// member record describes actually present on the device that record
/// names? The refusal split is the frame's, applied to a question
/// about the world rather than about a record:
///
/// - [`ReserveRefusal::Unavailable`] — *this daemon cannot ask*: it
///   was composed without role roots, it could not open the role
///   directory, or it cannot work out which role root to open because
///   an earlier role's member record is not there to say.
/// - [`ReserveRefusal::ObjectMissing`] — *the reserve is not proven
///   present*: no store directory, no object under the record's own
///   fingerprint, an object that fails the resolver's fstat
///   assertions, or a store on the wrong `st_dev`.
/// - [`ReserveRefusal::StateInvalid`] — the *record* cannot name an
///   object at all: a fingerprint no resolver minted, or a zero
///   `st_dev`.
pub(crate) fn reserve_object_present(
    svc: &Service,
    set_id: Uuid,
    member: &ReserveMemberRecord,
) -> (ReserveRefusal, bool) {
    // Checked before the value is ever used as a path component,
    // exactly as the resolver requires of every fingerprint read back
    // out of a protected record.
    if !store_path::valid_fingerprint(&member.device_fingerprint) || member.st_dev == 0 {
        return (ReserveRefusal::StateInvalid, false);
    }
    let (anchor, reason, ok) = anchor_role(svc, set_id, member);
    if !ok {
        return (reason, false);
    }
    let Ok(roots) = svc.role_roots() else {
        return (ReserveRefusal::Unavailable, false);
    };
    let path = anchor.root(roots);
    if path.is_empty() {
        return (ReserveRefusal::Unavailable, false);
    }
    // `O_NOFOLLOW` refuses a role root that is itself a symlink, and
    // the descriptor is what everything below resolves from — never
    // the path string a second time.
    let root = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return (ReserveRefusal::Unavailable, false),
    };
    // `create = false`: a store directory this call had to create is
    // proof nothing was ever allocated beneath it.
    let store = match store_path::open_device_store(&root, false) {
        Ok(store) => store,
        Err(_) => return (ReserveRefusal::ObjectMissing, false),
    };
    // `st_dev` is authoritative everywhere in this design; the
    // fingerprint is only a naming key.
    if store.st_dev() != member.st_dev {
        return (ReserveRefusal::ObjectMissing, false);
    }
    match store.open(&member.device_fingerprint) {
        Ok(_object) => (ReserveRefusal::StateInvalid, true),
        Err(_) => (ReserveRefusal::ObjectMissing, false),
    }
}

/// `restoreCapacityReserveAnchorRole` — re-derive, from the durable
/// member records alone, which role's root the given member's reserve
/// object lives beneath.
///
/// The allocator collapses the four roles onto the devices they share
/// and anchors each device's store to *the first role in
/// `RESERVE_ROLES` order that sits on this `st_dev`* — a deterministic
/// function of `st_dev` and the fixed role order precisely so the
/// daemon can recompute it without being told. An anchor read off the
/// wire would let a helper point the presence check at a directory of
/// its choosing.
///
/// Refusals: an earlier role with *no* record is [`Unavailable`] —
/// the set is mid-assembly, so the daemon cannot know which root to
/// open, and `StateInvalid` would point an operator at the record in
/// their hand (which is fine). An earlier record that exists and
/// cannot be parsed, or a store that cannot be read, keeps the read's
/// own classification.
fn anchor_role(
    svc: &Service,
    set_id: Uuid,
    member: &ReserveMemberRecord,
) -> (ReserveRole, ReserveRefusal, bool) {
    let Some(reserves) = svc.restore_capacity_reserves.as_ref() else {
        return (member.role, ReserveRefusal::Unavailable, false);
    };
    for role in RESERVE_ROLES {
        if role == member.role {
            // No earlier role shares this device: this member is its
            // own device's anchor.
            return (member.role, ReserveRefusal::Unavailable, true);
        }
        match reserves.read_member(set_id, role) {
            Ok(record) => {
                // State is irrelevant: where an object lives is decided
                // by `st_dev` and the role order, not by how far along
                // the lifecycle a role has travelled.
                if record.st_dev == member.st_dev {
                    return (role, ReserveRefusal::Unavailable, true);
                }
            }
            Err(e) if super::is_reserve_not_found(&e) => {
                return (member.role, ReserveRefusal::Unavailable, false);
            }
            Err(e) => {
                let reason = if super::is_reserve_ambiguous(&e) {
                    ReserveRefusal::StateInvalid
                } else {
                    ReserveRefusal::Unavailable
                };
                return (member.role, reason, false);
            }
        }
    }
    // Unreachable while `member.role` is one of the four fixed roles;
    // fail closed rather than guess.
    (member.role, ReserveRefusal::StateInvalid, false)
}

/// Wire [`reserve_object_present`] onto the service as the method the
/// `0xc3` confirm path calls — kept a free function so the object seam
/// stays out of `server.rs`.
impl Service {
    pub(crate) fn reserve_object_present(
        &self,
        set_id: Uuid,
        member: &ReserveMemberRecord,
    ) -> (ReserveRefusal, bool) {
        reserve_object_present(self, set_id, member)
    }
}
