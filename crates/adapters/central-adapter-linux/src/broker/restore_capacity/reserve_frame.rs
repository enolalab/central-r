//! `restore_capacity_reserve_frame_linux.go` — frame `0xc3`, the root
//! helper's write path into the capacity reserve's protected state.
//!
//! It is a separate frame rather than another kind byte on `0xc2` for
//! the same reason `0xc2`'s three kinds are separate from each other:
//! `0xc2` releases credentials to the *engine* the helper launched, and
//! its predicate (`validate_peer`) is built around that child's
//! identity, while this frame admits only the *helper*
//! (`validate_helper_peer`) and writes protected state the gate will
//! later read. A frame whose peer predicate admits the engine must
//! never also admit a write into the evidence that gates the engine's
//! own credential.
//!
//! Three kinds, each with its own precondition:
//!
//! - kind 1 — persist a new, unbound reserve set's intent;
//! - kind 2 — persist one role's pre-allocation member intent;
//! - kind 3 — confirm one member's physical allocation, which the
//!   daemon evidences by opening the reserve object for itself before
//!   advancing the record.

use std::io::{Read, Write};

use central_foundation::failure::Failure;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::broker::deadline::DeadlineStream;
use crate::broker::protocol;
use crate::broker::restore_launch::RestoreLaunchBinding;
use crate::broker::server::Service;
use crate::broker::wire;
use crate::sys::peercred::PeerCred;

use super::store::{ReserveMemberIntent, ReserveMemberRecord, ReserveSetIntent};
use super::{RESERVE_ABSOLUTE_LIFETIME, RESERVE_ROLES, ReserveRole, ReserveState};

/// `restoreCapacityReserveFrameMarker`.
pub(crate) use crate::broker::protocol::RESTORE_CAPACITY_RESERVE_FRAME_MARKER as FRAME_MARKER;

/// `restoreCapacityReserveSetKind` — persist a new reserve set's
/// intent record.
pub(crate) const SET_KIND: u8 = 1;
/// `restoreCapacityReserveMemberKind` — persist one role's intent.
pub(crate) const MEMBER_KIND: u8 = 2;
/// `restoreCapacityReserveConfirmKind` — the helper's statement that
/// the physical allocation for one role has happened; the only thing
/// that moves a member from intent to allocated, on the *helper's*
/// frame rather than the engine's (`0xc4`): the process that allocates
/// is not the process that draws receipts against the allocation.
pub(crate) const CONFIRM_KIND: u8 = 3;

pub(crate) const ROLE_FIELD_SIZE: usize = 16;
pub(crate) const FINGERPRINT_FIELD_SIZE: usize = 64;

/// Kind 1: backup, repository binding, dump bytes, object bytes,
/// artifact count. Carries neither the launch evidence id nor the
/// absolute expiry (both daemon-owned) and no operation id — under
/// "verify allocates" the set is created *before* the operation exists;
/// `0xc4` kind 3 binds it later.
pub(crate) const SET_PAYLOAD_SIZE: usize = 16 + 16 + 8 + 8 + 8;
/// Kind 2: set, role, device fingerprint, st_dev, reserved bytes,
/// observed free bytes, observation time.
pub(crate) const MEMBER_PAYLOAD_SIZE: usize =
    16 + ROLE_FIELD_SIZE + FINGERPRINT_FIELD_SIZE + 8 + 8 + 8 + 8;
/// Kind 3: set, role, and the two post-allocation re-measurement
/// figures — observed free bytes and observation time. Nothing else:
/// the device fingerprint, st_dev and reserved bytes are read back off
/// the durable member record, so a wire field for any of them would
/// let a helper confirm one role's allocation while describing another
/// role's device.
pub(crate) const CONFIRM_PAYLOAD_SIZE: usize = 16 + ROLE_FIELD_SIZE + 8 + 8;

/// `restoreCapacityReserveAcceptFrameSize` — status byte + set id +
/// the daemon's own completeness/allocated answer, computed from the
/// durable records alone.
pub(crate) const ACCEPT_FRAME_SIZE: usize = 1 + 16 + 1;
pub(crate) const ACCEPT_STATUS: u8 = 0x01;

/// `restoreCapacityReserveMaxReservedBytes` — one role's reserve
/// figure bounded in the supported-recovery vocabulary: no single role
/// can legitimately reserve more than the whole database-plus-object
/// footprint this build can restore at all, and the ceiling keeps the
/// gate's later sum of four roles in range.
const MAX_RESERVED_BYTES: u64 = central_backup::backup::capacity::SUPPORTED_RECOVERY_DATABASE_BYTES
    + central_backup::backup::capacity::SUPPORTED_RECOVERY_OBJECT_BYTES;

// --- Refusal vocabulary --------------------------------------------------

/// `restoreCapacityReserveRefusal` — the frame's closed, locator-free
/// refusal vocabulary. Peer denial and frame-parse denial are distinct
/// values so the "validate the peer before reading the body" ordering
/// is observable from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReserveRefusal {
    PeerDenied,
    FrameInvalid,
    StateInvalid,
    /// `restoreCapacityReserveObjectMissing` — kind 3's own refusal:
    /// the member record is eligible in every other way and the
    /// reserve object it names is not on the device it names. Not
    /// folded into the state bucket: an eligible record with no object
    /// behind it means the confirmation is outrunning the allocation
    /// it claims.
    ObjectMissing,
    /// `restoreCapacityReserveConflict` — a member record already
    /// exists for this `(set, role)`, is still usable, and the
    /// candidate is not the same logical intent. A helper told
    /// CONFLICT stops retrying — which is exactly right.
    Conflict,
    /// The store bucket, distinct from every eligibility answer.
    Unavailable,
}

impl ReserveRefusal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PeerDenied => "RESTORE_RESERVE_PEER_DENIED",
            Self::FrameInvalid => "RESTORE_RESERVE_FRAME_INVALID",
            Self::StateInvalid => "RESTORE_RESERVE_STATE_INVALID",
            Self::ObjectMissing => "RESTORE_RESERVE_OBJECT_MISSING",
            Self::Conflict => "RESTORE_RESERVE_CONFLICT",
            Self::Unavailable => "RESTORE_RESERVE_UNAVAILABLE",
        }
    }

    /// `restoreCapacityReserveRefusal.Valid` — the client-side
    /// vocabulary check.
    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "RESTORE_RESERVE_PEER_DENIED" => Self::PeerDenied,
            "RESTORE_RESERVE_FRAME_INVALID" => Self::FrameInvalid,
            "RESTORE_RESERVE_STATE_INVALID" => Self::StateInvalid,
            "RESTORE_RESERVE_OBJECT_MISSING" => Self::ObjectMissing,
            "RESTORE_RESERVE_CONFLICT" => Self::Conflict,
            "RESTORE_RESERVE_UNAVAILABLE" => Self::Unavailable,
            _ => return None,
        })
    }

    fn failure(self) -> Failure {
        Failure::denied("broker_restore_reserve_refused", self.as_str().to_string())
    }
}

/// `RestoreCapacityReserveAllocationConfirmation` — the helper's
/// statement that one role's physical reserve now exists, carrying
/// only what the daemon cannot re-derive: the post-allocation
/// re-measurement.
#[derive(Debug, Clone)]
pub struct AllocationConfirmation {
    pub role: ReserveRole,
    pub observed_free_bytes: u64,
    pub observed_at: OffsetDateTime,
}

// --- Request -------------------------------------------------------------

/// `restoreCapacityReserveRequest` — one parsed `0xc3` frame. Exactly
/// one of `set`, `member` or `confirm` is meaningful, selected by
/// `kind`. None carries a launch evidence id (that comes from the
/// validated peer binding) and none carries an operation id (`0xc4`
/// kind 3 binds it).
pub(crate) struct ReserveRequest {
    pub kind: u8,
    pub set_id: Uuid,
    pub set: ReserveSetIntent,
    pub member: ReserveMemberIntent,
    pub confirm: AllocationConfirmation,
}

fn frame_invalid(detail: &str) -> Failure {
    Failure::invalid("broker_restore_reserve_frame", format!("broker: {detail}"))
}

fn valid_uuid_v7(id: &Uuid) -> bool {
    !id.is_nil() && id.get_version_num() == 7
}

/// `decodeRestoreCapacityReserveFixedField` — one NUL-padded,
/// fixed-width text field. The alphabet is deliberately narrow —
/// printable, non-space ASCII with no path separator — because these
/// values are persisted into a protected record and later reported.
fn decode_fixed_field(raw: &[u8]) -> Result<String, Failure> {
    let invalid = || frame_invalid("invalid restore capacity reserve text field");
    let mut end = raw.len();
    while end > 0 && raw[end - 1] == 0 {
        end -= 1;
    }
    let trimmed = &raw[..end];
    // Empty, or a NUL anywhere but the trailing pad (i.e. interior) —
    // both are `strings.TrimRight` + `Contains` under upstream.
    if trimmed.is_empty() || trimmed.contains(&0) {
        return Err(invalid());
    }
    for b in trimmed {
        if *b <= 0x20 || *b >= 0x7f || *b == b'/' {
            return Err(invalid());
        }
    }
    std::str::from_utf8(trimmed)
        .map(|s| s.to_string())
        .map_err(|_| invalid())
}

/// Fixed-width UUID field. The callers read exactly `*_PAYLOAD_SIZE`
/// bytes before slicing, so the field is 16 bytes by construction —
/// `copy_from_slice` stands in for the infallible `try_into`.
fn uuid_field(payload: &[u8]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&payload[..16]);
    Uuid::from_bytes(bytes)
}

/// Fixed-width big-endian field, same construction.
fn be8(payload: &[u8]) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&payload[..8]);
    bytes
}

fn decode_role(raw: &[u8]) -> Result<ReserveRole, Failure> {
    let text = decode_fixed_field(raw)?;
    match text.as_str() {
        "postgres_data" => Ok(ReserveRole::PostgresData),
        "postgres_wal" => Ok(ReserveRole::PostgresWal),
        "postgres_temp" => Ok(ReserveRole::PostgresTemp),
        "object_data" => Ok(ReserveRole::ObjectData),
        _ => Err(frame_invalid("invalid restore capacity reserve role")),
    }
}

fn encode_fixed_field(value: &str, size: usize) -> Result<Vec<u8>, Failure> {
    if value.is_empty() || value.len() > size {
        return Err(ReserveRefusal::FrameInvalid.failure());
    }
    let mut field = vec![0u8; size];
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(field)
}

/// `nanos` ↔ `OffsetDateTime` — the wire carries
/// `time.Time.UnixNano()` as big-endian u64.
fn nanos_to_time(nanos: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos)).ok()
}
fn time_to_nanos(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos()).unwrap_or(i64::MAX)
}

/// `readRestoreCapacityReserveRequest` — read and shape-validate one
/// frame body, marker already consumed. No protected-state access:
/// everything refused is a property of the bytes.
pub(crate) fn read_request(conn: &mut DeadlineStream) -> Result<ReserveRequest, Failure> {
    let mut kind = [0u8; 1];
    conn.read_exact(&mut kind)
        .map_err(|e| frame_invalid(&format!("read frame kind: {e}")))?;
    match kind[0] {
        SET_KIND => {
            let mut payload = [0u8; SET_PAYLOAD_SIZE];
            conn.read_exact(&mut payload)
                .map_err(|e| frame_invalid(&format!("read set payload: {e}")))?;
            let backup_id = uuid_field(&payload[0..16]);
            let binding_id = uuid_field(&payload[16..32]);
            if !valid_uuid_v7(&backup_id) || !valid_uuid_v7(&binding_id) {
                return Err(frame_invalid(
                    "invalid restore capacity reserve set request",
                ));
            }
            let intent = ReserveSetIntent {
                launch_evidence_id: Uuid::nil(),
                backup_id,
                repository_binding_id: binding_id,
                dump_bytes: u64::from_be_bytes(be8(&payload[32..40])),
                object_bytes: u64::from_be_bytes(be8(&payload[40..48])),
                artifact_count: u64::from_be_bytes(be8(&payload[48..56])),
                absolute_expires_at: wire::go_zero_time(),
            };
            // The same supported-recovery bounds the frozen consumer
            // applies. ArtifactCount == 0 is legitimate (SC-DEF-55): a
            // fresh backup has a real dump and no artifacts yet.
            if intent.dump_bytes == 0
                || intent.dump_bytes
                    > central_backup::backup::capacity::SUPPORTED_RECOVERY_DATABASE_BYTES
                || intent.object_bytes
                    > central_backup::backup::capacity::SUPPORTED_RECOVERY_OBJECT_BYTES
                || intent.artifact_count
                    > central_backup::backup::capacity::SUPPORTED_RECOVERY_RECORD_COUNT
            {
                return Err(frame_invalid(
                    "invalid restore capacity reserve demand figures",
                ));
            }
            Ok(ReserveRequest {
                kind: SET_KIND,
                set_id: Uuid::nil(),
                set: intent,
                member: empty_member(),
                confirm: empty_confirm(),
            })
        }
        MEMBER_KIND => {
            let mut payload = [0u8; MEMBER_PAYLOAD_SIZE];
            conn.read_exact(&mut payload)
                .map_err(|e| frame_invalid(&format!("read member payload: {e}")))?;
            let set_id = uuid_field(&payload[0..16]);
            if !valid_uuid_v7(&set_id) {
                return Err(frame_invalid(
                    "invalid restore capacity reserve member request",
                ));
            }
            let role_end = 16 + ROLE_FIELD_SIZE;
            let role = decode_role(&payload[16..role_end])?;
            let fp_end = role_end + FINGERPRINT_FIELD_SIZE;
            let fingerprint = decode_fixed_field(&payload[role_end..fp_end])?;
            let observed_nanos = i64::from_be_bytes(be8(&payload[fp_end + 24..fp_end + 32]));
            if observed_nanos <= 0 {
                return Err(frame_invalid(
                    "invalid restore capacity reserve observation time",
                ));
            }
            let observed_at = nanos_to_time(observed_nanos)
                .ok_or_else(|| frame_invalid("invalid observation time"))?;
            let member = ReserveMemberIntent {
                role,
                device_fingerprint: fingerprint,
                st_dev: u64::from_be_bytes(be8(&payload[fp_end..fp_end + 8])),
                reserved_bytes: u64::from_be_bytes(be8(&payload[fp_end + 8..fp_end + 16])),
                observed_free_bytes: u64::from_be_bytes(be8(&payload[fp_end + 16..fp_end + 24])),
                observed_at,
            };
            // ReservedBytes is bounded on both sides; ObservedFreeBytes
            // deliberately has no ceiling — it is a live reading off a
            // real device, and this frame performs no arithmetic on it.
            if member.st_dev == 0
                || member.reserved_bytes == 0
                || member.reserved_bytes > MAX_RESERVED_BYTES
            {
                return Err(frame_invalid(
                    "invalid restore capacity reserve member figures",
                ));
            }
            Ok(ReserveRequest {
                kind: MEMBER_KIND,
                set_id,
                set: empty_set(),
                member,
                confirm: empty_confirm(),
            })
        }
        CONFIRM_KIND => {
            let mut payload = [0u8; CONFIRM_PAYLOAD_SIZE];
            conn.read_exact(&mut payload)
                .map_err(|e| frame_invalid(&format!("read confirm payload: {e}")))?;
            let set_id = uuid_field(&payload[0..16]);
            if !valid_uuid_v7(&set_id) {
                return Err(frame_invalid(
                    "invalid restore capacity reserve confirmation request",
                ));
            }
            let role_end = 16 + ROLE_FIELD_SIZE;
            let role = decode_role(&payload[16..role_end])?;
            let observed_nanos = i64::from_be_bytes(be8(&payload[role_end + 8..role_end + 16]));
            if observed_nanos <= 0 {
                return Err(frame_invalid(
                    "invalid restore capacity reserve observation time",
                ));
            }
            let observed_at = nanos_to_time(observed_nanos)
                .ok_or_else(|| frame_invalid("invalid observation time"))?;
            Ok(ReserveRequest {
                kind: CONFIRM_KIND,
                set_id,
                set: empty_set(),
                member: empty_member(),
                confirm: AllocationConfirmation {
                    role,
                    observed_free_bytes: u64::from_be_bytes(be8(&payload[role_end..role_end + 8])),
                    observed_at,
                },
            })
        }
        _ => Err(frame_invalid("invalid restore capacity reserve frame kind")),
    }
}

fn empty_set() -> ReserveSetIntent {
    ReserveSetIntent {
        launch_evidence_id: Uuid::nil(),
        backup_id: Uuid::nil(),
        repository_binding_id: Uuid::nil(),
        dump_bytes: 0,
        object_bytes: 0,
        artifact_count: 0,
        absolute_expires_at: wire::go_zero_time(),
    }
}
fn empty_member() -> ReserveMemberIntent {
    ReserveMemberIntent {
        role: ReserveRole::PostgresData,
        device_fingerprint: String::new(),
        st_dev: 0,
        reserved_bytes: 0,
        observed_free_bytes: 0,
        observed_at: wire::go_zero_time(),
    }
}
fn empty_confirm() -> AllocationConfirmation {
    AllocationConfirmation {
        role: ReserveRole::PostgresData,
        observed_free_bytes: 0,
        observed_at: wire::go_zero_time(),
    }
}

// --- Service methods ------------------------------------------------------

impl Service {
    /// `handleRestoreCapacityReserveConnection` — frame `0xc3`'s entry
    /// point. The peer predicate is `validate_helper_peer` — not
    /// `validate_peer` (that names the engine child) and not the
    /// blanket root gate (that cannot tell the helper from any other
    /// root process) — run *before* a single frame byte is read.
    pub(crate) fn handle_restore_capacity_reserve_connection(
        &self,
        conn: &mut DeadlineStream,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if self.restore_launches.is_none() || self.restore_capacity_reserves.is_none() {
            protocol::write_deny(conn, "unknown", ReserveRefusal::Unavailable.as_str());
            return Err(Failure::internal(
                "broker_restore_capacity",
                "broker: restore capacity reserve store unavailable",
            ));
        }
        let Some(launches) = self.restore_launches.as_ref() else {
            protocol::write_deny(conn, "unknown", ReserveRefusal::Unavailable.as_str());
            return Err(Failure::internal(
                "broker_restore_capacity",
                "broker: restore capacity launch store unavailable",
            ));
        };
        let binding = match launches.validate_helper_peer(peer) {
            Ok(b) => b,
            Err(e) => {
                protocol::write_deny(conn, "unknown", ReserveRefusal::PeerDenied.as_str());
                return Err(e);
            }
        };
        let request = match read_request(conn) {
            Ok(request) => request,
            Err(e) => {
                protocol::write_deny(conn, "unknown", ReserveRefusal::FrameInvalid.as_str());
                return Err(e);
            }
        };
        self.handle_restore_capacity_reserve_transport(
            conn,
            &request,
            binding,
            OffsetDateTime::now_utc(),
        )
    }

    /// `handleRestoreCapacityReserveTransport` — persist one
    /// already-parsed reserve write from an already-validated helper.
    pub(crate) fn handle_restore_capacity_reserve_transport(
        &self,
        conn: &mut DeadlineStream,
        request: &ReserveRequest,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        if self.restore_capacity_reserves.is_none()
            || binding.launch_evidence_id.is_nil()
            || wire::is_go_zero_time(now)
        {
            return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
        }
        match request.kind {
            SET_KIND => {
                let Some(reserves) = self.restore_capacity_reserves.as_ref() else {
                    return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
                };
                let mut intent = request.set.clone();
                // Both of these are the daemon's to decide, not the
                // caller's: the launch evidence id ties the set to the
                // launch that admitted this very connection; the
                // absolute expiry is the fixed 8-hour window.
                intent.launch_evidence_id = binding.launch_evidence_id;
                intent.absolute_expires_at = now + RESERVE_ABSOLUTE_LIFETIME;
                let record = match reserves.create_set_intent(intent, now) {
                    Ok(r) => r,
                    Err(_) => return Self::reserve_denied(conn, ReserveRefusal::Unavailable),
                };
                // The set is left unbound: under "verify allocates" the
                // operation does not exist yet; `0xc4` kind 3 binds it.
                write_reserve_accept(conn, record.set_id, false)
            }
            MEMBER_KIND => self.member_restore_capacity_reserve(conn, request, binding, now),
            CONFIRM_KIND => self.confirm_restore_capacity_reserve(conn, request, binding, now),
            _ => Self::reserve_denied(conn, ReserveRefusal::FrameInvalid),
        }
    }

    /// `denied` — write the refusal and treat the frame as handled.
    fn reserve_denied(conn: &mut DeadlineStream, reason: ReserveRefusal) -> Result<(), Failure> {
        protocol::write_deny(conn, "unknown", reason.as_str());
        Ok(())
    }

    /// `restoreCapacityReserveReadRefusal` — absent and
    /// present-but-unparsable are the same eligibility answer; every
    /// other store failure takes the store bucket.
    fn reserve_set_read_refusal(e: &Failure) -> ReserveRefusal {
        if super::is_reserve_not_found(e) || super::is_reserve_ambiguous(e) {
            ReserveRefusal::StateInvalid
        } else {
            ReserveRefusal::Unavailable
        }
    }

    /// Kind 2: persist one member intent against an intent-state,
    /// same-launch, unexpired set.
    fn member_restore_capacity_reserve(
        &self,
        conn: &mut DeadlineStream,
        request: &ReserveRequest,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let Some(reserves) = self.restore_capacity_reserves.as_ref() else {
            return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
        };
        let set = match reserves.read_set(request.set_id) {
            Ok(s) => s,
            Err(e) => return Self::reserve_denied(conn, Self::reserve_set_read_refusal(&e)),
        };
        // The set × launch check — without it an admitted helper could
        // add members to any set on the host, including one bound to a
        // different launch.
        if set.launch_evidence_id != binding.launch_evidence_id {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        // Members are recorded before anything is allocated, so the
        // only set state that admits a member write is intent.
        if set.state != ReserveState::Intent {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        if now >= set.absolute_expires_at {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        // A helper-recorded observation must be in the past and no
        // older than the set's whole lifetime.
        if request.member.observed_at > now
            || request.member.observed_at <= now - RESERVE_ABSOLUTE_LIFETIME
        {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        let candidate = CandidateMember {
            set_id: request.set_id,
            role: request.member.role,
            device_fingerprint: request.member.device_fingerprint.clone(),
            st_dev: request.member.st_dev,
            reserved_bytes: request.member.reserved_bytes,
            observed_free_bytes: request.member.observed_free_bytes,
            observed_at: request.member.observed_at,
        };
        let existing = reserves.read_member(request.set_id, request.member.role);
        if let (reason, false) =
            classify_member(existing.as_ref().ok(), existing.as_ref().err(), &candidate)
        {
            return Self::reserve_denied(conn, reason);
        }
        if reserves
            .create_member_intent(request.set_id, request.member.clone(), now)
            .is_err()
        {
            // CreateMemberIntent answers a genuine differing-record
            // collision and a broken store with the same error — the
            // reason is decided from the durable record, not read off
            // that error.
            let existing = reserves.read_member(request.set_id, request.member.role);
            if let (reason, false) =
                classify_member(existing.as_ref().ok(), existing.as_ref().err(), &candidate)
            {
                return Self::reserve_denied(conn, reason);
            }
            return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
        }
        let complete = self.reserve_set_complete(request.set_id);
        write_reserve_accept(conn, request.set_id, complete)
    }

    /// `restoreCapacityReserveSetComplete` — every capacity role has a
    /// durable member record that is not released. Answers from the
    /// durable records alone; fails closed on any role it cannot read.
    fn reserve_set_complete(&self, set_id: Uuid) -> bool {
        let reserves = match self.restore_capacity_reserves.as_ref() {
            Some(r) => r,
            None => return false,
        };
        RESERVE_ROLES.iter().all(|role| {
            reserves
                .read_member(set_id, *role)
                .map(|m| m.set_id == set_id && m.role == *role && m.state != ReserveState::Released)
                .unwrap_or(false)
        })
    }

    /// `restoreCapacityReserveSetAllocated` — every capacity role's
    /// member record is exactly `allocated`. The stricter test (not
    /// "allocated or later") costs nothing reachable: while the set is
    /// in intent no member can legitimately be further along.
    fn reserve_set_allocated(&self, set_id: Uuid) -> bool {
        let reserves = match self.restore_capacity_reserves.as_ref() {
            Some(r) => r,
            None => return false,
        };
        RESERVE_ROLES.iter().all(|role| {
            reserves
                .read_member(set_id, *role)
                .map(|m| {
                    m.set_id == set_id && m.role == *role && m.state == ReserveState::Allocated
                })
                .unwrap_or(false)
        })
    }

    /// `confirmRestoreCapacityReserveAllocation` — kind 3: advance one
    /// member from intent to allocated on the helper's statement that
    /// its reserve object now physically exists — but only after the
    /// daemon has opened that object for itself.
    fn confirm_restore_capacity_reserve(
        &self,
        conn: &mut DeadlineStream,
        request: &ReserveRequest,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let Some(reserves) = self.restore_capacity_reserves.as_ref() else {
            return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
        };
        let set_id = request.set_id;
        let confirmation = &request.confirm;
        let set = match reserves.read_set(set_id) {
            Ok(s) => s,
            Err(e) => return Self::reserve_denied(conn, Self::reserve_set_read_refusal(&e)),
        };
        if set.launch_evidence_id != binding.launch_evidence_id {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        // `intent` is the ordinary state; `allocated` is admitted for
        // the retry it exists to survive — the last member's
        // confirmation advances the set, and a helper whose response
        // was lost must not be refused for re-sending.
        if set.state != ReserveState::Intent && set.state != ReserveState::Allocated {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        if now >= set.absolute_expires_at {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        if confirmation.observed_at > now
            || confirmation.observed_at <= now - RESERVE_ABSOLUTE_LIFETIME
        {
            return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
        }
        let member = reserves.read_member(set_id, confirmation.role);
        let (reason, advance, already_confirmed) =
            classify_confirmation(member.as_ref().ok(), member.as_ref().err(), confirmation);
        if !advance && !already_confirmed {
            return Self::reserve_denied(conn, reason);
        }
        if advance {
            // The disk check — the reason this frame's advance is
            // evidence rather than an assertion. It runs only on the
            // advancing path: an already-confirmed member's object was
            // proven when it was confirmed.
            // `advance` is only classified over an `Ok` member.
            let Ok(member) = member else {
                return Self::reserve_denied(conn, ReserveRefusal::StateInvalid);
            };
            let (reason, present) = self.reserve_object_present(set_id, &member);
            if !present {
                return Self::reserve_denied(conn, reason);
            }
            if reserves
                .confirm_member_allocation(
                    set_id,
                    confirmation.role,
                    confirmation.observed_free_bytes,
                    confirmation.observed_at,
                    now,
                )
                .is_err()
            {
                let member = reserves.read_member(set_id, confirmation.role);
                let (retry_reason, retry_advance, retry_confirmed) = classify_confirmation(
                    member.as_ref().ok(),
                    member.as_ref().err(),
                    confirmation,
                );
                if !retry_advance && !retry_confirmed {
                    return Self::reserve_denied(conn, retry_reason);
                }
                if !retry_confirmed {
                    return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
                }
            }
        }
        // The set advance, computed from the durable member records
        // alone — attempted on the idempotent path too, so a daemon
        // that died between the last confirmation and this write does
        // not strand a fully confirmed set in intent.
        let allocated = self.reserve_set_allocated(set_id);
        if allocated
            && reserves
                .advance_set_state(set_id, ReserveState::Allocated, now)
                .is_err()
        {
            return Self::reserve_denied(conn, ReserveRefusal::Unavailable);
        }
        write_reserve_accept(conn, set_id, allocated)
    }
}

/// `CandidateMember` — the content a member intent would write, held
/// separately so `classify_member` can compare it against the durable
/// record (`sameRestoreCapacityReserveMemberIntent`).
struct CandidateMember {
    set_id: Uuid,
    role: ReserveRole,
    device_fingerprint: String,
    st_dev: u64,
    reserved_bytes: u64,
    observed_free_bytes: u64,
    observed_at: OffsetDateTime,
}

/// `classifyRestoreCapacityReserveMember` — map one durable member
/// read onto the refusal vocabulary, reporting whether the candidate
/// write may proceed. Used twice — before the create and again after
/// a failed one — so the two paths cannot drift.
fn classify_member(
    existing: Option<&ReserveMemberRecord>,
    read_err: Option<&Failure>,
    candidate: &CandidateMember,
) -> (ReserveRefusal, bool) {
    if let Some(existing) = existing {
        // A member no longer in intent — released by the sweep, or
        // already allocated — can never be re-created and can never
        // count towards completion; answering an identical re-send
        // with "accepted" would promise a set that cannot complete.
        if existing.state != ReserveState::Intent {
            return (ReserveRefusal::StateInvalid, false);
        }
        let same = existing.set_id == candidate.set_id
            && existing.role == candidate.role
            && existing.device_fingerprint == candidate.device_fingerprint
            && existing.st_dev == candidate.st_dev
            && existing.reserved_bytes == candidate.reserved_bytes
            && existing.observed_free_bytes == candidate.observed_free_bytes
            && existing.observed_at == candidate.observed_at;
        if !same {
            return (ReserveRefusal::Conflict, false);
        }
        return (ReserveRefusal::StateInvalid, true);
    }
    match read_err {
        Some(e) if super::is_reserve_not_found(e) => (ReserveRefusal::StateInvalid, true),
        // Same rule as the set side: unparseable is never admitted and
        // never reported as absent.
        Some(e) if super::is_reserve_ambiguous(e) => (ReserveRefusal::StateInvalid, false),
        Some(_) => (ReserveRefusal::Unavailable, false),
        None => (ReserveRefusal::Unavailable, false),
    }
}

/// `classifyRestoreCapacityReserveConfirmation` — map one durable
/// member read to kind 3's vocabulary: `(reason, advance,
/// already_confirmed)`. Used twice, before and after the store write.
fn classify_confirmation(
    existing: Option<&ReserveMemberRecord>,
    read_err: Option<&Failure>,
    confirmation: &AllocationConfirmation,
) -> (ReserveRefusal, bool, bool) {
    let Some(existing) = existing else {
        let reason = match read_err {
            Some(e) => Service::reserve_set_read_refusal(e),
            None => ReserveRefusal::Unavailable,
        };
        // A confirmation naming a role no intent was recorded for is
        // the advance outrunning the record it claims to be about.
        return (reason, false, false);
    };
    match existing.state {
        ReserveState::Intent => {
            // A post-allocation re-measurement cannot predate the
            // pre-allocation one the same helper recorded on this very
            // record.
            if confirmation.observed_at < existing.observed_at {
                return (ReserveRefusal::StateInvalid, false, false);
            }
            (ReserveRefusal::StateInvalid, true, false)
        }
        ReserveState::Allocated => {
            // The retry case: byte-identical is the idempotent success;
            // anything else is a disagreement the durable record wins.
            if existing.observed_free_bytes == confirmation.observed_free_bytes
                && existing.observed_at == confirmation.observed_at
            {
                (ReserveRefusal::StateInvalid, false, true)
            } else {
                (ReserveRefusal::Conflict, false, false)
            }
        }
        // Provisionally consumed, verified, or released: the reserve
        // has already been spent, decided, or given back.
        _ => (ReserveRefusal::StateInvalid, false, false),
    }
}

/// `writeRestoreCapacityReserveAccept` — status + set id + the
/// daemon's own complete/allocated answer.
fn write_reserve_accept(
    conn: &mut DeadlineStream,
    set_id: Uuid,
    complete: bool,
) -> Result<(), Failure> {
    let mut frame = [0u8; ACCEPT_FRAME_SIZE];
    frame[0] = ACCEPT_STATUS;
    frame[1..17].copy_from_slice(set_id.as_bytes());
    if complete {
        frame[17] = 1;
    }
    conn.write_all(&frame).map_err(|e| {
        Failure::internal(
            "broker_restore_capacity",
            format!("broker: write restore capacity reserve acceptance: {e}"),
        )
    })
}

// --- Helper client --------------------------------------------------------

/// `RestoreCapacityReserveSetRequest` — the helper's side of kind 1.
/// Deliberately no launch-evidence, expiry, or operation field: the
/// daemon fills the first two in and `0xc4` kind 3 supplies the third.
#[derive(Debug, Clone)]
pub struct ReserveSetRequest {
    pub backup_id: Uuid,
    pub repository_binding_id: Uuid,
    pub dump_bytes: u64,
    pub object_bytes: u64,
    pub artifact_count: u64,
}

/// `RestoreCapacityReserveClient` — the root helper's side of `0xc3`.
/// Each method fixes its own kind: the helper cannot create a set
/// through a code path that only needed to add a member.
pub struct ReserveClient {
    socket_path: std::path::PathBuf,
}

impl ReserveClient {
    /// `NewRestoreCapacityReserveClient`.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `CreateReserveSet` — persist a new reserve set's intent and
    /// return the daemon-minted set id member writes address.
    pub fn create_reserve_set(&self, request: &ReserveSetRequest) -> Result<Uuid, Failure> {
        if request.backup_id.is_nil() || request.repository_binding_id.is_nil() {
            return Err(ReserveRefusal::FrameInvalid.failure());
        }
        let mut payload = Vec::with_capacity(SET_PAYLOAD_SIZE);
        payload.extend_from_slice(request.backup_id.as_bytes());
        payload.extend_from_slice(request.repository_binding_id.as_bytes());
        payload.extend_from_slice(&request.dump_bytes.to_be_bytes());
        payload.extend_from_slice(&request.object_bytes.to_be_bytes());
        payload.extend_from_slice(&request.artifact_count.to_be_bytes());
        let (set_id, _) = self.submit(SET_KIND, &payload)?;
        Ok(set_id)
    }

    /// `CreateReserveMember` — persist one role's intent; returns the
    /// daemon's completeness answer from the durable records.
    pub fn create_reserve_member(
        &self,
        set_id: Uuid,
        intent: &ReserveMemberIntent,
    ) -> Result<bool, Failure> {
        if set_id.is_nil() || wire::is_go_zero_time(intent.observed_at) {
            return Err(ReserveRefusal::FrameInvalid.failure());
        }
        let role = encode_fixed_field(intent.role.as_str(), ROLE_FIELD_SIZE)?;
        let fingerprint = encode_fixed_field(&intent.device_fingerprint, FINGERPRINT_FIELD_SIZE)?;
        let mut payload = Vec::with_capacity(MEMBER_PAYLOAD_SIZE);
        payload.extend_from_slice(set_id.as_bytes());
        payload.extend_from_slice(&role);
        payload.extend_from_slice(&fingerprint);
        payload.extend_from_slice(&intent.st_dev.to_be_bytes());
        payload.extend_from_slice(&intent.reserved_bytes.to_be_bytes());
        payload.extend_from_slice(&intent.observed_free_bytes.to_be_bytes());
        payload.extend_from_slice(&time_to_nanos(intent.observed_at).to_be_bytes());
        let (_, complete) = self.submit(MEMBER_KIND, &payload)?;
        Ok(complete)
    }

    /// `ConfirmReserveAllocation` — advance one member to allocated on
    /// the daemon's own presence check; returns its allocated answer.
    pub fn confirm_reserve_allocation(
        &self,
        set_id: Uuid,
        confirmation: &AllocationConfirmation,
    ) -> Result<bool, Failure> {
        if set_id.is_nil() || wire::is_go_zero_time(confirmation.observed_at) {
            return Err(ReserveRefusal::FrameInvalid.failure());
        }
        let role = encode_fixed_field(confirmation.role.as_str(), ROLE_FIELD_SIZE)?;
        let mut payload = Vec::with_capacity(CONFIRM_PAYLOAD_SIZE);
        payload.extend_from_slice(set_id.as_bytes());
        payload.extend_from_slice(&role);
        payload.extend_from_slice(&confirmation.observed_free_bytes.to_be_bytes());
        payload.extend_from_slice(&time_to_nanos(confirmation.observed_at).to_be_bytes());
        let (_, allocated) = self.submit(CONFIRM_KIND, &payload)?;
        Ok(allocated)
    }

    fn submit(&self, kind: u8, payload: &[u8]) -> Result<(Uuid, bool), Failure> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(ReserveRefusal::Unavailable.failure());
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| ReserveRefusal::Unavailable.failure())?;
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.push(FRAME_MARKER);
        frame.push(kind);
        frame.extend_from_slice(payload);
        conn.write_all(&frame)
            .map_err(|_| ReserveRefusal::Unavailable.failure())?;
        let mut response = [0u8; 4096];
        let n = conn
            .read(&mut response)
            .map_err(|_| ReserveRefusal::Unavailable.failure())?;
        if n == 0 {
            return Err(ReserveRefusal::Unavailable.failure());
        }
        if response[0] != ACCEPT_STATUS {
            return Err(denial_reason(&response[..n]).failure());
        }
        if n < ACCEPT_FRAME_SIZE {
            return Err(ReserveRefusal::Unavailable.failure());
        }
        let set_id = uuid_field(&response[1..17]);
        if !valid_uuid_v7(&set_id) {
            return Err(ReserveRefusal::Unavailable.failure());
        }
        Ok((set_id, response[17] == 1))
    }
}

/// `restoreCapacityReserveDenialReason` — recover the sanitized
/// reason; anything outside this frame's closed vocabulary becomes
/// `Unavailable`.
fn denial_reason(raw: &[u8]) -> ReserveRefusal {
    #[derive(serde::Deserialize)]
    struct Evidence {
        message: String,
    }
    #[derive(serde::Deserialize)]
    struct Response {
        outcome: String,
        evidence: Evidence,
    }
    if raw.is_empty() || raw.len() > 4096 {
        return ReserveRefusal::Unavailable;
    }
    let text = std::str::from_utf8(raw)
        .unwrap_or("")
        .trim_end_matches('\n');
    match serde_json::from_str::<Response>(text) {
        Ok(resp) if resp.outcome == "denied" => {
            ReserveRefusal::from_str(&resp.evidence.message).unwrap_or(ReserveRefusal::Unavailable)
        }
        _ => ReserveRefusal::Unavailable,
    }
}
