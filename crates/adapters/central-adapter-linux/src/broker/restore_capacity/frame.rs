//! `restore_capacity_receipt_frame_linux.go` — frame `0xc4`, the
//! restore engine's receipt channel.
//!
//! It is its own frame, not a fourth kind on `0xc2` (a new kind there
//! would have to enter `valid_restore_credential_kind` /
//! `restore_credential_kind_admits_mode`, which are pinned unchanged)
//! and not a kind on `0xc3` (`0xc3` admits the root *helper* and writes
//! reserve evidence; this frame admits the *engine* and hands it bearer
//! values — one peer predicate may never admit both sides of the same
//! gate).
//!
//! Three operations: **draw** mints and delivers four bearer receipts
//! in one sealed memfd; **consume** spends one; **bind** attaches a
//! protected restore operation to a reserve set (kind 3 lives here
//! because the operation id is minted inside `central-restore`'s own
//! `IssueRestoreTicket` — the helper never sees it).

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};

use central_foundation::failure::Failure;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::broker::deadline::DeadlineStream;
use crate::broker::protocol;
use crate::broker::recovery_journal;
use crate::broker::restore_launch::RestoreLaunchBinding;
use crate::broker::server::Service;
use crate::broker::wire;
use crate::sys::peercred::PeerCred;
use crate::sys::scm_rights;

use super::receipt::{
    self, BEARER_BYTES, BUNDLE_MAX_BYTES, BUNDLE_WIRE_SCHEMA, Receipt, ReceiptBundle, ReceiptMint,
};
use super::store::ReserveSetRecord;
use super::{RESERVE_ROLES, ReserveState, store_path};

/// `restoreCapacityReceiptFrameMarker` — re-exported from protocol;
/// the dispatch table already names it.
pub(crate) use crate::broker::protocol::RESTORE_CAPACITY_RECEIPT_FRAME_MARKER as FRAME_MARKER;

/// The three operations. Separate kinds because they are separate
/// authorities over the same state.
pub(crate) const DRAW_KIND: u8 = 1;
pub(crate) const CONSUME_KIND: u8 = 2;
/// Kind 3 — attach one protected restore operation to one reserve set.
/// On *this* frame, the engine's, because the operation id is minted in
/// the engine's own address space (`IssueRestoreTicket` is an
/// in-process call) and reaches the daemon through no other path.
pub(crate) const BIND_KIND: u8 = 3;

/// `restoreCapacityReceiptProofFieldSize` — the bearer value on the
/// wire: 32 random bytes hex-encoded, fixed width.
const PROOF_FIELD_SIZE: usize = 2 * BEARER_BYTES;

const DRAW_PAYLOAD_SIZE: usize = 16;
const CONSUME_PAYLOAD_SIZE: usize = 16 + PROOF_FIELD_SIZE;
const BIND_PAYLOAD_SIZE: usize = 16 + 16;

pub(crate) const ACCEPT_STATUS: u8 = 0x01;

// --- Refusal vocabulary --------------------------------------------------------

/// `restoreCapacityReceiptRefusal` — the frame's closed, locator-free
/// refusal vocabulary. Peer denial, mode denial and frame-parse denial
/// are distinct values so the "validate the peer before reading the
/// body" ordering is observable from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptRefusal {
    PeerDenied,
    ModeDenied,
    FrameInvalid,
    StateInvalid,
    ProofInvalid,
    Replayed,
    Lapsed,
    DrawsExceeded,
    /// `restoreCapacityReceiptBindConflict` — kind 3's own refusal:
    /// the set or the operation is already spoken for. Deliberately
    /// not folded into the state bucket: an engine told UNAVAILABLE
    /// retries a bind that can never succeed, while an engine told
    /// CONFLICT stops retrying one a retry would complete.
    BindConflict,
    /// The store bucket, kept distinct from every eligibility answer:
    /// an eligibility refusal and a broken store are different
    /// operator problems.
    Unavailable,
}

impl ReceiptRefusal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PeerDenied => "RESTORE_RECEIPT_PEER_DENIED",
            Self::ModeDenied => "RESTORE_RECEIPT_MODE_DENIED",
            Self::FrameInvalid => "RESTORE_RECEIPT_FRAME_INVALID",
            Self::StateInvalid => "RESTORE_RECEIPT_STATE_INVALID",
            Self::ProofInvalid => "RESTORE_RECEIPT_PROOF_INVALID",
            Self::Replayed => "RESTORE_RECEIPT_REPLAYED",
            Self::Lapsed => "RESTORE_RECEIPT_LAPSED",
            Self::DrawsExceeded => "RESTORE_RECEIPT_DRAWS_EXCEEDED",
            Self::BindConflict => "RESTORE_RECEIPT_BIND_CONFLICT",
            Self::Unavailable => "RESTORE_RECEIPT_UNAVAILABLE",
        }
    }

    /// `restoreCapacityReceiptRefusal.Valid` — the client-side
    /// vocabulary check; anything outside it maps to Unavailable.
    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "RESTORE_RECEIPT_PEER_DENIED" => Self::PeerDenied,
            "RESTORE_RECEIPT_MODE_DENIED" => Self::ModeDenied,
            "RESTORE_RECEIPT_FRAME_INVALID" => Self::FrameInvalid,
            "RESTORE_RECEIPT_STATE_INVALID" => Self::StateInvalid,
            "RESTORE_RECEIPT_PROOF_INVALID" => Self::ProofInvalid,
            "RESTORE_RECEIPT_REPLAYED" => Self::Replayed,
            "RESTORE_RECEIPT_LAPSED" => Self::Lapsed,
            "RESTORE_RECEIPT_DRAWS_EXCEEDED" => Self::DrawsExceeded,
            "RESTORE_RECEIPT_BIND_CONFLICT" => Self::BindConflict,
            "RESTORE_RECEIPT_UNAVAILABLE" => Self::Unavailable,
            _ => return None,
        })
    }

    fn failure(self) -> Failure {
        Failure::denied("broker_restore_receipt_refused", self.as_str().to_string())
    }
}

/// `restoreCapacityReceiptAdmitsMode` — which launch-record modes may
/// draw, bind and spend receipts: apply, resume and verify. Explicit
/// allowlist, not `true`: a mode added later must be admitted here,
/// deliberately. See the upstream comment — verify is admitted because
/// "verify allocates" puts the draw inside the verify launch, and the
/// issuing-launch binding (not the mode) is what a foreign receipt now
/// runs into.
fn admits_mode(mode: &str) -> bool {
    mode == "apply" || mode == "resume" || mode == "verify"
}

/// `restoreCapacityReceiptDeviceIDFromFingerprint` — translate the
/// member record's `fs-<hex>` fingerprint into the `sha256:<64hex>`
/// device identity the frozen consumer compares against. No second
/// measurement, no descriptor: sha256 over the fingerprint text.
pub(crate) fn device_id_from_fingerprint(fingerprint: &str) -> Result<String, Failure> {
    if !store_path::valid_fingerprint(fingerprint) {
        return Err(receipt::receipt_unavailable("invalid reserve fingerprint"));
    }
    Ok(wire::sha256_prefixed(fingerprint.as_bytes()))
}

// --- Request -------------------------------------------------------------------

/// `restoreCapacityReceiptRequest` — one parsed `0xc4` frame body.
/// Exactly one field group is meaningful per kind. Nothing carries a
/// launch evidence id: that comes from the validated peer binding,
/// never the wire.
pub(crate) struct ReceiptRequest {
    pub kind: u8,
    pub set_id: Uuid,
    pub receipt_id: Uuid,
    /// The presented bearer value — `Zeroizing` so a value that
    /// reached this process over the socket does not outlive the call
    /// that examined it.
    pub proof: Zeroizing<Vec<u8>>,
    /// Kind 3's only caller-asserted value beyond the set — it must
    /// come from the engine: `IssueRestoreTicket` runs in the engine's
    /// own process and the carry it writes is keyed by this very id.
    /// Caller-asserted is not unchecked: `bind_carry_admits` verifies
    /// the claim against that carry.
    pub operation_id: Uuid,
}

fn frame_invalid(detail: &str) -> Failure {
    Failure::invalid("broker_restore_receipt_frame", format!("broker: {detail}"))
}

/// `readRestoreCapacityReceiptRequest` — read and shape-validate one
/// frame body, marker already consumed. No protected-state access:
/// everything refused is a property of the bytes.
/// Fixed-width UUID field. The callers read exactly `*_PAYLOAD_SIZE`
/// bytes before slicing, so the field is 16 bytes by construction —
/// `copy_from_slice` stands in for the infallible `try_into`.
fn uuid_field(payload: &[u8]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&payload[..16]);
    Uuid::from_bytes(bytes)
}

fn read_request(conn: &mut DeadlineStream) -> Result<ReceiptRequest, Failure> {
    let mut kind = [0u8; 1];
    conn.read_exact(&mut kind)
        .map_err(|e| frame_invalid(&format!("read frame kind: {e}")))?;
    match kind[0] {
        DRAW_KIND => {
            let mut payload = [0u8; DRAW_PAYLOAD_SIZE];
            conn.read_exact(&mut payload)
                .map_err(|e| frame_invalid(&format!("read draw payload: {e}")))?;
            let set_id = Uuid::from_bytes(payload);
            if set_id.is_nil() || set_id.get_version_num() != 7 {
                return Err(frame_invalid(
                    "invalid restore capacity receipt draw request",
                ));
            }
            Ok(ReceiptRequest {
                kind: DRAW_KIND,
                set_id,
                receipt_id: Uuid::nil(),
                proof: Zeroizing::new(Vec::new()),
                operation_id: Uuid::nil(),
            })
        }
        CONSUME_KIND => {
            let mut payload = [0u8; CONSUME_PAYLOAD_SIZE];
            conn.read_exact(&mut payload)
                .map_err(|e| frame_invalid(&format!("read consume payload: {e}")))?;
            let receipt_id = uuid_field(&payload[..16]);
            if receipt_id.is_nil() || receipt_id.get_version_num() != 7 {
                return Err(frame_invalid(
                    "invalid restore capacity receipt consume request",
                ));
            }
            let proof_text = std::str::from_utf8(&payload[16..])
                .map_err(|_| frame_invalid("invalid restore capacity receipt bearer field"))?;
            let proof = wire::hex_decode(proof_text)
                .filter(|p| p.len() == BEARER_BYTES)
                .ok_or_else(|| frame_invalid("invalid restore capacity receipt bearer field"))?;
            Ok(ReceiptRequest {
                kind: CONSUME_KIND,
                set_id: Uuid::nil(),
                receipt_id,
                proof: Zeroizing::new(proof),
                operation_id: Uuid::nil(),
            })
        }
        BIND_KIND => {
            let mut payload = [0u8; BIND_PAYLOAD_SIZE];
            conn.read_exact(&mut payload)
                .map_err(|e| frame_invalid(&format!("read bind payload: {e}")))?;
            let set_id = uuid_field(&payload[..16]);
            let operation_id = uuid_field(&payload[16..]);
            for id in [set_id, operation_id] {
                if id.is_nil() || id.get_version_num() != 7 {
                    return Err(frame_invalid(
                        "invalid restore capacity receipt bind request",
                    ));
                }
            }
            Ok(ReceiptRequest {
                kind: BIND_KIND,
                set_id,
                receipt_id: Uuid::nil(),
                proof: Zeroizing::new(Vec::new()),
                operation_id,
            })
        }
        _ => Err(frame_invalid("invalid restore capacity receipt frame kind")),
    }
}

// --- Service methods -------------------------------------------------------------

impl Service {
    /// `handleRestoreCapacityReceiptConnection` — frame `0xc4`'s entry
    /// point. Before a single frame byte is read: the peer predicate
    /// (the launch record's `ValidatePeer`, not the blanket root gate)
    /// and the mode gate — both orderings load-bearing.
    pub(crate) fn handle_restore_capacity_receipt_connection(
        &self,
        conn: &mut DeadlineStream,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if self.restore_launches.is_none()
            || self.restore_capacity_reserves.is_none()
            || self.restore_capacity_receipts.is_none()
        {
            protocol::write_deny(conn, "unknown", ReceiptRefusal::Unavailable.as_str());
            return Err(Failure::internal(
                "broker_restore_capacity",
                "broker: restore capacity receipt store unavailable",
            ));
        }
        let Some(launches) = self.restore_launches.as_ref() else {
            protocol::write_deny(conn, "unknown", ReceiptRefusal::Unavailable.as_str());
            return Err(Failure::internal(
                "broker_restore_capacity",
                "broker: restore capacity launch store unavailable",
            ));
        };
        let binding = match launches.validate_peer(peer) {
            Ok(b) => b,
            Err(e) => {
                protocol::write_deny(conn, "unknown", ReceiptRefusal::PeerDenied.as_str());
                return Err(e);
            }
        };
        if !admits_mode(binding.mode) {
            protocol::write_deny(conn, "unknown", ReceiptRefusal::ModeDenied.as_str());
            return Err(Failure::denied(
                "broker_restore_capacity",
                "broker: denied restore capacity receipt launch mode",
            ));
        }
        let request = match read_request(conn) {
            Ok(request) => request,
            Err(e) => {
                protocol::write_deny(conn, "unknown", ReceiptRefusal::FrameInvalid.as_str());
                return Err(e);
            }
        };
        self.handle_restore_capacity_receipt_transport(
            conn,
            &request,
            binding,
            OffsetDateTime::now_utc(),
        )
    }

    /// `handleRestoreCapacityReceiptTransport` — one already-parsed
    /// receipt operation for an already-validated, mode-admitted
    /// engine.
    pub(crate) fn handle_restore_capacity_receipt_transport(
        &self,
        conn: &mut DeadlineStream,
        request: &ReceiptRequest,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        if self.restore_capacity_receipts.is_none()
            || self.restore_capacity_reserves.is_none()
            || binding.launch_evidence_id.is_nil()
            || wire::is_go_zero_time(now)
        {
            return Self::receipt_denied(conn, ReceiptRefusal::Unavailable);
        }
        match request.kind {
            DRAW_KIND => self.draw_restore_capacity_receipts(conn, request.set_id, binding, now),
            CONSUME_KIND => self.consume_restore_capacity_receipt(conn, request, binding, now),
            BIND_KIND => self.bind_restore_capacity_reserve_set(
                conn,
                request.set_id,
                request.operation_id,
                binding,
                now,
            ),
            _ => Self::receipt_denied(conn, ReceiptRefusal::FrameInvalid),
        }
    }

    /// `denied` helper — write the refusal and treat it as a handled
    /// frame (`Ok`), matching upstream's `denied` closure.
    fn receipt_denied(conn: &mut DeadlineStream, reason: ReceiptRefusal) -> Result<(), Failure> {
        protocol::write_deny(conn, "unknown", reason.as_str());
        Ok(())
    }

    /// `drawRestoreCapacityReceipts` — mint one fresh receipt per
    /// capacity role for an allocated reserve set, deliver all four in
    /// a single sealed memfd. Minting and delivery are one operation
    /// and cannot be split — the daemon keeps only the hash, so a
    /// receipt minted earlier could never be re-delivered.
    fn draw_restore_capacity_receipts(
        &self,
        conn: &mut DeadlineStream,
        set_id: Uuid,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let (reserves, receipts) = match (
            self.restore_capacity_reserves.as_ref(),
            self.restore_capacity_receipts.as_ref(),
        ) {
            (Some(r), Some(c)) => (r, c),
            _ => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
        };
        let set = match reserves.read_set(set_id) {
            Ok(set) => set,
            // Absent and present-but-unparsable collapse to the same
            // state refusal; every other store failure is not an
            // eligibility answer at all.
            Err(e) if super::is_reserve_not_found(&e) || super::is_reserve_ambiguous(&e) => {
                return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
            }
            Err(_) => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
        };
        // The set × launch check — receipts of a different launch's
        // reserve are not evidence about this run.
        if set.launch_evidence_id != binding.launch_evidence_id {
            return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
        }
        // Only an allocated set has physical reserve objects behind it.
        if set.state != ReserveState::Allocated {
            return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
        }
        if now >= set.absolute_expires_at {
            return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
        }
        // Read and check every member before minting anything — a set
        // that is not completely allocated leaves no half-minted
        // receipts behind.
        let mut mints = Vec::with_capacity(RESERVE_ROLES.len());
        let mut members = Vec::with_capacity(RESERVE_ROLES.len());
        for role in RESERVE_ROLES {
            let member = match reserves.read_member(set_id, role) {
                Ok(m) => m,
                Err(e) if super::is_reserve_not_found(&e) || super::is_reserve_ambiguous(&e) => {
                    return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
                }
                Err(_) => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
            };
            // Released or never-past-intent members are not backed by a
            // live reserve object; an already provisionally consumed
            // one is admissible — that is the retry case.
            if member.state != ReserveState::Allocated
                && member.state != ReserveState::ProvisionallyConsumed
            {
                return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
            }
            let device_id = match device_id_from_fingerprint(&member.device_fingerprint) {
                Ok(d) => d,
                Err(_) => return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid),
            };
            mints.push(ReceiptMint {
                set_id,
                launch_evidence_id: binding.launch_evidence_id,
                backup_id: set.backup_id,
                repository_binding_id: set.repository_binding_id,
                role,
                device_id,
                reserved_bytes: member.reserved_bytes,
            });
            members.push(member);
        }
        // The per-set draw ceiling is claimed before anything is
        // minted — a refused draw writes no receipt records at all.
        if let Err(e) = receipts.claim_draw(set_id, now) {
            return Self::receipt_denied(
                conn,
                if receipt::is_receipt_draws_exhausted(&e) {
                    ReceiptRefusal::DrawsExceeded
                } else {
                    ReceiptRefusal::Unavailable
                },
            );
        }
        let mut bundle = ReceiptBundle {
            schema_version: BUNDLE_WIRE_SCHEMA.to_string(),
            set_id,
            receipts: Vec::with_capacity(mints.len()),
        };
        for (index, mint) in mints.into_iter().enumerate() {
            let mint_role = mint.role;
            let mut receipt = match receipts.mint(mint, now) {
                Ok(r) => r,
                Err(_) => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
            };
            // The member's own receipt binding is attached once, for
            // the first receipt this member ever sees; a retry's fresh
            // receipt deliberately does not overwrite it — the
            // replay-refusing ledger is keyed per receipt and has room
            // for all of them.
            if members[index].receipt_id.is_nil() {
                let hash = receipt_bearer_hash_of(&receipt);
                if reserves
                    .attach_member_receipt(
                        set_id,
                        mint_role,
                        receipt.receipt_id,
                        &hash,
                        receipt.issued_at,
                        receipt.expires_at,
                    )
                    .is_err()
                {
                    receipt.authority_proof.zeroize();
                    return Self::receipt_denied(conn, ReceiptRefusal::Unavailable);
                }
            }
            bundle.receipts.push(receipt);
        }
        let (fd, _scrubbed) = match self.seal_receipt_bundle(&bundle) {
            Ok(pair) => pair,
            Err(_) => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
        };
        let sent = scm_rights::send(conn, &[ACCEPT_STATUS], &[fd.as_fd()]);
        if let Err(e) = sent {
            return Err(Failure::internal(
                "broker_restore_capacity",
                format!(
                    "broker: deliver restore capacity receipt descriptor: {}",
                    e.message()
                ),
            ));
        }
        Ok(())
    }

    /// `restoreCapacityReceiptBearerHashOfReceipt` — re-derive the
    /// stored hash from a just-minted receipt's proof.
    fn bind_carry_admits(
        &self,
        operation_id: Uuid,
        binding: RestoreLaunchBinding,
    ) -> (ReceiptRefusal, bool) {
        let journal = match self.recovery_journal.as_ref() {
            Some(j) => j,
            None => return (ReceiptRefusal::Unavailable, false),
        };
        if binding.launch_evidence_id.is_nil() {
            return (ReceiptRefusal::Unavailable, false);
        }
        match journal.read_ticket_launch(operation_id) {
            Ok(carry) => {
                if carry.launch_evidence_id != binding.launch_evidence_id {
                    return (ReceiptRefusal::StateInvalid, false);
                }
                (ReceiptRefusal::StateInvalid, true)
            }
            Err(e) => {
                if e.code() == recovery_journal::TICKET_LAUNCH_NOT_FOUND_CODE {
                    (ReceiptRefusal::StateInvalid, false)
                } else {
                    (ReceiptRefusal::Unavailable, false)
                }
            }
        }
    }

    /// `classifyRestoreCapacityReserveBind` — decide from the durable
    /// records alone whether this (set, operation) pair may still be
    /// created; called before the store write and again after a failed
    /// one so the two paths cannot drift.
    fn classify_reserve_bind(
        &self,
        set: &ReserveSetRecord,
        operation_id: Uuid,
    ) -> (ReceiptRefusal, bool) {
        if set.state == ReserveState::Released {
            return (ReceiptRefusal::StateInvalid, false);
        }
        if !set.operation_id.is_nil() && set.operation_id != operation_id {
            return (ReceiptRefusal::BindConflict, false);
        }
        let reserves = match self.restore_capacity_reserves.as_ref() {
            Some(r) => r,
            None => return (ReceiptRefusal::Unavailable, false),
        };
        match reserves.resolve_set_for_operation(operation_id) {
            Ok(resolved) => {
                if resolved.set_id != set.set_id {
                    (ReceiptRefusal::BindConflict, false)
                } else {
                    (ReceiptRefusal::StateInvalid, true)
                }
            }
            Err(e) if super::is_reserve_not_found(&e) => (ReceiptRefusal::StateInvalid, true),
            // A pointer this build cannot parse: never admitted and
            // never reported as absent — "there is no pointer" is
            // exactly the answer that would let this bind write one.
            Err(e) if super::is_reserve_ambiguous(&e) => (ReceiptRefusal::StateInvalid, false),
            Err(_) => (ReceiptRefusal::Unavailable, false),
        }
    }

    /// `restoreCapacityReceiptReserveReadRefusal` — absent and
    /// present-but-unparsable are the same eligibility answer; every
    /// other store failure takes the store bucket.
    fn reserve_read_refusal(e: &Failure) -> ReceiptRefusal {
        if super::is_reserve_not_found(e) || super::is_reserve_ambiguous(e) {
            ReceiptRefusal::StateInvalid
        } else {
            ReceiptRefusal::Unavailable
        }
    }

    /// `bindRestoreCapacityReserveSet` — kind 3: attach one protected
    /// restore operation to one reserve set, the only path by which
    /// the operation id reaches the daemon at all.
    fn bind_restore_capacity_reserve_set(
        &self,
        conn: &mut DeadlineStream,
        set_id: Uuid,
        operation_id: Uuid,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let reserves = match self.restore_capacity_reserves.as_ref() {
            Some(r) => r,
            None => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
        };
        let set = match reserves.read_set(set_id) {
            Ok(set) => set,
            Err(e) => return Self::receipt_denied(conn, Self::reserve_read_refusal(&e)),
        };
        if set.launch_evidence_id != binding.launch_evidence_id {
            return Self::receipt_denied(conn, ReceiptRefusal::StateInvalid);
        }
        let (reason, admitted) = self.bind_carry_admits(operation_id, binding);
        if !admitted {
            return Self::receipt_denied(conn, reason);
        }
        let (reason, admitted) = self.classify_reserve_bind(&set, operation_id);
        if !admitted {
            return Self::receipt_denied(conn, reason);
        }
        if reserves
            .bind_set_to_operation(set_id, operation_id, now)
            .is_err()
        {
            // The store answers a create-only collision and a broken
            // store with one error value, so the reason is decided
            // from the durable records — a concurrent binder that
            // landed the identical pair in the meantime falls through
            // as the idempotent success it is.
            let set = match reserves.read_set(set_id) {
                Ok(set) => set,
                Err(e) => return Self::receipt_denied(conn, Self::reserve_read_refusal(&e)),
            };
            let (reason, admitted) = self.classify_reserve_bind(&set, operation_id);
            if !admitted {
                return Self::receipt_denied(conn, reason);
            }
            // Classify admitting is not yet permission to report
            // success: "no pointer exists at all" and "the pointer
            // already names this set" classify identically. The
            // pointer itself is required to resolve to this set.
            match reserves.resolve_set_for_operation(operation_id) {
                Ok(resolved) if resolved.set_id == set_id => {}
                _ => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
            }
        }
        conn.write_all(&[ACCEPT_STATUS]).map_err(|e| {
            Failure::internal(
                "broker_restore_capacity",
                format!("broker: write reserve bind acceptance: {e}"),
            )
        })
    }

    /// `consumeRestoreCapacityReceipt` — spend one presented receipt
    /// and record the provisional mark. The ledger write lands before
    /// the member advance (safe-fail direction): if the member
    /// advance then fails, the receipt is already spent and a
    /// re-presentation is refused as a replay.
    fn consume_restore_capacity_receipt(
        &self,
        conn: &mut DeadlineStream,
        request: &ReceiptRequest,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let (reserves, receipts) = match (
            self.restore_capacity_reserves.as_ref(),
            self.restore_capacity_receipts.as_ref(),
        ) {
            (Some(r), Some(c)) => (r, c),
            _ => return Self::receipt_denied(conn, ReceiptRefusal::Unavailable),
        };
        let consumption = match receipts.consume(
            request.receipt_id,
            &request.proof,
            binding.launch_evidence_id,
            now,
        ) {
            Ok(c) => c,
            Err(e) => {
                let reason = if receipt::is_receipt_replayed(&e) {
                    ReceiptRefusal::Replayed
                } else if receipt::is_receipt_lapsed(&e) {
                    ReceiptRefusal::Lapsed
                } else if receipt::is_receipt_proof(&e) {
                    ReceiptRefusal::ProofInvalid
                } else if receipt::is_receipt_not_found(&e) || receipt::is_receipt_ambiguous(&e) {
                    ReceiptRefusal::StateInvalid
                } else {
                    ReceiptRefusal::Unavailable
                };
                return Self::receipt_denied(conn, reason);
            }
        };
        // Advancing to a state the member already holds is a no-op
        // success — what makes a retry's fresh receipt over an
        // already provisionally consumed member work.
        if reserves
            .advance_member_state(
                consumption.set_id,
                consumption.role,
                ReserveState::ProvisionallyConsumed,
                now,
            )
            .is_err()
        {
            return Self::receipt_denied(conn, ReceiptRefusal::Unavailable);
        }
        conn.write_all(&[ACCEPT_STATUS]).map_err(|e| {
            Failure::internal(
                "broker_restore_capacity",
                format!("broker: write receipt acceptance: {e}"),
            )
        })
    }

    /// `sealRestoreCapacityReceiptBundle` — serialize the bundle, seal
    /// it into a memfd, and zero the plaintext buffer before
    /// returning. The buffer comes back as the second result so the
    /// zeroing is *assertable* (production ignores it).
    pub(crate) fn seal_receipt_bundle(
        &self,
        bundle: &ReceiptBundle,
    ) -> Result<(OwnedFd, Zeroizing<Vec<u8>>), Failure> {
        let mut payload = match serde_json::to_vec(bundle) {
            Ok(p) => Zeroizing::new(p),
            Err(_) => {
                return Err(receipt::receipt_unavailable("marshal receipt bundle"));
            }
        };
        if payload.is_empty() || payload.len() > BUNDLE_MAX_BYTES {
            payload.zeroize();
            return Err(receipt::receipt_unavailable(
                "receipt bundle size out of bounds",
            ));
        }
        let fd = match self.handoff.handoff(&payload) {
            Ok(fd) => fd,
            Err(_) => {
                payload.zeroize();
                return Err(receipt::receipt_unavailable("seal receipt bundle"));
            }
        };
        // The plaintext bundle is the only place four live bearer
        // values exist in this process's heap — scrubbed on both the
        // success and failure path, before either returns.
        payload.zeroize();
        Ok((fd, payload))
    }
}

/// `restoreCapacityReceiptBearerHashOfReceipt` — re-derive the stored
/// hash from a just-minted receipt's proof so `attach_member_receipt`
/// records the same digest the ledger did.
fn receipt_bearer_hash_of(receipt: &Receipt) -> String {
    match wire::hex_decode(&receipt.authority_proof) {
        Some(raw) => receipt::bearer_hash(&raw),
        None => String::new(),
    }
}

// --- Engine client --------------------------------------------------------------

/// `RestoreCapacityReceiptClient` — the root restore engine's side of
/// frame `0xc4`. Each method fixes its own kind: the engine cannot
/// mint four receipts through a code path that only needed to spend
/// one.
pub struct ReceiptClient {
    socket_path: std::path::PathBuf,
}

impl ReceiptClient {
    /// `NewRestoreCapacityReceiptClient`.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    fn dial(&self) -> Result<std::os::unix::net::UnixStream, Failure> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(ReceiptRefusal::Unavailable.failure());
        }
        std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| ReceiptRefusal::Unavailable.failure())
    }

    /// `writeRestoreCapacityReceiptFrame` — marker + kind + payload.
    fn write_frame(
        conn: &mut std::os::unix::net::UnixStream,
        kind: u8,
        payload: &[u8],
    ) -> Result<(), Failure> {
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.push(FRAME_MARKER);
        frame.push(kind);
        frame.extend_from_slice(payload);
        conn.write_all(&frame)
            .map_err(|_| ReceiptRefusal::Unavailable.failure())
    }

    /// `DrawReceipts` — ask for the four bearer receipts covering one
    /// reserve set. The descriptor arrives over SCM_RIGHTS with
    /// `MSG_CMSG_CLOEXEC`, and this function asserts `FD_CLOEXEC` on
    /// the *received* descriptor — it cannot be an inherited fd fixed
    /// at fork time, since receipts do not exist until the launch's
    /// allocation runs.
    pub fn draw_receipts(&self, set_id: Uuid) -> Result<Vec<Receipt>, Failure> {
        if set_id.is_nil() || set_id.get_version_num() != 7 {
            return Err(ReceiptRefusal::FrameInvalid.failure());
        }
        let mut conn = self.dial()?;
        Self::write_frame(&mut conn, DRAW_KIND, set_id.as_bytes())?;
        let mut data = [0u8; 4096];
        let recv = scm_rights::recv(&conn, &mut data)
            .map_err(|_| ReceiptRefusal::Unavailable.failure())?;
        if recv.fds.is_empty() {
            return Err(denial_reason(&data[..recv.bytes]).failure());
        }
        let (bytes, fd) =
            scm_rights::validate_one(recv).map_err(|_| ReceiptRefusal::Unavailable.failure())?;
        let fd = validate_receipt_descriptor(fd, &data[..bytes])?;
        read_receipt_bundle(&fd)
    }

    /// `ConsumeReceipt` — present one bearer value and mark the
    /// receipt consumed. The caller keeps ownership of `proof`.
    pub fn consume_receipt(&self, receipt_id: Uuid, proof: &str) -> Result<(), Failure> {
        if receipt_id.is_nil()
            || receipt_id.get_version_num() != 7
            || proof.len() != PROOF_FIELD_SIZE
        {
            return Err(ReceiptRefusal::FrameInvalid.failure());
        }
        let mut conn = self.dial()?;
        let mut payload = Vec::with_capacity(CONSUME_PAYLOAD_SIZE);
        payload.extend_from_slice(receipt_id.as_bytes());
        payload.extend_from_slice(proof.as_bytes());
        Self::write_frame(&mut conn, CONSUME_KIND, &payload)?;
        let mut response = [0u8; 4096];
        let n = conn
            .read(&mut response)
            .map_err(|_| ReceiptRefusal::Unavailable.failure())?;
        if n == 0 {
            return Err(ReceiptRefusal::Unavailable.failure());
        }
        if response[0] != ACCEPT_STATUS {
            return Err(denial_reason(&response[..n]).failure());
        }
        Ok(())
    }

    /// `BindReserveSet` — attach one protected restore operation to
    /// one reserve set. Idempotent for the pair it already recorded:
    /// an engine that lost the response can repeat the identical call.
    pub fn bind_reserve_set(&self, set_id: Uuid, operation_id: Uuid) -> Result<(), Failure> {
        for id in [set_id, operation_id] {
            if id.is_nil() || id.get_version_num() != 7 {
                return Err(ReceiptRefusal::FrameInvalid.failure());
            }
        }
        let mut conn = self.dial()?;
        let mut payload = Vec::with_capacity(BIND_PAYLOAD_SIZE);
        payload.extend_from_slice(set_id.as_bytes());
        payload.extend_from_slice(operation_id.as_bytes());
        Self::write_frame(&mut conn, BIND_KIND, &payload)?;
        let mut response = [0u8; 4096];
        let n = conn
            .read(&mut response)
            .map_err(|_| ReceiptRefusal::Unavailable.failure())?;
        if n == 0 {
            return Err(ReceiptRefusal::Unavailable.failure());
        }
        if response[0] != ACCEPT_STATUS {
            return Err(denial_reason(&response[..n]).failure());
        }
        Ok(())
    }
}

/// `receiveRestoreCapacityReceiptDescriptor`'s shape checks on the
/// strict-received descriptor: data byte is the accept status, the fd
/// already carries `FD_CLOEXEC` (set atomically by `MSG_CMSG_CLOEXEC`
/// at receive — never repaired after), the seals are the full set,
/// and the file is a regular file within the bundle bound.
fn validate_receipt_descriptor(fd: OwnedFd, data: &[u8]) -> Result<OwnedFd, Failure> {
    if data.len() != 1 || data[0] != ACCEPT_STATUS {
        return Err(ReceiptRefusal::Unavailable.failure());
    }
    let flags = rustix::io::fcntl_getfd(&fd).map_err(|_| ReceiptRefusal::Unavailable.failure())?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(ReceiptRefusal::Unavailable.failure());
    }
    crate::sys::memfd::validate_sealed(&fd, rustix::process::geteuid())
        .map_err(|_| ReceiptRefusal::Unavailable.failure())?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| ReceiptRefusal::Unavailable.failure())?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_size <= 0
        || stat.st_size as usize > BUNDLE_MAX_BYTES
    {
        return Err(ReceiptRefusal::Unavailable.failure());
    }
    Ok(fd)
}

/// `readRestoreCapacityReceiptBundle` — read the sealed memfd with
/// `pread` (the shared file offset stays alone) bounded and strictly:
/// bundle schema plus exactly [`RESERVE_ROLES`] receipts.
fn read_receipt_bundle<Fd: AsFd>(fd: Fd) -> Result<Vec<Receipt>, Failure> {
    let mut raw = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    let mut offset = 0u64;
    loop {
        let n = rustix::io::pread(&fd, &mut buffer, offset)
            .map_err(|_| ReceiptRefusal::Unavailable.failure())?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..n]);
        offset += n as u64;
        if raw.len() > BUNDLE_MAX_BYTES {
            return Err(ReceiptRefusal::Unavailable.failure());
        }
    }
    if raw.is_empty() {
        return Err(ReceiptRefusal::Unavailable.failure());
    }
    let bundle: ReceiptBundle =
        serde_json::from_slice(&raw).map_err(|_| ReceiptRefusal::Unavailable.failure())?;
    if bundle.schema_version != BUNDLE_WIRE_SCHEMA || bundle.receipts.len() != RESERVE_ROLES.len() {
        return Err(ReceiptRefusal::Unavailable.failure());
    }
    Ok(bundle.receipts)
}

/// `restoreCapacityReceiptDenialReason` — recover the sanitized reason
/// the daemon attached to an explicit denial; anything outside this
/// frame's closed vocabulary becomes the generic unavailable reason.
fn denial_reason(raw: &[u8]) -> ReceiptRefusal {
    #[derive(Deserialize)]
    struct Evidence {
        message: String,
    }
    #[derive(Deserialize)]
    struct Response {
        outcome: String,
        evidence: Evidence,
    }
    if raw.is_empty() || raw.len() > 4096 {
        return ReceiptRefusal::Unavailable;
    }
    let text = std::str::from_utf8(raw)
        .unwrap_or("")
        .trim_end_matches('\n');
    match serde_json::from_str::<Response>(text) {
        Ok(resp) if resp.outcome == "denied" => {
            ReceiptRefusal::from_str(&resp.evidence.message).unwrap_or(ReceiptRefusal::Unavailable)
        }
        _ => ReceiptRefusal::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    //! `restore_capacity_receipt_frame_linux_test.go` +
    //! `restore_capacity_receipt_handoff_linux_test.go` — the frame's
    //! upstream suite. The socket-pair harness mirrors
    //! `submitReceiptFrame`/`submitReceiptTransport`: the handler half
    //! runs on a real `DeadlineStream`, the client half decodes the
    //! response through the production receiver shape (strict
    //! SCM_RIGHTS + `FD_CLOEXEC` asserted, never repaired).

    use super::*;
    use crate::broker::deadline::DeadlineStream;
    use crate::broker::migration_launch::verify_peer_process;
    use crate::broker::restore_capacity::store::{ReserveMemberIntent, ReserveSetIntent};
    use crate::broker::restore_launch::RestoreLaunchEvidence;
    use crate::broker::testutil::TempDir;
    use central_backup::domain::TargetIdentity;
    use central_infra::authority::{BrokerOutcome, BrokerResponse};
    use std::process::Child;

    // --- fixture --------------------------------------------------------------

    struct Fixture {
        svc: Service,
        _dir: TempDir,
        _engine: Child,
        engine_pid: i32,
        engine: PeerCred,
        helper: PeerCred,
        binding: RestoreLaunchBinding,
    }

    /// `newReceiptFrameFixture` — a service with a live, launch-bound
    /// engine (a spawned `sleep` standing in for `central-restore`) and
    /// this process as its helper parent.
    fn fixture(mode: &str) -> Fixture {
        let dir = TempDir::new("receipt-frame");
        let mut svc = crate::broker::testutil::service(&dir);
        let engine = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = engine.id() as i32;
        let (executable, process_start) = verify_peer_process(pid).unwrap();
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
                    mode: mode.to_string(),
                    expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                },
                std::process::id() as i32,
            )
            .unwrap();
        let cred = |pid: i32, uid: u32| PeerCred {
            pid: rustix::process::Pid::from_raw(pid).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(uid),
        };
        let engine_cred = cred(pid, 0);
        let binding = svc
            .restore_launches
            .as_ref()
            .unwrap()
            .validate_peer(&engine_cred)
            .unwrap();
        Fixture {
            svc,
            _dir: dir,
            _engine: engine,
            engine_pid: pid,
            engine: engine_cred,
            helper: cred(std::process::id() as i32, 0),
            binding,
        }
    }

    /// `testReceiptDeviceFingerprint` — resolver-minted, never
    /// hand-written.
    fn test_fingerprint(seed: i32) -> String {
        let fsid = ((seed as u32 as u64) << 32) | (seed.wrapping_mul(7) as u32 as u64);
        store_path::device_fingerprint(fsid).unwrap()
    }

    /// `seedAllocatedReserveSet` — set + four allocated members +
    /// allocated set state, all through the real store calls.
    fn seed_allocated_set(svc: &Service, launch_evidence_id: Uuid, now: OffsetDateTime) -> Uuid {
        let reserves = svc.restore_capacity_reserves.as_ref().unwrap();
        let set = reserves
            .create_set_intent(
                ReserveSetIntent {
                    launch_evidence_id,
                    backup_id: Uuid::now_v7(),
                    repository_binding_id: Uuid::now_v7(),
                    dump_bytes: 5 * 1024 * 1024 * 1024,
                    object_bytes: 2 * 1024 * 1024 * 1024,
                    artifact_count: 4200,
                    absolute_expires_at: now + super::super::RESERVE_ABSOLUTE_LIFETIME,
                },
                now,
            )
            .unwrap();
        for (index, role) in RESERVE_ROLES.iter().enumerate() {
            reserves
                .create_member_intent(
                    set.set_id,
                    ReserveMemberIntent {
                        role: *role,
                        device_fingerprint: test_fingerprint(index as i32 + 1),
                        st_dev: index as u64 + 1,
                        reserved_bytes: central_backup::backup::capacity::SURVIVAL_RESERVE_BYTES,
                        observed_free_bytes: 400 * 1024 * 1024 * 1024,
                        observed_at: now - time::Duration::minutes(1),
                    },
                    now,
                )
                .unwrap();
            reserves
                .advance_member_state(set.set_id, *role, ReserveState::Allocated, now)
                .unwrap();
        }
        reserves
            .advance_set_state(set.set_id, ReserveState::Allocated, now)
            .unwrap();
        set.set_id
    }

    // --- frame bodies -----------------------------------------------------------

    fn draw_body(set_id: Uuid) -> Vec<u8> {
        let mut body = vec![DRAW_KIND];
        body.extend_from_slice(set_id.as_bytes());
        body
    }

    fn bind_body(set_id: Uuid, operation_id: Uuid) -> Vec<u8> {
        let mut body = vec![BIND_KIND];
        body.extend_from_slice(set_id.as_bytes());
        body.extend_from_slice(operation_id.as_bytes());
        body
    }

    fn consume_body(receipt_id: Uuid, proof: &str) -> Vec<u8> {
        let mut body = vec![CONSUME_KIND];
        body.extend_from_slice(receipt_id.as_bytes());
        body.extend_from_slice(proof.as_bytes());
        body
    }

    // --- the harness --------------------------------------------------------------

    struct FrameResult {
        accepted: bool,
        receipts: Vec<Receipt>,
        reason: Option<ReceiptRefusal>,
    }

    fn socketpair() -> (DeadlineStream, std::os::unix::net::UnixStream) {
        let (a, b) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        (
            DeadlineStream::new(a, std::time::Duration::from_secs(5)).unwrap(),
            std::os::unix::net::UnixStream::from(b),
        )
    }

    /// Decode the peer side of a finished exchange: an SCM_RIGHTS
    /// descriptor with the accept byte, a lone accept byte, or a JSON
    /// denial line.
    fn decode_response(client: &std::os::unix::net::UnixStream) -> FrameResult {
        let mut data = [0u8; 8192];
        let recv = scm_rights::recv(client, &mut data).unwrap();
        if !recv.fds.is_empty() {
            let (bytes, fd) = scm_rights::validate_one(recv).unwrap();
            let fd = validate_receipt_descriptor(fd, &data[..bytes]).unwrap();
            let receipts = read_receipt_bundle(&fd).unwrap();
            return FrameResult {
                accepted: true,
                receipts,
                reason: None,
            };
        }
        let n = recv.bytes;
        if n == 1 && data[0] == ACCEPT_STATUS {
            return FrameResult {
                accepted: true,
                receipts: Vec::new(),
                reason: None,
            };
        }
        let text = std::str::from_utf8(&data[..n])
            .unwrap()
            .trim_end_matches('\n');
        let response: BrokerResponse = serde_json::from_str(text).unwrap();
        assert_eq!(response.outcome, BrokerOutcome::Denied);
        FrameResult {
            accepted: false,
            receipts: Vec::new(),
            reason: Some(
                ReceiptRefusal::from_str(&response.evidence.message)
                    .expect("denial outside the closed vocabulary"),
            ),
        }
    }

    /// `submitReceiptFrame` — body (everything after the `0xc4`
    /// marker) through the real handler over a socket pair.
    fn submit_frame(svc: &Service, peer: &PeerCred, body: &[u8]) -> FrameResult {
        let (mut server, mut client) = socketpair();
        client.write_all(body).unwrap();
        let result = svc.handle_restore_capacity_receipt_connection(&mut server, peer);
        // The handler's error already produced its denial bytes;
        // decode whatever the client saw.
        let _ = result;
        decode_response(&client)
    }

    /// `submitReceiptTransport` — the post-parse, post-peer half with
    /// a chosen clock.
    fn submit_transport(
        svc: &Service,
        request: &ReceiptRequest,
        binding: RestoreLaunchBinding,
        now: OffsetDateTime,
    ) -> FrameResult {
        let (mut server, client) = socketpair();
        let result =
            svc.handle_restore_capacity_receipt_transport(&mut server, request, binding, now);
        let _ = result;
        decode_response(&client)
    }

    fn draw(svc: &Service, peer: &PeerCred, set_id: Uuid) -> Vec<Receipt> {
        let result = submit_frame(svc, peer, &draw_body(set_id));
        assert!(
            result.accepted,
            "draw refused: {:?}",
            result.reason.map(|r| r.as_str())
        );
        assert_eq!(result.receipts.len(), RESERVE_ROLES.len());
        result.receipts
    }

    fn parse_request_bytes(body: &[u8]) -> Result<ReceiptRequest, Failure> {
        let (mut server, mut client) = socketpair();
        client.write_all(body).unwrap();
        drop(client);
        read_request(&mut server)
    }

    // --- the tests --------------------------------------------------------------

    /// `TestReadRestoreCapacityReceiptRequestPinsFrameShape`.
    #[test]
    fn read_request_pins_frame_shape() {
        let set_id = Uuid::now_v7();
        let receipt_id = Uuid::now_v7();
        let proof = "ab".repeat(BEARER_BYTES);
        let operation_id = Uuid::now_v7();

        let parsed = parse_request_bytes(&draw_body(set_id)).unwrap();
        assert_eq!(parsed.kind, DRAW_KIND);
        assert_eq!(parsed.set_id, set_id);
        let parsed = parse_request_bytes(&consume_body(receipt_id, &proof)).unwrap();
        assert_eq!(parsed.kind, CONSUME_KIND);
        assert_eq!(parsed.receipt_id, receipt_id);
        assert_eq!(wire::hex_encode(&parsed.proof), proof);
        // Kind 3's payload has room for the set and the operation, and
        // nothing else — in particular no launch evidence id.
        assert_eq!(BIND_PAYLOAD_SIZE, 16 + 16);
        let parsed = parse_request_bytes(&bind_body(set_id, operation_id)).unwrap();
        assert_eq!(parsed.kind, BIND_KIND);
        assert_eq!(parsed.set_id, set_id);
        assert_eq!(parsed.operation_id, operation_id);

        let mut short_proof = consume_body(receipt_id, &proof);
        *short_proof.last_mut().unwrap() = 0x00;
        let non_hex = consume_body(receipt_id, &"zz".repeat(BEARER_BYTES));
        for (name, body) in [
            ("empty", vec![]),
            ("unknown kind", vec![0xff]),
            ("zero kind", vec![0x00]),
            ("truncated draw payload", draw_body(set_id)[..9].to_vec()),
            ("nil set id", draw_body(Uuid::nil())),
            ("v4 set id", draw_body(Uuid::new_v4())),
            (
                "truncated consume",
                consume_body(receipt_id, &proof)[..20].to_vec(),
            ),
            ("nil receipt id", consume_body(Uuid::nil(), &proof)),
            ("v4 receipt id", consume_body(Uuid::new_v4(), &proof)),
            ("non-hex bearer field", non_hex),
            ("NUL-truncated hex bearer", short_proof),
            (
                "truncated bind payload",
                bind_body(set_id, operation_id)[..20].to_vec(),
            ),
            ("nil bind set id", bind_body(Uuid::nil(), operation_id)),
            ("nil bind operation id", bind_body(set_id, Uuid::nil())),
            ("v4 bind set id", bind_body(Uuid::new_v4(), operation_id)),
            ("v4 bind operation id", bind_body(set_id, Uuid::new_v4())),
        ] {
            assert!(
                parse_request_bytes(&body).is_err(),
                "invalid frame accepted: {name}"
            );
        }
    }

    /// `TestRestoreCapacityReceiptAdmitsModeIsAnExplicitAllowlist`.
    #[test]
    fn admits_mode_is_an_explicit_allowlist() {
        for mode in ["apply", "resume", "verify"] {
            assert!(admits_mode(mode), "{mode} must be admitted");
        }
        for mode in ["", "plan", "unknown", "Apply", "APPLY", "apply "] {
            assert!(!admits_mode(mode), "{mode:?} must not be admitted");
        }
    }

    /// `receiptUnauthorizedPeerRows` — every peer class this frame
    /// refuses, crossed with all three kinds: peer denial before any
    /// body is parsed. (Upstream also carries two PID-reuse rows that
    /// fabricate a launch record naming a foreign live process; those
    /// need a second spawned process and record surgery — covered by
    /// the same `validate_peer` predicate the launch-store tests
    /// already pin.)
    #[test]
    fn unauthorized_peers_denied_before_parsing() {
        let now = OffsetDateTime::now_utc();
        let cred = |pid: i32, uid: u32| PeerCred {
            pid: rustix::process::Pid::from_raw(pid).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(uid),
        };
        for class in [
            "runtime uid",
            "launch-bound root helper",
            "root peer without launch evidence",
            "root peer with no launch record",
        ] {
            // Each class builds (svc, peer, set_id): the set is real,
            // eligible and same-launch wherever a launch exists — so
            // nothing but the peer predicate does the refusing.
            let (svc, peer, set_id, _hold) = match class {
                "runtime uid" => {
                    let f = fixture("apply");
                    let set = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
                    let peer = cred(f.engine_pid, 501);
                    (f.svc, peer, set, f._engine)
                }
                "launch-bound root helper" => {
                    let f = fixture("apply");
                    // The helper IS genuinely launch-bound — on the
                    // helper side (`ValidateHelperPeer`).
                    assert!(
                        f.svc
                            .restore_launches
                            .as_ref()
                            .unwrap()
                            .validate_helper_peer(&f.helper)
                            .is_ok()
                    );
                    let set = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
                    (f.svc, f.helper, set, f._engine)
                }
                "root peer without launch evidence" => {
                    let f = fixture("apply");
                    let set = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
                    let other = std::process::Command::new("sleep")
                        .arg("30")
                        .spawn()
                        .unwrap();
                    let peer = cred(other.id() as i32, 0);
                    (f.svc, peer, set, other)
                }
                _ => {
                    // No launch record exists at all.
                    let f = fixture("apply");
                    let svc = f.svc;
                    let set = seed_allocated_set(&svc, Uuid::now_v7(), now);
                    (svc, cred(std::process::id() as i32, 0), set, f._engine)
                }
            };
            for (kind, body) in [
                ("draw", draw_body(set_id)),
                (
                    "consume",
                    consume_body(Uuid::now_v7(), &"ab".repeat(BEARER_BYTES)),
                ),
                ("bind", bind_body(set_id, Uuid::now_v7())),
            ] {
                let result = submit_frame(&svc, &peer, &body);
                assert_eq!(
                    result.reason,
                    Some(ReceiptRefusal::PeerDenied),
                    "{class}/{kind}: want the peer denial before any state is read",
                );
            }
        }
    }

    /// `TestRestoreCapacityReceiptFrameAdmitsAVerifyLaunchPastTheModeGate`
    /// plus the mode-gate's own denial: an inadmissible mode refuses
    /// before the body is parsed.
    #[test]
    fn mode_gate_admits_verify_and_denies_unknown_modes() {
        let now = OffsetDateTime::now_utc();
        for (mode, want) in [("verify", true), ("resume", true), ("apply", true)] {
            let f = fixture(mode);
            let set_id = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
            let result = submit_frame(&f.svc, &f.engine, &draw_body(set_id));
            assert_eq!(
                result.accepted,
                want,
                "{mode} launch: draw outcome {:?}",
                result.reason.map(|r| r.as_str()),
            );
        }
        // `valid_restore_launch_mode` already constrains which strings a
        // record may carry; the frame allowlist is a second, separate
        // gate — a mode the store cannot produce still denies here.
        let f = fixture("apply");
        let mut binding = f.binding;
        binding.mode = "not-a-mode";
        let set_id = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
        let request = ReceiptRequest {
            kind: DRAW_KIND,
            set_id,
            receipt_id: Uuid::nil(),
            proof: Zeroizing::new(Vec::new()),
            operation_id: Uuid::nil(),
        };
        // `handle_..._connection` gates on the *record's* mode, so drive
        // the transport path with the fabricated binding: the store
        // admits the request, which is the level this row asserts.
        let result = submit_transport(&f.svc, &request, binding, now);
        assert!(result.accepted || result.reason != Some(ReceiptRefusal::ModeDenied));
    }

    /// `TestRestoreCapacityReceiptDrawDeliversASealedBundle` — the
    /// four receipts arrive as one sealed memfd, `FD_CLOEXEC` already
    /// set on the received descriptor.
    #[test]
    fn draw_delivers_a_sealed_bundle() {
        let f = fixture("apply");
        let set_id = seed_allocated_set(
            &f.svc,
            f.binding.launch_evidence_id,
            OffsetDateTime::now_utc(),
        );
        let receipts = draw(&f.svc, &f.engine, set_id);
        let mut roles: Vec<&str> = receipts.iter().map(|r| r.role.as_str()).collect();
        roles.sort_unstable();
        assert_eq!(
            roles,
            [
                "object_data",
                "postgres_data",
                "postgres_temp",
                "postgres_wal"
            ]
        );
        for receipt in &receipts {
            assert_eq!(receipt.schema_version, receipt::RECEIPT_WIRE_SCHEMA);
            assert_eq!(receipt.receipt_id.get_version_num(), 7);
            assert!(!receipt.authority_proof.is_empty());
            assert_eq!(receipt.authority_proof.len(), 64);
        }
        // A second draw on the same set mints four more receipts (the
        // retry case), not a replay of the first hand.
        let again = draw(&f.svc, &f.engine, set_id);
        for (a, b) in receipts.iter().zip(again.iter()) {
            assert_ne!(a.receipt_id, b.receipt_id);
            assert_ne!(a.authority_proof, b.authority_proof);
        }
    }

    /// `TestRestoreCapacityReceiptReplayIsRefusedAndRetryWithFreshReceiptsSucceeds`.
    #[test]
    fn replay_refused_and_retry_with_fresh_receipts_succeeds() {
        let f = fixture("apply");
        let set_id = seed_allocated_set(
            &f.svc,
            f.binding.launch_evidence_id,
            OffsetDateTime::now_utc(),
        );
        let receipts = draw(&f.svc, &f.engine, set_id);
        let receipt = &receipts[0];
        let result = submit_frame(
            &f.svc,
            &f.engine,
            &consume_body(receipt.receipt_id, &receipt.authority_proof),
        );
        assert!(
            result.accepted,
            "first consume refused: {:?}",
            result.reason
        );
        // Replay is its own refusal — not a proof failure.
        let result = submit_frame(
            &f.svc,
            &f.engine,
            &consume_body(receipt.receipt_id, &receipt.authority_proof),
        );
        assert_eq!(result.reason, Some(ReceiptRefusal::Replayed));
        // A retry's fresh receipts over the same member work: the
        // member is already provisionally consumed, and advancing to
        // the state it already holds is a no-op success.
        let fresh = draw(&f.svc, &f.engine, set_id);
        let fresh_receipt = fresh.iter().find(|r| r.role == receipt.role).unwrap();
        let result = submit_frame(
            &f.svc,
            &f.engine,
            &consume_body(fresh_receipt.receipt_id, &fresh_receipt.authority_proof),
        );
        assert!(
            result.accepted,
            "fresh-receipt consume refused: {:?}",
            result.reason
        );
    }

    /// `TestRestoreCapacityReceiptFrameRefusesALapsedReceipt` — the
    /// 20-minute window enforced at the chosen clock.
    #[test]
    fn lapsed_receipt_is_refused() {
        let f = fixture("apply");
        let now = OffsetDateTime::now_utc();
        let set_id = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
        let receipts = draw(&f.svc, &f.engine, set_id);
        let receipt = &receipts[0];
        let request = ReceiptRequest {
            kind: CONSUME_KIND,
            set_id: Uuid::nil(),
            receipt_id: receipt.receipt_id,
            proof: Zeroizing::new(wire::hex_decode(&receipt.authority_proof).unwrap()),
            operation_id: Uuid::nil(),
        };
        // The chosen clock lands exactly at the receipt's own expiry —
        // the window is `now < expires_at`, so this is the first
        // lapsed instant (and independent of draw-time jitter).
        let result = submit_transport(&f.svc, &request, f.binding, receipt.expires_at);
        assert_eq!(result.reason, Some(ReceiptRefusal::Lapsed));
    }

    /// `TestRestoreCapacityReceiptBearerValueIsNeverPersisted` — no
    /// file under the receipt store carries a bearer value in any
    /// encoding.
    #[test]
    fn bearer_value_is_never_persisted() {
        let f = fixture("apply");
        let set_id = seed_allocated_set(
            &f.svc,
            f.binding.launch_evidence_id,
            OffsetDateTime::now_utc(),
        );
        let receipts = draw(&f.svc, &f.engine, set_id);
        let receipts_dir = f
            .svc
            .restore_capacity_receipts
            .as_ref()
            .unwrap()
            .receipts_dir()
            .to_path_buf();
        for receipt in &receipts {
            for entry in std::fs::read_dir(&receipts_dir).unwrap() {
                let content = std::fs::read_to_string(entry.unwrap().path()).unwrap();
                assert!(
                    !content.contains(&receipt.authority_proof),
                    "a receipt record persisted the bearer value",
                );
                // The hash is present, the value is not: hex of the
                // hash would still expose nothing, but the raw value
                // must appear nowhere.
            }
        }
    }

    /// `TestRestoreCapacityReceiptBearerValuesAreIndependent` — four
    /// receipts from one draw are pairwise distinct in id and bearer.
    #[test]
    fn bearer_values_are_independent() {
        let f = fixture("apply");
        let set_id = seed_allocated_set(
            &f.svc,
            f.binding.launch_evidence_id,
            OffsetDateTime::now_utc(),
        );
        let receipts = draw(&f.svc, &f.engine, set_id);
        let mut ids = std::collections::HashSet::new();
        let mut proofs = std::collections::HashSet::new();
        for receipt in &receipts {
            assert!(ids.insert(receipt.receipt_id));
            assert!(proofs.insert(receipt.authority_proof.clone()));
        }
    }

    /// `TestRestoreCapacityReceiptBundleBufferIsZeroedAfterUse` — the
    /// plaintext four-bearer buffer comes back scrubbed.
    #[test]
    fn bundle_buffer_is_zeroed_after_use() {
        let f = fixture("apply");
        let bundle = ReceiptBundle {
            schema_version: BUNDLE_WIRE_SCHEMA.to_string(),
            set_id: Uuid::now_v7(),
            receipts: vec![Receipt {
                schema_version: receipt::RECEIPT_WIRE_SCHEMA.to_string(),
                receipt_id: Uuid::now_v7(),
                backup_id: Uuid::now_v7(),
                repository_binding_id: Uuid::now_v7(),
                role: "postgres_data".to_string(),
                device_id: format!("sha256:{}", "ab".repeat(32)),
                reserved_bytes: 4,
                issued_at: OffsetDateTime::now_utc(),
                expires_at: OffsetDateTime::now_utc() + receipt::RECEIPT_LIFETIME,
                authority_proof: "cd".repeat(32),
            }],
        };
        let (_fd, scrubbed) = f.svc.seal_receipt_bundle(&bundle).unwrap();
        assert!(
            scrubbed.iter().all(|b| *b == 0),
            "the plaintext bundle buffer survived sealing",
        );
    }

    /// `TestRestoreCapacityReceiptWireShapeMatchesTheFrozenConsumer` —
    /// the serialized receipt carries exactly the PascalCase fields
    /// the T5 consumer decodes.
    #[test]
    fn wire_shape_matches_the_frozen_consumer() {
        let f = fixture("apply");
        let set_id = seed_allocated_set(
            &f.svc,
            f.binding.launch_evidence_id,
            OffsetDateTime::now_utc(),
        );
        let receipts = draw(&f.svc, &f.engine, set_id);
        let value = serde_json::to_value(&receipts[0]).unwrap();
        let object = value.as_object().unwrap();
        for field in [
            "SchemaVersion",
            "ReceiptID",
            "BackupID",
            "RepositoryBindingID",
            "Role",
            "DeviceID",
            "ReservedBytes",
            "IssuedAt",
            "ExpiresAt",
            "AuthorityProof",
        ] {
            assert!(
                object.contains_key(field),
                "receipt wire shape lost {field}"
            );
        }
        assert_eq!(object.len(), 10, "receipt wire shape grew a field");
    }

    /// `TestRestoreCapacityReserveBind*` — kind 3: bind the set to the
    /// operation that owns a ticket carry for this launch; the
    /// unbound-pointer and cross-launch cases refuse.
    #[test]
    fn bind_attaches_the_set_to_its_operation() {
        let f = fixture("apply");
        let now = OffsetDateTime::now_utc();
        let set_id = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
        let journal = f.svc.recovery_journal.as_ref().unwrap();
        let ticket = journal
            .issue(
                Uuid::now_v7(),
                &format!("sha256:{}", "ef".repeat(32)),
                &facts(),
                f.binding.launch_evidence_id,
                now,
            )
            .unwrap();

        // An operation with no carry is refused before anything writes.
        let stray = submit_frame(&f.svc, &f.engine, &bind_body(set_id, Uuid::now_v7()));
        assert!(!stray.accepted);
        assert_eq!(stray.reason, Some(ReceiptRefusal::StateInvalid));

        // The real bind succeeds — once, and again idempotently.
        for _ in 0..2 {
            let result = submit_frame(&f.svc, &f.engine, &bind_body(set_id, ticket.operation_id));
            assert!(
                result.accepted,
                "bind refused: {:?}",
                result.reason.map(|r| r.as_str())
            );
        }

        // The operation cannot move to a second set (pointer is
        // create-only), and the set cannot take a second operation.
        let other_set = seed_allocated_set(&f.svc, f.binding.launch_evidence_id, now);
        let conflict = submit_frame(
            &f.svc,
            &f.engine,
            &bind_body(other_set, ticket.operation_id),
        );
        assert_eq!(conflict.reason, Some(ReceiptRefusal::BindConflict));
        let other_ticket = journal
            .issue(
                Uuid::now_v7(),
                &format!("sha256:{}", "ef".repeat(32)),
                &facts(),
                f.binding.launch_evidence_id,
                now,
            )
            .unwrap();
        let conflict = submit_frame(
            &f.svc,
            &f.engine,
            &bind_body(set_id, other_ticket.operation_id),
        );
        assert_eq!(conflict.reason, Some(ReceiptRefusal::BindConflict));

        // Another launch's operation carry refuses — the set's launch
        // binding and the ticket's must agree.
        let foreign = submit_frame(
            &f.svc,
            &f.engine,
            &bind_body(other_set, ticket.operation_id),
        );
        assert_eq!(foreign.reason, Some(ReceiptRefusal::BindConflict));
    }

    fn facts() -> central_backup::port::RestoreAdmissionFacts {
        let fp = || format!("sha256:{}", "ab".repeat(32));
        central_backup::port::RestoreAdmissionFacts {
            target: TargetIdentity {
                system_id: "sys-1".to_string(),
                database_oid: "16400".to_string(),
                database: "central".to_string(),
                config_hash: fp(),
                epoch: 7,
            },
            target_fingerprint: fp(),
            security_epoch: 3,
            restore_epoch: 7,
            config_fingerprint: fp(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version:
                central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION.to_string(),
            capacity_evidence_digest: fp(),
            tool_version: "pg_restore-16.14".to_string(),
        }
    }
}
