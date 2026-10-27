//! `restore_capacity_reserve_store.go` — the protected, HMAC-signed
//! home for reserve set/member records and the operation→set pointer
//! index. PostgreSQL-free: restore verify must reach this state while
//! the database itself is being restored. Serialization is the recovery
//! journal's per-record `flock` discipline over create-only and
//! atomic-replace JSON files.

use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::broker::durable;
use crate::broker::protected_file::open_protected_file;
use crate::broker::recovery_journal::generation_key;
use crate::broker::signing::SigningService;
use crate::broker::wire;

use super::{
    RESERVE_ROLES, ReserveRole, ReserveState, reserve_ambiguous, reserve_not_found,
    reserve_unavailable,
};

/// `RestoreCapacityReserveRecordSchema` — the schema string every
/// record in this store carries.
pub(crate) const RECORD_SCHEMA: &str = "central.restore-capacity-reserve-record/v1";

const DIRECTORY: &str = "restore-capacity-reserves";
const SETS_DIR: &str = "sets";
const MEMBERS_DIR: &str = "members";
const OPERATIONS_DIR: &str = "operations";

const SET_HMAC_DOMAIN: &str = "slice-c-restore-capacity-reserve-set-v1";
const MEMBER_HMAC_DOMAIN: &str = "slice-c-restore-capacity-reserve-member-v1";
const OPERATION_HMAC_DOMAIN: &str = "slice-c-restore-capacity-reserve-operation-v1";

/// `restoreCapacityReserveMaxRecordBytes` — generous headroom for a
/// fixed-cardinality record, not a sizing target.
const MAX_RECORD_BYTES: u64 = 16 * 1024;

// --- transitions ---------------------------------------------------------

/// `restoreCapacityReserveTransitionAllowed` — strictly +1 or release;
/// member records use this directly and skip nothing.
fn transition_allowed(from: ReserveState, to: ReserveState) -> bool {
    if to == ReserveState::Released {
        return from != ReserveState::Released;
    }
    (to as u8) == (from as u8) + 1
}

/// `restoreCapacityReserveSetTransitionAllowed` — member rules plus the
/// set-granularity `allocated → verified` skip the gate commits under.
fn set_transition_allowed(from: ReserveState, to: ReserveState) -> bool {
    transition_allowed(from, to)
        || (from == ReserveState::Allocated && to == ReserveState::Verified)
}

// --- set record ------------------------------------------------------------

/// `RestoreCapacityReserveSetRecord` — one reserve set bound (eventually)
/// to the operation it protects. JSON shape is the Go struct verbatim:
/// Go's `,omitempty` on `time.Time`/`uuid.UUID` fields never fires, so
/// every field is always emitted, including zero times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReserveSetRecord {
    pub schema_version: String,
    pub set_id: Uuid,
    pub operation_id: Uuid,
    pub launch_evidence_id: Uuid,
    pub backup_id: Uuid,
    pub repository_binding_id: Uuid,
    pub dump_bytes: u64,
    pub object_bytes: u64,
    pub artifact_count: u64,
    pub state: ReserveState,
    #[serde(with = "wire::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub absolute_expires_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub allocated_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub consumed_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub verified_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub released_at: OffsetDateTime,
    pub hmac: String,
}

impl ReserveSetRecord {
    /// `RestoreCapacityReserveSetRecord.valid`.
    pub(crate) fn valid(&self) -> bool {
        if self.schema_version != RECORD_SCHEMA
            || self.set_id.is_nil()
            || self.set_id.get_version_num() != 7
            || self.launch_evidence_id.is_nil()
            || self.backup_id.is_nil()
            || self.repository_binding_id.is_nil()
            || self.dump_bytes == 0
            || wire::is_go_zero_time(self.created_at)
            || wire::is_go_zero_time(self.absolute_expires_at)
            || self.absolute_expires_at <= self.created_at
        {
            return false;
        }
        // Optional, but never junk: nil or a V7 the journal minted.
        if !self.operation_id.is_nil() && self.operation_id.get_version_num() != 7 {
            return false;
        }
        let z = wire::is_go_zero_time;
        match self.state {
            ReserveState::Intent => {
                z(self.allocated_at)
                    && z(self.consumed_at)
                    && z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::Allocated => {
                !z(self.allocated_at)
                    && z(self.consumed_at)
                    && z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::ProvisionallyConsumed => {
                !z(self.allocated_at)
                    && !z(self.consumed_at)
                    && z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::Verified => {
                !z(self.allocated_at) && !z(self.verified_at) && z(self.released_at)
            }
            ReserveState::Released => !z(self.released_at),
        }
    }

    /// `restoreCapacityReserveSetPayload` — the exact bytes HMAC'd:
    /// `hmac` cleared, everything else marshaled.
    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(reserve_unavailable(
                "reserve set payload of an invalid record",
            ));
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone)
            .map_err(|e| reserve_unavailable(format!("marshal reserve set payload: {e}")))
    }
}

// --- member record ---------------------------------------------------------

/// `RestoreCapacityReserveMemberRecord` — one role's share of a set.
/// `receipt_id` is emitted always (Go `uuid` is an array — `omitempty`
/// never fires); `bearer_value_hash` omits when empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReserveMemberRecord {
    pub schema_version: String,
    pub set_id: Uuid,
    pub role: ReserveRole,
    pub device_fingerprint: String,
    pub st_dev: u64,
    pub reserved_bytes: u64,
    pub observed_free_bytes: u64,
    #[serde(with = "wire::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub receipt_id: Uuid,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bearer_value_hash: String,
    #[serde(with = "wire::rfc3339")]
    pub receipt_issued_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub receipt_expires_at: OffsetDateTime,
    pub state: ReserveState,
    #[serde(with = "wire::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub allocated_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub consumed_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub verified_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub released_at: OffsetDateTime,
    pub hmac: String,
}

impl ReserveMemberRecord {
    /// `receiptFieldsSet` — any receipt field populated.
    fn receipt_fields_set(&self) -> bool {
        !self.receipt_id.is_nil()
            || !self.bearer_value_hash.is_empty()
            || !wire::is_go_zero_time(self.receipt_issued_at)
            || !wire::is_go_zero_time(self.receipt_expires_at)
    }

    /// `receiptComplete` — a whole receipt binding: V7 id, valid hash,
    /// and an issued-before-expiry window.
    pub(crate) fn receipt_complete(&self) -> bool {
        !self.receipt_id.is_nil()
            && self.receipt_id.get_version_num() == 7
            && wire::valid_prefixed_sha256(&self.bearer_value_hash)
            && !wire::is_go_zero_time(self.receipt_issued_at)
            && !wire::is_go_zero_time(self.receipt_expires_at)
            && self.receipt_expires_at > self.receipt_issued_at
    }

    /// `RestoreCapacityReserveMemberRecord.valid`.
    pub(crate) fn valid(&self) -> bool {
        if self.schema_version != RECORD_SCHEMA
            || self.set_id.is_nil()
            || self.device_fingerprint.is_empty()
            || self.st_dev == 0
            || self.reserved_bytes == 0
            || wire::is_go_zero_time(self.observed_at)
            || wire::is_go_zero_time(self.created_at)
        {
            return false;
        }
        if self.receipt_fields_set() && !self.receipt_complete() {
            return false;
        }
        let z = wire::is_go_zero_time;
        match self.state {
            ReserveState::Intent => {
                z(self.allocated_at)
                    && !self.receipt_fields_set()
                    && z(self.consumed_at)
                    && z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::Allocated => {
                !z(self.allocated_at)
                    && z(self.consumed_at)
                    && z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::ProvisionallyConsumed => {
                !z(self.allocated_at)
                    && self.receipt_complete()
                    && !z(self.consumed_at)
                    && z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::Verified => {
                !z(self.allocated_at)
                    && self.receipt_complete()
                    && !z(self.consumed_at)
                    && !z(self.verified_at)
                    && z(self.released_at)
            }
            ReserveState::Released => !z(self.released_at),
        }
    }

    /// `restoreCapacityReserveMemberPayload`.
    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(reserve_unavailable(
                "reserve member payload of an invalid record",
            ));
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone)
            .map_err(|e| reserve_unavailable(format!("marshal reserve member payload: {e}")))
    }
}

// --- operation index record -------------------------------------------------

/// `restoreCapacityReserveOperationIndexRecord` — the create-only
/// operation→set pointer the gate resolves through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationIndexRecord {
    pub schema_version: String,
    pub operation_id: Uuid,
    pub set_id: Uuid,
    pub launch_evidence_id: Uuid,
    #[serde(with = "wire::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub hmac: String,
}

impl OperationIndexRecord {
    fn valid(&self) -> bool {
        self.schema_version == RECORD_SCHEMA
            && !self.operation_id.is_nil()
            && !self.set_id.is_nil()
            && self.set_id.get_version_num() == 7
            && !self.launch_evidence_id.is_nil()
            && !wire::is_go_zero_time(self.updated_at)
    }

    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(reserve_unavailable(
                "operation index payload of an invalid record",
            ));
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone)
            .map_err(|e| reserve_unavailable(format!("marshal operation index payload: {e}")))
    }
}

// --- intents ---------------------------------------------------------------

/// `RestoreCapacityReserveSetIntent` — caller-supplied content of a new
/// set. Carries no operation id: "verify allocates" means the set exists
/// before the operation does.
#[derive(Debug, Clone)]
pub struct ReserveSetIntent {
    pub launch_evidence_id: Uuid,
    pub backup_id: Uuid,
    pub repository_binding_id: Uuid,
    pub dump_bytes: u64,
    pub object_bytes: u64,
    pub artifact_count: u64,
    pub absolute_expires_at: OffsetDateTime,
}

/// `RestoreCapacityReserveMemberIntent` — one role's pre-allocation
/// measurement.
#[derive(Debug, Clone)]
pub struct ReserveMemberIntent {
    pub role: ReserveRole,
    pub device_fingerprint: String,
    pub st_dev: u64,
    pub reserved_bytes: u64,
    pub observed_free_bytes: u64,
    pub observed_at: OffsetDateTime,
}

// --- protected read + two-pass decode ---------------------------------------

/// `readRestoreCapacityReserveBytes` — the same protected-file
/// discipline `readPrivateJSON` applies, minus the decode.
pub(crate) fn read_reserve_bytes(path: &Path) -> Result<Vec<u8>, Failure> {
    // `errors.Is(err, os.ErrNotExist)` → not-found; anything else
    // → unavailable. `open_protected_file` maps everything to Failure,
    // so the existence check runs first; a file that vanishes between
    // the two reads is genuinely ambiguous and lands on unavailable
    // (the retain direction).
    match durable::lstat(path) {
        Ok(_) => {}
        Err(rustix::io::Errno::NOENT) => {
            return Err(reserve_not_found(format!(
                "reserve record {} does not exist",
                path.display()
            )));
        }
        Err(_) => {
            return Err(reserve_unavailable(format!(
                "inspect reserve record {} failed",
                path.display()
            )));
        }
    }
    let file = open_protected_file(path)
        .map_err(|e| reserve_unavailable(format!("open reserve record: {}", e.message())))?;
    let meta = file
        .metadata()
        .map_err(|e| reserve_unavailable(format!("stat reserve record: {e}")))?;
    let st = rustix::fs::fstat(&file)
        .map_err(|e| reserve_unavailable(format!("fstat reserve record: {e}")))?;
    durable::validate_private_file(&st, "restore capacity reserve record")
        .map_err(|e| reserve_unavailable(e.message().to_string()))?;
    if meta.len() == 0 || meta.len() > MAX_RECORD_BYTES {
        return Err(reserve_unavailable("reserve record size out of bounds"));
    }
    use std::io::Read;
    let mut raw = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| reserve_unavailable(format!("read reserve record: {e}")))?;
    if raw.is_empty() || raw.len() as u64 > MAX_RECORD_BYTES {
        return Err(reserve_unavailable("reserve record size out of bounds"));
    }
    Ok(raw)
}

/// `decodeRestoreCapacityReserveRecord` — permissive schema-version
/// envelope first (an unknown future version is *ambiguous*, never
/// absent), then a strict `deny_unknown_fields` decode of the same
/// bytes; trailing content is ambiguous too.
pub(crate) fn decode_record<T: DeserializeOwned>(raw: &[u8]) -> Result<T, Failure> {
    #[derive(Deserialize)]
    struct Envelope<'a> {
        schema_version: &'a str,
    }
    let envelope: Envelope<'_> = serde_json::from_slice(raw)
        .map_err(|e| reserve_ambiguous(format!("reserve record envelope: {e}")))?;
    if envelope.schema_version != RECORD_SCHEMA {
        return Err(reserve_ambiguous(format!(
            "reserve record schema_version {:?} is not {RECORD_SCHEMA:?}",
            envelope.schema_version
        )));
    }
    // `from_slice` refuses trailing non-whitespace bytes — Go's second
    // `Decode` expecting `io.EOF`.
    serde_json::from_slice(raw)
        .map_err(|e| reserve_ambiguous(format!("reserve record decode: {e}")))
}

// --- the store -----------------------------------------------------------------

/// `RestoreCapacityReserveStore` — `{sets,members,operations}/` under a
/// broker-owned root, one HMAC'd JSON file per record, `flock`
/// serialization per record.
pub(crate) struct ReserveStore {
    sets: PathBuf,
    members: PathBuf,
    operations: PathBuf,
    pub(crate) signing: std::sync::Arc<SigningService>,
}

impl ReserveStore {
    /// `newRestoreCapacityReserveStore`.
    pub(crate) fn new(
        broker_root: &Path,
        signing: std::sync::Arc<SigningService>,
    ) -> Result<Self, Failure> {
        durable::validate_broker_owned_root(broker_root, "restore capacity reserve broker root")?;
        let root = broker_root.join(DIRECTORY);
        let sets = root.join(SETS_DIR);
        let members = root.join(MEMBERS_DIR);
        let operations = root.join(OPERATIONS_DIR);
        for (path, name) in [
            (&root, "restore capacity reserve root"),
            (&sets, "restore capacity reserve set root"),
            (&members, "restore capacity reserve member root"),
            (&operations, "restore capacity reserve operation index root"),
        ] {
            rustix::fs::mkdir(
                path,
                rustix::fs::Mode::from_raw_mode(durable::PRIVATE_DIRECTORY_MODE),
            )
            .or_else(|e| {
                if e == rustix::io::Errno::EXIST {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|e| {
                reserve_unavailable(format!(
                    "restore capacity reserve store: create {name}: {e}"
                ))
            })?;
            durable::validate_private_directory(path, name)
                .map_err(|e| reserve_unavailable(e.message().to_string()))?;
        }
        Ok(Self {
            sets,
            members,
            operations,
            signing,
        })
    }

    /// `s.sets` — sweep enumeration root.
    pub(crate) fn sets_dir(&self) -> &Path {
        &self.sets
    }

    /// `s.members` — sweep enumeration root.
    pub(crate) fn members_dir(&self) -> &Path {
        &self.members
    }

    /// `s.operations` — sweep enumeration root.
    pub(crate) fn operations_dir(&self) -> &Path {
        &self.operations
    }

    /// `s.setPath`.
    pub(crate) fn set_path(&self, set_id: Uuid) -> PathBuf {
        self.sets
            .join(format!("{}.json", generation_key(&set_id.to_string())))
    }

    /// `s.operationPath`.
    pub(crate) fn operation_path(&self, operation_id: Uuid) -> PathBuf {
        self.operations.join(format!(
            "{}.json",
            generation_key(&operation_id.to_string())
        ))
    }

    /// `s.memberPath`.
    pub(crate) fn member_path(&self, set_id: Uuid, role: ReserveRole) -> PathBuf {
        self.members.join(format!(
            "{}.json",
            generation_key(&format!("{set_id}/{}", role.as_str()))
        ))
    }

    /// Per-record `flock` — `record.json.lock`.
    fn open_lock(&self, record_path: &Path) -> Result<std::os::fd::OwnedFd, Failure> {
        let lock_path = {
            let mut os = record_path.as_os_str().to_os_string();
            os.push(".lock");
            PathBuf::from(os)
        };
        durable::open_lock(&lock_path)
            .map_err(|e| reserve_unavailable(format!("lock reserve record: {}", e.message())))
    }

    fn sign_set(&self, record: &mut ReserveSetRecord) -> Result<(), Failure> {
        record.hmac = self
            .signing
            .fingerprint(SET_HMAC_DOMAIN, &record.payload()?);
        Ok(())
    }

    fn sign_member(&self, record: &mut ReserveMemberRecord) -> Result<(), Failure> {
        record.hmac = self
            .signing
            .fingerprint(MEMBER_HMAC_DOMAIN, &record.payload()?);
        Ok(())
    }

    /// `CreateSetIntent` — persists a brand-new unbound set in the
    /// `intent` state; create-only, so a conflicting existing record is
    /// a refusal, not a silent replace.
    pub(crate) fn create_set_intent(
        &self,
        intent: ReserveSetIntent,
        now: OffsetDateTime,
    ) -> Result<ReserveSetRecord, Failure> {
        if intent.launch_evidence_id.is_nil()
            || intent.backup_id.is_nil()
            || intent.repository_binding_id.is_nil()
            || intent.dump_bytes == 0
            || wire::is_go_zero_time(now)
            || wire::is_go_zero_time(intent.absolute_expires_at)
            || intent.absolute_expires_at <= now
        {
            return Err(reserve_unavailable("invalid reserve set intent"));
        }
        let set_id = Uuid::now_v7();
        let mut record = ReserveSetRecord {
            schema_version: RECORD_SCHEMA.to_string(),
            set_id,
            operation_id: Uuid::nil(),
            launch_evidence_id: intent.launch_evidence_id,
            backup_id: intent.backup_id,
            repository_binding_id: intent.repository_binding_id,
            dump_bytes: intent.dump_bytes,
            object_bytes: intent.object_bytes,
            artifact_count: intent.artifact_count,
            state: ReserveState::Intent,
            created_at: now,
            absolute_expires_at: intent.absolute_expires_at,
            allocated_at: wire::go_zero_time(),
            consumed_at: wire::go_zero_time(),
            verified_at: wire::go_zero_time(),
            released_at: wire::go_zero_time(),
            hmac: String::new(),
        };
        self.sign_set(&mut record)?;
        let path = self.set_path(set_id);
        let lock = self.open_lock(&path)?;
        let write = durable::write_exclusive_json(&path, &record);
        durable::unlock_and_close(lock);
        write.map_err(|e| reserve_unavailable(format!("publish reserve set: {}", e.message())))?;
        Ok(record)
    }

    /// `BindSetToOperation` — attach the operation id a set was created
    /// without, and write the create-only pointer. Set lock first, then
    /// pointer lock — the order every path in this store takes them in.
    pub(crate) fn bind_set_to_operation(
        &self,
        set_id: Uuid,
        operation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ReserveSetRecord, Failure> {
        if set_id.is_nil()
            || operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || wire::is_go_zero_time(now)
        {
            return Err(reserve_unavailable("invalid bind arguments"));
        }
        let path = self.set_path(set_id);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = self.read_set(set_id)?;
            if record.state == ReserveState::Released {
                return Err(reserve_unavailable("cannot bind a released reserve set"));
            }
            if !record.operation_id.is_nil() && record.operation_id != operation_id {
                return Err(reserve_unavailable(
                    "reserve set is bound to a different operation",
                ));
            }
            // Pointer lock before the set record is touched — a refused
            // bind must not have stamped the operation durably.
            let index_lock = self.open_lock(&self.operation_path(operation_id))?;
            let inner = (|| {
                self.operation_index_admits_set(operation_id, set_id)?;
                if record.operation_id.is_nil() {
                    record.operation_id = operation_id;
                    self.sign_set(&mut record)?;
                    durable::replace_json(&path, &record).map_err(|e| {
                        reserve_unavailable(format!("rewrite reserve set: {}", e.message()))
                    })?;
                }
                self.write_operation_index_locked(&record)
            })();
            durable::unlock_and_close(index_lock);
            inner?;
            Ok(record)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `operationIndexAdmitsSet` — the create-only rule. Same-set
    /// pointer is the idempotent repeat; any other set refuses; an
    /// unreadable pointer resolves its ambiguity away from admission.
    /// The caller holds the pointer's lock.
    fn operation_index_admits_set(&self, operation_id: Uuid, set_id: Uuid) -> Result<(), Failure> {
        match self.read_operation_index(operation_id) {
            Ok(existing) => {
                if existing.set_id != set_id {
                    return Err(reserve_unavailable(
                        "operation pointer names a different set",
                    ));
                }
                Ok(())
            }
            Err(e) if super::is_reserve_not_found(&e) => Ok(()),
            Err(_) => Err(reserve_unavailable("operation pointer is unreadable")),
        }
    }

    /// `writeOperationIndexLocked` — the pointer write, after the set
    /// record; the caller holds the pointer's lock.
    fn write_operation_index_locked(&self, set: &ReserveSetRecord) -> Result<(), Failure> {
        let mut record = OperationIndexRecord {
            schema_version: RECORD_SCHEMA.to_string(),
            operation_id: set.operation_id,
            set_id: set.set_id,
            launch_evidence_id: set.launch_evidence_id,
            updated_at: set.created_at,
            hmac: String::new(),
        };
        record.hmac = self
            .signing
            .fingerprint(OPERATION_HMAC_DOMAIN, &record.payload()?);
        durable::replace_json(&self.operation_path(set.operation_id), &record)
            .map_err(|e| reserve_unavailable(format!("write operation pointer: {}", e.message())))
    }

    /// `readOperationIndex` — authenticate one pointer.
    pub(crate) fn read_operation_index(
        &self,
        operation_id: Uuid,
    ) -> Result<OperationIndexRecord, Failure> {
        let raw = read_reserve_bytes(&self.operation_path(operation_id))?;
        let record: OperationIndexRecord = decode_record(&raw)?;
        if record.operation_id != operation_id || !record.valid() {
            return Err(reserve_unavailable(
                "operation pointer does not name this operation",
            ));
        }
        let expected = self
            .signing
            .fingerprint(OPERATION_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(reserve_unavailable("operation pointer HMAC mismatch"));
        }
        Ok(record)
    }

    /// `ResolveSetForOperation` — pointer plus set, cross-checked both
    /// directions (operation id and launch evidence must agree).
    pub(crate) fn resolve_set_for_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<ReserveSetRecord, Failure> {
        if operation_id.is_nil() {
            return Err(reserve_unavailable("nil operation id"));
        }
        let index = self.read_operation_index(operation_id)?;
        let set = self.read_set(index.set_id)?;
        if set.operation_id != operation_id || set.launch_evidence_id != index.launch_evidence_id {
            return Err(reserve_unavailable(
                "reserve set and operation pointer disagree",
            ));
        }
        Ok(set)
    }

    /// `CreateMemberIntent` — intent-before-allocate. Retry with
    /// byte-identical content against a still-intent record is the
    /// idempotent success; anything else on conflict is refused.
    pub(crate) fn create_member_intent(
        &self,
        set_id: Uuid,
        intent: ReserveMemberIntent,
        now: OffsetDateTime,
    ) -> Result<ReserveMemberRecord, Failure> {
        if set_id.is_nil()
            || intent.device_fingerprint.is_empty()
            || intent.st_dev == 0
            || intent.reserved_bytes == 0
            || wire::is_go_zero_time(intent.observed_at)
            || wire::is_go_zero_time(now)
        {
            return Err(reserve_unavailable("invalid member intent"));
        }
        let mut record = ReserveMemberRecord {
            schema_version: RECORD_SCHEMA.to_string(),
            set_id,
            role: intent.role,
            device_fingerprint: intent.device_fingerprint,
            st_dev: intent.st_dev,
            reserved_bytes: intent.reserved_bytes,
            observed_free_bytes: intent.observed_free_bytes,
            observed_at: intent.observed_at,
            receipt_id: Uuid::nil(),
            bearer_value_hash: String::new(),
            receipt_issued_at: wire::go_zero_time(),
            receipt_expires_at: wire::go_zero_time(),
            state: ReserveState::Intent,
            created_at: now,
            allocated_at: wire::go_zero_time(),
            consumed_at: wire::go_zero_time(),
            verified_at: wire::go_zero_time(),
            released_at: wire::go_zero_time(),
            hmac: String::new(),
        };
        self.sign_member(&mut record)?;
        let path = self.member_path(set_id, intent.role);
        let lock = self.open_lock(&path)?;
        let write = durable::write_exclusive_json(&path, &record);
        if write.is_ok() {
            durable::unlock_and_close(lock);
            return Ok(record);
        }
        let existing = self.read_member(set_id, intent.role);
        durable::unlock_and_close(lock);
        match existing {
            Ok(existing)
                if existing.state == ReserveState::Intent
                    && same_member_intent(&existing, &record) =>
            {
                Ok(existing)
            }
            _ => Err(reserve_unavailable(
                "member intent conflicts with the durable record",
            )),
        }
    }

    /// `AttachMemberReceipt` — bind a minted receipt to an allocated
    /// member, once. An identical attach is the idempotent retry; a
    /// differing one refuses.
    pub(crate) fn attach_member_receipt(
        &self,
        set_id: Uuid,
        role: ReserveRole,
        receipt_id: Uuid,
        bearer_value_hash: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ReserveMemberRecord, Failure> {
        if set_id.is_nil()
            || receipt_id.is_nil()
            || receipt_id.get_version_num() != 7
            || !wire::valid_prefixed_sha256(bearer_value_hash)
            || wire::is_go_zero_time(issued_at)
            || wire::is_go_zero_time(expires_at)
            || expires_at <= issued_at
        {
            return Err(reserve_unavailable("invalid receipt attach arguments"));
        }
        let path = self.member_path(set_id, role);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = self.read_member(set_id, role)?;
            if record.state != ReserveState::Allocated {
                return Err(reserve_unavailable("member is not allocated"));
            }
            if !record.receipt_id.is_nil() {
                if record.receipt_id == receipt_id
                    && record.bearer_value_hash == bearer_value_hash
                    && record.receipt_issued_at == issued_at
                    && record.receipt_expires_at == expires_at
                {
                    return Ok(record);
                }
                return Err(reserve_unavailable(
                    "member already carries a different receipt",
                ));
            }
            record.receipt_id = receipt_id;
            record.bearer_value_hash = bearer_value_hash.to_string();
            record.receipt_issued_at = issued_at;
            record.receipt_expires_at = expires_at;
            self.sign_member(&mut record)?;
            durable::replace_json(&path, &record)
                .map_err(|e| reserve_unavailable(format!("rewrite member: {}", e.message())))?;
            Ok(record)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `ConfirmMemberAllocation` — the intent→allocated transition plus
    /// the post-allocation observation, one signed replace under the
    /// record's lock.
    pub(crate) fn confirm_member_allocation(
        &self,
        set_id: Uuid,
        role: ReserveRole,
        observed_free_bytes: u64,
        observed_at: OffsetDateTime,
        at: OffsetDateTime,
    ) -> Result<ReserveMemberRecord, Failure> {
        if set_id.is_nil() || wire::is_go_zero_time(observed_at) || wire::is_go_zero_time(at) {
            return Err(reserve_unavailable("invalid allocation confirmation"));
        }
        let path = self.member_path(set_id, role);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = self.read_member(set_id, role)?;
            if record.state == ReserveState::Allocated {
                if record.observed_free_bytes == observed_free_bytes
                    && record.observed_at == observed_at
                {
                    return Ok(record);
                }
                return Err(reserve_unavailable(
                    "confirmation disagrees with the durable observation",
                ));
            }
            if !transition_allowed(record.state, ReserveState::Allocated) {
                return Err(reserve_unavailable("member cannot advance to allocated"));
            }
            record.observed_free_bytes = observed_free_bytes;
            record.observed_at = observed_at;
            record.allocated_at = at;
            record.state = ReserveState::Allocated;
            self.sign_member(&mut record)?;
            durable::replace_json(&path, &record)
                .map_err(|e| reserve_unavailable(format!("rewrite member: {}", e.message())))?;
            Ok(record)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `AdvanceSetState` — no-op when the record already holds `target`
    /// (idempotent release); an ambiguous record is returned unmutated
    /// and the file is never touched.
    pub(crate) fn advance_set_state(
        &self,
        set_id: Uuid,
        target: ReserveState,
        at: OffsetDateTime,
    ) -> Result<ReserveSetRecord, Failure> {
        if set_id.is_nil() || wire::is_go_zero_time(at) {
            return Err(reserve_unavailable("invalid advance arguments"));
        }
        let path = self.set_path(set_id);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = self.read_set(set_id)?;
            if record.state == target {
                return Ok(record);
            }
            if !set_transition_allowed(record.state, target) {
                return Err(reserve_unavailable("set cannot advance to target state"));
            }
            match target {
                ReserveState::Allocated => record.allocated_at = at,
                ReserveState::ProvisionallyConsumed => record.consumed_at = at,
                ReserveState::Verified => record.verified_at = at,
                ReserveState::Released => record.released_at = at,
                ReserveState::Intent => {}
            }
            record.state = target;
            self.sign_set(&mut record)?;
            durable::replace_json(&path, &record)
                .map_err(|e| reserve_unavailable(format!("rewrite set: {}", e.message())))?;
            Ok(record)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `AdvanceMemberState` — member-granularity advance; provisional
    /// consumption and verification both require a complete receipt
    /// binding already attached.
    pub(crate) fn advance_member_state(
        &self,
        set_id: Uuid,
        role: ReserveRole,
        target: ReserveState,
        at: OffsetDateTime,
    ) -> Result<ReserveMemberRecord, Failure> {
        if set_id.is_nil() || wire::is_go_zero_time(at) {
            return Err(reserve_unavailable("invalid advance arguments"));
        }
        let path = self.member_path(set_id, role);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = self.read_member(set_id, role)?;
            if record.state == target {
                return Ok(record);
            }
            if !transition_allowed(record.state, target) {
                return Err(reserve_unavailable("member cannot advance to target state"));
            }
            if (target == ReserveState::ProvisionallyConsumed || target == ReserveState::Verified)
                && !record.receipt_complete()
            {
                return Err(reserve_unavailable(
                    "member lacks a complete receipt binding",
                ));
            }
            match target {
                ReserveState::Allocated => record.allocated_at = at,
                ReserveState::ProvisionallyConsumed => record.consumed_at = at,
                ReserveState::Verified => record.verified_at = at,
                ReserveState::Released => record.released_at = at,
                ReserveState::Intent => {}
            }
            record.state = target;
            self.sign_member(&mut record)?;
            durable::replace_json(&path, &record)
                .map_err(|e| reserve_unavailable(format!("rewrite member: {}", e.message())))?;
            Ok(record)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `ReleaseSet`.
    pub(crate) fn release_set(
        &self,
        set_id: Uuid,
        at: OffsetDateTime,
    ) -> Result<ReserveSetRecord, Failure> {
        self.advance_set_state(set_id, ReserveState::Released, at)
    }

    /// `ReleaseMember`.
    pub(crate) fn release_member(
        &self,
        set_id: Uuid,
        role: ReserveRole,
        at: OffsetDateTime,
    ) -> Result<ReserveMemberRecord, Failure> {
        self.advance_member_state(set_id, role, ReserveState::Released, at)
    }

    /// `ReadSet` — non-mutating, lock-free.
    pub(crate) fn read_set(&self, set_id: Uuid) -> Result<ReserveSetRecord, Failure> {
        if set_id.is_nil() {
            return Err(reserve_unavailable("nil set id"));
        }
        let raw = read_reserve_bytes(&self.set_path(set_id))?;
        let record: ReserveSetRecord = decode_record(&raw)?;
        if record.set_id != set_id || !record.valid() {
            return Err(reserve_unavailable("set record identity or shape invalid"));
        }
        let expected = self
            .signing
            .fingerprint(SET_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(reserve_unavailable("set record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `ReadMember` — non-mutating, lock-free.
    pub(crate) fn read_member(
        &self,
        set_id: Uuid,
        role: ReserveRole,
    ) -> Result<ReserveMemberRecord, Failure> {
        if set_id.is_nil() {
            return Err(reserve_unavailable("nil set id"));
        }
        let raw = read_reserve_bytes(&self.member_path(set_id, role))?;
        let record: ReserveMemberRecord = decode_record(&raw)?;
        if record.set_id != set_id || record.role != role || !record.valid() {
            return Err(reserve_unavailable(
                "member record identity or shape invalid",
            ));
        }
        let expected = self
            .signing
            .fingerprint(MEMBER_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(reserve_unavailable("member record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `readSetAtPath` — the sweep's variant: identity unknown at call
    /// time; the record must validate and live at the path the store
    /// itself would mint for the identity it claims.
    pub(crate) fn read_set_at_path(&self, path: &Path) -> Result<ReserveSetRecord, Failure> {
        let raw = read_reserve_bytes(path)?;
        let record: ReserveSetRecord = decode_record(&raw)?;
        if !record.valid() || self.set_path(record.set_id) != path {
            return Err(reserve_unavailable("set record path/identity mismatch"));
        }
        let expected = self
            .signing
            .fingerprint(SET_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(reserve_unavailable("set record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `readMemberAtPath`.
    pub(crate) fn read_member_at_path(&self, path: &Path) -> Result<ReserveMemberRecord, Failure> {
        let raw = read_reserve_bytes(path)?;
        let record: ReserveMemberRecord = decode_record(&raw)?;
        if !record.valid() || self.member_path(record.set_id, record.role) != path {
            return Err(reserve_unavailable("member record path/identity mismatch"));
        }
        let expected = self
            .signing
            .fingerprint(MEMBER_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(reserve_unavailable("member record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `readOperationIndexAtPath`.
    pub(crate) fn read_operation_index_at_path(
        &self,
        path: &Path,
    ) -> Result<OperationIndexRecord, Failure> {
        let raw = read_reserve_bytes(path)?;
        let record: OperationIndexRecord = decode_record(&raw)?;
        if !record.valid() || self.operation_path(record.operation_id) != path {
            return Err(reserve_unavailable(
                "operation pointer path/identity mismatch",
            ));
        }
        let expected = self
            .signing
            .fingerprint(OPERATION_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(reserve_unavailable("operation pointer HMAC mismatch"));
        }
        Ok(record)
    }
}

/// `sameRestoreCapacityReserveMemberIntent`.
fn same_member_intent(existing: &ReserveMemberRecord, candidate: &ReserveMemberRecord) -> bool {
    existing.set_id == candidate.set_id
        && existing.role == candidate.role
        && existing.device_fingerprint == candidate.device_fingerprint
        && existing.st_dev == candidate.st_dev
        && existing.reserved_bytes == candidate.reserved_bytes
        && existing.observed_free_bytes == candidate.observed_free_bytes
        && existing.observed_at == candidate.observed_at
}

/// The completeness rule frame `0xc3` derives from durable records only:
/// every role has a member record, and each is at-or-past `allocated`.
/// Never caller memory.
#[allow(dead_code)] // completeness check the engine-side bind path uses
pub(crate) fn member_records_complete(members: &[ReserveMemberRecord]) -> bool {
    if members.len() != RESERVE_ROLES.len() {
        return false;
    }
    RESERVE_ROLES.iter().all(|role| {
        members.iter().any(|m| {
            m.role == *role
                && matches!(
                    m.state,
                    ReserveState::Allocated
                        | ReserveState::ProvisionallyConsumed
                        | ReserveState::Verified
                )
        })
    })
}

#[cfg(test)]
mod tests {
    //! `restore_capacity_reserve_store_test.go` — the durable record
    //! layer's upstream suite, ported one-to-one.

    use super::*;
    use crate::broker::restore_capacity::{
        RESERVE_UNAVAILABLE, is_reserve_ambiguous, is_reserve_not_found,
    };
    use crate::broker::signing::SigningService;
    use crate::broker::testutil::TempDir;
    use std::sync::Arc;
    use time::macros::datetime;
    use uuid::Uuid;

    const NOW: time::OffsetDateTime = datetime!(2026-08-13 12:00:00 UTC);

    fn new_test_store() -> (ReserveStore, TempDir) {
        let root = TempDir::new("reserve-store");
        rustix::fs::chmod(&*root, rustix::fs::Mode::from_raw_mode(0o700)).unwrap();
        let store = ReserveStore::new(&root, Arc::new(SigningService::new())).unwrap();
        (store, root)
    }

    fn test_set_intent(now: OffsetDateTime) -> ReserveSetIntent {
        ReserveSetIntent {
            launch_evidence_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            repository_binding_id: Uuid::now_v7(),
            dump_bytes: 5 * 1024 * 1024 * 1024,
            object_bytes: 2 * 1024 * 1024 * 1024,
            artifact_count: 4200,
            absolute_expires_at: now + time::Duration::hours(8),
        }
    }

    fn test_member_intent(role: ReserveRole, now: OffsetDateTime) -> ReserveMemberIntent {
        ReserveMemberIntent {
            role,
            device_fingerprint: format!("fsid-{}", role.as_str()),
            st_dev: 0xBEEF,
            reserved_bytes: 4 * 1024 * 1024 * 1024,
            observed_free_bytes: 40 * 1024 * 1024 * 1024,
            observed_at: now,
        }
    }

    /// `fixedHex64` — a deterministic 64-char hex for test bearer
    /// hashes, distinguishing values by seeding the low byte.
    fn fixed_hex64(seed: u8) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        (0..64)
            .map(|i| HEX[(usize::from(seed) + i) % 16] as char)
            .collect()
    }

    #[test]
    fn create_set_intent_persists_and_reads_back() {
        let (store, _root) = new_test_store();
        let created = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        assert_eq!(created.state, ReserveState::Intent);
        assert!(!created.set_id.is_nil());
        assert_eq!(created.set_id.get_version_num(), 7);
        let read = store.read_set(created.set_id).unwrap();
        assert_eq!(read, created);
        // A set a "verify allocates" host creates names no operation,
        // and no operation→set pointer exists for it. Both halves matter.
        assert!(created.operation_id.is_nil());
        assert!(store.resolve_set_for_operation(Uuid::now_v7()).is_err());
    }

    #[test]
    fn bind_set_to_operation_is_create_only_and_never_rebinds() {
        let (store, _root) = new_test_store();
        let first = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let second = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let operation = Uuid::now_v7();

        let bound = store
            .bind_set_to_operation(first.set_id, operation, NOW)
            .unwrap();
        assert_eq!(bound.operation_id, operation);
        let resolved = store.resolve_set_for_operation(operation).unwrap();
        assert_eq!(resolved.set_id, first.set_id);

        // Idempotent repeat.
        let again = store
            .bind_set_to_operation(first.set_id, operation, NOW + time::Duration::minutes(1))
            .unwrap();
        assert_eq!(again.set_id, first.set_id);
        assert_eq!(again.operation_id, operation);

        // Create-only per operation: the pointer will not move to another set.
        assert!(
            store
                .bind_set_to_operation(second.set_id, operation, NOW)
                .is_err()
        );
        assert!(second.operation_id.is_nil());
        let refused = store.read_set(second.set_id).unwrap();
        assert!(refused.operation_id.is_nil());
        let resolved = store.resolve_set_for_operation(operation).unwrap();
        assert_eq!(resolved.set_id, first.set_id);

        // No rebinding: the set will not take a second operation.
        let other = Uuid::now_v7();
        assert!(
            store
                .bind_set_to_operation(first.set_id, other, NOW)
                .is_err()
        );
        assert!(store.resolve_set_for_operation(other).is_err());
        let still = store.read_set(first.set_id).unwrap();
        assert_eq!(still.operation_id, operation);

        // An unparseable pointer refuses rather than being overwritten —
        // and the refused set stays bindable.
        let unreadable = Uuid::now_v7();
        let fresh = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .bind_set_to_operation(fresh.set_id, unreadable, NOW)
            .unwrap();
        std::fs::write(
            store.operation_path(unreadable),
            br#"{"schema_version":"central.not-a-schema-this-build-knows/v9"}"#,
        )
        .unwrap();
        let spare = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        assert!(
            store
                .bind_set_to_operation(spare.set_id, unreadable, NOW)
                .is_err()
        );
        let still_unbound = store.read_set(spare.set_id).unwrap();
        assert!(still_unbound.operation_id.is_nil());

        // A released set refuses a bind outright.
        let released = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store.release_set(released.set_id, NOW).unwrap();
        assert!(
            store
                .bind_set_to_operation(released.set_id, Uuid::now_v7(), NOW)
                .is_err()
        );
    }

    #[test]
    fn member_intent_survives_crash_before_allocation() {
        let (store, root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let intent = test_member_intent(ReserveRole::PostgresData, NOW);
        let member = store
            .create_member_intent(set.set_id, intent.clone(), NOW)
            .unwrap();
        assert_eq!(member.state, ReserveState::Intent);
        assert!(wire::is_go_zero_time(member.allocated_at));

        // The "crash": a completely fresh store over the same root.
        let restarted = ReserveStore::new(&root, Arc::new(SigningService::new())).unwrap();
        let recovered = restarted
            .read_member(set.set_id, ReserveRole::PostgresData)
            .unwrap();
        assert_eq!(recovered.state, ReserveState::Intent);
        assert_eq!(recovered.device_fingerprint, intent.device_fingerprint);
        assert_eq!(recovered.st_dev, intent.st_dev);
        assert_eq!(recovered.reserved_bytes, intent.reserved_bytes);
        assert_eq!(recovered.observed_free_bytes, intent.observed_free_bytes);
        assert_eq!(recovered.observed_at, intent.observed_at);
        assert!(wire::is_go_zero_time(recovered.allocated_at));
    }

    #[test]
    fn concurrent_member_intent_creation_serializes() {
        let (store, _root) = new_test_store();
        let store = Arc::new(store);
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let intent = test_member_intent(ReserveRole::ObjectData, NOW);
        const ATTEMPTS: usize = 12;
        let barrier = Arc::new(std::sync::Barrier::new(ATTEMPTS));
        let mut handles = Vec::new();
        for _ in 0..ATTEMPTS {
            let (store, barrier, intent) = (store.clone(), barrier.clone(), intent.clone());
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.create_member_intent(set.set_id, intent, NOW)
            }));
        }
        let mut expected: Option<ReserveMemberRecord> = None;
        for h in handles {
            let record = h.join().unwrap().unwrap();
            if let Some(exp) = &expected {
                assert_eq!(&record, exp, "concurrent identical creates diverged");
            } else {
                expected = Some(record);
            }
        }
        let stored = store
            .read_member(set.set_id, ReserveRole::ObjectData)
            .unwrap();
        assert_eq!(stored, expected.unwrap());
    }

    #[test]
    fn concurrent_receipt_attach_serializes() {
        let (store, _root) = new_test_store();
        let store = Arc::new(store);
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::PostgresData, NOW),
                NOW,
            )
            .unwrap();
        store
            .advance_member_state(
                set.set_id,
                ReserveRole::PostgresData,
                ReserveState::Allocated,
                NOW + time::Duration::minutes(1),
            )
            .unwrap();
        const ATTEMPTS: usize = 24;
        let candidates: Vec<Uuid> = (0..ATTEMPTS).map(|_| Uuid::now_v7()).collect();
        let barrier = Arc::new(std::sync::Barrier::new(ATTEMPTS));
        let mut handles = Vec::new();
        for (i, candidate) in candidates.iter().enumerate() {
            let (store, barrier, candidate) = (store.clone(), barrier.clone(), *candidate);
            let hash = format!("sha256:{}", fixed_hex64(i as u8));
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                (
                    candidate,
                    store.attach_member_receipt(
                        set.set_id,
                        ReserveRole::PostgresData,
                        candidate,
                        &hash,
                        NOW + time::Duration::minutes(2),
                        NOW + time::Duration::minutes(22),
                    ),
                )
            }));
        }
        let mut successes = 0usize;
        let mut winner = Uuid::nil();
        for h in handles {
            let (candidate, result) = h.join().unwrap();
            if result.is_ok() {
                successes += 1;
                winner = candidate;
            }
        }
        assert_eq!(successes, 1, "exactly one distinct attach may win");
        let final_record = store
            .read_member(set.set_id, ReserveRole::PostgresData)
            .unwrap();
        assert_eq!(final_record.receipt_id, winner);
    }

    #[test]
    fn concurrent_state_advance_never_produces_an_invalid_record() {
        let (store, _root) = new_test_store();
        let store = Arc::new(store);
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::PostgresWal, NOW),
                NOW,
            )
            .unwrap();
        const ATTEMPTS: usize = 16;
        let barrier = Arc::new(std::sync::Barrier::new(ATTEMPTS));
        let mut handles = Vec::new();
        for i in 0..ATTEMPTS {
            let (store, barrier) = (store.clone(), barrier.clone());
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // Even-indexed writers aim at the invalid intent→verified skip.
                let target = if i % 2 == 0 {
                    ReserveState::Verified
                } else {
                    ReserveState::Allocated
                };
                let _ = store.advance_member_state(
                    set.set_id,
                    ReserveRole::PostgresWal,
                    target,
                    NOW + time::Duration::minutes(1),
                );
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_record = store
            .read_member(set.set_id, ReserveRole::PostgresWal)
            .unwrap();
        assert_eq!(final_record.state, ReserveState::Allocated);
        assert!(!wire::is_go_zero_time(final_record.allocated_at));
        assert!(wire::is_go_zero_time(final_record.verified_at));
    }

    #[test]
    fn unrecognized_schema_version_is_ambiguous_and_never_mutated() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let member = store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::PostgresTemp, NOW),
                NOW,
            )
            .unwrap();
        let path = store.member_path(set.set_id, ReserveRole::PostgresTemp);

        // A future-schema record is ambiguous, never absent — and no
        // lifecycle call may mutate or remove the file.
        let mut future = member.clone();
        future.schema_version = "central.restore-capacity-reserve-record/v2".to_string();
        durable::replace_json(&path, &future).unwrap();
        let before = std::fs::read(&path).unwrap();

        let err = store
            .read_member(set.set_id, ReserveRole::PostgresTemp)
            .unwrap_err();
        assert!(is_reserve_ambiguous(&err));
        let err = store
            .advance_member_state(
                set.set_id,
                ReserveRole::PostgresTemp,
                ReserveState::Allocated,
                NOW,
            )
            .unwrap_err();
        assert!(is_reserve_ambiguous(&err));
        let err = store
            .release_member(set.set_id, ReserveRole::PostgresTemp, NOW)
            .unwrap_err();
        assert!(is_reserve_ambiguous(&err));
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            before, after,
            "a refused operation must never mutate the file"
        );

        // Same rule on a set record.
        let set_path = store.set_path(set.set_id);
        let mut future_set = set.clone();
        future_set.schema_version = "central.restore-capacity-reserve-record/v2".to_string();
        durable::replace_json(&set_path, &future_set).unwrap();
        let err = store.read_set(set.set_id).unwrap_err();
        assert!(is_reserve_ambiguous(&err));
        let err = store.release_set(set.set_id, NOW).unwrap_err();
        assert!(is_reserve_ambiguous(&err));
    }

    #[test]
    fn member_full_lifecycle_and_idempotent_release() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::PostgresData, NOW),
                NOW,
            )
            .unwrap();
        let allocated = store
            .advance_member_state(
                set.set_id,
                ReserveRole::PostgresData,
                ReserveState::Allocated,
                NOW + time::Duration::minutes(1),
            )
            .unwrap();
        assert_eq!(allocated.state, ReserveState::Allocated);
        assert!(!wire::is_go_zero_time(allocated.allocated_at));

        let receipt_id = Uuid::now_v7();
        let bearer_hash = format!("sha256:{}", fixed_hex64(0x11));
        let issued = NOW + time::Duration::minutes(2);
        let expires = NOW + time::Duration::minutes(22);
        let attached = store
            .attach_member_receipt(
                set.set_id,
                ReserveRole::PostgresData,
                receipt_id,
                &bearer_hash,
                issued,
                expires,
            )
            .unwrap();
        assert_eq!(attached.receipt_id, receipt_id);
        assert_eq!(attached.bearer_value_hash, bearer_hash);
        // Idempotent retry, then a differing attach refused.
        store
            .attach_member_receipt(
                set.set_id,
                ReserveRole::PostgresData,
                receipt_id,
                &bearer_hash,
                issued,
                expires,
            )
            .unwrap();
        assert!(
            store
                .attach_member_receipt(
                    set.set_id,
                    ReserveRole::PostgresData,
                    Uuid::now_v7(),
                    &bearer_hash,
                    issued,
                    expires,
                )
                .is_err()
        );

        let consumed = store
            .advance_member_state(
                set.set_id,
                ReserveRole::PostgresData,
                ReserveState::ProvisionallyConsumed,
                NOW + time::Duration::minutes(3),
            )
            .unwrap();
        assert_eq!(consumed.state, ReserveState::ProvisionallyConsumed);
        assert!(!wire::is_go_zero_time(consumed.consumed_at));
        let verified = store
            .advance_member_state(
                set.set_id,
                ReserveRole::PostgresData,
                ReserveState::Verified,
                NOW + time::Duration::minutes(4),
            )
            .unwrap();
        assert_eq!(verified.state, ReserveState::Verified);
        assert!(!wire::is_go_zero_time(verified.verified_at));
        let released = store
            .release_member(
                set.set_id,
                ReserveRole::PostgresData,
                NOW + time::Duration::minutes(5),
            )
            .unwrap();
        assert_eq!(released.state, ReserveState::Released);
        assert!(!wire::is_go_zero_time(released.released_at));
        // Release is idempotent and never moves ReleasedAt.
        let again = store
            .release_member(
                set.set_id,
                ReserveRole::PostgresData,
                NOW + time::Duration::hours(6),
            )
            .unwrap();
        assert_eq!(again.released_at, released.released_at);
    }

    #[test]
    fn set_allocated_may_skip_directly_to_verified() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .advance_set_state(
                set.set_id,
                ReserveState::Allocated,
                NOW + time::Duration::minutes(1),
            )
            .unwrap();
        let verified = store
            .advance_set_state(
                set.set_id,
                ReserveState::Verified,
                NOW + time::Duration::minutes(2),
            )
            .unwrap();
        assert_eq!(verified.state, ReserveState::Verified);
    }

    #[test]
    fn member_allocated_may_not_skip_directly_to_verified() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::PostgresData, NOW),
                NOW,
            )
            .unwrap();
        store
            .advance_member_state(
                set.set_id,
                ReserveRole::PostgresData,
                ReserveState::Allocated,
                NOW + time::Duration::minutes(1),
            )
            .unwrap();
        let before_skip = store
            .attach_member_receipt(
                set.set_id,
                ReserveRole::PostgresData,
                Uuid::now_v7(),
                &format!("sha256:{}", fixed_hex64(0x22)),
                NOW + time::Duration::minutes(2),
                NOW + time::Duration::minutes(22),
            )
            .unwrap();
        assert!(before_skip.receipt_complete());
        // The skip attempt must refuse — and leave the record untouched.
        assert!(
            store
                .advance_member_state(
                    set.set_id,
                    ReserveRole::PostgresData,
                    ReserveState::Verified,
                    NOW + time::Duration::minutes(3),
                )
                .is_err()
        );
        let after = store
            .read_member(set.set_id, ReserveRole::PostgresData)
            .unwrap();
        assert_eq!(after, before_skip);
        assert_eq!(after.state, ReserveState::Allocated);
        assert!(wire::is_go_zero_time(after.consumed_at));
        assert!(wire::is_go_zero_time(after.verified_at));
    }

    #[test]
    fn early_release_from_intent_is_allowed() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::ObjectData, NOW),
                NOW,
            )
            .unwrap();
        let released_set = store
            .release_set(set.set_id, NOW + time::Duration::minutes(1))
            .unwrap();
        assert_eq!(released_set.state, ReserveState::Released);
        let released_member = store
            .release_member(
                set.set_id,
                ReserveRole::ObjectData,
                NOW + time::Duration::minutes(1),
            )
            .unwrap();
        assert_eq!(released_member.state, ReserveState::Released);
    }

    #[test]
    fn tampered_hmac_is_refused() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let member = store
            .create_member_intent(
                set.set_id,
                test_member_intent(ReserveRole::PostgresWal, NOW),
                NOW,
            )
            .unwrap();
        let mut tampered = member.clone();
        tampered.reserved_bytes *= 2; // mutate a signed field without re-signing
        durable::replace_json(
            &store.member_path(set.set_id, ReserveRole::PostgresWal),
            &tampered,
        )
        .unwrap();
        let err = store
            .read_member(set.set_id, ReserveRole::PostgresWal)
            .unwrap_err();
        assert_eq!(err.code(), RESERVE_UNAVAILABLE);
    }

    #[test]
    fn member_not_found_is_distinct_from_ambiguous() {
        let (store, _root) = new_test_store();
        let err = store
            .read_member(Uuid::now_v7(), ReserveRole::PostgresData)
            .unwrap_err();
        assert!(is_reserve_not_found(&err));
    }

    #[test]
    fn create_member_intent_refuses_resend_after_member_advanced() {
        for (released, label) in [(true, "released"), (false, "allocated")] {
            let (store, _root) = new_test_store();
            let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
            let intent = test_member_intent(ReserveRole::PostgresData, NOW);
            store
                .create_member_intent(set.set_id, intent.clone(), NOW)
                .unwrap();
            let advanced = store
                .advance_member_state(
                    set.set_id,
                    ReserveRole::PostgresData,
                    if released {
                        ReserveState::Released
                    } else {
                        ReserveState::Allocated
                    },
                    NOW + time::Duration::minutes(1),
                )
                .unwrap();
            assert_eq!(
                advanced.state,
                if released {
                    ReserveState::Released
                } else {
                    ReserveState::Allocated
                },
                "advance to {label}",
            );

            // A byte-identical re-send against a post-intent member
            // refuses — never answered as an idempotent success.
            assert!(
                store
                    .create_member_intent(set.set_id, intent.clone(), NOW)
                    .is_err(),
                "byte-identical re-send against a {label} member was accepted",
            );
            let after = store
                .read_member(set.set_id, ReserveRole::PostgresData)
                .unwrap();
            assert_eq!(
                after, advanced,
                "refused re-send mutated the record ({label})"
            );
        }
    }

    #[test]
    fn create_member_intent_idempotent_retry_succeeds() {
        let (store, _root) = new_test_store();
        let set = store.create_set_intent(test_set_intent(NOW), NOW).unwrap();
        let intent = test_member_intent(ReserveRole::PostgresData, NOW);
        let first = store
            .create_member_intent(set.set_id, intent.clone(), NOW)
            .unwrap();
        let retry = store.create_member_intent(set.set_id, intent, NOW).unwrap();
        assert_eq!(retry, first);
    }
}
