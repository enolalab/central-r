//! `restore_capacity_receipt.go` — receipts and consumption for the
//! reserve gate. Three invariants drive everything here:
//!
//! - **The bearer value is never persisted.** The durable record keeps
//!   only `sha256(value)`; a byte-scan must never find the plaintext.
//! - **Comparison is constant time.** [`proof_matches`] is the one
//!   comparison path — `wire::hmac_equal` (constant-time) over the
//!   digest, never `==` over a secret.
//! - **Provisional consumption is keyed to the receipt, not the
//!   member.** The member record's lifecycle is monotonic, so a mark
//!   there could never lapse; the receipt-keyed mark lapses at the
//!   20-minute receipt window, which is also what distinguishes a
//!   retry's fresh receipt from a replayed one.

use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::broker::durable;
use crate::broker::protected_file::open_protected_file;
use crate::broker::recovery_journal::generation_key;
use crate::broker::signing::SigningService;
use crate::broker::wire;

use super::ReserveRole;

/// `RestoreCapacityReserveReceiptWireSchema` — the schema string the
/// frozen consumer (`DescriptorRestoreCapacitySource`) requires on
/// every receipt it accepts.
pub(crate) const RECEIPT_WIRE_SCHEMA: &str = "central.restore-capacity-reserve-receipt/v1";

/// `restoreCapacityReceiptRecordSchema` — the broker-owned ledger
/// schema.
const RECORD_SCHEMA: &str = "central.restore-capacity-receipt-record/v1";

/// `restoreCapacityReceiptBundleWireSchema` — the sealed bundle's
/// schema.
pub(crate) const BUNDLE_WIRE_SCHEMA: &str = "central.restore-capacity-receipt-bundle/v1";

const DIRECTORY: &str = "restore-capacity-receipts";
const RECEIPTS_DIR: &str = "receipts";
const DRAWS_DIR: &str = "draws";
const SPENDS_DIR: &str = "spends";

const RECEIPT_HMAC_DOMAIN: &str = "slice-c-restore-capacity-receipt-v1";
const DRAW_HMAC_DOMAIN: &str = "slice-c-restore-capacity-receipt-draw-v1";
const SPEND_HMAC_DOMAIN: &str = "slice-c-restore-capacity-receipt-spend-v1";

const MAX_RECORD_BYTES: u64 = 16 * 1024;
/// `restoreCapacityReceiptBundleMaxBytes` — the sealed memfd's bound.
pub(crate) const BUNDLE_MAX_BYTES: usize = 16 * 1024;
/// `restoreCapacityReceiptHandoffPurpose` — the sealed memfd's purpose
/// label.
pub(crate) const HANDOFF_PURPOSE: &str = "restore-capacity-receipts";

/// `RestoreCapacityReceiptLifetime` — the design's 20-minute receipt
/// window, deliberately far shorter than the set's 8-hour absolute
/// expiry: the receipt bounds how long a bearer value in memory is
/// worth anything and how long a provisional mark stays in force.
pub(crate) const RECEIPT_LIFETIME: time::Duration = time::Duration::minutes(20);

/// `restoreCapacityReceiptBearerBytes` — the bearer value's entropy,
/// per the design's "at least 32 bytes" decision.
pub(crate) const BEARER_BYTES: usize = 32;

/// `restoreCapacityReceiptMaxDrawsPerSet` — the per-set mint ceiling:
/// a draw is legitimately repeatable (that is what makes a retry
/// possible), so without a ceiling an admitted peer could grow this
/// store without bound inside the set's 8-hour window.
const MAX_DRAWS_PER_SET: u64 = 8;

// --- Sentinel refusals ---------------------------------------------------

const RECEIPT_UNAVAILABLE: &str = "broker_restore_receipt_unavailable";
const RECEIPT_NOT_FOUND: &str = "broker_restore_receipt_not_found";
const RECEIPT_AMBIGUOUS: &str = "broker_restore_receipt_ambiguous";
const RECEIPT_REPLAYED: &str = "broker_restore_receipt_replayed";
const RECEIPT_LAPSED: &str = "broker_restore_receipt_lapsed";
const RECEIPT_PROOF: &str = "broker_restore_receipt_proof";
const RECEIPT_DRAWS_EXHAUSTED: &str = "broker_restore_receipt_draws_exhausted";

pub(crate) fn receipt_unavailable(detail: impl Into<String>) -> Failure {
    Failure::internal(RECEIPT_UNAVAILABLE, detail.into())
}

pub(crate) fn receipt_not_found(detail: impl Into<String>) -> Failure {
    Failure::denied(RECEIPT_NOT_FOUND, detail.into())
}

pub(crate) fn receipt_ambiguous(detail: impl Into<String>) -> Failure {
    Failure::invalid(RECEIPT_AMBIGUOUS, detail.into())
}

fn receipt_replayed() -> Failure {
    Failure::denied(
        RECEIPT_REPLAYED,
        "broker: restore capacity receipt has already been consumed",
    )
}

fn receipt_lapsed() -> Failure {
    Failure::denied(
        RECEIPT_LAPSED,
        "broker: restore capacity receipt is outside its window",
    )
}

fn receipt_proof() -> Failure {
    Failure::denied(
        RECEIPT_PROOF,
        "broker: restore capacity receipt bearer value does not match",
    )
}

fn receipt_draws_exhausted() -> Failure {
    Failure::denied(
        RECEIPT_DRAWS_EXHAUSTED,
        "broker: restore capacity receipt draws exhausted for this reserve set",
    )
}

pub(crate) fn is_receipt_not_found(f: &Failure) -> bool {
    f.code() == RECEIPT_NOT_FOUND
}

pub(crate) fn is_receipt_ambiguous(f: &Failure) -> bool {
    f.code() == RECEIPT_AMBIGUOUS
}

pub(crate) fn is_receipt_replayed(f: &Failure) -> bool {
    f.code() == RECEIPT_REPLAYED
}

pub(crate) fn is_receipt_lapsed(f: &Failure) -> bool {
    f.code() == RECEIPT_LAPSED
}

pub(crate) fn is_receipt_proof(f: &Failure) -> bool {
    f.code() == RECEIPT_PROOF
}

pub(crate) fn is_receipt_draws_exhausted(f: &Failure) -> bool {
    f.code() == RECEIPT_DRAWS_EXHAUSTED
}

// --- Wire shapes -----------------------------------------------------------

/// `RestoreCapacityReceipt` — the wire shape of one bearer receipt.
/// Field names and types are pinned to the frozen consumer's
/// `RestoreCapacityReserveReceipt`; it carries no json tags upstream
/// (PascalCase encoding is the contract), so serde renames are
/// explicit here.
///
/// `authority_proof` is the bearer value: it exists only in the sealed
/// memfd and in the engine — never persisted, never logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    #[serde(rename = "SchemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ReceiptID")]
    pub receipt_id: Uuid,
    #[serde(rename = "BackupID")]
    pub backup_id: Uuid,
    #[serde(rename = "RepositoryBindingID")]
    pub repository_binding_id: Uuid,
    #[serde(rename = "Role")]
    pub role: String,
    #[serde(rename = "DeviceID")]
    pub device_id: String,
    #[serde(rename = "ReservedBytes")]
    pub reserved_bytes: u64,
    #[serde(rename = "IssuedAt", with = "wire::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(rename = "AuthorityProof")]
    pub authority_proof: String,
}

/// `RestoreCapacityReceiptBundle` — the sealed memfd's whole content:
/// the four receipts one reserve set needs, delivered together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBundle {
    pub schema_version: String,
    pub set_id: Uuid,
    pub receipts: Vec<Receipt>,
}

// --- Ledger records ---------------------------------------------------------

/// `restoreCapacityReceiptRecord` — the durable ledger entry for one
/// receipt. It carries the bearer value's *hash* and nothing else:
/// there is deliberately no field that could hold the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptRecord {
    pub schema_version: String,
    pub receipt_id: Uuid,
    pub set_id: Uuid,
    pub launch_evidence_id: Uuid,
    pub backup_id: Uuid,
    pub repository_binding_id: Uuid,
    pub role: ReserveRole,
    pub device_id: String,
    pub reserved_bytes: u64,
    #[serde(with = "wire::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub bearer_value_hash: String,
    #[serde(with = "wire::rfc3339")]
    pub consumed_at: OffsetDateTime,
    pub hmac: String,
}

impl ReceiptRecord {
    fn valid(&self) -> bool {
        self.schema_version == RECORD_SCHEMA
            && !self.receipt_id.is_nil()
            && self.receipt_id.get_version_num() == 7
            && !self.set_id.is_nil()
            && !self.launch_evidence_id.is_nil()
            && !self.backup_id.is_nil()
            && !self.repository_binding_id.is_nil()
            && wire::valid_prefixed_sha256(&self.device_id)
            && self.reserved_bytes != 0
            && !wire::is_go_zero_time(self.issued_at)
            && !wire::is_go_zero_time(self.expires_at)
            && self.expires_at > self.issued_at
            && wire::valid_prefixed_sha256(&self.bearer_value_hash)
            && (wire::is_go_zero_time(self.consumed_at) || self.consumed_at >= self.issued_at)
    }

    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(receipt_unavailable("receipt payload of an invalid record"));
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone)
            .map_err(|e| receipt_unavailable(format!("marshal receipt payload: {e}")))
    }
}

/// `restoreCapacityReceiptDrawRecord` — the per-set draw counter, a
/// separate replaceable record rather than a field on the set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DrawRecord {
    pub schema_version: String,
    pub set_id: Uuid,
    pub draws: u64,
    #[serde(with = "wire::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub hmac: String,
}

impl DrawRecord {
    fn valid(&self) -> bool {
        self.schema_version == RECORD_SCHEMA
            && !self.set_id.is_nil()
            && self.draws != 0
            && self.draws <= MAX_DRAWS_PER_SET
            && !wire::is_go_zero_time(self.updated_at)
    }

    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(receipt_unavailable("draw payload of an invalid record"));
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone)
            .map_err(|e| receipt_unavailable(format!("marshal draw payload: {e}")))
    }
}

/// `restoreCapacityReceiptSpendRecord` — the receipt most recently
/// *spent* for one `(set, role)`, plus the window that spend is in
/// force for. Replaceable: a later spend over the same reserve
/// supersedes an earlier one, which is what makes a retry's fresh
/// receipt the live one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SpendRecord {
    pub schema_version: String,
    pub set_id: Uuid,
    pub role: ReserveRole,
    pub receipt_id: Uuid,
    pub launch_evidence_id: Uuid,
    #[serde(with = "wire::rfc3339")]
    pub consumed_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub hmac: String,
}

impl SpendRecord {
    fn valid(&self) -> bool {
        self.schema_version == RECORD_SCHEMA
            && !self.set_id.is_nil()
            && !self.receipt_id.is_nil()
            && self.receipt_id.get_version_num() == 7
            && !self.launch_evidence_id.is_nil()
            && !wire::is_go_zero_time(self.consumed_at)
            && !wire::is_go_zero_time(self.expires_at)
            && self.expires_at > self.consumed_at
    }

    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(receipt_unavailable("spend payload of an invalid record"));
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone)
            .map_err(|e| receipt_unavailable(format!("marshal spend payload: {e}")))
    }
}

// --- Bearer values -----------------------------------------------------------

/// `restoreCapacityReceiptBearerValue` — mint one bearer value. It
/// takes no parameters, and that is the whole point: the value cannot
/// be a function of the receipt id, the set, the role, or the clock
/// because none are expressible through this signature. The only input
/// is `getrandom`.
pub(crate) fn bearer_value() -> Result<Zeroizing<[u8; BEARER_BYTES]>, Failure> {
    let mut bearer = Zeroizing::new([0u8; BEARER_BYTES]);
    rustix::rand::getrandom(&mut *bearer, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| receipt_unavailable(format!("bearer entropy: {e}")))?;
    Ok(bearer)
}

/// `restoreCapacityReceiptBearerHash` — the one derivation from a
/// bearer value to what is durably stored: plain SHA-256, `sha256:` +
/// hex, like `validPrefixedSHA256` expects.
pub(crate) fn bearer_hash(bearer: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bearer);
    format!("sha256:{}", wire::hex_encode(&digest))
}

/// `restoreCapacityReceiptProofMatches` — the *only* place a presented
/// bearer value is compared against what was stored, and the
/// comparison is `wire::hmac_equal` (constant-time) over the derived
/// hash — never `==` over a secret.
pub(crate) fn proof_matches(presented: &[u8], stored_hash: &str) -> bool {
    wire::hmac_equal(bearer_hash(presented).as_bytes(), stored_hash.as_bytes())
}

// --- Mint / consumption results ----------------------------------------------

/// `RestoreCapacityReceiptMint` — everything one receipt is minted
/// from; every field comes from durable reserve records, never the
/// wire.
pub(crate) struct ReceiptMint {
    pub set_id: Uuid,
    pub launch_evidence_id: Uuid,
    pub backup_id: Uuid,
    pub repository_binding_id: Uuid,
    pub role: ReserveRole,
    pub device_id: String,
    pub reserved_bytes: u64,
}

/// `RestoreCapacityReceiptConsumption` — what a successful consume
/// yields: the member identity the spent receipt belongs to and the
/// window the provisional mark is in force for.
#[derive(Debug)]
pub(crate) struct ReceiptConsumption {
    pub receipt_id: Uuid,
    pub set_id: Uuid,
    pub role: ReserveRole,
    pub consumed_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// `RestoreCapacityProvisionalMark` — one receipt-keyed provisional
/// consumption mark and whether it is still in force.
#[derive(Debug)]
pub(crate) struct ProvisionalMark {
    pub receipt_id: Uuid,
    pub set_id: Uuid,
    pub role: ReserveRole,
    pub consumed: bool,
    pub in_force: bool,
    pub consumed_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

// --- protected read + two-pass decode ------------------------------------------

fn read_receipt_bytes(path: &Path) -> Result<Vec<u8>, Failure> {
    match durable::lstat(path) {
        Ok(_) => {}
        Err(rustix::io::Errno::NOENT) => {
            return Err(receipt_not_found(format!(
                "receipt record {} does not exist",
                path.display()
            )));
        }
        Err(_) => {
            return Err(receipt_unavailable(format!(
                "inspect receipt record {} failed",
                path.display()
            )));
        }
    }
    let file = open_protected_file(path)
        .map_err(|e| receipt_unavailable(format!("open receipt record: {}", e.message())))?;
    let meta = file
        .metadata()
        .map_err(|e| receipt_unavailable(format!("stat receipt record: {e}")))?;
    let st = rustix::fs::fstat(&file)
        .map_err(|e| receipt_unavailable(format!("fstat receipt record: {e}")))?;
    durable::validate_private_file(&st, "restore capacity receipt record")
        .map_err(|e| receipt_unavailable(e.message().to_string()))?;
    if meta.len() == 0 || meta.len() > MAX_RECORD_BYTES {
        return Err(receipt_unavailable("receipt record size out of bounds"));
    }
    use std::io::Read;
    let mut raw = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| receipt_unavailable(format!("read receipt record: {e}")))?;
    if raw.is_empty() || raw.len() as u64 > MAX_RECORD_BYTES {
        return Err(receipt_unavailable("receipt record size out of bounds"));
    }
    Ok(raw)
}

/// `decodeRestoreCapacityReceiptRecord` — the same two-pass rule the
/// reserve store applies: unrecognized schema is ambiguous, never
/// absent.
fn decode_record<T: DeserializeOwned>(raw: &[u8]) -> Result<T, Failure> {
    #[derive(Deserialize)]
    struct Envelope<'a> {
        schema_version: &'a str,
    }
    let envelope: Envelope<'_> = serde_json::from_slice(raw)
        .map_err(|e| receipt_ambiguous(format!("receipt record envelope: {e}")))?;
    if envelope.schema_version != RECORD_SCHEMA {
        return Err(receipt_ambiguous(format!(
            "receipt record schema_version {:?} is not {RECORD_SCHEMA:?}",
            envelope.schema_version
        )));
    }
    serde_json::from_slice(raw)
        .map_err(|e| receipt_ambiguous(format!("receipt record decode: {e}")))
}

// --- the ledger ----------------------------------------------------------------

/// `restoreCapacityReceiptStore` — `{receipts,draws,spends}/` under
/// `restore-capacity-receipts/`, the same per-record `flock`
/// serialization as the reserve store.
pub(crate) struct ReceiptStore {
    receipts: PathBuf,
    draws: PathBuf,
    spends: PathBuf,
    signing: std::sync::Arc<SigningService>,
}

impl ReceiptStore {
    /// `newRestoreCapacityReceiptStore`.
    pub(crate) fn new(
        broker_root: &Path,
        signing: std::sync::Arc<SigningService>,
    ) -> Result<Self, Failure> {
        durable::validate_broker_owned_root(broker_root, "restore capacity receipt broker root")?;
        let root = broker_root.join(DIRECTORY);
        let receipts = root.join(RECEIPTS_DIR);
        let draws = root.join(DRAWS_DIR);
        let spends = root.join(SPENDS_DIR);
        for (path, name) in [
            (&root, "restore capacity receipt root"),
            (&receipts, "restore capacity receipt record root"),
            (&draws, "restore capacity receipt draw root"),
            (&spends, "restore capacity receipt spend root"),
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
                receipt_unavailable(format!(
                    "restore capacity receipt store: create {name}: {e}"
                ))
            })?;
            durable::validate_private_directory(path, name)
                .map_err(|e| receipt_unavailable(e.message().to_string()))?;
        }
        Ok(Self {
            receipts,
            draws,
            spends,
            signing,
        })
    }

    /// `s.receipts`/`s.draws`/`s.spends` — sweep enumeration roots.
    pub(crate) fn receipts_dir(&self) -> &Path {
        &self.receipts
    }

    pub(crate) fn draws_dir(&self) -> &Path {
        &self.draws
    }

    pub(crate) fn spends_dir(&self) -> &Path {
        &self.spends
    }

    /// `s.receiptPath`/`s.drawPath`/`s.spendPath`.
    pub(crate) fn receipt_path(&self, receipt_id: Uuid) -> PathBuf {
        self.receipts
            .join(format!("{}.json", generation_key(&receipt_id.to_string())))
    }

    pub(crate) fn draw_path(&self, set_id: Uuid) -> PathBuf {
        self.draws
            .join(format!("{}.json", generation_key(&set_id.to_string())))
    }

    pub(crate) fn spend_path(&self, set_id: Uuid, role: ReserveRole) -> PathBuf {
        self.spends.join(format!(
            "{}.json",
            generation_key(&format!("{set_id}/{}", role.as_str()))
        ))
    }

    fn open_lock(&self, record_path: &Path) -> Result<std::os::fd::OwnedFd, Failure> {
        let lock_path = {
            let mut os = record_path.as_os_str().to_os_string();
            os.push(".lock");
            PathBuf::from(os)
        };
        durable::open_lock(&lock_path)
            .map_err(|e| receipt_unavailable(format!("lock receipt record: {}", e.message())))
    }

    fn sign_receipt(&self, record: &mut ReceiptRecord) -> Result<(), Failure> {
        record.hmac = self
            .signing
            .fingerprint(RECEIPT_HMAC_DOMAIN, &record.payload()?);
        Ok(())
    }

    fn sign_draw(&self, record: &mut DrawRecord) -> Result<(), Failure> {
        record.hmac = self
            .signing
            .fingerprint(DRAW_HMAC_DOMAIN, &record.payload()?);
        Ok(())
    }

    /// `Mint` — one bearer receipt: fresh V7 id, 32 `getrandom` bytes,
    /// a durable record carrying only the hash. `O_EXCL`, never
    /// replace: a freshly minted receipt id can never legitimately
    /// collide, so a collision is a broken store rather than a retry.
    pub(crate) fn mint(&self, mint: ReceiptMint, now: OffsetDateTime) -> Result<Receipt, Failure> {
        if mint.set_id.is_nil()
            || mint.launch_evidence_id.is_nil()
            || mint.backup_id.is_nil()
            || mint.repository_binding_id.is_nil()
            || mint.reserved_bytes == 0
            || !wire::valid_prefixed_sha256(&mint.device_id)
            || wire::is_go_zero_time(now)
        {
            return Err(receipt_unavailable("invalid mint arguments"));
        }
        let receipt_id = Uuid::now_v7();
        let bearer = bearer_value()?;
        let issued_at = now;
        let expires_at = issued_at + RECEIPT_LIFETIME;
        let hash = bearer_hash(&*bearer);
        let proof = wire::hex_encode(&*bearer);
        let mut record = ReceiptRecord {
            schema_version: RECORD_SCHEMA.to_string(),
            receipt_id,
            set_id: mint.set_id,
            launch_evidence_id: mint.launch_evidence_id,
            backup_id: mint.backup_id,
            repository_binding_id: mint.repository_binding_id,
            role: mint.role,
            device_id: mint.device_id.clone(),
            reserved_bytes: mint.reserved_bytes,
            issued_at,
            expires_at,
            bearer_value_hash: hash,
            consumed_at: wire::go_zero_time(),
            hmac: String::new(),
        };
        self.sign_receipt(&mut record)?;
        let path = self.receipt_path(receipt_id);
        let lock = self.open_lock(&path)?;
        let write = durable::write_exclusive_json(&path, &record);
        durable::unlock_and_close(lock);
        write.map_err(|e| receipt_unavailable(format!("publish receipt: {}", e.message())))?;
        // `bearer` (the raw 32 bytes) is a `Zeroizing` — scrubbed on
        // drop. `proof` is the one live copy the bundle will scrub.
        Ok(Receipt {
            schema_version: RECEIPT_WIRE_SCHEMA.to_string(),
            receipt_id,
            backup_id: mint.backup_id,
            repository_binding_id: mint.repository_binding_id,
            role: mint.role.as_str().to_string(),
            device_id: mint.device_id,
            reserved_bytes: mint.reserved_bytes,
            issued_at,
            expires_at,
            authority_proof: proof,
        })
    }

    /// `Consume` — spend one receipt, exactly once. Refusal order:
    /// launch binding, bearer value (constant time, *before* replay so
    /// "already spent" is only disclosed to a holder of the value),
    /// replay, the 20-minute window.
    pub(crate) fn consume(
        &self,
        receipt_id: Uuid,
        presented: &[u8],
        launch_evidence_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ReceiptConsumption, Failure> {
        if receipt_id.is_nil()
            || receipt_id.get_version_num() != 7
            || presented.len() != BEARER_BYTES
            || launch_evidence_id.is_nil()
            || wire::is_go_zero_time(now)
        {
            return Err(receipt_unavailable("invalid consume arguments"));
        }
        let path = self.receipt_path(receipt_id);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = self.read_receipt(receipt_id)?;
            if record.launch_evidence_id != launch_evidence_id {
                return Err(receipt_proof());
            }
            if !proof_matches(presented, &record.bearer_value_hash) {
                return Err(receipt_proof());
            }
            if !wire::is_go_zero_time(record.consumed_at) {
                return Err(receipt_replayed());
            }
            if now < record.issued_at || now >= record.expires_at {
                return Err(receipt_lapsed());
            }
            record.consumed_at = now;
            self.sign_receipt(&mut record)?;
            durable::replace_json(&path, &record)
                .map_err(|e| receipt_unavailable(format!("rewrite receipt: {}", e.message())))?;
            // The spend pointer lands *after* the receipt is marked —
            // a failure here still reports a failed consume even though
            // the receipt is spent; a re-presentation is refused as a
            // replay and the engine draws fresh (the safe direction).
            self.write_spend(&record)?;
            Ok(ReceiptConsumption {
                receipt_id: record.receipt_id,
                set_id: record.set_id,
                role: record.role,
                consumed_at: record.consumed_at,
                expires_at: record.expires_at,
            })
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `writeSpend` — the `(set, role) → spent receipt` pointer.
    fn write_spend(&self, receipt: &ReceiptRecord) -> Result<(), Failure> {
        let mut record = SpendRecord {
            schema_version: RECORD_SCHEMA.to_string(),
            set_id: receipt.set_id,
            role: receipt.role,
            receipt_id: receipt.receipt_id,
            launch_evidence_id: receipt.launch_evidence_id,
            consumed_at: receipt.consumed_at,
            expires_at: receipt.expires_at,
            hmac: String::new(),
        };
        record.hmac = self
            .signing
            .fingerprint(SPEND_HMAC_DOMAIN, &record.payload()?);
        let path = self.spend_path(record.set_id, record.role);
        let lock = self.open_lock(&path)?;
        let write = durable::replace_json(&path, &record);
        durable::unlock_and_close(lock);
        write.map_err(|e| receipt_unavailable(format!("write spend: {}", e.message())))
    }

    /// `ReadSpend` — which receipt was most recently spent for one
    /// `(set, role)`, from the ledger.
    pub(crate) fn read_spend(
        &self,
        set_id: Uuid,
        role: ReserveRole,
    ) -> Result<SpendRecord, Failure> {
        if set_id.is_nil() {
            return Err(receipt_unavailable("nil set id"));
        }
        let raw = read_receipt_bytes(&self.spend_path(set_id, role))?;
        let record: SpendRecord = decode_record(&raw)?;
        if record.set_id != set_id || record.role != role || !record.valid() {
            return Err(receipt_unavailable(
                "spend record identity or shape invalid",
            ));
        }
        let expected = self
            .signing
            .fingerprint(SPEND_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(receipt_unavailable("spend record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `readSpendAtPath` — the sweep's variant: identity unknown at
    /// call time; the record must validate and live where the store
    /// would have minted it.
    pub(crate) fn read_spend_at_path(&self, path: &Path) -> Result<SpendRecord, Failure> {
        let raw = read_receipt_bytes(path)?;
        let record: SpendRecord = decode_record(&raw)?;
        if !record.valid() || self.spend_path(record.set_id, record.role) != path {
            return Err(receipt_unavailable("spend record path/identity mismatch"));
        }
        let expected = self
            .signing
            .fingerprint(SPEND_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(receipt_unavailable("spend record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `ProvisionalMark` — the receipt-keyed provisional consumption
    /// mark: consumed, and still in force inside its own window.
    pub(crate) fn provisional_mark(
        &self,
        receipt_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ProvisionalMark, Failure> {
        if receipt_id.is_nil() || wire::is_go_zero_time(now) {
            return Err(receipt_unavailable("invalid mark arguments"));
        }
        let record = self.read_receipt(receipt_id)?;
        let consumed = !wire::is_go_zero_time(record.consumed_at);
        Ok(ProvisionalMark {
            receipt_id: record.receipt_id,
            set_id: record.set_id,
            role: record.role,
            consumed,
            in_force: consumed && now < record.expires_at,
            consumed_at: record.consumed_at,
            expires_at: record.expires_at,
        })
    }

    /// `ReadReceipt` — non-mutating.
    pub(crate) fn read_receipt(&self, receipt_id: Uuid) -> Result<ReceiptRecord, Failure> {
        if receipt_id.is_nil() {
            return Err(receipt_unavailable("nil receipt id"));
        }
        let raw = read_receipt_bytes(&self.receipt_path(receipt_id))?;
        let record: ReceiptRecord = decode_record(&raw)?;
        if record.receipt_id != receipt_id || !record.valid() {
            return Err(receipt_unavailable(
                "receipt record identity or shape invalid",
            ));
        }
        let expected = self
            .signing
            .fingerprint(RECEIPT_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(receipt_unavailable("receipt record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `readReceiptAtPath` — sweep variant (receipt directory is
    /// enumerated by name only).
    pub(crate) fn read_receipt_at_path(&self, path: &Path) -> Result<ReceiptRecord, Failure> {
        let raw = read_receipt_bytes(path)?;
        let record: ReceiptRecord = decode_record(&raw)?;
        if !record.valid() || self.receipt_path(record.receipt_id) != path {
            return Err(receipt_unavailable("receipt record path/identity mismatch"));
        }
        let expected = self
            .signing
            .fingerprint(RECEIPT_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(receipt_unavailable("receipt record HMAC mismatch"));
        }
        Ok(record)
    }

    /// `ClaimDraw` — record one more draw against this set, refusing
    /// past the per-set ceiling. Taken before any receipt is minted,
    /// so a refused draw mints nothing.
    pub(crate) fn claim_draw(&self, set_id: Uuid, now: OffsetDateTime) -> Result<u64, Failure> {
        if set_id.is_nil() || wire::is_go_zero_time(now) {
            return Err(receipt_unavailable("invalid draw arguments"));
        }
        let path = self.draw_path(set_id);
        let lock = self.open_lock(&path)?;
        let result = (|| {
            let mut record = match self.read_draw(set_id) {
                Ok(record) => record,
                Err(e) if is_receipt_not_found(&e) => DrawRecord {
                    schema_version: RECORD_SCHEMA.to_string(),
                    set_id,
                    draws: 0,
                    updated_at: wire::go_zero_time(),
                    hmac: String::new(),
                },
                Err(e) => return Err(e),
            };
            if record.draws >= MAX_DRAWS_PER_SET {
                return Err(receipt_draws_exhausted());
            }
            record.draws += 1;
            record.updated_at = now;
            self.sign_draw(&mut record)?;
            durable::replace_json(&path, &record)
                .map_err(|e| receipt_unavailable(format!("write draw: {}", e.message())))?;
            Ok(record.draws)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `readDraw` — authenticate the per-set counter.
    fn read_draw(&self, set_id: Uuid) -> Result<DrawRecord, Failure> {
        let raw = read_receipt_bytes(&self.draw_path(set_id))?;
        let record: DrawRecord = decode_record(&raw)?;
        if record.set_id != set_id || !record.valid() {
            return Err(receipt_unavailable("draw record identity or shape invalid"));
        }
        let expected = self
            .signing
            .fingerprint(DRAW_HMAC_DOMAIN, &record.payload()?);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(receipt_unavailable("draw record HMAC mismatch"));
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    //! `restore_capacity_receipt_test.go` — the ledger's upstream suite.
    //! The two AST-level assertions upstream runs over its own source are
    //! carried over as source-text scans: in Rust the property is just as
    //! invisible to behavioural tests (a timing loop passes against `==`
    //! identically, and a receipt-id-derived bearer is distinct and
    //! zeroable just like a random one), so the assertion stays on the
    //! symbol and the call site.

    use super::*;
    use crate::broker::restore_capacity::store_path;
    use crate::broker::signing::SigningService;
    use crate::broker::testutil::TempDir;
    use std::sync::Arc;

    fn new_receipt_store() -> (ReceiptStore, TempDir) {
        let root = TempDir::new("receipt-store");
        rustix::fs::chmod(&*root, rustix::fs::Mode::from_raw_mode(0o700)).unwrap();
        (
            ReceiptStore::new(&root, Arc::new(SigningService::new())).unwrap(),
            root,
        )
    }

    /// `testReceiptDeviceFingerprint` — minted through the resolver's own
    /// derivation, never hand-written: the receipt's device id is sha256
    /// over exactly this value.
    fn test_device_fingerprint(seed: i32) -> String {
        let fsid = ((seed as u32 as u64) << 32) | (seed.wrapping_mul(7) as u32 as u64);
        store_path::device_fingerprint(fsid).unwrap()
    }

    fn test_mint() -> ReceiptMint {
        let fingerprint = test_device_fingerprint(11);
        let device_id = super::super::frame::device_id_from_fingerprint(&fingerprint).unwrap();
        ReceiptMint {
            set_id: Uuid::now_v7(),
            launch_evidence_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            repository_binding_id: Uuid::now_v7(),
            role: ReserveRole::PostgresData,
            device_id,
            reserved_bytes: central_backup::backup::capacity::SURVIVAL_RESERVE_BYTES,
        }
    }

    fn decode_proof(proof: &str) -> Vec<u8> {
        wire::hex_decode(proof).unwrap()
    }

    #[test]
    fn mint_produces_a_consumer_admissible_receipt() {
        let (store, _root) = new_receipt_store();
        let mint = test_mint();
        let now = OffsetDateTime::now_utc();
        let receipt = store.mint(mint_ref(&mint), now).unwrap();
        assert_eq!(receipt.schema_version, RECEIPT_WIRE_SCHEMA);
        assert!(!receipt.receipt_id.is_nil());
        assert_eq!(receipt.receipt_id.get_version_num(), 7);
        assert_eq!(receipt.backup_id, mint.backup_id);
        assert_eq!(receipt.repository_binding_id, mint.repository_binding_id);
        assert_eq!(receipt.role, mint.role.as_str());
        assert_eq!(receipt.device_id, mint.device_id);
        // The consumer requires "sha256:" + 64 lowercase hex.
        assert!(receipt.device_id.starts_with("sha256:"));
        assert_eq!(receipt.device_id.len(), "sha256:".len() + 64);
        assert_eq!(receipt.device_id.to_lowercase(), receipt.device_id);
        assert!(receipt.reserved_bytes >= central_backup::backup::capacity::SURVIVAL_RESERVE_BYTES);
        assert!(!wire::is_go_zero_time(receipt.issued_at));
        assert!(!wire::is_go_zero_time(receipt.expires_at));
        assert!(receipt.expires_at > receipt.issued_at);
        assert!(now >= receipt.issued_at);
        assert!(now < receipt.expires_at);
        assert_eq!(receipt.expires_at - receipt.issued_at, RECEIPT_LIFETIME);
        assert!(!receipt.authority_proof.is_empty());
    }

    fn mint_ref(mint: &ReceiptMint) -> ReceiptMint {
        ReceiptMint {
            set_id: mint.set_id,
            launch_evidence_id: mint.launch_evidence_id,
            backup_id: mint.backup_id,
            repository_binding_id: mint.repository_binding_id,
            role: mint.role,
            device_id: mint.device_id.clone(),
            reserved_bytes: mint.reserved_bytes,
        }
    }

    #[test]
    fn consumption_refusal_order() {
        let (store, _root) = new_receipt_store();
        let mint = test_mint();
        let now = OffsetDateTime::now_utc();
        let receipt = store.mint(mint_ref(&mint), now).unwrap();
        let proof = decode_proof(&receipt.authority_proof);

        // A receipt minted for one launch may never be spent by another.
        let err = store
            .consume(receipt.receipt_id, &proof, Uuid::now_v7(), now)
            .unwrap_err();
        assert!(is_receipt_proof(&err));
        // The wrong bearer value.
        let mut wrong = proof.clone();
        wrong[0] ^= 0xff;
        let err = store
            .consume(receipt.receipt_id, &wrong, mint.launch_evidence_id, now)
            .unwrap_err();
        assert!(is_receipt_proof(&err));
        // Outside the window, before it is ever spent.
        let err = store
            .consume(
                receipt.receipt_id,
                &proof,
                mint.launch_evidence_id,
                now + RECEIPT_LIFETIME,
            )
            .unwrap_err();
        assert!(is_receipt_lapsed(&err));
        // The legitimate spend.
        let consumption = store
            .consume(
                receipt.receipt_id,
                &proof,
                mint.launch_evidence_id,
                now + time::Duration::minutes(1),
            )
            .unwrap();
        assert_eq!(consumption.set_id, mint.set_id);
        assert_eq!(consumption.role, mint.role);
        assert!(!wire::is_go_zero_time(consumption.consumed_at));
        // Replay, with the correct value, is the replay refusal —
        // distinct from a proof failure.
        let err = store
            .consume(
                receipt.receipt_id,
                &proof,
                mint.launch_evidence_id,
                now + time::Duration::minutes(2),
            )
            .unwrap_err();
        assert!(is_receipt_replayed(&err));
        // A non-holder is told nothing about spent state: the
        // constant-time comparison runs first.
        let err = store
            .consume(
                receipt.receipt_id,
                &wrong,
                mint.launch_evidence_id,
                now + time::Duration::minutes(2),
            )
            .unwrap_err();
        assert!(is_receipt_proof(&err));
        // An unknown receipt is absent, never ambiguous.
        let err = store
            .consume(Uuid::now_v7(), &proof, mint.launch_evidence_id, now)
            .unwrap_err();
        assert!(is_receipt_not_found(&err));
    }

    #[test]
    fn provisional_mark_lapses_at_the_receipt_window() {
        let (store, _root) = new_receipt_store();
        let mint = test_mint();
        let issued = OffsetDateTime::now_utc();
        let receipt = store.mint(mint_ref(&mint), issued).unwrap();
        let proof = decode_proof(&receipt.authority_proof);

        let before = store.provisional_mark(receipt.receipt_id, issued).unwrap();
        assert!(!before.consumed);
        assert!(!before.in_force);
        store
            .consume(receipt.receipt_id, &proof, mint.launch_evidence_id, issued)
            .unwrap();

        let absolute_expiry = issued + crate::broker::restore_capacity::RESERVE_ABSOLUTE_LIFETIME;
        for (at, in_force) in [
            (issued, true),
            (issued + time::Duration::minutes(1), true),
            (
                issued + RECEIPT_LIFETIME - time::Duration::nanoseconds(1),
                true,
            ),
            (issued + RECEIPT_LIFETIME, false),
            (
                issued + RECEIPT_LIFETIME + time::Duration::minutes(1),
                false,
            ),
        ] {
            let mark = store.provisional_mark(receipt.receipt_id, at).unwrap();
            assert!(mark.consumed, "a consumed receipt reports no consumption");
            assert_eq!(
                mark.in_force, in_force,
                "mark in force at {at} (window {}, set expiry {})",
                mark.expires_at, absolute_expiry
            );
            // The two clocks are genuinely different: the set is still
            // far from its absolute expiry at every row above.
            assert!(
                at < absolute_expiry,
                "fixture proves nothing about distinct clocks"
            );
        }
        // A lapsed mark does not resurrect the receipt: it is still spent.
        let err = store
            .consume(
                receipt.receipt_id,
                &proof,
                mint.launch_evidence_id,
                issued + RECEIPT_LIFETIME + time::Duration::minutes(1),
            )
            .unwrap_err();
        assert!(is_receipt_replayed(&err));
    }

    #[test]
    fn draw_ceiling_is_enforced() {
        let (store, _root) = new_receipt_store();
        let set_id = Uuid::now_v7();
        let now = OffsetDateTime::now_utc();
        for draw in 1..=MAX_DRAWS_PER_SET {
            let got = store.claim_draw(set_id, now).unwrap();
            assert_eq!(got, draw);
        }
        let err = store.claim_draw(set_id, now).unwrap_err();
        assert!(is_receipt_draws_exhausted(&err));
        // The ceiling is per set, not per host.
        assert!(store.claim_draw(Uuid::now_v7(), now).is_ok());
    }

    #[test]
    fn record_ambiguity_is_not_absence() {
        let (store, _root) = new_receipt_store();
        let mint = test_mint();
        let now = OffsetDateTime::now_utc();
        let receipt = store.mint(mint_ref(&mint), now).unwrap();
        let mut record = store.read_receipt(receipt.receipt_id).unwrap();
        record.schema_version = "central.restore-capacity-receipt-record/v2".to_string();
        durable::replace_json(&store.receipt_path(receipt.receipt_id), &record).unwrap();
        let err = store.read_receipt(receipt.receipt_id).unwrap_err();
        assert!(is_receipt_ambiguous(&err));
        let err = store
            .consume(
                receipt.receipt_id,
                &decode_proof(&receipt.authority_proof),
                mint.launch_evidence_id,
                now,
            )
            .unwrap_err();
        assert!(is_receipt_ambiguous(&err));
    }

    #[test]
    fn record_tampering_is_refused() {
        let (store, _root) = new_receipt_store();
        let mint = test_mint();
        let now = OffsetDateTime::now_utc();
        let receipt = store.mint(mint_ref(&mint), now).unwrap();
        let proof = decode_proof(&receipt.authority_proof);
        store
            .consume(receipt.receipt_id, &proof, mint.launch_evidence_id, now)
            .unwrap();
        let mut record = store.read_receipt(receipt.receipt_id).unwrap();
        record.consumed_at = wire::go_zero_time();
        durable::replace_json(&store.receipt_path(receipt.receipt_id), &record).unwrap();
        let err = store
            .consume(receipt.receipt_id, &proof, mint.launch_evidence_id, now)
            .unwrap_err();
        assert_eq!(err.code(), RECEIPT_UNAVAILABLE);
    }

    // --- source-level assertions -------------------------------------------
    //
    // Upstream parses its own AST for these two; the Rust port scans the
    // file's own source with `include_str!`, which is the same kind of
    // assertion — a behavioural test cannot see either property.

    /// Extract a `fn name` body from the file's own source: everything
    /// from the `fn name(` signature to the next top-level `fn ` or
    /// `///` at column 0. Good enough for the two single-purpose
    /// functions these assertions cover — both are short and followed
    /// by a doc comment or another item.
    fn source_fn<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("this file declares no {signature}"));
        let body = &source[start..];
        // Find the end: the first `\nfn `, `\n/// ` or `\n// ---` at
        // column 0 after the signature.
        let mut end = body.len();
        for marker in ["\nfn ", "\n/// ", "\n// ---", "\nimpl ", "\n#[", "\npub"] {
            if let Some(pos) = body[1..].find(marker) {
                end = end.min(pos + 1);
            }
        }
        &body[..end]
    }

    #[test]
    fn proof_comparison_is_constant_time() {
        // Bearer assertion 3: the comparison path calls the
        // constant-time helper, and nowhere in this file does `==`/`!=`
        // touch a bearer- or proof-named value — so the single
        // comparison path cannot be quietly bypassed.
        let source = include_str!("receipt.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let matcher = source_fn(source, "fn proof_matches(");
        assert!(
            matcher.contains("hmac_equal"),
            "proof_matches does not call the constant-time comparator",
        );
        for name in [
            "presented ==",
            "stored_hash ==",
            "bearer ==",
            "authority_proof ==",
            "bearer_value_hash ==",
            "== presented",
            "== bearer",
        ] {
            assert!(
                !source.contains(name),
                "a bearer/proof value is compared with == at {name:?}; the only comparison path must be constant-time",
            );
        }
    }

    #[test]
    fn bearer_value_is_bound_to_its_entropy_source() {
        // Bearer assertion 5: `bearer_value` takes no parameters (so a
        // derivation from the receipt id is unexpressible through it),
        // reads `getrandom`, and mint obtains its bearer from that
        // function alone — plus the behavioural floor that repeated
        // calls do not repeat.
        let source = include_str!("receipt.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(
            source.contains("pub(crate) fn bearer_value() ->"),
            "bearer_value takes parameters; a derivation from the receipt id becomes expressible",
        );
        let generator = source_fn(source, "fn bearer_value()");
        assert!(
            generator.contains("getrandom"),
            "bearer_value does not read from an entropy source",
        );
        // mint must obtain the bearer from bearer_value exactly once.
        let mint = source_fn(source, "fn mint(");
        assert_eq!(
            mint.matches("bearer_value()").count(),
            1,
            "mint obtains its bearer from bearer_value other than exactly once",
        );

        // The behavioural floor: the generator does not repeat itself.
        let mut seen = std::collections::HashSet::with_capacity(64);
        for _ in 0..64 {
            let value = bearer_value().unwrap();
            assert_eq!(value.len(), BEARER_BYTES);
            assert!(
                seen.insert(wire::hex_encode(&*value)),
                "bearer_value repeated a value"
            );
        }
    }
}
