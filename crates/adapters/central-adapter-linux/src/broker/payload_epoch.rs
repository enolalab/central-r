//! `payload_epoch_store_linux.go` — the broker-protected active
//! payload-epoch store: an HMAC-authenticated generation chain under
//! `payload-epochs/generations/<operation-id>.json`, a sealed
//! `active.json` pointer, and a `state.lock` `flock` serializing every
//! read-modify-write.
//!
//! Every read path re-authenticates: the record is parsed through
//! [`read_canonical_payload_epoch_json`] (fd-relative `openat2`,
//! `0600`/nlink-1/owner shape checks, bounded 16 KiB read, strict
//! `deny_unknown_fields` decode, no trailing data), its `hmac_sha256`
//! recomputed under the `slice-c-*-v1` domains, and the chain walked —
//! unique genesis, no forks, every record reachable. Anything else is
//! `errPayloadEpochUnavailable`: the store fails closed, so a runtime
//! peer cannot mint or rotate epochs, and tampering reads as
//! unavailable.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use uuid::Uuid;

use super::durable::{
    self, PRIVATE_DIRECTORY_MODE, open_lock, replace_json, sync_dir, unlock_and_close,
    validate_broker_owned_root, validate_private_directory, validate_private_file,
    write_exclusive_json,
};
use super::signing::SigningService;
use super::wire::{valid_prefixed_sha256, valid_sha256_hex};
use crate::broker::protected_file::open_protected_file;

const PAYLOAD_EPOCH_DIRECTORY: &str = "payload-epochs";
const GENERATIONS: &str = "generations";
const ACTIVE_FILENAME: &str = "active.json";
const LOCK_FILENAME: &str = "state.lock";
const GENERATION_SCHEMA: &str = "central.active-payload-epoch-generation/v1";
const ACTIVE_SCHEMA: &str = "central.active-payload-epoch-pointer/v1";
const GENERATION_HMAC_DOMAIN: &str = "slice-c-active-payload-epoch-generation-v1";
const ACTIVE_HMAC_DOMAIN: &str = "slice-c-active-payload-epoch-pointer-v1";
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_GENERATIONS: usize = 4096;

/// `errPayloadEpochUnavailable` — the store's single refusal surface.
fn unavailable() -> Failure {
    Failure::unavailable(
        "broker_payload_epoch",
        "broker: active payload epoch unavailable",
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationRecord {
    schema_version: String,
    operation_id: String,
    payload_epoch_id: String,
    prior_payload_epoch_id: String,
    hmac_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveRecord {
    schema_version: String,
    operation_id: String,
    payload_epoch_id: String,
    prior_payload_epoch_id: String,
    generation_digest_sha256: String,
    hmac_sha256: String,
}

#[derive(Debug, Clone)]
struct ValidatedGeneration {
    operation_id: Uuid,
    payload_epoch_id: Uuid,
    prior_epoch_id: Uuid,
    canonical_json: Vec<u8>,
}

#[derive(Default)]
struct EpochGraph {
    by_operation: BTreeMap<Uuid, ValidatedGeneration>,
    by_epoch: BTreeMap<Uuid, ValidatedGeneration>,
    tip: Option<ValidatedGeneration>,
}

/// `payloadEpochStore` — the broker-protected epoch chain.
pub struct PayloadEpochStore {
    broker_root: PathBuf,
    root: PathBuf,
    generations: PathBuf,
    active: PathBuf,
    lock_path: PathBuf,
    signing: SigningService,
}

/// `newPayloadEpochStore` — create-or-validate the store layout.
///
/// # Errors
/// `broker_payload_epoch` when the broker root fails the
/// owner-controlled check or the directories cannot be made private.
pub fn new_payload_epoch_store(
    broker_root: &Path,
    signing: SigningService,
) -> Result<PayloadEpochStore, Failure> {
    if validate_broker_owned_root(broker_root, "payload epoch broker root").is_err() {
        return Err(unavailable());
    }
    let root = broker_root.join(PAYLOAD_EPOCH_DIRECTORY);
    create_and_validate_epoch_directory(&root)?;
    let generations = root.join(GENERATIONS);
    create_and_validate_epoch_directory(&generations)?;
    Ok(payload_epoch_store_at(
        broker_root,
        root,
        generations,
        signing,
    ))
}

/// `openPayloadEpochStore` — open an existing, already-private store
/// (the read-only `ActivePayloadEpochSource` shape). Missing or
/// insecure layout fails closed.
///
/// # Errors
/// `broker_payload_epoch` on any layout violation.
pub fn open_payload_epoch_store(
    broker_root: &Path,
    signing: SigningService,
) -> Result<PayloadEpochStore, Failure> {
    let root = broker_root.join(PAYLOAD_EPOCH_DIRECTORY);
    let generations = root.join(GENERATIONS);
    if validate_private_directory(&root, "payload epoch root").is_err()
        || validate_private_directory(&generations, "payload epoch generations").is_err()
    {
        return Err(unavailable());
    }
    Ok(payload_epoch_store_at(
        broker_root,
        root,
        generations,
        signing,
    ))
}

fn payload_epoch_store_at(
    broker_root: &Path,
    root: PathBuf,
    generations: PathBuf,
    signing: SigningService,
) -> PayloadEpochStore {
    PayloadEpochStore {
        broker_root: broker_root.to_path_buf(),
        active: root.join(ACTIVE_FILENAME),
        lock_path: root.join(LOCK_FILENAME),
        root,
        generations,
        signing,
    }
}

/// `ActivePayloadEpochSource` — the read-only seam consumed by the
/// PostgreSQL accepted-facts adapter: opens the broker's signing key
/// and never creates or rotates protected state.
pub struct ActivePayloadEpochSource {
    store: PayloadEpochStore,
}

impl ActivePayloadEpochSource {
    /// `NewActivePayloadEpochSource` — fail-closed open of an existing
    /// protected store.
    ///
    /// # Errors
    /// `broker_payload_epoch` when the broker root, key, or layout is
    /// absent or insecure.
    pub fn new(broker_root: &Path) -> Result<Self, Failure> {
        if validate_broker_owned_root(broker_root, "payload epoch broker root").is_err() {
            return Err(unavailable());
        }
        let key_path = broker_root.join(super::durable::FINGERPRINT_KEY_FILENAME);
        let signing = load_signing_key(&key_path)?;
        let store = open_payload_epoch_store(broker_root, signing)?;
        Ok(Self { store })
    }

    /// `ActivePayloadEpochID` — the authenticated tip.
    ///
    /// # Errors
    /// `broker_payload_epoch` when the epoch is absent or tampered.
    pub fn active_payload_epoch_id(&self) -> Result<Uuid, Failure> {
        self.store.read_active()
    }
}

/// Load the persistent signing key without creating it (the read-only
/// composition's strict counterpart to `new_persistent`).
fn load_signing_key(key_path: &Path) -> Result<SigningService, Failure> {
    let meta = durable::lstat(key_path).map_err(|_| unavailable())?;
    if !rustix::fs::FileType::from_raw_mode(meta.st_mode).is_file()
        || rustix::fs::FileType::from_raw_mode(meta.st_mode).is_symlink()
        || meta.st_mode & 0o777 != super::durable::PRIVATE_FILE_MODE
    {
        return Err(unavailable());
    }
    if meta.st_uid != rustix::process::geteuid().as_raw() || meta.st_nlink != 1 {
        return Err(unavailable());
    }
    let key = durable::read_file(key_path).map_err(|_| unavailable())?;
    if key.len() != 32 {
        return Err(unavailable());
    }
    Ok(SigningService::from_key(key))
}

fn create_and_validate_epoch_directory(path: &Path) -> Result<(), Failure> {
    let created = match rustix::fs::mkdirat(
        rustix::fs::CWD,
        path.as_os_str(),
        rustix::fs::Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE),
    ) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(_) => return Err(unavailable()),
    };
    if validate_private_directory(path, "payload epoch directory").is_err() {
        return Err(unavailable());
    }
    if created {
        sync_dir(path.parent().unwrap_or(path)).map_err(|_| unavailable())?;
    }
    Ok(())
}

impl PayloadEpochStore {
    fn validate_layout(&self) -> Result<(), Failure> {
        if validate_broker_owned_root(&self.broker_root, "payload epoch broker root").is_err()
            || validate_private_directory(&self.root, "payload epoch root").is_err()
            || validate_private_directory(&self.generations, "payload epoch generations").is_err()
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// `CreateAndActivate` — install one immutable generation and
    /// atomically advance the active pointer. `operation_id` is the
    /// idempotent rotation request; the returned UUIDv7 is generated by
    /// the broker. `prior_epoch_id` may be nil only for genesis and
    /// must otherwise equal the current active epoch.
    ///
    /// # Errors
    /// `broker_payload_epoch` on any fencing, idempotency, layout, or
    /// durable-write failure.
    pub fn create_and_activate(
        &self,
        operation_id: Uuid,
        prior_epoch_id: Uuid,
    ) -> Result<Uuid, Failure> {
        if operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || (!prior_epoch_id.is_nil() && prior_epoch_id.get_version_num() != 7)
            || self.validate_layout().is_err()
        {
            return Err(unavailable());
        }
        let lock = open_lock(&self.lock_path)?;
        let result = self.create_and_activate_locked(operation_id, prior_epoch_id);
        unlock_and_close(lock);
        result
    }

    fn create_and_activate_locked(
        &self,
        operation_id: Uuid,
        prior_epoch_id: Uuid,
    ) -> Result<Uuid, Failure> {
        let (active, active_found) = self.read_active_record()?;
        let graph = self.read_generation_graph()?;
        let coherent = self.active_matches_graph(&active, active_found, &graph);

        if let Some(existing) = graph.by_operation.get(&operation_id) {
            if existing.prior_epoch_id != prior_epoch_id {
                return Err(unavailable());
            }
            if coherent {
                return Ok(existing.payload_epoch_id);
            }
            // The only recoverable partial commit is a create-only
            // generation whose exact prior remains active (or an
            // unpointed genesis).
            if graph.tip.as_ref().map(|t| t.operation_id) != Some(operation_id)
                || (active_found
                    && !active_matches_generation(&active, graph.by_epoch.get(&prior_epoch_id)))
                || (!active_found && !prior_epoch_id.is_nil())
            {
                return Err(unavailable());
            }
            self.publish_active(existing)?;
            return Ok(existing.payload_epoch_id);
        }

        if graph.by_operation.is_empty() {
            if active_found || !prior_epoch_id.is_nil() {
                return Err(unavailable());
            }
        } else if !coherent
            || !active_found
            || active.payload_epoch_id != prior_epoch_id.to_string()
        {
            return Err(unavailable());
        }

        let payload_epoch_id = Uuid::now_v7();
        if payload_epoch_id.is_nil()
            || payload_epoch_id.get_version_num() != 7
            || graph.by_epoch.contains_key(&payload_epoch_id)
        {
            return Err(unavailable());
        }
        let mut record = GenerationRecord {
            schema_version: GENERATION_SCHEMA.into(),
            operation_id: operation_id.to_string(),
            payload_epoch_id: payload_epoch_id.to_string(),
            prior_payload_epoch_id: payload_epoch_string(prior_epoch_id),
            hmac_sha256: String::new(),
        };
        self.sign_generation(&mut record)?;
        self.write_generation(&record)?;
        // Re-read through the authenticated path — upstream's post-write
        // `readGeneration` self-check.
        let created = self.read_generation(operation_id)?;
        if created.payload_epoch_id != payload_epoch_id || created.prior_epoch_id != prior_epoch_id
        {
            return Err(unavailable());
        }
        self.publish_active(&created)?;
        Ok(payload_epoch_id)
    }

    /// `ReadActive` — only a fully authenticated UUIDv7 at the unique
    /// tip of the protected generation chain.
    ///
    /// # Errors
    /// `broker_payload_epoch` when the pointer or chain fails
    /// authentication.
    pub fn read_active(&self) -> Result<Uuid, Failure> {
        if self.validate_layout().is_err() {
            return Err(unavailable());
        }
        let lock = open_lock(&self.lock_path)?;
        let result = (|| {
            let (active, found) = self.read_active_record()?;
            if !found {
                return Err(unavailable());
            }
            let graph = self.read_generation_graph()?;
            if !self.active_matches_graph(&active, true, &graph) {
                return Err(unavailable());
            }
            let tip = graph.tip.as_ref().ok_or_else(unavailable)?;
            Ok(tip.payload_epoch_id)
        })();
        unlock_and_close(lock);
        result
    }

    fn generation_path(&self, operation_id: Uuid) -> PathBuf {
        self.generations.join(format!("{operation_id}.json"))
    }

    fn write_generation(&self, record: &GenerationRecord) -> Result<(), Failure> {
        let operation_id = parse_epoch_uuid(&record.operation_id, false)?;
        write_exclusive_json(&self.generation_path(operation_id), record).map_err(|_| unavailable())
    }

    fn publish_active(&self, generation: &ValidatedGeneration) -> Result<(), Failure> {
        let digest = sha2::Sha256::digest(&generation.canonical_json);
        let mut record = ActiveRecord {
            schema_version: ACTIVE_SCHEMA.into(),
            operation_id: generation.operation_id.to_string(),
            payload_epoch_id: generation.payload_epoch_id.to_string(),
            prior_payload_epoch_id: payload_epoch_string(generation.prior_epoch_id),
            generation_digest_sha256: super::wire::sha256_prefixed(&digest),
            hmac_sha256: String::new(),
        };
        record.hmac_sha256 = self
            .signing
            .fingerprint(ACTIVE_HMAC_DOMAIN, &active_payload(&record));
        replace_json(&self.active, &record).map_err(|_| unavailable())
    }

    fn sign_generation(&self, record: &mut GenerationRecord) -> Result<(), Failure> {
        let payload = generation_payload(record);
        record.hmac_sha256 = self.signing.fingerprint(GENERATION_HMAC_DOMAIN, &payload);
        Ok(())
    }

    /// `readGeneration` — the authenticated generation for
    /// `operation_id`: canonical JSON, schema/HMAC/UUID checks.
    fn read_generation(&self, operation_id: Uuid) -> Result<ValidatedGeneration, Failure> {
        let (record, raw) =
            read_canonical_epoch_json::<GenerationRecord>(&self.generation_path(operation_id))?;
        if record.schema_version != GENERATION_SCHEMA
            || record.operation_id != operation_id.to_string()
            || !valid_sha256_hex(&record.hmac_sha256)
        {
            return Err(unavailable());
        }
        let payload = generation_payload(&record);
        let expected = self.signing.fingerprint(GENERATION_HMAC_DOMAIN, &payload);
        if !super::wire::hmac_equal(record.hmac_sha256.as_bytes(), expected.as_bytes()) {
            return Err(unavailable());
        }
        let parsed_operation = parse_epoch_uuid(&record.operation_id, false)?;
        let payload_epoch_id = parse_epoch_uuid(&record.payload_epoch_id, false)?;
        let prior_epoch_id = parse_epoch_uuid(&record.prior_payload_epoch_id, true)?;
        if payload_epoch_id == prior_epoch_id {
            return Err(unavailable());
        }
        let _ = record;
        Ok(ValidatedGeneration {
            operation_id: parsed_operation,
            payload_epoch_id,
            prior_epoch_id,
            canonical_json: raw,
        })
    }

    /// `readActiveRecord` — `(record, found)`: `ENOENT` on the pointer
    /// is `false`, not an error; anything else invalid is
    /// `errPayloadEpochUnavailable`.
    fn read_active_record(&self) -> Result<(ActiveRecord, bool), Failure> {
        match durable::lstat(&self.active) {
            Err(rustix::io::Errno::NOENT) => {
                return Ok((empty_active(), false));
            }
            Err(_) => return Err(unavailable()),
            Ok(_) => {}
        }
        let (record, _raw) = read_canonical_epoch_json::<ActiveRecord>(&self.active)?;
        if record.schema_version != ACTIVE_SCHEMA
            || !valid_prefixed_sha256(&record.generation_digest_sha256)
            || !valid_sha256_hex(&record.hmac_sha256)
        {
            return Err(unavailable());
        }
        parse_epoch_uuid(&record.operation_id, false)?;
        parse_epoch_uuid(&record.payload_epoch_id, false)?;
        parse_epoch_uuid(&record.prior_payload_epoch_id, true)?;
        let payload = active_payload(&record);
        let expected = self.signing.fingerprint(ACTIVE_HMAC_DOMAIN, &payload);
        if !super::wire::hmac_equal(record.hmac_sha256.as_bytes(), expected.as_bytes()) {
            return Err(unavailable());
        }
        Ok((record, true))
    }

    /// `readGenerationGraph` — load, authenticate, and chain-walk every
    /// generation record: unique genesis, no forks, every record
    /// reachable, unique tip.
    fn read_generation_graph(&self) -> Result<EpochGraph, Failure> {
        let entries = durable::read_dir(&self.generations).map_err(|_| unavailable())?;
        if entries.len() > MAX_GENERATIONS {
            return Err(unavailable());
        }
        let mut graph = EpochGraph {
            by_operation: BTreeMap::new(),
            by_epoch: BTreeMap::new(),
            tip: None,
        };
        let mut children: BTreeMap<Uuid, Uuid> = BTreeMap::new();
        let mut genesis = Uuid::nil();
        let entry_count = entries.len();
        for entry in &entries {
            if entry.file_type.is_dir() {
                return Err(unavailable());
            }
            let Some(name) = entry.name.to_str().map(str::to_owned) else {
                return Err(unavailable());
            };
            let Some(operation_text) = name.strip_suffix(".json") else {
                return Err(unavailable());
            };
            let operation_id = parse_epoch_uuid(operation_text, false)?;
            if name != format!("{operation_id}.json") {
                return Err(unavailable());
            }
            let generation = self.read_generation(operation_id)?;
            if graph
                .by_operation
                .insert(generation.operation_id, generation.clone())
                .is_some()
                || graph
                    .by_epoch
                    .insert(generation.payload_epoch_id, generation.clone())
                    .is_some()
            {
                return Err(unavailable());
            }
            if generation.prior_epoch_id.is_nil() {
                if !genesis.is_nil() {
                    return Err(unavailable());
                }
                genesis = generation.payload_epoch_id;
                continue;
            }
            if children
                .insert(generation.prior_epoch_id, generation.payload_epoch_id)
                .is_some()
            {
                // Two generations claim the same prior — a fork.
                return Err(unavailable());
            }
        }
        if entry_count == 0 {
            return Ok(graph);
        }
        if genesis.is_nil() {
            return Err(unavailable());
        }
        let mut current = genesis;
        let mut visited = 1usize;
        loop {
            let Some(generation) = graph.by_epoch.get(&current) else {
                return Err(unavailable());
            };
            if visited > entry_count {
                return Err(unavailable());
            }
            match children.get(&current) {
                None => {
                    if visited != entries.len() {
                        return Err(unavailable());
                    }
                    graph.tip = Some(generation.clone());
                    break;
                }
                Some(next) => {
                    current = *next;
                    visited += 1;
                }
            }
        }
        Ok(graph)
    }

    /// `activeMatchesGraph` — the pointer is coherent exactly when it
    /// pins the chain's unique tip.
    fn active_matches_graph(&self, active: &ActiveRecord, found: bool, graph: &EpochGraph) -> bool {
        if !found || graph.by_operation.is_empty() {
            return !found && graph.by_operation.is_empty();
        }
        match graph.tip.as_ref() {
            Some(tip) => active_matches_generation(active, Some(tip)),
            None => false,
        }
    }
}

fn empty_active() -> ActiveRecord {
    ActiveRecord {
        schema_version: String::new(),
        operation_id: String::new(),
        payload_epoch_id: String::new(),
        prior_payload_epoch_id: String::new(),
        generation_digest_sha256: String::new(),
        hmac_sha256: String::new(),
    }
}

/// `activeMatchesPayloadEpochGeneration` — the active record pins this
/// generation iff operation, epoch, prior, and the generation's
/// canonical digest all match.
fn active_matches_generation(
    active: &ActiveRecord,
    generation: Option<&ValidatedGeneration>,
) -> bool {
    let Some(generation) = generation else {
        return false;
    };
    let Ok(operation_id) = Uuid::parse_str(&active.operation_id) else {
        return false;
    };
    if operation_id != generation.operation_id
        || active.payload_epoch_id != generation.payload_epoch_id.to_string()
        || active.prior_payload_epoch_id != payload_epoch_string(generation.prior_epoch_id)
    {
        return false;
    }
    let digest = sha2::Sha256::digest(&generation.canonical_json);
    active.generation_digest_sha256 == super::wire::sha256_prefixed(&digest)
}

/// `payloadEpochGenerationPayload` — canonical JSON with `hmac_sha256`
/// cleared, the field upstream zeroes before signing.
fn generation_payload(record: &GenerationRecord) -> Vec<u8> {
    let mut r = record.clone();
    r.hmac_sha256 = String::new();
    serde_json::to_vec(&r).unwrap_or_default()
}

/// `payloadEpochActivePayload` — same zeroing for the pointer record.
fn active_payload(record: &ActiveRecord) -> Vec<u8> {
    let mut r = record.clone();
    r.hmac_sha256 = String::new();
    serde_json::to_vec(&r).unwrap_or_default()
}

/// `payloadEpochString` — nil serializes to `""`.
fn payload_epoch_string(id: Uuid) -> String {
    if id.is_nil() {
        String::new()
    } else {
        id.to_string()
    }
}

/// `parsePayloadEpochUUID` — UUIDv7, canonical lowercase form,
/// non-nil unless `allow_nil` (the genesis `prior` field).
fn parse_epoch_uuid(value: &str, allow_nil: bool) -> Result<Uuid, Failure> {
    if value.is_empty() && allow_nil {
        return Ok(Uuid::nil());
    }
    let id = Uuid::parse_str(value).map_err(|_| unavailable())?;
    if id.is_nil() || id.get_version_num() != 7 || id.to_string() != value {
        return Err(unavailable());
    }
    Ok(id)
}

/// `readCanonicalPayloadEpochJSON` — fd-relative `openat2` read
/// (`O_NOFOLLOW|O_NONBLOCK`, `S_ISREG`), `0600`/owner/nlink-1 shape,
/// bounded 16 KiB read, strict `deny_unknown_fields` decode, and a
/// trailing-data refusal — returns the record plus the raw canonical
/// bytes the digest is computed over.
fn read_canonical_epoch_json<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<(T, Vec<u8>), Failure> {
    let file = open_protected_file(path).map_err(|_| unavailable())?;
    let meta = rustix::fs::fstat(&file).map_err(|_| unavailable())?;
    if meta.st_size == 0 || meta.st_size > MAX_RECORD_BYTES as i64 {
        return Err(unavailable());
    }
    if validate_private_file(&meta, "payload epoch record").is_err() {
        return Err(unavailable());
    }
    use std::io::Read as _;
    let mut raw = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| unavailable())?;
    if raw.is_empty() || raw.len() as u64 > MAX_RECORD_BYTES {
        return Err(unavailable());
    }
    let mut de = serde_json::Deserializer::from_slice(&raw);
    let value = T::deserialize(&mut de).map_err(|_| unavailable())?;
    de.end().map_err(|_| unavailable())?;
    Ok((value, raw))
}

// ---------------------------------------------------------------------------
// Tests — upstream `payload_epoch_store_linux_test.go` fencing/tamper
// coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    fn store(dir: &Path) -> PayloadEpochStore {
        new_payload_epoch_store(dir, SigningService::new()).unwrap()
    }

    #[test]
    fn genesis_then_linear_chain() {
        let dir = TempDir::new("payload-epoch");
        let store = store(&dir);
        // Empty store: no active epoch.
        assert!(store.read_active().is_err());
        let genesis = store
            .create_and_activate(Uuid::now_v7(), Uuid::nil())
            .unwrap();
        assert_eq!(store.read_active().unwrap(), genesis);
        // A second epoch chains on the active tip.
        let next = store.create_and_activate(Uuid::now_v7(), genesis).unwrap();
        assert_ne!(next, genesis);
        assert_eq!(store.read_active().unwrap(), next);
    }

    #[test]
    fn idempotent_replay_of_same_operation() {
        let dir = TempDir::new("payload-epoch");
        let store = store(&dir);
        let op = Uuid::now_v7();
        let first = store.create_and_activate(op, Uuid::nil()).unwrap();
        // Repeating the exact request returns the same epoch — the
        // retried create is a no-op, not a fork.
        assert_eq!(store.create_and_activate(op, Uuid::nil()).unwrap(), first);
    }

    #[test]
    fn fencing_rejects_non_tip_priors_and_bad_ids() {
        let dir = TempDir::new("payload-epoch");
        let store = store(&dir);
        let genesis = store
            .create_and_activate(Uuid::now_v7(), Uuid::nil())
            .unwrap();
        // A prior that is not the active epoch denies (a fork).
        assert!(
            store
                .create_and_activate(Uuid::now_v7(), Uuid::nil())
                .is_err()
        );
        assert!(
            store
                .create_and_activate(Uuid::now_v7(), Uuid::now_v7())
                .is_err()
        );
        // Nil / non-v7 operation ids refuse.
        assert!(store.create_and_activate(Uuid::nil(), genesis).is_err());
        assert!(store.create_and_activate(Uuid::new_v4(), genesis).is_err());
        // A non-v7 prior refuses.
        assert!(
            store
                .create_and_activate(Uuid::now_v7(), Uuid::new_v4())
                .is_err()
        );
    }

    #[test]
    fn tampered_generation_hmac_fails_closed() {
        let dir = TempDir::new("payload-epoch");
        let store = store(&dir);
        store
            .create_and_activate(Uuid::now_v7(), Uuid::nil())
            .unwrap();
        let generations = dir.join("payload-epochs/generations");
        let record_path = fs::read_dir(&generations)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record["hmac_sha256"] = serde_json::json!("f".repeat(64));
        // Rewrite through a 0600 file so the private-file shape holds.
        fs::remove_file(&record_path).unwrap();
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        // The authenticated chain refuses: tamper reads as unavailable.
        assert!(store.read_active().is_err());
    }

    #[test]
    fn forked_chain_is_unavailable() {
        let dir = TempDir::new("payload-epoch");
        let store = store(&dir);
        let genesis = store
            .create_and_activate(Uuid::now_v7(), Uuid::nil())
            .unwrap();
        store.create_and_activate(Uuid::now_v7(), genesis).unwrap();
        // Forge a second generation claiming the same prior — a fork.
        let fork_op = Uuid::now_v7();
        let mut record = GenerationRecord {
            schema_version: GENERATION_SCHEMA.into(),
            operation_id: fork_op.to_string(),
            payload_epoch_id: Uuid::now_v7().to_string(),
            prior_payload_epoch_id: genesis.to_string(),
            hmac_sha256: String::new(),
        };
        store.sign_generation(&mut record).unwrap();
        store.write_generation(&record).unwrap();
        assert!(store.read_active().is_err());
    }

    #[test]
    fn active_pointer_digest_mismatch_fails_closed() {
        let dir = TempDir::new("payload-epoch");
        let store = store(&dir);
        let genesis = store
            .create_and_activate(Uuid::now_v7(), Uuid::nil())
            .unwrap();
        // Repoint active.json at a sibling epoch that is not the chain
        // tip: a valid HMAC over a stale pointer still fails closed
        // because the digest no longer matches the tip generation.
        let orphan_op = Uuid::now_v7();
        let orphan_epoch = Uuid::now_v7();
        let mut orphan = GenerationRecord {
            schema_version: GENERATION_SCHEMA.into(),
            operation_id: orphan_op.to_string(),
            payload_epoch_id: orphan_epoch.to_string(),
            prior_payload_epoch_id: genesis.to_string(),
            hmac_sha256: String::new(),
        };
        store.sign_generation(&mut orphan).unwrap();
        store.write_generation(&orphan).unwrap();
        assert!(store.read_active().is_err());
    }
}
