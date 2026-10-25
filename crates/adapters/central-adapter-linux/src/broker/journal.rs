//! `journal.go` — the authority-transition journal: a directory tree of
//! `prepared.json` / `issued.json` / `committed.json` phase files under
//! `<root>/authority-records/<stream>/<seq>-<operation>/`, plus the
//! `lifecycle-records/<op>/<seq>/` tree and `prepare-records/`
//! operation store.
//!
//! Wire and durability parity notes:
//! - Every phase file is `os.Create`+`fsync`+dir-fsync; the committed
//!   phase additionally writes `committed.tmp` (`0400`), fsyncs, and
//!   installs with `RENAME_NOREPLACE` — a committed record can never be
//!   overwritten by a retried commit.
//! - `issued.json` HMACs the payload *before* `payload_digest` and
//!   `payload_bytes` are populated (upstream ordering); the committed
//!   record is Ed25519-signed when a signer is attached.
//! - `Recover` settles orphaned chains: an intact `issued.json` is
//!   committed as-is, a *corrupt* issued file is skipped (never
//!   reinterpreted as prepared), and a missing issued file falls back
//!   to `prepared.json` which is re-issued then committed.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use central_foundation::failure::Failure;
use central_infra::authority::{AuthorityTransitionPayload, CommittedReceipt, PrepareOperation};
use central_infra::domain::{LifecycleOperation, LifecyclePhase};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable::{
    self, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE, rename_noreplace, rename_replace, sync_dir,
    sync_file,
};
use super::signing::{Ed25519Signer, SigningService};
use super::wire::{hex_encode, rfc3339};

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_journal", msg.into())
}

/// `LifecycleRecord` — the on-disk journal entry for one lifecycle
/// phase transition (snake_case upstream tags).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleRecord {
    /// `operation_id`.
    pub operation_id: String,
    /// `instance_id`.
    pub instance_id: String,
    /// `phase` — upstream overwrites this with the protocol phase
    /// (`prepared`/`issued`/`committed`) during the write sequence.
    pub phase: String,
    /// `timestamp`.
    #[serde(with = "rfc3339")]
    pub timestamp: OffsetDateTime,
    /// `hmac,omitempty`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hmac: String,
    /// `signature,omitempty`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// `Journal` — `rootPath` + signing identity + optional Ed25519 signer.
pub struct Journal {
    root_path: PathBuf,
    signing: std::sync::Arc<SigningService>,
    signer: Option<std::sync::Arc<Ed25519Signer>>,
    mu: Mutex<()>,
}

impl Journal {
    /// `NewJournal`.
    #[must_use]
    pub fn new(
        root_path: PathBuf,
        signing: std::sync::Arc<SigningService>,
        signer: Option<std::sync::Arc<Ed25519Signer>>,
    ) -> Self {
        Self {
            root_path,
            signing,
            signer,
            mu: Mutex::new(()),
        }
    }

    /// `RootPath` — exported for test inspection.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, Failure> {
        self.mu
            .lock()
            .map_err(|_| internal("journal: lock poisoned"))
    }

    /// `AppendLifecycle` — one `%020d` sequence directory per call under
    /// `lifecycle-records/<op.id>`; prepared → issued (HMAC under
    /// `lifecycle`) → committed (`RENAME_NOREPLACE`, signed).
    ///
    /// # Errors
    /// `broker_journal` on any filesystem, marshal, or signing failure.
    pub fn append_lifecycle(
        &self,
        op: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        let _guard = self.lock()?;
        let mut record = LifecycleRecord {
            operation_id: op.id.clone(),
            instance_id: op.binding.instance_id.clone(),
            phase: phase.as_str().to_owned(),
            timestamp: OffsetDateTime::now_utc(),
            hmac: String::new(),
            signature: String::new(),
        };

        let op_dir = self.root_path.join("lifecycle-records").join(&op.id);
        durable::mkdir_p(&op_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: lifecycle mkdir: {e}")))?;

        // Allocate next sequence number within the operation directory.
        let mut max_seq = 0u64;
        for entry in durable::read_dir(&op_dir)
            .map_err(|e| internal(format!("journal: lifecycle readdir: {e}")))?
        {
            if entry.file_type.is_dir()
                && let Some(seq) = parse_seq_name(&entry.name.to_string_lossy())
            {
                max_seq = max_seq.max(seq);
            }
        }
        let seq_num = max_seq + 1;

        let seq_dir = op_dir.join(format!("{seq_num:020}"));
        durable::mkdir_p(&seq_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: lifecycle mkdir seq: {e}")))?;

        // Phase 1: prepared.
        record.phase = "prepared".into();
        write_lifecycle_phase(&seq_dir, "prepared.json", &record).map_err(|e| {
            internal(format!(
                "journal: lifecycle write prepared: {}",
                e.message()
            ))
        })?;

        // Phase 2: issued (compute HMAC).
        record.phase = "issued".into();
        let canonical = serde_json::to_vec(&record)
            .map_err(|e| internal(format!("journal: lifecycle marshal: {e}")))?;
        record.hmac = self.signing.fingerprint("lifecycle", &canonical);
        write_lifecycle_phase(&seq_dir, "issued.json", &record)
            .map_err(|e| internal(format!("journal: lifecycle write issued: {}", e.message())))?;

        // Phase 3: committed (atomic install).
        record.phase = "committed".into();
        let committed_path = seq_dir.join("committed.json");
        let tmp_path = seq_dir.join("committed.tmp");
        let mut canonical = serde_json::to_vec(&record)
            .map_err(|e| internal(format!("journal: lifecycle marshal: {e}")))?;
        if let Some(signer) = &self.signer {
            record.signature = signer.sign(&canonical);
            canonical = serde_json::to_vec(&record)
                .map_err(|e| internal(format!("journal: lifecycle re-marshal: {e}")))?;
        }
        durable::write_file(&tmp_path, &canonical, 0o400)
            .map_err(|e| internal(format!("journal: lifecycle write tmp: {e}")))?;
        sync_file(&tmp_path)
            .map_err(|e| internal(format!("journal: lifecycle sync tmp: {}", e.message())))?;
        rename_noreplace(&tmp_path, &committed_path).map_err(|e| {
            let _ = durable::remove_file(&tmp_path);
            internal(format!("journal: lifecycle atomic commit: {}", e.message()))
        })?;
        sync_dir(&seq_dir)
    }

    /// `Append` — the unlocked three-phase write (upstream does not
    /// take `j.mu` here; only `AppendCommitted`/`AppendLifecycle`/
    /// recovery do).
    ///
    /// # Errors
    /// `broker_journal` on any filesystem, marshal, or signing failure.
    pub fn append(
        &self,
        stream_id: &str,
        payload: &mut AuthorityTransitionPayload,
    ) -> Result<(), Failure> {
        let stream_dir = self.root_path.join("authority-records").join(stream_id);
        durable::mkdir_p(&stream_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: mkdir stream: {e}")))?;
        let seq_dir = stream_dir.join(format!(
            "{:020}-{}",
            payload.sequence_num, payload.operation
        ));
        durable::mkdir_p(&seq_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: mkdir seq: {e}")))?;
        self.commit_phases(&seq_dir, payload)
    }

    /// `AppendCommitted` — allocates the next sequence under the mutex,
    /// writes all three phases, returns `{id: uuid4, sequence}`.
    ///
    /// # Errors
    /// `broker_journal` on any filesystem, marshal, or signing failure.
    pub fn append_committed(
        &self,
        stream_id: &str,
        payload: &mut AuthorityTransitionPayload,
    ) -> Result<CommittedReceipt, Failure> {
        let _guard = self.lock()?;

        let stream_dir = self.root_path.join("authority-records").join(stream_id);
        durable::mkdir_p(&stream_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: mkdir stream: {e}")))?;

        let mut max_seq = 0u64;
        for entry in durable::read_dir(&stream_dir)
            .map_err(|e| internal(format!("journal: readdir stream: {e}")))?
        {
            if entry.file_type.is_dir()
                && let Some(seq) = parse_seq_dir_name(&entry.name.to_string_lossy())
            {
                max_seq = max_seq.max(seq);
            }
        }
        payload.sequence_num = max_seq + 1;

        let seq_dir = stream_dir.join(format!(
            "{:020}-{}",
            payload.sequence_num, payload.operation
        ));
        durable::mkdir_p(&seq_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: mkdir seq: {e}")))?;

        self.commit_phases(&seq_dir, payload)?;

        Ok(CommittedReceipt {
            id: Uuid::new_v4().to_string(),
            sequence: payload.sequence_num,
        })
    }

    /// The shared prepared → issued → committed write sequence both
    /// `Append` and `AppendCommitted` use.
    fn commit_phases(
        &self,
        seq_dir: &Path,
        payload: &mut AuthorityTransitionPayload,
    ) -> Result<(), Failure> {
        payload.phase = "prepared".into();
        self.write_phase(seq_dir, "prepared.json", payload)?;

        payload.phase = "issued".into();
        let canonical = serde_json::to_vec(&*payload)
            .map_err(|e| internal(format!("journal: marshal: {e}")))?;
        payload.hmac = self.signing.fingerprint("authority-transition", &canonical);
        // Upstream `sha256.Sum256(payload.Payload)` + `len(payload.Payload)`:
        // the digest and byte count are over the verbatim RawMessage, never
        // a serde re-encoding (which sorts keys and would digest different
        // bytes than the durable record carries).
        let digest = sha2::Sha256::digest(raw_payload_bytes(payload));
        payload.payload_digest = hex_encode(&digest);
        payload.payload_bytes = raw_payload_bytes(payload).len() as u64;
        self.write_phase(seq_dir, "issued.json", payload)?;

        payload.phase = "committed".into();
        let committed_path = seq_dir.join("committed.json");
        let tmp_path = seq_dir.join("committed.tmp");
        let mut committed = serde_json::to_vec(&*payload)
            .map_err(|e| internal(format!("journal: marshal: {e}")))?;
        if let Some(signer) = &self.signer {
            payload.signature = signer.sign(&committed);
            committed = serde_json::to_vec(&*payload)
                .map_err(|e| internal(format!("journal: marshal: {e}")))?;
        }
        durable::write_file(&tmp_path, &committed, 0o400)
            .map_err(|e| internal(format!("journal: write tmp: {e}")))?;
        sync_file(&tmp_path)?;
        rename_noreplace(&tmp_path, &committed_path).map_err(|e| {
            let _ = durable::remove_file(&tmp_path);
            internal(format!("journal: atomic commit: {}", e.message()))
        })?;
        sync_dir(seq_dir)
    }

    /// `prepareDir`.
    fn prepare_dir(&self) -> PathBuf {
        self.root_path.join("prepare-records")
    }

    /// `Unsettled` — the first prepare-record entry whose phase is not
    /// terminal; `None` when the directory is absent or empty.
    ///
    /// # Errors
    /// Infallible by upstream design — unreadable/corrupt entries are
    /// skipped — but declared `Result`-free to mirror that.
    #[must_use]
    pub fn unsettled(&self) -> Option<PrepareOperation> {
        let _guard = self.mu.lock().ok()?;
        let dir = self.prepare_dir();
        let entries = durable::read_dir(&dir).ok()?;
        for entry in entries {
            if entry.file_type.is_dir() || !entry.name.to_string_lossy().ends_with(".json") {
                continue;
            }
            let Ok(data) = durable::read_file(&dir.join(&entry.name)) else {
                continue;
            };
            let Ok(op) = serde_json::from_slice::<PrepareOperation>(&data) else {
                continue;
            };
            if !op.phase.is_terminal() {
                return Some(op);
            }
        }
        None
    }

    /// `Exact` — load `prepare-records/<id>.json`; absent, corrupt, or
    /// ID-mismatched records are errors.
    ///
    /// # Errors
    /// `broker_journal` on read, decode, or ID-mismatch failure.
    pub fn exact(&self, id: &str) -> Result<PrepareOperation, Failure> {
        let _guard = self.lock()?;
        let path = self.prepare_dir().join(format!("{id}.json"));
        let data = durable::read_file(&path)
            .map_err(|e| internal(format!("journal: exact prepare: {e}")))?;
        let op: PrepareOperation = serde_json::from_slice(&data)
            .map_err(|e| internal(format!("journal: exact prepare: {e}")))?;
        if op.operation_id != id {
            return Err(internal("journal: exact prepare: ID mismatch"));
        }
        Ok(op)
    }

    /// `Record` — persist a prepare operation result as
    /// `prepare-records/<operation_id>.json` via tmp+fsync+rename. The
    /// upstream signature takes `dependencyprepare.Result`; the Rust
    /// capability callsite owns the `PrepareOperation` mapping, so this
    /// records the operation record directly.
    ///
    /// # Errors
    /// `broker_journal` on mkdir, marshal, or durable-write failure.
    pub fn record_operation(&self, op: &PrepareOperation) -> Result<(), Failure> {
        let _guard = self.lock()?;
        let dir = self.prepare_dir();
        durable::mkdir_p(&dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("journal: record prepare: {e}")))?;
        let data = serde_json::to_vec(op)
            .map_err(|e| internal(format!("journal: record prepare: {e}")))?;
        let path = dir.join(format!("{}.json", op.operation_id));
        let tmp_path = dir.join(format!("{}.json.tmp", op.operation_id));
        durable::write_file(&tmp_path, &data, PRIVATE_FILE_MODE)
            .map_err(|e| internal(format!("journal: record prepare: {e}")))?;
        sync_file(&tmp_path)?;
        rename_replace(&tmp_path, &path).map_err(|e| {
            let _ = durable::remove_file(&tmp_path);
            internal(format!("journal: record prepare: {}", e.message()))
        })?;
        sync_dir(&dir)
    }

    /// `Recover` — settle every orphaned `<stream>/<seq>` chain under
    /// `authority-records`: intact `issued.json` commits as-is; a
    /// *corrupt* issued file skips the chain (never reinterpreted);
    /// missing issued falls back to `prepared.json`, re-issues, then
    /// commits. Per-chain failures are logged and skipped, matching
    /// upstream's continue-on-error recovery.
    ///
    /// # Errors
    /// `broker_journal` only when the records root itself is
    /// unreadable; per-record failures do not propagate.
    pub fn recover(&self) -> Result<usize, Failure> {
        let _guard = self.lock()?;
        let records_dir = self.root_path.join("authority-records");
        if !durable::exists(&records_dir) {
            return Ok(0);
        }
        let streams = durable::read_dir(&records_dir)
            .map_err(|e| internal(format!("journal: recover readdir: {e}")))?;
        let mut recovered = 0usize;
        for stream in streams {
            if !stream.file_type.is_dir() {
                continue;
            }
            let stream_dir = records_dir.join(&stream.name);
            let Ok(entries) = durable::read_dir(&stream_dir) else {
                continue;
            };
            for entry in entries {
                if !entry.file_type.is_dir() {
                    continue;
                }
                let seq_dir = stream_dir.join(&entry.name);
                if durable::exists(&seq_dir.join("committed.json")) {
                    continue;
                }
                let issued_path = seq_dir.join("issued.json");
                let prepared_path = seq_dir.join("prepared.json");

                let mut payload: AuthorityTransitionPayload;
                let mut have_issued = false;
                match durable::read_file(&issued_path) {
                    Ok(data) => match serde_json::from_slice(&data) {
                        Ok(p) => {
                            payload = p;
                            have_issued = true;
                        }
                        Err(_) => continue, // corrupt issued: never reinterpret
                    },
                    Err(_) => match durable::read_file(&prepared_path) {
                        Ok(data) => match serde_json::from_slice(&data) {
                            Ok(p) => payload = p,
                            Err(_) => continue,
                        },
                        Err(_) => continue,
                    },
                }

                if !have_issued {
                    payload.phase = "issued".into();
                    let Ok(canonical) = serde_json::to_vec(&payload) else {
                        continue;
                    };
                    payload.hmac = self.signing.fingerprint("authority-transition", &canonical);
                    let digest = sha2::Sha256::digest(raw_payload_bytes(&payload));
                    payload.payload_digest = hex_encode(&digest);
                    payload.payload_bytes = raw_payload_bytes(&payload).len() as u64;
                    if self.write_phase(&seq_dir, "issued.json", &payload).is_err() {
                        continue;
                    }
                }

                payload.phase = "committed".into();
                let tmp_path = seq_dir.join("committed.tmp");
                let committed_path = seq_dir.join("committed.json");
                let Ok(mut committed) = serde_json::to_vec(&payload) else {
                    continue;
                };
                if let Some(signer) = &self.signer {
                    payload.signature = signer.sign(&committed);
                    let Ok(c) = serde_json::to_vec(&payload) else {
                        continue;
                    };
                    committed = c;
                }
                if durable::write_file(&tmp_path, &committed, 0o400).is_err()
                    || sync_file(&tmp_path).is_err()
                {
                    continue;
                }
                if rename_noreplace(&tmp_path, &committed_path).is_err() {
                    let _ = durable::remove_file(&tmp_path);
                    continue;
                }
                if sync_dir(&seq_dir).is_err() {
                    continue;
                }
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    /// `writePhase` — marshal, create, fsync file, fsync dir.
    fn write_phase(
        &self,
        seq_dir: &Path,
        filename: &str,
        payload: &AuthorityTransitionPayload,
    ) -> Result<(), Failure> {
        let path = seq_dir.join(filename);
        let data = serde_json::to_vec(payload).map_err(|e| internal(format!("journal: {e}")))?;
        durable::write_file(&path, &data, PRIVATE_FILE_MODE)
            .map_err(|e| internal(format!("journal: {e}")))?;
        sync_file(&path)?;
        sync_dir(seq_dir)
    }
}

/// `writeLifecyclePhase` — same shape as `writePhase` for lifecycle
/// records.
fn write_lifecycle_phase(
    seq_dir: &Path,
    filename: &str,
    record: &LifecycleRecord,
) -> Result<(), Failure> {
    let path = seq_dir.join(filename);
    let data = serde_json::to_vec(record).map_err(|e| internal(format!("journal: {e}")))?;
    durable::write_file(&path, &data, 0o600).map_err(|e| internal(format!("journal: {e}")))?;
    sync_file(&path)?;
    sync_dir(seq_dir)
}

/// `%020d` — the lifecycle sequence-directory name.
fn parse_seq_name(name: &str) -> Option<u64> {
    if name.len() != 20 || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse().ok()
}

/// `%020d-<operation>` — the authority-record sequence-directory name.
fn parse_seq_dir_name(name: &str) -> Option<u64> {
    let (num, _op) = name.split_once('-')?;
    parse_seq_name(num)
}

/// `payload.Payload` as the byte slice upstream's
/// `sha256.Sum256(payload.Payload)` and `len(payload.Payload)` operate
/// on: `None` (Go nil `RawMessage`) is the empty slice — digest of `""`
/// and `payload_bytes` 0 — while `Some` is the verbatim captured JSON.
fn raw_payload_bytes(record: &AuthorityTransitionPayload) -> &[u8] {
    record
        .payload
        .as_ref()
        .map_or(&[][..], |raw| raw.get().as_bytes())
}

// ---------------------------------------------------------------------------
// Tests — upstream journal crash/replay coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use std::fs;
    use std::sync::Arc;

    fn journal(dir: &Path) -> Journal {
        Journal::new(
            dir.to_path_buf(),
            Arc::new(SigningService::new()),
            Some(Arc::new(Ed25519Signer::new().unwrap())),
        )
    }

    /// `json.RawMessage` construction — the verbatim bytes the journal
    /// both hashes and persists.
    fn raw_value(json: &str) -> Box<serde_json::value::RawValue> {
        serde_json::value::RawValue::from_string(json.to_owned()).unwrap()
    }

    fn payload(op: &str) -> AuthorityTransitionPayload {
        AuthorityTransitionPayload {
            schema_version: "central.authority-transition/v1".into(),
            stream_id: "stream-1".into(),
            sequence_num: 0,
            phase: String::new(),
            operation: op.into(),
            instance_id: "inst".into(),
            binding_id: "bind".into(),
            launch_id: "launch".into(),
            nonce: "nonce".into(),
            payload: Some(raw_value(r#"{"k":"v"}"#)),
            payload_digest: String::new(),
            payload_bytes: 0,
            prior_digest: String::new(),
            broker_key_ver: "v1".into(),
            hmac: String::new(),
            signature: String::new(),
            signed_at: String::new(),
        }
    }

    #[test]
    fn append_writes_all_three_phases() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let mut p = payload("bind");
        p.sequence_num = 7;
        j.append("stream-1", &mut p).unwrap();
        let seq_dir = dir
            .join("authority-records/stream-1")
            .join("00000000000000000007-bind");
        let prepared: AuthorityTransitionPayload =
            serde_json::from_slice(&fs::read(seq_dir.join("prepared.json")).unwrap()).unwrap();
        let issued: AuthorityTransitionPayload =
            serde_json::from_slice(&fs::read(seq_dir.join("issued.json")).unwrap()).unwrap();
        let committed: AuthorityTransitionPayload =
            serde_json::from_slice(&fs::read(seq_dir.join("committed.json")).unwrap()).unwrap();
        assert_eq!(prepared.phase, "prepared");
        assert_eq!(issued.phase, "issued");
        assert_eq!(committed.phase, "committed");
        // Upstream ordering: the issued-phase HMAC covers the record
        // before the payload digest/bytes are populated.
        assert!(prepared.hmac.is_empty());
        assert!(!issued.hmac.is_empty());
        assert!(!issued.payload_digest.is_empty());
        assert_ne!(issued.payload_bytes, 0);
        // The committed record carries the Ed25519 signature.
        assert!(!committed.signature.is_empty());
    }

    #[test]
    fn issued_digest_hashes_verbatim_payload_bytes() {
        // Regression for the Value-reserialization bug: a payload whose
        // object keys are NOT in sorted order must hash the raw bytes —
        // upstream `sha256.Sum256(json.RawMessage)` — not the
        // BTreeMap-sorted `serde_json::to_vec` re-encoding the digest
        // used to produce.
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let mut p = payload("bind");
        p.sequence_num = 9;
        p.payload = Some(raw_value(r#"{"b":1,"a":2}"#));
        j.append("stream-1", &mut p).unwrap();
        let seq_dir = dir
            .join("authority-records/stream-1")
            .join("00000000000000000009-bind");
        let issued_raw = fs::read(seq_dir.join("issued.json")).unwrap();
        let issued: AuthorityTransitionPayload = serde_json::from_slice(&issued_raw).unwrap();
        let expected = hex_encode(&sha2::Sha256::digest(br#"{"b":1,"a":2}"#));
        assert_eq!(issued.payload_digest, expected);
        assert_eq!(issued.payload_bytes, 13);
        // The durable record embeds the same raw bytes that were hashed.
        let text = String::from_utf8(issued_raw).unwrap();
        assert!(
            text.contains(r#""payload":{"b":1,"a":2}"#),
            "verbatim payload lost: {text}"
        );
        // A recovered re-issue computes the same digest — recovery
        // shares the append path's raw-byte hashing.
        let committed_raw = fs::read(seq_dir.join("committed.json")).unwrap();
        let committed: AuthorityTransitionPayload = serde_json::from_slice(&committed_raw).unwrap();
        assert_eq!(committed.payload_digest, expected);
        assert_eq!(committed.payload.unwrap().get(), r#"{"b":1,"a":2}"#);
    }

    #[test]
    fn nil_payload_digests_empty_bytes_and_emits_null() {
        // Go nil `json.RawMessage`: `sha256.Sum256(nil)`, `len(nil)`,
        // and `"payload":null` on output — never `"{}"`.
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let mut p = payload("bind");
        p.sequence_num = 11;
        p.payload = None;
        j.append("stream-1", &mut p).unwrap();
        let seq_dir = dir
            .join("authority-records/stream-1")
            .join("00000000000000000011-bind");
        let issued_raw = fs::read(seq_dir.join("issued.json")).unwrap();
        let issued: AuthorityTransitionPayload = serde_json::from_slice(&issued_raw).unwrap();
        assert_eq!(
            issued.payload_digest,
            hex_encode(&sha2::Sha256::digest(b""))
        );
        assert_eq!(issued.payload_bytes, 0);
        let text = String::from_utf8(issued_raw).unwrap();
        assert!(text.contains(r#""payload":null"#), "nil payload: {text}");
    }

    #[test]
    fn append_committed_allocates_monotonic_sequences() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let r1 = j.append_committed("s", &mut payload("a")).unwrap();
        let r2 = j.append_committed("s", &mut payload("b")).unwrap();
        assert_eq!(r1.sequence, 1);
        assert_eq!(r2.sequence, 2);
        assert_ne!(r1.id, r2.id);
    }

    #[test]
    fn recover_commits_prepared_only_chain() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        // Simulate a crash after prepared.json: the record exists
        // without issued/committed.
        let seq_dir = dir
            .join("authority-records/stream-1")
            .join("00000000000000000003-bind");
        fs::create_dir_all(&seq_dir).unwrap();
        let mut p = payload("bind");
        p.sequence_num = 3;
        p.phase = "prepared".into();
        fs::write(
            seq_dir.join("prepared.json"),
            serde_json::to_vec(&p).unwrap(),
        )
        .unwrap();
        assert_eq!(j.recover().unwrap(), 1);
        let committed: AuthorityTransitionPayload =
            serde_json::from_slice(&fs::read(seq_dir.join("committed.json")).unwrap()).unwrap();
        assert_eq!(committed.phase, "committed");
        assert!(!committed.hmac.is_empty());
        // A settled chain is not recovered twice.
        assert_eq!(j.recover().unwrap(), 0);
    }

    #[test]
    fn recover_commits_intact_issued_chain() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let seq_dir = dir
            .join("authority-records/stream-1")
            .join("00000000000000000001-rotate");
        fs::create_dir_all(&seq_dir).unwrap();
        let mut p = payload("rotate");
        p.sequence_num = 1;
        p.phase = "issued".into();
        let canonical = serde_json::to_vec(&p).unwrap();
        p.hmac = j.signing.fingerprint("authority-transition", &canonical);
        fs::write(seq_dir.join("issued.json"), serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(j.recover().unwrap(), 1);
        assert!(seq_dir.join("committed.json").exists());
    }

    #[test]
    fn recover_never_reinterprets_corrupt_issued() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let seq_dir = dir
            .join("authority-records/stream-1")
            .join("00000000000000000002-bind");
        fs::create_dir_all(&seq_dir).unwrap();
        fs::write(seq_dir.join("prepared.json"), b"{\"phase\":\"prepared\"}").unwrap();
        fs::write(seq_dir.join("issued.json"), b"not-json").unwrap();
        // The torn tail is skipped: no committed.json is minted from
        // unreadable bytes and nothing is reinterpreted as prepared.
        assert_eq!(j.recover().unwrap(), 0);
        assert!(!seq_dir.join("committed.json").exists());
    }

    #[test]
    fn lifecycle_records_round_trip() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        let op = LifecycleOperation {
            id: "life-1".into(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::Started,
            binding: central_infra::domain::LifecycleBinding {
                instance_id: "inst".into(),
                ..Default::default()
            },
            observation: Default::default(),
            created_at: OffsetDateTime::now_utc(),
        };
        j.append_lifecycle(&op, LifecyclePhase::Started).unwrap();
        j.append_lifecycle(&op, LifecyclePhase::Verified).unwrap();
        let op_dir = dir.join("lifecycle-records/life-1");
        let mut seqs: Vec<_> = fs::read_dir(&op_dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_owned))
            .collect();
        seqs.sort();
        assert_eq!(seqs, ["00000000000000000001", "00000000000000000002"]);
        let committed: LifecycleRecord = serde_json::from_slice(
            &fs::read(op_dir.join("00000000000000000002/committed.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(committed.phase, "committed");
        assert!(!committed.hmac.is_empty());
        assert!(!committed.signature.is_empty());
    }

    #[test]
    fn prepare_records_settle() {
        let dir = TempDir::new("journal");
        let j = journal(&dir);
        assert!(j.unsettled().is_none());
        let mut op = PrepareOperation {
            operation_id: "op-77".into(),
            phase: central_infra::authority::PrepareOperationPhase::Acquiring,
            admission_id: "adm".into(),
            selector: "sel".into(),
            deadline: OffsetDateTime::now_utc(),
            reason: String::new(),
            reused: 0,
            acquired: 0,
            receipt_id: String::new(),
            created_at: OffsetDateTime::now_utc(),
        };
        j.record_operation(&op).unwrap();
        assert_eq!(j.unsettled().unwrap().operation_id, "op-77");
        assert_eq!(j.exact("op-77").unwrap().operation_id, "op-77");
        assert!(j.exact("missing").is_err());
        op.phase = central_infra::authority::PrepareOperationPhase::Failed;
        j.record_operation(&op).unwrap();
        assert!(j.unsettled().is_none());
    }
}
