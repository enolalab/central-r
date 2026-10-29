//! `FileJournal` — upstream `factory_linux.go`'s durable record of a
//! dependency-prepare operation's checkpoints, one `<operation_id>.json`
//! per operation under a private directory.
//!
//! `record` writes the [`PrepareOperation`] verbatim (full fine-grained
//! phase and deadline — a lossy projection through the operator-facing
//! result is exactly what made upstream's first resume re-build a staged
//! candidate). The operation ID is validated before it is joined into a
//! path on every entry point: it arrives from the operator as
//! `--resume=<id>` and names a file this root-owned process then trusts
//! as an authoritative record.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use central_foundation::failure::Failure;
use central_infra::authority::PrepareOperation;
use central_infra::domain::valid_operation_id;
use time::OffsetDateTime;

const JOURNAL_CODE: &str = "PREPARE_JOURNAL";

fn journal_failure(message: impl Into<String>) -> Failure {
    Failure::internal(JOURNAL_CODE, message)
}

/// Durable prepare-operation journal (upstream `FileJournal`).
#[derive(Debug)]
pub struct FileJournal {
    dir: PathBuf,
    mu: Mutex<()>,
}

impl FileJournal {
    /// `NewFileJournal` — creates the journal directory (`0700`).
    ///
    /// # Errors
    /// `PREPARE_JOURNAL` when the directory cannot be created.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, Failure> {
        let dir = dir.into();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| journal_failure(format!("file journal: {e}")))?;
        Ok(Self {
            dir,
            mu: Mutex::new(()),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, Failure> {
        self.mu
            .lock()
            .map_err(|_| journal_failure("file journal: lock poisoned"))
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// `Record` — persist the operation via tmp + fsync + rename + dir
    /// fsync. A zero `created_at` is stamped with the current time.
    ///
    /// # Errors
    /// `OPERATION_ID_INVALID` for an unsafe ID; `PREPARE_JOURNAL` for any
    /// marshal or durable-write failure.
    pub fn record(&self, op: &PrepareOperation) -> Result<(), Failure> {
        valid_operation_id(&op.operation_id)?;
        let _guard = self.lock()?;
        let mut op = op.clone();
        if op.created_at.year() <= 1 {
            op.created_at = OffsetDateTime::now_utc();
        }
        let data = serde_json::to_vec(&op)
            .map_err(|e| journal_failure(format!("file journal: marshal: {e}")))?;
        let path = self.record_path(&op.operation_id);
        let tmp = path.with_extension("json.tmp");
        let write = || -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            journal_failure(format!("file journal: write tmp: {e}"))
        })?;
        fs::rename(&tmp, &path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            journal_failure(format!("file journal: rename: {e}"))
        })?;
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| journal_failure(format!("file journal: sync dir: {e}")))
    }

    /// `Unsettled` — the first non-terminal record in directory order;
    /// unreadable or corrupt entries are skipped (upstream parity).
    #[must_use]
    pub fn unsettled(&self) -> Option<PrepareOperation> {
        let _guard = self.mu.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<_> = fs::read_dir(&self.dir)
            .ok()?
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| !t.is_dir()))
            .filter(|e| {
                Path::new(&e.file_name())
                    .extension()
                    .is_some_and(|x| x == "json")
            })
            .map(|e| e.path())
            .collect();
        names.sort();
        names.into_iter().find_map(|p| {
            let op: PrepareOperation = serde_json::from_slice(&fs::read(p).ok()?).ok()?;
            (!op.phase.is_terminal()).then_some(op)
        })
    }

    /// `Exact` — read one journalled operation by ID. The ID is validated
    /// before it is joined, and the record must name the requested ID.
    ///
    /// # Errors
    /// `OPERATION_ID_INVALID`; `PREPARE_JOURNAL` when the record is
    /// absent, unreadable, corrupt, or names a different operation.
    pub fn exact(&self, id: &str) -> Result<PrepareOperation, Failure> {
        valid_operation_id(id)?;
        let _guard = self.lock()?;
        let data = fs::read(self.record_path(id)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                journal_failure(format!("journal: operation {id:?} not found"))
            } else {
                journal_failure(format!("journal: read {id:?}: {e}"))
            }
        })?;
        let op: PrepareOperation = serde_json::from_slice(&data)
            .map_err(|e| journal_failure(format!("journal: unmarshal {id:?}: {e}")))?;
        if op.operation_id != id {
            return Err(journal_failure(format!(
                "journal: record {id:?} names operation {:?}",
                op.operation_id
            )));
        }
        Ok(op)
    }

    /// The journal directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[cfg(test)]
    fn mode_of(&self, id: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(self.record_path(id))
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::authority::PrepareOperationPhase;
    use time::Duration;

    fn op(id: &str, phase: PrepareOperationPhase) -> PrepareOperation {
        let now = OffsetDateTime::now_utc();
        PrepareOperation {
            operation_id: id.to_owned(),
            phase,
            admission_id: "adm".to_owned(),
            selector: "minio".to_owned(),
            deadline: now + Duration::minutes(20),
            reason: String::new(),
            reused: 0,
            acquired: 1,
            receipt_id: "rcpt".to_owned(),
            created_at: now,
        }
    }

    struct Tmp(PathBuf);

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn journal() -> (Tmp, FileJournal) {
        let root = std::env::temp_dir().join(format!(
            "central-pp-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let j = FileJournal::new(root.join("journal")).expect("journal");
        (Tmp(root), j)
    }

    #[test]
    fn round_trip_preserves_fine_grained_phase_and_deadline() {
        let (_t, j) = journal();
        let want = op("prepare-1", PrepareOperationPhase::PromotionAdmitted);
        j.record(&want).expect("record");
        let got = j.exact("prepare-1").expect("exact");
        assert_eq!(got.phase, PrepareOperationPhase::PromotionAdmitted);
        assert_eq!(got.deadline, want.deadline);
        assert_eq!(got.receipt_id, "rcpt");
        assert_eq!(j.mode_of("prepare-1"), 0o600);
    }

    #[test]
    fn unsafe_ids_are_refused_on_every_entry_point() {
        let (_t, j) = journal();
        for id in ["", ".", "..", "../attacker", "a/b", "a\0b"] {
            assert!(j.exact(id).is_err(), "exact {id:?}");
            assert!(
                j.record(&op(id, PrepareOperationPhase::Acquiring)).is_err(),
                "record {id:?}"
            );
        }
    }

    #[test]
    fn forged_record_naming_another_operation_is_refused() {
        let (_t, j) = journal();
        j.record(&op("real", PrepareOperationPhase::Completed))
            .expect("record");
        fs::copy(j.record_path("real"), j.record_path("forged")).expect("copy");
        let err = j.exact("forged").expect_err("mismatch");
        assert!(
            err.message().contains("names operation"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn unsettled_skips_terminal_and_corrupt_records() {
        let (_t, j) = journal();
        j.record(&op("a-done", PrepareOperationPhase::Completed))
            .expect("a");
        j.record(&op("b-failed", PrepareOperationPhase::Failed))
            .expect("b");
        fs::write(j.dir().join("c-corrupt.json"), b"{not json").expect("corrupt");
        assert!(j.unsettled().is_none());
        j.record(&op("d-live", PrepareOperationPhase::BuildOne))
            .expect("d");
        assert_eq!(j.unsettled().expect("unsettled").operation_id, "d-live");
    }

    #[test]
    fn exact_reports_missing_operation() {
        let (_t, j) = journal();
        let err = j.exact("nope").expect_err("missing");
        assert!(err.message().contains("not found"));
    }

    #[test]
    fn record_replaces_atomically_and_leaves_no_tmp() {
        let (_t, j) = journal();
        j.record(&op("p", PrepareOperationPhase::Acquiring))
            .expect("1");
        j.record(&op("p", PrepareOperationPhase::Completed))
            .expect("2");
        assert_eq!(
            j.exact("p").expect("exact").phase,
            PrepareOperationPhase::Completed
        );
        assert!(!j.dir().join("p.json.tmp").exists());
    }
}
