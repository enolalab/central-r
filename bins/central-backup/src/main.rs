//! `central-backup` — the fixed C01 worker launched only by the
//! root-owned native supervisor. It accepts no path, target,
//! credential, or option; every capability arrives through the three
//! inherited descriptors the grammar fixes:
//!
//! - FD 3 — the 16-byte launch evidence (consumed, then closed)
//! - FD 4 — the repository root directory (made `FD_CLOEXEC`)
//! - FD 5 — the CBW1 target-lock monitor channel (adopted CLOEXEC by
//!   the kernel composition before any subprocess can inherit it)
//!
//! Ported upstream-verbatim from `cmd/central-backup/main.go`; the
//! production compositions live in `central-kernel::backup_compose`.
//!
//! `deny(unsafe_code)` keeps the grammar free of `unsafe`; `sys.rs`
//! is the single audited module (`allow`) exactly like
//! `central-backup-launcherd`.
#![deny(unsafe_code)]

mod sys;

use std::os::fd::RawFd;

use central_foundation::failure::Failure;
use uuid::Uuid;

/// `launchEvidenceFD` — the supervisor's fixed evidence slot.
const LAUNCH_EVIDENCE_FD: RawFd = 3;
/// `repositoryFD` — the supervisor's fixed repository slot.
const REPOSITORY_FD: RawFd = 4;

/// A production worker entry point — `central-kernel::backup_compose`'s
/// `run_backup_worker`/`run_throughput_probe_worker`, injected here so
/// the privileged descriptor grammar is testable without credentials
/// or external services (upstream's `backupWorker`/`throughputProbeWorker`
/// seam).
type Worker = fn(Uuid, Uuid, std::os::fd::BorrowedFd<'_>) -> Result<(), Failure>;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if execute_central_backup(&args, LAUNCH_EVIDENCE_FD, REPOSITORY_FD).is_err() {
        // The native supervisor records only the exit outcome. Never
        // render the wrapped cause: database, object-store, and broker
        // errors can contain a locator even though production adapters
        // normally redact them.
        eprintln!("central-backup: BACKUP_WORKER_FAILED");
        std::process::exit(6);
    }
}

/// `executeCentralBackup` — the mode dispatch; the fd arguments stay
/// parameters exactly like upstream so the grammar remains testable.
fn execute_central_backup(
    args: &[String],
    evidence_fd: RawFd,
    repo_fd: RawFd,
) -> Result<(), Failure> {
    if args.len() != 3 {
        return Err(worker_invocation_denied());
    }
    match args[1].as_str() {
        "create" => {
            // `executeBackupWorker` — the injected-fd seam refuses
            // anything but the supervisor's fixed slots.
            if evidence_fd != LAUNCH_EVIDENCE_FD || repo_fd != REPOSITORY_FD {
                return Err(worker_invocation_denied());
            }
            run_bound_backup_worker(
                args,
                evidence_fd,
                repo_fd,
                central_kernel::backup_compose::run_backup_worker,
            )
        }
        "throughput-probe" => {
            if evidence_fd != LAUNCH_EVIDENCE_FD || repo_fd != REPOSITORY_FD {
                return Err(probe_invocation_denied());
            }
            run_bound_throughput_probe(
                args,
                evidence_fd,
                repo_fd,
                central_kernel::backup_compose::run_throughput_probe_worker,
            )
        }
        _ => Err(worker_invocation_denied()),
    }
}

fn worker_invocation_denied() -> Failure {
    Failure::denied("backup_worker", "backup worker invocation denied")
}

fn repository_authority_denied() -> Failure {
    Failure::denied("backup_worker", "backup worker repository authority denied")
}

fn launch_authority_denied() -> Failure {
    Failure::denied("backup_worker", "backup worker launch authority denied")
}

fn probe_invocation_denied() -> Failure {
    Failure::denied("backup_worker", "backup throughput probe invocation denied")
}

fn probe_repository_authority_denied() -> Failure {
    Failure::denied(
        "backup_worker",
        "backup throughput probe repository authority denied",
    )
}

/// `runBoundBackupWorker` — `create`'s full pre-dispatch gate:
/// three args, a non-nil operation id, the fixed evidence/repository
/// slots, `FD_CLOEXEC`, a directory-shaped FD 4, and the 16-byte
/// evidence consume.
fn run_bound_backup_worker(
    args: &[String],
    evidence_fd: RawFd,
    repo_fd: RawFd,
    worker: Worker,
) -> Result<(), Failure> {
    if args.len() != 3 || args[1] != "create" || evidence_fd < 0 || repo_fd < 0 {
        return Err(worker_invocation_denied());
    }
    let operation_id = Uuid::parse_str(&args[2]).map_err(|_| worker_invocation_denied())?;
    if operation_id.is_nil() {
        return Err(worker_invocation_denied());
    }
    sys::mark_cloexec(repo_fd).map_err(|_| repository_authority_denied())?;
    if !sys::is_directory(repo_fd) {
        return Err(repository_authority_denied());
    }
    let launch_evidence_id = consume_launch_evidence(evidence_fd)?;
    worker(
        launch_evidence_id,
        operation_id,
        sys::borrow_process_fd(repo_fd),
    )
}

/// `runBoundThroughputProbe` — `throughput-probe`'s gate; identical to
/// `create`'s except the operation id must also be v7 and every
/// refusal names the probe grammar.
fn run_bound_throughput_probe(
    args: &[String],
    evidence_fd: RawFd,
    repo_fd: RawFd,
    worker: Worker,
) -> Result<(), Failure> {
    if args.len() != 3 || args[1] != "throughput-probe" || evidence_fd < 0 || repo_fd < 0 {
        return Err(probe_invocation_denied());
    }
    let operation_id = Uuid::parse_str(&args[2]).map_err(|_| probe_invocation_denied())?;
    if operation_id.is_nil() || operation_id.get_version_num() != 7 {
        return Err(probe_invocation_denied());
    }
    sys::mark_cloexec(repo_fd).map_err(|_| probe_repository_authority_denied())?;
    if !sys::is_directory(repo_fd) {
        return Err(probe_repository_authority_denied());
    }
    let launch_evidence_id = consume_launch_evidence(evidence_fd)?;
    worker(
        launch_evidence_id,
        operation_id,
        sys::borrow_process_fd(repo_fd),
    )
}

/// `consumeLaunchEvidence` — exactly 16 bytes, an immediate EOF, a
/// non-nil UUID; then the descriptor is closed upstream-verbatim.
fn consume_launch_evidence(fd: RawFd) -> Result<Uuid, Failure> {
    if fd < 0 {
        return Err(launch_authority_denied());
    }
    let mut payload = [0u8; 16];
    sys::read_exact_to_eof_and_close(fd, &mut payload).map_err(|_| launch_authority_denied())?;
    let launch_id = Uuid::from_bytes(payload);
    if launch_id.is_nil() {
        return Err(launch_authority_denied());
    }
    Ok(launch_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Descriptor numbers are a process-wide namespace: a closed slot
    /// can be reused by a parallel test before a by-number check runs.
    /// The fd-allocating tests take this lock so open/close
    /// observations stay deterministic.
    static FD_SERIAL: Mutex<()> = Mutex::new(());

    fn denied_message(err: &Failure) -> &str {
        err.message()
    }

    fn args(mode: &str, op: &str) -> Vec<String> {
        vec!["central-backup".into(), mode.into(), op.into()]
    }

    /// A pipe read end whose `into_raw_fd` transfers ownership — the
    /// consume path then owns and closes it (upstream `file.Close()`),
    /// with no unsafe descriptor juggling anywhere.
    fn pipe_with(payload: &[u8]) -> RawFd {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(payload).unwrap();
        drop(writer);
        reader.into_raw_fd()
    }

    /// `consumeLaunchEvidence` — 16 bytes + EOF or refusal; the slot
    /// closes either way.
    #[test]
    fn consume_launch_evidence_is_exact_and_closes() {
        let _fd_guard = FD_SERIAL.lock().unwrap();
        let id = Uuid::now_v7();
        let fd = pipe_with(id.as_bytes());
        let got = consume_launch_evidence(fd).unwrap();
        assert_eq!(got, id);
        // The slot is closed — fcntl fails now.
        assert!(!sys::is_open(fd));

        // Short payload refuses; trailing bytes refuse; nil refuses.
        let err = consume_launch_evidence(pipe_with(&id.as_bytes()[..8])).unwrap_err();
        assert_eq!(
            denied_message(&err),
            "backup worker launch authority denied"
        );
        let mut padded = id.as_bytes().to_vec();
        padded.push(0);
        let err = consume_launch_evidence(pipe_with(&padded)).unwrap_err();
        assert_eq!(
            denied_message(&err),
            "backup worker launch authority denied"
        );
        let err = consume_launch_evidence(pipe_with(&[0u8; 16])).unwrap_err();
        assert_eq!(
            denied_message(&err),
            "backup worker launch authority denied"
        );
        let err = consume_launch_evidence(-1).unwrap_err();
        assert_eq!(
            denied_message(&err),
            "backup worker launch authority denied"
        );
    }

    /// The dispatch table refuses bad arity and unknown verbs before
    /// any descriptor work — `execute_central_backup` holds the same
    /// fixed-slot gate upstream's `executeBackupWorker` does.
    #[test]
    fn dispatch_is_closed() {
        let op = Uuid::now_v7().to_string();
        for bad in [
            vec!["central-backup".into()],
            vec!["central-backup".into(), "create".into()],
            vec![
                "central-backup".into(),
                "create".into(),
                op.clone(),
                "extra".into(),
            ],
            args("bogus", &op),
        ] {
            let err = execute_central_backup(&bad, LAUNCH_EVIDENCE_FD, REPOSITORY_FD).unwrap_err();
            assert_eq!(denied_message(&err), "backup worker invocation denied");
        }
        // Non-fixed descriptor slots refuse identically (create).
        let err = execute_central_backup(&args("create", &op), 30, 31).unwrap_err();
        assert_eq!(denied_message(&err), "backup worker invocation denied");
    }

    /// A fully-shaped invocation reaches the worker with the consumed
    /// evidence, parsed operation, and FD 4 now CLOEXEC.
    #[test]
    fn shaped_invocation_dispatches_to_worker() {
        let _fd_guard = FD_SERIAL.lock().unwrap();
        static CALLS: AtomicU64 = AtomicU64::new(0);
        static LAST: Mutex<Option<(Uuid, Uuid)>> = Mutex::new(None);
        fn worker(e: Uuid, o: Uuid, fd: std::os::fd::BorrowedFd<'_>) -> Result<(), Failure> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            *LAST.lock().unwrap() = Some((e, o));
            // The repository descriptor arrives CLOEXEC.
            assert!(sys::is_cloexec(fd.as_raw_fd()));
            Ok(())
        }
        let dir = std::env::temp_dir().join(format!(
            "cbw-main-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_file = std::fs::File::open(&dir).unwrap();

        let evidence_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        run_bound_backup_worker(
            &args("create", &operation_id.to_string()),
            pipe_with(evidence_id.as_bytes()),
            dir_file.as_raw_fd(),
            worker,
        )
        .unwrap();
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(*LAST.lock().unwrap(), Some((evidence_id, operation_id)));

        // Probe path — same handoff through its own grammar.
        let evidence_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        run_bound_throughput_probe(
            &args("throughput-probe", &operation_id.to_string()),
            pipe_with(evidence_id.as_bytes()),
            dir_file.as_raw_fd(),
            worker,
        )
        .unwrap();
        assert_eq!(*LAST.lock().unwrap(), Some((evidence_id, operation_id)));
        drop(dir_file);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The fd-shape gates: a non-directory FD 4 or an un-cloexec-able
    /// descriptor refuses with the per-verb authority strings — before
    /// the evidence channel is even touched.
    #[test]
    fn descriptor_shape_gates() {
        let _fd_guard = FD_SERIAL.lock().unwrap();
        fn noop(_e: Uuid, _o: Uuid, _fd: std::os::fd::BorrowedFd<'_>) -> Result<(), Failure> {
            unreachable!("worker must not run on a refused invocation")
        }
        let op = Uuid::now_v7().to_string();
        let file = std::env::temp_dir().join(format!("cbw-notdir-{}", Uuid::now_v7()));
        std::fs::write(&file, b"x").unwrap();
        let file_fd = std::fs::File::open(&file).unwrap();

        // FD 4 naming a regular file is not a repository root.
        let err = run_bound_backup_worker(
            &args("create", &op),
            pipe_with(Uuid::now_v7().as_bytes()),
            file_fd.as_raw_fd(),
            noop,
        )
        .unwrap_err();
        assert_eq!(
            denied_message(&err),
            "backup worker repository authority denied"
        );
        // Probe's refusal vocabulary is its own.
        let err = run_bound_throughput_probe(
            &args("throughput-probe", &op),
            pipe_with(Uuid::now_v7().as_bytes()),
            file_fd.as_raw_fd(),
            noop,
        )
        .unwrap_err();
        assert_eq!(
            denied_message(&err),
            "backup throughput probe repository authority denied"
        );
        drop(file_fd);
        std::fs::remove_file(&file).ok();
    }

    /// The operation-id gate: malformed, nil, and (probe only) non-v7
    /// all refuse inside each verb's own vocabulary before fd work.
    #[test]
    fn operation_id_gates() {
        fn noop(_e: Uuid, _o: Uuid, _fd: std::os::fd::BorrowedFd<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        let dir = std::env::temp_dir().join(format!("cbw-op-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_file = std::fs::File::open(&dir).unwrap();
        for op in ["not-a-uuid".to_owned(), Uuid::nil().to_string()] {
            let err = run_bound_backup_worker(
                &args("create", &op),
                pipe_with(Uuid::now_v7().as_bytes()),
                dir_file.as_raw_fd(),
                noop,
            )
            .unwrap_err();
            assert_eq!(denied_message(&err), "backup worker invocation denied");
        }
        for op in [
            "not-a-uuid".to_owned(),
            Uuid::nil().to_string(),
            Uuid::new_v4().to_string(),
        ] {
            let err = run_bound_throughput_probe(
                &args("throughput-probe", &op),
                pipe_with(Uuid::now_v7().as_bytes()),
                dir_file.as_raw_fd(),
                noop,
            )
            .unwrap_err();
            assert_eq!(
                denied_message(&err),
                "backup throughput probe invocation denied"
            );
        }
        drop(dir_file);
        std::fs::remove_dir_all(&dir).ok();
    }
}
