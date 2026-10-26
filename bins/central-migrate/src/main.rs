//! `central-migrate` — the dedicated, descriptor-only migration
//! operator. Port of `cmd/central-migrate/main.go`.
//!
//! The operator deliberately accepts no DSN, credential path, or
//! environment fallback: it is launched by the migration launcher with
//! the launch evidence on the fixed FD3 and the sealed credential
//! descriptor on FD4, runs the one bound operation through the
//! kernel-composed migration coordinator, and reports the outcome
//! durably through the broker authority — the task-2 seam
//! [`migrate_compose::run_operator`], which today fails closed.

mod sys;

use central_foundation::failure::Failure;
use central_kernel::migrate_compose::{self, MigrationCommand};

fn main() {
    if let Err(err) = run() {
        eprintln!("central-migrate: {err}");
        // Upstream `os.Exit(6)` — every operator failure is the
        // terminal class; classified exit mapping belongs to the
        // `central migrate *` client's durable-outcome read.
        std::process::exit(6);
    }
}

fn run() -> Result<(), Failure> {
    // `must run as central-migrate`.
    if !sys::running_as_central_migrate() {
        return Err(Failure::internal(
            "operator_identity",
            "must run as central-migrate",
        ));
    }
    // `args_os` so non-UTF-8 argv yields the upstream "invalid
    // migration command" refusal instead of an `env::args` panic.
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let (command, operation_id) = parse_invocation(&args)?;
    let evidence = sys::read_launch_evidence()?;
    // Reapply CLOEXEC on FD4 now, after exec and before descriptor
    // handoff; the guard is the deferred close on every path.
    let credential = sys::protect_credential_descriptor()?;
    // The B05 client is invoked by the operator composition with its
    // protected binding context — never a database URL.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Failure::internal("runtime", format!("central-migrate: {e}")))?;
    runtime.block_on(migrate_compose::run_operator(
        command,
        operation_id,
        evidence,
        credential.as_raw_fd(),
    ))?;
    Ok(())
}

/// `parseInvocation` — exactly `central-migrate <command>
/// <operationID>`; the command is the closed set and the operation ID
/// a non-nil UUID.
fn parse_invocation(args: &[String]) -> Result<(MigrationCommand, uuid::Uuid), Failure> {
    if args.len() != 3 {
        return Err(Failure::invalid(
            "invalid_migration_command",
            "invalid migration command",
        ));
    }
    let Some(command) = MigrationCommand::parse(&args[1]) else {
        return Err(Failure::invalid(
            "invalid_migration_command",
            "invalid migration command",
        ));
    };
    let operation_id = uuid::Uuid::parse_str(&args[2])
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| Failure::invalid("invalid_operation_id", "invalid original operation ID"))?;
    Ok((command, operation_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn args(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| (*s).to_owned()).collect()
    }

    const OP: &str = "019f1234-5678-7abc-8def-0123456789ab";

    // `parseInvocation` — the exact-argv closed grammar.

    #[test]
    fn parse_invocation_accepts_each_command() {
        for verb in ["up", "resume", "status", "verify", "reset"] {
            let (command, op) = parse_invocation(&args(&["central-migrate", verb, OP])).unwrap();
            assert_eq!(command.as_str(), verb);
            assert_eq!(op.to_string(), OP);
        }
    }

    #[test]
    fn parse_invocation_rejects_bad_argc() {
        for argv in [
            vec!["central-migrate"],
            vec!["central-migrate", "up"],
            vec!["central-migrate", "up", OP, "extra"],
        ] {
            let err = parse_invocation(&args(&argv)).unwrap_err();
            assert_eq!(err.code(), "invalid_migration_command");
        }
    }

    #[test]
    fn parse_invocation_rejects_unknown_and_case_commands() {
        for verb in ["bogus", "UP", "force", "migrate", "--operation"] {
            let err = parse_invocation(&args(&["central-migrate", verb, OP])).unwrap_err();
            assert_eq!(err.code(), "invalid_migration_command", "verb={verb}");
        }
    }

    #[test]
    fn parse_invocation_rejects_malformed_and_nil_operation_ids() {
        for id in [
            "not-a-uuid",
            "",
            "00000000-0000-0000-0000-000000000000",
            "019f1234-5678-7abc-8def-0123456789a", // short
        ] {
            let err = parse_invocation(&args(&["central-migrate", "up", id])).unwrap_err();
            assert_eq!(err.code(), "invalid_operation_id", "id={id:?}");
        }
    }

    // `readLaunchEvidenceUUID` — the fixed 16-byte FD3 protocol.

    #[test]
    fn launch_evidence_accepts_exactly_16_bytes() {
        let id = uuid::Uuid::now_v7();
        let got = sys::read_launch_evidence_uuid(Cursor::new(id.into_bytes())).unwrap();
        assert_eq!(got, id);
    }

    #[test]
    fn launch_evidence_rejects_short_reads() {
        for len in [0usize, 1, 15] {
            let err = sys::read_launch_evidence_uuid(Cursor::new(vec![0xab; len])).unwrap_err();
            assert_eq!(err.code(), "launch_evidence_read", "len={len}");
        }
    }

    #[test]
    fn launch_evidence_rejects_trailing_bytes() {
        let mut wire = uuid::Uuid::now_v7().into_bytes().to_vec();
        wire.push(0x00);
        let err = sys::read_launch_evidence_uuid(Cursor::new(wire)).unwrap_err();
        assert_eq!(err.code(), "launch_evidence_framing");
    }

    #[test]
    fn launch_evidence_rejects_nil_uuid() {
        let err = sys::read_launch_evidence_uuid(Cursor::new([0u8; 16])).unwrap_err();
        assert_eq!(err.code(), "launch_evidence_uuid");
    }

    // The identity gate's predicate.

    #[test]
    fn central_migrate_identity_requires_uid_and_gid_986() {
        assert!(sys::is_central_migrate_identity(986, 986));
        assert!(!sys::is_central_migrate_identity(0, 986));
        assert!(!sys::is_central_migrate_identity(986, 0));
        assert!(!sys::is_central_migrate_identity(1000, 1000));
    }
}
