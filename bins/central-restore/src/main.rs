//! `central-restore` is the fixed C04/C05 root recovery engine. It is
//! launched only by the root helper, after that helper's own PAM plus
//! physical-TTY ceremony has produced a one-use protected
//! authorization. It accepts no path, target, credential, connection
//! string, or option: every selector is an opaque protected identity
//! that the broker validates and consumes.
//!
//! It is a separate binary from `central-backup` on purpose.
//! `central-backup` is the unprivileged worker; this engine holds the
//! `postgres_migration_v1` credential that drives `pg_restore`, which
//! no worker may ever receive.
//!
//! `deny(unsafe_code)` keeps the grammar free of `unsafe`; `sys.rs`
//! is the audited raw-descriptor edge.
#![deny(unsafe_code)]

mod sys;

use std::io::Write;

use central_backup::app::RestoreVerificationResult;
use central_backup::recovery::operation::RestoreOperation;
use central_backup::recovery::refusal::{RestoreRefusalReason, classify_restore_refusal};
use central_kernel::restore_compose::{
    IMPORT_STAGING_FD, InheritedRestoreDescriptors, PROTECTED_ROOT_FD, REPOSITORY_FD,
    RESTORE_CAPACITY_ROLE_ROOT_FD, RESTORE_LAUNCH_GATE_FD, RestoreEngineOps,
    new_production_restore_engine, read_restore_launch_gate,
};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// `receipt` is the only thing this process writes to stdout. The
/// helper relays it to the operator, so it carries no repository
/// path, object key, target descriptor, connection string, ticket
/// nonce, or HMAC. `skip_serializing_if` is Go's `,omitempty`: an
/// empty field never reaches the wire.
#[derive(serde::Serialize)]
struct Receipt {
    schema_version: String,
    mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ticket_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backup_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    checkpoint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    expires_at: String,
    /// `Reason` is set only on a refusal receipt (no phase, no
    /// checkpoint): one of [`RestoreRefusalReason`]'s closed,
    /// locator-free values.
    #[serde(skip_serializing_if = "String::is_empty")]
    reason: String,
}

const RECEIPT_SCHEMA_VERSION: &str = "central.restore-engine-receipt/v1";

/// `restoreImportPhase`/`restoreImportCheckpoint` are the only
/// success vocabulary an import run emits: the run either completes
/// the whole data plane (`pg_restore`, verified shape, verified
/// bodies, consumed marker) or refuses. There are no partial phases
/// to report, and the launcher pins both values exactly.
const RESTORE_IMPORT_PHASE: &str = "imported";
const RESTORE_IMPORT_CHECKPOINT: &str = "plan_consumed";

/// `executeCentralRestore`'s terminal error — the cause is never
/// rendered because adapter errors can carry a locator even though
/// production adapters normally redact them.
struct Denied;

fn main() -> std::process::ExitCode {
    // This must be the first thing main() does, before anything else
    // in this process touches the protected root, a credential, or
    // the broker: see `waitForRestoreLaunchGate`
    // (cmd/central-restore/production_linux.go) for why a blocking
    // read here is what makes ADR 0015's ordering guarantee hold
    // regardless of scheduling.
    let Ok(reserve_set_id) = wait_for_restore_launch_gate() else {
        eprintln!("central-restore: RESTORE_ENGINE_UNAVAILABLE");
        return std::process::ExitCode::from(6);
    };
    let args: Vec<String> = std::env::args().collect();
    let inherited = inherited_descriptors(args.get(1).is_some_and(|m| m == "import"));
    let Ok(engine) = new_production_restore_engine(reserve_set_id, &inherited) else {
        // A composition failure must never look like a completed
        // recovery.
        eprintln!("central-restore: RESTORE_ENGINE_UNAVAILABLE");
        return std::process::ExitCode::from(6);
    };
    let mut out = std::io::stdout().lock();
    if execute_central_restore(&args, &engine, &mut out).is_err() {
        // Never render the wrapped cause: adapter errors can carry a
        // locator even though production adapters normally redact
        // them.
        eprintln!("central-restore: RESTORE_ENGINE_FAILED");
        return std::process::ExitCode::from(6);
    }
    std::process::ExitCode::SUCCESS
}

/// `waitForRestoreLaunchGate` blocks until the root helper's bind
/// with the broker either releases this process (the fixed-size
/// release message written to the gate pipe) or denies it (the pipe
/// closed with nothing written, observed here as EOF). Returns the
/// reserve-set identity the helper allocated for this launch —
/// `Uuid::nil()` for apply and resume.
fn wait_for_restore_launch_gate() -> Result<Uuid, Denied> {
    read_restore_launch_gate(sys::adopt_launch_gate(RESTORE_LAUNCH_GATE_FD)).map_err(|_| Denied)
}

/// The fixed descriptor set one launch hands the composition. Every
/// number is a constant the root helper pinned before exec; nothing
/// in argv or the environment selects them, so this process cannot be
/// pointed at another instance's protected state or at a repository
/// the helper did not authorize. The import staging slot is borrowed
/// only for an `import` launch — the launcher appends it after the
/// gate exactly then, so the gate stays fd 9 in every mode.
fn inherited_descriptors(import_mode: bool) -> InheritedRestoreDescriptors {
    InheritedRestoreDescriptors {
        protected_root: sys::borrow_process_fd(PROTECTED_ROOT_FD),
        repository: sys::borrow_process_fd(REPOSITORY_FD),
        role_roots: [
            sys::borrow_process_fd(RESTORE_CAPACITY_ROLE_ROOT_FD),
            sys::borrow_process_fd(RESTORE_CAPACITY_ROLE_ROOT_FD + 1),
            sys::borrow_process_fd(RESTORE_CAPACITY_ROLE_ROOT_FD + 2),
            sys::borrow_process_fd(RESTORE_CAPACITY_ROLE_ROOT_FD + 3),
        ],
        import_staging: import_mode.then(|| sys::borrow_process_fd(IMPORT_STAGING_FD)),
    }
}

/// `executeCentralRestore` — the whole argv contract. Anything that
/// is not exactly `verify|apply|resume|import` plus its opaque
/// identities is denied before the engine is consulted.
fn execute_central_restore(
    args: &[String],
    engine: &dyn RestoreEngineOps,
    out: &mut impl Write,
) -> Result<(), Denied> {
    if args.len() < 2 {
        return Err(Denied);
    }
    match args[1].as_str() {
        "verify" => run_verify(args, engine, out),
        "apply" => run_apply(args, engine, out),
        "resume" => run_resume(args, engine, out),
        "import" => run_import(args, engine, out),
        _ => Err(Denied),
    }
}

fn run_import(
    args: &[String],
    engine: &dyn RestoreEngineOps,
    out: &mut impl Write,
) -> Result<(), Denied> {
    if args.len() != 3 {
        return Err(Denied);
    }
    let operation_id = parse_opaque_identity(&args[2])?;
    match engine.import(operation_id) {
        Err(failure) => write_restore_refusal_receipt(
            out,
            "import",
            Some(operation_id),
            classify_restore_refusal(Some(&failure), RestoreRefusalReason::EngineUnavailable),
        ),
        Ok(result) => {
            // The substitution check: a result for any other
            // operation is a state refusal, never published — the
            // launcher matched this receipt to the operation it
            // launched.
            if result.operation_id != operation_id {
                return write_restore_refusal_receipt(
                    out,
                    "import",
                    Some(operation_id),
                    RestoreRefusalReason::StateInvalid,
                );
            }
            // Counts and digests stay inside the consumed marker on
            // the work dir; the receipt carries only the terminal
            // vocabulary, so possession of it cannot by itself
            // describe what was restored.
            write_receipt(
                out,
                &Receipt {
                    schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
                    mode: "import".to_owned(),
                    operation_id: result.operation_id.to_string(),
                    phase: RESTORE_IMPORT_PHASE.to_owned(),
                    checkpoint: RESTORE_IMPORT_CHECKPOINT.to_owned(),
                    ..Receipt::empty()
                },
            )
        }
    }
}

fn run_verify(
    args: &[String],
    engine: &dyn RestoreEngineOps,
    out: &mut impl Write,
) -> Result<(), Denied> {
    if args.len() != 3 {
        return Err(Denied);
    }
    let backup_id = parse_opaque_identity(&args[2])?;
    match engine.verify(backup_id) {
        Err(failure) => write_restore_refusal_receipt(
            out,
            "verify",
            None,
            classify_restore_refusal(Some(&failure), RestoreRefusalReason::EngineUnavailable),
        ),
        Ok(result) => {
            match publishable_verification(&result, backup_id) {
                None => write_restore_refusal_receipt(
                    out,
                    "verify",
                    None,
                    RestoreRefusalReason::StateInvalid,
                ),
                Some((operation_id, expires_at)) => {
                    // The ticket ID is deliberately absent:
                    // verification publishes only the pre-allocated
                    // operation identity, so possession of this
                    // receipt cannot by itself name the protected
                    // ticket a destructive apply consumes.
                    write_receipt(
                        out,
                        &Receipt {
                            schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
                            mode: "verify".to_owned(),
                            backup_id: result.backup_id.to_string(),
                            operation_id: operation_id.to_string(),
                            expires_at,
                            ..Receipt::empty()
                        },
                    )
                }
            }
        }
    }
}

/// `result.OperationID == uuid.Nil || result.BackupID != backupID ||
/// result.ExpiresAt.IsZero()` — a verify result that cannot be
/// published must not become a refusal naming another backup either.
fn publishable_verification(
    result: &RestoreVerificationResult,
    backup_id: Uuid,
) -> Option<(Uuid, String)> {
    if result.operation_id.is_nil() || result.backup_id != backup_id {
        return None;
    }
    let expires_at = result.expires_at.format(&Rfc3339).ok()?;
    if expires_at.is_empty() {
        return None;
    }
    Some((result.operation_id, expires_at))
}

fn run_apply(
    args: &[String],
    engine: &dyn RestoreEngineOps,
    out: &mut impl Write,
) -> Result<(), Denied> {
    let (operation_id, authorization_id) = two_opaque_identities(args, "apply")?;
    match engine.apply(operation_id, authorization_id) {
        Err(step) => write_restore_refusal_receipt(
            out,
            "apply",
            Some(operation_id),
            classify_restore_refusal(Some(&step.failure), RestoreRefusalReason::EngineUnavailable),
        ),
        Ok(operation) => write_operation_receipt(out, "apply", &operation),
    }
}

fn run_resume(
    args: &[String],
    engine: &dyn RestoreEngineOps,
    out: &mut impl Write,
) -> Result<(), Denied> {
    let (operation_id, authorization_id) = two_opaque_identities(args, "resume")?;
    match engine.resume(operation_id, authorization_id) {
        Err(step) => write_restore_refusal_receipt(
            out,
            "resume",
            Some(operation_id),
            classify_restore_refusal(Some(&step.failure), RestoreRefusalReason::EngineUnavailable),
        ),
        Ok(operation) => write_operation_receipt(out, "resume", &operation),
    }
}

/// `twoOpaqueIdentities` enforces the exact argv shape. Both
/// identities must be distinct UUIDv7 values: a caller that passes
/// the same identity twice is trying to make one protected record
/// stand in for two independent ones.
fn two_opaque_identities(args: &[String], mode: &str) -> Result<(Uuid, Uuid), Denied> {
    if args.len() != 4 || args[1] != mode {
        return Err(Denied);
    }
    let first = parse_opaque_identity(&args[2])?;
    let second = parse_opaque_identity(&args[3])?;
    if first == second {
        return Err(Denied);
    }
    Ok((first, second))
}

/// `parseOpaqueIdentity` — a canonical UUIDv7 string and nothing
/// else: `id.String() != value` refuses the non-canonical spellings
/// (braces, `urn:` prefix, missing hyphens, uppercase) the parser
/// would otherwise accept.
fn parse_opaque_identity(value: &str) -> Result<Uuid, Denied> {
    let id = Uuid::try_parse(value).map_err(|_| Denied)?;
    if id.is_nil() || id.get_version_num() != 7 || id.to_string() != value {
        return Err(Denied);
    }
    Ok(id)
}

/// `writeOperationReceipt` — `operation.Validate() != nil ||
/// OperationID == uuid.Nil || Phase == "" || LastCheckpoint == ""`.
/// Rust's `RestorePhase`/`RestoreCheckpoint` enums have no empty
/// spelling, so `is_valid` collapses to the `validate` plus nil check.
fn write_operation_receipt(
    out: &mut impl Write,
    mode: &str,
    operation: &RestoreOperation,
) -> Result<(), Denied> {
    if operation.validate().is_err() || operation.operation_id.is_nil() {
        return Err(Denied);
    }
    write_receipt(
        out,
        &Receipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
            mode: mode.to_owned(),
            operation_id: operation.operation_id.to_string(),
            backup_id: operation.backup_id.to_string(),
            phase: operation.phase.as_str().to_owned(),
            checkpoint: operation.last_checkpoint.as_str().to_owned(),
            ..Receipt::empty()
        },
    )
}

fn write_receipt(out: &mut impl Write, value: &Receipt) -> Result<(), Denied> {
    let encoded = serde_json::to_string(value).map_err(|_| Denied)?;
    writeln!(out, "{encoded}").map_err(|_| Denied)
}

/// `writeRestoreRefusalReceipt` is this process's only channel to its
/// launcher for a refusal: it writes a bounded, locator-free receipt
/// carrying nothing but the schema, mode, the operation identity when
/// one is already known to the caller (apply/resume/import; never
/// verify, which mints its operation identity only on success), and
/// the sanitized reason — no phase, no checkpoint, so it can never be
/// mistaken for a completed operation. It still returns `Denied` so
/// the process exits non-zero exactly as before the reason was added.
fn write_restore_refusal_receipt(
    out: &mut impl Write,
    mode: &str,
    operation_id: Option<Uuid>,
    reason: RestoreRefusalReason,
) -> Result<(), Denied> {
    write_receipt(
        out,
        &Receipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
            mode: mode.to_owned(),
            operation_id: operation_id.map(|id| id.to_string()).unwrap_or_default(),
            reason: reason.as_str().to_owned(),
            ..Receipt::empty()
        },
    )?;
    Err(Denied)
}

impl Receipt {
    /// The empty-field baseline every receipt spread fills — `Default`
    /// is not derived so a new field cannot silently default past a
    /// review of whether it belongs on the wire.
    fn empty() -> Self {
        Self {
            schema_version: String::new(),
            mode: String::new(),
            ticket_id: String::new(),
            backup_id: String::new(),
            operation_id: String::new(),
            phase: String::new(),
            checkpoint: String::new(),
            expires_at: String::new(),
            reason: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    //! `cmd/central-restore/main_test.go` — the invocation grammar and
    //! receipt shape batteries, run against the same
    //! [`execute_central_restore`] seam upstream injects its stub
    //! engine through.

    use super::*;

    use central_backup::app::{RestoreImportResult, RestoreStepFailure};
    use central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
    use central_backup::domain::TargetIdentity;
    use central_backup::recovery::operation::new_restore_operation;
    use central_foundation::failure::Failure;

    /// `engineStub` — records calls and returns canned results.
    #[derive(Default)]
    struct EngineStub {
        verify: Option<Result<RestoreVerificationResult, Failure>>,
        apply: Option<central_backup::app::RestoreStep>,
        resume: Option<central_backup::app::RestoreStep>,
        import: Option<Result<RestoreImportResult, Failure>>,
        calls: usize,
        last_first: Option<Uuid>,
        last_second: Option<Uuid>,
    }

    /// `&self` methods cannot record, so the stub lives behind a
    /// shared cell: the trait is `Send + Sync`, so `Mutex` is the
    /// honest shared-mutable shape.
    struct SharedStub {
        inner: std::sync::Mutex<EngineStub>,
    }

    impl SharedStub {
        fn new() -> Self {
            Self {
                inner: std::sync::Mutex::new(EngineStub::default()),
            }
        }
        fn calls(&self) -> usize {
            self.inner.lock().unwrap().calls
        }
        fn last(&self) -> (Option<Uuid>, Option<Uuid>) {
            let g = self.inner.lock().unwrap();
            (g.last_first, g.last_second)
        }
    }

    impl RestoreEngineOps for SharedStub {
        fn verify(&self, backup_id: Uuid) -> Result<RestoreVerificationResult, Failure> {
            let mut g = self.inner.lock().unwrap();
            g.calls += 1;
            g.last_first = Some(backup_id);
            g.verify
                .take()
                .unwrap_or_else(|| Err(RestoreRefusalReason::EngineUnavailable.into_failure()))
        }
        fn apply(
            &self,
            operation_id: Uuid,
            authorization_id: Uuid,
        ) -> central_backup::app::RestoreStep {
            let mut g = self.inner.lock().unwrap();
            g.calls += 1;
            g.last_first = Some(operation_id);
            g.last_second = Some(authorization_id);
            g.apply.take().unwrap_or_else(|| {
                Err(RestoreStepFailure {
                    operation: None,
                    failure: RestoreRefusalReason::EngineUnavailable.into_failure(),
                })
            })
        }
        fn resume(
            &self,
            operation_id: Uuid,
            authorization_id: Uuid,
        ) -> central_backup::app::RestoreStep {
            let mut g = self.inner.lock().unwrap();
            g.calls += 1;
            g.last_first = Some(operation_id);
            g.last_second = Some(authorization_id);
            g.resume.take().unwrap_or_else(|| {
                Err(RestoreStepFailure {
                    operation: None,
                    failure: RestoreRefusalReason::EngineUnavailable.into_failure(),
                })
            })
        }
        fn import(&self, operation_id: Uuid) -> Result<RestoreImportResult, Failure> {
            let mut g = self.inner.lock().unwrap();
            g.calls += 1;
            g.last_first = Some(operation_id);
            g.import
                .take()
                .unwrap_or_else(|| Err(RestoreRefusalReason::EngineUnavailable.into_failure()))
        }
    }

    /// `captureReceipt` — run the dispatcher against a buffer.
    fn run(args: &[&str], engine: &dyn RestoreEngineOps) -> (String, Result<(), Denied>) {
        let argv: Vec<String> = std::iter::once("central-restore".to_owned())
            .chain(args.iter().map(|s| (*s).to_owned()))
            .collect();
        let mut out: Vec<u8> = Vec::new();
        let result = execute_central_restore(&argv, engine, &mut out);
        (String::from_utf8_lossy(&out).into_owned(), result)
    }

    /// `newValidOperation` — a complete protected ticket built into an
    /// operation exactly as upstream's fixture does.
    fn valid_operation() -> RestoreOperation {
        let now = time::OffsetDateTime::now_utc();
        let digest = format!("sha256:{}", "ab".repeat(32));
        let ticket = central_backup::recovery::operation::RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: TargetIdentity {
                system_id: "7000000000000000000".to_owned(),
                database_oid: "16384".to_owned(),
                database: "central".to_owned(),
                config_hash: digest.clone(),
                epoch: 1,
            },
            target_fingerprint: digest.clone(),
            manifest_digest: digest.clone(),
            security_epoch: 3,
            restore_epoch: 4,
            config_fingerprint: digest.clone(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.to_owned(),
            capacity_evidence_digest: digest,
            tool_version: "16.14".to_owned(),
            hidden_nonce: vec![1, 2, 3, 4],
            issued_at: now - time::Duration::minutes(1),
            expires_at: now + time::Duration::minutes(10),
            hmac: String::new(),
        };
        new_restore_operation(&ticket, now).expect("valid fixture")
    }

    #[test]
    fn invocation_rejects_every_shape_outside_the_fixed_grammar() {
        let valid = Uuid::now_v7().to_string();
        let other = Uuid::now_v7().to_string();
        let v4 = Uuid::new_v4().to_string();
        let upper = valid.to_uppercase();
        let nil = Uuid::nil().to_string();
        let flag = format!("--backup-id={valid}");
        let cases: Vec<Vec<&str>> = vec![
            vec!["rollback", &valid, &other],
            vec!["verify"],
            vec!["verify", &valid, &other],
            vec!["import"],
            vec!["import", &valid, &other],
            vec!["import", "not-a-uuid"],
            vec!["import", &valid, &valid],
            vec!["import", &upper],
            vec!["apply", &valid],
            vec!["apply", &valid, &other, &valid],
            vec!["resume", &valid],
            // A repeated identity would let one protected record
            // stand in for two.
            vec!["apply", &valid, &valid],
            vec!["resume", &valid, &valid],
            vec!["apply", &v4, &other],
            vec!["apply", &nil, &other],
            vec!["apply", &upper, &other],
            // Nothing resembling a path, flag, or credential may be
            // accepted.
            vec!["apply", "/var/lib/central-protected/v1", &other],
            vec!["verify", &flag],
        ];
        for args in cases {
            let engine = SharedStub::new();
            let (receipt, result) = run(&args, &engine);
            assert!(result.is_err(), "invalid invocation accepted: {args:?}");
            assert_eq!(
                engine.calls(),
                0,
                "invalid invocation reached the engine: {args:?}"
            );
            assert!(
                receipt.is_empty(),
                "invalid invocation wrote a receipt: {args:?}"
            );
        }
        // `executeCentralRestore` with no mode at all.
        let engine = SharedStub::new();
        let argv = vec!["central-restore".to_owned()];
        let mut out: Vec<u8> = Vec::new();
        assert!(execute_central_restore(&argv, &engine, &mut out).is_err());
        assert_eq!(engine.calls(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn verify_publishes_operation_identity_without_ticket_or_secret_material() {
        let backup_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let engine = SharedStub::new();
        engine.inner.lock().unwrap().verify = Some(Ok(RestoreVerificationResult {
            operation_id,
            backup_id,
            manifest_digest: "0f1e2d3c".to_owned(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(10),
        }));
        let (receipt, result) = run(&["verify", &backup_id.to_string()], &engine);
        assert!(result.is_ok(), "verify refused");
        let decoded: serde_json::Value =
            serde_json::from_str(receipt.trim()).expect("receipt is not one JSON document");
        assert_eq!(decoded["schema_version"], RECEIPT_SCHEMA_VERSION);
        assert_eq!(decoded["mode"], "verify");
        assert_eq!(decoded["operation_id"], operation_id.to_string());
        assert_eq!(decoded["backup_id"], backup_id.to_string());
        // The ticket ID names the record a destructive apply
        // consumes, and the manifest digest is repository evidence:
        // neither belongs in this receipt.
        for forbidden in ["ticket_id", "manifest_digest", "hmac", "nonce"] {
            assert!(
                decoded.get(forbidden).is_none(),
                "receipt exposed {forbidden}: {decoded}"
            );
        }
        assert_eq!(engine.last().0, Some(backup_id));
    }

    #[test]
    fn verify_rejects_result_for_a_different_backup() {
        let requested = Uuid::now_v7();
        let substituted = Uuid::now_v7();
        let engine = SharedStub::new();
        engine.inner.lock().unwrap().verify = Some(Ok(RestoreVerificationResult {
            operation_id: Uuid::now_v7(),
            backup_id: substituted,
            manifest_digest: "0f1e2d3c".to_owned(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
        }));
        let (receipt, result) = run(&["verify", &requested.to_string()], &engine);
        assert!(result.is_err(), "substituted backup accepted");
        let decoded: serde_json::Value =
            serde_json::from_str(receipt.trim()).expect("refusal receipt is not one JSON document");
        assert_eq!(decoded["mode"], "verify");
        assert_eq!(decoded["reason"], "RESTORE_STATE_INVALID");
        // Neither the requested nor the substituted backup identity
        // may appear: a refusal receipt for a substitution attempt
        // names nothing at all.
        for forbidden in ["operation_id", "backup_id", "phase", "checkpoint"] {
            assert!(
                decoded.get(forbidden).is_none(),
                "refusal receipt exposed {forbidden}: {decoded}"
            );
        }
        assert!(
            !receipt.contains(&substituted.to_string()),
            "refusal receipt named the substituted backup: {receipt}"
        );
    }

    #[test]
    fn apply_and_resume_forward_exact_identities_and_emit_phase() {
        let operation = valid_operation();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        for mode in ["apply", "resume"] {
            let engine = SharedStub::new();
            let step = Ok(operation.clone());
            {
                let mut g = engine.inner.lock().unwrap();
                if mode == "apply" {
                    g.apply = Some(step);
                } else {
                    g.resume = Some(step);
                }
            }
            let (receipt, result) = run(&[mode, &first.to_string(), &second.to_string()], &engine);
            assert!(result.is_ok(), "{mode} refused");
            let (got_first, got_second) = engine.last();
            assert_eq!(got_first, Some(first), "identities reordered");
            assert_eq!(got_second, Some(second), "identities reordered");
            let decoded: serde_json::Value =
                serde_json::from_str(receipt.trim()).expect("receipt is not one JSON document");
            assert_eq!(decoded["mode"], mode);
            assert_eq!(decoded["operation_id"], operation.operation_id.to_string());
            assert_eq!(decoded["phase"], operation.phase.as_str());
            assert_eq!(decoded["checkpoint"], operation.last_checkpoint.as_str());
        }
    }

    #[test]
    fn import_forwards_the_exact_identity_and_emits_the_terminal_vocabulary() {
        let operation_id = Uuid::now_v7();
        let engine = SharedStub::new();
        engine.inner.lock().unwrap().import = Some(Ok(RestoreImportResult {
            operation_id,
            plan_sha256: "plan".to_owned(),
            dump_sha256: "dump".to_owned(),
            tables_present: 3,
            bodies_verified: 5,
            shape_checksum: "shape".to_owned(),
        }));
        let (receipt, result) = run(&["import", &operation_id.to_string()], &engine);
        assert!(result.is_ok(), "import refused");
        assert_eq!(engine.calls(), 1);
        assert_eq!(engine.last().0, Some(operation_id));
        let decoded: serde_json::Value =
            serde_json::from_str(receipt.trim()).expect("receipt is not one JSON document");
        assert_eq!(decoded["schema_version"], RECEIPT_SCHEMA_VERSION);
        assert_eq!(decoded["mode"], "import");
        assert_eq!(decoded["operation_id"], operation_id.to_string());
        assert_eq!(decoded["phase"], "imported");
        assert_eq!(decoded["checkpoint"], "plan_consumed");
        assert!(
            decoded.get("reason").is_none(),
            "success receipt carries a reason: {decoded}"
        );
    }

    #[test]
    fn import_rejects_a_result_for_a_different_operation() {
        let operation_id = Uuid::now_v7();
        let engine = SharedStub::new();
        engine.inner.lock().unwrap().import = Some(Ok(RestoreImportResult {
            operation_id: Uuid::now_v7(),
            plan_sha256: String::new(),
            dump_sha256: String::new(),
            tables_present: 0,
            bodies_verified: 0,
            shape_checksum: String::new(),
        }));
        let (receipt, result) = run(&["import", &operation_id.to_string()], &engine);
        assert!(result.is_err(), "substituted import result accepted");
        let decoded: serde_json::Value =
            serde_json::from_str(receipt.trim()).expect("refusal receipt is not one JSON document");
        assert_eq!(decoded["mode"], "import");
        assert_eq!(decoded["reason"], "RESTORE_STATE_INVALID");
        assert!(
            decoded.get("phase").is_none(),
            "refusal receipt carries a phase: {decoded}"
        );
    }

    #[test]
    fn engine_failure_writes_only_a_sanitized_refusal_receipt() {
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        for mode in ["apply", "resume"] {
            let engine = SharedStub::new();
            // An unclassified failure — its own text may carry a
            // locator — must fall back to engine-unavailable.
            {
                let mut g = engine.inner.lock().unwrap();
                let step = Err(RestoreStepFailure {
                    operation: None,
                    failure: Failure::invalid(
                        "adapter",
                        "adapter detail naming /var/lib/central-protected/v1",
                    ),
                });
                if mode == "apply" {
                    g.apply = Some(step);
                } else {
                    g.resume = Some(step);
                }
            }
            let (receipt, result) = run(&[mode, &first.to_string(), &second.to_string()], &engine);
            assert!(result.is_err(), "engine failure reported as success");
            assert!(
                !receipt.contains("/var/lib"),
                "adapter locator leaked: {receipt}"
            );
            let decoded: serde_json::Value = serde_json::from_str(receipt.trim())
                .expect("refusal receipt is not one JSON document");
            assert_eq!(decoded["mode"], mode);
            assert_eq!(decoded["reason"], "RESTORE_ENGINE_UNAVAILABLE");
            // The operation identity is exactly the one this caller
            // already supplied (first), present so the launcher's
            // anti-substitution match still has something to check on
            // a refusal, not a new disclosure.
            assert_eq!(decoded["operation_id"], first.to_string());
            for forbidden in ["backup_id", "phase", "checkpoint", "ticket_id"] {
                assert!(
                    decoded.get(forbidden).is_none(),
                    "refusal receipt exposed {forbidden}: {decoded}"
                );
            }
        }
    }

    #[test]
    fn engine_failure_classifies_distinct_refusal_causes() {
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        let cases: [(&str, RestoreRefusalReason); 3] = [
            (
                "restore state does not permit this",
                RestoreRefusalReason::StateInvalid,
            ),
            ("recovery media invalid", RestoreRefusalReason::MediaInvalid),
            (
                "capacity insufficient",
                RestoreRefusalReason::CapacityInsufficient,
            ),
        ];
        for mode in ["apply", "resume"] {
            let mut got: Vec<&'static str> = Vec::new();
            for (name, reason) in &cases {
                let engine = SharedStub::new();
                {
                    let mut g = engine.inner.lock().unwrap();
                    let step = Err(RestoreStepFailure {
                        operation: None,
                        failure: (*reason).into_failure(),
                    });
                    if mode == "apply" {
                        g.apply = Some(step);
                    } else {
                        g.resume = Some(step);
                    }
                }
                let (receipt, result) =
                    run(&[mode, &first.to_string(), &second.to_string()], &engine);
                assert!(result.is_err(), "{mode}/{name}: engine failure as success");
                let decoded: serde_json::Value = serde_json::from_str(receipt.trim())
                    .expect("refusal receipt is not one JSON document");
                assert_eq!(
                    decoded["reason"],
                    reason.as_str(),
                    "{mode}/{name}: receipt reason"
                );
                got.push(Box::leak(
                    decoded["reason"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                        .into_boxed_str(),
                ));
            }
            assert_ne!(got[0], got[1]);
            assert_ne!(got[1], got[2]);
            assert_ne!(got[0], got[2]);
        }
    }

    #[test]
    fn invalid_operation_result_is_not_published() {
        let engine = SharedStub::new();
        // `validate()` fails on a nearly-empty operation — the result
        // substitution a buggy adapter could return.
        engine.inner.lock().unwrap().apply = Some(Err(RestoreStepFailure {
            operation: None,
            failure: RestoreRefusalReason::StateInvalid.into_failure(),
        }));
        let (receipt, result) = run(
            &[
                "apply",
                &Uuid::now_v7().to_string(),
                &Uuid::now_v7().to_string(),
            ],
            &engine,
        );
        assert!(result.is_err());
        // A refusal receipt is the one permitted publication; the
        // operation record itself may never ride it.
        let decoded: serde_json::Value =
            serde_json::from_str(receipt.trim()).expect("refusal receipt is not one JSON document");
        assert!(decoded.get("phase").is_none());
        assert!(decoded.get("checkpoint").is_none());
    }

    #[test]
    fn production_composition_fails_closed() {
        // FDs 0/1/2 are open in the test harness but are not
        // directories, so adoption fails closed exactly as upstream's
        // absent-descriptor run does.
        let inherited = inherited_descriptors(false);
        let result = new_production_restore_engine(Uuid::now_v7(), &inherited);
        assert!(
            result.is_err(),
            "production engine composed without its roots"
        );
    }
}
