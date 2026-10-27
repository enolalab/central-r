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
