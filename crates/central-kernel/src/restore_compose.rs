//! `cmd/central-restore`'s production composition —
//! `production_linux.go`, `engine.go`,
//! `lazy_migration_session_linux.go`, and
//! `restore_bootstrap_fk_drop_linux.go` ported to the Rust kernel.
//!
//! The root restore engine is launched only by the root helper, after
//! the helper's own PAM plus physical-TTY ceremony has produced a
//! one-use protected authorization. It resolves no path, reads no
//! environment variable, and accepts no argv selector: the protected
//! root, the recovery repository, and the four capacity role roots all
//! arrive as fixed inherited descriptors the helper already opened,
//! and every credential is drawn from the broker over frame `0xc2`,
//! operation-scoped and zeroized after use.
//!
//! Slice boundary: ADR 0034's import *data plane* (`PlanImportSource`,
//! `PGRestoreForImport`, `ImportDataPlaneRunner`) is not yet ported, so
//! [`UnavailableRestoreImporter`] is the fail-closed placeholder the
//! composition installs — the same position upstream's
//! `unavailableAdmissionInspector` held before the reserve gate
//! shipped. The helper's `import_minio` seam already refuses an import
//! launch before an engine is ever spawned.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use central_adapter_linux::backup::{
    ComposedRestoreEngine as AdapterComposedRestoreEngine, PgRestore, PgRestoreConfig, Repository,
    RepositoryVerifier, RestoreAuditProjection, RestoreAuthorityResetter,
    RestoreCapacityDescriptor, RestoreCapacityReserveReceipt, RestoreCapacityReserveVerifier,
    RestoreCapacityRole, RestoreDatabaseRunner, RestoreDumpSource, RestoreInventoryVerifier,
    RestoreTargetAdmissionSource, S3BackupObjectSource, SealedRestorePassfileProvider,
    inspect_repository_descriptor, new_backup_reader_from_sealed_credential,
    new_descriptor_restore_capacity_source, new_repository_admission_inspector,
    read_sealed_passfile_value,
};
use central_adapter_linux::broker::restore_capacity::frame::ReceiptClient;
use central_adapter_linux::broker::restore_capacity::receipt::Receipt;
use central_adapter_linux::broker::restore_credential::RestoreCredentialClient;
use central_adapter_linux::broker::server::Service;
use central_adapter_linux::broker::{PRODUCTION_SOCKET_PATH, protocol::CENTRAL_RUNTIME_UID};
use central_adapter_postgres::backup::{
    PostgresRestoreTargetExcluder, RestoreTargetAdmissionReader, TrustedPayloadEpochSource,
    open_runtime_connection,
};
use central_adapter_postgres::migrate::runtime_connection::open_migration_connection;
use central_adapter_postgres::migrate::{
    reapply_runtime_grants, recreate_recovery_bootstrap_registrations_table,
};
use central_adapter_postgres::recovery::RecoveryAuditStore;
use central_adapter_postgres::recovery::RestoredInventoryVerifier;
use central_adapter_postgres::store_support::BlockingConn;
use central_artifact::port::{ObjectInfo, ObjectRef};
use central_backup::app::{
    AuthorityResetCoordinator, RestoreCoordinator, RestoreImportResult, RestoreStep,
    RestoreStepFailure, RestoreVerificationResult, RestoreVerifier,
};
use central_backup::backup::capacity::{
    DEFAULT_RECOVERY_DEADLINE, RecoveryProfile, default_recovery_profile,
};
use central_backup::port::{
    BackupSealVerifier, BrokerAuthorityReset, PostgresAuthorityReset, ReadClose,
    RecoveryInventorySource, RecoveryRepositoryVerifier, RecoveryVerificationEvidence,
    RestoreAdmissionFacts, RestoreAdmissionInspector, RestoreEngine, RestoreJournalStore,
    RestoreQuarantineStore, RestoreTargetExcluder, RestoreTargetExclusion, RestoreTicketIssuer,
};
use central_backup::recovery::operation::{
    AuthorityResetReceipt, RecoveryBootstrapActivation, RecoveryBootstrapDraft,
    RecoveryBootstrapRegistration, RestoreApplyAuthorization, RestoreCheckpoint, RestoreOperation,
    RestorePhase, RestoreTicket,
};
use central_backup::recovery::quarantine::QuarantineFinding;
use central_backup::recovery::refusal::{RestoreRefusalReason, classify_restore_refusal};
use central_backup::repository::RepositoryBinding;
use central_foundation::failure::Failure;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fixed descriptor and gate ABI — `production_linux.go`'s constants.
// ---------------------------------------------------------------------------

/// `productionBrokerSocket` — the protected broker's production
/// socket; the engine never learns another endpoint.
pub const PRODUCTION_BROKER_SOCKET: &str = PRODUCTION_SOCKET_PATH;

/// `productionHelperExecutablePath` — the one path the real root
/// helper is installed at. SC-DEF-58:
/// [`Service::new_for_restore_engine`] needs this explicitly because
/// `central-restore` is not itself the helper — self-resolving
/// `/proc/self/exe` here would name this binary, not the helper's, and
/// the restore-launch record's `helper_executable` (written by the
/// genuine helper) would then never match. It must name the exact same
/// path the helper's own `ProductionRestoreEngineLauncher` expects to
/// be running from — the two sides deliberately share no constant and
/// are kept in lockstep by hand.
pub const PRODUCTION_HELPER_EXECUTABLE_PATH: &str = "/usr/lib/central/central";

/// `protectedRootFD` — the protected root arrives as this inherited
/// descriptor the root helper already opened. Nothing in argv or the
/// environment selects it.
pub const PROTECTED_ROOT_FD: i32 = 3;

/// `repositoryFD` — the recovery repository's inherited descriptor.
pub const REPOSITORY_FD: i32 = 4;

/// `restoreCapacityRoleRootFD` — the first of the four capacity-role
/// directory descriptors, one per role, in the fixed order
/// [`RESTORE_CAPACITY_ROLE_ROOT_ORDER`] names. They are what
/// `DescriptorRestoreCapacitySource` measures free space against: the
/// runtime supplies neither their fd numbers nor their roles, and
/// there is no pathname-based fallback anywhere in that source.
pub const RESTORE_CAPACITY_ROLE_ROOT_FD: i32 = 5;

/// `restoreLaunchGateFD` — the read end of the pipe the helper's
/// `bind_and_run` appends as this process's last inherited descriptor,
/// after the protected root, the repository, and the four role roots.
/// The gate read blocks as this process's first action, before
/// anything else — including composing the protected root — so ADR
/// 0015's binding provably exists before this process's first daemon
/// call rather than merely usually preceding it.
pub const RESTORE_LAUNCH_GATE_FD: i32 = RESTORE_CAPACITY_ROLE_ROOT_FD + 4;

/// `importStagingFD` — the inherited descriptor carrying the staged
/// restore-plan work dir for an import launch. The launcher appends it
/// after the launch-gate pipe, so the gate stays fd 9 exactly as in
/// the restore modes and only import launches carry a tenth
/// descriptor. This number mirrors the helper launcher's descriptor
/// list; the two are deliberately duplicated, not shared, and must be
/// kept in lockstep by hand.
pub const IMPORT_STAGING_FD: i32 = RESTORE_LAUNCH_GATE_FD + 1;

/// `restoreLaunchGateReleaseByte` — must name the exact same value as
/// the helper's own release byte: the two sides intentionally share no
/// common constants, so this duplication is deliberate and kept in
/// lockstep by hand.
pub const RESTORE_LAUNCH_GATE_RELEASE_BYTE: u8 = 0x01;

/// `restoreLaunchGateMessageSize` — the release byte followed by the
/// 16-byte identity of the reserve set the verify launch allocated
/// (all-zero for apply and resume, which allocate nothing). A short
/// read blocks on a pipe whose writer has already moved on; the
/// launcher's deadline bounds the hang.
pub const RESTORE_LAUNCH_GATE_MESSAGE_SIZE: usize = 1 + 16;

/// `pinnedPgRestorePath`/`pinnedPgRestoreVersion` — the helper-selected
/// installation values; none may arrive through restore argv.
pub const PINNED_PG_RESTORE_BINARY: &str = "/usr/lib/postgresql/16/bin/pg_restore";
/// Upstream pins `"16.14"` verbatim.
pub const PINNED_PG_RESTORE_VERSION: &str =
    central_adapter_linux::backup::PINNED_PG_RESTORE_VERSION;

/// `restoreCapacityRoleRootOrder` fixes which capacity role this
/// process finds at which inherited descriptor, mirroring the
/// launcher's own role-root order. It is the frozen capacity source's
/// own role vocabulary, so there is no second spelling of the four
/// roles to keep in step — only the order.
pub const RESTORE_CAPACITY_ROLE_ROOT_ORDER: [RestoreCapacityRole; 4] = [
    RestoreCapacityRole::PostgresData,
    RestoreCapacityRole::PostgresWal,
    RestoreCapacityRole::PostgresTemp,
    RestoreCapacityRole::ObjectData,
];

/// `errRestoreEngineUnavailable` — the composition's whole
/// boundary: adapter errors may carry locators, so every internal
/// failure collapses to the refusal sentinel the receipt layer knows
/// how to classify.
fn engine_unavailable() -> Failure {
    RestoreRefusalReason::EngineUnavailable.into_failure()
}

/// `errRestoreCapacityReserveAuthorityUnavailable` — upstream's plain
/// (non-refusal) sentinel: the receipt layer classifies it to
/// `EngineUnavailable` exactly like every other unclassified failure.
fn reserve_authority_unavailable() -> Failure {
    Failure::unavailable(
        "restore_capacity_reserve_authority",
        "restore capacity reserve authority unavailable",
    )
}

// ---------------------------------------------------------------------------
// Launch gate — `readRestoreLaunchGate`.
// ---------------------------------------------------------------------------

/// `readRestoreLaunchGate` — the gate message's whole grammar with the
/// reader supplied, so it is testable without a process that owns the
/// fixed inherited descriptor. Blocks until the root helper's bind
/// with the broker either releases this process (the fixed-size
/// release message) or denies it (the pipe closed with nothing
/// written, observed here as EOF). A message of any length other than
/// exactly [`RESTORE_LAUNCH_GATE_MESSAGE_SIZE`], or a first byte other
/// than the release value, is treated identically to EOF: fail closed
/// on anything but an unambiguous release.
///
/// Returns the identity of the reserve set the helper allocated for
/// this launch — `Uuid::nil()` for apply and resume, which allocate
/// nothing and spend a set the verify launch created.
///
/// # Errors
/// `EngineUnavailable` on any non-release shape.
pub fn read_restore_launch_gate(mut gate: impl Read) -> Result<Uuid, Failure> {
    let mut message = [0u8; RESTORE_LAUNCH_GATE_MESSAGE_SIZE];
    // `read_exact`, not one `read`: a pipe write is not guaranteed to
    // arrive as one read, and a short read treated as a denial would
    // refuse genuine launches non-deterministically.
    gate.read_exact(&mut message)
        .map_err(|_| engine_unavailable())?;
    if message[0] != RESTORE_LAUNCH_GATE_RELEASE_BYTE {
        return Err(engine_unavailable());
    }
    // A trailing byte means this is not the message the launcher
    // writes. A closed writer (`Err` or `Ok(0)`) is exactly the
    // expected tail — upstream treats `n != 0` the same way.
    let mut trailing = [0u8; 1];
    if matches!(gate.read(&mut trailing), Ok(n) if n != 0) {
        return Err(engine_unavailable());
    }
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&message[1..]);
    let reserve_set_id = Uuid::from_bytes(tail);
    if !reserve_set_id.is_nil() && reserve_set_id.get_version_num() != 7 {
        return Err(engine_unavailable());
    }
    Ok(reserve_set_id)
}

// ---------------------------------------------------------------------------
// Inherited descriptor adoption — `adoptInheritedDirectory` +
// `adoptRestoreCapacityRoleRoots`.
// ---------------------------------------------------------------------------

/// `InheritedRestoreDescriptors` — the fixed descriptor set one
/// restore engine launch hands the composition. The `'static`
/// [`BorrowedFd`]s are sound because the launcher pins these slots for
/// the process lifetime; the unsafe `borrow_raw` that produces them
/// lives only in `bins/central-restore`'s audited edge — this module
/// never sees a raw descriptor.
pub struct InheritedRestoreDescriptors {
    /// [`PROTECTED_ROOT_FD`] — the broker's protected root.
    pub protected_root: BorrowedFd<'static>,
    /// [`REPOSITORY_FD`] — the recovery repository root.
    pub repository: BorrowedFd<'static>,
    /// [`RESTORE_CAPACITY_ROLE_ROOT_FD`]..=8 — the four capacity role
    /// roots in [`RESTORE_CAPACITY_ROLE_ROOT_ORDER`].
    pub role_roots: [BorrowedFd<'static>; 4],
    /// [`IMPORT_STAGING_FD`] — present only for `import` launches.
    pub import_staging: Option<BorrowedFd<'static>>,
}

/// `adoptInheritedDirectory` validates one inherited descriptor and
/// returns its `/proc` path. The descriptor, not a pathname, is the
/// authority: a directory swapped or symlinked after the helper opened
/// it cannot be substituted here.
///
/// # Errors
/// `EngineUnavailable` unless `fd` is a root-owned `0700` directory;
/// also when `FD_CLOEXEC` cannot be set — the protected root must not
/// leak into a `pg_restore` child.
pub fn adopt_inherited_directory(fd: BorrowedFd<'_>) -> Result<PathBuf, Failure> {
    let stat = rustix::fs::fstat(fd).map_err(|_| engine_unavailable())?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(engine_unavailable());
    }
    let flags = rustix::io::fcntl_getfd(fd).map_err(|_| engine_unavailable())?;
    rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| engine_unavailable())?;
    Ok(PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())))
}

/// `adoptRestoreCapacityRoleRoots` validates the four inherited
/// role-root descriptors and maps each to its role. Like
/// [`adopt_inherited_directory`] it asserts `FD_CLOEXEC` before
/// `pg_restore` can ever be spawned; unlike it, it does not require
/// root:root 0700 — a capacity role root is a service data directory
/// whose ownership the service that runs on it decides, not protected
/// state this codebase creates. The predicate is the one the helper's
/// own allocator applies to the same directories, so the two sides
/// measure the same device or refuse.
///
/// # Errors
/// `EngineUnavailable` on any non-directory or `st_dev == 0` slot.
pub fn adopt_restore_capacity_role_roots(
    role_roots: &[BorrowedFd<'static>; 4],
) -> Result<[(RestoreCapacityRole, BorrowedFd<'static>); 4], Failure> {
    let mut mapped = [(RestoreCapacityRole::PostgresData, role_roots[0]); 4];
    for (offset, role) in RESTORE_CAPACITY_ROLE_ROOT_ORDER.iter().enumerate() {
        mapped[offset] = (*role, role_roots[offset]);
    }
    for (_, fd) in &mut mapped {
        let stat = rustix::fs::fstat(*fd).map_err(|_| engine_unavailable())?;
        if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() || stat.st_dev == 0 {
            return Err(engine_unavailable());
        }
        let flags = rustix::io::fcntl_getfd(*fd).map_err(|_| engine_unavailable())?;
        rustix::io::fcntl_setfd(*fd, flags | rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| engine_unavailable())?;
    }
    Ok(mapped)
}

// ---------------------------------------------------------------------------
// Package-local ports — engine.go's `protectedRestoreState`,
// `restoreVerifier`, `restoreCoordinator`, `restoreImporter`, and
// `restoreEngine`; production_linux.go's frame-0xc4/0xc2 narrowings.
// ---------------------------------------------------------------------------

/// `protectedRestoreState` — the root-only in-process view of the
/// broker's protected journal. Begin and Resume compare whole ticket
/// and authorization values, so the engine must read them here rather
/// than trust argv: an opaque identity selects a record, it never
/// substitutes for one.
pub trait ProtectedRestoreState: Send + Sync {
    /// `ReadIssuedRestoreTicketForOperation`.
    fn read_issued_restore_ticket_for_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<RestoreTicket, Failure>;
    /// `ReadIssuedRestoreApplyAuthorization`.
    fn read_issued_restore_apply_authorization(
        &self,
        authorization_id: Uuid,
    ) -> Result<RestoreApplyAuthorization, Failure>;
}

impl ProtectedRestoreState for Service {
    fn read_issued_restore_ticket_for_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<RestoreTicket, Failure> {
        Service::read_issued_restore_ticket_for_operation(self, operation_id)
    }

    fn read_issued_restore_apply_authorization(
        &self,
        authorization_id: Uuid,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        Service::read_issued_restore_apply_authorization(self, authorization_id)
    }
}

/// `restoreVerifier` issues one protected ticket after non-mutating
/// verification. It returns only the operator-safe projection: the
/// ticket's HMAC and hidden nonce stay inside the broker.
pub trait RestoreVerifyPort: Send + Sync {
    /// `Verify`.
    fn verify(&self, backup_id: Uuid) -> Result<RestoreVerificationResult, Failure>;
}

/// `restoreCoordinator` owns every phase transition. This process
/// never advances a checkpoint itself.
pub trait RestoreCoordinatePort: Send + Sync {
    /// `Apply`.
    fn apply(
        &self,
        ticket: &RestoreTicket,
        authorization: &RestoreApplyAuthorization,
    ) -> RestoreStep;
    /// `Resume`.
    fn resume(&self, operation_id: Uuid, authorization: &RestoreApplyAuthorization) -> RestoreStep;
}

/// `restoreImporter` runs one staged restore-plan against the data
/// plane. ADR 0034's production implementation is the backup adapter's
/// import runner behind broker-drawn credentials; the engine holds it
/// as a collaborator so every mode stays constructible and testable
/// without a database or an object store.
pub trait RestoreImporter: Send + Sync {
    /// `Import`.
    fn import(&self, operation_id: Uuid) -> Result<RestoreImportResult, Failure>;
}

/// `restoreEngine` — the whole seam between the bin's invocation
/// contract and the production composition. Each method resolves its
/// own protected state from the broker; none accepts an
/// operator-supplied locator.
pub trait RestoreEngineOps: Send + Sync {
    /// `Verify`.
    fn verify(&self, backup_id: Uuid) -> Result<RestoreVerificationResult, Failure>;
    /// `Apply` — `(operationID, authorizationID)`.
    fn apply(&self, operation_id: Uuid, authorization_id: Uuid) -> RestoreStep;
    /// `Resume` — `(operationID, authorizationID)`.
    fn resume(&self, operation_id: Uuid, authorization_id: Uuid) -> RestoreStep;
    /// `Import`.
    fn import(&self, operation_id: Uuid) -> Result<RestoreImportResult, Failure>;
}

/// `restoreCapacityReceiptClient` — frame `0xc4` narrowed to the two
/// operations the admission path performs: drawing the four bearer
/// receipts for one reserve set, and spending one.
pub trait RestoreCapacityReceiptPort: Send + Sync {
    /// `DrawReceipts`.
    fn draw_receipts(&self, set_id: Uuid) -> Result<Vec<Receipt>, Failure>;
    /// `ConsumeReceipt`.
    fn consume_receipt(&self, receipt_id: Uuid, proof: &str) -> Result<(), Failure>;
}

/// `restoreCapacityReserveBinder` — frame `0xc4` kind 3: the only
/// path by which the operation id a successful verify just minted
/// reaches the daemon.
pub trait RestoreCapacityReserveBinder: Send + Sync {
    /// `BindReserveSet`.
    fn bind_reserve_set(&self, set_id: Uuid, operation_id: Uuid) -> Result<(), Failure>;
}

impl RestoreCapacityReceiptPort for ReceiptClient {
    fn draw_receipts(&self, set_id: Uuid) -> Result<Vec<Receipt>, Failure> {
        ReceiptClient::draw_receipts(self, set_id)
    }

    fn consume_receipt(&self, receipt_id: Uuid, proof: &str) -> Result<(), Failure> {
        ReceiptClient::consume_receipt(self, receipt_id, proof)
    }
}

impl RestoreCapacityReserveBinder for ReceiptClient {
    fn bind_reserve_set(&self, set_id: Uuid, operation_id: Uuid) -> Result<(), Failure> {
        ReceiptClient::bind_reserve_set(self, set_id, operation_id)
    }
}

/// `auditMigrationCredentialProvider` — kind 4 (SC-DEF-63): the same
/// `central_migration` secret material `open_sealed_restore_passfile`
/// releases for `pg_restore` itself, but admitted across the whole
/// live-operation window instead of only the single
/// `Applying`/`TicketConsumed` checkpoint `pg_restore` runs at — see
/// [`RestoreCredentialClient::open_audit_migration_credential`]'s doc
/// for why kind 1's narrower precondition cannot be reused here.
pub trait AuditMigrationCredentialProvider: Send + Sync {
    /// `OpenAuditMigrationCredential`.
    fn open_audit_migration_credential(&self, operation_id: Uuid) -> Result<File, Failure>;
}

impl AuditMigrationCredentialProvider for RestoreCredentialClient {
    fn open_audit_migration_credential(&self, operation_id: Uuid) -> Result<File, Failure> {
        RestoreCredentialClient::open_audit_migration_credential(self, operation_id).map(File::from)
    }
}

// ---------------------------------------------------------------------------
// Composed engine — `composedRestoreEngine` + `newRestoreEngine`.
// ---------------------------------------------------------------------------

/// `ComposedRestoreEngine` binds the four collaborators for one
/// invocation — upstream's `composedRestoreEngine`.
pub struct ComposedRestoreEngine {
    state: Arc<dyn ProtectedRestoreState>,
    verifier: Arc<dyn RestoreVerifyPort>,
    coordinator: Arc<dyn RestoreCoordinatePort>,
    importer: Arc<dyn RestoreImporter>,
}

/// `newRestoreEngine` — every collaborator is required; a nil
/// composition is never a working engine.
pub fn new_restore_engine(
    state: Option<Arc<dyn ProtectedRestoreState>>,
    verifier: Option<Arc<dyn RestoreVerifyPort>>,
    coordinator: Option<Arc<dyn RestoreCoordinatePort>>,
    importer: Option<Arc<dyn RestoreImporter>>,
) -> Result<ComposedRestoreEngine, Failure> {
    let (Some(state), Some(verifier), Some(coordinator), Some(importer)) =
        (state, verifier, coordinator, importer)
    else {
        return Err(engine_unavailable());
    };
    Ok(ComposedRestoreEngine {
        state,
        verifier,
        coordinator,
        importer,
    })
}

impl ComposedRestoreEngine {
    /// `Verify` — confirms immutable backup evidence and current
    /// target facts. A result for a different backup than requested is
    /// the substitution this check exists to stop, distinct from any
    /// inspector failure.
    pub fn verify(&self, backup_id: Uuid) -> Result<RestoreVerificationResult, Failure> {
        if backup_id.is_nil() {
            return Err(engine_unavailable());
        }
        // Preserve the verifier's own sanitized classification instead
        // of collapsing it: this is the exact flattening point the
        // operator used to see one message from regardless of cause.
        let result = self.verifier.verify(backup_id)?;
        if result.backup_id != backup_id {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        Ok(result)
    }

    /// `Apply` — the destructive path. The ticket is resolved from the
    /// operation, never named by the caller; two independently valid
    /// protected records must still describe the same ceremony before
    /// any destructive path is entered.
    pub fn apply(&self, operation_id: Uuid, authorization_id: Uuid) -> RestoreStep {
        if operation_id.is_nil() || authorization_id.is_nil() {
            return Err(RestoreStepFailure {
                operation: None,
                failure: engine_unavailable(),
            });
        }
        let state_invalid = |failure: Failure| RestoreStepFailure {
            operation: None,
            failure,
        };
        let ticket = self
            .state
            .read_issued_restore_ticket_for_operation(operation_id)
            .map_err(|e| {
                state_invalid(
                    classify_restore_refusal(Some(&e), RestoreRefusalReason::StateInvalid)
                        .into_failure(),
                )
            })?;
        if ticket.ticket_id.is_nil() || ticket.operation_id != operation_id {
            return Err(state_invalid(
                RestoreRefusalReason::StateInvalid.into_failure(),
            ));
        }
        let authorization = self
            .state
            .read_issued_restore_apply_authorization(authorization_id)
            .map_err(|e| {
                state_invalid(
                    classify_restore_refusal(Some(&e), RestoreRefusalReason::StateInvalid)
                        .into_failure(),
                )
            })?;
        if authorization.authorization_id != authorization_id
            || authorization.operation_id != operation_id
        {
            return Err(state_invalid(
                RestoreRefusalReason::StateInvalid.into_failure(),
            ));
        }
        // Reject a mismatched pair here rather than relying on the
        // journal alone.
        if !authorization.binds(&ticket) {
            return Err(state_invalid(
                RestoreRefusalReason::StateInvalid.into_failure(),
            ));
        }
        self.coordinator.apply(&ticket, &authorization)
    }

    /// `Resume` — a fresh authorization continues exactly its own
    /// operation.
    pub fn resume(&self, operation_id: Uuid, authorization_id: Uuid) -> RestoreStep {
        if operation_id.is_nil() || authorization_id.is_nil() {
            return Err(RestoreStepFailure {
                operation: None,
                failure: engine_unavailable(),
            });
        }
        let authorization = self
            .state
            .read_issued_restore_apply_authorization(authorization_id)
            .map_err(|e| RestoreStepFailure {
                operation: None,
                failure: classify_restore_refusal(Some(&e), RestoreRefusalReason::StateInvalid)
                    .into_failure(),
            })?;
        if authorization.authorization_id != authorization_id
            || authorization.operation_id != operation_id
        {
            return Err(RestoreStepFailure {
                operation: None,
                failure: RestoreRefusalReason::StateInvalid.into_failure(),
            });
        }
        self.coordinator.resume(operation_id, &authorization)
    }

    /// `Import` — one staged restore-plan against the data plane.
    pub fn import(&self, operation_id: Uuid) -> Result<RestoreImportResult, Failure> {
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.importer.import(operation_id)
    }
}

impl RestoreEngineOps for ComposedRestoreEngine {
    fn verify(&self, backup_id: Uuid) -> Result<RestoreVerificationResult, Failure> {
        ComposedRestoreEngine::verify(self, backup_id)
    }
    fn apply(&self, operation_id: Uuid, authorization_id: Uuid) -> RestoreStep {
        ComposedRestoreEngine::apply(self, operation_id, authorization_id)
    }
    fn resume(&self, operation_id: Uuid, authorization_id: Uuid) -> RestoreStep {
        ComposedRestoreEngine::resume(self, operation_id, authorization_id)
    }
    fn import(&self, operation_id: Uuid) -> Result<RestoreImportResult, Failure> {
        ComposedRestoreEngine::import(self, operation_id)
    }
}

/// `ComposedRestoreCoordinator` — `backupapp.NewRestoreCoordinator`
/// behind the kernel-local port. The coordinator is stateless, so the
/// wrapper builds it per call over the same journal and engine the
/// roots supplied — the Rust ownership form of upstream's held
/// reference.
struct ComposedRestoreCoordinator {
    journal: Arc<dyn RestoreJournalStore>,
    engine: Arc<dyn RestoreEngine>,
}

impl RestoreCoordinatePort for ComposedRestoreCoordinator {
    fn apply(
        &self,
        ticket: &RestoreTicket,
        authorization: &RestoreApplyAuthorization,
    ) -> RestoreStep {
        RestoreCoordinator::new(&*self.journal, &*self.engine).apply(ticket, authorization)
    }

    fn resume(&self, operation_id: Uuid, authorization: &RestoreApplyAuthorization) -> RestoreStep {
        RestoreCoordinator::new(&*self.journal, &*self.engine).resume(operation_id, authorization)
    }
}

/// `reserveBindingVerifier` performs frame `0xc4` kind 3 immediately
/// after a successful verification, and refuses the verification if it
/// cannot.
///
/// The bind has to happen here, in this process, after Verify: the
/// operation id it carries is minted by `IssueRestoreTicket`, an
/// in-process call inside `RestoreVerifier::verify`, so no other
/// process in the system has ever seen it and there is no earlier
/// point at which the pair exists.
///
/// A bind failure fails the whole verification rather than being
/// reported and swallowed. The alternative is worse in exactly the
/// case this authority exists for: the operator would be handed a
/// ticket, run apply hours later on a damaged machine, and be refused
/// by the capacity gate for a reserve that was allocated and held the
/// entire time.
///
/// It wraps rather than extends `RestoreVerifier` because the
/// app-layer verifier is domain code that must not learn about broker
/// frames, and because apply and resume compose the identical engine
/// and must be unaffected — they never call `verify`, so this type is
/// inert for them.
struct ReserveBindingVerifier {
    repository: Arc<dyn RecoveryRepositoryVerifier>,
    seals: Arc<dyn BackupSealVerifier>,
    inspector: Arc<dyn RestoreAdmissionInspector>,
    issuer: Arc<dyn RestoreTicketIssuer>,
    profile: RecoveryProfile,
    binder: Option<Arc<dyn RestoreCapacityReserveBinder>>,
    set_id: Uuid,
}

impl RestoreVerifyPort for ReserveBindingVerifier {
    fn verify(&self, backup_id: Uuid) -> Result<RestoreVerificationResult, Failure> {
        let verifier = RestoreVerifier::new(
            &*self.repository,
            &*self.seals,
            &*self.inspector,
            &*self.issuer,
            self.profile,
        );
        let result = verifier.verify(backup_id)?;
        let Some(binder) = &self.binder else {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        if self.set_id.is_nil() || result.operation_id.is_nil() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        binder
            .bind_reserve_set(self.set_id, result.operation_id)
            .map_err(|e| {
                classify_restore_refusal(Some(&e), RestoreRefusalReason::StateInvalid)
                    .into_failure()
            })?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// `lazyMigrationSession` — the SC-DEF-62 shared `central_migration`
// session, opened on the first call that supplies a real operation.
// ---------------------------------------------------------------------------

/// `LazyMigrationSession` — see upstream's doc: `RecoveryAuditStore`
/// is "deliberately bound to one dedicated `central_migration`
/// connection: callers retain the C04 target exclusion on that same
/// session while every projection is written", but the production
/// composition has to build the excluder and the audit projection
/// before any restore operation exists (a `restore verify` invocation
/// constructs the whole engine even though it never uses either), and
/// a migration credential can only be drawn for a real, already-minted
/// operation. There is no fourth recovery database role, so
/// `central_runtime` was the stand-in — exactly why projection's first
/// real invocation failed with `permission denied`.
///
/// The session defers opening the dedicated `central_migration`
/// connection until the first real caller supplies a concrete
/// operation, then reuses that same connection — and therefore the
/// same PostgreSQL session — for every subsequent
/// excluder/audit/resetter call for the rest of this process's
/// lifetime. `central-restore` is a one-shot process per invocation,
/// so "reuse for the process lifetime" is exactly "reuse for the
/// operation." A first failure is cached identically (upstream's
/// sticky `s.err`).
struct LazyMigrationSession {
    credentials: Arc<dyn AuditMigrationCredentialProvider>,
    conn: OnceLock<Result<Arc<BlockingConn>, Failure>>,
}

impl LazyMigrationSession {
    fn new(credentials: Arc<dyn AuditMigrationCredentialProvider>) -> Self {
        Self {
            credentials,
            conn: OnceLock::new(),
        }
    }

    fn connection(&self, operation: &RestoreOperation) -> Result<Arc<BlockingConn>, Failure> {
        self.conn.get_or_init(|| self.connect(operation)).clone()
    }

    fn connect(&self, operation: &RestoreOperation) -> Result<Arc<BlockingConn>, Failure> {
        let passfile = self
            .credentials
            .open_audit_migration_credential(operation.operation_id)
            .map_err(|e| {
                classify_restore_refusal(Some(&e), RestoreRefusalReason::EngineUnavailable)
                    .into_failure()
            })?;
        let value = Zeroizing::new(
            read_sealed_passfile_value(&passfile).map_err(|_| engine_unavailable())?,
        );
        BlockingConn::new_connecting(move || async move { open_migration_connection(&value).await })
            .map(Arc::new)
            .map_err(|_| engine_unavailable())
    }
}

/// `lazyMigrationExcluder` — [`RestoreTargetExcluder`] on the shared
/// session, so the C04 advisory lock it acquires is held on the exact
/// connection `LazyMigrationAuditProjection` and
/// `LazyMigrationAuthorityResetter` go on to write through.
struct LazyMigrationExcluder {
    session: Arc<LazyMigrationSession>,
}

impl RestoreTargetExcluder for LazyMigrationExcluder {
    fn acquire_restore_target_exclusion(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Box<dyn RestoreTargetExclusion>, Failure> {
        let conn = self.session.connection(operation)?;
        PostgresRestoreTargetExcluder::from_blocking_conn(conn)
            .acquire_restore_target_exclusion(operation)
    }
}

/// `lazyMigrationAuditProjection` — [`RestoreAuditProjection`] on the
/// shared session.
struct LazyMigrationAuditProjection {
    session: Arc<LazyMigrationSession>,
}

impl LazyMigrationAuditProjection {
    fn store(&self, operation: &RestoreOperation) -> Result<RecoveryAuditStore, Failure> {
        let conn = self.session.connection(operation)?;
        Ok(RecoveryAuditStore::from_blocking_conn(conn))
    }
}

impl RestoreAuditProjection for LazyMigrationAuditProjection {
    fn project_restore_operation(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        self.store(operation)?.project_restore_operation(operation)
    }

    fn record_quarantine_findings(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure> {
        self.store(operation)?
            .record_quarantine_findings(operation, findings)
    }

    fn unresolved_quarantine_count(&self, operation: &RestoreOperation) -> Result<u64, Failure> {
        self.store(operation)?
            .unresolved_quarantine_count(operation)
    }
}

/// `lazyMigrationAuthorityResetter` — [`PostgresAuthorityReset`] on
/// the shared session.
struct LazyMigrationAuthorityResetter {
    session: Arc<LazyMigrationSession>,
}

impl LazyMigrationAuthorityResetter {
    fn store(&self, operation: &RestoreOperation) -> Result<RecoveryAuditStore, Failure> {
        let conn = self.session.connection(operation)?;
        Ok(RecoveryAuditStore::from_blocking_conn(conn))
    }
}

impl PostgresAuthorityReset for LazyMigrationAuthorityResetter {
    fn reset_database_authority(
        &self,
        operation: &RestoreOperation,
        draft: &RecoveryBootstrapDraft,
    ) -> Result<RecoveryBootstrapRegistration, Failure> {
        self.store(operation)?
            .reset_database_authority(operation, draft)
    }

    fn finalize_database_authority_reset(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
        activation: &RecoveryBootstrapActivation,
    ) -> Result<AuthorityResetReceipt, Failure> {
        self.store(operation)?.finalize_database_authority_reset(
            operation,
            registration,
            activation,
        )
    }
}

/// `ComposedAuthorityResetter` — `backupapp.NewAuthorityResetCoordinator`
/// behind the adapter's [`RestoreAuthorityResetter`] port. The
/// coordinator is stateless, so this wrapper builds it per call over
/// the broker and lazy-session ports — the Rust ownership form of
/// upstream's held reference.
struct ComposedAuthorityResetter {
    broker: Arc<dyn BrokerAuthorityReset>,
    database: Arc<dyn PostgresAuthorityReset>,
}

impl RestoreAuthorityResetter for ComposedAuthorityResetter {
    fn reset_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<AuthorityResetReceipt, Failure> {
        AuthorityResetCoordinator::new(&*self.broker, &*self.database).reset_authority(operation)
    }
}

// ---------------------------------------------------------------------------
// `fkDroppingRestoreDatabase` — SC-DEF-60/61/65's DDL wrapper around
// the pinned pg_restore adapter.
// ---------------------------------------------------------------------------

/// `recoveryBootstrapRegistrationsDropTableDDL` removes the one table
/// that blocks `pg_restore`'s `--clean` cycle from completing.
///
/// SC-DEF-52 deliberately excludes
/// `central.recovery_bootstrap_registrations` from every real backup
/// (`central_runtime`, the role `pg_dump` runs as, must never read it —
/// it is C05's broker-protected proof of exactly one fresh bootstrap
/// generation). Because the table is never dumped, nothing in the
/// restored archive ever asks to drop it or its foreign key into
/// `central.recovery_operations`. SC-DEF-60 found this blocks
/// `--clean` twice over: the foreign key stops `pg_restore` from
/// dropping `recovery_operations`'s primary key, and the table itself
/// is still schema `central`'s, so `DROP SCHEMA central` fails
/// identically.
///
/// This is the correct scope: C05's whole purpose is that no
/// pre-restore authority state survives a restore, and this table's
/// rows are exactly that. The migration chain recreates it the next
/// time `central migrate up` runs — but this run's own C05 reset
/// needs it first, so [`FkDroppingRestoreDatabase`] recreates it in
/// step 4 (SC-DEF-65).
/// `recoveryBootstrapRegistrationsDropTableDDL` — names
/// [`RECOVERY_BOOTSTRAP_REGISTRATION_TABLE`] verbatim; `concat!`
/// cannot splice a `const`, so the literal is duplicated deliberately
/// exactly as upstream's two packages duplicate the table name.
const RECOVERY_BOOTSTRAP_REGISTRATIONS_DROP_TABLE_DDL: &str =
    "DROP TABLE IF EXISTS central.recovery_bootstrap_registrations CASCADE";

/// `FkDroppingRestoreDatabase` decorates the pinned `pg_restore`
/// adapter with the pre/post-restore DDL steps. It holds no connection
/// across calls: a fresh migration credential is fetched, used once,
/// and closed for every step, exactly as the pinned adapter itself
/// does for its own passfile.
struct FkDroppingRestoreDatabase {
    inner: Arc<dyn RestoreDatabaseRunner>,
    credentials: Arc<dyn SealedRestorePassfileProvider>,
}

impl FkDroppingRestoreDatabase {
    /// One dedicated `central_migration` session for one DDL step —
    /// kind 1 (`OpenSealedRestorePassfile`), the same draw the pinned
    /// adapter performs for `pg_restore` itself.
    fn migration_conn(&self, operation: &RestoreOperation) -> Result<BlockingConn, Failure> {
        let passfile = self
            .credentials
            .open_sealed_restore_passfile(operation)
            .map_err(|e| {
                classify_restore_refusal(Some(&e), RestoreRefusalReason::EngineUnavailable)
                    .into_failure()
            })?;
        let value = Zeroizing::new(
            read_sealed_passfile_value(&passfile).map_err(|_| engine_unavailable())?,
        );
        BlockingConn::new_connecting(move || async move { open_migration_connection(&value).await })
            .map_err(|_| engine_unavailable())
    }
}

impl RestoreDatabaseRunner for FkDroppingRestoreDatabase {
    fn restore_database(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        let drop_conn = self.migration_conn(operation)?;
        drop_conn.run(|conn| {
            Box::pin(async move {
                sqlx::raw_sql(RECOVERY_BOOTSTRAP_REGISTRATIONS_DROP_TABLE_DDL)
                    .execute(&mut *conn)
                    .await
                    .map_err(|_| engine_unavailable())?;
                Ok(())
            })
        })?;
        self.inner.restore_database(operation)?;
        // SC-DEF-61: pg_restore just ran with --no-privileges
        // (deliberately, so the dump can never carry or replay
        // arbitrary ACL statements), which leaves central_runtime with
        // zero privileges on schema central even though every table
        // and row restored correctly. Re-sync them now so the
        // coordinator's next step does not have to fail first.
        let grants_conn = self.migration_conn(operation)?;
        grants_conn.run(|conn| {
            Box::pin(async move {
                reapply_runtime_grants(conn)
                    .await
                    .map_err(|_| engine_unavailable())
            })
        })?;
        // SC-DEF-65: the table this Restore call itself dropped is
        // never recreated by any later step in this same run, and the
        // C05 reset ahead must read from and insert into it.
        let recreate_conn = self.migration_conn(operation)?;
        recreate_conn.run(|conn| {
            Box::pin(async move {
                recreate_recovery_bootstrap_registrations_table(conn)
                    .await
                    .map_err(|_| engine_unavailable())
            })
        })
    }
}

// ---------------------------------------------------------------------------
// `RepositoryDumpSource` — binds `PgRestore` to the fixed repository
// and installed profile.
// ---------------------------------------------------------------------------

/// `RepositoryDumpSource` — each apply re-verifies the complete
/// sealed media before yielding the dump descriptor. It deliberately
/// has no path argument: a command controller cannot direct
/// `pg_restore` at arbitrary recovery media.
struct RepositoryDumpSource {
    repository: Repository,
    profile: RecoveryProfile,
}

impl RestoreDumpSource for RepositoryDumpSource {
    fn open_verified_dump(&self, operation: &RestoreOperation) -> Result<File, Failure> {
        if self.profile.validate().is_err()
            || operation.phase != RestorePhase::Applying
            || operation.last_checkpoint != RestoreCheckpoint::TicketConsumed
        {
            return Err(engine_unavailable());
        }
        self.repository
            .open_verified_dump(operation.backup_id, &self.profile)
    }
}

// ---------------------------------------------------------------------------
// `productionRestoreAdmissionInspector` — draws this launch's four
// capacity receipts, then delegates to the frozen adapter inspector.
// ---------------------------------------------------------------------------

/// `productionRestoreAdmissionInspector` — the composition C03 could
/// not complete until the reserve gate existed. It is deliberately
/// *lazy*: every collaborator it can resolve at composition time it
/// resolves and refuses on; the four receipts it cannot, because
/// drawing them is a protected daemon call that mints bearer values,
/// and composition runs for apply and resume too — neither of which
/// ever consults the inspector. Drawing eagerly would make every apply
/// mint four bearer values it will never present, against a set it
/// does not have.
struct ProductionRestoreAdmissionInspector {
    repository_fd: BorrowedFd<'static>,
    binding: RepositoryBinding,
    seals: Arc<dyn BackupSealVerifier>,
    target: Arc<dyn RestoreTargetAdmissionSource>,
    profile: RecoveryProfile,
    receipts: Arc<dyn RestoreCapacityReceiptPort>,
    reserve_set_id: Uuid,
    role_roots: [(RestoreCapacityRole, BorrowedFd<'static>); 4],
}

impl RestoreAdmissionInspector for ProductionRestoreAdmissionInspector {
    /// `InspectRestoreAdmission` — no reserve set means this launch
    /// allocated nothing (the apply/resume shape, which never reaches
    /// here, or a verify whose launcher could not allocate); either
    /// way there is no physical cushion, and admission must not be
    /// granted on the strength of one that does not exist.
    fn inspect_restore_admission(
        &self,
        backup_id: Uuid,
        evidence: &RecoveryVerificationEvidence,
    ) -> Result<RestoreAdmissionFacts, Failure> {
        if self.reserve_set_id.is_nil() || self.reserve_set_id.get_version_num() != 7 {
            return Err(reserve_authority_unavailable());
        }
        let drawn = self
            .receipts
            .draw_receipts(self.reserve_set_id)
            .map_err(|_| reserve_authority_unavailable())?;
        let descriptors = restore_capacity_descriptors(&drawn, &self.role_roots)?;
        let source = new_descriptor_restore_capacity_source(
            descriptors,
            Arc::new(RestoreCapacityReceiptVerifier {
                receipts: self.receipts.clone(),
            }),
        )
        .map_err(|_| reserve_authority_unavailable())?;
        // Upstream shares one `*Repository`; Rust's owned-descriptor
        // model re-derives the identical read-only handle per call —
        // same descriptor, same binding, same shared lock class.
        let repository = Repository::read_only_from_descriptor(self.repository_fd, &self.binding)
            .map_err(|_| reserve_authority_unavailable())?;
        let inspector = new_repository_admission_inspector(
            repository,
            self.seals.clone(),
            self.target.clone(),
            Box::new(source),
            self.profile,
        )
        .map_err(|_| reserve_authority_unavailable())?;
        inspector.inspect_restore_admission(backup_id, evidence)
    }
}

/// `restoreCapacityDescriptors` pairs each inherited role-root
/// descriptor with the drawn receipt for that exact role. A draw that
/// is missing a role, carries a role twice, or carries one this build
/// does not know is refused outright: the frozen source requires
/// exactly one descriptor per role and treats the receipt's role as
/// authoritative for the device it is compared against.
fn restore_capacity_descriptors(
    drawn: &[Receipt],
    role_roots: &[(RestoreCapacityRole, BorrowedFd<'static>); 4],
) -> Result<Vec<RestoreCapacityDescriptor<BorrowedFd<'static>>>, Failure> {
    if drawn.len() != RESTORE_CAPACITY_ROLE_ROOT_ORDER.len() {
        return Err(reserve_authority_unavailable());
    }
    let mut by_role = std::collections::HashMap::with_capacity(drawn.len());
    for receipt in drawn {
        let Some(role) = RestoreCapacityRole::parse(&receipt.role) else {
            return Err(reserve_authority_unavailable());
        };
        if by_role.insert(role, receipt).is_some() {
            return Err(reserve_authority_unavailable());
        }
    }
    let mut descriptors = Vec::with_capacity(RESTORE_CAPACITY_ROLE_ROOT_ORDER.len());
    for (role, fd) in role_roots {
        let Some(receipt) = by_role.get(role) else {
            return Err(reserve_authority_unavailable());
        };
        descriptors.push(RestoreCapacityDescriptor {
            role: *role,
            fd: *fd,
            reserve: RestoreCapacityReserveReceipt {
                schema_version: receipt.schema_version.clone(),
                receipt_id: receipt.receipt_id,
                backup_id: receipt.backup_id,
                repository_binding_id: receipt.repository_binding_id,
                role: *role,
                device_id: receipt.device_id.clone(),
                reserved_bytes: receipt.reserved_bytes,
                issued_at: receipt.issued_at,
                expires_at: receipt.expires_at,
                authority_proof: receipt.authority_proof.clone(),
            },
        });
    }
    Ok(descriptors)
}

/// `restoreCapacityReceiptVerifier` — the frozen source's
/// [`RestoreCapacityReserveVerifier`]: presenting one bearer value to
/// the daemon, which is what spending a receipt *is*. The source calls
/// it once per descriptor before it compares device fingerprints, so a
/// helper and consumer that disagree about device identity burn a
/// receipt on every attempt — a property the design chose deliberately
/// and this composition must not second-guess by pre-checking the
/// fingerprint here.
struct RestoreCapacityReceiptVerifier {
    receipts: Arc<dyn RestoreCapacityReceiptPort>,
}

impl RestoreCapacityReserveVerifier for RestoreCapacityReceiptVerifier {
    fn verify_restore_capacity_reserve(
        &self,
        receipt: &RestoreCapacityReserveReceipt,
    ) -> Result<(), Failure> {
        if receipt.receipt_id.is_nil() || receipt.authority_proof.is_empty() {
            return Err(reserve_authority_unavailable());
        }
        self.receipts
            .consume_receipt(receipt.receipt_id, &receipt.authority_proof)
            .map_err(|_| reserve_authority_unavailable())
    }
}

// ---------------------------------------------------------------------------
// Trusted-source bridges.
// ---------------------------------------------------------------------------

/// `ServicePayloadEpochSource` — the protected payload epoch stays
/// protected-state authority supplied through
/// [`TrustedPayloadEpochSource`]; it is never inferred from
/// PostgreSQL.
struct ServicePayloadEpochSource {
    service: Arc<Service>,
}

impl TrustedPayloadEpochSource for ServicePayloadEpochSource {
    fn active_payload_epoch_id(&self) -> Result<Uuid, Failure> {
        self.service
            .payload_epochs
            .as_ref()
            .ok_or_else(engine_unavailable)?
            .read_active()
            .map_err(|_| engine_unavailable())
    }
}

/// `PostgresTargetAdmissionSource` — the field-for-field copy of the
/// PostgreSQL reader's admission shape into the adapter's locator-free
/// vocabulary; the reader already collapses its own errors.
struct PostgresTargetAdmissionSource {
    reader: RestoreTargetAdmissionReader,
}

impl RestoreTargetAdmissionSource for PostgresTargetAdmissionSource {
    fn read_restore_target_admission(
        &self,
        backup_id: Uuid,
    ) -> Result<central_adapter_linux::backup::RestoreTargetAdmission, Failure> {
        let admission = self.reader.read_restore_target_admission(backup_id)?;
        Ok(central_adapter_linux::backup::RestoreTargetAdmission {
            target: admission.target,
            target_fingerprint: admission.target_fingerprint,
            security_epoch: admission.security_epoch,
            restore_epoch: admission.restore_epoch,
            config_fingerprint: admission.config_fingerprint,
            payload_epoch_id: admission.payload_epoch_id,
            database_schema_version: admission.database_schema_version,
            restore_tool_version: admission.restore_tool_version,
        })
    }
}

/// `RestoreObjectReader` — the one-line
/// [`ReadyArtifactObjectReader`] bridge upstream leaves to the
/// composition root (the `S3BackupObjectSource` sync/async seam stays
/// the only place the conversion happens).
struct RestoreObjectReader {
    objects: Arc<S3BackupObjectSource>,
}

impl central_adapter_postgres::backup::ReadyArtifactObjectReader for RestoreObjectReader {
    fn read(&self, reference: &ObjectRef) -> Result<(Box<dyn ReadClose>, ObjectInfo), Failure> {
        self.objects.read_ready_object(reference)
    }
}

/// `operationScopedInventoryVerifier` defers building the MinIO reader
/// until an operation exists, because the restore object credential is
/// bound to that exact operation. Building it eagerly would need a
/// credential no protected state could yet authorize.
///
/// Rust ownership note: upstream shares the composition's `*pgx.Conn`
/// between the admission reader and this verifier; an owned
/// `PgConnection` cannot be shared across two consumers, so this
/// verifier draws a fresh admission-runtime credential session inside
/// `verify_inventory` — the same credential kind upstream's shared
/// conn was opened with, over the identical read-only role.
struct OperationScopedInventoryVerifier {
    repository: Arc<dyn RecoveryInventorySource>,
    credentials: Arc<RestoreCredentialClient>,
    object_runtime: tokio::runtime::Runtime,
    profile: RecoveryProfile,
}

impl RestoreInventoryVerifier for OperationScopedInventoryVerifier {
    fn verify_inventory(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Vec<QuarantineFinding>, Failure> {
        if operation.validate().is_err() {
            return Err(engine_unavailable());
        }
        let credential = self
            .credentials
            .open_minio_restore_credential(operation.operation_id)
            .map_err(|_| engine_unavailable())?;
        let store = new_backup_reader_from_sealed_credential(File::from(credential))
            .map_err(|_| engine_unavailable())?;
        let source =
            S3BackupObjectSource::new(Arc::new(store), self.object_runtime.handle().clone())
                .map_err(|_| engine_unavailable())?;
        let objects: Arc<dyn central_adapter_postgres::backup::ReadyArtifactObjectReader> =
            Arc::new(RestoreObjectReader {
                objects: Arc::new(source),
            });
        let passfile = self
            .credentials
            .open_admission_runtime_credential()
            .map_err(|_| engine_unavailable())?;
        let value = Zeroizing::new(
            read_sealed_passfile_value(&passfile).map_err(|_| engine_unavailable())?,
        );
        let verifier = RestoredInventoryVerifier::new_connecting(
            move || async move { open_runtime_connection(&value).await },
            self.repository.clone(),
            objects,
            self.profile,
        )
        .map_err(|_| engine_unavailable())?;
        verifier.verify_inventory(operation)
    }
}

// ---------------------------------------------------------------------------
// Deferred import collaborator.
// ---------------------------------------------------------------------------

/// `UnavailableRestoreImporter` — ADR 0034's data-plane import runner
/// (`PlanImportSource`, `PGRestoreForImport`, `ImportDataPlaneRunner`)
/// is not yet ported, so this is the fail-closed placeholder the
/// production composition installs — the same position upstream's
/// `unavailableAdmissionInspector` held before the reserve gate
/// shipped. It draws nothing and refuses `EngineUnavailable` — and the
/// helper's `import_minio` seam refuses an import launch before this
/// is ever reached anyway.
pub struct UnavailableRestoreImporter;

impl RestoreImporter for UnavailableRestoreImporter {
    fn import(&self, _operation_id: Uuid) -> Result<RestoreImportResult, Failure> {
        Err(engine_unavailable())
    }
}

// ---------------------------------------------------------------------------
// `productionRestoreRoots` + `newRestoreEngineFromRoots` +
// `newProductionRestoreEngine`.
// ---------------------------------------------------------------------------

/// `ProductionRestoreRoots` — the collaborators one restore run needs.
/// They are explicit fields rather than values the engine resolves
/// for itself, so a partially available composition fails before
/// anything destructive begins. `Option` is the Rust spelling of
/// upstream's nil checks.
pub struct ProductionRestoreRoots {
    /// `Journal` — the protected broker state. [`Service`] satisfies
    /// both this and [`ProtectedRestoreState`] from one in-process
    /// root handle.
    pub journal: Option<Arc<dyn RestoreJournalStore>>,
    /// `State` — the root-only protected readers.
    pub state: Option<Arc<dyn ProtectedRestoreState>>,
    /// `Repository` — `RecoveryRepositoryVerifier`.
    pub repository: Option<Arc<dyn RecoveryRepositoryVerifier>>,
    /// `Seals` — `BackupSealVerifier`.
    pub seals: Option<Arc<dyn BackupSealVerifier>>,
    /// `Inspector` — `RestoreAdmissionInspector`.
    pub inspector: Option<Arc<dyn RestoreAdmissionInspector>>,
    /// `Issuer` — `RestoreTicketIssuer`.
    pub issuer: Option<Arc<dyn RestoreTicketIssuer>>,
    /// `Excluder` — `RestoreTargetExcluder`.
    pub excluder: Option<Box<dyn RestoreTargetExcluder>>,
    /// `Database` — the pinned `pg_restore` adapter, which takes its
    /// credential from broker frame `0xc2` and never from this
    /// process's config.
    pub database: Option<Box<dyn RestoreDatabaseRunner>>,
    /// `Audit` — `RestoreAuditProjection`.
    pub audit: Option<Box<dyn RestoreAuditProjection>>,
    /// `Inventory` — `RestoreInventoryVerifier`.
    pub inventory: Option<Box<dyn RestoreInventoryVerifier>>,
    /// `Resetter` — `RestoreAuthorityResetter`.
    pub resetter: Option<Box<dyn RestoreAuthorityResetter>>,
    /// `ReserveBinder` and `reserve_set_id` close the last gap in the
    /// reserve gate: `IssueRestoreTicket` mints the operation id in
    /// *this* process, so the daemon has no way to discover which
    /// reserve set the resulting operation continues. Frame `0xc4`
    /// kind 3 is that path, and a verify that cannot complete it must
    /// fail rather than hand the operator a ticket the apply-time gate
    /// will refuse.
    pub reserve_binder: Option<Arc<dyn RestoreCapacityReserveBinder>>,
    /// The reserve set this launch's verify allocated (nil for
    /// apply/resume — inert there because they never call verify).
    pub reserve_set_id: Uuid,
    /// `Importer` runs ADR 0034's data-plane import. It draws nothing
    /// at composition: every credential it needs is operation-scoped
    /// and is drawn inside `import`, so restore modes compose it
    /// without presenting anything they will never use.
    pub importer: Option<Arc<dyn RestoreImporter>>,
}

/// `newRestoreEngineFromRoots` — the whole production assembly,
/// separate from [`new_production_restore_engine`] so the composition
/// can be exercised without a live protected root, PostgreSQL target,
/// or MinIO endpoint.
///
/// # Errors
/// `EngineUnavailable` on any absent collaborator or invalid profile.
pub fn new_restore_engine_from_roots(
    roots: ProductionRestoreRoots,
    profile: RecoveryProfile,
) -> Result<ComposedRestoreEngine, Failure> {
    if profile.validate().is_err() {
        return Err(engine_unavailable());
    }
    let (
        Some(journal),
        Some(state),
        Some(repository),
        Some(seals),
        Some(inspector),
        Some(issuer),
        Some(excluder),
        Some(database),
        Some(audit),
        Some(inventory),
        Some(resetter),
        Some(importer),
    ) = (
        roots.journal,
        roots.state,
        roots.repository,
        roots.seals,
        roots.inspector,
        roots.issuer,
        roots.excluder,
        roots.database,
        roots.audit,
        roots.inventory,
        roots.resetter,
        roots.importer,
    )
    else {
        return Err(engine_unavailable());
    };
    let engine = AdapterComposedRestoreEngine::new(excluder, database, audit, inventory, resetter)
        .map_err(|_| engine_unavailable())?;
    let coordinator: Arc<dyn RestoreCoordinatePort> = Arc::new(ComposedRestoreCoordinator {
        journal,
        engine: Arc::new(engine),
    });
    let verifier: Arc<dyn RestoreVerifyPort> = Arc::new(ReserveBindingVerifier {
        repository,
        seals,
        inspector,
        issuer,
        profile,
        binder: roots.reserve_binder,
        set_id: roots.reserve_set_id,
    });
    new_restore_engine(
        Some(state),
        Some(verifier),
        Some(coordinator),
        Some(importer),
    )
}

/// `newProductionRestoreEngine` composes the real engine from the
/// inherited descriptors plus broker-delivered credentials. It
/// resolves no path, reads no environment variable, and accepts no
/// argv selector.
///
/// `reserve_set_id` is the capacity reserve set the root helper
/// allocated for this launch, delivered over the launch gate. It is
/// `Uuid::nil()` for apply and resume, which never consult the
/// admission inspector.
///
/// # Errors
/// `EngineUnavailable` on any adoption, broker, credential, or
/// composition failure — a composition failure must never look like a
/// completed recovery.
pub fn new_production_restore_engine(
    reserve_set_id: Uuid,
    inherited: &InheritedRestoreDescriptors,
) -> Result<ComposedRestoreEngine, Failure> {
    let protected_root = adopt_inherited_directory(inherited.protected_root)?;
    let service = Arc::new(
        Service::new_for_restore_engine(
            protected_root,
            CENTRAL_RUNTIME_UID,
            PRODUCTION_HELPER_EXECUTABLE_PATH,
        )
        .map_err(|_| engine_unavailable())?,
    );
    let binding =
        inspect_repository_descriptor(inherited.repository).map_err(|_| engine_unavailable())?;
    // Restore only ever reads the repository. A writable handle would
    // let a recovery run mutate the very evidence it is being
    // verified against. Upstream shares one `*Repository`; Rust opens
    // one read-only handle per consumer over the same descriptor —
    // identical authority, identical shared-lock class.
    let repository_for_verifier =
        Repository::read_only_from_descriptor(inherited.repository, &binding)
            .map_err(|_| engine_unavailable())?;
    let repository_for_dumps =
        Repository::read_only_from_descriptor(inherited.repository, &binding)
            .map_err(|_| engine_unavailable())?;
    let profile = default_recovery_profile();
    let credentials = Arc::new(RestoreCredentialClient::new(
        PRODUCTION_BROKER_SOCKET.to_owned(),
    ));

    // Verification runs before any operation exists, so its target
    // read uses the admission credential; every object read later is
    // operation-bound.
    let admission_passfile = credentials
        .open_admission_runtime_credential()
        .map_err(|_| engine_unavailable())?;
    let admission_value = Zeroizing::new(
        read_sealed_passfile_value(&admission_passfile).map_err(|_| engine_unavailable())?,
    );
    let payload_epochs: Arc<dyn TrustedPayloadEpochSource> = Arc::new(ServicePayloadEpochSource {
        service: service.clone(),
    });
    let target_admission = RestoreTargetAdmissionReader::new_connecting(
        move || async move { open_runtime_connection(&admission_value).await },
        payload_epochs,
    )
    .map_err(|_| engine_unavailable())?;

    // SC-DEF-62: the excluder and the audit projection share one
    // lazily opened `central_migration` session, opened on the first
    // call either of them receives with a real operation.
    let migration_session = Arc::new(LazyMigrationSession::new(
        credentials.clone() as Arc<dyn AuditMigrationCredentialProvider>
    ));
    let audit = LazyMigrationAuditProjection {
        session: migration_session.clone(),
    };
    let excluder = LazyMigrationExcluder {
        session: migration_session.clone(),
    };
    let repository_verifier = Arc::new(RepositoryVerifier::new(repository_for_verifier));
    let receipt_client = Arc::new(ReceiptClient::new(PRODUCTION_BROKER_SOCKET));
    let role_roots = adopt_restore_capacity_role_roots(&inherited.role_roots)?;
    let inspector: Arc<dyn RestoreAdmissionInspector> =
        Arc::new(ProductionRestoreAdmissionInspector {
            repository_fd: inherited.repository,
            binding,
            seals: service.clone() as Arc<dyn BackupSealVerifier>,
            target: Arc::new(PostgresTargetAdmissionSource {
                reader: target_admission,
            }),
            profile,
            receipts: receipt_client.clone() as Arc<dyn RestoreCapacityReceiptPort>,
            reserve_set_id,
            role_roots,
        });
    let object_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("central-restore-objects")
        .build()
        .map_err(|_| engine_unavailable())?;
    let inventory = OperationScopedInventoryVerifier {
        repository: repository_verifier.clone() as Arc<dyn RecoveryInventorySource>,
        credentials: credentials.clone(),
        object_runtime,
        profile,
    };
    let pg_config = PgRestoreConfig {
        binary_path: PathBuf::from(PINNED_PG_RESTORE_BINARY),
        version: PINNED_PG_RESTORE_VERSION.to_owned(),
        max_elapsed: DEFAULT_RECOVERY_DEADLINE.unsigned_abs(),
    };
    let pinned_database = PgRestore::new(
        pg_config,
        Box::new(RepositoryDumpSource {
            repository: repository_for_dumps,
            profile,
        }),
        Box::new(credentials.clone()) as Box<dyn SealedRestorePassfileProvider>,
    )
    .map_err(|_| engine_unavailable())?;
    // SC-DEF-60: drop the one foreign key SC-DEF-52's exclusion of
    // `central.recovery_bootstrap_registrations` leaves behind,
    // immediately before pg_restore's own --clean drop of
    // `central.recovery_operations` runs into it.
    let database = FkDroppingRestoreDatabase {
        inner: Arc::new(pinned_database),
        credentials: credentials.clone() as Arc<dyn SealedRestorePassfileProvider>,
    };
    let resetter = ComposedAuthorityResetter {
        broker: service.clone() as Arc<dyn BrokerAuthorityReset>,
        database: Arc::new(LazyMigrationAuthorityResetter {
            session: migration_session,
        }),
    };
    new_restore_engine_from_roots(
        ProductionRestoreRoots {
            journal: Some(service.clone() as Arc<dyn RestoreJournalStore>),
            state: Some(service.clone() as Arc<dyn ProtectedRestoreState>),
            repository: Some(repository_verifier as Arc<dyn RecoveryRepositoryVerifier>),
            seals: Some(service.clone() as Arc<dyn BackupSealVerifier>),
            inspector: Some(inspector),
            issuer: Some(service as Arc<dyn RestoreTicketIssuer>),
            excluder: Some(Box::new(excluder)),
            database: Some(Box::new(database)),
            audit: Some(Box::new(audit)),
            inventory: Some(Box::new(inventory)),
            resetter: Some(Box::new(resetter)),
            reserve_binder: Some(receipt_client as Arc<dyn RestoreCapacityReserveBinder>),
            reserve_set_id,
            importer: Some(Arc::new(UnavailableRestoreImporter)),
        },
        profile,
    )
}
