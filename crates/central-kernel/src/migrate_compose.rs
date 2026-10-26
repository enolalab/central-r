//! `central-kernel::migrate_compose` — the composition root for the
//! dedicated migration operator, porting `cmd/central-migrate`'s
//! `newMigrationCoordinator`/`executeMigrationCommand` and the
//! operator-facing `targetIdentity`.
//!
//! Upstream composes `central-migrate` over the broker
//! migration-authority client: proofs, the protected-state inspector,
//! and the provisioning journal all live on that one authorized
//! connection, and the migration session itself is the single
//! non-rebinding `central_migration` PostgreSQL connection. The Rust
//! port keeps the same shape:
//!
//! * [`MigrationSession`] owns the one `PgConnection` and satisfies
//!   the coordinator's erased `MigrationRunner`/`MigrationInspector`/
//!   `ResetRunner` contract — it constructs the R1 postgres adapters
//!   per call (upstream wires the same conn into all three).
//! * [`MigrationOperator`] composes the coordinator per verb —
//!   `executeMigrationCommand` verbatim, including the command-closed
//!   dispatch and the broker-issued reset confirmation.
//! * The authority is injected as `&dyn …` refs: `with_authority`
//!   binds the real client (R6 task 2 lands it), `without_authority`
//!   binds [`NullMigrationAuthority`] — the fail-closed read surface.
//!
//! The production connect path lands in [`run_operator`]:
//! `MaterializePostgresMigration` fills the credential descriptor
//! (B05, `0xb5`), the validated passfile opens the fixed-role
//! `central_migration` connection, and
//! [`BrokerMigrationAuthority`] — the `MigrationProvisioningStore` +
//! `MigrationOperatorInspector` + proof client composite — supplies
//! `with_authority`'s three erased refs. `without_authority` keeps
//! the [`NullMigrationAuthority`] fail-closed read surface for the
//! DSN-gated test seam.

use std::sync::Arc;

use central_adapter_linux::broker::migration_client::{
    BrokerMigrationAuthority, MigrationAuthorityClient, MigrationClient, broker_socket_path,
};
use central_adapter_linux::sys::memfd::read_migration_passfile;
use central_adapter_postgres::migrate::{
    BaselineInstaller, DynProofService, Inspector, ResetRunner as PgResetRunner, Runner,
    runtime_connection,
};
use central_backup::app::ProvisioningRecordStore;
use central_backup::app::{
    MigrationAuthority, MigrationCoordinator, MigrationOperatorResult, NullMigrationAuthority,
};
use central_backup::domain::{BaselineManifest, TargetIdentity};
use central_backup::port::{
    CommitUpRequest, DynBrokerProofService, IssueResetConfirmationRequest, MigrationInspector,
    MigrationRunner, PostgresMigrationFacts, PrepareUpRequest, PrepareUpResult,
    ProtectedOperatorStateInspector, ResetRequest, ResetRunner, ResumeRequest, ResumeResult,
    UpRequest, UpResult,
};
use central_foundation::failure::Failure;
use sqlx::{Connection as _, PgConnection};

/// Result alias for this module.
pub type Result<T> = core::result::Result<T, Failure>;

/// The upstream `newMigrationCoordinator` baseline-digest label —
/// `NewMigrationCoordinator(…, "sha256:v0-baseline", …)` binds the
/// journal's baseline digest to this fixed identity, not to the
/// manifest's own digest.
pub const EMBEDDED_BASELINE_DIGEST: &str = "sha256:v0-baseline";

fn wrap(context: &'static str, err: Failure) -> Failure {
    Failure::new(
        err.kind(),
        err.code(),
        format!("{context}: {}", err.message()),
    )
}

/// The closed migration-command set — upstream `isMigrationCommand`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationCommand {
    /// `up` — provision the version-zero baseline.
    Up,
    /// `resume` — continue the recorded in-flight operation.
    Resume,
    /// `status` — read the durable status projection.
    Status,
    /// `verify` — the read-only checksum/shape audit.
    Verify,
    /// `reset` — the version-zero-only destructive reset.
    Reset,
}

impl MigrationCommand {
    /// `isMigrationCommand` — exact closed-set parse; anything else is
    /// not a migration command.
    #[must_use]
    pub fn parse(command: &str) -> Option<Self> {
        match command {
            "up" => Some(Self::Up),
            "resume" => Some(Self::Resume),
            "status" => Some(Self::Status),
            "verify" => Some(Self::Verify),
            "reset" => Some(Self::Reset),
            _ => None,
        }
    }

    /// The wire verb string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Resume => "resume",
            Self::Status => "status",
            Self::Verify => "verify",
            Self::Reset => "reset",
        }
    }
}

/// `MigrationSession` — the one non-rebinding `central_migration`
/// PostgreSQL session the runner, inspector, and reset runner share
/// (upstream wires the same `*pgx.Conn` into all three).
///
/// The session carries the proof *consume* seam
/// ([`DynProofService`]) the runners need; the coordinator's proof
/// *issue* seam and the journal/inspector reads are supplied to
/// [`MigrationOperator`] as separate erased refs — two erased views of
/// the one authority `Arc`, exactly as upstream splits
/// `port.MigrationRunner`'s embedded `BrokerProofService` use from the
/// coordinator's own proof calls.
pub struct MigrationSession {
    conn: PgConnection,
    proofs: Option<Arc<dyn DynProofService>>,
}

impl MigrationSession {
    /// `NewRunner`/`NewResetRunner`/`NewInspectorForConn` over one conn.
    #[must_use]
    pub fn new(conn: PgConnection, proofs: Option<Arc<dyn DynProofService>>) -> Self {
        Self { conn, proofs }
    }

    /// Open the operator session from a DSN. Production never calls
    /// this with user-controlled input — the production conn comes
    /// from the broker-sealed passfile descriptor (task 2); this is
    /// the composition seam the DSN-gated integration tests and the
    /// local dev harness use.
    ///
    /// # Errors
    /// The session cannot connect.
    pub async fn connect(dsn: &str, proofs: Option<Arc<dyn DynProofService>>) -> Result<Self> {
        let conn = PgConnection::connect(dsn).await.map_err(|e| {
            Failure::unavailable("migration_session_connect", format!("connect: {e}"))
        })?;
        Ok(Self { conn, proofs })
    }

    /// The underlying connection — `target_identity`'s read-only
    /// identity queries.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.conn
    }

    /// `targetIdentity` — `current_database()` + the `pg_database` OID;
    /// `SystemID`/`ConfigHash` carry upstream's fixed local bindings
    /// (`"local"`/`"auto"`, epoch 0). Query failures degrade to the
    /// upstream fallbacks (`"central"`/`"0"`).
    pub async fn target_identity(&mut self) -> TargetIdentity {
        let database: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&mut self.conn)
            .await
            .unwrap_or_else(|_| "central".into());
        let database_oid: String = sqlx::query_scalar::<_, String>(
            "SELECT oid::text FROM pg_database WHERE datname = current_database()",
        )
        .fetch_one(&mut self.conn)
        .await
        .unwrap_or_else(|_| "0".into());
        TargetIdentity {
            system_id: "local".into(),
            database_oid,
            database,
            config_hash: "auto".into(),
            epoch: 0,
        }
    }
}

impl MigrationRunner for MigrationSession {
    fn prepare_up<'a>(
        &'a mut self,
        req: &'a PrepareUpRequest,
    ) -> central_backup::port::BoxFuture<'a, Result<PrepareUpResult>> {
        Box::pin(async move {
            Runner::new_dyn(&mut self.conn, self.proofs.clone())
                .prepare_up(req)
                .await
        })
    }
    fn commit_up<'a>(
        &'a mut self,
        req: &'a CommitUpRequest,
    ) -> central_backup::port::BoxFuture<'a, Result<UpResult>> {
        Box::pin(async move {
            Runner::new_dyn(&mut self.conn, self.proofs.clone())
                .commit_up(req)
                .await
        })
    }
    fn up<'a>(
        &'a mut self,
        req: &'a UpRequest,
    ) -> central_backup::port::BoxFuture<'a, Result<UpResult>> {
        Box::pin(async move {
            Runner::new_dyn(&mut self.conn, self.proofs.clone())
                .up(req)
                .await
        })
    }
    fn resume<'a>(
        &'a mut self,
        req: &'a ResumeRequest,
    ) -> central_backup::port::BoxFuture<'a, Result<ResumeResult>> {
        Box::pin(async move {
            Runner::new_dyn(&mut self.conn, self.proofs.clone())
                .resume(req)
                .await
        })
    }
}

impl MigrationInspector for MigrationSession {
    fn inspect<'a>(
        &'a mut self,
    ) -> central_backup::port::BoxFuture<'a, Result<PostgresMigrationFacts>> {
        Box::pin(async move { Inspector::for_connection(&mut self.conn).inspect().await })
    }
}

impl ResetRunner for MigrationSession {
    fn delete_schema<'a>(
        &'a mut self,
        req: &'a ResetRequest,
    ) -> central_backup::port::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            PgResetRunner::new_dyn(&mut self.conn, self.proofs.clone())
                .delete_schema(req)
                .await
        })
    }
}

/// `executeMigrationCommand` — the migration operator: the session,
/// the (possibly fail-closed) authority refs, the bound target, and
/// the manifest the coordinator audits against.
pub struct MigrationOperator<'a> {
    session: MigrationSession,
    proofs: Option<&'a dyn DynBrokerProofService>,
    operator_inspector: &'a dyn ProtectedOperatorStateInspector,
    record_store: &'a dyn ProvisioningRecordStore,
    target: TargetIdentity,
    baseline_digest: String,
    expected_manifest: BaselineManifest,
}

impl<'a> MigrationOperator<'a> {
    /// `newMigrationCoordinator` over the real broker authority (task
    /// 2 lands the client; the same `&T` supplies all three erased
    /// refs the coordinator needs).
    #[must_use]
    pub fn with_authority<T: MigrationAuthority>(
        session: MigrationSession,
        authority: &'a T,
        target: TargetIdentity,
    ) -> Self {
        Self {
            session,
            proofs: Some(authority),
            operator_inspector: authority,
            record_store: authority,
            target,
            baseline_digest: EMBEDDED_BASELINE_DIGEST.into(),
            expected_manifest: BaselineInstaller::new().baseline_manifest(),
        }
    }

    /// The Task-1 fail-closed composition: no broker authority — the
    /// read-only verbs answer from the session and the honest absent
    /// record; mutating legs fail closed at the first journal or proof
    /// call. `proofs` is `None` so `reset` reports upstream's own
    /// "reset confirmation service is unavailable".
    #[must_use]
    pub fn without_authority(session: MigrationSession, target: TargetIdentity) -> Self {
        static NULL: NullMigrationAuthority = NullMigrationAuthority;
        Self {
            session,
            proofs: None,
            operator_inspector: &NULL,
            record_store: &NULL,
            target,
            baseline_digest: EMBEDDED_BASELINE_DIGEST.into(),
            expected_manifest: BaselineInstaller::new().baseline_manifest(),
        }
    }

    /// `executeMigrationCommand` — command-closed dispatch. The
    /// operation ID is bound into every protected call so execution
    /// evidence stays tied to the helper's original request rather
    /// than a process-local replacement UUID.
    ///
    /// # Errors
    /// A nil operation ID, any coordinator verb failure, or (for
    /// `reset`) the confirmation issue/reset failure.
    pub async fn execute(
        &mut self,
        command: MigrationCommand,
        operation_id: uuid::Uuid,
    ) -> Result<MigrationOperatorResult> {
        if operation_id.is_nil() {
            return Err(Failure::invalid(
                "invalid_migration_execution",
                "invalid migration execution",
            ));
        }

        let mut coordinator = MigrationCoordinator::new(
            &mut self.session,
            self.operator_inspector,
            self.record_store,
            self.baseline_digest.clone(),
            self.proofs,
            self.expected_manifest.clone(),
        );
        coordinator.bind_operation_id(operation_id);

        let command_name = command.as_str();
        match command {
            MigrationCommand::Up => {
                let op = coordinator.up(&self.target).await?;
                Ok(MigrationOperatorResult {
                    command: command_name.into(),
                    state: op.record_state.as_str().into(),
                    phase: op.provisioning_phase.as_str().into(),
                    safe_next_action: "RUN_CENTRAL_MIGRATE_STATUS".into(),
                    ..MigrationOperatorResult::default()
                })
            }
            MigrationCommand::Resume => {
                let op = coordinator.resume(operation_id).await?;
                Ok(MigrationOperatorResult {
                    command: command_name.into(),
                    state: op.record_state.as_str().into(),
                    phase: op.provisioning_phase.as_str().into(),
                    safe_next_action: "RUN_CENTRAL_MIGRATE_STATUS".into(),
                    ..MigrationOperatorResult::default()
                })
            }
            MigrationCommand::Status => {
                let status = coordinator.status().await?;
                Ok(MigrationOperatorResult {
                    command: command_name.into(),
                    initialized: status.initialized,
                    ready: status.ready,
                    safe_next_action: status.safe_next_action,
                    ..MigrationOperatorResult::default()
                })
            }
            MigrationCommand::Verify => {
                let verify = coordinator.verify().await?;
                Ok(MigrationOperatorResult {
                    command: command_name.into(),
                    matches: verify.matches,
                    drifts: verify.drifts,
                    ..MigrationOperatorResult::default()
                })
            }
            MigrationCommand::Reset => {
                // Upstream's `proofs == nil` gate — the reset
                // confirmation is issued by the broker authority, not
                // the operator.
                let Some(proofs) = self.proofs else {
                    return Err(Failure::unavailable(
                        "reset_confirmation_unavailable",
                        "reset confirmation service is unavailable",
                    ));
                };
                let confirmation = proofs
                    .issue_reset_confirmation(&IssueResetConfirmationRequest {
                        operation_id,
                        target_fingerprint: self.target.fingerprint(),
                    })
                    .await
                    .map_err(|e| wrap("issue reset confirmation", e))?;
                coordinator.reset(operation_id, confirmation).await?;
                Ok(MigrationOperatorResult {
                    command: command_name.into(),
                    safe_next_action: "RUN_CENTRAL_MIGRATE_STATUS".into(),
                    ..MigrationOperatorResult::default()
                })
            }
        }
    }
}

/// `run` — the production operator seam `central-migrate` calls after
/// its gates, porting `cmd/central-migrate`'s post-`parseInvocation`
/// flow verbatim:
///
/// 1. `broker.NewMigrationAuthorityClient` bound to the original
///    operation ID and the consumed launch evidence.
/// 2. `MaterializePostgresMigration` — the B05 custody exchange that
///    fills the (still empty) credential descriptor in place; no DSN
///    or credential path enters the request.
/// 3. `runMigrationWithAuthority` — `report_started`, then the
///    sealed-passfile `central_migration` connect, the bound-target
///    authority composition, `execute`, and the deferred durable
///    terminal report. A missing authority, materialization, or
///    descriptor stays a typed refusal — never a local fallback.
///
/// `credential_fd` is the borrowed, already-`CLOEXEC` FD4 the
/// launcher's handoff produced; ownership (and its deferred close)
/// stays with the caller, exactly like upstream's `defer
/// unix.Close(credentialDescriptorFD)`.
///
/// # Errors
/// Nil identities, client construction, B05 materialization,
/// passfile shape, connect, coordinator execution, or the terminal
/// report itself — all typed `Failure`s.
pub async fn run_operator(
    command: MigrationCommand,
    operation_id: uuid::Uuid,
    launch_evidence: uuid::Uuid,
    credential_fd: std::os::fd::BorrowedFd<'_>,
) -> Result<MigrationOperatorResult> {
    if operation_id.is_nil() || launch_evidence.is_nil() {
        return Err(Failure::invalid(
            "invalid_migration_execution",
            "invalid migration execution",
        ));
    }
    let socket = broker_socket_path().to_string_lossy().into_owned();
    let reporter =
        MigrationAuthorityClient::new(&socket, operation_id, launch_evidence.to_string())
            .map_err(|e| wrap("compose broker authority client", e))?;
    let client = MigrationClient::new(&socket);
    client
        .materialize_operator_credential(operation_id, &launch_evidence.to_string(), credential_fd)
        .map_err(|e| wrap("materialize credential", e))?;

    run_with_authority(&reporter, async {
        let value = read_migration_passfile(credential_fd).map_err(|e| wrap("connect", e))?;
        let conn = runtime_connection::open_migration_connection(&value)
            .await
            .map_err(|e| wrap("connect", e))?;
        drop(value);
        let mut session = MigrationSession::new(conn, None);
        let target = session.target_identity().await;
        let authority = BrokerMigrationAuthority::new(reporter.clone(), target.clone());
        session.proofs = Some(Arc::new(authority.clone()));
        let mut operator = MigrationOperator::with_authority(session, &authority, target);
        let result = operator
            .execute(command, operation_id)
            .await
            .map_err(|e| wrap("execute", e))?;
        Ok(result)
    })
    .await
}

/// `runMigrationWithAuthority` — `ReportStarted` gates execution; the
/// deferred `ReportTerminal` runs on every outcome path and reports
/// `failed` with the fixed upstream reason when `execute` errs.
async fn run_with_authority(
    reporter: &MigrationAuthorityClient,
    execute: impl std::future::Future<Output = Result<MigrationOperatorResult>>,
) -> Result<MigrationOperatorResult> {
    if let Err(start_err) = reporter.report_started() {
        // `errors.Join(report-start, terminal-report)` — the start
        // failure stays primary; a second failure appends.
        let mut failure = Failure::unavailable(
            "report_migration_start",
            format!("report migration start: {}", start_err.message()),
        );
        if let Err(report_err) = report_terminal(reporter, false, None) {
            failure = Failure::unavailable(
                "report_migration_start",
                format!("{}\n{}", failure.message(), report_err.message()),
            );
        }
        return Err(failure);
    }
    let result = execute.await;
    let succeeded = result.is_ok();
    if let Err(report_err) = report_terminal(reporter, succeeded, result.as_ref().ok()) {
        return Err(match result {
            Err(exec_err) => Failure::unavailable(
                "migration_execute",
                format!("{}\n{}", exec_err.message(), report_err.message()),
            ),
            Ok(_) => report_err,
        });
    }
    result
}

/// `reportMigrationTerminal` — the durable terminal mark. Failure is
/// reported with upstream's fixed operator-safe reason; durable broker
/// state is recovery evidence, not a diagnostic sink.
fn report_terminal(
    reporter: &MigrationAuthorityClient,
    succeeded: bool,
    result: Option<&MigrationOperatorResult>,
) -> Result<()> {
    let reason = if succeeded {
        ""
    } else {
        "migration operator failed"
    };
    reporter
        .report_terminal(succeeded, reason, result)
        .map_err(|e| {
            Failure::unavailable(
                "report_migration_terminal",
                format!("report migration terminal outcome: {}", e.message()),
            )
        })
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use central_foundation::failure::FailureKind;

    use super::*;

    #[test]
    fn command_parse_is_the_closed_five_verb_set() {
        assert_eq!(MigrationCommand::parse("up"), Some(MigrationCommand::Up));
        assert_eq!(
            MigrationCommand::parse("resume"),
            Some(MigrationCommand::Resume)
        );
        assert_eq!(
            MigrationCommand::parse("status"),
            Some(MigrationCommand::Status)
        );
        assert_eq!(
            MigrationCommand::parse("verify"),
            Some(MigrationCommand::Verify)
        );
        assert_eq!(
            MigrationCommand::parse("reset"),
            Some(MigrationCommand::Reset)
        );
        for bad in ["UP", "Up", "migrate", "", "down", "resume ", " status"] {
            assert_eq!(MigrationCommand::parse(bad), None, "{bad:?} must not parse");
        }
    }

    #[test]
    fn command_as_str_round_trips() {
        for verb in ["up", "resume", "status", "verify", "reset"] {
            assert_eq!(MigrationCommand::parse(verb).unwrap().as_str(), verb);
        }
    }

    /// The nil-identity gate precedes every broker call — a nil
    /// operation or evidence ID refuses `invalid` before any socket
    /// is touched.
    #[tokio::test]
    async fn run_operator_refuses_nil_identities() {
        let fd = std::fs::File::open("/dev/null").expect("/dev/null");
        let err = run_operator(
            MigrationCommand::Status,
            uuid::Uuid::nil(),
            uuid::Uuid::now_v7(),
            fd.as_fd(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
        assert_eq!(err.code(), "invalid_migration_execution");
        let err = run_operator(
            MigrationCommand::Status,
            uuid::Uuid::now_v7(),
            uuid::Uuid::nil(),
            fd.as_fd(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), "invalid_migration_execution");
    }
}
