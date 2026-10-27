//! `helper/migration_launch.go` + `cmd/central/migration_outcome_reader.go`
//! — the helper's `migrate-launch` and `migrate-read-outcome` verbs.
//!
//! The helper authenticates the operator (PAM, plus the reset TTY
//! ceremony for `reset`), asks the fixed `central-migration-launcherd`
//! to start the fixed `central-migrate` binary as UID/GID 986/986,
//! submits the observed child identity to the broker for one-use
//! launch evidence, and commits that evidence to the launcher. Every
//! refusal between launch and commit synchronously aborts and reaps
//! the child — an uncommitted launch can never outlive its request.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::PeerIdentity;
use super::grant::CeremonyScope;
use super::protocol::{Request, Response};

/// `centralMigrateExecutable` — the fixed operator binary.
pub const CENTRAL_MIGRATE_EXECUTABLE: &str = "/usr/lib/central/central-migrate";
/// `migrationLaunchDeadline` — 30 seconds bounds launch, evidence
/// issuance, and commit as one budget, exactly like upstream.
pub const MIGRATION_LAUNCH_DEADLINE: Duration = Duration::from_secs(30);
/// `authority.CentralMigrateUID/GID`.
pub const CENTRAL_MIGRATE_UID: u32 = 986;
/// `authority.CentralMigrateUID/GID`.
pub const CENTRAL_MIGRATE_GID: u32 = 986;

/// `helper.MigrationLaunchRequest` — the closed, credential-free
/// launch request the server decodes; `operation_id` is bound by the
/// enclosing helper request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationLaunchRequest {
    /// The enclosing request's operation identity (`json:"-"`).
    #[serde(skip)]
    pub operation_id: String,
    /// The closed command (`up|resume|status|verify|reset`).
    pub command: String,
    /// Reserved args — must be empty.
    #[serde(default)]
    pub args: Vec<String>,
}

/// `helper.MigrationOutcomeReadRequest` — the one capability the
/// operator's polling loop has.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationOutcomeReadRequest {
    /// The enclosing request's operation identity (`json:"-"`).
    #[serde(skip)]
    pub operation_id: String,
    /// The broker-issued launch evidence identity.
    pub launch_evidence_id: String,
}

/// `ParseMigrationLaunchRequest` — closed decoding: unknown fields
/// refuse so a DSN, configuration path, or future flag cannot
/// silently become authority.
pub fn parse_migration_launch_request(req: &Request) -> Result<MigrationLaunchRequest, String> {
    let payload = req
        .payload
        .as_ref()
        .ok_or_else(|| "missing migration launch payload".to_owned())?;
    let mut launch: MigrationLaunchRequest = serde_json::from_str(payload.get())
        .map_err(|e| format!("invalid migration launch request: {e}"))?;
    launch.operation_id = req.operation_id.clone();
    Ok(launch)
}

/// `ParseMigrationOutcomeReadRequest` — same closed decoding plus the
/// evidence-id presence gate.
pub fn parse_migration_outcome_read_request(
    req: &Request,
) -> Result<MigrationOutcomeReadRequest, String> {
    let payload = req
        .payload
        .as_ref()
        .ok_or_else(|| "missing migration outcome payload".to_owned())?;
    let read: MigrationOutcomeReadRequest = serde_json::from_str(payload.get())
        .map_err(|e| format!("invalid migration outcome request: {e}"))?;
    if read.launch_evidence_id.is_empty() {
        return Err("missing launch evidence ID".to_owned());
    }
    Ok(MigrationOutcomeReadRequest {
        operation_id: req.operation_id.clone(),
        ..read
    })
}

/// `MigrationResetScope` — helper composition, not caller input.
/// Both identities are displayed in the reset ceremony so a copied
/// operation ID cannot authorize a reset of another instance/target.
pub type MigrationResetScope = CeremonyScope;

/// `helper.PAMConfirmer` for the migration launch handler — `Confirm`
/// + `VerifyAndConsume`, plus the optional reset TTY ceremony
///   (`migrationResetTTYCeremony`; `None` maps Go's failed type
///   assertion).
pub trait MigrationPamConfirmer: Send + Sync {
    /// `Confirm` — the lifecycle ceremony.
    fn confirm(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
    ) -> Result<String, Failure>;
    /// `VerifyAndConsume`.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmMigrationReset` — `Some` where the confirmer supports
    /// the destructive ceremony; `None` is upstream's `!ok`.
    fn confirm_migration_reset(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &MigrationResetScope,
        _op_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `helper.MigrationLaunchEvidenceIssuer` — the broker-facing seam.
pub trait MigrationLaunchEvidenceIssuer: Send + Sync {
    /// `IssueMigrationLaunch` — submit the observed child identity;
    /// the broker mints the opaque evidence identifier.
    fn issue_migration_launch(
        &self,
        evidence: &crate::broker::migration_client::MigrationLaunchEvidence,
    ) -> Result<String, Failure>;
}

/// `helper.MigrationProcessSpec` — the complete fixed launch policy;
/// every field is composition-supplied, never caller-supplied.
pub struct MigrationProcessSpec<'a> {
    pub executable: &'a str,
    pub operation_id: &'a str,
    pub args: &'a [String],
    pub uid: u32,
    pub gid: u32,
    pub deadline: Instant,
    pub env: &'a [&'a str],
}

/// `helper.MigrationProcess` — the observed child identity. The
/// `pidfd` is owned; dropping the value releases it, exactly like
/// upstream's deferred `CloseIdentity`.
pub struct MigrationProcess {
    pub launch_id: String,
    pub pid: i32,
    pub pidfd: OwnedFd,
    pub process_start: String,
    pub executable: String,
}

/// `helper.MigrationProcessLauncher` — the launcher-daemon seam.
pub trait MigrationProcessLauncher: Send + Sync {
    /// `Launch` — start the fixed operator under the CML1 protocol.
    fn launch(&self, spec: &MigrationProcessSpec<'_>) -> Result<MigrationProcess, Failure>;
    /// `Commit` — bind the admitted launch to the broker evidence.
    fn commit(&self, launch_id: &str, evidence_id: &str) -> Result<(), Failure>;
    /// `Abort` — terminate and reap an uncommitted launch.
    fn abort(&self, launch_id: &str) -> Result<(), Failure>;
}

/// `helper.MigrationLauncher` — the `Server::migration` field type.
pub trait MigrationLauncher: Send + Sync {
    /// `Launch` — the full authenticated launch.
    fn launch(&self, request: MigrationLaunchRequest, peer: &PeerIdentity) -> Response;
}

/// `helper.MigrationOutcomeReader` — the `Server::migration_outcome`
/// field type (SC-DEF-41: the helper proxies the broker read the
/// operator's own CLI may not perform).
pub trait MigrationOutcomeReader: Send + Sync {
    /// `ReadOutcome`.
    fn read_outcome(&self, request: &MigrationOutcomeReadRequest, peer: &PeerIdentity) -> Response;
}

fn migration_launch_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
    result: Option<serde_json::Value>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, code, reason);
    if let Some(value) = result
        && let Ok(raw) = serde_json::to_string(&value)
        && let Ok(raw) = serde_json::value::RawValue::from_string(raw)
    {
        resp.result = Some(raw);
    }
    resp
}

/// `validateMigrationCommand` — the closed grammar: a UUID operation
/// ID, a known command, no args.
fn validate_migration_command(request: &MigrationLaunchRequest) -> Result<(), ()> {
    if uuid::Uuid::parse_str(&request.operation_id).is_err() {
        return Err(());
    }
    match request.command.as_str() {
        "up" | "resume" | "status" | "verify" | "reset" if request.args.is_empty() => Ok(()),
        _ => Err(()),
    }
}

/// `abortMigrationLaunch` — synchronous kill+reap acknowledgement on a
/// fresh budget, never the possibly expired request's.
fn abort_migration_launch(launcher: &dyn MigrationProcessLauncher, launch_id: &str) -> bool {
    if launch_id.is_empty() {
        return false;
    }
    launcher.abort(launch_id).is_ok()
}

/// `MigrationLaunchHandler` — the helper is the sole migration
/// operator launcher. It authenticates before launching and never
/// issues evidence until it holds a complete child identity.
pub struct MigrationLaunchHandler {
    pam: Box<dyn MigrationPamConfirmer>,
    issuer: Box<dyn MigrationLaunchEvidenceIssuer>,
    launcher: Box<dyn MigrationProcessLauncher>,
    reset_scope: MigrationResetScope,
}

impl MigrationLaunchHandler {
    /// `NewMigrationLaunchHandler` — the production pieces.
    pub fn new(
        pam: Box<dyn MigrationPamConfirmer>,
        issuer: Box<dyn MigrationLaunchEvidenceIssuer>,
        launcher: Box<dyn MigrationProcessLauncher>,
    ) -> Self {
        Self {
            pam,
            issuer,
            launcher,
            reset_scope: MigrationResetScope::default(),
        }
    }

    /// `SetResetScope` — trusted composition only.
    pub fn set_reset_scope(&mut self, scope: MigrationResetScope) {
        self.reset_scope = scope;
    }
}

impl MigrationLauncher for MigrationLaunchHandler {
    fn launch(&self, request: MigrationLaunchRequest, peer: &PeerIdentity) -> Response {
        if peer.pid <= 0 {
            return migration_launch_response(
                &request.operation_id,
                "denied",
                7,
                "MIGRATION_LAUNCH_PEER_DENIED",
                None,
            );
        }
        if validate_migration_command(&request).is_err() {
            return migration_launch_response(
                &request.operation_id,
                "denied",
                2,
                "INVALID_MIGRATION_COMMAND",
                None,
            );
        }
        // `h == nil || h.pam == nil || h.issuer == nil || h.launcher == nil`
        // — the Rust handler is constructed complete, so this gate is
        // the Server's `migration.is_none()` arm upstream also has.
        let request_deadline = Instant::now() + MIGRATION_LAUNCH_DEADLINE;
        let confirmation = if request.command == "reset" {
            if self.reset_scope.instance_id.is_empty() || self.reset_scope.target_id.is_empty() {
                return migration_launch_response(
                    &request.operation_id,
                    "denied",
                    7,
                    "MIGRATION_RESET_TTY_CONFIRMATION_REQUIRED",
                    None,
                );
            }
            match self.pam.confirm_migration_reset(
                *peer,
                Some(request_deadline),
                &self.reset_scope,
                &request.operation_id,
            ) {
                Some(Ok(token)) => token,
                // `!ok` — this confirmer has no reset ceremony.
                None => {
                    return migration_launch_response(
                        &request.operation_id,
                        "denied",
                        7,
                        "MIGRATION_RESET_TTY_CONFIRMATION_REQUIRED",
                        None,
                    );
                }
                // A ceremony failure is AUTHORITY_DENIED like every
                // other PAM failure, not the missing-ceremony answer.
                Some(Err(_)) => {
                    return migration_launch_response(
                        &request.operation_id,
                        "denied",
                        7,
                        "AUTHORITY_DENIED",
                        None,
                    );
                }
            }
        } else {
            match self
                .pam
                .confirm(*peer, Some(request_deadline), &request.operation_id)
            {
                Ok(token) => token,
                Err(_) => {
                    return migration_launch_response(
                        &request.operation_id,
                        "denied",
                        7,
                        "AUTHORITY_DENIED",
                        None,
                    );
                }
            }
        };
        if !self.pam.verify_and_consume(&confirmation) {
            return migration_launch_response(
                &request.operation_id,
                "denied",
                7,
                "AUTHORITY_DENIED",
                None,
            );
        }

        let deadline = request_deadline;
        let process = match self.launcher.launch(&MigrationProcessSpec {
            executable: CENTRAL_MIGRATE_EXECUTABLE,
            operation_id: &request.operation_id,
            args: std::slice::from_ref(&request.command),
            uid: CENTRAL_MIGRATE_UID,
            gid: CENTRAL_MIGRATE_GID,
            deadline,
            env: &["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"],
        }) {
            Ok(p) => p,
            Err(_) => {
                return migration_launch_response(
                    &request.operation_id,
                    "error",
                    6,
                    "MIGRATION_LAUNCH_FAILED",
                    None,
                );
            }
        };
        let complete_identity = !process.launch_id.is_empty()
            && process.pid > 0
            && !process.process_start.is_empty()
            && process.executable == CENTRAL_MIGRATE_EXECUTABLE;
        if !complete_identity {
            return if !abort_migration_launch(self.launcher.as_ref(), &process.launch_id) {
                migration_launch_response(
                    &request.operation_id,
                    "error",
                    6,
                    "MIGRATION_LAUNCH_ABORT_FAILED",
                    None,
                )
            } else {
                migration_launch_response(
                    &request.operation_id,
                    "error",
                    6,
                    "MIGRATION_LAUNCH_IDENTITY_UNAVAILABLE",
                    None,
                )
            };
        }
        let expires_at = OffsetDateTime::now_utc() + MIGRATION_LAUNCH_DEADLINE;
        let evidence_id = match self.issuer.issue_migration_launch(
            &crate::broker::migration_client::MigrationLaunchEvidence {
                pid: process.pid,
                pidfd: process.pidfd.as_fd().as_raw_fd(),
                process_start: process.process_start.clone(),
                executable: process.executable.clone(),
                mode: "migrate".to_owned(),
                operation_id: request.operation_id.clone(),
                expires_at,
            },
        ) {
            Ok(id) if !id.is_empty() => id,
            _ => {
                return if !abort_migration_launch(self.launcher.as_ref(), &process.launch_id) {
                    migration_launch_response(
                        &request.operation_id,
                        "error",
                        6,
                        "MIGRATION_LAUNCH_ABORT_FAILED",
                        None,
                    )
                } else {
                    migration_launch_response(
                        &request.operation_id,
                        "error",
                        6,
                        "MIGRATION_LAUNCH_EVIDENCE_FAILED",
                        None,
                    )
                };
            }
        };
        if self
            .launcher
            .commit(&process.launch_id, &evidence_id)
            .is_err()
        {
            return if !abort_migration_launch(self.launcher.as_ref(), &process.launch_id) {
                migration_launch_response(
                    &request.operation_id,
                    "error",
                    6,
                    "MIGRATION_LAUNCH_ABORT_FAILED",
                    None,
                )
            } else {
                migration_launch_response(
                    &request.operation_id,
                    "error",
                    6,
                    "MIGRATION_LAUNCH_COMMIT_FAILED",
                    None,
                )
            };
        }
        migration_launch_response(
            &request.operation_id,
            "success",
            0,
            "",
            Some(serde_json::json!({
                "operation_id": request.operation_id,
                "launch_evidence_id": evidence_id,
            })),
        )
    }
}

impl MigrationPamConfirmer for super::pam_ceremony::PamConfirmer {
    fn confirm(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
    ) -> Result<String, Failure> {
        super::pam_ceremony::PamConfirmer::confirm(self, peer, deadline, op_id)
    }
    fn verify_and_consume(&self, token: &str) -> bool {
        super::pam_ceremony::PamConfirmer::verify_and_consume(self, token)
    }
    fn confirm_migration_reset(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &MigrationResetScope,
        op_id: &str,
    ) -> Option<Result<String, Failure>> {
        Some(super::pam_ceremony::PamConfirmer::confirm_migration_reset(
            self, peer, deadline, scope, op_id,
        ))
    }
}

/// `nativeMigrationProcessLauncher` — adapts the reviewed native
/// launcher protocol to the helper's broker-evidence port. It never
/// forks or execs a child.
pub struct NativeMigrationProcessLauncher {
    client: crate::migration_launcher::Client,
}

impl Default for NativeMigrationProcessLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeMigrationProcessLauncher {
    /// `newNativeMigrationProcessLauncher` — the fixed socket.
    pub fn new() -> Self {
        Self {
            client: crate::migration_launcher::Client::new(),
        }
    }

    /// The test seam — a configurable client.
    #[doc(hidden)]
    pub fn with_client(client: crate::migration_launcher::Client) -> Self {
        Self { client }
    }
}

fn native_migration_command(command: &str) -> Option<crate::migration_launcher::Command> {
    match command {
        "up" => Some(crate::migration_launcher::Command::Up),
        "resume" => Some(crate::migration_launcher::Command::Resume),
        "status" => Some(crate::migration_launcher::Command::Status),
        "verify" => Some(crate::migration_launcher::Command::Verify),
        "reset" => Some(crate::migration_launcher::Command::Reset),
        _ => None,
    }
}

/// `migrationProcessExecutable` — `/proc/<pid>/exe` fully resolved.
/// `pub(crate)` so the backup launcher's process-identity evidence
/// reuses the exact same `/proc` read (`backup_launch.go`'s
/// `processExecutable` is byte-identical logic).
pub(crate) fn migration_process_executable(pid: i32) -> Result<String, Failure> {
    let link = PathBuf::from(format!("/proc/{pid}/exe"));
    let resolved = std::fs::canonicalize(&link).map_err(|e| {
        Failure::internal(
            "helper_migration",
            format!("helper: read child executable: {e}"),
        )
    })?;
    Ok(resolved.to_string_lossy().into_owned())
}

/// `migrationProcessStart` — `/proc/<pid>/stat` field 22 (starttime),
/// parsed after the last `)` exactly like upstream's `LastIndex`.
/// `pub(crate)` for the same reason as
/// [`migration_process_executable`].
pub(crate) fn migration_process_start(pid: i32) -> Result<String, Failure> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| {
        Failure::internal(
            "helper_migration",
            format!("helper: read child process start: {e}"),
        )
    })?;
    let end = contents.rfind(')').ok_or_else(|| {
        Failure::internal("helper_migration", "helper: malformed child process stat")
    })?;
    let fields: Vec<&str> = contents[end + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(Failure::internal(
            "helper_migration",
            "helper: missing child process start",
        ));
    }
    Ok(fields[19].to_owned())
}

fn budget_from_deadline(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

impl MigrationProcessLauncher for NativeMigrationProcessLauncher {
    fn launch(&self, spec: &MigrationProcessSpec<'_>) -> Result<MigrationProcess, Failure> {
        let invalid = |m: &str| Failure::denied("helper_migration", format!("helper: {m}"));
        if spec.executable != CENTRAL_MIGRATE_EXECUTABLE
            || spec.uid != CENTRAL_MIGRATE_UID
            || spec.gid != CENTRAL_MIGRATE_GID
            || spec.args.is_empty()
            || spec.args.len() > 2
        {
            return Err(invalid("invalid native migration launch specification"));
        }
        let operation_id = uuid::Uuid::parse_str(spec.operation_id).map_err(|e| {
            Failure::invalid(
                "helper_migration",
                format!("helper: parse migration operation ID: {e}"),
            )
        })?;
        let command = native_migration_command(&spec.args[0])
            .ok_or_else(|| invalid("invalid native migration command"))?;
        let result = self.client.launch(
            budget_from_deadline(spec.deadline),
            &crate::migration_launcher::Request {
                command,
                operation_id,
            },
        )?;
        let pid = result.pid as i32;
        let cleanup = |launcher: &Self, launch_id: uuid::Uuid| {
            let _ = launcher.client.abort(MIGRATION_LAUNCH_DEADLINE, launch_id);
        };
        let executable = match migration_process_executable(pid) {
            Ok(e) => e,
            Err(e) => {
                cleanup(self, result.launch_id);
                return Err(e);
            }
        };
        let process_start = match migration_process_start(pid) {
            Ok(s) => s,
            Err(e) => {
                cleanup(self, result.launch_id);
                return Err(e);
            }
        };
        Ok(MigrationProcess {
            launch_id: result.launch_id.to_string(),
            pid,
            pidfd: result.pidfd,
            process_start,
            executable,
        })
    }

    fn commit(&self, launch_id: &str, evidence_id: &str) -> Result<(), Failure> {
        let launch = uuid::Uuid::parse_str(launch_id).map_err(|e| {
            Failure::invalid(
                "helper_migration",
                format!("helper: parse native launch ID: {e}"),
            )
        })?;
        let evidence = uuid::Uuid::parse_str(evidence_id).map_err(|e| {
            Failure::invalid(
                "helper_migration",
                format!("helper: parse broker evidence ID: {e}"),
            )
        })?;
        self.client
            .commit(MIGRATION_LAUNCH_DEADLINE, launch, evidence)
    }

    fn abort(&self, launch_id: &str) -> Result<(), Failure> {
        let launch = uuid::Uuid::parse_str(launch_id).map_err(|e| {
            Failure::invalid(
                "helper_migration",
                format!("helper: parse native launch ID: {e}"),
            )
        })?;
        self.client.abort(MIGRATION_LAUNCH_DEADLINE, launch)
    }
}

/// `BrokerLaunchEvidenceIssuer` — `helper.MigrationLaunchEvidenceIssuer`
/// over the real broker client.
pub struct BrokerLaunchEvidenceIssuer {
    issuer: crate::broker::migration_client::MigrationLaunchIssuer,
}

impl BrokerLaunchEvidenceIssuer {
    /// `broker.NewMigrationLaunchEvidenceIssuer`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            issuer: crate::broker::migration_client::MigrationLaunchIssuer::new(socket_path),
        }
    }
}

impl MigrationLaunchEvidenceIssuer for BrokerLaunchEvidenceIssuer {
    fn issue_migration_launch(
        &self,
        evidence: &crate::broker::migration_client::MigrationLaunchEvidence,
    ) -> Result<String, Failure> {
        self.issuer.issue_migration_launch(evidence)
    }
}

/// `productionMigrationOutcomeReader` — runs inside the root helper
/// (the broker's own peer gate already admits it) and forwards the
/// read to `read_migration_launch_outcome` on the operator's behalf.
pub struct ProductionMigrationOutcomeReader {
    socket_path: String,
}

impl ProductionMigrationOutcomeReader {
    /// `newProductionMigrationOutcomeReader`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl MigrationOutcomeReader for ProductionMigrationOutcomeReader {
    fn read_outcome(&self, request: &MigrationOutcomeReadRequest, peer: &PeerIdentity) -> Response {
        if peer.pid <= 0 || request.operation_id.is_empty() || request.launch_evidence_id.is_empty()
        {
            return Response::denied(
                &request.operation_id,
                2,
                "INVALID_MIGRATION_OUTCOME_REQUEST",
            );
        }
        match crate::broker::migration_client::read_migration_launch_outcome(
            &self.socket_path,
            &request.operation_id,
            &request.launch_evidence_id,
        ) {
            Err(_) => Response::new(
                &request.operation_id,
                "error",
                3,
                "MIGRATION_OUTCOME_READ_FAILED",
            ),
            Ok(outcome) => {
                let mut resp = Response::new(&request.operation_id, "success", 0, "");
                match serde_json::to_string(&outcome)
                    .ok()
                    .and_then(|s| serde_json::value::RawValue::from_string(s).ok())
                {
                    Some(raw) => resp.result = Some(raw),
                    None => {
                        return Response::new(
                            &request.operation_id,
                            "error",
                            6,
                            "MIGRATION_OUTCOME_ENCODE_FAILED",
                        );
                    }
                }
                resp
            }
        }
    }
}
