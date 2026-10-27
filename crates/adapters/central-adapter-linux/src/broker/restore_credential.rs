//! Frame `0xc2` — the descriptor-only restore credential transport,
//! ported from upstream
//! `internal/adapter/authority/broker/restore_migration_credential_linux.go`.
//!
//! It is deliberately a separate frame rather than another kind byte
//! on the backup-worker frame: that frame authorizes an unprivileged
//! worker launch, while this one authorizes the root restore
//! coordinator and releases the migration credential, which no worker
//! may ever hold.
//!
//! Slice boundary (R6-7c): kinds 2–6 are live. Kind 1 — the
//! destructive `pg_restore` migration draw — remains fail-closed: its
//! second precondition is the capacity-reserve gate
//! (`assertRestoreCapacityReserveGate`), which needs the T8
//! reserve/receipt stores this Service does not carry, so the gate's
//! own nil-store `STATE_INVALID` answer is the only answer this slice
//! can produce and the passfile is never read.

use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};

use central_foundation::failure::Failure;
use rustix::process::Uid;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use central_backup::recovery::operation::{RestoreCheckpoint, RestoreOperation, RestorePhase};
use central_backup::recovery::refusal::{RestoreRefusalReason, classify_restore_refusal};
use central_infra::authority::BrokerResponse;
use central_infra::domain::{MINIO_IMPORT_KEY_SCOPE, MINIO_RESTORE_KEY_SCOPE, Purpose};

use crate::sys::peercred::PeerCred;
use crate::sys::scm_rights;

use super::backup_worker_credential::{
    validate_central_migration_passfile, validate_central_runtime_passfile,
    validate_credential_descriptor,
};
use super::deadline::DeadlineStream;
use super::protocol::{
    self, RESTORE_AUDIT_MIGRATION_CREDENTIAL, RESTORE_IMPORT_MIGRATION_CREDENTIAL,
    RESTORE_MIGRATION_CREDENTIAL, RESTORE_MIGRATION_CREDENTIAL_FRAME_SIZE,
    RESTORE_MINIO_CREDENTIAL, RESTORE_MINIO_IMPORT_CREDENTIAL, RESTORE_RUNTIME_CREDENTIAL,
    RestoreCredentialRequest,
};
use super::restore_launch::RestoreLaunchBinding;
use super::server::Service;

/// The fixed artifacts bucket every operation-bound MinIO receipt must
/// name — `central-artifacts-v1`, as upstream.
const ARTIFACTS_BUCKET: &str = "central-artifacts-v1";

fn unavailable() -> Failure {
    Failure::internal(
        "recovery_journal_unavailable",
        "recovery journal unavailable",
    )
}

/// `restoreCredentialKindAdmitsMode` restricts which launch-record
/// `mode` may obtain which credential kind, closing the gap
/// `validate_peer` alone leaves open: it proves a connecting peer's
/// process identity, but says nothing about whether the mode that
/// identity was bound under is allowed to hold the credential kind it
/// is now asking for.
///
/// The migration credential rewrites the target and the MinIO restore
/// credential is fetched only from `operationScopedInventoryVerifier`
/// during the apply/resume inventory-verification step — both
/// apply/resume only. A verify-mode engine must never be admitted for
/// either, even though its process identity is genuine.
///
/// The runtime credential alone is used by every mode: verify fetches
/// it (with no operation) before any protected operation exists, and
/// apply/resume fetch it again, with an operation, for the pinned
/// `pg_restore` adapter's own target connection. Import joins the
/// admission set for the same composition reason; its with-operation
/// fetch still refuses downstream in `assert_live_restore`, because no
/// restore operation ever exists for foreign data.
///
/// The two ADR 0034 import kinds admit only the import mode: the
/// import MinIO writer and the import migration draw must never be
/// reachable from an apply/resume/verify run, just as the restore
/// credentials are unreachable from an import run.
#[must_use]
pub(crate) fn restore_credential_kind_admits_mode(kind: u8, mode: &str) -> bool {
    match kind {
        RESTORE_MIGRATION_CREDENTIAL
        | RESTORE_MINIO_CREDENTIAL
        | RESTORE_AUDIT_MIGRATION_CREDENTIAL => mode == "apply" || mode == "resume",
        RESTORE_RUNTIME_CREDENTIAL => {
            mode == "apply" || mode == "resume" || mode == "verify" || mode == "import"
        }
        RESTORE_MINIO_IMPORT_CREDENTIAL | RESTORE_IMPORT_MIGRATION_CREDENTIAL => mode == "import",
        _ => false,
    }
}

impl Service {
    /// `handleRestoreCredentialTransport` releases exactly one sealed
    /// credential for one root restore run. It is not a general
    /// credential route: each kind carries its own protected-state
    /// precondition, so a state that only admits reading inventory can
    /// never release the credential that rewrites the database.
    ///
    /// # Errors
    /// Returns `Err` only on the descriptor-send transport failure —
    /// exactly upstream, where `WriteMsgUnix` failing is the one path
    /// that is not a refusal.
    pub(crate) fn handle_restore_credential_transport(
        &self,
        conn: &mut DeadlineStream,
        request: &RestoreCredentialRequest,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        let mut denied = |reason: RestoreRefusalReason| {
            let reason = if reason.as_str().is_empty() {
                RestoreRefusalReason::StateInvalid
            } else {
                reason
            };
            protocol::write_deny(conn, &request.operation_id.to_string(), reason.as_str());
        };
        if self.recovery_journal.is_none()
            || self.bootstrap.is_none()
            || self.restore_launches.is_none()
            || !protocol::valid_restore_credential_kind(request.kind)
        {
            denied(RestoreRefusalReason::StateInvalid);
            return Ok(());
        }
        // ADR 0015: the broker's root peer gate (uid 0 && gid 0) cannot
        // by itself distinguish the restore engine from any other root
        // process. `validate_peer` checks the connecting peer against
        // the record the root helper bound at launch — including the
        // uid/gid constraint the blanket check used to perform alone —
        // rather than trusting any root peer that happens to speak
        // this frame.
        let Some(launches) = &self.restore_launches else {
            denied(RestoreRefusalReason::StateInvalid);
            return Ok(());
        };
        let Ok(binding) = launches.validate_peer(peer) else {
            denied(RestoreRefusalReason::StateInvalid);
            return Ok(());
        };
        // The launch record's mode is signed at bind time but says
        // nothing on its own about which credential kind this
        // connection may draw: a verify-launched engine's process
        // identity checks out just as cleanly as an apply engine's, so
        // without this check it would be admitted for the migration
        // and MinIO restore credentials too — both of which only ever
        // a live apply/resume run may hold.
        if !restore_credential_kind_admits_mode(request.kind, binding.mode) {
            denied(RestoreRefusalReason::StateInvalid);
            return Ok(());
        }
        // The validated binding is passed on rather than re-derived
        // downstream — the capacity-reserve design's decision 1.
        let (mut value, _purpose) = match self.resolve_restore_credential(request, &binding) {
            Ok(resolved) => resolved,
            Err(e) => {
                denied(classify_restore_refusal(
                    Some(&e),
                    RestoreRefusalReason::StateInvalid,
                ));
                return Ok(());
            }
        };
        let fd = match self.handoff.handoff(&value) {
            Ok(fd) => fd,
            Err(_) => {
                value.zeroize();
                denied(RestoreRefusalReason::EngineUnavailable);
                return Ok(());
            }
        };
        value.zeroize();
        protocol::send_descriptor(&*conn, fd.as_fd()).map_err(|e| {
            Failure::internal(
                "broker",
                format!(
                    "broker: deliver restore credential descriptor: {}",
                    e.message()
                ),
            )
        })
    }

    /// `resolveRestoreCredential` takes the validated launch binding
    /// as a parameter because kind 1's capacity gate needs it (the
    /// design's decision 1: the gate receives the binding rather than
    /// re-deriving it). Kinds 2, 3, 5, and 6 do not read it at all —
    /// the mode check those kinds rely on already ran in
    /// [`Self::handle_restore_credential_transport`] via
    /// [`restore_credential_kind_admits_mode`].
    fn resolve_restore_credential(
        &self,
        request: &RestoreCredentialRequest,
        binding: &RestoreLaunchBinding,
    ) -> Result<(Zeroizing<Vec<u8>>, &'static str), Failure> {
        match request.kind {
            RESTORE_MIGRATION_CREDENTIAL => {
                let value =
                    self.resolve_restore_migration_credential(request.operation_id, binding)?;
                Ok((value, Purpose::PostgresMigration.as_str()))
            }
            RESTORE_AUDIT_MIGRATION_CREDENTIAL => {
                let value =
                    self.resolve_restore_audit_migration_credential(request.operation_id)?;
                Ok((value, Purpose::PostgresMigration.as_str()))
            }
            RESTORE_MINIO_IMPORT_CREDENTIAL => {
                let generation =
                    self.resolve_bound_import_minio_generation(request.operation_id)?;
                let value = self.backend.read(&generation).map_err(|_| unavailable())?;
                Ok((Zeroizing::new(value), Purpose::MinioImport.as_str()))
            }
            RESTORE_IMPORT_MIGRATION_CREDENTIAL => {
                let _generation =
                    self.resolve_bound_import_minio_generation(request.operation_id)?;
                let value = self.read_active_migration_passfile()?;
                Ok((value, Purpose::PostgresMigration.as_str()))
            }
            RESTORE_RUNTIME_CREDENTIAL => {
                // Verification runs before any operation exists, so a
                // nil operation is admissible here and only here. With
                // an operation, it must still be a live restore: a
                // finished one has no reason to reopen the target.
                if !request.operation_id.is_nil() {
                    self.assert_live_restore(request.operation_id)?;
                }
                let value = self.read_active_postgres_runtime_passfile()?;
                if validate_central_runtime_passfile(&value).is_err() {
                    return Err(unavailable());
                }
                Ok((value, Purpose::PostgresRuntime.as_str()))
            }
            RESTORE_MINIO_CREDENTIAL => {
                self.assert_inventory_verification_window(request.operation_id)?;
                let Some(journal) = &self.recovery_journal else {
                    return Err(unavailable());
                };
                let Ok((generation, receipt)) = journal
                    .resolve_bound_minio_handoff(request.operation_id, Purpose::MinioRestore)
                else {
                    return Err(unavailable());
                };
                if receipt.bucket != ARTIFACTS_BUCKET
                    || receipt.key_prefix != MINIO_RESTORE_KEY_SCOPE
                {
                    return Err(unavailable());
                }
                let value = self.backend.read(&generation).map_err(|_| unavailable())?;
                Ok((Zeroizing::new(value), Purpose::MinioRestore.as_str()))
            }
            _ => Err(unavailable()),
        }
    }

    /// `assertLiveRestore` requires an existing protected operation
    /// that has not reached a terminal state. Serving is blocked for
    /// exactly that window, so it is the only window in which a
    /// restore run may hold target credentials. `is_terminal`
    /// excludes both terminal outcomes so a dead operation cannot
    /// still yield credentials.
    fn assert_live_restore(&self, operation_id: Uuid) -> Result<(), Failure> {
        let Some(journal) = &self.recovery_journal else {
            return Err(unavailable());
        };
        let operation = journal.read(operation_id)?;
        if operation.validate().is_err()
            || operation.operation_id != operation_id
            || operation.is_terminal()
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// `assertInventoryVerificationWindow` — ADR 0017's narrowed
    /// precondition for the object-store restore credential (kind 3):
    /// `RestoreOperation::admits_inventory_verification` is the single
    /// shared definition of that window.
    fn assert_inventory_verification_window(&self, operation_id: Uuid) -> Result<(), Failure> {
        let Some(journal) = &self.recovery_journal else {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        let Ok(operation) = journal.read(operation_id) else {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        if operation.validate().is_err()
            || operation.operation_id != operation_id
            || !operation.admits_inventory_verification()
        {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        Ok(())
    }

    /// `resolveBoundImportMinioGeneration` — the shared precondition
    /// behind both ADR 0034 import kinds (5 and 6). The bound
    /// `minio_import_v1` receipt is the only broker-side record of an
    /// import operation — there is no restore operation, no ticket, no
    /// authorization — so both the MinIO writer and the migration draw
    /// key off it: bound (post-provisioner), unexpired (revalidated on
    /// every read inside `resolve_bound_minio_handoff`), exact bucket,
    /// and the import scope.
    fn resolve_bound_import_minio_generation(
        &self,
        operation_id: Uuid,
    ) -> Result<super::protected_file::Generation, Failure> {
        let Some(journal) = &self.recovery_journal else {
            return Err(unavailable());
        };
        let Ok((generation, receipt)) =
            journal.resolve_bound_minio_handoff(operation_id, Purpose::MinioImport)
        else {
            return Err(unavailable());
        };
        if receipt.bucket != ARTIFACTS_BUCKET || receipt.key_prefix != MINIO_IMPORT_KEY_SCOPE {
            return Err(unavailable());
        }
        Ok(generation)
    }

    /// `resolveRestoreMigrationCredential` reads the active migration
    /// credential only after the protected journal proves the exact
    /// destructive-admission state and the capacity-reserve gate
    /// proves the disk it is about to rewrite onto has been physically
    /// reserved.
    ///
    /// `launch` is the validated launch binding, threaded from the
    /// transport handler (the design's decision 1) and used only by
    /// the gate.
    ///
    /// A `Service` composed without the capacity stores answers the
    /// gate's nil-store refusal — `RESTORE_STATE_INVALID` — and never
    /// reaches the passfile read, so an unwired deployment stays
    /// fail-closed.
    fn resolve_restore_migration_credential(
        &self,
        operation_id: Uuid,
        launch: &RestoreLaunchBinding,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let Some(journal) = &self.recovery_journal else {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        let Ok(operation) = journal.read(operation_id) else {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        if operation.validate().is_err()
            || operation.operation_id != operation_id
            || operation.phase != RestorePhase::Applying
            || operation.last_checkpoint != RestoreCheckpoint::TicketConsumed
        {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        // The capacity gate. It runs after the operation-state
        // precondition (which is what makes "the destructive window
        // has been entered" true and is what the gate's expiry
        // decision rests on) and before any credential material is
        // read, so a refusal never touches the secret store. The gate
        // itself lives in `restore_capacity::gate` — see
        // `Service::assert_restore_capacity_reserve_gate` for the four
        // preconditions and the expiry decision.
        self.assert_restore_capacity_reserve_gate(
            &operation,
            launch,
            time::OffsetDateTime::now_utc(),
        )?;
        self.read_active_migration_passfile()
    }

    /// `resolveRestoreAuditMigrationCredential` releases the same
    /// `central_migration` secret material as kind 1, under
    /// `assert_live_restore`'s wider window instead of kind 1's single
    /// Applying/TicketConsumed checkpoint. There is no capacity-reserve
    /// gate: unlike kind 1, this credential never drives a destructive
    /// rewrite of the target, only the audit projection, C04 exclusion,
    /// and C05 authority reset writes that follow one.
    fn resolve_restore_audit_migration_credential(
        &self,
        operation_id: Uuid,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        if let Err(err) = self.assert_live_restore(operation_id) {
            // Not yet a live operation is not necessarily ineligible:
            // Apply's own `acquireTargetExclusion` runs before
            // `begin_restore` ever writes the operation record, using
            // the prospective (not yet persisted) one.
            // `has_issued_restore_apply_authorization_for_operation`
            // is that one earlier window, and only that one.
            let Some(journal) = &self.recovery_journal else {
                return Err(err);
            };
            let admitted = journal.has_issued_restore_apply_authorization_for_operation(
                operation_id,
                time::OffsetDateTime::now_utc(),
            );
            match admitted {
                Ok(true) => {}
                _ => return Err(err),
            }
        }
        self.read_active_migration_passfile()
    }

    /// `readActiveMigrationPassfile` — the shared secret-store read
    /// both kind 1 and kind 4 use once their own, distinct
    /// protected-operation precondition has already admitted the
    /// request.
    fn read_active_migration_passfile(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let Some(bootstrap) = &self.bootstrap else {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        let Ok((binding, lease)) = bootstrap.active_binding_for_purpose(Purpose::PostgresMigration)
        else {
            // The migration credential's own binding/lease authority
            // is missing, mismatched, or expired: still a
            // state-ineligibility, but of the authority record rather
            // than the restore operation.
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        };
        if binding.purpose != Purpose::PostgresMigration
            || binding.generation_id.is_nil()
            || binding.binding_id.is_nil()
            || lease.binding_id != binding.binding_id
            || lease.fencing_token == 0
            || lease.expires_at <= time::OffsetDateTime::now_utc()
        {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        let generation = self
            .backend
            .get_by_id(Uuid::from_bytes(*binding.generation_id.as_bytes()))
            .map_err(|_| RestoreRefusalReason::StateInvalid.into_failure())?;
        if generation.purpose != Purpose::PostgresMigration.as_str() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        let value = self
            .backend
            .read(&generation)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        let value = Zeroizing::new(value);
        if validate_central_migration_passfile(&value).is_err() {
            // The stored credential material itself is unreadable or
            // malformed: an engine/storage problem, not an
            // eligibility problem, so it gets its own bucket.
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// Client — `RestoreCredentialClient`
// ---------------------------------------------------------------------------

/// `RestoreCredentialClient` is the root restore engine's side of
/// frame `0xc2`. Each method fixes its own kind, so the engine cannot
/// ask for the migration credential through a code path that only
/// needed to read the target.
pub struct RestoreCredentialClient {
    /// The broker's socket path.
    pub socket_path: String,
}

impl RestoreCredentialClient {
    /// `NewRestoreCredentialClient`.
    #[must_use]
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    /// `OpenSealedRestorePassfile` satisfies the pinned `pg_restore`
    /// adapter's narrow credential boundary. The adapter passes the
    /// operation it is about to replace, and the broker independently
    /// re-checks that same state.
    ///
    /// # Errors
    /// `RESTORE_STATE_INVALID` when the operation is not at the
    /// destructive checkpoint; the transport denial otherwise.
    pub fn open_sealed_restore_passfile(
        &self,
        operation: &RestoreOperation,
    ) -> Result<OwnedFd, Failure> {
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Applying
            || operation.last_checkpoint != RestoreCheckpoint::TicketConsumed
        {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.fetch(RESTORE_MIGRATION_CREDENTIAL, operation.operation_id)
    }

    /// `OpenAdmissionRuntimeCredential` serves verification, which
    /// runs before any protected operation exists.
    ///
    /// # Errors
    /// The transport result.
    pub fn open_admission_runtime_credential(&self) -> Result<OwnedFd, Failure> {
        self.fetch(RESTORE_RUNTIME_CREDENTIAL, Uuid::nil())
    }

    /// `OpenRuntimeCredential`.
    ///
    /// # Errors
    /// `RESTORE_STATE_INVALID` on a nil operation; the transport
    /// result otherwise.
    pub fn open_runtime_credential(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id.is_nil() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.fetch(RESTORE_RUNTIME_CREDENTIAL, operation_id)
    }

    /// `OpenMinioRestoreCredential`.
    ///
    /// # Errors
    /// `RESTORE_STATE_INVALID` on a nil operation; the transport
    /// result otherwise.
    pub fn open_minio_restore_credential(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id.is_nil() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.fetch(RESTORE_MINIO_CREDENTIAL, operation_id)
    }

    /// `OpenMinioImportCredential` — kind 5: the `minio_import_v1`
    /// writer, drawn only by an import-mode engine for the import
    /// operation the bound receipt names.
    ///
    /// # Errors
    /// `RESTORE_STATE_INVALID` on a nil operation; the transport
    /// result otherwise.
    pub fn open_minio_import_credential(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id.is_nil() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.fetch(RESTORE_MINIO_IMPORT_CREDENTIAL, operation_id)
    }

    /// `OpenImportMigrationCredential` — kind 6: the
    /// `central_migration` passfile the import engine's pinned
    /// `pg_restore` draws, admitted by the bound import receipt rather
    /// than by a restore-operation checkpoint that can never exist for
    /// foreign data.
    ///
    /// # Errors
    /// `RESTORE_STATE_INVALID` on a nil operation; the transport
    /// result otherwise.
    pub fn open_import_migration_credential(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id.is_nil() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.fetch(RESTORE_IMPORT_MIGRATION_CREDENTIAL, operation_id)
    }

    /// `OpenAuditMigrationCredential` — kind 4: the same
    /// `central_migration` secret material `open_sealed_restore_passfile`
    /// releases, but admitted across the whole live-operation window
    /// instead of only the single checkpoint `pg_restore` itself runs
    /// at.
    ///
    /// # Errors
    /// `RESTORE_STATE_INVALID` on a nil operation; the transport
    /// result otherwise.
    pub fn open_audit_migration_credential(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id.is_nil() {
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        self.fetch(RESTORE_AUDIT_MIGRATION_CREDENTIAL, operation_id)
    }

    /// `(*RestoreCredentialClient).fetch` — dial, send the 18-byte
    /// fixed frame, and receive either the sealed credential
    /// descriptor or an explicit denial carrying one of the closed
    /// refusal reasons.
    fn fetch(&self, kind: u8, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if self.socket_path.is_empty()
            || !protocol::valid_restore_credential_kind(kind)
            || (!operation_id.is_nil() && operation_id.get_version_num() != 7)
        {
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        let mut frame = [0u8; RESTORE_MIGRATION_CREDENTIAL_FRAME_SIZE];
        frame[0] = protocol::RESTORE_MIGRATION_CREDENTIAL_FRAME_MARKER;
        frame[1] = kind;
        frame[2..18].copy_from_slice(operation_id.as_bytes());
        conn.write_all(&frame)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        let mut data = [0u8; 4096];
        let recv = scm_rights::recv(&conn, &mut data)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        if recv.rights_msgs == 0 {
            // An explicit deny frame, not a transport failure:
            // recover whatever sanitized reason the broker attached,
            // if any.
            return Err(restore_credential_denial_reason(&data[..recv.bytes]));
        }
        let (bytes, fd) = scm_rights::validate_one(recv)
            .map_err(|_| RestoreRefusalReason::EngineUnavailable.into_failure())?;
        if bytes != 1 || data[0] != scm_rights::TRANSPORT_MARKER {
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }
        // Restore-engine credentials are always root-owned
        // (SC-DEF-45's chown exception is scoped to the throughput
        // probe credential alone).
        if validate_credential_descriptor(&fd, Uid::ROOT).is_err() {
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }
        Ok(fd)
    }
}

/// `restoreCredentialDenialReason` recovers the sanitized reason the
/// broker wrote into an explicit deny response, if any. It is
/// best-effort and conservative: any response that cannot be decoded
/// as the broker's own bounded protocol shape, that is not an explicit
/// denial, or whose message is not one of the closed
/// `RestoreRefusalReason` values yields the generic
/// engine-unavailable reason rather than trusting arbitrary wire
/// content — this is the boundary that keeps a locator from ever
/// crossing the socket into this process's error values.
fn restore_credential_denial_reason(raw: &[u8]) -> Failure {
    if raw.is_empty() || raw.len() > 4096 {
        return RestoreRefusalReason::EngineUnavailable.into_failure();
    }
    let trimmed = {
        let mut end = raw.len();
        while end > 0 && raw[end - 1] == b'\n' {
            end -= 1;
        }
        &raw[..end]
    };
    let Ok(response) = serde_json::from_slice::<BrokerResponse>(trimmed) else {
        return RestoreRefusalReason::EngineUnavailable.into_failure();
    };
    if response.outcome != central_infra::authority::BrokerOutcome::Denied {
        return RestoreRefusalReason::EngineUnavailable.into_failure();
    }
    let Some(reason) = RestoreRefusalReason::from_wire(&response.evidence.message) else {
        return RestoreRefusalReason::EngineUnavailable.into_failure();
    };
    reason.into_failure()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `validRestoreCredentialKind` — the closed kind set.
    #[test]
    fn kind_set() {
        for kind in 1..=6u8 {
            assert!(protocol::valid_restore_credential_kind(kind), "kind {kind}");
        }
        for kind in [0u8, 7, 255] {
            assert!(!protocol::valid_restore_credential_kind(kind));
        }
    }

    /// `restoreCredentialKindAdmitsMode` — the mode/kind matrix is
    /// upstream's exact closed set.
    #[test]
    fn mode_admission_matrix() {
        // Destructive + minio-restore kinds: apply/resume only.
        for kind in [
            RESTORE_MIGRATION_CREDENTIAL,
            RESTORE_MINIO_CREDENTIAL,
            RESTORE_AUDIT_MIGRATION_CREDENTIAL,
        ] {
            assert!(restore_credential_kind_admits_mode(kind, "apply"));
            assert!(restore_credential_kind_admits_mode(kind, "resume"));
            assert!(!restore_credential_kind_admits_mode(kind, "verify"));
            assert!(!restore_credential_kind_admits_mode(kind, "import"));
        }
        // Runtime credential: every mode.
        for mode in ["apply", "resume", "verify", "import"] {
            assert!(restore_credential_kind_admits_mode(
                RESTORE_RUNTIME_CREDENTIAL,
                mode
            ));
        }
        // Import kinds: import only.
        for kind in [
            RESTORE_MINIO_IMPORT_CREDENTIAL,
            RESTORE_IMPORT_MIGRATION_CREDENTIAL,
        ] {
            assert!(restore_credential_kind_admits_mode(kind, "import"));
            assert!(!restore_credential_kind_admits_mode(kind, "apply"));
            assert!(!restore_credential_kind_admits_mode(kind, "verify"));
        }
        assert!(!restore_credential_kind_admits_mode(0, "apply"));
        assert!(!restore_credential_kind_admits_mode(99, "apply"));
    }

    /// `readRestoreCredentialRequest` — the frame gate: kind closed,
    /// operation must be nil or UUIDv7, and only kind 2 may carry a
    /// nil operation.
    #[test]
    fn request_frame_gate() {
        use std::io::Cursor;
        let op = Uuid::now_v7();
        let mut body = vec![RESTORE_MINIO_CREDENTIAL];
        body.extend_from_slice(op.as_bytes());
        let req = protocol::read_restore_credential_request(&mut Cursor::new(body)).unwrap();
        assert_eq!(req.kind, RESTORE_MINIO_CREDENTIAL);
        assert_eq!(req.operation_id, op);

        // Nil operation: allowed only for kind 2.
        let mut nil_op = vec![RESTORE_RUNTIME_CREDENTIAL];
        nil_op.extend_from_slice(Uuid::nil().as_bytes());
        assert!(protocol::read_restore_credential_request(&mut Cursor::new(nil_op)).is_ok());
        let mut nil_op = vec![RESTORE_MIGRATION_CREDENTIAL];
        nil_op.extend_from_slice(Uuid::nil().as_bytes());
        assert!(protocol::read_restore_credential_request(&mut Cursor::new(nil_op)).is_err());

        // Non-v7 operation refuses.
        let mut v4 = vec![RESTORE_RUNTIME_CREDENTIAL];
        v4.extend_from_slice(Uuid::new_v4().as_bytes());
        assert!(protocol::read_restore_credential_request(&mut Cursor::new(v4)).is_err());

        // Unknown kind refuses.
        let mut bad = vec![0u8];
        bad.extend_from_slice(op.as_bytes());
        assert!(protocol::read_restore_credential_request(&mut Cursor::new(bad)).is_err());

        // Short frame refuses.
        assert!(protocol::read_restore_credential_request(&mut Cursor::new(vec![1u8; 4])).is_err());
    }

    /// `restoreCredentialDenialReason` — only a broker-shaped deny
    /// frame with a closed refusal reason round-trips; everything else
    /// collapses to `EngineUnavailable` so arbitrary wire text never
    /// becomes an error message.
    #[test]
    fn denial_reason_sanitization() {
        // A well-formed deny frame carrying a known reason.
        let mut buf = Vec::new();
        protocol::write_deny(&mut buf, "op", "RESTORE_CAPACITY_INSUFFICIENT");
        let failure = restore_credential_denial_reason(&buf);
        assert_eq!(failure.code(), "RESTORE_CAPACITY_INSUFFICIENT");
        assert_eq!(failure.message(), "RESTORE_CAPACITY_INSUFFICIENT");

        // A deny frame with arbitrary locator text collapses.
        let mut buf = Vec::new();
        protocol::write_deny(&mut buf, "op", "/etc/secrets/password leaked");
        let failure = restore_credential_denial_reason(&buf);
        assert_eq!(failure.code(), "RESTORE_ENGINE_UNAVAILABLE");

        // Non-JSON collapses.
        let failure = restore_credential_denial_reason(b"not json");
        assert_eq!(failure.code(), "RESTORE_ENGINE_UNAVAILABLE");

        // Empty collapses.
        let failure = restore_credential_denial_reason(b"");
        assert_eq!(failure.code(), "RESTORE_ENGINE_UNAVAILABLE");

        // A success outcome collapses.
        let mut buf = Vec::new();
        protocol::write_accept(&mut buf, "op");
        let failure = restore_credential_denial_reason(&buf);
        assert_eq!(failure.code(), "RESTORE_ENGINE_UNAVAILABLE");
    }

    /// A restore operation at the destructive checkpoint — the only
    /// shape kind 1's broker-side precondition admits, and the shape
    /// `open_sealed_restore_passfile` requires client-side.
    fn applying_operation() -> RestoreOperation {
        use central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
        use central_backup::domain::TargetIdentity;
        use central_backup::recovery::operation::{RestoreTicket, new_restore_operation};
        use time::macros::datetime;
        let ticket = RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: TargetIdentity {
                system_id: "sys".into(),
                database_oid: "42".into(),
                database: "central".into(),
                config_hash: "cfg".into(),
                epoch: 1,
            },
            target_fingerprint: format!("sha256:{}", "a".repeat(64)),
            manifest_digest: format!("sha256:{}", "b".repeat(64)),
            security_epoch: 7,
            restore_epoch: 3,
            config_fingerprint: format!("sha256:{}", "c".repeat(64)),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: format!("sha256:{}", "d".repeat(64)),
            tool_version: "pg_dump-16.14".into(),
            hidden_nonce: b"nonce".to_vec(),
            issued_at: datetime!(2026-03-01 12:00:00 UTC),
            expires_at: datetime!(2026-03-01 13:00:00 UTC),
            hmac: String::new(),
        };
        new_restore_operation(&ticket, datetime!(2026-03-01 12:30:00 UTC)).unwrap()
    }

    /// Kind 1's capacity gate fails closed against the evidence, not
    /// against the stores: with the T8 stores composed but no reserve
    /// set bound to this operation, the only answer is
    /// `STATE_INVALID` — even for an operation parked at the one
    /// checkpoint that would otherwise admit it.
    #[test]
    fn kind_one_capacity_gate_refuses_without_reserve() {
        let root = std::env::temp_dir().join(format!("rcred-{}", Uuid::now_v7()));
        let svc = Service::new(root.clone(), 501).expect("service");
        let operation = applying_operation();
        let binding = RestoreLaunchBinding {
            launch_evidence_id: Uuid::now_v7(),
            mode: "apply",
        };
        let err = svc
            .assert_restore_capacity_reserve_gate(
                &operation,
                &binding,
                time::OffsetDateTime::now_utc(),
            )
            .unwrap_err();
        assert_eq!(err.code(), "RESTORE_STATE_INVALID");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The client fetch refuses a wrong-checkpoint operation before
    /// dialing — `OpenSealedRestorePassfile`'s state pre-check.
    #[test]
    fn sealed_passfile_precheck() {
        let client = RestoreCredentialClient::new("/nonexistent".to_owned());
        let mut operation = applying_operation();
        operation.phase = RestorePhase::Verifying;
        let err = client.open_sealed_restore_passfile(&operation).unwrap_err();
        assert_eq!(err.code(), "RESTORE_STATE_INVALID");
    }

    /// The kind-1 broker resolution refuses any operation that is not
    /// at the destructive checkpoint before ever reaching the gate.
    #[test]
    fn migration_credential_wrong_phase() {
        let root = std::env::temp_dir().join(format!("rcred-{}", Uuid::now_v7()));
        let svc = Service::new(root.clone(), 501).expect("service");
        let mut operation = applying_operation();
        operation.phase = RestorePhase::Verifying;
        let binding = RestoreLaunchBinding {
            launch_evidence_id: Uuid::now_v7(),
            mode: "apply",
        };
        // The operation is not in the journal — `journal.read` fails,
        // still `STATE_INVALID`.
        let err = svc
            .resolve_restore_migration_credential(operation.operation_id, &binding)
            .unwrap_err();
        assert_eq!(err.code(), "RESTORE_STATE_INVALID");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Nil-operation draws refuse client-side for every kind but the
    /// admission runtime credential.
    #[test]
    fn nil_operation_refusals() {
        let client = RestoreCredentialClient::new("/nonexistent".to_owned());
        assert!(client.open_runtime_credential(Uuid::nil()).is_err());
        assert!(client.open_minio_restore_credential(Uuid::nil()).is_err());
        assert!(client.open_minio_import_credential(Uuid::nil()).is_err());
        assert!(
            client
                .open_import_migration_credential(Uuid::nil())
                .is_err()
        );
        assert!(client.open_audit_migration_credential(Uuid::nil()).is_err());
    }
}
