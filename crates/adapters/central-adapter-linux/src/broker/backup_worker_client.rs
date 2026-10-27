//! Backup worker-side broker clients — the helper-launched worker half
//! ported from upstream
//! `internal/adapter/authority/broker/backup_authority_rpc.go`
//! (`BackupWorkerJournal`, `BackupWorkerSealer`) and
//! `internal/adapter/authority/broker/backup_throughput_launch_rpc.go`
//! (`BackupThroughputWorkerAuthority`).
//!
//! Every call is bound to the exact launch evidence and operation the
//! broker issued for this worker; the broker re-binds the live kernel
//! peer per connection, so the client carries no token or credential.
//! Request shapes reuse the same wire structs the server decodes, so
//! byte parity holds by construction; every call then re-validates the
//! result against the launch binding exactly like upstream.

use std::path::PathBuf;

use central_backup::backup::capacity::default_recovery_profile;
use central_backup::backup::operation::{
    BackupAcceptedFacts, BackupOperation, BackupPhase, BackupSealProposal,
};
use central_backup::port::{BackupAuthorityLease, BackupJournalStore, BackupThroughputSource};
use central_backup::recovery::profile::ThroughputEvidence;
use central_backup::repository::BackupSealCompanion;
use central_foundation::failure::Failure;
use time::OffsetDateTime;
use uuid::Uuid;

use super::backup_authority::{
    BackupLaunchAuthorityWire, BackupSealRPCRequest, BackupThroughputWorkerIdentityRequest,
    BackupThroughputWorkerStageRequest, BackupThroughputWorkerTargetRequest,
    BackupWorkerCASRPCRequest, BackupWorkerIdentityRPCRequest, BackupWorkerOperationRPCRequest,
    BackupWorkerThroughputRPCRequest, PayloadEpochResult,
};
use super::backup_throughput_launch::{
    BACKUP_THROUGHPUT_LAUNCH_ACTIVE, BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED,
    BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED, BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED,
    BackupThroughputTargetLockAttestation, BackupThroughputWorkerContext,
};
use super::lifecycle_client::LifecycleClient;
use super::protocol::{
    BACKUP_SEAL_RPC, BACKUP_THROUGHPUT_WORKER_CONTEXT_RPC, BACKUP_THROUGHPUT_WORKER_STAGE_RPC,
    BACKUP_THROUGHPUT_WORKER_TARGET_RPC, BACKUP_WORKER_CAS_RPC, BACKUP_WORKER_CONTEXT_RPC,
    BACKUP_WORKER_CREATE_RPC, BACKUP_WORKER_EPOCH_RPC, BACKUP_WORKER_READ_RPC,
    BACKUP_WORKER_THROUGHPUT_RPC,
};
use super::recovery_journal::{
    accepted_facts_to_wire, backup_operation_from_wire, backup_operation_to_wire,
    seal_companion_from_wire, seal_proposal_to_wire,
};
use super::throughput_journal::{evidence_from_wire, evidence_to_wire};
use super::wire;

fn unavailable(message: &'static str) -> Failure {
    Failure::unavailable("backup_worker_client", message)
}

fn denied(message: &'static str) -> Failure {
    Failure::denied("backup_worker_client", message)
}

/// `helper.BackupLaunchAuthority` — the launch binding the broker
/// returns to the exact worker that presents the launch evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupLaunchAuthority {
    pub launch_evidence_id: Uuid,
    pub operation_id: Uuid,
    pub backup_id: Uuid,
}

/// `BackupWorkerJournal` — usable only by the exact helper-launched
/// worker. Every call carries the opaque launch evidence and is
/// re-bound to the live kernel peer by `HandleConn` before protected
/// state can change. Implements [`BackupJournalStore`],
/// [`BackupAuthorityLease`], and [`BackupThroughputSource`]; the
/// kernel wraps [`Self::active_payload_epoch_id`] for
/// `TrustedPayloadEpochSource`.
pub struct BackupWorkerJournal {
    client: LifecycleClient,
    launch_evidence_id: Uuid,
    operation_id: Uuid,
}

impl BackupWorkerJournal {
    /// `NewBackupWorkerJournal`.
    pub fn new(socket_path: PathBuf, launch_evidence_id: Uuid, operation_id: Uuid) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
            launch_evidence_id,
            operation_id,
        }
    }

    /// `Authority` — the launch authority bound to this worker.
    ///
    /// # Errors
    /// `backup_worker_client` `unavailable` when the launch binding is
    /// structurally incomplete; `denied` on transport failure or a
    /// mismatched broker reply.
    pub fn authority(&self) -> Result<BackupLaunchAuthority, Failure> {
        if self.launch_evidence_id.is_nil() || self.operation_id.is_nil() {
            return Err(unavailable("broker backup worker journal: unavailable"));
        }
        let request = BackupWorkerIdentityRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
        };
        let result: BackupLaunchAuthorityWire = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_WORKER_CONTEXT_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup worker journal: denied"))?;
        if result.launch_evidence_id != self.launch_evidence_id
            || result.operation_id != self.operation_id
            || result.backup_id.is_nil()
        {
            return Err(denied("broker backup worker journal: denied"));
        }
        Ok(BackupLaunchAuthority {
            launch_evidence_id: result.launch_evidence_id,
            operation_id: result.operation_id,
            backup_id: result.backup_id,
        })
    }

    /// `ActivePayloadEpochID` — the broker-authenticated active payload
    /// generation, released only to the exact live worker bound to this
    /// launch.
    ///
    /// # Errors
    /// `unavailable` when the launch binding is incomplete; `denied`
    /// on transport failure or a non-v7 epoch.
    pub fn active_payload_epoch_id(&self) -> Result<Uuid, Failure> {
        if self.launch_evidence_id.is_nil() || self.operation_id.is_nil() {
            return Err(unavailable(
                "broker backup worker payload epoch: unavailable",
            ));
        }
        let request = BackupWorkerIdentityRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
        };
        let result: PayloadEpochResult = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_WORKER_EPOCH_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup worker payload epoch: denied"))?;
        if result.payload_epoch_id.is_nil() || result.payload_epoch_id.get_version_num() != 7 {
            return Err(denied("broker backup worker payload epoch: denied"));
        }
        Ok(result.payload_epoch_id)
    }
}

impl BackupJournalStore for BackupWorkerJournal {
    /// `CreateBackup` — persists the planned operation through the
    /// broker journal; the worker may only create its own operation.
    fn create_backup(&self, operation: &BackupOperation) -> Result<(), Failure> {
        if operation.operation_id != self.operation_id || operation.phase != BackupPhase::Planned {
            return Err(unavailable("broker backup worker journal: unavailable"));
        }
        #[derive(serde::Deserialize)]
        struct CreatedResult {
            created: bool,
        }
        let request = BackupWorkerOperationRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
            operation: backup_operation_to_wire(operation),
        };
        let result: CreatedResult = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_WORKER_CREATE_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup worker journal: denied"))?;
        if !result.created {
            return Err(denied("broker backup worker journal: denied"));
        }
        Ok(())
    }

    /// `ReadBackup` — the durable record; the worker may only read the
    /// operation this client is bound to.
    fn read_backup(&self, operation_id: Uuid) -> Result<BackupOperation, Failure> {
        if operation_id != self.operation_id {
            return Err(unavailable("broker backup worker journal: unavailable"));
        }
        let request = BackupWorkerIdentityRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
        };
        let result: super::recovery_journal::BackupOperationWire = self
            .client
            .call_with_operation_id(&operation_id.to_string(), BACKUP_WORKER_READ_RPC, &request)
            .map_err(|_| denied("broker backup worker journal: denied"))?;
        let operation = backup_operation_from_wire(&result)
            .map_err(|_| denied("broker backup worker journal: denied"))?;
        operation
            .validate()
            .map_err(|_| denied("broker backup worker journal: denied"))?;
        Ok(operation)
    }

    /// `CompareAndSwapBackup` — both operations must be the one this
    /// client is bound to; the broker performs the atomic transition.
    fn compare_and_swap_backup(
        &self,
        expected: &BackupOperation,
        next: &BackupOperation,
    ) -> Result<(), Failure> {
        if expected.operation_id != self.operation_id || next.operation_id != self.operation_id {
            return Err(unavailable("broker backup worker journal: unavailable"));
        }
        #[derive(serde::Deserialize)]
        struct UpdatedResult {
            updated: bool,
        }
        let request = BackupWorkerCASRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
            expected: backup_operation_to_wire(expected),
            next: backup_operation_to_wire(next),
        };
        let result: UpdatedResult = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_WORKER_CAS_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup worker journal: denied"))?;
        if !result.updated {
            return Err(denied("broker backup worker journal: denied"));
        }
        Ok(())
    }
}

impl BackupAuthorityLease for BackupWorkerJournal {
    /// `AssertHeld` — the coordinator's continuous authority guard,
    /// revalidating the exact live process against the broker launch
    /// record. Returns no token or repository detail.
    fn assert_held(&self) -> Result<(), Failure> {
        self.authority().map(|_| ())
    }
}

impl BackupThroughputSource for BackupWorkerJournal {
    /// `ReadBackupThroughput` — the active receipt the broker binds to
    /// this exact worker, repository, payload epoch, accepted
    /// target/config, and operation-bound MinIO backup policy.
    fn read_backup_throughput(
        &self,
        operation: &BackupOperation,
        facts: &BackupAcceptedFacts,
    ) -> Result<ThroughputEvidence, Failure> {
        if operation.operation_id != self.operation_id
            || operation.phase != BackupPhase::Planned
            || facts.validate().is_err()
        {
            return Err(unavailable("broker backup worker throughput: unavailable"));
        }
        let request = BackupWorkerThroughputRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
            operation: backup_operation_to_wire(operation),
            accepted_facts: accepted_facts_to_wire(facts),
        };
        let result: super::throughput_journal::ThroughputEvidenceWire = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_WORKER_THROUGHPUT_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup worker throughput: denied"))?;
        let evidence = evidence_from_wire(&result);
        evidence
            .valid_at(OffsetDateTime::now_utc(), &default_recovery_profile())
            .map_err(|_| denied("broker backup worker throughput: denied"))?;
        Ok(evidence)
    }
}

/// `BackupWorkerSealer` — seals the backup manifest through the
/// broker; bound only to the launch evidence (the proposal carries the
/// operation identity).
pub struct BackupWorkerSealer {
    client: LifecycleClient,
    launch_evidence_id: Uuid,
}

impl BackupWorkerSealer {
    /// `NewBackupWorkerSealer`.
    pub fn new(socket_path: PathBuf, launch_evidence_id: Uuid) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
            launch_evidence_id,
        }
    }
}

impl central_backup::port::BackupSealer for BackupWorkerSealer {
    /// `SealBackup` — the broker countersigns the proposal and returns
    /// the seal companion; the client verifies it before trusting it.
    fn seal_backup(&self, proposal: &BackupSealProposal) -> Result<BackupSealCompanion, Failure> {
        if self.launch_evidence_id.is_nil() || proposal.validate().is_err() {
            return Err(unavailable("broker backup seal: unavailable"));
        }
        let request = BackupSealRPCRequest {
            launch_evidence_id: self.launch_evidence_id,
            proposal: seal_proposal_to_wire(proposal),
        };
        let result: super::recovery_journal::BackupSealCompanionWire = self
            .client
            .call_with_operation_id(
                &proposal.operation_id.to_string(),
                BACKUP_SEAL_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup seal: denied"))?;
        let companion =
            seal_companion_from_wire(&result).map_err(|_| denied("broker backup seal: denied"))?;
        companion
            .verify()
            .map_err(|_| denied("broker backup seal: denied"))?;
        Ok(companion)
    }
}

/// `BackupThroughputWorkerAuthority` — the C02 probe worker's broker
/// authority: worker context, target-lock attestation, and staged
/// measurement.
pub struct BackupThroughputWorkerAuthority {
    client: LifecycleClient,
    launch_evidence_id: Uuid,
    operation_id: Uuid,
}

impl BackupThroughputWorkerAuthority {
    /// `NewBackupThroughputWorkerAuthority`.
    pub fn new(socket_path: PathBuf, launch_evidence_id: Uuid, operation_id: Uuid) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
            launch_evidence_id,
            operation_id,
        }
    }

    /// `WorkerContext` — the current launch state for the exact worker.
    ///
    /// # Errors
    /// `denied` on a structurally incomplete binding, transport
    /// failure, or a context that violates the phase invariants.
    pub fn worker_context(&self) -> Result<BackupThroughputWorkerContext, Failure> {
        if self.launch_evidence_id.is_nil() || self.operation_id.is_nil() {
            return Err(denied("broker backup throughput worker: denied"));
        }
        let request = BackupThroughputWorkerIdentityRequest {
            launch_evidence_id: self.launch_evidence_id,
        };
        let result: BackupThroughputWorkerContext = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_THROUGHPUT_WORKER_CONTEXT_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup throughput worker: denied"))?;
        if result.launch_evidence_id != self.launch_evidence_id
            || result.operation_id != self.operation_id
            || result.accepted_at == OffsetDateTime::UNIX_EPOCH
            || !(result.accepted_at < result.deadline)
            || result.static_binding.validate().is_err()
            || !valid_backup_throughput_worker_context(&result)
        {
            return Err(denied("broker backup throughput worker: denied"));
        }
        Ok(result)
    }

    /// `Context` — retained as a narrow alias for adapters that name
    /// their input source by capability rather than worker role.
    pub fn context(&self) -> Result<BackupThroughputWorkerContext, Failure> {
        self.worker_context()
    }

    /// `MarkTargetLocked` — records the probe worker's target-lock
    /// attestation on the broker launch record.
    ///
    /// # Errors
    /// `denied` on an incomplete binding, transport failure, or a
    /// non-committed reply.
    pub fn mark_target_locked(
        &self,
        attestation: &BackupThroughputTargetLockAttestation,
    ) -> Result<(), Failure> {
        if self.launch_evidence_id.is_nil() || self.operation_id.is_nil() {
            return Err(denied("broker backup throughput worker: denied"));
        }
        #[derive(serde::Deserialize)]
        struct LockedResult {
            locked: bool,
        }
        let request = BackupThroughputWorkerTargetRequest {
            launch_evidence_id: self.launch_evidence_id,
            attestation: attestation.clone(),
        };
        let result: LockedResult = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_THROUGHPUT_WORKER_TARGET_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup throughput worker: denied"))?;
        if !result.locked {
            return Err(denied("broker backup throughput worker: denied"));
        }
        Ok(())
    }

    /// `Stage` — publishes the measured throughput evidence for this
    /// exact probe operation.
    ///
    /// # Errors
    /// `denied` on an incomplete binding, a mismatched probe operation,
    /// a zero staged timestamp, transport failure, or a non-committed
    /// reply.
    pub fn stage(
        &self,
        evidence: &ThroughputEvidence,
        staged_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        if self.launch_evidence_id.is_nil()
            || self.operation_id.is_nil()
            || evidence.probe_operation_id != self.operation_id
            || staged_at == OffsetDateTime::UNIX_EPOCH
        {
            return Err(denied("broker backup throughput worker: denied"));
        }
        #[derive(serde::Deserialize)]
        struct StagedResult {
            staged: bool,
        }
        let request = BackupThroughputWorkerStageRequest {
            launch_evidence_id: self.launch_evidence_id,
            evidence: evidence_to_wire(evidence),
            staged_at: staged_at.to_offset(time::UtcOffset::UTC),
        };
        let result: StagedResult = self
            .client
            .call_with_operation_id(
                &self.operation_id.to_string(),
                BACKUP_THROUGHPUT_WORKER_STAGE_RPC,
                &request,
            )
            .map_err(|_| denied("broker backup throughput worker: denied"))?;
        if !result.staged {
            return Err(denied("broker backup throughput worker: denied"));
        }
        Ok(())
    }
}

/// `validBackupThroughputWorkerContext` — the phase-state invariants
/// the worker context must satisfy.
fn valid_backup_throughput_worker_context(result: &BackupThroughputWorkerContext) -> bool {
    match result.phase.as_str() {
        BACKUP_THROUGHPUT_LAUNCH_ACTIVE => {
            result.target_fingerprint.is_empty()
                && result.fixture_load_elapsed.is_zero()
                && result.provision_receipt_binding.is_empty()
        }
        BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED => {
            result
                .static_binding
                .with_target_fingerprint(&result.target_fingerprint)
                .is_ok()
                && result.fixture_load_elapsed.is_zero()
                && result.provision_receipt_binding.is_empty()
        }
        BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED | BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED => {
            result
                .static_binding
                .with_target_fingerprint(&result.target_fingerprint)
                .is_ok()
                && result.fixture_load_elapsed.is_positive()
                && wire::valid_prefixed_sha256(&result.provision_receipt_binding)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_backup::backup::operation::{new_backup_accepted_facts, new_backup_operation};
    use central_backup::domain::TargetIdentity;
    use central_backup::port::BackupSealer;
    use central_backup::recovery::profile::{
        BACKUP_THROUGHPUT_RECEIPT_SCHEMA, ThroughputEvidenceBinding,
    };
    use central_foundation::failure::FailureKind;

    fn fp(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16400".into(),
            database: "central".into(),
            config_hash: fp(0x30),
            epoch: 7,
        }
    }

    fn operation(operation_id: Uuid) -> BackupOperation {
        new_backup_operation(operation_id, Uuid::now_v7(), target(), now()).unwrap()
    }

    fn facts() -> BackupAcceptedFacts {
        new_backup_accepted_facts(
            now(),
            &fp(0x31),
            &fp(0x32),
            Uuid::now_v7(),
            Uuid::now_v7(),
            &fp(0x33),
        )
        .unwrap()
    }

    fn binding() -> ThroughputEvidenceBinding {
        ThroughputEvidenceBinding {
            instance_id: Uuid::now_v7(),
            payload_epoch_id: Uuid::now_v7(),
            target_fingerprint: fp(0x11),
            repository_binding_id: Uuid::now_v7(),
            device_mount_set_digest: fp(0x22),
            host_profile_digest: fp(0x23),
            dependency_provisioning_digest: fp(0x24),
            postgres_image_digest: fp(0x25),
            minio_image_digest: fp(0x26),
            pg_dump_tool_digest: fp(0x27),
            pg_dump_tool_version: "16.14".into(),
            config_digest: fp(0x28),
            minio_backup_policy_digest: fp(0x29),
            fixture_digest: fp(0x2a),
            transfer_envelope_version: "central.backup-transfer-envelope/v1".into(),
            transfer_envelope_digest: fp(0x2b),
        }
    }

    fn evidence(probe_operation_id: Uuid) -> ThroughputEvidence {
        let t = now();
        ThroughputEvidence {
            schema_version: BACKUP_THROUGHPUT_RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::now_v7(),
            probe_operation_id,
            probe_started_at: t,
            probe_completed_at: t,
            probe_elapsed: time::Duration::seconds(30),
            measured_at: t,
            expires_at: t + time::Duration::hours(1),
            binding: binding(),
            dump_archive_bytes: 1024,
            dump_work_bytes: 2048,
            dump_elapsed: time::Duration::seconds(2),
            fixture_load_elapsed: time::Duration::seconds(1),
            dump_bytes_per_sec: 512,
            object_payload_bytes: 4096,
            object_work_bytes: 3 * 4096,
            object_elapsed: time::Duration::seconds(2),
            object_bytes_per_sec: 2048,
            cleanup_state: "clean".into(),
            cleanup_verified_at: t,
        }
    }

    fn worker_context(phase: &str) -> BackupThroughputWorkerContext {
        let t = now();
        BackupThroughputWorkerContext {
            launch_evidence_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            phase: phase.into(),
            accepted_at: t,
            deadline: t + time::Duration::minutes(5),
            static_binding:
                super::super::backup_throughput_launch::static_backup_throughput_binding(&binding()),
            target_fingerprint: String::new(),
            fixture_load_elapsed: time::Duration::ZERO,
            provision_receipt_binding: String::new(),
        }
    }

    fn journal(socket: &str, evidence_id: Uuid, operation_id: Uuid) -> BackupWorkerJournal {
        BackupWorkerJournal::new(PathBuf::from(socket), evidence_id, operation_id)
    }

    fn assert_kind(result: Result<impl std::fmt::Debug, Failure>, kind: FailureKind, msg: &str) {
        let err = result.unwrap_err();
        assert_eq!(err.kind(), kind, "{err:?}");
        assert_eq!(err.message(), msg, "{err:?}");
    }

    /// Nil launch bindings refuse before dialing — `unavailable` for
    /// journal/epoch, matching upstream's pre-flight gate.
    #[test]
    fn journal_preconditions_refuse_before_dialing() {
        let evidence_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let socket = "/nonexistent/broker.sock";

        assert_kind(
            journal(socket, Uuid::nil(), operation_id).authority(),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
        assert_kind(
            journal(socket, evidence_id, Uuid::nil()).authority(),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
        assert_kind(
            journal(socket, Uuid::nil(), operation_id).active_payload_epoch_id(),
            FailureKind::Unavailable,
            "broker backup worker payload epoch: unavailable",
        );

        let j = journal(socket, evidence_id, operation_id);
        // Wrong operation identity refuses before the wire.
        assert_kind(
            j.create_backup(&operation(Uuid::now_v7())),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
        assert_kind(
            j.read_backup(Uuid::now_v7()),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
        let op = operation(operation_id);
        assert_kind(
            j.compare_and_swap_backup(&operation(Uuid::now_v7()), &op),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
        assert_kind(
            j.compare_and_swap_backup(&op, &operation(Uuid::now_v7())),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
        // A non-planned phase refuses before the wire.
        let mut admitted = op.clone();
        admitted.phase = BackupPhase::Admitted;
        assert_kind(
            j.create_backup(&admitted),
            FailureKind::Unavailable,
            "broker backup worker journal: unavailable",
        );
    }

    /// Throughput reads gate on operation identity, phase, and fact
    /// validity before dialing.
    #[test]
    fn throughput_preconditions_refuse_before_dialing() {
        let operation_id = Uuid::now_v7();
        let j = journal("/nonexistent/broker.sock", Uuid::now_v7(), operation_id);

        assert_kind(
            j.read_backup_throughput(&operation(Uuid::now_v7()), &facts()),
            FailureKind::Unavailable,
            "broker backup worker throughput: unavailable",
        );
        let mut admitted = operation(operation_id);
        admitted.phase = BackupPhase::Admitted;
        assert_kind(
            j.read_backup_throughput(&admitted, &facts()),
            FailureKind::Unavailable,
            "broker backup worker throughput: unavailable",
        );
        assert_kind(
            j.read_backup_throughput(&operation(operation_id), &BackupAcceptedFacts::default()),
            FailureKind::Unavailable,
            "broker backup worker throughput: unavailable",
        );
    }

    /// A valid request still fails closed when no broker answers —
    /// `denied`, never a panic or a partial read.
    #[test]
    fn unreachable_broker_maps_to_denied() {
        let operation_id = Uuid::now_v7();
        let j = journal("/nonexistent/broker.sock", Uuid::now_v7(), operation_id);
        assert_kind(
            j.authority(),
            FailureKind::Denied,
            "broker backup worker journal: denied",
        );
        assert_kind(
            j.active_payload_epoch_id(),
            FailureKind::Denied,
            "broker backup worker payload epoch: denied",
        );
        assert_kind(
            j.read_backup_throughput(&operation(operation_id), &facts()),
            FailureKind::Denied,
            "broker backup worker throughput: denied",
        );
        assert_kind(
            j.create_backup(&operation(operation_id)),
            FailureKind::Denied,
            "broker backup worker journal: denied",
        );
        assert_kind(
            j.read_backup(operation_id),
            FailureKind::Denied,
            "broker backup worker journal: denied",
        );
        let op = operation(operation_id);
        assert_kind(
            j.compare_and_swap_backup(&op, &op),
            FailureKind::Denied,
            "broker backup worker journal: denied",
        );
        assert_kind(
            j.assert_held(),
            FailureKind::Denied,
            "broker backup worker journal: denied",
        );
    }

    /// The sealer refuses nil evidence and invalid proposals before
    /// dialing, and maps an unreachable broker to `denied`.
    #[test]
    fn sealer_preconditions() {
        let proposal = BackupSealProposal {
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: target(),
            accepted_at: now(),
            repository_binding_id: Uuid::now_v7(),
            target_fingerprint: fp(0x31),
            config_fingerprint: fp(0x32),
            payload_epoch_id: Uuid::now_v7(),
            root_manifest_json: b"{}".to_vec(),
            manifest_digest: [0x40; 32],
            file_tree_digest: [0x41; 32],
            proposed_at: now(),
        };
        // Invalid proposals (manifest does not re-parse / identity
        // incomplete) refuse before the wire.
        let sealer = BackupWorkerSealer::new(PathBuf::from("/nonexistent/s"), Uuid::now_v7());
        assert_kind(
            sealer.seal_backup(&proposal),
            FailureKind::Unavailable,
            "broker backup seal: unavailable",
        );
        let nil_sealer = BackupWorkerSealer::new(PathBuf::from("/nonexistent/s"), Uuid::nil());
        assert_kind(
            nil_sealer.seal_backup(&proposal),
            FailureKind::Unavailable,
            "broker backup seal: unavailable",
        );
    }

    /// Throughput-worker calls refuse with `denied` on incomplete
    /// bindings — upstream uses `denied` for every refusal here.
    #[test]
    fn throughput_worker_preconditions() {
        let evidence_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let attestation = BackupThroughputTargetLockAttestation {
            target_fingerprint: fp(0x11),
            target_lock_proof_sha256: [0x44; 32],
            locked_at: now(),
        };
        let nil_auth =
            BackupThroughputWorkerAuthority::new(PathBuf::from("/s"), Uuid::nil(), operation_id);
        assert_kind(
            nil_auth.worker_context(),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
        assert_kind(
            nil_auth.mark_target_locked(&attestation),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
        assert_kind(
            nil_auth.stage(&evidence(operation_id), now()),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );

        let auth = BackupThroughputWorkerAuthority::new(
            PathBuf::from("/nonexistent/s"),
            evidence_id,
            operation_id,
        );
        // Probe operation binding and staged_at refuse before the wire.
        assert_kind(
            auth.stage(&evidence(Uuid::now_v7()), now()),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
        assert_kind(
            auth.stage(&evidence(operation_id), OffsetDateTime::UNIX_EPOCH),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
        // Unreachable broker → denied.
        assert_kind(
            auth.worker_context(),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
        assert_kind(
            auth.mark_target_locked(&attestation),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
        assert_kind(
            auth.stage(&evidence(operation_id), now()),
            FailureKind::Denied,
            "broker backup throughput worker: denied",
        );
    }

    /// `validBackupThroughputWorkerContext` — the exact phase-state
    /// matrix upstream enforces on the decoded worker context.
    #[test]
    fn worker_context_phase_matrix() {
        // `active`: no fingerprint, no fixture elapsed, no receipt.
        let ctx = worker_context(BACKUP_THROUGHPUT_LAUNCH_ACTIVE);
        assert!(valid_backup_throughput_worker_context(&ctx));
        let mut ctx = worker_context(BACKUP_THROUGHPUT_LAUNCH_ACTIVE);
        ctx.target_fingerprint = fp(0x11);
        assert!(!valid_backup_throughput_worker_context(&ctx));
        let mut ctx = worker_context(BACKUP_THROUGHPUT_LAUNCH_ACTIVE);
        ctx.provision_receipt_binding = fp(0x50);
        assert!(!valid_backup_throughput_worker_context(&ctx));

        // `target_locked`: fingerprint must bind against the static
        // binding; elapsed/receipt still empty.
        let mut ctx = worker_context(BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED);
        assert!(!valid_backup_throughput_worker_context(&ctx));
        ctx.target_fingerprint = fp(0x11);
        assert!(valid_backup_throughput_worker_context(&ctx));
        ctx.fixture_load_elapsed = time::Duration::seconds(1);
        assert!(!valid_backup_throughput_worker_context(&ctx));
        let mut ctx = worker_context(BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED);
        ctx.target_fingerprint = "not-a-fingerprint".into();
        assert!(!valid_backup_throughput_worker_context(&ctx));

        // `fixture_loaded`/`measurement_staged`: fingerprint binds,
        // elapsed positive, receipt is a prefixed sha256.
        for phase in [
            BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED,
            BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED,
        ] {
            let mut ctx = worker_context(phase);
            ctx.target_fingerprint = fp(0x11);
            assert!(!valid_backup_throughput_worker_context(&ctx));
            ctx.fixture_load_elapsed = time::Duration::seconds(3);
            ctx.provision_receipt_binding = fp(0x50);
            assert!(valid_backup_throughput_worker_context(&ctx));
            ctx.provision_receipt_binding = "deadbeef".into();
            assert!(!valid_backup_throughput_worker_context(&ctx));
        }

        // Unknown phases refuse.
        let ctx = worker_context("bogus");
        assert!(!valid_backup_throughput_worker_context(&ctx));
    }
}
