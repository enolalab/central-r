//! `server.go` + the R5 slice of `service.go` — the single-threaded
//! protected broker: `Service` composition, `HandleConn`'s
//! marker-dispatched connection handler, `LISTEN_FDS` socket
//! activation, and `Dispatch`'s closed operation matrix.
//!
//! Slice boundary: the B04/B05/B10 secret-bootstrap machinery (the
//! `SecretBootstrap` session, migration/backup/restore launch stores,
//! the MinIO runtime binding store, the recovery journal, the TLS
//! authority) is R6. Every RPC those stores back is registered here as
//! a closed denial so the wire contract — peer gates, marker dispatch,
//! denial codes — is complete and exercised before the R6 internals
//! land. What this slice does implement end-to-end: the lifecycle
//! authorization RPCs, `hmac_fingerprint`, the migration proof and
//! provisioning records, and the descriptor-transport peer gates.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use central_foundation::failure::Failure;
use central_foundation::identity::{HandoffReceiptId, OperationId, SecretBindingId};
use central_infra::authority::{
    B04AdoptRequest, B04AdoptResult, B04IssueProofRequest, B04MaterializeRequest,
    B04MaterializeResult, B05MaterializePostgresMigrationRequest,
    B05MaterializePostgresMigrationResult, B05MigrationLaunchResult, BrokerEvidence, BrokerOutcome,
    BrokerRequest, BrokerResponse, LifecycleAuthorization, LifecycleAuthorizationRequest,
    ProtectedGeneration,
};
use central_infra::domain::{
    AdoptRequest, HandoffReceipt, HandoffRequest, MigrationLaunchBinding, Purpose,
};
use central_infra::port::LeafSignRequest;
use serde::Deserialize;
use time::OffsetDateTime;
use zeroize::Zeroize as _;

use crate::sys::peercred::{PeerCred, peercred};

use super::backup_launch::BackupLaunchStore;
use super::backup_throughput_launch::BackupThroughputLaunchStore;
use super::bootstrap_session::{self, BootstrapSession};
use super::handoff::{self, HandoffService};
use super::journal::Journal;
use super::lifecycle::LifecycleNonceStore;
use super::migration_launch::{MigrationLaunchOutcomeState, MigrationLaunchStore};
use super::payload_epoch::PayloadEpochStore;
use super::proof::{self, ProofService};
use super::protected_file::ProtectedFileBackend;
use super::protocol::{self, *};
use super::provisioning::{
    self, ProvisioningRecord, ProvisioningStore, ReplaceProvisioningRecordRequest,
};
use super::recovery_journal::RecoveryJournalStore;
use super::restore_launch::RestoreLaunchStore;
use super::secret_bootstrap::SecretBootstrap;
use super::signing::{Ed25519Signer, SigningService};
use super::throughput_journal::ThroughputJournalStore;
use super::tls::TlsAuthority;

/// `brokerConnectionDeadline` — one second; bounds the initial framed
/// exchange and every pre-authentication denial.
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(1);

/// `migrationRPCDenied` — upstream never fills `Evidence.OperationID`:
/// the field is `""` on every denial wire.
fn migration_denied(operation_id: &str, message: impl Into<String>) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: BrokerOutcome::Denied,
        result: None,
        evidence: BrokerEvidence {
            operation_id: String::new(),
            code: String::new(),
            message: message.into(),
        },
    }
}

/// `migrationRPCDeniedWithCode`.
fn migration_denied_with_code(
    operation_id: &str,
    code: &str,
    message: impl Into<String>,
) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: BrokerOutcome::Denied,
        result: None,
        evidence: BrokerEvidence {
            operation_id: String::new(),
            code: code.into(),
            message: message.into(),
        },
    }
}

/// `backupRPCDenied` — `Code` and `Message` both carry the denial code.
pub(crate) fn backup_denied(operation_id: &str, code: &str) -> BrokerResponse {
    migration_denied_with_code(operation_id, code, code)
}

/// A success response carrying `result`.
pub(crate) fn success(
    operation_id: &str,
    result: Box<serde_json::value::RawValue>,
) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: BrokerOutcome::Success,
        result: Some(result),
        evidence: BrokerEvidence::default(),
    }
}

/// Upstream's `json.Marshal(result)` embedded verbatim in
/// `BrokerResponse.Result`: typed structs marshal in declaration order
/// (Go's field order), while `serde_json::json!` literals keep their
/// already-sorted map order — identical to the former `to_value` path.
/// A marshal failure degrades to JSON `null`, the same shape the old
/// `to_value(..).unwrap_or_default()` call sites produced.
fn marshal_result<T: serde::Serialize + ?Sized>(value: &T) -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(value).unwrap_or_else(|_| {
        serde_json::value::RawValue::from_string("null".to_owned())
            .unwrap_or_else(|_| unreachable!("null is valid JSON"))
    })
}

/// `BrokerError` outcome — upstream's non-denial failure class
/// (`sign_leaf` is the R5 arm that emits it).
fn error_response(operation_id: &str, message: impl Into<String>) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: BrokerOutcome::Error,
        result: None,
        evidence: BrokerEvidence {
            operation_id: String::new(),
            code: String::new(),
            message: message.into(),
        },
    }
}

/// `Service` — aggregates the broker sub-components, including the R6
/// authority stores (recovery journal, backup/throughput/restore
/// launch stores, payload-epoch chain, throughput journal) that the
/// live dispatch arms in `backup_authority`/`recovery_authority` use.
pub struct Service {
    /// The protected-state root (`0700`, broker-owned).
    pub root_path: PathBuf,
    /// The protected generation/value backend.
    pub backend: ProtectedFileBackend,
    /// The persistent HMAC identity.
    pub(crate) signing: Arc<SigningService>,
    /// The Ed25519 external-verifiability signer.
    pub signer: Option<Arc<Ed25519Signer>>,
    /// The broker's local TLS certificate authority (`s.tls`).
    pub tls: Option<TlsAuthority>,
    /// The authority-transition journal (`journal.RootPath` is the
    /// protected root's parent, upstream's `filepath.Dir(rootPath)`).
    pub journal: Option<Arc<Journal>>,
    /// The durable lifecycle nonce tombstones.
    pub(crate) nonces: Option<LifecycleNonceStore>,
    /// The provisioning record store.
    pub provisioning: Option<ProvisioningStore>,
    /// The proof service.
    pub proofs: Option<ProofService>,
    /// The payload epoch store (`s.payloadEpochs`) — shared with the
    /// throughput launch store, hence the `Arc`.
    pub payload_epochs: Option<Arc<PayloadEpochStore>>,
    /// The protected recovery/backup operation journal
    /// (`s.recoveryJournal`).
    pub recovery_journal: Option<Arc<RecoveryJournalStore>>,
    /// Backup worker launch evidence (`s.backupLaunches`).
    pub backup_launches: Option<BackupLaunchStore>,
    /// Restore engine launch evidence (`s.restoreLaunches`).
    pub restore_launches: Option<RestoreLaunchStore>,
    /// The C02 throughput journal (`s.throughput`).
    pub throughput: Option<Arc<ThroughputJournalStore>>,
    /// The throughput probe launch store (`s.throughputLaunches`).
    pub throughput_launches: Option<BackupThroughputLaunchStore>,
    /// The sealed-memfd handoff factory (`s.handoff` — outbound
    /// descriptor minting; the inbound B04 transport uses the
    /// `handoff` module's free functions directly).
    pub handoff: HandoffService,
    /// The durable B04 secret-bootstrap session (`s.bootstrap`).
    pub bootstrap: Option<SecretBootstrap>,
    /// The persistent bootstrap-candidate session
    /// (`s.bootstrapSession`).
    pub bootstrap_session: Option<BootstrapSession>,
    /// The migration launch evidence/outcome store (`s.launches`).
    pub launches: Option<MigrationLaunchStore>,
    /// The central runtime UID `isRuntimeOrRootPeer` widens to (ADR
    /// 0013).
    pub runtime_uid: u32,
    /// `bootstrapMu` — guards `bootstraps`/`bootstrap_value`.
    pub(crate) bootstrap_mu: Mutex<ServiceBootstrapState>,
}

/// The bootstrap cache the mutex covers.
pub(crate) struct ServiceBootstrapState {
    /// `bootstrap.<purpose>.<instance>` → generation.
    pub bootstraps: BTreeMap<String, ProtectedGeneration>,
    /// `bootstrapValue` — the one-use staged bootstrap value held only
    /// in broker memory until `present_bootstrap` consumes it.
    pub bootstrap_value: Vec<u8>,
}

impl Service {
    /// `NewService` — persistent signing identity, persistent TLS
    /// authority, journal rooted at `root_path`'s parent (upstream
    /// `filepath.Dir(rootPath)`), protected backend, nonce store, the
    /// durable secret-bootstrap session, provisioning store,
    /// persistent proof service, the bootstrap-candidate session, and
    /// the payload-epoch store.
    ///
    /// # Errors
    /// Any sub-component's `new_*` error — signing identity, TLS
    /// authority, nonce root, bootstrap recovery, proof state, epoch
    /// root.
    pub fn new(root_path: PathBuf, runtime_uid: u32) -> Result<Self, Failure> {
        let signing = Arc::new(SigningService::new_persistent(&root_path)?);
        let tls = Some(TlsAuthority::new_persistent(&root_path)?);
        let signer = Some(Arc::new(Ed25519Signer::new()?));
        let nonces = Some(LifecycleNonceStore::new(&root_path)?);
        let backend = ProtectedFileBackend::new(root_path.clone());
        let journal_root = root_path
            .parent()
            .map_or_else(|| root_path.clone(), PathBuf::from);
        let journal = Arc::new(Journal::new(journal_root, signing.clone(), signer.clone()));
        let handoff = HandoffService::new();
        let bootstrap = Some(SecretBootstrap::new(
            root_path.clone(),
            backend.clone(),
            journal.clone(),
            signing.clone(),
        )?);
        let provisioning = Some(ProvisioningStore::new(
            root_path.clone(),
            Some(journal.clone()),
        ));
        let proofs = Some(proof::new_persistent_proof_service(
            &root_path,
            SigningService::from_key(signing.key_copy()),
            Some(journal.clone()),
        )?);
        let bootstrap_session = Some(BootstrapSession::new_persistent(&root_path)?);
        let payload_epochs = Some(super::payload_epoch::new_payload_epoch_store(
            &root_path,
            SigningService::from_key(signing.key_copy()),
        )?);
        let launches = Some(MigrationLaunchStore::new(&root_path, signing.clone())?);
        // R6 stores (`newServiceWithHelperExecutable`): the protected
        // recovery journal, then every store bound to it.
        let recovery_journal = Arc::new(RecoveryJournalStore::new(
            &root_path,
            signing.clone(),
            backend.clone(),
        )?);
        // `runtimeGID := os.Getgid()` unless the runtime is the pinned
        // central UID — then the pairing is the fixed 501/501.
        let runtime_gid = if runtime_uid == CENTRAL_RUNTIME_UID {
            CENTRAL_RUNTIME_UID
        } else {
            rustix::process::getgid().as_raw()
        };
        let backup_launches = Some(BackupLaunchStore::new(
            &root_path,
            signing.clone(),
            recovery_journal.clone(),
            runtime_uid,
            runtime_gid,
        )?);
        let throughput = Arc::new(ThroughputJournalStore::new(
            &root_path,
            signing.clone(),
            central_backup::backup::capacity::default_recovery_profile(),
        )?);
        let payload_epochs = Arc::new(
            payload_epochs
                .ok_or_else(|| Failure::internal("broker", "payload epoch store unavailable"))?,
        );
        let throughput_launches = Some(BackupThroughputLaunchStore::new(
            &root_path,
            signing.clone(),
            recovery_journal.clone(),
            throughput.clone(),
            payload_epochs.clone(),
            runtime_uid,
            runtime_gid,
        )?);
        let restore_launches = Some(RestoreLaunchStore::new(
            &root_path,
            signing.clone(),
            recovery_journal.clone(),
        )?);
        Ok(Self {
            root_path,
            backend,
            signing,
            signer,
            tls,
            journal: Some(journal),
            nonces,
            provisioning,
            proofs,
            payload_epochs: Some(payload_epochs),
            recovery_journal: Some(recovery_journal),
            backup_launches,
            restore_launches,
            throughput: Some(throughput),
            throughput_launches,
            handoff,
            bootstrap,
            bootstrap_session,
            launches,
            runtime_uid,
            bootstrap_mu: Mutex::new(ServiceBootstrapState {
                bootstraps: BTreeMap::new(),
                bootstrap_value: Vec::new(),
            }),
        })
    }

    /// A service over pre-built components — the test seam upstream
    /// exercises through package-internal construction.
    #[allow(clippy::too_many_arguments)]
    pub fn compose(
        root_path: PathBuf,
        backend: ProtectedFileBackend,
        signing: Arc<SigningService>,
        signer: Option<Arc<Ed25519Signer>>,
        tls: Option<TlsAuthority>,
        journal: Option<Arc<Journal>>,
        nonces: Option<LifecycleNonceStore>,
        provisioning: Option<ProvisioningStore>,
        proofs: Option<ProofService>,
        payload_epochs: Option<Arc<PayloadEpochStore>>,
        recovery_journal: Option<Arc<RecoveryJournalStore>>,
        backup_launches: Option<BackupLaunchStore>,
        restore_launches: Option<RestoreLaunchStore>,
        throughput: Option<Arc<ThroughputJournalStore>>,
        throughput_launches: Option<BackupThroughputLaunchStore>,
        handoff: HandoffService,
        bootstrap: Option<SecretBootstrap>,
        bootstrap_session: Option<BootstrapSession>,
        launches: Option<MigrationLaunchStore>,
        runtime_uid: u32,
    ) -> Self {
        Self {
            root_path,
            backend,
            signing,
            signer,
            tls,
            journal,
            nonces,
            provisioning,
            proofs,
            payload_epochs,
            recovery_journal,
            backup_launches,
            restore_launches,
            throughput,
            throughput_launches,
            handoff,
            bootstrap,
            bootstrap_session,
            launches,
            runtime_uid,
            bootstrap_mu: Mutex::new(ServiceBootstrapState {
                bootstraps: BTreeMap::new(),
                bootstrap_value: Vec::new(),
            }),
        }
    }

    // ------------------------------------------------------------------
    // Dispatch — the closed operation matrix (service.go Dispatch)
    // ------------------------------------------------------------------

    /// `Service.Dispatch` — upstream's switch order: bootstrap
    /// presentation, the recovery authority RPCs, migration proofs and
    /// records, the B04/B05 materialization ladder, the ten
    /// transport-required backup purposes, the permanent denials, then
    /// the live B03/B04 arms and bootstrap candidates. Connection-only
    /// purposes upstream never registers here (every other
    /// `HandleConn`-gated RPC) fall to `"unknown purpose"`, exactly as
    /// upstream's `default` — the closed R6 denial remains only for
    /// upstream RPCs this slice deliberately does not port
    /// (`is_r6_purpose`).
    #[must_use]
    pub fn dispatch(&self, req: &BrokerRequest) -> BrokerResponse {
        match req.purpose.as_str() {
            PRESENT_BOOTSTRAP_RPC => self.dispatch_present_bootstrap(req),
            RESTORE_APPLY_AUTHORIZATION_RPC => self.dispatch_restore_apply_authorization(req),
            RESTORE_RESUME_AUTHORIZATION_RPC => self.dispatch_restore_resume_authorization(req),
            RESTORE_ABANDON_AUTHORIZATION_RPC => self.dispatch_restore_abandon_authorization(req),
            RESTORE_ABANDON_RPC => self.dispatch_restore_abandon(req),
            RESTORE_BARRIER_INSPECT_RPC => self.dispatch_restore_barrier_inspect(req),
            RESTORE_TICKET_BARRIER_INSPECT_RPC => self.dispatch_restore_ticket_barrier_inspect(req),
            RESTORE_BROKER_AUTHORITY_PREPARE_RPC | RESTORE_BOOTSTRAP_ACTIVATE_RPC => {
                self.dispatch_recovery_broker_authority_reset(req)
            }
            MIGRATION_ISSUE_EMPTY_PROOF_RPC
            | MIGRATION_VERIFY_EMPTY_PROOF_RPC
            | MIGRATION_CONSUME_EMPTY_PROOF_RPC
            | MIGRATION_ISSUE_RESET_RPC
            | MIGRATION_VERIFY_RESET_RPC
            | MIGRATION_CONSUME_RESET_RPC => self.dispatch_migration_proof(req),
            MIGRATION_READ_RECORD_RPC
            | MIGRATION_CREATE_RECORD_RPC
            | MIGRATION_REPLACE_RECORD_RPC => self.dispatch_migration_provisioning(req),
            // `dispatchMigrationOutcome(req, nil)` — `s.launches == nil`
            // is this slice's permanent state, so upstream's first
            // branch is the whole outcome.
            MIGRATION_READ_OUTCOME_RPC => self.dispatch_migration_outcome(req, None),
            ADOPT_B03_MINIO_BOOTSTRAP_RPC => self.dispatch_b04_adopt(req),
            ISSUE_B04_LIFECYCLE_PROOF_RPC => self.dispatch_b04_issue_proof(req),
            MATERIALIZE_MINIO_ROOT_RPC => migration_denied(
                &req.operation_id,
                "B04_HANDOFF_DENIED: descriptor-only transport required",
            ),
            MATERIALIZE_POSTGRES_MIGRATION_RPC => self.dispatch_b05_materialize_postgres(req),
            MATERIALIZE_MINIO_RUNTIME_RPC => migration_denied(
                &req.operation_id,
                "B10_MINIO_RUNTIME_DENIED: descriptor-only transport required",
            ),
            ISSUE_MIGRATION_LAUNCH_RPC => self.dispatch_b05_issue_migration_launch(req),
            // Upstream's `HandleConn` peer gates intercept these ten
            // before `Dispatch`; the transport-required fallback is what
            // upstream's own `Dispatch` still answers with — code and
            // message are the same string there.
            BACKUP_ISSUE_LAUNCH_RPC
            | BACKUP_SEAL_RPC
            | BACKUP_MARK_REAPED_RPC
            | BACKUP_COMPLETE_RPC
            | BACKUP_VERIFY_SEAL_RPC
            | BACKUP_READ_STATUS_RPC
            | BACKUP_WORKER_CONTEXT_RPC
            | BACKUP_WORKER_CREATE_RPC
            | BACKUP_WORKER_READ_RPC
            | BACKUP_WORKER_CAS_RPC => {
                backup_denied(&req.operation_id, "BACKUP_AUTHORITY_TRANSPORT_REQUIRED")
            }
            CREATE_PROTECTED_GENERATION_RPC => migration_denied(
                &req.operation_id,
                "B04_HANDOFF_DENIED: create_protected_generation is permanently denied",
            ),
            // `sign_leaf` is a live upstream RPC backed by the TLS
            // authority: upstream answers `BrokerError` (not a denial)
            // when signing fails.
            SIGN_LEAF_RPC => self.dispatch_sign_leaf(req),
            HMAC_FINGERPRINT_RPC => self.dispatch_hmac_fingerprint(req),
            AUTHORIZE_LIFECYCLE_RPC => self.dispatch_authorize_lifecycle(req),
            CONSUME_LIFECYCLE_RPC => self.dispatch_consume_lifecycle(req),
            VERIFY_LIFECYCLE_LOCK_OWNER_RPC => self.dispatch_verify_lock_owner(req),
            MATERIALIZE_DEPENDENCY_HANDOFF_RPC => migration_denied(
                &req.operation_id,
                "B04_HANDOFF_DENIED: legacy pathname handoff is disabled",
            ),
            REGISTER_BOOTSTRAP_CANDIDATE_RPC | ACTIVATE_BOOTSTRAP_CANDIDATE_RPC => {
                self.dispatch_bootstrap_candidate(req)
            }
            // Upstream RPCs this slice deliberately does not port get
            // the closed denial; every other unregistered name is
            // upstream's `default` — `"unknown purpose"` (this includes
            // the connection-only backup/throughput/payload-epoch and
            // restore-launch purposes, which `HandleConn` serves).
            _ if protocol::is_r6_purpose(&req.purpose) => migration_denied(
                &req.operation_id,
                format!("BROKER_AUTHORITY_DENIED: {}", UNSUPPORTED_IN_THIS_SLICE),
            ),
            _ => migration_denied(&req.operation_id, "unknown purpose"),
        }
    }

    fn payload_request<'a>(
        &self,
        req: &'a BrokerRequest,
    ) -> Option<&'a serde_json::value::RawValue> {
        req.payload.as_ref()?.get("request").map(Box::as_ref)
    }

    /// `dispatchSignLeaf` — `sign_leaf`'s upstream arm: the payload's
    /// `request` decodes into `LeafSignRequest` (Go's `json.Unmarshal`
    /// error is ignored — a malformed request becomes the zero request
    /// and the authority itself rejects the empty key). Signer errors
    /// surface as `BrokerError`, not a denial.
    fn dispatch_sign_leaf(&self, req: &BrokerRequest) -> BrokerResponse {
        /// `port.LeafSignRequest`'s wire form — `public_key` is Go's
        /// `[]byte` standard-base64 JSON string.
        #[derive(Deserialize, Default)]
        struct LeafSignWire {
            #[serde(default, with = "super::wire::b64")]
            public_key: Vec<u8>,
            #[serde(default)]
            not_after: i64,
        }
        let wire_req: LeafSignWire = req
            .payload
            .as_ref()
            .and_then(|p| p.get("request"))
            .map(|r| serde_json::from_str(r.get()).unwrap_or_default())
            .unwrap_or_default();
        let Some(tls) = &self.tls else {
            return error_response(&req.operation_id, "broker: TLS authority unavailable");
        };
        match tls.sign_leaf(&LeafSignRequest {
            public_key: wire_req.public_key,
            not_after: wire_req.not_after,
        }) {
            Err(e) => error_response(&req.operation_id, e.message().to_owned()),
            // `port.LeafCertificate` marshals PascalCase upstream (no
            // Go tags): `{"Raw":"<std b64>","Fingerprint":"…"}`.
            Ok(leaf) => success(
                &req.operation_id,
                marshal_result(&serde_json::json!({
                    "Raw": super::wire::b64_encode(&leaf.raw),
                    "Fingerprint": leaf.fingerprint,
                })),
            ),
        }
    }

    /// `dispatchBootstrapCandidate` — `register_bootstrap_candidate` /
    /// `activate_bootstrap_candidate`: the closed candidate decoder,
    /// then the persistent session's register/activate. Upstream
    /// signals every failure as code `AUTHORITY_DENIED` with no
    /// message.
    fn dispatch_bootstrap_candidate(&self, req: &BrokerRequest) -> BrokerResponse {
        let denied = || BrokerResponse {
            operation_id: req.operation_id.clone(),
            outcome: BrokerOutcome::Denied,
            result: None,
            evidence: BrokerEvidence {
                operation_id: String::new(),
                code: "AUTHORITY_DENIED".to_owned(),
                message: String::new(),
            },
        };
        let Ok(binding) = bootstrap_session::decode_candidate_binding(req.payload.as_ref()) else {
            return denied();
        };
        let Some(session) = &self.bootstrap_session else {
            return denied();
        };
        let result = if req.purpose == REGISTER_BOOTSTRAP_CANDIDATE_RPC {
            session.register(&binding)
        } else {
            session.activate(&binding)
        };
        match result {
            Err(_) => denied(),
            Ok(()) => BrokerResponse {
                operation_id: req.operation_id.clone(),
                outcome: BrokerOutcome::Success,
                result: None,
                evidence: BrokerEvidence::default(),
            },
        }
    }

    /// `presentBootstrap` — the one-use staged value leaves broker
    /// memory as the response's `{"value": <raw-std-b64>}`. An empty
    /// in-memory stage first falls back to
    /// `recoveryJournal.takeActivatedRecoveryBootstrap`, exactly as
    /// upstream `service.go`, and denies `BOOTSTRAP_NOT_STAGED` only
    /// when that journal take also fails.
    fn dispatch_present_bootstrap(&self, req: &BrokerRequest) -> BrokerResponse {
        let mut value = match self.bootstrap_lock() {
            Ok(mut guard) => {
                let value = guard.bootstrap_value.clone();
                if !guard.bootstrap_value.is_empty() {
                    guard.bootstrap_value.zeroize();
                    guard.bootstrap_value = Vec::new();
                }
                value
            }
            Err(_) => Vec::new(),
        };
        // Upstream falls back to `recoveryJournal.takeActivatedRecoveryBootstrap`
        // before reporting an empty stage: the journal's one-use take
        // preserves the same semantics and the same denial on failure.
        if value.is_empty()
            && let Some(journal) = &self.recovery_journal
        {
            value = journal
                .take_activated_recovery_bootstrap()
                .unwrap_or_default();
        }
        if value.is_empty() {
            return BrokerResponse {
                operation_id: req.operation_id.clone(),
                outcome: BrokerOutcome::Denied,
                result: None,
                evidence: BrokerEvidence {
                    operation_id: String::new(),
                    code: "BOOTSTRAP_NOT_STAGED".to_owned(),
                    message: String::new(),
                },
            };
        }
        // `defer zeroBytes(value)` — the plaintext staging buffer is
        // scrubbed after the response is built.
        let result =
            marshal_result(&serde_json::json!({"value": super::wire::b64_raw_encode(&value)}));
        value.zeroize();
        success(&req.operation_id, result)
    }

    /// `StageBootstrapValue` — the protected bootstrap installation
    /// flow's in-memory hand to `present_bootstrap`. The value is held
    /// only under `bootstrapMu` until the one-use presentation RPC;
    /// bounds `0 < len <= 4096`, exactly as upstream.
    ///
    /// # Errors
    /// `broker` denied when `value` is empty or exceeds 4096 bytes.
    pub fn stage_bootstrap_value(&self, value: &[u8]) -> Result<(), Failure> {
        if value.is_empty() || value.len() > 4096 {
            return Err(Failure::denied(
                "broker",
                "broker: bootstrap value out of bounds",
            ));
        }
        let mut guard = self.bootstrap_lock()?;
        guard.bootstrap_value = value.to_vec();
        Ok(())
    }

    /// `dispatchB04Adopt` — `adopt_b03_minio_bootstrap`'s upstream
    /// validation ladder, ending in the real
    /// `s.bootstrap.AdoptB03`.
    fn dispatch_b04_adopt(&self, req: &BrokerRequest) -> BrokerResponse {
        const CLASS: &str = "B04_HANDOFF_DENIED: ";
        let Some(payload) = req.payload.as_ref() else {
            return migration_denied(&req.operation_id, format!("{CLASS}empty payload"));
        };
        let Some(raw) = payload.get("request") else {
            return migration_denied(&req.operation_id, format!("{CLASS}missing request field"));
        };
        let wire: B04AdoptRequest = match serde_json::from_str(raw.get()) {
            Ok(w) => w,
            Err(_) => {
                return migration_denied(&req.operation_id, format!("{CLASS}invalid request"));
            }
        };
        if wire.purpose != "minio_root_v1" {
            return migration_denied(&req.operation_id, format!("{CLASS}unsupported purpose"));
        }
        if wire.fencing_token == 0
            || wire.stopped_topology_proof.is_empty()
            || wire.mount_release_proof.is_empty()
            || wire.binding_evidence.is_empty()
            || super::wire::is_go_zero_time(wire.evidence_expires_at)
            || wire.evidence_expires_at <= OffsetDateTime::now_utc()
        {
            return migration_denied(
                &req.operation_id,
                format!("{CLASS}missing lifecycle evidence"),
            );
        }
        let Some(bootstrap) = &self.bootstrap else {
            return migration_denied(
                &req.operation_id,
                format!("{CLASS}{UNSUPPORTED_IN_THIS_SLICE}"),
            );
        };
        // `s.bootstrap.VerifyLifecycleProof` — the caller's evidence
        // must match a broker-issued, unexpired proof.
        if let Err(e) = bootstrap.verify_lifecycle_proof(
            &wire.instance_id,
            wire.fencing_token,
            &wire.stopped_topology_proof,
            &wire.mount_release_proof,
            &wire.binding_evidence,
            wire.evidence_expires_at,
        ) {
            return migration_denied(&req.operation_id, format!("{CLASS}{}", e.message()));
        }
        // Upstream `uuid.FromString` accepts any UUID version; the
        // domain newtype's strict v7 parse is reached only through
        // `from_trusted_db_bytes` after the wire-shape check — the
        // nil-UUID rejection stays in `AdoptRequest::validate`.
        let Ok(op_uuid) = uuid::Uuid::parse_str(&wire.operation_id) else {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid operation id"));
        };
        let adopt_req = AdoptRequest {
            instance_id: wire.instance_id,
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::from_trusted_db_bytes(*op_uuid.as_bytes()),
            fencing_token: wire.fencing_token,
        };
        match bootstrap.adopt_b03(&adopt_req) {
            Err(e) => migration_denied(&req.operation_id, format!("{CLASS}{}", e.message())),
            Ok((binding, outcome)) => success(
                &req.operation_id,
                marshal_result(&B04AdoptResult {
                    binding_id: binding.binding_id.to_string(),
                    generation_id: binding.generation_id.to_string(),
                    outcome: outcome.as_str().to_owned(),
                    ..B04AdoptResult::default()
                }),
            ),
        }
    }

    /// `dispatchB04IssueProof` — `issue_b04_lifecycle_proof`'s ladder,
    /// ending in the real `s.bootstrap.IssueLifecycleProof` (SC-DEF-12:
    /// the broker durably signs the caller's stopped-topology /
    /// mount-release / binding tokens so a later adopt has a
    /// broker-issued record to verify against).
    fn dispatch_b04_issue_proof(&self, req: &BrokerRequest) -> BrokerResponse {
        const CLASS: &str = "B04_PROOF_DENIED: ";
        let Some(payload) = req.payload.as_ref() else {
            return migration_denied(&req.operation_id, format!("{CLASS}empty payload"));
        };
        let Some(raw) = payload.get("request") else {
            return migration_denied(&req.operation_id, format!("{CLASS}missing request field"));
        };
        let wire: B04IssueProofRequest = match serde_json::from_str(raw.get()) {
            Ok(w) => w,
            Err(_) => {
                return migration_denied(&req.operation_id, format!("{CLASS}invalid request"));
            }
        };
        if wire.fencing_token == 0
            || wire.stopped_topology_proof.is_empty()
            || wire.mount_release_proof.is_empty()
            || wire.binding_evidence.is_empty()
            || super::wire::is_go_zero_time(wire.evidence_expires_at)
            || wire.evidence_expires_at <= OffsetDateTime::now_utc()
        {
            return migration_denied(&req.operation_id, format!("{CLASS}incomplete evidence"));
        }
        let Ok(op_uuid) = uuid::Uuid::parse_str(&wire.operation_id) else {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid operation id"));
        };
        let Some(bootstrap) = &self.bootstrap else {
            return migration_denied(
                &req.operation_id,
                format!("{CLASS}{UNSUPPORTED_IN_THIS_SLICE}"),
            );
        };
        // lockID is passed as the operation ID: IssueLifecycleProof uses
        // it only for idempotent re-issue detection on retry within the
        // same operation, never for verification.
        match bootstrap.issue_lifecycle_proof(
            &wire.instance_id,
            OperationId::from_trusted_db_bytes(*op_uuid.as_bytes()),
            &wire.operation_id,
            "",
            "",
            wire.fencing_token,
            &wire.stopped_topology_proof,
            &wire.mount_release_proof,
            &wire.binding_evidence,
        ) {
            Err(e) => migration_denied(&req.operation_id, format!("{CLASS}{}", e.message())),
            Ok(_) => BrokerResponse {
                operation_id: req.operation_id.clone(),
                outcome: BrokerOutcome::Success,
                result: None,
                evidence: BrokerEvidence::default(),
            },
        }
    }

    /// `dispatchB05MaterializePostgres` — the JSON dispatch path of
    /// `materialize_postgres_migration`. Production B05 materialization
    /// enters through the framed `0xb5` transport; this ladder is
    /// upstream's validation ending in the descriptor-only denial.
    fn dispatch_b05_materialize_postgres(&self, req: &BrokerRequest) -> BrokerResponse {
        const CLASS: &str = "B05_HANDOFF_DENIED: ";
        let Some(payload) = req.payload.as_ref() else {
            return migration_denied(&req.operation_id, format!("{CLASS}empty payload"));
        };
        let Some(raw) = payload.get("request") else {
            return migration_denied(&req.operation_id, format!("{CLASS}missing request field"));
        };
        let wire: B05MaterializePostgresMigrationRequest = match serde_json::from_str(raw.get()) {
            Ok(w) => w,
            Err(_) => {
                return migration_denied(&req.operation_id, format!("{CLASS}invalid request"));
            }
        };
        if wire.service != "central-migrate"
            || wire.target != "scm_rights"
            || wire.uid != CENTRAL_MIGRATE_UID
            || wire.gid != CENTRAL_MIGRATE_GID
        {
            return migration_denied(
                &req.operation_id,
                format!("{CLASS}invalid dependency binding"),
            );
        }
        if uuid::Uuid::parse_str(&wire.binding_id).is_err() {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid binding id"));
        }
        if uuid::Uuid::parse_str(&wire.operation_id).is_err() {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid operation id"));
        }
        migration_denied(
            &req.operation_id,
            format!("{CLASS}descriptor-only transport required"),
        )
    }

    /// `dispatchB05IssueMigrationLaunch` — `issue_migration_launch`'s
    /// ladder: request shape, then upstream's identity checks, then
    /// `s.bootstrap.ActiveBindingForPurpose` — R6, and the denial text
    /// upstream emits when that store has no live binding is exactly
    /// what this slice answers.
    fn dispatch_b05_issue_migration_launch(&self, req: &BrokerRequest) -> BrokerResponse {
        const CLASS: &str = "B05_LAUNCH_DENIED: ";
        // `migrationLaunchIssueRequest` — upstream's private wire shape.
        #[derive(Deserialize)]
        struct IssueRequest {
            #[serde(default)]
            pid: i32,
            #[serde(default)]
            process_start: String,
            #[serde(default)]
            executable: String,
            #[serde(default)]
            mode: String,
            #[serde(default)]
            operation_id: String,
            #[serde(default = "super::wire::go_zero_time", with = "super::wire::rfc3339")]
            expires_at: OffsetDateTime,
        }
        let Some(raw) = req.payload.as_ref().and_then(|p| p.get("request")) else {
            return migration_denied(&req.operation_id, format!("{CLASS}missing request"));
        };
        let issue: IssueRequest = match serde_json::from_str(raw.get()) {
            Ok(w) => w,
            Err(_) => {
                return migration_denied(&req.operation_id, format!("{CLASS}invalid request"));
            }
        };
        if uuid::Uuid::parse_str(&issue.operation_id).is_err()
            || req.operation_id != issue.operation_id
            || issue.pid <= 0
            || issue.executable.is_empty()
            || issue.process_start.is_empty()
            || issue.mode != "migrate"
            || super::wire::is_go_zero_time(issue.expires_at)
            || issue.expires_at <= OffsetDateTime::now_utc()
        {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid launch identity"));
        }
        // `s.bootstrap.ActiveBindingForPurpose` — the live protected
        // binding supplies the lease identity the evidence binds to.
        let Some(bootstrap) = &self.bootstrap else {
            return migration_denied(
                &req.operation_id,
                format!("{CLASS}protected migration binding unavailable"),
            );
        };
        let Ok((protected, lease)) =
            bootstrap.active_binding_for_purpose(Purpose::PostgresMigration)
        else {
            return migration_denied(
                &req.operation_id,
                format!("{CLASS}protected migration binding unavailable"),
            );
        };
        let Some(launches) = &self.launches else {
            return migration_denied(
                &req.operation_id,
                "B05_LAUNCH_ERROR: launch evidence store is unavailable",
            );
        };
        let Ok(op_uuid) = uuid::Uuid::parse_str(&issue.operation_id) else {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid launch identity"));
        };
        let issued = launches.issue(MigrationLaunchBinding {
            launch_evidence_id: String::new(),
            operation_id: OperationId::from_trusted_db_bytes(*op_uuid.as_bytes()),
            binding_id: protected.binding_id,
            fencing_token: lease.fencing_token,
            nonce: Vec::new(),
            peer_uid: CENTRAL_MIGRATE_UID,
            peer_gid: CENTRAL_MIGRATE_GID,
            peer_pid: issue.pid,
            executable: issue.executable,
            mode: issue.mode,
            process_start: issue.process_start,
            deadline: issue.expires_at,
            created_at: OffsetDateTime::now_utc(),
            hmac: String::new(),
        });
        match issued {
            Ok(b) => success(
                &req.operation_id,
                marshal_result(&B05MigrationLaunchResult {
                    operation_id: b.operation_id.to_string(),
                    launch_evidence_id: b.launch_evidence_id,
                }),
            ),
            Err(e) => BrokerResponse {
                operation_id: req.operation_id.clone(),
                outcome: BrokerOutcome::Error,
                result: None,
                evidence: BrokerEvidence {
                    operation_id: String::new(),
                    code: String::new(),
                    message: format!("B05_LAUNCH_ERROR: {}", e.message()),
                },
            },
        }
    }

    /// `validateMigrationAuthorityLaunch` — every migration-authority
    /// RPC from a `central-migrate` peer must carry a consumed launch
    /// evidence bound to the request's operation ID and the peer's
    /// process identity.
    fn validate_migration_authority_launch(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        let Some(launches) = &self.launches else {
            return Err(Failure::denied("broker", "missing launch authority"));
        };
        let Some(payload) = &req.payload else {
            return Err(Failure::denied("broker", "missing launch authority"));
        };
        let Some(raw) = payload.get("launch_evidence_id") else {
            return Err(Failure::denied("broker", "missing launch evidence"));
        };
        let evidence_id = match serde_json::from_str::<String>(raw.get()) {
            Ok(id) if !id.is_empty() => id,
            _ => return Err(Failure::denied("broker", "invalid launch evidence")),
        };
        let binding = launches.load_consumed_and_validate(&evidence_id, peer)?;
        if binding.operation_id.to_string() != req.operation_id {
            return Err(Failure::denied("broker", "launch operation mismatch"));
        }
        Ok(())
    }

    /// `dispatchMigrationOutcome` — report/read the durable launch
    /// outcome. Reads reconcile an unreported consumed launch to
    /// `ambiguous` when the operator died; reports are accepted only
    /// from the validated `central-migrate` peer.
    fn dispatch_migration_outcome(
        &self,
        req: &BrokerRequest,
        peer: Option<&PeerCred>,
    ) -> BrokerResponse {
        let Some(launches) = &self.launches else {
            return migration_denied(&req.operation_id, "migration launch outcomes unavailable");
        };
        let Some(payload) = &req.payload else {
            return migration_denied(&req.operation_id, "migration launch outcomes unavailable");
        };
        let Some(raw) = payload.get("request") else {
            return migration_denied(
                &req.operation_id,
                "missing migration launch outcome request",
            );
        };
        #[derive(Deserialize)]
        struct OutcomeRequest {
            launch_evidence_id: String,
            #[serde(default)]
            state: Option<MigrationLaunchOutcomeState>,
            #[serde(default)]
            reason: Option<String>,
            #[serde(default)]
            operator_result: Option<central_backup::app::MigrationOperatorResult>,
        }
        let request: OutcomeRequest = match serde_json::from_str::<OutcomeRequest>(raw.get()) {
            Ok(r) if !r.launch_evidence_id.is_empty() => r,
            _ => {
                return migration_denied(
                    &req.operation_id,
                    "invalid migration launch outcome request",
                );
            }
        };
        if req.purpose == MIGRATION_READ_OUTCOME_RPC {
            return match launches
                .reconcile_unreported(&request.launch_evidence_id, &req.operation_id)
            {
                Ok(outcome) => success(&req.operation_id, marshal_result(&outcome)),
                Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
            };
        }
        let Some(peer) = peer else {
            return migration_denied(&req.operation_id, "missing migration launch peer");
        };
        let Some(state) = request.state else {
            return migration_denied(&req.operation_id, "invalid reported outcome");
        };
        if let Err(e) = launches.report_outcome(
            &request.launch_evidence_id,
            peer,
            state,
            request.reason.as_deref().unwrap_or(""),
            request.operator_result,
        ) {
            return migration_denied(&req.operation_id, e.message().to_owned());
        }
        match launches.read_outcome(&request.launch_evidence_id, &req.operation_id) {
            Ok(outcome) => success(&req.operation_id, marshal_result(&outcome)),
            Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
        }
    }

    /// `dispatchMigrationProof` — the six migration proof RPCs over the
    /// persistent `ProofService`.
    fn dispatch_migration_proof(&self, req: &BrokerRequest) -> BrokerResponse {
        let Some(proofs) = &self.proofs else {
            return migration_denied(&req.operation_id, "missing migration proof request");
        };
        let Some(raw) = self.payload_request(req) else {
            return migration_denied(&req.operation_id, "missing migration proof request");
        };
        #[derive(Deserialize)]
        struct ProofRequest {
            #[serde(default)]
            issue_empty: Option<proof::IssueEmptyTargetProofRequestWire>,
            #[serde(default)]
            target: Option<super::provisioning::TargetIdentityWire>,
            #[serde(default)]
            proof: Option<proof::VerifiedEmptyTargetWire>,
            #[serde(default)]
            issue_reset: Option<proof::IssueResetConfirmationRequestWire>,
            #[serde(default)]
            reset: Option<proof::ResetConfirmationWire>,
        }
        let request: ProofRequest = match serde_json::from_str(raw.get()) {
            Ok(r) => r,
            Err(_) => {
                return migration_denied(&req.operation_id, "invalid migration proof request");
            }
        };
        let target = request
            .target
            .map(|t| central_backup::domain::TargetIdentity::from(&t))
            .unwrap_or_default();
        match req.purpose.as_str() {
            MIGRATION_ISSUE_EMPTY_PROOF_RPC => {
                let Some(issue) = request.issue_empty else {
                    return migration_denied(
                        &req.operation_id,
                        "operation, target, session, and baseline binding required",
                    );
                };
                if issue.operation_id.to_string() != req.operation_id
                    || issue.target.system_id.is_empty()
                    || issue.baseline_digest.is_empty()
                    || issue.session_binding.backend_start.is_empty()
                    || issue.session_binding.boot_id.is_empty()
                {
                    return migration_denied(
                        &req.operation_id,
                        "operation, target, session, and baseline binding required",
                    );
                }
                let issue_req = central_backup::port::IssueEmptyTargetProofRequest {
                    operation_id: issue.operation_id,
                    target: central_backup::domain::TargetIdentity::from(&issue.target),
                    session_binding: central_backup::domain::SessionBinding::from(
                        &issue.session_binding,
                    ),
                    baseline_digest: issue.baseline_digest,
                };
                match proofs.issue_empty_target_proof(&issue_req) {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(p) => success(
                        &req.operation_id,
                        marshal_result(&proof::VerifiedEmptyTargetWire::from(&p)),
                    ),
                }
            }
            MIGRATION_VERIFY_EMPTY_PROOF_RPC => {
                let Some(p) = request.proof else {
                    return migration_denied(
                        &req.operation_id,
                        "operation and target binding required",
                    );
                };
                if p.operation_id.to_string() != req.operation_id || target.system_id.is_empty() {
                    return migration_denied(
                        &req.operation_id,
                        "operation and target binding required",
                    );
                }
                match proofs.verify_empty_target(
                    &target,
                    &central_backup::domain::VerifiedEmptyTarget::from(&p),
                ) {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(()) => success(
                        &req.operation_id,
                        marshal_result(&serde_json::json!({"verified": true})),
                    ),
                }
            }
            MIGRATION_CONSUME_EMPTY_PROOF_RPC => {
                let Some(p) = request.proof else {
                    return migration_denied(&req.operation_id, "operation binding required");
                };
                if p.operation_id.to_string() != req.operation_id {
                    return migration_denied(&req.operation_id, "operation binding required");
                }
                let proof = central_backup::domain::VerifiedEmptyTarget::from(&p);
                let result = if target.system_id.is_empty() {
                    proofs.consume_empty_proof(&proof)
                } else {
                    proofs.consume_verified_empty_target(&target, &proof)
                };
                match result {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(()) => success(
                        &req.operation_id,
                        marshal_result(&serde_json::json!({"consumed": true})),
                    ),
                }
            }
            MIGRATION_ISSUE_RESET_RPC => {
                let Some(issue) = request.issue_reset else {
                    return migration_denied(
                        &req.operation_id,
                        "operation and target binding required",
                    );
                };
                if issue.operation_id.to_string() != req.operation_id
                    || issue.target_fingerprint.is_empty()
                {
                    return migration_denied(
                        &req.operation_id,
                        "operation and target binding required",
                    );
                }
                let issue_req = central_backup::port::IssueResetConfirmationRequest {
                    operation_id: issue.operation_id,
                    target_fingerprint: issue.target_fingerprint,
                };
                match proofs.issue_reset_confirmation(&issue_req) {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(c) => success(
                        &req.operation_id,
                        marshal_result(&proof::ResetConfirmationWire::from(&c)),
                    ),
                }
            }
            MIGRATION_VERIFY_RESET_RPC => {
                let Some(r) = request.reset else {
                    return migration_denied(
                        &req.operation_id,
                        "operation and target binding required",
                    );
                };
                if r.operation_id.to_string() != req.operation_id || r.target_fingerprint.is_empty()
                {
                    return migration_denied(
                        &req.operation_id,
                        "operation and target binding required",
                    );
                }
                match proofs
                    .verify_reset_confirmation(&central_backup::domain::ResetConfirmation::from(&r))
                {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(()) => success(
                        &req.operation_id,
                        marshal_result(&serde_json::json!({"verified": true})),
                    ),
                }
            }
            MIGRATION_CONSUME_RESET_RPC => {
                let Some(r) = request.reset else {
                    return migration_denied(&req.operation_id, "operation binding required");
                };
                if r.operation_id.to_string() != req.operation_id {
                    return migration_denied(&req.operation_id, "operation binding required");
                }
                let confirmation = central_backup::domain::ResetConfirmation::from(&r);
                let result = if target.system_id.is_empty() {
                    proofs.consume_reset_confirmation(&confirmation)
                } else if confirmation.target_fingerprint
                    != provisioning::target_fingerprint(&target)
                {
                    return migration_denied(&req.operation_id, "target binding mismatch");
                } else {
                    proofs.consume_verified_reset_confirmation(&target, &confirmation)
                };
                match result {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(()) => success(
                        &req.operation_id,
                        marshal_result(&serde_json::json!({"consumed": true})),
                    ),
                }
            }
            _ => migration_denied(&req.operation_id, "unknown migration proof RPC"),
        }
    }

    /// `dispatchMigrationProvisioning` — read/create/replace over the
    /// `ProvisioningStore`.
    fn dispatch_migration_provisioning(&self, req: &BrokerRequest) -> BrokerResponse {
        let Some(store) = &self.provisioning else {
            return migration_denied(&req.operation_id, "missing provisioning request");
        };
        let Some(raw) = self.payload_request(req) else {
            return migration_denied(&req.operation_id, "missing provisioning request");
        };
        #[derive(Deserialize)]
        struct ProvRequest {
            #[serde(default)]
            target: Option<super::provisioning::TargetIdentityWire>,
            #[serde(default)]
            record: Option<ProvisioningRecord>,
            #[serde(default)]
            replace: Option<ReplaceProvisioningRecordRequest>,
        }
        let request: ProvRequest = match serde_json::from_str(raw.get()) {
            Ok(r) => r,
            Err(_) => {
                return migration_denied(&req.operation_id, "invalid provisioning request");
            }
        };
        let target_wire = match request.target {
            Some(t) if !t.system_id.is_empty() => t,
            _ => return migration_denied(&req.operation_id, "invalid provisioning request"),
        };
        let target = central_backup::domain::TargetIdentity::from(&target_wire);
        let succeed =
            |record: &ProvisioningRecord| success(&req.operation_id, marshal_result(record));
        match req.purpose.as_str() {
            MIGRATION_CREATE_RECORD_RPC => {
                let Some(record) = request.record else {
                    return migration_denied(&req.operation_id, "operation binding mismatch");
                };
                if record.operation_id.to_string() != req.operation_id {
                    return migration_denied(&req.operation_id, "operation binding mismatch");
                }
                match store.create_provisioning_record(&target, record) {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(record) => succeed(&record),
                }
            }
            MIGRATION_READ_RECORD_RPC => match store.read_provisioning_record(&target) {
                Err(e) if e.kind() == central_foundation::failure::FailureKind::NotFound => {
                    migration_denied_with_code(
                        &req.operation_id,
                        MIGRATION_RECORD_ABSENT_CODE,
                        e.message().to_owned(),
                    )
                }
                Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                Ok(record) => succeed(&record),
            },
            MIGRATION_REPLACE_RECORD_RPC => {
                let Some(replace) = request.replace else {
                    return migration_denied(&req.operation_id, "operation binding mismatch");
                };
                let replace_target = central_backup::domain::TargetIdentity::from(&replace.target);
                if replace_target != target
                    || replace.next.operation_id.to_string() != req.operation_id
                {
                    return migration_denied(&req.operation_id, "operation binding mismatch");
                }
                match store.read_provisioning_record(&target) {
                    Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                    Ok(current) => {
                        if current.operation_id.to_string() != req.operation_id {
                            return migration_denied(
                                &req.operation_id,
                                "operation binding mismatch",
                            );
                        }
                        match store.replace_provisioning_record(&replace) {
                            Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
                            Ok(record) => succeed(&record),
                        }
                    }
                }
            }
            _ => migration_denied(&req.operation_id, "unknown provisioning RPC"),
        }
    }

    /// `authorize_lifecycle` — decode `payload.request` as the bound
    /// request and issue a one-use authorization.
    fn dispatch_authorize_lifecycle(&self, req: &BrokerRequest) -> BrokerResponse {
        let Some(raw) = self.payload_request(req) else {
            return migration_denied(&req.operation_id, "invalid lifecycle authorization request");
        };
        let request: LifecycleAuthorizationRequest = match serde_json::from_str(raw.get()) {
            Ok(r) => r,
            Err(_) => {
                return migration_denied(
                    &req.operation_id,
                    "invalid lifecycle authorization request",
                );
            }
        };
        match self.authorize_bound_lifecycle(&request) {
            Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
            Ok(claim) => success(&req.operation_id, marshal_result(&claim)),
        }
    }

    /// `consume_lifecycle` — `{claim, request}` under `payload.request`.
    fn dispatch_consume_lifecycle(&self, req: &BrokerRequest) -> BrokerResponse {
        #[derive(Deserialize)]
        struct ConsumeRequest {
            claim: LifecycleAuthorization,
            request: LifecycleAuthorizationRequest,
        }
        let Some(raw) = self.payload_request(req) else {
            return migration_denied(
                &req.operation_id,
                "invalid lifecycle authorization consume request",
            );
        };
        let payload: ConsumeRequest = match serde_json::from_str(raw.get()) {
            Ok(r) => r,
            Err(_) => {
                return migration_denied(
                    &req.operation_id,
                    "invalid lifecycle authorization consume request",
                );
            }
        };
        match self.consume_bound_lifecycle_authorization(&payload.claim, &payload.request) {
            Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
            Ok(()) => BrokerResponse {
                operation_id: req.operation_id.clone(),
                outcome: BrokerOutcome::Success,
                result: None,
                evidence: BrokerEvidence::default(),
            },
        }
    }

    /// `verify_lifecycle_lock_owner` — `{lock_id, owner_pid}`.
    fn dispatch_verify_lock_owner(&self, req: &BrokerRequest) -> BrokerResponse {
        #[derive(Deserialize)]
        struct OwnerRequest {
            lock_id: String,
            owner_pid: i32,
        }
        let Some(raw) = self.payload_request(req) else {
            return migration_denied(
                &req.operation_id,
                "invalid lifecycle lock verification request",
            );
        };
        let request: OwnerRequest = match serde_json::from_str(raw.get()) {
            Ok(r) => r,
            Err(_) => {
                return migration_denied(
                    &req.operation_id,
                    "invalid lifecycle lock verification request",
                );
            }
        };
        match self.verify_dead_owner(&request.lock_id, request.owner_pid) {
            Err(e) => migration_denied(&req.operation_id, e.message().to_owned()),
            // `port.DeadOwnerProof` marshals PascalCase (no Go tags).
            Ok(p) => success(
                &req.operation_id,
                marshal_result(&serde_json::json!({
                    "LockID": p.lock_id,
                    "OwnerPID": p.owner_pid,
                    "Dead": p.dead,
                    "VerifiedAt": super::wire::format_rfc3339_nano(p.verified_at),
                })),
            ),
        }
    }

    /// `hmac_fingerprint` — `{domain, data}` → `{"fingerprint": …}`.
    /// Upstream fingerprints the *raw* `json.RawMessage` bytes of both
    /// values (Go `string(domain)` keeps the JSON quotes and spacing);
    /// `RawValue` passthrough hands over the same bytes verbatim —
    /// never a `Value` re-encoding, which would sort keys and strip
    /// insignificant whitespace before hashing.
    fn dispatch_hmac_fingerprint(&self, req: &BrokerRequest) -> BrokerResponse {
        let domain_raw = req
            .payload
            .as_ref()
            .and_then(|p| p.get("domain"))
            .map_or(&[][..], |v| v.get().as_bytes());
        let data_raw = req
            .payload
            .as_ref()
            .and_then(|p| p.get("data"))
            .map_or(&[][..], |v| v.get().as_bytes());
        let fp = self
            .signing
            .fingerprint(String::from_utf8_lossy(domain_raw).as_ref(), data_raw);
        success(
            &req.operation_id,
            marshal_result(&serde_json::json!({"fingerprint": fp})),
        )
    }

    /// The B04 ACK frame's opaque proof — `b04-ok:` + the
    /// `b04-materialize` fingerprint over the *returned receipt*
    /// (upstream `service.go`'s inline recompute over `receipt`
    /// fields), never over `handoff_req`: the request's `receipt_id`
    /// is minted fresh on every presentation, so on a resume it names
    /// a receipt that was never persisted while the durable record —
    /// and the JSON result's `opaque_token` — carries the persisted
    /// receipt's HMAC. Hashing the receipt keeps the ACK and the
    /// durable record the same identity on first issue and on resume
    /// alike.
    fn materialize_ack_proof(&self, receipt: &HandoffReceipt) -> Vec<u8> {
        let receipt_hmac =
            handoff::compute_materialize_receipt_hmac_for_receipt(&self.signing, receipt);
        let mut opaque_proof = Vec::with_capacity("b04-ok:".len() + receipt_hmac.len());
        opaque_proof.extend_from_slice(b"b04-ok:");
        opaque_proof.extend_from_slice(receipt_hmac.as_bytes());
        opaque_proof
    }

    // ------------------------------------------------------------------
    // Framed transports — B04 is live; B05/B10 remain closed denials
    // ------------------------------------------------------------------

    /// `handleB04MaterializeTransport` — the full B04 materialization
    /// flow in upstream's descriptor-first order:
    ///  1. Receive and validate the FD via SCM_RIGHTS
    ///  2. `ValidateMaterializeRequest` (no plaintext released)
    ///  3. `StartReserved` + `StartWrite`
    ///  4. `ResolveCredential` (plaintext read only after the FD is
    ///     validated)
    ///  5. `WriteValueToDescriptor` + fsync + close
    ///  6. `CompleteBrokerWrite` + send the ACK frame
    ///  7. Read the helper confirmation (`0x03`)
    ///  8. `ConfirmHelperAcknowledged` + `AcknowledgeMaterialization`
    ///  9. Write the JSON response
    ///
    /// The plaintext never appears in the JSON response, a log line,
    /// or a file — only inside the sealed descriptor the peer
    /// supplied.
    #[allow(clippy::too_many_lines)]
    fn handle_b04_materialize_transport(
        &self,
        conn: &mut super::deadline::DeadlineStream,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        const CLASS: &str = "B04_HANDOFF_DENIED: ";
        let deny = |conn: &mut super::deadline::DeadlineStream, msg: String| {
            protocol::write_deny(conn, &req.operation_id, &msg);
        };
        let Some(raw) = req.payload.as_ref().and_then(|p| p.get("request")) else {
            deny(conn, format!("{CLASS}missing request field"));
            return Ok(());
        };
        let wire_req: B04MaterializeRequest = match serde_json::from_str(raw.get()) {
            Ok(w) => w,
            Err(_) => {
                deny(conn, format!("{CLASS}invalid request"));
                return Ok(());
            }
        };
        // The closed dependency binding — `minio`,
        // `/run/secrets/minio-root-password`, owner `1000:1000`.
        if wire_req.service != "minio"
            || wire_req.target != "/run/secrets/minio-root-password"
            || wire_req.uid != 1000
            || wire_req.gid != 1000
        {
            deny(conn, format!("{CLASS}invalid dependency binding"));
            return Ok(());
        }
        if wire_req.peer_uid != peer.uid.as_raw() || wire_req.peer_pid != peer.pid.as_raw_pid() {
            deny(conn, format!("{CLASS}peer identity mismatch"));
            return Ok(());
        }
        let Ok(binding_uuid) = uuid::Uuid::parse_str(&wire_req.binding_id) else {
            deny(conn, format!("{CLASS}invalid binding id"));
            return Ok(());
        };
        let Ok(op_uuid) = uuid::Uuid::parse_str(&wire_req.operation_id) else {
            deny(conn, format!("{CLASS}invalid operation id"));
            return Ok(());
        };
        let Some(bootstrap) = &self.bootstrap else {
            deny(conn, format!("{CLASS}{UNSUPPORTED_IN_THIS_SLICE}"));
            return Ok(());
        };
        let mut handoff_req = HandoffRequest {
            binding_id: SecretBindingId::from_trusted_db_bytes(*binding_uuid.as_bytes()),
            operation_id: OperationId::from_trusted_db_bytes(*op_uuid.as_bytes()),
            receipt_id: HandoffReceiptId::new(),
            receipt_hmac: String::new(),
            fencing_token: wire_req.fencing_token,
            peer_uid: peer.uid.as_raw(),
            peer_pid: peer.pid.as_raw_pid(),
            purpose: Purpose::MinioRoot,
            service: wire_req.service,
            target: wire_req.target,
            uid: wire_req.uid,
            gid: wire_req.gid,
        };
        handoff_req.receipt_hmac = bootstrap.compute_receipt_hmac(&handoff_req);

        // Step 1: receive and validate the destination descriptor
        // before any plaintext is read.
        let fd = match handoff::receive_descriptor(conn) {
            Ok(fd) => fd,
            Err(e) => {
                deny(conn, format!("{CLASS}transport: {}", e.message()));
                return Ok(());
            }
        };

        // Step 2: validate the request (no plaintext released). The
        // returned receipt is the resume-stable record; the optional
        // operation is `None` when an existing receipt answers the
        // retry — the receipt's own `operation_id` still names the
        // operation the state machine advances (upstream binds
        // `op.OperationID`; where `op` is present the two must agree —
        // a divergence would mean the durable binding was forged
        // upstream of this point).
        let (receipt, op) = match bootstrap.validate_materialize_request(&handoff_req) {
            Ok(pair) => pair,
            Err(e) => {
                deny(conn, format!("{CLASS}{}", e.message()));
                return Ok(());
            }
        };
        if let Some(op) = &op {
            debug_assert!(
                op.operation_id == receipt.operation_id,
                "receipt {} names a different operation than op {}",
                receipt.receipt_id,
                op.operation_id
            );
        }

        // Step 3: reserved → write_started.
        if let Err(e) = bootstrap.start_reserved(receipt.operation_id) {
            deny(conn, format!("{CLASS}state: {}", e.message()));
            return Ok(());
        }
        if let Err(e) = bootstrap.start_write(receipt.operation_id) {
            deny(conn, format!("{CLASS}state: {}", e.message()));
            return Ok(());
        }

        // Step 4: resolve the credential — plaintext enters the
        // process only after the descriptor is validated.
        let secret = match bootstrap.resolve_credential(&receipt) {
            Ok(s) => zeroize::Zeroizing::new(s),
            Err(e) => {
                deny(conn, format!("{CLASS}resolve: {}", e.message()));
                return Ok(());
            }
        };

        // Step 5: write the value into the sealed descriptor.
        if let Err(e) = handoff::write_value_to_descriptor(fd, &secret) {
            deny(conn, format!("{CLASS}write: {}", e.message()));
            return Ok(());
        }
        drop(secret); // `defer`-equivalent scrub of the plaintext copy.

        // Step 6: broker write complete → emit the ACK frame.
        if let Err(e) = bootstrap.complete_broker_write(receipt.operation_id) {
            deny(conn, format!("{CLASS}state: {}", e.message()));
            return Ok(());
        }
        let opaque_proof = self.materialize_ack_proof(&receipt);
        // Frame: 0x01 ack marker (1), proof length (2), uid (2),
        // gid (2), opaque proof (N) — upstream's big-endian uint16s.
        let mut frame = Vec::with_capacity(7 + opaque_proof.len());
        frame.push(0x01);
        frame.extend_from_slice(&(opaque_proof.len() as u16).to_be_bytes());
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend_from_slice(&opaque_proof);
        if let Err(e) = conn.write_all(&frame) {
            return Err(Failure::internal(
                "broker",
                format!("B04 transport: write ack: {e}"),
            ));
        }

        // Step 7: read the helper's ownership confirmation (`0x03`).
        let mut confirmation = [0u8; 1];
        if conn.read_exact(&mut confirmation).is_err() || confirmation[0] != 0x03 {
            deny(
                conn,
                format!("{CLASS}helper did not confirm ownership handoff"),
            );
            return Ok(());
        }

        // Step 8: helper acknowledged → acknowledged.
        if let Err(e) = bootstrap.confirm_helper_acknowledged(receipt.operation_id) {
            deny(conn, format!("{CLASS}helper ack: {}", e.message()));
            return Ok(());
        }
        if let Err(e) = bootstrap.acknowledge_materialization(receipt.operation_id) {
            deny(conn, format!("{CLASS}acknowledge: {}", e.message()));
            return Ok(());
        }

        // Step 9: the safe JSON response — identities and the opaque
        // receipt HMAC only, never plaintext.
        let resp = success(
            &req.operation_id,
            marshal_result(&B04MaterializeResult {
                operation_id: receipt.operation_id.to_string(),
                receipt_id: receipt.receipt_id.to_string(),
                binding_id: receipt.binding_id.to_string(),
                opaque_token: receipt.hmac.clone(),
                safe_next_action: String::new(),
            }),
        );
        protocol::write_response(conn, &resp)
    }

    /// `handleB05MaterializeTransport` — the full postgres_migration
    /// materialization flow in descriptor-first order, mirroring B04:
    ///
    /// 1. Receive and validate the destination FD via `SCM_RIGHTS`
    /// 2. `ValidateMaterializeRequest` (no plaintext released)
    /// 3. `StartReserved` + `StartWrite`
    /// 4. `ResolveCredential` (plaintext only after FD validated)
    /// 5. `WriteValueToDescriptor` + fsync + close
    /// 6. `CompleteBrokerWrite` + ACK frame `[0x01|len|986|986|"b05-ok:"+hmac]`
    /// 7. Helper confirmation `0x03`
    /// 8. `ConfirmHelperAcknowledged` + `AcknowledgeMaterialization`
    /// 9. JSON response
    ///
    /// B05 adds the launch-evidence gate up front: `LoadAndConsume`
    /// tombstones the evidence so no second credential can ever be
    /// disclosed for it, `ValidatePeer` re-verifies the operator's
    /// process identity, and `FailConsumed` settles the outcome to
    /// `failed` when any later step cannot complete.
    fn handle_b05_materialize_transport(
        &self,
        conn: &mut super::deadline::DeadlineStream,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        const CLASS: &str = "B05_HANDOFF_DENIED: ";
        macro_rules! deny {
            ($msg:expr) => {{
                protocol::write_deny(conn, &req.operation_id, &format!("{}{}", CLASS, $msg));
                return Ok(());
            }};
        }
        let Some(raw) = req.payload.as_ref().and_then(|p| p.get("request")) else {
            deny!("missing request field");
        };
        let wire_req: B05MaterializePostgresMigrationRequest = match serde_json::from_str(raw.get())
        {
            Ok(w) => w,
            Err(_) => deny!("invalid request"),
        };
        if req.operation_id != wire_req.operation_id {
            deny!("outer operation mismatch");
        }
        if wire_req.service != "central-migrate"
            || wire_req.target != "scm_rights"
            || wire_req.uid != CENTRAL_MIGRATE_UID
            || wire_req.gid != CENTRAL_MIGRATE_GID
        {
            deny!("invalid dependency binding");
        }
        if wire_req.peer_uid != peer.uid.as_raw() || wire_req.peer_pid != peer.pid.as_raw_pid() {
            deny!("peer identity mismatch");
        }
        let Ok(op_uuid) = uuid::Uuid::parse_str(&wire_req.operation_id) else {
            deny!("invalid operation id");
        };
        let op_id = OperationId::from_trusted_db_bytes(*op_uuid.as_bytes());
        let Some(launches) = &self.launches else {
            deny!("launch evidence store is unavailable");
        };
        let Some(bootstrap) = &self.bootstrap else {
            deny!("launch evidence store is unavailable");
        };
        let launch_binding = match launches.load_and_consume(&wire_req.launch_evidence_id) {
            Ok(b) => b,
            Err(e) => deny!(format!("launch evidence: {}", e.message())),
        };
        // From here on, any refusal settles the consumed launch to
        // `failed` — upstream's deferred `FailConsumed`.
        macro_rules! deny_settle {
            ($msg:expr) => {{
                let _ = launches.fail_consumed(
                    &launch_binding,
                    "migration credential materialization failed",
                );
                deny!($msg);
            }};
        }
        if launch_binding.operation_id != op_id {
            deny_settle!("launch evidence operation mismatch");
        }
        if (!wire_req.binding_id.is_empty()
            && wire_req.binding_id != launch_binding.binding_id.to_string())
            || (wire_req.fencing_token != 0
                && wire_req.fencing_token != launch_binding.fencing_token)
        {
            deny_settle!("caller attempted to replace protected binding");
        }
        if let Err(e) = launches.validate_peer(&launch_binding, peer) {
            deny_settle!(format!("launch evidence: {}", e.message()));
        }

        let mut handoff_req = HandoffRequest {
            binding_id: launch_binding.binding_id,
            operation_id: op_id,
            receipt_id: HandoffReceiptId::new(),
            receipt_hmac: String::new(),
            fencing_token: launch_binding.fencing_token,
            peer_uid: peer.uid.as_raw(),
            peer_pid: peer.pid.as_raw_pid(),
            purpose: Purpose::PostgresMigration,
            service: wire_req.service,
            target: wire_req.target,
            uid: wire_req.uid,
            gid: wire_req.gid,
        };
        handoff_req.receipt_hmac = bootstrap.compute_receipt_hmac(&handoff_req);

        // Step 1: receive and validate the destination descriptor
        // before any plaintext is read.
        let fd = match handoff::receive_descriptor(conn) {
            Ok(fd) => fd,
            Err(e) => deny_settle!(format!("transport: {}", e.message())),
        };

        // Step 2: validate the request (no plaintext released).
        let (receipt, op) = match bootstrap.validate_materialize_request(&handoff_req) {
            Ok(pair) => pair,
            Err(e) => deny_settle!(e.message().to_owned()),
        };
        if let Some(op) = &op {
            debug_assert!(
                op.operation_id == receipt.operation_id,
                "receipt {} names a different operation than op {}",
                receipt.receipt_id,
                op.operation_id
            );
        }

        // Step 3: reserved → write_started.
        if let Err(e) = bootstrap.start_reserved(receipt.operation_id) {
            deny_settle!(format!("state: {}", e.message()));
        }
        if let Err(e) = bootstrap.start_write(receipt.operation_id) {
            deny_settle!(format!("state: {}", e.message()));
        }

        // Step 4: resolve the credential — plaintext enters the
        // process only after the descriptor is validated.
        let secret = match bootstrap.resolve_credential(&receipt) {
            Ok(s) => zeroize::Zeroizing::new(s),
            Err(e) => deny_settle!(format!("resolve: {}", e.message())),
        };

        // Step 5: write the value into the descriptor (fd consumed).
        if let Err(e) = handoff::write_value_to_descriptor(fd, &secret) {
            deny_settle!(format!("write: {}", e.message()));
        }
        drop(secret);

        // Step 6: broker write complete → ACK frame.
        if let Err(e) = bootstrap.complete_broker_write(receipt.operation_id) {
            deny_settle!(format!("state: {}", e.message()));
        }
        // `b05-materialize` fingerprint over the returned receipt —
        // uid/gid are the migrate identity.
        let proof_payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            receipt.binding_id,
            receipt.operation_id,
            receipt.receipt_id,
            receipt.purpose.as_str(),
            receipt.peer_uid,
            receipt.peer_pid,
            receipt.service,
            receipt.target,
            receipt.uid,
            receipt.gid
        );
        let receipt_hmac = self
            .signing
            .fingerprint("b05-materialize", proof_payload.as_bytes());
        let mut opaque_proof = Vec::with_capacity("b05-ok:".len() + receipt_hmac.len());
        opaque_proof.extend_from_slice(b"b05-ok:");
        opaque_proof.extend_from_slice(receipt_hmac.as_bytes());
        let mut frame = Vec::with_capacity(7 + opaque_proof.len());
        frame.push(0x01);
        frame.extend_from_slice(&(opaque_proof.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(CENTRAL_MIGRATE_UID as u16).to_be_bytes());
        frame.extend_from_slice(&(CENTRAL_MIGRATE_GID as u16).to_be_bytes());
        frame.extend_from_slice(&opaque_proof);
        if let Err(e) = conn.write_all(&frame) {
            let _ = launches.fail_consumed(
                &launch_binding,
                "migration credential materialization failed",
            );
            return Err(Failure::internal(
                "broker",
                format!("B05 transport: write ack: {e}"),
            ));
        }

        // Step 7: read the helper's ownership confirmation (`0x03`).
        let mut confirmation = [0u8; 1];
        if conn.read_exact(&mut confirmation).is_err() || confirmation[0] != 0x03 {
            deny_settle!("helper did not confirm ownership handoff");
        }

        // Step 8: helper acknowledged → acknowledged.
        if let Err(e) = bootstrap.confirm_helper_acknowledged(receipt.operation_id) {
            deny_settle!(format!("helper ack: {}", e.message()));
        }
        if let Err(e) = bootstrap.acknowledge_materialization(receipt.operation_id) {
            deny_settle!(format!("acknowledge: {}", e.message()));
        }

        // Step 9: the safe JSON response — identities and the opaque
        // receipt HMAC only, never plaintext.
        let resp = success(
            &req.operation_id,
            marshal_result(&B05MaterializePostgresMigrationResult {
                operation_id: receipt.operation_id.to_string(),
                receipt_id: receipt.receipt_id.to_string(),
                binding_id: receipt.binding_id.to_string(),
                opaque_token: receipt.hmac.clone(),
                safe_next_action: String::new(),
            }),
        );
        protocol::write_response(conn, &resp)
    }

    /// `handleB10MinioRuntimeTransport` — the runtime binding store is
    /// R6; the peer gate has already run, so deny closed.
    fn handle_b10_minio_runtime_transport(
        &self,
        conn: &mut super::deadline::DeadlineStream,
        req: &BrokerRequest,
        _peer: &PeerCred,
    ) -> Result<(), Failure> {
        protocol::write_deny(
            conn,
            &req.operation_id,
            "B10_MINIO_RUNTIME_DENIED: protected runtime binding unavailable",
        );
        Ok(())
    }

    /// `handleB10MinioProvisionedTransport` — the provisioner gate is
    /// re-checked here (upstream re-checks in the handler, not just the
    /// dispatch branch); the inbound credential store is R6, so an
    /// authorized peer's frame is read and then denied.
    fn handle_b10_minio_provisioned_transport(
        &self,
        conn: &mut super::deadline::DeadlineStream,
        descriptor: &central_infra::authority::MinioProvisionedDescriptor,
        fd: OwnedFd,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        drop(fd); // exactly one close, on every path
        if !is_minio_provisioner_peer(peer) {
            protocol::write_deny(
                conn,
                &descriptor.operation_id,
                "B10_PROVISION_DENIED: peer credential mismatch",
            );
            return Err(Failure::denied(
                "broker",
                format!(
                    "broker: denied minio-provision peer {}:{}",
                    peer.uid.as_raw(),
                    peer.gid.as_raw()
                ),
            ));
        }
        protocol::write_deny(
            conn,
            &descriptor.operation_id,
            &format!("B10_PROVISION_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HandleConn — the per-connection handler
// ---------------------------------------------------------------------------

/// `HandleConn` — deadline → `SO_PEERCRED` → marker dispatch. A marker
/// byte selects the framed transport; anything else is a JSON line
/// scanned at most [`MAX_REQUEST_LINE`] bytes.
///
/// # Errors
/// `broker` on any protocol violation — the denial is already written
/// to the connection before the error returns.
pub fn handle_conn(conn: std::os::unix::net::UnixStream, svc: &Service) -> Result<(), Failure> {
    // One-second deadline over the framed exchange — upstream's
    // `conn.SetDeadline(now+1s)` runs on Go's epoll netpoller; the
    // port carries it on `fcntl`-set `O_NONBLOCK` + `read`/`write` +
    // a `nanosleep` cadence so every syscall the hardened broker
    // emits is on the seccomp allow-list (ADR 0044 — `SO_RCVTIMEO`,
    // `FIONBIO`, `recvfrom`/`sendto` are not).
    let mut conn = super::deadline::DeadlineStream::new(conn.into(), CONNECTION_DEADLINE)?;

    let peer = match peercred(&conn) {
        Ok(p) => p,
        Err(e) => {
            protocol::write_deny(&mut conn, "unknown", "SO_PEERCRED failed");
            return Err(Failure::internal(
                "broker",
                format!("broker: SO_PEERCRED failed: {}", e.message()),
            ));
        }
    };

    let mut first = [0u8; 1];
    if let Err(e) = conn.read_exact(&mut first) {
        return Err(Failure::internal(
            "broker",
            format!("broker: read request prefix: {e}"),
        ));
    }

    match first[0] {
        B04_FRAME_MARKER => {
            let req =
                match protocol::read_request_frame(&mut conn, "B04", MATERIALIZE_MINIO_ROOT_RPC) {
                    Ok(r) => r,
                    Err(e) => {
                        protocol::write_deny(&mut conn, "unknown", "invalid B04 frame");
                        return Err(e);
                    }
                };
            if !is_runtime_or_root_peer(svc.runtime_uid, &peer) {
                protocol::write_deny(&mut conn, &req.operation_id, "authority denied");
                return Err(Failure::denied(
                    "broker",
                    format!("broker: denied UID {}", peer.uid.as_raw()),
                ));
            }
            svc.handle_b04_materialize_transport(&mut conn, &req, &peer)
        }
        B05_MIGRATION_FRAME_MARKER => {
            let req = match protocol::read_request_frame(
                &mut conn,
                "B05",
                MATERIALIZE_POSTGRES_MIGRATION_RPC,
            ) {
                Ok(r) => r,
                Err(e) => {
                    protocol::write_deny(&mut conn, "unknown", "invalid B05 frame");
                    return Err(e);
                }
            };
            if !is_central_migrate_peer(&peer) {
                protocol::write_deny(&mut conn, &req.operation_id, "authority denied");
                return Err(Failure::denied(
                    "broker",
                    format!(
                        "broker: denied B05 peer {}:{}",
                        peer.uid.as_raw(),
                        peer.gid.as_raw()
                    ),
                ));
            }
            svc.handle_b05_materialize_transport(&mut conn, &req, &peer)
        }
        B10_MINIO_RUNTIME_FRAME_MARKER => {
            let req =
                match protocol::read_request_frame(&mut conn, "B10", MATERIALIZE_MINIO_RUNTIME_RPC)
                {
                    Ok(r) => r,
                    Err(e) => {
                        protocol::write_deny(&mut conn, "unknown", "invalid B10 frame");
                        return Err(e);
                    }
                };
            if !is_minio_runtime_outbound_peer(svc.runtime_uid, &peer) {
                protocol::write_deny(&mut conn, &req.operation_id, "authority denied");
                return Err(Failure::denied(
                    "broker",
                    format!(
                        "broker: denied B10 minio runtime peer {}:{}",
                        peer.uid.as_raw(),
                        peer.gid.as_raw()
                    ),
                ));
            }
            svc.handle_b10_minio_runtime_transport(&mut conn, &req, &peer)
        }
        B10_PROVISIONED_FRAME_MARKER => {
            // Reject before receiving the sealed descriptor: an
            // unauthorized peer must not make the broker allocate an fd
            // or parse a payload on its behalf.
            if !is_minio_provisioner_peer(&peer) {
                protocol::write_deny(&mut conn, "unknown", "authority denied");
                return Err(Failure::denied(
                    "broker",
                    format!(
                        "broker: denied minio-provision peer {}:{}",
                        peer.uid.as_raw(),
                        peer.gid.as_raw()
                    ),
                ));
            }
            match read_b10_provisioned_frame(&conn) {
                Err(e) => {
                    protocol::write_deny(&mut conn, "unknown", "invalid provisioned frame");
                    Err(e)
                }
                Ok((descriptor, fd)) => {
                    svc.handle_b10_minio_provisioned_transport(&mut conn, &descriptor, fd, &peer)
                }
            }
        }
        // R6 framed transports — deny before parsing, with upstream's
        // codes.
        BACKUP_WORKER_CREDENTIAL_FRAME_MARKER => {
            // Upstream `readBackupWorkerCredentialRequest` runs BEFORE
            // the worker peer check: a well-formed frame's denial
            // echoes its `operation_id`, a malformed one denies as
            // `"unknown"` — never vice versa.
            match protocol::read_backup_worker_credential_request(&mut conn) {
                Ok(request) => {
                    // `s.backupLaunches == nil` is upstream's first
                    // closed gate, then the launch store's pinned
                    // runtime UID/GID — the handler re-checks the
                    // worker identity against the launch evidence.
                    let worker_peer = svc.backup_launches.as_ref().is_some_and(|launches| {
                        peer.uid.as_raw() == launches.runtime_uid()
                            && peer.gid.as_raw() == launches.runtime_gid()
                    });
                    if !worker_peer {
                        protocol::write_deny(
                            &mut conn,
                            &request.operation_id.to_string(),
                            "BACKUP_WORKER_CREDENTIAL_DENIED",
                        );
                        return Err(Failure::denied(
                            "broker",
                            "broker: denied backup credential peer",
                        ));
                    }
                    svc.handle_backup_worker_credential_transport(&mut conn, &request, &peer)
                }
                Err(e) => {
                    protocol::write_deny(&mut conn, "unknown", "BACKUP_WORKER_CREDENTIAL_DENIED");
                    Err(e)
                }
            }
        }
        RESTORE_MIGRATION_CREDENTIAL_FRAME_MARKER => {
            // Reject a non-root peer before parsing: the migration
            // credential is never released to the runtime, the backup
            // worker, or the operator.
            if !is_root_backup_helper_peer(&peer) {
                protocol::write_deny(&mut conn, "unknown", "RESTORE_CREDENTIAL_DENIED");
                return Err(Failure::denied(
                    "broker",
                    format!(
                        "broker: denied restore credential peer {}:{}",
                        peer.uid.as_raw(),
                        peer.gid.as_raw()
                    ),
                ));
            }
            match protocol::read_restore_credential_request(&mut conn) {
                Ok(request) => svc.handle_restore_credential_transport(&mut conn, &request, &peer),
                Err(e) => {
                    protocol::write_deny(&mut conn, "unknown", "RESTORE_CREDENTIAL_DENIED");
                    Err(e)
                }
            }
        }
        // Upstream runs these frames' peer predicates inside their
        // handlers — the launch record's helper/engine validation —
        // before any frame body is read (server.go's comments on the
        // 0xc3/0xc4/0xc5 arms). That launch-record machinery is R6;
        // this slice denies every peer with the same `Denied` outcome
        // the predicates produce, and R6 restores the real predicate
        // checks behind this dispatch arm.
        RESTORE_CAPACITY_RESERVE_FRAME_MARKER
        | RESTORE_CAPACITY_RECEIPT_FRAME_MARKER
        | RESTORE_CAPACITY_RESERVE_INSPECTION_FRAME_MARKER => {
            protocol::write_deny(
                &mut conn,
                "unknown",
                &format!("BROKER_AUTHORITY_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
            );
            Err(Failure::denied(
                "broker",
                "broker: unsupported framed transport",
            ))
        }
        _ => {
            // JSON line transport — the first byte is part of the line,
            // exactly like upstream's `io.MultiReader` of `first`+conn.
            let mut line = Vec::with_capacity(256);
            line.push(first[0]);
            {
                // `&DeadlineStream: Read` — no second descriptor is
                // dup'd; the borrow ends before the write half runs.
                let reader = BufReader::with_capacity(MAX_REQUEST_LINE, &conn);
                // Upstream's `bufio.Scanner` aborts once a token passes
                // its 64 KiB buffer — a peer withholding '\n' can never
                // grow it further. `Take` bounds the read side the same
                // way: at most `MAX_REQUEST_LINE + 1` bytes accumulate
                // before the too-long check refuses, instead of
                // `read_until` buffering unboundedly first.
                let mut limited =
                    reader.take((MAX_REQUEST_LINE + 1).saturating_sub(line.len()) as u64);
                match limited.read_until(b'\n', &mut line) {
                    Err(e) => {
                        return Err(Failure::internal(
                            "broker",
                            format!("broker: read request: {e}"),
                        ));
                    }
                    Ok(0) => {
                        return Err(Failure::internal("broker", "broker: empty request"));
                    }
                    Ok(_) => {}
                }
            }
            if line.len() > MAX_REQUEST_LINE {
                return Err(Failure::invalid(
                    "broker",
                    "broker: read request: token too long",
                ));
            }
            let line_trimmed = if line.last() == Some(&b'\n') {
                &line[..line.len() - 1]
            } else {
                &line[..]
            };
            let req = match protocol::decode_broker_request(line_trimmed) {
                Ok(r) => r,
                Err(e) => {
                    protocol::write_deny(&mut conn, "unknown", "invalid request");
                    return Err(e);
                }
            };
            dispatch_json(&mut conn, svc, &req, &peer)
        }
    }
}

/// `readB10ProvisionedFrame` — one `recvmsg` carrying the
/// length-prefixed JSON descriptor AND the sealed memfd as ancillary
/// data; [`DeadlineStream::recv_one`] enforces the single-rights
/// single-fd shape under the connection deadline, then
/// [`crate::sys::memfd::validate_sealed`] proves the descriptor.
fn read_b10_provisioned_frame(
    conn: &super::deadline::DeadlineStream,
) -> Result<
    (
        central_infra::authority::MinioProvisionedDescriptor,
        OwnedFd,
    ),
    Failure,
> {
    let mut data = vec![0u8; MAX_B10_PROVISIONED_FRAME_SIZE];
    let (n, fd) = conn.recv_one(&mut data).map_err(|e| {
        Failure::invalid(
            "broker",
            format!("broker: read provisioned frame: {}", e.message()),
        )
    })?;
    let descriptor = match protocol::decode_b10_provisioned_descriptor(&data[..n]) {
        Ok(d) => d,
        Err(e) => {
            drop(fd);
            return Err(e);
        }
    };
    if let Err(e) = crate::sys::memfd::validate_sealed(
        &fd,
        rustix::process::Uid::from_raw(MINIO_PROVISIONER_UID),
    ) {
        drop(fd);
        return Err(e);
    }
    Ok((descriptor, fd))
}

/// The JSON-path peer-authorization chain from `HandleConn`, then
/// `Dispatch`.
fn dispatch_json(
    conn: &mut super::deadline::DeadlineStream,
    svc: &Service,
    req: &BrokerRequest,
    peer: &PeerCred,
) -> Result<(), Failure> {
    if is_bootstrap_authority_purpose(&req.purpose) && is_central_migrate_peer(peer) {
        protocol::write_deny(conn, &req.operation_id, "authority denied");
        return Err(Failure::denied(
            "broker",
            "broker: denied bootstrap authority to migration peer",
        ));
    }
    if is_backup_worker_authority_purpose(&req.purpose) {
        // `svc.backupLaunches == nil` upstream denies identically to a
        // wrong-credential peer — same closed store rule here.
        let launches = svc.backup_launches.as_ref();
        if launches.is_none_or(|l| {
            peer.uid.as_raw() != l.runtime_uid() || peer.gid.as_raw() != l.runtime_gid()
        }) {
            protocol::write_deny(conn, &req.operation_id, "BACKUP_WORKER_AUTHORITY_DENIED");
            return Err(Failure::denied(
                "broker",
                "broker: denied backup worker peer",
            ));
        }
        let resp = match req.purpose.as_str() {
            BACKUP_SEAL_RPC => svc.dispatch_backup_seal(req, peer),
            BACKUP_WORKER_CONTEXT_RPC => svc.dispatch_backup_worker_context(req, peer),
            BACKUP_WORKER_EPOCH_RPC => svc.dispatch_backup_worker_payload_epoch(req, peer),
            BACKUP_WORKER_THROUGHPUT_RPC => svc.dispatch_backup_worker_throughput(req, peer),
            BACKUP_WORKER_CREATE_RPC => svc.dispatch_backup_worker_create(req, peer),
            BACKUP_WORKER_READ_RPC => svc.dispatch_backup_worker_read(req, peer),
            BACKUP_WORKER_CAS_RPC => svc.dispatch_backup_worker_cas(req, peer),
            BACKUP_THROUGHPUT_WORKER_CONTEXT_RPC => {
                svc.dispatch_backup_throughput_worker_context(req, peer)
            }
            BACKUP_THROUGHPUT_WORKER_TARGET_RPC => {
                svc.dispatch_backup_throughput_worker_target_locked(req, peer)
            }
            BACKUP_THROUGHPUT_WORKER_STAGE_RPC => {
                svc.dispatch_backup_throughput_worker_stage(req, peer)
            }
            _ => unreachable!("is_backup_worker_authority_purpose covers every arm"),
        };
        let _ = protocol::write_response(conn, &resp);
        return Ok(());
    }
    if is_postgres_service_role_authority_purpose(&req.purpose) {
        if !is_root_backup_helper_peer(peer) {
            protocol::write_deny(conn, &req.operation_id, "POSTGRES_SERVICE_ROLE_BIND_DENIED");
            return Err(Failure::denied(
                "broker",
                "broker: denied postgres service role bind peer",
            ));
        }
        protocol::write_deny(
            conn,
            &req.operation_id,
            &format!("POSTGRES_SERVICE_ROLE_BIND_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
        );
        return Ok(());
    }
    if is_advisory_evaluation_authority_purpose(&req.purpose) {
        if !is_root_backup_helper_peer(peer) {
            protocol::write_deny(conn, &req.operation_id, "ADVISORY_EVALUATION_APPEND_DENIED");
            return Err(Failure::denied(
                "broker",
                "broker: denied advisory evaluation append peer",
            ));
        }
        protocol::write_deny(
            conn,
            &req.operation_id,
            &format!("ADVISORY_EVALUATION_APPEND_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
        );
        return Ok(());
    }
    if is_backup_helper_authority_purpose(&req.purpose) {
        if !is_root_backup_helper_peer(peer) {
            protocol::write_deny(conn, &req.operation_id, "BACKUP_HELPER_AUTHORITY_DENIED");
            return Err(Failure::denied(
                "broker",
                "broker: denied backup helper peer",
            ));
        }
        let resp = match req.purpose.as_str() {
            BACKUP_ISSUE_LAUNCH_RPC => svc.dispatch_backup_launch_issue(req),
            BACKUP_THROUGHPUT_ISSUE_LAUNCH_RPC => svc.dispatch_backup_throughput_launch_issue(req),
            BACKUP_THROUGHPUT_READ_LAUNCH_RPC => svc.dispatch_backup_throughput_launch_read(req),
            BACKUP_THROUGHPUT_FIXTURE_LOADED_RPC => {
                svc.dispatch_backup_throughput_fixture_loaded(req)
            }
            BACKUP_ISSUE_MINIO_RPC => svc.dispatch_backup_minio_issue(req),
            BACKUP_MARK_REAPED_RPC => svc.dispatch_backup_mark_reaped(req),
            BACKUP_COMPLETE_RPC => svc.dispatch_backup_complete(req),
            BACKUP_VERIFY_SEAL_RPC => svc.dispatch_backup_verify_seal(req),
            BACKUP_READ_STATUS_RPC => svc.dispatch_backup_read_status(req),
            BACKUP_THROUGHPUT_CURRENT_RPC
            | BACKUP_THROUGHPUT_ACCEPT_RPC
            | BACKUP_THROUGHPUT_COMPLETE_PENDING_RPC
            | BACKUP_THROUGHPUT_ACTIVATE_RPC
            | BACKUP_THROUGHPUT_FAILED_RPC
            | BACKUP_THROUGHPUT_CLEANUP_REQUIRED_RPC
            | BACKUP_THROUGHPUT_CLEANUP_RESOLVED_RPC => {
                svc.dispatch_backup_throughput_authority(req)
            }
            BACKUP_ENSURE_PAYLOAD_EPOCH_RPC => svc.dispatch_backup_ensure_payload_epoch(req),
            _ => unreachable!("is_backup_helper_authority_purpose covers every arm"),
        };
        let _ = protocol::write_response(conn, &resp);
        return Ok(());
    }
    if is_restore_helper_authority_purpose(&req.purpose) {
        if !is_root_backup_helper_peer(peer) {
            protocol::write_deny(conn, &req.operation_id, "RESTORE_HELPER_AUTHORITY_DENIED");
            return Err(Failure::denied(
                "broker",
                "broker: denied restore helper peer",
            ));
        }
        let resp = svc.dispatch_restore_issue_launch(req, peer);
        let _ = protocol::write_response(conn, &resp);
        return Ok(());
    }
    if is_recovery_authority_purpose(&req.purpose) && !is_central_migrate_peer(peer) {
        protocol::write_deny(conn, &req.operation_id, "authority denied");
        return Err(Failure::denied(
            "broker",
            "broker: denied recovery mutation to non-migration peer",
        ));
    }
    if !is_runtime_or_root_peer(svc.runtime_uid, peer)
        && !(is_central_migrate_peer(peer) && is_migration_authority_purpose(&req.purpose))
    {
        protocol::write_deny(conn, &req.operation_id, "authority denied");
        return Err(Failure::denied(
            "broker",
            format!("broker: denied UID {}", peer.uid.as_raw()),
        ));
    }
    if is_central_migrate_peer(peer)
        && is_migration_authority_purpose(&req.purpose)
        && let Err(e) = svc.validate_migration_authority_launch(req, peer)
    {
        protocol::write_deny(
            conn,
            &req.operation_id,
            &format!("B05_MIGRATION_AUTHORITY_DENIED: {}", e.message()),
        );
        return Err(Failure::denied(
            "broker",
            format!(
                "broker: migration authority launch validation: {}",
                e.message()
            ),
        ));
    }
    if req.purpose == MIGRATION_REPORT_OUTCOME_RPC {
        let resp = svc.dispatch_migration_outcome(req, Some(peer));
        let _ = protocol::write_response(conn, &resp);
        return Ok(());
    }
    let resp = svc.dispatch(req);
    protocol::write_response(conn, &resp)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Serve — socket activation and path binding
// ---------------------------------------------------------------------------

/// `Serve` — accept on the passed listener fd (socket activation:
/// `LISTEN_FDS`'s fd `3+index` reaches here through
/// [`activated_listener`]) until `shutdown` fires. The listener is
/// nonblocking and polled at a 10 ms cadence so the loop can observe
/// the flag — the upstream `ctx`-cancel + `listener.Close()` shape has
/// no `UnixListener` equivalent on a borrowed accept.
///
/// # Errors
/// `broker` cancelled when `shutdown` fires — upstream's
/// `ctx.Err()` return (`main.go` exits the daemon 3 on it; the
/// `broker serve` operator path maps it back to a clean exit 0);
/// `broker` internal when the fd is not a listener or `accept` fails
/// for a reason other than a would-block poll.
pub fn serve(
    listen_fd: OwnedFd,
    svc: &Service,
    shutdown: &std::sync::atomic::AtomicBool,
) -> Result<(), Failure> {
    // `O_NONBLOCK` via `fcntl` — `UnixListener::set_nonblocking` emits
    // `ioctl(FIONBIO)`, which the broker's seccomp filter does not
    // allow (ADR 0044).
    let flags = rustix::fs::fcntl_getfl(&listen_fd)
        .map_err(|e| Failure::internal("broker", format!("broker: file listener: {e}")))?;
    rustix::fs::fcntl_setfl(&listen_fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|e| Failure::internal("broker", format!("broker: file listener: {e}")))?;
    let listener = UnixListener::from(listen_fd);
    while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
        match listener.accept() {
            Ok((conn, _)) => {
                if let Err(e) = handle_conn(conn, svc) {
                    eprintln!("broker: connection error: {}", e.message());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // `thread::sleep` emits `clock_nanosleep` (230) — not
                // on the allow-list; `nanosleep` (35) is (ADR 0044).
                crate::sys::audited::nanosleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(Failure::internal("broker", format!("broker: accept: {e}")));
            }
        }
    }
    // Upstream `Serve` returns `ctx.Err()` when the context is
    // canceled — the daemon's exit-3 shape; `run_broker_serve_at`
    // maps it to operator-mode exit 0.
    Err(Failure::cancelled("broker", "context canceled"))
}

/// `ServeOnPath` — bind a `0666` Unix socket at `socket_path` and serve
/// (production parity: `central-broker.socket` ships `SocketMode=0666`;
/// authorization is per-RPC behind `SO_PEERCRED`, never filesystem).
///
/// # Errors
/// `broker` on bind/chmod/accept failure.
pub fn serve_on_path(
    socket_path: &std::path::Path,
    svc: &Service,
    shutdown: &std::sync::atomic::AtomicBool,
) -> Result<(), Failure> {
    let listener = UnixListener::bind(socket_path)
        .map_err(|e| Failure::internal("broker", format!("broker: listen: {e}")))?;
    // Pre-`harden()` path only: this is the operator `broker serve`
    // mode — `UnixListener::bind` itself emits `socket`/`bind`/`listen`,
    // none of which the filter admits, so `fs::set_permissions`'s
    // `fchmodat` (268) can never run under it. The hardened daemon
    // serves the socket-activated fd instead (ADR 0044).
    fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )
    .map_err(|e| Failure::internal("broker", format!("broker: chmod socket: {e}")))?;
    serve(listener.into(), svc, shutdown)
}

/// `LISTEN_FDS` socket activation: fd `3 + index`. `LISTEN_PID` must be
/// this process; `LISTEN_FDS` must exceed `index`.
///
/// # Errors
/// `broker` denied on any activation-environment violation.
pub fn activated_listener(index: u32) -> Result<OwnedFd, Failure> {
    activated_listener_at(index, &|k| std::env::var(k).ok())
}

/// [`activated_listener`] with the environment read through `env` —
/// `run_broker_daemon_at`'s test seam. The checks are the activation
/// contract itself: only the process `LISTEN_PID` names may claim a
/// descriptor, and only below `LISTEN_FDS`.
///
/// # Errors
/// `broker` denied on any activation-environment violation.
pub(crate) fn activated_listener_at(
    index: u32,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<OwnedFd, Failure> {
    let listen_pid: u64 = env("LISTEN_PID").and_then(|v| v.parse().ok()).unwrap_or(0);
    if listen_pid != u64::from(std::process::id()) {
        return Err(Failure::denied(
            "broker",
            "broker: LISTEN_PID does not name this process",
        ));
    }
    let listen_fds: u32 = env("LISTEN_FDS").and_then(|v| v.parse().ok()).unwrap_or(0);
    if index >= listen_fds {
        return Err(Failure::denied(
            "broker",
            format!("broker: LISTEN_FDS={listen_fds} has no fd at index {index}"),
        ));
    }
    // Fd `3 + index` — the audited primitive proves it open before
    // claiming ownership.
    crate::sys::audited::socket_activation_fd(index)
        .map_err(|e| Failure::internal("broker", format!("broker: activated fd: {e}")))
}

impl Service {
    /// Locks the bootstrap cache (`bootstrapMu`).
    pub(crate) fn bootstrap_lock(&self) -> Result<MutexGuard<'_, ServiceBootstrapState>, Failure> {
        self.bootstrap_mu
            .lock()
            .map_err(|_| Failure::internal("broker_lifecycle", "bootstrap cache lock poisoned"))
    }
}

// ---------------------------------------------------------------------------
// Tests — upstream `server_test.go`/`broker_test.go` dispatch and
// connection coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::{TempDir, service};
    use central_infra::authority::BrokerOutcome;
    use std::collections::BTreeMap;

    /// `json.RawMessage` construction — the verbatim JSON bytes a
    /// `BrokerRequest` payload value carries.
    fn raw(json: &str) -> Box<serde_json::value::RawValue> {
        serde_json::value::RawValue::from_string(json.to_owned()).unwrap()
    }

    fn request(
        purpose: &str,
        payload: Option<BTreeMap<String, Box<serde_json::value::RawValue>>>,
    ) -> BrokerRequest {
        BrokerRequest {
            operation_id: uuid::Uuid::new_v4().to_string(),
            purpose: purpose.into(),
            session_token: String::new(),
            payload,
        }
    }

    fn request_payload(
        value: serde_json::Value,
    ) -> Option<BTreeMap<String, Box<serde_json::value::RawValue>>> {
        Some(BTreeMap::from([(
            "request".to_owned(),
            serde_json::from_value(value).unwrap(),
        )]))
    }

    /// `payload.request` set to arbitrary verbatim JSON.
    fn request_raw(json: &str) -> Option<BTreeMap<String, Box<serde_json::value::RawValue>>> {
        Some(BTreeMap::from([("request".to_owned(), raw(json))]))
    }

    /// Decode a response's verbatim `result` bytes for assertions —
    /// the `json.Unmarshal(response.Result, …)` half of a Go test.
    fn result_value(resp: &BrokerResponse) -> serde_json::Value {
        serde_json::from_str(resp.result.as_ref().unwrap().get()).unwrap()
    }

    #[test]
    fn dispatch_denies_unknown_and_descriptor_only_purposes() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        // Unknown purpose → upstream's closed denial text.
        let resp = svc.dispatch(&request("totally_unknown", None));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "unknown purpose");
        // Descriptor-only operations deny through the JSON path.
        for (purpose, code) in [
            (MATERIALIZE_MINIO_ROOT_RPC, "B04_HANDOFF_DENIED"),
            (MATERIALIZE_MINIO_RUNTIME_RPC, "B10_MINIO_RUNTIME_DENIED"),
            (CREATE_PROTECTED_GENERATION_RPC, "B04_HANDOFF_DENIED"),
            (MATERIALIZE_DEPENDENCY_HANDOFF_RPC, "B04_HANDOFF_DENIED"),
        ] {
            let resp = svc.dispatch(&request(purpose, None));
            assert_eq!(resp.outcome, BrokerOutcome::Denied);
            assert!(
                resp.evidence.message.starts_with(code),
                "{purpose} denied as {:?}",
                resp.evidence.message
            );
        }
    }

    #[test]
    fn dispatch_table_covers_every_upstream_purpose() {
        // Every purpose upstream's `service.go` `Dispatch` switch
        // registers must land on a real arm — a live handler, an
        // upstream denial ladder, the transport-required fallback, or
        // the closed denial — and NEVER on the `"unknown purpose"`
        // default.
        let dir = TempDir::new("server");
        let svc = service(&dir);
        for purpose in [
            // Live in this slice.
            MIGRATION_ISSUE_EMPTY_PROOF_RPC,
            MIGRATION_VERIFY_EMPTY_PROOF_RPC,
            MIGRATION_CONSUME_EMPTY_PROOF_RPC,
            MIGRATION_ISSUE_RESET_RPC,
            MIGRATION_VERIFY_RESET_RPC,
            MIGRATION_CONSUME_RESET_RPC,
            MIGRATION_READ_RECORD_RPC,
            MIGRATION_CREATE_RECORD_RPC,
            MIGRATION_REPLACE_RECORD_RPC,
            AUTHORIZE_LIFECYCLE_RPC,
            CONSUME_LIFECYCLE_RPC,
            VERIFY_LIFECYCLE_LOCK_OWNER_RPC,
            HMAC_FINGERPRINT_RPC,
            SIGN_LEAF_RPC,
            PRESENT_BOOTSTRAP_RPC,
            REGISTER_BOOTSTRAP_CANDIDATE_RPC,
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            ADOPT_B03_MINIO_BOOTSTRAP_RPC,
            ISSUE_B04_LIFECYCLE_PROOF_RPC,
            // The live recovery arms upstream registers in `Dispatch`.
            RESTORE_APPLY_AUTHORIZATION_RPC,
            RESTORE_RESUME_AUTHORIZATION_RPC,
            RESTORE_ABANDON_AUTHORIZATION_RPC,
            RESTORE_ABANDON_RPC,
            RESTORE_BARRIER_INSPECT_RPC,
            RESTORE_TICKET_BARRIER_INSPECT_RPC,
            RESTORE_BROKER_AUTHORITY_PREPARE_RPC,
            RESTORE_BOOTSTRAP_ACTIVATE_RPC,
            // Upstream denial ladders.
            MIGRATION_READ_OUTCOME_RPC,
            MATERIALIZE_MINIO_ROOT_RPC,
            MATERIALIZE_POSTGRES_MIGRATION_RPC,
            MATERIALIZE_MINIO_RUNTIME_RPC,
            ISSUE_MIGRATION_LAUNCH_RPC,
            // Upstream's transport-required fallback set.
            BACKUP_ISSUE_LAUNCH_RPC,
            BACKUP_SEAL_RPC,
            BACKUP_MARK_REAPED_RPC,
            BACKUP_COMPLETE_RPC,
            BACKUP_VERIFY_SEAL_RPC,
            BACKUP_READ_STATUS_RPC,
            BACKUP_WORKER_CONTEXT_RPC,
            BACKUP_WORKER_CREATE_RPC,
            BACKUP_WORKER_READ_RPC,
            BACKUP_WORKER_CAS_RPC,
            // Permanent denials.
            CREATE_PROTECTED_GENERATION_RPC,
            MATERIALIZE_DEPENDENCY_HANDOFF_RPC,
            // The closed set — upstream RPCs this slice does not port.
            "bind_postgres_service_role",
            "append_advisory_evaluation",
        ] {
            // Live purposes may succeed on an empty request (e.g.
            // `hmac_fingerprint` fingerprints empty domain+data) or
            // deny through their own ladder — the gate is only that
            // none falls through to the unregistered-purpose default.
            let resp = svc.dispatch(&request(purpose, None));
            assert_ne!(
                resp.evidence.message, "unknown purpose",
                "{purpose} fell through to unknown"
            );
        }
        // Connection-only purposes upstream's `Dispatch` never registers
        // — `HandleConn` serves them — MUST answer `"unknown purpose"`
        // through `dispatch`, exactly as upstream's `default` does.
        for purpose in [
            RESTORE_ISSUE_LAUNCH_RPC,
            BACKUP_ISSUE_MINIO_RPC,
            BACKUP_WORKER_EPOCH_RPC,
            BACKUP_WORKER_THROUGHPUT_RPC,
            BACKUP_ENSURE_PAYLOAD_EPOCH_RPC,
            BACKUP_THROUGHPUT_ISSUE_LAUNCH_RPC,
            BACKUP_THROUGHPUT_READ_LAUNCH_RPC,
            BACKUP_THROUGHPUT_FIXTURE_LOADED_RPC,
            BACKUP_THROUGHPUT_CURRENT_RPC,
            BACKUP_THROUGHPUT_ACCEPT_RPC,
            BACKUP_THROUGHPUT_COMPLETE_PENDING_RPC,
            BACKUP_THROUGHPUT_ACTIVATE_RPC,
            BACKUP_THROUGHPUT_FAILED_RPC,
            BACKUP_THROUGHPUT_CLEANUP_REQUIRED_RPC,
            BACKUP_THROUGHPUT_CLEANUP_RESOLVED_RPC,
            BACKUP_THROUGHPUT_WORKER_CONTEXT_RPC,
            BACKUP_THROUGHPUT_WORKER_TARGET_RPC,
            BACKUP_THROUGHPUT_WORKER_STAGE_RPC,
            MIGRATION_REPORT_OUTCOME_RPC,
        ] {
            let resp = svc.dispatch(&request(purpose, None));
            assert_eq!(resp.outcome, BrokerOutcome::Denied, "{purpose}");
            assert_eq!(
                resp.evidence.message, "unknown purpose",
                "{purpose} should hit upstream's connection-only default"
            );
        }
    }

    #[test]
    fn dispatch_b05_materialize_postgres_ladder() {
        // `dispatchB05MaterializePostgres`'s upstream rungs, in order.
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let denied = |payload| {
            svc.dispatch(&request(MATERIALIZE_POSTGRES_MIGRATION_RPC, payload))
                .evidence
                .message
        };
        assert_eq!(denied(None), "B05_HANDOFF_DENIED: empty payload");
        assert_eq!(
            denied(Some(BTreeMap::new())),
            "B05_HANDOFF_DENIED: missing request field"
        );
        assert_eq!(
            denied(request_raw(r#""x""#)),
            "B05_HANDOFF_DENIED: invalid request"
        );
        // All-default request — the binding fields fail first.
        assert_eq!(
            denied(request_raw("{}")),
            "B05_HANDOFF_DENIED: invalid dependency binding"
        );
        let binding = |binding_id: &str, op: &str| {
            format!(
                r#"{{"service":"central-migrate","target":"scm_rights","uid":986,"gid":986,"binding_id":"{binding_id}","operation_id":"{op}"}}"#
            )
        };
        assert_eq!(
            denied(request_raw(&binding("not-a-uuid", "op"))),
            "B05_HANDOFF_DENIED: invalid binding id"
        );
        let ok_binding = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            denied(request_raw(&binding(&ok_binding, "not-a-uuid"))),
            "B05_HANDOFF_DENIED: invalid operation id"
        );
        assert_eq!(
            denied(request_raw(&binding(
                &ok_binding,
                &uuid::Uuid::new_v4().to_string()
            ))),
            "B05_HANDOFF_DENIED: descriptor-only transport required"
        );
    }

    #[test]
    fn dispatch_b04_adopt_ladder() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let denied = |payload| {
            svc.dispatch(&request(ADOPT_B03_MINIO_BOOTSTRAP_RPC, payload))
                .evidence
                .message
        };
        assert_eq!(denied(None), "B04_HANDOFF_DENIED: empty payload");
        assert_eq!(
            denied(Some(BTreeMap::new())),
            "B04_HANDOFF_DENIED: missing request field"
        );
        assert_eq!(
            denied(request_raw(r#""x""#)),
            "B04_HANDOFF_DENIED: invalid request"
        );
        assert_eq!(
            denied(request_raw(r#"{"purpose":"postgres_migration_v1"}"#)),
            "B04_HANDOFF_DENIED: unsupported purpose"
        );
        assert_eq!(
            denied(request_raw(r#"{"purpose":"minio_root_v1"}"#)),
            "B04_HANDOFF_DENIED: missing lifecycle evidence"
        );
        // Complete, unexpired evidence reaches `VerifyLifecycleProof`:
        // no broker-issued proof exists, so the denial is upstream's
        // own `B04_HANDOFF_DENIED: <proof error>` — the proof store's
        // message already carries the class prefix, exactly as
        // upstream's `"B04_HANDOFF_DENIED: " + err.Error()` produces.
        let future = super::super::wire::format_rfc3339_nano(
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
        let evidence = format!(
            r#"{{"instance_id":"i","purpose":"minio_root_v1","operation_id":"{op}","fencing_token":7,"stopped_topology_proof":"s","mount_release_proof":"m","binding_evidence":"b","evidence_expires_at":"{future}"}}"#,
            op = uuid::Uuid::new_v4()
        );
        let msg = denied(request_raw(&evidence));
        assert!(
            msg.starts_with("B04_HANDOFF_DENIED: "),
            "unexpected adopt denial: {msg}"
        );
        assert!(
            msg.contains("lifecycle proof"),
            "unexpected adopt denial: {msg}"
        );
    }

    #[test]
    fn dispatch_b04_issue_proof_ladder() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let denied = |payload| {
            svc.dispatch(&request(ISSUE_B04_LIFECYCLE_PROOF_RPC, payload))
                .evidence
                .message
        };
        assert_eq!(denied(None), "B04_PROOF_DENIED: empty payload");
        assert_eq!(
            denied(Some(BTreeMap::new())),
            "B04_PROOF_DENIED: missing request field"
        );
        assert_eq!(
            denied(request_raw(r#""x""#)),
            "B04_PROOF_DENIED: invalid request"
        );
        assert_eq!(
            denied(request_raw("{}")),
            "B04_PROOF_DENIED: incomplete evidence"
        );
        let future = super::super::wire::format_rfc3339_nano(
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
        let evidence = |op: &str| {
            format!(
                r#"{{"instance_id":"i","operation_id":"{op}","fencing_token":7,"stopped_topology_proof":"s","mount_release_proof":"m","binding_evidence":"b","evidence_expires_at":"{future}"}}"#
            )
        };
        assert_eq!(
            denied(request_raw(&evidence("not-a-uuid"))),
            "B04_PROOF_DENIED: invalid operation id"
        );
        // Complete evidence mints the durable broker proof — a Success
        // with no result body, exactly as upstream.
        let resp = svc.dispatch(&request(
            ISSUE_B04_LIFECYCLE_PROOF_RPC,
            request_raw(&evidence(&uuid::Uuid::new_v4().to_string())),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        assert!(resp.result.is_none());
        // Re-issue inside the same operation is idempotent.
        let resp = svc.dispatch(&request(
            ISSUE_B04_LIFECYCLE_PROOF_RPC,
            request_raw(&evidence(&uuid::Uuid::new_v4().to_string())),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
    }

    #[test]
    fn dispatch_b05_issue_migration_launch_ladder() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let denied = |payload| {
            svc.dispatch(&request(ISSUE_MIGRATION_LAUNCH_RPC, payload))
                .evidence
                .message
        };
        assert_eq!(denied(None), "B05_LAUNCH_DENIED: missing request");
        assert_eq!(
            denied(request_raw(r#""x""#)),
            "B05_LAUNCH_DENIED: invalid request"
        );
        assert_eq!(
            denied(request_raw("{}")),
            "B05_LAUNCH_DENIED: invalid launch identity"
        );
        // A valid launch identity reaches the protected-binding check —
        // upstream's fixed message when no live binding exists.
        // `operation_id` must be a UUID echoing the envelope's own.
        let op = uuid::Uuid::new_v4().to_string();
        let mut req = request(
            ISSUE_MIGRATION_LAUNCH_RPC,
            request_raw(&format!(
                r#"{{"pid":4242,"process_start":"1","executable":"/usr/bin/central-migrate","mode":"migrate","operation_id":"{op}","expires_at":"{}"}}"#,
                super::super::wire::format_rfc3339_nano(
                    OffsetDateTime::now_utc() + time::Duration::minutes(5)
                )
            )),
        );
        req.operation_id = op;
        let resp = svc.dispatch(&req);
        assert_eq!(
            resp.evidence.message,
            "B05_LAUNCH_DENIED: protected migration binding unavailable"
        );
    }

    #[test]
    fn dispatch_backup_transport_required_uses_upstream_shape() {
        // The ten purposes upstream's own `Dispatch` answers with
        // `backupRPCDenied(_, "BACKUP_AUTHORITY_TRANSPORT_REQUIRED")` —
        // code AND message carry the code.
        let dir = TempDir::new("server");
        let svc = service(&dir);
        for purpose in [
            BACKUP_ISSUE_LAUNCH_RPC,
            BACKUP_SEAL_RPC,
            BACKUP_MARK_REAPED_RPC,
            BACKUP_COMPLETE_RPC,
            BACKUP_VERIFY_SEAL_RPC,
            BACKUP_READ_STATUS_RPC,
            BACKUP_WORKER_CONTEXT_RPC,
            BACKUP_WORKER_CREATE_RPC,
            BACKUP_WORKER_READ_RPC,
            BACKUP_WORKER_CAS_RPC,
        ] {
            let resp = svc.dispatch(&request(purpose, None));
            assert_eq!(resp.outcome, BrokerOutcome::Denied, "{purpose}");
            assert_eq!(
                resp.evidence.code, "BACKUP_AUTHORITY_TRANSPORT_REQUIRED",
                "{purpose}"
            );
            assert_eq!(
                resp.evidence.message, "BACKUP_AUTHORITY_TRANSPORT_REQUIRED",
                "{purpose}"
            );
        }
    }

    #[test]
    fn dispatch_denies_every_r6_purpose_closed() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        // Only the two upstream RPCs this slice does not port keep the
        // closed denial — everything else is live or connection-only.
        for purpose in ["bind_postgres_service_role", "append_advisory_evaluation"] {
            let resp = svc.dispatch(&request(purpose, None));
            assert_eq!(resp.outcome, BrokerOutcome::Denied, "{purpose}");
            assert_eq!(
                resp.evidence.message,
                format!("BROKER_AUTHORITY_DENIED: {}", UNSUPPORTED_IN_THIS_SLICE),
                "{purpose}"
            );
        }
        // The live recovery arms answer through their own denial
        // ladders on an empty request — never the closed text.
        for purpose in [
            RESTORE_APPLY_AUTHORIZATION_RPC,
            RESTORE_RESUME_AUTHORIZATION_RPC,
            RESTORE_ABANDON_AUTHORIZATION_RPC,
            RESTORE_ABANDON_RPC,
            RESTORE_BARRIER_INSPECT_RPC,
            RESTORE_TICKET_BARRIER_INSPECT_RPC,
            RESTORE_BROKER_AUTHORITY_PREPARE_RPC,
            RESTORE_BOOTSTRAP_ACTIVATE_RPC,
        ] {
            let resp = svc.dispatch(&request(purpose, None));
            assert_eq!(resp.outcome, BrokerOutcome::Denied, "{purpose}");
            assert!(
                !resp.evidence.message.starts_with("BROKER_AUTHORITY_DENIED"),
                "{purpose} got the closed text: {}",
                resp.evidence.message
            );
            assert_ne!(
                resp.evidence.message, "unknown purpose",
                "{purpose} fell through"
            );
        }
        // `migration_read_launch_outcome` keeps upstream's own
        // missing-store denial, not the slice's R6 text.
        let resp = svc.dispatch(&request(MIGRATION_READ_OUTCOME_RPC, None));
        assert_eq!(
            resp.evidence.message,
            "migration launch outcomes unavailable"
        );
    }

    #[test]
    fn migration_proof_rpcs_round_trip() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let op = uuid::Uuid::now_v7();
        let issue = serde_json::json!({
            "issue_empty": {
                "OperationID": op,
                "Target": {"SystemID":"sys","DatabaseOID":"1","Database":"central","ConfigHash":"c","Epoch":1},
                "SessionBinding": {"BackendPID":1,"BackendStart":"s","BootID":"b","LockIdentities":["a","b","c"]},
                "BaselineDigest": "sha256:x"
            }
        });
        let mut req = request(MIGRATION_ISSUE_EMPTY_PROOF_RPC, request_payload(issue));
        req.operation_id = op.to_string();
        let resp = svc.dispatch(&req);
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let issued = result_value(&resp);
        // Verify over the issued proof, then consume — replay denies.
        // The dispatch binds request.operation_id to the proof's.
        let verify = serde_json::json!({
            "target": {"SystemID":"sys","DatabaseOID":"1","Database":"central","ConfigHash":"c","Epoch":1},
            "proof": issued,
        });
        let bound = |purpose: &str| {
            let mut r = request(purpose, request_payload(verify.clone()));
            r.operation_id = op.to_string();
            r
        };
        let resp = svc.dispatch(&bound(MIGRATION_VERIFY_EMPTY_PROOF_RPC));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let resp = svc.dispatch(&bound(MIGRATION_CONSUME_EMPTY_PROOF_RPC));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let resp = svc.dispatch(&bound(MIGRATION_CONSUME_EMPTY_PROOF_RPC));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
    }

    #[test]
    fn provisioning_rpcs_round_trip() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let target = serde_json::json!({"SystemID":"sys","DatabaseOID":"1","Database":"central","ConfigHash":"c","Epoch":1});
        let op = uuid::Uuid::now_v7();
        // Absent read → denied with the stable code.
        let resp = svc.dispatch(&request(
            MIGRATION_READ_RECORD_RPC,
            request_payload(serde_json::json!({"target": target})),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.code, MIGRATION_RECORD_ABSENT_CODE);
        // Create — the record's operation_id must match the request.
        let mut record = ProvisioningRecord::absent_placeholder();
        record.operation_id = op;
        let create = serde_json::json!({
            "target": target,
            "record": serde_json::to_value(&record).unwrap()
        });
        let mut req = request(MIGRATION_CREATE_RECORD_RPC, request_payload(create));
        req.operation_id = op.to_string();
        let resp = svc.dispatch(&req);
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        assert_eq!(result_value(&resp)["Revision"], 1);
        // Read it back.
        let resp = svc.dispatch(&request(
            MIGRATION_READ_RECORD_RPC,
            request_payload(serde_json::json!({"target": target})),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
    }

    #[test]
    fn lifecycle_rpcs_round_trip() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let req_body = serde_json::json!({
            "InstanceID": "inst", "Operation": "up", "RequestDigest": "d",
            "PeerUID": 1000, "PeerPID": 4242
        });
        let resp = svc.dispatch(&request(
            AUTHORIZE_LIFECYCLE_RPC,
            request_payload(req_body.clone()),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let claim = result_value(&resp);
        let resp = svc.dispatch(&request(
            CONSUME_LIFECYCLE_RPC,
            request_payload(serde_json::json!({"claim": claim, "request": req_body})),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        // Dead-owner: this process is alive.
        let resp = svc.dispatch(&request(
            VERIFY_LIFECYCLE_LOCK_OWNER_RPC,
            request_payload(serde_json::json!({
                "lock_id": "l", "owner_pid": std::process::id()
            })),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        assert_eq!(result_value(&resp)["Dead"], false);
    }

    #[test]
    fn hmac_fingerprint_rpc_fingerprints_verbatim_bytes() {
        // Upstream hashes the raw `json.RawMessage` — a `{"b":1,"a":2}`
        // domain fingerprints differently than its `Value`-sorted
        // `{"a":2,"b":1}` re-encoding would. `svc.signing` computes the
        // expected HMAC over the same bytes upstream sees.
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let resp = svc.dispatch(&request(
            HMAC_FINGERPRINT_RPC,
            Some(BTreeMap::from([
                ("domain".to_owned(), raw(r#"{"b":1,"a":2}"#)),
                ("data".to_owned(), raw(r#""x""#)),
            ])),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let expected = svc.signing.fingerprint(r#"{"b":1,"a":2}"#, br#""x""#);
        assert_eq!(
            result_value(&resp)["fingerprint"].as_str().unwrap(),
            expected
        );
    }

    // -- HandleConn over a real socketpair ----------------------------------

    /// Drive one JSON-line request through `handle_conn`; the test
    /// process's euid is the service's runtime uid so the peer gate
    /// admits it exactly as production admits `central`.
    fn roundtrip(line: &[u8]) -> BrokerResponse {
        let dir = TempDir::new("server-conn");
        let svc = service(&dir);
        let (server_end, mut client_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || handle_conn(server_end, &svc));
        client_end.write_all(line).unwrap();
        client_end.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut client_end, &mut buf).unwrap();
        drop(client_end);
        let _ = handle.join();
        serde_json::from_str(buf.trim_end()).unwrap()
    }

    #[test]
    fn handle_conn_round_trips_json_and_denies_unknown() {
        let req = br#"{"operation_id":"op-1","purpose":"does_not_exist","payload":{}}"#;
        let mut line = req.to_vec();
        line.push(0x0a);
        let resp = roundtrip(&line);
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "unknown purpose");
        assert_eq!(resp.operation_id, "op-1");
    }

    #[test]
    fn handle_conn_denies_malformed_json_line() {
        let resp = roundtrip(
            b"not-json
",
        );
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "invalid request");
    }

    #[test]
    fn handle_conn_b1_frame_reaches_denied_transport() {
        // The test process presents its own euid — admitted by the
        // runtime-uid gate — so the R6-closed transport denial is what
        // comes back, proving both the frame decode and the peer gate.
        let request = br#"{"operation_id":"op-b1","purpose":"materialize_minio_runtime","payload":{"request":{}}}"#;
        let mut frame = vec![protocol::B10_MINIO_RUNTIME_FRAME_MARKER];
        frame.extend_from_slice(&(request.len() as u32).to_be_bytes());
        frame.extend_from_slice(request);
        let resp = roundtrip(&frame);
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(
            resp.evidence.message,
            "B10_MINIO_RUNTIME_DENIED: protected runtime binding unavailable"
        );
        assert_eq!(resp.operation_id, "op-b1");
    }

    #[test]
    fn handle_conn_c1_frame_echoes_operation_id() {
        // Upstream reads the 33-byte credential request BEFORE the
        // worker peer check, so a well-formed frame's closed denial
        // echoes its operation_id.
        let launch = uuid::Uuid::now_v7();
        let op = uuid::Uuid::now_v7();
        let mut frame = vec![protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER];
        frame.push(protocol::BACKUP_WORKER_POSTGRES_CREDENTIAL);
        frame.extend_from_slice(launch.as_bytes());
        frame.extend_from_slice(op.as_bytes());
        let resp = roundtrip(&frame);
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "BACKUP_WORKER_CREDENTIAL_DENIED");
        assert_eq!(resp.operation_id, op.to_string());
        // A nil operation id parses invalid → denies as "unknown".
        let mut frame = vec![protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER];
        frame.push(protocol::BACKUP_WORKER_POSTGRES_CREDENTIAL);
        frame.extend_from_slice(launch.as_bytes());
        frame.extend_from_slice(&[0u8; 16]);
        let resp = roundtrip(&frame);
        assert_eq!(resp.operation_id, "unknown");
        assert_eq!(resp.evidence.message, "BACKUP_WORKER_CREDENTIAL_DENIED");
        // A truncated frame never reaches the parse — still "unknown".
        let resp = roundtrip(&[protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER, 0x01]);
        assert_eq!(resp.operation_id, "unknown");
        assert_eq!(resp.evidence.message, "BACKUP_WORKER_CREDENTIAL_DENIED");
    }

    #[test]
    fn handle_conn_refuses_overlong_line_without_newline() {
        // `bufio.Scanner` parity: a peer that never sends '\n' is
        // refused once the line passes 64 KiB — the bounded read must
        // not wait for a newline or EOF, and must not buffer past
        // `MAX_REQUEST_LINE + 1`.
        let dir = TempDir::new("server-conn");
        let svc = service(&dir);
        let (server_end, mut client_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || handle_conn(server_end, &svc));
        let writer = std::thread::spawn(move || {
            let mut payload = vec![b'{'];
            payload.extend(std::iter::repeat_n(b' ', MAX_REQUEST_LINE + 2));
            let _ = client_end.write_all(&payload);
            client_end
        });
        // The handler refuses as soon as the cap is hit — no
        // `shutdown(Write)` is needed to make it return.
        let err = handle.join().unwrap().unwrap_err();
        assert!(
            err.message().contains("token too long"),
            "unexpected refusal: {}",
            err.message()
        );
        drop(writer.join().unwrap());
    }

    // -- Task-7 live dispatch coverage ---------------------------------

    #[test]
    fn sign_leaf_rpc_signs_and_errors() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let not_after = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let resp = svc.dispatch(&request(
            SIGN_LEAF_RPC,
            request_raw(&format!(
                r#"{{"public_key":"{}","not_after":{not_after}}}"#,
                super::super::wire::b64_encode(key.verifying_key().as_bytes()),
            )),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let result = result_value(&resp);
        let der = super::super::wire::b64_decode(result["Raw"].as_str().unwrap()).unwrap();
        // `Fingerprint` is sha256-hex over the DER the response carries.
        assert_eq!(
            result["Fingerprint"].as_str().unwrap(),
            super::super::wire::sha256_hex(&der)
        );
        // The certificate parses and names the broker CA as issuer.
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let issuer_cn = cert
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap()
            .to_owned();
        assert_eq!(issuer_cn, "Central Local CA");
        // Malformed or absent request → upstream's `BrokerError`, never
        // a denial and never "unknown purpose".
        let resp = svc.dispatch(&request(SIGN_LEAF_RPC, request_raw(r#""x""#)));
        assert_eq!(resp.outcome, BrokerOutcome::Error);
        let resp = svc.dispatch(&request(SIGN_LEAF_RPC, None));
        assert_eq!(resp.outcome, BrokerOutcome::Error);
    }

    #[test]
    fn bootstrap_candidate_rpcs_register_activate_and_recover() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let binding_payload = |candidate_id: &str, generation: u64| {
            Some(BTreeMap::from([(
                "binding".to_owned(),
                raw(&format!(
                    r#"{{"candidate_id":"{candidate_id}","generation":{generation},"digest":"{}"}}"#,
                    super::super::wire::b64_raw_encode(&[7u8; 32])
                )),
            )]))
        };
        // Absent payload → upstream's code-only AUTHORITY_DENIED.
        let resp = svc.dispatch(&request(REGISTER_BOOTSTRAP_CANDIDATE_RPC, None));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.code, "AUTHORITY_DENIED");
        assert!(resp.evidence.message.is_empty());
        // Register then activate the identical binding.
        let resp = svc.dispatch(&request(
            REGISTER_BOOTSTRAP_CANDIDATE_RPC,
            binding_payload("cand-1", 1),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        // A different candidate at the same generation cannot activate.
        let resp = svc.dispatch(&request(
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            binding_payload("cand-other", 1),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.code, "AUTHORITY_DENIED");
        let resp = svc.dispatch(&request(
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            binding_payload("cand-1", 1),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        // The activation is consumed — a replay denies.
        let resp = svc.dispatch(&request(
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            binding_payload("cand-1", 1),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        // Restart recovery: a second Service over the same root reloads
        // the activated candidate — the replay stays denied.
        let svc2 = service(&dir);
        let resp = svc2.dispatch(&request(
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            binding_payload("cand-1", 1),
        ));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
    }

    #[test]
    fn present_bootstrap_is_one_use_and_bounded() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        // Nothing staged → the code-only BOOTSTRAP_NOT_STAGED denial.
        let resp = svc.dispatch(&request(PRESENT_BOOTSTRAP_RPC, None));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.code, "BOOTSTRAP_NOT_STAGED");
        assert!(resp.evidence.message.is_empty());
        // Stage → present once → the raw-std-b64 value.
        svc.stage_bootstrap_value(b"bootstrap-secret").unwrap();
        let resp = svc.dispatch(&request(PRESENT_BOOTSTRAP_RPC, None));
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        assert_eq!(
            result_value(&resp)["value"].as_str().unwrap(),
            super::super::wire::b64_raw_encode(b"bootstrap-secret")
        );
        // Consumed — the second presentation denies identically.
        let resp = svc.dispatch(&request(PRESENT_BOOTSTRAP_RPC, None));
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.code, "BOOTSTRAP_NOT_STAGED");
        // Upstream's `StageBootstrapValue` bounds: 0 < len <= 4096.
        assert!(svc.stage_bootstrap_value(b"").is_err());
        assert!(svc.stage_bootstrap_value(&[0u8; 4097]).is_err());
    }

    /// Drive one `0xb4` framed request through `handle_conn`, then read
    /// the denial `BrokerResponse` line (all pre-descriptor rungs deny
    /// as ordinary JSON responses).
    fn b04_frame_roundtrip(request_json: serde_json::Value) -> BrokerResponse {
        let dir = TempDir::new("server-conn");
        let svc = service(&dir);
        let (server_end, mut client_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || handle_conn(server_end, &svc));
        let req = serde_json::json!({
            "operation_id": "op-b04",
            "purpose": MATERIALIZE_MINIO_ROOT_RPC,
            "payload": {"request": request_json},
        })
        .to_string();
        let mut frame = vec![B04_FRAME_MARKER];
        frame.extend_from_slice(&(req.len() as u32).to_be_bytes());
        frame.extend_from_slice(req.as_bytes());
        client_end.write_all(&frame).unwrap();
        client_end.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut client_end, &mut buf).unwrap();
        drop(client_end);
        let _ = handle.join();
        serde_json::from_str(buf.trim_end()).unwrap()
    }

    #[test]
    fn b04_transport_rungs_deny_in_order() {
        // `payload.request` absent.
        let dir = TempDir::new("server-conn");
        let svc = service(&dir);
        let (server_end, mut client_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || handle_conn(server_end, &svc));
        let req = br#"{"operation_id":"op-b04","purpose":"materialize_minio_root","payload":{}}"#;
        let mut frame = vec![B04_FRAME_MARKER];
        frame.extend_from_slice(&(req.len() as u32).to_be_bytes());
        frame.extend_from_slice(req);
        client_end.write_all(&frame).unwrap();
        client_end.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut client_end, &mut buf).unwrap();
        let _ = handle.join();
        let resp: BrokerResponse = serde_json::from_str(buf.trim_end()).unwrap();
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(
            resp.evidence.message,
            "B04_HANDOFF_DENIED: missing request field"
        );
        // Malformed request JSON.
        let resp = b04_frame_roundtrip(serde_json::Value::String("x".into()));
        assert_eq!(resp.evidence.message, "B04_HANDOFF_DENIED: invalid request");
        // Default-shaped request fails the closed dependency binding.
        let resp = b04_frame_roundtrip(serde_json::json!({}));
        assert_eq!(
            resp.evidence.message,
            "B04_HANDOFF_DENIED: invalid dependency binding"
        );
        // Correct binding, wrong peer identity.
        let resp = b04_frame_roundtrip(serde_json::json!({
            "service": "minio",
            "target": "/run/secrets/minio-root-password",
            "uid": 1000, "gid": 1000,
            "peer_uid": 0, "peer_pid": -1,
        }));
        assert_eq!(
            resp.evidence.message,
            "B04_HANDOFF_DENIED: peer identity mismatch"
        );
        // Real peer identity, malformed binding id.
        let resp = b04_frame_roundtrip(serde_json::json!({
            "service": "minio",
            "target": "/run/secrets/minio-root-password",
            "uid": 1000, "gid": 1000,
            "peer_uid": rustix::process::geteuid().as_raw(),
            "peer_pid": std::process::id(),
            "binding_id": "not-a-uuid",
        }));
        assert_eq!(
            resp.evidence.message,
            "B04_HANDOFF_DENIED: invalid binding id"
        );
        // Binding parses, malformed operation id.
        let resp = b04_frame_roundtrip(serde_json::json!({
            "service": "minio",
            "target": "/run/secrets/minio-root-password",
            "uid": 1000, "gid": 1000,
            "peer_uid": rustix::process::geteuid().as_raw(),
            "peer_pid": std::process::id(),
            "binding_id": uuid::Uuid::new_v4(),
            "operation_id": "not-a-uuid",
        }));
        assert_eq!(
            resp.evidence.message,
            "B04_HANDOFF_DENIED: invalid operation id"
        );
    }

    /// The deepest rung a test can drive deterministically: a fully
    /// valid request reaches `ReceiveDescriptor` — the broker then
    /// either refuses the descriptor's shape (non-root test host: the
    /// memfd cannot be root-owned) or the lease lookup (root: no B04
    /// adoption has produced a lease for the binding). Both are the
    /// custody failures upstream emits at that point.
    #[test]
    fn b04_transport_reaches_descriptor_then_store() {
        let dir = TempDir::new("server-conn");
        let svc = service(&dir);
        let (server_end, mut client_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || handle_conn(server_end, &svc));
        let op = uuid::Uuid::new_v4();
        let req = serde_json::json!({
            "operation_id": "op-b04",
            "purpose": MATERIALIZE_MINIO_ROOT_RPC,
            "payload": {"request": {
                "service": "minio",
                "target": "/run/secrets/minio-root-password",
                "uid": 1000, "gid": 1000,
                "peer_uid": rustix::process::geteuid().as_raw(),
                "peer_pid": std::process::id(),
                "binding_id": uuid::Uuid::new_v4(),
                "operation_id": op,
                "fencing_token": 7,
            }},
        })
        .to_string();
        let mut frame = vec![B04_FRAME_MARKER];
        frame.extend_from_slice(&(req.len() as u32).to_be_bytes());
        frame.extend_from_slice(req.as_bytes());
        client_end.write_all(&frame).unwrap();
        // Send the destination descriptor: empty 0400 sealed-capable
        // memfd — the shape `validate_destination` checks against the
        // root-owner requirement.
        let fd = rustix::fs::memfd_create(
            "central-test",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .unwrap();
        rustix::fs::fchmod(&fd, rustix::fs::Mode::from_bits_retain(0o400)).unwrap();
        crate::broker::handoff::send_b04_descriptor(&client_end, &fd).unwrap();
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut client_end, &mut buf).unwrap();
        let _ = handle.join();
        let resp: BrokerResponse = serde_json::from_str(buf.trim_end()).unwrap();
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.operation_id, "op-b04");
        if rustix::process::geteuid().is_root() {
            // Descriptor validated → the store answers for the
            // never-adopted binding.
            assert_eq!(resp.evidence.message, "B04_HANDOFF_DENIED: no active lease");
        } else {
            // The descriptor must be root-owned; the test's memfd
            // cannot satisfy that, and the denial is the custody
            // refusal upstream emits before any plaintext resolves.
            assert!(
                resp.evidence
                    .message
                    .starts_with("B04_HANDOFF_DENIED: transport:"),
                "unexpected denial: {}",
                resp.evidence.message
            );
        }
    }

    /// R5-T7-F1 — the ACK frame's `b04-ok:<hmac>` proves the
    /// *persisted* receipt. First presentation mints the durable
    /// receipt + operation (`issued`); the retry — the flow dying
    /// after validate, then re-presenting the same `operation_id`
    /// with the fresh `receipt_id` every transport pass mints — hits
    /// the `operations.get` resume branch and returns the *persisted*
    /// receipt, whose `receipt_id` differs from the request's. The
    /// proof must equal that record's `hmac` — the same value
    /// `opaque_token` returns — never a recompute over the ephemeral
    /// request.
    #[test]
    fn b04_ack_proof_binds_persisted_receipt_on_resume() {
        let dir = TempDir::new("server-ack");
        let svc = service(&dir);
        let sb = svc.bootstrap.as_ref().unwrap();
        // Stage: one adopted binding → an active lease under fence 5.
        let (binding, _) = sb
            .adopt_b03(&AdoptRequest {
                instance_id: "inst-ack".to_owned(),
                purpose: Purpose::MinioRoot,
                legacy_generation_id: None,
                operation_id: OperationId::new(),
                fencing_token: 5,
            })
            .unwrap();
        let operation_id = OperationId::new();
        let handoff_req = |receipt_id: HandoffReceiptId| {
            let mut req = HandoffRequest {
                binding_id: binding.binding_id,
                peer_uid: rustix::process::geteuid().as_raw(),
                peer_pid: std::process::id() as i32,
                operation_id,
                receipt_id,
                receipt_hmac: String::new(),
                fencing_token: 5,
                purpose: Purpose::MinioRoot,
                service: "minio".to_owned(),
                target: "/run/secrets/minio-root-password".to_owned(),
                uid: 1000,
                gid: 1000,
            };
            req.receipt_hmac = sb.compute_receipt_hmac(&req);
            req
        };
        // First presentation — mints the durable pair.
        let req1 = handoff_req(HandoffReceiptId::new());
        let (issued_receipt, _) = sb.validate_materialize_request(&req1).unwrap();
        // Re-present the same operation with a fresh receipt id — the
        // resume branch returns the persisted receipt.
        let req2 = handoff_req(HandoffReceiptId::new());
        assert_ne!(req2.receipt_id, issued_receipt.receipt_id);
        let (receipt, op) = sb.validate_materialize_request(&req2).unwrap();
        assert_eq!(receipt.receipt_id, issued_receipt.receipt_id);
        assert_eq!(receipt.hmac, issued_receipt.hmac);
        assert!(op.is_some());
        // The ACK opaque proof equals the persisted receipt HMAC —
        // byte-for-byte the `b04-ok:` body the frame embeds.
        let proof = svc.materialize_ack_proof(&receipt);
        let mut expected = b"b04-ok:".to_vec();
        expected.extend_from_slice(receipt.hmac.as_bytes());
        assert_eq!(proof, expected);
        // A recompute over the ephemeral request names a different
        // identity — the divergence this fix removes.
        let request_hmac = handoff::compute_materialize_receipt_hmac(&svc.signing, &req2);
        assert_ne!(request_hmac, receipt.hmac);
    }

    // -- dispatch_json peer gates (upstream HandleConn) --------------------

    /// A fabricated `SO_PEERCRED` triple — upstream's `unix.Ucred`.
    fn peer(uid: u32, gid: u32) -> PeerCred {
        PeerCred {
            pid: rustix::process::Pid::from_raw(4321).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(gid),
        }
    }

    /// One `dispatch_json` exchange over a socketpair — returns the
    /// handler's result and the decoded response line.
    fn json_call(
        svc: &Service,
        cred: PeerCred,
        req: &BrokerRequest,
    ) -> (Result<(), Failure>, BrokerResponse) {
        use crate::broker::deadline::DeadlineStream;
        use rustix::net::{AddressFamily, SocketFlags, SocketType};
        use std::io::Read;
        let (a, b) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut conn = DeadlineStream::new(a, std::time::Duration::from_secs(5)).unwrap();
        let result = dispatch_json(&mut conn, svc, req, &cred);
        drop(conn); // EOF so the peer read finishes.
        let mut buf = String::new();
        std::fs::File::from(b).read_to_string(&mut buf).unwrap();
        let resp: BrokerResponse = serde_json::from_str(buf.trim_end_matches('\n')).unwrap();
        (result, resp)
    }

    #[test]
    fn dispatch_json_worker_gate_binds_launch_store_identity() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let launches = svc.backup_launches.as_ref().unwrap();
        let req = request(BACKUP_SEAL_RPC, None);
        // A root peer is NOT the worker — upstream's
        // `BACKUP_WORKER_AUTHORITY_DENIED` write_deny, exactly.
        let (result, resp) = json_call(&svc, peer(0, 0), &req);
        assert!(result.is_err());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "BACKUP_WORKER_AUTHORITY_DENIED");
        // The launch store's runtime identity reaches the live arm —
        // decode fails with the handler's own code, not the gate's.
        let (result, resp) = json_call(
            &svc,
            peer(launches.runtime_uid(), launches.runtime_gid()),
            &req,
        );
        assert!(result.is_ok());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "BACKUP_SEAL_DENIED");
        assert_eq!(resp.evidence.code, "BACKUP_SEAL_DENIED");
    }

    #[test]
    fn dispatch_json_helper_gates_require_root() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let req = request(BACKUP_READ_STATUS_RPC, None);
        // A non-root peer is refused at the gate — the handler's code
        // never runs (`uid==0 && gid==0 && pid>0` upstream).
        let (result, resp) = json_call(&svc, peer(4242, 4242), &req);
        assert!(result.is_err());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "BACKUP_HELPER_AUTHORITY_DENIED");
        // The same gate rejects `restore_issue_launch` with its own
        // code — before the launch store is even consulted.
        let (result, resp) = json_call(
            &svc,
            peer(4242, 4242),
            &request(RESTORE_ISSUE_LAUNCH_RPC, None),
        );
        assert!(result.is_err());
        assert_eq!(resp.evidence.message, "RESTORE_HELPER_AUTHORITY_DENIED");
        // Root reaches the live arm — empty op → the handler's code.
        let (result, resp) = json_call(&svc, peer(0, 0), &req);
        assert!(result.is_ok());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "BACKUP_STATUS_DENIED");
        // `restore_issue_launch` — its own handler denial ladder.
        let (result, resp) = json_call(&svc, peer(0, 0), &request(RESTORE_ISSUE_LAUNCH_RPC, None));
        assert!(result.is_ok());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(
            resp.evidence.message,
            "RESTORE_LAUNCH_DENIED: missing request"
        );
    }

    #[test]
    fn dispatch_json_recovery_mutations_require_migration_peer() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        let req = request(RESTORE_BROKER_AUTHORITY_PREPARE_RPC, None);
        // A non-migration peer is refused at the gate — even root.
        let (result, resp) = json_call(&svc, peer(0, 0), &req);
        assert!(result.is_err());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.evidence.message, "authority denied");
        // The migration peer passes the gate, then fails the launch
        // binding — upstream's `B05_MIGRATION_AUTHORITY_DENIED`.
        let (result, resp) = json_call(&svc, peer(CENTRAL_MIGRATE_UID, CENTRAL_MIGRATE_GID), &req);
        assert!(result.is_err());
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(
            resp.evidence.message,
            "B05_MIGRATION_AUTHORITY_DENIED: missing launch authority"
        );
    }

    #[test]
    fn dispatch_json_closed_and_live_purposes() {
        let dir = TempDir::new("server");
        let svc = service(&dir);
        // `bind_postgres_service_role` — root-only gate, then the
        // slice's closed denial (the RPC is deliberately unported).
        let (result, resp) = json_call(
            &svc,
            peer(4242, 4242),
            &request(POSTGRES_SERVICE_ROLE_BIND_RPC, None),
        );
        assert!(result.is_err());
        assert_eq!(resp.evidence.message, "POSTGRES_SERVICE_ROLE_BIND_DENIED");
        let (_, resp) = json_call(
            &svc,
            peer(0, 0),
            &request(POSTGRES_SERVICE_ROLE_BIND_RPC, None),
        );
        assert_eq!(
            resp.evidence.message,
            format!("POSTGRES_SERVICE_ROLE_BIND_DENIED: {UNSUPPORTED_IN_THIS_SLICE}")
        );
        // `inspect_restore_barrier` — a root peer reaches the live
        // handler; an exactly-empty payload answers with the barrier.
        let (_, resp) = json_call(
            &svc,
            peer(0, 0),
            &request(RESTORE_BARRIER_INSPECT_RPC, Some(BTreeMap::new())),
        );
        assert_eq!(resp.outcome, BrokerOutcome::Success);
        let value = result_value(&resp);
        assert_eq!(value["active"], false);
    }
}
