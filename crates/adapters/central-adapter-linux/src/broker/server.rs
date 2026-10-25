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
use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use central_foundation::failure::Failure;
use central_infra::authority::{
    B04AdoptRequest, B04IssueProofRequest, B05MaterializePostgresMigrationRequest, BrokerEvidence,
    BrokerOutcome, BrokerRequest, BrokerResponse, LifecycleAuthorization,
    LifecycleAuthorizationRequest, ProtectedGeneration,
};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::sys::peercred::{PeerCred, peercred};

use super::journal::Journal;
use super::lifecycle::LifecycleNonceStore;
use super::payload_epoch::PayloadEpochStore;
use super::proof::{self, ProofService};
use super::protected_file::ProtectedFileBackend;
use super::protocol::{self, *};
use super::provisioning::{
    self, ProvisioningRecord, ProvisioningStore, ReplaceProvisioningRecordRequest,
};
use super::signing::{Ed25519Signer, SigningService};

/// `brokerConnectionDeadline` — one second; bounds the initial framed
/// exchange and every pre-authentication denial.
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(1);

/// `migrationRPCDenied`.
fn migration_denied(operation_id: &str, message: impl Into<String>) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: BrokerOutcome::Denied,
        result: None,
        evidence: BrokerEvidence {
            operation_id: operation_id.into(),
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
            operation_id: operation_id.into(),
            code: code.into(),
            message: message.into(),
        },
    }
}

/// `backupRPCDenied` — `Code` and `Message` both carry the denial code.
fn backup_denied(operation_id: &str, code: &str) -> BrokerResponse {
    migration_denied_with_code(operation_id, code, code)
}

/// A success response carrying `result`.
fn success(operation_id: &str, result: serde_json::Value) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: BrokerOutcome::Success,
        result: Some(result),
        evidence: BrokerEvidence::default(),
    }
}

/// `Service` — aggregates the broker sub-components. Fields whose
/// upstream counterparts are R6 stores are absent; dispatch denies
/// their purposes with the slice's closed denial.
pub struct Service {
    /// The protected-state root (`0700`, broker-owned).
    pub root_path: PathBuf,
    /// The protected generation/value backend.
    pub backend: ProtectedFileBackend,
    /// The persistent HMAC identity.
    pub(crate) signing: Arc<SigningService>,
    /// The Ed25519 external-verifiability signer.
    pub signer: Option<Arc<Ed25519Signer>>,
    /// The authority-transition journal (`journal.RootPath` is the
    /// protected root's parent, upstream's `filepath.Dir(rootPath)`).
    pub journal: Option<Arc<Journal>>,
    /// The durable lifecycle nonce tombstones.
    pub(crate) nonces: Option<LifecycleNonceStore>,
    /// The provisioning record store.
    pub provisioning: Option<ProvisioningStore>,
    /// The proof service.
    pub proofs: Option<ProofService>,
    /// The payload epoch store.
    pub payload_epochs: Option<PayloadEpochStore>,
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
}

impl Service {
    /// `NewService` — persistent signing identity, journal rooted at
    /// `root_path`'s parent (upstream `filepath.Dir(rootPath)`),
    /// protected backend, nonce store, provisioning store, persistent
    /// proof service, payload-epoch store.
    ///
    /// # Errors
    /// Any sub-component's `new_*` error — signing identity, nonce
    /// root, proof state, epoch root.
    pub fn new(root_path: PathBuf, runtime_uid: u32) -> Result<Self, Failure> {
        let signing = Arc::new(SigningService::new_persistent(&root_path)?);
        let signer = Some(Arc::new(Ed25519Signer::new()?));
        let nonces = Some(LifecycleNonceStore::new(&root_path)?);
        let backend = ProtectedFileBackend::new(root_path.clone());
        let journal_root = root_path
            .parent()
            .map_or_else(|| root_path.clone(), PathBuf::from);
        let journal = Arc::new(Journal::new(journal_root, signing.clone(), signer.clone()));
        let provisioning = Some(ProvisioningStore::new(
            root_path.clone(),
            Some(journal.clone()),
        ));
        let proofs = Some(proof::new_persistent_proof_service(
            &root_path,
            SigningService::from_key(signing.key_copy()),
            Some(journal.clone()),
        )?);
        let payload_epochs = Some(super::payload_epoch::new_payload_epoch_store(
            &root_path,
            SigningService::from_key(signing.key_copy()),
        )?);
        Ok(Self {
            root_path,
            backend,
            signing,
            signer,
            journal: Some(journal),
            nonces,
            provisioning,
            proofs,
            payload_epochs,
            runtime_uid,
            bootstrap_mu: Mutex::new(ServiceBootstrapState {
                bootstraps: BTreeMap::new(),
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
        journal: Option<Arc<Journal>>,
        nonces: Option<LifecycleNonceStore>,
        provisioning: Option<ProvisioningStore>,
        proofs: Option<ProofService>,
        payload_epochs: Option<PayloadEpochStore>,
        runtime_uid: u32,
    ) -> Self {
        Self {
            root_path,
            backend,
            signing,
            signer,
            journal,
            nonces,
            provisioning,
            proofs,
            payload_epochs,
            runtime_uid,
            bootstrap_mu: Mutex::new(ServiceBootstrapState {
                bootstraps: BTreeMap::new(),
            }),
        }
    }

    // ------------------------------------------------------------------
    // Dispatch — the closed operation matrix (service.go Dispatch)
    // ------------------------------------------------------------------

    /// `Dispatch` routes a decoded request by `purpose` — upstream
    /// `service.go`'s switch, in upstream order. Every arm is either a
    /// live handler, the upstream denial ladder its handler runs, or —
    /// for purposes upstream's `HandleConn` gates behind peer
    /// credentials before `Dispatch` could ever see them — the
    /// defensive `BACKUP_AUTHORITY_TRANSPORT_REQUIRED` fallback
    /// upstream keeps for exactly those. What remains is the slice's
    /// closed R6 denial, then `"unknown purpose"`.
    #[must_use]
    pub fn dispatch(&self, req: &BrokerRequest) -> BrokerResponse {
        match req.purpose.as_str() {
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
            MIGRATION_READ_OUTCOME_RPC => {
                migration_denied(&req.operation_id, "migration launch outcomes unavailable")
            }
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
            // authority — R6 machinery, so it closes like every other
            // R6-backed purpose below rather than erroring.
            HMAC_FINGERPRINT_RPC => self.dispatch_hmac_fingerprint(req),
            AUTHORIZE_LIFECYCLE_RPC => self.dispatch_authorize_lifecycle(req),
            CONSUME_LIFECYCLE_RPC => self.dispatch_consume_lifecycle(req),
            VERIFY_LIFECYCLE_LOCK_OWNER_RPC => self.dispatch_verify_lock_owner(req),
            MATERIALIZE_DEPENDENCY_HANDOFF_RPC => migration_denied(
                &req.operation_id,
                "B04_HANDOFF_DENIED: legacy pathname handoff is disabled",
            ),
            // R6 surface — registered names with closed denials.
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

    /// `dispatchB04Adopt` — `adopt_b03_minio_bootstrap`'s upstream
    /// validation ladder. The adopt itself is R6 machinery
    /// (`s.bootstrap`), but every rung upstream rejects before reaching
    /// it is part of the wire contract and reproduces here exactly.
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
        // `s.bootstrap.VerifyLifecycleProof` — the B04 bootstrap session
        // is R6, so the caller's evidence can never verify; upstream
        // wraps that store error under the same class.
        migration_denied(
            &req.operation_id,
            format!("{CLASS}{UNSUPPORTED_IN_THIS_SLICE}"),
        )
    }

    /// `dispatchB04IssueProof` — `issue_b04_lifecycle_proof`'s ladder;
    /// `s.bootstrap.IssueLifecycleProof` is R6.
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
        if uuid::Uuid::parse_str(&wire.operation_id).is_err() {
            return migration_denied(&req.operation_id, format!("{CLASS}invalid operation id"));
        }
        // `s.bootstrap.IssueLifecycleProof` — R6.
        migration_denied(
            &req.operation_id,
            format!("{CLASS}{UNSUPPORTED_IN_THIS_SLICE}"),
        )
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
        // `s.bootstrap.ActiveBindingForPurpose` — no bootstrap session
        // exists in this slice, so no protected migration binding can
        // ever be live; upstream emits this same fixed message.
        migration_denied(
            &req.operation_id,
            format!("{CLASS}protected migration binding unavailable"),
        )
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
                    Ok(p) => match serde_json::to_value(proof::VerifiedEmptyTargetWire::from(&p)) {
                        Ok(v) => success(&req.operation_id, v),
                        Err(_) => {
                            migration_denied(&req.operation_id, "encode migration proof result")
                        }
                    },
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
                    Ok(()) => success(&req.operation_id, serde_json::json!({"verified": true})),
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
                    Ok(()) => success(&req.operation_id, serde_json::json!({"consumed": true})),
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
                    Ok(c) => match serde_json::to_value(proof::ResetConfirmationWire::from(&c)) {
                        Ok(v) => success(&req.operation_id, v),
                        Err(_) => {
                            migration_denied(&req.operation_id, "encode migration proof result")
                        }
                    },
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
                    Ok(()) => success(&req.operation_id, serde_json::json!({"verified": true})),
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
                    Ok(()) => success(&req.operation_id, serde_json::json!({"consumed": true})),
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
        let succeed = |record: &ProvisioningRecord| match serde_json::to_value(record) {
            Ok(v) => success(&req.operation_id, v),
            Err(_) => migration_denied(&req.operation_id, "encode provisioning result"),
        };
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
            Ok(claim) => match serde_json::to_value(claim) {
                Ok(v) => success(&req.operation_id, v),
                Err(_) => migration_denied(&req.operation_id, "encode lifecycle claim"),
            },
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
            Ok(p) => {
                // `port.DeadOwnerProof` marshals PascalCase (no Go tags).
                match serde_json::to_value(serde_json::json!({
                    "LockID": p.lock_id,
                    "OwnerPID": p.owner_pid,
                    "Dead": p.dead,
                    "VerifiedAt": super::wire::format_rfc3339_nano(p.verified_at),
                })) {
                    Ok(v) => success(&req.operation_id, v),
                    Err(_) => migration_denied(&req.operation_id, "encode lock owner proof"),
                }
            }
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
        success(&req.operation_id, serde_json::json!({"fingerprint": fp}))
    }

    // ------------------------------------------------------------------
    // Framed transports — R6 machinery, closed denials
    // ------------------------------------------------------------------

    /// `handleB04MaterializeTransport` — the B04 bootstrap session is
    /// R6; the transport still enforces the request's outer binding
    /// checks before denying, so the denial semantics a test or a peer
    /// sees are upstream's.
    fn handle_b04_materialize_transport(
        &self,
        conn: &mut std::os::unix::net::UnixStream,
        req: &BrokerRequest,
        _peer: &PeerCred,
    ) -> Result<(), Failure> {
        protocol::write_deny(
            conn,
            &req.operation_id,
            &format!("B04_HANDOFF_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
        );
        Ok(())
    }

    /// `handleB05MaterializeTransport` — no launch evidence store in
    /// this slice: upstream's exact `s.launches == nil` denial.
    fn handle_b05_materialize_transport(
        &self,
        conn: &mut std::os::unix::net::UnixStream,
        req: &BrokerRequest,
        _peer: &PeerCred,
    ) -> Result<(), Failure> {
        protocol::write_deny(
            conn,
            &req.operation_id,
            "B05_HANDOFF_DENIED: launch evidence store is unavailable",
        );
        Ok(())
    }

    /// `handleB10MinioRuntimeTransport` — the runtime binding store is
    /// R6; the peer gate has already run, so deny closed.
    fn handle_b10_minio_runtime_transport(
        &self,
        conn: &mut std::os::unix::net::UnixStream,
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
        conn: &mut std::os::unix::net::UnixStream,
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
    let mut conn = conn;
    // One-second deadline over the framed exchange — the audited
    // primitive sets SO_RCVTIMEO/SO_SNDTIMEO.
    conn.set_read_timeout(Some(CONNECTION_DEADLINE))
        .map_err(|e| {
            Failure::internal("broker", format!("broker: set connection deadline: {e}"))
        })?;
    conn.set_write_timeout(Some(CONNECTION_DEADLINE))
        .map_err(|e| {
            Failure::internal("broker", format!("broker: set connection deadline: {e}"))
        })?;

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
                    // closed gate (`handleBackupWorkerCredentialTransport`
                    // re-checks the worker identity against it).
                    protocol::write_deny(
                        &mut conn,
                        &request.operation_id.to_string(),
                        "BACKUP_WORKER_CREDENTIAL_DENIED",
                    );
                    Err(Failure::denied(
                        "broker",
                        "broker: denied backup credential peer",
                    ))
                }
                Err(e) => {
                    protocol::write_deny(&mut conn, "unknown", "BACKUP_WORKER_CREDENTIAL_DENIED");
                    Err(e)
                }
            }
        }
        RESTORE_MIGRATION_CREDENTIAL_FRAME_MARKER => {
            protocol::write_deny(&mut conn, "unknown", "RESTORE_CREDENTIAL_DENIED");
            Err(Failure::denied(
                "broker",
                format!(
                    "broker: denied restore credential peer {}:{}",
                    peer.uid.as_raw(),
                    peer.gid.as_raw()
                ),
            ))
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
                let read_half = conn.try_clone().map_err(io_failure)?;
                let reader = BufReader::with_capacity(MAX_REQUEST_LINE, read_half);
                // Upstream's `bufio.Scanner` aborts once a token passes
                // its 64 KiB buffer — a peer withholding '\n' can never
                // grow it further. `Take` bounds the read side the same
                // way: at most `MAX_REQUEST_LINE + 1` bytes accumulate
                // before the too-long check refuses, instead of
                // `read_until` buffering unboundedly first.
                let mut limited = reader.take((MAX_REQUEST_LINE + 1 - line.len()) as u64);
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
/// data; [`crate::sys::scm_rights::recv_one`] enforces the
/// single-rights single-fd shape, then
/// [`crate::sys::memfd::validate_sealed`] proves the descriptor.
fn read_b10_provisioned_frame<Fd: AsFd>(
    conn: Fd,
) -> Result<
    (
        central_infra::authority::MinioProvisionedDescriptor,
        OwnedFd,
    ),
    Failure,
> {
    let mut data = vec![0u8; MAX_B10_PROVISIONED_FRAME_SIZE];
    let (n, fd) = crate::sys::scm_rights::recv_one(conn, &mut data).map_err(|e| {
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
    conn: &mut std::os::unix::net::UnixStream,
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
        // The worker launch store is R6; there is no worker identity to
        // check against, so every worker peer denies.
        protocol::write_deny(conn, &req.operation_id, "BACKUP_WORKER_AUTHORITY_DENIED");
        return Err(Failure::denied(
            "broker",
            "broker: denied backup worker peer",
        ));
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
        protocol::write_deny(
            conn,
            &req.operation_id,
            &format!("BACKUP_HELPER_AUTHORITY_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
        );
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
        protocol::write_deny(
            conn,
            &req.operation_id,
            &format!("RESTORE_HELPER_AUTHORITY_DENIED: {UNSUPPORTED_IN_THIS_SLICE}"),
        );
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
    if is_central_migrate_peer(peer) && is_migration_authority_purpose(&req.purpose) {
        // `validateMigrationAuthorityLaunch` — the launch evidence store
        // is R6, so every migration launch validation fails closed with
        // upstream's `s.launches == nil` message.
        protocol::write_deny(
            conn,
            &req.operation_id,
            "B05_MIGRATION_AUTHORITY_DENIED: missing launch authority",
        );
        return Err(Failure::denied(
            "broker",
            "broker: migration authority launch validation: missing launch authority",
        ));
    }
    if req.purpose == MIGRATION_REPORT_OUTCOME_RPC {
        let resp = migration_denied(&req.operation_id, "migration launch outcomes unavailable");
        let _ = protocol::write_response(conn, &resp);
        return Ok(());
    }
    let resp = svc.dispatch(req);
    protocol::write_response(conn, &resp)?;
    Ok(())
}

fn io_failure(e: std::io::Error) -> Failure {
    Failure::internal("broker", format!("broker: io: {e}"))
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
/// `broker` when the fd is not a listener or `accept` fails for a
/// reason other than a would-block poll.
pub fn serve(
    listen_fd: OwnedFd,
    svc: &Service,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), Failure> {
    let listener = UnixListener::from(listen_fd);
    listener
        .set_nonblocking(true)
        .map_err(|e| Failure::internal("broker", format!("broker: file listener: {e}")))?;
    while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
        match listener.accept() {
            Ok((conn, _)) => {
                if let Err(e) = handle_conn(conn, svc) {
                    eprintln!("broker: connection error: {}", e.message());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(Failure::internal("broker", format!("broker: accept: {e}")));
            }
        }
    }
    Ok(())
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
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), Failure> {
    let listener = UnixListener::bind(socket_path)
        .map_err(|e| Failure::internal("broker", format!("broker: listen: {e}")))?;
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
    let listen_pid: u64 = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if listen_pid != u64::from(std::process::id()) {
        return Err(Failure::denied(
            "broker",
            "broker: LISTEN_PID does not name this process",
        ));
    }
    let listen_fds: u32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
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
    use std::io::Write as _;

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
        // The R5-T6 completeness gate: every purpose in upstream
        // `service.go`'s `Dispatch` switch must land on a real arm —
        // a live handler, an upstream denial ladder, the
        // transport-required fallback, or the closed R6 denial — and
        // NEVER on the `"unknown purpose"` default.
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
            // Upstream denial ladders.
            MIGRATION_READ_OUTCOME_RPC,
            ADOPT_B03_MINIO_BOOTSTRAP_RPC,
            ISSUE_B04_LIFECYCLE_PROOF_RPC,
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
            // The closed R6 surface.
            SIGN_LEAF_RPC,
            PRESENT_BOOTSTRAP_RPC,
            REGISTER_BOOTSTRAP_CANDIDATE_RPC,
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            "issue_restore_apply_authorization",
            "issue_restore_resume_authorization",
            "issue_restore_abandon_authorization",
            "abandon_restore",
            "inspect_restore_barrier",
            "inspect_restore_ticket_barrier",
            "prepare_recovery_broker_authority",
            "activate_recovery_bootstrap",
            "bind_postgres_service_role",
            "append_advisory_evaluation",
            "restore_issue_launch",
            "backup_issue_minio_handoff",
            "backup_ensure_payload_epoch",
            "backup_worker_active_payload_epoch",
            "backup_worker_read_throughput",
            "backup_throughput_issue_launch",
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
        // Complete, unexpired evidence reaches the R6 bootstrap
        // session boundary — the adopt's own upstream class.
        let future = super::super::wire::format_rfc3339_nano(
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
        let evidence = format!(
            r#"{{"instance_id":"i","purpose":"minio_root_v1","operation_id":"{op}","fencing_token":7,"stopped_topology_proof":"s","mount_release_proof":"m","binding_evidence":"b","evidence_expires_at":"{future}"}}"#,
            op = uuid::Uuid::new_v4()
        );
        assert_eq!(
            denied(request_raw(&evidence)),
            format!("B04_HANDOFF_DENIED: {UNSUPPORTED_IN_THIS_SLICE}")
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
        assert_eq!(
            denied(request_raw(&evidence(&uuid::Uuid::new_v4().to_string()))),
            format!("B04_PROOF_DENIED: {UNSUPPORTED_IN_THIS_SLICE}")
        );
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
        for purpose in [
            "backup_issue_minio_handoff",
            "backup_worker_active_payload_epoch",
            "backup_worker_read_throughput",
            "backup_ensure_payload_epoch",
            "restore_issue_launch",
            "issue_restore_apply_authorization",
            "abandon_restore",
            "prepare_recovery_broker_authority",
            "activate_recovery_bootstrap",
            "bind_postgres_service_role",
            "append_advisory_evaluation",
            "sign_leaf",
            "migration_report_launch_outcome",
            "present_bootstrap",
            "register_bootstrap_candidate",
            "activate_bootstrap_candidate",
        ] {
            let resp = svc.dispatch(&request(purpose, None));
            assert_eq!(resp.outcome, BrokerOutcome::Denied, "{purpose}");
            assert_eq!(
                resp.evidence.message,
                format!("BROKER_AUTHORITY_DENIED: {}", UNSUPPORTED_IN_THIS_SLICE),
                "{purpose}"
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
        let issued = resp.result.unwrap();
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
        assert_eq!(resp.result.unwrap()["Revision"], 1);
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
        let claim = resp.result.unwrap();
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
        assert_eq!(resp.result.unwrap()["Dead"], false);
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
            resp.result.unwrap()["fingerprint"].as_str().unwrap(),
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
}
