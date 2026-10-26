//! `migration_client_linux.go` + `migration_authority_client.go` +
//! `migration_launch_issuer.go` — the client half of the broker's
//! migration-authority surface.
//!
//! Three roles, one file, exactly like upstream keeps them in the
//! broker package:
//!
//! * [`MigrationClient::materialize_postgres_migration`] — the
//!   `central-migrate` operator's B05 framed transport (`0xb5`): sends
//!   the empty destination memfd over `SCM_RIGHTS`, reads the framed
//!   ack, confirms the custody handoff, and returns the safe result.
//! * [`MigrationAuthorityClient`] — the `central-migrate`-only JSON
//!   client whose every request carries the consumed launch evidence;
//!   the broker revalidates peer + evidence per call.
//! * [`read_migration_launch_outcome`] + [`MigrationLaunchIssuer`] —
//!   the root/helper-side surfaces (SC-DEF-41 and the launch-evidence
//!   issuer respectively).
//!
//! None of these types ever carries signing material, a credential
//! path, or a DSN.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{BorrowedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use central_backup::app::MigrationOperatorResult;
use central_foundation::failure::Failure;
use central_infra::authority::{
    B05MaterializePostgresMigrationRequest, B05MaterializePostgresMigrationResult,
    B05MigrationLaunchResult, BrokerOutcome, BrokerRequest, BrokerResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use time::OffsetDateTime;

use super::migration_launch::{MigrationLaunchOutcome, MigrationLaunchOutcomeState};
use super::protocol::{
    B05_MIGRATION_FRAME_MARKER, CENTRAL_MIGRATE_GID, CENTRAL_MIGRATE_UID,
    ISSUE_MIGRATION_LAUNCH_RPC, MIGRATION_CONSUME_EMPTY_PROOF_RPC, MIGRATION_CONSUME_RESET_RPC,
    MIGRATION_CREATE_RECORD_RPC, MIGRATION_ISSUE_EMPTY_PROOF_RPC, MIGRATION_ISSUE_RESET_RPC,
    MIGRATION_READ_OUTCOME_RPC, MIGRATION_READ_RECORD_RPC, MIGRATION_REPLACE_RECORD_RPC,
    MIGRATION_REPORT_OUTCOME_RPC, MIGRATION_VERIFY_EMPTY_PROOF_RPC, MIGRATION_VERIFY_RESET_RPC,
};
use super::wire;
use crate::sys::peercred::peercred;
use crate::sys::scm_rights;

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_migration_client", msg.into())
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_migration_client", msg.into())
}

/// `broker.ProductionSocketPath` on the helper/operator side —
/// [`super::PRODUCTION_SOCKET_PATH`].
pub fn broker_socket_path() -> PathBuf {
    PathBuf::from(super::PRODUCTION_SOCKET_PATH)
}

/// `b05PeerCredentials` + the root check every broker-facing client
/// performs before it writes a request byte: the far end of the
/// protected socket must be the root-owned broker.
fn verify_broker_peer(conn: &UnixStream) -> Result<(), Failure> {
    let peer = peercred(conn)
        .map_err(|e| internal(format!("broker peer verification failed: {}", e.message())))?;
    if peer.uid.as_raw() != 0 {
        return Err(denied(
            "migration authority broker peer verification failed",
        ));
    }
    Ok(())
}

/// Write one JSON-line `BrokerRequest` and read the response line —
/// the shared transport under every plain-RPC call in this file.
fn round_trip(socket_path: &str, request: &BrokerRequest) -> Result<BrokerResponse, Failure> {
    let mut conn = UnixStream::connect(socket_path)
        .map_err(|e| internal(format!("migration authority dial: {e}")))?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| internal(format!("migration authority deadline: {e}")))?;
    conn.set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| internal(format!("migration authority deadline: {e}")))?;
    verify_broker_peer(&conn)?;
    let mut encoded = serde_json::to_vec(request)
        .map_err(|e| internal(format!("migration authority marshal: {e}")))?;
    encoded.push(b'\n');
    conn.write_all(&encoded)
        .map_err(|e| internal(format!("migration authority write: {e}")))?;
    let mut line = String::new();
    // One bounded line — the same cap the broker's own scanner
    // enforces.
    let mut byte = [0u8; 1];
    while line.len() <= super::protocol::MAX_REQUEST_LINE {
        match conn.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0] as char);
            }
            Err(e) => return Err(internal(format!("migration authority read: {e}"))),
        }
    }
    if line.is_empty() {
        return Err(internal("migration authority read: connection closed"));
    }
    serde_json::from_str(&line).map_err(|e| internal(format!("migration authority read: {e}")))
}

/// `migrationRPCResponseError` — a denial or mismatched response is a
/// typed refusal carrying the broker's evidence message; the caller's
/// `Is(ErrRecordAbsent)` seam matches on the absent-record code.
fn response_error(purpose: &str, resp: &BrokerResponse) -> Failure {
    if resp.evidence.code == super::protocol::MIGRATION_RECORD_ABSENT_CODE {
        return Failure::not_found(
            "broker_migration_record_absent",
            format!("broker migration RPC {purpose}: {}", resp.evidence.message),
        );
    }
    denied(format!(
        "broker migration RPC {purpose} ({}): {}",
        resp.evidence.code, resp.evidence.message
    ))
}

/// `MigrationClient` — the B05 descriptor-transport client.
pub struct MigrationClient {
    socket_path: String,
}

impl MigrationClient {
    /// `NewMigrationClient`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `MaterializePostgresMigration` — the B05 custody exchange:
    /// request frame, destination descriptor, framed ack, ownership
    /// confirmation, completion response.
    ///
    /// `descriptor` is the *empty* memfd the broker writes the
    /// `central_migration` passfile into; it must already satisfy
    /// `validateB05Descriptor` (CLOEXEC, regular root-owned `0400`
    /// tmpfs file, size 0, ≤1 link).
    pub fn materialize_postgres_migration(
        &self,
        wire: &B05MaterializePostgresMigrationRequest,
        descriptor: BorrowedFd<'_>,
    ) -> Result<B05MaterializePostgresMigrationResult, Failure> {
        const CLASS: &str = "B05 client: ";
        macro_rules! err {
            ($($a:tt)*) => { internal(format!("{}{}", CLASS, format!($($a)*))) };
        }
        if self.socket_path.is_empty() || wire.launch_evidence_id.is_empty() {
            return Err(err!("incomplete materialization request"));
        }
        if uuid::Uuid::parse_str(&wire.operation_id).is_err() {
            return Err(err!("invalid operation ID"));
        }
        if wire.service != "central-migrate"
            || wire.target != "scm_rights"
            || wire.uid != CENTRAL_MIGRATE_UID
            || wire.gid != CENTRAL_MIGRATE_GID
        {
            return Err(err!("invalid fixed binding"));
        }
        validate_b05_descriptor(descriptor)?;
        let conn = UnixStream::connect(&self.socket_path).map_err(|e| err!("dial broker: {e}"))?;
        conn.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| err!("deadline: {e}"))?;
        conn.set_write_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| err!("deadline: {e}"))?;
        verify_broker_peer(&conn).map_err(|e| internal(format!("{}{}", CLASS, e.message())))?;

        // `wire.PeerUID, wire.PeerPID = geteuid(), getpid()` — the
        // caller's own kernel identity, bound into the request.
        let mut wire = wire.clone();
        wire.peer_uid = rustix::process::geteuid().as_raw();
        wire.peer_pid = rustix::process::getpid().as_raw_pid();
        let payload = serde_json::to_value(&wire)
            .and_then(|v| serde_json::to_string(&v))
            .map_err(|e| err!("marshal request: {e}"))?;
        let raw: Box<RawValue> =
            serde_json::from_str(&payload).map_err(|e| err!("marshal request: {e}"))?;
        let request = BrokerRequest {
            operation_id: wire.operation_id.clone(),
            purpose: super::protocol::MATERIALIZE_POSTGRES_MIGRATION_RPC.to_owned(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([("request".to_owned(), raw)])),
        };
        let request_bytes =
            serde_json::to_vec(&request).map_err(|e| err!("marshal request: {e}"))?;
        let mut frame = Vec::with_capacity(5 + request_bytes.len());
        frame.push(B05_MIGRATION_FRAME_MARKER);
        frame.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&request_bytes);
        (&conn)
            .write_all(&frame)
            .map_err(|e| err!("write request: {e}"))?;

        // `WriteMsgUnix([0x01], rights(descriptor))` — the empty
        // destination memfd crosses before the broker resolves the
        // credential.
        scm_rights::send(&conn, &[0x01], &[descriptor])
            .map_err(|e| err!("send descriptor: {e}"))?;

        // Framed ack: `[0x01 | len16 | uid16 | gid16 | proof]`.
        let mut ack = [0u8; 7];
        (&conn)
            .read_exact(&mut ack)
            .map_err(|e| err!("read acknowledgement: {e}"))?;
        if ack[0] != 0x01
            || u16::from_be_bytes([ack[3], ack[4]]) != CENTRAL_MIGRATE_UID as u16
            || u16::from_be_bytes([ack[5], ack[6]]) != CENTRAL_MIGRATE_GID as u16
        {
            return Err(err!("invalid broker acknowledgement"));
        }
        let proof_len = u16::from_be_bytes([ack[1], ack[2]]) as usize;
        if proof_len == 0 {
            return Err(err!("empty broker acknowledgement"));
        }
        let mut proof = vec![0u8; proof_len];
        (&conn)
            .read_exact(&mut proof)
            .map_err(|e| err!("read acknowledgement: {e}"))?;

        // `conn.Write([0x03])` — the ownership confirmation.
        (&conn)
            .write_all(&[0x03])
            .map_err(|e| err!("confirm handoff: {e}"))?;

        let mut line = Vec::with_capacity(4096);
        let mut byte = [0u8; 1];
        loop {
            match (&conn).read(&mut byte) {
                Ok(0) => return Err(err!("broker completion failed")),
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    line.push(byte[0]);
                    if line.len() > super::protocol::MAX_REQUEST_LINE {
                        return Err(err!("broker completion failed"));
                    }
                }
                Err(e) => return Err(err!("broker completion failed: {e}")),
            }
        }
        let response: BrokerResponse =
            serde_json::from_slice(&line).map_err(|_| err!("broker completion failed"))?;
        if response.outcome != BrokerOutcome::Success {
            return Err(err!("broker completion failed"));
        }
        let result: B05MaterializePostgresMigrationResult = response
            .result
            .and_then(|r| serde_json::from_value(r).ok())
            .filter(|r: &B05MaterializePostgresMigrationResult| r.operation_id == wire.operation_id)
            .ok_or_else(|| err!("invalid completion result"))?;
        Ok(result)
    }

    /// The `central-migrate` operator's fixed materialization call —
    /// builds the operation/evidence-scoped B05 request with the
    /// closed `central-migrate`/`scm_rights`/986:986 binding; nothing
    /// caller-controlled enters the frame.
    pub fn materialize_operator_credential(
        &self,
        operation_id: uuid::Uuid,
        launch_evidence_id: &str,
        descriptor: BorrowedFd<'_>,
    ) -> Result<B05MaterializePostgresMigrationResult, Failure> {
        self.materialize_postgres_migration(
            &B05MaterializePostgresMigrationRequest {
                launch_evidence_id: launch_evidence_id.to_owned(),
                binding_id: String::new(),
                operation_id: operation_id.to_string(),
                receipt_id: String::new(),
                receipt_hmac: String::new(),
                fencing_token: 0,
                peer_uid: 0,
                peer_pid: 0,
                service: "central-migrate".into(),
                target: "scm_rights".into(),
                uid: CENTRAL_MIGRATE_UID,
                gid: CENTRAL_MIGRATE_GID,
            },
            descriptor,
        )
    }
}

/// `validateB05Descriptor` — the client's pre-send descriptor gate:
/// CLOEXEC, a regular root-owned `0400` tmpfs file, size 0, at most
/// one link. Upstream accepts the anonymous (0-link) memfd or a
/// 1-link named file and rejects every other alias.
fn validate_b05_descriptor(fd: BorrowedFd<'_>) -> Result<(), Failure> {
    fn fail() -> Failure {
        internal("B05 client: descriptor is not an empty root-owned sealed file")
    }
    let borrowed = fd;
    let flags = rustix::io::fcntl_getfd(borrowed)
        .map_err(|_| internal("B05 client: descriptor lacks CLOEXEC"))?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(internal("B05 client: descriptor lacks CLOEXEC"));
    }
    let stat = rustix::fs::fstat(borrowed).map_err(|_| fail())?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_nlink > 1
        || stat.st_size != 0
        || stat.st_mode & 0o777 != 0o400
    {
        return Err(fail());
    }
    // `TMPFS_MAGIC` — same constant `sys::memfd` validates against.
    const TMPFS_MAGIC: rustix::fs::FsWord = 0x0102_1994;
    let fs = rustix::fs::fstatfs(borrowed)
        .map_err(|_| internal("B05 client: descriptor is not tmpfs"))?;
    if fs.f_type != TMPFS_MAGIC {
        return Err(internal("B05 client: descriptor is not tmpfs"));
    }
    Ok(())
}

/// `MigrationAuthorityClient` — the `central-migrate`-only client for
/// the closed broker authority RPCs. It carries no signing keys and
/// no local state.
#[derive(Clone)]
pub struct MigrationAuthorityClient {
    socket_path: String,
    operation_id: uuid::Uuid,
    launch_evidence_id: String,
}

impl MigrationAuthorityClient {
    /// `NewMigrationAuthorityClient` — socket, operation, and the
    /// consumed launch evidence are all required.
    pub fn new(
        socket_path: impl Into<String>,
        operation_id: uuid::Uuid,
        launch_evidence_id: impl Into<String>,
    ) -> Result<Self, Failure> {
        let socket_path = socket_path.into();
        let launch_evidence_id = launch_evidence_id.into();
        if socket_path.is_empty() || operation_id.is_nil() || launch_evidence_id.is_empty() {
            return Err(internal(
                "migration authority client requires socket, operation ID, and launch evidence",
            ));
        }
        Ok(Self {
            socket_path,
            operation_id,
            launch_evidence_id,
        })
    }

    /// `call` — one authority RPC. Every request carries the launch
    /// evidence alongside `request`; the broker's
    /// `validateMigrationAuthorityLaunch` gate binds evidence, peer,
    /// and operation before the dispatch runs.
    fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        purpose: &str,
        payload: &P,
    ) -> Result<R, Failure> {
        let request_raw: Box<RawValue> = serde_json::from_str(
            &serde_json::to_string(payload).map_err(|e| internal(format!("marshal: {e}")))?,
        )
        .map_err(|e| internal(format!("marshal: {e}")))?;
        let evidence_raw: Box<RawValue> = serde_json::from_str(
            &serde_json::to_string(&self.launch_evidence_id)
                .map_err(|e| internal(format!("marshal: {e}")))?,
        )
        .map_err(|e| internal(format!("marshal: {e}")))?;
        let request = BrokerRequest {
            operation_id: self.operation_id.to_string(),
            purpose: purpose.to_owned(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([
                ("request".to_owned(), request_raw),
                ("launch_evidence_id".to_owned(), evidence_raw),
            ])),
        };
        let response = round_trip(&self.socket_path, &request)?;
        if response.operation_id != self.operation_id.to_string()
            || response.outcome != BrokerOutcome::Success
        {
            return Err(response_error(purpose, &response));
        }
        match response.result {
            Some(result) => serde_json::from_value(result).map_err(|_| {
                internal(format!(
                    "migration authority {purpose} returned invalid result"
                ))
            }),
            None => serde_json::from_value(serde_json::Value::Null).map_err(|_| {
                internal(format!(
                    "migration authority {purpose} returned invalid result"
                ))
            }),
        }
    }

    fn call_unit<P: Serialize>(&self, purpose: &str, payload: &P) -> Result<(), Failure> {
        let _: serde_json::Value = self.call(purpose, payload)?;
        Ok(())
    }

    /// `ReportStarted` — the operator's first durable lifecycle mark.
    pub fn report_started(&self) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct OutcomeRequest<'a> {
            launch_evidence_id: &'a str,
            state: MigrationLaunchOutcomeState,
        }
        self.call_unit(
            MIGRATION_REPORT_OUTCOME_RPC,
            &OutcomeRequest {
                launch_evidence_id: &self.launch_evidence_id,
                state: MigrationLaunchOutcomeState::Started,
            },
        )
    }

    /// `ReportTerminal` — persist the terminal outcome; `succeeded`
    /// clears `reason`, exactly like upstream.
    pub fn report_terminal(
        &self,
        succeeded: bool,
        reason: &str,
        result: Option<&MigrationOperatorResult>,
    ) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct OutcomeRequest<'a> {
            launch_evidence_id: &'a str,
            state: MigrationLaunchOutcomeState,
            #[serde(skip_serializing_if = "str::is_empty")]
            reason: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            operator_result: Option<&'a MigrationOperatorResult>,
        }
        let (state, reason) = if succeeded {
            (MigrationLaunchOutcomeState::Succeeded, "")
        } else {
            (MigrationLaunchOutcomeState::Failed, reason)
        };
        self.call_unit(
            MIGRATION_REPORT_OUTCOME_RPC,
            &OutcomeRequest {
                launch_evidence_id: &self.launch_evidence_id,
                state,
                reason,
                operator_result: result,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Proof RPCs — `BrokerProofService`'s method set as plain calls; the
// central-kernel composition wraps them into the async port traits.
// ---------------------------------------------------------------------------

/// The `migrationProofRequest` wire shape — closed optional fields,
/// exactly like upstream's tagged struct.
#[derive(Serialize)]
struct ProofRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    issue_empty: Option<&'a super::proof::IssueEmptyTargetProofRequestWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a super::provisioning::TargetIdentityWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<&'a super::proof::VerifiedEmptyTargetWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issue_reset: Option<&'a super::proof::IssueResetConfirmationRequestWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<&'a super::proof::ResetConfirmationWire>,
}

/// `migrationProvisioningRequest`.
#[derive(Serialize)]
struct ProvRequest<'a> {
    target: &'a super::provisioning::TargetIdentityWire,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<&'a super::provisioning::ProvisioningRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replace: Option<&'a super::provisioning::ReplaceProvisioningRecordRequest>,
}

impl MigrationAuthorityClient {
    /// `IssueEmptyTargetProof`.
    pub fn issue_empty_target_proof(
        &self,
        req: &super::proof::IssueEmptyTargetProofRequestWire,
    ) -> Result<super::proof::VerifiedEmptyTargetWire, Failure> {
        if req.operation_id.to_string() != self.operation_id.to_string() {
            return Err(internal("issue proof operation binding mismatch"));
        }
        self.call(
            MIGRATION_ISSUE_EMPTY_PROOF_RPC,
            &ProofRequest {
                issue_empty: Some(req),
                target: None,
                proof: None,
                issue_reset: None,
                reset: None,
            },
        )
    }

    /// `VerifyEmptyTarget`.
    pub fn verify_empty_target(
        &self,
        target: &super::provisioning::TargetIdentityWire,
        proof: &super::proof::VerifiedEmptyTargetWire,
    ) -> Result<(), Failure> {
        self.call_unit(
            MIGRATION_VERIFY_EMPTY_PROOF_RPC,
            &ProofRequest {
                issue_empty: None,
                target: Some(target),
                proof: Some(proof),
                issue_reset: None,
                reset: None,
            },
        )
    }

    /// `ConsumeEmptyProof` — bare consume (no target binding).
    pub fn consume_empty_proof(
        &self,
        proof: &super::proof::VerifiedEmptyTargetWire,
    ) -> Result<(), Failure> {
        self.call_unit(
            MIGRATION_CONSUME_EMPTY_PROOF_RPC,
            &ProofRequest {
                issue_empty: None,
                target: None,
                proof: Some(proof),
                issue_reset: None,
                reset: None,
            },
        )
    }

    /// `ConsumeVerifiedEmptyTarget`.
    pub fn consume_verified_empty_target(
        &self,
        target: &super::provisioning::TargetIdentityWire,
        proof: &super::proof::VerifiedEmptyTargetWire,
    ) -> Result<(), Failure> {
        self.call_unit(
            MIGRATION_CONSUME_EMPTY_PROOF_RPC,
            &ProofRequest {
                issue_empty: None,
                target: Some(target),
                proof: Some(proof),
                issue_reset: None,
                reset: None,
            },
        )
    }

    /// `IssueResetConfirmation`.
    pub fn issue_reset_confirmation(
        &self,
        req: &super::proof::IssueResetConfirmationRequestWire,
    ) -> Result<super::proof::ResetConfirmationWire, Failure> {
        if req.operation_id.to_string() != self.operation_id.to_string() {
            return Err(internal("issue reset operation binding mismatch"));
        }
        self.call(
            MIGRATION_ISSUE_RESET_RPC,
            &ProofRequest {
                issue_empty: None,
                target: None,
                proof: None,
                issue_reset: Some(req),
                reset: None,
            },
        )
    }

    /// `VerifyResetConfirmation`.
    pub fn verify_reset_confirmation(
        &self,
        confirmation: &super::proof::ResetConfirmationWire,
    ) -> Result<(), Failure> {
        self.call_unit(
            MIGRATION_VERIFY_RESET_RPC,
            &ProofRequest {
                issue_empty: None,
                target: None,
                proof: None,
                issue_reset: None,
                reset: Some(confirmation),
            },
        )
    }

    /// `ConsumeResetConfirmation` — bare consume.
    pub fn consume_reset_confirmation(
        &self,
        confirmation: &super::proof::ResetConfirmationWire,
    ) -> Result<(), Failure> {
        self.call_unit(
            MIGRATION_CONSUME_RESET_RPC,
            &ProofRequest {
                issue_empty: None,
                target: None,
                proof: None,
                issue_reset: None,
                reset: Some(confirmation),
            },
        )
    }

    /// `ConsumeVerifiedResetConfirmation`.
    pub fn consume_verified_reset_confirmation(
        &self,
        target: &super::provisioning::TargetIdentityWire,
        confirmation: &super::proof::ResetConfirmationWire,
    ) -> Result<(), Failure> {
        self.call_unit(
            MIGRATION_CONSUME_RESET_RPC,
            &ProofRequest {
                issue_empty: None,
                target: Some(target),
                proof: None,
                issue_reset: None,
                reset: Some(confirmation),
            },
        )
    }

    /// `readRecord`.
    pub fn read_record(
        &self,
        target: &super::provisioning::TargetIdentityWire,
    ) -> Result<super::provisioning::ProvisioningRecord, Failure> {
        self.call(
            MIGRATION_READ_RECORD_RPC,
            &ProvRequest {
                target,
                record: None,
                replace: None,
            },
        )
    }

    /// `createRecord`.
    pub fn create_record(
        &self,
        target: &super::provisioning::TargetIdentityWire,
        record: &super::provisioning::ProvisioningRecord,
    ) -> Result<super::provisioning::ProvisioningRecord, Failure> {
        self.call(
            MIGRATION_CREATE_RECORD_RPC,
            &ProvRequest {
                target,
                record: Some(record),
                replace: None,
            },
        )
    }

    /// `replaceRecord`.
    pub fn replace_record(
        &self,
        request: &super::provisioning::ReplaceProvisioningRecordRequest,
    ) -> Result<super::provisioning::ProvisioningRecord, Failure> {
        self.call(
            MIGRATION_REPLACE_RECORD_RPC,
            &ProvRequest {
                target: &request.target,
                record: None,
                replace: Some(request),
            },
        )
    }
}

/// `ReadMigrationLaunchOutcome` — the root/runtime query surface used
/// by the CLI through the helper. It grants no reporting authority:
/// only the operator peer can call `migration_report_launch_outcome`.
pub fn read_migration_launch_outcome(
    socket_path: &str,
    operation_id: &str,
    evidence_id: &str,
) -> Result<MigrationLaunchOutcome, Failure> {
    if socket_path.is_empty() || operation_id.is_empty() || evidence_id.is_empty() {
        return Err(internal(
            "migration launch outcome query requires socket, operation ID, and evidence",
        ));
    }
    let payload_raw: Box<RawValue> = serde_json::from_str(
        &serde_json::to_string(&serde_json::json!({ "launch_evidence_id": evidence_id }))
            .map_err(|e| internal(format!("migration outcome marshal: {e}")))?,
    )
    .map_err(|e| internal(format!("migration outcome marshal: {e}")))?;
    let request = BrokerRequest {
        operation_id: operation_id.to_owned(),
        purpose: MIGRATION_READ_OUTCOME_RPC.to_owned(),
        session_token: String::new(),
        payload: Some(BTreeMap::from([("request".to_owned(), payload_raw)])),
    };
    let response = round_trip(socket_path, &request)?;
    if response.operation_id != operation_id || response.outcome != BrokerOutcome::Success {
        return Err(response_error(MIGRATION_READ_OUTCOME_RPC, &response));
    }
    response
        .result
        .and_then(|r| serde_json::from_value(r).ok())
        .ok_or_else(|| internal("migration outcome decode"))
}

/// `MigrationLaunchIssuer` — submits helper-observed child identity
/// to the separately running protected broker, which alone mints
/// durable evidence. Implements the helper's
/// `MigrationLaunchEvidenceIssuer` port.
pub struct MigrationLaunchIssuer {
    socket_path: String,
}

/// The helper-observed child identity submitted to the broker —
/// `helper.MigrationLaunchEvidence`.
pub struct MigrationLaunchEvidence {
    pub pid: i32,
    pub pidfd: RawFd,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    pub operation_id: String,
    pub expires_at: OffsetDateTime,
}

impl MigrationLaunchIssuer {
    /// `NewMigrationLaunchEvidenceIssuer`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `IssueMigrationLaunch` — `issue_migration_launch` with the
    /// operation ID preserved, not regenerated.
    pub fn issue_migration_launch(
        &self,
        evidence: &MigrationLaunchEvidence,
    ) -> Result<String, Failure> {
        const CLASS: &str = "broker migration launch: ";
        macro_rules! err {
            ($($a:tt)*) => { internal(format!("{}{}", CLASS, format!($($a)*))) };
        }
        if self.socket_path.is_empty() || evidence.pid <= 0 || evidence.pidfd < 0 {
            return Err(err!("incomplete child identity"));
        }
        if uuid::Uuid::parse_str(&evidence.operation_id).is_err() {
            return Err(err!("invalid operation ID"));
        }
        #[derive(Serialize)]
        struct IssueRequest<'a> {
            pid: i32,
            process_start: &'a str,
            executable: &'a str,
            mode: &'a str,
            operation_id: &'a str,
            #[serde(with = "wire::rfc3339")]
            expires_at: OffsetDateTime,
        }
        let payload_raw: Box<RawValue> = serde_json::from_str(
            &serde_json::to_string(&IssueRequest {
                pid: evidence.pid,
                process_start: &evidence.process_start,
                executable: &evidence.executable,
                mode: &evidence.mode,
                operation_id: &evidence.operation_id,
                expires_at: evidence.expires_at,
            })
            .map_err(|e| err!("marshal: {e}"))?,
        )
        .map_err(|e| err!("marshal: {e}"))?;
        let request = BrokerRequest {
            operation_id: evidence.operation_id.clone(),
            purpose: ISSUE_MIGRATION_LAUNCH_RPC.to_owned(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([("request".to_owned(), payload_raw)])),
        };
        let response = round_trip(&self.socket_path, &request)
            .map_err(|e| internal(format!("{}{}", CLASS, e.message())))?;
        if response.operation_id != evidence.operation_id
            || response.outcome != BrokerOutcome::Success
        {
            return Err(response_error(ISSUE_MIGRATION_LAUNCH_RPC, &response));
        }
        let result: B05MigrationLaunchResult = response
            .result
            .and_then(|r| serde_json::from_value(r).ok())
            .ok_or_else(|| err!("invalid issued evidence ID"))?;
        if uuid::Uuid::parse_str(&result.launch_evidence_id).is_err() {
            return Err(err!("invalid issued evidence ID"));
        }
        Ok(result.launch_evidence_id)
    }
}

// ---------------------------------------------------------------------------
// `MigrationProvisioningStore` + `MigrationOperatorInspector` + the
// client's own `BrokerProofService` — one authority value satisfying
// `central_backup::app::MigrationAuthority`, exactly like upstream
// composes `MigrationOperator::with_authority` over the same client.
// ---------------------------------------------------------------------------

use central_backup::app::{
    ProvisioningRecord, ProvisioningRecordStore, ReplaceProvisioningRecordRequest,
};
use central_backup::domain::{
    ExternalRecordState, ProvisioningPhase, ResetConfirmation, SessionBinding, TargetIdentity,
    VerifiedEmptyTarget,
};
use central_backup::port::{
    BoxFuture, BrokerProofService, IssueEmptyTargetProofRequest, IssueResetConfirmationRequest,
    ProtectedOperatorState, ProtectedOperatorStateInspector,
};

use super::proof::{
    IssueEmptyTargetProofRequestWire, IssueResetConfirmationRequestWire, ResetConfirmationWire,
    VerifiedEmptyTargetWire,
};
use super::provisioning::{
    ProvisioningJournalIntent, ProvisioningRecord as RecordWire,
    ReplaceProvisioningRecordRequest as ReplaceWire, SessionBindingWire, TargetIdentityWire,
};
use super::wire::GO_ZERO_TIME;

/// `toAppRecord` — wire record → the capability `app.ProvisioningRecord`.
fn to_app_record(record: &RecordWire) -> ProvisioningRecord {
    ProvisioningRecord {
        target: TargetIdentity::from(&record.target),
        operation_id: record.operation_id,
        state: record.state.clone(),
        phase: record.phase.clone(),
        candidate_id: record.candidate_id,
        candidate_digest: record.candidate_digest.clone(),
        baseline_digest: record.baseline_digest.clone(),
        epoch_zero_markers: record.epoch_zero_markers.clone().unwrap_or_default(),
        session_binding: SessionBinding::from(&record.session_binding),
        revision: record.revision,
        created_at: (record.created_at != GO_ZERO_TIME).then_some(record.created_at),
        updated_at: (record.updated_at != GO_ZERO_TIME).then_some(record.updated_at),
    }
}

/// `fromAppRecord`.
fn from_app_record(record: &ProvisioningRecord) -> RecordWire {
    RecordWire {
        target: TargetIdentityWire::from(&record.target),
        operation_id: record.operation_id,
        state: record.state.clone(),
        phase: record.phase.clone(),
        candidate_id: record.candidate_id,
        candidate_digest: record.candidate_digest.clone(),
        baseline_digest: record.baseline_digest.clone(),
        epoch_zero_markers: Some(record.epoch_zero_markers.clone()),
        session_binding: SessionBindingWire::from(&record.session_binding),
        revision: record.revision,
        created_at: record.created_at.unwrap_or(GO_ZERO_TIME),
        updated_at: record.updated_at.unwrap_or(GO_ZERO_TIME),
    }
}

/// `NewMigrationOperatorInspector` + `NewMigrationProvisioningStore`
/// over one [`MigrationAuthorityClient`] — the production
/// [`central_backup::app::MigrationAuthority`] `central-migrate` is
/// composed with. `target` is bound exactly like upstream's
/// `NewMigrationOperatorInspector(client, target)`: the operator
/// discovers it from the `central_migration` session after connect.
#[derive(Clone)]
pub struct BrokerMigrationAuthority {
    client: MigrationAuthorityClient,
    target: TargetIdentity,
}

impl BrokerMigrationAuthority {
    /// `NewMigrationOperatorInspector`/`NewMigrationProvisioningStore`
    /// — bind the client to the session-discovered target.
    #[must_use]
    pub fn new(client: MigrationAuthorityClient, target: TargetIdentity) -> Self {
        Self { client, target }
    }
}

impl BrokerProofService for BrokerMigrationAuthority {
    async fn issue_empty_target_proof(
        &self,
        req: IssueEmptyTargetProofRequest,
    ) -> Result<VerifiedEmptyTarget, Failure> {
        let wire = IssueEmptyTargetProofRequestWire {
            operation_id: req.operation_id,
            target: TargetIdentityWire::from(&req.target),
            session_binding: SessionBindingWire::from(&req.session_binding),
            baseline_digest: req.baseline_digest,
        };
        self.client
            .issue_empty_target_proof(&wire)
            .map(|w| VerifiedEmptyTarget::from(&w))
    }

    async fn verify_empty_target(
        &self,
        target: &TargetIdentity,
        proof: &VerifiedEmptyTarget,
    ) -> Result<(), Failure> {
        self.client.verify_empty_target(
            &TargetIdentityWire::from(target),
            &VerifiedEmptyTargetWire::from(proof),
        )
    }

    async fn consume_empty_proof(&self, proof: VerifiedEmptyTarget) -> Result<(), Failure> {
        self.client
            .consume_empty_proof(&VerifiedEmptyTargetWire::from(&proof))
    }

    async fn consume_verified_empty_target(
        &self,
        target: &TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> Result<(), Failure> {
        self.client.consume_verified_empty_target(
            &TargetIdentityWire::from(target),
            &VerifiedEmptyTargetWire::from(&proof),
        )
    }

    async fn issue_reset_confirmation(
        &self,
        req: IssueResetConfirmationRequest,
    ) -> Result<ResetConfirmation, Failure> {
        let wire = IssueResetConfirmationRequestWire {
            operation_id: req.operation_id,
            target_fingerprint: req.target_fingerprint,
        };
        self.client
            .issue_reset_confirmation(&wire)
            .map(|w| ResetConfirmation::from(&w))
    }

    async fn verify_reset_confirmation(
        &self,
        confirmation: &ResetConfirmation,
    ) -> Result<(), Failure> {
        self.client
            .verify_reset_confirmation(&ResetConfirmationWire::from(confirmation))
    }

    async fn consume_reset_confirmation(
        &self,
        confirmation: ResetConfirmation,
    ) -> Result<(), Failure> {
        self.client
            .consume_reset_confirmation(&ResetConfirmationWire::from(&confirmation))
    }

    async fn consume_verified_reset_confirmation(
        &self,
        target: &TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> Result<(), Failure> {
        self.client.consume_verified_reset_confirmation(
            &TargetIdentityWire::from(target),
            &ResetConfirmationWire::from(&confirmation),
        )
    }
}

impl ProtectedOperatorStateInspector for BrokerMigrationAuthority {
    /// `MigrationOperatorInspector.Inspect` — read the bound target's
    /// record; `record_absent` projects to `Absent`, never an error.
    fn inspect_operator_state<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<ProtectedOperatorState, Failure>> {
        Box::pin(async move {
            let record = match self
                .client
                .read_record(&TargetIdentityWire::from(&self.target))
            {
                Ok(record) => record,
                Err(e) if e.code() == "broker_migration_record_absent" => {
                    return Ok(ProtectedOperatorState {
                        record_state: ExternalRecordState::Absent,
                        target: self.target.clone(),
                        ..ProtectedOperatorState::default()
                    });
                }
                Err(e) => return Err(e),
            };
            Ok(ProtectedOperatorState {
                record_state: ExternalRecordState::parse(&record.state),
                provisioning_phase: ProvisioningPhase::parse(&record.phase),
                target: TargetIdentity::from(&record.target),
                operation_id: record.operation_id,
                revision: record.revision,
                session_binding: SessionBinding::from(&record.session_binding),
                detected_at: (record.updated_at != GO_ZERO_TIME).then_some(record.updated_at),
            })
        })
    }
}

impl ProvisioningRecordStore for BrokerMigrationAuthority {
    /// `MigrationProvisioningStore.ReadProvisioningRecord`.
    fn read_provisioning_record<'a>(
        &'a self,
        target: &'a TargetIdentity,
    ) -> BoxFuture<'a, Result<ProvisioningRecord, Failure>> {
        Box::pin(async move {
            self.client
                .read_record(&TargetIdentityWire::from(target))
                .map(|r| to_app_record(&r))
        })
    }

    /// `MigrationProvisioningStore.ReplaceProvisioningRecord` — the
    /// client-side request carries a zero `JournalIntent`, exactly
    /// like upstream's `ReplaceProvisioningRecordRequest{Target,
    /// ExpectedRevision, Next}` literal: the store builds the journaled
    /// intent itself.
    fn replace_provisioning_record<'a>(
        &'a self,
        req: ReplaceProvisioningRecordRequest,
    ) -> BoxFuture<'a, Result<ProvisioningRecord, Failure>> {
        Box::pin(async move {
            let wire = ReplaceWire {
                target: TargetIdentityWire::from(&req.target),
                expected_revision: req.expected_revision,
                next: from_app_record(&req.next),
                journal_intent: ProvisioningJournalIntent::default(),
            };
            self.client.replace_record(&wire).map(|r| to_app_record(&r))
        })
    }

    /// `MigrationProvisioningStore.CreateProvisioningRecord`.
    fn create_provisioning_record<'a>(
        &'a self,
        target: &'a TargetIdentity,
        record: ProvisioningRecord,
    ) -> BoxFuture<'a, Result<ProvisioningRecord, Failure>> {
        Box::pin(async move {
            self.client
                .create_record(&TargetIdentityWire::from(target), &from_app_record(&record))
                .map(|r| to_app_record(&r))
        })
    }
}
