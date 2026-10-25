//! `lifecycle_client.go` + `lifecycle_client_linux.go` — the helper's
//! typed client for the broker's lifecycle authority RPCs: bound
//! one-use authorizations, dead-owner proofs, B04 adopt/issue-proof,
//! and the descriptor-only B04 materialize transport.
//!
//! The client never opens the broker's durable state itself — every
//! call is one newline-terminated `BrokerRequest` on the protected
//! Unix socket, or the `0xB4` framed transport for the descriptor
//! handoff. `materialize_minio_root` reproduces upstream's exact
//! sequence: euid-0 + tmpfs-target gates, `O_EXCL|O_NOFOLLOW` `0400`
//! file, framed request, `SCM_RIGHTS` descriptor send, 7-byte ack,
//! proof read, chmod/chown, `0x03` commit, JSON response.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use central_foundation::failure::Failure;
use central_infra::authority::{
    B04AdoptRequest, B04AdoptResult, B04IssueProofRequest, B04MaterializeRequest,
    B04MaterializeResult, BrokerOutcome, BrokerRequest, BrokerResponse, LifecycleAuthorization,
    LifecycleAuthorizationRequest,
};
use central_infra::domain::B04LifecycleEvidence;
use central_infra::port::{BootstrapHandoff, DeadOwnerProof, MountProof};

use super::protocol;

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_lifecycle_client", msg.into())
}
fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_lifecycle_client", msg.into())
}
fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("broker_lifecycle_client", msg.into())
}

/// `ErrB04SCMRightsTransportRequired` — the fail-closed refusal when
/// the descriptor transport's host preconditions do not hold.
pub const ERR_B04_SCM_RIGHTS_TRANSPORT_REQUIRED: &str =
    "broker lifecycle: B04 SCM_RIGHTS transport required";

/// `LifecycleClient` invokes the broker's one-use lifecycle
/// authorization RPCs over its protected Unix socket. Used by the
/// helper rather than an unauthoritative in-process broker service.
pub struct LifecycleClient {
    socket_path: PathBuf,
    adoptions: Mutex<BTreeMap<String, B04AdoptResult>>,
}

/// `TMPFS_MAGIC` — `statfs.f_type` for the tmpfs handoff target.
const TMPFS_MAGIC: rustix::fs::FsWord = 0x0102_1994;

/// `b04UUID` — `life-` prefixes are stripped before the operation id
/// is framed as a UUID.
fn b04_uuid(operation_id: &str) -> String {
    operation_id
        .strip_prefix("life-")
        .unwrap_or(operation_id)
        .to_owned()
}

impl LifecycleClient {
    /// `NewLifecycleClient`.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            adoptions: Mutex::new(BTreeMap::new()),
        }
    }

    /// `AdoptB03Minio` — the mandatory lifecycle bootstrap authority
    /// port: incomplete bindings deny, and the adoption is cached so a
    /// later [`Self::materialize_minio_root`] can prove it.
    ///
    /// # Errors
    /// `broker_lifecycle_client` on the RPC failure or an incomplete
    /// binding in the response.
    pub fn adopt_b03_minio(&self, evidence: &B04LifecycleEvidence) -> Result<(), Failure> {
        let req = B04AdoptRequest {
            instance_id: evidence.instance_id.clone(),
            purpose: "minio_root_v1".into(),
            operation_id: b04_uuid(&evidence.operation_id),
            fencing_token: evidence.fencing_token,
            stopped_topology_proof: evidence.stopped_topology_proof.clone(),
            mount_release_proof: evidence.mount_release_proof.clone(),
            binding_evidence: evidence.binding_evidence.clone(),
            evidence_expires_at: evidence.expires_at.unwrap_or(super::wire::GO_ZERO_TIME),
        };
        let result: B04AdoptResult = self.call("adopt_b03_minio_bootstrap", &req)?;
        if result.binding_id.is_empty() || result.generation_id.is_empty() {
            return Err(internal(
                "broker lifecycle: B04 adoption returned incomplete binding",
            ));
        }
        self.adoptions
            .lock()
            .map_err(|_| internal("adoption cache lock poisoned"))?
            .insert(evidence.operation_id.clone(), result);
        Ok(())
    }

    /// `IssueLifecycleProof` — asks the broker to durably sign the
    /// caller's own stopped-topology/mount-release/binding tokens
    /// (SC-DEF-12) before [`Self::adopt_b03_minio`] is called with the
    /// same evidence.
    ///
    /// # Errors
    /// `broker_lifecycle_client` on the RPC failure.
    pub fn issue_lifecycle_proof(&self, evidence: &B04LifecycleEvidence) -> Result<(), Failure> {
        let req = B04IssueProofRequest {
            instance_id: evidence.instance_id.clone(),
            operation_id: b04_uuid(&evidence.operation_id),
            fencing_token: evidence.fencing_token,
            stopped_topology_proof: evidence.stopped_topology_proof.clone(),
            mount_release_proof: evidence.mount_release_proof.clone(),
            binding_evidence: evidence.binding_evidence.clone(),
            evidence_expires_at: evidence.expires_at.unwrap_or(super::wire::GO_ZERO_TIME),
        };
        self.call_unit("issue_b04_lifecycle_proof", &req)
    }

    /// `MaterializeMinioRootRequest` — the typed materialize request
    /// over the ordinary JSON transport (which the broker denies;
    /// materialization is descriptor-only).
    ///
    /// # Errors
    /// `broker_lifecycle_client` on marshal/dial/write/read/decode or
    /// a non-success outcome.
    pub fn materialize_minio_root_request(
        &self,
        req: &B04MaterializeRequest,
    ) -> Result<B04MaterializeResult, Failure> {
        self.call("materialize_minio_root", req)
    }

    /// `MaterializeMinioRoot` — the descriptor-only transport:
    /// `0xB4` framed request, `SCM_RIGHTS` descriptor send, 7-byte ack
    /// `[0x01, proofLen:u16be, uid:u16be, gid:u16be]`, proof bytes,
    /// chmod/chown, `0x03` commit, JSON response.
    ///
    /// # Errors
    /// [`ERR_B04_SCM_RIGHTS_TRANSPORT_REQUIRED`] when the host
    /// preconditions (euid 0, registered adoption, exact target,
    /// service, uid/gid) do not hold; `broker_lifecycle_client` on any
    /// transport failure or denial.
    pub fn materialize_minio_root(
        &self,
        handoff: &BootstrapHandoff,
    ) -> Result<MountProof, Failure> {
        let adoption = {
            let adoptions = self
                .adoptions
                .lock()
                .map_err(|_| internal("adoption cache lock poisoned"))?;
            match adoptions.get(&handoff.b04_operation_id) {
                Some(a) => a.clone(),
                None => return Err(denied(ERR_B04_SCM_RIGHTS_TRANSPORT_REQUIRED)),
            }
        };
        self.materialize_minio_root_transport(handoff, &adoption)
    }

    /// `materializeMinioRoot` (linux) — the framed transport itself.
    fn materialize_minio_root_transport(
        &self,
        handoff: &BootstrapHandoff,
        adoption: &B04AdoptResult,
    ) -> Result<MountProof, Failure> {
        let expected_target = Path::new("/run/central-infra")
            .join(&handoff.instance_id)
            .join("secrets");
        if rustix::process::geteuid().as_raw() != 0
            || handoff.instance_id.is_empty()
            || handoff.target != expected_target.to_string_lossy()
            || handoff.service != central_infra::domain::ServiceMode::Minio
            || handoff.uid != 1000
            || handoff.gid != 1000
        {
            return Err(denied(ERR_B04_SCM_RIGHTS_TRANSPORT_REQUIRED));
        }
        // Helper-side process — unfiltered; `create_dir_all`/`OpenOptions`
        // may emit whatever `std::fs` reaches on this toolchain.
        std::fs::create_dir_all(&handoff.target)
            .map_err(|e| internal(format!("broker lifecycle: handoff target mkdir: {e}")))?;
        let stats = rustix::fs::statfs(&handoff.target)
            .map_err(|e| internal(format!("broker lifecycle: handoff target statfs: {e}")))?;
        if stats.f_type != TMPFS_MAGIC {
            return Err(internal("broker lifecycle: handoff target is not tmpfs"));
        }
        let path = Path::new(&handoff.target).join("minio-root-password");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| internal(format!("broker lifecycle: open handoff file: {e}")))?;

        let op_text = b04_uuid(&handoff.b04_operation_id);
        let op_id = uuid::Uuid::parse_str(&op_text)
            .map_err(|e| invalid(format!("broker lifecycle: invalid B04 operation: {e}")))?;
        // PeerUID/PeerPID must be this process's own identity: this
        // connection is dialed from the helper daemon itself, so that
        // is exactly what the broker's SO_PEERCRED read of it reports.
        let payload = B04MaterializeRequest {
            binding_id: adoption.binding_id.clone(),
            operation_id: op_id.to_string(),
            receipt_id: String::new(),
            receipt_hmac: String::new(),
            fencing_token: handoff.b04_fencing_token,
            peer_uid: rustix::process::getuid().as_raw(),
            peer_pid: rustix::process::getpid().as_raw_pid(),
            service: "minio".into(),
            target: "/run/secrets/minio-root-password".into(),
            uid: 1000,
            gid: 1000,
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| internal(format!("broker lifecycle: marshal: {e}")))?;
        let request = serde_json::to_vec(&BrokerRequest {
            operation_id: op_id.to_string(),
            purpose: "materialize_minio_root".into(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([(
                "request".to_owned(),
                serde_json::from_slice::<Box<serde_json::value::RawValue>>(&payload_bytes)
                    .map_err(|e| internal(format!("broker lifecycle: marshal: {e}")))?,
            )])),
        })
        .map_err(|e| internal(format!("broker lifecycle: marshal: {e}")))?;

        let mut conn = UnixStream::connect(&self.socket_path)
            .map_err(|e| internal(format!("broker lifecycle: dial: {e}")))?;
        let mut frame = Vec::with_capacity(request.len() + 5);
        frame.push(protocol::B04_FRAME_MARKER);
        frame.extend_from_slice(&(request.len() as u32).to_be_bytes());
        frame.extend_from_slice(&request);
        conn.write_all(&frame)
            .map_err(|e| internal(format!("broker lifecycle: write frame: {e}")))?;
        protocol::send_descriptor(&conn, file.as_fd())?;

        // The fixed 7-byte ack — a denial is a variable-length JSON
        // response instead, so a non-0x01 first byte means the stream
        // has already been consumed into that denial.
        let mut ack = [0u8; 7];
        conn.read_exact(&mut ack)
            .map_err(|e| internal(format!("broker lifecycle: B04 acknowledgement failed: {e}")))?;
        if ack[0] != 0x01 {
            return Err(denied(format!(
                "broker lifecycle: B04 handoff denied (ack=0x{:02x})",
                ack[0]
            )));
        }
        let proof_len = u16::from_be_bytes([ack[1], ack[2]]);
        if proof_len == 0
            || u16::from_be_bytes([ack[3], ack[4]]) != 1000
            || u16::from_be_bytes([ack[5], ack[6]]) != 1000
        {
            return Err(denied(ERR_B04_SCM_RIGHTS_TRANSPORT_REQUIRED));
        }
        let mut proof = vec![0u8; proof_len as usize];
        conn.read_exact(&mut proof)
            .map_err(|e| internal(format!("broker lifecycle: B04 proof read: {e}")))?;
        drop(file); // upstream `unix.Close(fd)` before chmod/chown
        // These path-based calls run in the *helper* process, which
        // installs no seccomp filter — only the broker daemon hardens
        // (`broker::daemon::run_broker_daemon_at`); `fchmodat`/
        // `fchownat` emissions are safe here (ADR 0044).
        rustix::fs::chmodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::from_raw_mode(0o400),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|e| internal(format!("broker lifecycle: chmod handoff file: {e}")))?;
        rustix::fs::chown(
            &path,
            Some(rustix::process::Uid::from_raw(1000)),
            Some(rustix::process::Gid::from_raw(1000)),
        )
        .map_err(|e| internal(format!("broker lifecycle: chown handoff file: {e}")))?;
        conn.write_all(&[0x03])
            .map_err(|e| internal(format!("broker lifecycle: B04 commit: {e}")))?;
        let response = read_response_line(&mut conn)?;
        if response.outcome != BrokerOutcome::Success {
            return Err(denied("broker lifecycle: B04 commit failed"));
        }
        Ok(MountProof {
            handoff_digest: String::from_utf8_lossy(&proof).into_owned(),
            mount_path: path.to_string_lossy().into_owned(),
            confirmed: true,
        })
    }

    /// `AuthorizeBoundLifecycle` — `authorize_lifecycle` → the bound
    /// claim.
    ///
    /// # Errors
    /// `broker_lifecycle_client` on RPC failure or denial.
    pub fn authorize_bound_lifecycle(
        &self,
        request: &LifecycleAuthorizationRequest,
    ) -> Result<LifecycleAuthorization, Failure> {
        self.call(protocol::AUTHORIZE_LIFECYCLE_RPC, request)
    }

    /// `ConsumeBoundLifecycleAuthorization` — `consume_lifecycle`
    /// with `{claim, request}`.
    ///
    /// # Errors
    /// `broker_lifecycle_client` on RPC failure or denial.
    pub fn consume_bound_lifecycle_authorization(
        &self,
        claim: &LifecycleAuthorization,
        request: &LifecycleAuthorizationRequest,
    ) -> Result<(), Failure> {
        #[derive(serde::Serialize)]
        struct Consume<'a> {
            claim: &'a LifecycleAuthorization,
            request: &'a LifecycleAuthorizationRequest,
        }
        self.call_unit(protocol::CONSUME_LIFECYCLE_RPC, &Consume { claim, request })
    }

    /// `VerifyDeadOwner` — `verify_lifecycle_lock_owner` → the
    /// broker-attested proof (the broker, not lease expiry, decides
    /// whether the PID is dead).
    ///
    /// # Errors
    /// `broker_lifecycle_client` on RPC failure or denial.
    pub fn verify_dead_owner(
        &self,
        lock_id: &str,
        owner_pid: i32,
    ) -> Result<DeadOwnerProof, Failure> {
        #[derive(serde::Serialize)]
        struct OwnerRequest<'a> {
            lock_id: &'a str,
            owner_pid: i32,
        }
        #[derive(serde::Deserialize)]
        struct OwnerProof {
            #[serde(rename = "LockID")]
            lock_id: String,
            #[serde(rename = "OwnerPID")]
            owner_pid: i32,
            #[serde(rename = "Dead")]
            dead: bool,
            #[serde(rename = "VerifiedAt", with = "super::wire::rfc3339")]
            verified_at: time::OffsetDateTime,
        }
        let proof: OwnerProof = self.call(
            protocol::VERIFY_LIFECYCLE_LOCK_OWNER_RPC,
            &OwnerRequest { lock_id, owner_pid },
        )?;
        Ok(DeadOwnerProof {
            lock_id: proof.lock_id,
            owner_pid: proof.owner_pid,
            dead: proof.dead,
            verified_at: proof.verified_at,
        })
    }

    /// `BindPostgresServiceRole` — ADR 0019 §4's rotate-then-sync
    /// write RPC: `value` is the exact passfile bytes the caller has
    /// already ALTERed live on the PostgreSQL server for the named
    /// purpose's service role. Only the root helper may call this —
    /// `isRootBackupHelperPeer` gates it at the transport.
    ///
    /// # Errors
    /// `broker_lifecycle_client` on RPC failure or denial.
    pub fn bind_postgres_service_role(
        &self,
        instance_id: &str,
        purpose: &str,
        value: &[u8],
    ) -> Result<(), Failure> {
        #[derive(serde::Serialize)]
        struct BindRequest<'a> {
            #[serde(rename = "InstanceID")]
            instance_id: &'a str,
            #[serde(rename = "Purpose")]
            purpose: &'a str,
            #[serde(rename = "Value")]
            value: String,
        }
        self.call_unit(
            protocol::POSTGRES_SERVICE_ROLE_BIND_RPC,
            &BindRequest {
                instance_id,
                purpose,
                value: super::wire::b64_raw_encode(value),
            },
        )
    }

    /// `call` — `time.Now().UnixNano()` operation identity, like
    /// upstream's default.
    fn call<R: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        purpose: &str,
        payload: &R,
    ) -> Result<T, Failure> {
        let op_id = format!(
            "helper-lifecycle-{}",
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        self.call_with_operation_id(&op_id, purpose, payload)
    }

    fn call_unit<R: serde::Serialize>(&self, purpose: &str, payload: &R) -> Result<(), Failure> {
        let _: serde_json::Value = self.call(purpose, payload)?;
        Ok(())
    }

    /// `callWithOperationID` — preserves the operation identity that
    /// downstream authority records bind. Empty ids refuse.
    fn call_with_operation_id<R: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        operation_id: &str,
        purpose: &str,
        payload: &R,
    ) -> Result<T, Failure> {
        if operation_id.is_empty() {
            return Err(invalid("broker lifecycle: operation ID is required"));
        }
        let data = serde_json::to_vec(payload)
            .map_err(|e| internal(format!("broker lifecycle: marshal: {e}")))?;
        let mut conn = UnixStream::connect(&self.socket_path)
            .map_err(|e| internal(format!("broker lifecycle: dial: {e}")))?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| internal(format!("broker lifecycle: dial timeout: {e}")))?;
        let value: Box<serde_json::value::RawValue> = serde_json::from_slice(&data)
            .map_err(|e| internal(format!("broker lifecycle: marshal: {e}")))?;
        let req = BrokerRequest {
            operation_id: operation_id.to_owned(),
            purpose: purpose.to_owned(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([("request".to_owned(), value)])),
        };
        let mut encoded = serde_json::to_vec(&req)
            .map_err(|e| internal(format!("broker lifecycle: marshal: {e}")))?;
        encoded.push(b'\n');
        conn.write_all(&encoded)
            .map_err(|e| internal(format!("broker lifecycle: write: {e}")))?;
        let response = read_response_line(&mut conn)?;
        if response.outcome != BrokerOutcome::Success {
            return Err(denied(format!(
                "broker lifecycle: {}",
                response.evidence.message
            )));
        }
        match response.result {
            Some(result) => serde_json::from_value(result)
                .map_err(|e| internal(format!("broker lifecycle: decode result: {e}"))),
            // `nil` result decodes as the Go zero value.
            None => serde_json::from_value(serde_json::Value::Null)
                .map_err(|e| internal(format!("broker lifecycle: decode result: {e}"))),
        }
    }
}

/// `json.NewDecoder(conn).Decode(&response)` — one JSON line off the
/// wire.
fn read_response_line(conn: &mut UnixStream) -> Result<BrokerResponse, Failure> {
    let mut reader = BufReader::new(
        conn.try_clone()
            .map_err(|e| internal(format!("broker lifecycle: read clone: {e}")))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| internal(format!("broker lifecycle: read: {e}")))?;
    if line.is_empty() {
        return Err(internal("broker lifecycle: read: connection closed"));
    }
    serde_json::from_str(&line).map_err(|e| internal(format!("broker lifecycle: read: {e}")))
}
