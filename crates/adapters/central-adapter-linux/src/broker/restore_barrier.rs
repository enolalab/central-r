//! `internal/adapter/authority/broker/recovery_authority_rpc.go`'s
//! `RestoreBarrierClient` — the runtime's read-only view of the
//! broker-owned restore barrier. It receives no repository path,
//! credential, or ticket material and is suitable for the serving
//! startup gate.
//!
//! Unlike [`super::lifecycle_client::LifecycleClient`], which wraps
//! every payload as `{"request": …}`, this client mirrors upstream's
//! dedicated transport verbatim: a raw `BrokerRequest` whose
//! `Payload` is the *empty* object — the exact shape
//! `dispatch_restore_barrier_inspect` and
//! `dispatch_restore_ticket_barrier_inspect` require (a nil payload
//! denies; a non-empty one never carries a `"request"` member these
//! RPCs would read). Each call mints a fresh UUIDv7 request identity
//! and requires the response to echo it.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Instant;

use central_backup::recovery::operation::RestoreOperation;
use central_foundation::failure::Failure;
use central_infra::authority::{BrokerOutcome, BrokerRequest, BrokerResponse};
use serde::Deserialize;
use uuid::Uuid;

use super::recovery_journal::{RestoreOperationWire, operation_from_wire};

pub(crate) const RESTORE_BARRIER_INSPECT_RPC: &str = "inspect_restore_barrier";
pub(crate) const RESTORE_TICKET_BARRIER_INSPECT_RPC: &str = "inspect_restore_ticket_barrier";

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("restore_barrier_client", msg.into())
}
fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("restore_barrier_client", msg.into())
}

/// `restoreBarrierResult` — the client-side decode half of the
/// server wire in `recovery_authority.rs`.
#[derive(Deserialize)]
struct RestoreBarrierResult {
    active: bool,
    operation: RestoreOperationWire,
}

/// `restoreTicketBarrierResult` — `null` decodes to `None`, exactly
/// like a nil Go slice.
#[derive(Deserialize)]
struct RestoreTicketBarrierResult {
    operation_ids: Option<Vec<Uuid>>,
}

/// `RestoreBarrierClient` is the runtime's read-only view of the
/// broker-owned restore barrier.
pub(crate) struct RestoreBarrierClient {
    socket_path: PathBuf,
}

impl RestoreBarrierClient {
    /// `NewRestoreBarrierClient` — an empty socket path refuses at
    /// composition, like upstream.
    pub(crate) fn new(socket_path: PathBuf) -> Result<Self, Failure> {
        if socket_path.as_os_str().is_empty() {
            return Err(denied("restore barrier client requires broker socket"));
        }
        Ok(Self { socket_path })
    }

    /// The shared request/response leg: fresh UUIDv7 identity, raw
    /// empty-object payload, deadline-bounded I/O, echo check.
    fn inspect<T: serde::de::DeserializeOwned>(
        &self,
        deadline: Instant,
        purpose: &str,
    ) -> Result<T, Failure> {
        let operation_id = Uuid::now_v7();
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| internal(format!("{purpose}: request deadline expired")))?;
        let mut conn = UnixStream::connect(&self.socket_path)
            .map_err(|e| internal(format!("{purpose}: dial: {e}")))?;
        conn.set_read_timeout(Some(timeout))
            .and_then(|()| conn.set_write_timeout(Some(timeout)))
            .map_err(|e| internal(format!("{purpose}: deadline: {e}")))?;
        let req = BrokerRequest {
            operation_id: operation_id.to_string(),
            purpose: purpose.to_owned(),
            session_token: String::new(),
            // `map[string]json.RawMessage{}` — present and exactly
            // empty, the only shape these dispatches accept.
            payload: Some(BTreeMap::new()),
        };
        let mut encoded = serde_json::to_vec(&req)
            .map_err(|e| internal(format!("{purpose}: encode request: {e}")))?;
        encoded.push(b'\n');
        conn.write_all(&encoded)
            .map_err(|e| internal(format!("{purpose}: write request: {e}")))?;
        let mut line = String::new();
        BufReader::new(
            conn.try_clone()
                .map_err(|e| internal(format!("{purpose}: read clone: {e}")))?,
        )
        .read_line(&mut line)
        .map_err(|e| internal(format!("{purpose}: read response: {e}")))?;
        if line.is_empty() {
            return Err(internal(format!("{purpose}: read: connection closed")));
        }
        let response: BrokerResponse = serde_json::from_str(&line)
            .map_err(|e| internal(format!("{purpose}: read response: {e}")))?;
        if response.operation_id != operation_id.to_string()
            || response.outcome != BrokerOutcome::Success
        {
            return Err(denied(format!("{purpose}: inspection denied")));
        }
        serde_json::from_str(
            response
                .result
                .as_deref()
                .map_or("null", serde_json::value::RawValue::get),
        )
        .map_err(|e| internal(format!("{purpose}: decode response: {e}")))
    }

    /// `InspectRestoreBarrier` — the single non-terminal operation
    /// the protected barrier reports, or `None` when the barrier is
    /// inactive (upstream's `active = false` return pair).
    pub(crate) fn inspect_restore_barrier(
        &self,
        deadline: Instant,
    ) -> Result<Option<RestoreOperation>, Failure> {
        let result: RestoreBarrierResult = self.inspect(deadline, RESTORE_BARRIER_INSPECT_RPC)?;
        if result.active {
            // A terminal operation (served or abandoned) must never be
            // reported as the active barrier occupant; this mirrors
            // `inspectRestoreBarrierLocked`, which excludes both
            // outcomes via `IsTerminal` rather than only `Ready`.
            let operation = operation_from_wire(&result.operation)
                .map_err(|_| internal("inspect_restore_barrier: response is invalid"))?;
            if operation.validate().is_err() || operation.is_terminal() {
                return Err(internal("inspect_restore_barrier: response is invalid"));
            }
            return Ok(Some(operation));
        }
        if !result.operation.operation_id.is_nil() {
            return Err(internal("inspect_restore_barrier: response is ambiguous"));
        }
        Ok(None)
    }

    /// `IssuedTicketOperationIDs` — apply's own resolution read
    /// (SC-DEF-59): the operation IDs of every currently valid,
    /// unconsumed restore ticket. Returns the raw list undecided —
    /// the caller's resolver owns the cardinality decision, exactly
    /// as [`Self::inspect_restore_barrier`]'s contract does.
    pub(crate) fn issued_ticket_operation_ids(
        &self,
        deadline: Instant,
    ) -> Result<Vec<Uuid>, Failure> {
        let result: RestoreTicketBarrierResult =
            self.inspect(deadline, RESTORE_TICKET_BARRIER_INSPECT_RPC)?;
        Ok(result.operation_ids.unwrap_or_default())
    }
}
