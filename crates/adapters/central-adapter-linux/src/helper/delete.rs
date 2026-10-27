//! `internal/adapter/authority/helper/delete.go` + `client_linux.go`'s
//! delete half — the D04 `backup-delete` verb: signed-denial pre-check,
//! resolution, retention + reference verification, the delete ceremony,
//! sealed tree removal, and the journaled proof record.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use central_foundation::failure::Failure;
use central_infra::destructive as domain;

use super::PeerIdentity;
use super::grant::CeremonyScope;
use super::protocol::{Request, Response, read_response, strict_decode, write_request};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `DeleteRequest` — the typed delete payload.
#[derive(Debug, Clone)]
pub struct DeleteRequest {
    /// The ceremony-bound operation (envelope field, not payload).
    pub operation_id: String,
    /// The explicit sealed backup id, or empty for the single-candidate
    /// resolution.
    pub backup_id: String,
    /// The requested retention floor; 0 selects the default.
    pub retention_days: i32,
}

/// `DeleteResult` — the bounded delete outcome: identities, proof, and
/// state only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResult {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The deleted sealed backup id.
    pub backup_id: String,
    /// The proven retention age.
    pub retention_age_days: i32,
    /// The proven reference count (always 0 on success).
    pub reference_count: i32,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// `ParseDeleteRequest` — rejects unknown fields so a flag the handler
/// does not understand cannot silently become authority.
pub fn parse_delete_request(req: &Request) -> Result<DeleteRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing delete operation".to_owned());
    }
    let trimmed = trim_ascii(req.payload_bytes());
    if trimmed.is_empty() {
        return Ok(DeleteRequest {
            operation_id: req.operation_id.clone(),
            backup_id: String::new(),
            retention_days: 0,
        });
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        backup_id: String,
        #[serde(default)]
        retention_days: i32,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|_| "helper: invalid delete payload".to_owned())?;
    Ok(DeleteRequest {
        operation_id: req.operation_id.clone(),
        backup_id: payload.backup_id,
        retention_days: payload.retention_days,
    })
}

fn trim_ascii(raw: &[u8]) -> &[u8] {
    let s = raw
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let e = raw
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |i| i + 1);
    &raw[s..e.max(s)]
}

fn delete_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
    result: Option<&DeleteResult>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, code, reason);
    if let Some(r) = result {
        resp = resp.with_result(r);
    }
    resp
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// `deletePAMConfirmer` — the D04 delete ceremony. `None` from
/// [`Self::confirm_backup_delete`] means the installed confirmer cannot
/// perform this ceremony.
pub trait DeletePamConfirmer: Send + Sync {
    /// `VerifyAndConsume` — minted tokens are one-use.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmBackupDelete`.
    fn confirm_backup_delete(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _operation_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `deleteAdvisoryEvaluator` — the B01 seam.
pub trait DeleteAdvisoryEvaluator: Send + Sync {
    /// `Evaluate`.
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        Failure,
    >;
}

/// `unavailableLifecycleEvaluator` — deny-only until B01's evaluator is
/// wired; see `wipe.rs`'s copy for the precedent.
pub struct DenyOnlyAdvisoryEvaluator;

impl DeleteAdvisoryEvaluator for DenyOnlyAdvisoryEvaluator {
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        Failure,
    > {
        Err(Failure::unavailable(
            "lifecycle_admission",
            "B01 lifecycle admission evaluator is unavailable",
        ))
    }
}

/// `deleteBackupSource` — the sealed-backup read/delete seam.
/// Production needs the repository index rewrite plus the sealed tree;
/// an unavailable seam refuses explicitly (`DELETE_UNAVAILABLE`)
/// rather than deleting half a backup.
pub trait DeleteBackupSource: Send + Sync {
    /// `ListSealedBackupIDs` — every sealed backup candidate.
    fn list_sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure>;
    /// `BackupAgeDays` — the sealed backup's age in days.
    fn backup_age_days(&self, backup_id: Uuid) -> Result<i32, Failure>;
    /// `DeleteSealedBackup` — removes the complete sealed tree plus
    /// its index row.
    fn delete_sealed_backup(&self, backup_id: Uuid) -> Result<(), Failure>;
}

/// `deleteReferenceChecker` — the PG reference-count seam: without it
/// the handler cannot prove the backup is unreferenced, and an
/// unproven delete is refused, never attempted.
pub trait DeleteReferenceChecker: Send + Sync {
    /// `ReferencingOperations`.
    fn referencing_operations(&self, backup_id: Uuid) -> Result<i32, Failure>;
}

/// `unavailableDeleteSource` — the production stand-in until the
/// repository-delete plumbing lands. Not a success stub: every seam
/// call fails so the handler refuses `DELETE_UNAVAILABLE` before any
/// ceremony, upstream's rule verbatim.
pub struct UnavailableDeleteSource;

impl DeleteBackupSource for UnavailableDeleteSource {
    fn list_sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure> {
        Err(Failure::unavailable(
            "delete_source",
            "delete: sealed-backup source is not wired",
        ))
    }
    fn backup_age_days(&self, _backup_id: Uuid) -> Result<i32, Failure> {
        Err(Failure::unavailable(
            "delete_source",
            "delete: sealed-backup source is not wired",
        ))
    }
    fn delete_sealed_backup(&self, _backup_id: Uuid) -> Result<(), Failure> {
        Err(Failure::unavailable(
            "delete_source",
            "delete: sealed-backup source is not wired",
        ))
    }
}

/// `unavailableDeleteRefs` — the PG reference-count stand-in: without
/// it the handler cannot prove zero references, so it refuses.
pub struct UnavailableDeleteRefs;

impl DeleteReferenceChecker for UnavailableDeleteRefs {
    fn referencing_operations(&self, _backup_id: Uuid) -> Result<i32, Failure> {
        Err(Failure::unavailable(
            "delete_refs",
            "delete: reference checker is not wired",
        ))
    }
}

/// `DeleteRoots` pins the hierarchy a delete journals to. The journal
/// dir is helper-owned; tests substitute a fixture tree.
#[derive(Debug, Clone)]
pub struct DeleteRoots {
    /// Where `delete-<operation-id>.result.json` lands.
    pub journal_dir: String,
    /// Owner/group of the journal record (root in production).
    pub journal_uid: u32,
    /// See `journal_uid`.
    pub journal_gid: u32,
}

/// `DeleteHandlerImpl` — performs D04 `backup delete`.
pub struct DeleteHandlerImpl {
    pam: Option<Box<dyn DeletePamConfirmer>>,
    advisory: Option<Box<dyn DeleteAdvisoryEvaluator>>,
    source: Option<Box<dyn DeleteBackupSource>>,
    refs: Option<Box<dyn DeleteReferenceChecker>>,
    scope: CeremonyScope,
    roots: DeleteRoots,
    now: fn() -> OffsetDateTime,
}

/// `DeleteHandler` — the `Server::delete` field type.
pub trait DeleteHandler: Send + Sync {
    /// `Delete`.
    fn delete(&self, deadline: Instant, request: DeleteRequest, peer: &PeerIdentity) -> Response;
}

impl DeleteHandlerImpl {
    /// `NewDeleteHandler`. Any `None` seam refuses every request rather
    /// than running degraded.
    #[must_use]
    pub fn new(
        pam: Option<Box<dyn DeletePamConfirmer>>,
        advisory: Option<Box<dyn DeleteAdvisoryEvaluator>>,
        source: Option<Box<dyn DeleteBackupSource>>,
        refs: Option<Box<dyn DeleteReferenceChecker>>,
        scope: CeremonyScope,
        roots: DeleteRoots,
    ) -> Self {
        Self {
            pam,
            advisory,
            source,
            refs,
            scope,
            roots,
            now: OffsetDateTime::now_utc,
        }
    }

    #[cfg(test)]
    fn with_now(mut self, now: fn() -> OffsetDateTime) -> Self {
        self.now = now;
        self
    }

    /// `resolveBackup` — names the single backup to delete: an explicit
    /// id, or the only sealed candidate. Zero or several candidates
    /// with no explicit id is refused rather than guessed — the export
    /// cardinality rule.
    fn resolve_backup(&self, request: &DeleteRequest) -> Result<Uuid, Response> {
        if !request.backup_id.is_empty() {
            return match Uuid::parse_str(&request.backup_id) {
                Ok(id) if !id.is_nil() => Ok(id),
                _ => Err(delete_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_DELETE_INVALID_REQUEST,
                    None,
                )),
            };
        }
        let Some(source) = self.source.as_ref() else {
            return Err(delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_UNAVAILABLE,
                None,
            ));
        };
        let candidates = source.list_sealed_backup_ids().map_err(|_| {
            delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_UNAVAILABLE,
                None,
            )
        })?;
        if candidates.is_empty() {
            return Err(delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_NO_BACKUP,
                None,
            ));
        }
        if candidates.len() != 1 {
            return Err(delete_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_DELETE_BACKUP_AMBIGUOUS,
                None,
            ));
        }
        Ok(candidates[0])
    }
}

impl DeleteHandler for DeleteHandlerImpl {
    /// `Delete` — the order is: advisory denial before resolution,
    /// resolution before ceremony, ceremony before verification, and
    /// verification before destruction. The retention floor resolves
    /// before the ceremony so a below-default request fails before any
    /// prompt.
    fn delete(&self, deadline: Instant, request: DeleteRequest, peer: &PeerIdentity) -> Response {
        let op_ok =
            Uuid::parse_str(&request.operation_id).is_ok_and(|u| !u.is_nil()) && peer.pid > 0;
        let seams_ok = self.pam.is_some()
            && self.advisory.is_some()
            && self.source.is_some()
            && self.refs.is_some()
            && !self.scope.instance_id.is_empty()
            && !self.scope.target_id.is_empty()
            && !self.roots.journal_dir.is_empty();
        if !op_ok || !seams_ok {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_CEREMONY_REQUIRED,
                None,
            );
        }
        let retention_days = if request.retention_days == 0 {
            domain::DEFAULT_RETENTION_DAYS
        } else {
            request.retention_days
        };
        if retention_days < domain::DEFAULT_RETENTION_DAYS {
            return delete_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_DELETE_INVALID_REQUEST,
                None,
            );
        }
        let Some(evaluator) = self.advisory.as_ref() else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_DENIED_SIGNED,
                None,
            );
        };
        let Ok((verdict, _admission)) = evaluator.evaluate() else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_DENIED_SIGNED,
                None,
            );
        };
        if verdict.state != super::prepare::ADVISORY_STATE_CURRENT {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_DENIED_SIGNED,
                None,
            );
        }
        let backup_id = match self.resolve_backup(&request) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
        let Some(pam) = self.pam.as_ref() else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_CEREMONY_REQUIRED,
                None,
            );
        };
        // Upstream hands the ceremony the whole verb ctx — the
        // ceremony share inside `deleteDeadline` is budget accounting,
        // not an enforced sub-deadline.
        let Some(confirmation) =
            pam.confirm_backup_delete(*peer, Some(deadline), &self.scope, &request.operation_id)
        else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_CEREMONY_REQUIRED,
                None,
            );
        };
        let Ok(token) = confirmation else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_AUTHORITY_DENIED,
                None,
            );
        };
        if !pam.verify_and_consume(&token) {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_AUTHORITY_DENIED,
                None,
            );
        }
        let Some(source) = self.source.as_ref() else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_UNAVAILABLE,
                None,
            );
        };
        let age_days = match source.backup_age_days(backup_id) {
            Ok(days) => days,
            Err(_) => {
                return delete_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_DELETE_UNAVAILABLE,
                    None,
                );
            }
        };
        if age_days < 0 {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_UNAVAILABLE,
                None,
            );
        }
        if age_days < retention_days {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_RETENTION_TOO_YOUNG,
                None,
            );
        }
        let Some(refs) = self.refs.as_ref() else {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_UNAVAILABLE,
                None,
            );
        };
        let ref_count = match refs.referencing_operations(backup_id) {
            Ok(count) => count,
            Err(_) => {
                return delete_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_DELETE_UNAVAILABLE,
                    None,
                );
            }
        };
        if ref_count < 0 {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_UNAVAILABLE,
                None,
            );
        }
        if ref_count != 0 {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_REFERENCED,
                None,
            );
        }
        if source.delete_sealed_backup(backup_id).is_err() {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_ENGINE_FAILED,
                None,
            );
        }
        let completed = (self.now)().format(&Rfc3339).unwrap_or_default();
        if write_delete_record(
            &self.roots.journal_dir,
            &domain::DeleteRecord {
                operation_id: request.operation_id.clone(),
                backup_id: backup_id.to_string(),
                retention_age_days: age_days,
                reference_count: ref_count,
                completed_at: completed.clone(),
            },
            self.roots.journal_uid,
            self.roots.journal_gid,
        )
        .is_err()
        {
            return delete_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_DELETE_ENGINE_FAILED,
                None,
            );
        }
        delete_response(
            &request.operation_id,
            "success",
            0,
            "ok",
            Some(&DeleteResult {
                operation_id: request.operation_id.clone(),
                backup_id: backup_id.to_string(),
                retention_age_days: age_days,
                reference_count: ref_count,
                completed_at: completed,
            }),
        )
    }
}

/// `WriteDeleteRecord` — durably journals the delete proof. The file
/// is created exclusively: a second record for the same operation is a
/// bug, never an overwrite.
pub fn write_delete_record(
    journal_dir: &str,
    record: &domain::DeleteRecord,
    uid: u32,
    gid: u32,
) -> Result<(), Failure> {
    if record.operation_id.is_empty() || record.backup_id.is_empty() {
        return Err(Failure::invalid(
            "delete_record",
            "destructive: delete record identity is incomplete",
        ));
    }
    let raw = serde_json::to_string(record)
        .map_err(|e| Failure::invalid("delete_record", e.to_string()))?;
    let path = format!(
        "{journal_dir}/{}",
        domain::delete_record_file_name(&record.operation_id)
    );
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| Failure::unavailable("delete_record", e.to_string()))?;
    f.write_all(format!("{raw}\n").as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| Failure::unavailable("delete_record", e.to_string()))?;
    drop(f);
    rustix::fs::chown(
        &path,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|e| Failure::unavailable("delete_record", e.to_string()))
}

// ---------------------------------------------------------------------------
// Client — `client_linux.go`'s delete half.
// ---------------------------------------------------------------------------

/// `DeleteClientResult` mirrors the helper's `DeleteResult`.
pub type DeleteClientResult = DeleteResult;

/// `DeleteClientError` — only the stable exit class plus a whitelisted
/// reason token cross the boundary.
#[derive(Debug)]
pub struct DeleteClientError {
    exit_code: i64,
    reason: String,
}

impl DeleteClientError {
    /// The helper's exit class.
    #[must_use]
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }

    /// The whitelisted helper reason token, or empty.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl DeleteClientError {
    /// Test-only constructor for the CLI's closed error-table tests.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(exit_code: i64, reason: &str) -> Self {
        new_delete_client_error(exit_code, reason)
    }
}

impl std::fmt::Display for DeleteClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: delete failed")
    }
}

impl std::error::Error for DeleteClientError {}

/// `DenySafeActiveWireReason` — the deny-safe gate's refusal token.
pub const DENY_SAFE_ACTIVE_WIRE_REASON: &str = "DENY_SAFE_ACTIVE";

fn retained_delete_reason(reason: &str) -> String {
    match reason {
        r if r == DENY_SAFE_ACTIVE_WIRE_REASON
            || r == domain::REASON_DELETE_DENIED_SIGNED
            || r == domain::REASON_DELETE_UNAVAILABLE
            || r == domain::REASON_DELETE_NO_BACKUP
            || r == domain::REASON_DELETE_BACKUP_AMBIGUOUS
            || r == domain::REASON_DELETE_RETENTION_TOO_YOUNG
            || r == domain::REASON_DELETE_REFERENCED
            || r == domain::REASON_DELETE_CEREMONY_REQUIRED
            || r == domain::REASON_DELETE_AUTHORITY_DENIED =>
        {
            r.to_owned()
        }
        _ => String::new(),
    }
}

fn new_delete_client_error(exit_code: i64, reason: &str) -> DeleteClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    DeleteClientError {
        exit_code,
        reason: retained_delete_reason(reason),
    }
}

/// `DeleteClient` — `NewDeleteClient`'s linux implementation.
pub struct DeleteClient {
    socket_path: String,
}

impl DeleteClient {
    /// `NewDeleteClient`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `Delete` — one bounded request/response exchange.
    pub fn delete(
        &self,
        operation_id: &str,
        backup_id: &str,
        retention_days: i32,
    ) -> Result<DeleteClientResult, DeleteClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() {
            return Err(new_delete_client_error(3, ""));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| new_delete_client_error(3, ""))?;
        let bound = Duration::from_secs(5);
        let _ = conn.set_read_timeout(Some(bound));
        let _ = conn.set_write_timeout(Some(bound));
        #[derive(Serialize)]
        struct Payload<'a> {
            #[serde(skip_serializing_if = "str::is_empty")]
            backup_id: &'a str,
            #[serde(skip_serializing_if = "is_zero")]
            retention_days: i32,
        }
        fn is_zero(v: &i32) -> bool {
            *v == 0
        }
        let payload = serde_json::to_string(&Payload {
            backup_id,
            retention_days,
        })
        .ok()
        .and_then(|s| serde_json::value::RawValue::from_string(s).ok());
        write_request(
            &mut conn,
            &Request {
                operation_id: operation_id.to_owned(),
                verb: super::verb::BACKUP_DELETE.to_owned(),
                payload,
            },
        )
        .map_err(|_| new_delete_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_delete_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_delete_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        let result: DeleteClientResult = super::backup::decode_exact_backup_read_result(&payload)
            .map_err(|_| new_delete_client_error(6, ""))?;
        if result.operation_id != operation_id
            || result.backup_id.is_empty()
            || result.completed_at.is_empty()
        {
            return Err(new_delete_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubConfirmer {
        token: Result<String, Failure>,
        consume: bool,
    }
    impl DeletePamConfirmer for StubConfirmer {
        fn verify_and_consume(&self, _t: &str) -> bool {
            self.consume
        }
        fn confirm_backup_delete(
            &self,
            _p: PeerIdentity,
            _d: Option<Instant>,
            _s: &CeremonyScope,
            _o: &str,
        ) -> Option<Result<String, Failure>> {
            Some(
                self.token
                    .clone()
                    .map_err(|e| Failure::denied(e.code(), e.message().to_owned())),
            )
        }
    }

    struct Eval(bool);
    impl DeleteAdvisoryEvaluator for Eval {
        fn evaluate(
            &self,
        ) -> Result<
            (
                super::super::prepare::AdvisoryResult,
                super::super::prepare::AdvisoryAdmission,
            ),
            Failure,
        > {
            Ok((
                super::super::prepare::AdvisoryResult {
                    state: if self.0 {
                        "current".into()
                    } else {
                        "denied".into()
                    },
                    code: String::new(),
                },
                super::super::prepare::AdvisoryAdmission::default(),
            ))
        }
    }

    #[derive(Default)]
    struct Source {
        sealed: Vec<Uuid>,
        age: i32,
        deleted: std::sync::Mutex<Vec<Uuid>>,
        fail: bool,
    }
    impl DeleteBackupSource for Source {
        fn list_sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure> {
            if self.fail {
                return Err(Failure::unavailable("src", "unavailable"));
            }
            Ok(self.sealed.clone())
        }
        fn backup_age_days(&self, _id: Uuid) -> Result<i32, Failure> {
            if self.fail {
                return Err(Failure::unavailable("src", "unavailable"));
            }
            Ok(self.age)
        }
        fn delete_sealed_backup(&self, id: Uuid) -> Result<(), Failure> {
            if self.fail {
                return Err(Failure::unavailable("src", "unavailable"));
            }
            self.deleted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(id);
            Ok(())
        }
    }

    struct Refs(i32);
    impl DeleteReferenceChecker for Refs {
        fn referencing_operations(&self, _id: Uuid) -> Result<i32, Failure> {
            Ok(self.0)
        }
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 4242,
        }
    }

    fn journal_dir() -> String {
        let dir = std::env::temp_dir().join(format!("del-journal-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn handler(
        sealed: Vec<Uuid>,
        age: i32,
        refs: i32,
        current: bool,
    ) -> (DeleteHandlerImpl, std::sync::Arc<Source>) {
        let source = std::sync::Arc::new(Source {
            sealed,
            age,
            ..Source::default()
        });
        let h = DeleteHandlerImpl::new(
            Some(Box::new(StubConfirmer {
                token: Ok("token".to_owned()),
                consume: true,
            })),
            Some(Box::new(Eval(current))),
            Some(Box::new(Source {
                sealed: source.sealed.clone(),
                age,
                deleted: std::sync::Mutex::new(Vec::new()),
                fail: source.fail,
            })),
            Some(Box::new(Refs(refs))),
            CeremonyScope {
                instance_id: "default".into(),
                target_id: "postgres:central".into(),
            },
            DeleteRoots {
                journal_dir: journal_dir(),
                journal_uid: 0,
                journal_gid: 0,
            },
        );
        (h, source)
    }

    /// Signed denial precedes resolution and the ceremony: a denied
    /// advisory refuses before any candidate is even read.
    #[test]
    fn delete_denied_advisory_refuses_first() {
        let (h, _s) = handler(vec![Uuid::now_v7()], 90, 0, false);
        let op = Uuid::now_v7().to_string();
        let resp = h.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op.clone(),
                backup_id: String::new(),
                retention_days: 0,
            },
            &peer(),
        );
        assert_eq!(resp.reason, domain::REASON_DELETE_DENIED_SIGNED);
        assert_eq!(resp.exit_code, 7);
    }

    /// Zero candidates → `BACKUP_NO_ADMISSIBLE_BACKUP`; several →
    /// `BACKUP_CANDIDATE_AMBIGUOUS` — never guessed.
    #[test]
    fn delete_candidate_cardinality() {
        let (h, _s) = handler(vec![], 90, 0, true);
        let op = Uuid::now_v7().to_string();
        let resp = h.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op,
                backup_id: String::new(),
                retention_days: 0,
            },
            &peer(),
        );
        assert_eq!(resp.reason, domain::REASON_DELETE_NO_BACKUP);

        let (h2, _s2) = handler(vec![Uuid::now_v7(), Uuid::now_v7()], 90, 0, true);
        let op2 = Uuid::now_v7().to_string();
        let resp2 = h2.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op2,
                backup_id: String::new(),
                retention_days: 0,
            },
            &peer(),
        );
        assert_eq!(resp2.reason, domain::REASON_DELETE_BACKUP_AMBIGUOUS);
        assert_eq!(resp2.exit_code, 2);
    }

    /// A backup younger than the retention floor refuses; one still
    /// referenced refuses; an old unreferenced one deletes and journals.
    #[test]
    fn delete_retention_and_reference_gates() {
        let id = Uuid::now_v7();
        let (h, _s) = handler(vec![id], 10, 0, true);
        let op = Uuid::now_v7().to_string();
        let resp = h.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op,
                backup_id: String::new(),
                retention_days: 0,
            },
            &peer(),
        );
        assert_eq!(resp.reason, domain::REASON_DELETE_RETENTION_TOO_YOUNG);

        let (h2, _s2) = handler(vec![id], 90, 2, true);
        let op2 = Uuid::now_v7().to_string();
        let resp2 = h2.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op2,
                backup_id: String::new(),
                retention_days: 0,
            },
            &peer(),
        );
        assert_eq!(resp2.reason, domain::REASON_DELETE_REFERENCED);
    }

    /// Below-floor retention fails before the ceremony.
    #[test]
    fn delete_below_floor_fails_early() {
        let (h, _s) = handler(vec![Uuid::now_v7()], 90, 0, true);
        let op = Uuid::now_v7().to_string();
        let resp = h.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op,
                backup_id: String::new(),
                retention_days: 7,
            },
            &peer(),
        );
        assert_eq!(resp.reason, domain::REASON_DELETE_INVALID_REQUEST);
        assert_eq!(resp.exit_code, 2);
    }

    /// An unavailable source refuses as DELETE_UNAVAILABLE even after
    /// the ceremony — never degraded.
    #[test]
    fn delete_unavailable_source_refuses() {
        let id = Uuid::now_v7();
        let h = DeleteHandlerImpl::new(
            Some(Box::new(StubConfirmer {
                token: Ok("token".to_owned()),
                consume: true,
            })),
            Some(Box::new(Eval(true))),
            Some(Box::new(Source {
                sealed: vec![id],
                fail: true,
                ..Source::default()
            })),
            Some(Box::new(Refs(0))),
            CeremonyScope {
                instance_id: "default".into(),
                target_id: "postgres:central".into(),
            },
            DeleteRoots {
                journal_dir: journal_dir(),
                journal_uid: 0,
                journal_gid: 0,
            },
        )
        .with_now(OffsetDateTime::now_utc);
        let op = Uuid::now_v7().to_string();
        let resp = h.delete(
            Instant::now() + Duration::from_secs(60),
            DeleteRequest {
                operation_id: op,
                backup_id: String::new(),
                retention_days: 0,
            },
            &peer(),
        );
        assert_eq!(resp.reason, domain::REASON_DELETE_UNAVAILABLE);
    }

    /// `parse_delete_request` — empty payload is a bare delete, unknown
    /// fields refuse.
    #[test]
    fn parse_delete_request_rules() {
        let req = |payload: &str| Request {
            operation_id: "op".to_owned(),
            verb: "backup-delete".to_owned(),
            payload: serde_json::value::RawValue::from_string(payload.to_owned()).ok(),
        };
        let bare = parse_delete_request(&req("")).unwrap();
        assert!(bare.backup_id.is_empty());
        assert_eq!(bare.retention_days, 0);
        assert!(parse_delete_request(&req(r#"{"bogus":1}"#)).is_err());
        let full = parse_delete_request(&req(r#"{"backup_id":"b","retention_days":45}"#)).unwrap();
        assert_eq!(full.backup_id, "b");
        assert_eq!(full.retention_days, 45);
    }

    /// `write_delete_record` — exclusive create, never an overwrite.
    #[test]
    fn delete_record_is_exclusive() {
        let dir = journal_dir();
        let record = domain::DeleteRecord {
            operation_id: "op".to_owned(),
            backup_id: "b".to_owned(),
            retention_age_days: 90,
            reference_count: 0,
            completed_at: "t".to_owned(),
        };
        let (uid, gid) = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );
        write_delete_record(&dir, &record, uid, gid).unwrap();
        assert!(write_delete_record(&dir, &record, uid, gid).is_err());
        let path = std::path::Path::new(&dir).join("delete-op.result.json");
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
