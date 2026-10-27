//! `helper/restore_verify.go` + `helper/restore_apply.go` +
//! `helper/restore_abandon.go` + `helper/restore_refusal.go` +
//! `helper/restore_operator_client_linux.go` — the four helper restore
//! verbs and the unprivileged operator client.
//!
//! `restore-verify` runs no ceremony: verification mutates nothing,
//! and a PAM prompt on a non-destructive read would train operators
//! to authenticate reflexively before the one act that genuinely
//! needs it. `restore-apply`/`restore-resume` share the apply
//! ceremony; `restore-abandon` has its own — a confirmer that can
//! only authorize a restore must never be usable to give one up.
//! Every ceremony is fresh: each destructive verb mints and consumes
//! exactly one confirmation token.
//!
//! Refusals crossing to the operator pass two closed allowlists —
//! the resolver's four `RESTORE_*` tokens and the domain's
//! [`RestoreRefusalReason`] — exactly as upstream's
//! `admittedRestoreRefusalReason`/`admittedRestoreEngineRefusal`.

use std::time::{Duration, Instant};

use central_backup::recovery::operation::{
    RESTORE_ABANDON_ACKNOWLEDGEMENT, RestoreAbandonAuthorization, RestoreApplyAuthorization,
    RestoreOperation, RestorePhase,
};
use central_backup::recovery::refusal::RestoreRefusalReason;
use central_foundation::failure::{Failure, FailureKind};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::PeerIdentity;
use super::grant::CeremonyScope;
use super::protocol::{Request, Response, read_response, write_request};

fn is_v7(id: Uuid) -> bool {
    id.get_version_num() == 7
}

/// `restoreCeremonyDeadline` — the human share of a destructive
/// restore verb's budget, enforced on the apply/resume ceremony so
/// the engine's own share survives what the operator did not spend
/// typing.
pub const RESTORE_CEREMONY_DEADLINE: Duration = Duration::from_secs(2 * 60);
/// `restoreAbandonDeadline` — the ceremony share alone; no engine.
pub const RESTORE_ABANDON_DEADLINE: Duration = RESTORE_CEREMONY_DEADLINE;
/// `restoreVerifyHelperMediaWalks` — the helper's two full media
/// walks (the parent's own plus the child's single walk).
pub const RESTORE_VERIFY_HELPER_MEDIA_WALKS: u64 = 2;

// ---------------------------------------------------------------------------
// `restore_refusal.go` — the closed allowlists.
// ---------------------------------------------------------------------------

/// `RestoreRefusalNoLiveOperation`.
pub const RESTORE_REFUSAL_NO_LIVE_OPERATION: &str = "RESTORE_NO_LIVE_OPERATION";
/// `RestoreRefusalAmbiguousLiveOperation`.
pub const RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS: &str = "RESTORE_LIVE_OPERATION_AMBIGUOUS";
/// `RestoreRefusalNoBackupCandidate`.
pub const RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP: &str = "RESTORE_NO_ADMISSIBLE_BACKUP";
/// `RestoreRefusalAmbiguousBackupCandidate`.
pub const RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS: &str = "RESTORE_BACKUP_CANDIDATE_AMBIGUOUS";

/// `admittedRestoreRefusalReason` — the resolver's closed set. Any
/// other value is discarded and the caller falls back to its generic
/// failure, exactly as an unrecognized reason always has.
pub fn admitted_restore_refusal_reason(reason: &str) -> Option<&'static str> {
    match reason {
        RESTORE_REFUSAL_NO_LIVE_OPERATION => Some(RESTORE_REFUSAL_NO_LIVE_OPERATION),
        RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS => Some(RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS),
        RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP => Some(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP),
        RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS => {
            Some(RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS)
        }
        _ => None,
    }
}

/// `admittedRestoreEngineRefusal` — the engine's own sanitized,
/// locator-free causes, delegated to the domain's closed
/// [`RestoreRefusalReason::from_wire`] so the sets cannot drift.
pub fn admitted_restore_engine_refusal(reason: &str) -> Option<&'static str> {
    RestoreRefusalReason::from_wire(reason).map(|r| r.as_str())
}

/// `NewRestoreRefusal` — the resolver's typed refusal, travelling as
/// a [`Failure`] whose machine code is the candidate token. The
/// handlers admit that code only through the closed allowlists, so a
/// reason outside the set degrades to the caller's generic failure
/// rather than widening it — and the free-text message never stands
/// in for the code as identity. Producers SHOULD build refusals only
/// through this constructor and
/// [`RestoreRefusalReason::into_failure`].
pub fn new_restore_refusal(reason: &'static str) -> Failure {
    Failure::new(FailureKind::Denied, reason, format!("helper: {reason}"))
}

/// The verify/run-engine extraction: the failure's stable machine
/// code through the engine's closed set first, then the resolver's —
/// upstream's `ClassifyRestoreRefusal` followed by the `errors.As`
/// `*RestoreRefusal` arm, in that order.
fn failure_restore_reason(failure: &Failure) -> Option<&'static str> {
    admitted_restore_engine_refusal(failure.code())
        .or_else(|| admitted_restore_refusal_reason(failure.code()))
}

/// `runEngine`'s narrower extraction — the engine's set alone.
fn failure_engine_reason(failure: &Failure) -> Option<&'static str> {
    admitted_restore_engine_refusal(failure.code())
}

// ---------------------------------------------------------------------------
// Requests/results — the closed typed payloads.
// ---------------------------------------------------------------------------

/// `RestoreVerifyRequest` — the enclosing ID is transport correlation
/// only; the privileged side resolves the single admissible backup.
#[derive(Debug, Clone)]
pub struct RestoreVerifyRequest {
    pub operation_id: String,
}

/// `RestoreApplyRequest` — no ticket, target, credential, flag, or
/// path. The broker resolves the ticket bound to the operation.
#[derive(Debug, Clone)]
pub struct RestoreApplyRequest {
    pub operation_id: String,
}

/// `RestoreResumeRequest` — same closed shape as apply.
#[derive(Debug, Clone)]
pub struct RestoreResumeRequest {
    pub operation_id: String,
}

/// `RestoreAbandonRequest` — no acknowledgement text, force flag, or
/// target; the acknowledgement is the broker's fixed constant.
#[derive(Debug, Clone)]
pub struct RestoreAbandonRequest {
    pub operation_id: String,
}

/// `RestoreVerifyResult` — the safe verify projection: an opaque
/// ticket identity, the backup it was minted against, and its RFC3339
/// expiry. Nonce and HMAC are protected-state material and absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreVerifyResult {
    pub ticket_id: String,
    pub backup_id: String,
    pub expires_at: String,
}

/// `RestoreOperationResult` — the bounded projection apply, resume,
/// and abandon all answer with. No ticket, authorization, path,
/// object key, or credential; field order is the exact marshal order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOperationResult {
    pub operation_id: String,
    pub phase: String,
    pub checkpoint: String,
}

fn parse_empty_payload(operation_id: &str, payload: &[u8], what: &str) -> Result<String, String> {
    if operation_id.is_empty() {
        return Err(format!("helper: missing restore {what} operation"));
    }
    super::protocol::payload_is_empty_object(payload)
        .map_err(|e| format!("helper: invalid restore {what} payload: {e}"))?;
    Ok(operation_id.to_owned())
}

/// `ParseRestoreVerifyRequest`.
pub fn parse_restore_verify_request(req: &Request) -> Result<RestoreVerifyRequest, String> {
    Ok(RestoreVerifyRequest {
        operation_id: parse_empty_payload(&req.operation_id, req.payload_bytes(), "verify")?,
    })
}

/// `ParseRestoreApplyRequest`.
pub fn parse_restore_apply_request(req: &Request) -> Result<RestoreApplyRequest, String> {
    Ok(RestoreApplyRequest {
        operation_id: parse_empty_payload(&req.operation_id, req.payload_bytes(), "apply")?,
    })
}

/// `ParseRestoreResumeRequest`.
pub fn parse_restore_resume_request(req: &Request) -> Result<RestoreResumeRequest, String> {
    Ok(RestoreResumeRequest {
        operation_id: parse_empty_payload(&req.operation_id, req.payload_bytes(), "resume")?,
    })
}

/// `ParseRestoreAbandonRequest`.
pub fn parse_restore_abandon_request(req: &Request) -> Result<RestoreAbandonRequest, String> {
    Ok(RestoreAbandonRequest {
        operation_id: parse_empty_payload(&req.operation_id, req.payload_bytes(), "abandon")?,
    })
}

fn restore_response(operation_id: &str, outcome: &str, code: i64, reason: &str) -> Response {
    Response::new(operation_id, outcome, code, reason)
}

// ---------------------------------------------------------------------------
// `restore_verify.go`.
// ---------------------------------------------------------------------------

/// `RestoreVerifyReceipt` — the runner's bounded outcome: no phase or
/// checkpoint, because verification never advances an operation.
#[derive(Debug, Clone)]
pub struct RestoreVerifyReceipt {
    pub ticket_id: String,
    pub backup_id: String,
    pub expires_at: OffsetDateTime,
}

/// `RestoreVerifyRunner` — the privileged half of `central restore
/// verify`: resolves the single admissible backup candidate, walks
/// its sealed media, physically reserves capacity, and returns the
/// one-use ticket verification minted. It takes no arguments — a
/// candidate accepted here would put the choice back in reach of the
/// caller. A refused run carries the admitted refusal as its
/// [`Failure::code`] (built only through [`new_restore_refusal`] or
/// [`RestoreRefusalReason::into_failure`]).
pub trait RestoreVerifyRunner: Send + Sync {
    fn run_restore_verify(&self, deadline: Instant) -> Result<RestoreVerifyReceipt, Failure>;
}

/// `RestoreVerifyHandler` — the `Server::restore_verify` field type.
pub trait RestoreVerifyHandler: Send + Sync {
    fn verify_restore(
        &self,
        deadline: Instant,
        request: RestoreVerifyRequest,
        peer: &PeerIdentity,
    ) -> Response;
}

/// `RestoreVerifyHandlerImpl` — deliberately thin: every refusal that
/// matters is decided beneath it; its own job is rejecting a
/// malformed peer and publishing a receipt it has itself checked.
pub struct RestoreVerifyHandlerImpl {
    runner: Option<Box<dyn RestoreVerifyRunner>>,
    now: fn() -> OffsetDateTime,
}

impl RestoreVerifyHandlerImpl {
    /// `NewRestoreVerifyHandler`.
    pub fn new(runner: Option<Box<dyn RestoreVerifyRunner>>) -> Self {
        Self {
            runner,
            now: OffsetDateTime::now_utc,
        }
    }

    /// The test seam for `h.now`.
    #[doc(hidden)]
    pub fn set_now(&mut self, now: fn() -> OffsetDateTime) {
        self.now = now;
    }
}

impl RestoreVerifyHandler for RestoreVerifyHandlerImpl {
    fn verify_restore(
        &self,
        deadline: Instant,
        request: RestoreVerifyRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Some(runner) = &self.runner else {
            return restore_response(
                &request.operation_id,
                "denied",
                7,
                "RESTORE_VERIFY_UNAVAILABLE",
            );
        };
        if request.operation_id.is_empty() || peer.pid <= 0 {
            return restore_response(
                &request.operation_id,
                "denied",
                7,
                "RESTORE_VERIFY_UNAVAILABLE",
            );
        }
        let receipt = match runner.run_restore_verify(deadline) {
            Ok(r) => r,
            Err(e) => {
                let reason = failure_restore_reason(&e).unwrap_or("RESTORE_VERIFY_FAILED");
                return restore_response(&request.operation_id, "error", 6, reason);
            }
        };
        // `IsZero() || !ExpiresAt.After(now)` — the second arm covers
        // the first: a zero or past expiry is not a usable ticket.
        if receipt.ticket_id.is_empty()
            || receipt.backup_id.is_empty()
            || receipt.expires_at <= (self.now)()
        {
            return restore_response(&request.operation_id, "error", 6, "RESTORE_VERIFY_FAILED");
        }
        // Go's `ExpiresAt.UTC().Format(time.RFC3339)` — seconds only.
        let expires = receipt
            .expires_at
            .to_offset(time::UtcOffset::UTC)
            .replace_nanosecond(0)
            .unwrap_or(receipt.expires_at.to_offset(time::UtcOffset::UTC));
        restore_response(&request.operation_id, "success", 0, "").with_result(
            &RestoreVerifyResult {
                ticket_id: receipt.ticket_id,
                backup_id: receipt.backup_id,
                expires_at: expires.format(&Rfc3339).unwrap_or_else(|_| String::new()),
            },
        )
    }
}

// ---------------------------------------------------------------------------
// `restore_apply.go` — apply and resume on the one handler, exactly
// as upstream.
// ---------------------------------------------------------------------------

/// `restoreApplyPAMConfirmer` — the operation-specific destructive
/// ceremony plus the base `VerifyAndConsume`. `None` from
/// [`Self::confirm_restore_apply`] maps Go's failed type assertion —
/// a confirmer that cannot run this exact ceremony is refused rather
/// than falling back to another one.
pub trait RestoreApplyPamConfirmer: Send + Sync {
    /// `VerifyAndConsume` — minted tokens are one-use.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmRestoreApply` — `Some` where the confirmer supports
    /// the destructive apply ceremony.
    fn confirm_restore_apply(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _op_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `RestoreApplyAuthorizationIssuer` — the broker-facing authority
/// seam; it validates the opaque IDs against its protected ticket
/// record and persists the one-use authorization.
pub trait RestoreApplyAuthorizationIssuer: Send + Sync {
    /// `IssueRestoreApplyAuthorizationForOperation`.
    fn issue_restore_apply_authorization(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        issued_at: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure>;
    /// `IssueRestoreResumeAuthorizationForOperation`.
    fn issue_restore_resume_authorization(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        issued_at: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure>;
}

/// `RestoreEngineReceipt` — the bounded, locator-free outcome the
/// root restore engine reports.
#[derive(Debug, Clone)]
pub struct RestoreEngineReceipt {
    pub operation_id: String,
    pub phase: String,
    pub checkpoint: String,
}

/// `RestoreEngineLauncher` runs `/usr/lib/central/central-restore`
/// for exactly one authorized operation — a separate seam from the
/// issuer so proving the ceremony and performing the destructive run
/// remain distinct authorities. The T8 capacity/migration-kind-1
/// transport (`0xc3`–`0xc5`) is a later task's production
/// implementation; this slice ships the seam fail-closed.
pub trait RestoreEngineLauncher: Send + Sync {
    /// `LaunchRestore`.
    fn launch_restore(
        &self,
        deadline: Instant,
        mode: &str,
        operation_id: Uuid,
        authorization_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure>;
    /// `LaunchRestoreImport` — `central-restore import` for one
    /// staged import operation (no authorization identity exists for
    /// foreign data; the staged plan takes its place).
    fn launch_restore_import(
        &self,
        deadline: Instant,
        operation_id: Uuid,
    ) -> Result<RestoreEngineReceipt, Failure>;
}

/// `RestoreApplyHandler`/`RestoreResumeHandler` — the server's field
/// types; one handler type backs both, upstream-fashion.
pub trait RestoreApplyHandler: Send + Sync {
    fn authorize_restore_apply(
        &self,
        deadline: Instant,
        request: RestoreApplyRequest,
        peer: &PeerIdentity,
    ) -> Response;
}

/// `RestoreResumeHandler`.
pub trait RestoreResumeHandler: Send + Sync {
    fn authorize_restore_resume(
        &self,
        deadline: Instant,
        request: RestoreResumeRequest,
        peer: &PeerIdentity,
    ) -> Response;
}

/// `RestoreApplyAuthorizationHandler` — fresh local ceremony before
/// any C04 restore may consume its ticket. With a launcher installed
/// the authorization never reaches the operator: it is spent inside
/// the launch, so a confirmation cannot be harvested and replayed
/// against a differently composed engine.
pub struct RestoreApplyAuthorizationHandler {
    pam: Option<Box<dyn RestoreApplyPamConfirmer>>,
    issuer: Option<Box<dyn RestoreApplyAuthorizationIssuer>>,
    scope: CeremonyScope,
    launcher: Option<Box<dyn RestoreEngineLauncher>>,
    now: fn() -> OffsetDateTime,
}

impl RestoreApplyAuthorizationHandler {
    /// `NewRestoreApplyAuthorizationHandler` — no engine; the issued
    /// authorization projection is the result.
    pub fn new(
        pam: Option<Box<dyn RestoreApplyPamConfirmer>>,
        issuer: Option<Box<dyn RestoreApplyAuthorizationIssuer>>,
        scope: CeremonyScope,
    ) -> Self {
        Self {
            pam,
            issuer,
            scope,
            launcher: None,
            now: OffsetDateTime::now_utc,
        }
    }

    /// `NewRestoreApplyAuthorizationHandlerWithEngine` — the complete
    /// operator flow: fresh ceremony, one-use authorization, then the
    /// root engine run.
    pub fn with_engine(
        pam: Option<Box<dyn RestoreApplyPamConfirmer>>,
        issuer: Option<Box<dyn RestoreApplyAuthorizationIssuer>>,
        scope: CeremonyScope,
        launcher: Box<dyn RestoreEngineLauncher>,
    ) -> Self {
        Self {
            pam,
            issuer,
            scope,
            launcher: Some(launcher),
            now: OffsetDateTime::now_utc,
        }
    }

    /// The test seam for `h.now`.
    #[doc(hidden)]
    pub fn set_now(&mut self, now: fn() -> OffsetDateTime) {
        self.now = now;
    }

    /// `confirmRestoreCeremony` — the physical-TTY ceremony runs
    /// under its own share of the verb's budget rather than under the
    /// whole of it: `min` of the transport deadline and two minutes,
    /// leaving the caller's deadline — with the engine's share still
    /// on it — for the issuance and the run that follow.
    fn confirm_restore_ceremony(
        deadline: Instant,
        confirmer: &dyn RestoreApplyPamConfirmer,
        peer: PeerIdentity,
        scope: &CeremonyScope,
        operation_id: &str,
    ) -> Option<Result<String, Failure>> {
        let bound = std::cmp::min(deadline, Instant::now() + RESTORE_CEREMONY_DEADLINE);
        confirmer.confirm_restore_apply(peer, Some(bound), scope, operation_id)
    }

    /// The shared apply/resume flow; `mode` is `"apply"|"resume"`,
    /// `required`/`tty`/`denied` the per-verb refusal tokens.
    #[allow(clippy::too_many_arguments)] // per-verb refusal tokens
    fn authorize(
        &self,
        deadline: Instant,
        operation_id_raw: &str,
        mode: &str,
        peer: &PeerIdentity,
        required: &'static str,
        tty_required: &'static str,
        auth_denied: &'static str,
        engine_failed: &'static str,
    ) -> Response {
        let (Some(pam), Some(issuer)) = (&self.pam, &self.issuer) else {
            return restore_response(operation_id_raw, "denied", 7, required);
        };
        let Ok(operation_id) = Uuid::parse_str(operation_id_raw) else {
            return restore_response(operation_id_raw, "denied", 7, required);
        };
        if peer.pid <= 0 || self.scope.instance_id.is_empty() || self.scope.target_id.is_empty() {
            return restore_response(operation_id_raw, "denied", 7, required);
        }
        let confirmation = match Self::confirm_restore_ceremony(
            deadline,
            pam.as_ref(),
            *peer,
            &self.scope,
            operation_id_raw,
        ) {
            Some(Ok(token)) => token,
            // `!ok` — this confirmer has no apply ceremony.
            None => return restore_response(operation_id_raw, "denied", 7, tty_required),
            Some(Err(_)) => {
                return restore_response(operation_id_raw, "denied", 7, "AUTHORITY_DENIED");
            }
        };
        if !pam.verify_and_consume(&confirmation) {
            return restore_response(operation_id_raw, "denied", 7, "AUTHORITY_DENIED");
        }
        let issued_at = (self.now)();
        let authorization = match mode {
            "apply" => issuer.issue_restore_apply_authorization(
                deadline,
                operation_id,
                peer.uid,
                peer.pid,
                issued_at,
            ),
            _ => issuer.issue_restore_resume_authorization(
                deadline,
                operation_id,
                peer.uid,
                peer.pid,
                issued_at,
            ),
        };
        let Ok(authorization) = authorization else {
            return restore_response(operation_id_raw, "denied", 7, auth_denied);
        };
        if !authorization.valid_at((self.now)())
            || authorization.operation_id != operation_id
            || authorization.ticket_id.is_nil()
        {
            return restore_response(operation_id_raw, "denied", 7, auth_denied);
        }
        if let Some(launcher) = &self.launcher {
            return self.run_engine(
                deadline,
                mode,
                operation_id,
                authorization.authorization_id,
                engine_failed,
                launcher.as_ref(),
            );
        }
        /// `struct{AuthorizationID, ExpiresAt}` — upstream's
        /// non-engine result, declaration order; `time.Time` marshals
        /// RFC3339Nano, which `wire::rfc3339` reproduces.
        #[derive(Serialize)]
        struct AuthorizationResult {
            authorization_id: String,
            #[serde(with = "crate::broker::wire::rfc3339")]
            expires_at: OffsetDateTime,
        }
        restore_response(operation_id_raw, "success", 0, "").with_result(&AuthorizationResult {
            authorization_id: authorization.authorization_id.to_string(),
            expires_at: authorization.expires_at,
        })
    }

    /// `runEngine` — called only after an authorization exists. A
    /// launcher failure is never reported as success: the protected
    /// operation stays non-ready and the operator is directed to
    /// resume.
    fn run_engine(
        &self,
        deadline: Instant,
        mode: &str,
        operation_id: Uuid,
        authorization_id: Uuid,
        denied_reason: &'static str,
        launcher: &dyn RestoreEngineLauncher,
    ) -> Response {
        let receipt = match launcher.launch_restore(deadline, mode, operation_id, authorization_id)
        {
            Ok(r) => r,
            Err(e) => {
                let reason = failure_engine_reason(&e).unwrap_or(denied_reason);
                return restore_response(&operation_id.to_string(), "error", 6, reason);
            }
        };
        if receipt.operation_id != operation_id.to_string()
            || receipt.phase.is_empty()
            || receipt.checkpoint.is_empty()
        {
            return restore_response(&operation_id.to_string(), "error", 6, denied_reason);
        }
        restore_response(&operation_id.to_string(), "success", 0, "").with_result(
            &RestoreOperationResult {
                operation_id: receipt.operation_id,
                phase: receipt.phase,
                checkpoint: receipt.checkpoint,
            },
        )
    }
}

impl RestoreApplyHandler for RestoreApplyAuthorizationHandler {
    fn authorize_restore_apply(
        &self,
        deadline: Instant,
        request: RestoreApplyRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.authorize(
            deadline,
            &request.operation_id,
            "apply",
            peer,
            "RESTORE_APPLY_AUTHORIZATION_REQUIRED",
            "RESTORE_APPLY_TTY_CONFIRMATION_REQUIRED",
            "RESTORE_APPLY_AUTHORIZATION_DENIED",
            "RESTORE_APPLY_ENGINE_FAILED",
        )
    }
}

impl RestoreResumeHandler for RestoreApplyAuthorizationHandler {
    fn authorize_restore_resume(
        &self,
        deadline: Instant,
        request: RestoreResumeRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.authorize(
            deadline,
            &request.operation_id,
            "resume",
            peer,
            "RESTORE_RESUME_AUTHORIZATION_REQUIRED",
            "RESTORE_RESUME_TTY_CONFIRMATION_REQUIRED",
            "RESTORE_RESUME_AUTHORIZATION_DENIED",
            "RESTORE_RESUME_ENGINE_FAILED",
        )
    }
}

/// `PamConfirmer` supports the destructive apply ceremony, so it
/// answers `Some(..)` where a confirmer lacking the method would
/// answer `None`.
impl RestoreApplyPamConfirmer for super::pam_ceremony::PamConfirmer {
    fn verify_and_consume(&self, token: &str) -> bool {
        super::pam_ceremony::PamConfirmer::verify_and_consume(self, token)
    }
    fn confirm_restore_apply(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &CeremonyScope,
        op_id: &str,
    ) -> Option<Result<String, Failure>> {
        Some(super::pam_ceremony::PamConfirmer::confirm_restore_apply(
            self, peer, deadline, scope, op_id,
        ))
    }
}

// ---------------------------------------------------------------------------
// `restore_abandon.go`.
// ---------------------------------------------------------------------------

/// `RestoreAbandonAuthority` — the broker-facing seam for ADR 0016,
/// deliberately two calls rather than one: the first records that the
/// operator completed a fresh ceremony, the second spends that record
/// on exactly one terminal transition. Splitting them is what makes
/// the authorization genuinely one-use.
pub trait RestoreAbandonAuthority: Send + Sync {
    /// `IssueRestoreAbandonAuthorizationForOperation`.
    fn issue_restore_abandon_authorization(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        issued_at: OffsetDateTime,
    ) -> Result<RestoreAbandonAuthorization, Failure>;
    /// `AbandonRestore`.
    fn abandon_restore(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        authorization: &RestoreAbandonAuthorization,
        at: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure>;
}

/// `restoreAbandonPAMConfirmer` — the third destructive ceremony,
/// kept as its own method rather than a parameter on the apply
/// ceremony. `None` maps Go's failed type assertion; a confirmer that
/// can only authorize a restore must not be usable to authorize
/// giving one up.
pub trait RestoreAbandonPamConfirmer: Send + Sync {
    /// `VerifyAndConsume`.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmRestoreAbandon`.
    fn confirm_restore_abandon(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _op_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `RestoreAbandonHandler` — the server's field type.
pub trait RestoreAbandonHandler: Send + Sync {
    fn authorize_restore_abandon(
        &self,
        deadline: Instant,
        request: RestoreAbandonRequest,
        peer: &PeerIdentity,
    ) -> Response;
}

/// `RestoreAbandonHandlerImpl` — the fresh local authority ceremony
/// for ADR 0016's terminal outcome, then the broker publishes it.
/// There is no ticket (abandonment consumes no admission, it ends
/// one), no engine (a pure journal transition), and the
/// acknowledgement is the broker's to attach — never this handler's
/// and never the caller's.
pub struct RestoreAbandonHandlerImpl {
    pam: Option<Box<dyn RestoreAbandonPamConfirmer>>,
    authority: Option<Box<dyn RestoreAbandonAuthority>>,
    scope: CeremonyScope,
    now: fn() -> OffsetDateTime,
}

impl RestoreAbandonHandlerImpl {
    /// `NewRestoreAbandonHandler`.
    pub fn new(
        pam: Option<Box<dyn RestoreAbandonPamConfirmer>>,
        authority: Option<Box<dyn RestoreAbandonAuthority>>,
        scope: CeremonyScope,
    ) -> Self {
        Self {
            pam,
            authority,
            scope,
            now: OffsetDateTime::now_utc,
        }
    }

    /// The test seam for `h.now`.
    #[doc(hidden)]
    pub fn set_now(&mut self, now: fn() -> OffsetDateTime) {
        self.now = now;
    }
}

impl RestoreAbandonHandler for RestoreAbandonHandlerImpl {
    fn authorize_restore_abandon(
        &self,
        deadline: Instant,
        request: RestoreAbandonRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let (Some(pam), Some(authority)) = (&self.pam, &self.authority) else {
            return restore_response(
                &request.operation_id,
                "denied",
                7,
                "RESTORE_ABANDON_AUTHORIZATION_REQUIRED",
            );
        };
        let Ok(operation_id) = Uuid::parse_str(&request.operation_id) else {
            return restore_response(
                &request.operation_id,
                "denied",
                7,
                "RESTORE_ABANDON_AUTHORIZATION_REQUIRED",
            );
        };
        if operation_id.is_nil()
            || peer.pid <= 0
            || self.scope.instance_id.is_empty()
            || self.scope.target_id.is_empty()
        {
            return restore_response(
                &request.operation_id,
                "denied",
                7,
                "RESTORE_ABANDON_AUTHORIZATION_REQUIRED",
            );
        }
        // Upstream passes the connection ctx straight through — the
        // abandon transport deadline IS the ceremony budget, so no
        // separate share is carved out the way apply/resume carve one.
        let confirmation = match pam.confirm_restore_abandon(
            *peer,
            Some(deadline),
            &self.scope,
            &request.operation_id,
        ) {
            Some(Ok(token)) => token,
            None => {
                return restore_response(
                    &request.operation_id,
                    "denied",
                    7,
                    "RESTORE_ABANDON_TTY_CONFIRMATION_REQUIRED",
                );
            }
            Some(Err(_)) => {
                return restore_response(&request.operation_id, "denied", 7, "AUTHORITY_DENIED");
            }
        };
        if !pam.verify_and_consume(&confirmation) {
            return restore_response(&request.operation_id, "denied", 7, "AUTHORITY_DENIED");
        }
        let authorization = match authority.issue_restore_abandon_authorization(
            deadline,
            operation_id,
            peer.uid,
            peer.pid,
            (self.now)(),
        ) {
            Ok(a) => a,
            Err(_) => {
                return restore_response(
                    &request.operation_id,
                    "denied",
                    7,
                    "RESTORE_ABANDON_AUTHORIZATION_DENIED",
                );
            }
        };
        // The acknowledgement is re-checked here as well as inside
        // `valid_at`: it is the one field that carries the operator's
        // consent to data loss, and a broker that answered without it
        // must not reach the transition.
        if !authorization.valid_at((self.now)())
            || authorization.operation_id != operation_id
            || authorization.acknowledgement != RESTORE_ABANDON_ACKNOWLEDGEMENT
        {
            return restore_response(
                &request.operation_id,
                "denied",
                7,
                "RESTORE_ABANDON_AUTHORIZATION_DENIED",
            );
        }
        let operation =
            match authority.abandon_restore(deadline, operation_id, &authorization, (self.now)()) {
                Ok(o) => o,
                Err(_) => {
                    return restore_response(
                        &request.operation_id,
                        "error",
                        6,
                        "RESTORE_ABANDON_FAILED",
                    );
                }
            };
        if operation.operation_id != operation_id
            || operation.phase != RestorePhase::Abandoned
            || !operation.is_terminal()
        {
            return restore_response(&request.operation_id, "error", 6, "RESTORE_ABANDON_FAILED");
        }
        restore_response(&request.operation_id, "success", 0, "").with_result(
            &RestoreOperationResult {
                operation_id: operation.operation_id.to_string(),
                phase: operation.phase.as_str().to_owned(),
                checkpoint: operation.last_checkpoint.as_str().to_owned(),
            },
        )
    }
}

impl RestoreAbandonPamConfirmer for super::pam_ceremony::PamConfirmer {
    fn verify_and_consume(&self, token: &str) -> bool {
        super::pam_ceremony::PamConfirmer::verify_and_consume(self, token)
    }
    fn confirm_restore_abandon(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &CeremonyScope,
        op_id: &str,
    ) -> Option<Result<String, Failure>> {
        Some(super::pam_ceremony::PamConfirmer::confirm_restore_abandon(
            self, peer, deadline, scope, op_id,
        ))
    }
}

// ---------------------------------------------------------------------------
// `restore_operator_client_linux.go` — the unprivileged CLI's whole
// view of the privileged restore verbs.
// ---------------------------------------------------------------------------

/// `RestoreOperatorClientError` — the stable exit class plus at most
/// one reason drawn from each closed allowlist. The helper's
/// diagnostic text is deliberately not retained.
#[derive(Debug)]
pub struct RestoreOperatorClientError {
    exit_code: i64,
    reason: String,
    engine: String,
}

impl std::fmt::Display for RestoreOperatorClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: restore verb failed")
    }
}

impl std::error::Error for RestoreOperatorClientError {}

impl RestoreOperatorClientError {
    /// `ExitCode`.
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }
    /// `Reason` — the admitted resolver refusal token, or empty.
    pub fn reason(&self) -> &str {
        &self.reason
    }
    /// `EngineRefusal` — the restore engine's own sanitized cause, or
    /// empty. Kept separate so a caller cannot confuse "the resolver
    /// refused to choose" with "the media did not verify".
    pub fn engine_refusal(&self) -> &str {
        &self.engine
    }
}

fn new_restore_operator_client_error(exit_code: i64) -> RestoreOperatorClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    RestoreOperatorClientError {
        exit_code,
        reason: String::new(),
        engine: String::new(),
    }
}

fn new_restore_operator_client_refusal(exit_code: i64, reason: &str) -> RestoreOperatorClientError {
    let mut failure = new_restore_operator_client_error(exit_code);
    if let Some(r) = admitted_restore_refusal_reason(reason) {
        failure.reason = r.to_owned();
    }
    if let Some(e) = admitted_restore_engine_refusal(reason) {
        failure.engine = e.to_owned();
    }
    failure
}

/// `validRestoreOperatorUUID` — parse + non-nil + v7 + canonical.
fn valid_restore_operator_uuid(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(id) => !id.is_nil() && is_v7(id) && id.to_string() == value,
        Err(_) => false,
    }
}

/// `RestoreOperatorClient` — `NewRestoreOperatorClient`'s linux
/// implementation. Every method takes only a deadline: which backup
/// is verified and which operation is applied, resumed, or abandoned
/// are resolved on the privileged side, so an operator can neither
/// name nor redirect them.
pub struct RestoreOperatorClient {
    socket_path: String,
}

impl RestoreOperatorClient {
    /// `NewRestoreOperatorClient`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `VerifyRestore`.
    pub fn verify_restore(
        &self,
        deadline: Option<Instant>,
    ) -> Result<RestoreVerifyResult, RestoreOperatorClientError> {
        let result: RestoreVerifyResult = self.call(deadline, super::verb::RESTORE_VERIFY)?;
        // Shape-check before any of it is shown to an operator: a
        // verify result is the thing that tells them a destructive
        // apply is now possible, so a half-formed one must not be
        // reported as one.
        if !valid_restore_operator_uuid(&result.ticket_id)
            || !valid_restore_operator_uuid(&result.backup_id)
            || result.expires_at.is_empty()
            || OffsetDateTime::parse(&result.expires_at, &Rfc3339).is_err()
        {
            return Err(new_restore_operator_client_error(6));
        }
        Ok(result)
    }

    /// `ApplyRestore`.
    pub fn apply_restore(
        &self,
        deadline: Option<Instant>,
    ) -> Result<RestoreOperationResult, RestoreOperatorClientError> {
        self.operation(deadline, super::verb::RESTORE_APPLY)
    }

    /// `ResumeRestore`.
    pub fn resume_restore(
        &self,
        deadline: Option<Instant>,
    ) -> Result<RestoreOperationResult, RestoreOperatorClientError> {
        self.operation(deadline, super::verb::RESTORE_RESUME)
    }

    /// `AbandonRestore`.
    pub fn abandon_restore(
        &self,
        deadline: Option<Instant>,
    ) -> Result<RestoreOperationResult, RestoreOperatorClientError> {
        self.operation(deadline, super::verb::RESTORE_ABANDON)
    }

    fn operation(
        &self,
        deadline: Option<Instant>,
        verb: &str,
    ) -> Result<RestoreOperationResult, RestoreOperatorClientError> {
        let result: RestoreOperationResult = self.call(deadline, verb)?;
        if !valid_restore_operator_uuid(&result.operation_id)
            || result.phase.is_empty()
            || result.checkpoint.is_empty()
        {
            return Err(new_restore_operator_client_error(6));
        }
        Ok(result)
    }

    /// `call` — mints a fresh transport correlation identity per
    /// request: deliberately NOT the protected operation's identity.
    /// The helper answers with this same identity in the envelope, so
    /// the strict equality check still binds request to response; the
    /// resolved protected identity travels in the result body, where
    /// it is a report rather than a selector. The connection deadline
    /// comes from the caller's deadline and nowhere else — a restore
    /// verb's budget is the human at a physical TTY plus, for apply
    /// and resume, a full pg_restore.
    fn call<T: for<'de> Deserialize<'de> + Serialize>(
        &self,
        deadline: Option<Instant>,
        verb: &str,
    ) -> Result<T, RestoreOperatorClientError> {
        if self.socket_path.is_empty() {
            return Err(new_restore_operator_client_error(3));
        }
        let transport_id = Uuid::now_v7().to_string();
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| new_restore_operator_client_error(3))?;
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = conn.set_read_timeout(Some(remaining));
            let _ = conn.set_write_timeout(Some(remaining));
        }
        let payload = RawValue::from_string("{}".to_owned()).ok();
        let request = Request {
            operation_id: transport_id,
            verb: verb.to_owned(),
            payload,
        };
        write_request(&mut conn, &request).map_err(|_| new_restore_operator_client_error(3))?;
        let response =
            read_response(&mut conn).map_err(|_| new_restore_operator_client_error(3))?;
        if response.operation_id != request.operation_id
            || response.outcome != "success"
            || response.exit_code != 0
        {
            return Err(new_restore_operator_client_refusal(
                response.exit_code,
                &response.reason,
            ));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        super::backup::decode_exact_backup_read_result(&payload)
            .map_err(|_| new_restore_operator_client_error(6))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::protocol::Request;

    fn req(operation_id: &str, payload: Option<&str>) -> Request {
        Request {
            operation_id: operation_id.to_owned(),
            verb: "v".to_owned(),
            payload: payload.and_then(|p| RawValue::from_string(p.to_owned()).ok()),
        }
    }

    /// The four parsers share the empty-object grammar: absent/`{}`
    /// admit, any field refuses — a smuggled selector must fail the
    /// request, never be ignored.
    #[test]
    fn restore_parsers_reject_every_field() {
        type Parser = fn(&Request) -> Result<(), String>;
        let cases: [(&str, Parser); 4] = [
            ("verify", |r| parse_restore_verify_request(r).map(|_| ())),
            ("apply", |r| parse_restore_apply_request(r).map(|_| ())),
            ("resume", |r| parse_restore_resume_request(r).map(|_| ())),
            ("abandon", |r| parse_restore_abandon_request(r).map(|_| ())),
        ];
        for (name, parse) in cases {
            assert!(parse(&req("op", None)).is_ok(), "{name}");
            assert!(parse(&req("op", Some("{}"))).is_ok(), "{name}");
            assert!(parse(&req("op", Some("{\"x\":1}"))).is_err(), "{name}");
            assert!(
                parse(&req("op", Some("{\"ticket_id\":\"t\"}"))).is_err(),
                "{name}"
            );
            assert!(parse(&req("", None)).is_err(), "{name}");
            assert!(parse(&req("op", Some("[]"))).is_err(), "{name}");
        }
    }

    /// The resolver allowlist is exactly upstream's four tokens; the
    /// engine allowlist defers to the domain's closed set.
    #[test]
    fn restore_refusal_allowlists_are_closed() {
        for token in [
            RESTORE_REFUSAL_NO_LIVE_OPERATION,
            RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS,
            RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP,
            RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS,
        ] {
            assert_eq!(admitted_restore_refusal_reason(token), Some(token));
            assert_eq!(admitted_restore_engine_refusal(token), None);
        }
        for token in [
            "RESTORE_STATE_INVALID",
            "RESTORE_MEDIA_INVALID",
            "RESTORE_CAPACITY_INSUFFICIENT",
            "RESTORE_ENGINE_UNAVAILABLE",
            "RESTORE_TARGET_ADMISSION_STALE",
        ] {
            assert_eq!(admitted_restore_engine_refusal(token), Some(token));
            assert_eq!(admitted_restore_refusal_reason(token), None);
        }
        assert_eq!(
            admitted_restore_refusal_reason("RESTORE_VERIFY_FAILED"),
            None
        );
        assert_eq!(
            admitted_restore_engine_refusal("RESTORE_VERIFY_FAILED"),
            None
        );
        assert_eq!(admitted_restore_refusal_reason(""), None);
        assert_eq!(admitted_restore_engine_refusal(""), None);
    }

    /// `new_restore_refusal` carries the candidate as the machine
    /// code; classification admits it through the closed sets only.
    #[test]
    fn restore_refusal_classification_uses_code_not_message() {
        let f = new_restore_refusal(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP);
        assert_eq!(
            failure_restore_reason(&f),
            Some(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP)
        );
        let f = RestoreRefusalReason::MediaInvalid.into_failure();
        assert_eq!(failure_restore_reason(&f), Some("RESTORE_MEDIA_INVALID"));
        let f = new_restore_refusal("SOME_OTHER_REASON");
        assert_eq!(failure_restore_reason(&f), None);
        let f = Failure::internal("x", "RESTORE_MEDIA_INVALID in message");
        assert_eq!(failure_restore_reason(&f), None);
    }

    /// `validRestoreOperatorUUID` — non-nil, v7, canonical.
    #[test]
    fn restore_operator_uuid_shape_is_closed() {
        let v7 = Uuid::now_v7().to_string();
        assert!(valid_restore_operator_uuid(&v7));
        assert!(!valid_restore_operator_uuid(&Uuid::nil().to_string()));
        assert!(!valid_restore_operator_uuid(&Uuid::new_v4().to_string()));
        assert!(!valid_restore_operator_uuid(&v7.to_uppercase()));
        assert!(!valid_restore_operator_uuid("not-a-uuid"));
        assert!(!valid_restore_operator_uuid(""));
    }

    /// `newRestoreOperatorClientError`/`…Refusal` — exit clamp and
    /// allowlist separation.
    #[test]
    fn restore_operator_error_keeps_separate_allowlists() {
        let e = new_restore_operator_client_error(0);
        assert_eq!(e.exit_code(), 6);
        let e = new_restore_operator_client_error(9);
        assert_eq!(e.exit_code(), 6);
        let e = new_restore_operator_client_error(3);
        assert_eq!(e.exit_code(), 3);
        assert!(e.reason().is_empty() && e.engine_refusal().is_empty());

        let e = new_restore_operator_client_refusal(7, RESTORE_REFUSAL_NO_LIVE_OPERATION);
        assert_eq!(e.reason(), RESTORE_REFUSAL_NO_LIVE_OPERATION);
        assert!(e.engine_refusal().is_empty());
        let e = new_restore_operator_client_refusal(6, "RESTORE_MEDIA_INVALID");
        assert!(e.reason().is_empty());
        assert_eq!(e.engine_refusal(), "RESTORE_MEDIA_INVALID");
        let e = new_restore_operator_client_refusal(6, "helper: /secret/path");
        assert!(e.reason().is_empty() && e.engine_refusal().is_empty());
    }
}
