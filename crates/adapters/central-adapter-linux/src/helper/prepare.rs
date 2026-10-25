//! `prepare.go` + `prepare_confirmation.go` — the `prepare` verb: the
//! helper-minted confirmation binding, the client claim's deny-only
//! cross-check, the advisory evaluation gate, the bound ceremony, and
//! the service seam. Every field of the binding is obtained by the
//! helper itself — the whole point is that a claim the caller writes
//! is an attacker input that looks like authorization; only a
//! helper-minted binding is authorization.

use super::PeerIdentity;
use super::audit::format_rfc3339nano;
use super::protocol::*;
use central_foundation::failure::Failure;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

fn internal(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::internal(code, msg.into())
}

const PREPARE_CONFIRMATION_LIFETIME: time::Duration = time::Duration::minutes(5);
const MAX_SPENT_NONCES: usize = 4096;

// ---------------------------------------------------------------------------
// Advisory seam (`advisory.Result`/`Admission` narrowed to what prepare reads)
// ---------------------------------------------------------------------------

/// `advisory.Result` — the installed advisory's evaluation verdict.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryResult {
    /// `advisory.State` — `"current"` admits; everything else denies.
    pub state: String,
    /// `advisory.Code` — the closed machine vocabulary.
    pub code: String,
}

/// `advisory.Admission` — the evaluation's receipt. Only the receipt
/// id crosses into a binding; the admission itself stays opaque.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryAdmission {
    pub receipt_id: String,
}

/// `EvaluateService` — the installed-advisory evaluator seam.
pub trait EvaluateService: Send + Sync {
    fn evaluate(&self) -> Result<(AdvisoryResult, AdvisoryAdmission), Failure>;
}

/// `advisory.Current`.
pub const ADVISORY_STATE_CURRENT: &str = "current";

// ---------------------------------------------------------------------------
// DependencyPrepare seam (`dependencyprepare.Result`/`Service` narrowed)
// ---------------------------------------------------------------------------

/// `dependencyprepare.Result` — the service's outcome as the wire
/// projection consumes it. Everything here is a phase name, a count,
/// an id, or a duration: no path, URL, or build output may be carried.
#[derive(Debug, Clone, Default)]
pub struct PrepareOpResult {
    pub exit_code: i64,
    pub reason: String,
    pub operation_id: String,
    pub receipt_id: String,
    /// `dependencyprepare.Phase` — `"failed"` is the only one the
    /// response path distinguishes.
    pub phase: String,
    pub resume_required: bool,
    pub reused: i64,
    pub acquired: i64,
    /// `SafeNextAction` — validated against the closed set before it
    /// crosses.
    pub safe_next_action: String,
    pub stage_timings: Vec<StageTiming>,
    pub counters: ResourceCounters,
    pub elapsed_ms: i64,
    pub admission_id: String,
    pub selector: String,
}

/// `dependencyprepare.Failed`.
pub const PHASE_FAILED: &str = "failed";

/// `SafeNextAction.IsValid` — the closed set.
pub fn safe_next_action_is_valid(a: &str) -> bool {
    matches!(
        a,
        "" | "RESUME_REQUIRED" | "PREPARATION_REQUIRED" | "TERMINAL_FAILURE"
    )
}

/// `DependencyPrepareService` — the dependency pipeline seam.
pub trait DependencyPrepareService: Send + Sync {
    fn prepare(&self, admission: &AdvisoryAdmission) -> PrepareOpResult;
    fn resume(&self, id: &str) -> PrepareOpResult;
    fn prepare_from_release(&self, admission: &AdvisoryAdmission, dir: &str) -> PrepareOpResult;
    fn prepare_export_release(&self, admission: &AdvisoryAdmission, dir: &str) -> PrepareOpResult;
}

/// `dependencyprepare.ValidOperationID` — a resume target is joined
/// into the helper's journal directory, so it must be one safe path
/// component.
pub fn valid_operation_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("prepare: operation ID must not be empty".to_owned());
    }
    if id == "." || id == ".." || id.contains('/') || id.contains('\0') {
        return Err(format!(
            "prepare: {id:?} is not a single safe path component"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response helpers (prepare.go's bottom half)
// ---------------------------------------------------------------------------

/// `safeDetail` — marshal a diagnostic as `{"detail": …}`; the only
/// way this field is written, because an error containing a quote
/// could otherwise choose what the object contained.
fn safe_detail(detail: &str) -> Option<Box<serde_json::value::RawValue>> {
    #[derive(Serialize)]
    struct Detail<'a> {
        detail: &'a str,
    }
    serde_json::to_string(&Detail { detail })
        .ok()
        .and_then(|s| serde_json::value::RawValue::from_string(s).ok())
}

/// `remediationCatalog` — advisory codes to operator-facing remedies.
fn remediation_for_code(code: &str) -> String {
    let known = match code {
        "INVALID_ADVISORY" => "The installed advisory is invalid or corrupt.",
        "SIGNATURE_INVALID" => "The advisory signature could not be verified.",
        "ADVISORY_EXPIRED" => "The advisory has expired. Install a current advisory.",
        "ADVISORY_HARD_EXPIRED" => "The advisory has hard-expired. Install a current advisory.",
        "ADVISORY_HOST_MISMATCH" => "This host is not compatible with the advisory requirements.",
        "EMERGENCY_DENY" => "The advisory contains an emergency deny directive.",
        "ADVISORY_SOURCE_UNAVAILABLE" => "The advisory source could not be accessed.",
        "ADVISORY_EVIDENCE_UNAVAILABLE" => "Could not record advisory evaluation evidence.",
        "B04_CUTOVER_REPAIR_REQUIRED" => {
            "B04 secret bootstrap cutover failed. Resume the lifecycle operation with the same binding to recover."
        }
        "B04_PROTECTED_STATE_REPAIR_REQUIRED" => {
            "B04 protected secret state requires repair. Resume the lifecycle operation with the same binding."
        }
        "B04_HANDOFF_DENIED" => {
            "B04 credential handoff was denied. Verify the calling identity and binding."
        }
        "B04_HANDOFF_CLEANUP_REQUIRED" => {
            "B04 credential cleanup is incomplete. Run `central down` to complete teardown."
        }
        "B04_BINDING_REVOKED" => {
            "The B04 secret binding has been revoked. Materialize a new binding."
        }
        _ => return "An unknown advisory evaluation error occurred.".to_owned(),
    };
    known.to_owned()
}

/// `prepareRemediations` — the one next step for the prepare denials
/// an operator can act on; a reason with no entry carries no
/// remediation rather than a guess.
fn prepare_remediation(code: &str) -> Option<&'static str> {
    match code {
        "AUTHORITY_DENIED" => Some(
            "Prepare was not authorized. On a grant-mode host, root runs `sudo central grant issue --kind prepare --ttl 1h` first; at a physical console, run `central local prepare` there and answer the prompts.",
        ),
        "PREPARE_UNAVAILABLE" => Some(
            "This host holds no dependency-signing key and cannot build dependencies. Import a signed release instead: `central local prepare --from-release=<dir>`.",
        ),
        _ => None,
    }
}

/// `B04ReasonResult` — a B04 reason code mapped to a safe diagnostic
/// outcome. Never carries secret bytes, paths, OS errors, or receipt
/// HMACs.
#[derive(Debug, Clone, Serialize)]
pub struct B04ReasonResult {
    pub reason_code: String,
    pub outcome: String,
    pub exit_code: i64,
    pub safe_next_action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub binding_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub phase: String,
}

/// `B04SafeReason` — the closed mapping, verbatim.
pub fn b04_safe_reason(
    code: &str,
    operation_id: &str,
    binding_id: &str,
    phase: &str,
) -> B04ReasonResult {
    let mut r = B04ReasonResult {
        reason_code: code.to_owned(),
        outcome: String::new(),
        exit_code: 0,
        safe_next_action: String::new(),
        operation_id: operation_id.to_owned(),
        binding_id: binding_id.to_owned(),
        phase: phase.to_owned(),
    };
    match code {
        "B04_CUTOVER_REPAIR_REQUIRED" => {
            r.outcome = "denied".into();
            r.exit_code = 5;
            r.safe_next_action =
                "Resume the lifecycle operation with the same binding to retry B03 adoption."
                    .into();
        }
        "B04_PROTECTED_STATE_REPAIR_REQUIRED" => {
            r.outcome = "denied".into();
            r.exit_code = 5;
            r.safe_next_action =
                "Protected state repair required. Run `central down` then `central up`.".into();
        }
        "B04_HANDOFF_DENIED" => {
            r.outcome = "denied".into();
            r.exit_code = 5;
            r.safe_next_action =
                "Verify the calling identity, binding, and target destination.".into();
        }
        "B04_HANDOFF_CLEANUP_REQUIRED" => {
            r.outcome = "denied".into();
            r.exit_code = 1;
            r.safe_next_action =
                "Run `central down` to complete teardown and credential cleanup.".into();
        }
        "B04_BINDING_REVOKED" => {
            r.outcome = "denied".into();
            r.exit_code = 0;
            r.safe_next_action =
                "The binding has been revoked. Run `central up` to obtain a new binding.".into();
        }
        _ => {
            r.outcome = "error".into();
            r.exit_code = 1;
            r.safe_next_action =
                "An unknown B04 error occurred. Review broker logs for details.".into();
        }
    }
    r
}

/// `detailsFromResult` — the single projection of a service result
/// onto the wire.
fn details_from_result(r: &PrepareOpResult, operation_id: &str) -> PrepareResultDetails {
    let mut details = PrepareResultDetails {
        operation_id: operation_id.to_owned(),
        phase: r.phase.clone(),
        receipt_id: r.receipt_id.clone(),
        selector: r.selector.clone(),
        resume_required: r.resume_required,
        reused: r.reused,
        acquired: r.acquired,
        advisory_id: r.admission_id.clone(),
        safe_next_action: r.safe_next_action.clone(),
        operation_elapsed_ms: r.elapsed_ms,
        stage_timings: r.stage_timings.clone(),
        ..PrepareResultDetails::default()
    };
    if !safe_next_action_is_valid(&details.safe_next_action) {
        // An action outside the closed set names no action at all.
        details.safe_next_action.clear();
    }
    if r.phase == PHASE_FAILED && !r.reason.is_empty() && !r.resume_required {
        details.reason_code = redacted_reason_code(&r.reason);
        if let Some(remediation) = prepare_remediation(&details.reason_code) {
            details.remediation = remediation.to_owned();
        }
    }
    if r.counters != ResourceCounters::default() {
        details.resource_counters = Some(r.counters.clone());
    }
    details
}

fn response(
    operation_id: &str,
    outcome: &str,
    exit_code: i64,
    reason: &str,
    result: Option<serde_json::Value>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, exit_code, reason);
    if let Some(v) = result
        && let Ok(raw) = serde_json::to_string(&v)
    {
        resp.result = serde_json::value::RawValue::from_string(raw).ok();
    }
    resp
}

fn details_response(
    operation_id: &str,
    outcome: &str,
    exit_code: i64,
    reason: &str,
    details: &PrepareResultDetails,
) -> Response {
    Response::new(operation_id, outcome, exit_code, reason).with_result(details)
}

/// `redactedReasonCode` — `CODE` or `CODE: detail` reduces to the
/// code; a reason that is not a code reports PREPARE_FAILED.
pub fn redacted_reason_code(reason: &str) -> String {
    let code = reason.split(':').next().unwrap_or("").trim();
    if code.is_empty() {
        return String::new();
    }
    if code
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        code.to_owned()
    } else {
        "PREPARE_FAILED".to_owned()
    }
}

/// `resumeIDOrOperation`.
fn resume_id_or_operation(service_id: &str, requested_id: &str) -> String {
    if !service_id.is_empty() {
        service_id.to_owned()
    } else {
        requested_id.to_owned()
    }
}

/// `prepareResponse` — the settled-outcome projection.
fn prepare_response(op_id: &str, r: &PrepareOpResult) -> Response {
    if r.resume_required {
        let mut detail = details_from_result(r, &r.operation_id);
        detail.resume_required = true;
        return details_response(op_id, "denied", 6, "UNSETTLED_OPERATION", &detail);
    }
    let mut exit_code = 0;
    let mut outcome = "success";
    let mut reason = String::new();
    if r.phase == PHASE_FAILED {
        exit_code = 1;
        outcome = "denied";
        reason = redacted_reason_code(&r.reason);
    }
    let mut detail = details_from_result(r, &r.operation_id);
    detail.phase = r.phase.clone();
    details_response(op_id, outcome, exit_code, &reason, &detail)
}

// ---------------------------------------------------------------------------
// Confirmation binding (prepare_confirmation.go)
// ---------------------------------------------------------------------------

/// `ConfirmationBinding` — what a one-use prepare confirmation
/// authorizes: this request, this resume target, on this host, at this
/// boot, under this helper, once. Every field is the helper's own.
#[derive(Debug, Clone)]
pub struct ConfirmationBinding {
    pub request_digest: String,
    pub resume_operation_id: String,
    pub config_binding: String,
    pub boot_id: String,
    pub helper_release: String,
    pub nonce: String,
    pub issued_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

/// `PrepareConfirmationSource` — the helper's own answer to every
/// question a binding asks. Nothing on it may be derived from a
/// request.
#[derive(Clone)]
pub struct PrepareConfirmationSource {
    pub config_binding: String,
    /// The lock's `helper_release_digest` where decided, else this
    /// process's `helperInstanceID`.
    pub helper_release: String,
    /// Settable for tests; empty reads the kernel's boot id.
    pub boot_id: String,
    /// Settable for tests.
    pub now: Option<std::sync::Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>>,
}

impl PrepareConfirmationSource {
    fn now(&self) -> time::OffsetDateTime {
        match &self.now {
            Some(f) => f(),
            None => time::OffsetDateTime::now_utc(),
        }
    }

    fn resolve(&self) -> Result<Self, Failure> {
        let mut s = self.clone();
        if s.config_binding.is_empty() {
            return Err(internal(
                "sys_prepare_source",
                "helper: prepare confirmation source names no config binding",
            ));
        }
        if s.helper_release.is_empty() {
            return Err(internal(
                "sys_prepare_source",
                "helper: prepare confirmation source names no helper release",
            ));
        }
        if s.boot_id.is_empty() {
            s.boot_id = super::read_boot_id()?;
        }
        Ok(s)
    }

    /// `bind` — mint the binding for one request. The nonce is the
    /// helper's, from the system CSPRNG.
    pub fn bind(&self, req: &Request, pr: &PrepareRequest) -> Result<ConfirmationBinding, Failure> {
        let resolved = self.resolve()?;
        let mut nonce = [0u8; 32];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty()).map_err(
            |e| {
                internal(
                    "sys_prepare_nonce",
                    format!("helper: generate confirmation nonce: {e}"),
                )
            },
        )?;
        let issued = resolved.now();
        Ok(ConfirmationBinding {
            request_digest: prepare_request_digest(req, pr),
            resume_operation_id: pr.resume_operation_id.clone(),
            config_binding: resolved.config_binding.clone(),
            boot_id: resolved.boot_id.clone(),
            helper_release: resolved.helper_release.clone(),
            nonce: crate::broker::wire::b64_url_raw_encode(&nonce),
            issued_at: issued,
            expires_at: issued + PREPARE_CONFIRMATION_LIFETIME,
        })
    }
}

/// `prepareRequestDigest` — over the bytes the helper actually
/// received: the payload is hashed as received, never re-serialized.
pub fn prepare_request_digest(req: &Request, pr: &PrepareRequest) -> String {
    let mut h = Sha256::new();
    h.update(format!("operation_id={}\n", req.operation_id).as_bytes());
    h.update(format!("verb={}\n", req.verb).as_bytes());
    h.update(
        format!(
            "payload=sha256:{}\n",
            hex_encode(&Sha256::digest(req.payload_bytes()))
        )
        .as_bytes(),
    );
    h.update(format!("resume_operation_id={}\n", pr.resume_operation_id).as_bytes());
    format!("sha256:{}", hex_encode(&h.finalize()))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl ConfirmationBinding {
    /// `Fingerprint` — the value the confirmer stores against a minted
    /// token; a token minted for one binding cannot consume another.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        for field in [
            format!("request_digest={}", self.request_digest),
            format!("resume_operation_id={}", self.resume_operation_id),
            format!("config_binding={}", self.config_binding),
            format!("boot_id={}", self.boot_id),
            format!("helper_release={}", self.helper_release),
            format!("nonce={}", self.nonce),
            format!("issued_at={}", format_rfc3339nano(self.issued_at)),
            format!("expires_at={}", format_rfc3339nano(self.expires_at)),
        ] {
            h.update(format!("{field}\n").as_bytes());
        }
        format!("sha256:{}", hex_encode(&h.finalize()))
    }

    /// `validAt`.
    pub fn valid_at(&self, now: time::OffsetDateTime) -> Result<(), String> {
        if !(self.expires_at > self.issued_at) {
            return Err("confirmation binding expires before it was issued".to_owned());
        }
        if now > self.expires_at {
            return Err("confirmation binding has expired".to_owned());
        }
        Ok(())
    }

    /// `matchesClaim` — the claim is a cross-check and nothing more:
    /// it can only ever cause a denial. The binding's nonce is NOT
    /// compared — a caller cannot know it; replay is caught by the
    /// spent set.
    pub fn matches_claim(
        &self,
        claim: &PrepareConfirmationClaim,
        now: time::OffsetDateTime,
    ) -> Result<(), String> {
        if claim.resume_operation_id != self.resume_operation_id {
            return Err(format!(
                "claim resume_operation_id {:?} != request resume_operation_id {:?}",
                claim.resume_operation_id, self.resume_operation_id
            ));
        }
        for (name, claimed, bound) in [
            (
                "request_digest",
                claim.request_digest.as_str(),
                self.request_digest.as_str(),
            ),
            (
                "config_binding",
                claim.config_binding.as_str(),
                self.config_binding.as_str(),
            ),
            ("boot_id", claim.boot_id.as_str(), self.boot_id.as_str()),
            (
                "helper_release",
                claim.helper_release.as_str(),
                self.helper_release.as_str(),
            ),
        ] {
            if claimed != bound {
                return Err(format!(
                    "claim {name} does not match the helper's own value"
                ));
            }
        }
        let issued = time::OffsetDateTime::parse(
            &claim.issued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| "claim issued_at is not a timestamp".to_owned())?;
        if issued > now + time::Duration::seconds(1) {
            return Err("claim issued_at is in the helper's future".to_owned());
        }
        if now - issued > PREPARE_CONFIRMATION_LIFETIME {
            return Err("claim issued_at is older than a confirmation may live".to_owned());
        }
        let expires = time::OffsetDateTime::parse(
            &claim.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| "claim expires_at is not a timestamp".to_owned())?;
        if expires > issued + PREPARE_CONFIRMATION_LIFETIME + time::Duration::seconds(1) {
            return Err("claim expires_at outlives what a confirmation may live".to_owned());
        }
        Ok(())
    }
}

/// `validateConfirmationClaim` — shape and freshness before the
/// field-by-field compare.
fn validate_confirmation_claim(
    claim: &PrepareConfirmationClaim,
    now: time::OffsetDateTime,
) -> Result<(), String> {
    if claim.request_digest.is_empty() {
        return Err("empty request_digest".to_owned());
    }
    if claim.boot_id.is_empty() {
        return Err("empty boot_id".to_owned());
    }
    if claim.helper_release.is_empty() {
        return Err("empty helper_release".to_owned());
    }
    if claim.nonce.is_empty() {
        return Err("empty nonce".to_owned());
    }
    if claim.issued_at.is_empty() {
        return Err("empty issued_at".to_owned());
    }
    if claim.expires_at.is_empty() {
        return Err("empty expires_at".to_owned());
    }
    if claim.config_binding.is_empty() {
        return Err("empty config_binding".to_owned());
    }
    let issued = time::OffsetDateTime::parse(
        &claim.issued_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| format!("invalid issued_at: {e}"))?;
    let expires = time::OffsetDateTime::parse(
        &claim.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| format!("invalid expires_at: {e}"))?;
    if !(expires > issued) {
        return Err(format!(
            "expires_at {} is not after issued_at {}",
            claim.expires_at, claim.issued_at
        ));
    }
    if now > expires {
        return Err(format!("claim expired at {}", claim.expires_at));
    }
    Ok(())
}

/// `spentNonces` — the (nonce, request digest) pairs already
/// presented; a claim cannot be presented twice. Entries prune at the
/// confirmation lifetime and the set is capped so a caller cannot
/// grow the helper's memory.
pub struct SpentNonces {
    spent: Mutex<HashMap<String, time::OffsetDateTime>>,
}

impl SpentNonces {
    pub fn new() -> Self {
        SpentNonces {
            spent: Mutex::new(HashMap::new()),
        }
    }

    /// `spend` — `true` when the pair was already presented (or the
    /// live set is full: forgetting is what would let a replay
    /// through).
    pub fn spend(&self, claim: &PrepareConfirmationClaim, now: time::OffsetDateTime) -> bool {
        let key = format!("{}\u{0}{}", claim.nonce, claim.request_digest);
        let mut spent = self.spent.lock().unwrap_or_else(|e| e.into_inner());
        spent.retain(|_, at| now - *at <= PREPARE_CONFIRMATION_LIFETIME);
        if spent.contains_key(&key) {
            return true;
        }
        if spent.len() >= MAX_SPENT_NONCES {
            return true;
        }
        spent.insert(key, now);
        false
    }
}

impl Default for SpentNonces {
    fn default() -> Self {
        Self::new()
    }
}

/// `helperInstanceID` — this helper process's identifier, minted once
/// from the CSPRNG and never leaving the process except inside a
/// binding.
pub fn helper_instance_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let mut raw = [0u8; 32];
        match rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty()) {
            Ok(_) => format!(
                "helper-instance:{}",
                crate::broker::wire::b64_url_raw_encode(&raw)
            ),
            // A helper that cannot read the CSPRNG cannot mint a
            // binding; empty makes resolve() refuse.
            Err(_) => String::new(),
        }
    })
}

/// `HelperReleaseIdentity` — the lock's decided release digest where
/// there is one, else this process's identifier.
pub fn helper_release_identity(locked_release_digest: &str) -> String {
    if !locked_release_digest.is_empty() && !locked_release_digest.ends_with(&"0".repeat(64)) {
        return locked_release_digest.to_owned();
    }
    helper_instance_id().to_owned()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `preparePAMConfirmer` — the narrow capability the handler requires:
/// a confirmation minted *for* a binding and consumable only *against*
/// that binding. A handler whose confirmer cannot do this refuses
/// rather than falling back to a bare nonce.
pub trait PreparePamConfirmer: Send + Sync {
    fn confirm_prepare(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
        binding: &ConfirmationBinding,
    ) -> Result<String, Failure>;
    fn verify_and_consume_prepare(&self, token: &str, binding: &ConfirmationBinding) -> bool;
}

/// `evaluatePrepareHandler` — `NewPrepareHandler`: evaluation only.
pub struct EvaluatePrepareHandler {
    pub svc: Box<dyn EvaluateService>,
}

impl super::server::PrepareHandler for EvaluatePrepareHandler {
    /// `handleEvaluate` — the advisory evaluation verb's projection.
    fn prepare(
        &self,
        _peer: PeerIdentity,
        _deadline: Instant,
        req: &Request,
        _pr: PrepareRequest,
    ) -> Response {
        let (result, admission) = match self.svc.evaluate() {
            Ok(ok) => ok,
            Err(_) => {
                return response(
                    &req.operation_id,
                    "error",
                    6,
                    "ADVISORY_EVALUATION_FAILED",
                    None,
                );
            }
        };
        let details = PrepareResultDetails {
            authority_state: result.state.clone(),
            reason_code: result.code.clone(),
            remediation: remediation_for_code(&result.code),
            evidence_id: admission.receipt_id.clone(),
            ..PrepareResultDetails::default()
        };
        let (outcome, exit_code) = if result.state == ADVISORY_STATE_CURRENT {
            ("success", 0)
        } else {
            ("denied", 5)
        };
        details_response(
            &req.operation_id,
            outcome,
            exit_code,
            &result.code,
            &details,
        )
    }
}

/// `dependencyPrepareHandler` — `NewDependencyPrepareHandler`.
pub struct DependencyPrepareHandler {
    pub svc: Box<dyn DependencyPrepareService>,
    pub eval: Box<dyn EvaluateService>,
    pub pam: Box<dyn PreparePamConfirmer>,
    pub source: PrepareConfirmationSource,
    pub spent: SpentNonces,
}

impl DependencyPrepareHandler {
    pub fn new(
        svc: Box<dyn DependencyPrepareService>,
        eval: Box<dyn EvaluateService>,
        pam: Box<dyn PreparePamConfirmer>,
        source: PrepareConfirmationSource,
    ) -> Self {
        DependencyPrepareHandler {
            svc,
            eval,
            pam,
            source,
            spent: SpentNonces::new(),
        }
    }

    fn handle_prepare(&self, op_id: &str, admission: &AdvisoryAdmission) -> Response {
        prepare_response(op_id, &self.svc.prepare(admission))
    }

    fn handle_from_release(
        &self,
        op_id: &str,
        admission: &AdvisoryAdmission,
        dir: &str,
    ) -> Response {
        prepare_response(op_id, &self.svc.prepare_from_release(admission, dir))
    }

    fn handle_export_release(
        &self,
        op_id: &str,
        admission: &AdvisoryAdmission,
        dir: &str,
    ) -> Response {
        prepare_response(op_id, &self.svc.prepare_export_release(admission, dir))
    }

    fn handle_resume(&self, op_id: &str, resume_id: &str) -> Response {
        let r = self.svc.resume(resume_id);
        let id = resume_id_or_operation(&r.operation_id, resume_id);
        if r.phase == PHASE_FAILED || r.exit_code != 0 {
            let details = details_from_result(&r, &id);
            return details_response(
                op_id,
                "denied",
                r.exit_code,
                &redacted_reason_code(&r.reason),
                &details,
            );
        }
        let details = details_from_result(&r, &id);
        details_response(op_id, "success", 0, "", &details)
    }
}

impl super::server::PrepareHandler for DependencyPrepareHandler {
    /// `Prepare` — the upstream ordering verbatim: deadline, request
    /// shape, confirmer capability, helper-minted binding, the
    /// deny-only claim cross-check, evaluation, bound ceremony,
    /// consume-against-binding, expiry recheck, then dispatch.
    fn prepare(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        req: &Request,
        pr: PrepareRequest,
    ) -> Response {
        let op_id = &req.operation_id;

        if Instant::now() >= deadline {
            let mut resp = response(op_id, "denied", 128 + 2, "SIGNAL_INTERRUPT", None);
            resp.result = safe_detail("context deadline exceeded");
            return resp;
        }

        // The resume target is checked for shape before anything else
        // runs: it is a caller-supplied string the helper joins into
        // its journal directory, so `../attacker` would name any
        // *.json on the host a forgeable prepare record.
        if !pr.resume_operation_id.is_empty()
            && valid_operation_id(&pr.resume_operation_id).is_err()
        {
            return response(op_id, "denied", 5, "INVALID_RESUME_OPERATION_ID", None);
        }
        if !pr.resume_operation_id.is_empty()
            && (!pr.from_release_dir.is_empty() || !pr.export_release_dir.is_empty())
        {
            return response(op_id, "denied", 5, "INVALID_RELEASE_REQUEST", None);
        }
        if !pr.from_release_dir.is_empty() && !pr.export_release_dir.is_empty() {
            return response(op_id, "denied", 5, "INVALID_RELEASE_REQUEST", None);
        }
        for dir in [&pr.from_release_dir, &pr.export_release_dir] {
            if dir.is_empty() {
                continue;
            }
            if !std::path::Path::new(dir).is_absolute() || dir.len() > 4096 || dir.contains('\0') {
                return response(op_id, "denied", 5, "INVALID_RELEASE_REQUEST", None);
            }
        }

        // The helper mints its own binding for this exact request
        // before anything else is evaluated.
        let binding = match self.source.bind(req, &pr) {
            Ok(b) => b,
            // The reason names no path: bind's error can quote /proc,
            // and a result never carries one.
            Err(_) => return response(op_id, "denied", 5, "CONFIRMATION_SOURCE_UNAVAILABLE", None),
        };

        // A client-supplied claim is a cross-check and nothing else:
        // every field must equal the value the helper obtained for
        // itself, and a claim is never what admits a request. Two of
        // the compared fields are unsatisfiable over this transport
        // (request_digest binds the payload the claim travels in;
        // helper_release is a per-process value a caller cannot know),
        // so a claim-bearing prepare is denied unconditionally — the
        // shipped client never sends one. Fail-closed, as upstream.
        if let Some(claim) = &pr.confirmation_claim {
            if let Err(e) = validate_confirmation_claim(claim, self.source.now()) {
                let mut resp = response(op_id, "denied", 5, "INVALID_CONFIRMATION_CLAIM", None);
                resp.result = safe_detail(&e);
                return resp;
            }
            if let Err(e) = binding.matches_claim(claim, self.source.now()) {
                let mut resp = response(op_id, "denied", 5, "CONFIRMATION_CLAIM_MISMATCH", None);
                resp.result = safe_detail(&e);
                return resp;
            }
            // A claim is spendable once: its nonce used to be checked
            // for emptiness and then discarded, so a captured claim
            // could be presented again for as long as its window
            // lasted.
            if self.spent.spend(claim, self.source.now()) {
                return response(op_id, "denied", 5, "REPLAYED_CONFIRMATION", None);
            }
        }

        let (result, admission) = match self.eval.evaluate() {
            Ok(ok) => ok,
            Err(_) => return response(op_id, "error", 6, "ADVISORY_UNAVAILABLE", None),
        };

        if result.state != ADVISORY_STATE_CURRENT {
            let details = PrepareResultDetails {
                authority_state: result.state.clone(),
                reason_code: result.code.clone(),
                remediation: remediation_for_code(&result.code),
                ..PrepareResultDetails::default()
            };
            return details_response(op_id, "denied", 5, "STALE_ADMISSION", &details);
        }

        if admission.receipt_id.is_empty() {
            return response(op_id, "denied", 5, "MISSING_ADMISSION_RECEIPT", None);
        }

        // PAM authentication and the physical-console ceremony (or the
        // grant spend) run inside ConfirmPrepare; the binding is an
        // addition to what the token is worth, never a substitute.
        let token = match self
            .pam
            .confirm_prepare(peer, Some(deadline), op_id, &binding)
        {
            Ok(t) => t,
            Err(_) => {
                let details = PrepareResultDetails {
                    authority_state: "denied".to_owned(),
                    reason_code: "AUTHORITY_DENIED".to_owned(),
                    remediation: prepare_remediation("AUTHORITY_DENIED")
                        .unwrap_or("")
                        .to_owned(),
                    ..PrepareResultDetails::default()
                };
                // The ceremony's error is a PAM/TTY error and can name
                // a device or a module path, so nothing of it crosses:
                // the result carries only the code and the fixed
                // remedy from the catalogue.
                return details_response(op_id, "denied", 5, "AUTHORITY_DENIED", &details);
            }
        };

        // The token is consumed against the binding it was minted for:
        // no longer a bare nonce that authorizes whatever presents it.
        if !self.pam.verify_and_consume_prepare(&token, &binding) {
            return response(op_id, "denied", 5, "REPLAYED_CONFIRMATION", None);
        }

        // Checked after the ceremony as well as before it: the console
        // ceremony is human-paced, and a binding that expired while
        // the operator was at the keyboard must not carry a mutation.
        if binding.valid_at(self.source.now()).is_err() {
            return response(op_id, "denied", 5, "CONFIRMATION_EXPIRED", None);
        }

        if !pr.resume_operation_id.is_empty() {
            return self.handle_resume(op_id, &pr.resume_operation_id);
        }
        if !pr.from_release_dir.is_empty() {
            return self.handle_from_release(op_id, &admission, &pr.from_release_dir);
        }
        if !pr.export_release_dir.is_empty() {
            return self.handle_export_release(op_id, &admission, &pr.export_release_dir);
        }
        self.handle_prepare(op_id, &admission)
    }
}

/// `unavailablePrepareHandler` — the verb's answer when the host
/// cannot compose the prepare graph: refuses explicitly rather than
/// being left unset.
pub struct UnavailablePrepareHandler;

impl super::server::PrepareHandler for UnavailablePrepareHandler {
    fn prepare(
        &self,
        _peer: PeerIdentity,
        _deadline: Instant,
        req: &Request,
        _pr: PrepareRequest,
    ) -> Response {
        let details = PrepareResultDetails {
            authority_state: "denied".to_owned(),
            reason_code: "PREPARE_UNAVAILABLE".to_owned(),
            remediation: prepare_remediation("PREPARE_UNAVAILABLE")
                .unwrap_or("")
                .to_owned(),
            ..PrepareResultDetails::default()
        };
        details_response(
            &req.operation_id,
            "denied",
            5,
            "PREPARE_UNAVAILABLE",
            &details,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> PrepareConfirmationSource {
        PrepareConfirmationSource {
            config_binding: "cfg-1".into(),
            helper_release: "rel-1".into(),
            boot_id: "boot-1".into(),
            now: Some(std::sync::Arc::new(|| {
                time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
            })),
        }
    }

    /// `Fingerprint` binds every field: two bindings differing in one
    /// field mint different fingerprints.
    #[test]
    fn fingerprint_binds_every_field() {
        let req = Request {
            operation_id: "op-1".into(),
            verb: super::super::verb::PREPARE.into(),
            payload: None,
        };
        let pr = PrepareRequest::default();
        let b1 = source().bind(&req, &pr).unwrap();
        let mut s2 = source();
        s2.config_binding = "cfg-2".into();
        let b2 = s2.bind(&req, &pr).unwrap();
        assert_ne!(b1.fingerprint(), b2.fingerprint());
        // The digest covers the received payload bytes.
        assert!(b1.request_digest.starts_with("sha256:"));
    }

    /// `matchesClaim` — a claim can only ever deny: a wrong field or a
    /// stale timestamp is a mismatch; the binding's own nonce is never
    /// compared.
    #[test]
    fn claim_cross_check_only_denies() {
        let req = Request {
            operation_id: "op-1".into(),
            verb: "prepare".into(),
            payload: None,
        };
        let binding = source().bind(&req, &PrepareRequest::default()).unwrap();
        let now = source().now.unwrap()();
        let good = PrepareConfirmationClaim {
            request_digest: binding.request_digest.clone(),
            resume_operation_id: String::new(),
            config_binding: binding.config_binding.clone(),
            boot_id: binding.boot_id.clone(),
            helper_release: binding.helper_release.clone(),
            issued_at: format_rfc3339nano(now - time::Duration::seconds(10)),
            expires_at: format_rfc3339nano(now + time::Duration::seconds(60)),
            nonce: "caller-nonce".into(),
        };
        binding.matches_claim(&good, now).unwrap();
        let mut bad = good.clone();
        bad.boot_id = "other-boot".into();
        assert!(binding.matches_claim(&bad, now).is_err());
        let mut stale = good.clone();
        stale.issued_at = format_rfc3339nano(now - time::Duration::hours(1));
        assert!(binding.matches_claim(&stale, now).is_err());
    }

    /// `SpentNonces` — a presented pair cannot be presented twice;
    /// the cap refuses rather than forgets.
    #[test]
    fn spent_nonces_replay_guard() {
        let spent = SpentNonces::new();
        let now = time::OffsetDateTime::now_utc();
        let claim = PrepareConfirmationClaim {
            request_digest: "sha256:x".into(),
            resume_operation_id: String::new(),
            config_binding: "c".into(),
            boot_id: "b".into(),
            helper_release: "h".into(),
            issued_at: String::new(),
            expires_at: String::new(),
            nonce: "n-1".into(),
        };
        assert!(!spent.spend(&claim, now));
        assert!(spent.spend(&claim, now));
        // A different nonce for the same digest is a different spend.
        let mut c2 = claim.clone();
        c2.nonce = "n-2".into();
        assert!(!spent.spend(&c2, now));
    }

    /// `validOperationID` — the resume target is one safe path
    /// component: `.`, `..`, `/` and NUL are refused.
    #[test]
    fn resume_id_shape() {
        assert!(valid_operation_id("op-123").is_ok());
        for bad in ["", ".", "..", "a/b", "../x", "a\0b"] {
            assert!(valid_operation_id(bad).is_err(), "{bad:?}");
        }
    }

    /// `redactedReasonCode` — `CODE: wrapped detail` reduces to CODE;
    /// a non-code reason reports PREPARE_FAILED.
    #[test]
    fn reason_code_redaction() {
        assert_eq!(
            redacted_reason_code("ACQUIRE_FAILED: /opt/build went away"),
            "ACQUIRE_FAILED"
        );
        assert_eq!(
            redacted_reason_code("some lowercase text"),
            "PREPARE_FAILED"
        );
        assert_eq!(redacted_reason_code(""), "");
    }
}
