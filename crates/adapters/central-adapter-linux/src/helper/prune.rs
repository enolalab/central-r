//! `internal/adapter/authority/helper/prune.go` + `client_linux.go`'s
//! prune half — the D04 `backup-prune` verb: the read-only plan and the
//! destructive apply (ceremony + batched execution with checkpoint
//! resume) share the one helper verb; the handler — not the transport —
//! enforces that only apply carries a ceremony.

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

/// `PruneAction` selects the read-only plan from the destructive apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneAction {
    /// `plan` — read-only; no ceremony.
    Plan,
    /// `apply` — destructive; the ceremony binds the plan id.
    Apply,
}

/// `PruneBody` — the wire form of one plan body: the frozen plan-time
/// proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneBody {
    /// Artifact identity.
    pub artifact_id: String,
    /// Workspace identity.
    pub workspace_id: String,
    /// The ready object key.
    pub object_key: String,
    /// The artifact's one-time staging generation.
    pub staging_generation: String,
    /// Body size.
    pub size: i64,
    /// Proven retention age at plan time.
    pub retention_age_days: i32,
    /// Proven reference count at plan time.
    pub reference_count: i32,
}

/// `PruneRequest` carries either a plan or an apply. `plan_id` is
/// minted by the handler on plan; on apply it names the plan being
/// applied and binds the ceremony (the `backup_prune` grant's
/// operation ID), so a grant for one plan cannot be spent applying
/// another.
#[derive(Debug, Clone)]
pub struct PruneRequest {
    /// The ceremony-bound operation (envelope field, not payload).
    pub operation_id: String,
    /// `plan` or `apply`.
    pub action: PruneAction,
    /// The plan being applied (apply only).
    pub plan_id: String,
    /// The requested retention floor; 0 selects the default.
    pub retention_days: i32,
    /// The frozen plan bodies (apply only).
    pub bodies: Vec<PruneBody>,
}

/// `PruneResult` — the bounded prune outcome: identities and counts
/// only. `bodies` is set on plan, counts on apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneResult {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The plan identity.
    pub plan_id: String,
    /// The eligible bodies (plan only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bodies: Option<Vec<PruneBody>>,
    /// Bodies deleted (apply only).
    #[serde(default)]
    pub bodies_deleted: i64,
    /// Batches completed (apply only).
    #[serde(default)]
    pub batches_done: i64,
    /// Whether the apply resumed a crashed predecessor.
    #[serde(default)]
    pub resumed_after_crash: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// `ParsePruneRequest` — rejects unknown fields so a flag the handler
/// does not understand cannot silently become authority.
pub fn parse_prune_request(req: &Request) -> Result<PruneRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing prune operation".to_owned());
    }
    let trimmed = trim_ascii(req.payload_bytes());
    if trimmed.is_empty() {
        return Err("helper: prune requires an action payload".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        action: String,
        #[serde(default)]
        plan_id: String,
        #[serde(default)]
        retention_days: i32,
        #[serde(default)]
        bodies: Vec<PruneBody>,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|_| "helper: invalid prune payload".to_owned())?;
    let action = match payload.action.as_str() {
        "plan" => PruneAction::Plan,
        "apply" => PruneAction::Apply,
        _ => return Err("helper: prune requires action plan or apply".to_owned()),
    };
    Ok(PruneRequest {
        operation_id: req.operation_id.clone(),
        action,
        plan_id: payload.plan_id,
        retention_days: payload.retention_days,
        bodies: payload.bodies,
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

fn prune_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
    result: Option<&PruneResult>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, code, reason);
    if let Some(r) = result {
        resp = resp.with_result(r);
    }
    resp
}

fn to_prune_bodies(bodies: &[domain::PruneCandidate]) -> Option<Vec<PruneBody>> {
    if bodies.is_empty() {
        return None;
    }
    Some(
        bodies
            .iter()
            .map(|b| PruneBody {
                artifact_id: b.artifact_id.to_string(),
                workspace_id: b.workspace_id.to_string(),
                object_key: b.object_key.clone(),
                staging_generation: b.staging_generation.to_string(),
                size: b.size,
                retention_age_days: b.retention_age_days,
                reference_count: b.reference_count,
            })
            .collect(),
    )
}

fn from_prune_body(wire: &PruneBody) -> Result<domain::PruneCandidate, String> {
    let artifact_id = Uuid::parse_str(&wire.artifact_id)
        .ok()
        .filter(|u| !u.is_nil())
        .ok_or_else(|| "helper: prune body artifact id is invalid".to_owned())?;
    let workspace_id = Uuid::parse_str(&wire.workspace_id)
        .ok()
        .filter(|u| !u.is_nil())
        .ok_or_else(|| "helper: prune body workspace id is invalid".to_owned())?;
    let staging_generation = Uuid::parse_str(&wire.staging_generation)
        .ok()
        .filter(|u| !u.is_nil())
        .ok_or_else(|| "helper: prune body staging generation is invalid".to_owned())?;
    Ok(domain::PruneCandidate {
        artifact_id,
        workspace_id,
        object_key: wire.object_key.clone(),
        staging_generation,
        size: wire.size,
        retention_age_days: wire.retention_age_days,
        reference_count: wire.reference_count,
    })
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// `prunePAMConfirmer` — the D04 prune-apply ceremony. Plan carries no
/// ceremony (read-only, the backup-verify shape); apply refuses when
/// the installed confirmer cannot perform this ceremony.
pub trait PrunePamConfirmer: Send + Sync {
    /// `VerifyAndConsume` — minted tokens are one-use.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmBackupPrune` — `Some` where supported.
    fn confirm_backup_prune(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _plan_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `pruneAdvisoryEvaluator` — the B01 seam: both plan and apply
/// proceed only on a `current` result.
pub trait PruneAdvisoryEvaluator: Send + Sync {
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

/// `unavailableLifecycleEvaluator` — deny-only until B01's evaluator
/// is wired; see `wipe.rs`'s copy for the precedent.
pub struct DenyOnlyAdvisoryEvaluator;

impl PruneAdvisoryEvaluator for DenyOnlyAdvisoryEvaluator {
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

/// `PruneHandlerImpl` — performs D04 prune plan (read-only) and prune
/// apply (ceremony + batched execution with checkpoint resume).
pub struct PruneHandlerImpl {
    pam: Option<Box<dyn PrunePamConfirmer>>,
    advisory: Option<Box<dyn PruneAdvisoryEvaluator>>,
    engine: Option<Box<dyn domain::PruneEngine>>,
    scope: CeremonyScope,
    now: fn() -> OffsetDateTime,
    new_plan_id: fn() -> Uuid,
}

/// `PruneHandler` — the `Server::prune` field type.
pub trait PruneHandler: Send + Sync {
    /// `Prune`.
    fn prune(&self, deadline: Instant, request: PruneRequest, peer: &PeerIdentity) -> Response;
}

impl PruneHandlerImpl {
    /// `NewPruneHandler`. A `None` engine refuses every request —
    /// plan included — rather than inventing eligibility without PG.
    #[must_use]
    pub fn new(
        pam: Option<Box<dyn PrunePamConfirmer>>,
        advisory: Option<Box<dyn PruneAdvisoryEvaluator>>,
        engine: Option<Box<dyn domain::PruneEngine>>,
        scope: CeremonyScope,
    ) -> Self {
        Self {
            pam,
            advisory,
            engine,
            scope,
            now: OffsetDateTime::now_utc,
            new_plan_id: Uuid::now_v7,
        }
    }

    /// `plan` — lists the currently eligible bodies and mints the plan
    /// ID. No ceremony: it mutates nothing, like backup-verify.
    fn plan(&self, request: &PruneRequest, retention_days: i32) -> Response {
        let Some(engine) = self.engine.as_ref() else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_UNAVAILABLE,
                None,
            );
        };
        let eligible = match engine.list_prune_eligible(retention_days) {
            Ok(e) => e,
            Err(_) => {
                return prune_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_PRUNE_UNAVAILABLE,
                    None,
                );
            }
        };
        for body in &eligible {
            if domain::validate_prune_candidate(body, retention_days).is_err() {
                return prune_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_PRUNE_UNAVAILABLE,
                    None,
                );
            }
        }
        let plan_id = (self.new_plan_id)();
        prune_response(
            &request.operation_id,
            "success",
            0,
            "ok",
            Some(&PruneResult {
                operation_id: request.operation_id.clone(),
                plan_id: plan_id.to_string(),
                bodies: to_prune_bodies(&eligible),
                bodies_deleted: 0,
                batches_done: 0,
                resumed_after_crash: false,
                completed_at: (self.now)().format(&Rfc3339).unwrap_or_default(),
            }),
        )
    }

    /// `apply` — runs the ceremony bound to the plan ID, then executes
    /// every non-done batch. A plan whose bodies changed since plan
    /// time is refused as stale rather than partially applied... except
    /// mid-run staleness, which stops the run after the completed
    /// batches: completed batches stay done (their tombstones are
    /// permanent) and the operator re-plans the rest.
    fn apply(
        &self,
        deadline: Instant,
        request: &PruneRequest,
        peer: &PeerIdentity,
        retention_days: i32,
    ) -> Response {
        let plan_id = match Uuid::parse_str(&request.plan_id) {
            Ok(id) if !id.is_nil() => id,
            _ => {
                return prune_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_PRUNE_INVALID_REQUEST,
                    None,
                );
            }
        };
        if request.bodies.is_empty() {
            return prune_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_PRUNE_INVALID_REQUEST,
                None,
            );
        }
        let mut bodies = Vec::with_capacity(request.bodies.len());
        for wire in &request.bodies {
            match from_prune_body(wire) {
                Ok(body) => bodies.push(body),
                Err(_) => {
                    return prune_response(
                        &request.operation_id,
                        "denied",
                        2,
                        domain::REASON_PRUNE_INVALID_REQUEST,
                        None,
                    );
                }
            }
        }
        let Some(pam) = self.pam.as_ref() else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_CEREMONY_REQUIRED,
                None,
            );
        };
        // Upstream hands the ceremony the whole verb ctx — the
        // ceremony share inside `pruneDeadline` is budget accounting,
        // not an enforced sub-deadline.
        let Some(confirmation) =
            pam.confirm_backup_prune(*peer, Some(deadline), &self.scope, &plan_id.to_string())
        else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_CEREMONY_REQUIRED,
                None,
            );
        };
        let Ok(token) = confirmation else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_AUTHORITY_DENIED,
                None,
            );
        };
        if !pam.verify_and_consume(&token) {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_AUTHORITY_DENIED,
                None,
            );
        }
        let Some(engine) = self.engine.as_ref() else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_UNAVAILABLE,
                None,
            );
        };
        let resumed = match engine.batch_states(plan_id) {
            Ok(states) => !states.is_empty(),
            Err(_) => {
                return prune_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_PRUNE_UNAVAILABLE,
                    None,
                );
            }
        };
        let plan = domain::PrunePlan {
            plan_id,
            bodies,
            retention_days,
        };
        match domain::apply_prune_batches(engine.as_ref(), &plan, retention_days) {
            Ok((deleted, done)) => prune_response(
                &request.operation_id,
                "success",
                0,
                "ok",
                Some(&PruneResult {
                    operation_id: request.operation_id.clone(),
                    plan_id: plan_id.to_string(),
                    bodies: None,
                    bodies_deleted: deleted,
                    batches_done: done,
                    resumed_after_crash: resumed,
                    completed_at: (self.now)().format(&Rfc3339).unwrap_or_default(),
                }),
            ),
            Err(e) => prune_response(
                &request.operation_id,
                "denied",
                7,
                if e.stale {
                    domain::REASON_PRUNE_PLAN_STALE
                } else {
                    domain::REASON_PRUNE_ENGINE_FAILED
                },
                None,
            ),
        }
    }
}

impl PruneHandler for PruneHandlerImpl {
    /// `Prune` — advisory denial comes first for both actions; only
    /// apply runs the ceremony, and the ceremony binds the plan ID so
    /// the one-use grant cannot cross plans.
    fn prune(&self, deadline: Instant, request: PruneRequest, peer: &PeerIdentity) -> Response {
        let op_ok =
            Uuid::parse_str(&request.operation_id).is_ok_and(|u| !u.is_nil()) && peer.pid > 0;
        let seams_ok = self.pam.is_some()
            && self.advisory.is_some()
            && !self.scope.instance_id.is_empty()
            && !self.scope.target_id.is_empty();
        if !op_ok || !seams_ok {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_CEREMONY_REQUIRED,
                None,
            );
        }
        // A missing engine is unavailability, not a ceremony problem:
        // without PG the handler cannot even list eligibility, and
        // saying "ceremony required" would send the operator to
        // complete a ritual that cannot help. (Found by the D07
        // acceptance suite.)
        if self.engine.is_none() {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_UNAVAILABLE,
                None,
            );
        }
        let retention_days = if request.retention_days == 0 {
            domain::DEFAULT_RETENTION_DAYS
        } else {
            request.retention_days
        };
        if retention_days < domain::DEFAULT_RETENTION_DAYS {
            return prune_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_PRUNE_INVALID_REQUEST,
                None,
            );
        }
        let Some(evaluator) = self.advisory.as_ref() else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_DENIED_SIGNED,
                None,
            );
        };
        let Ok((verdict, _admission)) = evaluator.evaluate() else {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_DENIED_SIGNED,
                None,
            );
        };
        if verdict.state != super::prepare::ADVISORY_STATE_CURRENT {
            return prune_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_PRUNE_DENIED_SIGNED,
                None,
            );
        }
        match request.action {
            PruneAction::Plan => self.plan(&request, retention_days),
            PruneAction::Apply => self.apply(deadline, &request, peer, retention_days),
        }
    }
}

// ---------------------------------------------------------------------------
// Client — `client_linux.go`'s prune half.
// ---------------------------------------------------------------------------

/// `PruneClientError` — only the stable exit class plus a whitelisted
/// reason token cross the boundary.
#[derive(Debug)]
pub struct PruneClientError {
    exit_code: i64,
    reason: String,
}

impl PruneClientError {
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

impl PruneClientError {
    /// Test-only constructor for the CLI's closed error-table tests.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(exit_code: i64, reason: &str) -> Self {
        new_prune_client_error(exit_code, reason)
    }
}

impl std::fmt::Display for PruneClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: prune failed")
    }
}

impl std::error::Error for PruneClientError {}

/// `DenySafeActiveWireReason` — the deny-safe gate's refusal token.
pub const DENY_SAFE_ACTIVE_WIRE_REASON: &str = "DENY_SAFE_ACTIVE";

fn retained_prune_reason(reason: &str) -> String {
    match reason {
        r if r == DENY_SAFE_ACTIVE_WIRE_REASON
            || r == domain::REASON_PRUNE_DENIED_SIGNED
            || r == domain::REASON_PRUNE_UNAVAILABLE
            || r == domain::REASON_PRUNE_PLAN_STALE
            || r == domain::REASON_PRUNE_CEREMONY_REQUIRED
            || r == domain::REASON_PRUNE_AUTHORITY_DENIED =>
        {
            r.to_owned()
        }
        _ => String::new(),
    }
}

fn new_prune_client_error(exit_code: i64, reason: &str) -> PruneClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    PruneClientError {
        exit_code,
        reason: retained_prune_reason(reason),
    }
}

/// `PruneClient` — `NewPruneClient`'s linux implementation: both prune
/// verbs over the one helper verb.
pub struct PruneClient {
    socket_path: String,
}

impl PruneClient {
    /// `NewPruneClient`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `Plan` — the read-only plan.
    pub fn plan(
        &self,
        operation_id: &str,
        retention_days: i32,
    ) -> Result<PruneResult, PruneClientError> {
        #[derive(Serialize)]
        struct Payload {
            action: &'static str,
            #[serde(skip_serializing_if = "is_zero")]
            retention_days: i32,
        }
        fn is_zero(v: &i32) -> bool {
            *v == 0
        }
        self.call(
            operation_id,
            &Payload {
                action: "plan",
                retention_days,
            },
        )
    }

    /// `Apply` — the destructive apply bound to `plan_id`.
    pub fn apply(
        &self,
        operation_id: &str,
        plan_id: &str,
        bodies: &[PruneBody],
        retention_days: i32,
    ) -> Result<PruneResult, PruneClientError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            action: &'static str,
            plan_id: &'a str,
            bodies: &'a [PruneBody],
            #[serde(skip_serializing_if = "is_zero")]
            retention_days: i32,
        }
        fn is_zero(v: &i32) -> bool {
            *v == 0
        }
        if plan_id.is_empty() || bodies.is_empty() {
            return Err(new_prune_client_error(3, ""));
        }
        self.call(
            operation_id,
            &Payload {
                action: "apply",
                plan_id,
                bodies,
                retention_days,
            },
        )
    }

    fn call<T: Serialize>(
        &self,
        operation_id: &str,
        payload: &T,
    ) -> Result<PruneResult, PruneClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() {
            return Err(new_prune_client_error(3, ""));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| new_prune_client_error(3, ""))?;
        let bound = Duration::from_secs(5);
        let _ = conn.set_read_timeout(Some(bound));
        let _ = conn.set_write_timeout(Some(bound));
        let payload = serde_json::to_string(payload)
            .ok()
            .and_then(|s| serde_json::value::RawValue::from_string(s).ok());
        write_request(
            &mut conn,
            &Request {
                operation_id: operation_id.to_owned(),
                verb: super::verb::BACKUP_PRUNE.to_owned(),
                payload,
            },
        )
        .map_err(|_| new_prune_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_prune_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_prune_client_error(response.exit_code, &response.reason));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        let result: PruneResult = super::backup::decode_exact_backup_read_result(&payload)
            .map_err(|_| new_prune_client_error(6, ""))?;
        if result.operation_id != operation_id || result.plan_id.is_empty() {
            return Err(new_prune_client_error(response.exit_code, &response.reason));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Confirmer;
    impl PrunePamConfirmer for Confirmer {
        fn verify_and_consume(&self, _t: &str) -> bool {
            true
        }
        fn confirm_backup_prune(
            &self,
            _p: PeerIdentity,
            _d: Option<Instant>,
            _s: &CeremonyScope,
            _plan: &str,
        ) -> Option<Result<String, Failure>> {
            Some(Ok("token".to_owned()))
        }
    }

    struct NoPruneCeremony;
    impl PrunePamConfirmer for NoPruneCeremony {
        fn verify_and_consume(&self, _t: &str) -> bool {
            true
        }
    }

    struct Eval(bool);
    impl PruneAdvisoryEvaluator for Eval {
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
    struct Engine {
        eligible: Vec<domain::PruneCandidate>,
        calls: std::sync::Mutex<Vec<String>>,
        tombstoned: std::sync::Mutex<std::collections::HashSet<(Uuid, Uuid)>>,
        states: std::sync::Mutex<HashMap<i32, domain::PruneRowState>>,
        fail_reprove: bool,
    }
    impl domain::PruneInventory for Engine {
        fn list_prune_eligible(
            &self,
            _r: i32,
        ) -> Result<Vec<domain::PruneCandidate>, domain::PruneEngineError> {
            Ok(self.eligible.clone())
        }
        fn reprove_body(
            &self,
            artifact_id: Uuid,
            workspace_id: Uuid,
            _r: i32,
        ) -> Result<domain::PruneCandidate, domain::PruneEngineError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("reprove:{artifact_id}"));
            if self.fail_reprove {
                let mut bad = self.eligible[0].clone();
                bad.reference_count = 1;
                let _ = workspace_id;
                return Ok(bad);
            }
            self.eligible
                .iter()
                .find(|c| c.artifact_id == artifact_id)
                .cloned()
                .ok_or_else(|| domain::PruneEngineError::engine("gone"))
        }
    }
    impl domain::PruneJournal for Engine {
        fn mark_batch_applying(
            &self,
            batch: &domain::PruneBatch,
        ) -> Result<(), domain::PruneEngineError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("applying:{}", batch.batch_seq));
            self.states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(batch.batch_seq, domain::PruneRowState::Applying);
            Ok(())
        }
        fn record_body_deleted(
            &self,
            _b: &domain::PruneBatch,
            body: &domain::PruneCandidate,
            _t: Uuid,
        ) -> Result<(), domain::PruneEngineError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("record:{}", body.artifact_id));
            self.tombstoned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert((body.workspace_id, body.artifact_id));
            Ok(())
        }
        fn mark_batch_done(&self, _p: Uuid, seq: i32) -> Result<(), domain::PruneEngineError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("done:{seq}"));
            self.states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(seq, domain::PruneRowState::Done);
            Ok(())
        }
        fn batch_states(
            &self,
            _p: Uuid,
        ) -> Result<HashMap<i32, domain::PruneRowState>, domain::PruneEngineError> {
            Ok(self
                .states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone())
        }
        fn has_tombstone(&self, w: Uuid, a: Uuid) -> Result<bool, domain::PruneEngineError> {
            Ok(self
                .tombstoned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(w, a)))
        }
    }
    impl domain::PruneBodyStore for Engine {
        fn delete_body(&self, key: &str) -> Result<(), domain::PruneEngineError> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("delete:{key}"));
            Ok(())
        }
    }

    fn candidate() -> domain::PruneCandidate {
        domain::PruneCandidate {
            artifact_id: Uuid::now_v7(),
            workspace_id: Uuid::now_v7(),
            object_key: format!("obj/{}", Uuid::now_v7()),
            staging_generation: Uuid::now_v7(),
            size: 5,
            retention_age_days: 90,
            reference_count: 0,
        }
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 4242,
        }
    }

    fn scope() -> CeremonyScope {
        CeremonyScope {
            instance_id: "default".into(),
            target_id: "postgres:central".into(),
        }
    }

    fn engine_boxed(eligible: Vec<domain::PruneCandidate>) -> std::sync::Arc<Engine> {
        std::sync::Arc::new(Engine {
            eligible,
            ..Engine::default()
        })
    }

    struct SharedEngine(std::sync::Arc<Engine>);
    impl domain::PruneInventory for SharedEngine {
        fn list_prune_eligible(
            &self,
            r: i32,
        ) -> Result<Vec<domain::PruneCandidate>, domain::PruneEngineError> {
            self.0.list_prune_eligible(r)
        }
        fn reprove_body(
            &self,
            a: Uuid,
            w: Uuid,
            r: i32,
        ) -> Result<domain::PruneCandidate, domain::PruneEngineError> {
            self.0.reprove_body(a, w, r)
        }
    }
    impl domain::PruneJournal for SharedEngine {
        fn mark_batch_applying(
            &self,
            b: &domain::PruneBatch,
        ) -> Result<(), domain::PruneEngineError> {
            self.0.mark_batch_applying(b)
        }
        fn record_body_deleted(
            &self,
            b: &domain::PruneBatch,
            c: &domain::PruneCandidate,
            t: Uuid,
        ) -> Result<(), domain::PruneEngineError> {
            self.0.record_body_deleted(b, c, t)
        }
        fn mark_batch_done(&self, p: Uuid, s: i32) -> Result<(), domain::PruneEngineError> {
            self.0.mark_batch_done(p, s)
        }
        fn batch_states(
            &self,
            p: Uuid,
        ) -> Result<HashMap<i32, domain::PruneRowState>, domain::PruneEngineError> {
            self.0.batch_states(p)
        }
        fn has_tombstone(&self, w: Uuid, a: Uuid) -> Result<bool, domain::PruneEngineError> {
            self.0.has_tombstone(w, a)
        }
    }
    impl domain::PruneBodyStore for SharedEngine {
        fn delete_body(&self, k: &str) -> Result<(), domain::PruneEngineError> {
            self.0.delete_body(k)
        }
    }

    /// Plan is read-only: no ceremony, just the eligible set plus a
    /// minted plan id.
    #[test]
    fn prune_plan_lists_eligible_without_ceremony() {
        let engine = engine_boxed(vec![candidate(), candidate()]);
        let h = PruneHandlerImpl::new(
            Some(Box::new(NoPruneCeremony)),
            Some(Box::new(Eval(true))),
            Some(Box::new(SharedEngine(engine.clone()))),
            scope(),
        );
        let op = Uuid::now_v7().to_string();
        let resp = h.prune(
            Instant::now() + Duration::from_secs(60),
            PruneRequest {
                operation_id: op,
                action: PruneAction::Plan,
                plan_id: String::new(),
                retention_days: 0,
                bodies: vec![],
            },
            &peer(),
        );
        assert_eq!(resp.outcome, "success");
        assert_eq!(resp.exit_code, 0);
        let result: PruneResult =
            serde_json::from_str(resp.result.as_ref().unwrap().get()).unwrap();
        assert!(!result.plan_id.is_empty());
        assert_eq!(result.bodies.as_ref().map(Vec::len), Some(2));
    }

    /// A missing engine refuses plan AND apply as PRUNE_UNAVAILABLE —
    /// the production composition's exact answer until PG lands.
    #[test]
    fn prune_unavailable_engine_refuses_both() {
        let h = PruneHandlerImpl::new(
            Some(Box::new(Confirmer)),
            Some(Box::new(Eval(true))),
            None,
            scope(),
        );
        let op = Uuid::now_v7().to_string();
        for action in [PruneAction::Plan, PruneAction::Apply] {
            let resp = h.prune(
                Instant::now() + Duration::from_secs(60),
                PruneRequest {
                    operation_id: op.clone(),
                    action,
                    plan_id: Uuid::now_v7().to_string(),
                    retention_days: 0,
                    bodies: vec![PruneBody {
                        artifact_id: Uuid::now_v7().to_string(),
                        workspace_id: Uuid::now_v7().to_string(),
                        object_key: "k".into(),
                        staging_generation: Uuid::now_v7().to_string(),
                        size: 1,
                        retention_age_days: 90,
                        reference_count: 0,
                    }],
                },
                &peer(),
            );
            assert_eq!(resp.reason, domain::REASON_PRUNE_UNAVAILABLE);
        }
    }

    /// Apply runs the ceremony bound to the plan id, then deletes
    /// every body: reprove → tombstone-skip → record → delete.
    #[test]
    fn prune_apply_deletes_every_body_once() {
        let bodies = vec![candidate(), candidate()];
        let engine = engine_boxed(bodies.clone());
        let h = PruneHandlerImpl::new(
            Some(Box::new(Confirmer)),
            Some(Box::new(Eval(true))),
            Some(Box::new(SharedEngine(engine.clone()))),
            scope(),
        );
        let op = Uuid::now_v7().to_string();
        let plan_id = Uuid::now_v7();
        let wire: Vec<PruneBody> = bodies
            .iter()
            .map(|b| PruneBody {
                artifact_id: b.artifact_id.to_string(),
                workspace_id: b.workspace_id.to_string(),
                object_key: b.object_key.clone(),
                staging_generation: b.staging_generation.to_string(),
                size: b.size,
                retention_age_days: b.retention_age_days,
                reference_count: b.reference_count,
            })
            .collect();
        let resp = h.prune(
            Instant::now() + Duration::from_secs(60),
            PruneRequest {
                operation_id: op,
                action: PruneAction::Apply,
                plan_id: plan_id.to_string(),
                retention_days: 0,
                bodies: wire,
            },
            &peer(),
        );
        assert_eq!(resp.outcome, "success");
        let calls = engine.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.iter().filter(|c| c.starts_with("delete:")).count(), 2);
    }

    /// A stale apply (a body gained a reference) refuses as
    /// PRUNE_PLAN_STALE — nothing deleted.
    #[test]
    fn prune_apply_stale_refuses() {
        let engine = std::sync::Arc::new(Engine {
            eligible: vec![candidate()],
            fail_reprove: true,
            ..Engine::default()
        });
        let h = PruneHandlerImpl::new(
            Some(Box::new(Confirmer)),
            Some(Box::new(Eval(true))),
            Some(Box::new(SharedEngine(engine.clone()))),
            scope(),
        );
        let wire = PruneBody {
            artifact_id: engine.eligible[0].artifact_id.to_string(),
            workspace_id: engine.eligible[0].workspace_id.to_string(),
            object_key: "k".into(),
            staging_generation: engine.eligible[0].staging_generation.to_string(),
            size: 1,
            retention_age_days: 90,
            reference_count: 0,
        };
        let op = Uuid::now_v7().to_string();
        let resp = h.prune(
            Instant::now() + Duration::from_secs(60),
            PruneRequest {
                operation_id: op,
                action: PruneAction::Apply,
                plan_id: Uuid::now_v7().to_string(),
                retention_days: 0,
                bodies: vec![wire],
            },
            &peer(),
        );
        assert_eq!(resp.reason, domain::REASON_PRUNE_PLAN_STALE);
    }

    /// `parse_prune_request` — action required, unknown fields refused.
    #[test]
    fn parse_prune_request_rules() {
        let req = |payload: &str| Request {
            operation_id: "op".to_owned(),
            verb: "backup-prune".to_owned(),
            payload: serde_json::value::RawValue::from_string(payload.to_owned()).ok(),
        };
        assert!(parse_prune_request(&req("")).is_err());
        assert!(parse_prune_request(&req(r#"{"action":"bogus"}"#)).is_err());
        assert!(parse_prune_request(&req(r#"{"action":"plan","x":1}"#)).is_err());
        let plan = parse_prune_request(&req(r#"{"action":"plan"}"#)).unwrap();
        assert_eq!(plan.action, PruneAction::Plan);
    }
}
