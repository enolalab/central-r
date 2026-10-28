//! `maintenance.go` + `maintenance_apply.go` — E01/E02/E03: read-only
//! compatibility planning and the PAM-authorized recording of
//! matrix-approved dependency transitions. The handlers never install,
//! pull, or edit anything; they verify the target is already
//! observable and then commit the authority record.

use super::grant::CeremonyScope;
use super::protocol::*;
use super::{PeerIdentity, verb};
use central_foundation::failure::Failure;
use central_infra::maintenance as m;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

pub const REASON_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
pub const REASON_MAINTENANCE_UNAVAILABLE: &str = "MAINTENANCE_UNAVAILABLE";
pub const REASON_MAINTENANCE_MATRIX_TAMPERED: &str = "MAINTENANCE_MATRIX_TAMPERED";
pub const REASON_INVALID_MAINTENANCE_REQUEST: &str = "INVALID_MAINTENANCE_REQUEST";

/// `MaintenanceRequest` — the E01 plan payload: zero or more
/// `name=target` transition checks.
#[derive(Debug, Clone, Default)]
pub struct MaintenanceRequest {
    pub operation_id: String,
    pub checks: Vec<String>,
}

/// `ParseMaintenanceRequest` — unknown fields and malformed checks
/// are refused.
pub fn parse_maintenance_request(req: &Request) -> Result<MaintenanceRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing maintenance operation".to_owned());
    }
    let trimmed = {
        let p = req.payload_bytes();
        let s = p
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(p.len());
        let e = p
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(s, |i| i + 1);
        &p[s..e.max(s)]
    };
    if trimmed.is_empty() {
        return Ok(MaintenanceRequest {
            operation_id: req.operation_id.clone(),
            ..MaintenanceRequest::default()
        });
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        checks: Vec<String>,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|e| format!("helper: invalid maintenance payload: {e}"))?;
    for c in &payload.checks {
        let (name, target) = c
            .split_once('=')
            .ok_or_else(|| format!("helper: invalid check {c:?}"))?;
        if name.is_empty() || target.is_empty() {
            return Err(format!("helper: invalid check {c:?}"));
        }
    }
    Ok(MaintenanceRequest {
        operation_id: req.operation_id.clone(),
        checks: payload.checks,
    })
}

/// `MaintenanceResult` — the bounded plan outcome: observed versions,
/// verdict counts, the governing matrix identity, and refused checks.
/// Versions and digests cross; file contents and keys never do.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceResult {
    pub operation_id: String,
    pub initialized: bool,
    pub entries: i64,
    pub allowed: i64,
    pub forbidden: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<m::Verdict>,
    pub dependencies: Vec<m::Observed>,
    pub observed: BTreeMap<String, String>,
    pub matrix_digest: String,
    pub sequence_num: u64,
    pub completed_at: String,
}

/// `MaintenanceProbes` observes installed versions by matrix entry
/// name. A missing probe leaves the dependency "unprobed" — reported,
/// never fabricated.
pub type MaintenanceProbes =
    BTreeMap<String, Box<dyn Fn() -> Result<String, Failure> + Send + Sync>>;

fn now_rfc3339() -> String {
    super::audit::format_rfc3339nano(time::OffsetDateTime::now_utc())
}

fn valid_operation_id(op: &str) -> bool {
    uuid::Uuid::parse_str(op)
        .map(|u| u != uuid::Uuid::nil())
        .unwrap_or(false)
}

fn maintenance_response(operation_id: &str, outcome: &str, code: i64, reason: &str) -> Response {
    Response::new(operation_id, outcome, code, reason)
}

/// `MaintenanceHandlerImpl` performs E01: read-only compatibility
/// planning. It carries no ceremony (read-only, the state-audit
/// shape) and is admitted in deny-safe mode.
pub struct MaintenanceHandlerImpl {
    pub store: Option<m::Store>,
    pub probes: MaintenanceProbes,
}

/// The transport seam.
pub trait MaintenanceHandler: Send + Sync {
    fn maintenance_plan(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        request: MaintenanceRequest,
    ) -> Response;
}

impl MaintenanceHandler for MaintenanceHandlerImpl {
    /// `MaintenancePlan` — loads (bootstrapping on first use), probes
    /// the host, and answers every requested check. An unlisted
    /// transition refuses the whole request.
    fn maintenance_plan(
        &self,
        peer: PeerIdentity,
        _deadline: Instant,
        request: MaintenanceRequest,
    ) -> Response {
        let op = request.operation_id.as_str();
        if !valid_operation_id(op) || !peer.available() || self.store.is_none() {
            return maintenance_response(op, "denied", 7, REASON_AUTHORITY_DENIED);
        }
        let Some(store) = &self.store else {
            return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
        };
        let (matrix, initialized) = match store.load_or_bootstrap() {
            Ok((matrix, init)) => (matrix, init),
            Err(e) if e.code() == m::MATRIX_TAMPERED_CODE => {
                return maintenance_response(op, "denied", 7, REASON_MAINTENANCE_MATRIX_TAMPERED);
            }
            Err(_) => {
                return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
            }
        };
        let mut observed: BTreeMap<String, String> = BTreeMap::new();
        for (name, probe) in &self.probes {
            if let Ok(v) = probe()
                && !v.is_empty()
            {
                observed.insert(name.clone(), v);
            }
        }
        let plan = m::evaluate_current(&matrix, &observed);
        let mut result = MaintenanceResult {
            operation_id: op.to_owned(),
            initialized,
            entries: matrix.entries.len() as i64,
            dependencies: plan.dependencies,
            observed,
            sequence_num: matrix.sequence_num,
            completed_at: now_rfc3339(),
            matrix_digest: matrix.digest().unwrap_or_default(),
            ..MaintenanceResult::default()
        };
        for raw in &request.checks {
            let Some((name, target)) = raw.split_once('=') else {
                continue;
            };
            let v = m::evaluate(&matrix, &m::Transition { name, to: target });
            if v.allowed {
                result.allowed += 1;
            } else {
                result.forbidden += 1;
                result.violations.push(v);
            }
        }
        let resp = maintenance_response(
            op,
            if result.forbidden > 0 {
                "denied"
            } else {
                "success"
            },
            if result.forbidden > 0 { 7 } else { 0 },
            if result.forbidden > 0 {
                m::REASON_UNLISTED
            } else {
                ""
            },
        );
        resp.with_result(&result)
    }
}

// ---------------------------------------------------------------------------
// MaintenanceApply (maintenance_apply.go)
// ---------------------------------------------------------------------------

/// `MaintenanceApplyRequest` — the E02/E03 apply payload: one
/// `name=target` transition to authorize and attempt, a resume naming
/// a pending attempt id, a rollback naming an applied attempt id, or
/// an abandon naming a pending attempt id. Exactly one is set.
#[derive(Debug, Clone, Default)]
pub struct MaintenanceApplyRequest {
    pub operation_id: String,
    pub set: String,
    pub resume: String,
    pub rollback: String,
    pub abandon: String,
}

/// `ParseMaintenanceApplyRequest` — unknown fields, trailing data, a
/// payload carrying both set and resume, and malformed values are
/// refused.
pub fn parse_maintenance_apply_request(req: &Request) -> Result<MaintenanceApplyRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing maintenance operation".to_owned());
    }
    let trimmed = {
        let p = req.payload_bytes();
        let s = p
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(p.len());
        let e = p
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(s, |i| i + 1);
        &p[s..e.max(s)]
    };
    if trimmed.is_empty() {
        return Err("helper: invalid maintenance-apply payload".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        set: String,
        #[serde(default)]
        resume: String,
        #[serde(default)]
        rollback: String,
        #[serde(default)]
        abandon: String,
    }
    let payload: Payload = strict_decode(trimmed)
        .map_err(|e| format!("helper: invalid maintenance-apply payload: {e}"))?;
    let filled = [
        &payload.set,
        &payload.resume,
        &payload.rollback,
        &payload.abandon,
    ]
    .iter()
    .filter(|v| !v.is_empty())
    .count();
    if filled != 1 {
        return Err(
            "helper: exactly one of set, resume, rollback, or abandon is required".to_owned(),
        );
    }
    if !payload.set.is_empty() {
        let (name, target) = payload
            .set
            .split_once('=')
            .ok_or_else(|| format!("helper: invalid set {:?}", payload.set))?;
        if name.is_empty() || target.is_empty() {
            return Err(format!("helper: invalid set {:?}", payload.set));
        }
    }
    for id_field in [&payload.resume, &payload.rollback, &payload.abandon] {
        if id_field.is_empty() {
            continue;
        }
        if !valid_operation_id(id_field) {
            return Err("helper: invalid attempt id".to_owned());
        }
    }
    Ok(MaintenanceApplyRequest {
        operation_id: req.operation_id.clone(),
        set: payload.set,
        resume: payload.resume,
        rollback: payload.rollback,
        abandon: payload.abandon,
    })
}

/// `MaintenanceApplyResult` — the bounded apply outcome: the attempt
/// identity, the transition, the gate verdict, and the matrix identity
/// the result ran against.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceApplyResult {
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attempt_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dependency: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gate: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gate_detail: String,
    pub sequence_num: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub matrix_digest: String,
    pub completed_at: String,
}

/// `maintenanceApplyPAMConfirmer` — the narrow capability the patch
/// handler requires of its confirmer. `None` refuses —
/// `MAINTENANCE_UNAVAILABLE`, upstream's failed type assertion.
pub trait MaintenanceApplyPamConfirmer: Send + Sync {
    fn confirm_maintenance_apply(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &CeremonyScope,
        operation_id: &str,
    ) -> Result<String, Failure>;
    fn verify_and_consume(&self, token: &str) -> bool;
}

/// `MaintenanceApplyImageProbe` answers whether an image digest is
/// resolvable on this host. `None` refuses digest-gated entries rather
/// than fabricating.
pub type MaintenanceApplyImageProbe = dyn Fn(&str) -> Result<bool, Failure> + Send + Sync;

/// `MaintenanceApplyHandlerImpl` performs E02: PAM-authorized
/// recording of a matrix-approved dependency transition.
pub struct MaintenanceApplyHandlerImpl {
    pub store: Option<m::Store>,
    pub probes: MaintenanceProbes,
    pub images: Option<Box<MaintenanceApplyImageProbe>>,
    pub pam: Option<Box<dyn MaintenanceApplyPamConfirmer>>,
    pub scope: CeremonyScope,
}

/// The transport seam.
pub trait MaintenanceApplyHandler: Send + Sync {
    fn maintenance_apply(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        request: MaintenanceApplyRequest,
    ) -> Response;
}

impl MaintenanceApplyHandler for MaintenanceApplyHandlerImpl {
    /// `MaintenanceApply` — upstream ordering verbatim: validate,
    /// load, matrix approval, pending exclusion, gate-verb check,
    /// ceremony, pending row, gate, then commit+applied or failed. A
    /// crash between the pending row and the verdict leaves a
    /// resumable attempt.
    fn maintenance_apply(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        request: MaintenanceApplyRequest,
    ) -> Response {
        let op = request.operation_id.as_str();
        if !valid_operation_id(op)
            || !peer.available()
            || self.store.is_none()
            || self.pam.is_none()
            || self.scope.instance_id.is_empty()
            || self.scope.target_id.is_empty()
        {
            return maintenance_response(op, "denied", 7, REASON_AUTHORITY_DENIED);
        }
        let Some(pam) = &self.pam else {
            // Upstream's narrow-interface assertion — unreachable once
            // the AUTHORITY_DENIED gate above has run.
            return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
        };
        let Some(store) = &self.store else {
            return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
        };
        let (mut matrix, _initialized) = match store.load_or_bootstrap() {
            Ok(v) => v,
            Err(e) if e.code() == m::MATRIX_TAMPERED_CODE => {
                return maintenance_response(op, "denied", 7, REASON_MAINTENANCE_MATRIX_TAMPERED);
            }
            Err(_) => {
                return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
            }
        };

        let mut attempt = m::Attempt::default();
        let mut entry = m::Entry::default();
        let mut mode = "patch";
        let mut pending_op = m::OP_PATCH_PENDING;
        let mut applied_op = m::OP_PATCH_APPLIED;
        let mut failed_op = m::OP_PATCH_FAILED;

        if !request.set.is_empty() {
            let Some((name, target)) = request.set.split_once('=') else {
                return maintenance_response(op, "denied", 7, m::REASON_UNLISTED);
            };
            let Some(e) = matrix.entry_by_name(name) else {
                return maintenance_response(op, "denied", 7, m::REASON_UNLISTED);
            };
            if !m::evaluate(&matrix, &m::Transition { name, to: target }).allowed {
                return maintenance_response(op, "denied", 7, m::REASON_UNLISTED);
            }
            match store.pending_attempt() {
                Err(_) => {
                    return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
                }
                Ok(Some((pending, _))) => {
                    return maintenance_response(op, "denied", 7, m::REASON_PATCH_PENDING)
                        .with_result(&MaintenanceApplyResult {
                            operation_id: op.to_owned(),
                            attempt_id: pending.attempt_id,
                            completed_at: String::new(),
                            ..MaintenanceApplyResult::default()
                        });
                }
                Ok(None) => {}
            }
            attempt = m::Attempt {
                dependency: name.to_owned(),
                from: e.current.clone(),
                to: target.to_owned(),
                gate: e.gate.clone(),
                ..m::Attempt::default()
            };
            entry = e;
        } else if !request.resume.is_empty() {
            let (found, status) = match store.find_attempt(&request.resume) {
                Ok(v) => v,
                Err(_) => {
                    return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
                }
            };
            let Some(found) = found else {
                return maintenance_response(op, "denied", 7, m::REASON_PATCH_UNKNOWN);
            };
            if status != m::OP_PATCH_PENDING && status != m::OP_ROLLBACK_PENDING {
                return maintenance_response(op, "denied", 7, m::REASON_PATCH_CLOSED).with_result(
                    &MaintenanceApplyResult {
                        operation_id: op.to_owned(),
                        attempt_id: found.attempt_id,
                        completed_at: String::new(),
                        ..MaintenanceApplyResult::default()
                    },
                );
            }
            if status == m::OP_ROLLBACK_PENDING {
                mode = "rollback";
                pending_op = m::OP_ROLLBACK_PENDING;
                applied_op = m::OP_ROLLBACK_APPLIED;
                failed_op = m::OP_ROLLBACK_FAILED;
            }
            let Some(e) = matrix.entry_by_name(&found.dependency) else {
                return maintenance_response(op, "denied", 7, m::REASON_UNLISTED);
            };
            if !m::evaluate(
                &matrix,
                &m::Transition {
                    name: &found.dependency,
                    to: &found.to,
                },
            )
            .allowed
            {
                return maintenance_response(op, "denied", 7, m::REASON_UNLISTED);
            }
            attempt = found;
            entry = e;
        } else if !request.rollback.is_empty() {
            mode = "rollback";
            pending_op = m::OP_ROLLBACK_PENDING;
            applied_op = m::OP_ROLLBACK_APPLIED;
            failed_op = m::OP_ROLLBACK_FAILED;
            let (found, status) = match store.find_attempt(&request.rollback) {
                Ok(v) => v,
                Err(_) => {
                    return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
                }
            };
            let Some(found) = found else {
                return maintenance_response(op, "denied", 7, m::REASON_PATCH_UNKNOWN);
            };
            if status != m::OP_PATCH_APPLIED {
                return maintenance_response(op, "denied", 7, m::REASON_PATCH_CLOSED).with_result(
                    &MaintenanceApplyResult {
                        operation_id: op.to_owned(),
                        attempt_id: found.attempt_id,
                        completed_at: String::new(),
                        ..MaintenanceApplyResult::default()
                    },
                );
            }
            let Some(e) = matrix.entry_by_name(&found.dependency) else {
                return maintenance_response(op, "denied", 7, m::REASON_UNLISTED);
            };
            // A matrix whose current moved past the attempt's target
            // makes this rollback ambiguous — refuse rather than guess.
            if e.current != found.to {
                return maintenance_response(op, "denied", 7, m::REASON_ROLLBACK_STALE)
                    .with_result(&MaintenanceApplyResult {
                        operation_id: op.to_owned(),
                        mode: "rollback".to_owned(),
                        attempt_id: found.attempt_id,
                        completed_at: String::new(),
                        ..MaintenanceApplyResult::default()
                    });
            }
            match store.pending_attempt() {
                Err(_) => {
                    return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
                }
                Ok(Some((pending, _))) => {
                    return maintenance_response(op, "denied", 7, m::REASON_PATCH_PENDING)
                        .with_result(&MaintenanceApplyResult {
                            operation_id: op.to_owned(),
                            attempt_id: pending.attempt_id,
                            completed_at: String::new(),
                            ..MaintenanceApplyResult::default()
                        });
                }
                Ok(None) => {}
            }
            attempt = m::Attempt {
                attempt_id: found.attempt_id.clone(),
                dependency: found.dependency.clone(),
                from: found.to.clone(),
                to: found.from.clone(),
                gate: found.gate.clone(),
                ..m::Attempt::default()
            };
            entry = e;
        } else if !request.abandon.is_empty() {
            let (found, status) = match store.find_attempt(&request.abandon) {
                Ok(v) => v,
                Err(_) => {
                    return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
                }
            };
            let Some(found) = found else {
                return maintenance_response(op, "denied", 7, m::REASON_PATCH_UNKNOWN);
            };
            let abandon_op = match status.as_str() {
                s if s == m::OP_PATCH_PENDING => m::OP_PATCH_ABANDONED,
                s if s == m::OP_ROLLBACK_PENDING => m::OP_ROLLBACK_ABANDONED,
                _ => {
                    return maintenance_response(op, "denied", 7, m::REASON_PATCH_CLOSED)
                        .with_result(&MaintenanceApplyResult {
                            operation_id: op.to_owned(),
                            mode: "abandon".to_owned(),
                            attempt_id: found.attempt_id,
                            completed_at: String::new(),
                            ..MaintenanceApplyResult::default()
                        });
                }
            };
            // Abandoning an authorized-but-unresolved attempt is an
            // authority act — the ceremony runs here too.
            let confirmation = pam
                .confirm_maintenance_apply(peer, Some(deadline), &self.scope, &request.operation_id)
                .ok()
                .filter(|token| pam.verify_and_consume(token));
            if confirmation.is_none() {
                return maintenance_response(op, "denied", 7, REASON_AUTHORITY_DENIED);
            }
            if store.append_attempt(abandon_op, &found, "", "").is_err() {
                return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
            }
            let mut result = MaintenanceApplyResult {
                operation_id: op.to_owned(),
                mode: "abandon".to_owned(),
                attempt_id: found.attempt_id,
                dependency: found.dependency,
                from: found.from,
                to: found.to,
                sequence_num: matrix.sequence_num,
                matrix_digest: matrix.digest().unwrap_or_default(),
                completed_at: now_rfc3339(),
                ..MaintenanceApplyResult::default()
            };
            if result.matrix_digest.is_empty() {
                result.matrix_digest = String::new();
            }
            return maintenance_response(op, "success", 0, "").with_result(&result);
        }

        // Refuse unimplemented gate verbs before the ceremony: an
        // attempt that can never pass earns no consent prompt and no
        // journal row.
        if !gate_verb_implemented(&entry) {
            return maintenance_response(op, "denied", 7, m::REASON_GATE_UNKNOWN);
        }

        let confirmation = pam
            .confirm_maintenance_apply(peer, Some(deadline), &self.scope, &request.operation_id)
            .ok()
            .filter(|token| pam.verify_and_consume(token));
        if confirmation.is_none() {
            return maintenance_response(op, "denied", 7, REASON_AUTHORITY_DENIED);
        }

        if !request.set.is_empty() || !request.rollback.is_empty() {
            if attempt.attempt_id.is_empty() {
                attempt.attempt_id = uuid::Uuid::new_v4().to_string();
            }
            if store.append_attempt(pending_op, &attempt, "", "").is_err() {
                return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
            }
        }

        let gate = self.run_gate(&entry, &attempt);
        let mut result = MaintenanceApplyResult {
            operation_id: op.to_owned(),
            mode: mode.to_owned(),
            attempt_id: attempt.attempt_id.clone(),
            dependency: attempt.dependency.clone(),
            from: attempt.from.clone(),
            to: attempt.to.clone(),
            gate: gate.verb.clone(),
            sequence_num: matrix.sequence_num,
            matrix_digest: matrix.digest().unwrap_or_default(),
            completed_at: now_rfc3339(),
            ..MaintenanceApplyResult::default()
        };
        if !gate.pass {
            if store
                .append_attempt(failed_op, &attempt, &gate.verb, &gate.detail)
                .is_err()
            {
                return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
            }
            result.gate_detail = gate.detail.clone();
            return maintenance_response(op, "denied", 7, m::REASON_GATE_FAILED)
                .with_result(&result);
        }

        // Commit the matrix update first, then the applied row echoing
        // the new digest — a crash between them leaves the attempt
        // pending and the matrix already moved, which resume
        // reconciles by re-running the gate.
        for e in &mut matrix.entries {
            if e.name == attempt.dependency {
                e.current = attempt.to.clone();
            }
        }
        matrix.sequence_num += 1;
        if store.commit_update(&matrix).is_err() {
            return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
        }
        if store
            .append_attempt(applied_op, &attempt, &gate.verb, "")
            .is_err()
        {
            return maintenance_response(op, "deferred", 5, REASON_MAINTENANCE_UNAVAILABLE);
        }
        result.sequence_num = matrix.sequence_num;
        result.matrix_digest = matrix.digest().unwrap_or_default();
        maintenance_response(op, "success", 0, "").with_result(&result)
    }
}

impl MaintenanceApplyHandlerImpl {
    /// `RunGate` — binds the domain gate evaluator to this handler's
    /// seams.
    fn run_gate(&self, e: &m::Entry, a: &m::Attempt) -> m::GateResult {
        let probes = &self.probes;
        let images = &self.images;
        m::run_gate(
            e,
            a,
            Some(&|name| {
                probes.get(name).map_or_else(
                    || Err(Failure::unavailable("maintenance_probe", "no probe")),
                    |p| p(),
                )
            }),
            images
                .as_deref()
                .map(|f| f as &dyn Fn(&str) -> Result<bool, Failure>),
        )
    }
}

/// `gateVerbFor` — resolves the entry's declared gate to an
/// implemented verb, or refuses when E02 implements no such gate.
fn gate_verb_implemented(e: &m::Entry) -> bool {
    let verb = gate_verb_for(e);
    verb == m::GATE_VERSION_PRESENT || verb == m::GATE_DIGEST_PRESENT
}

/// `maintenanceGateVerb` — the domain's gate-string mapping via a
/// zero-attempt `run_gate` (the mapping ignores the attempt and
/// seams).
fn gate_verb_for(e: &m::Entry) -> String {
    m::run_gate(e, &m::Attempt::default(), None, None).verb
}

// ---------------------------------------------------------------------------
// Clients — client_linux.go's linuxMaintenanceClient family.
// ---------------------------------------------------------------------------

/// `MaintenanceClientResult` mirrors the helper's `MaintenanceResult`.
pub type MaintenanceClientResult = MaintenanceResult;

/// `MaintenanceApplyClientResult` mirrors the helper's
/// `MaintenanceApplyResult`.
pub type MaintenanceApplyClientResult = MaintenanceApplyResult;

/// `MaintenanceClientError` — the stable exit class plus a
/// whitelisted reason token; denied results may carry a bounded
/// partial result.
#[derive(Debug)]
pub struct MaintenanceClientError {
    exit_code: i64,
    reason: String,
    result: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl MaintenanceClientError {
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    /// `ErrResult` — the denied plan's bounded partial result, when
    /// the helper attached one (`MAINTENANCE_TRANSITION_UNLISTED`).
    pub fn plan_result(&self) -> Option<&MaintenanceResult> {
        self.result
            .as_ref()
            .and_then(|b| b.downcast_ref::<MaintenanceResult>())
    }
    /// The denied apply's bounded partial result, when attached.
    pub fn apply_result(&self) -> Option<&MaintenanceApplyResult> {
        self.result
            .as_ref()
            .and_then(|b| b.downcast_ref::<MaintenanceApplyResult>())
    }
}

impl std::fmt::Display for MaintenanceClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "helper: maintenance failed")
    }
}
impl std::error::Error for MaintenanceClientError {}

/// `retainedMaintenanceReason` — the plan client's complete whitelist.
fn retained_maintenance_reason(reason: &str) -> String {
    match reason {
        central_infra::advisory::REASON_DENY_SAFE_ACTIVE
        | m::REASON_UNLISTED
        | REASON_MAINTENANCE_MATRIX_TAMPERED => reason.to_owned(),
        _ => String::new(),
    }
}

/// `retainedMaintenanceApplyReason` — the apply client's complete
/// whitelist.
fn retained_maintenance_apply_reason(reason: &str) -> String {
    match reason {
        central_infra::advisory::REASON_DENY_SAFE_ACTIVE
        | m::REASON_UNLISTED
        | REASON_MAINTENANCE_MATRIX_TAMPERED
        | m::REASON_PATCH_PENDING
        | m::REASON_PATCH_UNKNOWN
        | m::REASON_PATCH_CLOSED
        | m::REASON_GATE_FAILED
        | m::REASON_GATE_UNKNOWN
        | m::REASON_ROLLBACK_STALE => reason.to_owned(),
        _ => String::new(),
    }
}

fn new_maintenance_client_error(exit_code: i64, reason: &str) -> MaintenanceClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    MaintenanceClientError {
        exit_code,
        reason: retained_maintenance_reason(reason),
        result: None,
    }
}

fn new_maintenance_apply_client_error(exit_code: i64, reason: &str) -> MaintenanceClientError {
    let mut err = new_maintenance_client_error(exit_code, "");
    err.reason = retained_maintenance_apply_reason(reason);
    err
}

fn decode_exact<T: for<'de> Deserialize<'de> + Serialize>(
    payload: &[u8],
    what: &str,
) -> Result<T, String> {
    if payload.is_empty() {
        return Err(format!("helper: {what} result is invalid"));
    }
    let result: T = strict_decode(payload)?;
    let canonical = serde_json::to_vec(&result)
        .map_err(|_| format!("helper: {what} result is not canonical"))?;
    if canonical != payload {
        return Err(format!("helper: {what} result is not canonical"));
    }
    Ok(result)
}

fn dial(
    socket_path: &str,
    budget: std::time::Duration,
) -> Result<std::os::unix::net::UnixStream, MaintenanceClientError> {
    let conn = super::browser::dial_unix_bounded(
        std::path::Path::new(socket_path),
        super::client::DIAL_TIMEOUT,
    )
    .map_err(|_| new_maintenance_client_error(3, ""))?;
    let _ = conn.set_read_timeout(Some(super::client::DIAL_TIMEOUT + budget));
    let _ = conn.set_write_timeout(Some(super::client::DIAL_TIMEOUT));
    Ok(conn)
}

/// `MaintenanceClient` — `linuxMaintenanceClient`: dials the
/// maintenance-plan verb.
pub struct MaintenanceClient {
    socket_path: String,
}

impl MaintenanceClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        MaintenanceClient {
            socket_path: socket_path.into(),
        }
    }

    /// `Plan` — sends `checks` and validates the bounded result.
    /// A `MAINTENANCE_TRANSITION_UNLISTED` denial carries the partial
    /// result inside the error.
    pub fn plan(
        &self,
        operation_id: &str,
        checks: &[String],
    ) -> Result<MaintenanceClientResult, MaintenanceClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() {
            return Err(new_maintenance_client_error(3, ""));
        }
        let mut conn = dial(&self.socket_path, super::server::MAINTENANCE_PLAN_BUDGET)?;
        let payload = serde_json::json!({ "checks": checks });
        let msg = Request {
            operation_id: operation_id.to_owned(),
            verb: verb::MAINTENANCE_PLAN.to_owned(),
            payload: serde_json::value::RawValue::from_string(payload.to_string()).ok(),
        };
        write_request(&mut conn, &msg).map_err(|_| new_maintenance_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_maintenance_client_error(3, ""))?;
        let raw = response
            .result
            .as_ref()
            .map_or(&b""[..], |r| r.get().as_bytes());
        if response.outcome != "success" || response.exit_code != 0 {
            let mut err = new_maintenance_client_error(response.exit_code, &response.reason);
            // A denied plan still carries its violations — decode them
            // so the CLI can echo the refused transitions.
            if response.outcome == "denied"
                && let Ok(denied) = decode_exact::<MaintenanceResult>(raw, "maintenance")
            {
                err.result = Some(Box::new(denied));
            }
            return Err(err);
        }
        if raw.is_empty() {
            return Err(new_maintenance_client_error(6, ""));
        }
        let result: MaintenanceResult =
            decode_exact(raw, "maintenance").map_err(|_| new_maintenance_client_error(6, ""))?;
        if result.operation_id != operation_id || result.completed_at.is_empty() {
            return Err(new_maintenance_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        Ok(result)
    }
}

/// `MaintenanceApplyClient` — `linuxMaintenanceApplyClient`: dials
/// the maintenance-apply verb.
pub struct MaintenanceApplyClient {
    socket_path: String,
}

impl MaintenanceApplyClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        MaintenanceApplyClient {
            socket_path: socket_path.into(),
        }
    }

    /// `Apply` — sends exactly one of set/resume/rollback/abandon and
    /// validates the bounded result. Denials may carry the partial
    /// apply result inside the error.
    pub fn apply(
        &self,
        operation_id: &str,
        request: &MaintenanceApplyRequest,
    ) -> Result<MaintenanceApplyClientResult, MaintenanceClientError> {
        let filled = [
            &request.set,
            &request.resume,
            &request.rollback,
            &request.abandon,
        ]
        .iter()
        .filter(|v| !v.is_empty())
        .count();
        if self.socket_path.is_empty() || operation_id.is_empty() || filled != 1 {
            return Err(new_maintenance_apply_client_error(3, ""));
        }
        let mut payload = serde_json::Map::new();
        if !request.set.is_empty() {
            payload.insert("set".to_owned(), request.set.clone().into());
        }
        if !request.resume.is_empty() {
            payload.insert("resume".to_owned(), request.resume.clone().into());
        }
        if !request.rollback.is_empty() {
            payload.insert("rollback".to_owned(), request.rollback.clone().into());
        }
        if !request.abandon.is_empty() {
            payload.insert("abandon".to_owned(), request.abandon.clone().into());
        }
        let mut conn = dial(&self.socket_path, super::server::MAINTENANCE_APPLY_BUDGET)?;
        let msg = Request {
            operation_id: operation_id.to_owned(),
            verb: verb::MAINTENANCE_APPLY.to_owned(),
            payload: serde_json::value::RawValue::from_string(
                serde_json::Value::Object(payload).to_string(),
            )
            .ok(),
        };
        write_request(&mut conn, &msg).map_err(|_| new_maintenance_apply_client_error(3, ""))?;
        let response =
            read_response(&mut conn).map_err(|_| new_maintenance_apply_client_error(3, ""))?;
        let raw = response
            .result
            .as_ref()
            .map_or(&b""[..], |r| r.get().as_bytes());
        if response.outcome != "success" || response.exit_code != 0 {
            let mut err = new_maintenance_apply_client_error(response.exit_code, &response.reason);
            // A denied apply still carries the attempt identity and
            // gate detail — decode them so the CLI can echo them.
            if !raw.is_empty()
                && let Ok(denied) = decode_exact::<MaintenanceApplyResult>(raw, "maintenance apply")
            {
                err.result = Some(Box::new(denied));
            }
            return Err(err);
        }
        if raw.is_empty() {
            return Err(new_maintenance_apply_client_error(6, ""));
        }
        let result: MaintenanceApplyResult = decode_exact(raw, "maintenance apply")
            .map_err(|_| new_maintenance_apply_client_error(6, ""))?;
        if result.operation_id != operation_id
            || result.completed_at.is_empty()
            || result.attempt_id.is_empty()
        {
            return Err(new_maintenance_apply_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        Ok(result)
    }
}
