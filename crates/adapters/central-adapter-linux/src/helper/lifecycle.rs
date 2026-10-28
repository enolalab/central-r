//! `production_lifecycle.go` — the lifecycle handler seam and the
//! production handler that binds fresh PAM + broker one-use
//! authorization to the exact request and peer.

use super::protocol::*;
use super::{LifecycleAuthorization, LifecycleAuthorizationRequest, PeerIdentity};
use central_foundation::failure::Failure;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// `lifecycleOperationDeadline` — the B03 policy, not a convenience
/// timeout.
pub fn lifecycle_operation_deadline(verb: &str) -> Duration {
    match verb {
        "up" => Duration::from_secs(400),
        "down" => Duration::from_secs(90),
        "status" => Duration::from_secs(3),
        _ => Duration::ZERO,
    }
}

/// The resolved lifecycle operation the service runs —
/// `infralifecycle.Request`'s helper-visible fields: the instance and
/// config bindings plus the active receipt's identity and digests the
/// resolver reads fresh per request (upstream's `resolve` fills
/// `ReceiptID`, `ModelDigest`, and `PayloadEpoch` from
/// `receipts.Active`).
#[derive(Debug, Clone, Default)]
pub struct LifecycleOperation {
    pub instance_id: String,
    pub config_binding: String,
    pub receipt_id: String,
    pub model_digest: String,
    pub payload_epoch: String,
}

/// The service's result — `infralifecycle.Result` as the wire consumes
/// it. The helper serializes, it never fabricates.
#[derive(Debug, Clone, Default)]
pub struct LifecycleServiceResult {
    pub operation_id: String,
    pub phase: String,
    pub state: String,
    pub reason: String,
    pub receipt_id: String,
    pub safe_next_action: String,
    pub exit_code: i64,
}

/// `lifecycleApplication` — the injected service seam.
pub trait LifecycleApplication: Send + Sync {
    fn up(&self, deadline: Instant, operation: LifecycleOperation) -> LifecycleServiceResult;
    fn down(&self, deadline: Instant, operation: LifecycleOperation) -> LifecycleServiceResult;
    fn status(&self, deadline: Instant, operation: LifecycleOperation) -> LifecycleServiceResult;
}

/// `LifecycleRequestResolver` — resolves the helper's fixed binding;
/// implementations must not accept topology from the request.
pub trait LifecycleRequestResolver: Send + Sync {
    fn resolve(&self, request: &LifecycleRequest) -> Result<LifecycleOperation, Failure>;
}

/// `LifecycleAuthorizer` — the broker authorization seam.
pub trait LifecycleAuthorizer: Send + Sync {
    fn authorize_bound_lifecycle(
        &self,
        request: &LifecycleAuthorizationRequest,
    ) -> Result<LifecycleAuthorization, Failure>;
    fn consume_bound_lifecycle_authorization(
        &self,
        claim: &LifecycleAuthorization,
        request: &LifecycleAuthorizationRequest,
    ) -> Result<(), Failure>;
}

/// The PAM capability `HandleLifecycle` needs — upstream's
/// `PAMConfirmer` narrowed to Confirm/VerifyAndConsume.
pub trait LifecycleConfirmer: Send + Sync {
    fn confirm(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
    ) -> Result<String, Failure>;
    fn verify_and_consume(&self, token: &str) -> bool;
}

/// `LifecycleHandler` — the transport seam.
pub trait LifecycleHandler: Send + Sync {
    fn handle_lifecycle(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        req: &Request,
        lifecycle: LifecycleRequest,
    ) -> Response;
}

/// `ProductionLifecycleHandler`.
pub struct ProductionLifecycleHandler {
    service: Box<dyn LifecycleApplication>,
    resolver: Box<dyn LifecycleRequestResolver>,
    authorizer: Option<Box<dyn LifecycleAuthorizer>>,
    pam: Option<Box<dyn LifecycleConfirmer>>,
}

impl ProductionLifecycleHandler {
    /// `NewProductionLifecycleHandler` — service + resolver only; up and
    /// down then answer LIFECYCLE_AUTHORIZATION_REQUIRED.
    pub fn new(
        service: Box<dyn LifecycleApplication>,
        resolver: Box<dyn LifecycleRequestResolver>,
    ) -> Self {
        ProductionLifecycleHandler {
            service,
            resolver,
            authorizer: None,
            pam: None,
        }
    }

    /// `NewAuthorizedProductionLifecycleHandler` — the only form that may
    /// run the production service for mutating verbs.
    pub fn new_authorized(
        service: Box<dyn LifecycleApplication>,
        resolver: Box<dyn LifecycleRequestResolver>,
        authorizer: Box<dyn LifecycleAuthorizer>,
        pam: Box<dyn LifecycleConfirmer>,
    ) -> Self {
        ProductionLifecycleHandler {
            service,
            resolver,
            authorizer: Some(authorizer),
            pam: Some(pam),
        }
    }
}

impl LifecycleHandler for ProductionLifecycleHandler {
    /// `HandleLifecycle` — verbatim reason vocabulary and ordering.
    fn handle_lifecycle(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        req: &Request,
        lifecycle: LifecycleRequest,
    ) -> Response {
        let operation = match self.resolver.resolve(&lifecycle) {
            Ok(o) => o,
            Err(_) => return Response::denied(&req.operation_id, 5, "LIFECYCLE_BINDING_INVALID"),
        };
        if req.verb == "up" || req.verb == "down" {
            let (Some(authorizer), Some(pam)) = (&self.authorizer, &self.pam) else {
                return Response::denied(&req.operation_id, 7, "LIFECYCLE_AUTHORIZATION_REQUIRED");
            };
            if !peer.available() {
                return Response::denied(&req.operation_id, 7, "LIFECYCLE_PEER_UNAVAILABLE");
            }
            let request =
                lifecycle_authorization_request(req, &lifecycle, &operation.instance_id, peer);
            let confirmation = match pam.confirm(peer, Some(deadline), &req.operation_id) {
                Ok(token) => token,
                Err(_) => return Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED"),
            };
            if !pam.verify_and_consume(&confirmation) {
                return Response::denied(&req.operation_id, 7, "AUTHORITY_DENIED");
            }
            let claim = match authorizer.authorize_bound_lifecycle(&request) {
                Ok(c) => c,
                Err(_) => {
                    return Response::denied(
                        &req.operation_id,
                        7,
                        "LIFECYCLE_AUTHORIZATION_DENIED",
                    );
                }
            };
            if authorizer
                .consume_bound_lifecycle_authorization(&claim, &request)
                .is_err()
            {
                return Response::denied(&req.operation_id, 7, "LIFECYCLE_AUTHORIZATION_REJECTED");
            }
        }
        let result = match req.verb.as_str() {
            "up" => self.service.up(deadline, operation.clone()),
            "down" => self.service.down(deadline, operation.clone()),
            "status" => self.service.status(deadline, operation.clone()),
            _ => return Response::denied(&req.operation_id, 5, "UNSUPPORTED_IN_THIS_SLICE"),
        };
        let details = LifecycleResultDetails {
            operation_id: result.operation_id.clone(),
            phase: result.phase.clone(),
            state: result.state.clone(),
            reason_code: lifecycle_reason_code(&result.reason),
            receipt_id: result.receipt_id.clone(),
            safe_next_action: result.safe_next_action.clone(),
        };
        if result.exit_code != 0 {
            return Response::denied(&req.operation_id, result.exit_code, &result.reason)
                .with_result(&details);
        }
        Response::new(&req.operation_id, "success", 0, &result.state).with_result(&details)
    }
}

/// `lifecycleAuthorizationRequest` — digest binds operation, request
/// bytes and peer.
pub fn lifecycle_authorization_request(
    req: &Request,
    lifecycle: &LifecycleRequest,
    instance_id: &str,
    peer: PeerIdentity,
) -> LifecycleAuthorizationRequest {
    #[derive(serde::Serialize)]
    struct DigestSource<'a> {
        operation_id: &'a str,
        verb: &'a str,
        config_binding: &'a str,
    }
    // Upstream ignores this marshal error: a three-string struct cannot
    // fail to encode, and the digest's bytes are whatever was produced.
    let payload = serde_json::to_vec(&DigestSource {
        operation_id: &req.operation_id,
        verb: &req.verb,
        config_binding: &lifecycle.config_binding,
    })
    .unwrap_or_default();
    let digest = Sha256::digest(&payload);
    LifecycleAuthorizationRequest {
        instance_id: instance_id.to_owned(),
        operation: req.verb.clone(),
        request_digest: format!(
            "sha256:{}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        peer_uid: peer.uid,
        peer_pid: peer.pid,
    }
}

/// `lifecycleReasonCode` — reduce `CODE: detail` to the code; a reason
/// that is not a code contributes nothing.
pub fn lifecycle_reason_code(reason: &str) -> String {
    let code = reason.split(':').next().unwrap_or("").trim();
    if code
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        code.to_owned()
    } else {
        String::new()
    }
}
