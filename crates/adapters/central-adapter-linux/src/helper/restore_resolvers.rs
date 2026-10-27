//! `cmd/central/restore_resolvers.go` — the composition-root seam that
//! turns the three operation-shaped helper verbs from "act on the
//! operation the caller named" into "act on the single operation
//! protected state says is live".
//!
//! The restore CLI's grammar is zero-argument by design: `central
//! restore apply` takes no ticket, no operation identity, and no path,
//! and opaque UUIDv7 identities stay out of operator hands. Something
//! must therefore decide *which* protected operation a verb acts on,
//! and this module is that decision.
//!
//! The rule, decided 2026-08-14, is: resolve the single candidate, and
//! refuse to guess. When exactly one candidate matches, the verb
//! proceeds against it. When none matches, the verb refuses. When more
//! than one matches, the verb refuses and does NOT choose — never the
//! newest, never the first, never the most likely.
//!
//! The resolution runs on the privileged side, inside the root helper.
//! It has to: the unprivileged CLI process cannot read protected broker
//! state, and a resolver the operator could influence would defeat the
//! point of resolving at all. The transport identity the CLI sent is
//! discarded for selection and restored on the response, so the
//! client's strict request/response binding still holds while the
//! protected identity it acted on travels in the result body.

use std::time::Instant;

use central_backup::recovery::operation::RestoreOperation;
use central_foundation::failure::Failure;
use uuid::Uuid;

use super::PeerIdentity;
use super::protocol::Response;
use super::restore::{
    RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS, RESTORE_REFUSAL_NO_LIVE_OPERATION,
    RestoreAbandonHandler, RestoreAbandonRequest, RestoreApplyHandler, RestoreApplyRequest,
    RestoreResumeHandler, RestoreResumeRequest,
};

/// `errRestoreLiveOperationAbsent` — an operator who has nothing to
/// abandon gets a different answer than one whose host carries two
/// live restores; the two are separate sentinels, not one "resolution
/// failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverRefusal {
    /// `errRestoreLiveOperationAbsent` →
    /// [`RESTORE_REFUSAL_NO_LIVE_OPERATION`].
    NoLiveOperation,
    /// `errRestoreLiveOperationAmbiguous` →
    /// [`RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS`]. Never resolved by
    /// picking.
    AmbiguousLiveOperation,
}

/// The resolution error: a refusal sentinel, or a generic failure that
/// collapses to `AUTHORITY_DENIED` — an unexpected failure can never
/// be reported to an operator as "there is nothing to restore"
/// (upstream's `restoreResolverRefusal` default arm).
enum ResolveError {
    Refusal(ResolverRefusal),
    /// Any non-sentinel failure (broker down, protected root
    /// unreadable) — collapsed to `AUTHORITY_DENIED`, so the error
    /// payload itself is deliberately not carried across.
    Failed,
}

/// `restoreLiveOperationSource` enumerates every non-terminal
/// protected restore operation. It returns a slice rather than an
/// at-most-one value on purpose: the resolver below owns the
/// cardinality decision, and a source that made that decision for it
/// would be a second place where "which one?" is answered.
pub trait RestoreLiveOperationSource: Send + Sync {
    /// `LiveRestoreOperations`.
    fn live_restore_operations(&self, deadline: Instant) -> Result<Vec<RestoreOperation>, Failure>;
}

/// `restoreLiveTicketSource` enumerates every operation ID with a
/// currently valid, unconsumed restore ticket. SC-DEF-59: this is
/// apply's own resolution source, distinct from
/// [`RestoreLiveOperationSource`] — apply's whole job is to consume a
/// *fresh* ticket for the first time, before any operation record
/// exists, so it cannot resolve against "the operation the barrier
/// already reports live" the way resume and abandon correctly do.
pub trait RestoreLiveTicketSource: Send + Sync {
    /// `LiveRestoreTicketOperationIDs`.
    fn live_restore_ticket_operation_ids(&self, deadline: Instant) -> Result<Vec<Uuid>, Failure>;
}

/// `resolveSingleLiveRestoreOperation` — the whole rule, as a pure
/// function over the candidate set so it is directly testable without
/// a broker.
fn resolve_single_live_restore_operation(
    source: Option<&dyn RestoreLiveOperationSource>,
    deadline: Instant,
) -> Result<RestoreOperation, ResolveError> {
    let Some(source) = source else {
        return Err(ResolveError::Refusal(ResolverRefusal::NoLiveOperation));
    };
    let candidates = source
        .live_restore_operations(deadline)
        .map_err(|_| ResolveError::Failed)?;
    match candidates.as_slice() {
        [] => Err(ResolveError::Refusal(ResolverRefusal::NoLiveOperation)),
        [operation] => {
            if operation.validate().is_err() || operation.is_terminal() {
                // A terminal or malformed record is not a live
                // operation. It is refused as absent rather than acted
                // on: abandoning something already abandoned, or
                // applying to a record whose invariants do not hold,
                // are both worse than answering "there is nothing
                // here".
                return Err(ResolveError::Refusal(ResolverRefusal::NoLiveOperation));
            }
            Ok(operation.clone())
        }
        _ => Err(ResolveError::Refusal(
            ResolverRefusal::AmbiguousLiveOperation,
        )),
    }
}

/// `resolveSingleLiveRestoreTicketOperation` — mirrors
/// [`resolve_single_live_restore_operation`]'s cardinality rule
/// exactly, over ticket operation IDs instead of operation records:
/// zero is absent, more than one is ambiguous, and a resolved identity
/// must still be a well-formed UUIDv7 before it is trusted.
fn resolve_single_live_restore_ticket_operation(
    source: Option<&dyn RestoreLiveTicketSource>,
    deadline: Instant,
) -> Result<Uuid, ResolveError> {
    let Some(source) = source else {
        return Err(ResolveError::Refusal(ResolverRefusal::NoLiveOperation));
    };
    let candidates = source
        .live_restore_ticket_operation_ids(deadline)
        .map_err(|_| ResolveError::Failed)?;
    match candidates.as_slice() {
        [] => Err(ResolveError::Refusal(ResolverRefusal::NoLiveOperation)),
        [operation_id] => {
            if operation_id.is_nil() || operation_id.get_version_num() != 7 {
                return Err(ResolveError::Refusal(ResolverRefusal::NoLiveOperation));
            }
            Ok(*operation_id)
        }
        _ => Err(ResolveError::Refusal(
            ResolverRefusal::AmbiguousLiveOperation,
        )),
    }
}

/// `restoreResolverRefusal` maps a resolver sentinel onto the helper
/// response the operator's client will see. Anything that is not one
/// of the two sentinels — a broker that is down, a protected root that
/// cannot be read — collapses to the generic denial, so an unexpected
/// failure can never be reported to an operator as "there is nothing
/// to restore".
fn restore_resolver_refusal(operation_id: &str, err: &ResolveError) -> Response {
    match err {
        ResolveError::Refusal(ResolverRefusal::NoLiveOperation) => {
            Response::new(operation_id, "denied", 6, RESTORE_REFUSAL_NO_LIVE_OPERATION)
        }
        ResolveError::Refusal(ResolverRefusal::AmbiguousLiveOperation) => Response::new(
            operation_id,
            "denied",
            6,
            RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS,
        ),
        ResolveError::Failed => Response::new(operation_id, "denied", 7, "AUTHORITY_DENIED"),
    }
}

/// `restoreTransportBinding` puts the caller's transport identity back
/// on the response envelope. The inner handler stamps the resolved
/// protected identity there, which would break the client's
/// request/response binding check for no benefit: the resolved
/// identity is already in the result body, which is where it belongs
/// as a report rather than as a selector.
fn restore_transport_binding(transport_id: &str, mut response: Response) -> Response {
    response.operation_id = transport_id.to_owned();
    response
}

/// `brokerRestoreBarrierOperations` is the production source. The
/// broker's restore barrier is the protected record of which restore
/// currently occupies the host, and it is the only authority on that
/// question.
///
/// It reports at most one operation today, because
/// `inspectRestoreBarrierLocked` enforces single-occupancy one layer
/// down and refuses before answering when it finds a second
/// non-terminal record. The resolver's ambiguity branch above is
/// therefore defence in depth rather than the branch this source
/// exercises: it exists so that the cardinality rule lives with the
/// verb the operator runs, and so a future source that can genuinely
/// see several candidates cannot silently start choosing.
pub(crate) struct BrokerRestoreBarrierOperations {
    client: std::sync::Arc<crate::broker::restore_barrier::RestoreBarrierClient>,
}

impl BrokerRestoreBarrierOperations {
    pub(crate) fn new(
        client: std::sync::Arc<crate::broker::restore_barrier::RestoreBarrierClient>,
    ) -> Self {
        Self { client }
    }
}

impl RestoreLiveOperationSource for BrokerRestoreBarrierOperations {
    fn live_restore_operations(&self, deadline: Instant) -> Result<Vec<RestoreOperation>, Failure> {
        Ok(self
            .client
            .inspect_restore_barrier(deadline)?
            .into_iter()
            .collect())
    }
}

/// `brokerRestoreTicketOperations` is the production source, backed
/// by the same broker socket restore barrier inspection already uses.
pub(crate) struct BrokerRestoreTicketOperations {
    client: std::sync::Arc<crate::broker::restore_barrier::RestoreBarrierClient>,
}

impl BrokerRestoreTicketOperations {
    pub(crate) fn new(
        client: std::sync::Arc<crate::broker::restore_barrier::RestoreBarrierClient>,
    ) -> Self {
        Self { client }
    }
}

impl RestoreLiveTicketSource for BrokerRestoreTicketOperations {
    fn live_restore_ticket_operation_ids(&self, deadline: Instant) -> Result<Vec<Uuid>, Failure> {
        self.client.issued_ticket_operation_ids(deadline)
    }
}

/// `resolvingRestoreOperationHandler` — the composition-root seam.
/// One value backs all three verbs, upstream-fashion; `source`
/// resolves resume and abandon (the live barrier occupant), while
/// `ticket_source` resolves apply and only apply (SC-DEF-59 — apply
/// consumes a fresh ticket *before* the barrier reports anything
/// live). Nothing the caller sent can influence which operation is
/// chosen.
pub struct ResolvingRestoreOperationHandler {
    /// Resolves resume and abandon: the single operation the broker's
    /// restore barrier already reports live.
    source: Option<Box<dyn RestoreLiveOperationSource>>,
    /// Resolves apply, and only apply: the issued-ticket barrier.
    ticket_source: Option<Box<dyn RestoreLiveTicketSource>>,
    apply: Option<Box<dyn RestoreApplyHandler>>,
    resume: Option<Box<dyn RestoreResumeHandler>>,
    abandon: Option<Box<dyn RestoreAbandonHandler>>,
}

impl ResolvingRestoreOperationHandler {
    /// The production composition — every slot named, like upstream's
    /// struct literal; `None` on a verb slot degrades that verb to its
    /// `*_AUTHORIZATION_UNAVAILABLE` deferral exactly as a nil inner
    /// handler does upstream.
    pub fn new(
        source: Option<Box<dyn RestoreLiveOperationSource>>,
        ticket_source: Option<Box<dyn RestoreLiveTicketSource>>,
        apply: Option<Box<dyn RestoreApplyHandler>>,
        resume: Option<Box<dyn RestoreResumeHandler>>,
        abandon: Option<Box<dyn RestoreAbandonHandler>>,
    ) -> Self {
        Self {
            source,
            ticket_source,
            apply,
            resume,
            abandon,
        }
    }

    fn resolve(&self, deadline: Instant, transport_id: &str) -> Result<String, Response> {
        resolve_single_live_restore_operation(self.source.as_deref(), deadline)
            .map(|operation| operation.operation_id.to_string())
            .map_err(|err| restore_resolver_refusal(transport_id, &err))
    }

    fn resolve_ticket(&self, deadline: Instant, transport_id: &str) -> Result<String, Response> {
        resolve_single_live_restore_ticket_operation(self.ticket_source.as_deref(), deadline)
            .map(|operation_id| operation_id.to_string())
            .map_err(|err| restore_resolver_refusal(transport_id, &err))
    }
}

impl RestoreApplyHandler for ResolvingRestoreOperationHandler {
    /// `AuthorizeRestoreApply`.
    fn authorize_restore_apply(
        &self,
        deadline: Instant,
        request: RestoreApplyRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Some(apply) = &self.apply else {
            return Response::new(
                &request.operation_id,
                "deferred",
                5,
                "RESTORE_APPLY_AUTHORIZATION_UNAVAILABLE",
            );
        };
        let resolved = match self.resolve_ticket(deadline, &request.operation_id) {
            Ok(resolved) => resolved,
            Err(refusal) => return refusal,
        };
        restore_transport_binding(
            &request.operation_id,
            apply.authorize_restore_apply(
                deadline,
                RestoreApplyRequest {
                    operation_id: resolved,
                },
                peer,
            ),
        )
    }
}

impl RestoreResumeHandler for ResolvingRestoreOperationHandler {
    /// `AuthorizeRestoreResume`.
    fn authorize_restore_resume(
        &self,
        deadline: Instant,
        request: RestoreResumeRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Some(resume) = &self.resume else {
            return Response::new(
                &request.operation_id,
                "deferred",
                5,
                "RESTORE_RESUME_AUTHORIZATION_UNAVAILABLE",
            );
        };
        let resolved = match self.resolve(deadline, &request.operation_id) {
            Ok(resolved) => resolved,
            Err(refusal) => return refusal,
        };
        restore_transport_binding(
            &request.operation_id,
            resume.authorize_restore_resume(
                deadline,
                RestoreResumeRequest {
                    operation_id: resolved,
                },
                peer,
            ),
        )
    }
}

impl RestoreAbandonHandler for ResolvingRestoreOperationHandler {
    /// `AuthorizeRestoreAbandon`.
    fn authorize_restore_abandon(
        &self,
        deadline: Instant,
        request: RestoreAbandonRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Some(abandon) = &self.abandon else {
            return Response::new(
                &request.operation_id,
                "deferred",
                5,
                "RESTORE_ABANDON_AUTHORIZATION_UNAVAILABLE",
            );
        };
        let resolved = match self.resolve(deadline, &request.operation_id) {
            Ok(resolved) => resolved,
            Err(refusal) => return refusal,
        };
        restore_transport_binding(
            &request.operation_id,
            abandon.authorize_restore_abandon(
                deadline,
                RestoreAbandonRequest {
                    operation_id: resolved,
                },
                peer,
            ),
        )
    }
}

/// `Arc` handles on the one [`ResolvingRestoreOperationHandler`]
/// satisfy all three handler ports: upstream's `newHelperServer`
/// installs the same `resolvingRestoreOperationHandler` as `apply`,
/// `resume`, and `abandon`, and the helper `Server`'s three
/// `Box<dyn>` fields are the Rust shape of that sharing — the `Arc`
/// clones are the sharing, exactly like
/// [`super::restore::RestoreApplyAuthorizationHandler`]'s pair.
impl RestoreApplyHandler for std::sync::Arc<ResolvingRestoreOperationHandler> {
    fn authorize_restore_apply(
        &self,
        deadline: Instant,
        request: RestoreApplyRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.as_ref()
            .authorize_restore_apply(deadline, request, peer)
    }
}

/// See [`RestoreApplyHandler`]'s `Arc` impl — one handler, three
/// verbs.
impl RestoreResumeHandler for std::sync::Arc<ResolvingRestoreOperationHandler> {
    fn authorize_restore_resume(
        &self,
        deadline: Instant,
        request: RestoreResumeRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.as_ref()
            .authorize_restore_resume(deadline, request, peer)
    }
}

/// See [`RestoreApplyHandler`]'s `Arc` impl — one handler, three
/// verbs.
impl RestoreAbandonHandler for std::sync::Arc<ResolvingRestoreOperationHandler> {
    fn authorize_restore_abandon(
        &self,
        deadline: Instant,
        request: RestoreAbandonRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.as_ref()
            .authorize_restore_abandon(deadline, request, peer)
    }
}
