//! Narrow capability ports the transport layers consume — the Rust
//! port of upstream's `middleware.CSRFService`, `middleware.SessionService`,
//! and `web.SessionService` seams.
//!
//! Each trait is satisfied by `central_session::app::Service<S, B>` for
//! any `S: SessionStore`, `B: ProtectedBootstrap`, mirroring upstream's
//! composition adapters (`bufferedSessionAdapter`, `csrfSessionAdapter`)
//! without the transport depending on a concrete store. The kernel wires
//! the concrete `Service` in Task 13; tests use in-memory fakes.

use std::future::Future;
use std::pin::Pin;

use central_foundation::failure::Failure as DomainFailure;
use central_foundation::identity::{RunId, SessionId, TaskId, WorkspaceId};
use central_session::app::Service;
use central_session::contract::{Failure, PreAuthCSRF};
use central_session::domain::{
    ActivationRequest, DeliveryRequest, DeliveryResult, ExchangeRequest, ExchangeResult, Session,
    ValidationRequest,
};
use central_session::port::{ProtectedBootstrap, SessionStore};

/// A `Send` boxed future — the dyn-compatible async shape used by every
/// `/app` port below (same pattern as `central_artifact::port::ByteStreamFuture`).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// `CSRFService` — the pre-auth CSRF seam the [`crate::middleware::preauth`]
/// layer needs: mint a fresh pair on safe routes, validate a presented
/// pair on the bootstrap-exchange route.
pub trait PreAuthCsrf: Send + Sync + 'static {
    /// `IssuePreAuthCSRF` — infallible in the Rust port (`rand::random`
    /// cannot fail where upstream's `crypto/rand.Read` could).
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF;

    /// `ValidatePreAuthCSRF` — rejects a zero, mismatched, or replayed
    /// pair; a `Failure` here means the request is rejected before any
    /// mutation.
    fn validate_pre_auth_csrf(&self, pair: &PreAuthCSRF) -> Result<(), Failure>;
}

impl<S, B> PreAuthCsrf for Service<S, B>
where
    S: SessionStore,
    B: ProtectedBootstrap,
{
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        Service::issue_pre_auth_csrf(self)
    }

    fn validate_pre_auth_csrf(&self, pair: &PreAuthCSRF) -> Result<(), Failure> {
        Service::validate_pre_auth_csrf(self, pair)
    }
}

/// `SessionService` — the buffered precommit seam (upstream
/// `bufferedSessionAdapter`): the buffered layer calls
/// `activate_delivery` exactly once per request immediately before
/// flushing a successful response, and `revoke` on post-activation
/// failure. Upstream maps `Revoke` onto `Service::Logout`.
#[trait_variant::make(Send)]
pub trait DeliveryPrecommit: Send + Sync + 'static {
    /// `ActivateDelivery` — atomically transitions the `delivery_pending`
    /// session to `active`, persisting the freshly minted hashes.
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure>;

    /// `Revoke` — upstream's `svc.Revoke` → `Service::Logout` mapping.
    async fn revoke(&self, id: SessionId) -> Result<(), Failure>;
}

impl<S, B> DeliveryPrecommit for Service<S, B>
where
    S: SessionStore,
    B: ProtectedBootstrap,
{
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
        Service::activate_delivery(self, req).await
    }

    async fn revoke(&self, id: SessionId) -> Result<(), Failure> {
        Service::logout(self, id).await
    }
}

/// `SessionService` — the request-time session-validation seam
/// (upstream `web.Handler.sessions.Validate`).
#[trait_variant::make(Send)]
pub trait SessionValidator: Send + Sync + 'static {
    /// `Validate` — token-hash comparison, epoch assertion, expiry
    /// check. `presented_csrf_hash` carries the session-CSRF comparison
    /// for mutation routes.
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure>;
}

impl<S, B> SessionValidator for Service<S, B>
where
    S: SessionStore,
    B: ProtectedBootstrap,
{
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
        Service::validate(self, req).await
    }
}

// ---------------------------------------------------------------------------
// Task 12 — the application-surface seams (upstream `web.Config`'s ports).
// ---------------------------------------------------------------------------

/// `web.SessionService` — the broader session surface the `/app` and
/// `/api/v1/session` handlers consume: session validation (GET pages
/// authenticate themselves so an anonymous request renders the bootstrap
/// shell rather than a redirect), logout revocation, the atomic bootstrap
/// exchange, and delivery preparation.
pub trait SessionService: Send + Sync + 'static {
    /// `IssuePreAuthCSRF` — mints a fresh double-submit pair (logout
    /// recovery needs a fresh cookie even though the preauth middleware
    /// already issues one on safe routes).
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF;

    /// `Validate` — identical to [`SessionValidator::validate`].
    fn validate(&self, req: ValidationRequest) -> BoxFuture<'_, Result<Session, Failure>>;

    /// `Logout` — revokes the session server-side.
    fn logout(&self, id: SessionId) -> BoxFuture<'_, Result<(), Failure>>;

    /// `ExchangeBootstrap` — the atomic single-use token exchange; the
    /// transport must have already validated the pre-auth CSRF pair.
    fn exchange_bootstrap(
        &self,
        req: ExchangeRequest,
    ) -> BoxFuture<'_, Result<ExchangeResult, Failure>>;

    /// `PrepareDelivery` — records `delivery_pending` for the exchanged
    /// session and arms the buffered precommit slot.
    fn prepare_delivery(
        &self,
        req: DeliveryRequest,
    ) -> BoxFuture<'_, Result<DeliveryResult, Failure>>;
}

impl<S, B> SessionService for Service<S, B>
where
    S: SessionStore + Send + Sync,
    B: ProtectedBootstrap + Send + Sync,
{
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        Service::issue_pre_auth_csrf(self)
    }

    fn validate(&self, req: ValidationRequest) -> BoxFuture<'_, Result<Session, Failure>> {
        Box::pin(async move { Service::validate(self, req).await })
    }

    fn logout(&self, id: SessionId) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move { Service::logout(self, id).await })
    }

    fn exchange_bootstrap(
        &self,
        req: ExchangeRequest,
    ) -> BoxFuture<'_, Result<ExchangeResult, Failure>> {
        Box::pin(async move { Service::exchange_bootstrap(self, req).await })
    }

    fn prepare_delivery(
        &self,
        req: DeliveryRequest,
    ) -> BoxFuture<'_, Result<DeliveryResult, Failure>> {
        Box::pin(async move { Service::prepare_delivery(self, req).await })
    }
}

/// `web.TaskService` — the task reads and mutations the `/app` handlers
/// consume. Like upstream, no `central_task::app::TaskService` blanket impl
/// exists: `load_aggregate` lives on the store port, not the app service,
/// so the composition root wires a small adapter over both (Task 13).
pub trait TaskService: Send + Sync + 'static {
    /// `ListTasks` — one bounded page of workspace task summaries.
    fn list_tasks(
        &self,
        req: central_task::query::TaskListRequest,
    ) -> BoxFuture<'_, Result<central_task::query::TaskListProjection, DomainFailure>>;

    /// `TaskDetail` — one bounded detail projection; `NotFound` for a
    /// missing or cross-workspace task.
    fn task_detail(
        &self,
        req: central_task::query::TaskDetailRequest,
    ) -> BoxFuture<'_, Result<central_task::query::TaskDetailProjection, DomainFailure>>;

    /// `ListTaskEvents` — bounded newest-first lifecycle events.
    fn list_task_events(
        &self,
        req: central_task::query::TaskEventLogRequest,
    ) -> BoxFuture<'_, Result<central_task::query::TaskEventLogProjection, DomainFailure>>;

    /// `SubmitTask`.
    fn submit_task(
        &self,
        req: central_task::domain::SubmitTaskRequest,
        meta: central_task::app::CommandMeta,
    ) -> BoxFuture<'_, Result<central_task::domain::CommitResult, DomainFailure>>;

    /// `RequestCancellation`.
    fn request_cancellation(
        &self,
        req: central_task::domain::RequestCancellationRequest,
        meta: central_task::app::CommandMeta,
    ) -> BoxFuture<'_, Result<central_task::domain::CommitResult, DomainFailure>>;

    /// `CancelUnclaimedTask` — ends a never-claimed task cancelled in one
    /// commit (harness phase 3e decisions 2 and 3).
    fn cancel_unclaimed_task(
        &self,
        req: central_task::domain::CancelUnclaimedTaskRequest,
        meta: central_task::app::CommandMeta,
    ) -> BoxFuture<'_, Result<central_task::domain::CommitResult, DomainFailure>>;

    /// `RetryFailedTask`.
    fn retry_failed_task(
        &self,
        req: central_task::domain::RetryFailedTaskRequest,
        meta: central_task::app::CommandMeta,
    ) -> BoxFuture<'_, Result<central_task::domain::CommitResult, DomainFailure>>;

    /// `RerunCancelledTask` — creates a new Task with lineage.
    fn rerun_cancelled_task(
        &self,
        req: central_task::domain::RerunCancelledTaskRequest,
        meta: central_task::app::CommandMeta,
    ) -> BoxFuture<'_, Result<central_task::domain::CommitResult, DomainFailure>>;

    /// `LoadAggregate` — the durable aggregate plus the optimistic-lock
    /// versions every mutation echoes back.
    fn load_aggregate(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'_, Result<central_task::port::LoadedAggregate, DomainFailure>>;
}

/// `web.ArtifactDeliveryService` — the ready-artifact delivery guard the
/// preview/download routes re-validate on every request. Satisfied by
/// `central_artifact::app::Service` — kept as a trait so the kernel adapter
/// and test fakes share one shape.
pub trait ArtifactDelivery: Send + Sync + 'static {
    /// `DeliverReadyArtifact` — durable guard evaluation plus an opened
    /// body stream on `Allowed`.
    fn deliver_ready_artifact(
        &self,
        request: central_artifact::app::DeliverReadyArtifactRequest,
    ) -> BoxFuture<'_, Result<central_artifact::app::DeliverArtifactOutcome, DomainFailure>>;
}

/// `web.RecoveryClaimabilityReader` — the durable restart-barrier gate
/// every mutation route consults before mutating (and the detail page
/// renders). Wired to the same execution capability instance the read
/// path decorates with, so the two can never drift.
pub trait RecoveryClaimability: Send + Sync + 'static {
    /// `RecoveryClaimability` — whether `run_id` is claimable in the
    /// current recovery epoch; any error must fail the caller closed.
    fn recovery_claimability(
        &self,
        scope: central_execution::domain::TrustedScope,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_execution::domain::Claimability, DomainFailure>>;
}

impl<T> RecoveryClaimability for T
where
    T: central_execution::port::RecoveryClaimabilityReader + Send + Sync + 'static,
{
    fn recovery_claimability(
        &self,
        scope: central_execution::domain::TrustedScope,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_execution::domain::Claimability, DomainFailure>> {
        Box::pin(async move {
            central_execution::port::RecoveryClaimabilityReader::recovery_claimability(
                self, scope, task_id, run_id,
            )
            .await
        })
    }
}

/// `web.RunSubmitter` — the OPTIONAL run-submission write port
/// `ServeRunSubmit` consumes (issue #122); the runsubmit
/// [`central_runsubmit::app::Service`] satisfies it directly. Like
/// upstream's `RunControlPorts.Submitter` it is nil-tolerant: an
/// unwired port hides the runs-list form and answers the POST the same
/// bare 503 as an unwired read port.
pub trait RunSubmitter: Send + Sync + 'static {
    /// `Submit` — one Phase-2 run (leader + flat workers) in the
    /// session workspace through the shared saga.
    fn submit(
        &self,
        req: central_runsubmit::domain::SubmitRequest,
    ) -> BoxFuture<'_, Result<central_runsubmit::domain::SubmitResult, DomainFailure>>;
}

impl<T, L, R, G> RunSubmitter for central_runsubmit::app::Service<T, L, R, G>
where
    T: central_runsubmit::app::TaskCommands,
    L: central_task::port::AggregateLoader,
    R: central_task::port::RunByKeyReader,
    G: central_runsubmit::app::GraphStore,
{
    fn submit(
        &self,
        req: central_runsubmit::domain::SubmitRequest,
    ) -> BoxFuture<'_, Result<central_runsubmit::domain::SubmitResult, DomainFailure>> {
        Box::pin(async move { central_runsubmit::app::Service::submit(self, req).await })
    }
}

/// `execquery.RunTurnActivityRead` — the OPTIONAL per-run provider-turn
/// timeline the detail page renders when wired (ADR 0021). A composition
/// without it simply omits the section.
pub trait RunTurnActivityRead: Send + Sync + 'static {
    /// `Read` — one bounded page of attempt activity, oldest first.
    fn read(
        &self,
        req: central_execution::query::RunTurnActivityRequest,
    ) -> BoxFuture<'_, Result<central_execution::query::RunTurnActivityResult, DomainFailure>>;
}
