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
use std::sync::Arc;

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

// ---------------------------------------------------------------------------
// Task 11 — the runview read projections and the run-control write
// ports (upstream `web.RunsReader`/`FleetReader`/`RunLineageReader`/
// `RunControlPorts`, issue #96 slice 2E). Every trait is satisfied by
// the PostgreSQL runview store (plus the artifact lineage store for the
// lineage composite) — `BoxFuture` keeps them dyn-compatible under
// `Arc<dyn ...>` while the capability seam stays `trait_variant` async.
// ---------------------------------------------------------------------------

/// `web.RunsReader` — the narrow read port the run list, run detail,
/// node detail, and the controls' scope checks consume. Upstream's
/// subset of `runview/port.Reader`: the run census, the scoped
/// single-row lookups, the materialized DAG, the journal, the attempt
/// ledger, the current-state map, and live leases.
pub trait RunsReader: Send + Sync + 'static {
    /// `ListRuns`.
    fn list_runs(
        &self,
        workspace_id: WorkspaceId,
        after: Option<central_runview::domain::RunCursor>,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::RunSummary>, DomainFailure>>;

    /// `RunForID` — absent and cross-workspace rows answer
    /// `not_found`/`RUNVIEW_NOT_FOUND` alike.
    fn run_for_id(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunSummary, DomainFailure>>;

    /// `RunScope` — the workspace the run belongs to; `Ok(None)` when
    /// no run carries the id. The control POSTs' run scope check uses
    /// this single-column probe rather than the full `run_for_id`
    /// projection.
    fn run_scope(&self, run_id: RunId)
    -> BoxFuture<'_, Result<Option<WorkspaceId>, DomainFailure>>;

    /// `NodeForID`.
    fn node_for_id(
        &self,
        workspace_id: WorkspaceId,
        node_id: central_foundation::identity::WorkflowNodeId,
    ) -> BoxFuture<'_, Result<central_runview::domain::GraphNode, DomainFailure>>;

    /// `GraphForRun`.
    fn graph_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunGraph, DomainFailure>>;

    /// `EventsForRun` — the canonical journal envelope verbatim.
    fn events_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_eventjournal::domain::RunEvent>, DomainFailure>>;

    /// `AttemptsForNode`.
    fn attempts_for_node(
        &self,
        node_id: central_foundation::identity::WorkflowNodeId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::AttemptRow>, DomainFailure>>;

    /// `NodesCurrent` — the `compare_fold` input.
    fn nodes_current(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<std::collections::BTreeMap<String, String>, DomainFailure>>;

    /// `LiveLeases`.
    fn live_leases(
        &self,
        workspace_id: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::LeaseRow>, DomainFailure>>;
}

impl<T> RunsReader for T
where
    T: central_runview::port::Reader,
{
    fn list_runs(
        &self,
        workspace_id: WorkspaceId,
        after: Option<central_runview::domain::RunCursor>,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::RunSummary>, DomainFailure>> {
        Box::pin(async move { self.list_runs(workspace_id, after, limit).await })
    }

    fn run_for_id(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunSummary, DomainFailure>> {
        Box::pin(async move { self.run_for_id(workspace_id, run_id).await })
    }

    fn run_scope(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Option<WorkspaceId>, DomainFailure>> {
        Box::pin(async move { self.run_scope(run_id).await })
    }

    fn node_for_id(
        &self,
        workspace_id: WorkspaceId,
        node_id: central_foundation::identity::WorkflowNodeId,
    ) -> BoxFuture<'_, Result<central_runview::domain::GraphNode, DomainFailure>> {
        Box::pin(async move { self.node_for_id(workspace_id, node_id).await })
    }

    fn graph_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunGraph, DomainFailure>> {
        Box::pin(async move { self.graph_for_run(run_id).await })
    }

    fn events_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_eventjournal::domain::RunEvent>, DomainFailure>> {
        Box::pin(async move { self.events_for_run(run_id).await })
    }

    fn attempts_for_node(
        &self,
        node_id: central_foundation::identity::WorkflowNodeId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::AttemptRow>, DomainFailure>> {
        Box::pin(async move { self.attempts_for_node(node_id).await })
    }

    fn nodes_current(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<std::collections::BTreeMap<String, String>, DomainFailure>> {
        Box::pin(async move { self.nodes_current(run_id).await })
    }

    fn live_leases(
        &self,
        workspace_id: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::LeaseRow>, DomainFailure>> {
        Box::pin(async move { self.live_leases(workspace_id).await })
    }
}

/// `web.FleetReader` — the narrow read port the fleet observability
/// page consumes: workers, live leases, the bounded run scan that
/// names deferred-admission groups, per-run deferrals, and the outbox
/// probe. Satisfied by the same runview store that backs `RunsReader`.
pub trait FleetReader: Send + Sync + 'static {
    /// `Workers`.
    fn workers(
        &self,
        workspace_id: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::WorkerRow>, DomainFailure>>;

    /// `LiveLeases`.
    fn live_leases(
        &self,
        workspace_id: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::LeaseRow>, DomainFailure>>;

    /// `ListRuns` — one bounded page; the fleet page reads the newest
    /// runs to name the deferral groups.
    fn list_runs(
        &self,
        workspace_id: WorkspaceId,
        after: Option<central_runview::domain::RunCursor>,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::RunSummary>, DomainFailure>>;

    /// `DeferredAdmissions` — one run's journaled `admission_deferred`
    /// events in claim-FIFO order.
    fn deferred_admissions(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::DeferredRow>, DomainFailure>>;

    /// `OutboxHealth` — the publisher's own stall probe.
    fn outbox_health(
        &self,
    ) -> BoxFuture<'_, Result<central_runview::domain::OutboxHealth, DomainFailure>>;
}

impl<T> FleetReader for T
where
    T: central_runview::port::Reader,
{
    fn workers(
        &self,
        workspace_id: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::WorkerRow>, DomainFailure>> {
        Box::pin(async move { self.workers(workspace_id).await })
    }

    fn live_leases(
        &self,
        workspace_id: WorkspaceId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::LeaseRow>, DomainFailure>> {
        Box::pin(async move { self.live_leases(workspace_id).await })
    }

    fn list_runs(
        &self,
        workspace_id: WorkspaceId,
        after: Option<central_runview::domain::RunCursor>,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::RunSummary>, DomainFailure>> {
        Box::pin(async move { self.list_runs(workspace_id, after, limit).await })
    }

    fn deferred_admissions(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::DeferredRow>, DomainFailure>> {
        Box::pin(async move { self.deferred_admissions(run_id).await })
    }

    fn outbox_health(
        &self,
    ) -> BoxFuture<'_, Result<central_runview::domain::OutboxHealth, DomainFailure>> {
        Box::pin(async move { self.outbox_health().await })
    }
}

/// `web.RunLineageReader` — the narrow read port the run lineage view
/// consumes. In serve composition it is satisfied by the PostgreSQL
/// lineage store joined with the runview store (upstream's
/// `runLineageBackend`): the lineage store contributes the journaled
/// edge reads and the `find_artifact` lifecycle projection, the
/// runview store contributes node keys, attempt attribution, and the
/// run's workspace scope. Every method is a plain read — no locks, no
/// writes, no journaled side effects.
pub trait RunLineageReader: Send + Sync + 'static {
    /// `RunScope` — the workspace the run belongs to; `Ok(None)` when
    /// no run carries the id.
    fn run_scope(&self, run_id: RunId)
    -> BoxFuture<'_, Result<Option<WorkspaceId>, DomainFailure>>;

    /// `GraphForRun`.
    fn graph_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunGraph, DomainFailure>>;

    /// `AttemptsForRun`.
    fn attempts_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::AttemptRow>, DomainFailure>>;

    /// `ProduceEdgesForRun` — the run's journaled produce edges.
    fn produce_edges_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_artifact::lineage::ProduceEdge>, DomainFailure>>;

    /// `ReadEdgesForRun` — the run's journaled read edges with their
    /// declared|undeclared classification.
    fn read_edges_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_artifact::lineage::ReadEdge>, DomainFailure>>;

    /// `FindArtifact` — the artifact's lineage projection (identity,
    /// workspace, lifecycle state), `Ok(None)` when unresolved.
    fn find_artifact(
        &self,
        artifact_id: central_foundation::identity::ArtifactId,
    ) -> BoxFuture<'_, Result<Option<central_artifact::lineage::LineageArtifact>, DomainFailure>>;
}

/// `runLineageBackend` — the composition adapter satisfying
/// [`RunLineageReader`] over one runview [`central_runview::port::Reader`]
/// plus the artifact `LineageReader`/`ReadStore` pair (upstream's
/// `runLineageBackend` in `serve_composition.go`). The kernel wires the
/// same PostgreSQL store behind both generics.
pub struct RunLineageBackend<R, L> {
    /// The runview projection store (scope, graph, attempts).
    pub runs: R,
    /// The artifact lineage store (edges + artifact resolution).
    pub lineage: L,
}

impl<R, L> RunLineageReader for RunLineageBackend<R, L>
where
    R: central_runview::port::Reader + Send + Sync,
    L: central_artifact::port::LineageReader + central_artifact::port::ReadStore + Send + Sync,
{
    fn run_scope(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Option<WorkspaceId>, DomainFailure>> {
        Box::pin(async move { self.runs.run_scope(run_id).await })
    }

    fn graph_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<central_runview::domain::RunGraph, DomainFailure>> {
        Box::pin(async move { self.runs.graph_for_run(run_id).await })
    }

    fn attempts_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_runview::domain::AttemptRow>, DomainFailure>> {
        Box::pin(async move { self.runs.attempts_for_run(run_id).await })
    }

    fn produce_edges_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_artifact::lineage::ProduceEdge>, DomainFailure>> {
        Box::pin(async move {
            central_artifact::port::LineageReader::produce_edges_for_run(&self.lineage, run_id)
                .await
        })
    }

    fn read_edges_for_run(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_artifact::lineage::ReadEdge>, DomainFailure>> {
        Box::pin(async move {
            central_artifact::port::LineageReader::read_edges_for_run(&self.lineage, run_id).await
        })
    }

    fn find_artifact(
        &self,
        artifact_id: central_foundation::identity::ArtifactId,
    ) -> BoxFuture<'_, Result<Option<central_artifact::lineage::LineageArtifact>, DomainFailure>>
    {
        Box::pin(async move {
            central_artifact::port::ReadStore::find_artifact(&self.lineage, artifact_id).await
        })
    }
}

/// `web.RunCanceller` — the write-side port the run/node cancel
/// controls consume; `central_workflow::port::WorkflowStore` satisfies
/// it directly.
pub trait RunCanceller: Send + Sync + 'static {
    /// `CancelNode` — the spec-1 cascade in one commit; returns every
    /// affected node id. A terminal root refuses `DENIED`; replaying a
    /// committed cancel is an idempotent success.
    fn cancel_node<'a>(
        &'a self,
        node_id: central_foundation::identity::WorkflowNodeId,
        actor: &'a str,
    ) -> BoxFuture<'a, Result<Vec<central_foundation::identity::WorkflowNodeId>, DomainFailure>>;
}

impl<T> RunCanceller for T
where
    T: central_workflow::port::WorkflowStore,
{
    fn cancel_node<'a>(
        &'a self,
        node_id: central_foundation::identity::WorkflowNodeId,
        actor: &'a str,
    ) -> BoxFuture<'a, Result<Vec<central_foundation::identity::WorkflowNodeId>, DomainFailure>>
    {
        Box::pin(async move { self.cancel_node(node_id, actor).await })
    }
}

/// `web.AmbiguityResolver` — the write-side port the operator decision
/// control consumes; `central_workflow::port::WorkflowStore` satisfies
/// it directly.
pub trait AmbiguityResolver: Send + Sync + 'static {
    /// `ResolveAmbiguous` — records the one-row-ever `attempt_decision`
    /// on the node's parked attempt and applies the transition the
    /// decision names. `fingerprint` is the SHA-256 of the canonical
    /// decision payload — identical bytes to the CLI's
    /// `central node decide`.
    fn resolve_ambiguous<'a>(
        &'a self,
        node_id: central_foundation::identity::WorkflowNodeId,
        decision: &'a str,
        fingerprint: [u8; 32],
        actor: &'a str,
    ) -> BoxFuture<'a, Result<(), DomainFailure>>;
}

impl<T> AmbiguityResolver for T
where
    T: central_workflow::port::WorkflowStore,
{
    fn resolve_ambiguous<'a>(
        &'a self,
        node_id: central_foundation::identity::WorkflowNodeId,
        decision: &'a str,
        fingerprint: [u8; 32],
        actor: &'a str,
    ) -> BoxFuture<'a, Result<(), DomainFailure>> {
        Box::pin(async move {
            self.resolve_ambiguous(node_id, decision, fingerprint, actor)
                .await
        })
    }
}

/// `web.Resumer` — the write-side port the checkpoint-resume control
/// consumes; `central_checkpoint::port::ResumeStore` satisfies it
/// directly. `resume_preflight` returns the resolved checkpoint record
/// on success or a spec-3 `Failure` — the reason code renders inline.
pub trait Resumer: Send + Sync + 'static {
    /// `ResumePreflight`.
    fn resume_preflight<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>>;

    /// `ResumeSubtree`.
    fn resume_subtree<'a>(
        &'a self,
        token: &'a str,
        actor: &'a str,
    ) -> BoxFuture<'a, Result<(), DomainFailure>>;
}

impl<T> Resumer for T
where
    T: central_checkpoint::port::ResumeStore,
{
    fn resume_preflight<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>> {
        Box::pin(async move { self.resume_preflight(token).await })
    }

    fn resume_subtree<'a>(
        &'a self,
        token: &'a str,
        actor: &'a str,
    ) -> BoxFuture<'a, Result<(), DomainFailure>> {
        Box::pin(async move { self.resume_subtree(token, actor).await })
    }
}

/// `web.CheckpointControls` — the port the checkpoint controls
/// consume: `write_checkpoint` plus the retention/GC surface and the
/// scoped reads the pin/unpin scope check and the controls page list
/// need. `central_checkpoint::port::ResumeStore` satisfies it in full.
pub trait CheckpointControls: Send + Sync + 'static {
    /// `WriteCheckpoint`.
    fn write_checkpoint<'a>(
        &'a self,
        run_id: RunId,
        node_id: central_foundation::identity::WorkflowNodeId,
        actor: &'a str,
        gc_class: central_checkpoint::domain::GcClass,
        checkpoint_seq: i64,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>>;

    /// `LoadCheckpoint` — the pin/unpin scope check: the record's
    /// workspace must equal the session workspace before the class
    /// change is attempted.
    fn load_checkpoint(
        &self,
        checkpoint_id: central_foundation::identity::ResumeCheckpointId,
    ) -> BoxFuture<'_, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>>;

    /// `UpdateGCClass`.
    fn update_gc_class(
        &self,
        checkpoint_id: central_foundation::identity::ResumeCheckpointId,
        class: central_checkpoint::domain::GcClass,
    ) -> BoxFuture<'_, Result<(), DomainFailure>>;

    /// `Collect` — one GC pass, the same selection the janitor runs on
    /// schedule. A partial pass returns the collected count inside the
    /// outcome AND marks `has_failures()`.
    fn collect(
        &self,
        now: time::OffsetDateTime,
    ) -> BoxFuture<'_, Result<central_checkpoint::port::CollectOutcome, DomainFailure>>;

    /// `ListCheckpoints`.
    fn list_checkpoints(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_checkpoint::domain::ResumeCheckpoint>, DomainFailure>>;
}

impl<T> CheckpointControls for T
where
    T: central_checkpoint::port::ResumeStore,
{
    fn write_checkpoint<'a>(
        &'a self,
        run_id: RunId,
        node_id: central_foundation::identity::WorkflowNodeId,
        actor: &'a str,
        gc_class: central_checkpoint::domain::GcClass,
        checkpoint_seq: i64,
    ) -> BoxFuture<'a, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>> {
        Box::pin(async move {
            self.write_checkpoint(run_id, node_id, actor, gc_class, checkpoint_seq)
                .await
        })
    }

    fn load_checkpoint(
        &self,
        checkpoint_id: central_foundation::identity::ResumeCheckpointId,
    ) -> BoxFuture<'_, Result<central_checkpoint::domain::ResumeCheckpoint, DomainFailure>> {
        Box::pin(async move { self.load_resume_checkpoint_by_id(checkpoint_id).await })
    }

    fn update_gc_class(
        &self,
        checkpoint_id: central_foundation::identity::ResumeCheckpointId,
        class: central_checkpoint::domain::GcClass,
    ) -> BoxFuture<'_, Result<(), DomainFailure>> {
        Box::pin(async move { self.update_gc_class(checkpoint_id, class).await })
    }

    fn collect(
        &self,
        now: time::OffsetDateTime,
    ) -> BoxFuture<'_, Result<central_checkpoint::port::CollectOutcome, DomainFailure>> {
        Box::pin(async move { central_checkpoint::port::CollectStore::collect(self, now).await })
    }

    fn list_checkpoints(
        &self,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<central_checkpoint::domain::ResumeCheckpoint>, DomainFailure>>
    {
        Box::pin(async move { self.list_checkpoints(run_id).await })
    }
}

/// `web.RunControlPorts` — the optional write-side ports behind the
/// operator controls. Each field is independently nil-tolerant on the
/// `turn_activity`/`harness`/`run_lineage` precedent: a composition
/// that omits one renders the controls page without that control and
/// answers its POST the same bare 503 as an unwired read port. They
/// are deliberately not required-panic ports like `tasks`/`artifacts`:
/// this surface is a Phase-2 enhancement layered on the (also
/// nil-tolerant) `runs` reader.
#[derive(Default)]
pub struct RunControlPorts {
    /// `CancelNode`.
    pub canceller: Option<Arc<dyn RunCanceller>>,
    /// `ResolveAmbiguous`.
    pub resolver: Option<Arc<dyn AmbiguityResolver>>,
    /// `ResumePreflight`/`ResumeSubtree`.
    pub resumer: Option<Arc<dyn Resumer>>,
    /// `WriteCheckpoint`/`LoadCheckpoint`/`UpdateGCClass`/`Collect`/
    /// `ListCheckpoints`.
    pub checkpoints: Option<Arc<dyn CheckpointControls>>,
}
