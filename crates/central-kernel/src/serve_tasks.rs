//! `ServeTaskService` — the kernel's port of upstream
//! `cmd/central/task_service_adapter.go`.
//!
//! The transport's [`ports::TaskService`] joins B07's
//! `central_task::app::TaskService` — which owns `list_tasks`,
//! `task_detail`, `submit_task`, `request_cancellation`,
//! `cancel_unclaimed_task`, `retry_failed_task` and
//! `rerun_cancelled_task` — with a separately held
//! [`central_task::port::AggregateLoader`] for `load_aggregate` and a
//! [`central_task::query::TaskEventLogRead`] for `list_task_events`.
//! The app service has no aggregate-load or event-log read of its
//! own; this adapter is the single place the three meet so the
//! `/app` handlers (and the harness operator's "Mark cancelled" and
//! "Mark failed and rerun" task surfaces) load the exact
//! optimistic-lock versions they must echo back through one narrow
//! port.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_foundation::identity::{TaskId, WorkspaceId};
use central_task::app as task_app;
use central_task::domain as task;
use central_task::port::{AggregateLoader, LoadedAggregate};
use central_task::query::{self, TaskEventLogRead};
use central_transport_http::ports::{self, BoxFuture};

/// The [`AggregateLoader`] surface as a `dyn`-compatible boxed-future
/// trait — `AggregateLoader` is `trait_variant`-generated and so not
/// object-safe; upstream holds the concrete `*pgtask.Store` here.
pub trait AggregateLoad: Send + Sync + 'static {
    /// `AggregateLoader::load_aggregate`.
    fn load<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'a, Result<LoadedAggregate, Failure>>;
}

impl<T: AggregateLoader> AggregateLoad for T {
    fn load<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'a, Result<LoadedAggregate, Failure>> {
        Box::pin(async move { self.load_aggregate(workspace_id, task_id).await })
    }
}

/// The [`TaskEventLogRead`] surface as a `dyn`-compatible boxed-future
/// trait, for the same reason.
pub trait EventLogRead: Send + Sync + 'static {
    /// `TaskEventLogRead::read`.
    fn read<'a>(
        &'a self,
        req: query::TaskEventLogRequest,
    ) -> BoxFuture<'a, Result<query::TaskEventLogProjection, Failure>>;
}

impl<T: TaskEventLogRead> EventLogRead for T {
    fn read<'a>(
        &'a self,
        req: query::TaskEventLogRequest,
    ) -> BoxFuture<'a, Result<query::TaskEventLogProjection, Failure>> {
        Box::pin(async move { self.read(req).await })
    }
}

/// Upstream `taskServiceAdapter` — the composed `/app` task surface.
pub struct ServeTaskService {
    service: Arc<dyn ServeTaskApp>,
    loader: Arc<dyn AggregateLoad>,
    events: Arc<dyn EventLogRead>,
}

impl ServeTaskService {
    /// Wires the adapter over the app service, the aggregate loader
    /// and the event-log read — upstream
    /// `&taskServiceAdapter{Service: taskAppService, loader:
    /// taskStore, events: taskEventLogStore}`.
    pub fn new(
        service: Arc<dyn ServeTaskApp>,
        loader: Arc<dyn AggregateLoad>,
        events: Arc<dyn EventLogRead>,
    ) -> Self {
        Self {
            service,
            loader,
            events,
        }
    }
}

/// The `task::app::TaskService` command/query surface this adapter
/// consumes — kept as a trait so kernel tests fake it (upstream
/// embeds the concrete `*taskapp.Service`; the Rust port cannot
/// embed, so the trait names the same seven methods).
pub trait ServeTaskApp: Send + Sync + 'static {
    /// `TaskService::list_tasks`.
    fn list_tasks<'a>(
        &'a self,
        req: query::TaskListRequest,
    ) -> BoxFuture<'a, Result<query::TaskListProjection, Failure>>;
    /// `TaskService::task_detail`.
    fn task_detail<'a>(
        &'a self,
        req: query::TaskDetailRequest,
    ) -> BoxFuture<'a, Result<query::TaskDetailProjection, Failure>>;
    /// `TaskService::submit_task`.
    fn submit_task<'a>(
        &'a self,
        req: task::SubmitTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>>;
    /// `TaskService::request_cancellation`.
    fn request_cancellation<'a>(
        &'a self,
        req: task::RequestCancellationRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>>;
    /// `TaskService::cancel_unclaimed_task`.
    fn cancel_unclaimed_task<'a>(
        &'a self,
        req: task::CancelUnclaimedTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>>;
    /// `TaskService::retry_failed_task`.
    fn retry_failed_task<'a>(
        &'a self,
        req: task::RetryFailedTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>>;
    /// `TaskService::rerun_cancelled_task`.
    fn rerun_cancelled_task<'a>(
        &'a self,
        req: task::RerunCancelledTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>>;
}

impl<S, L, D> ServeTaskApp for task_app::TaskService<S, L, D>
where
    S: central_task::port::ChangeSetStore + Send + Sync + 'static,
    L: query::TaskListRead + Send + Sync + 'static,
    D: query::TaskDetailRead + Send + Sync + 'static,
{
    fn list_tasks<'a>(
        &'a self,
        req: query::TaskListRequest,
    ) -> BoxFuture<'a, Result<query::TaskListProjection, Failure>> {
        Box::pin(async move { self.list_tasks(req).await })
    }

    fn task_detail<'a>(
        &'a self,
        req: query::TaskDetailRequest,
    ) -> BoxFuture<'a, Result<query::TaskDetailProjection, Failure>> {
        Box::pin(async move { self.task_detail(req).await })
    }

    fn submit_task<'a>(
        &'a self,
        req: task::SubmitTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>> {
        Box::pin(async move { self.submit_task(req, meta).await })
    }

    fn request_cancellation<'a>(
        &'a self,
        req: task::RequestCancellationRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>> {
        Box::pin(async move { self.request_cancellation(req, meta).await })
    }

    fn cancel_unclaimed_task<'a>(
        &'a self,
        req: task::CancelUnclaimedTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>> {
        Box::pin(async move { self.cancel_unclaimed_task(req, meta).await })
    }

    fn retry_failed_task<'a>(
        &'a self,
        req: task::RetryFailedTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>> {
        Box::pin(async move { self.retry_failed_task(req, meta).await })
    }

    fn rerun_cancelled_task<'a>(
        &'a self,
        req: task::RerunCancelledTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'a, Result<task::CommitResult, Failure>> {
        Box::pin(async move { self.rerun_cancelled_task(req, meta).await })
    }
}

impl ports::TaskService for ServeTaskService {
    /// `ListTasks` — one bounded page of workspace task summaries.
    fn list_tasks(
        &self,
        req: query::TaskListRequest,
    ) -> BoxFuture<'_, Result<query::TaskListProjection, Failure>> {
        self.service.list_tasks(req)
    }

    /// `TaskDetail` — one bounded detail projection.
    fn task_detail(
        &self,
        req: query::TaskDetailRequest,
    ) -> BoxFuture<'_, Result<query::TaskDetailProjection, Failure>> {
        self.service.task_detail(req)
    }

    /// `ListTaskEvents` — the durable event-log read, validated and
    /// page-normalized exactly like upstream's adapter body.
    fn list_task_events(
        &self,
        req: query::TaskEventLogRequest,
    ) -> BoxFuture<'_, Result<query::TaskEventLogProjection, Failure>> {
        Box::pin(async move {
            query::validate_task_event_log_request(&req)?;
            let mut req = req;
            req.page_size = query::normalize_task_event_log_page_size(req.page_size);
            self.events.read(req).await
        })
    }

    /// `SubmitTask`.
    fn submit_task(
        &self,
        req: task::SubmitTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'_, Result<task::CommitResult, Failure>> {
        self.service.submit_task(req, meta)
    }

    /// `RequestCancellation`.
    fn request_cancellation(
        &self,
        req: task::RequestCancellationRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'_, Result<task::CommitResult, Failure>> {
        self.service.request_cancellation(req, meta)
    }

    /// `CancelUnclaimedTask` — ends a never-claimed task cancelled in
    /// one commit (harness phase 3e decisions 2 and 3).
    fn cancel_unclaimed_task(
        &self,
        req: task::CancelUnclaimedTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'_, Result<task::CommitResult, Failure>> {
        self.service.cancel_unclaimed_task(req, meta)
    }

    /// `RetryFailedTask`.
    fn retry_failed_task(
        &self,
        req: task::RetryFailedTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'_, Result<task::CommitResult, Failure>> {
        self.service.retry_failed_task(req, meta)
    }

    /// `RerunCancelledTask` — creates a new Task with lineage.
    fn rerun_cancelled_task(
        &self,
        req: task::RerunCancelledTaskRequest,
        meta: task_app::CommandMeta,
    ) -> BoxFuture<'_, Result<task::CommitResult, Failure>> {
        self.service.rerun_cancelled_task(req, meta)
    }

    /// `LoadAggregate` — the durable aggregate plus the
    /// optimistic-lock versions every mutation echoes back. Never
    /// mutates state; a missing or cross-workspace task answers
    /// `TASK_NOT_FOUND`, exactly as
    /// [`AggregateLoader`] documents.
    fn load_aggregate(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'_, Result<LoadedAggregate, Failure>> {
        Box::pin(async move { self.loader.load(workspace_id, task_id).await })
    }
}
