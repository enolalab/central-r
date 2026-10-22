//! Task Service — orchestration only (ports `internal/task/app/
//! service.go`; rust-application-boundaries.md §2.2).
//!
//! Every command method evaluates the domain transition, stamps the
//! command scope and command identity onto the commit request, and
//! commits through [`crate::port::ChangeSetStore`]. No business rules
//! live here; no transaction is opened here. Futures are
//! cancellation-safe at every `.await`: a dropped future leaves either
//! a durable commit (with its receipt) or no mutation — the adapter
//! owns atomicity.

use central_foundation::failure::Failure;
use central_foundation::identity::{CausationId, CorrelationId};

use crate::domain::{
    self, ActivateScheduledRunRequest, CancelUnclaimedTaskRequest, ClaimCurrentRunRequest,
    CommitResult, CompleteTaskRequest, FailTaskRequest, RequestCancellationRequest,
    RerunCancelledTaskRequest, ResumeSameRunRequest, RetryFailedTaskRequest,
    ScheduleRunRetryRequest, SettleCancellationRequest, SubmitTaskRequest, TaskChangeSet,
    WaitTaskRequest,
};
use crate::port::{ChangeSetStore, CommitTaskChangeSetRequest};
use crate::query::{
    self, TaskDetailProjection, TaskDetailRead, TaskDetailRequest, TaskListProjection,
    TaskListRead, TaskListRequest,
};

/// Command scope constants stamped on `command_receipts` rows — the
/// dedup coordinate a replay is compared under (`command_scope`).
mod scope {
    pub const SUBMIT_TASK: &str = "task.submit";
    pub const CLAIM_CURRENT_RUN: &str = "task.claim_current_run";
    pub const WAIT_TASK: &str = "task.wait";
    pub const SCHEDULE_RUN_RETRY: &str = "task.schedule_run_retry";
    pub const COMPLETE_TASK: &str = "task.complete";
    pub const RESUME_SAME_RUN: &str = "task.resume_same_run";
    pub const ACTIVATE_SCHEDULED_RUN: &str = "task.activate_scheduled_run";
    pub const FAIL_TASK: &str = "task.fail";
    pub const RETRY_FAILED_TASK: &str = "task.retry_failed";
    pub const REQUEST_CANCELLATION: &str = "task.request_cancellation";
    pub const SETTLE_CANCELLATION: &str = "task.settle_cancellation";
    pub const CANCEL_UNCLAIMED_TASK: &str = "task.cancel_unclaimed";
    pub const RERUN_CANCELLED_TASK: &str = "task.rerun_cancelled";
}

/// Command identity carried to the durable receipt — who asked, under
/// which idempotency coordinate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandMeta {
    /// The caller's dedup key (`command_receipts.idempotency_key`;
    /// `None` issues no receipt dedup row).
    pub idempotency_key: Option<String>,
    /// The scope-wide correlation identity.
    pub correlation_id: Option<CorrelationId>,
    /// The immediate-cause identity.
    pub causation_id: Option<CausationId>,
}

/// Orchestrates B07 task lifecycle commands and task-query reads.
pub struct TaskService<S: ChangeSetStore, L: TaskListRead, D: TaskDetailRead> {
    store: S,
    list_read: L,
    detail_read: D,
}

impl<S: ChangeSetStore, L: TaskListRead, D: TaskDetailRead> TaskService<S, L, D> {
    /// Wires the service against its store and read contracts.
    pub const fn new(store: S, list_read: L, detail_read: D) -> Self {
        Self {
            store,
            list_read,
            detail_read,
        }
    }

    /// `task.submit` — creates a queued task with its first queued run.
    pub async fn submit_task(
        &self,
        req: SubmitTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::submit_task(req)?;
        self.commit(cs, meta, scope::SUBMIT_TASK).await
    }

    /// `task.claim_current_run` — queued → running claim.
    pub async fn claim_current_run(
        &self,
        req: ClaimCurrentRunRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::claim_current_run(req)?;
        self.commit(cs, meta, scope::CLAIM_CURRENT_RUN).await
    }

    /// `task.wait` — running → waiting with a typed reason.
    pub async fn wait_task(
        &self,
        req: WaitTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::wait_task(req)?;
        self.commit(cs, meta, scope::WAIT_TASK).await
    }

    /// `task.schedule_run_retry` — running/waiting → retry-delay wait.
    pub async fn schedule_run_retry(
        &self,
        req: ScheduleRunRetryRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::schedule_run_retry(req)?;
        self.commit(cs, meta, scope::SCHEDULE_RUN_RETRY).await
    }

    /// `task.complete` — running → completed.
    pub async fn complete_task(
        &self,
        req: CompleteTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::complete_task(req)?;
        self.commit(cs, meta, scope::COMPLETE_TASK).await
    }

    /// `task.activate_scheduled_run` — retry-delay wait → queued with
    /// a fresh run.
    pub async fn activate_scheduled_run(
        &self,
        req: ActivateScheduledRunRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::activate_scheduled_run(req)?;
        self.commit(cs, meta, scope::ACTIVATE_SCHEDULED_RUN).await
    }

    /// `task.resume_same_run` — waiting → queued, same run.
    pub async fn resume_same_run(
        &self,
        req: ResumeSameRunRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::resume_same_run(req)?;
        self.commit(cs, meta, scope::RESUME_SAME_RUN).await
    }

    // `resume_reconciled_run` is deliberately absent here, matching
    // upstream: the reconciliation resume is reachable only through the
    // execution facade's composite commit, never as a standalone task
    // command.

    /// `task.fail` — running/waiting → failed.
    pub async fn fail_task(
        &self,
        req: FailTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::fail_task(req)?;
        self.commit(cs, meta, scope::FAIL_TASK).await
    }

    /// `task.retry_failed` — failed → queued with a fresh run, prior
    /// evidence preserved.
    pub async fn retry_failed_task(
        &self,
        req: RetryFailedTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::retry_failed_task(req)?;
        self.commit(cs, meta, scope::RETRY_FAILED_TASK).await
    }

    /// `task.request_cancellation` — records cancellation intent.
    pub async fn request_cancellation(
        &self,
        req: RequestCancellationRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::request_cancellation(req)?;
        self.commit(cs, meta, scope::REQUEST_CANCELLATION).await
    }

    /// `task.settle_cancellation` — cancelling → cancelled.
    pub async fn settle_cancellation(
        &self,
        req: SettleCancellationRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::settle_cancellation(req)?;
        self.commit(cs, meta, scope::SETTLE_CANCELLATION).await
    }

    /// `task.cancel_unclaimed` — ends a Task whose current Run was
    /// never claimed cancelled in one commit (harness phase 3e
    /// decisions 2 and 3).
    pub async fn cancel_unclaimed_task(
        &self,
        req: CancelUnclaimedTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::cancel_unclaimed_task(req)?;
        self.commit(cs, meta, scope::CANCEL_UNCLAIMED_TASK).await
    }

    /// `task.rerun_cancelled` — creates a new Task with lineage to a
    /// cancelled source.
    pub async fn rerun_cancelled_task(
        &self,
        req: RerunCancelledTaskRequest,
        meta: CommandMeta,
    ) -> Result<CommitResult, Failure> {
        let cs = domain::rerun_cancelled_task(req)?;
        self.commit(cs, meta, scope::RERUN_CANCELLED_TASK).await
    }

    /// The bounded workspace task list (§7.5 row 2).
    pub async fn list_tasks(&self, req: TaskListRequest) -> Result<TaskListProjection, Failure> {
        query::validate_task_list_request(&req)?;
        let mut req = req;
        req.page_size = query::normalize_task_list_page_size(req.page_size);
        self.list_read.read(req).await
    }

    /// The bounded task detail projection (§7.5 row 3).
    pub async fn task_detail(
        &self,
        req: TaskDetailRequest,
    ) -> Result<TaskDetailProjection, Failure> {
        query::validate_task_detail_request(&req)?;
        let mut req = req;
        req.run_page_size = query::normalize_task_detail_run_page_size(req.run_page_size);
        self.detail_read.read(req).await
    }

    async fn commit(
        &self,
        change_set: TaskChangeSet,
        meta: CommandMeta,
        command_scope: &'static str,
    ) -> Result<CommitResult, Failure> {
        self.store
            .commit_task_change_set(CommitTaskChangeSetRequest {
                workspace_id: change_set.task.workspace_id,
                change_set,
                command_scope,
                idempotency_key: meta.idempotency_key,
                correlation_id: meta.correlation_id,
                causation_id: meta.causation_id,
            })
            .await
    }
}

// ---------------------------------------------------------------------------
// Tests — port of internal/task/app/{service_test,
// cancel_unclaimed_test}.go. `TestNewTaskServicePanicsOnNilDeps` has no
// Rust analogue: generic port parameters cannot be nil, so the
// "constructed without a store" case is unrepresentable by
// construction — the equivalent guarantee lives in the type system.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{self, MutationInput, SubmitTaskRequest, TaskAggregate, TaskStatus};
    use crate::port::CommitTaskChangeSetRequest;
    use crate::query::{DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE, DEFAULT_TASK_LIST_PAGE_SIZE};
    use central_foundation::identity::{CausationId, CorrelationId, TaskId, WorkspaceId};
    use time::OffsetDateTime;

    /// Minimal std-only `block_on` — `Waker::noop` (Rust ≥1.85) keeps
    /// the workspace `unsafe_code = "forbid"` lint intact; stub ports
    /// never pend, so a pending poll just yields.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(v) => return v,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Default)]
    struct FakeStore {
        last_req: Mutex<Option<CommitTaskChangeSetRequest>>,
        err: Mutex<Option<Failure>>,
    }

    impl ChangeSetStore for FakeStore {
        async fn commit_task_change_set(
            &self,
            req: CommitTaskChangeSetRequest,
        ) -> Result<CommitResult, Failure> {
            if let Some(err) = self.err.lock().unwrap().clone() {
                return Err(err);
            }
            let result = CommitResult {
                task: req.change_set.task.clone(),
                runs: req.change_set.runs.clone(),
                events: req.change_set.events.clone(),
            };
            *self.last_req.lock().unwrap() = Some(req);
            Ok(result)
        }
    }

    struct FakeListRead {
        read_req: Mutex<Option<TaskListRequest>>,
        err: Option<Failure>,
    }

    impl TaskListRead for FakeListRead {
        async fn read(&self, req: TaskListRequest) -> Result<TaskListProjection, Failure> {
            *self.read_req.lock().unwrap() = Some(req);
            if let Some(err) = &self.err {
                return Err(err.clone());
            }
            Ok(TaskListProjection {
                tasks: Vec::new(),
                next_cursor: None,
            })
        }
    }

    struct FakeDetailRead {
        read_req: Mutex<Option<TaskDetailRequest>>,
    }

    impl TaskDetailRead for FakeDetailRead {
        async fn read(&self, req: TaskDetailRequest) -> Result<TaskDetailProjection, Failure> {
            *self.read_req.lock().unwrap() = Some(req);
            Err(Failure::not_found(
                domain::codes::TASK_NOT_FOUND,
                "test task absent",
            ))
        }
    }

    struct NoopListRead;
    struct NoopDetailRead;

    impl TaskListRead for NoopListRead {
        async fn read(&self, _req: TaskListRequest) -> Result<TaskListProjection, Failure> {
            Ok(TaskListProjection {
                tasks: Vec::new(),
                next_cursor: None,
            })
        }
    }

    impl TaskDetailRead for NoopDetailRead {
        async fn read(&self, _req: TaskDetailRequest) -> Result<TaskDetailProjection, Failure> {
            Err(Failure::not_found(
                domain::codes::TASK_NOT_FOUND,
                "test task absent",
            ))
        }
    }

    fn service() -> TaskService<FakeStore, NoopListRead, NoopDetailRead> {
        TaskService::new(FakeStore::default(), NoopListRead, NoopDetailRead)
    }

    fn submit_req() -> SubmitTaskRequest {
        SubmitTaskRequest {
            workspace_id: WorkspaceId::new(),
            title: "x".to_string(),
            input: "in.yaml".to_string(),
            permission_policy: None,
            budget: domain::Budget::default(),
            run_key: None,
            now: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn mutation(agg: TaskAggregate) -> MutationInput {
        MutationInput {
            expected_task_version: agg.task.version,
            expected_run_version: agg.current_run.as_ref().map_or(0, |r| r.version),
            aggregate: agg,
            now: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn apply(cs: &TaskChangeSet) -> TaskAggregate {
        TaskAggregate {
            task: cs.task.clone(),
            current_run: cs.runs.first().cloned(),
        }
    }

    /// Chains submit → claim → request → settle to build a settled
    /// cancelled task aggregate for rerun service tests.
    fn cancelled_source_aggregate() -> TaskAggregate {
        let mut agg = apply(&domain::submit_task(submit_req()).unwrap());
        let cs = domain::claim_current_run(ClaimCurrentRunRequest {
            input: mutation(agg.clone()),
            owner: "worker-1".to_string(),
        })
        .unwrap();
        agg = apply(&cs);
        let cs = domain::request_cancellation(RequestCancellationRequest {
            input: mutation(agg.clone()),
        })
        .unwrap();
        agg = apply(&cs);
        let cs = domain::settle_cancellation(SettleCancellationRequest {
            input: mutation(agg),
        })
        .unwrap();
        apply(&cs)
    }

    fn meta() -> CommandMeta {
        CommandMeta {
            idempotency_key: Some("idem-1".to_string()),
            correlation_id: Some(CorrelationId::new()),
            causation_id: Some(CausationId::new()),
        }
    }

    #[test]
    fn submit_task_propagates_idempotency_metadata() {
        let svc = service();
        block_on(svc.submit_task(submit_req(), meta())).unwrap();
        let got = svc.store.last_req.lock().unwrap().clone().unwrap();
        assert_eq!(got.idempotency_key.as_deref(), Some("idem-1"));
        assert!(got.correlation_id.is_some());
        assert!(got.causation_id.is_some());
        assert_eq!(got.command_scope, "task.submit");
    }

    #[test]
    fn rerun_cancelled_task_propagates_metadata_and_scope() {
        let svc = service();
        let source = cancelled_source_aggregate();
        block_on(svc.rerun_cancelled_task(
            RerunCancelledTaskRequest {
                source: source.clone(),
                expected_task_version: source.task.version,
                now: OffsetDateTime::UNIX_EPOCH,
            },
            meta(),
        ))
        .unwrap();
        let got = svc.store.last_req.lock().unwrap().clone().unwrap();
        assert_eq!(got.idempotency_key.as_deref(), Some("idem-1"));
        assert!(got.correlation_id.is_some());
        assert!(got.causation_id.is_some());
        assert_eq!(got.command_scope, "task.rerun_cancelled");
        assert_eq!(got.change_set.task.parent_task_id, Some(source.task.id));
    }

    #[test]
    fn list_tasks_normalizes_page_size() {
        let list = FakeListRead {
            read_req: Mutex::new(None),
            err: None,
        };
        let svc = TaskService::new(FakeStore::default(), list, NoopDetailRead);
        block_on(svc.list_tasks(TaskListRequest {
            workspace_id: WorkspaceId::new(),
            cursor: None,
            page_size: 0,
        }))
        .unwrap();
        let req = svc.list_read.read_req.lock().unwrap().clone().unwrap();
        assert_eq!(req.page_size, DEFAULT_TASK_LIST_PAGE_SIZE);
    }

    #[test]
    fn task_detail_normalizes_run_page_size() {
        let detail = FakeDetailRead {
            read_req: Mutex::new(None),
        };
        let svc = TaskService::new(FakeStore::default(), NoopListRead, detail);
        let _ = block_on(svc.task_detail(TaskDetailRequest {
            workspace_id: WorkspaceId::new(),
            task_id: TaskId::new(),
            run_cursor: None,
            run_page_size: 0,
        }));
        let req = svc.detail_read.read_req.lock().unwrap().clone().unwrap();
        assert_eq!(req.run_page_size, DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE);
    }

    #[test]
    fn list_task_read_error_passes_through() {
        let marker = Failure::unavailable("test_unavailable", "read failed");
        let list = FakeListRead {
            read_req: Mutex::new(None),
            err: Some(marker.clone()),
        };
        let svc = TaskService::new(FakeStore::default(), list, NoopDetailRead);
        let err = block_on(svc.list_tasks(TaskListRequest {
            workspace_id: WorkspaceId::new(),
            cursor: None,
            page_size: 0,
        }))
        .unwrap_err();
        assert_eq!(err, marker);
    }

    // -- app/cancel_unclaimed_test.go ------------------------------------------

    /// Harness phase 3e decision 2: the service commits
    /// `cancel_unclaimed_task` under its own command scope.
    #[test]
    fn cancel_unclaimed_task_commits_under_its_own_scope() {
        let svc = service();
        let created = domain::submit_task(submit_req()).unwrap();
        let agg = apply(&created);
        let workspace_id = agg.task.workspace_id;
        let got = block_on(svc.cancel_unclaimed_task(
            domain::CancelUnclaimedTaskRequest {
                input: mutation(agg),
            },
            meta(),
        ))
        .unwrap();
        let req = svc.store.last_req.lock().unwrap().clone().unwrap();
        assert_eq!(req.command_scope, "task.cancel_unclaimed");
        assert_eq!(req.idempotency_key.as_deref(), Some("idem-1"));
        assert!(req.correlation_id.is_some());
        assert!(req.causation_id.is_some());
        assert_eq!(req.workspace_id, workspace_id);
        assert_eq!(got.task.status, TaskStatus::Cancelled);
        assert_eq!(got.runs.len(), 1);
        assert_eq!(got.runs[0].status, domain::RunStatus::Cancelled);
        assert_eq!(got.events.len(), 2);
    }

    #[test]
    fn cancel_unclaimed_task_refusal_commits_nothing() {
        let svc = service();
        let created = domain::submit_task(submit_req()).unwrap();
        let mut agg = apply(&created);
        let run = agg.current_run.as_mut().unwrap();
        run.ownership_token = "worker".to_string();
        run.status = domain::RunStatus::Running;
        agg.task.status = TaskStatus::Running;
        let err = block_on(svc.cancel_unclaimed_task(
            domain::CancelUnclaimedTaskRequest {
                input: mutation(agg),
            },
            CommandMeta::default(),
        ))
        .unwrap_err();
        assert_eq!(err.kind(), central_foundation::failure::FailureKind::Denied);
        assert!(
            svc.store.last_req.lock().unwrap().is_none(),
            "a refused cancel reached the store"
        );
    }
}
