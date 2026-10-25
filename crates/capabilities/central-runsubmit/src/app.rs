//! Async orchestration layer — the port of `internal/runsubmit`'s
//! `Service` saga. One `Submit` call composes two `central-task`
//! commands (submit, then self-claim as `phase2`), two
//! `central-workflow` emit batches (leader root, then workers parented
//! to it), the shared readiness recomputation, and a readback that
//! asserts every node is `ready` — in upstream's exact order.
//!
//! Composition: [`TaskCommands`] is satisfied by
//! [`central_task::app::TaskService`], [`GraphStore`] by any
//! [`central_workflow::port::WorkflowStore`], and the load/replay
//! reads use [`central_task::port::AggregateLoader`] and
//! [`central_task::port::RunByKeyReader`]. `compose.go` wires the pg
//! stores over one pool.

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{CommandId, RunId, TaskId, WorkflowNodeId};
use central_task::app::{CommandMeta, TaskService};
use central_task::domain::{
    Budget, ClaimCurrentRunRequest, MutationInput, PermissionPolicy, RunStatus, SubmitTaskRequest,
    TaskAggregate, submit_request_fingerprint,
};
use central_task::port::{AggregateLoader, ChangeSetStore, RunByKeyReader};
use central_task::query::{TaskDetailRead, TaskListRead};
use central_workflow::domain::{ChildSpec, EmitResult, Node, NodeStatus};
use central_workflow::port::WorkflowStore;
use time::OffsetDateTime;

use crate::domain::{self, OWNER_PHASE2, SubmitRequest, SubmitResult, SubmittedNode};

/// The narrow task-command surface the saga drives — upstream
/// `runsubmit.TaskCommands` (`submit`, `claim`). `central_task`'s
/// [`TaskService`] satisfies it; the trait lives here because the
/// consumer defines the seam.
#[trait_variant::make(Send)]
pub trait TaskCommands: Send + Sync + 'static {
    /// `SubmitTask` — commits the task aggregate and its first queued
    /// run in one change-set.
    async fn submit_task(
        &self,
        req: SubmitTaskRequest,
        meta: CommandMeta,
    ) -> Result<central_task::domain::CommitResult, Failure>;

    /// `ClaimCurrentRun` — flips the queued run to running under a
    /// chosen owner token.
    async fn claim_current_run(
        &self,
        req: ClaimCurrentRunRequest,
        meta: CommandMeta,
    ) -> Result<central_task::domain::CommitResult, Failure>;
}

impl<S, L, D> TaskCommands for TaskService<S, L, D>
where
    S: ChangeSetStore,
    L: TaskListRead,
    D: TaskDetailRead,
{
    async fn submit_task(
        &self,
        req: SubmitTaskRequest,
        meta: CommandMeta,
    ) -> Result<central_task::domain::CommitResult, Failure> {
        TaskService::submit_task(self, req, meta).await
    }

    async fn claim_current_run(
        &self,
        req: ClaimCurrentRunRequest,
        meta: CommandMeta,
    ) -> Result<central_task::domain::CommitResult, Failure> {
        TaskService::claim_current_run(self, req, meta).await
    }
}

/// The narrow workflow-graph surface the saga drives — upstream
/// `runsubmit.GraphStore` (`emit_batch`, `recompute_ready`,
/// `nodes_for_run`). Satisfied by every
/// [`central_workflow::port::WorkflowStore`] (the blanket impl
/// delegates — the pg `Store` is the production instance; fakes
/// implement it directly).
#[trait_variant::make(Send)]
pub trait GraphStore: Send + Sync + 'static {
    /// Commits one child-spec batch under `parent_id` (`None` roots).
    async fn emit_batch(
        &self,
        run_id: RunId,
        parent_id: Option<WorkflowNodeId>,
        batch: ChildSpec,
    ) -> Result<EmitResult, Failure>;

    /// Recomputes `ready` for every node whose prerequisites resolved.
    async fn recompute_ready(&self, run_id: RunId) -> Result<Vec<WorkflowNodeId>, Failure>;

    /// Reads every node of the run (post-ready states).
    async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<Node>, Failure>;
}

impl<T: WorkflowStore> GraphStore for T {
    async fn emit_batch(
        &self,
        run_id: RunId,
        parent_id: Option<WorkflowNodeId>,
        batch: ChildSpec,
    ) -> Result<EmitResult, Failure> {
        WorkflowStore::emit_batch(self, run_id, parent_id, batch).await
    }

    async fn recompute_ready(&self, run_id: RunId) -> Result<Vec<WorkflowNodeId>, Failure> {
        WorkflowStore::recompute_ready(self, run_id).await
    }

    async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<Node>, Failure> {
        WorkflowStore::nodes_for_run(self, run_id).await
    }
}

/// `isTaskConflict` — the Conflict-kind predicate (upstream's
/// `task.Class` check).
fn is_task_conflict(f: &Failure) -> bool {
    f.kind() == FailureKind::Conflict
}

/// `isDupKey` — the Conflict-kind failure carrying the spec-5 token
/// the `run_key` coordinate shares with the `node_key` coordinate.
fn is_dup_key(f: &Failure) -> bool {
    is_task_conflict(f) && f.code() == domain::codes::DUPLICATE_IDEMPOTENCY_KEY
}

/// `dupKeyConflict` — the spec-5 conflict token on a resume-path
/// mismatch: the recorded row stands.
fn dup_key_conflict() -> Failure {
    Failure::conflict(
        domain::codes::DUPLICATE_IDEMPOTENCY_KEY,
        "the run key is already recorded under a different request, run, or owner",
    )
}

/// `specRejection` — the shared invalid-spec refusal for a
/// prevalidation or emit-batch rejection.
fn spec_rejection() -> Failure {
    Failure::invalid(domain::codes::SPEC_VALIDATION_FAILED, "child spec rejected")
}

/// A fresh command-receipt key — upstream mints
/// `uuid.NewV7().String()` per command.
fn minted_meta() -> CommandMeta {
    CommandMeta {
        idempotency_key: Some(CommandId::new().to_string()),
        correlation_id: None,
        causation_id: None,
    }
}

/// `Service` composes the four upstream seams. It is a value type —
/// callers share it behind `Arc` (transport) or hold it directly
/// (CLI). All four seams must be present: there is no half-wired
/// submit path (upstream's "service is not configured" refusal is
/// unrepresentable).
pub struct Service<T, L, R, G>
where
    T: TaskCommands,
    L: AggregateLoader,
    R: RunByKeyReader,
    G: GraphStore,
{
    /// `Tasks` — submit + claim commands.
    tasks: T,
    /// `Loads` — spec-5 replay-compare aggregate read.
    loads: L,
    /// `Runs` — spec-5 keyed-run lookup.
    runs: R,
    /// `Graph` — emit/ready/readback graph seam.
    graph: G,
}

impl<T, L, R, G> Service<T, L, R, G>
where
    T: TaskCommands,
    L: AggregateLoader,
    R: RunByKeyReader,
    G: GraphStore,
{
    /// `New` — the four upstream seams.
    pub const fn new(tasks: T, loads: L, runs: R, graph: G) -> Self {
        Self {
            tasks,
            loads,
            runs,
            graph,
        }
    }

    /// The graph seam — exposed read-only for composition surfaces
    /// that hand the same store to downstream views.
    pub const fn graph(&self) -> &G {
        &self.graph
    }

    /// `Submit` — runs pre-validation, the task submit + self-claim,
    /// the two emits, and the ready flip, resuming a recorded
    /// `run_key` on conflict: a keyed `DUPLICATE_IDEMPOTENCY_KEY` on
    /// submit, or any claim conflict, adopts the recorded run when the
    /// fingerprint matches (`deduped`) and returns the conflict
    /// otherwise, emitting nothing on any refusal path.
    ///
    /// # Errors
    /// `Invalid` for request-shape/spec refusals, `Conflict` for
    /// `DUPLICATE_IDEMPOTENCY_KEY` resume mismatches and claim
    /// contention; store failures surface unchanged.
    pub async fn submit(&self, req: SubmitRequest) -> Result<SubmitResult, Failure> {
        domain::validate_request(&req)?;
        if domain::prevalidate(req.workers).is_some() {
            return Err(spec_rejection());
        }
        let key = req
            .idempotency_key
            .clone()
            .filter(|k| !k.is_empty())
            .unwrap_or_else(|| CommandId::new().to_string());
        let task_req = SubmitTaskRequest {
            workspace_id: req.workspace_id,
            title: req.title.clone(),
            input: domain::submit_input(req.workers, req.run_key.is_some()),
            permission_policy: Some(PermissionPolicy::Deny),
            budget: Budget::default(),
            run_key: req.run_key.clone(),
            now: OffsetDateTime::now_utc(),
        };
        let res = match self
            .tasks
            .submit_task(
                task_req.clone(),
                CommandMeta {
                    idempotency_key: Some(key),
                    correlation_id: None,
                    causation_id: None,
                },
            )
            .await
        {
            Ok(res) => res,
            Err(err) => {
                if req.run_key.is_some() && is_dup_key(&err) {
                    return self.resume(&req, &task_req).await;
                }
                return Err(err);
            }
        };
        if res.runs.len() != 1 {
            return Err(Failure::internal(
                domain::codes::INVARIANT,
                format!(
                    "runsubmit: submit committed {} runs, want 1",
                    res.runs.len()
                ),
            ));
        }
        let run = res.runs[0].clone();
        // Self-claim as `phase2`: the owner token excludes the run
        // from Phase-1 dispatch case (a) while leaving the Phase-2
        // scheduler path untouched.
        let claim_req = ClaimCurrentRunRequest {
            input: MutationInput {
                aggregate: TaskAggregate {
                    task: res.task.clone(),
                    current_run: Some(run.clone()),
                },
                expected_task_version: res.task.version,
                expected_run_version: run.version,
                now: OffsetDateTime::now_utc(),
            },
            owner: OWNER_PHASE2.to_string(),
        };
        if let Err(err) = self.tasks.claim_current_run(claim_req, minted_meta()).await {
            if req.run_key.is_some() && is_task_conflict(&err) {
                return self.resume(&req, &task_req).await;
            }
            return Err(err);
        }
        self.emit_and_ready(&req, res.task.id, run.id, false).await
    }

    /// `resume` — adopts the recorded run for a keyed replay (spec D4 + SR2).
    /// The fingerprint must match and the run must be queued (claimed here)
    /// or already `phase2`-owned; anything else conflicts, emitting nothing.
    async fn resume(
        &self,
        req: &SubmitRequest,
        task_req: &SubmitTaskRequest,
    ) -> Result<SubmitResult, Failure> {
        let run_key = req.run_key.clone().unwrap_or_default();
        let mut run = match self.runs.run_by_key(req.workspace_id, &run_key).await {
            Ok(run) => run,
            Err(err) if err.kind() == FailureKind::NotFound => return Err(dup_key_conflict()),
            Err(err) => return Err(err),
        };
        let want = submit_request_fingerprint(task_req);
        if run.request_fingerprint != Some(want) {
            return Err(dup_key_conflict());
        }
        let loaded = self
            .loads
            .load_aggregate(req.workspace_id, run.task_id)
            .await?;
        let current = loaded.aggregate.current_run.clone();
        if current.as_ref().map(|c| c.id) != Some(run.id) {
            return Err(dup_key_conflict());
        }
        if matches!(current.as_ref().map(|c| c.status), Some(RunStatus::Queued)) {
            let claim_req = ClaimCurrentRunRequest {
                input: MutationInput {
                    aggregate: loaded.aggregate.clone(),
                    expected_task_version: loaded.task_version,
                    expected_run_version: loaded.run_version.ok_or_else(|| {
                        Failure::internal(
                            domain::codes::INVARIANT,
                            "runsubmit: current run carries no version",
                        )
                    })?,
                    now: OffsetDateTime::now_utc(),
                },
                owner: OWNER_PHASE2.to_string(),
            };
            if let Err(err) = self.tasks.claim_current_run(claim_req, minted_meta()).await {
                if !is_task_conflict(&err) {
                    return Err(err);
                }
                // A competing submit may have claimed it first: re-read
                // the coordinate; adopt it only when the fingerprint
                // matches and the phase2 owner stands.
                let re = match self.runs.run_by_key(req.workspace_id, &run_key).await {
                    Ok(re) => re,
                    Err(rerr) if rerr.kind() == FailureKind::NotFound => {
                        return Err(dup_key_conflict());
                    }
                    Err(rerr) => return Err(rerr),
                };
                if re.request_fingerprint != Some(want) || re.ownership_token != OWNER_PHASE2 {
                    return Err(err);
                }
                run = re;
            }
        } else if current.as_ref().map(|c| c.ownership_token.as_str()) != Some(OWNER_PHASE2) {
            return Err(dup_key_conflict());
        }
        self.emit_and_ready(req, loaded.aggregate.task.id, run.id, true)
            .await
    }

    /// `emitAndReady` — leader batch, then the worker batch parented
    /// to the committed leader, then the ready flip + readback
    /// assertion: every node must read `ready` (no-dep nodes always
    /// flip; anything else is an infrastructure surprise and fails the
    /// submit).
    async fn emit_and_ready(
        &self,
        req: &SubmitRequest,
        task_id: TaskId,
        run_id: RunId,
        deduped: bool,
    ) -> Result<SubmitResult, Failure> {
        let first = self
            .graph
            .emit_batch(run_id, None, domain::leader_batch())
            .await?;
        if first.rejected.is_some() {
            return Err(spec_rejection());
        }
        if first.nodes.len() != 1 {
            return Err(Failure::internal(
                domain::codes::INVARIANT,
                format!(
                    "runsubmit: leader emit committed {} nodes, want 1",
                    first.nodes.len()
                ),
            ));
        }
        let leader_id = first.nodes[0].id;
        let second = self
            .graph
            .emit_batch(run_id, Some(leader_id), domain::worker_batch(req.workers))
            .await?;
        if second.rejected.is_some() {
            return Err(spec_rejection());
        }
        if second.nodes.len() as i64 != req.workers {
            return Err(Failure::internal(
                domain::codes::INVARIANT,
                format!(
                    "runsubmit: worker emit committed {} nodes, want {}",
                    second.nodes.len(),
                    req.workers
                ),
            ));
        }
        self.graph.recompute_ready(run_id).await?;
        let mut nodes = self.graph.nodes_for_run(run_id).await?;
        for n in &nodes {
            if n.state != NodeStatus::Ready {
                return Err(Failure::internal(
                    domain::codes::INVARIANT,
                    format!(
                        "runsubmit: node {} is {} after ready flip",
                        n.node_key,
                        n.state.as_str()
                    ),
                ));
            }
        }
        nodes.sort_by(|a, b| a.node_key.cmp(&b.node_key));
        Ok(SubmitResult {
            task_id,
            run_id,
            nodes: nodes
                .into_iter()
                .map(|n| SubmittedNode {
                    node_id: n.id,
                    node_key: n.node_key,
                    state: n.state,
                })
                .collect(),
            deduped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use central_foundation::identity::WorkspaceId;
    use central_task::domain::{CommitResult, Run, Task, TaskStatus, codes as task_codes};
    use central_task::port::LoadedAggregate;
    use central_workflow::domain::ArtifactRef;

    fn ws() -> WorkspaceId {
        WorkspaceId::parse("019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a").unwrap()
    }

    fn req() -> SubmitRequest {
        SubmitRequest {
            workspace_id: ws(),
            title: "demo".to_string(),
            workers: 2,
            run_key: Some("k".to_string()),
            idempotency_key: Some("idem-1".to_string()),
        }
    }

    fn task_req_shape() -> SubmitTaskRequest {
        SubmitTaskRequest {
            workspace_id: ws(),
            title: "demo".to_string(),
            input: domain::submit_input(2, true),
            permission_policy: Some(PermissionPolicy::Deny),
            budget: Budget::default(),
            run_key: Some("k".to_string()),
            now: OffsetDateTime::now_utc(),
        }
    }

    fn task() -> Task {
        Task {
            id: TaskId::new(),
            workspace_id: ws(),
            version: 1,
            status: TaskStatus::Queued,
            current_run_id: None,
            parent_task_id: None,
            last_run_index: 0,
            retry_count: 0,
            retry_eligible_at: None,
            waiting_reason: None,
            failure_reason: String::new(),
            input: String::new(),
            title: "demo".to_string(),
            permission_policy: PermissionPolicy::Deny,
            budget: Budget::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn run(task_id: TaskId) -> Run {
        Run {
            id: RunId::new(),
            task_id,
            workspace_id: ws(),
            version: 1,
            status: RunStatus::Queued,
            index: 0,
            waiting_reason: None,
            failure_reason: String::new(),
            ownership_token: String::new(),
            run_key: Some("k".to_string()),
            request_fingerprint: Some(submit_request_fingerprint(&task_req_shape())),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn node(key: &str) -> Node {
        Node {
            id: WorkflowNodeId::new(),
            run_id: RunId::new(),
            workspace_id: ws(),
            node_key: key.to_string(),
            parent_id: None,
            harness: domain::HARNESS_NAME.to_string(),
            workspace_kind: "directory".to_string(),
            depth: 0,
            state: NodeStatus::Ready,
            budget_wall_clock_sec: None,
            budget_cost_micro_usd: None,
            max_attempts: 5,
            attempt_count: 0,
            not_before: None,
            input_artifact_refs: Vec::<ArtifactRef>::new(),
            spec: serde_json::Value::Null,
            spec_fingerprint: None,
            node_timeout_seconds: None,
            ready_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    // --- Fakes --------------------------------------------------------

    struct FakeTasks {
        submit_err: Mutex<Option<Failure>>,
        claim_err: Mutex<Option<Failure>>,
        claims: Mutex<Vec<ClaimCurrentRunRequest>>,
    }

    impl FakeTasks {
        fn fresh() -> Self {
            Self {
                submit_err: Mutex::new(None),
                claim_err: Mutex::new(None),
                claims: Mutex::new(Vec::new()),
            }
        }
    }

    impl TaskCommands for FakeTasks {
        async fn submit_task(
            &self,
            req: SubmitTaskRequest,
            _meta: CommandMeta,
        ) -> Result<CommitResult, Failure> {
            if let Some(e) = self.submit_err.lock().unwrap().take() {
                return Err(e);
            }
            let mut t = task();
            t.title = req.title.clone();
            let mut r = run(t.id);
            r.run_key = req.run_key.clone();
            r.request_fingerprint = Some(submit_request_fingerprint(&req));
            t.current_run_id = Some(r.id);
            Ok(CommitResult {
                task: t,
                runs: vec![r],
                events: Vec::new(),
            })
        }

        async fn claim_current_run(
            &self,
            req: ClaimCurrentRunRequest,
            _meta: CommandMeta,
        ) -> Result<CommitResult, Failure> {
            if let Some(e) = self.claim_err.lock().unwrap().take() {
                return Err(e);
            }
            self.claims.lock().unwrap().push(req.clone());
            Ok(CommitResult {
                task: req.input.aggregate.task,
                runs: req.input.aggregate.current_run.into_iter().collect(),
                events: Vec::new(),
            })
        }
    }

    #[derive(Default)]
    struct FakeLoads {
        aggregate: Mutex<Option<TaskAggregate>>,
        task_version: i64,
        run_version: Mutex<Option<i64>>,
    }

    impl AggregateLoader for FakeLoads {
        async fn load_aggregate(
            &self,
            _workspace_id: WorkspaceId,
            _task_id: TaskId,
        ) -> Result<LoadedAggregate, Failure> {
            let aggregate = self.aggregate.lock().unwrap().clone().ok_or_else(|| {
                Failure::not_found(task_codes::TASK_NOT_FOUND, "aggregate missing")
            })?;
            Ok(LoadedAggregate {
                aggregate,
                task_version: self.task_version,
                run_version: *self.run_version.lock().unwrap(),
            })
        }
    }

    struct FakeRuns {
        run: Mutex<Result<Run, Failure>>,
    }

    impl Default for FakeRuns {
        /// The unrecorded coordinate — `run_by_key` misses by default.
        fn default() -> Self {
            Self {
                run: Mutex::new(Err(Failure::not_found(
                    task_codes::TASK_NOT_FOUND,
                    "run key not recorded",
                ))),
            }
        }
    }

    impl RunByKeyReader for FakeRuns {
        async fn run_by_key(
            &self,
            _workspace_id: WorkspaceId,
            _run_key: &str,
        ) -> Result<Run, Failure> {
            self.run.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct FakeGraph {
        emit_errs: Mutex<Vec<Failure>>,
        emit_rejects: Mutex<usize>,
        nodes: Mutex<Vec<Node>>,
    }

    impl GraphStore for FakeGraph {
        async fn emit_batch(
            &self,
            _run_id: RunId,
            _parent_id: Option<WorkflowNodeId>,
            batch: ChildSpec,
        ) -> Result<EmitResult, Failure> {
            if let Some(e) = self.emit_errs.lock().unwrap().pop() {
                return Err(e);
            }
            if self.emit_rejects.lock().unwrap().checked_sub(1).is_some() {
                *self.emit_rejects.lock().unwrap() -= 1;
                return Ok(EmitResult {
                    nodes: Vec::new(),
                    rejected: Some(central_workflow::validate::Rejection {
                        reason_code: central_retry::domain::ReasonCode::SpecValidationFailed,
                        offending_keys: Vec::new(),
                        detail: "rejected".to_string(),
                    }),
                });
            }
            let nodes: Vec<Node> = batch.children.iter().map(|c| node(&c.node_key)).collect();
            self.nodes.lock().unwrap().extend(nodes.iter().cloned());
            Ok(EmitResult {
                nodes,
                rejected: None,
            })
        }

        async fn recompute_ready(&self, _run_id: RunId) -> Result<Vec<WorkflowNodeId>, Failure> {
            Ok(Vec::new())
        }

        async fn nodes_for_run(&self, _run_id: RunId) -> Result<Vec<Node>, Failure> {
            Ok(self.nodes.lock().unwrap().clone())
        }
    }

    type Svc = Service<FakeTasks, FakeLoads, FakeRuns, FakeGraph>;

    fn svc() -> Svc {
        Service::new(
            FakeTasks::fresh(),
            FakeLoads::default(),
            FakeRuns::default(),
            FakeGraph::default(),
        )
    }

    const DUP: &str = domain::codes::DUPLICATE_IDEMPOTENCY_KEY;

    // --- Upstream ports -------------------------------------------------

    /// `TestSubmitRunsTaskAndGraphInOrder` — the happy path: submit →
    /// phase2 self-claim → 3 ready nodes, not deduped.
    #[tokio::test]
    async fn submit_runs_task_and_graph_in_order() {
        let s = svc();
        let res = s.submit(req()).await.unwrap();
        assert!(!res.deduped);
        assert_eq!(
            res.nodes
                .iter()
                .map(|n| n.node_key.as_str())
                .collect::<Vec<_>>(),
            vec!["leader", "worker-1", "worker-2"]
        );
        assert!(res.nodes.iter().all(|n| n.state == NodeStatus::Ready));
        // The fresh path claims the committed run as phase2.
        let claims = s.tasks.claims.lock().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].owner, OWNER_PHASE2);
    }

    /// `TestSubmitValidatesBeforeSideEffects` — every request-shape
    /// refusal happens before any commit.
    #[tokio::test]
    async fn submit_validates_before_side_effects() {
        let s = svc();
        let mut r = req();
        r.title.clear();
        assert_eq!(
            s.submit(r).await.unwrap_err().code(),
            domain::codes::REQUEST_VALIDATION
        );
        let mut r = req();
        r.workers = 0;
        assert_eq!(s.submit(r).await.unwrap_err().kind(), FailureKind::Invalid);
        let mut r = req();
        r.title = "x".repeat(201);
        assert!(s.submit(r).await.is_err());
        let mut r = req();
        r.run_key = Some("k".repeat(129));
        assert!(s.submit(r).await.is_err());
        // Nothing claimed, nothing emitted.
        assert!(s.tasks.claims.lock().unwrap().is_empty());
        assert!(s.graph.nodes.lock().unwrap().is_empty());
    }

    /// `TestSubmitKeyedConflictResumesAdoptedRun` — a keyed
    /// submit conflict with a matching phase2-owned fingerprint
    /// adopts the recorded run without duplicate nodes.
    #[tokio::test]
    async fn submit_keyed_conflict_resumes_adopted_run() {
        let s = svc();
        let t = task();
        let mut r = run(t.id);
        r.status = RunStatus::Running;
        r.ownership_token = OWNER_PHASE2.to_string();
        *s.runs.run.lock().unwrap() = Ok(r.clone());
        *s.loads.aggregate.lock().unwrap() = Some(TaskAggregate {
            task: Task {
                current_run_id: Some(r.id),
                ..t.clone()
            },
            current_run: Some(r),
        });
        *s.tasks.submit_err.lock().unwrap() =
            Some(Failure::conflict(DUP, "run_key already recorded"));
        let res = s.submit(req()).await.unwrap();
        assert!(res.deduped);
        assert_eq!(res.nodes.len(), 3);
        // Phase2-owned running run: no claim attempted.
        assert!(s.tasks.claims.lock().unwrap().is_empty());
    }

    /// `TestSubmitKeyedConflictClaimsQueuedRun` — a recorded queued
    /// run is claimed as phase2 before emit.
    #[tokio::test]
    async fn submit_keyed_conflict_claims_queued_run() {
        let s = svc();
        let t = task();
        let r = run(t.id); // queued, no owner
        *s.runs.run.lock().unwrap() = Ok(r.clone());
        *s.loads.aggregate.lock().unwrap() = Some(TaskAggregate {
            task: Task {
                current_run_id: Some(r.id),
                ..t.clone()
            },
            current_run: Some(r),
        });
        *s.loads.run_version.lock().unwrap() = Some(1);
        *s.tasks.submit_err.lock().unwrap() = Some(Failure::conflict(DUP, "dup"));
        let res = s.submit(req()).await.unwrap();
        assert!(res.deduped);
        let claims = s.tasks.claims.lock().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].owner, OWNER_PHASE2);
    }

    /// `TestSubmitKeyedFingerprintMismatchConflicts` — a different
    /// request under the same `run_key` refuses with the spec-5 token.
    #[tokio::test]
    async fn submit_keyed_fingerprint_mismatch_conflicts() {
        let s = svc();
        let t = task();
        let mut r = run(t.id);
        r.request_fingerprint = Some([9u8; 32]);
        r.status = RunStatus::Running;
        r.ownership_token = OWNER_PHASE2.to_string();
        *s.runs.run.lock().unwrap() = Ok(r.clone());
        *s.loads.aggregate.lock().unwrap() = Some(TaskAggregate {
            task: Task {
                current_run_id: Some(r.id),
                ..t.clone()
            },
            current_run: Some(r),
        });
        *s.tasks.submit_err.lock().unwrap() = Some(Failure::conflict(DUP, "dup"));
        let err = s.submit(req()).await.unwrap_err();
        assert_eq!(err.code(), DUP);
        assert_eq!(err.kind(), FailureKind::Conflict);
    }

    /// `TestSubmitKeyedWrongOwnerConflicts` — a recorded run owned by
    /// another executor refuses to resume.
    #[tokio::test]
    async fn submit_keyed_wrong_owner_conflicts() {
        let s = svc();
        let t = task();
        let mut r = run(t.id);
        r.status = RunStatus::Running;
        r.ownership_token = "other-executor".to_string();
        *s.runs.run.lock().unwrap() = Ok(r.clone());
        *s.loads.aggregate.lock().unwrap() = Some(TaskAggregate {
            task: Task {
                current_run_id: Some(r.id),
                ..t.clone()
            },
            current_run: Some(r),
        });
        *s.tasks.submit_err.lock().unwrap() = Some(Failure::conflict(DUP, "dup"));
        let err = s.submit(req()).await.unwrap_err();
        assert_eq!(err.code(), DUP);
    }

    /// `TestSubmitWorkflowRejectionMapsToSharedSpecFailure` — an emit
    /// rejection surfaces as `SPEC_VALIDATION_FAILED` invalid.
    #[tokio::test]
    async fn submit_workflow_rejection_maps_to_shared_spec_failure() {
        let s = svc();
        *s.graph.emit_rejects.lock().unwrap() = 1;
        let err = s.submit(req()).await.unwrap_err();
        assert_eq!(err.code(), domain::codes::SPEC_VALIDATION_FAILED);
        assert_eq!(err.kind(), FailureKind::Invalid);
    }

    /// `TestSubmitNonReadyNodeFails` — a node that does not read
    /// `ready` after the flip fails the submission and names the node.
    #[tokio::test]
    async fn submit_non_ready_node_fails() {
        let s = svc();
        s.graph.nodes.lock().unwrap().push(Node {
            state: NodeStatus::Declared,
            ..node("stuck-1")
        });
        let err = s.submit(req()).await.unwrap_err();
        assert_eq!(err.code(), domain::codes::INVARIANT);
        assert!(err.message().contains("stuck-1"));
    }

    /// `TestSubmitClaimConflictResumes` — a claim conflict on the
    /// fresh path with a keyed request falls into resume (the
    /// competing submit already adopted the run).
    #[tokio::test]
    async fn submit_claim_conflict_resumes() {
        let s = svc();
        *s.tasks.claim_err.lock().unwrap() =
            Some(Failure::conflict(task_codes::RUN_MISMATCH, "lost CAS"));
        // resume() will run_by_key → not-found → dup-key conflict.
        *s.runs.run.lock().unwrap() = Err(Failure::not_found(task_codes::TASK_NOT_FOUND, "gone"));
        let err = s.submit(req()).await.unwrap_err();
        assert_eq!(err.code(), DUP);
    }

    /// `TestSubmitNonDupConflictSurfaces` — a non-dup-key submit
    /// conflict surfaces unchanged (no resume path).
    #[tokio::test]
    async fn submit_non_dup_conflict_surfaces() {
        let s = svc();
        *s.tasks.submit_err.lock().unwrap() =
            Some(Failure::conflict("IDEMPOTENCY_CONFLICT", "other"));
        let err = s.submit(req()).await.unwrap_err();
        assert_eq!(err.code(), "IDEMPOTENCY_CONFLICT");
    }

    /// `TestSubmitKeylessConflictDoesNotResume` — a dup-key conflict
    /// on a keyless submit cannot resume (no run_key coordinate).
    #[tokio::test]
    async fn submit_keyless_conflict_does_not_resume() {
        let s = svc();
        *s.tasks.submit_err.lock().unwrap() = Some(Failure::conflict(DUP, "dup"));
        let mut r = req();
        r.run_key = None;
        let err = s.submit(r).await.unwrap_err();
        assert_eq!(err.code(), DUP);
        // No run_key → no lookup attempted: run slot untouched.
        assert!(s.runs.run.lock().unwrap().is_err());
    }
}
