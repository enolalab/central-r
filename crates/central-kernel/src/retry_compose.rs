//! Slice-2D (issue #95) composition seams of the scheduler stack — the
//! kernel's port of upstream `cmd/central/scheduler_retry_composition.go`:
//! the `Killer` and `CompensationExecutor` the postgres scheduler store
//! pushes timeout kills and managed `on_terminal_failure` hooks through.
//!
//! Both are boundary types owned by this file so the composition root —
//! not a store default — carries the choice, per the same composition
//! rule every other Slice-2 seam follows.
//!
//! OWNING PACKET: P2D03/P2D04 wiring (task T6). SLICE: 2D (issue #95).

use std::sync::Arc;

use central_adapter_linux::dispatch_provision::DispatchProvisioner;
use central_adapter_postgres::scheduler::PgSchedulerStore;
use central_foundation::failure::Failure;
use central_foundation::identity::{SessionAttemptId, WorkflowNodeId};
use central_retry::app::sweeper::RetrySweeper as TimeoutSweeper;
use central_retry::port::{CompensationExecutor, Killer};
use central_scheduler::port::Provisioner;
use central_scheduler::query::SchedulerRead;

use crate::BoxFuture;
use crate::lifecycle::Component;
use crate::scheduler_compose::{SchedulerConfig, TickedPassComponent};

// ---------------------------------------------------------------------------
// Killer — the documented unconfirmed kill boundary
// ---------------------------------------------------------------------------

/// `unconfirmedKiller` — the composition-level `Killer` stand-in Slice
/// 2D wires: when the only launcher seam is the documented
/// `StubLauncher`, no harness process runs, so there is no session to
/// signal and no adapter that could confirm a kill. Every sweep kill
/// therefore evaluates UNCONFIRMED and the store parks the attempt
/// `attempt_ambiguous` for `central node decide` — a fabricated
/// "confirmed" would forge a definite `SESSION_WALL_CLOCK_REACHED`
/// failure on a session whose outcome is unknowable (spec-4 locked
/// input 2).
///
/// This is exactly what a `None` `Killer` does inside the store; the
/// explicit type exists so the choice is a composition decision with a
/// name, and so a real harness cancel control replaces it HERE — one
/// seam, no store change — when one lands.
pub struct UnconfirmedKiller;

impl Killer for UnconfirmedKiller {
    /// `Kill` — always reports an unconfirmed kill: nothing was
    /// signalled and nothing claims otherwise.
    async fn kill(&self, _attempt_id: SessionAttemptId) -> Result<bool, Failure> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// CompensationExecutor — the managed on_terminal_failure hooks
// ---------------------------------------------------------------------------

/// `attemptWorkspaceQuerier` — the narrow read the compensation
/// executor needs: upstream's `SELECT workspace_path ... WHERE node_id
/// AND workspace_path IS NOT NULL ORDER BY attempt_seq DESC LIMIT 1`
/// as one seam call. Rust's [`SchedulerRead`] is not dyn-compatible,
/// so the composition root owns this one-method seam and
/// [`PgSchedulerStore`] resolves the same latest-path projection over
/// its `list_node_attempts` read.
pub trait AttemptWorkspaceRead: Send + Sync {
    /// The newest `workspace_path` the node's attempts recorded at
    /// `mark_provisioning` — `None` when no attempt recorded one.
    fn latest_workspace_path<'a>(
        &'a self,
        node_id: WorkflowNodeId,
    ) -> BoxFuture<'a, Result<Option<String>, Failure>>;
}

impl AttemptWorkspaceRead for PgSchedulerStore {
    fn latest_workspace_path<'a>(
        &'a self,
        node_id: WorkflowNodeId,
    ) -> BoxFuture<'a, Result<Option<String>, Failure>> {
        Box::pin(async move {
            let attempts = SchedulerRead::list_node_attempts(self, node_id).await?;
            // `ORDER BY attempt_seq DESC LIMIT 1` over the rows that
            // recorded a path.
            Ok(attempts
                .iter()
                .filter(|a| a.workspace_path.is_some())
                .max_by_key(|a| a.attempt_seq)
                .and_then(|a| a.workspace_path.clone()))
        })
    }
}

/// `workspaceFreer` — the narrow provisioner seam the executor needs:
/// `free(path)`. A composition-level interface keeps the executor
/// testable without a scratch root.
pub trait WorkspaceFreer: Send + Sync {
    /// Removes the workspace at `path`; idempotent.
    ///
    /// # Errors
    /// Propagates the provisioner's refusal.
    fn free(&self, path: &str) -> Result<(), Failure>;
}

impl WorkspaceFreer for DispatchProvisioner {
    fn free(&self, path: &str) -> Result<(), Failure> {
        Provisioner::free(self, path)
    }
}

/// `schedulerCompensation` — the production `CompensationExecutor`:
/// the composition root's bridge between the scheduler store's
/// `central_retry::port::CompensationExecutor` seam and the
/// provisioner the dispatch path shares the scratch root with.
pub struct SchedulerCompensation {
    read: Arc<dyn AttemptWorkspaceRead>,
    prov: Arc<dyn WorkspaceFreer>,
}

impl SchedulerCompensation {
    /// `newSchedulerCompensation` — builds the executor over the
    /// validated scheduler environment. `cfg` comes from
    /// [`SchedulerConfig::load`], so the provisioner construction
    /// cannot fail on shape; an error still propagates rather than
    /// silently leaving the seam unwired.
    ///
    /// # Errors
    /// Propagates the provisioner's config refusal, wrapped as
    /// `scheduler composition` context.
    pub fn new(read: PgSchedulerStore, cfg: &SchedulerConfig) -> Result<Self, Failure> {
        let prov = DispatchProvisioner::new(&cfg.scratch_root, &cfg.source_repo).map_err(|f| {
            Failure::invalid(
                "scheduler_config_invalid",
                format!("scheduler compensation: {}", f.message()),
            )
        })?;
        Ok(Self {
            read: Arc::new(read),
            prov: Arc::new(prov),
        })
    }

    /// `withSeams` — builds the executor over injected seams; the
    /// composition tests drive fakes through it.
    #[must_use]
    pub fn with_seams(read: Arc<dyn AttemptWorkspaceRead>, prov: Arc<dyn WorkspaceFreer>) -> Self {
        Self { read, prov }
    }
}

impl CompensationExecutor for SchedulerCompensation {
    /// `CleanupWorkspace` — removes the node's provisioned workspace
    /// through the provisioner. The path is the one the latest attempt
    /// RECORDED at `mark_provisioning` — the durable truth, never a
    /// recomputed guess. The workspace path is `(run, node)`-keyed so
    /// every attempt of the node converges on it and the latest row
    /// names it. A node that failed before provisioning recorded no
    /// path: there is nothing to free and the hook reports success,
    /// keeping execution idempotent.
    async fn cleanup_workspace(&self, node_id: WorkflowNodeId) -> Result<(), Failure> {
        let Some(path) = self
            .read
            .latest_workspace_path(node_id)
            .await
            .map_err(|f| {
                Failure::internal(
                    "scheduler_compensation",
                    format!(
                        "scheduler compensation: read workspace path: {}",
                        f.message()
                    ),
                )
            })?
        else {
            return Ok(());
        };
        self.prov.free(&path).map_err(|f| {
            Failure::internal(
                "scheduler_compensation",
                format!("scheduler compensation: free workspace: {}", f.message()),
            )
        })
    }

    /// `RetainArtifacts` — marks the node's declared artifacts kept for
    /// inspection (spec-4 decision 6). Phase 2 carries no per-artifact
    /// retention flag on `central.artifacts` and no artifact sweep
    /// reaps a failed node's artifacts — the staging-expiry pass only
    /// touches unclaimed reserved/staging rows through B10's
    /// reconciliation claims — so retention is the standing state and
    /// the durable mark is the journaled `compensation_requested` row
    /// the store commits with `result=executed` (the dossier's "hook
    /// outcome persists on the journal; no new tables"). When a
    /// retention column lands the write goes here — one seam, no
    /// store change. Until then this deliberately never fabricates a
    /// row in a table the schema does not define.
    async fn retain_artifacts(&self, _node_id: WorkflowNodeId) -> Result<(), Failure> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The supervised timeout-sweeper component
// ---------------------------------------------------------------------------

/// `retryapp.TimeoutSweeper`'s supervised half (upstream
/// `&retryapp.TimeoutSweeper{Store: req.TimeoutSweep}` as a kernel
/// component): one `sweep_timeouts` pass at component start, then one
/// per `tick_interval`. Pass failures are contained inside the sweep —
/// a deadline pass that cannot commit leaves the attempts for the
/// next tick rather than killing serve.
pub fn timeout_sweeper_component(store: PgSchedulerStore) -> impl Component {
    let sweeper = Arc::new(TimeoutSweeper::new(store));
    let interval = sweeper.tick_interval();
    TickedPassComponent::new(
        "retry_timeout_sweeper",
        std::time::Duration::new(
            interval.whole_seconds().max(0) as u64,
            interval.subsec_nanoseconds().max(0) as u32,
        ),
        move || {
            let sweeper = sweeper.clone();
            Box::pin(async move { sweeper.sweep_once().await })
        },
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// `UnconfirmedKiller` — every kill reports unconfirmed so the
    /// store parks the attempt `attempt_ambiguous` (spec-4 locked
    /// input 2).
    #[tokio::test(flavor = "current_thread")]
    async fn unconfirmed_killer_never_confirms() {
        let killer = UnconfirmedKiller;
        assert_eq!(killer.kill(SessionAttemptId::new()).await, Ok(false));
    }

    struct FakeRead {
        path: Option<String>,
        err: Option<Failure>,
        calls: StdMutex<usize>,
    }

    impl AttemptWorkspaceRead for FakeRead {
        fn latest_workspace_path<'a>(
            &'a self,
            _node_id: WorkflowNodeId,
        ) -> BoxFuture<'a, Result<Option<String>, Failure>> {
            *self.calls.lock().unwrap() += 1;
            let path = self.path.clone();
            let err = self.err.clone();
            Box::pin(async move {
                match err {
                    Some(e) => Err(e),
                    None => Ok(path),
                }
            })
        }
    }

    #[derive(Default)]
    struct FakeFreer {
        freed: StdMutex<Vec<String>>,
        err: Option<Failure>,
    }

    impl WorkspaceFreer for FakeFreer {
        fn free(&self, path: &str) -> Result<(), Failure> {
            self.freed.lock().unwrap().push(path.to_string());
            match &self.err {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
    }

    fn compensation(
        path: Option<String>,
        read_err: Option<Failure>,
        free_err: Option<Failure>,
    ) -> (SchedulerCompensation, Arc<FakeFreer>, Arc<FakeRead>) {
        let read = Arc::new(FakeRead {
            path,
            err: read_err,
            calls: StdMutex::new(0),
        });
        let prov = Arc::new(FakeFreer {
            freed: StdMutex::new(Vec::new()),
            err: free_err,
        });
        (
            SchedulerCompensation::with_seams(
                read.clone() as Arc<dyn AttemptWorkspaceRead>,
                prov.clone() as Arc<dyn WorkspaceFreer>,
            ),
            prov,
            read,
        )
    }

    /// A node whose latest attempt recorded a workspace frees exactly
    /// that path through the provisioner.
    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_workspace_frees_the_recorded_path() {
        let (exec, prov, read) = compensation(Some("/scratch/ws/r/n".into()), None, None);
        exec.cleanup_workspace(WorkflowNodeId::new())
            .await
            .expect("cleanup");
        assert_eq!(*read.calls.lock().unwrap(), 1);
        assert_eq!(*prov.freed.lock().unwrap(), vec!["/scratch/ws/r/n"]);
    }

    /// A node that failed before provisioning recorded no path: the
    /// hook reports success and never touches the provisioner —
    /// execution stays idempotent.
    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_workspace_no_recorded_path_is_a_noop() {
        let (exec, prov, _) = compensation(None, None, None);
        exec.cleanup_workspace(WorkflowNodeId::new())
            .await
            .expect("cleanup");
        assert!(prov.freed.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_workspace_read_error_propagates() {
        let (exec, prov, _) =
            compensation(None, Some(Failure::unavailable("pg", "pool down")), None);
        let err = exec
            .cleanup_workspace(WorkflowNodeId::new())
            .await
            .expect_err("read error must propagate");
        assert!(err.message().contains("read workspace path"));
        assert!(prov.freed.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_workspace_free_error_propagates() {
        let (exec, _, _) = compensation(
            Some("/scratch/ws/r/n".into()),
            None,
            Some(Failure::internal("provision", "rm failed")),
        );
        let err = exec
            .cleanup_workspace(WorkflowNodeId::new())
            .await
            .expect_err("free error must propagate");
        assert!(err.message().contains("free workspace"));
    }

    /// `retain_artifacts` is the deliberate no-op until the schema
    /// carries a retention column.
    #[tokio::test(flavor = "current_thread")]
    async fn retain_artifacts_is_the_documented_noop() {
        let (exec, _, read) = compensation(None, None, None);
        exec.retain_artifacts(WorkflowNodeId::new())
            .await
            .expect("retain");
        // It does not even read — the hook never invents work.
        assert_eq!(*read.calls.lock().unwrap(), 0);
    }
}
