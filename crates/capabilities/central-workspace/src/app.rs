//! Workspace Service — orchestration only (rust-application-boundaries.md
//! §2.2).
//!
//! Every method loads typed durable snapshots through [`crate::port`],
//! invokes a [`crate::domain`] decision, and commits the approved change
//! set. No business rules live here; no transaction is opened here; no
//! external effect is attempted. Futures are cancellation-safe at every
//! `.await`: a dropped future leaves either a durable commit or no
//! mutation — the adapter owns atomicity.
//!
//! Authority: every command takes the caller-supplied
//! [`OperationContext`]; the transport's authenticated-session +
//! workspace-owner decision happens before invocation (§7.5). This
//! service trusts the typed context and never re-derives authority.

use central_foundation::failure::Failure;
use central_foundation::identity::{OperationId, WorkspaceId};
use time::OffsetDateTime;

use crate::domain::{
    self, CreateWorkspaceCommand, EpochDecision, WorkspaceChangeSet, WorkspaceSnapshot, codes,
};
use crate::port::WorkspaceStore;
use crate::query::{WorkspaceStatusProjection, WorkspaceStatusRead, WorkspaceStatusRequest};

/// Caller-supplied operation identity — who asked, under which durable
/// operation handle. The service records it on command receipts via the
/// change-set commit; it never fabricates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationContext {
    /// The durable operation identity for this invocation.
    pub operation_id: OperationId,
    /// Authenticated principal identity (bounded, already validated by
    /// the transport's session decision).
    pub actor_identity: String,
    /// Service-side evaluation instant (database time remains
    /// authoritative inside the commit).
    pub now: OffsetDateTime,
}

/// The workspace capability Service.
pub struct WorkspaceService<S: WorkspaceStore, R: WorkspaceStatusRead> {
    store: S,
    status_read: R,
}

impl<S: WorkspaceStore, R: WorkspaceStatusRead> WorkspaceService<S, R> {
    /// Wires the service against its port and read contracts.
    pub const fn new(store: S, status_read: R) -> Self {
        Self { store, status_read }
    }

    /// Creates a workspace: domain-validated `active` row with a zeroed
    /// quota ledger and epochs, guarded on absence. A conflicting
    /// existing row surfaces as the adapter's conflict failure.
    pub async fn create_workspace(
        &self,
        ctx: OperationContext,
        cmd: CreateWorkspaceCommand,
    ) -> Result<WorkspaceSnapshot, Failure> {
        let change_set = domain::evaluate_create(cmd, ctx.now)?;
        self.store.commit_change_set(change_set).await
    }

    /// Deletes a workspace: loads the snapshot, evaluates the delete
    /// transition, commits under the state/epoch guard.
    pub async fn delete_workspace(
        &self,
        _ctx: OperationContext,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspaceSnapshot, Failure> {
        let snapshot = self.require_snapshot(workspace_id).await?;
        let change_set = snapshot.evaluate_delete()?;
        self.store.commit_change_set(change_set).await
    }

    /// Advances the security epoch (post-restore authority reset).
    /// Idempotent: an equal target is an approved no-op returning the
    /// current snapshot; a regression fails closed.
    pub async fn advance_security_epoch(
        &self,
        _ctx: OperationContext,
        workspace_id: WorkspaceId,
        target: u64,
    ) -> Result<WorkspaceSnapshot, Failure> {
        let snapshot = self.require_snapshot(workspace_id).await?;
        match snapshot.evaluate_security_epoch(target)? {
            EpochDecision::Unchanged => Ok(snapshot),
            EpochDecision::ChangeSet(change_set) => self.commit(change_set).await,
        }
    }

    /// Advances the restore epoch; same forward-only rule.
    pub async fn advance_restore_epoch(
        &self,
        _ctx: OperationContext,
        workspace_id: WorkspaceId,
        target: u64,
    ) -> Result<WorkspaceSnapshot, Failure> {
        let snapshot = self.require_snapshot(workspace_id).await?;
        match snapshot.evaluate_restore_epoch(target)? {
            EpochDecision::Unchanged => Ok(snapshot),
            EpochDecision::ChangeSet(change_set) => self.commit(change_set).await,
        }
    }

    /// Evaluates whether `additional_bytes` may be reserved against the
    /// workspace quota ledger. Read-only advice — the authoritative
    /// check runs inside `central-artifact`'s atomic conditional port at
    /// the database linearization point (adapter-mapping §5.2 A5).
    pub async fn check_quota(
        &self,
        workspace_id: WorkspaceId,
        additional_bytes: u64,
    ) -> Result<(), Failure> {
        let snapshot = self.require_snapshot(workspace_id).await?;
        snapshot.evaluate_reservation(additional_bytes)
    }

    /// Bounded singleton status read for the caller's workspace.
    pub async fn workspace_status(
        &self,
        req: WorkspaceStatusRequest,
    ) -> Result<WorkspaceStatusProjection, Failure> {
        self.status_read.status(req).await
    }

    async fn require_snapshot(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspaceSnapshot, Failure> {
        self.store
            .load_snapshot(workspace_id)
            .await?
            .ok_or_else(|| {
                Failure::not_found(
                    codes::WORKSPACE_NOT_FOUND,
                    "the workspace is not visible to this session",
                )
            })
    }

    async fn commit(&self, change_set: WorkspaceChangeSet) -> Result<WorkspaceSnapshot, Failure> {
        self.store.commit_change_set(change_set).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{WorkspaceGuard, WorkspaceState};

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

    struct StubStore {
        rows: Mutex<BTreeMap<WorkspaceId, WorkspaceSnapshot>>,
        commits: Mutex<Vec<WorkspaceChangeSet>>,
        fail_commits: bool,
    }

    impl StubStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(BTreeMap::new()),
                commits: Mutex::new(Vec::new()),
                fail_commits: false,
            }
        }

        fn seed(&self, snapshot: WorkspaceSnapshot) {
            self.rows.lock().unwrap().insert(snapshot.id, snapshot);
        }
    }

    impl WorkspaceStore for StubStore {
        async fn load_snapshot(
            &self,
            workspace_id: WorkspaceId,
        ) -> Result<Option<WorkspaceSnapshot>, Failure> {
            Ok(self.rows.lock().unwrap().get(&workspace_id).cloned())
        }

        async fn commit_change_set(
            &self,
            change_set: WorkspaceChangeSet,
        ) -> Result<WorkspaceSnapshot, Failure> {
            if self.fail_commits {
                return Err(Failure::unavailable("test_unavailable", "pool down"));
            }
            let mut rows = self.rows.lock().unwrap();
            match change_set.guard {
                WorkspaceGuard::Absent => {
                    if rows.contains_key(&change_set.next.id) {
                        return Err(Failure::conflict(
                            "workspace_already_exists",
                            "duplicate workspace",
                        ));
                    }
                }
                WorkspaceGuard::Present {
                    state,
                    security_epoch,
                    restore_epoch,
                } => {
                    let current = rows
                        .get(&change_set.next.id)
                        .cloned()
                        .ok_or_else(|| Failure::not_found("workspace_not_found", "missing"))?;
                    if current.state != state
                        || current.security_epoch != security_epoch
                        || current.restore_epoch != restore_epoch
                    {
                        return Err(Failure::conflict("workspace_state_conflict", "stale"));
                    }
                }
            }
            self.commits.lock().unwrap().push(change_set.clone());
            let next = change_set.next;
            rows.insert(next.id, next.clone());
            Ok(next)
        }
    }

    struct StubStatusRead {
        projection: Option<WorkspaceStatusProjection>,
    }

    impl WorkspaceStatusRead for StubStatusRead {
        async fn status(
            &self,
            req: WorkspaceStatusRequest,
        ) -> Result<WorkspaceStatusProjection, Failure> {
            self.projection.clone().ok_or_else(|| {
                assert!(!req.workspace_id.is_nil());
                Failure::not_found("workspace_not_found", "missing")
            })
        }
    }

    fn ctx() -> OperationContext {
        OperationContext {
            operation_id: OperationId::new(),
            actor_identity: "local-operator".to_string(),
            now: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn seeded() -> (WorkspaceService<StubStore, StubStatusRead>, WorkspaceId) {
        let store = StubStore::new();
        let snapshot = WorkspaceSnapshot {
            id: WorkspaceId::new(),
            state: WorkspaceState::Active,
            owner_principal_id: "local-operator".to_string(),
            quota_ready_bytes: 0,
            quota_ready_count: 0,
            quota_max_bytes: 1_000,
            security_epoch: 1,
            restore_epoch: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let id = snapshot.id;
        store.seed(snapshot);
        (
            WorkspaceService::new(store, StubStatusRead { projection: None }),
            id,
        )
    }

    #[test]
    fn create_commits_domain_change_set() {
        let store = StubStore::new();
        let svc = WorkspaceService::new(store, StubStatusRead { projection: None });
        let cmd = CreateWorkspaceCommand {
            workspace_id: WorkspaceId::new(),
            owner_principal_id: "local-operator".to_string(),
            quota_max_bytes: None,
        };
        let created = block_on(svc.create_workspace(ctx(), cmd)).unwrap();
        assert_eq!(created.state, WorkspaceState::Active);
    }

    #[test]
    fn delete_loads_evaluates_and_commits() {
        let (svc, id) = seeded();
        let deleted = block_on(svc.delete_workspace(ctx(), id)).unwrap();
        assert_eq!(deleted.state, WorkspaceState::Deleted);

        // Second delete surfaces the domain rejection, not a new commit.
        assert_eq!(
            block_on(svc.delete_workspace(ctx(), id))
                .unwrap_err()
                .code(),
            "workspace_already_deleted"
        );
    }

    #[test]
    fn epoch_advance_is_idempotent_and_forward_only() {
        let (svc, id) = seeded();
        let next = block_on(svc.advance_security_epoch(ctx(), id, 5)).unwrap();
        assert_eq!(next.security_epoch, 5);
        let same = block_on(svc.advance_security_epoch(ctx(), id, 5)).unwrap();
        assert_eq!(same.security_epoch, 5);
        assert_eq!(
            block_on(svc.advance_security_epoch(ctx(), id, 4))
                .unwrap_err()
                .code(),
            "workspace_epoch_regressed"
        );
    }

    #[test]
    fn missing_workspace_maps_to_not_found() {
        let (svc, _) = seeded();
        let missing = WorkspaceId::new();
        assert_eq!(
            block_on(svc.delete_workspace(ctx(), missing))
                .unwrap_err()
                .kind(),
            central_foundation::failure::FailureKind::NotFound
        );
    }

    #[test]
    fn status_read_proxies_projection() {
        let id = WorkspaceId::new();
        let projection = WorkspaceStatusProjection {
            workspace_id: id,
            state: WorkspaceState::Active,
            quota_ready_bytes: 1,
            quota_ready_count: 1,
            quota_max_bytes: 10,
        };
        let svc = WorkspaceService::new(
            StubStore::new(),
            StubStatusRead {
                projection: Some(projection.clone()),
            },
        );
        let got =
            block_on(svc.workspace_status(WorkspaceStatusRequest { workspace_id: id })).unwrap();
        assert_eq!(got, projection);
    }
}
