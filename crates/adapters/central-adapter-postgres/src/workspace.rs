//! PostgreSQL store for `central-workspace`: [`WorkspaceStore`] (typed
//! snapshot load + guarded change-set commit) and
//! [`WorkspaceStatusRead`] (the bounded status projection).
//!
//! `central.workspaces` carries no `version` column — concurrency is
//! pinned by the [`domain::WorkspaceGuard`]: `Absent` commits as a
//! plain insert (the `workspaces_pkey` duplicate surfaces as
//! `workspace_already_exists`), `Present` commits as a conditional
//! update whose `WHERE` clause repeats the expected `state`,
//! `security_epoch`, and `restore_epoch` — a stale decision zero-rows
//! the update and surfaces as `workspace_state_conflict`
//! (adapter-mapping §3.1/§7.2).
//!
//! `updated_at` is database-authoritative (`clock_timestamp()`); the
//! returned snapshot reflects the committed row including the stamp.

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;
use central_workspace::domain::{
    WorkspaceChangeSet, WorkspaceGuard, WorkspaceSnapshot, WorkspaceState, codes,
};
use central_workspace::port::WorkspaceStore;
use central_workspace::query::{
    WorkspaceStatusProjection, WorkspaceStatusRead, WorkspaceStatusRequest,
};
use sqlx::PgPool;

use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{PG_DATA_CORRUPT, i64_as_u64, u64_as_i64, uuid_of};

/// PostgreSQL-backed workspace store — a pool handle plus the leaf
/// statements below. `Clone` is cheap (the pool is shared).
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct WorkspaceRow {
    id: uuid::Uuid,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    state: String,
    owner_principal_id: String,
    quota_ready_bytes: i64,
    quota_ready_count: i64,
    quota_max_bytes: i64,
    security_epoch: i64,
    restore_epoch: i64,
}

impl TryFrom<WorkspaceRow> for WorkspaceSnapshot {
    type Error = Failure;

    fn try_from(row: WorkspaceRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: WorkspaceId::from_trusted_db_bytes(row.id.into_bytes()),
            state: WorkspaceState::parse(&row.state).map_err(|_| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored workspace state is outside the closed vocabulary",
                )
            })?,
            owner_principal_id: row.owner_principal_id,
            quota_ready_bytes: i64_as_u64(row.quota_ready_bytes, "quota_ready_bytes")?,
            quota_ready_count: i64_as_u64(row.quota_ready_count, "quota_ready_count")?,
            quota_max_bytes: i64_as_u64(row.quota_max_bytes, "quota_max_bytes")?,
            security_epoch: i64_as_u64(row.security_epoch, "security_epoch")?,
            restore_epoch: i64_as_u64(row.restore_epoch, "restore_epoch")?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl WorkspaceStore for Store {
    async fn load_snapshot(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceSnapshot>, Failure> {
        let row = sqlx::query_as!(
            WorkspaceRow,
            "SELECT id, created_at, updated_at, state, owner_principal_id, \
             quota_ready_bytes, quota_ready_count, quota_max_bytes, \
             security_epoch, restore_epoch \
             FROM central.workspaces WHERE id = $1",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("workspace: load snapshot")?;
        row.map(WorkspaceSnapshot::try_from).transpose()
    }

    async fn commit_change_set(
        &self,
        change_set: WorkspaceChangeSet,
    ) -> Result<WorkspaceSnapshot, Failure> {
        let next = change_set.next;
        let state = next.state.as_str();
        let quota_ready_bytes = u64_as_i64(next.quota_ready_bytes, codes::WORKSPACE_INVALID)?;
        let quota_ready_count = u64_as_i64(next.quota_ready_count, codes::WORKSPACE_INVALID)?;
        let quota_max_bytes = u64_as_i64(next.quota_max_bytes, codes::WORKSPACE_INVALID)?;
        let security_epoch = u64_as_i64(next.security_epoch, codes::WORKSPACE_INVALID)?;
        let restore_epoch = u64_as_i64(next.restore_epoch, codes::WORKSPACE_INVALID)?;

        match change_set.guard {
            WorkspaceGuard::Absent => {
                // Provisioning path: the pkey duplicate is the only
                // guard — map it to the domain's already-exists
                // conflict rather than leaking the SQLSTATE.
                sqlx::query_as!(
                    WorkspaceRow,
                    "INSERT INTO central.workspaces \
                     (id, state, owner_principal_id, quota_ready_bytes, \
                      quota_ready_count, quota_max_bytes, security_epoch, \
                      restore_epoch, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                             clock_timestamp(), clock_timestamp()) \
                     RETURNING id, created_at, updated_at, state, owner_principal_id, \
                     quota_ready_bytes, quota_ready_count, quota_max_bytes, \
                     security_epoch, restore_epoch",
                    uuid_of(next.id.as_bytes()),
                    state,
                    next.owner_principal_id,
                    quota_ready_bytes,
                    quota_ready_count,
                    quota_max_bytes,
                    security_epoch,
                    restore_epoch,
                )
                .fetch_one(&self.pool)
                .await
                .map_err(|err| match classify_sqlx(&err) {
                    f if f.kind() == central_foundation::failure::FailureKind::Conflict => {
                        Failure::conflict(
                            codes::WORKSPACE_ALREADY_EXISTS,
                            "the workspace row already exists",
                        )
                    }
                    f => f,
                })
                .map(WorkspaceSnapshot::try_from)?
            }
            WorkspaceGuard::Present {
                state: expected_state,
                security_epoch: expected_security_epoch,
                restore_epoch: expected_restore_epoch,
            } => {
                let row = sqlx::query_as!(
                    WorkspaceRow,
                    "UPDATE central.workspaces SET \
                     state = $2, owner_principal_id = $3, \
                     quota_ready_bytes = $4, quota_ready_count = $5, \
                     quota_max_bytes = $6, security_epoch = $7, \
                     restore_epoch = $8, updated_at = clock_timestamp() \
                     WHERE id = $1 AND state = $9 \
                     AND security_epoch = $10 AND restore_epoch = $11 \
                     RETURNING id, created_at, updated_at, state, owner_principal_id, \
                     quota_ready_bytes, quota_ready_count, quota_max_bytes, \
                     security_epoch, restore_epoch",
                    uuid_of(next.id.as_bytes()),
                    state,
                    next.owner_principal_id,
                    quota_ready_bytes,
                    quota_ready_count,
                    quota_max_bytes,
                    security_epoch,
                    restore_epoch,
                    expected_state.as_str(),
                    u64_as_i64(expected_security_epoch, codes::WORKSPACE_INVALID)?,
                    u64_as_i64(expected_restore_epoch, codes::WORKSPACE_INVALID)?,
                )
                .fetch_optional(&self.pool)
                .await
                .ctx("workspace: commit guarded change set")?;
                let row = row.ok_or_else(|| {
                    Failure::conflict(
                        codes::WORKSPACE_STATE_CONFLICT,
                        "the workspace state or epochs changed since the decision",
                    )
                })?;
                WorkspaceSnapshot::try_from(row)
            }
        }
    }
}

impl WorkspaceStatusRead for Store {
    async fn status(
        &self,
        req: WorkspaceStatusRequest,
    ) -> Result<WorkspaceStatusProjection, Failure> {
        let row = sqlx::query!(
            "SELECT id, state, quota_ready_bytes, quota_ready_count, quota_max_bytes \
             FROM central.workspaces WHERE id = $1",
            uuid_of(req.workspace_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("workspace: read status")?;
        let row = row.ok_or_else(|| {
            Failure::not_found(codes::WORKSPACE_NOT_FOUND, "the workspace does not exist")
        })?;
        Ok(WorkspaceStatusProjection {
            workspace_id: WorkspaceId::from_trusted_db_bytes(row.id.into_bytes()),
            state: WorkspaceState::parse(&row.state).map_err(|_| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored workspace state is outside the closed vocabulary",
                )
            })?,
            quota_ready_bytes: i64_as_u64(row.quota_ready_bytes, "quota_ready_bytes")?,
            quota_ready_count: i64_as_u64(row.quota_ready_count, "quota_ready_count")?,
            quota_max_bytes: i64_as_u64(row.quota_max_bytes, "quota_max_bytes")?,
        })
    }
}
