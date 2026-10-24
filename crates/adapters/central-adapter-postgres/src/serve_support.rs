//! `serve_support` — the checked statements the `central serve`
//! composition runs on its dedicated, non-borrowable sessions: the
//! post-connect `central_runtime` role probe (upstream
//! `openDedicatedConn`) and the session-scoped control-lock advisory
//! pair (upstream `pgControlLock`/`pgControlLockLease`).
//!
//! The kernel keeps ownership of the `PgConnection`, the heartbeat
//! cadence, and the close ordering — this module holds only the SQL
//! leaves so every statement the serve composition issues stays
//! compile-time checked inside the adapter (the §2.4 invariant that
//! no `central.*`/unchecked SQL lives outside
//! `central-adapter-postgres`).

use central_foundation::failure::Failure;
use sqlx::PgConnection;

use crate::error::SqlxContext;

/// `SELECT current_user` — the post-connect authenticated-role probe
/// upstream's `openDedicatedConn` runs on both dedicated serve
/// sessions; the caller compares the returned name against
/// `central_runtime` (a mismatch is the caller's refusal, not a
/// driver failure).
///
/// # Errors
/// The classified driver failure when the probe fails.
pub async fn role_check(conn: &mut PgConnection) -> Result<String, Failure> {
    sqlx::query_scalar!("SELECT current_user AS \"role!\"")
        .fetch_one(&mut *conn)
        .await
        .ctx("serve: role check")
}

/// `pgControlLock`'s checked leaves — the session-scoped advisory
/// lock/unlock pair bound to one deployment-wide key. Callers own the
/// dedicated connection, the acquire deadline, the heartbeat, and the
/// close ordering; this type only owns the statements.
#[derive(Debug, Clone, Copy)]
pub struct ControlLock {
    key: i64,
}

impl ControlLock {
    /// Binds the advisory pair to `key` (the kernel passes upstream's
    /// `backup.ServeTargetExclusionLockKey`).
    #[must_use]
    pub const fn new(key: i64) -> Self {
        Self { key }
    }

    /// `SELECT pg_advisory_lock($1)` — blocks inside the session until
    /// the singleton is held; the caller's startup deadline bounds the
    /// wait and its heartbeat detects a dead control session
    /// afterwards.
    ///
    /// # Errors
    /// The classified driver failure when the acquire fails.
    pub async fn acquire(&self, conn: &mut PgConnection) -> Result<(), Failure> {
        sqlx::query!("SELECT pg_advisory_lock($1)", self.key)
            .fetch_one(&mut *conn)
            .await
            .ctx("serve: acquire control lock")?;
        Ok(())
    }

    /// `SELECT pg_advisory_unlock($1)` — releases the lock. The
    /// returned "was held" flag is advisory, exactly as upstream's
    /// lease treats it: an `Ok` is a clean close either way.
    ///
    /// # Errors
    /// The classified driver failure when the release fails.
    pub async fn release(&self, conn: &mut PgConnection) -> Result<(), Failure> {
        sqlx::query!("SELECT pg_advisory_unlock($1)", self.key)
            .fetch_one(&mut *conn)
            .await
            .ctx("serve: release control lock")?;
        Ok(())
    }
}
