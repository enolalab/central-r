//! `census.go` — the C01 database capacity census.
//!
//! [`CapacityCensusReader`] runs the exact ready-Artifact predicate used
//! by the paginated inventory source on one dedicated backup connection,
//! so the admission census and the inventory it bounds are the same set.

use central_foundation::failure::Failure;
use std::sync::Arc;

use crate::error::SqlxContext as _;
use crate::store_support::BlockingConn;

/// `ErrCapacityCensus` — deliberately stable and locator-free.
/// PostgreSQL diagnostics may contain a target or connection string and
/// never cross this recovery boundary.
fn capacity_census_unavailable() -> Failure {
    Failure::unavailable(
        "recovery_capacity_census",
        "recovery PostgreSQL capacity census is unavailable",
    )
}

/// `CapacityCensus` is a single database-derived admission observation.
/// It contains no object key, target locator, or credential — upstream
/// `port.BackupDatabaseCensus` (the capability's own struct; re-exported
/// here so this module stays the census seam).
pub use central_backup::port::BackupDatabaseCensus;

/// `CapacityCensusReader` — one dedicated runtime session, shared
/// with the rest of the C01 composition through the same `Arc`.
pub struct CapacityCensusReader {
    conn: Arc<BlockingConn>,
}

impl CapacityCensusReader {
    /// `NewCapacityCensusReader`.
    ///
    /// # Errors
    /// `recovery_capacity_census` never fires here — the constructor
    /// is infallible over an already-bridged session.
    pub fn new(conn: Arc<BlockingConn>) -> Result<Self, Failure> {
        Ok(Self { conn })
    }

    /// `ReadBackupCapacity` — the `backupCapacityCensusSQL` observation:
    /// one instant, the database size, and the ready-predicate sum+count.
    ///
    /// # Errors
    /// `recovery_capacity_census` on any read failure or out-of-range
    /// counter.
    pub fn read_backup_capacity(&self) -> Result<BackupDatabaseCensus, Failure> {
        let row = self.conn.run(|conn| {
            Box::pin(async move {
                sqlx::query!(
                    "SELECT clock_timestamp() AS \"database_time!\",
                        pg_database_size(current_database())::bigint AS \"database_bytes!\",
                        COALESCE(SUM(size), 0)::bigint AS \"object_bytes!\",
                        COUNT(*)::bigint AS \"record_count!\"
                    FROM central.artifacts
                    WHERE state = 'ready' AND delete_intent_at IS NULL"
                )
                .fetch_one(&mut *conn)
                .await
                .ctx("backup: read capacity census")
            })
        })?;
        if crate::backup::is_zero_time(row.database_time)
            || row.database_bytes < 0
            || row.object_bytes < 0
            || row.record_count < 0
        {
            return Err(capacity_census_unavailable());
        }
        Ok(BackupDatabaseCensus {
            database_time: row.database_time.to_offset(time::UtcOffset::UTC),
            database_bytes: u64::try_from(row.database_bytes)
                .map_err(|_| capacity_census_unavailable())?,
            object_bytes: u64::try_from(row.object_bytes)
                .map_err(|_| capacity_census_unavailable())?,
            record_count: u64::try_from(row.record_count)
                .map_err(|_| capacity_census_unavailable())?,
        })
    }
}

impl central_backup::port::BackupDatabaseCensusReader for CapacityCensusReader {
    /// `ReadBackupCapacity` — the inherent census read above, surfaced
    /// through the port so the worker composition hands the reader to
    /// the environment as a trait object.
    fn read_backup_capacity(&self) -> Result<BackupDatabaseCensus, Failure> {
        Self::read_backup_capacity(self)
    }
}
