//! `EpochMarkerRead` — the serve-time epoch monitor's leaf: the
//! latest `central.epoch_markers` pair, read-only.
//!
//! The pair is a deployment-level fact (upstream's `serveEpochMonitor`
//! polled it straight off the runtime pool), not an execution-domain
//! contract, so the trait lives in the adapter next to the other
//! monitor-facing read (`metrics.rs`) rather than in
//! `central-execution::port`. The kernel's `ServeEpochMonitor` holds
//! this port so no `central.*` SQL lives in the kernel crate.

use central_foundation::failure::Failure;

use super::Store;
use crate::error::SqlxContext;

/// One `central.epoch_markers` read — the stored `bigint` pair with
/// `COALESCE(…, 0)` applied, the monitor leaf verbatim; the caller
/// compares before narrowing to `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochMarkerPair {
    /// `COALESCE(security_epoch, 0)`.
    pub security: i64,
    /// `COALESCE(restore_epoch, 0)`.
    pub restore: i64,
}

/// `EpochMarkerRead` — the narrow read port the serve epoch monitor
/// consumes (upstream `serveEpochMonitor`'s per-tick query).
#[trait_variant::make(Send)]
pub trait EpochMarkerRead {
    /// The newest marker row by `updated_at` — the monitor's
    /// `ORDER BY updated_at DESC LIMIT 1` leaf.
    async fn read_epoch_markers(&self) -> Result<EpochMarkerPair, Failure>;
}

impl EpochMarkerRead for Store {
    async fn read_epoch_markers(&self) -> Result<EpochMarkerPair, Failure> {
        let row = sqlx::query!(
            "SELECT COALESCE(security_epoch, 0) AS \"security!\", \
             COALESCE(restore_epoch, 0) AS \"restore!\" \
             FROM central.epoch_markers ORDER BY updated_at DESC LIMIT 1",
        )
        .fetch_one(&self.pool)
        .await
        .ctx("execution: read epoch markers")?;
        Ok(EpochMarkerPair {
            security: row.security,
            restore: row.restore,
        })
    }
}
