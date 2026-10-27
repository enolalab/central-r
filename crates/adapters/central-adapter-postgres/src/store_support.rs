//! Shared persistence-boundary helpers for the store modules.
//!
//! These functions exist for exactly two jobs: converting identity
//! newtypes to and from `uuid` column values at the trusted adapter
//! boundary, and converting the domain's `u64` counters/epochs to and
//! from PostgreSQL `bigint`. Everything else stays in the leaf modules
//! so each store reads as one table's contract.

use central_foundation::failure::Failure;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

/// Stable machine code for durable rows that fail domain
/// reconstruction — a stored row that cannot re-validate is corrupt,
/// never a caller error.
pub(crate) const PG_DATA_CORRUPT: &str = "pg_data_corrupt";

/// `u8; 16` identity bytes → `uuid` column value.
pub(crate) fn uuid_of(bytes: &[u8; 16]) -> uuid::Uuid {
    uuid::Uuid::from_bytes(*bytes)
}

/// Optional identity bytes → optional `uuid` column value.
pub(crate) fn opt_uuid_of<T>(id: Option<T>, bytes: impl Fn(&T) -> &[u8; 16]) -> Option<uuid::Uuid> {
    id.map(|i| uuid_of(bytes(&i)))
}

/// Domain `u64` → `bigint` bind. Values above `i64::MAX` cannot be
/// represented — a caller-level `invalid`, since the domain's contract
/// is the `bigint` range.
pub(crate) fn u64_as_i64(value: u64, code: &'static str) -> Result<i64, Failure> {
    i64::try_from(value)
        .map_err(|_| Failure::invalid(code, "the value does not fit the bigint column range"))
}

/// `bigint` column value → domain `u64`. A negative stored value is
/// corrupt durable state — `internal`, not a caller failure.
pub(crate) fn i64_as_u64(value: i64, what: &'static str) -> Result<u64, Failure> {
    u64::try_from(value).map_err(|_| {
        Failure::internal(
            PG_DATA_CORRUPT,
            format!("a stored {what} is outside the u64 range"),
        )
    })
}

/// `usize` limit → `bigint` bind (page sizes are bounded well under
/// `i64::MAX` by the request contracts).
pub(crate) fn usize_as_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Begins a `READ COMMITTED` transaction with the upstream advisory
/// timeouts installed (eventjournal `Append`: `lock_timeout = 2s`,
/// `statement_timeout = 5s`, `idle_in_transaction_session_timeout =
/// 10s`). Every multi-statement commit coordinator in this adapter
/// goes through here so the lock-ordering discipline runs under one
/// bounded lease.
pub(crate) async fn begin_tx(pool: &PgPool) -> Result<Transaction<'static, Postgres>, Failure> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| crate::error::classify_sqlx(&e))?;
    for (name, value) in [
        ("lock_timeout", "2s"),
        ("statement_timeout", "5s"),
        ("idle_in_transaction_session_timeout", "10s"),
    ] {
        // Session/transaction configuration, not an application leaf
        // query — `set_config` cannot be represented through the
        // compile-checked macros (its name is a bound parameter).
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(|e| crate::error::classify_sqlx(&e))?;
    }
    Ok(tx)
}

// ---------------------------------------------------------------------------
// `BlockingConn` — the backup/recovery sync-port async bridge.
// ---------------------------------------------------------------------------

/// One dedicated [`PgConnection`] plus the private single-worker runtime
/// that drives it for the `central-backup` *synchronous* port traits.
///
/// Upstream binds the recovery stores to one dedicated `*pgx.Conn` (the
/// C04 target exclusion lives on that same session); the Rust ports are
/// deliberately synchronous (`central_backup::port` — "an adapter that
/// needs async I/O owns the bridging"), so this wrapper is that bridge:
/// [`Self::run`] holds the connection lock for the entire call and drives
/// the future to completion on the store's own runtime.
///
/// `run` must be invoked from a thread that is **not** inside an ambient
/// tokio runtime — `Runtime::block_on` panics inside one. The backup and
/// restore workers drive the sync coordinators on plain OS threads, so
/// that is the intended call context.
pub(crate) struct BlockingConn {
    conn: std::sync::Mutex<PgConnection>,
    runtime: tokio::runtime::Runtime,
}

impl BlockingConn {
    /// Wraps `conn` (a dedicated `central_migration`/`central_runtime`
    /// session) with a private one-worker runtime.
    ///
    /// # Errors
    /// `internal` when the runtime cannot be built.
    pub(crate) fn new(conn: PgConnection) -> Result<Self, Failure> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("central-pg-backup")
            .build()
            .map_err(|_| {
                Failure::internal(
                    crate::error::codes::PG_ADAPTER_ERROR,
                    "the backup/recovery bridge runtime is unavailable",
                )
            })?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
            runtime,
        })
    }

    /// Builds the bridge **and** connects inside it. A `PgConnection`
    /// binds its socket to the runtime reactor that performed the
    /// connect, so a connection made on an ambient runtime cannot later
    /// be driven here ("a Tokio 1.x context was found, but it is being
    /// shutdown"). [`Self::new`] remains for connections produced by a
    /// runtime the caller itself keeps alive for the connection's
    /// lifetime; composition code that only has a connect future should
    /// use this constructor.
    ///
    /// # Errors
    /// `internal` when the runtime cannot be built; whatever `connect`
    /// returns otherwise.
    #[cfg(test)]
    pub(crate) fn new_connecting<F, Fut>(connect: F) -> Result<Self, Failure>
    where
        F: FnOnce() -> Fut,
        Fut: core::future::Future<Output = Result<PgConnection, Failure>>,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("central-pg-backup")
            .build()
            .map_err(|_| {
                Failure::internal(
                    crate::error::codes::PG_ADAPTER_ERROR,
                    "the backup/recovery bridge runtime is unavailable",
                )
            })?;
        let conn = runtime.block_on(connect())?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
            runtime,
        })
    }

    /// Runs `f(&mut PgConnection)` to completion, holding the session
    /// lock for the whole call — the upstream dedicated-conn
    /// serialization (`*pgx.Conn` is not concurrent-safe either). A
    /// poisoned mutex is recovered: the connection itself is not
    /// corrupted by a panic above it.
    ///
    /// # Errors
    /// Whatever `f` returns.
    pub(crate) fn run<T, F>(&self, f: F) -> Result<T, Failure>
    where
        F: for<'a> FnOnce(
            &'a mut PgConnection,
        ) -> core::pin::Pin<
            Box<dyn core::future::Future<Output = Result<T, Failure>> + 'a>,
        >,
    {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        self.runtime.block_on(f(&mut guard))
    }
}
