//! `Inspector` — read-only migration facts plus `verify_serve_baseline`,
//! the authoritative serve-readiness audit (`inspector.go`).

use sqlx::{Connection as _, PgConnection, PgPool, Row};

use super::verify_shape::{
    schema_exists, table_exists, verify_baseline_shape, verify_full_chain, verify_migration_shapes,
};
use super::{
    DirtyEvidence, EpochMarker, EpochMarkers, PostgresMigrationFacts, Result, VersionChecksum,
};
use crate::error::SqlxContext;
use central_foundation::failure::Failure;

fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}

enum Conn<'a> {
    Dedicated(&'a mut PgConnection),
    Pool(PgPool),
}

/// Read-only inspector. `for_connection` keeps operator inspection on the
/// migration operator's one non-rebinding session (upstream
/// `NewInspectorForConn`); `connect` uses a max-1 pool (upstream
/// `NewInspector`).
pub struct Inspector<'a> {
    conn: Conn<'a>,
}

impl<'a> Inspector<'a> {
    /// Inspection on a dedicated, borrowed session.
    pub fn for_connection(conn: &'a mut PgConnection) -> Self {
        Self {
            conn: Conn::Dedicated(conn),
        }
    }

    /// Inspection through a max-1 pool (`NewInspector`).
    ///
    /// # Errors
    /// The pool cannot connect.
    pub async fn connect(dsn: &str) -> Result<Inspector<'static>> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(dsn)
            .await
            .ctx("inspector: connect")?;
        Ok(Inspector {
            conn: Conn::Pool(pool),
        })
    }

    /// `Inspect` — read-only [`PostgresMigrationFacts`].
    ///
    /// # Errors
    /// Pool acquisition or any inspection query fails, or a dirty record or
    /// non-terminal chain is observed.
    pub async fn inspect(&mut self) -> Result<PostgresMigrationFacts> {
        match &mut self.conn {
            Conn::Dedicated(conn) => inspect_facts(conn).await,
            Conn::Pool(pool) => {
                let mut conn = pool.acquire().await.ctx("inspector: acquire conn")?;
                inspect_facts(&mut conn).await
            }
        }
    }

    fn dedicated_conn(&mut self) -> Option<&mut PgConnection> {
        match &mut self.conn {
            Conn::Dedicated(conn) => Some(conn),
            Conn::Pool(_) => None,
        }
    }

    /// `VerifyServeBaseline` — the authoritative, read-only verification
    /// required before serve may claim readiness: `SET TRANSACTION READ
    /// ONLY`, `current_user == 'central_runtime'`, the exact `v0 → v37`
    /// chain + checksum ledger, the baseline shape, every migration's
    /// owned-object shape, and exactly one epoch marker. Requires a
    /// dedicated connection (upstream's `i.conn != nil` gate).
    ///
    /// # Errors
    /// No dedicated connection, wrong role, or any shape/chain check fails.
    pub async fn verify_serve_baseline(&mut self) -> Result<()> {
        let Some(conn) = self.dedicated_conn() else {
            return Err(invalid(
                "inspector_requires_dedicated_connection",
                "inspector: serve verification requires dedicated connection",
            ));
        };
        let mut tx = conn
            .begin()
            .await
            .ctx("inspector: begin serve verification")?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .ctx("inspector: set serve verification read only")?;
        let role: String = sqlx::query("SELECT current_user")
            .fetch_one(&mut *tx)
            .await
            .ctx("inspector: verify serve role")
            .map(|row| row.get::<String, _>(0))?;
        if role != "central_runtime" {
            let _ = tx.rollback().await;
            return Err(invalid(
                "inspector_serve_role",
                "inspector: serve role is not central_runtime",
            ));
        }
        let result = async {
            verify_baseline_shape(&mut tx, false)
                .await
                .map_err(|err| wrap("inspector: serve baseline shape", err))?;
            verify_full_chain(&mut tx)
                .await
                .map_err(|err| wrap("inspector: unsupported migration chain", err))?;
            verify_migration_shapes(&mut tx)
                .await
                .map_err(|err| wrap("inspector: migration schema shape", err))?;
            let epoch_rows: i64 = sqlx::query("SELECT count(*) FROM central.epoch_markers")
                .fetch_one(&mut *tx)
                .await
                .ctx("inspector: verify epochs")
                .map(|row| row.get::<i64, _>(0))?;
            if epoch_rows != 1 {
                return Err(invalid(
                    "inspector_epoch_state",
                    "inspector: unsupported epoch state",
                ));
            }
            Ok(())
        }
        .await;
        let _ = tx.rollback().await;
        result
    }
}

async fn inspect_facts(conn: &mut PgConnection) -> Result<PostgresMigrationFacts> {
    let mut tx = conn.begin().await.ctx("inspector: begin tx")?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .ctx("inspector: set read only")?;
    let result = inspect_facts_inner(&mut tx).await;
    let _ = tx.rollback().await;
    result
}

async fn inspect_facts_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<PostgresMigrationFacts> {
    if !schema_exists(tx)
        .await
        .map_err(|e| wrap("inspector: schema check", e))?
    {
        return Ok(PostgresMigrationFacts {
            initialized: false,
            applied_versions: Vec::new(),
            dirty: None,
            epochs: EpochMarkers::default(),
        });
    }
    let versions = applied_versions(tx)
        .await
        .map_err(|e| wrap("inspector: applied versions", e))?;
    if let Some(dirty) = dirty_version(tx)
        .await
        .map_err(|e| wrap("inspector: dirty check", e))?
    {
        return Err(invalid(
            "inspector_dirty_migration",
            format!("inspector: dirty migration version {}", dirty.version),
        ));
    }
    verify_full_chain(tx)
        .await
        .map_err(|e| wrap("inspector: migration checksum history", e))?;
    let epochs = epoch_markers(tx)
        .await
        .map_err(|e| wrap("inspector: epochs", e))?;
    Ok(PostgresMigrationFacts {
        initialized: !versions.is_empty(),
        applied_versions: versions,
        dirty: None,
        epochs,
    })
}

async fn applied_versions(conn: &mut PgConnection) -> Result<Vec<VersionChecksum>> {
    if !table_exists(conn, "schema_migrations").await? {
        return Ok(Vec::new());
    }
    sqlx::query("SELECT version, checksum FROM central.schema_migrations ORDER BY version ASC")
        .fetch_all(&mut *conn)
        .await
        .ctx("inspector: applied versions")
        .map(|rows| {
            rows.iter()
                .map(|row| VersionChecksum {
                    version: row.get::<i64, _>(0) as i32,
                    checksum: row.get::<String, _>(1),
                })
                .collect()
        })
}

async fn dirty_version(conn: &mut PgConnection) -> Result<Option<DirtyEvidence>> {
    if !table_exists(conn, "schema_migrations").await? {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT version, COALESCE(checksum, '') FROM central.schema_migrations \
         WHERE dirty = true ORDER BY version DESC LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await
    .ctx("inspector: dirty check")?;
    Ok(row.map(|row| DirtyEvidence {
        version: row.get::<i64, _>(0) as i32,
        reason: row.get::<String, _>(1),
        detected_at: time::OffsetDateTime::now_utc(),
    }))
}

async fn epoch_markers(conn: &mut PgConnection) -> Result<EpochMarkers> {
    let mut epochs = EpochMarkers::default();
    if !table_exists(conn, "epoch_markers").await? {
        return Ok(epochs);
    }
    let row = sqlx::query(
        "SELECT COALESCE(restore_epoch, 0), COALESCE(security_epoch, 0) \
         FROM central.epoch_markers ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await
    .ctx("inspector: epochs")?;
    if let Some(row) = row {
        epochs.migration = EpochMarker {
            epoch: row.get::<i64, _>(0) as u64,
            digest: String::new(),
        };
        epochs.security = EpochMarker {
            epoch: row.get::<i64, _>(1) as u64,
            digest: String::new(),
        };
    }
    Ok(epochs)
}

fn wrap(context: &'static str, err: Failure) -> Failure {
    Failure::new(
        err.kind(),
        err.code(),
        format!("{context}: {}", err.message()),
    )
}
