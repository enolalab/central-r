//! Runtime-grant application and post-`pg_restore` grant convergence.
//!
//! `reapply_incremental_runtime_grants.sql` is the trusted static script
//! that reproduces the upstream `ReapplyRuntimeGrants` sequence verbatim:
//! the baseline grant set, every migration's incremental grants, the b09
//! provider-turn table-level UPDATE revocations followed by the column-level
//! UPDATE grants, and the b36/b37 DELETE grants — under its own
//! `begin`/`commit`. `central.recovery_bootstrap_registrations` (b26) is
//! deliberately excluded exactly as upstream excludes it: `central_runtime`
//! never holds any privilege on it.

use sqlx::PgConnection;

use super::Result;
use super::manifest::REAPPLY_RUNTIME_GRANTS_SQL;
use super::verify_shape::{BASELINE_MUTATION_GRANTS, BASELINE_TABLES};
use crate::error::SqlxContext;

/// `ReapplyRuntimeGrants` — re-sync `central_runtime`'s schema/table
/// privileges against the full expected set on an already-migrated target.
/// Idempotent and write-free besides the grants themselves; safe to run
/// after every restore.
///
/// # Errors
/// Any grant statement fails (e.g. a referenced table is absent).
pub async fn reapply_runtime_grants(conn: &mut PgConnection) -> Result<()> {
    sqlx::raw_sql(REAPPLY_RUNTIME_GRANTS_SQL)
        .execute(&mut *conn)
        .await
        .ctx("reapply runtime grants")?;
    Ok(())
}

/// `baseline.go: applyRuntimeGrants` — just the baseline grant set (used by
/// the legacy version-zero repair path; the baseline file itself issues
/// these grants verbatim on a fresh install).
pub(crate) async fn apply_runtime_grants(conn: &mut PgConnection) -> Result<()> {
    sqlx::raw_sql("begin;\nSET LOCAL synchronous_commit = on;")
        .execute(&mut *conn)
        .await
        .ctx("baseline: begin runtime grants")?;
    let mut result = apply_runtime_grants_inner(conn).await;
    if result.is_ok() {
        result = sqlx::raw_sql("commit;")
            .execute(&mut *conn)
            .await
            .ctx("baseline: commit runtime grants")
            .map(|_| ());
    } else {
        let _ = sqlx::raw_sql("rollback;").execute(&mut *conn).await;
    }
    result
}

async fn apply_runtime_grants_inner(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("GRANT USAGE ON SCHEMA central TO central_runtime")
        .execute(&mut *conn)
        .await
        .ctx("baseline: grant schema usage")?;
    // Table/privilege names are trusted static constants — the upstream
    // grant statements are built with the same interpolation.
    for table in BASELINE_TABLES {
        let sql = format!("GRANT SELECT ON central.{table} TO central_runtime");
        sqlx::query(&sql)
            .execute(&mut *conn)
            .await
            .ctx("baseline: grant select")?;
    }
    for (table, privileges) in BASELINE_MUTATION_GRANTS {
        for privilege in privileges {
            let sql = format!("GRANT {privilege} ON central.{table} TO central_runtime");
            sqlx::query(&sql)
                .execute(&mut *conn)
                .await
                .ctx("baseline: grant mutation")?;
        }
    }
    Ok(())
}
