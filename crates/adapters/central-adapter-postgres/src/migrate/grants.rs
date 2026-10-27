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

/// `b26RecoveryBootstrapDDL` — v26's own idempotent DDL, verbatim from
/// `b26_recovery_bootstrap_registration.go`'s `b26RecoveryBootstrapDDL()`:
/// the table, its unique generation index, and the two `REVOKE`s that
/// keep `central_runtime` off it.
const RECOVERY_BOOTSTRAP_REGISTRATIONS_DDL: [&str; 4] = [
    "CREATE TABLE IF NOT EXISTS central.recovery_bootstrap_registrations (\n\t\t\toperation_id uuid PRIMARY KEY REFERENCES central.recovery_operations(operation_id) ON DELETE RESTRICT,\n\t\t\tdraft_id uuid NOT NULL UNIQUE,\n\t\t\tcandidate_id uuid NOT NULL UNIQUE,\n\t\t\tgeneration bigint NOT NULL CHECK (generation > 0),\n\t\t\tverifier_hash bytea NOT NULL CHECK (octet_length(verifier_hash) = 32),\n\t\t\tcandidate_digest bytea NOT NULL CHECK (octet_length(candidate_digest) = 32),\n\t\t\tbroker_receipt_hash bytea NOT NULL CHECK (octet_length(broker_receipt_hash) = 32),\n\t\t\tdatabase_receipt_hash bytea NOT NULL CHECK (octet_length(database_receipt_hash) = 32),\n\t\t\tregistered_at timestamptz NOT NULL\n\t\t)",
    "CREATE UNIQUE INDEX IF NOT EXISTS recovery_bootstrap_registrations_generation_idx\n\t\t\tON central.recovery_bootstrap_registrations (generation)",
    "REVOKE ALL ON central.recovery_bootstrap_registrations FROM PUBLIC",
    "REVOKE ALL ON central.recovery_bootstrap_registrations FROM central_runtime",
];

/// `RecreateRecoveryBootstrapRegistrationsTable` — re-runs v26's own
/// idempotent DDL directly, without going through the migration-chain
/// classifier.
///
/// SC-DEF-65: `central-restore`'s `FkDroppingRestoreDatabase` (SC-DEF-60)
/// `DROP`s this table before `pg_restore` runs, because it is
/// deliberately excluded from every backup (SC-DEF-52) and `pg_restore`'s
/// own `--clean` cycle cannot otherwise complete. Nothing before this fix
/// ever recreated it within that same restore run, yet the C05 authority
/// reset (`RecoveryAuditStore::reset_database_authority`/
/// `finalize_database_authority_reset`) reads from and inserts into this
/// exact table before the operation ever reaches `ready` — long before an
/// operator would run `central migrate up` and let the chain's own path
/// recreate it the ordinary way.
///
/// Calling the migration chain itself here would not work: on an
/// already-fully-migrated target (exactly the state a restored database is
/// in) its fast path verifies the existing shape and fails closed rather
/// than repairing anything — the identical trap SC-DEF-61's first attempt
/// at reapplying runtime grants hit. Running v26's own DDL directly,
/// exactly as done here, is the same fix shape SC-DEF-61 settled on.
///
/// # Errors
/// Any DDL statement or the surrounding transaction fails.
pub async fn recreate_recovery_bootstrap_registrations_table(
    conn: &mut PgConnection,
) -> Result<()> {
    sqlx::raw_sql("begin;")
        .execute(&mut *conn)
        .await
        .ctx("b26 recovery bootstrap: begin recreate")?;
    let mut outcome: Result<()> = Ok(());
    for (index, statement) in RECOVERY_BOOTSTRAP_REGISTRATIONS_DDL.iter().enumerate() {
        if let Err(e) = sqlx::raw_sql(statement).execute(&mut *conn).await {
            let label = match index {
                0 => "b26 recovery bootstrap: recreate statement 0",
                1 => "b26 recovery bootstrap: recreate statement 1",
                2 => "b26 recovery bootstrap: recreate statement 2",
                _ => "b26 recovery bootstrap: recreate statement 3",
            };
            outcome = Err::<(), sqlx::Error>(e).ctx(label);
            break;
        }
    }
    if outcome.is_ok() {
        outcome = sqlx::raw_sql("commit;")
            .execute(&mut *conn)
            .await
            .ctx("b26 recovery bootstrap: commit recreate")
            .map(|_| ());
    } else {
        let _ = sqlx::raw_sql("rollback;").execute(&mut *conn).await;
    }
    outcome
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
