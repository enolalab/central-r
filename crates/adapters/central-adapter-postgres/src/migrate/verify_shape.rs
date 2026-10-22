//! Shape verification: the `schema_migrations`/`migration_checksums`
//! ledger, the chain classifier, the baseline (`v0`) shape checks ported
//! verbatim from `baseline.go`, and the per-migration owned-object checks
//! used by `verify_serve_baseline`.
//!
//! The per-migration checks are presence-based — every relation, column,
//! index, named constraint, function, trigger, runtime grant, column grant,
//! and revocation the embedded corpus produces is asserted (and every
//! net-dropped object asserted absent) — rather than upstream's
//! canonical-definition inventory. See the task report for the fidelity
//! trade-off.

use sqlx::{PgConnection, Row};

use super::shape_spec::MIGRATION_SHAPES;
use super::{Result, WITH_V15_CHAIN, WITHOUT_V15_CHAIN};
use crate::error::SqlxContext;
use central_foundation::failure::Failure;

fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}

/// Does the `central` schema exist?
pub(crate) async fn schema_exists(conn: &mut PgConnection) -> Result<bool> {
    sqlx::query("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'central')")
        .fetch_one(&mut *conn)
        .await
        .ctx("baseline: check existing schema")
        .map(|row| row.get::<bool, _>(0))
}

/// Does `central.<table>` exist? Uses `to_regclass` rather than
/// `information_schema` so tables the role holds no privilege on (e.g.
/// `recovery_bootstrap_registrations`) are still observed.
pub(crate) async fn table_exists(conn: &mut PgConnection, table: &str) -> Result<bool> {
    sqlx::query("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("central.{table}"))
        .fetch_one(&mut *conn)
        .await
        .ctx("inspect table")
        .map(|row| row.get::<bool, _>(0))
}

/// One `schema_migrations` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationRecord {
    /// `version`.
    pub version: i64,
    /// `checksum`.
    pub checksum: String,
    /// `dirty`.
    pub dirty: bool,
}

/// `readMigrationRecords` — the version-ordered ledger rows.
pub(crate) async fn read_migration_records(
    conn: &mut PgConnection,
) -> Result<Vec<MigrationRecord>> {
    sqlx::query("SELECT version, checksum, dirty FROM central.schema_migrations ORDER BY version")
        .fetch_all(&mut *conn)
        .await
        .ctx("b08 migration: read version chain")
        .map(|rows| {
            rows.iter()
                .map(|row| MigrationRecord {
                    version: row.get::<i64, _>(0),
                    checksum: row.get::<String, _>(1),
                    dirty: row.get::<bool, _>(2),
                })
                .collect()
        })
}

/// Where the observed chain stands relative to the expected chain.
/// Ports `b08ChainState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainState {
    /// Clean `v0` only — the v8 intent has not been recorded.
    NeedsIntent,
    /// Version 8 is the dirty tail (requires the explicit resume path).
    Dirty,
    /// A valid clean (or v9/v10-dirty-tail) prefix.
    Clean,
}

/// `classifyB08MigrationChain` — admits an exact prefix of either the
/// corpus chain or the optional legacy chain that carries the v15
/// `b10-artifact-lifecycle-forward-correction` record after v14.
///
/// Upstream enumerates every chain length; this is the same decision
/// expressed as prefix matching:
///
/// - `records[0]` must be the clean `baseline-zero` v0.
/// - `records[1]` (v8) may be dirty only as a 2-record tail → [`ChainState::Dirty`].
/// - `records[2]` (v9) may be dirty only as a 3-record tail; `records[3]`
///   (v10) is admitted with upstream's version/checksum check only.
/// - `records[4..8]` (v11–v14) must be exact and clean.
/// - `records[8..]` must be clean and an exact prefix of either tail.
pub(crate) fn classify_chain(records: &[MigrationRecord]) -> Result<ChainState> {
    if records.is_empty() {
        return Err(invalid(
            "migration_chain_missing_predecessor",
            "b08 migration: missing version-zero predecessor",
        ));
    }
    {
        let mut seen = std::collections::HashSet::with_capacity(records.len());
        for record in records {
            if !seen.insert(record.version) {
                return Err(invalid(
                    "migration_chain_duplicate",
                    format!("b08 migration: duplicate version {}", record.version),
                ));
            }
        }
    }
    let head = &records[0];
    if head.version != 0 || head.checksum != "baseline-zero" || head.dirty {
        return Err(invalid(
            "migration_chain_invalid_predecessor",
            "b08 migration: invalid version-zero predecessor",
        ));
    }
    if records.len() == 1 {
        return Ok(ChainState::NeedsIntent);
    }
    if records.len() > 31 {
        return Err(invalid(
            "migration_chain_unknown",
            "b08 migration: unknown or duplicate migration chain",
        ));
    }

    // records[1]: version 8 — the only dirty-admissible tail of the b08
    // install admission.
    let v8 = &records[1];
    if v8.version != 8 || v8.checksum != "b08-execution-evidence" {
        return Err(invalid(
            "migration_chain_unknown_version",
            "b08 migration: unknown or missing migration version",
        ));
    }
    if v8.dirty {
        if records.len() != 2 {
            return Err(invalid(
                "migration_chain_dirty_not_tail",
                "b08 migration: dirty version 8 is not the migration tail",
            ));
        }
        return Ok(ChainState::Dirty);
    }

    if records.len() >= 3 {
        let correction = &records[2];
        if correction.version != 9 || correction.checksum != "b08-recovery-evidence-correction" {
            return Err(invalid(
                "migration_chain_unknown_version",
                "b08 migration: unknown migration version",
            ));
        }
        if correction.dirty && records.len() != 3 {
            return Err(invalid(
                "migration_chain_dirty_not_tail",
                "b08 migration: dirty version 9 is not the migration tail",
            ));
        }
    }
    if records.len() == 4 {
        let correction = &records[3];
        if correction.version != 10 || correction.checksum != "b08-final-safety-correction" {
            return Err(invalid(
                "migration_chain_unknown_version",
                "b08 migration: unknown migration version",
            ));
        }
    }
    const FIXED: [(usize, i64, &str, &str); 4] = [
        (4, 11, "b09-provider-evidence", "invalid B09 successor"),
        (
            5,
            12,
            "b09-provider-evidence-correction",
            "invalid B09 correction successor",
        ),
        (
            6,
            13,
            "b09-provider-evidence-response-id-correction",
            "invalid B09 response-id correction successor",
        ),
        (7, 14, "b10-artifact-lifecycle", "invalid B10 successor"),
    ];
    for (idx, version, checksum, label) in FIXED {
        if records.len() > idx {
            let record = &records[idx];
            if record.version != version || record.checksum != checksum || record.dirty {
                return Err(invalid(
                    "migration_chain_invalid_successor",
                    format!("b08 migration: {label}"),
                ));
            }
        }
    }
    if records.len() >= 9 {
        let tail = &records[8..];
        if tail.iter().any(|record| record.dirty) {
            return Err(invalid(
                "migration_chain_dirty_successor",
                "b08 migration: dirty successor is not admitted",
            ));
        }
        let matches = |chain: &[(i64, &str)]| {
            tail.len() <= chain.len() - 8
                && tail
                    .iter()
                    .zip(&chain[8..])
                    .all(|(r, (v, c))| r.version == *v && r.checksum == *c)
        };
        if !matches(WITH_V15_CHAIN) && !matches(WITHOUT_V15_CHAIN) {
            return Err(invalid(
                "migration_chain_invalid_tail",
                "b08 migration: invalid successor chain",
            ));
        }
    }
    Ok(ChainState::Clean)
}

/// `admitB08InstallChain` — classify and refuse the dirty-v8 resume path.
pub(crate) fn admit_install_chain(records: &[MigrationRecord]) -> Result<ChainState> {
    let state = classify_chain(records)?;
    if state == ChainState::Dirty {
        return Err(invalid(
            "migration_dirty_requires_resume",
            "b08 migration: dirty version 8 requires the explicit resume path",
        ));
    }
    Ok(state)
}

/// `verifyB08MigrationChecksumLedger` — `migration_checksums` must be the
/// exact, ordered, clean-record mirror of `schema_migrations`.
pub(crate) async fn verify_checksum_ledger(
    conn: &mut PgConnection,
    records: &[MigrationRecord],
) -> Result<()> {
    let expected: Vec<(i64, &str)> = records
        .iter()
        .filter(|record| !record.dirty)
        .map(|record| (record.version, record.checksum.as_str()))
        .collect();

    let rows = sqlx::query(
        "SELECT version, checksum FROM central.migration_checksums \
         ORDER BY version, checksum, recorded_at",
    )
    .fetch_all(&mut *conn)
    .await
    .ctx("inspect migration checksum ledger")?;

    if rows.len() != expected.len() {
        return Err(invalid(
            "migration_checksum_ledger_drift",
            format!(
                "migration checksum ledger row count = {}, want {}",
                rows.len(),
                expected.len()
            ),
        ));
    }
    for (row, (version, checksum)) in rows.iter().zip(&expected) {
        if row.get::<i64, _>(0) != *version || row.get::<String, _>(1) != *checksum {
            return Err(invalid(
                "migration_checksum_ledger_drift",
                "migration checksum ledger does not exactly match schema_migrations",
            ));
        }
    }
    Ok(())
}

/// `verifyB37RetryIdempotencyMigrationChain` — accept only the terminal,
/// fully clean chain through v37 (30 records without v15, 31 with it), then
/// the checksum ledger.
pub(crate) async fn verify_full_chain(conn: &mut PgConnection) -> Result<()> {
    let records = read_migration_records(conn).await?;
    if records.len() != WITH_V15_CHAIN.len() && records.len() != WITHOUT_V15_CHAIN.len() {
        return Err(invalid(
            "migration_chain_incomplete",
            "b37 retry idempotency: unsupported migration chain",
        ));
    }
    classify_chain(&records).map_err(|_| {
        invalid(
            "migration_chain_incomplete",
            "b37 retry idempotency: version chain is not clean",
        )
    })?;
    let tail = &records[records.len() - 1];
    if tail.version != 37 || tail.checksum != "b37-retry-idempotency" || tail.dirty {
        return Err(invalid(
            "migration_chain_incomplete",
            "b37 retry idempotency: invalid version thirty-seven tail",
        ));
    }
    verify_checksum_ledger(conn, &records).await
}

// ---------------------------------------------------------------------------
// Baseline (v0) shape — verbatim port of baseline.go's expected lists.
// ---------------------------------------------------------------------------

/// `BaselineInstaller.ExpectedTables` / `ExpectedRuntimeGrantTables`.
pub(crate) const BASELINE_TABLES: [&str; 24] = [
    "workspaces",
    "workspace_event_counters",
    "tasks",
    "runs",
    "steps",
    "step_attempts",
    "tool_calls",
    "tool_call_attempts",
    "artifacts",
    "artifact_tombstones",
    "events",
    "outbox",
    "command_receipts",
    "execution_ownership",
    "capacity_reservations",
    "bootstrap_generations",
    "sessions",
    "approvals",
    "secret_use_evidence",
    "checkpoints",
    "schema_migrations",
    "migration_checksums",
    "migration_progress",
    "epoch_markers",
];

/// `BaselineInstaller.ExpectedRuntimeMutationGrants`.
pub(crate) const BASELINE_MUTATION_GRANTS: [(&str, &[&str]); 10] = [
    ("bootstrap_generations", &["INSERT", "UPDATE"]),
    ("sessions", &["INSERT", "UPDATE"]),
    ("tasks", &["INSERT", "UPDATE"]),
    ("runs", &["INSERT", "UPDATE"]),
    ("workspace_event_counters", &["INSERT", "UPDATE"]),
    ("command_receipts", &["INSERT"]),
    ("events", &["INSERT"]),
    ("workspaces", &["UPDATE"]),
    ("artifacts", &["INSERT", "UPDATE"]),
    ("capacity_reservations", &["INSERT", "UPDATE"]),
];

/// `BaselineInstaller.expectedColumns` — the required-column spot list.
pub(crate) const BASELINE_REQUIRED_COLUMNS: [(&str, &str); 40] = [
    ("workspaces", "id"),
    ("workspaces", "state"),
    ("workspaces", "owner_principal_id"),
    ("tasks", "id"),
    ("tasks", "workspace_id"),
    ("tasks", "status"),
    ("tasks", "current_run_id"),
    ("tasks", "last_run_index"),
    ("tasks", "waiting_reason"),
    ("tasks", "idempotency_key"),
    ("runs", "id"),
    ("runs", "workspace_id"),
    ("runs", "task_id"),
    ("runs", "run_index"),
    ("runs", "waiting_reason"),
    ("runs", "ownership_token"),
    ("steps", "id"),
    ("steps", "step_index"),
    ("steps", "step_kind"),
    ("step_attempts", "id"),
    ("step_attempts", "attempt_index"),
    ("step_attempts", "adapter_identity"),
    ("tool_calls", "id"),
    ("tool_calls", "tool_index"),
    ("artifacts", "id"),
    ("artifacts", "object_key"),
    ("artifacts", "staging_generation"),
    ("events", "id"),
    ("events", "event_sequence"),
    ("outbox", "id"),
    ("outbox", "delivery_state"),
    ("bootstrap_generations", "id"),
    ("bootstrap_generations", "workspace_id"),
    ("bootstrap_generations", "generation"),
    ("bootstrap_generations", "presentation_deadline"),
    ("sessions", "id"),
    ("sessions", "token_hash"),
    ("schema_migrations", "version"),
    ("schema_migrations", "checksum"),
    ("schema_migrations", "dirty"),
];

/// Columns optional under the repairable-legacy shape.
const REPAIRABLE_OPTIONAL_COLUMNS: [(&str, &str); 5] = [
    ("tasks", "current_run_id"),
    ("tasks", "last_run_index"),
    ("tasks", "waiting_reason"),
    ("runs", "waiting_reason"),
    ("runs", "ownership_token"),
];

/// `BaselineInstaller.expectedIndexes`.
pub(crate) const BASELINE_INDEXES: [&str; 43] = [
    "tasks_workspace_status_created_idx",
    "tasks_workspace_id_idx",
    "tasks_retry_eligible_idx",
    "tasks_cleanup_expiry_idx",
    "runs_task_id_idx",
    "runs_status_idx",
    "runs_cleanup_idx",
    "steps_run_id_idx",
    "steps_status_idx",
    "step_attempts_step_id_idx",
    "step_attempts_status_idx",
    "tool_calls_step_id_idx",
    "tool_call_attempts_tool_call_id_idx",
    "tool_call_attempts_status_idx",
    "artifacts_task_id_idx",
    "artifacts_state_expiry_idx",
    "artifacts_delete_pending_idx",
    "artifacts_quarantine_idx",
    "artifacts_object_key_seek_idx",
    "events_workspace_sequence_idx",
    "events_aggregate_idx",
    "events_run_idx",
    "outbox_claim_idx",
    "outbox_owner_lease_idx",
    "outbox_delivered_cleanup_idx",
    "outbox_dead_letter_cleanup_idx",
    "command_receipts_cleanup_idx",
    "execution_ownership_expiry_idx",
    "capacity_reservations_state_cleanup_idx",
    "bootstrap_generations_active_idx",
    "sessions_workspace_principal_idx",
    "sessions_cleanup_idx",
    "sessions_pending_bootstrap_idx",
    "sessions_delivery_pending_idx",
    "sessions_first_use_idx",
    "approvals_workspace_capability_idx",
    "approvals_workspace_actor_idx",
    "approvals_security_epoch_idx",
    "secret_use_workspace_ref_idx",
    "secret_use_workspace_actor_idx",
    "checkpoints_run_id_idx",
    "checkpoints_recovery_idx",
    "migration_progress_version_state_idx",
];

/// `expectedIndexDefinitionFragments`.
const INDEX_DEFINITION_FRAGMENTS: [(&str, &[&str]); 2] = [
    (
        "tasks_workspace_status_created_idx",
        &["(workspace_id, status, updated_at DESC, id DESC)"],
    ),
    (
        "bootstrap_generations_active_idx",
        &["(workspace_id, generation DESC)", "WHERE"],
    ),
];

const EXPECTED_ACTIVE_GENERATION_PREDICATE: &str = "(state = 'active'::text)";

/// `BaselineInstaller.expectedUniqueConstraints`.
pub(crate) const BASELINE_UNIQUE_CONSTRAINTS: [&str; 20] = [
    "tasks_workspace_id_idempotency_key_unique",
    "runs_workspace_task_index_unique",
    "steps_workspace_run_index_unique",
    "step_attempts_workspace_step_attempt_unique",
    "tool_calls_workspace_step_tool_unique",
    "tool_call_attempts_workspace_tc_attempt_unique",
    "artifacts_workspace_staging_generation_unique",
    "artifacts_workspace_object_key_unique",
    "artifact_tombstones_artifact_id_unique",
    "events_workspace_sequence_unique",
    "outbox_workspace_event_unique",
    "command_receipts_scope_key_unique",
    "execution_ownership_scope_unique",
    "capacity_reservations_artifact_unique",
    "capacity_reservations_staging_gen_unique",
    "bootstrap_generations_workspace_generation_unique",
    "sessions_token_hash_unique",
    "checkpoints_workspace_run_kind_unique",
    "migration_checksums_version_recorded_unique",
    "migration_progress_operation_version_unique",
];

/// `BaselineInstaller.expectedForeignKeys`.
pub(crate) const BASELINE_FOREIGN_KEYS: [&str; 36] = [
    "workspace_event_counters_workspace_id_fkey",
    "tasks_workspace_id_fkey",
    "runs_workspace_id_fkey",
    "runs_task_id_fkey",
    "steps_workspace_id_fkey",
    "steps_run_id_fkey",
    "step_attempts_workspace_id_fkey",
    "step_attempts_step_id_fkey",
    "tool_calls_workspace_id_fkey",
    "tool_calls_step_id_fkey",
    "tool_call_attempts_workspace_id_fkey",
    "tool_call_attempts_tool_call_id_fkey",
    "artifacts_workspace_id_fkey",
    "artifacts_task_id_fkey",
    "artifacts_run_id_fkey",
    "artifact_tombstones_workspace_id_fkey",
    "events_workspace_id_fkey",
    "outbox_workspace_id_fkey",
    "outbox_event_id_fkey",
    "command_receipts_workspace_id_fkey",
    "execution_ownership_workspace_id_fkey",
    "execution_ownership_claimed_run_id_fkey",
    "execution_ownership_claimed_step_id_fkey",
    "execution_ownership_claimed_step_attempt_id_fkey",
    "capacity_reservations_workspace_id_fkey",
    "capacity_reservations_run_id_fkey",
    "capacity_reservations_artifact_id_fkey",
    "bootstrap_generations_workspace_id_fkey",
    "sessions_workspace_id_fkey",
    "approvals_workspace_id_fkey",
    "secret_use_evidence_workspace_id_fkey",
    "checkpoints_workspace_id_fkey",
    "checkpoints_run_id_fkey",
    "checkpoints_step_id_fkey",
    "migration_checksums_version_fkey",
    "migration_progress_version_fkey",
];

/// `baseline.go: verifyTables`.
async fn verify_tables(conn: &mut PgConnection) -> Result<()> {
    let mut missing = Vec::new();
    for table in BASELINE_TABLES {
        if !table_exists(conn, table).await? {
            missing.push(table);
        }
    }
    if !missing.is_empty() {
        return Err(invalid(
            "baseline_shape_missing_tables",
            format!(
                "baseline: missing tables after install: {}",
                missing.join(", ")
            ),
        ));
    }
    Ok(())
}

/// `pg_catalog`-based column check — `information_schema.columns` would
/// hide columns on tables the role holds no privilege on.
async fn column_exists(conn: &mut PgConnection, table: &str, column: &str) -> Result<bool> {
    sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM pg_attribute a \
         JOIN pg_class c ON c.oid = a.attrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'central' AND c.relname = $1 AND a.attname = $2 \
           AND a.attnum > 0 AND NOT a.attisdropped)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(&mut *conn)
    .await
    .ctx("baseline: verify column")
    .map(|row| row.get::<bool, _>(0))
}

/// `baseline.go: verifyColumns` (and `verifyRepairableColumns` under
/// `allow_repairable`).
async fn verify_columns(conn: &mut PgConnection, allow_repairable: bool) -> Result<()> {
    for (table, column) in BASELINE_REQUIRED_COLUMNS {
        if allow_repairable && REPAIRABLE_OPTIONAL_COLUMNS.contains(&(table, column)) {
            continue;
        }
        if !column_exists(conn, table, column).await? {
            return Err(invalid(
                "baseline_shape_missing_column",
                format!("baseline: missing column {table}.{column}"),
            ));
        }
    }
    Ok(())
}

/// `baseline.go: verifyIndexes` — name presence plus the two pinned
/// definition fragments (and the legacy-repairable variants under
/// `allow_repairable`).
async fn verify_indexes(conn: &mut PgConnection, allow_repairable: bool) -> Result<()> {
    let rows = sqlx::query(
        "SELECT p.indexname, p.indexdef, \
                COALESCE(pg_get_expr(i.indpred, i.indrelid), '') \
         FROM pg_indexes p \
         JOIN pg_class c ON c.relname = p.indexname \
         JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = p.schemaname \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE p.schemaname = 'central'",
    )
    .fetch_all(&mut *conn)
    .await
    .ctx("baseline: verify indexes query")?;
    let existing: std::collections::HashMap<String, (String, String)> = rows
        .iter()
        .map(|row| {
            (
                row.get::<String, _>(0),
                (row.get::<String, _>(1), row.get::<String, _>(2)),
            )
        })
        .collect();

    let mut missing = Vec::new();
    for index in BASELINE_INDEXES {
        let Some((definition, predicate)) = existing.get(index) else {
            if allow_repairable && index == "bootstrap_generations_active_idx" {
                continue;
            }
            missing.push(index);
            continue;
        };
        for (_, fragments) in INDEX_DEFINITION_FRAGMENTS
            .iter()
            .filter(|(k, _)| *k == index)
        {
            for fragment in *fragments {
                if !definition.contains(fragment) {
                    let legacy_task_list = allow_repairable
                        && index == "tasks_workspace_status_created_idx"
                        && definition.contains("(workspace_id, status, created_at DESC)");
                    let legacy_active = allow_repairable
                        && index == "bootstrap_generations_active_idx"
                        && definition.contains("(workspace_id, state)")
                        && predicate == EXPECTED_ACTIVE_GENERATION_PREDICATE;
                    if legacy_task_list || legacy_active {
                        continue;
                    }
                    return Err(invalid(
                        "baseline_shape_index_definition",
                        format!("baseline: index {index} has unexpected definition"),
                    ));
                }
            }
        }
        if index == "bootstrap_generations_active_idx"
            && predicate != EXPECTED_ACTIVE_GENERATION_PREDICATE
        {
            let legacy_active = allow_repairable
                && definition.contains("(workspace_id, state)")
                && predicate == EXPECTED_ACTIVE_GENERATION_PREDICATE;
            if !legacy_active {
                return Err(invalid(
                    "baseline_shape_index_predicate",
                    format!("baseline: index {index} has unexpected predicate"),
                ));
            }
        }
    }
    if !missing.is_empty() {
        return Err(invalid(
            "baseline_shape_missing_indexes",
            format!("baseline: missing indexes: {}", missing.join(", ")),
        ));
    }
    Ok(())
}

async fn verify_named_constraints(
    conn: &mut PgConnection,
    contype: char,
    expected: &[&str],
    label: &'static str,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT conname FROM pg_constraint \
         WHERE connamespace = 'central'::regnamespace AND contype = $1",
    )
    .bind(contype.to_string())
    .fetch_all(&mut *conn)
    .await
    .ctx("baseline: verify constraints query")?;
    let existing: std::collections::HashSet<String> =
        rows.iter().map(|row| row.get::<String, _>(0)).collect();
    let missing: Vec<&str> = expected
        .iter()
        .filter(|name| !existing.contains(**name))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(invalid(
            "baseline_shape_missing_constraints",
            format!("baseline: missing {label}: {}", missing.join(", ")),
        ));
    }
    Ok(())
}

/// `baseline.go: verifyRuntimeGrants` — schema USAGE, SELECT on every
/// baseline table, and the least-privilege mutation set.
async fn verify_runtime_grants(conn: &mut PgConnection) -> Result<()> {
    let schema_usage: bool =
        sqlx::query("SELECT has_schema_privilege('central_runtime', 'central', 'USAGE')")
            .fetch_one(&mut *conn)
            .await
            .ctx("baseline: verify central_runtime schema grant")
            .map(|row| row.get::<bool, _>(0))?;
    if !schema_usage {
        return Err(invalid(
            "baseline_shape_missing_grant",
            "baseline: central_runtime missing USAGE on schema central",
        ));
    }
    for table in BASELINE_TABLES {
        let granted = has_table_privilege(conn, table, "SELECT").await?;
        if !granted {
            return Err(invalid(
                "baseline_shape_missing_grant",
                format!("baseline: central_runtime missing SELECT on central.{table}"),
            ));
        }
    }
    for (table, privileges) in BASELINE_MUTATION_GRANTS {
        for privilege in privileges {
            if !has_table_privilege(conn, table, privilege).await? {
                return Err(invalid(
                    "baseline_shape_missing_grant",
                    format!("baseline: central_runtime missing {privilege} on central.{table}"),
                ));
            }
        }
    }
    Ok(())
}

/// `has_table_privilege('central_runtime', 'central.<table>', <priv>)`.
pub(crate) async fn has_table_privilege(
    conn: &mut PgConnection,
    table: &str,
    privilege: &str,
) -> Result<bool> {
    sqlx::query("SELECT has_table_privilege('central_runtime', $1, $2)")
        .bind(format!("central.{table}"))
        .bind(privilege)
        .fetch_one(&mut *conn)
        .await
        .ctx("verify table privilege")
        .map(|row| row.get::<bool, _>(0))
}

/// `baseline.go: verifyShape` — the complete v0 audit. Under
/// `allow_repairable` the legacy-repairable column/index variants are
/// admitted (the pre-repair admission check).
pub(crate) async fn verify_baseline_shape(
    conn: &mut PgConnection,
    allow_repairable: bool,
) -> Result<()> {
    verify_tables(conn).await?;
    verify_columns(conn, allow_repairable).await?;
    verify_indexes(conn, allow_repairable).await?;
    verify_named_constraints(
        conn,
        'u',
        &BASELINE_UNIQUE_CONSTRAINTS,
        "unique constraints",
    )
    .await?;
    verify_named_constraints(conn, 'f', &BASELINE_FOREIGN_KEYS, "foreign keys").await?;
    if !allow_repairable {
        verify_runtime_grants(conn).await?;
    }
    let row_count: i64 =
        sqlx::query("SELECT count(*) FROM central.schema_migrations WHERE version = 0")
            .fetch_one(&mut *conn)
            .await
            .ctx("baseline: verify records")
            .map(|row| row.get::<i64, _>(0))?;
    if row_count == 0 {
        return Err(invalid(
            "baseline_shape_missing_records",
            "baseline: no baseline records found after install",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-migration owned-object verification (serve-baseline ladder).
// ---------------------------------------------------------------------------

async fn index_named_exists(conn: &mut PgConnection, name: &str) -> Result<bool> {
    sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'central' AND c.relname = $1 AND c.relkind = 'i')",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await
    .ctx("inspect index")
    .map(|row| row.get::<bool, _>(0))
}

async fn constraint_named_exists(conn: &mut PgConnection, name: &str) -> Result<bool> {
    sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint c \
         JOIN pg_namespace n ON n.oid = c.connamespace \
         WHERE n.nspname = 'central' AND c.conname = $1)",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await
    .ctx("inspect constraint")
    .map(|row| row.get::<bool, _>(0))
}

async fn function_named_exists(conn: &mut PgConnection, name: &str) -> Result<bool> {
    sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'central' AND p.proname = $1)",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await
    .ctx("inspect function")
    .map(|row| row.get::<bool, _>(0))
}

async fn trigger_named_exists(conn: &mut PgConnection, name: &str) -> Result<bool> {
    sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger t \
         JOIN pg_class c ON c.oid = t.tgrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'central' AND t.tgname = $1 AND NOT t.tgisinternal)",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await
    .ctx("inspect trigger")
    .map(|row| row.get::<bool, _>(0))
}

/// Table-level ACL entries held by `central_runtime` on `central.<table>`
/// for `privilege` (`"ALL"` counts every privilege entry).
async fn runtime_acl_entries(conn: &mut PgConnection, table: &str, privilege: &str) -> Result<i64> {
    let sql = if privilege == "ALL" {
        "SELECT count(*) FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         CROSS JOIN LATERAL aclexplode(c.relacl) a \
         WHERE n.nspname = 'central' AND c.relname = $1 \
           AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'central_runtime')"
    } else {
        "SELECT count(*) FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         CROSS JOIN LATERAL aclexplode(c.relacl) a \
         WHERE n.nspname = 'central' AND c.relname = $1 \
           AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'central_runtime') \
           AND a.privilege_type = $2"
    };
    let mut query = sqlx::query(sql).bind(table);
    if privilege != "ALL" {
        query = query.bind(privilege);
    }
    query
        .fetch_one(&mut *conn)
        .await
        .ctx("inspect relation ACL")
        .map(|row| row.get::<i64, _>(0))
}

async fn has_column_update(conn: &mut PgConnection, table: &str, column: &str) -> Result<bool> {
    sqlx::query("SELECT has_column_privilege('central_runtime', $1, $2, 'UPDATE')")
        .bind(format!("central.{table}"))
        .bind(column)
        .fetch_one(&mut *conn)
        .await
        .ctx("inspect column privilege")
        .map(|row| row.get::<bool, _>(0))
}

/// The serve-baseline ladder: every object the corpus produces, asserted
/// present in the terminal state; every net-dropped object asserted absent;
/// runtime grants/column grants present and net-revoked table privileges
/// absent at the table level.
pub(crate) async fn verify_migration_shapes(conn: &mut PgConnection) -> Result<()> {
    for shape in MIGRATION_SHAPES {
        let label = shape.checksum;
        for table in shape.tables {
            if !table_exists(conn, table).await? {
                return Err(invalid(
                    "migration_shape_missing_table",
                    format!("{label}: missing central.{table}"),
                ));
            }
        }
        for (table, column) in shape.columns {
            if !column_exists(conn, table, column).await? {
                return Err(invalid(
                    "migration_shape_missing_column",
                    format!("{label}: missing column central.{table}.{column}"),
                ));
            }
        }
        for index in shape.indexes {
            if !index_named_exists(conn, index).await? {
                return Err(invalid(
                    "migration_shape_missing_index",
                    format!("{label}: missing index central.{index}"),
                ));
            }
        }
        for constraint in shape.constraints {
            if !constraint_named_exists(conn, constraint).await? {
                return Err(invalid(
                    "migration_shape_missing_constraint",
                    format!("{label}: missing constraint {constraint}"),
                ));
            }
        }
        for constraint in shape.absent_constraints {
            if constraint_named_exists(conn, constraint).await? {
                return Err(invalid(
                    "migration_shape_stray_constraint",
                    format!("{label}: stray constraint {constraint}"),
                ));
            }
        }
        for index in shape.absent_indexes {
            if index_named_exists(conn, index).await? {
                return Err(invalid(
                    "migration_shape_stray_index",
                    format!("{label}: stray index central.{index}"),
                ));
            }
        }
        for function in shape.functions {
            if !function_named_exists(conn, function).await? {
                return Err(invalid(
                    "migration_shape_missing_function",
                    format!("{label}: missing function central.{function}"),
                ));
            }
        }
        for trigger in shape.triggers {
            if !trigger_named_exists(conn, trigger).await? {
                return Err(invalid(
                    "migration_shape_missing_trigger",
                    format!("{label}: missing trigger {trigger}"),
                ));
            }
        }
        for trigger in shape.absent_triggers {
            if trigger_named_exists(conn, trigger).await? {
                return Err(invalid(
                    "migration_shape_stray_trigger",
                    format!("{label}: stray trigger {trigger}"),
                ));
            }
        }
        for (table, privilege) in shape.runtime_grants {
            if !has_table_privilege(conn, table, privilege).await? {
                return Err(invalid(
                    "migration_shape_missing_grant",
                    format!("{label}: central_runtime missing {privilege} on central.{table}"),
                ));
            }
        }
        for (table, privilege) in shape.revoked_table_privileges {
            if runtime_acl_entries(conn, table, privilege).await? != 0 {
                return Err(invalid(
                    "migration_shape_stray_privilege",
                    format!(
                        "{label}: central_runtime still holds table-level {privilege} on central.{table}"
                    ),
                ));
            }
        }
        for (table, column) in shape.column_grants {
            if !has_column_update(conn, table, column).await? {
                return Err(invalid(
                    "migration_shape_missing_column_grant",
                    format!("{label}: central_runtime missing UPDATE on central.{table}.{column}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(version: i64, checksum: &str, dirty: bool) -> MigrationRecord {
        MigrationRecord {
            version,
            checksum: checksum.to_owned(),
            dirty,
        }
    }

    fn chain_without_v15(end: usize) -> Vec<MigrationRecord> {
        WITHOUT_V15_CHAIN[..end]
            .iter()
            .map(|(v, c)| record(*v, c, false))
            .collect()
    }

    #[test]
    fn classify_requires_version_zero() {
        assert!(classify_chain(&[]).is_err());
        assert!(classify_chain(&[record(8, "b08-execution-evidence", false)]).is_err());
        assert!(classify_chain(&[record(0, "bogus", false)]).is_err());
        assert!(classify_chain(&[record(0, "baseline-zero", true)]).is_err());
    }

    #[test]
    fn classify_needs_intent_on_bare_v0() {
        assert_eq!(
            classify_chain(&[record(0, "baseline-zero", false)]).ok(),
            Some(ChainState::NeedsIntent)
        );
    }

    #[test]
    fn classify_dirty_v8_tail() {
        let records = vec![
            record(0, "baseline-zero", false),
            record(8, "b08-execution-evidence", true),
        ];
        assert_eq!(classify_chain(&records).ok(), Some(ChainState::Dirty));
        assert!(admit_install_chain(&records).is_err());
    }

    #[test]
    fn classify_rejects_dirty_v8_mid_chain() {
        let mut records = chain_without_v15(3);
        records[1].dirty = true;
        assert!(classify_chain(&records).is_err());
    }

    #[test]
    fn classify_admits_clean_prefixes() {
        for end in 1..=WITHOUT_V15_CHAIN.len() {
            let records = chain_without_v15(end);
            let expected = if end == 1 {
                ChainState::NeedsIntent
            } else {
                ChainState::Clean
            };
            assert_eq!(classify_chain(&records).ok(), Some(expected), "end={end}");
        }
    }

    #[test]
    fn classify_admits_with_v15_chain() {
        let records: Vec<MigrationRecord> = WITH_V15_CHAIN
            .iter()
            .map(|(v, c)| record(*v, c, false))
            .collect();
        assert_eq!(classify_chain(&records).ok(), Some(ChainState::Clean));
        // Prefixes of the with-v15 chain are also clean.
        for end in 9..WITH_V15_CHAIN.len() {
            assert_eq!(
                classify_chain(&records[..end]).ok(),
                Some(ChainState::Clean),
                "end={end}"
            );
        }
    }

    #[test]
    fn classify_rejects_dirty_late_successor() {
        let mut records = chain_without_v15(10);
        records[9].dirty = true;
        assert!(classify_chain(&records).is_err());
    }

    #[test]
    fn classify_rejects_wrong_checksum_and_gaps() {
        let mut records = chain_without_v15(3);
        records[2].checksum = "bogus".to_owned();
        assert!(classify_chain(&records).is_err());
        // Missing v9.
        let mut gap = chain_without_v15(2);
        gap.push(record(10, "b08-final-safety-correction", false));
        assert!(classify_chain(&gap).is_err());
    }

    #[test]
    fn classify_rejects_duplicates_and_overlong() {
        let mut records = vec![
            record(0, "baseline-zero", false),
            record(8, "b08-execution-evidence", false),
            record(8, "b08-execution-evidence", false),
        ];
        assert!(classify_chain(&records).is_err());
        records = chain_without_v15(30);
        records.push(record(99, "future", false));
        assert!(classify_chain(&records).is_err());
    }
}
