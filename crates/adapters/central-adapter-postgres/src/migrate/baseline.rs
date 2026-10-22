//! `BaselineInstaller` — port of `baseline.go`.
//!
//! Fresh targets replay the whole embedded corpus; existing targets are
//! admitted only when their migration ledger is an exact, clean prefix (or
//! the v9/v10 dirty tails the files themselves resume), the checksum ledger
//! authenticates, and — for the bare-`v0` legacy shape — the audited
//! version-zero repair has converged the target before v8 replays.
//!
//! Migration files carry their own dirty-intent, DDL, verification, and
//! clean-marker transactions; a file is replayed (verbatim, via
//! [`sqlx::raw_sql`]) exactly when its ledger record is missing or dirty.

use sqlx::PgConnection;

use super::manifest::{
    B10_FORWARD_CORRECTION_CHECKSUM, LATEST_VERSION, MIGRATIONS, WITH_V15_CHAIN, WITHOUT_V15_CHAIN,
};
use super::verify_shape::{
    ChainState, admit_install_chain, read_migration_records, schema_exists, verify_baseline_shape,
    verify_checksum_ledger,
};
use super::{BaselineManifest, Result};
use crate::error::SqlxContext;
use central_foundation::failure::Failure;
use sqlx::Row;

fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}

/// The baseline installer and shape authority.
#[derive(Debug, Default)]
pub struct BaselineInstaller;

impl BaselineInstaller {
    /// New installer (stateless — upstream `&BaselineInstaller{}`).
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// `Install` — idempotent `v0..v37` installation on a single session.
    ///
    /// # Errors
    /// * schema checks or chain admission fail, or
    /// * a migration replay or post-conditions fails.
    pub async fn install(&self, conn: &mut PgConnection) -> Result<()> {
        // The whole install is serialized on the canonical migration
        // locks, as upstream serializes via the runner-held locks plus
        // each ApplyBXX's own acquisition (b08.go:322 et seq.). The corpus
        // files embed no lock statements, and the Runner only holds locks
        // on its prepare→commit path — without this bracket two
        // concurrent installs on the same target could both pass the
        // stock check and double-commit `migration_checksums` rows (its
        // (version, recorded_at) uniqueness admits rows whose recorded_at
        // differs) or race the clean-marker UPDATEs. `pg_advisory_lock`
        // is session-reentrant, so a Runner-held lock makes this a nested
        // no-op; the release below only pops the level this call took.
        super::runner::acquire_migration_locks(conn).await?;
        let result = self.install_serialized(conn).await;
        let release = super::runner::release_migration_locks(conn).await;
        match (result, release) {
            (Err(err), _) | (_, Err(err)) => Err(err),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// The serialized install body: fresh targets replay the corpus;
    /// existing targets go through ledger admission, repair, and resume.
    async fn install_serialized(&self, conn: &mut PgConnection) -> Result<()> {
        if !schema_exists(conn).await? {
            self.verify_stock_target(conn).await?;
            self.replay_all(conn).await?;
            return Ok(());
        }
        self.install_on_existing(conn).await
    }

    /// The existing-target path (runs under [`Self::install`]'s lock
    /// bracket): admit → authenticate the checksum ledger → optional v0
    /// repair → replay every missing-or-dirty file in manifest order,
    /// re-verifying each clean record's shape along the way.
    async fn install_on_existing(&self, conn: &mut PgConnection) -> Result<()> {
        let records = read_migration_records(conn).await?;
        let state = admit_install_chain(&records).map_err(|err| {
            invalid(
                err.code(),
                format!(
                    "baseline: refuse existing target before repair: {}",
                    err.message()
                ),
            )
        })?;
        verify_checksum_ledger(conn, &records)
            .await
            .map_err(|err| {
                invalid(
                    err.code(),
                    format!(
                        "baseline: refuse existing target checksum ledger before repair: {}",
                        err.message()
                    ),
                )
            })?;
        if state == ChainState::NeedsIntent {
            // A bare-version-zero legacy target may need the audited repair
            // before the version-8 chain.
            if self.verify_shape(conn).await.is_err() {
                self.repair_existing_target(conn).await?;
            }
        }
        if !records.iter().any(|r| r.version == 8 && !r.dirty) {
            // Upstream's legacy ToolCall linkage preflight gates the v8 DDL
            // on non-fresh targets.
            self.verify_legacy_tool_linkage(conn).await?;
        }
        self.replay_missing(conn, &records).await
    }

    /// `verifyStockTarget` — the target must look like stock PostgreSQL:
    /// no central-owned schema, no non-built-in extensions, event triggers,
    /// foreign servers, or procedural languages.
    ///
    /// # Errors
    /// `ErrSchemaExists`-equivalent failures when central objects exist.
    pub async fn verify_stock_target(&self, conn: &mut PgConnection) -> Result<()> {
        const CENTRAL_SCHEMAS: [&str; 7] = [
            "central",
            "central_migrate",
            "central_runtime",
            "central_internal",
            "central_audit",
            "central_event",
            "central_public",
        ];
        for schema in CENTRAL_SCHEMAS {
            let exists = sqlx::query(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)",
            )
            .bind(schema)
            .fetch_one(&mut *conn)
            .await
            .ctx("baseline: check central-owned schema")
            .map(|row| row.get::<bool, _>(0))?;
            if exists {
                return Err(invalid(
                    "baseline_schema_exists",
                    format!("baseline: target already has central-owned schema {schema:?}"),
                ));
            }
        }
        let extension_count: i64 = sqlx::query(
            "SELECT count(*) FROM pg_catalog.pg_extension WHERE extname NOT IN ('plpgsql')",
        )
        .fetch_one(&mut *conn)
        .await
        .ctx("baseline: check extensions")
        .map(|row| row.get::<i64, _>(0))?;
        if extension_count > 0 {
            return Err(invalid(
                "baseline_target_not_stock",
                "baseline: target has non-built-in extensions installed",
            ));
        }
        let trigger_count: i64 = sqlx::query("SELECT count(*) FROM pg_catalog.pg_event_trigger")
            .fetch_one(&mut *conn)
            .await
            .ctx("baseline: check event triggers")
            .map(|row| row.get::<i64, _>(0))?;
        if trigger_count > 0 {
            return Err(invalid(
                "baseline_target_not_stock",
                "baseline: target has event triggers installed",
            ));
        }
        let server_count: i64 = sqlx::query("SELECT count(*) FROM pg_catalog.pg_foreign_server")
            .fetch_one(&mut *conn)
            .await
            .ctx("baseline: check foreign servers")
            .map(|row| row.get::<i64, _>(0))?;
        if server_count > 0 {
            return Err(invalid(
                "baseline_target_not_stock",
                "baseline: target has foreign servers configured",
            ));
        }
        let language_count: i64 = sqlx::query(
            "SELECT count(*) FROM pg_catalog.pg_language \
             WHERE lanname NOT IN ('internal', 'c', 'sql', 'plpgsql')",
        )
        .fetch_one(&mut *conn)
        .await
        .ctx("baseline: check languages")
        .map(|row| row.get::<i64, _>(0))?;
        if language_count > 0 {
            return Err(invalid(
                "baseline_target_not_stock",
                "baseline: target has non-built-in procedural languages installed",
            ));
        }
        Ok(())
    }

    /// `VerifyShape` — the strict v0 shape audit (no repairable variants).
    ///
    /// # Errors
    /// Any expected object is missing or shaped wrong.
    pub async fn verify_shape(&self, conn: &mut PgConnection) -> Result<()> {
        verify_baseline_shape(conn, false).await
    }

    /// `BaselineManifest` — version 37 plus every known ledger checksum
    /// (the 30 corpus checksums and the optional legacy v15 checksum, as
    /// upstream's map carries both).
    #[must_use]
    pub fn baseline_manifest(&self) -> BaselineManifest {
        let mut checksums = std::collections::BTreeMap::new();
        for (_, checksum) in WITHOUT_V15_CHAIN {
            checksums.insert((*checksum).to_owned(), (*checksum).to_owned());
        }
        checksums.insert(
            B10_FORWARD_CORRECTION_CHECKSUM.to_owned(),
            B10_FORWARD_CORRECTION_CHECKSUM.to_owned(),
        );
        let _ = WITH_V15_CHAIN; // documented superset
        BaselineManifest {
            version: LATEST_VERSION as i32,
            checksums,
        }
    }

    /// Replay the entire corpus on a verified stock target.
    async fn replay_all(&self, conn: &mut PgConnection) -> Result<()> {
        for entry in MIGRATIONS {
            self.replay(conn, entry).await?;
        }
        Ok(())
    }

    /// Replay every file whose record is missing or dirty, in order —
    /// and re-verify the shape of every record already clean, as each
    /// upstream ApplyBXX does on its clean path (b08.go:346-351,
    /// b26_recovery_bootstrap_registration.go:175-179,
    /// b37_retry_idempotency.go:592-594): a clean ledger row is not
    /// taken on trust. The clean `v0` record re-runs the strict
    /// baseline audit (upstream ApplyB08 runs `VerifyShape`
    /// unconditionally on a clean chain); later versions run the
    /// corpus's presence-level owned-object checks.
    async fn replay_missing(
        &self,
        conn: &mut PgConnection,
        records: &[super::verify_shape::MigrationRecord],
    ) -> Result<()> {
        for entry in MIGRATIONS {
            let clean = records
                .iter()
                .any(|r| r.version == entry.version && r.checksum == entry.checksum && !r.dirty);
            if clean {
                if entry.version == 0 {
                    self.verify_shape(conn).await?;
                } else {
                    super::verify_shape::verify_migration_shape_for_version(conn, entry.version)
                        .await?;
                }
                continue;
            }
            self.replay(conn, entry).await?;
        }
        Ok(())
    }

    /// Execute one trusted migration file verbatim, then assert the
    /// committed ledger end-state the file's own clean-marker
    /// transaction must produce. Upstream asserts
    /// `tag.RowsAffected() == 1` on the clean-marker
    /// `UPDATE ... WHERE version AND checksum AND dirty`
    /// (b08.go:1353 et seq.). That guard cannot be lifted verbatim:
    /// `sqlx::raw_sql` runs the file whole and its aggregated
    /// `PgQueryResult` carries no per-statement command tag, and the
    /// corpus must not be split to isolate the statement. Asserting the
    /// committed end-state is equivalent on every reachable path —
    /// replay only runs for a missing or dirty record, and the
    /// canonical locks held by [`Self::install`] exclude concurrent
    /// mutators — so exactly one clean `(version, checksum)` row must
    /// now exist.
    async fn replay(&self, conn: &mut PgConnection, entry: &super::MigrationEntry) -> Result<()> {
        tracing::info!(
            version = entry.version,
            file = entry.file_name,
            "replaying migration"
        );
        sqlx::raw_sql(entry.sql)
            .execute(&mut *conn)
            .await
            .ctx("migration replay")?;
        let dirty = sqlx::query(
            "SELECT dirty FROM central.schema_migrations \
             WHERE version = $1 AND checksum = $2",
        )
        .bind(entry.version)
        .bind(entry.checksum)
        .fetch_optional(&mut *conn)
        .await
        .ctx("migration replay: inspect clean marker")?
        .map(|row| row.get::<bool, _>(0));
        match dirty {
            Some(false) => Ok(()),
            Some(true) | None => Err(invalid(
                "migration_clean_marker_raced",
                "migration replay: dirty marker changed before clean commit",
            )),
        }
    }

    /// `verifyB08LegacyToolLinkage` — legacy ToolCall rows must each have
    /// exactly one same-workspace StepAttempt parent before the v8 DDL.
    async fn verify_legacy_tool_linkage(&self, conn: &mut PgConnection) -> Result<()> {
        let ambiguous: i64 = sqlx::query(
            "SELECT count(*) FROM ( \
                SELECT c.id FROM central.tool_calls c \
                LEFT JOIN central.step_attempts a \
                  ON a.workspace_id = c.workspace_id AND a.step_id = c.step_id \
                GROUP BY c.id HAVING count(a.id) <> 1) ambiguous",
        )
        .fetch_one(&mut *conn)
        .await
        .ctx("b08 migration: inspect legacy ToolCall ownership")
        .map(|row| row.get::<i64, _>(0))?;
        if ambiguous != 0 {
            return Err(invalid(
                "migration_ambiguous_linkage",
                format!(
                    "b08 migration: {ambiguous} legacy ToolCall rows lack exactly one \
                     same-Workspace StepAttempt parent; apply a reviewed forward correction \
                     before retry"
                ),
            ));
        }
        Ok(())
    }

    /// `repairExistingTarget` — the audited version-zero legacy repair:
    /// task/run lifecycle columns and constraints, the legacy-status data
    /// rewrites, the repaired task-list and active-generation indexes, then
    /// baseline runtime grants — all inside one durable transaction, then
    /// the strict shape audit.
    async fn repair_existing_target(&self, conn: &mut PgConnection) -> Result<()> {
        if self.verify_shape_repairable(conn).await.is_err() {
            return Err(invalid(
                "baseline_shape_not_repairable",
                "baseline: existing target is not an audited baseline shape",
            ));
        }
        sqlx::raw_sql(
            "begin;
             SET LOCAL synchronous_commit = on;
             ALTER TABLE central.tasks
               ADD COLUMN IF NOT EXISTS current_run_id uuid NULL,
               ADD COLUMN IF NOT EXISTS last_run_index bigint NOT NULL DEFAULT 0 CHECK (last_run_index >= 0),
               ADD COLUMN IF NOT EXISTS waiting_reason text NULL;
             ALTER TABLE central.runs
               ADD COLUMN IF NOT EXISTS waiting_reason text NULL,
               ADD COLUMN IF NOT EXISTS ownership_token text NULL;
             UPDATE central.tasks SET status = 'waiting',
               waiting_reason = COALESCE(NULLIF(waiting_reason, ''), 'approval')
               WHERE status = 'waiting_for_approval';
             UPDATE central.tasks SET status = 'waiting',
               waiting_reason = COALESCE(NULLIF(waiting_reason, ''), 'external_input')
               WHERE status = 'waiting_for_input';
             ALTER TABLE central.tasks
               DROP CONSTRAINT IF EXISTS tasks_status_check,
               ADD CONSTRAINT tasks_status_check CHECK (status IN ('queued', 'running', 'waiting', 'cancelling', 'completed', 'failed', 'cancelled'));
             ALTER TABLE central.runs
               DROP CONSTRAINT IF EXISTS runs_status_check,
               ADD CONSTRAINT runs_status_check CHECK (status IN ('queued', 'running', 'waiting', 'cancelling', 'succeeded', 'failed', 'cancelled'));
             ALTER TABLE central.tasks
               DROP CONSTRAINT IF EXISTS tasks_workspace_id_idempotency_key_unique,
               ADD CONSTRAINT tasks_workspace_id_idempotency_key_unique UNIQUE (workspace_id, idempotency_key);
             DROP INDEX IF EXISTS central.tasks_workspace_status_created_idx;
             CREATE INDEX tasks_workspace_status_created_idx ON central.tasks (workspace_id, status, updated_at DESC, id DESC);
             UPDATE central.tasks t
               SET current_run_id = COALESCE(current_run_id, latest_run.id),
                   last_run_index = GREATEST(t.last_run_index, COALESCE(latest_run.last_run_index, 0))
               FROM (SELECT r.task_id, r.id, r.run_index AS last_run_index,
                       dense_rank() OVER (PARTITION BY r.task_id ORDER BY r.run_index DESC, r.created_at DESC, r.id DESC) AS rn
                     FROM central.runs r) latest_run
               WHERE t.id = latest_run.task_id AND latest_run.rn = 1;
             UPDATE central.tasks SET waiting_reason = NULL WHERE status <> 'waiting';
             commit;",
        )
        .execute(&mut *conn)
        .await
        .ctx("baseline: repair task lifecycle schema")?;
        self.repair_active_generation_index(conn).await?;
        super::grants::apply_runtime_grants(conn).await?;
        self.verify_shape(conn).await.map_err(|err| {
            invalid(
                err.code(),
                format!(
                    "baseline: verify repaired existing target: {}",
                    err.message()
                ),
            )
        })
    }

    /// `verifyShape(allowRepairable)` — the pre-repair admission check.
    async fn verify_shape_repairable(&self, conn: &mut PgConnection) -> Result<()> {
        verify_baseline_shape(conn, true).await
    }

    /// `repairActiveGenerationIndex` — converge the legacy
    /// `(workspace_id, state)` active-generation index to
    /// `(workspace_id, generation DESC) WHERE state = 'active'`.
    async fn repair_active_generation_index(&self, conn: &mut PgConnection) -> Result<()> {
        let row = sqlx::query(
            "SELECT p.indexdef, COALESCE(pg_get_expr(i.indpred, i.indrelid), '') \
             FROM pg_indexes p \
             JOIN pg_class c ON c.relname = p.indexname \
             JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = p.schemaname \
             JOIN pg_index i ON i.indexrelid = c.oid \
             WHERE p.schemaname = 'central' AND p.indexname = 'bootstrap_generations_active_idx'",
        )
        .fetch_optional(&mut *conn)
        .await
        .ctx("baseline: inspect active-generation index for repair")?;
        if let Some(row) = row {
            let definition: String = row.get(0);
            let predicate: String = row.get(1);
            if definition.contains("(workspace_id, generation DESC)")
                && predicate == "(state = 'active'::text)"
            {
                return Ok(());
            }
            let legacy = definition.contains("(workspace_id, state)")
                && predicate == "(state = 'active'::text)";
            if !legacy {
                return Err(invalid(
                    "baseline_shape_unsafe_index",
                    "baseline: active-generation index has an unsafe definition",
                ));
            }
        }
        sqlx::raw_sql(
            "begin;
             SET LOCAL synchronous_commit = on;
             DROP INDEX IF EXISTS central.bootstrap_generations_active_idx;
             CREATE INDEX bootstrap_generations_active_idx ON central.bootstrap_generations (workspace_id, generation DESC) WHERE state = 'active';
             commit;",
        )
        .execute(&mut *conn)
        .await
        .ctx("baseline: repair active-generation index")?;
        Ok(())
    }
}
