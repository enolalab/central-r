-- version 14 | ledger checksum b10-artifact-lifecycle | source b10.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (14, 'b10-artifact-lifecycle', true) ON CONFLICT (version) DO NOTHING;


		INSERT INTO central.migration_progress (
			operation_id, version, progress_version, cursor_page, batch_count,
			records_processed, checksum_accumulator, source_checksum,
			classification, safety_binding_digest, last_committed_at
		) VALUES (
			gen_random_uuid(), 14, 1, 0, 0, 0,
			sha256(convert_to('b10-artifact-lifecycle' || ':init', 'UTF8')), 'b10-artifact-lifecycle', 'data_backfill',
			sha256(convert_to('b10-artifact-lifecycle' || ':safety', 'UTF8')), clock_timestamp()
		);

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.artifacts
			ADD COLUMN IF NOT EXISTS step_id uuid,
			ADD COLUMN IF NOT EXISTS step_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS tool_call_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS producer_id text,
			ADD COLUMN IF NOT EXISTS required_role text,
			ADD COLUMN IF NOT EXISTS staging_key text,
			ADD COLUMN IF NOT EXISTS content_generation uuid,
			ADD COLUMN IF NOT EXISTS ready_key text,
			ADD COLUMN IF NOT EXISTS declared_media_type text,
			ADD COLUMN IF NOT EXISTS detected_media_type text,
			ADD COLUMN IF NOT EXISTS display_name text,
			ADD COLUMN IF NOT EXISTS classification jsonb,
			ADD COLUMN IF NOT EXISTS limits_snapshot jsonb,
			ADD COLUMN IF NOT EXISTS rejection jsonb,
			ADD COLUMN IF NOT EXISTS ready_object_version text,
			ADD COLUMN IF NOT EXISTS reconciliation_state text NOT NULL DEFAULT 'none',
			ADD COLUMN IF NOT EXISTS reconciliation_failure_code text,
			ADD COLUMN IF NOT EXISTS reconciliation_updated_at timestamptz;

ALTER TABLE central.migration_progress
			ADD COLUMN IF NOT EXISTS phase text NOT NULL DEFAULT 'expand',
			ADD COLUMN IF NOT EXISTS cursor_workspace_id uuid,
			ADD COLUMN IF NOT EXISTS cursor_artifact_id uuid;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.migration_progress'::regclass AND conname = 'migration_progress_phase_b10_check'
		) THEN
			ALTER TABLE central.migration_progress ADD CONSTRAINT migration_progress_phase_b10_check CHECK (phase IN ('expand','classify','validate','enforce'));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.migration_progress'::regclass AND conname = 'migration_progress_cursor_pair_b10_check'
		) THEN
			ALTER TABLE central.migration_progress ADD CONSTRAINT migration_progress_cursor_pair_b10_check CHECK ((cursor_workspace_id IS NULL) = (cursor_artifact_id IS NULL));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_state_b10_check'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_state_b10_check CHECK (state IN ('reserved', 'staging', 'verifying', 'ready', 'delete_pending', 'deleted', 'quarantined', 'rejected'));
		END IF;
	END;
	$b08$;

ALTER TABLE central.artifacts DROP CONSTRAINT IF EXISTS artifacts_state_check;

CREATE TABLE IF NOT EXISTS central.artifact_command_receipts (
			id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			artifact_id uuid NOT NULL,
			command_kind text NOT NULL,
			idempotency_key text NOT NULL,
			request_fingerprint bytea NOT NULL,
			result_payload jsonb NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			expires_at timestamptz NOT NULL,
			CONSTRAINT artifact_command_receipts_scope_unique UNIQUE (workspace_id, command_kind, idempotency_key),
			CONSTRAINT artifact_command_receipts_fingerprint_check CHECK (octet_length(request_fingerprint) = 32)
		);

CREATE INDEX IF NOT EXISTS artifact_command_receipts_cleanup_idx ON central.artifact_command_receipts (workspace_id, expires_at);

CREATE TABLE IF NOT EXISTS central.artifact_reconciliation_progress (
			singleton boolean NOT NULL PRIMARY KEY,
			cursor_workspace_id uuid NULL,
			cursor_created_at timestamptz NULL,
			cursor_artifact_id uuid NULL,
			cycle bigint NOT NULL DEFAULT 0 CHECK (cycle >= 0),
			last_started_at timestamptz NULL,
			last_progress_at timestamptz NULL,
			last_completed_at timestamptz NULL,
			consecutive_dependency_failures bigint NOT NULL DEFAULT 0 CHECK (consecutive_dependency_failures >= 0),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			CONSTRAINT artifact_reconciliation_progress_singleton_check CHECK (singleton),
			CONSTRAINT artifact_reconciliation_progress_cursor_check CHECK (
				(cursor_workspace_id IS NULL AND cursor_created_at IS NULL AND cursor_artifact_id IS NULL)
				OR (cursor_workspace_id IS NOT NULL AND cursor_created_at IS NOT NULL AND cursor_artifact_id IS NOT NULL)
			)
		);

CREATE TABLE IF NOT EXISTS central.artifact_reconciliation_claims (
			artifact_id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			claim_kind text NOT NULL CHECK (claim_kind IN ('normal', 'large')),
			coordinator_generation bigint NOT NULL CHECK (coordinator_generation > 0),
			claim_token_hash bytea NOT NULL,
			lease_expires_at timestamptz NOT NULL,
			attempt_count bigint NOT NULL DEFAULT 1 CHECK (attempt_count > 0),
			next_eligible_at timestamptz NULL,
			last_failure_code text NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT artifact_reconciliation_claims_workspace_artifact_unique UNIQUE (workspace_id, artifact_id)
		);

CREATE INDEX IF NOT EXISTS artifact_reconciliation_claims_lease_idx ON central.artifact_reconciliation_claims (workspace_id, lease_expires_at);

CREATE TABLE IF NOT EXISTS central.provider_response_retrievals (
			id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL,
			run_id uuid NOT NULL,
			step_attempt_id uuid NOT NULL,
			provider_evidence_id uuid NOT NULL,
			response_id text NOT NULL,
			operation_id uuid NOT NULL,
			request_fingerprint bytea NOT NULL,
			expected_response_hash bytea NOT NULL,
			report_hash bytea NULL,
			report_size bigint NULL,
			fence_consumption_id uuid NOT NULL,
			state text NOT NULL CHECK (state IN ('prepared', 'delivered', 'reconciliation', 'verified')),
			failure_code text NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT provider_response_retrievals_operation_unique UNIQUE (workspace_id, operation_id),
			CONSTRAINT provider_response_retrievals_evidence_unique UNIQUE (workspace_id, provider_evidence_id),
			CONSTRAINT provider_response_retrievals_fingerprint_check CHECK (octet_length(request_fingerprint) = 32),
			CONSTRAINT provider_response_retrievals_expected_hash_check CHECK (octet_length(expected_response_hash) = 32),
			CONSTRAINT provider_response_retrievals_report_hash_check CHECK (report_hash IS NULL OR octet_length(report_hash) = 32),
			CONSTRAINT provider_response_retrievals_report_size_check CHECK (report_size IS NULL OR report_size >= 0)
		);

GRANT SELECT ON central.artifact_command_receipts TO central_runtime;

GRANT INSERT ON central.artifact_command_receipts TO central_runtime;

GRANT UPDATE ON central.artifact_command_receipts TO central_runtime;

GRANT SELECT ON central.artifact_reconciliation_progress TO central_runtime;

GRANT INSERT ON central.artifact_reconciliation_progress TO central_runtime;

GRANT UPDATE ON central.artifact_reconciliation_progress TO central_runtime;

GRANT SELECT ON central.artifact_reconciliation_claims TO central_runtime;

GRANT INSERT ON central.artifact_reconciliation_claims TO central_runtime;

GRANT UPDATE ON central.artifact_reconciliation_claims TO central_runtime;

GRANT SELECT ON central.provider_response_retrievals TO central_runtime;

GRANT INSERT ON central.provider_response_retrievals TO central_runtime;

GRANT UPDATE ON central.provider_response_retrievals TO central_runtime;

GRANT INSERT ON central.artifacts TO central_runtime;

GRANT UPDATE ON central.artifacts TO central_runtime;

GRANT INSERT ON central.capacity_reservations TO central_runtime;

GRANT UPDATE ON central.capacity_reservations TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.migration_progress
		SET phase = 'classify', progress_version = progress_version + 1, last_committed_at = clock_timestamp()
		WHERE version = 14 AND phase = 'expand';

commit;

begin;

SET LOCAL synchronous_commit = on;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.migration_progress
		SET phase = 'validate', progress_version = progress_version + 1, last_committed_at = clock_timestamp()
		WHERE version = 14 AND phase = 'classify';

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.migration_progress
		SET phase = 'enforce', progress_version = progress_version + 1, last_committed_at = clock_timestamp()
		WHERE version = 14 AND phase = 'validate';

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE UNIQUE INDEX IF NOT EXISTS artifacts_workspace_id_unique_idx ON central.artifacts (workspace_id, id);

ALTER TABLE central.artifacts DROP CONSTRAINT IF EXISTS artifacts_task_id_fkey;

ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_task_id_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks (workspace_id, id) NOT VALID;

ALTER TABLE central.artifacts DROP CONSTRAINT IF EXISTS artifacts_run_id_fkey;

ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_run_id_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs (workspace_id, id) NOT VALID;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_step_id_fkey'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_step_id_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps (workspace_id, id) NOT VALID;
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_step_attempt_id_fkey'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_step_attempt_id_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts (workspace_id, id) NOT VALID;
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_lineage_fkey'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_lineage_fkey FOREIGN KEY (workspace_id, lineage_artifact_id) REFERENCES central.artifacts (workspace_id, id) NOT VALID;
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_checksum_value_b10_check'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_checksum_value_b10_check CHECK (checksum_value IS NULL OR octet_length(checksum_value) = 32);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_ready_requires_metadata_b10_check'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_ready_requires_metadata_b10_check CHECK (state <> 'ready' OR reconciliation_state = 'legacy_unverified' OR (ready_key IS NOT NULL AND content_generation IS NOT NULL AND checksum_value IS NOT NULL));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_staging_requires_key_b10_check'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_staging_requires_key_b10_check CHECK (state NOT IN ('staging', 'verifying') OR staging_key IS NOT NULL);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifacts'::regclass AND conname = 'artifacts_no_ready_key_b10_check'
		) THEN
			ALTER TABLE central.artifacts ADD CONSTRAINT artifacts_no_ready_key_b10_check CHECK (state NOT IN ('reserved', 'rejected') OR ready_key IS NULL);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS artifacts_workspace_staging_key_unique_idx ON central.artifacts (workspace_id, staging_key) WHERE staging_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS artifacts_workspace_content_generation_unique_idx ON central.artifacts (workspace_id, content_generation) WHERE content_generation IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS artifacts_workspace_ready_key_unique_idx ON central.artifacts (workspace_id, ready_key) WHERE ready_key IS NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifact_command_receipts'::regclass AND conname = 'artifact_command_receipts_artifact_fkey'
		) THEN
			ALTER TABLE central.artifact_command_receipts ADD CONSTRAINT artifact_command_receipts_artifact_fkey FOREIGN KEY (workspace_id, artifact_id) REFERENCES central.artifacts (workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.artifact_reconciliation_claims'::regclass AND conname = 'artifact_reconciliation_claims_artifact_fkey'
		) THEN
			ALTER TABLE central.artifact_reconciliation_claims ADD CONSTRAINT artifact_reconciliation_claims_artifact_fkey FOREIGN KEY (workspace_id, artifact_id) REFERENCES central.artifacts (workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_response_retrievals'::regclass AND conname = 'provider_response_retrievals_evidence_fkey'
		) THEN
			ALTER TABLE central.provider_response_retrievals ADD CONSTRAINT provider_response_retrievals_evidence_fkey FOREIGN KEY (workspace_id, provider_evidence_id) REFERENCES central.provider_execution_evidence (workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_response_retrievals'::regclass AND conname = 'provider_response_retrievals_fence_fkey'
		) THEN
			ALTER TABLE central.provider_response_retrievals ADD CONSTRAINT provider_response_retrievals_fence_fkey FOREIGN KEY (fence_consumption_id) REFERENCES central.provider_fence_consumptions (id);
		END IF;
	END;
	$b08$;

INSERT INTO central.artifact_reconciliation_progress (singleton, cycle, consecutive_dependency_failures, version)
			VALUES (true, 0, 0, 0) ON CONFLICT (singleton) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 14 AND checksum = 'b10-artifact-lifecycle' AND dirty = true;

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (14, 'b10-artifact-lifecycle', clock_timestamp());

commit;

