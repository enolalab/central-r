-- version 9 | ledger checksum b08-recovery-evidence-correction | source b08_recovery_correction.go

begin;

SET LOCAL synchronous_commit = on;


		INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (9, 'b08-recovery-evidence-correction', true)
		ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.recovery_epoch_workspaces
		 ADD COLUMN IF NOT EXISTS retry_not_before timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS step_attempts_one_successor_idx
		 ON central.step_attempts (workspace_id, predecessor_id)
		 WHERE predecessor_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS central.execution_completion_receipts (
			id uuid PRIMARY KEY,
			workspace_id uuid NOT NULL,
			task_id uuid NOT NULL,
			run_id uuid NOT NULL,
			step_id uuid NOT NULL,
			step_attempt_id uuid NOT NULL,
			logical_operation_id uuid NOT NULL,
			physical_attempt_id uuid NOT NULL,
			invocation_id uuid NOT NULL,
			invocation_generation bigint NOT NULL CHECK (invocation_generation > 0),
			final_state text NOT NULL CHECK (final_state IN ('succeeded','failed')),
			outcome jsonb NOT NULL CHECK (octet_length(outcome::text) <= 262144),
			context jsonb CHECK (context IS NULL OR octet_length(context::text) <= 262144),
			evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
			producer_id text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			policy_version bigint NOT NULL DEFAULT 1,
			eligible_after timestamptz NOT NULL,
			legal_hold boolean NOT NULL DEFAULT false,
			CONSTRAINT execution_completion_receipts_workspace_attempt_fkey
				FOREIGN KEY (workspace_id, step_attempt_id)
				REFERENCES central.step_attempts(workspace_id, id),
			CONSTRAINT execution_completion_receipts_workspace_task_fkey
				FOREIGN KEY (workspace_id, task_id)
				REFERENCES central.tasks(workspace_id, id),
			CONSTRAINT execution_completion_receipts_workspace_run_fkey
				FOREIGN KEY (workspace_id, run_id)
				REFERENCES central.runs(workspace_id, id),
			CONSTRAINT execution_completion_receipts_workspace_step_fkey
				FOREIGN KEY (workspace_id, step_id)
				REFERENCES central.steps(workspace_id, id)
		);

CREATE UNIQUE INDEX IF NOT EXISTS execution_completion_receipts_attempt_idx
		 ON central.execution_completion_receipts (workspace_id, step_attempt_id);

CREATE UNIQUE INDEX IF NOT EXISTS execution_completion_receipts_invocation_idx
		 ON central.execution_completion_receipts (
			workspace_id, logical_operation_id, invocation_generation, invocation_id
		 );

CREATE INDEX IF NOT EXISTS execution_completion_receipts_retention_idx
		 ON central.execution_completion_receipts (workspace_id, eligible_after, id);

GRANT SELECT ON central.execution_completion_receipts TO central_runtime;

GRANT INSERT ON central.execution_completion_receipts TO central_runtime;

GRANT UPDATE ON central.tasks TO central_runtime;

GRANT UPDATE ON central.runs TO central_runtime;

GRANT INSERT ON central.workspace_event_counters TO central_runtime;

GRANT UPDATE ON central.workspace_event_counters TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;


		UPDATE central.schema_migrations
		SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 9 AND checksum = 'b08-recovery-evidence-correction' AND dirty = true;


		INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (9, 'b08-recovery-evidence-correction', clock_timestamp());

commit;

