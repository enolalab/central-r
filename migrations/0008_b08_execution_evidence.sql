-- version 8 | ledger checksum b08-execution-evidence | source b08.go

begin;

SET LOCAL synchronous_commit = on;


		INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (8, 'b08-execution-evidence', true)
		ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.runs ADD COLUMN IF NOT EXISTS reconciled_epoch bigint NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS workspaces_workspace_id_unique_idx ON central.workspaces (id);

CREATE UNIQUE INDEX IF NOT EXISTS tasks_workspace_id_unique_idx ON central.tasks (workspace_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS runs_workspace_id_unique_idx ON central.runs (workspace_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS steps_workspace_id_unique_idx ON central.steps (workspace_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS step_attempts_workspace_id_unique_idx ON central.step_attempts (workspace_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS tool_calls_workspace_id_unique_idx ON central.tool_calls (workspace_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS tool_call_attempts_workspace_id_unique_idx ON central.tool_call_attempts (workspace_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS events_workspace_id_unique_idx ON central.events (workspace_id, id);

ALTER TABLE central.steps
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS state text,
			ADD COLUMN IF NOT EXISTS logical_operation_id uuid,
			ADD COLUMN IF NOT EXISTS sequence bigint;

UPDATE central.steps s
		 SET task_id = COALESCE(s.task_id, r.task_id),
		     state = COALESCE(s.state, CASE s.status
			 WHEN 'queued' THEN 'queued' WHEN 'running' THEN 'running'
			 WHEN 'completed' THEN 'succeeded' WHEN 'failed' THEN 'failed'
			 WHEN 'cancelled' THEN 'cancelled' ELSE 'reconciliation' END),
		     logical_operation_id = COALESCE(s.logical_operation_id, gen_random_uuid()),
		     sequence = COALESCE(s.sequence, s.step_index)
		 FROM central.runs r
		 WHERE r.id = s.run_id;

ALTER TABLE central.steps
			ALTER COLUMN task_id SET NOT NULL,
			ALTER COLUMN state SET NOT NULL,
			ALTER COLUMN logical_operation_id SET NOT NULL,
			ALTER COLUMN sequence SET NOT NULL,
			ALTER COLUMN status DROP NOT NULL,
			ALTER COLUMN step_index DROP NOT NULL,
			ALTER COLUMN step_kind DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.steps'::regclass AND conname = 'steps_state_b08_check'
		) THEN
			ALTER TABLE central.steps ADD CONSTRAINT steps_state_b08_check CHECK (state IN ('queued','running','waiting','settling','succeeded','failed','cancelled','reconciliation'));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.steps'::regclass AND conname = 'steps_workspace_task_b08_fkey'
		) THEN
			ALTER TABLE central.steps ADD CONSTRAINT steps_workspace_task_b08_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.steps'::regclass AND conname = 'steps_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.steps ADD CONSTRAINT steps_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS steps_workspace_run_operation_unique_idx ON central.steps (workspace_id, run_id, logical_operation_id);

CREATE INDEX IF NOT EXISTS steps_workspace_state_created_idx ON central.steps (workspace_id, state, created_at, id);

ALTER TABLE central.step_attempts
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS run_id uuid,
			ADD COLUMN IF NOT EXISTS logical_operation_id uuid,
			ADD COLUMN IF NOT EXISTS physical_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS invocation_id uuid,
			ADD COLUMN IF NOT EXISTS invocation_generation bigint,
			ADD COLUMN IF NOT EXISTS predecessor_id uuid,
			ADD COLUMN IF NOT EXISTS sequence bigint,
			ADD COLUMN IF NOT EXISTS state text,
			ADD COLUMN IF NOT EXISTS outcome jsonb,
			ADD COLUMN IF NOT EXISTS context jsonb;

UPDATE central.step_attempts a
		 SET task_id = COALESCE(a.task_id, s.task_id),
		     run_id = COALESCE(a.run_id, s.run_id),
		     logical_operation_id = COALESCE(a.logical_operation_id, gen_random_uuid()),
		     physical_attempt_id = COALESCE(a.physical_attempt_id, a.id),
		     invocation_id = COALESCE(a.invocation_id, CASE WHEN a.status IN ('invoked','succeeded','retryable_failure','terminal_failure') THEN gen_random_uuid() END),
		     invocation_generation = COALESCE(a.invocation_generation, CASE WHEN a.status IN ('invoked','succeeded','retryable_failure','terminal_failure') THEN 1 END),
		     sequence = COALESCE(a.sequence, a.attempt_index),
		     state = COALESCE(a.state, CASE a.status
			 WHEN 'prepared' THEN 'prepared' WHEN 'invoked' THEN 'invoked'
			 WHEN 'succeeded' THEN 'succeeded' WHEN 'cancelled' THEN 'cancelled'
			 WHEN 'ambiguous' THEN 'reconciliation' ELSE 'failed' END),
		     outcome = COALESCE(a.outcome, a.outcome_evidence)
		 FROM central.steps s
		 WHERE s.id = a.step_id;

ALTER TABLE central.step_attempts
			ALTER COLUMN task_id SET NOT NULL,
			ALTER COLUMN run_id SET NOT NULL,
			ALTER COLUMN logical_operation_id SET NOT NULL,
			ALTER COLUMN physical_attempt_id SET NOT NULL,
			ALTER COLUMN sequence SET NOT NULL,
			ALTER COLUMN state SET NOT NULL,
			ALTER COLUMN status DROP NOT NULL,
			ALTER COLUMN attempt_index DROP NOT NULL,
			ALTER COLUMN adapter_identity DROP NOT NULL,
			ALTER COLUMN adapter_revision DROP NOT NULL,
			ALTER COLUMN operation_key DROP NOT NULL,
			ALTER COLUMN manifest_hash DROP NOT NULL,
			ALTER COLUMN budget_config DROP NOT NULL,
			ALTER COLUMN authority_deadline DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_state_b08_check'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_state_b08_check CHECK (state IN ('prepared','invoked','settling','succeeded','failed','cancelled','reconciliation'));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_invocation_pair_b08_check'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_invocation_pair_b08_check CHECK ((invocation_id IS NULL) = (invocation_generation IS NULL));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_workspace_step_b08_fkey'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_workspace_step_b08_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_workspace_task_b08_fkey'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_workspace_task_b08_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_predecessor_b08_fkey'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_predecessor_b08_fkey FOREIGN KEY (workspace_id, predecessor_id) REFERENCES central.step_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS step_attempts_physical_attempt_unique_idx ON central.step_attempts (physical_attempt_id);

CREATE UNIQUE INDEX IF NOT EXISTS step_attempts_one_active_run_idx ON central.step_attempts (workspace_id, run_id) WHERE state IN ('prepared','invoked','settling','reconciliation');

CREATE UNIQUE INDEX IF NOT EXISTS step_attempts_invocation_idx ON central.step_attempts (workspace_id, logical_operation_id, invocation_generation, invocation_id) WHERE invocation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS step_attempts_unsettled_idx ON central.step_attempts (workspace_id, state, updated_at, id) WHERE state IN ('prepared','invoked','settling','reconciliation');

ALTER TABLE central.tool_calls
			ADD COLUMN IF NOT EXISTS step_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS run_id uuid,
			ADD COLUMN IF NOT EXISTS logical_operation_id uuid,
			ADD COLUMN IF NOT EXISTS sequence bigint,
			ADD COLUMN IF NOT EXISTS state text;

UPDATE central.tool_calls c
		 SET step_attempt_id = COALESCE(c.step_attempt_id, (
			 SELECT a.id FROM central.step_attempts a
			 WHERE a.workspace_id = c.workspace_id AND a.step_id = c.step_id
		     )),
		     task_id = COALESCE(c.task_id, s.task_id),
		     run_id = COALESCE(c.run_id, s.run_id),
		     logical_operation_id = COALESCE(c.logical_operation_id, gen_random_uuid()),
		     sequence = COALESCE(c.sequence, c.tool_index),
		     state = COALESCE(c.state, CASE c.status
			 WHEN 'queued' THEN 'queued' WHEN 'running' THEN 'invoked'
			 WHEN 'completed' THEN 'succeeded' ELSE 'failed' END)
		 FROM central.steps s
		 WHERE s.id = c.step_id;

ALTER TABLE central.tool_calls
			ALTER COLUMN step_attempt_id SET NOT NULL,
			ALTER COLUMN task_id SET NOT NULL,
			ALTER COLUMN run_id SET NOT NULL,
			ALTER COLUMN logical_operation_id SET NOT NULL,
			ALTER COLUMN sequence SET NOT NULL,
			ALTER COLUMN state SET NOT NULL,
			ALTER COLUMN status DROP NOT NULL,
			ALTER COLUMN tool_index DROP NOT NULL,
			ALTER COLUMN tool_identity DROP NOT NULL,
			ALTER COLUMN tool_operation DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_calls'::regclass AND conname = 'tool_calls_state_b08_check'
		) THEN
			ALTER TABLE central.tool_calls ADD CONSTRAINT tool_calls_state_b08_check CHECK (state IN ('queued','prepared','invoked','settling','succeeded','failed','cancelled','reconciliation'));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_calls'::regclass AND conname = 'tool_calls_workspace_attempt_b08_fkey'
		) THEN
			ALTER TABLE central.tool_calls ADD CONSTRAINT tool_calls_workspace_attempt_b08_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_calls'::regclass AND conname = 'tool_calls_workspace_task_b08_fkey'
		) THEN
			ALTER TABLE central.tool_calls ADD CONSTRAINT tool_calls_workspace_task_b08_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_calls'::regclass AND conname = 'tool_calls_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.tool_calls ADD CONSTRAINT tool_calls_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS tool_calls_workspace_run_operation_unique_idx ON central.tool_calls (workspace_id, run_id, logical_operation_id);

CREATE INDEX IF NOT EXISTS tool_calls_workspace_state_created_idx ON central.tool_calls (workspace_id, state, created_at, id);

ALTER TABLE central.tool_call_attempts
			ADD COLUMN IF NOT EXISTS step_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS run_id uuid,
			ADD COLUMN IF NOT EXISTS logical_operation_id uuid,
			ADD COLUMN IF NOT EXISTS physical_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS invocation_id uuid,
			ADD COLUMN IF NOT EXISTS invocation_generation bigint,
			ADD COLUMN IF NOT EXISTS predecessor_id uuid,
			ADD COLUMN IF NOT EXISTS sequence bigint,
			ADD COLUMN IF NOT EXISTS state text,
			ADD COLUMN IF NOT EXISTS outcome jsonb,
			ADD COLUMN IF NOT EXISTS context jsonb;

UPDATE central.tool_call_attempts a
		 SET step_attempt_id = COALESCE(a.step_attempt_id, c.step_attempt_id),
		     task_id = COALESCE(a.task_id, c.task_id),
		     run_id = COALESCE(a.run_id, c.run_id),
		     logical_operation_id = COALESCE(a.logical_operation_id, c.logical_operation_id),
		     physical_attempt_id = COALESCE(a.physical_attempt_id, a.id),
		     invocation_id = COALESCE(a.invocation_id, CASE WHEN a.status IN ('invoked','succeeded','retryable_failure','terminal_failure') THEN gen_random_uuid() END),
		     invocation_generation = COALESCE(a.invocation_generation, CASE WHEN a.status IN ('invoked','succeeded','retryable_failure','terminal_failure') THEN 1 END),
		     sequence = COALESCE(a.sequence, a.attempt_index),
		     state = COALESCE(a.state, CASE a.status
			 WHEN 'prepared' THEN 'prepared' WHEN 'invoked' THEN 'invoked'
			 WHEN 'succeeded' THEN 'succeeded' WHEN 'cancelled' THEN 'cancelled'
			 WHEN 'ambiguous' THEN 'reconciliation' ELSE 'failed' END),
		     outcome = COALESCE(a.outcome, a.outcome_evidence)
		 FROM central.tool_calls c
		 WHERE c.id = a.tool_call_id;

ALTER TABLE central.tool_call_attempts
			ALTER COLUMN step_attempt_id SET NOT NULL,
			ALTER COLUMN task_id SET NOT NULL,
			ALTER COLUMN run_id SET NOT NULL,
			ALTER COLUMN logical_operation_id SET NOT NULL,
			ALTER COLUMN physical_attempt_id SET NOT NULL,
			ALTER COLUMN sequence SET NOT NULL,
			ALTER COLUMN state SET NOT NULL,
			ALTER COLUMN status DROP NOT NULL,
			ALTER COLUMN attempt_index DROP NOT NULL,
			ALTER COLUMN adapter_identity DROP NOT NULL,
			ALTER COLUMN adapter_revision DROP NOT NULL,
			ALTER COLUMN operation_key DROP NOT NULL,
			ALTER COLUMN manifest_hash DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_call_attempts'::regclass AND conname = 'tool_call_attempts_state_b08_check'
		) THEN
			ALTER TABLE central.tool_call_attempts ADD CONSTRAINT tool_call_attempts_state_b08_check CHECK (state IN ('prepared','invoked','settling','succeeded','failed','cancelled','reconciliation'));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_call_attempts'::regclass AND conname = 'tool_call_attempts_invocation_pair_b08_check'
		) THEN
			ALTER TABLE central.tool_call_attempts ADD CONSTRAINT tool_call_attempts_invocation_pair_b08_check CHECK ((invocation_id IS NULL) = (invocation_generation IS NULL));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_call_attempts'::regclass AND conname = 'tool_call_attempts_workspace_call_b08_fkey'
		) THEN
			ALTER TABLE central.tool_call_attempts ADD CONSTRAINT tool_call_attempts_workspace_call_b08_fkey FOREIGN KEY (workspace_id, tool_call_id) REFERENCES central.tool_calls(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_call_attempts'::regclass AND conname = 'tool_call_attempts_workspace_parent_b08_fkey'
		) THEN
			ALTER TABLE central.tool_call_attempts ADD CONSTRAINT tool_call_attempts_workspace_parent_b08_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tool_call_attempts'::regclass AND conname = 'tool_call_attempts_predecessor_b08_fkey'
		) THEN
			ALTER TABLE central.tool_call_attempts ADD CONSTRAINT tool_call_attempts_predecessor_b08_fkey FOREIGN KEY (workspace_id, predecessor_id) REFERENCES central.tool_call_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS tool_call_attempts_physical_attempt_unique_idx ON central.tool_call_attempts (physical_attempt_id);

CREATE UNIQUE INDEX IF NOT EXISTS tool_call_attempts_invocation_unique_idx ON central.tool_call_attempts (workspace_id, logical_operation_id, invocation_generation, invocation_id) WHERE invocation_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS tool_call_attempts_one_active_call_idx ON central.tool_call_attempts (workspace_id, tool_call_id) WHERE state IN ('prepared','invoked','settling','reconciliation');

CREATE INDEX IF NOT EXISTS tool_call_attempts_unsettled_idx ON central.tool_call_attempts (workspace_id, state, updated_at, id) WHERE state IN ('prepared','invoked','settling','reconciliation');

ALTER TABLE central.execution_ownership
			ADD COLUMN IF NOT EXISTS run_id uuid,
			ADD COLUMN IF NOT EXISTS lease_token_hash bytea,
			ADD COLUMN IF NOT EXISTS fencing_generation bigint NOT NULL DEFAULT 0,
			ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz,
			ADD COLUMN IF NOT EXISTS reconciled_epoch bigint NOT NULL DEFAULT 0;

UPDATE central.execution_ownership
		 SET run_id = COALESCE(run_id, claimed_run_id),
		     lease_token_hash = COALESCE(lease_token_hash, sha256(convert_to(fencing_token::text, 'UTF8'))),
		     lease_expires_at = COALESCE(lease_expires_at, lease_expiry);

ALTER TABLE central.execution_ownership
			ALTER COLUMN lease_token_hash SET NOT NULL,
			ALTER COLUMN lease_expires_at SET NOT NULL,
			ALTER COLUMN owner_scope DROP NOT NULL,
			ALTER COLUMN owner_identity DROP NOT NULL,
			ALTER COLUMN fencing_token DROP NOT NULL,
			ALTER COLUMN lease_expiry DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_ownership'::regclass AND conname = 'execution_ownership_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.execution_ownership ADD CONSTRAINT execution_ownership_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS execution_ownership_one_run_idx ON central.execution_ownership (workspace_id, run_id) WHERE run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS execution_ownership_workspace_lease_run_idx ON central.execution_ownership (workspace_id, lease_expires_at, run_id);

CREATE INDEX IF NOT EXISTS runs_workspace_reconciled_created_idx ON central.runs (workspace_id, reconciled_epoch, created_at, id);

CREATE INDEX IF NOT EXISTS runs_workspace_created_id_idx ON central.runs (workspace_id, created_at, id);

ALTER TABLE central.checkpoints
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS step_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS producer_id text,
			ADD COLUMN IF NOT EXISTS producer_version text,
			ADD COLUMN IF NOT EXISTS schema_version bigint,
			ADD COLUMN IF NOT EXISTS checksum bytea,
			ADD COLUMN IF NOT EXISTS payload bytea,
			ADD COLUMN IF NOT EXISTS resume_compatible boolean NOT NULL DEFAULT false,
			ADD COLUMN IF NOT EXISTS validated boolean NOT NULL DEFAULT false,
			ADD COLUMN IF NOT EXISTS policy_version bigint NOT NULL DEFAULT 1,
			ADD COLUMN IF NOT EXISTS recorded_at timestamptz,
			ADD COLUMN IF NOT EXISTS eligible_after timestamptz,
			ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false;

UPDATE central.checkpoints c
		 SET task_id = COALESCE(c.task_id, r.task_id),
		     producer_id = COALESCE(c.producer_id, 'legacy-baseline'),
		     producer_version = COALESCE(c.producer_version, '0'),
		     schema_version = COALESCE(c.schema_version, 0),
		     payload = COALESCE(c.payload, convert_to(c.metadata::text, 'UTF8')),
		     checksum = COALESCE(c.checksum, sha256(convert_to(c.metadata::text, 'UTF8'))),
		     recorded_at = COALESCE(c.recorded_at, c.created_at),
		     eligible_after = COALESCE(c.eligible_after, c.created_at + interval '90 days')
		 FROM central.runs r WHERE r.id = c.run_id;

ALTER TABLE central.checkpoints
			ALTER COLUMN task_id SET NOT NULL,
			ALTER COLUMN producer_id SET NOT NULL,
			ALTER COLUMN producer_version SET NOT NULL,
			ALTER COLUMN schema_version SET NOT NULL,
			ALTER COLUMN checksum SET NOT NULL,
			ALTER COLUMN payload SET NOT NULL,
			ALTER COLUMN recorded_at SET NOT NULL,
			ALTER COLUMN eligible_after SET NOT NULL,
			ALTER COLUMN checkpoint_kind DROP NOT NULL,
			ALTER COLUMN metadata DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.checkpoints'::regclass AND conname = 'checkpoints_payload_b08_check'
		) THEN
			ALTER TABLE central.checkpoints ADD CONSTRAINT checkpoints_payload_b08_check CHECK (octet_length(payload) <= 1048576 AND octet_length(checksum) = 32);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.checkpoints'::regclass AND conname = 'checkpoints_workspace_task_b08_fkey'
		) THEN
			ALTER TABLE central.checkpoints ADD CONSTRAINT checkpoints_workspace_task_b08_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.checkpoints'::regclass AND conname = 'checkpoints_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.checkpoints ADD CONSTRAINT checkpoints_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.checkpoints'::regclass AND conname = 'checkpoints_workspace_step_b08_fkey'
		) THEN
			ALTER TABLE central.checkpoints ADD CONSTRAINT checkpoints_workspace_step_b08_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.checkpoints'::regclass AND conname = 'checkpoints_workspace_attempt_b08_fkey'
		) THEN
			ALTER TABLE central.checkpoints ADD CONSTRAINT checkpoints_workspace_attempt_b08_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE INDEX IF NOT EXISTS checkpoints_workspace_run_recorded_idx ON central.checkpoints (workspace_id, run_id, recorded_at DESC, id DESC);

ALTER TABLE central.approvals
			ADD COLUMN IF NOT EXISTS approval_kind text NOT NULL DEFAULT 'capability',
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS run_id uuid,
			ADD COLUMN IF NOT EXISTS step_id uuid,
			ADD COLUMN IF NOT EXISTS subject_version bigint,
			ADD COLUMN IF NOT EXISTS logical_operation_id uuid,
			ADD COLUMN IF NOT EXISTS operation_digest bytea,
			ADD COLUMN IF NOT EXISTS expected_step_version bigint,
			ADD COLUMN IF NOT EXISTS decision_actor text,
			ADD COLUMN IF NOT EXISTS decision_reason text,
			ADD COLUMN IF NOT EXISTS decision_id uuid,
			ADD COLUMN IF NOT EXISTS decided_at timestamptz,
			ADD COLUMN IF NOT EXISTS predecessor_approval_id uuid,
			ADD COLUMN IF NOT EXISTS recorded_at timestamptz;

UPDATE central.approvals
		 SET recorded_at = COALESCE(recorded_at, created_at),
		     decision_actor = COALESCE(decision_actor, actor_identity),
		     decision_reason = COALESCE(decision_reason, reason);

ALTER TABLE central.approvals
			DROP CONSTRAINT IF EXISTS approvals_state_check,
			ADD CONSTRAINT approvals_state_check CHECK (state IN ('active','revoked','suspended','pending','approved','rejected','expired','superseded')),
			ALTER COLUMN capability_identity DROP NOT NULL,
			ALTER COLUMN scope DROP NOT NULL,
			ALTER COLUMN action DROP NOT NULL,
			ALTER COLUMN actor_identity DROP NOT NULL,
			ALTER COLUMN authority_identity DROP NOT NULL,
			ALTER COLUMN reason DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.approvals'::regclass AND conname = 'approvals_execution_subject_b08_check'
		) THEN
			ALTER TABLE central.approvals ADD CONSTRAINT approvals_execution_subject_b08_check CHECK (
			(approval_kind = 'capability') OR
			(approval_kind = 'execution' AND task_id IS NOT NULL AND run_id IS NOT NULL AND step_id IS NOT NULL
			 AND subject_version IS NOT NULL AND logical_operation_id IS NOT NULL
			 AND octet_length(operation_digest) = 32 AND expected_step_version IS NOT NULL
			 AND recorded_at IS NOT NULL)
		);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.approvals'::regclass AND conname = 'approvals_workspace_task_b08_fkey'
		) THEN
			ALTER TABLE central.approvals ADD CONSTRAINT approvals_workspace_task_b08_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.approvals'::regclass AND conname = 'approvals_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.approvals ADD CONSTRAINT approvals_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.approvals'::regclass AND conname = 'approvals_workspace_step_b08_fkey'
		) THEN
			ALTER TABLE central.approvals ADD CONSTRAINT approvals_workspace_step_b08_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS approvals_workspace_id_unique_idx ON central.approvals (workspace_id, id);

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.approvals'::regclass AND conname = 'approvals_predecessor_b08_fkey'
		) THEN
			ALTER TABLE central.approvals ADD CONSTRAINT approvals_predecessor_b08_fkey FOREIGN KEY (workspace_id, predecessor_approval_id) REFERENCES central.approvals(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS approvals_one_pending_subject_idx ON central.approvals (workspace_id, run_id, step_id, logical_operation_id) WHERE approval_kind = 'execution' AND state = 'pending';

ALTER TABLE central.events
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS step_id uuid,
			ADD COLUMN IF NOT EXISTS attempt_id uuid,
			ADD COLUMN IF NOT EXISTS kind text,
			ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'recorded',
			ADD COLUMN IF NOT EXISTS producer_id text,
			ADD COLUMN IF NOT EXISTS policy_version bigint NOT NULL DEFAULT 1,
			ADD COLUMN IF NOT EXISTS eligible_after timestamptz,
			ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false;

UPDATE central.events e
		 SET task_id = COALESCE(e.task_id, r.task_id),
		     kind = COALESCE(e.kind, e.event_type),
		     producer_id = COALESCE(e.producer_id, 'legacy-baseline'),
		     eligible_after = COALESCE(e.eligible_after, e.occurred_at + interval '90 days')
		 FROM central.runs r WHERE r.id = e.run_id;

UPDATE central.events
		 SET kind = COALESCE(kind, event_type),
		     producer_id = COALESCE(producer_id, 'legacy-baseline'),
		     eligible_after = COALESCE(eligible_after, occurred_at + interval '90 days');

ALTER TABLE central.events
			ALTER COLUMN kind SET NOT NULL,
			ALTER COLUMN producer_id SET NOT NULL,
			ALTER COLUMN eligible_after SET NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.events'::regclass AND conname = 'events_payload_b08_check'
		) THEN
			ALTER TABLE central.events ADD CONSTRAINT events_payload_b08_check CHECK (octet_length(convert_to(payload::text, 'UTF8')) <= 65536);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.events'::regclass AND conname = 'events_workspace_task_b08_fkey'
		) THEN
			ALTER TABLE central.events ADD CONSTRAINT events_workspace_task_b08_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.events'::regclass AND conname = 'events_workspace_run_b08_fkey'
		) THEN
			ALTER TABLE central.events ADD CONSTRAINT events_workspace_run_b08_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.events'::regclass AND conname = 'events_workspace_step_b08_fkey'
		) THEN
			ALTER TABLE central.events ADD CONSTRAINT events_workspace_step_b08_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.events'::regclass AND conname = 'events_workspace_attempt_b08_fkey'
		) THEN
			ALTER TABLE central.events ADD CONSTRAINT events_workspace_attempt_b08_fkey FOREIGN KEY (workspace_id, attempt_id) REFERENCES central.step_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE INDEX IF NOT EXISTS events_workspace_state_created_idx ON central.events (workspace_id, state, occurred_at, id);

ALTER TABLE central.outbox
			ADD COLUMN IF NOT EXISTS catalog_type text,
			ADD COLUMN IF NOT EXISTS deduplication_key text,
			ADD COLUMN IF NOT EXISTS producer_id text,
			ADD COLUMN IF NOT EXISTS payload jsonb,
			ADD COLUMN IF NOT EXISTS visible_at timestamptz,
			ADD COLUMN IF NOT EXISTS claim_token_hash bytea,
			ADD COLUMN IF NOT EXISTS claim_expires_at timestamptz,
			ADD COLUMN IF NOT EXISTS delivered_at timestamptz,
			ADD COLUMN IF NOT EXISTS policy_version bigint NOT NULL DEFAULT 1,
			ADD COLUMN IF NOT EXISTS eligible_after timestamptz,
			ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false;

ALTER TABLE central.outbox DROP CONSTRAINT IF EXISTS outbox_delivery_state_check;

UPDATE central.outbox
		 SET catalog_type = COALESCE(catalog_type, 'legacy.' || delivery_state),
		     deduplication_key = COALESCE(deduplication_key, event_id::text),
		     producer_id = COALESCE(producer_id, 'legacy-baseline'),
		     payload = COALESCE(payload, '{}'::jsonb),
		     visible_at = COALESCE(visible_at, retry_at, due_at),
		     claim_expires_at = COALESCE(claim_expires_at, lease_expiry),
		     delivered_at = COALESCE(delivered_at, CASE WHEN delivery_state = 'delivered' THEN updated_at END),
		     eligible_after = COALESCE(eligible_after, updated_at + interval '7 days'),
		     delivery_state = CASE
		       WHEN delivery_state IN ('delivered', 'dead_letter') THEN 'dispatched'
		       ELSE delivery_state
		     END;

ALTER TABLE central.outbox
			ALTER COLUMN catalog_type SET NOT NULL,
			ALTER COLUMN deduplication_key SET NOT NULL,
			ALTER COLUMN producer_id SET NOT NULL,
			ALTER COLUMN payload SET NOT NULL,
			ALTER COLUMN visible_at SET NOT NULL,
			ALTER COLUMN eligible_after SET NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.outbox'::regclass AND conname = 'outbox_delivery_state_check'
		) THEN
			ALTER TABLE central.outbox ADD CONSTRAINT outbox_delivery_state_check CHECK (delivery_state IN ('pending','claimed','dispatched'));
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.outbox'::regclass AND conname = 'outbox_payload_b08_check'
		) THEN
			ALTER TABLE central.outbox ADD CONSTRAINT outbox_payload_b08_check CHECK (octet_length(convert_to(payload::text, 'UTF8')) <= 65536);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.outbox'::regclass AND conname = 'outbox_workspace_event_b08_fkey'
		) THEN
			ALTER TABLE central.outbox ADD CONSTRAINT outbox_workspace_event_b08_fkey FOREIGN KEY (workspace_id, event_id) REFERENCES central.events(workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS outbox_workspace_catalog_dedup_unique_idx ON central.outbox (workspace_id, catalog_type, deduplication_key);

CREATE INDEX IF NOT EXISTS outbox_workspace_delivery_visible_idx ON central.outbox (workspace_id, delivery_state, visible_at, id) WHERE delivery_state IN ('pending','claimed');

CREATE TABLE IF NOT EXISTS central.execution_command_receipts (
			id uuid PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			command_scope text NOT NULL,
			idempotency_key text NOT NULL,
			request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
			principal_id text NOT NULL,
			capability text NOT NULL CHECK (capability IN ('executor','approver','workspace_operator','recovery_coordinator')),
			expected_version_digest bytea NOT NULL CHECK (octet_length(expected_version_digest) = 32),
			result_reference uuid NOT NULL,
			result_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
			created_at timestamptz NOT NULL DEFAULT now(),
			expires_at timestamptz NOT NULL,
			policy_version bigint NOT NULL DEFAULT 1,
			eligible_after timestamptz NOT NULL,
			legal_hold boolean NOT NULL DEFAULT false
		);

ALTER TABLE central.execution_command_receipts
		 ADD COLUMN IF NOT EXISTS result_payload jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE central.execution_command_receipts
		 SET result_payload = '{}'::jsonb
		 WHERE result_payload IS NULL;

ALTER TABLE central.execution_command_receipts
		 ALTER COLUMN result_payload SET DEFAULT '{}'::jsonb,
		 ALTER COLUMN result_payload SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS execution_command_receipts_scope_key_unique_idx ON central.execution_command_receipts (workspace_id, command_scope, idempotency_key);

CREATE INDEX IF NOT EXISTS execution_command_receipts_expiry_idx ON central.execution_command_receipts (workspace_id, expires_at, id);

CREATE TABLE IF NOT EXISTS central.recovery_coordinators (
			recovery_domain text PRIMARY KEY,
			version bigint NOT NULL DEFAULT 1,
			instance_id text NOT NULL,
			lease_token_hash bytea NOT NULL CHECK (octet_length(lease_token_hash) = 32),
			fencing_generation bigint NOT NULL CHECK (fencing_generation > 0),
			lease_expires_at timestamptz NOT NULL,
			state text NOT NULL CHECK (state IN ('claimed','expired','released')),
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now()
		);

CREATE INDEX IF NOT EXISTS recovery_coordinators_lease_idx ON central.recovery_coordinators (lease_expires_at, recovery_domain);

CREATE TABLE IF NOT EXISTS central.recovery_epochs (
			epoch_generation bigint PRIMARY KEY CHECK (epoch_generation > 0),
			coordinator_domain text NOT NULL REFERENCES central.recovery_coordinators(recovery_domain),
			coordinator_fence bigint NOT NULL,
			state text NOT NULL CHECK (state IN ('open','running','degraded','failed','completed')),
			snapshot_at timestamptz NOT NULL,
			scheduler_cursor uuid,
			workspace_count bigint NOT NULL DEFAULT 0,
			processed_count bigint NOT NULL DEFAULT 0,
			retry_attempt bigint NOT NULL DEFAULT 0,
			failure_class text,
			failure_reason text,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			completed_at timestamptz
		);

CREATE TABLE IF NOT EXISTS central.recovery_epoch_workspaces (
			epoch_generation bigint NOT NULL REFERENCES central.recovery_epochs(epoch_generation),
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			delivery_state text NOT NULL CHECK (delivery_state IN ('pending','claimed','completed','failed')),
			watermark_created_at timestamptz NOT NULL,
			watermark_run_id uuid NOT NULL,
			cursor_created_at timestamptz,
			cursor_run_id uuid,
			claim_token_hash bytea,
			claim_expires_at timestamptz,
			scanned_count bigint NOT NULL DEFAULT 0,
			reconciled_count bigint NOT NULL DEFAULT 0,
			retry_attempt bigint NOT NULL DEFAULT 0,
			failure_class text,
			failure_reason text,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (epoch_generation, workspace_id)
		);

CREATE INDEX IF NOT EXISTS recovery_epoch_workspaces_delivery_idx ON central.recovery_epoch_workspaces (epoch_generation, delivery_state, workspace_id);

CREATE INDEX IF NOT EXISTS recovery_epoch_workspaces_claim_idx ON central.recovery_epoch_workspaces (workspace_id, claim_expires_at, epoch_generation) WHERE delivery_state = 'claimed';

CREATE TABLE IF NOT EXISTS central.outbox_workspace_work (
			workspace_id uuid PRIMARY KEY REFERENCES central.workspaces(id),
			next_visible_at timestamptz NOT NULL,
			scheduler_cursor bigint NOT NULL DEFAULT 0,
			claim_token_hash bytea,
			claim_expires_at timestamptz,
			version bigint NOT NULL DEFAULT 1
		);

INSERT INTO central.outbox_workspace_work (workspace_id, next_visible_at)
		 SELECT workspace_id, min(visible_at)
		 FROM central.outbox
		 WHERE delivery_state IN ('pending','claimed')
		 GROUP BY workspace_id
		 ON CONFLICT (workspace_id) DO UPDATE
		 SET next_visible_at = LEAST(central.outbox_workspace_work.next_visible_at, EXCLUDED.next_visible_at);

CREATE INDEX IF NOT EXISTS outbox_workspace_work_ready_idx ON central.outbox_workspace_work (next_visible_at, workspace_id) WHERE claim_expires_at IS NULL;

GRANT SELECT ON central.steps TO central_runtime;

GRANT SELECT ON central.step_attempts TO central_runtime;

GRANT SELECT ON central.tool_calls TO central_runtime;

GRANT SELECT ON central.tool_call_attempts TO central_runtime;

GRANT SELECT ON central.execution_ownership TO central_runtime;

GRANT SELECT ON central.checkpoints TO central_runtime;

GRANT SELECT ON central.approvals TO central_runtime;

GRANT SELECT ON central.events TO central_runtime;

GRANT SELECT ON central.outbox TO central_runtime;

GRANT SELECT ON central.execution_command_receipts TO central_runtime;

GRANT SELECT ON central.recovery_coordinators TO central_runtime;

GRANT SELECT ON central.recovery_epochs TO central_runtime;

GRANT SELECT ON central.recovery_epoch_workspaces TO central_runtime;

GRANT SELECT ON central.outbox_workspace_work TO central_runtime;

GRANT INSERT ON central.recovery_epoch_workspaces TO central_runtime;

GRANT UPDATE ON central.recovery_epoch_workspaces TO central_runtime;

GRANT INSERT ON central.outbox_workspace_work TO central_runtime;

GRANT UPDATE ON central.outbox_workspace_work TO central_runtime;

GRANT INSERT ON central.step_attempts TO central_runtime;

GRANT UPDATE ON central.step_attempts TO central_runtime;

GRANT INSERT ON central.tool_calls TO central_runtime;

GRANT UPDATE ON central.tool_calls TO central_runtime;

GRANT INSERT ON central.tool_call_attempts TO central_runtime;

GRANT UPDATE ON central.tool_call_attempts TO central_runtime;

GRANT INSERT ON central.execution_ownership TO central_runtime;

GRANT UPDATE ON central.execution_ownership TO central_runtime;

GRANT INSERT ON central.approvals TO central_runtime;

GRANT UPDATE ON central.approvals TO central_runtime;

GRANT INSERT ON central.events TO central_runtime;

GRANT INSERT ON central.outbox TO central_runtime;

GRANT UPDATE ON central.outbox TO central_runtime;

GRANT INSERT ON central.execution_command_receipts TO central_runtime;

GRANT INSERT ON central.steps TO central_runtime;

GRANT UPDATE ON central.steps TO central_runtime;

GRANT INSERT ON central.checkpoints TO central_runtime;

GRANT UPDATE ON central.checkpoints TO central_runtime;

GRANT INSERT ON central.recovery_coordinators TO central_runtime;

GRANT UPDATE ON central.recovery_coordinators TO central_runtime;

GRANT INSERT ON central.recovery_epochs TO central_runtime;

GRANT UPDATE ON central.recovery_epochs TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;


		UPDATE central.schema_migrations
		SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 8 AND checksum = 'b08-execution-evidence' AND dirty = true;


		INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (8, 'b08-execution-evidence', clock_timestamp());

commit;

