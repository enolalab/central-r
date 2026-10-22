-- version 32 | ledger checksum b32-task-attempt-budgets | source b32_task_attempt_budgets.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (32, 'b32-task-attempt-budgets', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.tasks
			ADD COLUMN IF NOT EXISTS budget_cost_micro_usd bigint;

ALTER TABLE central.tasks
			ADD COLUMN IF NOT EXISTS budget_wall_clock_seconds integer;

ALTER TABLE central.tasks
			DROP CONSTRAINT IF EXISTS tasks_budget_cost_micro_usd_check;

ALTER TABLE central.tasks
			ADD CONSTRAINT tasks_budget_cost_micro_usd_check
			CHECK (budget_cost_micro_usd >= 10000 AND budget_cost_micro_usd <= 1000000000);

ALTER TABLE central.tasks
			DROP CONSTRAINT IF EXISTS tasks_budget_wall_clock_seconds_check;

ALTER TABLE central.tasks
			ADD CONSTRAINT tasks_budget_wall_clock_seconds_check
			CHECK (budget_wall_clock_seconds >= 60 AND budget_wall_clock_seconds <= 86400);

ALTER TABLE central.harness_attempts
			ADD COLUMN IF NOT EXISTS budget_cost_micro_usd bigint;

ALTER TABLE central.harness_attempts
			ADD COLUMN IF NOT EXISTS budget_wall_clock_seconds integer;

ALTER TABLE central.harness_attempts
			ADD COLUMN IF NOT EXISTS budget_cost_defaulted boolean;

ALTER TABLE central.harness_attempts
			ADD COLUMN IF NOT EXISTS budget_wall_clock_defaulted boolean;

UPDATE central.harness_attempts SET budget_cost_micro_usd = 5000000 WHERE budget_cost_micro_usd IS NULL;

UPDATE central.harness_attempts SET budget_wall_clock_seconds = 1800 WHERE budget_wall_clock_seconds IS NULL;

UPDATE central.harness_attempts SET budget_cost_defaulted = true WHERE budget_cost_defaulted IS NULL;

UPDATE central.harness_attempts SET budget_wall_clock_defaulted = true WHERE budget_wall_clock_defaulted IS NULL;

ALTER TABLE central.harness_attempts
			ALTER COLUMN budget_cost_micro_usd SET NOT NULL;

ALTER TABLE central.harness_attempts
			ALTER COLUMN budget_wall_clock_seconds SET NOT NULL;

ALTER TABLE central.harness_attempts
			ALTER COLUMN budget_cost_defaulted SET NOT NULL;

ALTER TABLE central.harness_attempts
			ALTER COLUMN budget_wall_clock_defaulted SET NOT NULL;

ALTER TABLE central.harness_attempts
			DROP CONSTRAINT IF EXISTS harness_attempts_budget_cost_micro_usd_check;

ALTER TABLE central.harness_attempts
			ADD CONSTRAINT harness_attempts_budget_cost_micro_usd_check
			CHECK (budget_cost_micro_usd >= 1 AND budget_cost_micro_usd <= 1000000000);

ALTER TABLE central.harness_attempts
			DROP CONSTRAINT IF EXISTS harness_attempts_budget_wall_clock_seconds_check;

ALTER TABLE central.harness_attempts
			ADD CONSTRAINT harness_attempts_budget_wall_clock_seconds_check
			CHECK (budget_wall_clock_seconds >= 1 AND budget_wall_clock_seconds <= 86400);

CREATE INDEX IF NOT EXISTS harness_attempts_run_idx
			ON central.harness_attempts (workspace_id, run_id, prepared_at DESC);

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 32 AND checksum = 'b32-task-attempt-budgets';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (32, 'b32-task-attempt-budgets', clock_timestamp());

commit;

