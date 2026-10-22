-- version 19 | ledger checksum b11-task-lineage | source b11_task_lineage.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (19, 'b11-task-lineage', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.tasks ADD COLUMN IF NOT EXISTS parent_task_id uuid NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.tasks'::regclass AND conname = 'tasks_parent_task_workspace_fkey'
		) THEN
			ALTER TABLE central.tasks
			ADD CONSTRAINT tasks_parent_task_workspace_fkey
			FOREIGN KEY (workspace_id, parent_task_id) REFERENCES central.tasks (workspace_id, id);
		END IF;
	END;
	$b08$;

CREATE INDEX IF NOT EXISTS tasks_parent_task_id_idx
			ON central.tasks (workspace_id, parent_task_id) WHERE parent_task_id IS NOT NULL;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 19 AND checksum = 'b11-task-lineage' AND dirty = true;

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (19, 'b11-task-lineage', clock_timestamp());

commit;

