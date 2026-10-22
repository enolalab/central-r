-- version 21 | ledger checksum b21-task-input-spec-shape | source b21_task_input_spec_shape.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (21, 'b21-task-input-spec-shape', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;


WITH candidate AS MATERIALIZED (
	SELECT workspace_id, id, input_spec #>> '{}' AS inner_text
	FROM central.tasks
	WHERE jsonb_typeof(input_spec) = 'string'
	  AND (input_spec #>> '{}') IS JSON
)
UPDATE central.tasks AS task
SET input_spec = candidate.inner_text::jsonb
FROM candidate
WHERE task.workspace_id = candidate.workspace_id
  AND task.id = candidate.id
  AND jsonb_typeof(candidate.inner_text::jsonb) <> 'string';

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 21 AND checksum = 'b21-task-input-spec-shape';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (21, 'b21-task-input-spec-shape', clock_timestamp());

commit;

