-- version 29 | ledger checksum b29-prune-log | source b29_prune_log.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (29, 'b29-prune-log', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.prune_log (
			plan_id uuid NOT NULL,
			batch_seq integer NOT NULL,
			artifact_id uuid NOT NULL,
			workspace_id uuid NOT NULL,
			retention_age_days integer NOT NULL,
			reference_count integer NOT NULL DEFAULT 0,
			state text NOT NULL DEFAULT 'pending'
				CHECK (state IN ('pending', 'applying', 'done')),
			checkpoint_at timestamptz,
			PRIMARY KEY (plan_id, batch_seq, artifact_id)
		);

GRANT SELECT ON central.prune_log TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 29 AND checksum = 'b29-prune-log';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (29, 'b29-prune-log', clock_timestamp());

commit;

