-- version 20 | ledger checksum b20-sentinel-workspace-id | source b20_sentinel_workspace_id.go

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 20 AND checksum = 'b20-sentinel-workspace-id';

INSERT INTO central.schema_migrations (version, checksum, dirty)
			VALUES (20, 'b20-sentinel-workspace-id', false) ON CONFLICT (version) DO UPDATE SET dirty = false, applied_at = clock_timestamp();

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (20, 'b20-sentinel-workspace-id', clock_timestamp());

commit;

