-- version 22 | ledger checksum b22-evidence-continuation-parent-grant | source b22_evidence_continuation_parent_grant.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (22, 'b22-evidence-continuation-parent-grant', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

GRANT UPDATE (continuation_parent_id) ON central.provider_execution_evidence TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 22 AND checksum = 'b22-evidence-continuation-parent-grant';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (22, 'b22-evidence-continuation-parent-grant', clock_timestamp());

commit;

