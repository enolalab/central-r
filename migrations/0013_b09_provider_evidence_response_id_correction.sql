-- version 13 | ledger checksum b09-provider-evidence-response-id-correction | source b09_response_id_correction.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations(version, checksum, dirty) VALUES (13,'b09-provider-evidence-response-id-correction',true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.provider_execution_evidence DROP CONSTRAINT provider_evidence_response_unique;

CREATE UNIQUE INDEX provider_evidence_response_unique_idx ON central.provider_execution_evidence (workspace_id, response_id) WHERE response_id IS NOT NULL;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty=false, applied_at=clock_timestamp() WHERE version=13 AND checksum='b09-provider-evidence-response-id-correction' AND dirty=true;

INSERT INTO central.migration_checksums(version,checksum,recorded_at) VALUES (13,'b09-provider-evidence-response-id-correction',clock_timestamp());

commit;

