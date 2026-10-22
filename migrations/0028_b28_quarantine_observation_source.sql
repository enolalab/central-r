-- version 28 | ledger checksum b28-quarantine-observation-source | source b28_quarantine_observation_source.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (28, 'b28-quarantine-observation-source', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.recovery_quarantines
			ADD COLUMN IF NOT EXISTS observation_source text;

UPDATE central.recovery_quarantines SET observation_source = CASE reason
			WHEN 'missing_body' THEN 'object_presence'
			WHEN 'checksum_mismatch' THEN 'object_digest'
			WHEN 'size_mismatch' THEN 'object_length'
			WHEN 'unexpected_artifact' THEN 'restored_scan'
			WHEN 'metadata_mismatch' THEN 'inventory_row'
		END WHERE observation_source IS NULL;

ALTER TABLE central.recovery_quarantines
			ALTER COLUMN observation_source SET NOT NULL;

ALTER TABLE central.recovery_quarantines
			DROP CONSTRAINT IF EXISTS recovery_quarantines_observation_source_check;

ALTER TABLE central.recovery_quarantines
			ADD CONSTRAINT recovery_quarantines_observation_source_check
			CHECK (observation_source IN ('inventory_row','restored_scan','object_presence','object_length','object_digest'));

ALTER TABLE central.recovery_quarantines
			DROP CONSTRAINT IF EXISTS recovery_quarantines_reason_source_check;

ALTER TABLE central.recovery_quarantines
			ADD CONSTRAINT recovery_quarantines_reason_source_check CHECK (
				(reason = 'missing_body' AND observation_source = 'object_presence') OR
				(reason = 'checksum_mismatch' AND observation_source = 'object_digest') OR
				(reason = 'size_mismatch' AND observation_source = 'object_length') OR
				(reason = 'unexpected_artifact' AND observation_source = 'restored_scan') OR
				(reason = 'metadata_mismatch' AND observation_source = 'inventory_row')
			);

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 28 AND checksum = 'b28-quarantine-observation-source';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (28, 'b28-quarantine-observation-source', clock_timestamp());

commit;

