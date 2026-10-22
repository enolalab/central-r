-- version 27 | ledger checksum b27-recovery-abandonment | source b27_recovery_abandonment.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (27, 'b27-recovery-abandonment', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.recovery_operations DROP CONSTRAINT recovery_operations_phase_check;

ALTER TABLE central.recovery_operations ADD CONSTRAINT recovery_operations_phase_check
			CHECK (phase IN ('applying','verifying','quarantined','ready','abandoned'));

ALTER TABLE central.recovery_operations DROP CONSTRAINT recovery_operations_state_check;

ALTER TABLE central.recovery_operations ADD CONSTRAINT recovery_operations_state_check CHECK (
			(phase = 'applying' AND last_checkpoint IN ('ticket_consumed','database_replaced') AND ready_at IS NULL) OR
			(phase = 'verifying' AND last_checkpoint IN ('database_replaced','inventory_verified','authority_reset') AND ready_at IS NULL) OR
			(phase = 'quarantined' AND last_checkpoint = 'inventory_verified' AND ready_at IS NULL) OR
			(phase = 'ready' AND last_checkpoint = 'authority_reset' AND ready_at IS NOT NULL) OR
			(phase = 'abandoned' AND last_checkpoint IN ('ticket_consumed','database_replaced','inventory_verified','authority_reset') AND ready_at IS NULL)
		);

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 27 AND checksum = 'b27-recovery-abandonment';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (27, 'b27-recovery-abandonment', clock_timestamp());

commit;

