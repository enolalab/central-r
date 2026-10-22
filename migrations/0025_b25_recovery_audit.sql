-- version 25 | ledger checksum b25-recovery-audit | source b25_recovery_audit.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (25, 'b25-recovery-audit', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.recovery_operations (
			operation_id uuid PRIMARY KEY,
			backup_id uuid NOT NULL,
			target_fingerprint bytea NOT NULL CHECK (octet_length(target_fingerprint) = 32),
			manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
			restore_epoch bigint NOT NULL CHECK (restore_epoch >= 0),
			security_epoch bigint NOT NULL CHECK (security_epoch >= 0),
			revision bigint NOT NULL CHECK (revision > 0),
			phase text NOT NULL CHECK (phase IN ('applying','verifying','quarantined','ready')),
			last_checkpoint text NOT NULL CHECK (last_checkpoint IN ('ticket_consumed','database_replaced','inventory_verified','authority_reset')),
			authority_reset_receipt_hash bytea NULL CHECK (authority_reset_receipt_hash IS NULL OR octet_length(authority_reset_receipt_hash) = 32),
			started_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			ready_at timestamptz NULL,
			CONSTRAINT recovery_operations_time_check CHECK (updated_at >= started_at AND (ready_at IS NULL OR ready_at = updated_at)),
			CONSTRAINT recovery_operations_state_check CHECK (
				(phase = 'applying' AND last_checkpoint IN ('ticket_consumed','database_replaced') AND ready_at IS NULL) OR
				(phase = 'verifying' AND last_checkpoint IN ('database_replaced','inventory_verified','authority_reset') AND ready_at IS NULL) OR
				(phase = 'quarantined' AND last_checkpoint = 'inventory_verified' AND ready_at IS NULL) OR
				(phase = 'ready' AND last_checkpoint = 'authority_reset' AND ready_at IS NOT NULL)
			),
			CONSTRAINT recovery_operations_authority_receipt_check CHECK (
				(authority_reset_receipt_hash IS NOT NULL) = (last_checkpoint = 'authority_reset')
			)
		);

CREATE INDEX IF NOT EXISTS recovery_operations_phase_updated_idx
			ON central.recovery_operations (phase, updated_at, operation_id);

CREATE TABLE IF NOT EXISTS central.recovery_quarantines (
			quarantine_id uuid PRIMARY KEY,
			operation_id uuid NOT NULL REFERENCES central.recovery_operations(operation_id) ON DELETE RESTRICT,
			artifact_id uuid NOT NULL,
			reason text NOT NULL CHECK (reason IN ('missing_body','checksum_mismatch','size_mismatch','unexpected_artifact','metadata_mismatch')),
			expected_checksum bytea NULL CHECK (expected_checksum IS NULL OR octet_length(expected_checksum) = 32),
			observed_checksum bytea NULL CHECK (observed_checksum IS NULL OR octet_length(observed_checksum) = 32),
			expected_size bigint NULL CHECK (expected_size IS NULL OR expected_size >= 0),
			observed_size bigint NULL CHECK (observed_size IS NULL OR observed_size >= 0),
			state text NOT NULL CHECK (state IN ('open','resolved')),
			resolution text NULL CHECK (resolution IS NULL OR resolution IN ('reingested','delete_finalized')),
			created_at timestamptz NOT NULL,
			resolved_at timestamptz NULL,
			CONSTRAINT recovery_quarantines_state_resolution_check CHECK (
				(state = 'open' AND resolution IS NULL AND resolved_at IS NULL) OR
				(state = 'resolved' AND resolution IS NOT NULL AND resolved_at IS NOT NULL AND resolved_at >= created_at)
			),
			CONSTRAINT recovery_quarantines_operation_artifact_unique UNIQUE (operation_id, artifact_id)
		);

CREATE INDEX IF NOT EXISTS recovery_quarantines_operation_state_idx
			ON central.recovery_quarantines (operation_id, state, artifact_id);

CREATE TABLE IF NOT EXISTS central.recovery_authority_reset_receipts (
			operation_id uuid PRIMARY KEY REFERENCES central.recovery_operations(operation_id) ON DELETE RESTRICT,
			previous_restore_epoch bigint NOT NULL CHECK (previous_restore_epoch >= 0),
			new_restore_epoch bigint NOT NULL,
			previous_security_epoch bigint NOT NULL CHECK (previous_security_epoch >= 0),
			new_security_epoch bigint NOT NULL,
			broker_receipt_hash bytea NOT NULL CHECK (octet_length(broker_receipt_hash) = 32),
			aggregate_receipt_hash bytea NOT NULL CHECK (octet_length(aggregate_receipt_hash) = 32),
			completed_at timestamptz NOT NULL,
			CONSTRAINT recovery_authority_reset_receipts_new_restore_epoch_check CHECK (new_restore_epoch > previous_restore_epoch),
			CONSTRAINT recovery_authority_reset_receipts_new_security_epoch_check CHECK (new_security_epoch > previous_security_epoch)
		);

REVOKE ALL ON central.recovery_operations, central.recovery_quarantines, central.recovery_authority_reset_receipts FROM PUBLIC;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.recovery_operations, central.recovery_quarantines, central.recovery_authority_reset_receipts FROM central_runtime;

GRANT SELECT ON central.recovery_operations, central.recovery_quarantines, central.recovery_authority_reset_receipts TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 25 AND checksum = 'b25-recovery-audit';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (25, 'b25-recovery-audit', clock_timestamp());

commit;

