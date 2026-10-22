-- version 26 | ledger checksum b26-recovery-bootstrap-registration | source b26_recovery_bootstrap_registration.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (26,'b26-recovery-bootstrap-registration',true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.recovery_bootstrap_registrations (
			operation_id uuid PRIMARY KEY REFERENCES central.recovery_operations(operation_id) ON DELETE RESTRICT,
			draft_id uuid NOT NULL UNIQUE,
			candidate_id uuid NOT NULL UNIQUE,
			generation bigint NOT NULL CHECK (generation > 0),
			verifier_hash bytea NOT NULL CHECK (octet_length(verifier_hash) = 32),
			candidate_digest bytea NOT NULL CHECK (octet_length(candidate_digest) = 32),
			broker_receipt_hash bytea NOT NULL CHECK (octet_length(broker_receipt_hash) = 32),
			database_receipt_hash bytea NOT NULL CHECK (octet_length(database_receipt_hash) = 32),
			registered_at timestamptz NOT NULL
		);

CREATE UNIQUE INDEX IF NOT EXISTS recovery_bootstrap_registrations_generation_idx
			ON central.recovery_bootstrap_registrations (generation);

REVOKE ALL ON central.recovery_bootstrap_registrations FROM PUBLIC;

REVOKE ALL ON central.recovery_bootstrap_registrations FROM central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty=false, applied_at=clock_timestamp()
		WHERE version=26 AND checksum='b26-recovery-bootstrap-registration';

INSERT INTO central.migration_checksums (version,checksum,recorded_at)
		VALUES (26,'b26-recovery-bootstrap-registration',clock_timestamp());

commit;

