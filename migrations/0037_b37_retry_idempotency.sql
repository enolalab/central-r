-- version 37 | ledger checksum b37-retry-idempotency | source b37_retry_idempotency.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (37, 'b37-retry-idempotency', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.runs
			ADD COLUMN IF NOT EXISTS run_key text,
			ADD COLUMN IF NOT EXISTS request_fingerprint bytea,
			ADD COLUMN IF NOT EXISTS deadline timestamptz;

ALTER TABLE central.workflow_nodes
			ADD COLUMN IF NOT EXISTS spec_fingerprint bytea,
			ADD COLUMN IF NOT EXISTS node_timeout_seconds bigint;

ALTER TABLE central.session_attempts
			ADD COLUMN IF NOT EXISTS outcome_fingerprint bytea;

ALTER TABLE central.resume_checkpoints
			ADD COLUMN IF NOT EXISTS checkpoint_seq bigint,
			ADD COLUMN IF NOT EXISTS payload_fingerprint bytea;

UPDATE central.resume_checkpoints c
			SET checkpoint_seq = numbered.seq
			FROM (
				SELECT checkpoint_id,
					row_number() OVER (PARTITION BY attempt_id ORDER BY created_at, checkpoint_id) AS seq
				FROM central.resume_checkpoints
			) numbered
			WHERE c.checkpoint_id = numbered.checkpoint_id
			  AND c.checkpoint_seq IS NULL;

ALTER TABLE central.resume_checkpoints
			ALTER COLUMN checkpoint_seq SET NOT NULL;

ALTER TABLE central.runs
			DROP CONSTRAINT IF EXISTS runs_status_check,
			ADD CONSTRAINT runs_status_check CHECK (status IN ('queued', 'running', 'waiting', 'cancelling', 'succeeded', 'failed', 'failed_terminal', 'cancelled'));

CREATE UNIQUE INDEX IF NOT EXISTS runs_run_key_unique_idx
			ON central.runs (workspace_id, run_key) WHERE run_key IS NOT NULL;

ALTER TABLE central.workflow_nodes
			DROP CONSTRAINT IF EXISTS workflow_nodes_node_timeout_seconds_check,
			ADD CONSTRAINT workflow_nodes_node_timeout_seconds_check CHECK (node_timeout_seconds >= 1);

ALTER TABLE central.resume_checkpoints
			DROP CONSTRAINT IF EXISTS resume_checkpoints_checkpoint_seq_check,
			ADD CONSTRAINT resume_checkpoints_checkpoint_seq_check CHECK (checkpoint_seq >= 1);

ALTER TABLE central.resume_checkpoints
			DROP CONSTRAINT IF EXISTS resume_checkpoints_attempt_checkpoint_unique,
			ADD CONSTRAINT resume_checkpoints_attempt_checkpoint_unique UNIQUE (attempt_id, checkpoint_seq);

CREATE TABLE IF NOT EXISTS central.event_outbox (
			run_id uuid NOT NULL,
			seq bigint NOT NULL,
			event_id uuid NOT NULL,
			published_at timestamptz,
			publish_attempts integer NOT NULL DEFAULT 0,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT event_outbox_pkey PRIMARY KEY (run_id, seq),
			CONSTRAINT event_outbox_event_fkey FOREIGN KEY (event_id)
				REFERENCES central.run_events (id),
			CONSTRAINT event_outbox_seq_check CHECK (seq >= 1),
			CONSTRAINT event_outbox_publish_attempts_check CHECK (publish_attempts >= 0)
		);

CREATE TABLE IF NOT EXISTS central.attempt_decisions (
			attempt_id uuid NOT NULL,
			run_id uuid NOT NULL,
			node_id uuid NOT NULL,
			decision text NOT NULL,
			payload_fingerprint bytea NOT NULL,
			decided_by text NOT NULL,
			decided_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT attempt_decisions_pkey PRIMARY KEY (attempt_id),
			CONSTRAINT attempt_decisions_attempt_fkey FOREIGN KEY (attempt_id)
				REFERENCES central.session_attempts (id),
			CONSTRAINT attempt_decisions_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT attempt_decisions_node_fkey FOREIGN KEY (node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT attempt_decisions_decision_check CHECK (decision IN ('resume', 'rerun')),
			CONSTRAINT attempt_decisions_fingerprint_check CHECK (octet_length(payload_fingerprint) = 32)
		);

CREATE TABLE IF NOT EXISTS central.attempt_outcomes (
			attempt_id uuid NOT NULL,
			outcome_kind text NOT NULL,
			reason_code text NOT NULL,
			failure_class text NOT NULL,
			payload_fingerprint bytea NOT NULL,
			recorded_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT attempt_outcomes_pkey PRIMARY KEY (attempt_id, outcome_kind),
			CONSTRAINT attempt_outcomes_attempt_fkey FOREIGN KEY (attempt_id)
				REFERENCES central.session_attempts (id),
			CONSTRAINT attempt_outcomes_outcome_kind_check CHECK (outcome_kind IN ('succeeded', 'failed', 'cancelled')),
			CONSTRAINT attempt_outcomes_fingerprint_check CHECK (octet_length(payload_fingerprint) = 32)
		);

CREATE TABLE IF NOT EXISTS central.artifact_finalizations (
			attempt_id uuid NOT NULL,
			artifact_name text NOT NULL,
			artifact_id uuid NOT NULL,
			checksum bytea NOT NULL,
			payload_fingerprint bytea NOT NULL,
			finalized_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT artifact_finalizations_pkey PRIMARY KEY (attempt_id, artifact_name),
			CONSTRAINT artifact_finalizations_attempt_fkey FOREIGN KEY (attempt_id)
				REFERENCES central.session_attempts (id),
			CONSTRAINT artifact_finalizations_artifact_fkey FOREIGN KEY (artifact_id)
				REFERENCES central.artifacts (id),
			CONSTRAINT artifact_finalizations_fingerprint_check CHECK (octet_length(payload_fingerprint) = 32)
		);

REVOKE ALL ON central.event_outbox, central.attempt_decisions, central.attempt_outcomes, central.artifact_finalizations FROM PUBLIC;

REVOKE TRUNCATE, REFERENCES, TRIGGER ON central.event_outbox FROM central_runtime;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.attempt_decisions, central.attempt_outcomes, central.artifact_finalizations FROM central_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON central.event_outbox TO central_runtime;

GRANT SELECT, INSERT ON central.attempt_decisions TO central_runtime;

GRANT SELECT, INSERT ON central.attempt_outcomes TO central_runtime;

GRANT SELECT, INSERT ON central.artifact_finalizations TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 37 AND checksum = 'b37-retry-idempotency';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (37, 'b37-retry-idempotency', clock_timestamp());

commit;

