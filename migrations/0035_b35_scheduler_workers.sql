-- version 35 | ledger checksum b35-scheduler-workers | source b35_scheduler_workers.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (35, 'b35-scheduler-workers', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.worker_registrations (
			id uuid NOT NULL,
			workspace_id uuid NOT NULL,
			protocol_version integer NOT NULL,
			harness_kinds text[] NOT NULL,
			workspace_kinds text[] NOT NULL,
			max_concurrent_attempts integer NOT NULL,
			state text NOT NULL,
			registered_at timestamptz NOT NULL DEFAULT now(),
			last_seen_at timestamptz,
			deregistered_at timestamptz,
			CONSTRAINT worker_registrations_pkey PRIMARY KEY (id),
			CONSTRAINT worker_registrations_workspace_fkey FOREIGN KEY (workspace_id)
				REFERENCES central.workspaces (id),
			CONSTRAINT worker_registrations_max_concurrent_attempts_check CHECK (max_concurrent_attempts >= 1),
			CONSTRAINT worker_registrations_state_check CHECK (state IN ('active', 'suspect', 'lost', 'deregistered'))
		);

CREATE TABLE IF NOT EXISTS central.session_attempts (
			id uuid NOT NULL,
			workspace_id uuid NOT NULL,
			run_id uuid NOT NULL,
			node_id uuid NOT NULL,
			attempt_seq integer NOT NULL,
			worker_id uuid,
			harness_attempt_id uuid,
			workspace_path text,
			workspace_kind text NOT NULL,
			state text NOT NULL,
			dispatch_reason_code text,
			reservation_id text,
			harness_session_id text,
			claimed_at timestamptz NOT NULL DEFAULT now(),
			started_at timestamptz,
			ended_at timestamptz,
			CONSTRAINT session_attempts_pkey PRIMARY KEY (id),
			CONSTRAINT session_attempts_node_attempt_unique UNIQUE (node_id, attempt_seq),
			CONSTRAINT session_attempts_workspace_fkey FOREIGN KEY (workspace_id)
				REFERENCES central.workspaces (id),
			CONSTRAINT session_attempts_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT session_attempts_node_fkey FOREIGN KEY (node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT session_attempts_worker_fkey FOREIGN KEY (worker_id)
				REFERENCES central.worker_registrations (id),
			CONSTRAINT session_attempts_harness_attempt_fkey FOREIGN KEY (harness_attempt_id)
				REFERENCES central.harness_attempts (id),
			CONSTRAINT session_attempts_attempt_seq_check CHECK (attempt_seq >= 1),
			CONSTRAINT session_attempts_state_check CHECK (state IN ('claimed', 'provisioning', 'started', 'succeeded', 'failed', 'ambiguous', 'cancelled'))
		);

CREATE TABLE IF NOT EXISTS central.node_leases (
			id uuid NOT NULL,
			node_id uuid NOT NULL,
			attempt_id uuid NOT NULL,
			worker_id uuid NOT NULL,
			issued_at timestamptz NOT NULL DEFAULT now(),
			last_heartbeat_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL,
			heartbeat_interval_seconds integer NOT NULL,
			released_at timestamptz,
			CONSTRAINT node_leases_pkey PRIMARY KEY (id),
			CONSTRAINT node_leases_node_fkey FOREIGN KEY (node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT node_leases_attempt_fkey FOREIGN KEY (attempt_id)
				REFERENCES central.session_attempts (id),
			CONSTRAINT node_leases_worker_fkey FOREIGN KEY (worker_id)
				REFERENCES central.worker_registrations (id),
			CONSTRAINT node_leases_heartbeat_interval_seconds_check CHECK (heartbeat_interval_seconds >= 1)
		);

CREATE UNIQUE INDEX IF NOT EXISTS session_attempts_live_node_idx
			ON central.session_attempts (node_id) WHERE state IN ('claimed', 'provisioning', 'started');

CREATE UNIQUE INDEX IF NOT EXISTS node_leases_live_node_idx
			ON central.node_leases (node_id) WHERE released_at IS NULL;

ALTER TABLE central.workflow_nodes ADD COLUMN IF NOT EXISTS ready_at timestamptz;

REVOKE ALL ON central.worker_registrations, central.session_attempts, central.node_leases FROM PUBLIC;

REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.worker_registrations, central.session_attempts, central.node_leases FROM central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.worker_registrations TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.session_attempts TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.node_leases TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 35 AND checksum = 'b35-scheduler-workers';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (35, 'b35-scheduler-workers', clock_timestamp());

commit;

