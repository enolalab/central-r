-- version 31 | ledger checksum b31-harness-permission-approvals | source b31_harness_permission_approvals.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (31, 'b31-harness-permission-approvals', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.tasks
			ADD COLUMN IF NOT EXISTS permission_policy text NOT NULL DEFAULT 'deny';

ALTER TABLE central.tasks
			DROP CONSTRAINT IF EXISTS tasks_permission_policy_check;

ALTER TABLE central.tasks
			ADD CONSTRAINT tasks_permission_policy_check
			CHECK (permission_policy IN ('deny', 'bridge', 'auto_allow'));

CREATE TABLE IF NOT EXISTS central.harness_permission_approvals (
			workspace_id uuid NOT NULL,
			id uuid NOT NULL,
			attempt_id uuid NOT NULL,
			task_id uuid NOT NULL,
			run_id uuid NOT NULL,
			request_id text NOT NULL,
			tool_call_id text,
			tool_name text NOT NULL,
			input_mac bytea NOT NULL,
			input_size bigint NOT NULL,
			state text NOT NULL,
			requested_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL,
			decided_at timestamptz,
			decided_by text,
			version bigint NOT NULL,
			CONSTRAINT harness_permission_approvals_pkey PRIMARY KEY (id),
			CONSTRAINT harness_permission_approvals_attempt_request_key UNIQUE (attempt_id, request_id),
			CONSTRAINT harness_permission_approvals_attempt_fkey FOREIGN KEY (workspace_id, attempt_id)
				REFERENCES central.harness_attempts (workspace_id, id) ON DELETE RESTRICT,
			CONSTRAINT harness_permission_approvals_task_fkey FOREIGN KEY (workspace_id, task_id)
				REFERENCES central.tasks (workspace_id, id) ON DELETE RESTRICT,
			CONSTRAINT harness_permission_approvals_run_fkey FOREIGN KEY (workspace_id, run_id)
				REFERENCES central.runs (workspace_id, id) ON DELETE RESTRICT,
			CONSTRAINT harness_permission_approvals_request_id_check CHECK (octet_length(request_id) >= 1 AND octet_length(request_id) <= 512),
			CONSTRAINT harness_permission_approvals_tool_call_id_check CHECK (octet_length(tool_call_id) <= 512),
			CONSTRAINT harness_permission_approvals_tool_name_check CHECK (octet_length(tool_name) <= 256),
			CONSTRAINT harness_permission_approvals_input_mac_check CHECK (octet_length(input_mac) = 32),
			CONSTRAINT harness_permission_approvals_input_size_check CHECK (input_size >= 0 AND input_size <= 262144),
			CONSTRAINT harness_permission_approvals_state_check CHECK (state IN ('pending', 'allowed', 'denied', 'expired', 'superseded')),
			CONSTRAINT harness_permission_approvals_expires_at_check CHECK (expires_at > requested_at),
			CONSTRAINT harness_permission_approvals_decided_by_check CHECK (octet_length(decided_by) >= 1 AND octet_length(decided_by) <= 256),
			CONSTRAINT harness_permission_approvals_decision_check CHECK ((state = 'pending') = (decided_at IS NULL) AND (state = 'pending') = (decided_by IS NULL)),
			CONSTRAINT harness_permission_approvals_version_check CHECK (version >= 0)
		);

CREATE UNIQUE INDEX IF NOT EXISTS harness_permission_approvals_one_pending_per_attempt_idx
			ON central.harness_permission_approvals (attempt_id) WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS harness_permission_approvals_pending_idx
			ON central.harness_permission_approvals (workspace_id, requested_at) WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS harness_permission_approvals_run_idx
			ON central.harness_permission_approvals (workspace_id, run_id, requested_at);

REVOKE ALL ON central.harness_permission_approvals FROM PUBLIC;

REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.harness_permission_approvals FROM central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.harness_permission_approvals TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 31 AND checksum = 'b31-harness-permission-approvals';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (31, 'b31-harness-permission-approvals', clock_timestamp());

commit;

