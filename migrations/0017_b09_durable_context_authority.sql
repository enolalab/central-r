-- version 17 | ledger checksum b09-durable-context-authority | source b09_durable_context_authority.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations(version, checksum, dirty) VALUES (17, 'b09-durable-context-authority', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE central.b09_run_snapshots (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL, run_id uuid NOT NULL, step_id uuid NOT NULL,
			provider text NOT NULL, model text NOT NULL, destination text NOT NULL, method text NOT NULL,
			profile_signature bytea NOT NULL, policy_revision text NOT NULL, tool_revision text NOT NULL, price_revision text NOT NULL,
			selected_budget jsonb NOT NULL, task_input_hash bytea NOT NULL, security_epoch bigint NOT NULL,
			context_hash bytea NOT NULL, sensitivity_manifest_hash bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT b09_run_snapshots_profile_signature_check CHECK (octet_length(profile_signature) = 32),
			CONSTRAINT b09_run_snapshots_task_input_hash_check CHECK (octet_length(task_input_hash) = 32),
			CONSTRAINT b09_run_snapshots_context_hash_check CHECK (octet_length(context_hash) = 32),
			CONSTRAINT b09_run_snapshots_manifest_hash_check CHECK (octet_length(sensitivity_manifest_hash) = 32),
			CONSTRAINT b09_run_snapshots_run_unique UNIQUE (workspace_id, run_id),
			CONSTRAINT b09_run_snapshots_id_workspace_unique UNIQUE (id, workspace_id),
			CONSTRAINT b09_run_snapshots_task_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id),
			CONSTRAINT b09_run_snapshots_run_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id),
			CONSTRAINT b09_run_snapshots_step_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id)
		);

CREATE TABLE central.b09_authorization_decisions (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL, run_id uuid NOT NULL, step_attempt_id uuid NOT NULL, physical_attempt_id uuid NOT NULL, snapshot_id uuid NOT NULL,
			provider text NOT NULL, destination text NOT NULL, scope text NOT NULL CHECK (scope = 'model_context.send+secret.use'), secret_reference text NOT NULL,
			sensitivity_manifest_hash bytea NOT NULL, policy_revision text NOT NULL, security_epoch bigint NOT NULL,
			grant_id text NOT NULL, decision text NOT NULL CHECK (decision IN ('allow', 'deny')), expires_at timestamptz NOT NULL,
			revoked_at timestamptz NULL, created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT b09_authorization_decisions_manifest_hash_check CHECK (octet_length(sensitivity_manifest_hash) = 32),
			CONSTRAINT b09_authorization_decisions_physical_attempt_unique UNIQUE (workspace_id, physical_attempt_id),
			CONSTRAINT b09_authorization_decisions_snapshot_fkey FOREIGN KEY (snapshot_id, workspace_id) REFERENCES central.b09_run_snapshots(id, workspace_id),
			CONSTRAINT b09_authorization_decisions_task_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id),
			CONSTRAINT b09_authorization_decisions_run_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id),
			CONSTRAINT b09_authorization_decisions_attempt_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id),
			CONSTRAINT b09_authorization_decisions_physical_attempt_fkey FOREIGN KEY (physical_attempt_id) REFERENCES central.step_attempts(physical_attempt_id)
		);

CREATE TABLE central.b09_price_reservations (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL, run_id uuid NOT NULL, step_attempt_id uuid NOT NULL, snapshot_id uuid NOT NULL,
			logical_operation_id uuid NOT NULL, physical_attempt_id uuid NOT NULL, price_revision text NOT NULL,
			quote_digest bytea NOT NULL, operation_digest bytea NOT NULL, request_digest bytea NOT NULL, parent_response_ref text NULL, worst_case_micros bigint NOT NULL CHECK (worst_case_micros > 0),
			state text NOT NULL CHECK (state IN ('reserved', 'settled', 'reconciliation', 'released')), expires_at timestamptz NOT NULL,
			settled_input_tokens bigint NULL CHECK (settled_input_tokens >= 0),
			settled_output_tokens bigint NULL CHECK (settled_output_tokens >= 0),
			settled_spend_micros bigint NULL CHECK (settled_spend_micros >= 0 AND settled_spend_micros <= worst_case_micros),
			settled_at timestamptz NULL, created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT b09_price_reservations_quote_digest_check CHECK (octet_length(quote_digest) = 32),
			CONSTRAINT b09_price_reservations_operation_digest_check CHECK (octet_length(operation_digest) = 32),
			CONSTRAINT b09_price_reservations_request_digest_check CHECK (octet_length(request_digest) = 32),
			CONSTRAINT b09_price_reservations_physical_attempt_unique UNIQUE (workspace_id, physical_attempt_id),
			CONSTRAINT b09_price_reservations_snapshot_fkey FOREIGN KEY (snapshot_id, workspace_id) REFERENCES central.b09_run_snapshots(id, workspace_id),
			CONSTRAINT b09_price_reservations_task_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id),
			CONSTRAINT b09_price_reservations_run_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id),
			CONSTRAINT b09_price_reservations_attempt_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id),
			CONSTRAINT b09_price_reservations_physical_attempt_fkey FOREIGN KEY (physical_attempt_id) REFERENCES central.step_attempts(physical_attempt_id)
		);

CREATE INDEX b09_run_snapshots_restart_idx ON central.b09_run_snapshots (workspace_id, task_id, run_id, step_id, id);

CREATE INDEX b09_authorization_decisions_current_idx ON central.b09_authorization_decisions (workspace_id, task_id, run_id, step_attempt_id, physical_attempt_id, security_epoch, expires_at, id) WHERE revoked_at IS NULL;

CREATE INDEX b09_price_reservations_restart_idx ON central.b09_price_reservations (workspace_id, task_id, run_id, step_attempt_id, state, expires_at, id);

GRANT SELECT ON central.b09_run_snapshots TO central_runtime;

GRANT INSERT ON central.b09_run_snapshots TO central_runtime;

GRANT SELECT ON central.b09_authorization_decisions TO central_runtime;

GRANT INSERT ON central.b09_authorization_decisions TO central_runtime;

GRANT UPDATE ON central.b09_authorization_decisions TO central_runtime;

GRANT SELECT ON central.b09_price_reservations TO central_runtime;

GRANT INSERT ON central.b09_price_reservations TO central_runtime;

GRANT UPDATE ON central.b09_price_reservations TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp() WHERE version = 17 AND checksum = 'b09-durable-context-authority' AND dirty = true;

INSERT INTO central.migration_checksums(version, checksum, recorded_at) VALUES (17, 'b09-durable-context-authority', clock_timestamp());

commit;

