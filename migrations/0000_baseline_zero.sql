-- version 0 | ledger checksum baseline-zero | source baseline.go

begin;

SET LOCAL synchronous_commit = on;

CREATE SCHEMA IF NOT EXISTS central AUTHORIZATION central_migration;

CREATE TABLE IF NOT EXISTS central.workspaces (
			id uuid NOT NULL PRIMARY KEY,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			state text NOT NULL CHECK (state IN ('active', 'deleted')),
			owner_principal_id text NOT NULL,
			quota_ready_bytes bigint NOT NULL DEFAULT 0 CHECK (quota_ready_bytes >= 0),
			quota_ready_count bigint NOT NULL DEFAULT 0 CHECK (quota_ready_count >= 0),
			quota_max_bytes bigint NOT NULL DEFAULT 10737418240 CHECK (quota_max_bytes > 0),
			security_epoch bigint NOT NULL DEFAULT 0,
			restore_epoch bigint NOT NULL DEFAULT 0
		);

CREATE TABLE IF NOT EXISTS central.workspace_event_counters (
			workspace_id uuid NOT NULL PRIMARY KEY REFERENCES central.workspaces(id),
			last_event_sequence bigint NOT NULL DEFAULT 0 CHECK (last_event_sequence >= 0)
		);

CREATE TABLE IF NOT EXISTS central.tasks (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			status text NOT NULL CHECK (status IN ('queued', 'running', 'waiting', 'cancelling', 'completed', 'failed', 'cancelled')),
			current_run_id uuid NULL,
			last_run_index bigint NOT NULL DEFAULT 0 CHECK (last_run_index >= 0),
			waiting_reason text NULL,
			title text NOT NULL,
			input_spec jsonb NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			correlation_id uuid NULL,
			causation_id uuid NULL,
			idempotency_key text NULL,
			failure_reason text NULL,
			retry_eligible_at timestamptz NULL,
			retry_count bigint NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
			expiry_at timestamptz NULL,
			CONSTRAINT tasks_workspace_id_idempotency_key_unique UNIQUE (workspace_id, idempotency_key)
		);

CREATE INDEX IF NOT EXISTS tasks_workspace_status_created_idx ON central.tasks (workspace_id, status, updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS tasks_workspace_id_idx ON central.tasks (workspace_id, id);

CREATE INDEX IF NOT EXISTS tasks_retry_eligible_idx ON central.tasks (workspace_id, retry_eligible_at) WHERE retry_eligible_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS tasks_cleanup_expiry_idx ON central.tasks (workspace_id, expiry_at) WHERE expiry_at IS NOT NULL AND status IN ('completed', 'failed', 'cancelled');

CREATE TABLE IF NOT EXISTS central.runs (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL REFERENCES central.tasks(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			status text NOT NULL CHECK (status IN ('queued', 'running', 'waiting', 'cancelling', 'succeeded', 'failed', 'cancelled')),
			run_index bigint NOT NULL CHECK (run_index >= 0),
			waiting_reason text NULL,
			ownership_token text NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			failure_reason text NULL,
			capacity_run_ready_bytes bigint NOT NULL DEFAULT 0 CHECK (capacity_run_ready_bytes >= 0),
			CONSTRAINT runs_workspace_task_index_unique UNIQUE (workspace_id, task_id, run_index)
		);

CREATE INDEX IF NOT EXISTS runs_task_id_idx ON central.runs (workspace_id, task_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS runs_status_idx ON central.runs (workspace_id, status);

CREATE INDEX IF NOT EXISTS runs_cleanup_idx ON central.runs (workspace_id, status, updated_at);

CREATE TABLE IF NOT EXISTS central.steps (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			run_id uuid NOT NULL REFERENCES central.runs(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
			step_index bigint NOT NULL CHECK (step_index >= 0),
			step_kind text NOT NULL CHECK (step_kind IN ('approval', 'provider', 'tool', 'checkpoint')),
			provider_operation text NULL,
			tool_operation text NULL,
			approval_capability text NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			failure_reason text NULL,
			CONSTRAINT steps_workspace_run_index_unique UNIQUE (workspace_id, run_id, step_index)
		);

CREATE INDEX IF NOT EXISTS steps_run_id_idx ON central.steps (workspace_id, run_id, step_index ASC);

CREATE INDEX IF NOT EXISTS steps_status_idx ON central.steps (workspace_id, status);

CREATE TABLE IF NOT EXISTS central.step_attempts (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			step_id uuid NOT NULL REFERENCES central.steps(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			status text NOT NULL CHECK (status IN ('prepared', 'invoked', 'succeeded', 'retryable_failure', 'terminal_failure', 'cancelled', 'ambiguous')),
			attempt_index bigint NOT NULL CHECK (attempt_index >= 0),
			adapter_identity text NOT NULL,
			adapter_revision text NOT NULL,
			operation_key text NOT NULL,
			manifest_hash bytea NOT NULL,
			budget_config jsonb NOT NULL,
			authority_deadline timestamptz NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			outcome_kind text NULL CHECK (outcome_kind IN ('success', 'retryable', 'terminal', 'cancelled', 'ambiguous')),
			outcome_evidence jsonb NULL,
			failure_reason text NULL,
			CONSTRAINT step_attempts_workspace_step_attempt_unique UNIQUE (workspace_id, step_id, attempt_index)
		);

CREATE INDEX IF NOT EXISTS step_attempts_step_id_idx ON central.step_attempts (workspace_id, step_id, attempt_index ASC);

CREATE INDEX IF NOT EXISTS step_attempts_status_idx ON central.step_attempts (workspace_id, status);

CREATE TABLE IF NOT EXISTS central.tool_calls (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			step_id uuid NOT NULL REFERENCES central.steps(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
			tool_index bigint NOT NULL CHECK (tool_index >= 0),
			tool_identity text NOT NULL,
			tool_operation text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			failure_reason text NULL,
			CONSTRAINT tool_calls_workspace_step_tool_unique UNIQUE (workspace_id, step_id, tool_index)
		);

CREATE INDEX IF NOT EXISTS tool_calls_step_id_idx ON central.tool_calls (workspace_id, step_id, tool_index ASC);

CREATE TABLE IF NOT EXISTS central.tool_call_attempts (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			tool_call_id uuid NOT NULL REFERENCES central.tool_calls(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			status text NOT NULL CHECK (status IN ('prepared', 'invoked', 'succeeded', 'retryable_failure', 'terminal_failure', 'cancelled', 'ambiguous')),
			attempt_index bigint NOT NULL CHECK (attempt_index >= 0),
			adapter_identity text NOT NULL,
			adapter_revision text NOT NULL,
			operation_key text NOT NULL,
			manifest_hash bytea NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			outcome_kind text NULL CHECK (outcome_kind IN ('success', 'retryable', 'terminal', 'cancelled', 'ambiguous')),
			outcome_evidence jsonb NULL,
			failure_reason text NULL,
			CONSTRAINT tool_call_attempts_workspace_tc_attempt_unique UNIQUE (workspace_id, tool_call_id, attempt_index)
		);

CREATE INDEX IF NOT EXISTS tool_call_attempts_tool_call_id_idx ON central.tool_call_attempts (workspace_id, tool_call_id, attempt_index ASC);

CREATE INDEX IF NOT EXISTS tool_call_attempts_status_idx ON central.tool_call_attempts (workspace_id, status);

CREATE TABLE IF NOT EXISTS central.artifacts (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL REFERENCES central.tasks(id),
			run_id uuid NOT NULL REFERENCES central.runs(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			state text NOT NULL CHECK (state IN ('reserved', 'staging', 'verifying', 'ready', 'delete_pending', 'deleted', 'quarantined')),
			media_type text NULL,
			size bigint NOT NULL DEFAULT 0 CHECK (size >= 0),
			staging_generation uuid NOT NULL,
			object_key text NOT NULL,
			checksum_algorithm text NULL,
			checksum_value bytea NULL,
			sensitivity text NOT NULL CHECK (sensitivity IN ('unrestricted', 'restricted', 'sensitive')),
			disposition text NOT NULL CHECK (disposition IN ('inline', 'attachment')),
			lineage_artifact_id uuid NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			ready_at timestamptz NULL,
			delete_intent_at timestamptz NULL,
			deleted_at timestamptz NULL,
			quarantined_reason text NULL,
			CONSTRAINT artifacts_workspace_staging_generation_unique UNIQUE (workspace_id, staging_generation),
			CONSTRAINT artifacts_workspace_object_key_unique UNIQUE (workspace_id, object_key)
		);

CREATE INDEX IF NOT EXISTS artifacts_task_id_idx ON central.artifacts (workspace_id, task_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS artifacts_state_expiry_idx ON central.artifacts (workspace_id, state, created_at) WHERE state IN ('reserved', 'staging', 'verifying');

CREATE INDEX IF NOT EXISTS artifacts_delete_pending_idx ON central.artifacts (workspace_id, state) WHERE state = 'delete_pending';

CREATE INDEX IF NOT EXISTS artifacts_quarantine_idx ON central.artifacts (workspace_id, state) WHERE state = 'quarantined';

CREATE INDEX IF NOT EXISTS artifacts_object_key_seek_idx ON central.artifacts (workspace_id, object_key, id);

CREATE TABLE IF NOT EXISTS central.artifact_tombstones (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			artifact_id uuid NOT NULL,
			object_key text NOT NULL,
			staging_generation uuid NOT NULL,
			checksum_algorithm text NULL,
			checksum_value bytea NULL,
			size_at_deletion bigint NOT NULL DEFAULT 0,
			deletion_reason text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT artifact_tombstones_artifact_id_unique UNIQUE (workspace_id, artifact_id)
		);

CREATE TABLE IF NOT EXISTS central.events (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			event_sequence bigint NOT NULL CHECK (event_sequence >= 0),
			event_type text NOT NULL,
			aggregate_id uuid NOT NULL,
			aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
			command_id uuid NULL,
			run_id uuid NULL,
			payload jsonb NOT NULL,
			correlation_id uuid NULL,
			causation_id uuid NULL,
			occurred_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT events_workspace_sequence_unique UNIQUE (workspace_id, event_sequence)
		);

CREATE INDEX IF NOT EXISTS events_workspace_sequence_idx ON central.events (workspace_id, event_sequence);

CREATE INDEX IF NOT EXISTS events_aggregate_idx ON central.events (workspace_id, aggregate_id, event_sequence);

CREATE INDEX IF NOT EXISTS events_run_idx ON central.events (workspace_id, run_id, event_sequence) WHERE run_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS central.outbox (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			event_id uuid NOT NULL REFERENCES central.events(id),
			delivery_state text NOT NULL CHECK (delivery_state IN ('pending', 'claimed', 'delivered', 'dead_letter')),
			due_at timestamptz NOT NULL DEFAULT now(),
			retry_at timestamptz NULL,
			owner_identity text NULL,
			fencing_token uuid NULL,
			lease_expiry timestamptz NULL,
			attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
			failure_reason text NULL,
			dead_letter_evidence text NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT outbox_workspace_event_unique UNIQUE (workspace_id, event_id)
		);

CREATE INDEX IF NOT EXISTS outbox_claim_idx ON central.outbox (workspace_id, delivery_state, due_at);

CREATE INDEX IF NOT EXISTS outbox_owner_lease_idx ON central.outbox (workspace_id, owner_identity, lease_expiry);

CREATE INDEX IF NOT EXISTS outbox_delivered_cleanup_idx ON central.outbox (workspace_id, delivery_state, updated_at) WHERE delivery_state = 'delivered';

CREATE INDEX IF NOT EXISTS outbox_dead_letter_cleanup_idx ON central.outbox (workspace_id, delivery_state, updated_at) WHERE delivery_state = 'dead_letter';

CREATE TABLE IF NOT EXISTS central.command_receipts (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			command_scope text NOT NULL,
			idempotency_key text NOT NULL,
			input_fingerprint bytea NOT NULL,
			expected_aggregate_versions jsonb NOT NULL,
			result_kind text NOT NULL,
			result_reference uuid NULL,
			correlation_id uuid NULL,
			causation_id uuid NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			expiry_at timestamptz NOT NULL,
			CONSTRAINT command_receipts_scope_key_unique UNIQUE (workspace_id, command_scope, idempotency_key)
		);

CREATE INDEX IF NOT EXISTS command_receipts_cleanup_idx ON central.command_receipts (workspace_id, expiry_at);

CREATE TABLE IF NOT EXISTS central.execution_ownership (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			owner_scope text NOT NULL,
			owner_identity text NOT NULL,
			fencing_token uuid NOT NULL,
			lease_expiry timestamptz NOT NULL,
			heartbeat_at timestamptz NOT NULL DEFAULT now(),
			claimed_run_id uuid NULL REFERENCES central.runs(id),
			claimed_step_id uuid NULL REFERENCES central.steps(id),
			claimed_step_attempt_id uuid NULL REFERENCES central.step_attempts(id),
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT execution_ownership_scope_unique UNIQUE (workspace_id, owner_scope)
		);

CREATE INDEX IF NOT EXISTS execution_ownership_expiry_idx ON central.execution_ownership (workspace_id, lease_expiry);

CREATE TABLE IF NOT EXISTS central.capacity_reservations (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			run_id uuid NOT NULL REFERENCES central.runs(id),
			artifact_id uuid NOT NULL REFERENCES central.artifacts(id),
			staging_generation uuid NOT NULL,
			reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
			state text NOT NULL CHECK (state IN ('reserved', 'settled', 'released')),
			created_at timestamptz NOT NULL DEFAULT now(),
			settled_at timestamptz NULL,
			released_at timestamptz NULL,
			CONSTRAINT capacity_reservations_artifact_unique UNIQUE (workspace_id, artifact_id),
			CONSTRAINT capacity_reservations_staging_gen_unique UNIQUE (workspace_id, staging_generation)
		);

CREATE INDEX IF NOT EXISTS capacity_reservations_state_cleanup_idx ON central.capacity_reservations (workspace_id, state, created_at) WHERE state = 'released';

CREATE TABLE IF NOT EXISTS central.bootstrap_generations (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			generation bigint NOT NULL CHECK (generation >= 0),
			verifier_hash bytea NOT NULL,
			state text NOT NULL CHECK (state IN ('active', 'consumed')),
			principal_identity text NOT NULL,
			candidate_id uuid NULL,
			candidate_digest bytea NULL,
			registered_generation bigint NULL,
			throttle_failure_window_start timestamptz NULL,
			throttle_failure_count bigint NOT NULL DEFAULT 0,
			throttle_next_eligible timestamptz NULL,
			presentation_deadline timestamptz NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			consumed_at timestamptz NULL,
			CONSTRAINT bootstrap_generations_workspace_generation_unique UNIQUE (workspace_id, generation)
		);

ALTER TABLE central.bootstrap_generations ADD COLUMN IF NOT EXISTS presentation_deadline timestamptz NULL;

CREATE INDEX IF NOT EXISTS bootstrap_generations_active_idx ON central.bootstrap_generations (workspace_id, generation DESC) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS central.sessions (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			token_hash bytea NOT NULL,
			csrf_hash bytea NOT NULL,
			principal_identity text NOT NULL,
			lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('pending_bootstrap', 'delivery_pending', 'active', 'revoked', 'expired')),
			security_epoch bigint NOT NULL DEFAULT 0,
			created_at timestamptz NOT NULL DEFAULT now(),
			last_seen_at timestamptz NOT NULL DEFAULT now(),
			idle_expiry timestamptz NOT NULL,
			absolute_expiry timestamptz NOT NULL,
			revoked_at timestamptz NULL,
			first_use_deadline timestamptz NULL,
			first_used_at timestamptz NULL,
			previous_session_id uuid NULL,
			rotation_at timestamptz NULL,
			delivery_outcome text NULL,
			CONSTRAINT sessions_token_hash_unique UNIQUE (token_hash)
		);

CREATE INDEX IF NOT EXISTS sessions_workspace_principal_idx ON central.sessions (workspace_id, principal_identity, lifecycle_state);

CREATE INDEX IF NOT EXISTS sessions_cleanup_idx ON central.sessions (workspace_id, lifecycle_state, idle_expiry) WHERE lifecycle_state IN ('revoked', 'expired');

CREATE INDEX IF NOT EXISTS sessions_pending_bootstrap_idx ON central.sessions (workspace_id, lifecycle_state) WHERE lifecycle_state = 'pending_bootstrap';

CREATE INDEX IF NOT EXISTS sessions_delivery_pending_idx ON central.sessions (workspace_id, lifecycle_state) WHERE lifecycle_state = 'delivery_pending';

CREATE INDEX IF NOT EXISTS sessions_first_use_idx ON central.sessions (workspace_id, lifecycle_state, first_use_deadline) WHERE lifecycle_state = 'active' AND first_used_at IS NULL;

CREATE TABLE IF NOT EXISTS central.approvals (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			capability_identity text NOT NULL,
			scope text NOT NULL,
			action text NOT NULL CHECK (action IN ('grant', 'revoke')),
			actor_identity text NOT NULL,
			authority_identity text NOT NULL,
			reason text NOT NULL,
			state text NOT NULL CHECK (state IN ('active', 'revoked', 'suspended', 'expired')),
			suspend_reason text NULL,
			security_epoch bigint NOT NULL DEFAULT 0,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			expiry_at timestamptz NULL
		);

CREATE INDEX IF NOT EXISTS approvals_workspace_capability_idx ON central.approvals (workspace_id, capability_identity, state);

CREATE INDEX IF NOT EXISTS approvals_workspace_actor_idx ON central.approvals (workspace_id, actor_identity, state);

CREATE INDEX IF NOT EXISTS approvals_security_epoch_idx ON central.approvals (workspace_id, security_epoch);

CREATE TABLE IF NOT EXISTS central.secret_use_evidence (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			secret_reference_id text NOT NULL,
			actor_identity text NOT NULL,
			operation_identity text NOT NULL,
			authorization_outcome text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now()
		);

CREATE INDEX IF NOT EXISTS secret_use_workspace_ref_idx ON central.secret_use_evidence (workspace_id, secret_reference_id, created_at DESC);

CREATE INDEX IF NOT EXISTS secret_use_workspace_actor_idx ON central.secret_use_evidence (workspace_id, actor_identity, created_at DESC);

CREATE TABLE IF NOT EXISTS central.checkpoints (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			run_id uuid NOT NULL REFERENCES central.runs(id),
			step_id uuid NULL REFERENCES central.steps(id),
			version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
			checkpoint_kind text NOT NULL CHECK (checkpoint_kind IN ('run_start', 'run_complete', 'step_boundary', 'external_effect', 'recovery')),
			metadata jsonb NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT checkpoints_workspace_run_kind_unique UNIQUE (workspace_id, run_id, checkpoint_kind, created_at)
		);

CREATE INDEX IF NOT EXISTS checkpoints_run_id_idx ON central.checkpoints (workspace_id, run_id, created_at DESC);

CREATE INDEX IF NOT EXISTS checkpoints_recovery_idx ON central.checkpoints (workspace_id, checkpoint_kind, created_at) WHERE checkpoint_kind IN ('step_boundary', 'external_effect');

CREATE TABLE IF NOT EXISTS central.schema_migrations (
			version bigint NOT NULL PRIMARY KEY,
			checksum text NOT NULL,
			dirty boolean NOT NULL DEFAULT false,
			applied_at timestamptz NOT NULL DEFAULT now(),
			operator_identity text NULL
		);

CREATE TABLE IF NOT EXISTS central.migration_checksums (
			version bigint NOT NULL REFERENCES central.schema_migrations(version),
			checksum text NOT NULL,
			recorded_at timestamptz NOT NULL DEFAULT now(),
			operation_id uuid NULL,
			CONSTRAINT migration_checksums_version_recorded_unique UNIQUE (version, recorded_at)
		);

CREATE TABLE IF NOT EXISTS central.migration_progress (
			operation_id uuid NOT NULL,
			version bigint NOT NULL REFERENCES central.schema_migrations(version),
			progress_version bigint NOT NULL DEFAULT 1,
			cursor_page bigint NOT NULL DEFAULT 0,
			batch_count bigint NOT NULL DEFAULT 0,
			records_processed bigint NOT NULL DEFAULT 0,
			checksum_accumulator bytea NOT NULL,
			source_checksum text NOT NULL,
			classification text NOT NULL CHECK (classification = 'data_backfill'),
			safety_binding_digest bytea NOT NULL,
			last_committed_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT migration_progress_operation_version_unique UNIQUE (operation_id, version)
		);

CREATE INDEX IF NOT EXISTS migration_progress_version_state_idx ON central.migration_progress (version, operation_id);

CREATE TABLE IF NOT EXISTS central.epoch_markers (
			id uuid NOT NULL PRIMARY KEY,
			workspace_id uuid NULL,
			restore_epoch bigint NOT NULL DEFAULT 0,
			security_epoch bigint NOT NULL DEFAULT 0,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now()
		);

INSERT INTO central.workspaces (id, created_at, updated_at, state, owner_principal_id, quota_ready_bytes, quota_ready_count, quota_max_bytes, security_epoch, restore_epoch) 
		VALUES ('019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a', now(), now(), 'active', 'system-provisioner', 0, 0, 10737418240, 0, 0)
		ON CONFLICT (id) DO NOTHING;

INSERT INTO central.schema_migrations (version, checksum, dirty) VALUES (0, 'baseline-zero', false) ON CONFLICT (version) DO NOTHING;

INSERT INTO central.migration_checksums (version, checksum, recorded_at) VALUES (0, 'baseline-zero', now()) ON CONFLICT (version, recorded_at) DO NOTHING;

INSERT INTO central.epoch_markers (id, workspace_id, restore_epoch, security_epoch, created_at, updated_at) VALUES (gen_random_uuid(), NULL, 0, 0, now(), now());

INSERT INTO central.bootstrap_generations (id, workspace_id, generation, verifier_hash, state, principal_identity, created_at) VALUES (gen_random_uuid(), '019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a', 0, decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 'active', 'baseline-provisioner', now()) ON CONFLICT (workspace_id, generation) DO NOTHING;

GRANT USAGE ON SCHEMA central TO central_runtime;

GRANT SELECT ON central.workspaces TO central_runtime;

GRANT SELECT ON central.workspace_event_counters TO central_runtime;

GRANT SELECT ON central.tasks TO central_runtime;

GRANT SELECT ON central.runs TO central_runtime;

GRANT SELECT ON central.steps TO central_runtime;

GRANT SELECT ON central.step_attempts TO central_runtime;

GRANT SELECT ON central.tool_calls TO central_runtime;

GRANT SELECT ON central.tool_call_attempts TO central_runtime;

GRANT SELECT ON central.artifacts TO central_runtime;

GRANT SELECT ON central.artifact_tombstones TO central_runtime;

GRANT SELECT ON central.events TO central_runtime;

GRANT SELECT ON central.outbox TO central_runtime;

GRANT SELECT ON central.command_receipts TO central_runtime;

GRANT SELECT ON central.execution_ownership TO central_runtime;

GRANT SELECT ON central.capacity_reservations TO central_runtime;

GRANT SELECT ON central.bootstrap_generations TO central_runtime;

GRANT SELECT ON central.sessions TO central_runtime;

GRANT SELECT ON central.approvals TO central_runtime;

GRANT SELECT ON central.secret_use_evidence TO central_runtime;

GRANT SELECT ON central.checkpoints TO central_runtime;

GRANT SELECT ON central.schema_migrations TO central_runtime;

GRANT SELECT ON central.migration_checksums TO central_runtime;

GRANT SELECT ON central.migration_progress TO central_runtime;

GRANT SELECT ON central.epoch_markers TO central_runtime;

GRANT INSERT ON central.runs TO central_runtime;

GRANT UPDATE ON central.runs TO central_runtime;

GRANT INSERT ON central.workspace_event_counters TO central_runtime;

GRANT UPDATE ON central.workspace_event_counters TO central_runtime;

GRANT INSERT ON central.events TO central_runtime;

GRANT INSERT ON central.bootstrap_generations TO central_runtime;

GRANT UPDATE ON central.bootstrap_generations TO central_runtime;

GRANT INSERT ON central.command_receipts TO central_runtime;

GRANT UPDATE ON central.workspaces TO central_runtime;

GRANT INSERT ON central.artifacts TO central_runtime;

GRANT UPDATE ON central.artifacts TO central_runtime;

GRANT INSERT ON central.capacity_reservations TO central_runtime;

GRANT UPDATE ON central.capacity_reservations TO central_runtime;

GRANT INSERT ON central.sessions TO central_runtime;

GRANT UPDATE ON central.sessions TO central_runtime;

GRANT INSERT ON central.tasks TO central_runtime;

GRANT UPDATE ON central.tasks TO central_runtime;

commit;

