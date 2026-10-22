-- version 30 | ledger checksum b30-harness-attempts | source b30_harness_attempts.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (30, 'b30-harness-attempts', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.harness_attempts (
			workspace_id uuid NOT NULL,
			id uuid NOT NULL,
			run_id uuid NOT NULL,
			kind text NOT NULL,
			adapter_version text NOT NULL,
			harness_version text,
			harness_session_id text,
			resume_of uuid,
			resume_session_id text,
			workspace_path text NOT NULL,
			base_sha text NOT NULL,
			permission text NOT NULL,
			sandbox_scope_id text,
			fence_generation bigint NOT NULL,
			version bigint NOT NULL,
			state text NOT NULL,
			pending_permission text,
			terminal_status text,
			terminal_reason text,
			terminal_exit_code bigint,
			resolution_kind text,
			resolution_decided_by text,
			ambiguity_reason text,
			last_event_seq bigint NOT NULL,
			usage_tokens_in bigint NOT NULL,
			usage_tokens_out bigint NOT NULL,
			usage_cache_read bigint NOT NULL,
			usage_cache_write bigint NOT NULL,
			usage_cost_micro_usd bigint NOT NULL,
			usage_scope text,
			usage_estimated boolean NOT NULL,
			prepared_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			ended_at timestamptz,
			CONSTRAINT harness_attempts_pkey PRIMARY KEY (id),
			CONSTRAINT harness_attempts_workspace_id_id_key UNIQUE (workspace_id, id),
			CONSTRAINT harness_attempts_run_fkey FOREIGN KEY (workspace_id, run_id)
				REFERENCES central.runs (workspace_id, id) ON DELETE RESTRICT,
			CONSTRAINT harness_attempts_resume_of_fkey FOREIGN KEY (workspace_id, resume_of)
				REFERENCES central.harness_attempts (workspace_id, id) ON DELETE RESTRICT,
			CONSTRAINT harness_attempts_resume_pair_check CHECK ((resume_of IS NULL) = (resume_session_id IS NULL)),
			CONSTRAINT harness_attempts_kind_check CHECK (octet_length(kind) <= 64),
			CONSTRAINT harness_attempts_adapter_version_check CHECK (octet_length(adapter_version) <= 128),
			CONSTRAINT harness_attempts_harness_version_check CHECK (octet_length(harness_version) <= 128),
			CONSTRAINT harness_attempts_harness_session_id_check CHECK (octet_length(harness_session_id) <= 512),
			CONSTRAINT harness_attempts_resume_session_id_check CHECK (octet_length(resume_session_id) <= 512),
			CONSTRAINT harness_attempts_workspace_path_check CHECK (octet_length(workspace_path) <= 4096),
			CONSTRAINT harness_attempts_base_sha_check CHECK (octet_length(base_sha) <= 128),
			CONSTRAINT harness_attempts_permission_check CHECK (permission IN ('deny', 'bridge', 'auto_allow')),
			CONSTRAINT harness_attempts_sandbox_scope_id_check CHECK (octet_length(sandbox_scope_id) <= 256),
			CONSTRAINT harness_attempts_fence_generation_check CHECK (fence_generation >= 1),
			CONSTRAINT harness_attempts_version_check CHECK (version >= 0),
			CONSTRAINT harness_attempts_state_check CHECK (state IN ('prepared', 'launching', 'running', 'awaiting_permission', 'ambiguous', 'succeeded', 'failed', 'interrupted', 'killed', 'budget_exhausted', 'resolved')),
			CONSTRAINT harness_attempts_pending_permission_check CHECK (octet_length(pending_permission) <= 512),
			CONSTRAINT harness_attempts_terminal_status_check CHECK (terminal_status IN ('succeeded', 'failed', 'max_turns', 'interrupted', 'killed', 'budget')),
			CONSTRAINT harness_attempts_terminal_reason_check CHECK (octet_length(terminal_reason) <= 4096),
			CONSTRAINT harness_attempts_resolution_kind_check CHECK (resolution_kind IN ('resume', 'rerun', 'abandon')),
			CONSTRAINT harness_attempts_resolution_decided_by_check CHECK (octet_length(resolution_decided_by) <= 256),
			CONSTRAINT harness_attempts_ambiguity_reason_check CHECK (octet_length(ambiguity_reason) <= 4096),
			CONSTRAINT harness_attempts_last_event_seq_check CHECK (last_event_seq >= 0),
			CONSTRAINT harness_attempts_usage_tokens_in_check CHECK (usage_tokens_in >= 0),
			CONSTRAINT harness_attempts_usage_tokens_out_check CHECK (usage_tokens_out >= 0),
			CONSTRAINT harness_attempts_usage_cache_read_check CHECK (usage_cache_read >= 0),
			CONSTRAINT harness_attempts_usage_cache_write_check CHECK (usage_cache_write >= 0),
			CONSTRAINT harness_attempts_usage_cost_micro_usd_check CHECK (usage_cost_micro_usd >= 0),
			CONSTRAINT harness_attempts_usage_scope_check CHECK (usage_scope IN ('step', 'run', 'session_cumulative'))
		);

CREATE UNIQUE INDEX IF NOT EXISTS harness_attempts_one_live_per_run_idx
			ON central.harness_attempts (workspace_id, run_id)
			WHERE state IN ('prepared', 'launching', 'running', 'awaiting_permission', 'ambiguous');

CREATE TABLE IF NOT EXISTS central.harness_events (
			workspace_id uuid NOT NULL,
			attempt_id uuid NOT NULL,
			seq bigint NOT NULL,
			kind text NOT NULL,
			at timestamptz NOT NULL,
			harness_session_id text,
			raw_size bigint NOT NULL,
			raw_sha256 bytea NOT NULL,
			tool_call_id text,
			tool_name text,
			tool_status text,
			permission_request_id text,
			permission_outcome text,
			terminal_status text,
			CONSTRAINT harness_events_pkey PRIMARY KEY (attempt_id, seq),
			CONSTRAINT harness_events_attempt_fkey FOREIGN KEY (workspace_id, attempt_id)
				REFERENCES central.harness_attempts (workspace_id, id) ON DELETE RESTRICT,
			CONSTRAINT harness_events_seq_check CHECK (seq >= 1),
			CONSTRAINT harness_events_kind_check CHECK (kind IN ('session_started', 'message', 'reasoning', 'tool_call', 'tool_result', 'permission_requested', 'permission_resolved', 'plan', 'usage_report', 'retry', 'warning', 'terminal_reported')),
			CONSTRAINT harness_events_harness_session_id_check CHECK (octet_length(harness_session_id) <= 512),
			CONSTRAINT harness_events_raw_size_check CHECK (raw_size >= 1),
			CONSTRAINT harness_events_raw_sha256_check CHECK (octet_length(raw_sha256) = 32),
			CONSTRAINT harness_events_tool_call_id_check CHECK (octet_length(tool_call_id) <= 512),
			CONSTRAINT harness_events_tool_name_check CHECK (octet_length(tool_name) <= 256),
			CONSTRAINT harness_events_tool_status_check CHECK (tool_status IN ('ok', 'error', 'denied', 'cut_off')),
			CONSTRAINT harness_events_permission_request_id_check CHECK (octet_length(permission_request_id) <= 512),
			CONSTRAINT harness_events_permission_outcome_check CHECK (permission_outcome IN ('allow', 'deny', 'timeout')),
			CONSTRAINT harness_events_terminal_status_check CHECK (terminal_status IN ('succeeded', 'failed', 'max_turns', 'interrupted', 'killed', 'budget'))
		);

REVOKE ALL ON central.harness_attempts, central.harness_events FROM PUBLIC;

REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.harness_attempts FROM central_runtime;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.harness_events FROM central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.harness_attempts TO central_runtime;

GRANT SELECT, INSERT ON central.harness_events TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 30 AND checksum = 'b30-harness-attempts';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (30, 'b30-harness-attempts', clock_timestamp());

commit;

