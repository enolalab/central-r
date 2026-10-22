-- version 16 | ledger checksum b09-provider-tool-call-mapping-correction | source b09_tool_call_mapping_correction.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations(version, checksum, dirty) VALUES (16, 'b09-provider-tool-call-mapping-correction', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.provider_function_call_evidence ADD CONSTRAINT provider_function_call_evidence_id_workspace_unique UNIQUE (id, workspace_id);

ALTER TABLE central.provider_function_call_evidence ADD CONSTRAINT provider_function_call_evidence_response_identity_unique UNIQUE (id, workspace_id, provider_response_id);

CREATE TABLE central.provider_tool_call_mappings (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL, run_id uuid NOT NULL, step_id uuid NOT NULL, step_attempt_id uuid NOT NULL,
			provider_response_evidence_id uuid NOT NULL,
			provider_function_call_evidence_id uuid NOT NULL,
			provider_call_id text NOT NULL, arguments_hash bytea NOT NULL,
			tool_call_id uuid NOT NULL, logical_operation_id uuid NOT NULL,
			policy_revision text NOT NULL, context_hash bytea NOT NULL,
			page_hash bytea NULL, result_hash bytea NULL,
			state text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(), settled_at timestamptz NULL,
			CONSTRAINT provider_tool_call_mappings_arguments_hash_check CHECK (octet_length(arguments_hash) = 32),
			CONSTRAINT provider_tool_call_mappings_context_hash_check CHECK (octet_length(context_hash) = 32),
			CONSTRAINT provider_tool_call_mappings_page_hash_check CHECK (page_hash IS NULL OR octet_length(page_hash) = 32),
			CONSTRAINT provider_tool_call_mappings_result_hash_check CHECK (result_hash IS NULL OR octet_length(result_hash) = 32),
			CONSTRAINT provider_tool_call_mappings_result_requires_page_check CHECK (result_hash IS NULL OR page_hash IS NOT NULL),
			CONSTRAINT provider_tool_call_mappings_state_check CHECK (state IN ('prepared', 'invoked', 'settled', 'reconciled')),
			CONSTRAINT provider_tool_call_mappings_function_unique UNIQUE (workspace_id, provider_function_call_evidence_id),
			CONSTRAINT provider_tool_call_mappings_call_unique UNIQUE (workspace_id, step_attempt_id, provider_call_id),
			CONSTRAINT provider_tool_call_mappings_tool_call_unique UNIQUE (workspace_id, tool_call_id),
			CONSTRAINT provider_tool_call_mappings_task_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id),
			CONSTRAINT provider_tool_call_mappings_run_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id),
			CONSTRAINT provider_tool_call_mappings_step_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id),
			CONSTRAINT provider_tool_call_mappings_attempt_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id),
			CONSTRAINT provider_tool_call_mappings_tool_call_fkey FOREIGN KEY (workspace_id, tool_call_id) REFERENCES central.tool_calls(workspace_id, id),
			CONSTRAINT provider_tool_call_mappings_response_fkey FOREIGN KEY (provider_response_evidence_id, workspace_id) REFERENCES central.provider_response_evidence(id, workspace_id),
			CONSTRAINT provider_tool_call_mappings_function_fkey FOREIGN KEY (provider_function_call_evidence_id, workspace_id, provider_response_evidence_id) REFERENCES central.provider_function_call_evidence(id, workspace_id, provider_response_id)
		);

CREATE INDEX provider_tool_call_mappings_restart_idx ON central.provider_tool_call_mappings (workspace_id, task_id, run_id, step_id, step_attempt_id, state, id);

CREATE INDEX provider_tool_call_mappings_response_idx ON central.provider_tool_call_mappings (workspace_id, provider_response_evidence_id, id);

GRANT SELECT ON central.provider_tool_call_mappings TO central_runtime;

GRANT INSERT ON central.provider_tool_call_mappings TO central_runtime;

GRANT UPDATE ON central.provider_tool_call_mappings TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp() WHERE version = 16 AND checksum = 'b09-provider-tool-call-mapping-correction' AND dirty = true;

INSERT INTO central.migration_checksums(version, checksum, recorded_at) VALUES (16, 'b09-provider-tool-call-mapping-correction', clock_timestamp());

commit;

