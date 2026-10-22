-- version 11 | ledger checksum b09-provider-evidence | source b09.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (11, 'b09-provider-evidence', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.provider_bindings (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			secret_reference text NOT NULL, opaque_generation uuid NOT NULL, provider text NOT NULL, adapter text NOT NULL, model text NOT NULL,
			destination text NOT NULL, method text NOT NULL, path text NOT NULL, binding_verifier bytea NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz NULL,
			CONSTRAINT provider_bindings_selector_unique UNIQUE (workspace_id, secret_reference, provider, adapter, model, destination, method, path),
			CONSTRAINT provider_bindings_verifier_check CHECK (octet_length(binding_verifier) = 32)
		);

CREATE TABLE IF NOT EXISTS central.provider_fence_consumptions (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), provider_binding_id uuid NOT NULL REFERENCES central.provider_bindings(id),
			workspace_id uuid NOT NULL REFERENCES central.workspaces(id), task_id uuid NOT NULL, run_id uuid NOT NULL,
			step_attempt_id uuid NOT NULL, logical_operation_id uuid NOT NULL, physical_attempt_id uuid NOT NULL,
			invocation_id uuid NOT NULL, policy_verifier bytea NOT NULL, context_verifier bytea NOT NULL,
			sensitivity_verifier bytea NOT NULL,
			fence_generation bigint NOT NULL CHECK (fence_generation > 0), fence_verifier bytea NOT NULL,
			fence_deadline timestamptz NOT NULL, consumed_at timestamptz NULL, result_code text NOT NULL,
			delivery_state text NOT NULL DEFAULT 'delivery_pending', handoff_failure_code text NULL,
			CONSTRAINT provider_fence_consumptions_selector_unique UNIQUE (workspace_id, logical_operation_id, invocation_id),
			CONSTRAINT provider_fence_consumptions_one_successful_consume UNIQUE (provider_binding_id, fence_generation),
			CONSTRAINT provider_fence_consumptions_delivery_state_check CHECK (delivery_state IN ('delivery_pending', 'delivered', 'reconciliation')),
			CONSTRAINT provider_fence_consumptions_verifier_check CHECK (octet_length(fence_verifier) = 32 AND octet_length(policy_verifier) = 32 AND octet_length(context_verifier) = 32 AND octet_length(sensitivity_verifier) = 32)
		);

CREATE TABLE IF NOT EXISTS central.provider_execution_evidence (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id),
			task_id uuid NOT NULL, run_id uuid NOT NULL, step_attempt_id uuid NOT NULL,
			logical_operation_id uuid NOT NULL, physical_attempt_id uuid NOT NULL, invocation_id uuid NOT NULL,
			response_id text NULL, continuation_parent_id uuid NULL, policy_revision text NOT NULL,
			price_revision text NOT NULL, request_hash bytea NOT NULL, response_hash bytea NULL,
			usage_input_tokens bigint NOT NULL DEFAULT 0 CHECK (usage_input_tokens >= 0),
			usage_output_tokens bigint NOT NULL DEFAULT 0 CHECK (usage_output_tokens >= 0),
			spend_reserved_micros bigint NOT NULL DEFAULT 0 CHECK (spend_reserved_micros >= 0),
			state text NOT NULL, reason_code text NULL, created_at timestamptz NOT NULL DEFAULT now(), settled_at timestamptz NULL,
			CONSTRAINT provider_evidence_attempt_unique UNIQUE (workspace_id, physical_attempt_id),
			CONSTRAINT provider_evidence_invocation_unique UNIQUE (workspace_id, logical_operation_id, invocation_id),
			CONSTRAINT provider_evidence_response_unique UNIQUE NULLS NOT DISTINCT (workspace_id, response_id),
			CONSTRAINT provider_evidence_continuation_parent_unique UNIQUE NULLS NOT DISTINCT (workspace_id, continuation_parent_id),
			CONSTRAINT provider_evidence_hash_check CHECK (octet_length(request_hash) = 32 AND (response_hash IS NULL OR octet_length(response_hash) = 32))
		);

CREATE INDEX IF NOT EXISTS provider_execution_evidence_reconciliation_idx ON central.provider_execution_evidence (workspace_id, state, created_at, id) WHERE state = 'reconciliation';

CREATE INDEX IF NOT EXISTS provider_fence_consumptions_unconsumed_idx ON central.provider_fence_consumptions (workspace_id, fence_deadline, id) WHERE consumed_at IS NULL;

GRANT SELECT ON central.provider_bindings TO central_runtime;

GRANT INSERT ON central.provider_bindings TO central_runtime;

GRANT UPDATE ON central.provider_bindings TO central_runtime;

GRANT SELECT ON central.provider_fence_consumptions TO central_runtime;

GRANT INSERT ON central.provider_fence_consumptions TO central_runtime;

GRANT UPDATE ON central.provider_fence_consumptions TO central_runtime;

GRANT SELECT ON central.provider_execution_evidence TO central_runtime;

GRANT INSERT ON central.provider_execution_evidence TO central_runtime;

GRANT UPDATE ON central.provider_execution_evidence TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 11 AND checksum = 'b09-provider-evidence' AND dirty = true;

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (11, 'b09-provider-evidence', clock_timestamp());

commit;

