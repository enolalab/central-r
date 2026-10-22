-- version 12 | ledger checksum b09-provider-evidence-correction | source b09_correction.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations(version, checksum, dirty) VALUES (12,'b09-provider-evidence-correction',true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.provider_bindings
			ADD COLUMN policy_verifier bytea,
			ADD COLUMN context_verifier bytea,
			ADD COLUMN sensitivity_verifier bytea,
			ADD COLUMN fence_generation bigint,
			ADD COLUMN fence_verifier bytea,
			ADD CONSTRAINT provider_bindings_policy_verifier_check CHECK (policy_verifier IS NULL OR octet_length(policy_verifier) = 32),
			ADD CONSTRAINT provider_bindings_context_verifier_check CHECK (context_verifier IS NULL OR octet_length(context_verifier) = 32),
			ADD CONSTRAINT provider_bindings_sensitivity_verifier_check CHECK (sensitivity_verifier IS NULL OR octet_length(sensitivity_verifier) = 32),
			ADD CONSTRAINT provider_bindings_fence_generation_check CHECK (fence_generation IS NULL OR fence_generation > 0),
			ADD CONSTRAINT provider_bindings_fence_verifier_check CHECK (fence_verifier IS NULL OR octet_length(fence_verifier) = 32);

ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_evidence_id_workspace_unique UNIQUE (id, workspace_id);

ALTER TABLE central.provider_execution_evidence DROP CONSTRAINT provider_evidence_continuation_parent_unique;

CREATE UNIQUE INDEX provider_evidence_continuation_parent_unique_idx ON central.provider_execution_evidence(workspace_id, continuation_parent_id) WHERE continuation_parent_id IS NOT NULL;

ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_evidence_continuation_parent_fk FOREIGN KEY (continuation_parent_id, workspace_id) REFERENCES central.provider_execution_evidence(id, workspace_id);

ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_evidence_continuation_parent_not_self_check CHECK (continuation_parent_id IS NULL OR continuation_parent_id <> id);

ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_evidence_state_check CHECK (state IN ('prepared','invoked','responded','continued','tool_prepared','tool_invoked','tool_settled','reconciled'));

ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_evidence_reason_check CHECK (reason_code IS NULL OR reason_code IN ('ambiguous_delivery','response_mismatch','handoff_failed'));

CREATE TABLE central.provider_command_receipts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id), command_kind text NOT NULL, idempotency_key text NOT NULL, request_hash bytea NOT NULL CONSTRAINT provider_command_receipts_request_hash_check CHECK(octet_length(request_hash)=32), evidence_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(workspace_id,command_kind,idempotency_key), FOREIGN KEY(evidence_id,workspace_id) REFERENCES central.provider_execution_evidence(id,workspace_id));

CREATE TABLE central.provider_response_evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id), provider_evidence_id uuid NOT NULL, response_hash bytea NOT NULL CONSTRAINT provider_response_evidence_response_hash_check CHECK(octet_length(response_hash)=32), UNIQUE(workspace_id,provider_evidence_id), FOREIGN KEY(provider_evidence_id,workspace_id) REFERENCES central.provider_execution_evidence(id,workspace_id));

ALTER TABLE central.provider_response_evidence ADD CONSTRAINT provider_response_id_workspace_unique UNIQUE(id,workspace_id);

CREATE TABLE central.provider_function_call_evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id), provider_response_id uuid NOT NULL, call_id text NOT NULL, arguments_hash bytea NOT NULL CONSTRAINT provider_function_call_evidence_arguments_hash_check CHECK(octet_length(arguments_hash)=32), UNIQUE(workspace_id,provider_response_id,call_id), FOREIGN KEY(provider_response_id,workspace_id) REFERENCES central.provider_response_evidence(id,workspace_id));

CREATE TABLE central.filesystem_page_evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id), provider_evidence_id uuid NOT NULL, page_hash bytea NOT NULL CONSTRAINT filesystem_page_evidence_page_hash_check CHECK(octet_length(page_hash)=32), result_hash bytea NULL CONSTRAINT filesystem_page_evidence_result_hash_check CHECK(result_hash IS NULL OR octet_length(result_hash)=32), UNIQUE(workspace_id,provider_evidence_id,page_hash), FOREIGN KEY(provider_evidence_id,workspace_id) REFERENCES central.provider_execution_evidence(id,workspace_id));

CREATE TABLE central.provider_reconciliation_proofs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id), provider_evidence_id uuid NOT NULL, reason_code text NOT NULL CONSTRAINT provider_reconciliation_proofs_reason_code_check CHECK(reason_code IN ('ambiguous_delivery','response_mismatch','handoff_failed')), proof_hash bytea NOT NULL CONSTRAINT provider_reconciliation_proofs_proof_hash_check CHECK(octet_length(proof_hash)=32), UNIQUE(workspace_id,provider_evidence_id), FOREIGN KEY(provider_evidence_id,workspace_id) REFERENCES central.provider_execution_evidence(id,workspace_id));

CREATE INDEX provider_command_receipts_lookup_idx ON central.provider_command_receipts(workspace_id,command_kind,idempotency_key);

CREATE TABLE central.provider_completion_references (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL REFERENCES central.workspaces(id), completion_receipt_id uuid NOT NULL REFERENCES central.execution_completion_receipts(id), evidence_kind text NOT NULL CONSTRAINT provider_completion_references_kind_check CHECK(evidence_kind IN ('provider_evidence','reconciliation_proof','tool_page_hash')), evidence_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(workspace_id, completion_receipt_id, evidence_kind, evidence_id));

CREATE INDEX provider_completion_references_receipt_idx ON central.provider_completion_references(workspace_id, completion_receipt_id, id);

GRANT SELECT, INSERT, UPDATE ON central.provider_command_receipts TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_response_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_function_call_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.filesystem_page_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_reconciliation_proofs TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_completion_references TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty=false, applied_at=clock_timestamp() WHERE version=12 AND checksum='b09-provider-evidence-correction' AND dirty=true;

INSERT INTO central.migration_checksums(version,checksum,recorded_at) VALUES (12,'b09-provider-evidence-correction',clock_timestamp());

commit;

