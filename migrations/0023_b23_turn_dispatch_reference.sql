-- version 23 | ledger checksum b23-turn-dispatch-reference | source b23_turn_dispatch_reference.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (23, 'b23-turn-dispatch-reference', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS dispatch_reference text;

UPDATE central.b09_provider_turns AS turn
		SET dispatch_reference = binding.opaque_generation::text
		FROM central.provider_bindings AS binding
		WHERE binding.workspace_id = turn.workspace_id
		  AND binding.id = turn.provider_binding_id
		  AND turn.dispatch_reference IS NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_dispatch_reference_check'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_dispatch_reference_check CHECK (dispatch_reference IS NULL OR length(btrim(dispatch_reference)) > 0);
		END IF;
	END;
	$b08$;

CREATE OR REPLACE FUNCTION central.b09_provider_turn_immutable_update() RETURNS trigger LANGUAGE plpgsql AS $b09$
	BEGIN
		IF TG_TABLE_NAME = 'b09_provider_turns' THEN
			IF ROW(NEW.workspace_id, NEW.turn_id, NEW.provider_binding_id, NEW.task_id, NEW.run_id, NEW.step_id, NEW.step_attempt_id, NEW.logical_operation_id, NEW.physical_attempt_id, NEW.invocation_id, NEW.parent_response_ref, NEW.parent_response_hash, NEW.parent_provider_turn_id, NEW.parent_logical_operation_id, NEW.parent_context_hash, NEW.parent_response_state, NEW.dispatch_reference, NEW.created_at)
				IS DISTINCT FROM ROW(OLD.workspace_id, OLD.turn_id, OLD.provider_binding_id, OLD.task_id, OLD.run_id, OLD.step_id, OLD.step_attempt_id, OLD.logical_operation_id, OLD.physical_attempt_id, OLD.invocation_id, OLD.parent_response_ref, OLD.parent_response_hash, OLD.parent_provider_turn_id, OLD.parent_logical_operation_id, OLD.parent_context_hash, OLD.parent_response_state, OLD.dispatch_reference, OLD.created_at) THEN
				RAISE EXCEPTION 'B09 provider-turn identity is immutable';
			END IF;
			IF NOT ((OLD.state = 'prepared' AND NEW.state IN ('prepared','invoked','reconciled')) OR
				(OLD.state = 'invoked' AND NEW.state IN ('invoked','responded','reconciled')) OR
				(OLD.state = 'responded' AND NEW.state = 'responded') OR
				(OLD.state = 'reconciled' AND NEW.state = 'reconciled')) THEN
				RAISE EXCEPTION 'B09 provider-turn state transition is invalid';
			END IF;
		ELSIF TG_TABLE_NAME = 'b09_authorization_decisions' THEN
			IF ROW(NEW.workspace_id, NEW.provider_turn_id, NEW.task_id, NEW.run_id, NEW.step_attempt_id, NEW.physical_attempt_id, NEW.snapshot_id, NEW.provider, NEW.destination, NEW.scope, NEW.secret_reference, NEW.sensitivity_manifest_hash, NEW.policy_revision, NEW.security_epoch, NEW.grant_id, NEW.decision, NEW.expires_at, NEW.created_at)
				IS DISTINCT FROM ROW(OLD.workspace_id, OLD.provider_turn_id, OLD.task_id, OLD.run_id, OLD.step_attempt_id, OLD.physical_attempt_id, OLD.snapshot_id, OLD.provider, OLD.destination, OLD.scope, OLD.secret_reference, OLD.sensitivity_manifest_hash, OLD.policy_revision, OLD.security_epoch, OLD.grant_id, OLD.decision, OLD.expires_at, OLD.created_at) THEN
				RAISE EXCEPTION 'B09 authorization decision is immutable';
			END IF;
		ELSIF TG_TABLE_NAME = 'b09_price_reservations' THEN
			IF ROW(NEW.workspace_id, NEW.provider_turn_id, NEW.task_id, NEW.run_id, NEW.step_attempt_id, NEW.snapshot_id, NEW.logical_operation_id, NEW.physical_attempt_id, NEW.price_revision, NEW.quote_digest, NEW.operation_digest, NEW.request_digest, NEW.parent_response_ref, NEW.parent_provider_turn_id, NEW.parent_logical_operation_id, NEW.parent_response_hash, NEW.parent_context_hash, NEW.parent_response_state, NEW.worst_case_micros, NEW.expires_at, NEW.created_at)
				IS DISTINCT FROM ROW(OLD.workspace_id, OLD.provider_turn_id, OLD.task_id, OLD.run_id, OLD.step_attempt_id, OLD.snapshot_id, OLD.logical_operation_id, OLD.physical_attempt_id, OLD.price_revision, OLD.quote_digest, OLD.operation_digest, OLD.request_digest, OLD.parent_response_ref, OLD.parent_provider_turn_id, OLD.parent_logical_operation_id, OLD.parent_response_hash, OLD.parent_context_hash, OLD.parent_response_state, OLD.worst_case_micros, OLD.expires_at, OLD.created_at) OR
				NOT ((OLD.state = 'reserved' AND NEW.state IN ('reserved','settled','reconciliation','released')) OR (OLD.state IN ('settled','reconciliation','released') AND NEW.state = OLD.state)) THEN
				RAISE EXCEPTION 'B09 price reservation authority is immutable';
			END IF;
		ELSIF TG_TABLE_NAME = 'provider_fence_consumptions' THEN
			IF ROW(NEW.id, NEW.provider_binding_id, NEW.workspace_id, NEW.provider_turn_id, NEW.task_id, NEW.run_id, NEW.step_attempt_id, NEW.logical_operation_id, NEW.physical_attempt_id, NEW.invocation_id, NEW.policy_verifier, NEW.context_verifier, NEW.sensitivity_verifier, NEW.fence_generation, NEW.fence_verifier, NEW.fence_deadline, NEW.consumed_at, NEW.result_code)
				IS DISTINCT FROM ROW(OLD.id, OLD.provider_binding_id, OLD.workspace_id, OLD.provider_turn_id, OLD.task_id, OLD.run_id, OLD.step_attempt_id, OLD.logical_operation_id, OLD.physical_attempt_id, OLD.invocation_id, OLD.policy_verifier, OLD.context_verifier, OLD.sensitivity_verifier, OLD.fence_generation, OLD.fence_verifier, OLD.fence_deadline, OLD.consumed_at, OLD.result_code) OR
				NOT ((OLD.delivery_state = 'delivery_pending' AND NEW.delivery_state IN ('delivery_pending','delivered','reconciliation')) OR (OLD.delivery_state IN ('delivered','reconciliation') AND NEW.delivery_state = OLD.delivery_state)) THEN
				RAISE EXCEPTION 'B09 provider fence authority is immutable';
			END IF;
		ELSIF TG_TABLE_NAME = 'provider_execution_evidence' THEN
			IF ROW(NEW.workspace_id, NEW.provider_turn_id, NEW.task_id, NEW.run_id, NEW.step_attempt_id, NEW.logical_operation_id, NEW.physical_attempt_id, NEW.invocation_id, NEW.continuation_parent_id, NEW.policy_revision, NEW.price_revision, NEW.request_hash, NEW.created_at)
				IS DISTINCT FROM ROW(OLD.workspace_id, OLD.provider_turn_id, OLD.task_id, OLD.run_id, OLD.step_attempt_id, OLD.logical_operation_id, OLD.physical_attempt_id, OLD.invocation_id, OLD.continuation_parent_id, OLD.policy_revision, OLD.price_revision, OLD.request_hash, OLD.created_at) OR
				(OLD.response_hash IS NOT NULL AND NEW.response_hash IS DISTINCT FROM OLD.response_hash) OR
				(OLD.response_id IS NOT NULL AND NEW.response_id IS DISTINCT FROM OLD.response_id) THEN
				RAISE EXCEPTION 'B09 provider evidence identity is immutable';
			END IF;
		ELSIF TG_TABLE_NAME = 'provider_tool_call_mappings' THEN
			IF ROW(NEW.workspace_id, NEW.provider_turn_id, NEW.task_id, NEW.run_id, NEW.step_id, NEW.step_attempt_id, NEW.provider_response_evidence_id, NEW.provider_function_call_evidence_id, NEW.provider_call_id, NEW.arguments_hash, NEW.tool_call_id, NEW.logical_operation_id, NEW.policy_revision, NEW.context_hash, NEW.created_at)
				IS DISTINCT FROM ROW(OLD.workspace_id, OLD.provider_turn_id, OLD.task_id, OLD.run_id, OLD.step_id, OLD.step_attempt_id, OLD.provider_response_evidence_id, OLD.provider_function_call_evidence_id, OLD.provider_call_id, OLD.arguments_hash, OLD.tool_call_id, OLD.logical_operation_id, OLD.policy_revision, OLD.context_hash, OLD.created_at) THEN
				RAISE EXCEPTION 'B09 provider mapping identity is immutable';
			END IF;
		END IF;
		RETURN NEW;
	END
	$b09$;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 23 AND checksum = 'b23-turn-dispatch-reference';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (23, 'b23-turn-dispatch-reference', clock_timestamp());

commit;

