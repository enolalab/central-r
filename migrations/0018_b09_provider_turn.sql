-- version 18 | ledger checksum b09-provider-turn | source b09_provider_turn.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations(version, checksum, dirty) VALUES (18, 'b09-provider-turn', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_bindings'::regclass AND conname = 'provider_bindings_id_workspace_unique'
		) THEN
			ALTER TABLE central.provider_bindings ADD CONSTRAINT provider_bindings_id_workspace_unique UNIQUE (workspace_id, id);
		END IF;
	END;
	$b08$;

ALTER TABLE central.provider_bindings DROP CONSTRAINT IF EXISTS provider_bindings_selector_unique;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_bindings'::regclass AND conname = 'provider_bindings_binding_unique'
		) THEN
			ALTER TABLE central.provider_bindings ADD CONSTRAINT provider_bindings_binding_unique UNIQUE (workspace_id, opaque_generation, secret_reference, provider, adapter, model, destination, method, path);
		END IF;
	END;
	$b08$;

CREATE UNIQUE INDEX IF NOT EXISTS provider_bindings_b09_generation_unique ON central.provider_bindings (workspace_id, opaque_generation) WHERE revoked_at IS NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.step_attempts'::regclass AND conname = 'step_attempts_b09_provider_turn_parent_unique'
		) THEN
			ALTER TABLE central.step_attempts ADD CONSTRAINT step_attempts_b09_provider_turn_parent_unique UNIQUE (workspace_id, task_id, run_id, step_id, id, logical_operation_id, physical_attempt_id, invocation_id);
		END IF;
	END;
	$b08$;

CREATE TABLE IF NOT EXISTS central.b09_provider_turns (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL,
			turn_id uuid NOT NULL, provider_binding_id uuid NULL, task_id uuid NOT NULL, run_id uuid NOT NULL, step_id uuid NOT NULL,
			step_attempt_id uuid NOT NULL, logical_operation_id uuid NOT NULL, physical_attempt_id uuid NOT NULL, invocation_id uuid NULL,
			parent_response_ref text NULL, parent_response_hash bytea NULL,
			parent_provider_turn_id uuid NULL, parent_logical_operation_id uuid NULL,
			parent_context_hash bytea NULL, parent_response_state text NULL,
			dispatch_reference text NULL,
			state text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(), invoked_at timestamptz NULL,
			responded_at timestamptz NULL, reconciled_at timestamptz NULL,
			CONSTRAINT b09_provider_turns_turn_id_check CHECK (turn_id <> '00000000-0000-0000-0000-000000000000'::uuid),
			CONSTRAINT b09_provider_turns_parent_hash_check CHECK (parent_response_hash IS NULL OR octet_length(parent_response_hash) = 32),
			CONSTRAINT b09_provider_turns_parent_context_hash_check CHECK (parent_context_hash IS NULL OR octet_length(parent_context_hash) = 32),
			CONSTRAINT b09_provider_turns_dispatch_reference_check CHECK (dispatch_reference IS NULL OR length(btrim(dispatch_reference)) > 0),
			CONSTRAINT b09_provider_turns_state_check CHECK (state IN ('prepared', 'invoked', 'responded', 'reconciled') AND (state = 'prepared' OR invocation_id IS NOT NULL)),
			CONSTRAINT b09_provider_turns_turn_unique UNIQUE (workspace_id, turn_id),
			CONSTRAINT b09_provider_turns_provider_binding_unique UNIQUE (workspace_id, provider_binding_id),
			CONSTRAINT b09_provider_turns_authority_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_attempt_id, physical_attempt_id),
			CONSTRAINT b09_provider_turns_reservation_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id),
			CONSTRAINT b09_provider_turns_execution_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id),
			CONSTRAINT b09_provider_turns_mapping_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id),
			CONSTRAINT b09_provider_turns_workspace_fkey FOREIGN KEY (workspace_id) REFERENCES central.workspaces(id),
			CONSTRAINT b09_provider_turns_provider_binding_fkey FOREIGN KEY (workspace_id, provider_binding_id) REFERENCES central.provider_bindings(workspace_id, id),
			CONSTRAINT b09_provider_turns_task_fkey FOREIGN KEY (workspace_id, task_id) REFERENCES central.tasks(workspace_id, id),
			CONSTRAINT b09_provider_turns_run_fkey FOREIGN KEY (workspace_id, run_id) REFERENCES central.runs(workspace_id, id),
			CONSTRAINT b09_provider_turns_step_fkey FOREIGN KEY (workspace_id, step_id) REFERENCES central.steps(workspace_id, id),
			CONSTRAINT b09_provider_turns_step_attempt_fkey FOREIGN KEY (workspace_id, step_attempt_id) REFERENCES central.step_attempts(workspace_id, id),
			CONSTRAINT b09_provider_turns_parent_fkey FOREIGN KEY (workspace_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id) REFERENCES central.step_attempts(workspace_id, task_id, run_id, step_id, id, logical_operation_id, physical_attempt_id, invocation_id)
		);

ALTER TABLE central.b09_run_snapshots ADD COLUMN IF NOT EXISTS workspace_root_id text;

UPDATE central.b09_run_snapshots snapshot SET workspace_root_id = task.input_spec->>'workspace_root_id' FROM central.tasks task WHERE task.workspace_id = snapshot.workspace_id AND task.id = snapshot.task_id AND snapshot.workspace_root_id IS NULL;

ALTER TABLE central.b09_run_snapshots ALTER COLUMN workspace_root_id SET NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_run_snapshots'::regclass AND conname = 'b09_run_snapshots_workspace_root_id_check'
		) THEN
			ALTER TABLE central.b09_run_snapshots ADD CONSTRAINT b09_run_snapshots_workspace_root_id_check CHECK (length(btrim(workspace_root_id)) > 0);
		END IF;
	END;
	$b08$;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS physical_attempt_id uuid;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS provider_binding_id uuid;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS parent_provider_turn_id uuid;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS parent_logical_operation_id uuid;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS parent_context_hash bytea;

ALTER TABLE central.b09_provider_turns ADD COLUMN IF NOT EXISTS parent_response_state text;

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

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_parent_context_hash_check'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_parent_context_hash_check CHECK (parent_context_hash IS NULL OR octet_length(parent_context_hash) = 32);
		END IF;
	END;
	$b08$;

ALTER TABLE central.b09_provider_turns ALTER COLUMN invocation_id DROP NOT NULL;

UPDATE central.b09_provider_turns SET physical_attempt_id = step_attempts.physical_attempt_id FROM central.step_attempts WHERE step_attempts.workspace_id = b09_provider_turns.workspace_id AND step_attempts.id = b09_provider_turns.step_attempt_id AND b09_provider_turns.physical_attempt_id IS NULL;

ALTER TABLE central.b09_provider_turns ALTER COLUMN physical_attempt_id SET NOT NULL;

ALTER TABLE central.b09_provider_turns DROP CONSTRAINT IF EXISTS b09_provider_turns_execution_unique;

INSERT INTO central.b09_provider_turns
			(workspace_id, turn_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id, parent_response_ref, parent_response_hash, parent_provider_turn_id, parent_logical_operation_id, parent_context_hash, parent_response_state, state, created_at)
		SELECT DISTINCT ON (legacy.workspace_id, legacy.physical_attempt_id)
			legacy.workspace_id, legacy.physical_attempt_id, attempt.task_id, attempt.run_id, attempt.step_id,
			attempt.id, attempt.logical_operation_id, attempt.physical_attempt_id, COALESCE(legacy.invocation_id, attempt.invocation_id),
			reservation.parent_response_ref, parent.response_hash, parent.physical_attempt_id, parent.logical_operation_id, parent_snapshot.context_hash, parent.state,
			CASE WHEN evidence.state IN ('invoked', 'responded', 'continued', 'tool_prepared', 'tool_invoked', 'tool_settled', 'reconciled') THEN
				CASE WHEN evidence.state = 'reconciled' THEN 'reconciled' WHEN evidence.state IN ('responded', 'continued', 'tool_prepared', 'tool_invoked', 'tool_settled') THEN 'responded' ELSE 'invoked' END
			ELSE 'prepared' END,
			COALESCE(evidence.created_at, reservation.created_at, clock_timestamp())
		FROM (
			SELECT decision.workspace_id, decision.task_id, decision.run_id, decision.step_attempt_id, attempt.logical_operation_id, decision.physical_attempt_id, NULL::uuid AS invocation_id
			FROM central.b09_authorization_decisions AS decision
			JOIN central.step_attempts AS attempt ON attempt.workspace_id = decision.workspace_id AND attempt.id = decision.step_attempt_id
			UNION ALL
			SELECT workspace_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, NULL::uuid FROM central.b09_price_reservations
			UNION ALL
			SELECT workspace_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id FROM central.provider_execution_evidence
			UNION ALL
			SELECT workspace_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id FROM central.provider_fence_consumptions
		) AS legacy
		JOIN central.step_attempts AS attempt ON attempt.workspace_id = legacy.workspace_id AND attempt.id = legacy.step_attempt_id
		 AND attempt.task_id = legacy.task_id AND attempt.run_id = legacy.run_id
		 AND attempt.logical_operation_id = legacy.logical_operation_id AND attempt.physical_attempt_id = legacy.physical_attempt_id
		 AND (legacy.invocation_id IS NULL OR attempt.invocation_id = legacy.invocation_id)
		LEFT JOIN central.provider_execution_evidence AS evidence ON evidence.workspace_id = legacy.workspace_id AND evidence.task_id = legacy.task_id AND evidence.run_id = legacy.run_id AND evidence.step_attempt_id = legacy.step_attempt_id AND evidence.logical_operation_id = legacy.logical_operation_id AND evidence.physical_attempt_id = legacy.physical_attempt_id AND (legacy.invocation_id IS NULL OR evidence.invocation_id = legacy.invocation_id)
		LEFT JOIN central.b09_price_reservations AS reservation ON reservation.workspace_id = legacy.workspace_id AND reservation.task_id = legacy.task_id AND reservation.run_id = legacy.run_id AND reservation.step_attempt_id = legacy.step_attempt_id AND reservation.logical_operation_id = legacy.logical_operation_id AND reservation.physical_attempt_id = legacy.physical_attempt_id
		LEFT JOIN central.provider_execution_evidence AS parent ON parent.workspace_id = reservation.workspace_id AND parent.task_id = reservation.task_id AND parent.run_id = reservation.run_id AND parent.step_attempt_id = reservation.step_attempt_id AND parent.response_id = reservation.parent_response_ref AND parent.state IN ('responded', 'tool_settled')
		LEFT JOIN central.b09_price_reservations AS parent_reservation ON parent_reservation.workspace_id = parent.workspace_id AND parent_reservation.physical_attempt_id = parent.physical_attempt_id
		LEFT JOIN central.b09_run_snapshots AS parent_snapshot ON parent_snapshot.workspace_id = parent_reservation.workspace_id AND parent_snapshot.id = parent_reservation.snapshot_id
		ORDER BY legacy.workspace_id, legacy.physical_attempt_id, evidence.created_at NULLS LAST
		ON CONFLICT (workspace_id, turn_id) DO NOTHING;

ALTER TABLE central.b09_authorization_decisions ADD COLUMN IF NOT EXISTS provider_turn_id uuid;

ALTER TABLE central.b09_price_reservations ADD COLUMN IF NOT EXISTS provider_turn_id uuid;

ALTER TABLE central.provider_fence_consumptions ADD COLUMN IF NOT EXISTS provider_turn_id uuid;

ALTER TABLE central.provider_execution_evidence ADD COLUMN IF NOT EXISTS provider_turn_id uuid;

ALTER TABLE central.provider_tool_call_mappings ADD COLUMN IF NOT EXISTS provider_turn_id uuid;

UPDATE central.b09_authorization_decisions decision SET provider_turn_id = turn.turn_id FROM central.b09_provider_turns turn WHERE turn.workspace_id = decision.workspace_id AND turn.turn_id = decision.physical_attempt_id;

UPDATE central.b09_price_reservations reservation SET provider_turn_id = turn.turn_id FROM central.b09_provider_turns turn WHERE turn.workspace_id = reservation.workspace_id AND turn.turn_id = reservation.physical_attempt_id;

ALTER TABLE central.b09_price_reservations ADD COLUMN IF NOT EXISTS parent_provider_turn_id uuid;

ALTER TABLE central.b09_price_reservations ADD COLUMN IF NOT EXISTS parent_logical_operation_id uuid;

ALTER TABLE central.b09_price_reservations ADD COLUMN IF NOT EXISTS parent_response_hash bytea;

ALTER TABLE central.b09_price_reservations ADD COLUMN IF NOT EXISTS parent_context_hash bytea;

ALTER TABLE central.b09_price_reservations ADD COLUMN IF NOT EXISTS parent_response_state text;

UPDATE central.b09_price_reservations reservation SET parent_provider_turn_id = turn.parent_provider_turn_id, parent_logical_operation_id = turn.parent_logical_operation_id, parent_response_hash = turn.parent_response_hash, parent_context_hash = turn.parent_context_hash, parent_response_state = turn.parent_response_state FROM central.b09_provider_turns turn WHERE turn.workspace_id = reservation.workspace_id AND turn.turn_id = reservation.provider_turn_id;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_price_reservations'::regclass AND conname = 'b09_price_reservations_parent_response_hash_check'
		) THEN
			ALTER TABLE central.b09_price_reservations ADD CONSTRAINT b09_price_reservations_parent_response_hash_check CHECK (parent_response_hash IS NULL OR octet_length(parent_response_hash) = 32);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_price_reservations'::regclass AND conname = 'b09_price_reservations_parent_context_hash_check'
		) THEN
			ALTER TABLE central.b09_price_reservations ADD CONSTRAINT b09_price_reservations_parent_context_hash_check CHECK (parent_context_hash IS NULL OR octet_length(parent_context_hash) = 32);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_price_reservations'::regclass AND conname = 'b09_price_reservations_parent_state_check'
		) THEN
			ALTER TABLE central.b09_price_reservations ADD CONSTRAINT b09_price_reservations_parent_state_check CHECK (parent_response_state IS NULL OR parent_response_state IN ('responded', 'tool_settled'));
		END IF;
	END;
	$b08$;

UPDATE central.provider_fence_consumptions fence SET provider_turn_id = turn.turn_id FROM central.b09_provider_turns turn WHERE turn.workspace_id = fence.workspace_id AND turn.turn_id = fence.physical_attempt_id;

UPDATE central.provider_execution_evidence evidence SET provider_turn_id = turn.turn_id FROM central.b09_provider_turns turn WHERE turn.workspace_id = evidence.workspace_id AND turn.turn_id = evidence.physical_attempt_id;

UPDATE central.provider_tool_call_mappings mapping SET provider_turn_id = evidence.provider_turn_id FROM central.provider_response_evidence response JOIN central.provider_execution_evidence evidence ON evidence.workspace_id = response.workspace_id AND evidence.id = response.provider_evidence_id WHERE response.workspace_id = mapping.workspace_id AND response.id = mapping.provider_response_evidence_id;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_authority_unique'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_authority_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_attempt_id, physical_attempt_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_reservation_unique'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_reservation_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_execution_unique'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_execution_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_mapping_unique'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_mapping_unique UNIQUE (workspace_id, turn_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_parent_fkey'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_parent_fkey FOREIGN KEY (workspace_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id) REFERENCES central.step_attempts(workspace_id, task_id, run_id, step_id, id, logical_operation_id, physical_attempt_id, invocation_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_provider_binding_fkey'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_provider_binding_fkey FOREIGN KEY (workspace_id, provider_binding_id) REFERENCES central.provider_bindings(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_provider_turns'::regclass AND conname = 'b09_provider_turns_provider_binding_unique'
		) THEN
			ALTER TABLE central.b09_provider_turns ADD CONSTRAINT b09_provider_turns_provider_binding_unique UNIQUE (workspace_id, provider_binding_id);
		END IF;
	END;
	$b08$;

ALTER TABLE central.b09_authorization_decisions ALTER COLUMN provider_turn_id SET NOT NULL;

ALTER TABLE central.b09_price_reservations ALTER COLUMN provider_turn_id SET NOT NULL;

ALTER TABLE central.provider_fence_consumptions ALTER COLUMN provider_turn_id SET NOT NULL;

ALTER TABLE central.provider_execution_evidence ALTER COLUMN provider_turn_id SET NOT NULL;

ALTER TABLE central.provider_tool_call_mappings ALTER COLUMN provider_turn_id SET NOT NULL;

ALTER TABLE central.b09_authorization_decisions DROP CONSTRAINT IF EXISTS b09_authorization_decisions_physical_attempt_unique;

ALTER TABLE central.b09_price_reservations DROP CONSTRAINT IF EXISTS b09_price_reservations_physical_attempt_unique;

ALTER TABLE central.provider_execution_evidence DROP CONSTRAINT IF EXISTS provider_evidence_attempt_unique;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_authorization_decisions'::regclass AND conname = 'b09_authorization_decisions_provider_turn_unique'
		) THEN
			ALTER TABLE central.b09_authorization_decisions ADD CONSTRAINT b09_authorization_decisions_provider_turn_unique UNIQUE (workspace_id, provider_turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_authorization_decisions'::regclass AND conname = 'b09_authorization_decisions_provider_turn_fkey'
		) THEN
			ALTER TABLE central.b09_authorization_decisions ADD CONSTRAINT b09_authorization_decisions_provider_turn_fkey FOREIGN KEY (workspace_id, provider_turn_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_authorization_decisions'::regclass AND conname = 'b09_authorization_decisions_provider_turn_parent_fkey'
		) THEN
			ALTER TABLE central.b09_authorization_decisions ADD CONSTRAINT b09_authorization_decisions_provider_turn_parent_fkey FOREIGN KEY (workspace_id, provider_turn_id, task_id, run_id, step_attempt_id, physical_attempt_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id, task_id, run_id, step_attempt_id, physical_attempt_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_price_reservations'::regclass AND conname = 'b09_price_reservations_provider_turn_unique'
		) THEN
			ALTER TABLE central.b09_price_reservations ADD CONSTRAINT b09_price_reservations_provider_turn_unique UNIQUE (workspace_id, provider_turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_price_reservations'::regclass AND conname = 'b09_price_reservations_provider_turn_fkey'
		) THEN
			ALTER TABLE central.b09_price_reservations ADD CONSTRAINT b09_price_reservations_provider_turn_fkey FOREIGN KEY (workspace_id, provider_turn_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.b09_price_reservations'::regclass AND conname = 'b09_price_reservations_provider_turn_parent_fkey'
		) THEN
			ALTER TABLE central.b09_price_reservations ADD CONSTRAINT b09_price_reservations_provider_turn_parent_fkey FOREIGN KEY (workspace_id, provider_turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_fence_consumptions'::regclass AND conname = 'provider_fence_consumptions_provider_turn_unique'
		) THEN
			ALTER TABLE central.provider_fence_consumptions ADD CONSTRAINT provider_fence_consumptions_provider_turn_unique UNIQUE (workspace_id, provider_turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_fence_consumptions'::regclass AND conname = 'provider_fence_consumptions_provider_turn_fkey'
		) THEN
			ALTER TABLE central.provider_fence_consumptions ADD CONSTRAINT provider_fence_consumptions_provider_turn_fkey FOREIGN KEY (workspace_id, provider_turn_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_fence_consumptions'::regclass AND conname = 'provider_fence_consumptions_provider_turn_parent_fkey'
		) THEN
			ALTER TABLE central.provider_fence_consumptions ADD CONSTRAINT provider_fence_consumptions_provider_turn_parent_fkey FOREIGN KEY (workspace_id, provider_turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_execution_evidence'::regclass AND conname = 'provider_execution_evidence_provider_turn_unique'
		) THEN
			ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_execution_evidence_provider_turn_unique UNIQUE (workspace_id, provider_turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_execution_evidence'::regclass AND conname = 'provider_execution_evidence_provider_turn_fkey'
		) THEN
			ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_execution_evidence_provider_turn_fkey FOREIGN KEY (workspace_id, provider_turn_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_execution_evidence'::regclass AND conname = 'provider_execution_evidence_provider_turn_parent_fkey'
		) THEN
			ALTER TABLE central.provider_execution_evidence ADD CONSTRAINT provider_execution_evidence_provider_turn_parent_fkey FOREIGN KEY (workspace_id, provider_turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id, task_id, run_id, step_attempt_id, logical_operation_id, physical_attempt_id, invocation_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_tool_call_mappings'::regclass AND conname = 'provider_tool_call_mappings_provider_turn_fkey'
		) THEN
			ALTER TABLE central.provider_tool_call_mappings ADD CONSTRAINT provider_tool_call_mappings_provider_turn_fkey FOREIGN KEY (workspace_id, provider_turn_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_tool_call_mappings'::regclass AND conname = 'provider_tool_call_mappings_provider_turn_parent_fkey'
		) THEN
			ALTER TABLE central.provider_tool_call_mappings ADD CONSTRAINT provider_tool_call_mappings_provider_turn_parent_fkey FOREIGN KEY (workspace_id, provider_turn_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id) REFERENCES central.b09_provider_turns(workspace_id, turn_id, task_id, run_id, step_id, step_attempt_id, logical_operation_id);
		END IF;
	END;
	$b08$;

ALTER TABLE central.provider_tool_call_mappings DROP CONSTRAINT IF EXISTS provider_tool_call_mappings_function_unique;

ALTER TABLE central.provider_tool_call_mappings DROP CONSTRAINT IF EXISTS provider_tool_call_mappings_call_unique;

ALTER TABLE central.provider_tool_call_mappings DROP CONSTRAINT IF EXISTS provider_tool_call_mappings_tool_call_unique;

ALTER TABLE central.provider_fence_consumptions DROP CONSTRAINT IF EXISTS provider_fence_consumptions_selector_unique;

ALTER TABLE central.provider_execution_evidence DROP CONSTRAINT IF EXISTS provider_evidence_invocation_unique;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_tool_call_mappings'::regclass AND conname = 'provider_tool_call_mappings_function_unique'
		) THEN
			ALTER TABLE central.provider_tool_call_mappings ADD CONSTRAINT provider_tool_call_mappings_function_unique UNIQUE (workspace_id, provider_turn_id, provider_function_call_evidence_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_tool_call_mappings'::regclass AND conname = 'provider_tool_call_mappings_call_unique'
		) THEN
			ALTER TABLE central.provider_tool_call_mappings ADD CONSTRAINT provider_tool_call_mappings_call_unique UNIQUE (workspace_id, provider_turn_id, step_attempt_id, provider_call_id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.provider_tool_call_mappings'::regclass AND conname = 'provider_tool_call_mappings_tool_call_unique'
		) THEN
			ALTER TABLE central.provider_tool_call_mappings ADD CONSTRAINT provider_tool_call_mappings_tool_call_unique UNIQUE (workspace_id, provider_turn_id, tool_call_id);
		END IF;
	END;
	$b08$;

DROP INDEX IF EXISTS central.b09_authorization_decisions_current_idx;

DROP INDEX IF EXISTS central.b09_price_reservations_restart_idx;

DROP INDEX IF EXISTS central.provider_tool_call_mappings_restart_idx;

CREATE INDEX b09_authorization_decisions_current_idx ON central.b09_authorization_decisions (workspace_id, task_id, run_id, step_attempt_id, provider_turn_id, security_epoch, expires_at, id) WHERE revoked_at IS NULL;

CREATE INDEX b09_price_reservations_restart_idx ON central.b09_price_reservations (workspace_id, task_id, run_id, step_attempt_id, provider_turn_id, state, expires_at, id);

CREATE INDEX provider_tool_call_mappings_restart_idx ON central.provider_tool_call_mappings (workspace_id, task_id, run_id, step_id, step_attempt_id, provider_turn_id, state, id);

CREATE INDEX b09_provider_turns_restart_idx ON central.b09_provider_turns (workspace_id, task_id, run_id, step_attempt_id, state, created_at, turn_id);

CREATE INDEX b09_provider_turns_parent_idx ON central.b09_provider_turns (workspace_id, parent_response_ref) WHERE parent_response_ref IS NOT NULL;

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

DROP TRIGGER IF EXISTS b09_provider_turns_immutable_update ON central.b09_provider_turns;

CREATE TRIGGER b09_provider_turns_immutable_update BEFORE UPDATE ON central.b09_provider_turns FOR EACH ROW EXECUTE FUNCTION central.b09_provider_turn_immutable_update();

DROP TRIGGER IF EXISTS b09_authorization_decisions_turn_immutable_update ON central.b09_authorization_decisions;

CREATE TRIGGER b09_authorization_decisions_turn_immutable_update BEFORE UPDATE ON central.b09_authorization_decisions FOR EACH ROW EXECUTE FUNCTION central.b09_provider_turn_immutable_update();

DROP TRIGGER IF EXISTS b09_price_reservations_turn_immutable_update ON central.b09_price_reservations;

CREATE TRIGGER b09_price_reservations_turn_immutable_update BEFORE UPDATE ON central.b09_price_reservations FOR EACH ROW EXECUTE FUNCTION central.b09_provider_turn_immutable_update();

DROP TRIGGER IF EXISTS provider_fence_consumptions_turn_immutable_update ON central.provider_fence_consumptions;

CREATE TRIGGER provider_fence_consumptions_turn_immutable_update BEFORE UPDATE ON central.provider_fence_consumptions FOR EACH ROW EXECUTE FUNCTION central.b09_provider_turn_immutable_update();

DROP TRIGGER IF EXISTS provider_execution_evidence_turn_immutable_update ON central.provider_execution_evidence;

CREATE TRIGGER provider_execution_evidence_turn_immutable_update BEFORE UPDATE ON central.provider_execution_evidence FOR EACH ROW EXECUTE FUNCTION central.b09_provider_turn_immutable_update();

DROP TRIGGER IF EXISTS provider_tool_call_mappings_turn_immutable_update ON central.provider_tool_call_mappings;

CREATE TRIGGER provider_tool_call_mappings_turn_immutable_update BEFORE UPDATE ON central.provider_tool_call_mappings FOR EACH ROW EXECUTE FUNCTION central.b09_provider_turn_immutable_update();

REVOKE UPDATE ON central.b09_provider_turns FROM central_runtime;

REVOKE UPDATE ON central.b09_authorization_decisions FROM central_runtime;

REVOKE UPDATE ON central.b09_price_reservations FROM central_runtime;

REVOKE UPDATE ON central.provider_fence_consumptions FROM central_runtime;

REVOKE UPDATE ON central.provider_execution_evidence FROM central_runtime;

REVOKE UPDATE ON central.provider_tool_call_mappings FROM central_runtime;

-- has_column_privilege is verified after the grants are applied;

GRANT UPDATE (state, invoked_at, responded_at, reconciled_at) ON central.b09_provider_turns TO central_runtime;

GRANT UPDATE (revoked_at) ON central.b09_authorization_decisions TO central_runtime;

GRANT UPDATE (state, settled_input_tokens, settled_output_tokens, settled_spend_micros, settled_at) ON central.b09_price_reservations TO central_runtime;

GRANT UPDATE (delivery_state, handoff_failure_code) ON central.provider_fence_consumptions TO central_runtime;

GRANT UPDATE (state, response_hash, response_id, usage_input_tokens, usage_output_tokens, spend_reserved_micros, reason_code, settled_at) ON central.provider_execution_evidence TO central_runtime;

GRANT UPDATE (state, page_hash, result_hash, updated_at, settled_at) ON central.provider_tool_call_mappings TO central_runtime;

GRANT SELECT ON central.b09_provider_turns TO central_runtime;

GRANT INSERT ON central.b09_provider_turns TO central_runtime;

GRANT SELECT ON central.b09_authorization_decisions TO central_runtime;

GRANT INSERT ON central.b09_authorization_decisions TO central_runtime;

GRANT SELECT ON central.b09_price_reservations TO central_runtime;

GRANT INSERT ON central.b09_price_reservations TO central_runtime;

GRANT SELECT ON central.provider_fence_consumptions TO central_runtime;

GRANT INSERT ON central.provider_fence_consumptions TO central_runtime;

GRANT SELECT ON central.provider_execution_evidence TO central_runtime;

GRANT INSERT ON central.provider_execution_evidence TO central_runtime;

GRANT SELECT ON central.provider_tool_call_mappings TO central_runtime;

GRANT INSERT ON central.provider_tool_call_mappings TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp() WHERE version = 18 AND checksum = 'b09-provider-turn' AND dirty = true;

INSERT INTO central.migration_checksums(version, checksum, recorded_at) VALUES (18, 'b09-provider-turn', clock_timestamp());

commit;

