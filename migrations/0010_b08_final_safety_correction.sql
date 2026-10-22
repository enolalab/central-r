-- version 10 | ledger checksum b08-final-safety-correction | source b08_final_correction.go

begin;

SET LOCAL synchronous_commit = on;


		INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (10, 'b08-final-safety-correction', true)
		ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;


	LOCK TABLE
		central.workspaces,
		central.tasks,
		central.runs,
		central.steps,
		central.step_attempts,
		central.events,
		central.execution_command_receipts,
		central.execution_ownership,
		central.outbox
	IN ACCESS EXCLUSIVE MODE;

ALTER TABLE central.execution_command_receipts
			ADD COLUMN IF NOT EXISTS task_id uuid,
			ADD COLUMN IF NOT EXISTS run_id uuid,
			ADD COLUMN IF NOT EXISTS step_id uuid,
			ADD COLUMN IF NOT EXISTS step_attempt_id uuid,
			ADD COLUMN IF NOT EXISTS logical_operation_id uuid;

UPDATE central.execution_command_receipts receipt
		 SET task_id = attempt.task_id,
		     run_id = attempt.run_id,
		     step_id = attempt.step_id,
		     step_attempt_id = attempt.id,
		     logical_operation_id = attempt.logical_operation_id
		 FROM central.events event
		 JOIN central.step_attempts attempt
		   ON attempt.workspace_id = event.workspace_id
		  AND attempt.id = event.attempt_id
		 JOIN central.steps step
		   ON step.workspace_id = attempt.workspace_id
		  AND step.id = attempt.step_id
		  AND step.task_id = attempt.task_id
		  AND step.run_id = attempt.run_id
		  AND step.logical_operation_id = attempt.logical_operation_id
		 JOIN central.runs run
		   ON run.workspace_id = attempt.workspace_id
		  AND run.id = attempt.run_id
		  AND run.task_id = attempt.task_id
		 JOIN central.tasks task
		   ON task.workspace_id = attempt.workspace_id
		  AND task.id = attempt.task_id
		 WHERE event.workspace_id = receipt.workspace_id
		   AND event.id = receipt.result_reference
		   AND event.task_id = attempt.task_id
		   AND event.run_id = attempt.run_id
		   AND event.step_id = attempt.step_id
		   AND receipt.command_scope <> 'execution.resume_recovery';

UPDATE central.execution_command_receipts
		 SET task_id = NULL,
		     run_id = NULL,
		     step_id = NULL,
		     step_attempt_id = NULL,
		     logical_operation_id = NULL
		 WHERE command_scope = 'execution.resume_recovery'
		   AND (task_id IS NOT NULL
		        OR run_id IS NOT NULL
		        OR step_id IS NOT NULL
		        OR step_attempt_id IS NOT NULL
		        OR logical_operation_id IS NOT NULL);

ALTER TABLE central.execution_command_receipts
			ALTER COLUMN task_id DROP NOT NULL,
			ALTER COLUMN run_id DROP NOT NULL,
			ALTER COLUMN step_id DROP NOT NULL,
			ALTER COLUMN step_attempt_id DROP NOT NULL,
			ALTER COLUMN logical_operation_id DROP NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_command_receipts'::regclass AND conname = 'execution_command_receipts_binding_final_check'
		) THEN
			ALTER TABLE central.execution_command_receipts
			 ADD CONSTRAINT execution_command_receipts_binding_final_check
			 CHECK (
			   (
			     command_scope = 'execution.resume_recovery'
			     AND task_id IS NULL
			     AND run_id IS NULL
			     AND step_id IS NULL
			     AND step_attempt_id IS NULL
			     AND logical_operation_id IS NULL
			   )
			   OR
			   (
			     command_scope <> 'execution.resume_recovery'
			     AND task_id IS NOT NULL
			     AND run_id IS NOT NULL
			     AND step_id IS NOT NULL
			     AND step_attempt_id IS NOT NULL
			     AND logical_operation_id IS NOT NULL
			   )
			 );
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_command_receipts'::regclass AND conname = 'execution_command_receipts_workspace_task_final_fkey'
		) THEN
			ALTER TABLE central.execution_command_receipts
			 ADD CONSTRAINT execution_command_receipts_workspace_task_final_fkey
			 FOREIGN KEY (workspace_id, task_id)
			 REFERENCES central.tasks(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_command_receipts'::regclass AND conname = 'execution_command_receipts_workspace_run_final_fkey'
		) THEN
			ALTER TABLE central.execution_command_receipts
			 ADD CONSTRAINT execution_command_receipts_workspace_run_final_fkey
			 FOREIGN KEY (workspace_id, run_id)
			 REFERENCES central.runs(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_command_receipts'::regclass AND conname = 'execution_command_receipts_workspace_step_final_fkey'
		) THEN
			ALTER TABLE central.execution_command_receipts
			 ADD CONSTRAINT execution_command_receipts_workspace_step_final_fkey
			 FOREIGN KEY (workspace_id, step_id)
			 REFERENCES central.steps(workspace_id, id);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_command_receipts'::regclass AND conname = 'execution_command_receipts_workspace_attempt_final_fkey'
		) THEN
			ALTER TABLE central.execution_command_receipts
			 ADD CONSTRAINT execution_command_receipts_workspace_attempt_final_fkey
			 FOREIGN KEY (workspace_id, step_attempt_id)
			 REFERENCES central.step_attempts(workspace_id, id);
		END IF;
	END;
	$b08$;

UPDATE central.execution_ownership
		 SET fencing_token = NULL,
		     lease_token_hash = CASE
		       WHEN octet_length(lease_token_hash) = 32
		         THEN lease_token_hash
		       ELSE sha256(convert_to(fencing_token::text, 'UTF8'))
		     END
		 WHERE fencing_token IS NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_ownership'::regclass AND conname = 'execution_ownership_lease_token_hash_final_check'
		) THEN
			ALTER TABLE central.execution_ownership
			 ADD CONSTRAINT execution_ownership_lease_token_hash_final_check
			 CHECK (octet_length(lease_token_hash) = 32);
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.execution_ownership'::regclass AND conname = 'execution_ownership_no_plaintext_fence_final_check'
		) THEN
			ALTER TABLE central.execution_ownership
			 ADD CONSTRAINT execution_ownership_no_plaintext_fence_final_check
			 CHECK (fencing_token IS NULL);
		END IF;
	END;
	$b08$;

UPDATE central.outbox
		 SET fencing_token = NULL,
		     claim_token_hash = CASE
		       WHEN claim_token_hash IS NULL
		         OR octet_length(claim_token_hash) <> 32
		         THEN sha256(convert_to(fencing_token::text, 'UTF8'))
		       ELSE claim_token_hash
		     END
		 WHERE fencing_token IS NOT NULL;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.outbox'::regclass AND conname = 'outbox_claim_token_hash_final_check'
		) THEN
			ALTER TABLE central.outbox
			 ADD CONSTRAINT outbox_claim_token_hash_final_check
			 CHECK (
			   claim_token_hash IS NULL
			   OR octet_length(claim_token_hash) = 32
			 );
		END IF;
	END;
	$b08$;

DO $b08$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'central.outbox'::regclass AND conname = 'outbox_no_plaintext_fence_final_check'
		) THEN
			ALTER TABLE central.outbox
			 ADD CONSTRAINT outbox_no_plaintext_fence_final_check
			 CHECK (fencing_token IS NULL);
		END IF;
	END;
	$b08$;

commit;

begin;

SET LOCAL synchronous_commit = on;


		UPDATE central.schema_migrations
		SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 10 AND checksum = 'b08-final-safety-correction' AND dirty = true;


		INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (10, 'b08-final-safety-correction', clock_timestamp());

commit;

