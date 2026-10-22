-- reapply runtime grants | source reapply_incremental_runtime_grants.go + baseline.go:applyRuntimeGrants

begin;

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

GRANT INSERT ON central.tasks TO central_runtime;

GRANT UPDATE ON central.tasks TO central_runtime;

GRANT INSERT ON central.runs TO central_runtime;

GRANT UPDATE ON central.runs TO central_runtime;

GRANT INSERT ON central.workspace_event_counters TO central_runtime;

GRANT UPDATE ON central.workspace_event_counters TO central_runtime;

GRANT INSERT ON central.command_receipts TO central_runtime;

GRANT UPDATE ON central.workspaces TO central_runtime;

GRANT INSERT ON central.artifacts TO central_runtime;

GRANT UPDATE ON central.artifacts TO central_runtime;

GRANT INSERT ON central.events TO central_runtime;

GRANT INSERT ON central.capacity_reservations TO central_runtime;

GRANT UPDATE ON central.capacity_reservations TO central_runtime;

GRANT INSERT ON central.bootstrap_generations TO central_runtime;

GRANT UPDATE ON central.bootstrap_generations TO central_runtime;

GRANT INSERT ON central.sessions TO central_runtime;

GRANT UPDATE ON central.sessions TO central_runtime;

GRANT SELECT ON central.execution_completion_receipts TO central_runtime;

GRANT INSERT ON central.execution_completion_receipts TO central_runtime;

GRANT UPDATE ON central.tasks TO central_runtime;

GRANT UPDATE ON central.runs TO central_runtime;

GRANT INSERT ON central.workspace_event_counters TO central_runtime;

GRANT UPDATE ON central.workspace_event_counters TO central_runtime;

GRANT SELECT ON central.execution_command_receipts TO central_runtime;

GRANT SELECT ON central.recovery_coordinators TO central_runtime;

GRANT SELECT ON central.recovery_epochs TO central_runtime;

GRANT SELECT ON central.recovery_epoch_workspaces TO central_runtime;

GRANT SELECT ON central.outbox_workspace_work TO central_runtime;

GRANT INSERT ON central.execution_ownership TO central_runtime;

GRANT UPDATE ON central.execution_ownership TO central_runtime;

GRANT INSERT ON central.approvals TO central_runtime;

GRANT UPDATE ON central.approvals TO central_runtime;

GRANT INSERT ON central.events TO central_runtime;

GRANT INSERT ON central.outbox TO central_runtime;

GRANT UPDATE ON central.outbox TO central_runtime;

GRANT INSERT ON central.execution_command_receipts TO central_runtime;

GRANT INSERT ON central.steps TO central_runtime;

GRANT UPDATE ON central.steps TO central_runtime;

GRANT INSERT ON central.checkpoints TO central_runtime;

GRANT UPDATE ON central.checkpoints TO central_runtime;

GRANT INSERT ON central.recovery_coordinators TO central_runtime;

GRANT UPDATE ON central.recovery_coordinators TO central_runtime;

GRANT INSERT ON central.recovery_epochs TO central_runtime;

GRANT UPDATE ON central.recovery_epochs TO central_runtime;

GRANT INSERT ON central.recovery_epoch_workspaces TO central_runtime;

GRANT UPDATE ON central.recovery_epoch_workspaces TO central_runtime;

GRANT INSERT ON central.outbox_workspace_work TO central_runtime;

GRANT UPDATE ON central.outbox_workspace_work TO central_runtime;

GRANT INSERT ON central.step_attempts TO central_runtime;

GRANT UPDATE ON central.step_attempts TO central_runtime;

GRANT INSERT ON central.tool_calls TO central_runtime;

GRANT UPDATE ON central.tool_calls TO central_runtime;

GRANT INSERT ON central.tool_call_attempts TO central_runtime;

GRANT UPDATE ON central.tool_call_attempts TO central_runtime;

GRANT SELECT ON central.provider_bindings TO central_runtime;

GRANT INSERT ON central.provider_bindings TO central_runtime;

GRANT UPDATE ON central.provider_bindings TO central_runtime;

GRANT SELECT ON central.provider_fence_consumptions TO central_runtime;

GRANT INSERT ON central.provider_fence_consumptions TO central_runtime;

GRANT UPDATE ON central.provider_fence_consumptions TO central_runtime;

GRANT SELECT ON central.provider_execution_evidence TO central_runtime;

GRANT INSERT ON central.provider_execution_evidence TO central_runtime;

GRANT UPDATE ON central.provider_execution_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_command_receipts TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_response_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_function_call_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.filesystem_page_evidence TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_reconciliation_proofs TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.provider_completion_references TO central_runtime;

GRANT SELECT ON central.b09_run_snapshots TO central_runtime;

GRANT INSERT ON central.b09_run_snapshots TO central_runtime;

GRANT SELECT ON central.b09_authorization_decisions TO central_runtime;

GRANT INSERT ON central.b09_authorization_decisions TO central_runtime;

GRANT UPDATE ON central.b09_authorization_decisions TO central_runtime;

GRANT SELECT ON central.b09_price_reservations TO central_runtime;

GRANT INSERT ON central.b09_price_reservations TO central_runtime;

GRANT UPDATE ON central.b09_price_reservations TO central_runtime;

GRANT SELECT ON central.provider_tool_call_mappings TO central_runtime;

GRANT INSERT ON central.provider_tool_call_mappings TO central_runtime;

GRANT UPDATE ON central.provider_tool_call_mappings TO central_runtime;

GRANT SELECT ON central.provider_tool_call_mappings TO central_runtime;

GRANT INSERT ON central.provider_tool_call_mappings TO central_runtime;

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

REVOKE UPDATE ON central.b09_provider_turns FROM central_runtime;

REVOKE UPDATE ON central.b09_authorization_decisions FROM central_runtime;

REVOKE UPDATE ON central.b09_price_reservations FROM central_runtime;

REVOKE UPDATE ON central.provider_fence_consumptions FROM central_runtime;

REVOKE UPDATE ON central.provider_execution_evidence FROM central_runtime;

REVOKE UPDATE ON central.provider_tool_call_mappings FROM central_runtime;

GRANT UPDATE (state, invoked_at, responded_at, reconciled_at) ON central.b09_provider_turns TO central_runtime;

GRANT UPDATE (revoked_at) ON central.b09_authorization_decisions TO central_runtime;

GRANT UPDATE (state, settled_input_tokens, settled_output_tokens, settled_spend_micros, settled_at) ON central.b09_price_reservations TO central_runtime;

GRANT UPDATE (delivery_state, handoff_failure_code) ON central.provider_fence_consumptions TO central_runtime;

GRANT UPDATE (state, response_hash, response_id, usage_input_tokens, usage_output_tokens, spend_reserved_micros, reason_code, settled_at) ON central.provider_execution_evidence TO central_runtime;

GRANT UPDATE (state, page_hash, result_hash, updated_at, settled_at) ON central.provider_tool_call_mappings TO central_runtime;

GRANT SELECT ON central.artifact_command_receipts TO central_runtime;

GRANT INSERT ON central.artifact_command_receipts TO central_runtime;

GRANT UPDATE ON central.artifact_command_receipts TO central_runtime;

GRANT SELECT ON central.artifact_reconciliation_progress TO central_runtime;

GRANT INSERT ON central.artifact_reconciliation_progress TO central_runtime;

GRANT UPDATE ON central.artifact_reconciliation_progress TO central_runtime;

GRANT SELECT ON central.artifact_reconciliation_claims TO central_runtime;

GRANT INSERT ON central.artifact_reconciliation_claims TO central_runtime;

GRANT UPDATE ON central.artifact_reconciliation_claims TO central_runtime;

GRANT SELECT ON central.provider_response_retrievals TO central_runtime;

GRANT INSERT ON central.provider_response_retrievals TO central_runtime;

GRANT UPDATE ON central.provider_response_retrievals TO central_runtime;

GRANT SELECT ON central.artifacts TO central_runtime;

GRANT INSERT ON central.artifacts TO central_runtime;

GRANT UPDATE ON central.artifacts TO central_runtime;

GRANT SELECT ON central.capacity_reservations TO central_runtime;

GRANT INSERT ON central.capacity_reservations TO central_runtime;

GRANT UPDATE ON central.capacity_reservations TO central_runtime;

GRANT UPDATE (continuation_parent_id) ON central.provider_execution_evidence TO central_runtime;

GRANT SELECT ON central.recovery_operations, central.recovery_quarantines, central.recovery_authority_reset_receipts TO central_runtime;

GRANT SELECT ON central.prune_log TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.harness_attempts TO central_runtime;

GRANT SELECT, INSERT ON central.harness_events TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.harness_permission_approvals TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.workflow_nodes TO central_runtime;

GRANT SELECT, INSERT ON central.workflow_edges TO central_runtime;

GRANT SELECT, INSERT ON central.run_events TO central_runtime;

GRANT SELECT, INSERT ON central.artifact_produce_edges TO central_runtime;

GRANT SELECT, INSERT ON central.artifact_read_edges TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.worker_registrations TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.session_attempts TO central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.node_leases TO central_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON central.resume_checkpoints TO central_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON central.event_outbox TO central_runtime;

GRANT SELECT, INSERT ON central.attempt_decisions TO central_runtime;

GRANT SELECT, INSERT ON central.attempt_outcomes TO central_runtime;

GRANT SELECT, INSERT ON central.artifact_finalizations TO central_runtime;

commit;

