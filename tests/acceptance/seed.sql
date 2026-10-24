-- Phase R3 acceptance fixtures — applied by scripts/r3-acceptance.sh as
-- `central_migration` AFTER `central serve` is ready (posting rows before
-- the startup reconcilers run would race them). All ids are fixed
-- UUIDv7-shaped constants so the suite is re-runnable against a reused
-- database: every fixture INSERT upserts back to the fixture state
-- (`ON CONFLICT DO UPDATE`), because a previous run legitimately mutates
-- the rows — cancelling the ambiguous task, deciding approvals, rotating
-- the bootstrap generation.
--
-- psql variables:
--   :token_hash        — hex sha256 of the bootstrap token the suite submits
--   :artifact_enabled  — `true` when the object store leg is provisioned
--   :report_sha256     — hex sha256 of the object body (artifact leg only)
--   :report_size       — byte length of the object body (artifact leg only)
--
-- Fixture identities live in the sentinel workspace
-- 019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a (baseline seeds it and the
-- generation-0 bootstrap row serve requires).

\set sentinel '019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a'

BEGIN;

-- 0. Rerun cleanup: a previous run's "Mark cancelled/failed" commits
--    keyed command receipts (`harness:request-cancel:<attempt>`,
--    `harness:resolve-cancel:<attempt>`); a replay against the reset
--    rows fails the committed-version revalidation. The keys derive
--    from the fixture attempt ids, so only those keys are removed —
--    receipts from operator-submitted tasks stay durable.
DELETE FROM central.command_receipts
 WHERE workspace_id = :'sentinel'
   AND (idempotency_key LIKE 'harness:%019e0000-0000-7000-8000-00000000a004'
     OR idempotency_key LIKE 'harness:%019e0000-0000-7000-8000-00000000b004');
-- The resolve commit keys its durable result in
-- `execution_command_receipts` (a separate receipt table for execution
-- commands): a replay whose fingerprint/expected-version digest drifted
-- after reseeding is rejected as IDEMPOTENCY_CONFLICT, so fixture-keyed
-- rows must go too.
DELETE FROM central.execution_command_receipts
 WHERE workspace_id = :'sentinel'
   AND (idempotency_key LIKE 'harness:%019e0000-0000-7000-8000-00000000a004'
     OR idempotency_key LIKE 'harness:%019e0000-0000-7000-8000-00000000b004');
-- Same story for the outbox: `deduplication_key` is derived from the
-- fixture entity ids plus the version the rerun resets to, so the
-- previous run's `task.lifecycle` / `execution.attempt.settled` rows
-- would violate `outbox_workspace_catalog_dedup_unique_idx` on replay.
DELETE FROM central.outbox
 WHERE workspace_id = :'sentinel'
   AND (deduplication_key LIKE '%019e0000-0000-7000-8000-00000000a001%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000a002%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000a003%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000a004%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000b001%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000b002%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000b003%'
     OR deduplication_key LIKE '%019e0000-0000-7000-8000-00000000b004%');

-- 1. Rotate the ACTIVE bootstrap verifier to sha256(:token) so the
--    suite exchanges a known token exactly like upstream B11 does.
--    The active row is generation 0 on a fresh baseline and advances
--    on every exchange — keying on `state` keeps reruns working.
UPDATE central.bootstrap_generations
   SET verifier_hash = decode(:'token_hash', 'hex')
 WHERE workspace_id = :'sentinel'
   AND state = 'active';

-- 2. Ambiguous harness attempt: Task waiting on reconciliation, one
--    Run, one Step + StepAttempt in `reconciliation`, one
--    `harness_attempts` row in `ambiguous`. Renders the
--    `#harness-resolve` panel ("Mark failed" / "Mark cancelled").
INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, last_run_index, title, input_spec, waiting_reason)
VALUES ('019e0000-0000-7000-8000-00000000a001', :'sentinel', 1, 'waiting',
        '019e0000-0000-7000-8000-00000000a002', 1,
        'R3 ambiguous harness attempt', '{}'::jsonb, 'reconciliation')
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, status = EXCLUDED.status,
        current_run_id = EXCLUDED.current_run_id,
        last_run_index = EXCLUDED.last_run_index, title = EXCLUDED.title,
        input_spec = EXCLUDED.input_spec,
        waiting_reason = EXCLUDED.waiting_reason;
-- `waiting_reason` must be set on BOTH rows: recovery's
-- `persist_recovery_waiting_state` no-ops only when task AND run are
-- already `waiting` + `reconciliation`; a NULL run reason makes the
-- domain reject a waiting->waiting transition during the epoch scan,
-- which degrades the epoch and quarantines the run (resolve POST 409).
INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index, waiting_reason)
VALUES ('019e0000-0000-7000-8000-00000000a002', :'sentinel',
        '019e0000-0000-7000-8000-00000000a001', 1, 'waiting', 1, 'reconciliation')
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, status = EXCLUDED.status,
        run_index = EXCLUDED.run_index,
        waiting_reason = EXCLUDED.waiting_reason;
INSERT INTO central.steps (id, workspace_id, task_id, run_id, version, state, logical_operation_id, sequence)
VALUES ('019e0000-0000-7000-8000-00000000a003', :'sentinel',
        '019e0000-0000-7000-8000-00000000a001',
        '019e0000-0000-7000-8000-00000000a002', 1, 'reconciliation',
        '019e0000-0000-7000-8000-00000000a005', 1)
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, state = EXCLUDED.state,
        logical_operation_id = EXCLUDED.logical_operation_id,
        sequence = EXCLUDED.sequence;
INSERT INTO central.step_attempts (id, workspace_id, step_id, task_id, run_id, version,
        logical_operation_id, physical_attempt_id, invocation_id, invocation_generation, sequence, state)
VALUES ('019e0000-0000-7000-8000-00000000a004', :'sentinel',
        '019e0000-0000-7000-8000-00000000a003',
        '019e0000-0000-7000-8000-00000000a001',
        '019e0000-0000-7000-8000-00000000a002', 1,
        '019e0000-0000-7000-8000-00000000a005',
        '019e0000-0000-7000-8000-00000000a006',
        '019e0000-0000-7000-8000-00000000a007', 1, 1, 'reconciliation')
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, state = EXCLUDED.state,
        logical_operation_id = EXCLUDED.logical_operation_id,
        physical_attempt_id = EXCLUDED.physical_attempt_id,
        invocation_id = EXCLUDED.invocation_id,
        invocation_generation = EXCLUDED.invocation_generation,
        sequence = EXCLUDED.sequence;
-- `ambiguous` is reachable straight from `prepared`: the domain
-- validator demands the ambiguity reason but no launch-recorded fields.
INSERT INTO central.harness_attempts (workspace_id, id, run_id, kind, adapter_version,
        harness_version, harness_session_id, sandbox_scope_id,
        workspace_path, base_sha, permission, fence_generation, version, state,
        pending_permission, terminal_status, terminal_reason, terminal_exit_code,
        resolution_kind, resolution_decided_by,
        ambiguity_reason, last_event_seq, usage_tokens_in, usage_tokens_out,
        usage_cache_read, usage_cache_write, usage_cost_micro_usd, usage_estimated,
        budget_cost_micro_usd, budget_wall_clock_seconds,
        budget_cost_defaulted, budget_wall_clock_defaulted,
        prepared_at, updated_at, ended_at)
VALUES (:'sentinel', '019e0000-0000-7000-8000-00000000a004',
        '019e0000-0000-7000-8000-00000000a002', 'claude-code', 'claudecode/phase-3a',
        NULL, NULL, NULL,
        '/tmp/r3-acceptance/workspace', '0000000000000000000000000000000000000000',
        'deny', 1, 1, 'ambiguous', NULL, NULL, NULL, NULL, NULL, NULL,
        'r3-acceptance: serve restart', 0, 0, 0, 0, 0, 0,
        false, 5000000, 1800, false, false, now(), now(), NULL)
ON CONFLICT (id) DO UPDATE SET
        harness_version = EXCLUDED.harness_version,
        harness_session_id = EXCLUDED.harness_session_id,
        sandbox_scope_id = EXCLUDED.sandbox_scope_id,
        permission = EXCLUDED.permission, version = EXCLUDED.version,
        state = EXCLUDED.state,
        pending_permission = EXCLUDED.pending_permission,
        terminal_status = EXCLUDED.terminal_status,
        terminal_reason = EXCLUDED.terminal_reason,
        terminal_exit_code = EXCLUDED.terminal_exit_code,
        resolution_kind = EXCLUDED.resolution_kind,
        resolution_decided_by = EXCLUDED.resolution_decided_by,
        ambiguity_reason = EXCLUDED.ambiguity_reason,
        last_event_seq = EXCLUDED.last_event_seq,
        updated_at = EXCLUDED.updated_at, ended_at = EXCLUDED.ended_at;

-- 3. Pending permission: running Task + Run + `awaiting_permission`
--    attempt + one pending approval. Renders the `#harness-permission-`
--    `banner` on every /app page and the `#harness-permission-pending`
--    panel (waiting copy — the in-memory approval bridge only holds
--    requests from live attempts, so Allow/Deny answer through the
--    stale-decision PRG path).
INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, last_run_index, title, input_spec)
VALUES ('019e0000-0000-7000-8000-00000000b001', :'sentinel', 1, 'running',
        '019e0000-0000-7000-8000-00000000b002', 1,
        'R3 pending permission request', '{}'::jsonb)
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, status = EXCLUDED.status,
        current_run_id = EXCLUDED.current_run_id,
        last_run_index = EXCLUDED.last_run_index, title = EXCLUDED.title,
        input_spec = EXCLUDED.input_spec;
INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index)
VALUES ('019e0000-0000-7000-8000-00000000b002', :'sentinel',
        '019e0000-0000-7000-8000-00000000b001', 1, 'running', 1)
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, status = EXCLUDED.status,
        run_index = EXCLUDED.run_index;
-- awaiting_permission is a post-Launch state: the domain validator
-- requires the launch-recorded fields (harness_version, session id,
-- sandbox scope) on top of the pending permission request id.
INSERT INTO central.harness_attempts (workspace_id, id, run_id, kind, adapter_version,
        harness_version, harness_session_id, sandbox_scope_id,
        workspace_path, base_sha, permission, fence_generation, version, state,
        pending_permission, terminal_status, terminal_reason, terminal_exit_code,
        resolution_kind, resolution_decided_by,
        ambiguity_reason, last_event_seq, usage_tokens_in, usage_tokens_out,
        usage_cache_read, usage_cache_write, usage_cost_micro_usd, usage_estimated,
        budget_cost_micro_usd, budget_wall_clock_seconds,
        budget_cost_defaulted, budget_wall_clock_defaulted,
        prepared_at, updated_at, ended_at)
VALUES (:'sentinel', '019e0000-0000-7000-8000-00000000b004',
        '019e0000-0000-7000-8000-00000000b002', 'claude-code', 'claudecode/phase-3a',
        'claude-code/2.0.0', 'r3-acceptance-session', 'r3-acceptance-scope',
        '/tmp/r3-acceptance/workspace', '0000000000000000000000000000000000000000',
        'bridge', 1, 1, 'awaiting_permission', 'r3-acceptance-request',
        NULL, NULL, NULL, NULL, NULL, NULL,
        0, 0, 0, 0, 0, 0,
        false, 5000000, 1800, false, false, now(), now(), NULL)
ON CONFLICT (id) DO UPDATE SET
        harness_version = EXCLUDED.harness_version,
        harness_session_id = EXCLUDED.harness_session_id,
        sandbox_scope_id = EXCLUDED.sandbox_scope_id,
        permission = EXCLUDED.permission, version = EXCLUDED.version,
        state = EXCLUDED.state,
        pending_permission = EXCLUDED.pending_permission,
        terminal_status = EXCLUDED.terminal_status,
        terminal_reason = EXCLUDED.terminal_reason,
        terminal_exit_code = EXCLUDED.terminal_exit_code,
        resolution_kind = EXCLUDED.resolution_kind,
        resolution_decided_by = EXCLUDED.resolution_decided_by,
        ambiguity_reason = EXCLUDED.ambiguity_reason,
        last_event_seq = EXCLUDED.last_event_seq,
        updated_at = EXCLUDED.updated_at, ended_at = EXCLUDED.ended_at;
INSERT INTO central.harness_permission_approvals (workspace_id, id, attempt_id, task_id, run_id,
        request_id, tool_name, input_mac, input_size, state, requested_at, expires_at,
        decided_at, decided_by, version)
VALUES (:'sentinel', '019e0000-0000-7000-8000-00000000b005',
        '019e0000-0000-7000-8000-00000000b004',
        '019e0000-0000-7000-8000-00000000b001',
        '019e0000-0000-7000-8000-00000000b002',
        'r3-acceptance-request', 'Bash',
        decode('5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a', 'hex'),
        42, 'pending', now(), now() + interval '30 minutes',
        NULL, NULL, 0)
ON CONFLICT (id) DO UPDATE SET
        attempt_id = EXCLUDED.attempt_id, task_id = EXCLUDED.task_id,
        run_id = EXCLUDED.run_id, request_id = EXCLUDED.request_id,
        tool_name = EXCLUDED.tool_name, input_mac = EXCLUDED.input_mac,
        input_size = EXCLUDED.input_size, state = EXCLUDED.state,
        requested_at = EXCLUDED.requested_at, expires_at = EXCLUDED.expires_at,
        decided_at = EXCLUDED.decided_at, decided_by = EXCLUDED.decided_by,
        version = EXCLUDED.version;

-- 4. Ready artifact: completed Task + succeeded Run + `ready` artifact
--    whose body the runner puts into the object store at the derived
--    ready key `v1/ready/<workspace>/<artifact>/<content-generation>`
--    (the S3 adapter refuses reads on keys outside `v1/ready/`).
--    Only seeded when the runner provisioned an object store.
\set ready_key 'v1/ready/019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a/019e0000-0000-7000-8000-00000000c003/019e0000-0000-7000-8000-00000000c011'
\if :artifact_enabled
INSERT INTO central.tasks (id, workspace_id, version, status, current_run_id, last_run_index, title, input_spec)
VALUES ('019e0000-0000-7000-8000-00000000c001', :'sentinel', 1, 'completed',
        '019e0000-0000-7000-8000-00000000c002', 1,
        'R3 completed task with report artifact', '{}'::jsonb)
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, status = EXCLUDED.status,
        current_run_id = EXCLUDED.current_run_id,
        last_run_index = EXCLUDED.last_run_index, title = EXCLUDED.title,
        input_spec = EXCLUDED.input_spec;
INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index)
VALUES ('019e0000-0000-7000-8000-00000000c002', :'sentinel',
        '019e0000-0000-7000-8000-00000000c001', 1, 'succeeded', 1)
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, status = EXCLUDED.status,
        run_index = EXCLUDED.run_index;
INSERT INTO central.artifacts (id, workspace_id, task_id, run_id, version, state,
        staging_generation, object_key, checksum_algorithm, checksum_value, size,
        sensitivity, disposition, required_role, producer_id,
        content_generation, ready_key, declared_media_type, detected_media_type,
        display_name, limits_snapshot, ready_at)
VALUES ('019e0000-0000-7000-8000-00000000c003', :'sentinel',
        '019e0000-0000-7000-8000-00000000c001',
        '019e0000-0000-7000-8000-00000000c002', 1, 'ready',
        '019e0000-0000-7000-8000-00000000c010', :'ready_key',
        'sha256', decode(:'report_sha256', 'hex'), :report_size,
        'unrestricted', 'attachment', 'harness.report', 'r3-acceptance',
        '019e0000-0000-7000-8000-00000000c011', :'ready_key',
        'text/markdown', 'text/markdown', 'R3 acceptance report',
        '{"max_bytes": 1048576}'::jsonb, now())
ON CONFLICT (id) DO UPDATE SET
        version = EXCLUDED.version, state = EXCLUDED.state,
        staging_generation = EXCLUDED.staging_generation,
        object_key = EXCLUDED.object_key,
        checksum_algorithm = EXCLUDED.checksum_algorithm,
        checksum_value = EXCLUDED.checksum_value, size = EXCLUDED.size,
        sensitivity = EXCLUDED.sensitivity, disposition = EXCLUDED.disposition,
        required_role = EXCLUDED.required_role, producer_id = EXCLUDED.producer_id,
        content_generation = EXCLUDED.content_generation,
        ready_key = EXCLUDED.ready_key,
        declared_media_type = EXCLUDED.declared_media_type,
        detected_media_type = EXCLUDED.detected_media_type,
        display_name = EXCLUDED.display_name,
        limits_snapshot = EXCLUDED.limits_snapshot,
        ready_at = EXCLUDED.ready_at;
\endif

COMMIT;
