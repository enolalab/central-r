-- version 33 | ledger checksum b33-workflow-graph | source b33_workflow_graph.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (33, 'b33-workflow-graph', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.workflow_nodes (
			id uuid NOT NULL,
			run_id uuid NOT NULL,
			workspace_id uuid NOT NULL,
			node_key text NOT NULL,
			parent_node_id uuid,
			harness text NOT NULL,
			workspace_kind text NOT NULL,
			depth integer NOT NULL,
			state text NOT NULL,
			budget_wall_clock_seconds bigint,
			budget_cost_micro_usd bigint,
			max_attempts integer NOT NULL DEFAULT 1,
			attempt_count integer NOT NULL DEFAULT 0,
			not_before timestamptz,
			input_artifact_refs jsonb NOT NULL DEFAULT '[]',
			spec jsonb NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT workflow_nodes_pkey PRIMARY KEY (id),
			CONSTRAINT workflow_nodes_run_key_unique UNIQUE (run_id, node_key),
			CONSTRAINT workflow_nodes_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT workflow_nodes_workspace_fkey FOREIGN KEY (workspace_id)
				REFERENCES central.workspaces (id),
			CONSTRAINT workflow_nodes_parent_fkey FOREIGN KEY (parent_node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT workflow_nodes_workspace_kind_check CHECK (workspace_kind IN ('worktree', 'directory')),
			CONSTRAINT workflow_nodes_depth_check CHECK (depth >= 0),
			CONSTRAINT workflow_nodes_state_check CHECK (state IN ('declared', 'ready', 'dispatched', 'running', 'succeeded', 'failed_terminal', 'attempt_ambiguous', 'cancelled')),
			CONSTRAINT workflow_nodes_max_attempts_check CHECK (max_attempts >= 1),
			CONSTRAINT workflow_nodes_attempt_count_check CHECK (attempt_count >= 0)
		);

CREATE TABLE IF NOT EXISTS central.workflow_edges (
			id uuid NOT NULL,
			run_id uuid NOT NULL,
			dependent_node_id uuid NOT NULL,
			prerequisite_node_id uuid NOT NULL,
			kind text NOT NULL,
			artifact_id uuid,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT workflow_edges_pkey PRIMARY KEY (id),
			CONSTRAINT workflow_edges_unique UNIQUE NULLS NOT DISTINCT (dependent_node_id, prerequisite_node_id, kind, artifact_id),
			CONSTRAINT workflow_edges_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT workflow_edges_dependent_fkey FOREIGN KEY (dependent_node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT workflow_edges_prerequisite_fkey FOREIGN KEY (prerequisite_node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT workflow_edges_artifact_fkey FOREIGN KEY (artifact_id)
				REFERENCES central.artifacts (id),
			CONSTRAINT workflow_edges_kind_check CHECK (kind IN ('ordering', 'artifact'))
		);

CREATE TABLE IF NOT EXISTS central.run_events (
			id uuid NOT NULL,
			workspace_id uuid NOT NULL,
			run_id uuid NOT NULL,
			seq bigint NOT NULL,
			node_id uuid,
			attempt_id uuid,
			kind text NOT NULL,
			actor text NOT NULL,
			reason_code text,
			payload jsonb NOT NULL,
			recorded_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT run_events_pkey PRIMARY KEY (id),
			CONSTRAINT run_events_run_seq_unique UNIQUE (run_id, seq),
			CONSTRAINT run_events_workspace_fkey FOREIGN KEY (workspace_id)
				REFERENCES central.workspaces (id),
			CONSTRAINT run_events_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT run_events_node_fkey FOREIGN KEY (node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT run_events_seq_check CHECK (seq >= 1)
		);

CREATE INDEX IF NOT EXISTS run_events_node_idx
			ON central.run_events (run_id, node_id, seq);

REVOKE ALL ON central.workflow_nodes, central.workflow_edges, central.run_events FROM PUBLIC;

REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.workflow_nodes FROM central_runtime;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.workflow_edges, central.run_events FROM central_runtime;

GRANT SELECT, INSERT, UPDATE ON central.workflow_nodes TO central_runtime;

GRANT SELECT, INSERT ON central.workflow_edges TO central_runtime;

GRANT SELECT, INSERT ON central.run_events TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 33 AND checksum = 'b33-workflow-graph';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (33, 'b33-workflow-graph', clock_timestamp());

commit;

