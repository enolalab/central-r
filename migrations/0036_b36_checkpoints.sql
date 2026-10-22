-- version 36 | ledger checksum b36-checkpoints | source b36_checkpoints.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (36, 'b36-checkpoints', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.resume_checkpoints (
			checkpoint_id uuid NOT NULL,
			workspace_id uuid NOT NULL,
			run_id uuid NOT NULL,
			node_id uuid NOT NULL,
			attempt_id uuid NOT NULL,
			format_version text NOT NULL,
			graph_schema_version text NOT NULL,
			event_watermark bigint NOT NULL,
			harness_session_id text,
			workspace_digest text,
			workspace_path text,
			completed_nodes text[] NOT NULL DEFAULT '{}',
			finalized_artifacts uuid[] NOT NULL DEFAULT '{}',
			in_flight_nodes text[] NOT NULL DEFAULT '{}',
			gc_class text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			expires_at timestamptz,
			content_digest text NOT NULL,
			CONSTRAINT resume_checkpoints_pkey PRIMARY KEY (checkpoint_id),
			CONSTRAINT resume_checkpoints_workspace_fkey FOREIGN KEY (workspace_id)
				REFERENCES central.workspaces (id),
			CONSTRAINT resume_checkpoints_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT resume_checkpoints_node_fkey FOREIGN KEY (node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT resume_checkpoints_attempt_fkey FOREIGN KEY (attempt_id)
				REFERENCES central.session_attempts (id),
			CONSTRAINT resume_checkpoints_event_watermark_check CHECK (event_watermark >= 0),
			CONSTRAINT resume_checkpoints_gc_class_check CHECK (gc_class IN ('supersedeable', 'run_terminal', 'pinned'))
		);

CREATE INDEX IF NOT EXISTS resume_checkpoints_anchor_idx
			ON central.resume_checkpoints (run_id, node_id, created_at DESC);

REVOKE ALL ON central.resume_checkpoints FROM PUBLIC;

REVOKE TRUNCATE, REFERENCES, TRIGGER ON central.resume_checkpoints FROM central_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON central.resume_checkpoints TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 36 AND checksum = 'b36-checkpoints';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (36, 'b36-checkpoints', clock_timestamp());

commit;

