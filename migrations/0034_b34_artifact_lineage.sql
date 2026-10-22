-- version 34 | ledger checksum b34-artifact-lineage | source b34_artifact_lineage.go

begin;

SET LOCAL synchronous_commit = on;

INSERT INTO central.schema_migrations (version, checksum, dirty)
		VALUES (34, 'b34-artifact-lineage', true) ON CONFLICT (version) DO NOTHING;

commit;

begin;

SET LOCAL synchronous_commit = on;

CREATE TABLE IF NOT EXISTS central.artifact_produce_edges (
			id uuid NOT NULL,
			run_id uuid NOT NULL,
			node_id uuid NOT NULL,
			attempt_id uuid NOT NULL,
			artifact_id uuid NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT artifact_produce_edges_pkey PRIMARY KEY (id),
			CONSTRAINT artifact_produce_edges_artifact_unique UNIQUE (artifact_id),
			CONSTRAINT artifact_produce_edges_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT artifact_produce_edges_node_fkey FOREIGN KEY (node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT artifact_produce_edges_artifact_fkey FOREIGN KEY (artifact_id)
				REFERENCES central.artifacts (id)
		);

CREATE TABLE IF NOT EXISTS central.artifact_read_edges (
			id uuid NOT NULL,
			run_id uuid NOT NULL,
			reader_node_id uuid,
			attempt_id uuid,
			artifact_id uuid NOT NULL,
			declared boolean NOT NULL,
			checksum text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT artifact_read_edges_pkey PRIMARY KEY (id),
			CONSTRAINT artifact_read_edges_attempt_unique UNIQUE (run_id, reader_node_id, attempt_id, artifact_id),
			CONSTRAINT artifact_read_edges_run_fkey FOREIGN KEY (run_id)
				REFERENCES central.runs (id),
			CONSTRAINT artifact_read_edges_reader_fkey FOREIGN KEY (reader_node_id)
				REFERENCES central.workflow_nodes (id),
			CONSTRAINT artifact_read_edges_artifact_fkey FOREIGN KEY (artifact_id)
				REFERENCES central.artifacts (id),
			CONSTRAINT artifact_read_edges_reader_pair_check CHECK ((reader_node_id IS NULL) = (attempt_id IS NULL))
		);

CREATE INDEX IF NOT EXISTS artifact_produce_edges_node_idx
			ON central.artifact_produce_edges (run_id, node_id);

CREATE INDEX IF NOT EXISTS artifact_read_edges_reader_idx
			ON central.artifact_read_edges (run_id, reader_node_id);

CREATE INDEX IF NOT EXISTS artifact_read_edges_artifact_idx
			ON central.artifact_read_edges (artifact_id);

REVOKE ALL ON central.artifact_produce_edges, central.artifact_read_edges FROM PUBLIC;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON central.artifact_produce_edges, central.artifact_read_edges FROM central_runtime;

GRANT SELECT, INSERT ON central.artifact_produce_edges TO central_runtime;

GRANT SELECT, INSERT ON central.artifact_read_edges TO central_runtime;

commit;

begin;

SET LOCAL synchronous_commit = on;

UPDATE central.schema_migrations SET dirty = false, applied_at = clock_timestamp()
		WHERE version = 34 AND checksum = 'b34-artifact-lineage';

INSERT INTO central.migration_checksums (version, checksum, recorded_at)
		VALUES (34, 'b34-artifact-lineage', clock_timestamp());

commit;

