# codex testdata provenance

Every file is pure JSONL (no comment lines — the session reader never
skips `#`). Real captures are sanitized per the issue-128 spec review
I1 (cf-ray/request-id/credential-adjacent tokens redacted, live ids
replaced with fixed test UUIDs, credential words in messages
rewritten, worktree paths canonicalized to `/work`); hand-built
fixtures follow the `rust-v0.162.1`
`exec_events.rs` serde schema and the JSONL processor row for row.

Real captures (codex 0.162.1, no credentials):

- `auth-failure.ndjson`: unauthenticated `exec --json` — thread.started,
  turn.started, `error` retry notices, a transport-fallback error item,
  `turn.failed`; exit 1 (spec E1).
- `resume-unknown-empty.ndjson`: `exec resume` of an unknown UUID —
  empty stdout, exit 1 (spec E4).

Hand-built (schema-derived):

- `success.ndjson`: minimal success — started, message, turn.completed.
- `command.ndjson`: command_execution started + completed ok.
- `command-failed.ndjson`: command failed, turn still completes.
- `command-declined.ndjson`: command declined.
- `file-change.ndjson`: completed-only file_change.
- `mcp-call.ndjson`: mcp_tool_call started + completed with result.
- `web-search.ndjson`: completed web_search with results.
- `collab-call.ndjson`: completed collab_tool_call.
- `reasoning-todo-skip.ndjson`: reasoning + todo started/updated/
  completed, all skipped.
- `error-item.ndjson`: non-fatal error item (warns).
- `top-error.ndjson`: top-level retry notice tolerated, then success.
- `usage-second-wins-skip.ndjson`: two turn.completed (second warns).
- `resume.ndjson`: resumed thread continues under the recorded id.
- `unknown-type.ndjson`: unknown envelope type tolerated.

Malformed lines are exercised inline in `session_test.go`, not as a
fixture (the hygiene test requires every fixture line to be valid
JSON).
