# R6 Task 15 — Advisory lifecycle + `central-advisory-sign` (E01–E04, B01)

Branch: `r6-backup-restore-maintenance`. Commits: `6daf6d4`..`2081b0a` (T15a: 4 commits; T15b: 3 commits).

## T15a (prior commits)

- `central-advisory-sign` binary (`genkey`/`bundle`/`verify`): Ed25519, JCS, SHA-256 message construction, std-B64 signatures, 0600 output, production-key verifier compatibility.
- B01 evaluator flip: `DenyOnlyAdvisoryEvaluator` stubs replaced by the shared production evaluator across lifecycle, prepare, wipe, delete, prune — protected active-bundle source, real host facts, wall clock, time witness, broker-backed transition recorder, compiled production trust.
- E04 lifecycle conformance suite + evidence emission (`CENTRAL_E04_EVIDENCE_DIR`).

## T15b (this slice) — broker `append_advisory_evaluation`

- `dispatch_append_advisory_evaluation` on the broker `Service` — byte-faithful port of upstream `advisory_evaluation_journal.go`: payload/request/evidence ladder, trimmed-byte size cap (16 KiB), `AdvisoryEvaluationEvidenceShape` (lax Go-`Unmarshal` mirror: optional fields, nested `host_facts`, RFC-3339 `evaluation_time` — verbatim upstream deny/commit semantics), verbatim evidence → `central.authority-transition/v1` on the `advisory-evaluation` stream via `Journal::append_committed`, `{receipt_id, receipt_sequence}` result.
- `HandleConn`/`dispatch_json` arm: `is_root_backup_helper_peer` gate (uid 0/gid 0/pid>0) before dispatch; `Dispatch` answers `"unknown purpose"` (upstream connection-only default) — `is_r6_purpose` no longer closes it. `bind_postgres_service_role` is now the only closed R6 RPC.
- `{"request":[…]}`/`[]` object-gated to "invalid request" (serde `visit_seq` would otherwise accept).
- e04 exclusion scan rewritten as `production_region`: lexical stripper (line/block comments, `"`/`b"`/`r#"`/`br#"` strings, char-vs-lifetime, `(`/`[`<`>` head depth) — fixes the split-at-first-`#[cfg(test)]` truncation that left ~2200 lines of `advisory_fetch.rs` unscanned.
- Stale `CENTRAL_DEVELOPMENT_LOCAL_ONLY` comment corrected (Rust has no dev-admission path).

## Review history

- T15a: approved; deferred seam = this RPC.
- T15b round 1 (CHANGES): strict-serde shape (HIGH), `//`-skip arithmetic + literal-blind stripper (MED×2) — fixed in `8069da1`.
- T15b round 2 (CHANGES): `visit_seq` array acceptance + nested `host_facts` null (MED×2) — fixed in `2081b0a`. Verified upstream `time.Time.UnmarshalJSON` `null`-no-op semantics against Go source. LOW residuals (dup-key last-wins, case-insensitive keys, RFC 3339 dialect, recursion limit) documented on the shape struct.

## Checks run

`cargo test -p central-adapter-linux --lib` (810/810), `--test a07_peers` (14/14), `--test a07_authority` (26/26), `cargo test -p central --test e04_advisory` (4/4), `cargo fmt --all -- --check`, `cargo clippy -p central-adapter-linux -p central -p central-infra --all-targets -- -D warnings` (clean).

## Carried/deferred

- `security-rescue-cleanup` — upstream-deferred (matrix `Implemented=false`); parity preserved.
- Prepare-root divergence (promotion must use `composition.dependency_root`) — latent until prepare promotion lands (R-deferred).
- E04 fixture/journal temp dirs persist when `CENTRAL_E04_EVIDENCE_DIR` unset (informational).
- Lifecycle composition, dev-local advisory mode, prepare promotion — future R-work.
