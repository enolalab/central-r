# SB-G4 — `central_runtime` holds no `DELETE` on `central.artifact_reconciliation_claims`, so a literal port leaves resolved/released large claims un-removable

- **Type:** Privilege/role defect latent in the canonical extracted baseline — upstream's own `b10.go` grants (`SELECT, INSERT, UPDATE`, no `DELETE`) do not cover upstream's own `queries.go` `DELETE`s against the same table — surfaced while porting the `ReconciliationStore` during Phase R2.
- **Found:** 2026-10-22, Task 6 of the R2 verified-artifact-lifecycle plan, while implementing `central-adapter-postgres::artifact::ReconciliationStore` (`crates/adapters/central-adapter-postgres/src/artifact/reconcile.rs`).
- **Found by:** line-by-line review of the extracted grant DDL (`migrations/0014_b10_artifact_lifecycle.sql`, plus `migrations/reapply_incremental_runtime_grants.sql`) against the statement list being ported — every `ClaimLarge` and `ReleaseLargeClaim` path issues an upstream `DELETE` the `central_runtime` grant matrix does not authorize.
- **Severity:** High and silent at schema-install time: `ClaimLarge` would fail `42501 insufficient_privilege` on its first call under the production role, so no large-claim pass could ever run; `ReleaseLargeClaim` would fail identically, leaving `claim_kind = 'large'` rows that — because a pending large claim takes the whole pass — starve normal reconciliation on every subsequent tick.
- **Status:** Fixed 2026-10-22 in commit `97384c5` (`feat(adapter-postgres): implement artifact ReconciliationStore, b34 lineage stores, and sqlx metadata`), direction 1 of "What a fix requires", under the ADR 0028 §D3 delegation — all four criteria hold.

## Resolution

Where upstream `DELETE`s a resolved or released large claim row, the port *demotes* it:

```sql
UPDATE central.artifact_reconciliation_claims
SET claim_kind = 'normal', lease_expires_at = clock_timestamp(), updated_at = clock_timestamp()
```

applied at the two exact sites upstream deletes — `claim_large` (`reconcile.rs`, the `queryDeleteResolvedLargeClaims` arm, demoting every large claim whose artifact resolved or vanished) and `release_large_claim` (the `queryDeleteLargeClaim` arm, demoting the one row the pass just processed).

The demoted row leaves `queryLockOldestLargeClaim`'s `WHERE claim_kind = 'large'` predicate permanently, so it can never be re-selected as dedicated work; its lease is elapsed and its kind is `normal`, so the normal incomplete-artifact cursor re-observes the artifact and re-defers it into a fresh large claim if it still needs one. That is exactly the liveness the `DELETE` provided — *no claim row outlives the work it describes* — under the strictly smaller `SELECT, INSERT, UPDATE` grant.

## Measured

Upstream baseline (`$CENTRAL_SRC`), grant side:

```go
// internal/adapter/postgres/migrate/b10.go:405-412
"artifact_reconciliation_claims":   {"SELECT", "INSERT", "UPDATE"},
```

Upstream baseline, mutation side:

```go
// internal/adapter/postgres/artifact/queries.go:302
queryDeleteResolvedLargeClaims = `
DELETE FROM central.artifact_reconciliation_claims c
WHERE c.claim_kind = 'large' AND NOT EXISTS (...)`

// internal/adapter/postgres/artifact/queries.go:325
queryDeleteLargeClaim = `
DELETE FROM central.artifact_reconciliation_claims
WHERE workspace_id = $1::uuid AND artifact_id = $2::uuid AND claim_kind = 'large'`
```

Extracted corpus in this repo (checksum-frozen, statement-for-statement):

```sql
-- migrations/0014_b10_artifact_lifecycle.sql:176-180
GRANT SELECT  ON central.artifact_reconciliation_claims TO central_runtime;
GRANT INSERT  ON central.artifact_reconciliation_claims TO central_runtime;
GRANT UPDATE  ON central.artifact_reconciliation_claims TO central_runtime;
-- (no DELETE; migrations/reapply_incremental_runtime_grants.sql:275-279 repeats the same three)
```

## Root cause

The upstream `b10` migration's runtime-grant matrix was written for the claim *lifecycle* statements (insert on defer, update on claim/lease/expiry/progress) and simply never enumerated the two cleanup `DELETE`s the same file's Go adapter later issues. Nothing upstream ever ran `ClaimLarge`/`ReleaseLargeClaim` under the real `central_runtime` role in a test — its integration suites connect with owner/superuser privileges, where `DELETE` succeeds regardless of the grant matrix — so the mismatch survived undetected upstream and was carried verbatim into this repo's canonical `v0..b37` extraction.

## What a fix requires

The ADR 0028 §D3 delegation permits an agent-applied fix only when all four criteria hold:

1. **It does not weaken any permission, peer-authorization, or ceremony check.** The demotion *shrinks* the required privilege surface — no `DELETE` is ever needed — and preserves the exact predicates of the statements it replaces (`claim_kind = 'large' AND NOT EXISTS …` and `(workspace_id, artifact_id, claim_kind = 'large')` are carried verbatim from `WHERE`-clause to `WHERE`-clause). Claim fencing (`claim_token_hash` validation on claim/expire paths) is untouched. ✓
2. **It does not change a wire format or an Accepted ADR's decision.** The `ReconciliationStore` port signatures, the `artifact_reconciliation_claims` schema, and the canonical extracted migration files are all unchanged; the difference is which SQL verb the adapter issues inside the same transaction boundary. ✓
3. **It is covered by a test that fails before and passes after.** `tests/artifact_reconcile_integration.rs` executes every `ReconciliationStore` call under the real `central_runtime` role (fixture rows are planted as `central_migration`, then the store pool reconnects as `central_runtime`). `claim_large_demotes_a_resolved_claim`, `release_large_claim_is_idempotent_and_demotes_the_row`, and `release_large_claim_fails_closed_on_an_incomplete_request` exercise the demotion; a literal-`DELETE` port fails those same tests with `42501 insufficient_privilege`. ✓
4. **It is recorded under `docs/internal/tasks/` with this analysis.** This file. ✓

Directions considered:

1. **UPDATE-demotion (applied).** Same predicates, same transactions, same liveness; strictly smaller grant requirement; zero schema/migration drift from the canonical corpus.
2. **Grant `DELETE` to `central_runtime`** via a new incremental migration. Rejected: it widens the production role's destructive power beyond upstream's own grant intent, mutates the checksum-frozen grant matrix the `v0..b37` extraction exists to preserve, and buys nothing the demotion does not already provide.
3. **Keep `DELETE` and run cleanup under an elevated role.** Rejected: it violates the adapter's single-role connection model (the runtime store holds one `central_runtime` pool), introduces a second credential at the hot path, and still leaves the grant matrix inconsistent with the statements issued.

## References

- `crates/adapters/central-adapter-postgres/src/artifact/reconcile.rs` — module doc (lines 14–23) plus the two demotion sites (`claim_large`, `release_large_claim`).
- `crates/adapters/central-adapter-postgres/tests/artifact_reconcile_integration.rs` — `central_runtime`-role test harness and the three demotion coverage tests.
- `migrations/0014_b10_artifact_lifecycle.sql:176-180`, `migrations/reapply_incremental_runtime_grants.sql:275-279` — the grant matrix as extracted.
- Upstream: `internal/adapter/postgres/migrate/b10.go:405-412` (grants), `internal/adapter/postgres/artifact/queries.go:302,325` (DELETEs), `internal/adapter/postgres/artifact/store.go:1749,1969` (call sites).
- `docs/adr/0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md` §D3 — the delegation rule this fix was applied under; `AGENTS.md` — the same four criteria.
- SC-DEF-23 (upstream `docs/internal/tasks/`) — the record format this file follows.
