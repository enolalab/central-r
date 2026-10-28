# R6-T16 — `bind_postgres_service_role` closed denial: Postgres service-role bindings can never be established (SC-DEF-39 parity gap)

- **Type:** Recorded slice-boundary deferral — a writer half upstream ports inside `local up` lifecycle composition, deliberately not landed in R0–R6. This file satisfies ADR 0028 §D3's "carried by a record" half for a defect that cannot be fixed under the four criteria (the port spans a new compose-runner decoration and a production credential store — an architecture-sized change, not a routine fix).
- **Found:** 2026-10-28, by the R6 final whole-branch review (C-1) — the same topology gap upstream recorded as SC-DEF-39 in `central/docs/internal/tasks/sc-def-39-*.md`.
- **Status:** **RESOLVED** on branch `lifecycle-composition` (commits `45f3740`…`d07fd5b`). The writer half and the full broker-backed lifecycle composition landed per direction 1 below — see "Resolution" at the bottom.

## The gap

Upstream establishes the three Postgres service-role bindings during `local up`: `postgresServiceRoleComposeRunner` decorates the compose topology so that once Postgres goes healthy, `productionPostgresServiceRoleCredentialStore.Sync` rotates and verifies `postgres_migration_v1`, `postgres_runtime_v1`, and `postgres_outbox_v1`, and the helper binds each materialized secret via the broker RPC `bind_postgres_service_role` (`internal/adapter/authority/broker/postgres_service_role_bind.go`, `cmd/central/postgres_service_role_credential.go`, `cmd/central/main.go:340-349`).

The Rust port carries the full read side — peer-gated `POSTGRES_SERVICE_ROLE_BIND_RPC`, `active_binding_for_purpose`, `bootstrap.bind_materialized_secret`, the sealed `active_password`/`write_init_script` superuser machinery — but **no writer**: `server.rs`'s dispatch_json arm answers `POSTGRES_SERVICE_ROLE_BIND_DENIED: unsupported in this slice` to the only peer allowed to call it (root backup-helper), and `LifecycleClient::bind_postgres_service_role` has no call sites.

## Consequence

Every Postgres credential draw in R6 is fail-closed dead on a real deployment, until lifecycle composition lands:

- `dispatch_b05_issue_migration_launch` requires `Purpose::PostgresMigration` binding → `central-migrate` can never launch (T1/T2 surface is fully ported but starved).
- `read_active_migration_passfile` (0xc2 kinds 1/4) → apply/resume restore and `backup import` cannot draw the migration credential (T3/T7/T12).
- `backup_worker_credential` (0xc1) → backup workers cannot draw the runtime credential (T5/T9).

`Purpose::PostgresOutbox` likewise has no writer. On a development instance without production service-role bindings this is invisible: the deferral only bites the production compose path.

## What a fix requires

Direction not yet chosen — carried to the lifecycle-composition slice. Two shapes:

1. **Full parity port (required eventually):** `dispatch_bind_postgres_service_role` → `bootstrap.bind_materialized_secret` (24h TTL) in the broker, `productionPostgresServiceRoleCredentialStore.Sync` in the helper composition, and a `postgresServiceRoleComposeRunner`-equivalent decorating `infra::lifecycle` `Topology::up` so Sync runs after Postgres health. This is architecture work — a new compose-runner decoration across `central-kernel`/adapter boundaries — which is precisely why it was not silently approximated here.
2. **Interim narrower path:** none proposed — any partial writer creates a binding topology divergent from upstream's exact sync semantics (SC-DEF-39 exists upstream because a partial write path once shipped).

Until either lands, the closed denial text `POSTGRES_SERVICE_ROLE_BIND_DENIED: unsupported in this slice` is the deliberate upstream-shaped refusal, and every dependent draw fails closed on `*_UNAVAILABLE`/`*_DENIED` — never silently.

## References

- Rust: `crates/adapters/central-adapter-linux/src/broker/server.rs` (`is_postgres_service_role_authority_purpose` arm, closed denial), `broker/lifecycle_client.rs` (`bind_postgres_service_role`, no callers), `broker/secret_bootstrap.rs` (`bind_materialized_secret`, read side only), `helper/pg_credentials.rs` (`active_password`/`write_init_script`, `#[allow(dead_code)]` awaiting the store port).
- Upstream: `internal/adapter/authority/broker/postgres_service_role_bind.go`, `cmd/central/postgres_service_role_credential.go`, `cmd/central/main.go:340-349` (compose decoration), `docs/internal/tasks/sc-def-39-*.md` (the upstream record this mirrors).
- `docs/adr/0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md` §D3 — the delegation rule this record satisfies.

## Resolution (lifecycle-composition slice, `45f3740`…`d07fd5b`)

Direction 1 — the full parity port — landed across five tasks, each through the implementer→reviewer→fix cycle:

- **LC-T1 `45f3740`/`0d3f09f`/`f54ece9`** — `dispatch_bind_postgres_service_role` in the broker: snake_case wire decode with Go `Unmarshal` absent/null semantics, raw-base64 value decode with zeroization, all three role-specific passfile validators (migration/runtime/outbox), root backup-helper peer gating, 24-hour binding TTL, upstream's exact denial ladder, and the `lifecycle_client` PascalCase→snake_case serializer fix.
- **LC-T2 `49b1240`/`0719b7b`** — the production Postgres service-role credential store over the existing superuser store: rotate-then-sync for all three roles (verify-then-`ALTER ROLE ... WITH LOGIN PASSWORD` via `pg_wire` `verify_as`/`alter_login`, closed role literals + constrained alphabet), atomic secret persistence with protected-dir fsync, and unconditional broker binding to renew the lease.
- **LC-T3 `aef73c3`/`26e4b87`** — `PostgresServiceRoleComposeRunner` decorator (Sync only when `postgres` is in the service set, after `up --wait` health), first-boot bootstrap decorator owning the init-script materialization, `LifecycleClient` trait impls (dead-owner verify, authorization+consume, service-role bind, B04 bootstrap), MinIO broker rendezvous over the trusted hardlink path.
- **LC-T4 `15c70fe`/`e31c887`/`d07fd5b`** — `helper_lifecycle_handler` composes the complete B03 chain (version-zero receipt, `CandidateStore` active-receipt reader, shared B01 evaluator, broker lifecycle client, both credential stores, decorated runner/bootstrap/rendezvous, per-request resolver, authorized handler) into `Server::lifecycle`, exiting 6 on refusal; rescue cleanup delegates `down` through the same handler as upstream's second ceremony; one shared confirmer across all handler slots.

`Purpose::PostgresMigration`/`PostgresRuntime`/`PostgresOutbox` bindings now establish during `local up` exactly as upstream; the closed denial remains only for a genuinely absent binding. Remaining boundaries are tracked in `current-phase.md`.
