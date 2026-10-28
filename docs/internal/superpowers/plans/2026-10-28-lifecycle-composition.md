# Plan — Lifecycle composition (post-R6 deferral closure)

Closes the `bind_postgres_service_role` + broker-backed lifecycle composition
boundary deferred past R0–R6 (recorded in
`docs/internal/tasks/r6-t16-postgres-service-role-bind-deferral.md` and
`docs/implementation/current-phase.md`). Upstream references:

- `internal/adapter/authority/broker/postgres_service_role_bind.go` (writer arm, ~92 lines)
- `cmd/central/postgres_service_role_credential.go` (store + syncer, ~216 lines)
- `cmd/central/postgres_service_role_compose_runner.go` (Up decorator, ~51 lines)
- `cmd/central/postgres_superuser_credential.go` tail (`postgresFirstBootBootstrap`, ~55 lines)
- `cmd/central/lifecycle_broker_rendezvous.go` (~43 lines)
- `cmd/central/main.go:330-360` (composition block)

Already ported machinery this consumes:

- `helper/pg_credentials.rs`: `ProductionPostgresSuperuserCredentialStore`
  (`ensure_first_boot_materialized`, `active_password`, `rotate_for_operation`,
  `write_init_script`) — `#[allow(dead_code)]` awaiting this slice.
- `helper/pg_wire.rs`: SCRAM `verify` + `alter` (central-user only; needs
  `verify_as`/`alter_login` variants).
- `helper/minio_provision.rs`: `ensure_backup_minio_broker_rendezvous` — the
  whole trust discipline the lifecycle rendezvous delegates to.
- `broker/lifecycle_client.rs`: `bind_postgres_service_role`,
  `verify_dead_owner`, `materialize_minio_root`, `adopt_b03_minio`,
  `issue_lifecycle_proof`, `authorize_bound_lifecycle`,
  `consume_bound_lifecycle_authorization` — all client methods exist,
  currently uncalled.
- `broker/secret_bootstrap.rs`: `bind_materialized_secret` (read side only).
- `infra/lifecycle.rs`: `new_production_service`, `DockerReceiptInspector`,
  `BrokerRendezvous` trait, `DeadOwnerVerifier` trait, `FileBootstrap`.
- `infra/compose.rs`: `CommandComposeRunner`.
- `infra/prepare`: `CandidateStore`, `ensure_version_zero_receipt`.
- `helper/daemon.rs`: `helper_advisory_evaluator`, `Server::lifecycle` field
  + `handle_lifecycle` dispatch (handler trait ported, slot unset).
- `helper/lifecycle.rs`: `ProductionLifecycleHandler` + `LifecycleRequestResolver`.

## Tasks

### LC-T1 — broker `bind_postgres_service_role` writer arm

Port `dispatchBindPostgresServiceRole` (`postgres_service_role_bind.go`) into
`broker/server.rs` replacing the `unsupported_in_this_slice` closed denial at
the existing peer-gated arm (`server.rs:~2538`, `isRootBackupHelperPeer` gate
already correct):

- Wire shape `{"request": {instance_id, purpose, value(b64)}}`.
- Purpose → validator map: `postgres_runtime_v1`/`postgres_migration_v1`/
  `postgres_outbox_v1` → `validate_central_{runtime,migration,outbox}_passfile`.
  Port `validate_central_outbox_passfile` (upstream
  `restore_migration_credential_linux.go:444`); runtime + migration validators
  already exist in `backup_worker_credential.rs`.
- base64 `RawStdEncoding` decode (no padding) → `zeroize` after use →
  purpose-keyed validation → `bind_materialized_secret` with `24h` TTL.
- Exact denial ladder: `empty payload` / `missing request field` /
  `invalid request` / `unsupported purpose` / `invalid value encoding` /
  `malformed value` / `unavailable` / `POSTGRES_SERVICE_ROLE_BIND_DENIED: {err}`.
- Keep purpose OUT of the closed `is_r6_purpose` set (connection-only RPC —
  `Dispatch` in-process stays `unknown purpose`, same as advisory append).
- Tests: full denial ladder + happy path asserting durable binding +
  wrong-peer gate + purpose classification.

### LC-T2 — `postgresServiceRoleCredentialStore` + pg_wire service-role syncer

Port `postgres_service_role_credential.go`:

- `pg_wire.rs`: `verify_as(role, password)` (connect as the named role, ping)
  and `alter_login(auth_password, role, new_password)`
  (`ALTER ROLE <role> WITH LOGIN PASSWORD '<p>'`) — role name is a closed
  literal, password alphabet closed by `valid_postgres_superuser_password`.
- `ProductionPostgresServiceRoleCredentialStore`: fixed ordered role set
  `postgres_migration_v1→central_migration`, `postgres_runtime_v1→central_runtime`,
  `postgres_outbox_v1→central_outbox`; protected dir
  `<protected>/<instance>/postgres-service-roles` (mode 0700, not symlink);
  `sync()` → per-role `sync_one` (read secret → verify → rotate on drift:
  mint → alter_login → write_secret) → passfile bytes
  `127.0.0.1:55432:central:<role>:<password>\n` → `broker.bind_postgres_service_role`.
- Error semantics: `sync` joins per-role errors (`errors.Join`), nil store/
  ctx refuses, superuser `active_password` failure propagates.

### LC-T3 — compose decorations + rendezvous + client trait impls

- `postgresServiceRoleComposeRunner` → `PostgresServiceRoleComposeRunner`:
  decorates `ComposeRunner::up` — on success AND postgres included in services
  (empty list = all) → `roles.sync()`. `compose_services_include` helper.
- `postgresFirstBootBootstrap` → decorate the lifecycle `Bootstrap` so
  `superuser.ensure_first_boot_materialized()` runs inside `materialize`
  before delegating to `FileBootstrap::materialize`. Add a `bootstrap`
  injection point to `ProductionServiceConfig` (upstream has
  `cfg.Bootstrap port.Bootstrap`; the Rust port folded `FileBootstrap`
  construction inside `new_production_service` — restore the config field,
  defaulting to the broker-backed `FileBootstrap`).
- `lifecycleBrokerRendezvous` → `LifecycleBrokerRendezvous` implementing
  `BrokerRendezvous` by delegating to `ensure_backup_minio_broker_rendezvous`
  (already ported).
- `LifecycleClient`: `impl DeadOwnerVerifier` (`verify_dead_owner`) and
  `impl B04Bootstrap` (`materialize_minio_root`/`adopt_b03_minio`/
  `issue_lifecycle_proof`).

### LC-T4 — helper daemon lifecycle composition

Wire `Server::lifecycle` in `helper/daemon.rs` (the documented gap at
`daemon.rs:935-953`):

1. `ensure_version_zero_receipt` on the dependency root (fail-fast like
   upstream `main.go`).
2. `receipts`: `CandidateStore` — add `impl ActiveReceiptReader` (read-only,
   no locker) if missing.
3. `evaluator`: `helper_advisory_evaluator` (exists).
4. `inspector`: `DockerReceiptInspector` with the docker binary path.
5. `runner`: `PostgresServiceRoleComposeRunner` over `CommandComposeRunner`.
6. `owner_verifier` + `b04_bootstrap`: `LifecycleClient` (impls from LC-T3).
7. `bootstrap`: `PostgresFirstBootBootstrap` over `FileBootstrap` +
   `ProductionPostgresSuperuserCredentialStore` (removes its `dead_code`).
8. `rendezvous`: `LifecycleBrokerRendezvous` over `broker_socket_path`.
9. Install `ProductionLifecycleHandler` (service + resolver + authorizer =
   `LifecycleClient`) into `Server::lifecycle`.
10. `run_lifecycle` (`local up|down|status`) now reaches a live handler —
    verify the CLI path end-to-end shape (root-gated e2e stays a reference-
    host step; unit-cover the composition).

### LC-T5 — closeout

- Update `docs/internal/tasks/r6-t16-postgres-service-role-bind-deferral.md`
  status → implemented (or supersede).
- Update `docs/implementation/current-phase.md` deferred-boundary list —
  remove `bind_postgres_service_role` + broker-backed lifecycle composition.
- Reports under `.superpowers/sdd/`; pipeline per §7.

## Wire/fail-closed rules

- Peer gate stays `isRootBackupHelperPeer` BEFORE body decode — no new peers.
- 24h TTL lease semantics verbatim; secret bytes zeroized, never in errors.
- `ALTER ROLE` statement literals only over closed alphabets.
- Sync runs strictly after postgres health (`up --wait` contract).
- No weakening of existing gates; no unrelated refactors.
