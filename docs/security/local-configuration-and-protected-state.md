# Local Configuration and Protected State

Design-only Gate 8 contract — commands are not currently available; Gate 9 slices return exit 5/UNSUPPORTED_IN_THIS_SLICE without mutation until implemented.

Every ADR-0009-dependent rule in this document (helper request, broker protocol, protected-state transition, PAM/TTY confirmation, TLS-signer, authoritative-config-path binding, and all authority-record envelopes) is documentary and becomes effective only when ADR 0009 is Accepted.

## 1. Authority and phase boundary

This document is the canonical configuration-and-protected-state contract for the Gate 8 local development environment. It consumes the approved [Gate 8 governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) and the [topology contract](../architecture/local-development-environment.md), through [ADR 0009](../adr/0009-adopt-local-development-environment-topology.md). Every table, field, type, constraint, command grammar, and closed matrix is normative and binding on Gate 9 implementation.

Gate 8 defines exact JSON schemas, field inventories, type systems, transition protocols, and closed state machines as normative Markdown. Gate 9 owns the executable slices that parse, validate, persist, and enforce them. Gate 10 owns the final Phase 0 closure audit.

## 2. Immutable startup configuration — `central.config/v1`

### 2.1 Source and discovery

The sole general startup source is one UTF-8 JSON document with top-level `schema_version` equal to `central.config/v1`. There is no `.env` file, environment-variable interpolation, per-field environment lookup, CLI topology override, implicit secret fallback, hot reload, or mutable global configuration.

**XDG discovery:** When `--config` is omitted, Central discovers an instance only when exactly one valid config exists beneath `$XDG_CONFIG_HOME/central/instances/<instance-id>/central.json`. If `$XDG_CONFIG_HOME` is unset, the fallback is `~/.config`. Zero matches is `CONFIG_NOT_FOUND`; two or more is `CONFIG_AMBIGUOUS`. Discovery is lockless; the signed view protects against stale reads.

**Configless init family:** Exactly four configless command families exist. `central local doctor --host-prerequisites` is read-only and instance-independent. The init family is: `central local init`, `central local init --status`, `central local init --resume=<init-operation-id>`, and `central local init --abandon=<init-operation-id>`. Every form rejects `--config`. All other configless invocations are invalid.

**Absolute `--config` path:** `central --config <absolute-path-to-central.json> ...` selects an existing document; it does not override any field and never names a prospective file. Successful `local init` prints the absolute config path only on the trusted local TTY plane. Its `central.local-result/v1` machine `details` variant returns only `instance_id`, `config_binding_id`, and `init_operation_id`; automation derives or discovers the path locally and no generic plane emits it.

**Implemented subset (install B1, 2026-09-30):** only the bare `central local init` is implemented. The root helper carries it out behind fresh PAM plus the console phrase `CONFIRM <code> init` at the operator's physical console (`physical_tty` only; grant-mode genesis waits for ADR 0037, Proposed). It refuses a host with less than 40 GiB free on the state filesystem (`CAPACITY_INSUFFICIENT` exit 4) and answers exit 0 `ALREADY_INITIALIZED` with the existing three IDs when an instance exists. It has no init journal: its accepted point is after the capacity check, under the genesis lock, with the host re-checked absent, and its commit point is the config rename. A failure between the two is exit 6 `MUTATION_FAILED`, with the paths to remove shown only at the physical console where the operator confirmed (never on the wire or in the helper's journal); a failure before the accepted point writes no instance and is exit 4 (capacity, lock timeout), 7 (ceremony refused) or 3 (helper unavailable, host not absent); a failure after the commit point is exit 6 with no path to remove, because the instance may exist. `--status`, `--resume` and `--abandon` answer exit 5 `UNSUPPORTED_IN_THIS_SLICE`. An unreachable helper, or a host holding partial state, is `HELPER_UNAVAILABLE` exit 3. See `docs/internal/tasks/install-b1-local-init-genesis-2026-09-30.md`.

**Canonicalization:** Parsing first rejects invalid UTF-8, duplicate/unknown keys, non-NFC strings, forbidden number forms, and trailing content. The normalized representation sorts every object key lexicographically, retains declared array order, emits integers in shortest decimal form, and otherwise uses RFC 8785 JSON Canonicalization Scheme.

**Safe configuration digest:** SHA-256 over the canonical encoding after replacing every `abspath` with its bound opaque root ID and omitting secret values, backend locators, and hidden nonces. The complete config digest uses the unredacted canonical document only inside protected state and is never logged or exported.

**Path binding:** Every config path must be an NFC-normalized absolute path with no `.`/`..`/symlink resolution ambiguity. Selection opens `/` as `O_PATH|O_DIRECTORY|O_CLOEXEC`, resolves each configured root component with `RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`, and records `statx` device, inode, mode, owner, link count, and `STATX_MNT_ID`. After a root descriptor is held, every descendant access uses `openat2` relative to it with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`. Roots and Workspace paths may not overlap by path or mount identity; root overlap is denial at parse time. The helper parses a single held `/proc/self/mountinfo` snapshot, rejects any nested mount below a payload root, and rejects FUSE, overlay, network, idmapped, shared-propagation, or unrecognized mount types/options for protected/payload state.

### 2.2 Schema rules

Type constraints: `uint` means a JSON integer in `[0, 2^53-1]`; durations use integer milliseconds and sizes use integer bytes. `uuid7` is canonical lowercase RFC 9562 UUIDv7. `binding` is an opaque canonical UUIDv7. `sha256` is 64 lowercase hexadecimal characters. `abspath` is an NFC-normalized absolute path. Arrays preserve order only where stated and contain no duplicate identity. "Fixed" means any other value is invalid, including a value otherwise inside the scalar type. Every listed object and field is required; no other field, `null`, floating-point number, or omitted object is accepted.

### 2.3 Complete field inventory

The `provider` object below is retained only as a compatibility-shaped signed
configuration projection for existing persisted views. It is not current
Central-owned routing or credential authority. Active B09 dispatch is governed
by authenticated opaque agent dispatch, grant, and egress evidence; an
external agent adapter owns provider selection, URLs, model configuration, and
credentials. Legacy provider fields may be empty or historical opaque values
and must never be used as admission gates.

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `schema_version` | string | fixed `central.config/v1` |
| `instance_id` | uuid7 | generated once; must match all bindings |
| `paths.authoritative_state_root` | abspath | fixed root-parented instance authority; root parent, locked-runtime instance owner |
| `paths.instance_data_root` | abspath | fixed `data/` descendant of authoritative state; descriptor-bound only |
| `paths.backup_repository_root` | abspath | fixed `backups/` sibling of data; descriptor-bound only |
| `paths.workspace_roots` | array | 0–32 entries, sorted by `root_id` |
| `paths.workspace_roots[].root_id` | uuid7 | unique opaque identity |
| `paths.workspace_roots[].path` | abspath | unique, non-overlapping governed Workspace root |

| JSON path | Type | Installed value | Hard constraint |
| --- | --- | ---: | --- |
| `http.application.host` | string | `127.0.0.1` | fixed |
| `http.application.port` | uint | `8080` | 1024–65535; tests may allocate another exact port |
| `http.operations.host` | string | `127.0.0.1` | fixed |
| `http.operations.port` | uint | `9090` | 1024–65535 and distinct from every other host port |
| `http.tls.binding_id` | binding | generated | purpose must be `application_tls_v1` |
| `http.tls.ca_fingerprint_sha256` | sha256 | generated | exact active CA generation |
| `http.tls.leaf_fingerprint_sha256` | sha256 | generated | exact active leaf generation |
| `http.non_streaming.active` | uint | `16` | 1–32 |
| `http.non_streaming.waiters` | uint | `32` | 0–64 |
| `http.non_streaming.admission_wait_ms` | uint | `2000` | 1–5000 and no later than route deadline |
| `http.non_streaming.api_buffer_bytes` | uint | `2097152` | fixed inherited maximum |
| `http.non_streaming.html_buffer_bytes` | uint | `1048576` | 1–2097152 |
| `http.non_streaming.body_read_ms` | uint | `30000` | 1000–120000 |
| `http.non_streaming.response_write_ms` | uint | `30000` | 1000–120000 |
| `http.non_streaming.route_total_ms` | uint | `65000` | 1000–120000 and at least admission + body-read + response-write |
| `http.max_header_bytes` | uint | `32768` | 4096–65536 |
| `http.max_header_value_bytes` | uint | `4096` | fixed inherited maximum; not above aggregate header bytes |
| `http.read_header_ms` | uint | `5000` | 1000–10000 |
| `http.idle_ms` | uint | `60000` | 1000–120000 |
| `http.graceful_shutdown_ms` | uint | `45000` | 30000–180000 and equals runtime total shutdown |

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `postgres.host` / `postgres.port` | string / uint | fixed `127.0.0.1` / installed `55432`, port 1024–65535 and globally distinct |
| `postgres.database` / `postgres.schema` | string | fixed `central` / `central` |
| `postgres.bindings.server_admin` | binding | purpose `postgres_server_admin_v1` |
| `postgres.bindings.runtime` | binding | purpose `postgres_runtime_v1` |
| `postgres.bindings.outbox` | binding | purpose `postgres_outbox_v1` |
| `postgres.bindings.migration` | binding | purpose `postgres_migration_v1` |
| `postgres.pools.runtime_general` | uint | installed `6`, range 1–8 |
| `postgres.pools.runtime_settlement` | uint | fixed `2` and never borrowable |
| `postgres.pools.outbox` | uint | installed `3`, range 1–4 |
| `postgres.pools.cleanup` | uint | installed `1`, range 1–2 |
| `postgres.pools.serve_lock_control` | uint | fixed `1` |
| `postgres.pools.coexisting_read_only` | uint | installed `2`, range 0–4 |
| `postgres.pools.offline_mutation` | uint | fixed `2`; every tool session consumes one permit |
| `postgres.timeouts.pool_acquire_ms` | uint | installed `2000`, range 1–5000 |
| `postgres.timeouts.statement_ms` | uint | installed `30000`, range 1000–120000 |
| `postgres.timeouts.lock_ms` | uint | installed `5000`, range 100–30000 and not above statement timeout |
| `postgres.timeouts.transaction_ms` | uint | installed `30000`, range 1000–120000 and not below statement timeout |
| `postgres.timeouts.idle_in_transaction_ms` | uint | installed `30000`, range 1000–60000 |
| `postgres.timeouts.connection_lifetime_ms` | uint | installed `1800000`, range 60000–3600000 |

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `object_store.scheme` / `object_store.host` / `object_store.port` | string/string/uint | fixed `http` / `127.0.0.1` / installed `59000`, port 1024–65535 and globally distinct |
| `object_store.bucket` / `object_store.region` / `object_store.path_style` | string/string/boolean | fixed `central-artifacts-v1` / `us-east-1` / `true` |
| `object_store.bindings.root` | binding | purpose `minio_root_v1` |
| `object_store.bindings.runtime` | binding | purpose `minio_runtime_v1` |
| `object_store.bindings.backup` | binding | purpose `minio_backup_v1` |
| `object_store.bindings.restore` | binding | purpose `minio_restore_v1` |
| `object_store.policy_digests.runtime` | sha256 | fixed `b4613cce4c0fe3e7b23cc7212d578919169cb1d64aab9c5b73fc544cf759d72f` |
| `object_store.policy_digests.backup` | sha256 | fixed `aa5f63fdf5b13e4bc2effd1a972a7c2ed6771faee3b56bc2fca7d822ad7d38b1` (SHA-256 of the generated canonical `minio_backup_v1` policy) |
| `object_store.policy_digests.restore` | sha256 | fixed `79ec56cee096807d98ca968500e2b5bd16ac948c008a2c83ab5cbfc5e338e6dc` |
| `protected_store.backend` | string | fixed `protected_file_v1` |
| `protected_store.binding_root_id` | binding | exact protected-state binding |
| `protected_store.max_secret_bytes` | uint | fixed `65536` |
| `protected_store.resolve_ms` | uint | installed `5000`, range 1–10000 |
| `protected_store.candidate_cleanup_age_ms` | uint | installed `86400000`, range 3600000–604800000 |
| `protected_store.retired_cleanup_age_ms` | uint | installed `604800000`, range 86400000–2592000000 and greater than candidate cleanup age |
| `bootstrap_session.binding_id` | binding | purpose `bootstrap_v1` |
| `bootstrap_session.token_bits` | uint | fixed `256` |
| `bootstrap_session.presentation_ms` | uint | installed `180000`, range 60000–300000; one reveal/exchange generation |
| `bootstrap_session.throttle_failures` | uint | installed `5`, range 3–10 |
| `bootstrap_session.throttle_window_ms` | uint | installed `60000`, range 10000–300000 |
| `bootstrap_session.first_use_ms` | uint | installed `60000`, range 1000–300000 |
| `bootstrap_session.idle_ms` | uint | installed `1800000`, range 60000–1800000 |
| `bootstrap_session.absolute_ms` | uint | installed `43200000`, range 1800000–43200000 and greater than idle |

| JSON path | Type | Installed value | Hard constraint |
| --- | --- | --- | --- |
| `provider` | object | required | compatibility-shaped signed policy fields and bounded budgets |
| `provider.provider` | string | opaque agent identity | non-empty compatibility value; non-authoritative |
| `provider.model` | string | opaque agent model identity | non-empty compatibility value; non-authoritative |
| `provider.destination` | string | opaque agent dispatch metadata | non-empty compatibility value; non-authoritative |
| `provider.method` | string | opaque dispatch metadata | non-empty compatibility value; non-authoritative |
| `provider.path` | string | opaque dispatch metadata | non-empty compatibility value; non-authoritative |
| `provider.policy_revision` | string | installed non-empty revision | non-empty |
| `provider.tool_revision` | string | installed non-empty revision | non-empty |
| `provider.price_data_revision` | string | installed non-empty revision | non-empty |
| `provider.secret_ref` | string | empty or legacy opaque value | compatibility-only; never an active Central credential selector |
| `provider.purpose` | string | empty or legacy opaque value | compatibility-only; never an active Central authority value |
| `provider.protected_paths` | string array | installed | sorted, unique canonical paths |
| `provider.default_budget` | object | required | all eight nested budgets are required, positive, and bounded |
| `provider.default_budget.request_bytes` | uint | positive | greater than zero |
| `provider.default_budget.response_bytes` | uint | positive | greater than zero |
| `provider.default_budget.input_tokens` | uint | positive | at most 2000000 |
| `provider.default_budget.output_tokens` | uint | positive | at most 200000 |
| `provider.default_budget.tool_calls_per_step` | uint | positive | at most 20 |
| `provider.default_budget.tool_calls_per_run` | uint | positive | at most 100 and no smaller than per-step limit |
| `provider.default_budget.wall_time_seconds` | uint | positive | at most 86400 |
| `provider.default_budget.spend_micros` | uint | positive | greater than zero |
| `provider.hard_budget` | object | required | all eight nested budgets are required and no smaller than defaults |
| `provider.hard_budget.request_bytes` | uint | no smaller than default | greater than or equal to `provider.default_budget.request_bytes` |
| `provider.hard_budget.response_bytes` | uint | no smaller than default | greater than or equal to `provider.default_budget.response_bytes` |
| `provider.hard_budget.input_tokens` | uint | no smaller than default | greater than or equal to `provider.default_budget.input_tokens` |
| `provider.hard_budget.output_tokens` | uint | no smaller than default | greater than or equal to `provider.default_budget.output_tokens` |
| `provider.hard_budget.tool_calls_per_step` | uint | no smaller than default | greater than or equal to `provider.default_budget.tool_calls_per_step` |
| `provider.hard_budget.tool_calls_per_run` | uint | no smaller than default | greater than or equal to `provider.default_budget.tool_calls_per_run` |
| `provider.hard_budget.wall_time_seconds` | uint | no smaller than default | greater than or equal to `provider.default_budget.wall_time_seconds` |
| `provider.hard_budget.spend_micros` | uint | no smaller than default | greater than or equal to `provider.default_budget.spend_micros` |
| `provider.input_token_price_micros` | uint | positive | at most 1000000; signed rate per input token |
| `provider.output_token_price_micros` | uint | positive | at most 1000000; signed rate per output token |
| `provider.local_grant_ttl_seconds` | uint | positive | at most 86400; local signed-grant lifetime |
| `provider.signature` | string | lowercase SHA-256 hex | exactly `CanonicalDigest()`; launcher-only |

The required compatibility profile is exactly one provider-shaped object,
occurring exactly once, and remains the sole policy projection in
`central.config/v1`. Its listed members are the complete closed schema; no
invented or extra provider or budget field is permitted. The `default_budget`
and `hard_budget` objects each contain exactly the eight listed budget leaves
and no others. The route-shaped and secret-shaped members are not active
bindings:

```text
provider             = opaque agent identity
model                = opaque agent model identity
destination          = opaque agent dispatch metadata
method               = opaque dispatch metadata
path                 = opaque dispatch metadata
secret_ref           = empty or legacy opaque value
purpose              = empty or legacy opaque value
```

Revision strings are non-empty. `protected_paths` is canonical, sorted, unique,
and component-wise non-overlapping. Each entry is either an NFC-normalized
absolute host path (clean, with no `.`/`..`, repeated separator, or trailing
separator except `/`), a single lower-case relative segment, or a lower-case
NFC-normalized clean rooted Workspace-relative path. Relative entries have no
trailing separator; a single segment overlaps any rooted entry containing that
segment, and rooted/absolute entries overlap on equality or complete
component-prefix. Such aliases and overlaps are rejected rather than silently
deduplicated. Default request, response, and spend budgets are positive; each hard
budget is greater than or equal to its matching default. `signature ==
CanonicalDigest()`, where the digest is lowercase SHA-256 hex over
`central.provider-profile/v1\x00 || JCS(providerProfileUnsigned)`. The unsigned
object contains every provider-profile field except `signature`.

The compatibility projection is exactly:

```text
Compatibility-visible fields: provider, model, destination, method, path,
policy_revision, tool_revision, price_data_revision, protected_paths,
default_budget, hard_budget.
Compatibility-only fields: secret_ref, purpose, signature. None is an active
Central-owned provider credential or routing requirement.
```

B07 persists only `policy_revision`. B09 does not receive provider
SecretReference authority from Central configuration or runtime snapshots.
Opaque agent dispatch, grant, and egress evidence is the active authority;
provider credential resolution, if needed by an adapter, remains outside
Central's B09 contract.

The former OpenAI-specific profile and transport documents are retained only as
superseded historical evidence. In particular, the 2026-07-29 OpenAI Responses
design and its implementation plan no longer define the active configuration,
admission, or report-retrieval boundary.

| JSON path | Type | Installed value | Hard constraint |
| --- | --- | ---: | --- |
| `artifact.active_transfers` | uint | `2` | 1–8 |
| `artifact.waiters` | uint | `8` | 0–32 |
| `artifact.admission_wait_ms` | uint | `5000` | 1–30000 and not beyond operation deadline |
| `artifact.copy_buffer_bytes` | uint | `262144` | 65536–1048576 |
| `artifact.stream_idle_ms` | uint | `30000` | 1000–120000 |
| `artifact.stream_total_ms` | uint | `1800000` | 60000–7200000 and greater than idle |
| `operator_modes.backup_elapsed_ms` | uint | `7200000` | 60000–28800000 |
| `operator_modes.restore_ticket_ms` | uint | `900000` | 60000–3600000 |
| `operator_modes.restore_elapsed_ms` | uint | `14400000` | fixed 4-hour accepted-operation deadline |
| `operator_modes.prepare_elapsed_ms` | uint | `1200000` | fixed 20-minute complete prepare deadline |
| `operator_modes.export_elapsed_ms` | uint | `7200000` | fixed 2-hour export deadline |
| `operator_modes.import_elapsed_ms` | uint | `7200000` | fixed 2-hour import deadline |
| `operator_modes.maintenance_elapsed_ms` | uint | `7200000` | fixed 2-hour accepted apply deadline |
| `operator_modes.browser_clear_elapsed_ms` | uint | `300000` | fixed five-minute accepted clear deadline |
| `operator_modes.browser_profile_bytes` | uint | `1073741824` | fixed ext4 project hard quota |
| `operator_modes.browser_profile_inodes` | uint | `50000` | fixed ext4 project inode hard quota |
| `operator_modes.browser_disk_cache_bytes` | uint | `268435456` | fixed cache ceiling; media cache disabled |
| `operator_modes.security_rescue_elapsed_ms` | uint | `14400000` | fixed four-hour hard-expired rescue deadline |
| `operator_modes.inventory_workers` | uint | `1` | 1–2 |
| `operator_modes.inventory_spool_bytes_per_worker` | uint | `8388608` | fixed maximum per worker |
| `operator_modes.inventory_chunk_records` | uint | `1000` | 1–1000 |
| `operator_modes.inventory_record_bytes` | uint | `4096` | fixed maximum encoded record |
| `operator_modes.inventory_slice_pages` | uint | `100` | 1–1000 |
| `operator_modes.inventory_slice_ms` | uint | `300000` | 1000–1800000 |
| `operator_modes.target_lock_ms` | uint | `30000` | 1–300000 |
| `operator_modes.migration_lock_ms` | uint | `15000` | 1–60000 |
| `operator_modes.total_lock_ms` | uint | `45000` | 1–360000 and at least each component lock |
| `operator_modes.capacity_survival_reserve_bytes` | uint | `4294967296` | fixed per writable device |
| `operator_modes.capacity_free_floor_bytes` | uint | `1073741824` | fixed, excludes allocated reserve |
| `operator_modes.capacity_write_quantum_bytes` | uint | `8388608` | fixed maximum between checks |
| `operator_modes.capacity_poll_ms` | uint | `1000` | fixed maximum restore polling interval |
| `operator_modes.body_transfer_workers` | uint | `1` | fixed installation-wide backup/restore worker |
| `operator_modes.body_copy_buffer_bytes` | uint | `262144` | fixed reusable streaming/checksum buffer |
| `operator_modes.multipart_part_bytes` | uint | `16777216` | fixed part size; one resident part and upload |
| `operator_modes.body_attempts` | uint | `3` | fixed total attempts including first |
| `operator_modes.body_idle_ms` | uint | `30000` | 1000–120000 |
| `operator_modes.body_total_ms` | uint | `1800000` | 60000–7200000, above idle and within operation remainder |
| `operator_modes.backup_reference_database_bytes` | uint | `5368709120` | fixed 5-GiB supported-profile ceiling |
| `operator_modes.backup_reference_object_bytes` | uint | `10737418240` | fixed inherited 10-GiB ceiling |
| `operator_modes.backup_reference_records` | uint | `10000` | fixed supported-profile ceiling |
| `operator_modes.backup_min_throughput_bytes_per_second` | uint | `16777216` | fixed 16 MiB/s for both measured paths |
| `operator_modes.backup_probe_bytes` | uint | `536870912` | fixed 512 MiB per measured path |
| `operator_modes.backup_probe_elapsed_ms` | uint | `300000` | fixed five-minute complete fixture/probe/cleanup parent |
| `operator_modes.backup_probe_max_age_ms` | uint | `604800000` | fixed seven days |
| `operator_modes.backup_admission_deadline_fraction_per_mille` | uint | `750` | fixed 75% of operation deadline |

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `tools.pg_dump.path` / `tools.pg_restore.path` | abspath | root-owned executable, not writable by operator |
| `tools.pg_dump.version` / `tools.pg_restore.version` | string | fixed `16.14` |
| `runtime.preflight_ms` | uint | installed `5000`, range 1–10000 |
| `runtime.preflight_page` | uint | installed `100`, range 1–1000 |
| `runtime.startup_dependency_ms` | uint | installed `30000`, range 1000–60000 |
| `runtime.dependency_retry_ms` | uint | installed `60000`, range 0–300000 |
| `runtime.retry_initial_ms` / `runtime.retry_max_ms` | uint | fixed `250` / installed `5000` (range 250–10000), initial not above max |
| `runtime.health_interval_ms` / `runtime.health_timeout_ms` | uint | installed `5000` / `2000`; interval 1000–30000, timeout 100–5000 and below interval |
| `runtime.go_memory_limit_bytes` | uint | fixed `671088640` (640 MiB) |
| `runtime.central_rss_ceiling_bytes` | uint | fixed `805306368` (768 MiB) |
| `runtime.operator_tool_rss_ceiling_bytes` | uint | fixed `536870912` (512 MiB) |
| `runtime.host_memory_reserve_bytes` | uint | fixed `2147483648` (2 GiB) |
| `runtime.host_memory_headroom_bytes` | uint | fixed `536870912` (512 MiB) |
| `runtime.settlement_ms` | uint | installed `30000`, range 1000–120000 |
| `runtime.total_shutdown_ms` | uint | installed `45000`, range 30000–180000 and not below settlement |
| `runtime.enabled_components` | string array | fixed sorted set `artifact_reconciliation`, `cleanup`, `execution`, `http`, `outbox`, `session_recovery`, `task_reconciliation` |
| `observability.log_format` / `observability.log_level` | string | fixed `json` / `info` |
| `observability.metric_registry` | string | fixed `central_custom_v1` |

### 2.4 Installed Gate 7 resource values (cross-field validation reference)

| Resource | Installed value |
| --- | ---: |
| Artifact active transfers | 2 |
| Artifact waiters | 8 |
| Artifact admission wait | 5 s |
| Artifact copy buffer | 256 KiB |
| Artifact stream idle / total | 30 s / 30 min |
| Non-streaming HTTP active / waiters | 16 / 32 |
| Non-streaming admission wait | 2 s |
| JSON / HTML response buffer | 2 MiB / 1 MiB |
| Aggregate response buffers | 32 MiB |
| HTTP header bytes / one value | 32 KiB / 4 KiB |
| Header-read / idle timeout | 5 s / 60 s |
| Runtime-general pool | 6 |
| Runtime-settlement pool | 2, never borrowable |
| Outbox pool | 3 |
| Cleanup pool | 1 |
| Serving shared-lock control | 1 |
| Coexisting read-only operator connections | 2 |
| Offline mutation connections | 2 |
| Pool acquisition | 2 s |
| Ordinary preflight | 5 s, page 100 |
| Inventory workers / spool | 1 / 8 MiB |
| Inventory chunk / encoded record | 1,000 / 4 KiB |
| Inventory work slice | 100 pages or 5 min |
| Settlement grace / total shutdown | 30 s / 45 s |

### 2.5 Cross-field constraints

Every cross-field violation is `CONFIG_INVALID` before adapter, listener, helper, Docker, database, or object-store mutation:

- Active non-streaming buffers must not exceed 32 MiB (api) or 64 MiB (aggregate).
- Artifact active × copy buffer must not exceed 8 MiB.
- Inventory workers × spool must not exceed 16 MiB.
- Serving data pools total exactly 12. Serving + control + coexisting readers must not exceed installed 16. No permitted combination may exceed hard 24.
- Offline mutation is available only after serving pools drain.
- Every port is distinct across all listeners.
- Roots and Workspace paths do not overlap by path or mount identity.
- Every binding purpose is unique and matches its field.
- TLS fingerprints match one active generation.
- Every nested deadline fits within its parent operation/authority deadline.
- Every permitted profile's aggregate memory ceiling + host headroom must fit the detected 8-GiB-or-larger host.
- Backup/restore body workers remain one with at most one 16-MiB multipart part + one 256-KiB copy buffer.

### 2.6 Complete normative JSON example

Identities and fingerprints are synthetic; they are never installation defaults.

```json
{"artifact":{"active_transfers":2,"admission_wait_ms":5000,"copy_buffer_bytes":262144,"stream_idle_ms":30000,"stream_total_ms":1800000,"waiters":8},"bootstrap_session":{"absolute_ms":43200000,"binding_id":"019b0000-0000-7000-8000-00000000000c","first_use_ms":60000,"idle_ms":1800000,"presentation_ms":180000,"throttle_failures":5,"throttle_window_ms":60000,"token_bits":256},"http":{"application":{"host":"127.0.0.1","port":8080},"graceful_shutdown_ms":45000,"idle_ms":60000,"max_header_bytes":32768,"max_header_value_bytes":4096,"non_streaming":{"active":16,"admission_wait_ms":2000,"api_buffer_bytes":2097152,"body_read_ms":30000,"html_buffer_bytes":1048576,"response_write_ms":30000,"route_total_ms":65000,"waiters":32},"operations":{"host":"127.0.0.1","port":9090},"read_header_ms":5000,"tls":{"binding_id":"019b0000-0000-7000-8000-000000000002","ca_fingerprint_sha256":"1111111111111111111111111111111111111111111111111111111111111111","leaf_fingerprint_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}},"instance_id":"019b0000-0000-7000-8000-000000000001","object_store":{"bindings":{"backup":"019b0000-0000-7000-8000-000000000009","restore":"019b0000-0000-7000-8000-00000000000a","root":"019b0000-0000-7000-8000-000000000007","runtime":"019b0000-0000-7000-8000-000000000008"},"bucket":"central-artifacts-v1","host":"127.0.0.1","path_style":true,"policy_digests":{"backup":"aa5f63fdf5b13e4bc2effd1a972a7c2ed6771faee3b56bc2fca7d822ad7d38b1","restore":"79ec56cee096807d98ca968500e2b5bd16ac948c008a2c83ab5cbfc5e338e6dc","runtime":"b4613cce4c0fe3e7b23cc7212d578919169cb1d64aab9c5b73fc544cf759d72f"},"port":59000,"region":"us-east-1","scheme":"http"},"observability":{"log_format":"json","log_level":"info","metric_registry":"central_custom_v1"},"operator_modes":{"backup_admission_deadline_fraction_per_mille":750,"backup_elapsed_ms":7200000,"backup_min_throughput_bytes_per_second":16777216,"backup_probe_bytes":536870912,"backup_probe_elapsed_ms":300000,"backup_probe_max_age_ms":604800000,"backup_reference_database_bytes":5368709120,"backup_reference_object_bytes":10737418240,"backup_reference_records":10000,"body_attempts":3,"body_copy_buffer_bytes":262144,"body_idle_ms":30000,"body_total_ms":1800000,"body_transfer_workers":1,"browser_clear_elapsed_ms":300000,"browser_disk_cache_bytes":268435456,"browser_profile_bytes":1073741824,"browser_profile_inodes":50000,"capacity_free_floor_bytes":1073741824,"capacity_poll_ms":1000,"capacity_survival_reserve_bytes":4294967296,"capacity_write_quantum_bytes":8388608,"export_elapsed_ms":7200000,"import_elapsed_ms":7200000,"inventory_chunk_records":1000,"inventory_record_bytes":4096,"inventory_slice_ms":300000,"inventory_slice_pages":100,"inventory_spool_bytes_per_worker":8388608,"inventory_workers":1,"maintenance_elapsed_ms":7200000,"migration_lock_ms":15000,"multipart_part_bytes":16777216,"prepare_elapsed_ms":1200000,"restore_elapsed_ms":14400000,"restore_ticket_ms":900000,"security_rescue_elapsed_ms":14400000,"target_lock_ms":30000,"total_lock_ms":45000},"paths":{"authoritative_state_root":"/var/lib/central-state/v1/instances/019b0000-0000-7000-8000-000000000001","backup_repository_root":"/var/lib/central-state/v1/instances/019b0000-0000-7000-8000-000000000001/backups","instance_data_root":"/var/lib/central-state/v1/instances/019b0000-0000-7000-8000-000000000001/data","workspace_roots":[]},"postgres":{"bindings":{"migration":"019b0000-0000-7000-8000-000000000006","outbox":"019b0000-0000-7000-8000-000000000005","runtime":"019b0000-0000-7000-8000-000000000004","server_admin":"019b0000-0000-7000-8000-000000000003"},"database":"central","host":"127.0.0.1","pools":{"cleanup":1,"coexisting_read_only":2,"offline_mutation":2,"outbox":3,"runtime_general":6,"runtime_settlement":2,"serve_lock_control":1},"port":55432,"schema":"central","timeouts":{"connection_lifetime_ms":1800000,"idle_in_transaction_ms":30000,"lock_ms":5000,"pool_acquire_ms":2000,"statement_ms":30000,"transaction_ms":30000}},"protected_store":{"backend":"protected_file_v1","binding_root_id":"019b0000-0000-7000-8000-00000000000b","candidate_cleanup_age_ms":86400000,"max_secret_bytes":65536,"resolve_ms":5000,"retired_cleanup_age_ms":604800000},"provider":{"default_budget":{"request_bytes":1048576,"response_bytes":4194304,"spend_micros":5000000},"destination":"https://api.openai.com:443/v1/responses","hard_budget":{"request_bytes":4194304,"response_bytes":8388608,"spend_micros":25000000},"method":"POST","model":"gpt-5.6","path":"/v1/responses","policy_revision":"policy-1","price_data_revision":"prices-1","protected_paths":[],"provider":"openai-responses","purpose":"provider_api_key_v1","secret_ref":"openai_api_key","signature":"3fa549930cad7f6ec75a741b53b63037b09a1466b1dd07b077c05f208de355fe","tool_revision":"tool-1"},"runtime":{"central_rss_ceiling_bytes":805306368,"dependency_retry_ms":60000,"enabled_components":["artifact_reconciliation","cleanup","execution","http","outbox","session_recovery","task_reconciliation"],"go_memory_limit_bytes":671088640,"health_interval_ms":5000,"health_timeout_ms":2000,"host_memory_headroom_bytes":536870912,"host_memory_reserve_bytes":2147483648,"operator_tool_rss_ceiling_bytes":536870912,"preflight_ms":5000,"preflight_page":100,"retry_initial_ms":250,"retry_max_ms":5000,"settlement_ms":30000,"startup_dependency_ms":30000,"total_shutdown_ms":45000},"schema_version":"central.config/v1","tools":{"pg_dump":{"path":"/usr/lib/postgresql/16/bin/pg_dump","version":"16.14"},"pg_restore":{"path":"/usr/lib/postgresql/16/bin/pg_restore","version":"16.14"}}}
```

## 3. Filesystem instance layout and bindings

### 3.1 Canonical layout

For instance UUIDv7 `<instance-id>`, XDG contains only non-authoritative operator views while all mutable authority lives below root-owned parents:

**XDG operator views (operator-owned, non-authoritative):**

```text
$XDG_CONFIG_HOME/central/instances/<instance-id>/
├── central.json                         # safe selection view, not authority
└── central.json.sig                     # broker Ed25519 signature binding view bytes to authority ID

$XDG_STATE_HOME/central/instances/<instance-id>/
├── generated/
│   ├── compose.override.yaml
│   └── compose.digest
└── views/<view-generation>.{json,sig}   # broker-signed sanitized snapshots only

$XDG_DATA_HOME/central/instances/<instance-id>/
└── views/<view-generation>.{json,sig}   # optional rebuildable safe inventory only
```

**Authoritative state (`/var/lib/central-state/v1`, root-owned `0700`, instance owned by `central-runtime`):**

```text
/var/lib/central-state/v1/instances/<instance-id>/
├── config.json
├── binding.json
├── authority-records/<stream-id>/<sequence>-<transition-id>.{payload,auth}.json
├── lifecycle.lock
├── runtime.lock
├── init-bootstrap.json
├── operations/
│   ├── target.json
│   ├── migration/<operation-id>.json
│   ├── backup/<operation-id>.json
│   ├── restore/<operation-id>.json
│   ├── wipe/<operation-id>.json
│   ├── dependency-upgrade/<operation-id>.json
│   └── maintenance/<operation-id>.json
├── payload-epochs/{active.json,generations/<payload-epoch-id>.json}
├── receipts/{history/<payload-epoch-id>/,prepare.json,trust.json,wipe.json,postgres-fs-init.json,minio-fs-init.json,postgres-provision.json,minio-provision.json}
├── audit/<audit-sequence>.json
├── data/{binding.json,postgres/,minio/}
└── backups/
    ├── binding.json
    ├── backup-repository.lock
    ├── repository-manifest.json
    ├── imports/<operation-id>.json
    ├── exports/<operation-id>.json
    ├── maintenance/<plan-id>.json
    └── backups/<backup-id>/
        ├── binding.json
        ├── database/central.dump
        ├── inventory/<chunk-ordinal>.json
        ├── bodies/sha256/<first-two-hex>/<remaining-hex>
        ├── root-manifest.json
        └── root-manifest.auth.json
```

**Protected state (`/var/lib/central-protected/v1`, root-owned `0700`):**

```text
/var/lib/central-protected/v1/instances/<instance-id>/
├── binding.json
├── fingerprint-keys/<key-version>.key
├── authority/
│   ├── keys/<key-version>.key
│   ├── view-signing/<key-id>.{key,pub}
│   └── journals/<stream-id>/<sequence>/<transition-id>/{prepared,issued,committed}.json
├── secrets/<binding-id>/
│   ├── binding.json
│   ├── binding.lock
│   ├── active.json
│   ├── candidates/<candidate-id>/<phase>.json
│   └── generations/<opaque-generation>.{meta.json,value}
├── bootstrap/
│   ├── binding.json
│   ├── binding.lock
│   ├── active.json
│   ├── presentation.json
│   ├── candidates/<candidate-id>/<phase>.json
│   └── generations/<opaque-generation>.{meta.json,value}
└── tls/
    ├── binding.json
    ├── binding.lock
    ├── active.json
    ├── candidates/<candidate-id>/<phase>.json
    ├── ca/<opaque-generation>.{cert,key}
    └── leaf/<opaque-generation>.{cert,key}
```

**Rescue scratch (root-owned `0700`, non-searchable by operator/runtime/agent/browser):**

```text
/var/lib/central-rescue/v1/instances/<instance-id>/<rescue-operation-id>/
├── binding.json
├── cleanup.json
├── postgres/
└── minio/
```

### 3.2 Projection behavior

Every generic authoritative transition is stored under the immutable sequence-specific `authority-records` path. The tree's fixed names (`config.json`, `active.json`, receipt names, operation names) are replaceable materialized projections only. Each projection has an elided `<name>.projection-auth.json` containing the exact committed stream/sequence/payload/envelope digests. A projection is never read as authority unless both files equal the broker journal's current committed stream head, and it can always be reconstructed from that head; a crash between their replacements merely leaves a stale projection.

### 3.3 Bindings

Each root has a versioned binding containing purpose, instance ID, creation nonce, canonical device/inode evidence, and a digest of the safe immutable fields. The configuration, state, data, and backup bindings are distinct and cross-reference only opaque binding IDs. A binding never contains a credential, raw Workspace path in a safe digest, or backend secret locator.

`payload-epochs/active.json` selects one create-only UUIDv7 generation. Every fs-init, provision, successful-up, migration/schema, restore/security-barrier, backup-throughput, dependency-upgrade, and target-mutating operation/receipt binds that exact payload epoch. Trust, TLS, prerequisite, dependency preparation, signed advisory, sealed-backup content, export/import lineage, and operator audit do not become invalid merely because payload was wiped. An epoch mismatch is never repairable by copying or editing a receipt; it is historical evidence only.

### 3.4 XDG views and signatures

XDG view roots belong to the operator UID but contain no authoritative mutable evidence; view directories are `0700` and files `0600`. `central.json` remains the complete strict schema but is a readable copy; its adjacent `central.view-signature/v1` Ed25519 signature binds exact bytes, config binding ID, authoritative config digest, instance ID, view generation, signing-key ID, and creation time. Snapshot readers verify it with the root-installed public key (`/usr/share/central/authority/v1/view-signing.pub`) and report its age without contacting privileged services.

A mutating helper additionally resolves that binding to `/var/lib/central-state/v1/instances/<instance-id>/config.json`, asks the broker to verify the signed binding, and then requires byte equality with authoritative config before use. Changed/deleted/forged view or signature is `CONFIG_INVALID`; no command adopts view bytes as authority.

Unprivileged `local status` and `local security status` read only broker-signed XDG safe views and loopback health, report `privileged_inspection=not_performed` plus snapshot generation/age, and never contact Docker, helper, or broker.

## 4. Protected local stores — `protected_file_v1`

### 4.1 Binding model

`protected_file_v1` maps an opaque binding ID to exactly one local directory under the protected state root. Immutable `binding.json` records schema `central.protected-binding/v1`, binding ID, purpose, allowed adapter/target class, owning Workspace when applicable, creation time, and creation nonce. Mutable status and active generation never appear in that immutable binding. `binding.lock` is a never-deleted advisory-lock inode; every stage/register/activate/revoke/retire/cleanup path holds it exclusively from initial revalidation through its last directory synchronization. Resolution holds it shared only through opening and validating the exact value descriptor, then releases it before adapter I/O.

### 4.2 Generation phases

Generation values and phase records are create-only. Canonical JSON phase files use these complete schemas:

| Record | Required safe fields |
| --- | --- |
| `<generation>.meta.json` | schema `central.protected-generation/v1`; binding/candidate/generation IDs; purpose; created-at; byte count; opaque HMAC version token plus key version; value-format enum `opaque_bytes` |
| `staged.json` | schema `central.protected-candidate-phase/v1`; phase `staged`; binding/candidate ID; ordered `generation_refs[] {role,generation_id,version_token}`; expected prior candidate/generation or explicit `null`; owning protocol; safe operation ID or `null`; created-at |
| `registered.json` | same schema; phase `registered`; exact staged digest; registration class; opaque authoritative-reference fingerprint; registered-at |
| `activated.json` | same schema; phase `activated`; exact registered digest; activation sequence; activated-at |
| `retired.json` | same schema; phase `retired`; replacing candidate/generation; retired-at; not-before-cleanup-at |
| `abandoned.json` | same schema; phase `abandoned`; fixed safe reason enum; authoritative no-reference proof fingerprint; abandoned-at; not-before-cleanup-at |
| `active.json` | schema `central.protected-active/v1`; binding/purpose; status `active`, `revoked`, or `deleted`; candidate/generation refs and opaque version tokens, or an empty tuple only for `deleted`; monotonically increasing activation sequence; activated-at; revoked/deleted-at and fixed reason or explicit `null` |

Ordinary secret/bootstrap candidates contain exactly one generation ref with role `value`. A TLS candidate contains exactly two refs, roles `ca` and `leaf`, and activation treats the tuple atomically. IDs are UUIDv7. The broker computes each safe version token as HMAC-SHA-256 under a root-only versioned fingerprint key with domain separation over schema, purpose, binding ID, candidate ID, generation ID, role, byte count, and value bytes. Raw/unsalted secret digests never leave broker memory or appear in metadata, receipts, PostgreSQL, audit, configuration, or observations. Public certificate, OCI, file-integrity, and sealed-backup digests remain ordinary public-content SHA-256 values and are not secret fingerprints. Times are UTC RFC 3339 with microseconds.

Unknown fields, duplicate roles, multiple phase files of the same name, a phase without all predecessors, conflicting terminal phases, token mismatch, nonmonotonic sequence, or purpose/binding/operation mismatch is `PROTECTED_STATE_INVALID`.

### 4.3 Staging protocol

Inside the broker while holding `binding.lock`:

1. Create the random candidate and generation identities.
2. Create a same-directory value temporary with `0600`; write bounded bytes while computing only the domain-separated HMAC token.
3. Synchronize; publish the value create-only.
4. Synchronize `generations/`; publish and synchronize generation metadata create-only.
5. Publish `staged.json` create-only; then synchronize the candidate and binding directories.

A crash before durable `staged.json` creates no eligible candidate. TLS repeats value/key/certificate publication for both roles before one staged tuple is published.

### 4.4 Registration and activation

The owning protocol next durably commits its authoritative registration under the global protected-state-before-database lock order. Only after that commit may it publish `registered.json`; if it crashes between those steps, reconciliation queries the exact authoritative operation/database reference and reconstructs only the matching registered phase. A phase file is evidence, never a substitute for that authoritative reference.

Activation revalidates candidate, every value/meta version token, authoritative registration, expected prior active tuple, and activation sequence while holding `binding.lock`. It writes a complete new `active.json` temporary, synchronizes it, atomically renames it over the pointer, synchronizes the binding directory, and only then publishes `activated.json`. The pointer rename is the activation linearization point. A crash afterward is reconciled by writing the uniquely implied activated phase; a crash beforehand leaves the old generation active. Concurrent candidates cannot both match the prior tuple/sequence.

After a later activation, the same locked protocol publishes `retired.json` for the displaced candidate with a seven-day installed retention. Revocation atomically replaces `active.json` with the same exact tuple/sequence and status `revoked`, synchronizes the binding directory, and immediately removes resolution eligibility; it never deletes bytes inline. Rotation preserves logical binding identity and may name a revoked tuple as its expected prior state.

### 4.5 Crash reconciliation

Follows durable evidence only:

| Evidence | Required action |
| --- | --- |
| value temporary, value without metadata, or metadata without `staged` | never resolve/register; after candidate cleanup age and exact no-reference proof, abandon and remove |
| durable `staged`, no authoritative registration | retain within candidate cleanup age; afterward recheck under lock, publish `abandoned`, then clean |
| exact authoritative registration, missing `registered` | reconstruct the one matching registered phase |
| durable `registered`, old active pointer | exact owning operation may activate; generic startup never chooses it |
| active pointer matches candidate, missing `activated` | verify all evidence and publish `activated` |
| displaced activated candidate missing `retired` | publish retirement derived from the newer active sequence |
| any conflict or unknowable external reference | fail closed; no generic cleanup or winner selection |

### 4.6 Cleanup

Exact-reference collection, not age-only deletion. After the installed one-day candidate or seven-day retired not-before time, the broker acquires `binding.lock` and proves absence from `active.json`, every nonterminal candidate, protected operation/target records, PostgreSQL registration/security epochs, restore barriers, and helper/container handoff receipts. It then:

1. Publishes `abandoned.json` where applicable.
2. Removes only the named value(s).
3. Synchronizes `generations/`.
4. Removes their metadata.
5. Synchronizes again.
6. Removes only that candidate journal.
7. Synchronizes the binding directory.

A crash resumes this order idempotently. It never deletes a registered, active, revoked-pointer, referenced, ambiguous, or concurrently selected generation. Terminal safe metadata is copied into the bounded operator-audit record before its candidate journal is removed; no plaintext or backend path enters audit.

### 4.7 Tombstones (logical deletion)

Distinct from revocation. After fresh PAM authorization and external-provider revocation proof where applicable, the owning protocol commits a create-only `central.protected-tombstone/v1` bound to the binding, current tuple/sequence, operation, database/reference epoch, and deletion deadline. Under `binding.lock` the broker:

1. Proves no database, operation, handoff, restore, or adapter reference remains.
2. Atomically replaces `active.json` with status `deleted`, an empty tuple, the next sequence, and the tombstone digest.
3. Synchronizes the binding directory.

Only then does the former revoked or active tuple become a retired cleanup candidate with a maximum seven-day terminal deadline. Cleanup repeats the reference proof, unlinks exact values and metadata with directory synchronization, and retains only the opaque tombstone/audit evidence. Revocation may retain repairable bytes temporarily; deletion cannot retain plaintext indefinitely. Unlink is not claimed to provide physical secure erasure on journaled or copy-on-write media.

### 4.8 Secret resolution

Resolution occurs only inside a registered secret-aware adapter, defaults to a five-second deadline (configurable via `protected_store.resolve_ms`), and rejects a value above 64 KiB. The resolver returns no plaintext to domain, generic runtime, generic process, logs, metrics, Events, receipts, config, or error surfaces. Mutable buffers are minimized and cleared best-effort after use. Missing, ambiguous, multiply active, wrong-owner, wrong-purpose, revoked, unreadable, oversized, or permission-drifted bindings fail closed with no fallback.

Protected credential material is excluded from Central backup payloads. The post-restore reconciliation compares only opaque identity and safe HMAC version token and requires fresh operator authority before re-enabling a SecretReference.

### 4.9 Namespace specialization

The `bootstrap/` namespace uses this same journal, generation metadata, exact registration, and atomic active-pointer protocol but is not a Workspace SecretReference and is never discoverable through the general resolver. The TLS namespace uses the same rules for its atomic CA/leaf tuple. `operations/target.json` is the Gate 7 external provisioning/restore/security barrier. Per-operation records hold exact migration, backup, and restore progress. Receipt filenames are fixed desired-state records, while an operation record retains one immutable operation identity and advances only by atomic exact-phase replacement.

## 5. Authority transition protocol

### 5.1 Immutable sequence-specific records

Every accepted configuration, operation, receipt, payload-epoch, repository-root-manifest, and audit transition is an immutable sequence-specific payload plus `central.authority-transition/v1` envelope under `authority-records/<stream-id>/`. The envelope contains transition/stream IDs, monotonic sequence, canonical payload digest and byte count, prior committed envelope digest, instance, authenticated launch ID, closed protocol phase, one-use nonce, broker key version, and domain-separated HMAC. The runtime may propose bytes through a bounded descriptor but cannot create a valid envelope.

### 5.2 Commit protocol

One exact crash-safe protocol:

1. Under the stream lock the runtime writes and synchronizes a transition-owned create-exclusive candidate and holds its immutable read-only descriptor.
2. The broker rereads it, validates the previous committed journal record and command state machine, then create-exclusively writes and synchronizes `prepared.json` containing the exact canonical payload bytes as base64url and descriptor evidence.
3. It next writes `issued.json` containing the exact envelope and synchronizes the transition directory.
4. Payload and envelope are each written completely to create-exclusive staging files, synchronized, and atomically installed at `<sequence>-<transition-id>.payload.json` and `<sequence>-<transition-id>.auth.json` with `renameat2(RENAME_NOREPLACE)`; each parent is synchronized before the next install.
5. A final-name collision is accepted only when a no-follow complete reread exactly matches the issued digest/bytes, otherwise it is `PROTECTED_STATE_INVALID` and is never unlinked or replaced.
6. The broker reopens both immutable files, verifies byte equality/HMAC, and writes `committed.json`; that append-only committed record is the stream head.

Only after `committed.json` is synchronized may the semantic transition be observed as accepted. Recovery scans only the next sequence after the last committed record. `prepared` without `issued` deterministically issues the stored bytes; exact final publication without `committed` is reverified and committed. A truncated or different immutable collision is terminal invalid evidence, never "repaired." Different bytes, another transition ID/nonce, an already consumed sequence, or a gap is `PROTECTED_STATE_INVALID`; reissue never creates a second envelope. After commit, a fixed materialized projection may be atomically replaced from the current committed payload and envelope.

### 5.3 Genesis and key rotation

Genesis is bound to the synchronized root init intent and installed broker/view-signing identities. Key rotation is itself a committed transition authenticated by both old and new keys; the old key remains verification-only until every referenced stream has crossed the rotation record.

### 5.4 Checkpoint and compaction

Authority payload limits: 1 MiB for config, 256 KiB for operation/receipt, 64 KiB for payload-epoch/binding, 8 KiB for audit, and 16 MiB only for repository root/checkpoint manifests. Envelopes and each phase record are at most 16 KiB excluding the prepared payload copy. A live stream tail is at most 64 committed transitions or 32 MiB, whichever comes first. At 48 transitions or 24 MiB the broker automatically creates a crash-safe `central.authority-checkpoint/v1` transition binding the prior checkpoint, ordered committed-envelope Merkle root, current stream head, retained key set, counts, and bytes. Verification reads one checkpoint plus at most the bounded tail, never full history.

### 5.5 Protected-state ceilings

Across an instance, uncheckpointed journals are limited to 8,192 transitions/512 MiB and the complete broker authority store to 2 GiB, with a separately preallocated 64 MiB settlement reserve. At 75% of either hard ceiling, new non-settlement mutations return `MAINTENANCE_REQUIRED`; current transition settlement, checkpointing, verify/status, export, security update, and down remain possible from the reserve. Exhausting the settlement reserve is `CLEANUP_REQUIRED` and blocks new accepted mutation without discarding the last committed head.

### 5.6 Journal retention and protected maintenance

Protected maintenance reclaims only checkpoint-covered, unreferenced old journal directories in bounded 8-MiB/1,000-entry quanta inside its existing two-hour deadline. Crash recovery either retains the old verified checkpoint/tail or commits the unique new checkpoint; it never advances a head by deletion.

Unsealed operations, retired/abandoned secret generations, and completed operator-audit records become maintenance-eligible under the existing one-day candidate/seven-day retired exact-reference rules plus one-year audit minimum and newest-10,000 preservation. `central local maintenance plan` selects only these bounded candidates; apply requires lifecycle exclusive + all affected binding/repository locks in canonical order, a 15-minute unchanged plan, fresh PAM plus helper-read confirmation of full plan ID/count/bytes, and create-before-delete audit evidence.

## 6. Bootstrap and TLS boundaries

### 6.1 Bootstrap token lifecycle

Bootstrap generations use 256 bits from the operating-system cryptographic random source. The protected store owns candidate plaintext; PostgreSQL owns only the accepted verifier, generation, database-time presentation expiry, consumption, throttle, and session linkage. A newly provisioned or post-exchange replacement generation is not browser-exchange eligible until an explicit presentation rotation.

`central bootstrap show` is the sole reveal path. It requires fresh PAM authentication plus the broker/helper-owned controlling-TTY ceremony, refuses redirected/stdout-JSON output, proves the exact `central serve` process holds `runtime.lock`, completes TLS authentication to the configured instance origin, and requires the profile to be ready before staging plaintext. Every invocation creates a fresh candidate rather than rereading the current plaintext. Plaintext never crosses the operator controller or runtime process.

The HTTP exchange accepts only the exact currently presented generation when database time is strictly earlier than its expiry; equality is expired. Expiry, replacement, or one successful exchange makes it permanently ineligible.

### 6.2 TLS signer boundary

TLS exposes the public chain plus a narrow `crypto.Signer` operation over the locked leaf key; the CA key signs only the fixed offline leaf-rotation object and never leaves the broker. The CA certificate is constrained to `127.0.0.1/32`; its signing key and the leaf private key are separate root-owned protected generations and are never resolved as plaintext by `central serve`. TLS handshakes use the broker's leaf-only signing operation.

Leaf rotation is an offline lifecycle-exclusive operation: stage and sign a new leaf under the active CA, validate key/certificate/instance linkage and validity, atomically activate it, and retain exact repair evidence. CA rotation stages a new CA and leaf, installs the new public anchor before activation, verifies the trust receipt, atomically activates both, and only then allows explicit removal of the old anchor.

### 6.3 Bootstrap token presentation (HMAC tokens)

The specialized `bootstrap/` namespace generates opaque HMAC version tokens under the same fingerprint-key contract as secrets. The presentation rotation protocol under exclusive `bootstrap/binding.lock` writes the 256-bit value once through the helper-controlled TTY to the operator, then atomically replaces `bootstrap/presentation.json`. The command offers no list, export, URL, clipboard, environment, generic reveal, or warning-bypass mode.

## 7. Command grammar, results, and remediation

### 7.1 Local command grammar

```text
central local init
central local init --status
central local init --resume=<init-operation-id>
central local init --abandon=<init-operation-id>
central local doctor --host-prerequisites
central local trust install
central local trust remove
central local tls rotate-leaf
central local tls rotate-ca
central local security status
central local security update
central local prepare
central local dependency-upgrade plan
central local dependency-upgrade apply --ticket=<ticket-id>
central local dependency-upgrade resume --operation=<operation-id>
central local maintenance plan
central local maintenance apply --plan=<plan-id>
central local runtime stage --binary=<absolute-go-binary> --manifest=<absolute-build-manifest>
central local browser open
central local browser clear
central local browser clear --operation=<browser-clear-operation-id>
central local up
central local status
central local doctor
central local doctor --write-probe
central local doctor --backup-throughput-probe
central local explain --reason=<reason-code>
central local down
central local wipe
central local wipe --operation=<operation-id>
central bootstrap show
```

Plus Gate 7 extension verbs owned through `backup/app`:
```text
central backup list [--cursor=<opaque-cursor>]
central backup export --backup=<backup-id> --destination=<absolute-empty-directory>
central backup export resume --operation=<operation-id>
central backup import --source=<absolute-export-directory>
central backup import resume --operation=<operation-id>
central backup delete plan --backup=<backup-id>
central backup delete apply --plan=<plan-id>
central backup prune plan
central backup prune apply --plan=<plan-id>
```

### 7.2 `central.local-result/v1` schema

Every `central local ...` and `central local tls/trust ...` JSON outcome emits exactly one UTF-8 JSON object on stdout. Every field below is required; fields marked nullable use explicit `null`, never omission.

| Field | Type | Exact contract |
| --- | --- | --- |
| `schema_version` | string | fixed `central.local-result/v1` |
| `command` | enum | `init`, `init_status`, `init_abandon`, `prepare`, `security_status`, `security_update`, `dependency_upgrade_plan`, `dependency_upgrade_apply`, `dependency_upgrade_resume`, `maintenance_plan`, `maintenance_apply`, `runtime_stage`, `browser_open`, `browser_clear`, `trust_install`, `trust_remove`, `tls_rotate_leaf`, `tls_rotate_ca`, `up`, `status`, `doctor_host_prerequisites`, `doctor`, `doctor_write_probe`, `doctor_backup_throughput_probe`, `explain`, `down`, `wipe` |
| `outcome` | enum | `succeeded`, `failed`, `interrupted` |
| `exit_class` | uint | one of `0`, `2`, `3`, `4`, `5`, `6`, `7`; must equal process exit status |
| `reason_code` | enum | one value from the mapping below |
| `environment_state` | enum/null | `ABSENT`, `INITIALIZED`, `DATA_READY`, `DEPENDENCIES_HEALTHY`, `PROVISIONED`, `MIGRATION_REQUIRED`, `ENVIRONMENT_READY`, `STOPPED`, `DEGRADED`, `DRIFTED`, or `null` when not safely derivable |
| `mutation_phase` | enum | `none`, `preflight`, `accepted`, `mutating`, `settling`, `complete` |
| `mutation_started` | boolean | true only after the command's documented accepted point |
| `retryable` | boolean | safe to repeat the same command/input without a resume operation |
| `resume_required` | boolean | only true when an exact operation continuation is mandatory |
| `operation_id` | uuid7/null | safe operation ID; required non-null when `resume_required` |
| `started_at` / `updated_at` | string | UTC RFC 3339 with microseconds; updated not before started |
| `progress.records` / `progress.bytes` / `progress.chunks` | uint/null | bounded committed progress only, never estimates or uncommitted work |
| `safe_next_action.kind` | enum | `none`, `retry_same`, `run_command`, `resume_exact`, `inspect_manual` |
| `safe_next_action.command` | string/null | one allowlisted command template, at most 256 ASCII bytes, containing only safe opaque IDs; non-null only for `run_command`/`resume_exact` |
| `remediation.catalog_version` | string | fixed `central.local-remediation/v1` |
| `remediation.entry_id` | string | fixed ASCII catalog ID corresponding exactly to `reason_code` |
| `remediation.failure_count` | uint | consecutive safe-fingerprint count including this result; zero only for exit `0` |
| `remediation.manual_after_count` | uint/null | exact catalog threshold, or null when not count-based |
| `remediation.manual_after_ms` | uint/null | exact catalog elapsed threshold, or null when not time-based |
| `details` | object | exactly one closed command-keyed variant below; never `null` and never presentation prose |
| `message` | string | fixed-code localized-safe English text, 1–512 NFC UTF-8 bytes; no raw dependency text or caller input |

### 7.3 `details` variants

`details.kind` equals `command`; every variant rejects fields not listed. A field unavailable because the command failed is explicit `null`. IDs are UUIDv7 or fixed bounded ASCII authority IDs; counts/bytes are `uint`; times are UTC RFC 3339 with microseconds. `findings` contains at most 64 entries sorted by fixed catalog order, each exactly `{entry_id,reason_code,state,authority_field_id,next_action_kind}` with bounded enums/IDs and no raw value.

| `details.kind` | Complete additional fields |
| --- | --- |
| `init` | `instance_id`, `config_binding_id`, `init_operation_id` |
| `init_status` | `incomplete_operations`, `observation_limit`, `observation_truncated` |
| `init_abandon` | `init_operation_id`, `reservation_state`, `audit_tombstone_id` |
| `prepare` | `preparation_id`, `dependency_set_id`, `advisory_bundle_id`, `reused_verified_input_count`, `acquired_verified_input_count` |
| `security_status`, `security_update` | `bundle_id`, `key_id`, `issued_at`, `expires_at`, `authority_state` (`current`, `stale_admitted`, `hard_expired`, `denied`, `missing`), `advisory_count`, `exception_count`, `deny_count`, `snapshot_generation`, `snapshot_signed_at`, `snapshot_observed_age_ms`, `snapshot_signing_key_id`, `snapshot_signature_state`, `loopback_health` |
| `dependency_upgrade_plan` | `ticket_id`, `transition_id`, `expires_at`, `classification`, `backup_id` |
| `dependency_upgrade_apply`, `dependency_upgrade_resume` | `transition_id`, `old_dependency_set_id`, `new_dependency_set_id`, `checkpoint` |
| `maintenance_plan` | `plan_id`, `expires_at`, `candidate_count`, `candidate_bytes`, `retained_count`, `retained_bytes` |
| `maintenance_apply` | `plan_id`, `deleted_count`, `deleted_bytes`, `checkpoint` |
| `runtime_stage` | `runtime_build_id`, `lease_expires_at`, `development_instance` |
| `browser_open` | `browser_profile_id`, `public_ca_token`, `origin_id`, `browser_process_state` |
| `browser_clear` | `browser_profile_id`, `sessions_revoked`, `bootstrap_generation_revoked`, `checkpoint` |
| `trust_install`, `trust_remove`, `tls_rotate_leaf`, `tls_rotate_ca` | `public_ca_token`, `public_leaf_token`, `browser_profile_id`, `trust_state` |
| `up`, `down` | `dependency_set_id`, `postgres_state`, `object_store_state`, `completed_step_count` |
| `doctor_host_prerequisites` | `manifest_id`, `host_profile_state`, `findings` |
| `status`, `doctor`, `doctor_write_probe`, `doctor_backup_throughput_probe` | `privileged_inspection`, `serve_state`, `findings`, `capacity_class`, `probe_id`, `snapshot_generation`, `snapshot_signed_at`, `snapshot_observed_age_ms`, `snapshot_signing_key_id`, `snapshot_signature_state`, `loopback_health` |
| `explain` | `requested_reason_code`, `catalog_entry_id` |
| `wipe` | `prior_payload_epoch_id`, `current_payload_epoch_id`, `completed_root_count`, `checkpoint` |

Additional `init_status.incomplete_operations` contains at most eight entries sorted by operation ID, each exactly `{init_operation_id,instance_id,phase,started_at,safe_next_action}`. Snapshot fields: `snapshot_signature_state` is exactly `valid_fresh`, `valid_stale`, `invalid`, or `missing`; `loopback_health` is independently `reachable`, `unreachable`, or `not_checked`.

### 7.4 Reason/exit matrix

| Exit | Allowed reason codes | Required semantics |
| ---: | --- | --- |
| `0` | `OK`, `MIGRATION_REQUIRED`, `OUTSIDE_SUPPORTED_PROFILE`, `UPGRADE_OUT_OF_PLACE_REQUIRED`, `SECURITY_AUTHORITY_STALE` | command completed its promised work; the latter four are successful diagnostic states with an exact next action or prominent warning |
| `2` | `INVALID_INVOCATION`, `CONFIG_NOT_FOUND`, `CONFIG_AMBIGUOUS`, `CONFIG_INVALID`, `CONFIRMATION_MISMATCH` | no accepted mutation; correct invocation/configuration first |
| `3` | `DEPENDENCY_UNAVAILABLE`, `HELPER_UNAVAILABLE`, `PREPARATION_REQUIRED`, `TLS_TRUST_REQUIRED`, `HOST_PREREQUISITE_MISMATCH`, `BACKUP_REQUIRED`, `THROUGHPUT_EVIDENCE_REQUIRED`, `MAINTENANCE_REQUIRED` | prerequisite unavailable before accepted mutation; retry only after stated prerequisite |
| `4` | `LOCK_TIMEOUT`, `RESOURCE_TIMEOUT`, `PORT_IN_USE`, `CAPACITY_INSUFFICIENT` | bounded pre-accepted-point contention/resource failure; no mutation remains active |
| `5` | `DRIFTED`, `INCOMPATIBLE`, `PROTECTED_STATE_INVALID`, `SNAPSHOT_INVALID`, `CLEANUP_REQUIRED`, `SECURITY_REVIEW_REQUIRED`, `SECURITY_AUTHORITY_HARD_EXPIRED`, `DEPENDENCY_DENIED`, `DEADLINE_NOT_PLAUSIBLE`, `UPGRADE_NOT_SAFE`, `UNSUPPORTED_IN_THIS_SLICE`, `OPERATION_SUPERSEDED_BY_WIPE` | unsafe mismatch, invalid diagnostic evidence, blocked/hard-expired authority, deferred capability, superseded operation, or unproven upgrade requiring exact diagnosis/governed repair; never blind retry |
| `6` | `RESUME_REQUIRED`, `PORT_BIND_RACE`, `MUTATION_FAILED`, `MUTATION_INDETERMINATE`, `ROLLBACK_FAILED` | accepted mutation failed/interrupted; operation evidence and exact next action required |
| `7` | `AUTHORITY_DENIED`, `HELPER_POLICY_DENIED`, `DOCKER_AUTHORITY_PRESENT` | authority or isolation policy denied; no privilege weakening is suggested |

`outcome=succeeded` iff exit `0`; `interrupted` is permitted only with exit `6`. Exit `2`, `3`, `4`, `5`, or `7` uses `failed`. `resume_required=true` requires exit `6`, reason `RESUME_REQUIRED`, non-null operation ID, `retryable=false`, and `safe_next_action.kind=resume_exact`. `retryable=true` is permitted only for exit `3` or `4` when no mutation started. The sole accepted-mutation exception is exit `6`/`PORT_BIND_RACE`: proven complete topology rollback, only exact idempotent durable-step receipts remaining, `resume_required=false`, and `safe_next_action.kind=retry_same`. `ROLLBACK_FAILED` and `MUTATION_INDETERMINATE` are never retryable. Exit `5` or `7` always selects `inspect_manual` or an exact non-mutating diagnostic command. `mutation_phase=complete` is required for exit `0`; `none` or `preflight` requires `mutation_started=false`; `accepted`, `mutating`, or `settling` requires it true.

### 7.5 `central.local-remediation/v1` thresholds

| Result class | Exact automated/operator guidance before manual inspection |
| --- | --- |
| exit `0` diagnostic state | one exact next command where applicable; no failure counter |
| exit `2` | correct the named invocation/config catalog field; after three consecutive results with the same safe failure fingerprint and unchanged config digest within 30 minutes, `inspect_manual` |
| exit `3` | perform the exact prerequisite command once; after three identical post-remediation failures or 30 minutes from the first, whichever occurs first, `inspect_manual` |
| exit `4` | at most three same-input retries with installed backoff inside 15 minutes; then `inspect_manual` |
| exit `5` or `7` | run the catalog's single non-mutating `local doctor`/status/explain command; if the same fingerprint remains, manual inspection is immediate and mutation retry is forbidden |
| exit `6`/`RESUME_REQUIRED` | only the exact operation resume command; after three failed resumes or the operation deadline, manual inspection; `MUTATION_INDETERMINATE` and `ROLLBACK_FAILED` are immediate manual inspection |

A failure fingerprint is a safe digest of reason code, instance/config/payload-epoch/authority identities, mutation phase, and bounded mismatch class—never raw detail. Counters come from protected operator audit, reset only after success or a catalog-declared relevant identity change, and never authorize a mutation. Crossing a threshold changes `safe_next_action.kind` to `inspect_manual`; it does not reveal additional detail or suggest force/permission weakening.

## 8. Helper request matrix

The root-owned infrastructure helper permits only this closed operation matrix:

| Request | Permitted authority |
| --- | --- |
| `init` / `init-status` / `init-resume` / `init-abandon` | create, discover, resume, or abandon only caller-bound configless journaled initialization; abandon is limited to an unaccepted empty reservation; no network or Docker |
| `prepare` | fetch, build, verify, and load only embedded locked dependency artifacts |
| `security-update` | fetch only the embedded advisory endpoint or consume the fixed inherited offline descriptor; verify and atomically activate only a release-key-signed admissible bundle |
| `dependency-upgrade-plan` | bounded compatibility/backup/capacity inspection plus creation of one exact protected upgrade ticket; no payload or container mutation |
| `dependency-upgrade-apply` / `dependency-upgrade-resume` | execute or resume only the ticket-bound embedded old-to-new patch transition and its fixed verification probes |
| `trust-install` / `trust-remove` | install or remove only the exact validated instance CA public certificate in the Ubuntu system and selected browser trust stores; never read a CA or server private key |
| `browser-open` | launch the exact managed Central browser/profile as `central-browser` in the active local Wayland session at the fixed HTTPS origin; no caller URL, flags, extension, proxy, or alternate profile |
| `browser-clear` / `browser-clear-resume` | after durable application-session/bootstrap invalidation, start or resume only the exact journaled replacement of the descriptor-bound managed profile |
| `runtime-stage` | after fresh PAM, copy one descriptor-opened Go binary plus its descriptor-opened canonical build manifest into the root-owned instance-scoped runtime staging store, verify their binding, and activate the digest for a bounded development lease; never execute from the repository path |
| `runtime-start` / `runtime-stop` / `operator-mode-start` | launch or settle only the embedded/staged-authority `central serve`, migration, bootstrap, backup, restore, and registered adapter modes as `central-runtime` with descriptor-bound config and broker access; never execute caller code or an unlisted mode |
| `security-rescue-cleanup` | stop/reap only the exact rescue operation topology and continue only its authenticated descriptor-bound scratch deletion journal; no backup/data mutation or caller path |
| `bootstrap-show` | after fresh PAM and ready-server proof, let the broker rotate and write one presentation generation directly to the helper-owned TTY; helper/controller never receive plaintext |
| `up` | render and validate the embedded Compose model; materialize exact service-scoped secret handoffs; run filesystem initialization, start, health-check, provision, and inspect steps |
| `status` / `doctor` | bounded read-only inspection of the exact instance resources; the explicit write probe uses an ordinary application credential rather than Docker authority |
| `down` | stop only exact instance-bound resources while preserving payload data |
| `wipe` | after exact fixed confirmation/locks/accepted receipt, run or resume only the sequential one-root-at-a-time no-network `central-local-infra` wipe protocol |

## 9. PAM / TTY confirmation rules

The request protocol is versioned and closed: operation, invoking UID, instance/binding/config/lock identities, exact operation or confirmation identity where required, and safe correlation ID. It contains no plaintext secret, secret pathname, container UID/GID, Compose fragment, image, socket, or executable argument. The invoking UID is authenticated by a root-owned `sudoers` policy with `env_reset`, `timestamp_timeout=0`, a fixed executable, `secure_path`, and no shell or arbitrary arguments; passwordless rules and cached credentials are forbidden.

Every helper request therefore requires a fresh PAM conversation. The helper verifies the active local logind/Wayland session and physical-seat TTY ancestry, takes an exclusive terminal lease, uses `vhangup`/reopen to invalidate prior same-UID terminal descriptors, applies `TIOCEXCL`, temporarily makes the reopened device root-only, and performs the PAM/confirmation conversation itself before restoring exact ownership/mode at final settlement. A caller-created PTY, remote/SSH session, missing physical seat, ownership transition failure, PAM failure, forwarding, or noninteractive invocation is `AUTHORITY_DENIED`; production has no automation bypass.

For `wipe`, restore apply, hard-expired rescue backup, backup/export deletion or pruning, trust removal, audit/protected-generation maintenance, and dependency-upgrade apply/resume, PAM success alone is insufficient. After fresh authentication the helper itself opens `/dev/tty`, displays the safe operation/target/plan IDs it independently recomputed, reads the fixed confirmation phrase with echo disabled, and binds a one-use confirmation digest to the helper authority, PAM session, boot ID, caller UID, operation ID, target/payload epoch, exact action, and a 60-second deadline. Controller-created PTYs, controller confirmation digests, stdin, flags, environment, redirected input, and replay are rejected.

## 10. Derived environment state

Environment state is derived from bindings, receipts, dependency health, provisioning evidence, schema inspection, and restore/security barriers:

```text
ABSENT
INITIALIZED
DATA_READY
DEPENDENCIES_HEALTHY
PROVISIONED
MIGRATION_REQUIRED
ENVIRONMENT_READY
STOPPED
DEGRADED
DRIFTED
```

Precedence (first match wins):
1. `DRIFTED` — unsafe/ambiguous binding, authority, policy, epoch, or mutation evidence
2. `DEGRADED` — exact cleanup-required, released-reserve, terminal dependency/runtime failure, or known incomplete accepted operation
3. `STOPPED` — otherwise exact intentionally stopped dependencies
4. `MIGRATION_REQUIRED` — healthy/provisioned dependencies with absent or behind schema
5. `ENVIRONMENT_READY` — compatible ready external barrier
6. `PROVISIONED`, `DEPENDENCIES_HEALTHY`, `DATA_READY`, `INITIALIZED`, `ABSENT` in descending evidence order

An init bootstrap journal requiring resume is `DEGRADED`, not `ABSENT`; a conflicting journal is `DRIFTED`.

## 11. Lifecycle locks

Each instance has fixed `lifecycle.lock` and `runtime.lock` files. Lock files are never removed during ordinary operation.

`central serve` holds `runtime.lock` exclusively and `lifecycle.lock` shared for its process lifetime. Every target-reading operation takes lifecycle shared ownership. Snapshot-only unprivileged `local status` and `local security status` are explicit exceptions: they cannot traverse the lock root, take no lifecycle lock, report signed snapshot age, and make no atomic/current-state claim.

`local init`, `local prepare`, `local security update`, `local browser clear`, every dependency-upgrade and local-maintenance phase, `local up`, `local down`, `local wipe`, dependency/TLS credential rotation, and other host-root/topology mutations take lifecycle exclusive ownership.

## 12. Diagnostic output planes

Central has exactly two diagnostic planes:

1. **Machine/generic:** JSON stdout, redirected stdout/stderr, structured logs, audit, HTTP health/metrics, test artifacts, and helper receipts. This plane contains no raw path/filename and follows bounded schemas and redaction rules.
2. **Trusted local TTY:** human output is enabled only when stdin, stdout, and stderr are terminals owned by the invoking operator UID, the command is not using JSON output, and selected config/root descriptors have been reopened and revalidated. It may show only the canonical config file, instance config/state/data root, backup repository, generated diagnostic Compose file, and an explicitly selected export/import path owned by that UID. Secret-generation/private-key paths, backend locators, object keys/body paths, database/MinIO payload descendants, root helper/audit internals, tmpfs secret paths, and arbitrary dependency error paths remain prohibited.

TTY paths are never interpolated from an error. Central derives them from held descriptors/bindings, rejects control/bidi/non-NFC bytes, renders a bounded JSON-escaped display value, and renders copyable commands with a fixed POSIX single-quote encoder. If descriptor ownership/identity cannot be proven or any terminal condition fails, output automatically uses the machine plane.

## 13. Normative inventory appendix

### 13.1 `central.config/v1` field census

Total required fields (excluding nested object containers): **138** named fields
across 13 top-level sections. The provider section defines 14 required profile
member fields, including the `default_budget` and `hard_budget` object
containers, and contributes 18 required non-container fields: 12 direct profile
leaves plus six required budget leaves. Every field listed in §2.3 and §2.4
appears exactly once. No field is missing, duplicate, or extra.

### 13.2 `central.local-result/v1` variant census

**27** command variants (1:1 with the command enum). Every variant listed in §7.3 appears exactly once. No variant is missing, duplicate, or extra.

### 13.3 `details` variant field census

Sum of all variant-specific fields (excluding inherited `schema_version`/`command` etc.): **73** distinct typed fields including `findings` compound entries. Every field listed in §7.3 appears exactly once.

### 13.4 Reason code census

**42** reason codes across 7 exit classes. Every code listed in §7.4 appears exactly once:

- Exit 0 (5): `OK`, `MIGRATION_REQUIRED`, `OUTSIDE_SUPPORTED_PROFILE`, `UPGRADE_OUT_OF_PLACE_REQUIRED`, `SECURITY_AUTHORITY_STALE`
- Exit 2 (5): `INVALID_INVOCATION`, `CONFIG_NOT_FOUND`, `CONFIG_AMBIGUOUS`, `CONFIG_INVALID`, `CONFIRMATION_MISMATCH`
- Exit 3 (8): `DEPENDENCY_UNAVAILABLE`, `HELPER_UNAVAILABLE`, `PREPARATION_REQUIRED`, `TLS_TRUST_REQUIRED`, `HOST_PREREQUISITE_MISMATCH`, `BACKUP_REQUIRED`, `THROUGHPUT_EVIDENCE_REQUIRED`, `MAINTENANCE_REQUIRED`
- Exit 4 (4): `LOCK_TIMEOUT`, `RESOURCE_TIMEOUT`, `PORT_IN_USE`, `CAPACITY_INSUFFICIENT`
- Exit 5 (12): `DRIFTED`, `INCOMPATIBLE`, `PROTECTED_STATE_INVALID`, `SNAPSHOT_INVALID`, `CLEANUP_REQUIRED`, `SECURITY_REVIEW_REQUIRED`, `SECURITY_AUTHORITY_HARD_EXPIRED`, `DEPENDENCY_DENIED`, `DEADLINE_NOT_PLAUSIBLE`, `UPGRADE_NOT_SAFE`, `UNSUPPORTED_IN_THIS_SLICE`, `OPERATION_SUPERSEDED_BY_WIPE`
- Exit 6 (5): `RESUME_REQUIRED`, `PORT_BIND_RACE`, `MUTATION_FAILED`, `MUTATION_INDETERMINATE`, `ROLLBACK_FAILED`
- Exit 7 (3): `AUTHORITY_DENIED`, `HELPER_POLICY_DENIED`, `DOCKER_AUTHORITY_PRESENT`

Total: 42 reason codes (the governing design has exactly these).

### 13.5 Derived environment state census

**10** derived states: `ABSENT`, `INITIALIZED`, `DATA_READY`, `DEPENDENCIES_HEALTHY`, `PROVISIONED`, `MIGRATION_REQUIRED`, `ENVIRONMENT_READY`, `STOPPED`, `DEGRADED`, `DRIFTED`.

### 13.6 Remediation threshold class census

**6** threshold classes: exit-0-diagnostic, exit-2, exit-3, exit-4, exit-5-or-7, exit-6-RESUME_REQUIRED.

### 13.7 Authority transition phase census

**3** journal phases: `prepared`, `issued`, `committed`. Additional projection-only phase `checkpoint` via `central.authority-checkpoint/v1`.

### 13.8 Protected-generation phase census

**6** phases: `staged`, `registered`, `activated`, `retired`, `abandoned`, plus the `active.json` pointer with status `active`, `revoked`, `deleted`.

### 13.9 Helper request operation census

**24** closed operations listed in §8.

## 14. Canonical references

- [Gate 8 governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md)
- [ADR 0009](../adr/0009-adopt-local-development-environment-topology.md)
- [Local topology contract](../architecture/local-development-environment.md)
- [Gate 2 Threat model](../security/threat-model.md)
- [Gate 2 SecretReference contract](../security/secret-reference.md)
- [Gate 7 PostgreSQL contract](../persistence/postgresql.md)
- [Gate 7 Rust application boundaries](../architecture/rust-application-boundaries.md)
