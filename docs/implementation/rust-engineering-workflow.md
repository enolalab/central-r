# Rust Engineering Workflow — Canonical Contract

- **Status:** Adopted
- **Replaces:** the upstream `go-engineering-workflow.md` for the Rust codebase. The upstream document is historical provenance only; this contract defines the `central-rust` toolchain, dependency, lint, verification, and test policy.
- **Governing documents:**
  - [Central-Rust Documentation and Architecture Design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md) — governing spec (§5)
  - [ADR 0043 — Adopt Rust Workspace and Harness-First Porting Strategy](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md)
  - [Rust Application Boundaries — Canonical Contract](../architecture/rust-application-boundaries.md)
  - [PostgreSQL Adapter Mapping — Canonical Contract](../persistence/postgresql-adapter-mapping.md)
  - [ADR 0007 — Adopt PostgreSQL Persistence and Recovery Contracts](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md)

## 1. Purpose and authority

This document is the canonical Rust engineering workflow for `central-rust`. It defines the pinned toolchain, the workspace dependency policy, lint and unsafe-code gates, compile-time SQL verification, advisory and license gates, the mandatory fail-fast verification pipeline, and the four-tier test taxonomy. Every rule is normative: a violation is an acceptance failure, not a style preference.

The upstream Go workflow's rigor is preserved, but every Go mechanism is restated in Rust terms. Where a Go concept has no Rust equivalent, this document says so explicitly rather than inventing a counterpart (§12). Nothing here weakens the boundary contract: this document describes how code is verified; [rust-application-boundaries.md](../architecture/rust-application-boundaries.md) describes what may exist and where it may live.

## 2. Toolchain baseline

### 2.1 `rust-toolchain.toml`

The workspace root contains a `rust-toolchain.toml` that pins the toolchain for every contributor and CI runner:

```toml
[toolchain]
channel = "1.99.1"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

- `channel` is an exact stable release pin (currently `"1.99.1"`); every contributor and CI runner resolves the identical `rustc`. Bumps are deliberate workspace changes that update this file and the doc together. Nightly-only features, `RUSTC_BOOTSTRAP`, and `-Z` flags are prohibited workspace-wide.
- `rustfmt` and `clippy` are mandatory components; `cargo fmt` and `cargo clippy` must work on a fresh `rustup` install without additional components.
- No crate may set `#![feature(…)]`, a per-crate `rust-toolchain` override, or a `build.rs` that requires a non-stable compiler.

### 2.2 MSRV policy

The minimum supported Rust version is the current stable channel at the time a workspace change lands. There is no deliberate MSRV below stable; if a future target requires one, it is declared in the workspace `Cargo.toml` as `rust-version` and enforced by `cargo clippy` (which honors `rust-version`) before use.

## 3. Workspace and dependency policy

### 3.1 Workspace manifest

The workspace root `Cargo.toml` declares all crates under `[workspace.members]`, all shared dependencies under `[workspace.dependencies]`, and all shared lints under `[workspace.lints]` (§5). Member crates declare `dep.workspace = true`; they never restate a version inline.

### 3.2 Exact pinning

- Every entry in `[workspace.dependencies]` uses an exact pinned version (`= "x.y.z"`) or a single-version requirement that resolves identically; `Cargo.lock` is committed and is the authority for resolved versions.
- `cargo build`, `cargo test`, `cargo clippy`, and `cargo sqlx prepare` run with `--locked` in CI so the lockfile is honored.
- `path` dependencies inside the workspace carry no `version` requirement of their own.

### 3.3 Prohibited dependency forms

- **No floating git branches.** Git dependencies are prohibited unless an Accepted ADR names the repository, the exact pinned commit hash, and the justification. A `git = "…"` dependency without a `rev = "<full-commit-sha>"` pin is an acceptance failure; branch or tag pins (`branch`, `tag`) are always prohibited.
- **No unapproved `[patch]`.** A `[patch.crates-io]` (or any `[patch.*]`) section requires an Accepted ADR recording the patched crate, the replacement source, and the removal condition. An unapproved `[patch]` is an acceptance failure.
- **No unvendored binary blobs.** Build scripts may not download artifacts at build time; everything needed to build the workspace offline is in the repository or in the pinned toolchain.
- **No published-crate surface.** `central-rust` produces no public SDK and publishes no crates; `publish = false` on every member crate.

### 3.4 Canonical `sqlx` declaration

`central-adapter-postgres` depends on `sqlx` v0.8+ with exactly this feature set and no others: `postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`. The `migrate` feature is disabled workspace-wide; `sqlx::migrate!`, `Migrator`, and the `_sqlx_migrations` table are prohibited ([postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md) §2.5–§2.6).

## 4. Compile-time SQL verification (replaces `sqlc` generation)

The upstream `sqlc` code-generation step has no Rust equivalent; its role — SQL checked before runtime — is filled by `sqlx` compile-time query macros plus committed offline metadata.

### 4.1 Verification schema provisioning

The canonical, ordered `.sql` files extracted from upstream `baseline.go` (`v0`) and `b08`..`b37` live in the workspace-root `migrations/` directory with an immutable SHA-256 checksum manifest. `migrations/` provisions a local PostgreSQL 16 verification database at the complete `v0..b37` schema state. Extraction is a one-time R1 deliverable; afterwards `migrations/` changes only through explicit forward migrations reviewed like code.

### 4.2 `cargo sqlx prepare`

Every leaf query in `central-adapter-postgres` is a `sqlx::query!` or `sqlx::query_as!` macro invocation checked at compile time against the provisioned `v0..b37` schema. The preparation command:

```bash
cargo sqlx prepare --workspace -- --all-targets
```

writes (or refreshes) the `.sqlx/` metadata directory at the workspace root. `.sqlx/` is committed to the repository; builds and test runs resolve query metadata offline with `SQLX_OFFLINE=true` so a database is not required for ordinary compile/test work.

### 4.3 Clean-preparation requirement

Like the upstream clean-regeneration rule, a change is incomplete if `.sqlx/` is stale: CI runs `cargo sqlx prepare --check --workspace -- --all-targets` and fails on any diff. Contributors never hand-edit `.sqlx/` files; they regenerate them with the verification database running.

### 4.4 Prohibited usage

- The unchecked `sqlx::query()` / `sqlx::query_as()` / `sqlx::query_scalar()` function forms are not used for leaf queries; they bypass compile-time verification.
- Dynamic SQL construction (`format!`, string concatenation, query-builder crates) is prohibited; every statement is a static literal reviewed at compile time.
- `sqlx` migration machinery is prohibited (§3.4); the native `central.schema_migrations` runner is the only migration executor.

## 5. Formatting, lint, and unsafe-code gates

### 5.1 Formatting

`cargo fmt --all` is the only formatter. Rustfmt configuration lives in the workspace-root `rustfmt.toml` (defaults only unless an Accepted ADR records an override). CI runs `cargo fmt --all -- --check`; unformatted code is an acceptance failure.

### 5.2 Workspace lints

The workspace `Cargo.toml` carries `[workspace.lints]` applied to every member. Capability crates (`central-task`, `central-execution`, `central-artifact`, `central-authorization`, `central-checkpoint`, `central-event`, `central-session`, `central-workflow`, and every other `domain`/`port`/`query`/`app` surface), transport crates (`central-transport-http`), the PostgreSQL adapter (`central-adapter-postgres`), object storage (`central-adapter-s3`), and harness crates set:

```toml
[lints.rust]
unsafe_code = "forbid"
```

Only `central-adapter-linux` and the launcher and protected-execution-mode binaries (`bins/`, e.g. `central-harness-launcherd`, `central-migration-launcherd`, and `bins/central`'s helper/broker/sandbox-launcher modes) may contain `unsafe` code, and only inside the audited OS-syscall boundary, expressed through safe `rustix` wrappers rather than raw `libc` calls. `unsafe_code = "forbid"` violations anywhere else are compile errors by construction, not review conventions.

### 5.3 Denied Clippy lints (production targets)

Non-test targets across the workspace deny all five of:

- `clippy::unwrap_used`
- `clippy::expect_used`
- `clippy::panic`
- `clippy::todo`
- `clippy::dbg_macro`

Test targets may relax `unwrap_used`/`expect_used` where a test failure is the intent; `panic`, `todo`, and `dbg_macro` stay denied everywhere. `clippy` also runs with `-D warnings` so every other warning class is a failure.

### 5.4 Compiler warnings

`rustc` warnings are not tolerated: `-D warnings` on the Clippy invocation covers them. `#[allow]` attributes require a reviewable justification comment; `#[allow]` on a boundary-contract rule (§5.2, §5.3) is an acceptance failure.

## 6. Advisory, license, and supply-chain gates — `cargo deny`

`cargo deny check` runs in the mandatory pipeline (§7) and enforces four checks:

1. **Licenses.** An allowlist of `MIT`, `Apache-2.0`, `BSD-3-Clause` (and compatible `MIT OR Apache-2.0` dual forms). Any other license, an unlicensed crate, or an unresolvable license expression fails.
2. **Sources.** Registry crates come only from `crates.io`; git dependencies are banned unless pinned to a full commit hash under an Accepted ADR (§3.3). Unknown registries and unpatched overrides fail.
3. **Advisories.** The RustSec advisory database is checked; any `RUSTSEC`/`GHSA`/`CVE` advisory on a resolved version fails the build until the dependency is bumped or an accepted, recorded exception applies.
4. **Bans and duplicates.** Deny-listed crates (anything known to conflict with Central constraints) and unexpected duplicate major versions fail; expected duplicates are individually recorded in `deny.toml`.

`deny.toml` is committed at the workspace root and is itself reviewed like code. The upstream `govulncheck` step has no direct Rust equivalent; `cargo deny check advisories` plus `cargo audit` are its replacement.

## 7. Mandatory fail-fast verification pipeline

Every PR runs these commands in exactly this order; the pipeline stops at the first failure:

```bash
# 1. Offline SQL metadata is in sync with compile-time-checked queries
cargo sqlx prepare --check --workspace -- --all-targets

# 2. Formatting
cargo fmt --all -- --check

# 3. Lints and warnings (all targets, all features, warnings as errors)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 4. Licenses, source restrictions, RustSec advisories, bans/duplicates
cargo deny check

# 5. Tests
cargo test --workspace
```

- `--locked` is implied in CI; the lockfile is honored.
- A green pipeline run is recorded per merge. Skipping a stage — e.g., running `cargo test` before `clippy` — is an acceptance failure because later stages assume earlier guarantees.
- `cargo sqlx prepare --check` runs against committed `.sqlx/`; the provisioning database is required only when `.sqlx/` must be regenerated (§4.3).

## 8. Test taxonomy

Four tiers, run in the order listed; each tier gates the next.

### 8.1 Tier 1 — Pure synchronous domain unit tests

Domain crates are synchronous and I/O-free by construction (boundary contract §2). Unit tests exercise value objects, state machines, failure taxonomy, validation, and pure coordination decisions with no clock, no network, no filesystem, and no database. They run under `cargo test` everywhere.

### 8.2 Tier 2 — Deterministic PostgreSQL/MinIO integration suites

`central-adapter-postgres` integration suites run against a local PostgreSQL 16 instance provisioned at `v0..b37` by `migrations/`; `central-adapter-s3` suites run against a local MinIO container. They verify change-set commit semantics, constraint/CAS behavior, receipt replay, outbox claim/settle, lease fencing, and migration-runner lifecycle end to end — with real database time, real advisory locks, and deterministic seeded data. These suites are deterministic: no wall-clock sleeps govern assertions; they poll for observable state.

### 8.3 Tier 3 — Reference-host Linux security and launcher suites

The audited syscall boundary (`central-adapter-linux`) and the launcher binaries run dedicated suites on the reference host: peer-credential verification, `SCM_RIGHTS`/`memfd` handoff, PAM/TTY ceremony, grant and wipe flows, TLS leaf signing, and the no-auto-migrate guarantee. They run only on the pinned reference-host profile, not on arbitrary developer machines.

### 8.4 Tier 4 — Playwright SSR browser acceptance

Wired since R3 closeout. `tests/acceptance/playwright/` drives the server-rendered surfaces end to end against a live `central serve`: bootstrap exchange and session delivery, pre-auth CSRF handling, the task list/detail pages, the harness resolve panel ("Mark cancelled" settles an ambiguous attempt), the permission approve/deny PRG flow, artifact preview/download against the object store, and an accessibility smoke pass (landmarks, labels, required markers, skip link). `scripts/r3-acceptance.sh` is the bounded runner: it provisions a scratch database through the native migration runner, starts `central serve` with `CENTRAL_LOCALEXEC=1`, waits for `/health/ready`, seeds the rerunnable fixtures in `tests/acceptance/seed.sql` (plus the artifact object body when `CENTRAL_TEST_MINIO_ENDPOINT` or the `adobe/s3mock` fallback supplies an S3 endpoint), runs Playwright, and tears down with bounded timeouts and meaningful exit codes.

## 9. Change rules

### 9.1 One coherent vertical slice per PR

Each change lands a complete vertical slice across its affected crates: capability `domain`/`port`/`query`/`app`, adapter implementation, `migrations/` forward step, `.sqlx/` regeneration, tests, and documentation in one commit series. Partial migrations, dangling `port.rs` traits with no adapter, or `.sqlx/` drift are acceptance failures.

### 9.2 Migration, code, and test atomicity

Every schema change ships with (a) the new ordered `.sql` file under `migrations/`, (b) the checksum-manifest update, (c) the native-runner expectation update, (d) regenerated `.sqlx/` metadata, and (e) the adapter test covering it — in the same change. The migration and the code that consumes it are never split across merges.

### 9.3 Required documentation updates

A change that alters a contract documented under `docs/` updates the document in the same change. Boundary-contract, adapter-mapping, and workflow changes are never allowed to drift ahead of the code that realizes them.

### 9.4 Branch naming

`r<phase>-<slice>-<slug>` (e.g. `r1-postgres-extraction`) matches the R-slice ownership in the boundary contract; `docs/` or `chore/` prefixes apply to documentation-only and maintenance changes.

### 9.5 Pre-merge checklist

- Pipeline §7 green on the exact commit being merged.
- `Cargo.lock`, `migrations/` manifest, and `.sqlx/` diff-free after regeneration.
- No new `unsafe` outside the audited boundary; no new dependency outside `[workspace.dependencies]`; no `[patch]` or floating git pin.
- Acceptance evidence recorded for the owning R-slice.

## 10. Profiling

Profiling is exceptional, not routine:

- **Trigger.** Only when an R-slice acceptance bound, an `EXPLAIN` evidence row, or a resource-cap check fails, or when a maintainer requests it.
- **Pinned tools.** `cargo bench` (criterion), `tokio-console` for async visibility, `pg_stat_statements`/`EXPLAIN (ANALYZE, BUFFERS)` for SQL, and the pinned container tooling for I/O evidence. No ad-hoc instrumentation is committed.
- **Bounded duration.** A profiling run is time-boxed; its evidence is recorded in the slice's acceptance record and the instrumentation is removed before merge.
- **Sensitive-payload exclusion.** Profiles, traces, and flame graphs never contain secrets, session/bootstrap material, or object payloads.

## 11. Dependency-advisory ownership and version-change rules

### 11.1 Owner

The workspace root `Cargo.toml` + `deny.toml` pair is owned by the maintainer; the R0–R6 delivery plan assigns caretaking to the slice that touches a dependency. The person landing a change runs `cargo deny check` and owns any advisory fallout until merge.

### 11.2 Version-change rules

- Bump one dependency per change unless an Accepted ADR justifies a coordinated bump.
- Record the resolved version in `Cargo.lock`; never hand-edit it.
- No downgrade of a pinned version to silence an advisory; the fix is a forward bump or an accepted exception.
- A dependency added to support one crate is declared in `[workspace.dependencies]` and consumed as `dep.workspace = true`.

### 11.3 Floating-branch and `[patch]` prohibition

Restated from §3.3: floating git branches, tags, or unpinned `rev` are always prohibited; `[patch]` requires an Accepted ADR. `cargo deny check` fails on violations.

## 12. Go-concept parity table

Where an upstream Go mechanism has no Rust equivalent, the equivalent is stated explicitly; where there is none, it is named as absent:

| Upstream Go mechanism | Rust equivalent |
| --- | --- |
| `go.mod` + vendored `vendor/` | Workspace `Cargo.toml` + committed `Cargo.lock` (no vendoring requirement; `cargo` resolves from the lockfile) |
| `go fmt` / `goimports` | `cargo fmt` (rustfmt only; no import-sorter exists — `rustfmt` covers imports) |
| `go vet` | Covered by `cargo clippy -D warnings` + rustc lints; there is no separate vet-equivalent pass |
| `golangci-lint` | `cargo clippy` workspace lints (§5) |
| `govulncheck` | `cargo deny check advisories` (+ `cargo audit` equivalent) |
| `sqlc` generation | `sqlx::query!`/`query_as!` compile-time macros + `.sqlx/` offline metadata (§4) |
| `golang-migrate` driver + `Force`/`Drop` | Native `central.schema_migrations` runner; `Force`/`Drop`/`_sqlx_migrations` prohibited (§4.4, §9.6 of the mapping doc) |
| `pgx/v5` driver | `sqlx` (`PgPool`/`PgConnection`) (§3.4) |
| `gin` HTTP | `axum` + `askama` SSR in `central-transport-http` (R3; not yet implemented) |
| `remark-cli` markdown/link check | Retained — language-independent; same tool, same CI position |
| Secret-sentinel scan | Retained — language-independent; same coverage rules (§13 below) |
| Architecture-import checks (`archguard` tests) | Cargo dependency graph + `[workspace.lints]`; capability crates cannot even name forbidden crates because they are not declared as dependencies |

## 13. Secret-sentinel coverage

The upstream sentinel scan is carried over unchanged in intent: no credentials, tokens, `.env` files, private keys, connection strings, or session/bootstrap material may be committed anywhere in the repository — including `migrations/`, `.sqlx/`, fixtures, testdata, and CI configuration. The scan runs as part of CI; a sentinel hit is a merge blocker, not a warning.

## 14. Architecture enforcement detection list

Cargo makes most upstream import rules structural: a capability crate physically cannot import `sqlx`, `axum`, S3 SDKs, or `rustix` unless its `Cargo.toml` declares them, so review focuses on the manifest plus `#[allow]`/feature gates rather than import scans. The standing detection list:

1. **Forbidden dependencies in capability manifests.** `sqlx`, `axum`, `tokio` (in `domain`/`port`/`query`), S3 SDKs, `rustix`, and `unsafe` may not appear in capability `Cargo.toml`s except where the boundary contract assigns the crate (§5.2).
2. **`unsafe` outside `central-adapter-linux` and the launcher/protected-execution-mode binaries.** Compile-enforced by `unsafe_code = "forbid"`; any `#[allow(unsafe_code)]` override is an acceptance failure.
3. **`sqlx` types in public port/query signatures.** `sqlx::Transaction`, `PgPool`, `PgConnection`, `sqlx::Error`, and `sqlx::types::*` must never appear in `port.rs`/`query.rs` or cross the adapter boundary.
4. **Dynamic SQL and prohibited query forms.** `format!`/`format_args!` on SQL text, `sqlx::query()`/`query_as()` function forms, and any non-macro query construction (§4.4).
5. **Prohibited query shapes.** Offset pagination, N+1, readiness exact counts, unbounded results, unqualified names, `public` schema (mapping doc §2.1).
6. **Migration framework bypass.** `sqlx::migrate!`, `Migrator`, `_sqlx_migrations`, external `migrate` CLIs, generic `Force`/`Drop` (mapping doc §9.6).
7. **Panic-class lints in production code.** `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro` (§5.3).
8. **Manifest drift.** New crate without boundary-contract provenance; `[patch]` without ADR; floating git pins; unlisted feature additions (§3, §11).
9. **Adapter leaking into kernel composition.** `central-kernel` composes through `port.rs` traits only; a direct `sqlx`/`s3`/`linux` dependency in its manifest is an acceptance failure.
10. **Async in domain roots.** `async fn`/`tokio`/`futures` in capability `domain`/`port`/`query` crates — domain roots are synchronous.

## 15. Tool version appendix

| Tool | Required form | Enforcement |
| --- | --- | --- |
| `rustc`/`cargo` | `rust-toolchain.toml` stable + `rustfmt`, `clippy` | rustup resolves; CI logs the resolved version |
| `cargo fmt` | `cargo fmt --all` | §5.1 |
| `cargo clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | §5.3, §7 |
| `cargo sqlx` (CLI) | `cargo sqlx prepare [--check] --workspace -- --all-targets` | §4, §7 |
| `cargo deny` | `cargo deny check` with committed `deny.toml` | §6, §7 |
| `cargo test` | `cargo test --workspace` | §7, §8 |
| `docker`/`minio`/`postgres 16` fixtures | R5 local-topology slice (see `local-development-environment.md`) | §8.2 |
| `playwright` | Tier-4 SSR acceptance (R3 onward) | §8.4 |

## 16. References

- [Rust Application Boundaries — Canonical Contract](../architecture/rust-application-boundaries.md)
- [PostgreSQL Adapter Mapping — Canonical Contract](../persistence/postgresql-adapter-mapping.md)
- [PostgreSQL Persistence Contract](../persistence/postgresql.md)
- [Migration and Recovery Contract](../persistence/migrations-and-recovery.md)
- [Central-Rust Documentation and Architecture Design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md)
- [ADR 0043 — Adopt Rust Workspace and Harness-First Porting Strategy](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md)
- [ADR 0007 — Adopt PostgreSQL Persistence and Recovery Contracts](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md)
- [ADR 0009 — Adopt Local Development Environment Topology](../adr/0009-adopt-local-development-environment-topology.md)
- `docs/implementation/current-phase.md` — current implementation scope (Task 5 deliverable)
- `docs/implementation/rust-vertical-slice-roadmap.md` — R1–R6 slice ownership (Task 5 deliverable)
