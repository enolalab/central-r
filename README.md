# Central (Rust)

**Central** is a local-first durable AI workspace. It coordinates agents and
subagents doing long-running work on your local data, tools, and
infrastructure. You can watch its state, checkpoint it, resume it, and manage
the artifacts it produces.

This repository (`central-rust`) is the full-parity Rust reimplementation of
the upstream Go `central` codebase. It is delivered as the `R0`–`R6`
vertical-slice sequence defined by
[ADR 0043](docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md).

> **Status:** pre-release. **The `R0`–`R6` sequence is complete**, followed by
> the post-R6 `lifecycle-composition` slice (broker-backed `local up|down|status`
> and the `bind_postgres_service_role` writer). Commands whose slice is not yet
> accepted (e.g. `local browser open`) exit with code `5` /
> `UNSUPPORTED_IN_THIS_SLICE` and change nothing.

---

## Goals

Central is not a chat interface. Its core abstraction is a **durable task or
workflow** with an explicit lifecycle, tools, outputs, and recovery behavior.

| Principle | What it means |
| --- | --- |
| **Local first** | Runs without a hosted control plane, so sensitive resources stay on your machine or network. |
| **Durable by default** | Important work survives process, worker, model, and network failures. |
| **Observable execution** | Plans, steps, state transitions, artifacts, failures, and costs can all be inspected. |
| **Controlled agency** | Privileged tools are permissioned, scoped, and gated by approval policies. |
| **Portable integrations** | Models, agents, and tools can be swapped through stable contracts. |
| **Cloud optionality** | The same concepts can later support hybrid and hosted execution (Central Server / Online Mode). |

Core capabilities:

- Task lifecycle instead of short-lived chat turns
- Multi-agent orchestration over dependency graphs (DAG workflows)
- Persisted checkpoints and resumable runs
- Artifact metadata and lineage in PostgreSQL, artifact bodies in S3-compatible storage
- Harness sessions for Claude Code, OpenCode, Codex, and Antigravity
- Approval boundaries for risky operations

See [docs/product/vision.md](docs/product/vision.md) for the full product
definition.

## Architecture at a glance

- **Language:** Rust, in a single Cargo Workspace (toolchain pinned in `rust-toolchain.toml`)
- **Database:** PostgreSQL 16 via `sqlx` compile-time-checked queries, with committed `.sqlx/` offline metadata
- **Artifact storage:** S3-compatible storage (`aws-sdk-s3`), with MinIO for local development
- **Web UI:** server-rendered HTML (`axum` + `askama`) with minimal JavaScript
- **Linux security boundary:** `rustix`, confined to `central-adapter-linux` and the launcher binaries
- **Local infrastructure:** Docker Compose (a digest-pinned, six-service topology)

```
crates/
  central-foundation/          identity (UUIDv7 newtypes), failure taxonomy, JCS
  capabilities/central-*/      domain crates: domain.rs · port.rs · query.rs · app.rs
  adapters/
    central-adapter-postgres/  sqlx stores + native migration runner
    central-adapter-s3/        S3/MinIO object storage
    central-adapter-harness/   Claude Code / OpenCode / Codex / Antigravity adapters
    central-adapter-linux/     audited OS boundary (broker, memfd, SCM_RIGHTS, PAM/TTY)
  transport/central-transport-http/  API v1 JSON, SSR Web UI, health & metrics
  central-kernel/              composition root, supervised runner, graceful shutdown
bins/                          central, launcher daemons, migrate/backup/restore tools
migrations/                    canonical v0..b37 SQL + checksum manifest
docs/                          product, architecture, ADRs, contracts, roadmap
```

Further reading: [architecture overview](docs/architecture/overview.md),
[durable execution](docs/architecture/durable-execution.md),
[Rust application boundaries](docs/architecture/rust-application-boundaries.md),
and the [newcomer guide](docs/newcomer-guide.md).

## Getting started (development)

### Prerequisites

- Linux (the host-authority and launcher features require Linux)
- The Rust toolchain from `rust-toolchain.toml` (`rustup` installs it automatically)
- PostgreSQL 16 and MinIO, needed only for the gated integration suites
- `sqlx-cli` and `cargo-deny`, needed only for the full verification pipeline

### Build and test

```bash
git clone https://github.com/enolalab/central-r.git
cd central-r

cargo build --workspace            # compile check
cargo test -p central-task         # test one crate (the usual inner loop)
```

### Full verification pipeline

This is the fail-fast order from
[rust-engineering-workflow.md](docs/implementation/rust-engineering-workflow.md) §7:

```bash
cargo sqlx prepare --check --workspace -- --all-targets && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets --all-features -- -D warnings && \
cargo deny check && \
cargo test --workspace
```

The PostgreSQL and MinIO integration suites run only when you set
`CENTRAL_TEST_DSN` / `CENTRAL_TEST_MINIO_ENDPOINT`. Root-only Tier 3 platform
tests also need `CENTRAL_TIER3=1` and the pinned reference host. If those
aren't set, the suites skip themselves, and that's expected.

After you change a checked SQL query, regenerate `.sqlx/` against a database
provisioned from `migrations/`:

```bash
cargo sqlx prepare --workspace -- --all-targets
```

### Main CLI surface

`bins/central` provides `serve`, `run submit`, `node decide`, `checkpoint *`,
`artifact read`, `local init|prepare|up|down|status|doctor`, `migrate *`,
`backup *`, and `restore *`, plus the protected `helper`,
`central-protected-broker`, and `central-sandbox-launcher` modes. For install
and operations, see [docs/operations/](docs/operations/) and
[known limitations](docs/known-limitations.md).

## Roadmap and progress

The slices are delivered in order. Each one lands complete: domain, adapters,
schema authority, `.sqlx/`, tests, and docs. The full roadmap is in
[rust-vertical-slice-roadmap.md](docs/implementation/rust-vertical-slice-roadmap.md),
and the live scope is in [current-phase.md](docs/implementation/current-phase.md).

| Slice | Scope | Status |
| --- | --- | --- |
| **R0** | Documentation and contract baseline: ported contracts, ADRs 0001–0043 | ✅ Complete |
| **R1** | Workspace scaffold, `v0..b37` SQL extraction, native migration runner, durable Task/Execution core | ✅ Complete |
| **R2** | Verified artifact lifecycle and S3/MinIO object storage | ✅ Complete |
| **R3** | Harness control plane (4 adapters), `central serve`, API v1 + SSR Web UI, harness launcher | ✅ Complete |
| **R4** | Multi-agent workflow orchestration (Phase 2 slices 2A–2F) and the 23-scenario recovery matrix | ✅ Complete |
| **R5** | Host authority, protected broker, audited Linux boundary, six-service Compose topology | ✅ Complete |
| **R6** | Backup, restore, wipe, maintenance, and launcher daemons | ✅ Complete |
| **LC** | Post-R6 lifecycle composition: broker `bind_postgres_service_role`, service-role credential store, compose/bootstrap decorations, helper-daemon `local up\|down\|status` | ✅ Complete |

```
R0 ██████████ R1 ██████████ R2 ██████████ R3 ██████████
R4 ██████████ R5 ██████████ R6 ██████████ LC ██████████   (16 / 16 + 5 / 5 tasks)
```

### Phase R6 progress

All 16 tasks are done: migrate CLI and launcher daemons, backup/restore domain
and evidence stores, broker recovery authority, C01–C06 recovery flows and
acceptance, wipe/reseed and delete/prune (D01/D04), `bx1` export/import
(D02/D03), audit/rescue/security update (D05/D06), D07 acceptance, maintenance
and `central-advisory-sign` (E01–E04), and the E05/E06 closeout.

### Post-R6: lifecycle composition

| # | Task | Status |
| --- | --- | --- |
| LC-T1 | Broker `bind_postgres_service_role` writer arm | ✅ Done |
| LC-T2 | Service-role credential store + `pg_wire` rotate-then-sync | ✅ Done |
| LC-T3 | Compose/bootstrap decorations, rendezvous, client authority impls | ✅ Done |
| LC-T4 | Helper-daemon lifecycle composition (`local up\|down\|status` live) | ✅ Done |
| LC-T5 | Closeout: R6 deferral resolved, `current-phase.md` updated | ✅ Done |

Prepare promotion/attestation (journal, attestation, image load, release import/export) landed on `prepare-promotion`. Still deferred: `local browser open` and the
root/Tier-3 physical evidence tiers.

**After R6:** the Rust port has reached full parity with upstream. The product
roadmap then continues toward hybrid execution and Central Server / Online Mode
(see [docs/product/roadmap.md](docs/product/roadmap.md) and
[docs/architecture/online-mode.md](docs/architecture/online-mode.md)).

To regenerate the HTML progress dashboard:

```bash
python3 scripts/roadmap-dashboard.py
```

## Contributing

- Read [AGENTS.md](AGENTS.md) before making architectural changes. It covers
  the required reading, architectural rules, and definition of done.
- Hard constraints:
  - PostgreSQL only.
  - Artifact metadata goes in PostgreSQL; artifact bodies go in object storage.
  - Every schema change needs a migration.
  - Task transitions must go through the task domain service.
  - Retriable operations must be idempotent.
- Never commit credentials, tokens, or `.env` files, and never weaken
  permission checks to make tests pass.

## License

Dual-licensed under **MIT OR Apache-2.0**.
