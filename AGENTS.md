# Central Agent Instructions

## Project

Central is a local-first durable AI workspace written primarily in Rust. It coordinates agents and subagents, persists task state in PostgreSQL, stores artifacts in S3-compatible object storage, and supports checkpoint, retry, and resume after failures.

The long-term product includes a Central Server and Online Mode, but current implementation work must prioritize the local-first runtime.

This repository (`central-rust`) is the full-parity Rust reimplementation of the upstream Go `central` codebase, delivered as the `R0`–`R6` vertical-slice sequence recorded by Accepted [ADR 0043](docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md).

## Required reading

Before architectural changes, read:

1. `docs/product/vision.md`
2. `docs/product/roadmap.md`
3. `docs/architecture/overview.md`
4. `docs/architecture/durable-execution.md`
5. `docs/architecture/rust-application-boundaries.md`
6. `docs/implementation/rust-engineering-workflow.md`
7. Relevant ADRs under `docs/adr/` when present

Current implementation scope is defined in `docs/implementation/current-phase.md`; the `R0`–`R6` delivery sequence is defined in `docs/implementation/rust-vertical-slice-roadmap.md`.

## Technology constraints

- Main language: Rust (single Cargo Workspace)
- Database: PostgreSQL 16 (`sqlx` compile-time checked queries with committed `.sqlx/` offline metadata)
- Artifact storage: S3-compatible storage (`aws-sdk-s3`), MinIO for local development
- Web UI: server-rendered HTML (`axum` + `askama`) with minimal JavaScript
- Linux security boundaries: `rustix` safe wrappers, isolated to `central-adapter-linux` and the launcher binaries
- Local infrastructure: Docker Compose

Do not replace PostgreSQL with SQLite. Do not store artifact payloads directly in PostgreSQL; store metadata in PostgreSQL and bodies in object storage.

## Architectural rules

- Domain packages own their interfaces and business rules.
- Infrastructure adapters must not leak concrete database or object-storage types into domain APIs.
- Task transitions must go through the task domain service.
- Retriable operations must be idempotent.
- Long-running operations must define persisted input, current state, retry policy, produced artifacts, failure reason, and resume behavior.
- A task is complete only after required artifacts and final state are durably persisted.

## Development workflow

For non-trivial work:

1. Read the active task and linked architecture documents.
2. Inspect the repository before editing.
3. Propose a concise plan.
4. Implement the smallest complete vertical slice.
5. Run formatting, tests, and static analysis.
6. Update documentation when behavior or architecture changes.
7. Report changed files, executed checks, and remaining risks.

Do not make unrelated refactors. Do not claim a command passed unless it was executed.

## Database and artifact rules

- Every schema change requires a migration.
- Use transactions for atomic state transitions.
- In-memory state is never the source of truth for durable tasks.
- Every artifact should include IDs for workspace, task, run, and producer, plus object key, media type, size, checksum, timestamp, and lineage where applicable.
- Object keys must not expose secrets or unsanitized sensitive filenames.

## Security

- Never commit credentials, tokens, `.env` files, or private data.
- Treat shell, filesystem, network, and database access as privileged tools.
- Do not weaken permission checks to make tests pass.
- Require explicit approval before destructive production actions.

## Delegation for cross-repository and security-adjacent fixes (ADR 0028, D3)

The agent may apply a fix unilaterally, in this repository or in `central-local-infra`, when **all** of the following hold:

1. It does not weaken any permission, peer-authorization or ceremony check.
2. It does not change a wire format or an Accepted ADR's decision.
3. It is covered by a test that fails before and passes after.
4. It is recorded under `docs/internal/tasks/` with the same "What a fix requires" analysis the SC-DEF series uses (SC-DEF-23 direction 1 is the model).

When 1 or 2 would be violated, the agent writes the ADR as Proposed **without blocking on it** and continues on every path the decision does not gate; ADR acceptance stays with the maintainer and is the one asynchronous human act. A defect that needs a ruling is not left open: it is either fixed under the four criteria or carried by a Proposed ADR.

## Definition of done

A task is done only when requested behavior is implemented, relevant tests pass, formatting and linting pass, migrations are included when needed, failure and resume behavior are considered, and documentation reflects the resulting behavior.
