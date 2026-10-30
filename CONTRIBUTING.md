# Contributing to Central

Thanks for your interest in Central. This document explains how to
build, test, and submit changes. By participating you agree to follow
the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues go through
[SECURITY.md](SECURITY.md), never a public issue.

## Before you start

- For anything beyond a small fix, open an issue first so the approach
  can be agreed before you write code.
- Read [AGENTS.md](AGENTS.md) for the architectural rules and the
  definition of done, and
  [`docs/implementation/rust-engineering-workflow.md`](docs/implementation/rust-engineering-workflow.md)
  for the verification pipeline and test tiers.
- Changes to the schema, task lifecycle, storage layout, wire formats,
  or a security boundary need an ADR under [`docs/adr/`](docs/adr/)
  (copy `template.md`, status `Proposed`). The maintainer decides ADRs.
- New dependencies and version bumps are discussed in the issue first.
  Shared versions are pinned in `[workspace.dependencies]` and the
  committed `Cargo.lock`.

## Hard constraints

- PostgreSQL only. Artifact metadata in PostgreSQL, artifact bodies in
  object storage — never payloads in the database.
- Every schema change ships with a forward migration under
  `migrations/`.
- SQL goes through compile-time-checked `sqlx::query!`/`query_as!`
  macros; regenerate `.sqlx/` when a checked query changes.
- Task transitions go through the task domain service; retriable
  operations must be idempotent.
- Never weaken a permission, peer-authorization, or ceremony check to
  make a test pass. Never commit credentials, tokens, or `.env` files.

## Build and test

```bash
cargo build --workspace                  # compile check
cargo test -p central-<crate>            # the usual inner loop
```

Before opening a pull request, run the full fail-fast pipeline:

```bash
cargo sqlx prepare --check --workspace -- --all-targets && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets --all-features -- -D warnings && \
cargo deny check && \
cargo test --workspace
```

PostgreSQL/MinIO integration suites run when `CENTRAL_TEST_DSN` /
`CENTRAL_TEST_MINIO_ENDPOINT` are set and skip otherwise. Root-required
and reference-host (Tier 3) tests skip automatically as non-root; that
skip is expected.

## Commits and pull requests

- Keep each pull request to one coherent change; no unrelated
  refactors.
- Write commit messages that explain *why*, in the existing
  `type(scope): summary` style (see `git log`).
- Update documentation when behavior or architecture changes.

### Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```text
Signed-off-by: Your Name <you@example.com>
```

Add it automatically with `git commit -s`. Pull requests with unsigned
commits cannot be merged. There is no CLA.

## License

Central is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option
([ADR 0040](docs/adr/0040-adopt-apache-2-0-licenses-and-dco-contributor-terms.md)).
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
