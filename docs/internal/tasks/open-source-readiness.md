# Open-source readiness — what `central-rust` still needs before the visibility flip

- **Type:** Readiness checklist (maintainer-owned), recorded 2026-10-30.
- **Goal:** publish `central-rust` as an open-source project that an outside user can clone, build, install, and contribute to.
- **Status:** Open. Items are ordered by phase; a phase should not start before the previous one's blockers close.
- **Evidence basis:** repository inspection on 2026-10-30 (tree, `git log`, `Cargo.toml`, ADRs 0040–0044, `current-phase.md`, `vm-ref-host-2026-10-29-findings.md`). No build or test run was part of this inspection.

## Phase 0 — Maintainer decisions (gate everything else)

- [x] **ADR 0040 Accepted (2026-10-30)** (DCO + licenses).
- [x] **License mismatch resolved (2026-10-30):** maintainer chose dual `MIT OR Apache-2.0` for `central-rust`; recorded as an amendment in ADR 0040. `Cargo.toml` already matches.
- [x] **Public repo name chosen (2026-10-30):** `enolalab/central-workspace`; recorded as an amendment in ADR 0041, README clone URL updated.
- [x] **ADR 0041 Accepted (2026-10-30).**
- [x] **GitHub repo renamed** `enolalab/central-r` → `enolalab/central-workspace` and local remote updated (2026-10-30; `git ls-remote` verified).
- [x] **ADR 0042 applied to this repo (2026-10-30):** amendment records the repo-specific inputs; agent `Co-Authored-By` trailers are **kept**.
- [x] **ADR 0044 Accepted (2026-10-30)** (fixed broker seccomp list).

## Phase 1 — Legal and community files

- [x] `LICENSE-MIT` + `LICENSE-APACHE` (dual license per the ADR 0040 amendment; verbatim standard texts) and README "License" section with the dual-license contribution clause + DCO line — done 2026-10-30.
- [ ] `NOTICE` and `THIRD_PARTY_LICENSES` — generate from `Cargo.lock` (e.g. `cargo about`); `cargo deny check licenses` must stay clean. Adding a tool requires asking first (dependency rule in `CLAUDE.md`).
- [ ] `CONTRIBUTING.md` — build/test commands from `CLAUDE.md` §Commands, DCO `Signed-off-by` requirement, the ADR process.
- [ ] `SECURITY.md` — private vulnerability-reporting channel (GitHub private advisories), supported versions. This project ships root helpers, a protected broker, and PAM code; a disclosure policy is mandatory.
- [ ] `CODE_OF_CONDUCT.md`.
- [ ] Per-crate `Cargo.toml` metadata: `repository`, `description`, `license` inherited from the workspace; `publish = false` on crates not meant for crates.io.

## Phase 2 — Repository hygiene (tree, then history)

- [ ] **Scrub personal paths from tracked files.** `git grep "/home/<maintainer>"` hits at least 10 files: `docs/implementation/roadmap-dashboard.html`, every `docs/internal/superpowers/plans/2026-10-2*.md`, and `specs/2026-10-21-central-rust-documentation-and-architecture-design.md`. Apply the ADR 0042 amendment mapping (`/home/<maintainer>` → `~`, etc.).
- [ ] **Add a hygiene regression gate** — a Rust-repo equivalent of upstream `ci/check-repo-hygiene.sh`.
- [ ] **Add `.gitleaks.toml` and run a full-history gitleaks scan**; triage every finding (upstream model: `docs/security/gitleaks-triage.md`).
- [ ] **Review `docs/internal/`** (plans, specs, evidence, tasks, `.superpowers/`, `.devin/`): decide what is published, moved, or removed. Internal review records written for a private process are explicitly called out in ADR 0042's context.
- [ ] **History rewrite** (destructive — requires explicit maintainer go-ahead at execution time):
  - all 297 commits carry the personal Gmail address as author → `--mailmap` to the public noreply identity;
  - 61 commit messages carry `Co-Authored-By: Devin` trailers → **kept** (ADR 0042 amendment);
  - personal paths in historical blobs → `--replace-text`;
  - no blob over 1 MB exists in history today (checked 2026-10-30), so no blob stripping is expected.
  - Backup first: `git clone --mirror` + `git bundle` + keep `commit-map`/`ref-map` (ADR 0042 decision 5). Run in a fresh clone, never in this worktree.
- [ ] Post-rewrite gates: gitleaks 0, `git log --all --format='%ae%n%ce' | sort -u` shows no personal email, identifier greps on messages and filenames return 0, `cargo build --workspace` + `cargo test --workspace` green on the rewritten HEAD.

## Phase 3 — CI and release pipeline

- [ ] **CI does not exist** (no `.github/workflows/`). Add jobs for the §7 fail-fast pipeline: `cargo sqlx prepare --check` → `fmt --check` → `clippy -D warnings` → `deny check` → `test --workspace`.
- [ ] A CI job with PostgreSQL 16 + MinIO services so the `CENTRAL_TEST_DSN` / `CENTRAL_TEST_MINIO_ENDPOINT`-gated suites actually run, not skip.
- [ ] DCO check on pull requests (ADR 0040 follow-up).
- [ ] Hygiene + gitleaks jobs from Phase 2.
- [ ] Branch protection on `main` (required checks, no force-push after the rewrite).
- [ ] Release workflow: tagged builds of `bins/*`, checksums, signed artifacts (signatures are lost by the rewrite — re-establish after it, per ADR 0042).
- [ ] Packaging: `packaging/systemd` exists; decide distribution format (tarball + install script, `.deb`, or both) and document it.

## Phase 4 — An outside user can actually install it

- [ ] **Public dependency images.** `central-local-infra` on GHCR is private (`denied` without a token — VM finding V7). Either publish it (requires its own ADR 0040 work: madmin-go replacement, license files, history rewrite) or document building it locally.
- [ ] **Port the attestation-key generation tool.** Without a key a host is import-only (`PREPARE_UNAVAILABLE`), so a self-builder cannot complete `local prepare`.
- [ ] **Release-authority custody for the public project** — who signs advisories/releases, where the key lives (`docs/operations/release-authority-custody.md`, ADR 0039).
- [ ] **Clean-host end-to-end run from a fresh clone:** `local init → prepare → up → migrate → serve → run submit → artifact read → backup → restore → down`, recorded as evidence. Today the reference VM reaches `MIGRATION_REQUIRED` with VM-only lock edits.
- [ ] **Operator traps from V7** — make `local doctor` detect Docker-created directories at secret/socket paths, or have `local up` refuse with a clear reason.
- [ ] `local doctor --host-prerequisites` reports `ok` on unsupported hosts — fix before users rely on it.

## Phase 5 — Public-facing documentation

- [ ] `README.md` rewritten for outsiders: what Central is, status/maturity disclaimer (pre-1.0, Linux-only, root components), quick start, link to the install guide.
- [ ] Verify `docs/operations/user-install-guide.md` (+ `.vi.md`) against the Phase 4 clean-host run.
- [ ] Remove or clearly mark internal-only links (upstream `central` records referenced throughout `docs/product/roadmap.md`) that outsiders cannot open.
- [ ] Threat model and capability policy (`docs/security/`) reviewed for publication — the root helper and broker will attract scrutiny.

## Phase 6 — Visibility flip

- [ ] All Phase 0–5 boxes checked.
- [ ] Close or land open branches/PRs (rewritten history cannot migrate them).
- [ ] Flip visibility; send the re-clone notice to every existing clone.
- [ ] Tag the first public release (`v0.1.0`) from the CI release workflow.

## Optional before the flip (credibility, not blockers)

- Independent (non-self-issued) review of the Slice C/D/E acceptance verdicts.
- Tier-3 physical-console evidence (`physical_tty` ceremony, `deferred-physical` criteria).
- Phase 1 performance/resource suite evidence.
