# ADR 0042: Rewrite git history with `git filter-repo` once, before the visibility flip

- **Number:** 0042
- **Title:** Rewrite git history with `git filter-repo` once, before the visibility flip
- **Status:** Accepted
- **Created:** 2026-10-04
- **Owners:** Central maintainer
- **Decision due:** 2026-10-11
- **Decision due history:** None
- **Implementation blocked at:** The rewrite-day force-push and the #56
  visibility flip — both still require the maintainer's explicit
  go-ahead at execution time (backup verification precedes the push
  per `docs/internal/superpowers/plans/2026-10-05-history-rewrite-execution.md`).
  The rewrite itself is unblocked by this acceptance.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-10-05)
- **Decision date:** 2026-10-05
- **Decision record:** Maintainer approval in session on 2026-10-05
  ("accept giúp tôi đi"); status transition committed by the agent in
  this dedicated commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/internal/superpowers/specs/2026-10-04-history-strategy-design.md`;
  `docs/internal/superpowers/plans/2026-10-04-history-strategy.md`;
  enolalab/central issues #40 (this decision), #43, #44, #56

## Context

Both repositories will be flipped public under issue #56. Their git
histories contain material that should not be published:

- ~20 MB of large dead blobs committed briefly in July and later
  deleted (`broker.test` ~7.6 MB, `central` ~6.9 MB, `dev/null`
  ~5.4 MB, evidence ~5.2 MB) — dead weight every clone pays for
  forever.
- Personal identifiers: the maintainer's pre-rewrite home-directory
  paths (`/home/<user>` form) in file contents and the maintainer's
  personal Gmail address in commit author/committer headers.
- `Claude-Session:` agent-harness URLs in 694 commit messages.
- Internal gate/review records written for a private development
  process.

The full-history gitleaks triage (issue #42,
`docs/security/gitleaks-triage.md`) classified all 42 baseline findings
as fixtures, placeholders, detection patterns, or doc quotes: **no real
secrets exist in history**. This is a hygiene and provenance decision,
not a security emergency — which is what makes options short of
deleting the repository viable at all.

## Decision

1. **Option (b): rewrite history once per repository with
   `git filter-repo`.** One pass over `central` and one pass over
   `central-local-infra`; this single ADR governs both.
2. **Timing: after the content-hygiene issues (#43, #44) merge and
   immediately before the #56 visibility flip.** Every hygiene issue
   landed first adds its removals in the same single pass; rewriting
   earlier would force a second rewrite or leave stragglers. The
   decision is recorded now so downstream issues can rely on it.
3. **Strip/rewrite list** — final list confirmed at execution, pinned
   here:
   - *Blob stripping — enumerate first, never a blanket size cutoff.*
     Enumerate `git rev-list --objects --all | git cat-file
     --batch-check`, list blobs over the size threshold, classify each,
     then strip via `--strip-blobs-with-ids` or an allowlist'd
     `--blob-callback`. A blind `--strip-blobs-bigger-than` is
     forbidden: it would strip legitimate HEAD files such as
     `vendor/golang.org/x/tools/internal/stdlib/manifest.go` (~1.5 MB
     generated symbol table — HEAD would stop building) and could
     orphan the content-addressed evidence blobs under
     `docs/internal/superpowers/reviews/evidence/**/blobs/sha256/`
     (HEAD path; pre-move commits carry the same tree at
     `docs/superpowers/reviews/evidence/**/blobs/sha256/` — the
     exclusion pathspec must cover BOTH forms because the #45 move
     only renamed HEAD) whose digests
     are referenced by `acceptance-manifest.json`/`supply-chain.json`.
     The root-level dead binaries (`broker.test`, `central`,
     `dev/null`) may additionally be stripped by anchored `--path`
     after verifying no legitimate `central/` directory prefix exists
     (path matching is prefix-based).
   - *Blob classification rule (pinned):* dead binary → strip;
     legitimate tracked file (e.g. `vendor/.../manifest.go`) → keep;
     evidence sha256 blob → **default keep**, because the digests are
     load-bearing for `acceptance-manifest.json`/`supply-chain.json` —
     each is decided explicitly at execution.
   - *Text replacement:* `--replace-text` rewrites the maintainer's
     pre-rewrite home paths → `$HOME`, plus whatever the #43 audit
     enumerates. It operates on
     blob contents only — not commit headers, commit messages, or
     filenames.
   - *Identity:* `--mailmap` rewrites author and committer name+email.
     **Both the author name and the email are normalized** to the
     maintainer's public identity — `Hiếu "k0walski" Nguyễn
     <34208688+hieuntg81@users.noreply.github.com>` — giving one
     consistent display name across all history and the GitHub noreply
     address. The maintainer's personal Gmail address and any other
     personal identity variant map to it.
   - *Commit messages:* `--message-callback` (operates on `bytes`,
     applies to commit and tag messages) strips the
     `Claude-Session: https://…` trailer lines and any personal
     identifier found in messages (`--replace-message` is the fallback
     if a fixed string suffices).
   - *Filenames:* `--filename-callback`/`--path-rename` if any path
     contains a personal identifier, verified by the post-rewrite
     checks.
   - *NOT rewritten:* `Signed-off-by` trailers, and SHA-shaped labels
     inside file contents (evidence dir names like
     `acceptance-8844c5d` are labels, not links). SHA references inside
     commit messages are auto-rewritten by filter-repo — do not pass
     `--preserve-commit-hashes`.
4. **Server-side retention — option (c): accept reachable-by-SHA old
   objects.** Force-push does not purge old objects on GitHub;
   pre-rewrite commits remain fetchable by SHA until GC. This ADR
   states plainly that **the personal identifiers enumerated in Context
   also remain fetchable by SHA after the visibility flip** — the
   maintainer accepts this knowingly, justified by #42's
   zero-real-secrets triage. The fallback is delete+recreate, invoked
   only if a real secret ever surfaces.
5. **Backup before rewrite:** `git clone --mirror` to a private
   location + `git bundle` archive + save
   `.git/filter-repo/commit-map` and `ref-map` into the backup — a
   durable old→new SHA mapping, strictly better than label-guessing.
6. **In-flight work policy:** merge or rebase before the rewrite; PRs
   still open at rewrite are closed, not migrated.
7. **Execution environment:** the rewrite runs in a separate fresh
   clone (`git clone --no-local` or mirror), never in the working
   worktree; filter-repo removes the `origin` remote, so re-add it
   afterward, then `git push --force --all` (+ `--tags` if tags exist).

## Consequences

### Benefits

- Personal paths, the personal email, session URLs, and ~20 MB of dead
  binary weight never appear in the published history — every clone
  starts clean.
- Attribution and the SC-DEF/acceptance provenance chain survive:
  commit messages, `Signed-off-by` trailers, and the genuine
  development narrative remain (unlike a squash).
- A single pass absorbs the #43/#44 hygiene removals, so no second
  rewrite is needed.
- Enumerate-first blob stripping makes the rewrite mechanically
  auditable: every stripped object is a named, classified blob.

### Costs and limitations

- **Every SHA changes.** Commit references inside file contents —
  evidence dir names, `tasks/` SC-DEF references, ADR
  cross-references, triage fingerprints — become stale labels.
  Mitigated by the private backup (mirror + bundle +
  `commit-map`/`ref-map`); the triage doc gains a note that
  pre-rewrite SHAs resolve via the backup.
- **Old objects remain fetchable by SHA server-side** (decision 4):
  pre-rewrite commits — including the personal identifiers — stay
  reachable via PR refs, Actions logs, and `gh` output until GitHub
  garbage-collects them. Accepted knowingly per the #42 triage.
- **Force-push + re-clone:** every existing clone (this machine's
  worktrees, the infra repository, any collaborator) must re-clone or
  `fetch --all && git reset --hard origin/main`.
- **Signatures are stripped:** `gpgsig` headers and tag signatures do
  not survive filter-repo — an accepted loss; #51 re-establishes
  signed releases post-rewrite. Execution verifies whether any signed
  commits or tags exist first.
- **Open PRs are closed, not migrated** (decision 6) — in-flight work
  must land or rebase before the rewrite.
- **`.gitleaks.toml` needs re-derivation only if commit-scoped entries
  are added:** all 12 allowlist entries today are path-scoped with
  zero `commits` entries, so they survive the rewrite cleanly; any
  `commits` entry added before the rewrite must be re-derived after
  it.
- The rewrite cannot run in the working worktree (decision 7): it
  needs a fresh clone, a re-added remote, and a force-push.

## Alternatives considered

### (a) Keep history as-is

No rewrite cost, but permanently publishes personal paths/emails and
~20 MB of dead binary weight for zero compensating benefit — every
consumer of the history (clone size, `git log` readability, gitleaks
noise) pays forever. Rejected.

### (c) Squash to a fresh root commit

Cheapest execution, but destroys attribution and the
SC-DEF/acceptance provenance chain the evidence directories encode,
and loses the project's genuine development narrative — an
anti-feature from an OSS credibility standpoint. Rejected.

### Server-side retention (a): delete and recreate the repository

Kills old objects outright but loses all PRs and issues, requires a
migration/export of tracker state, and breaks every existing link —
disproportionate when #42 proved no real secrets exist. Rejected;
retained only as the fallback if a real secret ever surfaces.

### Server-side retention (b): ask GitHub support to garbage-collect old objects

Depends on a support request being honored on the #56 timeline, gives
no verifiable guarantee for objects still reachable through PR refs
and other enumerations, and adds an external dependency the project
does not control. Rejected in favor of explicitly accepting the
residue.

## Amendment (issues #43 and #44, repo hygiene)

Issue #43 scrubbed the current tree ahead of this rewrite. Two inputs the rewrite runbook must consume:

- `--replace-text` must EXCLUDE the evidence tree at BOTH its pre-move path `docs/superpowers/reviews/evidence/**` (as it exists in pre-#45 commits) and its post-move path `docs/internal/superpowers/reviews/evidence/**` (HEAD) — path-scoped, not just content patterns: evidence blobs are content-addressed (`blobs/sha256/`), `logs.sha256`/`manifest.json` hash the logs, and `scripts/verify-sc-g0-evidence.sh` pins `EXPECT_MANIFEST_SHA`. Rewriting them desyncs three digest layers in the published history. Residual `/home/<user>` hits inside evidence/ (~43 at #43 time) stay — accepted residual, same as dash-encoded `/tmp/claude-1000/-home-<user>-…` paths.
- Identifier → placeholder mapping applied by #43 (the rewrite's strip list is the pre-rewrite literals, read from git log / the private backup, not from these docs):
  - `/home/<maintainer>` → `~` (plain paths incl. `~/[Cc]ode/central`)
  - `/home/<maintainer>/Code/central-issue-work` → `$CENTRAL_SRC`
  - `/home/<maintainer>/[Cc]ode/central-local-infra` → `$CENTRAL_INFRA_SRC`
  - personal emails (gmail + hieunguyen[.]io + @github.com) → `34208688+hieuntg81@users.noreply.github.com`
  - secondary VM home `/home/<h-user>` → `~`
  - bare handles (`hieuntg81`, `k0walski`) = public identity — never strip
- Regression gate now in CI: `ci/check-repo-hygiene.sh` (wired into `ci/test.sh`) greps tracked files for the identifier classes above, exempting `vendor/`, `evidence/**`, `THIRD_PARTY_LICENSES`, and itself.
- Issue #44 untracked the three build-output ELFs but history still carries them: the blob strip-list enumeration (decision 3) must additionally name `build/central-migration-launcherd`, `cmd/central-migration-launcherd/central-migration-launcherd`, and `cmd/central-backup-launcherd/central-backup-launcherd` alongside `broker.test`/`central` — same pinned mechanism, enumerated `--strip-blobs-with-ids`/allowlist'd `--blob-callback`, never blind `--strip-blobs-bigger-than`.

## Amendment (2026-10-30, `central-rust`)

This ADR's decisions apply to the Rust reimplementation
(`enolalab/central-workspace`, ADRs 0041/0043) as a third repository,
with these repository-specific inputs measured on 2026-10-30 (297
commits, `main` at `bee11cb`):

- **Identity (decision 3, `--mailmap`):** all 297 commits carry the
  maintainer's personal Gmail address as author/committer; author name
  is already `hieuntg81`. Map to the public identity pinned in decision
  3.
- **Agent trailers — kept (maintainer decision, 2026-10-30):** the 61
  `Co-Authored-By: Devin <…noreply.github.com>` trailers are **not**
  stripped. They record agent-assisted authorship transparently, carry
  only a public noreply address, and are not personal identifiers. The
  `--message-callback` therefore strips only `Claude-Session:` URLs and
  personal identifiers; none of the former and no `/home/` paths occur
  in this repository's commit messages today, so the callback is
  expected to be a no-op and stays as a guard.
- **Blob stripping:** no blob over 1 MB exists in history; no strip
  list is expected. The enumerate-first rule still governs execution.
- **Text replacement (`--replace-text`):** personal home-directory
  paths occurred in tracked docs (plans, specs,
  `roadmap-dashboard.html`). The tree scrub landed on 2026-10-30 with
  this mapping — the rewrite's `--replace-text` list uses the
  pre-scrub literals:
  - `/home/<maintainer>/Code/central-rust` → `$CENTRAL_RUST_SRC`
  - `/home/<maintainer>/Code/central-issue-work` and
    `/home/<maintainer>/Code/central` → `$CENTRAL_SRC`
  - `/home/<maintainer>/Code/central-local-infra` → `$CENTRAL_INFRA_SRC`
  - any remaining `/home/<maintainer>` → `~`
  - `SECURITY.md` and `CODE_OF_CONDUCT.md` are exempt from the email
    pattern (deliberate maintainer contact publication); the email is
    still stripped from commit headers and all other files.
  - Upstream/system homes (`/home/minio`, `/home/op`, `/home/operator`,
    `/home/plugin`, `/home/cache`) are not personal paths and stay.
- **Tags and signatures:** no tags and no signed commits exist, so
  nothing is lost to signature stripping.
- **Execution:** same as decisions 5–7 — mirror + bundle backup with
  `commit-map`/`ref-map`, fresh clone, re-add `origin`, force-push only
  on the maintainer's explicit go-ahead at execution time. Tracked in
  `docs/internal/tasks/open-source-readiness.md`.

## Follow-ups

- Rewrite runbook lands as part of #56 prep (or a dedicated execution
  issue) — not this issue's scope.
- Execution-time checks: `git tag` (none exist today; #51 tags come
  post-rewrite anyway) and a signed commits/tags existence check;
  final strip-list enumeration and per-blob classification.
- Post-rewrite gates, all required before the visibility flip:
  gitleaks baseline 0; `git log --all --format='%ae%n%ce' | sort -u`
  shows zero personal emails; `git log --format=%B` and
  `git log --name-only` greps for personal identifiers → 0;
  `go build ./...` + key tests pass on the rewritten HEAD.
- `docs/security/gitleaks-triage.md` gains a note at rewrite execution
  that pre-rewrite SHA fingerprints resolve via the private backup
  (stale-SHA note).
- `central-local-infra` gets its own rewrite pass following this same
  ADR — one ADR covers both repositories.
- Re-clone notice to every clone and collaborator after the
  force-push.

## References

- `docs/internal/superpowers/specs/2026-10-04-history-strategy-design.md`
- `docs/internal/superpowers/plans/2026-10-04-history-strategy.md`
- `docs/security/gitleaks-triage.md` (issue #42 full-history triage)
- [ADR 0041: Adopt enolalab as the canonical GitHub org and module path](0041-adopt-enolalab-as-canonical-org-and-module-path.md)
- https://github.com/enolalab/central/issues/40
- https://github.com/newren/git-filter-repo — `git filter-repo`
  documentation
