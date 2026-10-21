# ADR 0041: Adopt enolalab as the canonical GitHub org and module path

- **Number:** 0041
- **Title:** Adopt enolalab as the canonical GitHub org and module path
- **Status:** Proposed
- **Created:** 2026-10-04
- **Owners:** Central maintainer
- **Decision due:** 2026-10-11
- **Decision due history:** None
- **Implementation blocked at:** Public `go install` resolution, GHCR
  `ghcr.io/enolalab/*` image publishing (issue #51), and install docs
  naming the module path (issues #53, #55). The rename sweep itself
  proceeds in anticipation per ADR 0028 D3 — it changes no Accepted
  ADR's decision and weakens no check.
- **Decided by:** Not applicable while Proposed
- **Decision date:** Not applicable while Proposed
- **Decision record:** Not applicable while Proposed
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/internal/superpowers/specs/2026-10-04-org-module-path-design.md`;
  `docs/internal/superpowers/plans/2026-10-04-org-module-path.md`;
  enolalab/central issues #39 (this decision), #51, #53, #55, epic #57;
  enolalab/central-local-infra issue #2

## Context

Both repositories live under the GitHub org `enolalab` ("Enola Lab") —
`git@github.com:enolalab/central.git` — but both `go.mod` files declare
`module github.com/enolalabs/central` and
`module github.com/enolalabs/central-local-infra`. The `enolalabs` org
does not exist: `gh api orgs/enolalabs` returns 404.

When the repositories go public, `go install`, `go get`, and pkg.go.dev
resolve the module path against the repository URL. A module path
naming a nonexistent org will not resolve, so
`go install github.com/enolalabs/central/cmd/central@<tag>` fails from
day one.

The mismatch is widespread but mechanical: ~998 files in `central`
reference `enolalabs` (835 under `internal/` and `cmd/`, the rest in
docs, Makefile, scripts, and testdata) and ~69 files in
`central-local-infra`, counted pre-sweep. The repositories are still
private, so no external importer exists to break — this is the cheapest
possible moment to realign.

## Decision

1. **`enolalab` is the canonical GitHub org.** It is the existing org
   ("Enola Lab") that already owns both repositories, the GHCR
   namespace (`ghcr.io/enolalab/…`), and every git remote. The org is
   the real, controlled identity; the module path is in-repo metadata
   we fully control, so code realigns to the org — not the reverse.
2. **Module paths are renamed** to `github.com/enolalab/central` (this
   repository) and `github.com/enolalab/central-local-infra` (infra
   repository). Every `enolalabs` occurrence is renamed — go.mod, Go
   imports, ldflags `-X` paths, Makefile, CI, scripts, packaging,
   testdata, and non-exempt docs — except the exempt set defined in
   spec §3 (decided ADRs, historical specs/plans/reviews/tasks, and the
   content-addressed evidence blobs).
3. **Creating or renaming to an `enolalabs` org is rejected.** The org
   does not exist; creating or renaming an org is a maintainer-only
   GitHub action with blast radius outside the repositories — GHCR
   paths do not follow org renames, and OAuth apps, runners, deploy
   keys, and hard-coded remotes all break. It would also gate every
   later open-source issue on an external act this pipeline cannot
   perform.
4. **All cross-references switch in the same sweep — no mixed-state
   window.** No cross-repo Go imports exist in either direction; the
   cross-references are strings only (GHCR image names, OCI
   `image.source` labels, docs links, script strings). A half-renamed
   pair of repositories is strictly worse than either endpoint:
   `go install` would still fail and references would point at a
   phantom org.

## Consequences

### Benefits

- `go install github.com/enolalab/central/cmd/central@<tag>` resolves
  the day the repository goes public.
- One canonical identity for GHCR, documentation, and git remotes — no
  naming discrepancy for contributors or tooling to trip over.
- The rename is a scripted, mechanically verifiable sweep with an exact
  acceptance check (`git grep -l 'enolalabs'` returns only exempt
  paths).

### Costs and limitations

- A ~1000-file diff across the two repositories, landed in one sweep
  per repository.
- Historical records keep the old path by design: decided ADRs, past
  specs/plans/reviews, and task records continue to say `enolalabs` as
  historical fact.
- Content-addressed evidence blobs under
  `docs/internal/superpowers/reviews/evidence/` deliberately keep `enolalabs` —
  rewriting them would desync their sha256 filenames and invalidate the
  attestation chain.

## Alternatives considered

### Rename or create an `enolalabs` org

Making the org match the existing module paths avoids the in-repo sweep
but requires creating or renaming a GitHub org — a maintainer-only
action with blast radius outside the repositories (GHCR paths do not
follow renames; OAuth apps, runners, deploy keys, and hard-coded
remotes break) — and it would gate every later open-source issue on an
external act. Rejected per decision 3.

### Dual identity: keep the `enolalabs` module path under the `enolalab` org

No work now, but `go get`/`go install` resolve the module path against
the repository URL and cannot resolve a path naming a nonexistent org.
Rejected.

### Defer the rename until after going public

Deferring means every external importer breaks permanently the moment
the repository goes public, and the fix afterward rewrites history
under already-published module paths. Now, while private, is the
cheapest possible time. Rejected.

## Follow-ups

- enolalab/central-local-infra: the infra repository's module-path
  rename, same day, its own pull request (also advances infra issue #2).
- enolalab/central issue #51: GHCR image publishing uses
  `ghcr.io/enolalab/*`.
- enolalab/central issues #53 and #55: install documentation and README
  name the new module path.

## References

- `docs/internal/superpowers/specs/2026-10-04-org-module-path-design.md`
- `docs/internal/superpowers/plans/2026-10-04-org-module-path.md`
- https://github.com/enolalab/central/issues/39
