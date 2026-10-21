# central ↔ central-local-infra compatibility

`central` runs closed provisioners (`fs-init`, `minio-provision`,
`postgres-provision`, `wipe`) inside the `central-local-infra` image, pulled
as `ghcr.io/enolalab/central-local-infra@<digest>`.

## Version matrix

| central | central-local-infra |
|---------|---------------------|
| v0.x    | v0.y (same minor)   |

Pre-1.0 rule: a central release requires the infra release of the same
minor (`v0.3.x` ↔ `v0.3.y`). Exact digests — not tags — are the contract:
`internal/dependencyprepare/assets/dependency-lock.json` `modes[].inventory`
is the single source of truth. `helper_release_digest` is a deliberate
all-zero placeholder (ADR 0024); it is never the pin.

## Release order

1. Release infra: tag `v0.y.z` in `enolalab/central-local-infra`; its
   `release.yml` builds + pushes the image and prints the repo digest.
   One-time precondition: the ghcr package must be **public** (package
   settings → visibility) — anonymous pull is what `pin-infra`, CI, and
   the installer rely on.
2. In central: Actions → `pin-infra` → dispatch with the infra tag. The
   workflow rewrites the lock and opens a PR.
3. Maintainer: **close and reopen the pin PR** — a GITHUB_TOKEN-opened PR
   does not trigger `pull_request` checks. Merge when green.
4. Tag the central release (`RELEASING.md`).

## Contract

`testdata/provisioner-contract.json` is byte-identical in both repos and
pins every provisioner request shape central emits plus the receipt schema.
Change it in lockstep: a field added on one side without the other fails
the contract tests. `wipe` is receiver-side only — central never emits it.

## Supported platforms

- **Install path** (`install.sh`, release tarball or `--from-source`):
  **Ubuntu 24.04 amd64 only.** The installer's preflight enforces this —
  arm64, macOS, and other distributions are not supported install targets.
- **Source checkouts** build anywhere Go ≥1.26.6 runs (deps are vendored);
  only the installed runtime is Linux/Ubuntu-bound.
