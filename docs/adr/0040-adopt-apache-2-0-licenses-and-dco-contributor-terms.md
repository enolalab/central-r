# ADR 0040: Adopt Apache-2.0 licenses for central and central-local-infra, DCO contributor terms

- **Number:** 0040
- **Title:** Adopt Apache-2.0 licenses for central and central-local-infra, DCO contributor terms
- **Status:** Accepted
- **Created:** 2026-10-04
- **Owners:** Central maintainer
- **Decision due:** 2026-10-11
- **Decision due history:** Lapsed 2026-10-11; decided 2026-10-30
- **Implementation blocked at:** None — unblocked by this acceptance.
  `central-rust` license files land with the acceptance; the
  remaining follow-ups (NOTICE/THIRD_PARTY_LICENSES, `CONTRIBUTING.md`
  DCO text, DCO CI check, infra madmin-go replacement) are tracked
  below.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-10-30)
- **Decision date:** 2026-10-30
- **Decision record:** Maintainer approval in session on 2026-10-30
  ("accept 0040"), after choosing dual `MIT OR Apache-2.0` for
  `central-rust` (see the Amendment section)
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/internal/superpowers/specs/2026-10-04-license-selection-design.md`;
  `docs/internal/superpowers/plans/2026-10-04-license-selection.md`;
  enolalab/central issues #38 (this decision), #41, #46, #50, epic #57;
  enolalab/central-local-infra issue #1

## Context

Neither `enolalab/central` nor `enolalab/central-local-infra` ships a
`LICENSE`, `COPYING`, or `NOTICE` file. With no license text both
repositories are "all rights reserved": making them public would not
make them open source, and outside contributors have no stated terms.

A license scan of the vendored dependencies found almost everything
under MIT, Apache-2.0, BSD, or ISC — compatible with any reasonable
choice. Two exceptions, both in `central-local-infra` only:

- `github.com/minio/madmin-go/v3` is AGPL-3.0. Keeping it forces the
  infra binary to be distributed under AGPL-3.0 or a compatible
  license.
- `github.com/shoenig/go-m1cpu` is MPL-2.0 (file-level copyleft,
  compatible with Apache-2.0 distribution), pulled in indirectly via
  madmin-go → gopsutil. Its notice lands in infra's
  `THIRD_PARTY_LICENSES` only if the dependency survives the madmin-go
  replacement; it never appears in central's.

Two contribution-side questions ride along with the license choice:
whether contributions require a CLA or a DCO, and whether a trademark
policy for the name "Central" is needed now.

## Decision

1. `enolalab/central` is licensed **Apache-2.0**: an explicit patent
   grant, the standard choice for Go infrastructure and dev tooling,
   and compatible with every vendored dependency in the repository.
2. `enolalab/central-local-infra` is licensed **Apache-2.0**, reached
   by replacing `github.com/minio/madmin-go/v3` (AGPL-3.0) with direct
   MinIO Admin REST API calls. The madmin-go surface is bounded: eight
   call sites in `internal/minioprovision/admin.go`, all confined
   behind the `AdminClient` boundary (`New`, `AddUser`,
   `AddCannedPolicy`, `SetPolicy`, `AddServiceAccount`,
   `ListServiceAccounts`, `DeleteServiceAccount`, `ToErrorResponse`),
   plus a SigV4-signing transport and dual not-found error-code
   mapping; `minio-go/v7` (Apache-2.0, already vendored in infra)
   provides the SigV4 machinery the replacement can reuse. The
   replacement work is owned by `central-local-infra` issue #1, not by
   this ADR.
3. Contributions require the **Developer Certificate of Origin**
   (DCO): every commit in a pull request carries a `Signed-off-by:`
   trailer certifying the DCO. There is no CLA. Enforcement lands in
   CI under issue #50 and the requirement text lands in
   `CONTRIBUTING.md` under issue #46.
4. **No trademark policy file** (`TRADEMARKS.md`) is adopted now.
   "Central" is not a registered mark; redistribution under Apache-2.0
   grants no rights to any future mark, and a policy may be added
   later if branding solidifies.

## Consequences

### Benefits

- Uniform Apache-2.0 across both repositories keeps the legal story
  one sentence long for users and contributors.
- The DCO keeps contributor friction at zero: no paperwork and no
  CLA-assistant service to run.
- The decision unblocks issue #41 (central license files) and
  `central-local-infra` issue #1 (madmin-go replacement plus infra
  license files).

### Costs and limitations

- `central-local-infra` carries bounded replacement work (its issue
  #1) before its `LICENSE` can be written accurately; until that work
  lands, infra's published license depends on completing the
  replacement.
- The name "Central" remains unprotected; if branding solidifies, a
  trademark policy will need its own follow-up.

## Alternatives considered

### AGPL-3.0 for central-local-infra, keeping madmin-go

Keeping madmin-go and licensing the infra repository AGPL-3.0 saves a
bounded amount of replacement work but leaves the project with a
permanent two-license story, and AGPL's network clause becomes a
question every adopter must clear with counsel. Rejected.

### CLA instead of DCO

A Contributor License Agreement adds contributor paperwork and
CLA-assistant infrastructure that a maintainer-run project does not
need; the DCO covers the same contributor terms at zero friction.
Rejected.

### Adopt `TRADEMARKS.md` now

There is no registered mark to police, so maintaining a policy
document now is YAGNI. Recording the position in this ADR preserves
the option without the document. Rejected.

## Amendment (2026-10-30, `central-rust`)

This ADR was written for the upstream Go repositories. For the Rust
reimplementation (`central-rust`, ADR 0043) the maintainer chose
**dual licensing `MIT OR Apache-2.0`** on 2026-10-30, matching the root
`Cargo.toml` `license` field already in the tree and the Rust ecosystem
convention:

- `central-rust` ships `LICENSE-MIT` and `LICENSE-APACHE`; downstream
  users may choose either license.
- Contributions are accepted under both licenses (inbound = outbound);
  `CONTRIBUTING.md` states this alongside the DCO requirement.
- Decision 1 (Apache-2.0 for the Go `central`) and decision 2
  (Apache-2.0 for `central-local-infra`) are unchanged. Decisions 3
  (DCO, no CLA) and 4 (no trademark policy) apply to `central-rust`
  unchanged.
- `cargo deny check licenses` must keep every dependency compatible
  with both licenses.

## Follow-ups

- `central-rust`: write `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`, and
  `THIRD_PARTY_LICENSES`; add the dual-license + DCO text to
  `CONTRIBUTING.md` (tracked in
  `docs/internal/tasks/open-source-readiness.md`).
- enolalab/central issue #41: write `LICENSE`, `NOTICE`, and
  `THIRD_PARTY_LICENSES` for `central` (implements decision 1).
- enolalab/central-local-infra issue #1: replace madmin-go with direct
  MinIO Admin REST API calls, then write infra's `LICENSE`, `NOTICE`,
  and `THIRD_PARTY_LICENSES` (implements decision 2).
- enolalab/central issue #46: document the DCO `Signed-off-by`
  requirement in `CONTRIBUTING.md`.
- enolalab/central issue #50: add the DCO check to CI.

## References

- `docs/internal/superpowers/specs/2026-10-04-license-selection-design.md`
- https://github.com/enolalab/central/issues/38
