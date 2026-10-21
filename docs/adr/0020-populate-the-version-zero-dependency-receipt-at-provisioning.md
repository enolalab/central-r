# ADR 0020: Populate the version-zero dependency receipt at instance provisioning

- **Number:** 0020
- **Title:** Populate the version-zero dependency receipt at instance provisioning
- **Status:** Accepted
- **Created:** 2026-08-17
- **Owners:** Central maintainer
- **Decision due:** 2026-08-24
- **Decision due history:** None
- **Implementation blocked at:** Any production composition of
  `internal/dependencyprepare/app.Service`, and any code path that writes a
  live instance's `active` dependency selector outside a test. Both were
  blocked pending this decision; this ADR authorizes the narrow provisioning
  path below and continues to block the Slice E operator surface.
- **Decided by:** hieuntg81 (decision-making delegated 2026-08-17 to the
  session agent with explicit instruction to decide; recorded per the same
  delegation as `docs/internal/superpowers/reviews/2026-08-17-sc-g0-record-withdrawal.md`)
- **Decision date:** 2026-08-17
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** ADR 0030 (narrowly amends §1: `attestation_trust` is not a mode inventory and is updated by ADR 0030, not by an external delivery); ADR 0038 (release imports)
- **Related:** ADR 0019 (the other half of the same production bring-up
  chain); B05 version-zero provisioning
  (`docs/internal/superpowers/specs/2026-07-21-phase-1-b05-version-zero-provisioning-design.md`)
  as the scope this decision assigns the work to; the command registry's
  `local.dependency-upgrade-plan`/`local.dependency-upgrade-apply` rows
  (OwningSlice E), which this decision deliberately does not touch.

## Context

Every B02-gated consumer reads the instance's **active dependency receipt** —
`CandidateStore.Active` resolves `<DependencyRoot>/active` to a staged
candidate manifest carrying the seven modes' OCI inventories — and fails
closed when it is absent. That is correct: an instance that cannot prove
which images it runs must not run them.

But nothing in production ever populates it. The write side is fully built
and tested — `internal/dependencyprepare/app.Service` orchestrates fetch →
verify → build → stage → switch-selector through `CandidateStore.Stage` and
`SwitchSelector` — and has **zero production composition**: `cmd/central`
constructs only the read side. The operator-facing surface that would drive
it (`central local dependency upgrade plan|apply`) is registered as Slice E
scope and rightly does not exist yet. So a live instance's receipt can be
populated by no committed mechanism at all, and `central backup create`
(C01/C02), which needs the receipt to resolve its pinned images, cannot
succeed on any real host. The status ledger has carried this as "B02's own
incomplete candidate-promotion flow."

The wait-for-Slice-E reading is a category error: Slice E owns dependency
**upgrade** — moving a live instance from one accepted receipt to the next,
an operator decision with an operator surface. First **population** — giving
a freshly provisioned instance its version-zero receipt — is not an upgrade
and needs no operator decision beyond provisioning the instance at all. B05,
"version zero provisioning," is that scope's owner and is already Accepted.

## Decision

**A live instance's active dependency receipt is populated exactly once, at
instance provisioning time, as B05 version-zero scope — by composing the
existing `dependencyprepare` app service with production adapters against the
vendored dependency lock. Slice E's operator upgrade surface is untouched and
remains blocked.** Concretely:

1. **Source of truth.** The version-zero candidate is derived from
   `internal/dependencyprepare/assets/dependency-lock.json` at the running
   binary's own build — the same artifact whose SHA-256 every acceptance
   manifest already pins (`dependency_lock_sha256`), updated only from
   accepted external deliveries per the existing supply-chain rules. No
   network fetch, no mutable tag, no new trust root.
2. **Mechanism, not a new one.** Production composes the existing
   `app.Service` (journal, verifier, builder, candidate store, locker,
   capacity checker) and drives one prepare operation during instance
   provisioning, ending in `Stage` + `SwitchSelector` on the instance's
   dependency root. The domain flow, its journal semantics, and its
   fail-closed verification run unmodified; what this ADR adds is only the
   production wiring and its provisioning-time call site.
3. **Idempotent and non-interactive.** An instance whose active selector
   already resolves is left untouched — population is first-write-only, so a
   crashed provisioning retries safely and an upgraded instance can never be
   silently downgraded to version zero. No CLI verb, no registry row, no
   prompt: an operator who provisions an instance has already made the only
   decision involved.
4. **Slice E stays Slice E.** `central local dependency upgrade plan|apply`
   remains the only future operator surface for changing an existing
   receipt, remains Slice-E-owned, and remains unimplemented until that
   slice's own gates. This ADR neither implements, unblocks, nor prejudges
   it.

## Alternatives considered

- **Wire the Slice E commands now.** Rejected: it pulls a destructive
  operator flow across the backlog's declared slice ordering to solve a
  problem that is not an upgrade, and would ship an operator surface no
  Slice E design has reviewed.
- **Have `backup create` self-populate on first use.** Rejected: a backup
  path that mutates the instance's dependency identity as a side effect
  inverts B02's admission model — the receipt must gate the operation, not
  be created by it.
- **Hand-write the `active` file in provisioning scripts.** Rejected: it
  bypasses the staged-candidate verification the domain service exists to
  enforce, and the B03 episode already showed what hand-asserted state costs.

## Consequences

- A freshly provisioned instance has a verifiable active receipt from its
  first boot, closing the second of the two production gaps blocking
  `central backup create` (ADR 0019 closes the first).
- The version-zero receipt is exactly as trustworthy as the vendored
  dependency lock, which is exactly as trustworthy as the accepted external
  deliveries behind it — no new authority is minted.
- **This authorizes implementation; it accepts nothing.** No packet or gate
  changes status. The wiring lands with its own tests (composition,
  idempotence, crash-retry, refusal to overwrite an existing selector), and
  only SC-G1's clean-host evidence can prove the populated receipt drives a
  real sealed backup.
