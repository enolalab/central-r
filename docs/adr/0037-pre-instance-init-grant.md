# ADR 0037: Allow one pre-instance `init` grant for unattended genesis

- **Number:** 0037
- **Title:** Allow one pre-instance `init` grant for unattended genesis
- **Status:** Accepted
- **Created:** 2026-09-30
- **Owners:** Central maintainer
- **Decision due:** 2026-10-14
- **Decision due history:** None
- **Implementation blocked at:** `central grant issue --kind init`, the host-scoped genesis grant store under `/var/lib/central-protected/v1/genesis/`, a grant-mode `ConfirmInit`, and genesis writing the new instance's ceremony-mode file as `grant` (install sub-project B2, and the installer's default `grant` path in sub-project D). `physical_tty` genesis (sub-project B1) is not blocked and is implemented without this ADR.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-10-01)
- **Decision date:** 2026-10-01
- **Decision record:** Maintainer approval in session on 2026-10-01 (the maintainer approved recording the acceptance: "1 và 2"); status recorded by agent at maintainer direction in this dedicated status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0032 (the grant-kind set gains `init`); ADR 0028 D1 (the first grant kind that exists before an instance)
- **Amended by:** None
- **Related:** `docs/internal/superpowers/specs/2026-09-27-one-click-install-design.md` §B (B2) and decision 3; `docs/internal/superpowers/specs/2026-09-30-install-b1-local-init-genesis-design.md` decisions 4 and 11; `docs/internal/superpowers/reviews/2026-09-30-install-b1-spec-review.md`; `docs/internal/superpowers/plans/2026-09-30-install-b1.md`; `docs/internal/tasks/install-b1-local-init-genesis-2026-09-30.md`

## Context

ADR 0028 D1 added a second ceremony mode: a root-issued, one-use, short-lived operation grant that the helper spends instead of the PAM conversation and the typed phrase. ADR 0032 extended its closed kind set to the Slice D verbs. Both assume an instance exists: the grant store is `<instance state root>/grants`, the ceremony-mode file lives in the same root, and `central grant issue` resolves the instance composition before it writes anything (`productionGrantEnvironment`, `cmd/central/grant_cli.go`).

Genesis is the one operation that runs before any instance exists. Install sub-project B1 implements `central local init` with the `physical_tty` ceremony only: fresh PAM plus the phrase `CONFIRM <code> init` at the operator's physical console. The genesis helper builds its confirmer with `helper.NewPAMConfirmer()`, and `ConfirmInit` on a grant-mode confirmer refuses. The instance genesis creates has no ceremony-mode file, so it is `physical_tty` until the operator runs `central grant mode grant`.

The one-click install design (decision 3) makes `grant` the installer's default. An unattended installer therefore needs a grant that can exist before the instance does, and the instance should be `ceremony_mode: grant` from birth rather than after a later mode switch that itself needs root.

## Decision

Accepted:

1. **One pre-instance kind.** `central grant issue --kind init` (root only) is the single grant kind that may be issued when no instance resolves. Every other kind still requires an instance and is refused without one, unchanged. `--kind init` takes no `--operation`: genesis mints its own init operation ID.
2. **A host-scoped store.** The init grant is written to `/var/lib/central-protected/v1/genesis/`, root:root 0700, which holds at most one unconsumed init grant. It follows ADR 0028's discipline byte for byte except for the bindings that cannot exist yet: kind `init`, `BootID`, `HelperRelease`, `IssuedAt`, `ExpiresAt` capped at 15 minutes, a random nonce, and the helper-held HMAC. It carries no `InstanceID` or `TargetID`.
3. **Consumption.** The genesis helper (spec B1 decision 2) consumes an unexpired init grant atomically, bound to the configured operator peer and the current boot, in place of the `physical_tty` ceremony. With no grant present it runs the `physical_tty` ceremony exactly as B1 does. Nothing is auto-confirmed and no grant is minted by the helper.
4. **Grant mode from birth.** A genesis authorized by an init grant writes the new instance's ceremony-mode file as `grant`, with the instance's grant store, before the config commit point, so the instance is durably `ceremony_mode: grant` from its first resolution.
5. **Kind registry.** ADR 0032's grant-kind set gains `init`. On acceptance ADR 0032's `Amended by` field names this ADR.
6. **Honest property.** As in ADR 0028: in grant mode the control is "root on this host, deliberately, for this genesis, within this window". Evidence from a grant-mode genesis says so.

## Consequences

### Benefits

- The installer can create an instance unattended, under the same audited one-use discipline as every other grant.
- The instance is in `grant` mode from birth; no second root step switches it.
- The `physical_tty` path is unchanged and stays the default when no grant exists.

### Costs and limitations

- A second, host-scoped grant store outside any instance. It must be cleaned when genesis consumes its grant and audited like the instance stores, and it survives an instance wipe.
- A grant issued and not spent lingers until it expires; the 15-minute cap and the boot binding bound the window.
- The peer binding is the operator uid and pid only; the install C record already notes that harness sessions share the operator uid (review I2). This ADR does not close that.

## Alternatives considered

### The installer runs genesis as root without the helper

This is how the reference-host harness installs. It bypasses the contract that `local init` runs as the operator behind a ceremony, which the one-click install design rejected in its 2026-09-27 revision.

### `physical_tty` genesis, then `central grant mode grant`

This is what B1 ships. It works today, and it needs a person at the physical console once per install, which is what an unattended installer exists to avoid. It remains the fallback until this ADR is accepted.

### Store the init grant inside the instance directory

No instance ID exists before genesis, so there is no instance directory to name, and creating one ahead of genesis would be the partial state genesis refuses.

## Follow-ups

- Install sub-project B2: implement `--kind init`, the genesis store, the grant-mode `ConfirmInit`, and the ceremony-mode write, with per-mode confirmer tests (owner: Central maintainer; blocked on this ADR).
- On acceptance: set ADR 0032's `Amended by` and the index row in the same status-transition commit.

## References

- `docs/adr/0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md`
- `docs/adr/0032-extend-grant-ceremony-to-slice-d-verbs.md`
- `docs/internal/superpowers/specs/2026-09-30-install-b1-local-init-genesis-design.md`
- `internal/adapter/authority/helper/pam_linux.go` (`ConfirmInit`), `internal/adapter/authority/helper/grant.go`, `cmd/central/grant_cli.go`
