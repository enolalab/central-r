# ADR 0026: Remove `postgres-provision` from the B03 service census

- **Number:** 0026
- **Title:** Remove `postgres-provision` from the B03 service census
- **Status:** Accepted
- **Created:** 2026-08-20
- **Owners:** Central maintainer
- **Decision due:** None set
- **Decision due history:** None
- **Implementation blocked at:** Nothing further. This ADR authorizes the
  removal described under Decision and nothing wider — in particular it does
  **not** authorize removing the `PostgresProvisioned` lifecycle phase, changing
  `provisionReceipt`'s exit-0 requirement, or touching the seventh service
  `postgres-throughput-provision`.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-20)
- **Decision date:** 2026-08-20
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** B03's six-service census, accepted 2026-07-20 (see
  `docs/internal/superpowers/reviews/2026-08-12-b03-compose-lifecycle-acceptance-decision.md`)
- **Amended by:** None
- **Related:** ADR 0019 (production PostgreSQL role topology bootstrap, which
  subsumes this service's work); ADR 0014 (the seventh service,
  `postgres-throughput-provision`, which is a different thing and is
  unaffected); ADR 0020 §1 (lock mode inventories);
  `docs/internal/tasks/sc-def-04-postgres-provision-runs-the-server-not-a-provisioner.md`

## Context

`postgres-provision` cannot succeed on any host and never could. Measured
2026-08-20, running it exactly as the compose policy specifies:

```
Error: Database is uninitialized and superuser password is not specified.
EXIT=1
```

The chain is in SC-DEF-04 and is not restated here. In short: the policy gives
the service an empty command, `Render` emits `command:` only when non-empty, and
`ImageReference` maps `PostgresProv` to the upstream
`library/postgres:16.14-bookworm@…`. So the container runs the postgres image's
default entrypoint — the database **server** — while
`Topology.ProvisionPostgres` requires `State == "exited" && ExitCode == 0`.

The service's shape says it was designed as a **client**: `PGHOST=postgres`,
`PGUSER=central`, `PGDATABASE=central`, `PGCONNECT_TIMEOUT=10`, no volumes,
`user 999:999`. Something was meant to connect to the daemon and do work. No
command was ever written for it.

**The obvious fix does not exist, and this is the part worth recording.** It
reads as though `ImageReference` simply points the mode at the wrong image —
every other provisioner runs `central-local-infra` with a mode argument, and
this is the only one on an upstream image. That hypothesis was filed, approved,
and then disproven while starting the work:

- The delivery image's `postgres-provision` **mode** is C02's throughput-fixture
  prober. `PostgresProvisionParams`
  (`central-local-infra/internal/request/postgres_provision.go:35`) carries only
  a schema version, protocol identity, fence token, candidate config digest and
  a `ThroughputFixture` action from the closed set `create_load_v1` /
  `verify_v1` / `drop_v1`; its own comment states that "database, schema, SQL,
  roles, endpoints and credentials are deliberately absent".
- That mode is already consumed by a **different** Central service.
  `cmd/central/backup_throughput_postgres.go:201` runs the seventh Compose
  service `postgres-throughput-provision` with the mode argument
  `postgres-provision`.

Repointing B03's `postgres-provision` at the same image would conflate a
throughput prober with whatever B03 needed.

**What B03 needed is now done elsewhere.** ADR 0019 moved the production role
topology into the postgres daemon's own first boot: the first-boot superuser
environment, the passfile mount, and the no-password role script. Whatever this
service was intended to do before that ADR, the role topology it would have
established is established by the daemon starting.

## Decision

**`postgres-provision` is removed from B03's six-service census.** The service
is deleted from the compose policy, `PostgresProv` is removed from
`ValidateB03`'s required set, and `Topology.ProvisionPostgres` stops running a
provisioner container.

**The `PostgresProvisioned` lifecycle phase is kept**, and the transition into
it becomes direct from `ContainersHealthy`. This is deliberate on two grounds:

1. **It is honest.** After ADR 0019, PostgreSQL *is* provisioned once the daemon
   has started and passed its health check, which is precisely what the
   preceding `ContainersHealthy` phase establishes. The work moved; it did not
   disappear.
2. **It avoids a durable-state change nobody needs.** The phase participates in
   budget selection (`operationBudget`) and in `requiresVerifiedTeardown`, and
   it is journalled for resume. Removing a phase from a persisted state machine
   is a migration-shaped change, and this decision does not require one.

**No receipt is fabricated for the removed step.** `verifySemanticReceipt(sr,
"postgres")` is removed along with the call, rather than being fed a synthetic
receipt. A receipt that attested "the provisioner container exited 0" has
nothing to attest when there is no provisioner, and manufacturing one would be
the exact failure this repository has had to withdraw records over.

`provisionReceipt`'s `State == "exited" && ExitCode == 0` requirement is
**correct and stays**, for `minio-provision` which still uses it. It must never
be relaxed to accommodate a service that does nothing.

The seventh service, `postgres-throughput-provision`, is **untouched**. It is a
different service, serving C02, already correctly wired to the delivery image.

## Consequences

### Benefits

- Removes a step that could not succeed, and with it one of the blockers on a
  clean-host B03 bring-up, which SC-G1 requires.
- Stops B03's census claiming a service that does no work, so a receipt attests
  what actually ran.
- Costs nothing in guarantees: the role topology is established by ADR 0019's
  first boot and verified by the daemon health check that already gates the
  phase.

### Costs and limitations

- **It amends an accepted packet's contract.** B03 was accepted 2026-07-20 on a
  six-service census; it is now five. B03's acceptance was semantic — every
  assertion ran against fakes — so no recorded evidence is invalidated by the
  change, but the census figure in B03's records no longer matches the code and
  should be read with this ADR beside it.
- The compose-policy asset change re-keys `PolicyDigest`
  (`compose_linux.go`), which travels in every request body. Any pinned
  policy digest elsewhere must be regenerated rather than edited by hand.
- The lock's `postgres-provision` mode entry is a separate question governed by
  ADR 0020 §1 and is **not** decided here; see Follow-ups.

## Alternatives considered

### Give the service a real job and a real command

Keep it on the upstream postgres image as a client of the daemon, and write the
command it never had. Rejected because nothing identified work that remains
after ADR 0019's first-boot bootstrap. Adopting it would have meant inventing a
job to justify a service rather than removing a service that has none.

### Point `PostgresProv` at `central-local-infra`

The hypothesis filed in SC-DEF-04 and disproven in Context. It would bind B03 to
C02's throughput-fixture prober.

### Remove the `PostgresProvisioned` phase as well

Rejected for now: the phase is journalled and participates in budget and
teardown decisions, so removing it is migration-shaped work with no benefit
this decision needs. Recorded so the option is not lost.

## Follow-ups

- **Open, ADR 0020 §1:** decide whether the lock's `postgres-provision` mode
  entry is removed too, or retained as an inventory the census no longer
  requires. `ValidateB03` and the lock's mode list are different things —
  `isKnownServiceMode` already accepts modes `ValidateB03` does not require,
  which is exactly how `postgres-throughput-provision` lives there — so removal
  is not forced by this ADR.
- **Open:** B03's recorded census figure predates this amendment. Whether its
  acceptance record is annotated is a maintainer call, and per the withdrawal
  precedent an agent must not edit an acceptance record.
- SC-DEF-04 is closed by this decision and should be marked so.

## References

- `docs/internal/tasks/sc-def-04-postgres-provision-runs-the-server-not-a-provisioner.md` —
  the defect, its measurement, and the disproven hypothesis.
- `internal/adapter/infralifecycle/assets/compose-policy.json` — the service entry.
- `internal/adapter/infralifecycle/lifecycle_linux.go` — `ProvisionPostgres`,
  `provisionReceipt`.
- `internal/infralifecycle/app/service.go` — the `ContainersHealthy` →
  `PostgresProvisioned` transition.
- `internal/dependencyprepare/domain.go` — `ValidateB03`'s required set.
- ADR 0019 — the first-boot role topology that subsumes this service's work.
