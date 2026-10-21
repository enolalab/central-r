# ADR 0017: Narrow the object-store restore credential's precondition

- **Number:** 0017
- **Title:** Narrow the object-store restore credential's precondition
- **Status:** Accepted
- **Created:** 2026-08-13
- **Owners:** Central maintainer
- **Decision due:** 2026-08-20
- **Decision due history:** None
- **Implementation blocked at:** The fix for `docs/internal/tasks/sc-def-01-object-store-write-credential-gate.md`; no code may narrow or widen frame `0xc2` kind 3's precondition until this is decided.
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-13
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** ADR 0034 (Accepted 2026-09-26: adds a new MinIO-write
  purpose `PurposeMinioImport` beside the read-only `PurposeMinioRestore`;
  option B's removal of PutObject from the restore purpose is unchanged)
- **Related:** `docs/internal/tasks/sc-def-01-object-store-write-credential-gate.md`; ADR 0015 as the direct precedent — same frame, same file, an earlier precondition decision on this exact mechanism.

## Context

Frame `0xc2` serves three credential kinds, and its own comment states the intent: they are separate kinds "so a state
that admits a read cannot also release the credential that rewrites the database."

Kind 1, the PostgreSQL migration credential, requires `Phase == applying` **and** `LastCheckpoint == ticket_consumed`.
Kind 3, the object-store credential, requires only `assertLiveRestore` — any validating operation that has not reached
`ServingAllowed()` — plus a handoff receipt bound to the operation and purpose with an exact bucket and key prefix. And
kind 3 is not read-only: `PurposeMinioRestore` grants `PutObject` alongside `GetObject`.

So a write capability is released under a read-shaped precondition, which is the inverse of the stated intent.

**The obvious fix does not work, and a scouting pass established why.** Requiring kind 1's state for kind 3 would break
the flow: the only real consumer, `VerifyInventory`, is invoked from the restore coordinator at
`Verifying`/`DatabaseReplaced` or `Quarantined`/`InventoryVerified` — strictly *after* kind 1's window has closed. Kind 1
and kind 3 are needed at disjoint points, so they cannot share a precondition.

Two corrections to the filed defect, recorded so the decision rests on accurate facts:

- The defect's phrase "before any restore ticket has been consumed" does not describe a reachable state. `BeginRestore`
  durably creates the operation already at `Applying`/`TicketConsumed`, so no persisted operation exists before
  consumption. The real gap is narrower and still real: `assertLiveRestore` admits the **entire** live-operation window
  when the only consumer needs two specific checkpoints.
- The scout could not find production code that issues or binds a `PurposeMinioRestore` handoff receipt for a real
  restore run, which suggests kind 3 may not be reachable end to end today at all. That does not make the precondition
  moot — it makes it cheap to fix now, before anything depends on the loose behaviour.

## Decision

**Options A and B were both selected.** The options this ADR was proposed with are retained under Alternatives
considered.

**A — kind 3 is gated on the checkpoints its consumer actually needs.** It requires
`Phase == verifying && LastCheckpoint == database_replaced`, or `Phase == quarantined && LastCheckpoint ==
inventory_verified`. This predicate already exists, duplicated in two places in the tree, so the decision adopts a shape
the codebase had already settled on. It admits exactly the two states the real consumer reaches and refuses the rest of
the live window.

**B — `PutObject` is dropped from `PurposeMinioRestore`.** No consumer found needs it; `VerifyInventory` only reads.
Removing the capability is stronger than narrowing when it is handed out, because a credential that cannot write cannot
be misused by a caller reaching it through a path nobody anticipated.

### The risk accepted with B, and how it is bounded

B was held at medium-high rather than high confidence for one reason, and accepting it means accepting that reason: **no
design document explains why `PutObject` was granted**, so an intended future object-body writer may exist that nobody
wrote down. If it does, B breaks it, and the breakage appears later in code nobody has written yet.

That is accepted on the following basis. The capability has no demonstrated consumer today, and the scouting pass could
not find production code that even issues a `PurposeMinioRestore` handoff receipt for a real restore run — so nothing
observable is lost now. If a genuine writer emerges, re-granting a write capability to a restore credential is exactly
the kind of decision that should require its own ADR rather than being inherited silently from a grant no one
documented. B therefore converts an undocumented standing capability into a decision someone has to make deliberately,
which is the safer default in both directions.

## Consequences

### Benefits

- Under A, the frame's kinds finally match the intent its own comment states: a weaker state releases only weaker
  capability.
- Under B, the exposure is removed rather than time-boxed, which survives future callers that A alone would not.
- Both are cheap now and get more expensive once anything depends on the loose behaviour.

### Costs and limitations

- If an intended object-body writer exists but was never written down, B breaks it — and the breakage would appear later,
  in code nobody has written yet. That is the specific risk this ADR asks the maintainer to weigh.
- Neither option addresses the frame's generic root peer gate. Kind 3's protection still rests substantially on the bound
  handoff receipt, and this ADR does not change that.
- Neither option makes kind 3 reachable end to end. If it is genuinely non-functional today, that is separate work.

## Alternatives considered

### Reuse kind 1's `applying` + `ticket_consumed` precondition

The defect's own proposed fix, and the one a reasonable engineer would reach for first.

Not viable: it refutes itself on the evidence. Kind 1's window has closed by the time kind 3's only consumer runs, so
this would refuse every legitimate call. Recorded because the reasoning is what makes the selected option's shape correct
rather than arbitrary.

### Adopt A only, and leave the policy as it is

Narrow the timing, keep the capability. Not selected. It is defensible if a future object-body writer is genuinely
planned, and it is the smaller change — but it leaves the mechanism granting a write it has no demonstrated use for, so
the comment at the top of the file would remain aspirational for kind 3.

### Do nothing

Record that kind 3 releases a write under a read-shaped precondition, correct the file's comment so it stops claiming
otherwise, and accept the exposure. Not selected; recorded so the cost of declining is on the record.

## Follow-ups

- `docs/internal/tasks/sc-def-01-object-store-write-credential-gate.md` implements the selected option. Blocked until this is Accepted.
- Whether kind 3 is reachable end to end at all is an open question the scout raised and this ADR does not settle. It
  needs its own investigation regardless of what is decided here.
- The defect document's two factual corrections above should be reflected in it when the fix lands.

## References

- `internal/adapter/authority/broker/restore_migration_credential_linux.go` — the three kinds, their preconditions, and the comment stating the intent.
- `internal/secretbootstrap/minio_recovery_policy.go` — `PurposeMinioRestore` granting `PutObject` and `GetObject`.
- `internal/backup/app/restore_coordinator.go` — the `VerifyInventory` call sites that fix the real timing.
- `docs/adr/0015-bind-restore-engine-process-identity-outside-the-authorized-process.md` — precedent for a precondition decision on this mechanism.
