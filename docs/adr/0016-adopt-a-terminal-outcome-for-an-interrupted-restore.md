# ADR 0016: Adopt a terminal outcome for an interrupted restore

- **Number:** 0016
- **Title:** Adopt a terminal outcome for an interrupted restore
- **Status:** Accepted
- **Created:** 2026-08-13
- **Owners:** Central maintainer
- **Decision due:** 2026-08-20
- **Decision due history:** None
- **Implementation blocked at:** Prerequisite-plan Task 4; the capacity-reserve sweep's refusal to release a set bound to a non-terminal applying operation; and the operator instruction in the capacity design's stuck-apply flow, which currently names a transition that does not exist.
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-13
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** ADR 0028 (the abandonment ceremony may be satisfied by a pre-authorized grant naming the exact operation ID; "never automatic, never by timeout" is unchanged)
- **Related:** `docs/internal/superpowers/plans/2026-08-12-restore-capacity-reserve-prerequisites.md` Task 4; `docs/internal/superpowers/specs/2026-08-09-slice-c-required-recovery-design.md`; `docs/internal/superpowers/reviews/2026-08-12-restore-capacity-reserve-authority-security-review.md` finding C2; ADR 0001 and ADR 0002 as lifecycle-decision precedent.

## Context

The restore lifecycle has four phases — `applying`, `verifying`, `quarantined`, `ready` — and `IsResumable()` stays
true for `applying` indefinitely. `ServingAllowed()` requires `ready` plus an authority reset. There is no terminal
failure outcome.

That is deliberate in spirit: this slice forbids force flags and direct state repair precisely so an operator cannot
shortcut past a restore that is still resumable, abandoning a half-replaced database. But it produces a state with no
exit. The restore launcher sets `Pdeathsig: SIGKILL`, so an operator disconnect kills the engine mid-apply. The
operation then stays `applying` and resumable forever, and anything bound to it stays bound forever.

The capacity reserve design hit this directly: its sweep must refuse to release a reserve bound to a non-terminal
applying operation — correct, since force-releasing an in-flight reserve is the failure it exists to prevent — but that
makes up to 16 GiB pinned indefinitely, and its single-live-set rule then refuses every future verify for any other
backup. Its remedy instructs the operator to "explicitly accept that target as unrecoverable", which names no transition
that exists.

This is not a capacity problem. **Slice C needs this outcome whether or not a reserve mechanism ever ships**: today any
interrupted restore is unresolvable, and the recovery slice's own acceptance requires an operator to be able to act.

## Decision

**Option A was selected: a terminal `abandoned` outcome behind a deliberate ceremony.** The options this ADR was
proposed with are retained under Alternatives considered.

An operator may declare the outcome only through a fresh PAM and physical-TTY ceremony naming the exact operation, with
explicit acknowledgement that the target's data is being given up. It is irreversible: an abandoned operation can never
serve and can never resume. It releases resources bound to the operation. It is never reachable automatically, never by
timeout, and never as a side effect of any other command.

This is the only option that gives the operator a way forward while keeping the property the slice was built to protect.
Abandonment costs the same ceremony as a destructive restore, so it cannot be stumbled into, and its irreversibility
means it can never serve as a cheaper alternative to resuming.

The risk was weighed explicitly: any "declare defeat" transition is adjacent to the force flag this slice forbids. It is
accepted because the outcome forbids *more* than the current state does — an abandoned operation is permanently
unservable, whereas a stuck `applying` operation is merely stuck, and its resources are pinned with no exit.

This decision authorizes the lifecycle change and the operator verb it requires. It does not authorize the capacity
reserve gate, which remains held; it authorizes the transition that gate's release rules and stuck-apply instruction
must be written against.

## Consequences

### Benefits

- Under Option A, an interrupted restore has an exit, and the capacity design's stuck-apply instruction can name a real
  transition.
- Resources bound to a dead operation become releasable through a path that is auditable rather than implicit.
- Closes security-review finding C2, which the review rated blocking.

### Costs and limitations

- Option A is a domain lifecycle change: every consumer of restore phase and `IsResumable()` must be re-examined, and
  the serving gate must treat the new outcome as permanently unservable.
- It adds an operator-facing destructive verb, with the runbook, transcript, and denial-path work that implies.
- It cannot be reached without the PAM/TTY ceremony, so an operator who has lost console access to the host has no
  remote path — deliberate, and worth stating rather than discovering.

## Alternatives considered

### Automatic abandonment at the hard operation deadline

Let an operation that exceeds the 8-hour hard deadline become terminal on its own, releasing what it holds, with no
ceremony.

Not selected. It is simple and needs no new operator surface, but it is the option that most directly violates the
slice's core rule: it auto-abandons a restore that may still be resumable, silently converting a recoverable
half-restored database into an unrecoverable one because nobody was at the keyboard. Adopting it would mean accepting
that a timeout can destroy a recoverable target.

### No terminal outcome; an authenticated release override instead

Leave the lifecycle unchanged and give reconciliation an authenticated, journaled path to release resources bound to a
stuck operation, while the operation itself stays resumable forever.

Not selected, though it has a narrower blast radius and would solve the immediate resource-pinning symptom. It does not
solve the underlying problem: the operator still could not declare a target dead, the system would still treat an
abandoned restore as pending forever, and the capacity design's stuck-apply instruction would still have no transition
to name. It defers rather than resolves.

### Do nothing

Interrupted restores stay unresolvable. Resources bound to them pin indefinitely. The capacity design would have to
delete its stuck-apply instruction rather than fix it, and record that an operator disconnect mid-apply is unrecoverable
without manual intervention the slice forbids.

Not selected; recorded so the cost of not deciding stays on the record.

## Follow-ups

- Prerequisite-plan Task 4 implements the selected option. Owner: Central maintainer. Blocked until this ADR is Accepted.
- The capacity reserve design's revision 5 must state its release triggers and its stuck-apply instruction in terms of
  whatever this ADR decides.
- If Option A or C is selected, the operator runbook needs the new path, its denial cases, and its irreversibility.

## References

- `docs/internal/superpowers/reviews/2026-08-12-restore-capacity-reserve-authority-security-review.md` — finding C2.
- `internal/backup/recovery.go` — the current phase set, `IsResumable()`, and `ServingAllowed()`.
- `cmd/central/restore_engine_launcher.go` — `Pdeathsig: SIGKILL`, which produces the interrupted state without operator action.
- `docs/adr/0001-adopt-durable-task-domain-and-lifecycle.md`, `docs/adr/0002-authorize-accepted-to-superseded-status-transitions.md` — lifecycle-decision precedent.
