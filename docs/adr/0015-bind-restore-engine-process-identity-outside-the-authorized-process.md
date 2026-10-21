# ADR 0015: Bind restore engine process identity outside the authorized process

- **Number:** 0015
- **Title:** Bind restore engine process identity outside the authorized process
- **Status:** Accepted
- **Created:** 2026-08-13
- **Owners:** Central maintainer
- **Decision due:** 2026-08-20
- **Decision due history:** None
- **Implementation blocked at:** Prerequisite-plan Task 3, and any capacity-reserve precondition that relies on a launch record to distinguish the restore engine from another root peer.
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-13
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/internal/superpowers/plans/2026-08-12-restore-capacity-reserve-prerequisites.md` Task 3; `docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md` (held at revision 4); `docs/internal/superpowers/reviews/2026-08-12-restore-capacity-reserve-authority-security-review.md` findings S2 and B5; ADR 0013 as the precedent for frame peer-authorization decisions.

## Context

The broker daemon's root peer gate admits on `Uid == 0 && Gid == 0`. `SO_PEERCRED` therefore cannot distinguish the
root restore engine from any other root process on the host. Whatever record the daemon consults to decide "this peer is
the restore engine" is the only thing carrying that distinction.

Today no such record exists for `restore verify`. The capacity reserve design proposed one, and its security review
found the proposal circular: the record was to be validated by the engine itself, from a file the engine can write,
using `/proc/self` — "the record says I am me, and `/proc/self` agrees."

The existing backup path does not have this problem, and the reason is instructive. `backupLaunchStore.Issue` writes the
peer PID, executable, and process-start identity **at issue**, validated through `verifyPeerProcess`, because its
supervisor forks the child first and therefore knows a PID the child did not choose. `ValidateWorker` later compares a
connecting peer's kernel-supplied `peer.Pid` against that record. The unforgeable input is the kernel's view of a
*different* process.

The restore launcher runs its engine with `command.Run()`, which does not expose the child's PID before the process
exits, so no equivalent binding is possible today without restructuring.

This decision does not and cannot address an attacker with root code execution who replaces the engine binary. That
adversary holds the record-signing key inside the protected root and can forge any record. The question here is narrower
and still worth deciding: whether a *legitimate* deployment can tell its own engine apart from any other root process.

## Decision

**Option A was selected: bind at launch, from the launcher's own child PID.** The options this ADR was proposed with are
retained under Alternatives considered.

The restore launcher's `command.Run()` is split into `Start()`, then the launch record is patched with the child's
kernel-reported PID and its `verifyPeerProcess` executable and process-start identity, then `Wait()`. The daemon
validates any connecting peer against that already-bound record and refuses a peer that does not match. A legitimate
relaunch after a crash supersedes the prior binding through an explicit transition rather than by silently rebinding.

The identity is written by the parent that created the child, which is the only party in this flow with a view the child
cannot manufacture. This reproduces the mechanism already proven for the backup worker, introduces no new trust
primitive, and requires no wire-format change.

This decision authorizes the launcher restructuring and the daemon-side peer validation it enables. It does not
authorize the capacity reserve gate, which remains held.

## Consequences

### Benefits

- Under Option A, "only the root restore engine" becomes a statement the daemon can check, rather than an aspiration.
- The mechanism is already proven in this codebase on the backup path, so it introduces no new trust primitive.
- Closes security-review finding S2 and re-review finding B5 without a wire change.

### Costs and limitations

- Option A restructures the restore launcher's process handling, and requires a defined supersede transition for a
  legitimate relaunch after a crash — without one, a crashed-and-relaunched engine presents a new PID and is refused.
- No option defends against an attacker who replaces the engine binary; that adversary holds the signing key regardless.
- The verify launch path does not exist yet (prerequisite-plan Task 6), so Option A's binding cannot be exercised for
  `restore verify` until that lands.
- Option A binds whichever process the root helper launches at that path; it does not, and cannot, prove that process
  is the genuine engine and not an attacker-substituted one. Any process with root code execution can exec the pinned
  binary path as its own child and occupy the single launch slot, denying the genuine engine exactly as a crash would
  — this is the same residual root adversary the Context section already excludes, restated as a concrete
  denial-of-recovery path rather than left implicit.

## Alternatives considered

### Bind on the engine's first connect-back

The daemon binds the record to `peer.Pid` on first contact. This is what the capacity design's revision 4 proposed.

Not selected: the security review found it unimplementable as specified and unsafe as designed. The credentials frame
carries only a marker, a kind, and an operation ID, so nothing identifies *which* launch record to bind; and if the
daemon resolves "the single live record" implicitly, the first root peer to speak wins. Any root process that polls the
socket can take the binding, after which the genuine engine is refused and every later check certifies the attacker.
That is a denial-of-recovery primitive.

### Extend the credentials frame with a launch-evidence identifier

Keep connect-back binding, but add a field to the frame so the daemon knows which record to bind, and reject a second
binding attempt.

Not selected: this is the honest version of the connect-back option and it does work, but it costs a wire-format change
to a frame that already serves three credential kinds in Accepted code, with the compatibility handling and
denial-matrix rework that implies. The selected option achieves the same property without touching the wire.

### Accept that the launch record is a self-report

Record explicitly that the restore launch record does not distinguish the engine from another root process, and remove
every claim that it does.

Not selected, though it was the honest do-nothing option: it costs no code and misleads no one. Its consequence is that
any capacity-reserve gate built on the launch record inherits the same weakness, and the design would have to stop
claiming "only the root restore engine" anywhere.

## Follow-ups

- Prerequisite-plan Task 3 implements the selected option. Owner: Central maintainer. Blocked until this ADR is Accepted.
- Prerequisite-plan Task 6 must land before the binding can be exercised for `restore verify`.
- The capacity reserve design's revision 5 must describe the launch binding as this ADR decides it, not as revision 4
  described it.

## References

- `docs/internal/superpowers/reviews/2026-08-12-restore-capacity-reserve-authority-security-review.md` — finding S2.
- `docs/internal/superpowers/reviews/2026-08-12-restore-capacity-reserve-authority-rev4-review.md` — finding B5.
- `docs/adr/0013-widen-frame-0xb1-peer-authorization-to-admit-runtime-uid.md` — precedent for peer-authorization decisions.
- `internal/adapter/authority/broker/backup_launch.go` — the working precedent this ADR proposes to reproduce.
