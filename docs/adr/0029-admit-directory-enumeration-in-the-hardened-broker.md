# ADR 0029: Admit directory enumeration (getdents64) in the hardened broker and hold the reserve engine's no-enumeration property at the source level

- **Number:** 0029
- **Title:** Admit directory enumeration (getdents64) in the hardened broker and hold the reserve engine's no-enumeration property at the source level
- **Status:** Accepted (Option A)
- **Created:** 2026-09-06
- **Owners:** Central maintainer
- **Decision due:** 2026-09-13
- **Decision due history:** None
- **Implementation blocked at:** None; implemented under ADR 0028 D3 in the commit following the status transition.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-09-06)
- **Decision date:** 2026-09-06
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** The seccomp decision recorded in `docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md` ("the syscalls this adds to the daemon must be enumerated and added ... `hardening.go` stays frozen") and in the SC-DEF-07 note in `hardening.go` ("Deliberately NOT added: getdents64")
- **Amended by:** None
- **Related:** ADR 0018 (restore capacity reserve authority); ADR 0028 D3 (why this is an ADR and not a unilateral fix); `docs/internal/tasks/sc-def-07-*.md`, `docs/internal/tasks/sc-def-10-*.md`, `docs/internal/tasks/sc-def-24-*.md`

## Context

The broker's seccomp allow-list excludes `getdents64` (217) on purpose. The restore capacity reserve engine was designed around that exclusion: the sweep runs in the root helper "because it genuinely cannot run in the daemon", the reserve store keeps an operation→set pointer "because the only alternative is enumerating the set directory, which means getdents64: not on the hardened daemon's seccomp allow-list, and deliberately so", and `TestSeccompFilterRefusesReserveStoreSweep` runs the sweep's one enumeration primitive under the real filter and asserts the kernel kills it. The stated benefit: the most privileged process on the host cannot discover reserve objects by listing; it can only reach them by name.

That design rests on a premise nobody had tested: that the daemon's *other* code does not enumerate either. It does. On 2026-09-06 the first `central local up` ever run with the committed filter installed (SC-DEF-24 fixed the kills that came before it) died on:

```
7592  openat(AT_FDCWD, ".../protected/generations", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 9
7592  getdents64(9, ... /* 4 entries */, 8192) = 217
7591  +++ killed by SIGSYS +++
```

That is `protected_file.go:116`'s `os.ReadDir(gensDir)` — the protected-generation reader, on the `adopt_b03_minio_bootstrap` dispatch path. It is one of about twenty `os.ReadDir`/`Readdirnames` sites reachable from the daemon's request surface: `journal.go` (5), `recovery_journal.go` (3), `secret_bootstrap.go` (8), `payload_epoch_store_linux.go` (1), `protected_file.go` (1), plus the two reserve-engine sites the design already knows about. Listing a generation directory to find the newest generation, listing leases and bindings to reconcile them, listing an operation's journal stream — these are how the daemon's durable stores work, and every one of them is a `getdents64`.

So the filter as committed and the daemon as written cannot both be true. Every console run from SC-DEF-11 to SC-DEF-23 avoided finding this because the VM binary carried an uncommitted `return nil` at the top of `Harden()` (recorded in SC-DEF-24).

This is a security decision, not an allow-list bookkeeping change: admitting 217 removes a kernel-enforced property the reserve design cites. ADR 0028 D3 therefore requires it to be an ADR.

## Decision

**Proposed: Option A.** Admit `getdents64` to the allow-list, and move the reserve engine's "no enumeration" property from the kernel to the source level, where the design already holds half of it.

Concretely:

1. `installSeccompFilter` gains `217, // getdents64` with the SC-DEF-24/ADR 0029 evidence inline, in the same evidenced-addition form as every other entry. `fallocate` stays excluded; nothing on the daemon's path issues it.
2. `TestSeccompFilterRefusesReserveStoreSweep` is replaced, not deleted: its subject becomes a source-level assertion that no file under the reserve engine's own set (`restore_capacity_reserve_*.go`) enumerates a directory except through `restoreCapacityReserveSweepNames`, and that that function is not referenced from `service.go`'s dispatch. `TestRestoreCapacityReserveSweepEnumeratesThroughOneChokepoint` already pins the first half; the second half is new and is what keeps the sweep in the helper by construction rather than by comment.
3. The reserve store's operation→set pointer and the sweep's placement in the helper are **unchanged**. They were justified by the exclusion; they remain good design without it (the pointer is create-only and re-validated on every read; the sweep still runs beside the allocator with no need for daemon privilege). Their comments are updated to cite this ADR instead of the allow-list.
4. The reserve design spec's "hardening.go stays frozen" sentence is amended to point here.

What is given up, stated plainly: after this, a code change that made the daemon enumerate the reserve set directory would be caught by a test, not by the kernel. The kernel property was never real for the daemon as a whole — it was real only for the reserve engine's own files — so what is lost is a defence for one subsystem that the daemon's other subsystems already could not have.

### Option B — keep 217 refused; remove enumeration from the daemon's dispatch path

Rewrite the ~20 listing sites so every read is by known name: generations by a `current` pointer file, leases and bindings by index records, journal streams by sequence counters with a persisted high-water mark. This keeps the kernel property and extends it to the whole daemon.

Not proposed. It is a rewrite of the persistence layer of every store the daemon owns, touching Accepted B03/B04/B05 code, for a property those stores were never designed to have. It cannot be done with the confidence a one-line allow-list change carries, and it would have to be done before any Slice C gate can run.

### Option C — admit 217 and leave the tests and comments as they are

Not proposed. `TestSeccompFilterRefusesReserveStoreSweep` would go red, and the design's stated rationale would become false on the record. Option A is Option C plus honesty.

## Consequences

### Benefits

- The daemon survives its own filter on a real `local up`; SC-DEF-20 Task 4 and SC-G1–SC-G3 become runnable.
- The reserve engine's placement and record design stay exactly as accepted; only their justification moves.
- The invariant that mattered — the sweep never runs in the daemon — becomes a build-time assertion rather than a runtime kill.

### Costs and limitations

- One kernel-enforced property is replaced by a source-level test. A future daemon path that enumerates the reserve set directory is a test failure, not a SIGSYS.
- The allow-list is still being widened one kill at a time. The exhaustion run SC-DEF-10 and SC-DEF-24 both ask for (full `local up` → backup → restore cycle, filter neutralised, straced, diffed once) remains the right next step and is still owed.
- `TestSeccompFilterRefusesReserveStoreSweep`'s current form was cited by the reserve design's review as evidence; that citation needs the same amendment.

## Alternatives considered

Options B and C above. Also considered and rejected: exempting only specific directories via a path-aware filter — seccomp cannot inspect the path behind a descriptor, so there is no such filter.

## Follow-ups

- **Decision needed (this ADR).** Owner: Central maintainer.
- On Acceptance: implement 1–4 above in one commit under D3 with the source-level test failing-before/passing-after; re-run `local up` on the rehearsal VM with the committed filter; record the outcome in `docs/internal/tasks/sc-def-24-*.md`.
- The exhaustion run, when a person can ship the diagnostic build to the VM.

## References

- `internal/adapter/authority/broker/hardening.go` — the SC-DEF-07 exclusion note and the allow-list.
- `internal/adapter/authority/broker/protected_file.go:116` — the enumeration that died; `journal.go`, `recovery_journal.go`, `secret_bootstrap.go`, `payload_epoch_store_linux.go` — the others.
- `internal/adapter/authority/broker/restore_capacity_reserve_sweep_linux.go` ("Where this runs, and why — the seccomp decision"), `restore_capacity_reserve_store.go` (the pointer rationale).
- `internal/adapter/authority/broker/hardening_filter_test.go` — `TestSeccompFilterRefusesReserveStoreSweep`, `TestRestoreCapacityReserveSweepEnumeratesThroughOneChokepoint`.
- `docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md` §"The syscalls this adds to the daemon".
- `docs/internal/tasks/sc-def-24-broker-seccomp-kills-runtime-thread-creation-after-harden.md` — the run that found this, and the finding about the SC-DEF-11–23 evidence base.
