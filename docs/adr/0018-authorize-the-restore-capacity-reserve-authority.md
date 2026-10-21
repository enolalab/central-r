# ADR 0018: Authorize the restore capacity reserve authority

- **Number:** 0018
- **Title:** Authorize the restore capacity reserve authority
- **Status:** Accepted
- **Created:** 2026-08-13
- **Owners:** Central maintainer
- **Decision due:** 2026-08-20
- **Decision due history:** None
- **Implementation blocked at:** Any code implementing the reserve gate — helper-side physical allocation, frame `0xc3` and its record store, the new preconditions on frame `0xc2` kind 1's release, the launch-record field its predicate needs, and the reserve inspection surface. `unavailableAdmissionInspector` stays in place until this is Accepted.
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-13
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md` (revision 8); ADR 0015 (launch identity), ADR 0016 (terminal outcome), ADR 0017 (kind 3 precondition) as the decisions this one builds on; `docs/internal/superpowers/plans/2026-08-12-restore-capacity-reserve-prerequisites.md`.

## Context

C03's production `RestoreAdmissionInspector` is a fail-closed stub, so `restore verify` is unavailable and SC-G2 cannot
be attempted. The consumer side — receipt schema, four capacity roles, verifier port, and `DescriptorRestoreCapacitySource` —
is complete and frozen. What is missing is the producer and the gate.

The design reached this point the hard way. Seven review rounds across eight revisions each found the same class of
defect: a property the call graph could not deliver. Revisions 1–3 asserted an enforcement point that did not exist;
revision 4 placed it correctly and blocked on three prerequisites; revision 5 named real symbols that did not reach the
gate; revision 6 stated an invariant its own numbers violated; revision 7 found a predicate that would have compared a
bare PID. That history is why this ADR exists in the form it does: **the design now states what it cannot do as
prominently as what it can**, and this ADR is asked to authorize both halves.

The prerequisites are built and reviewed: shared demand arithmetic in the domain package, role roots reaching the broker
service, a launch identity bound by the parent before the child can speak, a terminal outcome for an interrupted restore,
typed operator-visible refusal reasons, a real `restore verify` invocation path, and a seccomp baseline established after
a BPF arch-check inversion was found that had made the filter kill the daemon on its first post-install syscall.

## Decision

**Option A was selected: the design is authorized as revision 8 specifies, residuals included.** The options this ADR was
proposed with are retained under Alternatives considered.

Authorized together:

- the helper's capability to physically allocate and release survival reserves on allowlisted devices under root;
- the narrowing of supported recovery-device filesystems to ext4 and XFS, as a product-constraint change owned by the
  local backup contract;
- frame `0xc3`, its denial matrix, and **the launch-record field carrying the helper's executable and process-start**,
  without which its predicate is a bare PID comparison and decision 2's residual is indefensible;
- the four new preconditions on frame `0xc2` kind 1's credential release;
- the reserve inspection surface, admitting root peers only;
- the five decisions recorded at the end of the design, **including their two residuals**, which are ratified here
  explicitly rather than absorbed;
- on seccomp, **the position and not a conclusion**: four of five daemon-side operations are traced and probed and need
  no amendment; the fifth, the `st_dev` anchor, is unprobed, and its likely no-amendment answer must be established by a
  probe before it is recorded as settled.

### Addendum, 2026-08-14 (hieuntg81): verify allocates

Recorded under this ADR's existing Accepted decision, not as a new ADR — this changes an implementation detail this
ADR authorized, not the decision to build the gate at all, and Status remains Accepted. The maintainer took this
decision directly, the same direct-decision authority this ADR's own `Decision record: Git status-transition commit`
used.

Revision 8, as authorized, left ambiguous which launch allocates the reserve and draws its receipts. The
implementation plan this ADR's Follow-ups section already names
([2026-08-13 restore-capacity-reserve-gate.md](../internal/superpowers/plans/2026-08-13-restore-capacity-reserve-gate.md),
Tasks 9B and 9C) found the ambiguity was load-bearing and irresolvable as revision 8 left it: the admission
inspector precondition 1 gates runs only under `restore verify`; frame `0xc4` as authorized refuses mode `verify`;
and no reserve set can exist at verify time because `CreateSetIntent` is keyed to an `OperationID` minted only after
the inspector has already returned. At most two of those three can hold together. This ADR's own Context sentence —
"C03's production `RestoreAdmissionInspector` is a fail-closed stub, so `restore verify` is unavailable" — already
assumed the inspector runs under verify, and therefore that verify allocates; the mode gate and the operation
keying, not that assumption, are what this addendum brings into line with it.

**Decision: verify allocates.** Allocation of the physical reserve and the draw of its four broker receipts move to
the `restore verify` launch. Frame `0xc3` kind 1 no longer carries `OperationID`. A new frame `0xc4` kind 3 (`bind`)
lets the engine, once its own in-process `IssueRestoreTicket` has minted an `OperationID`, tell the daemon which
reserve set the resulting operation continues.

**What this changes in what was ratified.** The preconditions on frame `0xc2` kind 1's release, authorized above,
checked a launch pin — the set's recorded launch evidence against the *calling peer's* launch evidence — that worked
only because the launch store's single record file meant an apply launch could never carry the same evidence id as
the verify launch that drew the receipts. Once verify allocates, apply and verify are *always* different launches by
construction, so that pin can no longer distinguish an authorized draw from an unauthorized one. It is replaced by
an issuing-launch binding: the ticket record carries the launch that issued it, the operation record carries that
forward, and the gate checks the set's creating launch against that chain rather than against the caller's own
launch. This is the change referenced in Costs and limitations above, where the object-bytes residual's
defensibility was tied to frame `0xc3`'s predicate holding: that predicate itself is unchanged by this addendum, but
the binding built on top of it — the one that stopped a receipt drawn under one launch from paying for a destructive
run under another — is exactly what this addendum replaces.

**A retention gap this addendum requires the sweep to close, before the launch pin is relaxed and not after.** A
reserve set whose operation record is absent is not protected by the release-trigger table the design records, and
the operation record is written only at apply. Left unaddressed, a *successful* verify's reserve would release
itself the moment the verify process exits, before the operator ever runs apply — the failure mode that would make
this whole authority a silent no-op on its own success path. The design's 2026-08-14 amendment (revision 9) records
the five retention rules this requires; they are part of what this addendum authorizes, not a separable follow-up,
and gate-plan Task 9B sequences the sweep's rules to land before the gate's pin is relaxed for exactly this reason.

**What this does not change.** The gate's independent physical re-checks — the daemon's own re-derivation of demand
from its seal, the floor and margin re-applied against the helper-recorded observation, and the daemon's own
`fstat` of allocated blocks — are unaffected and are not a substitute for the binding above; they answer whether the
reserve is physically real, not whether it was created for the operation now spending it.

See [the design's 2026-08-14 amendment](../internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md)
(revision 9) for the full replacement, proof, and reopening conditions, and
[the implementation plan's Tasks 9B and 9C](../internal/superpowers/plans/2026-08-13-restore-capacity-reserve-gate.md) for
the sequencing this addendum requires.

The property the gate buys is worth its surface. Against an attacker with root code execution and a substituted engine
binary the design provides nothing, and says so — but ENOSPC part-way through a `pg_restore` on a machine the operator
has already accepted as damaged is a realistic, non-adversarial data-loss path, and bugs, races, partial failures and
crash windows are the threat a single-operator local tool actually faces.

**What this authorizes and what it does not.** It authorizes implementation. It does not accept any Slice C packet:
SC-G2 remains a separate gate with its own immutable evidence manifest and independent verdict. It does not authorize
the object-bytes chunk reader, which the design deliberately declined. And it does not authorize implementation to begin
before the launch-record field lands, because two of the gate's guarantees rest on it.

## Consequences

### Benefits

- Restore admission gains a real capacity decision, checked by a different process than the one that computes it, at the
  release of the credential that performs the destructive act.
- The daemon re-derives the floor and margin from evidence the helper recorded, so a compromised or buggy engine cannot
  buy admission with its own numbers.
- Every mechanism the design names now exists in the tree, so implementation is wiring rather than invention.

### Costs and limitations

- **The object-bytes demand term is unverifiable at the gate.** The seal carries per-chunk entry counts, not per-entry
  sizes, so the daemon can re-derive dump bytes and artifact count but not object bytes. The adversary table records this
  as not prevented in every column. It is defensible only while frame `0xc3`'s predicate holds. **Addendum, 2026-08-14
  (hieuntg81).** That predicate is unchanged. What changed is the binding built on top of it: revision 8 located the
  work of stopping a verify-drawn receipt from paying for a destructive run in the launch pin,
  `set.LaunchEvidenceID == binding.LaunchEvidenceID`; the 2026-08-14 decision that verify allocates makes that pin
  structurally unable to do that work (apply and verify are now always different launches) and replaces it with an
  issuing-launch binding carried from the ticket through the operation record to the gate. See the Decision section's
  addendum below.
- **The demand plan knowingly understates the true write on every current topology.** Where the recovery repository
  shares a device with a PostgreSQL role, restore-side staging and quarantine writes are absorbed by the survival
  reserve rather than modelled. That is the reserve's purpose, but it is a stated tolerance.
- Against root code execution with a substituted engine binary the design provides no security property, and makes no
  tamper-evidence claim — both the original and a narrowed version of that claim were withdrawn in earlier revisions.
- On a host that only ever runs `central serve`, reserved bytes may remain past their own absolute expiry until the next
  root-owned invocation, because only root can free them and nothing runs on a schedule.
- The helper gains a new privileged capability: allocating and releasing multi-gigabyte files under root.

## Alternatives considered

### Authorize everything except the object-bytes residual

Require the daemon-side inventory chunk reader before implementation, so all three demand terms are daemon-derived.

Not selected. It buys a term whose exploitation already requires defeating frame `0xc3`'s predicate — and once that
falls, the free-space observations fall with the demand figures, so the gate's other preconditions are compromised
anyway. Against that it adds a bounded parse of repository data inside the most privileged process on the host. The
design records the reopening condition instead, which holds the question open more cheaply.

### Defer until a prototype exists

Withhold authorization until the gate is built far enough to demonstrate end to end.

Not selected, though it is coherent and would have caught things in earlier rounds. The part that kept failing review was
the prerequisites, and they are built and independently verified. What remains is the gate, which cannot be prototyped
without this authorization — so deferring would leave the design waiting on work that waits on the design.

### Do not build the gate

Keep `unavailableAdmissionInspector`, record that restore admission has no capacity authority, and stop.

Not selected. Recorded because it deserved stating rather than being assumed away, and with its real consequence noted:
it is not neutral. `restore verify` would remain unavailable, C03 could not complete, and SC-G2 could not be attempted —
it forecloses Slice C's recovery gate.

### Earlier enforcement placements

The design additionally records, and rejects with reasons, the placements seven review rounds eliminated: gating ticket
issuance rather than credential release, connect-back identity binding, byte-equality digest recomputation, and an
engine-hosted verification boundary.

## Follow-ups

- The design's [implementation plan](../internal/superpowers/plans/2026-08-13-restore-capacity-reserve-gate.md), which sequences
  the gate behind the launch-record field its predicate depends on. Drafted 2026-08-13; requires plan review before its
  Task 1 begins.
- ~~The `st_dev` anchor probe, before the seccomp position is recorded as settled.~~ **Settled 2026-08-13, gate-plan
  Task 2.** `TestSeccompFilterAllowsRoleRootStDevAnchor`
  (`internal/adapter/authority/broker/hardening_filter_test.go`) probes the anchor performed from a held descriptor
  (`os.Open` then `unix.Fstat`, never a path-based stat): it issues `openat` (257) and the raw `SYS_FSTAT` (5), both
  already on the allowlist, so **no amendment was needed**. Established by probe, including a mutation check that
  removed 5 from the allowlist, confirmed the probe died with `SIGSYS`, and restored it — not by reading the allowlist.
  All five daemon-side operations are now traced and probed.
- `docs/operations/local-backup-and-restore.md` and the local backup contract's supported-filesystem statement, per the
  design's documentation-impact section.
- SC-G2 acceptance remains a separate gate with its own manifest and independent verdict; this ADR authorizes
  implementation, not acceptance.
- **Addendum, 2026-08-14 (hieuntg81): verify allocates.** See the Decision section's addendum above and the design's
  own 2026-08-14 amendment (revision 9). Gate-plan Tasks 9B and 9C implement the issuing-launch binding and the
  frame changes it requires; Task 9B's sweep retention rules must land before the launch pin is relaxed, not after,
  or a successful verify's reserve releases itself before the operator can run apply.

## References

- `docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md` — revision 8, the design this authorizes.
- `docs/internal/superpowers/reviews/2026-08-12-restore-capacity-reserve-authority-security-review.md`, `…-rev4-review.md`, `…-spec-rereview.md`, `docs/internal/superpowers/reviews/2026-08-13-restore-capacity-reserve-authority-rev5-review.md` — the review history that shaped it.
- `docs/adr/0015-…`, `0016-…`, `0017-…` — the decisions this one builds on.
- `docs/internal/superpowers/plans/2026-08-12-restore-capacity-reserve-prerequisites.md` — the prerequisite work, complete.
