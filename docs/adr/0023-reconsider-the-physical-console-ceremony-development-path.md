# ADR 0023: Reconsider the physical-console ceremony's development path

- **Number:** 0023
- **Title:** Reconsider the physical-console ceremony's development path
- **Status:** Accepted (Options B and C; Option D not adopted)
- **Created:** 2026-08-19
- **Owners:** Central maintainer
- **Decision due:** None set
- **Decision due history:** None
- **Implementation blocked at:** Option D remains blocked — any change to
  `openPhysicalTTY` (`internal/adapter/authority/helper/pam_linux.go`), to what
  counts as a qualifying console in
  `docs/operations/slice-c-maintainer-tasks.md` B1, or to the
  `privilege_profile` / `ceremony_records` manifest fields
  (`docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md`, fields
  16 and 21) still requires its own follow-up ADR per "Follow-ups" below.
  Options B and C carry no such block: B is documentation already applied to
  the runbook, and C requires no code or governance change at all.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-19)
- **Decision date:** 2026-08-19
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None (would narrow, not replace, the control introduced for
  SC-G1–SC-G3 in `docs/operations/slice-c-maintainer-tasks.md`)
- **Amended by:** ADR 0028 (lifts the Option D block by adopting a `grant` ceremony mode instead of remote attestation; `openPhysicalTTY` and the `physical_tty` default are unchanged); ADR 0031 (widens the formal-acceptance path with a Docker evidence profile for SC-G3; does not replace the physical-console track)
- **Related:** Slice C acceptance governance spec (fields 16, 21); ADR 0015
  (restore-engine process identity); ADR 0016 (interrupted-restore terminal
  outcome); `internal/adapter/authority/helper/pam_linux.go`
  (`openPhysicalTTY`, `PerformTTYCeremony`)

## Context

SC-G1 through SC-G3 gate every destructive step (`restore apply`, `resume`,
`abandon`) on a confirmation typed at a **real** TTY: `openPhysicalTTY` reads
`/proc/<peer-pid>/fd/0`, requires the target to start with `/dev/tty` and
explicitly rejects anything under `/dev/pts/` — SSH, `screen`, `tmux`, and any
container/sandbox pty are all refused by construction, not by policy. The
manifest's `privilege_profile` field records whether a physical TTY was
present and is checked against the run log; a manifest asserting one that the
log doesn't corroborate is rejected.

The maintainer (this repo's operator) currently has no host that satisfies
Task B1 in `docs/operations/slice-c-maintainer-tasks.md`: root, Docker,
`/etc/pam.d/central-helper`, and a real serial/VT device. Their stated goal is
development velocity — Slice C's SC-G1–SC-G3 work (C01–C06) cannot be
exercised end-to-end, including in ordinary development iteration on the
ceremony-adjacent code, without first acquiring qualifying hardware.

Two distinct things are currently coupled by "no qualifying host":

1. **Formal acceptance** — the one-time act of a maintainer authorising an
   irreversible operation, where the physical-presence guarantee is the whole
   point (a present human, not a script, per the runbook).
2. **Development iteration** — writing, debugging, and exercising the code
   that *implements* the ceremony (the helper RPCs, the manifest fields, the
   B1–B4 automation), which does not inherently need a human physically
   present every time a developer runs a test.

**Audit finding (2026-08-19), corrects an earlier draft of this ADR:** the
codebase does *not* separate these today. `ceremony_open_linux_test.go` and
`tty_ceremony_read_linux_test.go` test `openPhysicalTTY`'s implementation
details (flags, deadlines, the exclusive lock) against a real device or by
parsing its own source; `reference_host_preflight_test.go`
(`TestPreflightPhysicalTTY`) only verifies the ceremony **fails closed**
without a physical peer. The entire `cmd/central/c06_*.go` suite goes further:
it actively asserts, in dozens of places, that "no substitute confirmer,
launcher or peer identity is registered anywhere." There is no path — test
double or otherwise — to exercise a *successful* ceremony without a real
`/dev/tty*` device, and adding one would contradict an invariant that suite
already protects deliberately. Even the project's own C06 driver, when run
against a real console device, documents that whether the device "counts as
physical for governance field 16 is a maintainer judgement and not a fact
this run establishes" (`c06CeremonyScopeDisclosure`,
`cmd/central/c06_ceremony_driver_test.go`) — this tension is already
recognised in-tree, not new.

What *is* true, and is the actual basis for Option B below: `openPhysicalTTY`
checks only that the peer's own `/proc/<pid>/fd/0` resolves to a real
`/dev/tty*` (not a `/dev/pts/*`) — nothing in the predicate requires a
dedicated serial line or specialised hardware. A locally-run VM (QEMU,
VirtualBox, etc.) with a virtual serial/console device attached to a terminal
window satisfies the same predicate this sandbox's `/dev/ttyS4` does — the
problem in this sandbox was never the device type, it was that the agent has
shell access to the same device the human would confirm on. A VM the agent
has no credentials or shell into, whose console only the maintainer's own
terminal reaches, resolves that specific problem without touching the control
at all.

## Decision

**Options B and C are accepted; Option D is not adopted.** Option A (status
quo) is superseded by B for development purposes; B1 hardware is still
required for B3/acceptance itself, which C addresses when the maintainer
provisions a qualifying VM. Neither accepted option touches
`openPhysicalTTY`, the B1 checklist's console requirement, or any manifest
field — B is a documentation change already applied to
`docs/operations/slice-c-maintainer-tasks.md`, and C is a host-provisioning
choice the maintainer makes when ready to run SC-G1, not a code or governance
change. Option D (replacing the physical-TTY check with a remote-attestation
factor) is explicitly **not adopted** — it's the one option that would change
the acceptance guarantee itself, and the maintainer's goal here was
development velocity, not a reason to believe the physical-presence property
is wrong on its merits. D stays available as a future option if a genuine
case is made on those grounds, per its own follow-up below.

### Option A — Status quo: no change

Keep B1 as the only path. SC-G1–SC-G3 development and acceptance both wait on
a qualifying physical host.

### Option B — Document the B1-vs-B2/B4 split; no code change

`openPhysicalTTY` and the C06 suite stay exactly as strict as today — no test
double is added, since the audit above found none can be added without
weakening an invariant the suite deliberately protects. What Option B adds is
documentation only: the runbook currently reads as if all of Task B needs a
qualifying B1 host. In fact only **B3** (the single console confirmation)
does. Developing or debugging B2's automation (build, install, bring-up,
`central backup create`, evidence archival) and B4's manifest/skeleton
preparation needs no physical console at all — that code can be iterated on
today, on any host, using the existing `testdata/*-reference-host` compose
fixtures the way this session already did for B06. Document that split in the
runbook so "no B1 host" stops reading as "no Slice C development possible."

### Option C — A locally-run VM as the qualifying host

Provision a VM (QEMU, VirtualBox, or similar) on hardware the maintainer
already owns, with a virtual serial/console device the maintainer's own
terminal window connects to. This satisfies `openPhysicalTTY`'s actual
predicate (a real `/dev/tty*`, not a `/dev/pts/*`) exactly as well as
dedicated hardware would, at no acquisition cost — the only requirement is
that the VM's console is reachable **solely** by the maintainer's own session,
with no credentials, shell, or hypervisor API access available to the agent.
This is a documentation/process change (how to stand up a qualifying host),
not a code or governance change, and doesn't reduce the guarantee at all: the
predicate the code checks is unchanged, and the isolation-from-the-agent
property is exactly what made this conversation's sandbox `/dev/ttyS4`
disqualified — a VM the agent has no access into does not share that flaw.

### Option D — Remote-attestation alternative to a physical TTY

Replace or supplement the physical-TTY check with an out-of-band proof of
human presence that doesn't require being physically at the machine (e.g. a
FIDO2/hardware-key touch, or a signed approval from a second device over a
side channel). This is the only option that actually changes the security
property (from "physically present at this machine" to "possesses a
particular second factor"), and is a materially larger design effort:
`openPhysicalTTY`'s guarantee — that the connecting peer's own stdin is a real
console, checked via `/proc/<pid>/fd/0` — has no direct equivalent for a
remote factor; a new binding between the confirming factor and the specific
`opID`/`target` would need to be designed and would touch the
`ceremony_records` manifest field's meaning (field 21) and possibly its
schema.

## Consequences

### Benefits

- **B (recommended first step):** Unblocks all Slice C development that isn't
  the ceremony confirmation itself, immediately and at zero cost — it's a
  documentation change, the control is untouched.
- **C (recommended to actually run SC-G1):** Solves "I have no host" at
  effectively zero cost (a VM on hardware already owned) and zero cost to the
  guarantee — the predicate checked is unchanged, only console-isolation from
  the agent is required.
- **D:** Would remove the physical-presence *hardware* requirement entirely,
  enabling acceptance runs from anywhere — but only if the replacement
  guarantee is judged equivalent, which is a real security decision, not a
  convenience one.

### Costs and limitations

- **B** doesn't get the maintainer any closer to actually running SC-G1
  itself; it only means B2/B4 iteration doesn't wait on hardware the
  maintainer doesn't have.
- **C** requires the maintainer to keep the VM's console genuinely isolated
  from the agent (no shared shell, no hypervisor control socket the agent can
  reach) — a discipline requirement, not a hardware cost, but a real one: a
  misconfigured VM (e.g. one the agent can `virsh console` into) recreates
  exactly this session's disqualifying flaw.
- **D** is the only option that touches the acceptance guarantee itself, so
  it carries the most risk, the most implementation cost, and needs the most
  scrutiny before being trusted for an irreversible operation. It should not
  be adopted for velocity alone.

## Alternatives considered

### Remove the physical-console requirement outright

Rejected outright, not merely deprioritized: the runbook is explicit that
removing this control "so acceptance can be self-issued... produces a false
certification, not an accepted Slice C." Velocity is not, on its own, a reason
this control is *wrong* — only a reason it's inconvenient, which the runbook
distinguishes explicitly ("if the controls are genuinely wrong... not merely
inconvenient").

### Let the agent perform the console confirmation

Rejected for the same reason it was refused earlier in this conversation: the
agent has direct access to this sandbox's `/dev/ttyS4`, so it cannot serve as
an independent human-presence proof for itself. No documentation or ADR change
alters that fact; it would need Option D's different guarantee to be
meaningful, and even then the agent must not be the confirming party.

## Follow-ups

- **Done:** the B1-vs-B2/B4 split language is applied to
  `docs/operations/slice-c-maintainer-tasks.md` (Option B).
- **Open, maintainer-owned:** provision a VM whose console the agent cannot
  reach (no shared shell, no hypervisor API access), then re-run the B1
  checklist against it before starting Task B (Option C). Not something the
  agent can do on the maintainer's behalf.
- **Not started:** Option D was not adopted. If reconsidered later on its own
  merits (not for velocity), it needs its own follow-up ADR specifying the new
  factor, its binding to `opID`/`target`, and the manifest-schema impact on
  `ceremony_records` (field 21) before any implementation.
- Independent of any of the above: the independent-verdict guarantee (a
  reviewer outside the implementation lineage) is unaffected and stays exactly
  as strict.

## References

- `docs/operations/slice-c-maintainer-tasks.md` — Task B1 checklist and "A
  legitimate alternative" section, which this ADR is the response to.
- `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md` —
  fields 16 (`privilege_profile`) and 21 (`ceremony_records`).
- `internal/adapter/authority/helper/pam_linux.go` — `openPhysicalTTY`,
  `PerformTTYCeremony`.
- `internal/adapter/authority/helper/ceremony_open_linux_test.go`,
  `tty_ceremony_read_linux_test.go` — implementation-detail tests against a
  real device; not behavioral doubles.
- `internal/dependencyprepare/preflight/reference_host_preflight_test.go`
  (`TestPreflightPhysicalTTY`) — verifies fail-closed behavior only.
- `cmd/central/c06_ceremony_driver_test.go` (`c06CeremonyScopeDisclosure`) —
  in-tree acknowledgment that "physical" is a maintainer judgement even for a
  real console the C06 harness measured.
