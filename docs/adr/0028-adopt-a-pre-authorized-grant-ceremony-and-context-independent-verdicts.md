# ADR 0028: Adopt a pre-authorized grant ceremony and context-independent verdicts for unattended Slice C delivery

- **Number:** 0028
- **Title:** Adopt a pre-authorized grant ceremony and context-independent verdicts for unattended Slice C delivery
- **Status:** Accepted (D1, D2 and D3 all selected)
- **Created:** 2026-09-06
- **Owners:** Central maintainer
- **Decision due:** 2026-09-13
- **Decision due history:** None
- **Implementation blocked at:** None; implementation authorized per Follow-ups. Before Acceptance this was: any change to `openPhysicalTTY` or to the five `Perform*TTYCeremony` functions; governance fields 16, 21, 24 and §5; SC-DEF-20 Task 4 and SC-G1–SC-G3 as unattended runs.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-09-06)
- **Decision date:** 2026-09-06
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0023 (lifts the Option D block by adopting a different second mode, not remote attestation); ADR 0016 (the abandonment ceremony may be satisfied by a grant naming the exact operation)
- **Amended by:** ADR 0032 (extends the D1 grant-kind set to Slice D verbs)
- **Related:** ADR 0015 (restore-engine identity, unchanged); `docs/operations/slice-c-maintainer-tasks.md` §"A legitimate alternative, if the controls are genuinely wrong"; `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md` fields 16, 21, 24 and §5 (E-3); `cmd/central/c06_ceremony_driver_test.go`; `docs/internal/tasks/sc-def-09-*.md`, `docs/internal/tasks/sc-def-10-*.md` (open maintainer rulings)

## Context

Slice C cannot currently be delivered without a human in three distinct places:

1. **The physical-console ceremony.** Every destructive verb (`restore apply`, `resume`, `abandon`, migration reset, prepare) is gated by `PerformTTYCeremony` and its three restore variants, which require the peer's own `/proc/<pid>/fd/0` to resolve to a real `/dev/tty*` and a human to type a random confirmation phrase. ADR 0023 (2026-08-19) kept this control, unblocked *development* around it (Option B) and pointed the maintainer at an isolated VM to actually run it (Option C). The VM path has since been exercised — the 2026-09-03/04 console campaign found and fixed SC-DEF-11 through SC-DEF-23 — but every iteration still costs a person at the console, and SC-DEF-20 Task 4, SC-G1, SC-G2 and SC-G3 each require at least one more.
2. **The independent verdict.** Governance rule E-3 forbids a verdict from "any party in the candidate's authorship lineage", and §5 names a distinct human reviewer identity. Every gate therefore waits for a second person.
3. **Maintainer rulings.** Cross-repository or security-adjacent fixes (SC-DEF-09, SC-DEF-10 today; SC-DEF-20 and SC-DEF-23 earlier) are surfaced rather than applied, per this campaign's standing practice, and wait for a decision.

The maintainer's stated goal on 2026-09-06 is **fully unattended delivery**: the agent should be able to carry Slice C from its current state to Accepted without a human at a console, a second human reviewer, or a per-defect ruling.

ADR 0023 rejected "remove the physical-console requirement outright" and "let the agent perform the console confirmation", and it was right to on the grounds it gave: velocity alone is not a reason a control is wrong. This ADR does not reargue that. It records a different judgement the maintainer is now making on the merits: **for this deployment, the security property Slice C actually needs is "only the host's root, deliberately, for exactly this operation" — not "a human physically present at a keyboard".** Physical presence was the mechanism chosen to evidence deliberateness; it is not the property itself. Once that is the judgement, a second mechanism that evidences the same deliberateness without a console is a legitimate design, provided it is recorded truthfully in the acceptance evidence rather than passed off as a physical ceremony.

The runbook already anticipates exactly this path: "If you conclude the physical-console ceremony is the wrong control on its merits... reconsider it in a new ADR with the trade-offs recorded, and amend the governance deliberately." This is that ADR.

## Decision

Three decisions, one per human touchpoint. Each is separable; the maintainer may accept a subset.

### D1 — A second ceremony mode: the pre-authorized operation grant

The helper gains a configured `ceremony_mode` with two values. **`physical_tty` remains the default and is byte-for-byte the current behaviour.** The new value, `grant`, replaces the TTY prompt with a **grant file** that must already exist when the destructive verb is invoked.

A grant is the same object a ceremony already produces, minted before the fact instead of during it. It reuses the existing helper-minted, never-caller-derived design of `ConfirmationBinding` and the restore ticket record:

- **Where:** a root-only directory inside the helper's protected root (`<state root>/v1/grants/`, `0700` root:root), one file per grant, `0600`, opened `O_NOFOLLOW` via an already-validated directory fd — the same anti-TOCTOU discipline `central-local-infra`'s `target/linux.go` uses.
- **What it binds:** ceremony kind (`restore_apply`, `restore_resume`, `restore_abandon`, `migration_reset`, `prepare`), `InstanceID`, `TargetID`, the exact operation ID where one exists, `BootID`, `HelperRelease`, `IssuedAt`, `ExpiresAt` (hard cap 24 h), a random nonce, and an HMAC under a key the helper alone holds. The helper resolves every one of these from its own `PrepareConfirmationSource`, exactly as bindings are resolved today; nothing in the grant is trusted from the request.
- **One-use:** the helper renames the grant to `<name>.consumed` atomically *before* it returns the confirmation token, so a crash between the two cannot replay it. A consumed or expired grant is a ceremony failure with the same denial as a mismatched phrase.
- **Who issues it:** a new root-only verb, `central grant issue --kind K --instance I --target T [--operation O] --ttl D`, running as the same root peer that today would sit at the console. It writes the file and prints its nonce. It has no `--force`, no wildcard scope, and cannot issue a grant for a kind the helper does not know.
- **What it replaces, exactly:** the console exchange — both the PAM password conversation and the typed phrase, since `Authenticate` collects the password through the same `openPhysicalTTY` the phrase uses and neither can run without a console. **What it does not change:** the socket peer policy (`SO_PEERCRED`, still enforced and recorded on the consumption record), ADR 0015's launch-record binding, the restore ticket record, the protected journal, and the fail-closed denial matrix. `abandon` still requires a grant naming the exact operation, so ADR 0016's "never automatic, never by timeout" holds in letter: something must deliberately issue a grant for that operation ID.

The honest statement of the resulting property: **in `grant` mode, the control degenerates to "root on this host, deliberately, for this exact operation, within this window".** Anything with root can issue a grant. That is the same adversary ADR 0015 already excludes, and it is the adversary the maintainer has judged acceptable for this deployment. It is a weaker property than physical presence, and the evidence must say so — see D1's governance changes below.

Governance changes (all amendments to `2026-08-14-slice-c-acceptance-governance.md`):

- Field 16 `privilege_profile` gains `ceremony_mode` (`physical_tty` | `grant`). `physical_tty: true` may only be asserted in `physical_tty` mode and is still checked against the run log. A manifest declaring `grant` mode with `physical_tty: true` is rejected.
- Field 21 `ceremony_records` entries gain `mode`, and in `grant` mode carry the grant nonce, its issue and consumption timestamps, and the issuing peer's uid/pid from the helper log. Checked against the helper log, as the TTY entries are today.
- Field 24 `destructive_confirmations` records the grant digest in place of the phrase digest.
- A gate verdict issued from a `grant`-mode run is recorded as **"Accepted (unattended profile)"** in `current-phase.md`, never as plain "Accepted". Re-running under `physical_tty` later upgrades it; nothing downgrades it.

Code changes this authorises (Architecture mode, full suite): `pam_linux.go` mode dispatch around the five `Perform*` functions; a new `grant_linux.go` (issue, resolve, consume); the config-schema field and its default; the `central grant issue` verb in `cmd/central`; `c06_ceremony_driver_test.go` and the preflight harness re-scoped so "no substitute confirmer is registered" is asserted **per mode** (still absolute in `physical_tty`); the runbook's Task B. `openPhysicalTTY` itself is untouched.

### D2 — Context-independent verdicts

E-3 is re-stated, not weakened in spirit: **a verdict may not be issued by any party with access to the candidate's implementation context.** For an agent-issued verdict that means, and the manifest must evidence:

- a fresh session (new session ID, recorded in the verdict) with **no** transcript, memory, plan, brief or report from the implementation lineage available to it — the `.superpowers/sdd/` tree and `docs/internal/superpowers/plans/` for the candidate are excluded from its checkout, not merely unread;
- a read-only, clean checkout of the immutable candidate commit and the manifest, nothing else writable;
- the verdict re-derives candidate authorship from commit trailers (already required by §5.1) and records the reviewing session ID, model ID and the excluded paths;
- the status-transition commit is still a separate documentation-only commit, made by the implementation session *after* the verdict lands (§5.1, unchanged).

What this does not give: a different *person*. Two sessions of the same model under the same account share training, blind spots and the maintainer's instructions. §5 must record this residual explicitly, and the "unattended profile" label from D1 applies to any gate whose verdict was issued this way, for the same reason.

### D3 — A standing delegation for rulings

`AGENTS.md` gains a short delegation policy so the agent stops blocking on cross-repository and security-adjacent fixes:

- The agent **may apply** a fix unilaterally, in either repository, when it (a) does not weaken any permission or peer-authorization check, (b) does not change a wire format or an Accepted ADR's decision, (c) is covered by a test that fails before and passes after, and (d) is recorded in `tasks/` with the same "What a fix requires" analysis as today. SC-DEF-23 direction 1 is the model.
- The agent **must still raise an ADR** — as Proposed, without blocking on it — when (a) or (b) would be violated, and continue on every path the decision does not gate. ADR acceptance stays with the maintainer. It is the one asynchronous human act this ADR leaves, and it is asynchronous by design: nothing waits on it except the specific change it authorises.
- Open rulings today are resolved under this policy: SC-DEF-10 (seccomp allow-list) qualifies for unilateral fix; SC-DEF-09 (MinIO recipe) is decided in this ADR's Follow-ups.

## Consequences

### Benefits

- With D1–D3 accepted, the remaining Slice C path — SC-DEF-20 Task 4, SC-DEF-02/03/09/10, SC-G1–SC-G3 evidence and verdicts, the `current-phase.md` transitions — can run as a scheduled, unattended loop. The maintainer's only remaining act is accepting ADRs, off the critical path.
- The production default is unchanged: an instance installed without `ceremony_mode: grant` behaves exactly as ADR 0023 left it. Nothing forces a physical-console deployment to lose the control.
- The evidence stays honest. "Unattended profile" is visible in every manifest and every status line; no fake physical ceremony is ever recorded (the runbook's "false certification" failure).
- The grant reuses proven primitives (helper-minted bindings, one-use consumption, fd-validated protected roots) rather than a new trust mechanism.

### Costs and limitations

- **The security property is weaker in `grant` mode**, and permanently so for any gate accepted under it: root-on-host possession replaces human physical presence. An attacker with root can issue a grant for any operation. This is the deliberate trade and the reason for the "unattended profile" label.
- D2's "independence" is context independence, not person independence. It defends against the implementer's *knowledge* contaminating the review, not against shared model behaviour. A future human verdict remains strictly stronger.
- ADR 0016's spirit — that abandonment "cannot be stumbled into" — now rests on the discipline that grants are issued per operation ID, not on a keyboard. An automation that issues `restore_abandon` grants freely has removed the control; the `central grant issue` verb's refusal of wildcard scope is the only guard, and it is not a strong one.
- The C06 suite loses its absolute "no substitute confirmer anywhere" invariant in favour of a per-mode one. That is a real reduction in what the suite proves and must be stated in the suite's scope disclosure.
- Two ceremony code paths to maintain and keep denial-matrix-equivalent.

## Alternatives considered

### Option D of ADR 0023 — remote attestation (FIDO2 touch, second-device approval)

Not selected. It keeps a human in the loop by construction, so it does not meet the stated goal; it is also the larger design (new factor, new binding to `opID`/`target`, field 21 schema change). It remains the right choice if the maintainer later wants *remote* rather than *unattended*.

### Remove the ceremony entirely

Rejected, as in ADR 0023 and the runbook. It would also require rewriting ADR 0016's decision rather than amending it, and it leaves no way to distinguish a deliberate destructive operation from an accidental one, even in principle. The grant keeps the "exactly this operation, deliberately" property at near-zero cost.

### A test double registered only under `authority_test` build tags

Rejected. ADR 0023's audit already found this contradicts the C06 invariant, and a tag-gated double produces exactly the evidence E-8 refuses ("fake-backed tests are not real-infrastructure evidence"). D1 instead makes the second mode a real, production-shaped path with its own truthful evidence profile.

### Let the maintainer pre-type confirmations into the console (expect-style scripting on the VM)

Rejected. It satisfies `openPhysicalTTY` by lying to it — the agent drives the console the human is supposed to own — which is precisely the disqualifying flaw ADR 0023 identified in the sandbox's `/dev/ttyS4`. It would record `physical_tty: true` for a run no human witnessed.

### Keep the human verdict, automate everything else (D1 + D3 only)

Viable and strictly safer than D2. Not recommended as the default because it leaves one synchronous human act per gate, three gates, and any re-run after a defect; the maintainer's goal was to remove that. Recorded so the option of accepting D1 and D3 without D2 is explicit.

## Follow-ups

- **Decision needed (this ADR):** accept D1, D2, D3 individually. Owner: Central maintainer.
- **SC-DEF-09 ruling, folded in here** to close the last open ruling: apply the fix direction the defect file proposes as its first option, under D3's criteria, once this ADR is Accepted. Owner: agent.
- **On Acceptance, Architecture-mode plan** (`docs/internal/superpowers/plans/2026-09-06-unattended-ceremony-grant.md`): grant mint/resolve/consume in `internal/adapter/authority/helper`; config field; `central grant issue`; C06 and preflight re-scoping; governance spec amendments to fields 16/21/24 and §5; runbook Task B update; `current-phase.md` label convention. Full suite plus `authority_test` tags as root on the VM (last console session — after this, the VM needs SSH only).
- **Then the unattended loop:** SC-DEF-20 Task 4 → SC-DEF-02/03/10 → SC-G1 evidence → D2 verdict → status commit → SC-G2 → SC-G3, each gate run from a clean checkout of a pinned commit (§6.1, unchanged).
- ADR 0023's front matter gains `Amended by: ADR 0028`; ADR 0016's gains the same with the one-line note that the abandonment ceremony may be satisfied by a grant naming the exact operation.

## References

- `internal/adapter/authority/helper/pam_linux.go` — `PerformTTYCeremony`, `Perform{MigrationReset,RestoreApply,RestoreAbandon}TTYCeremony`, `openPhysicalTTY`.
- `internal/adapter/authority/helper/prepare_confirmation.go` — `ConfirmationBinding`, `PrepareConfirmationSource`; the helper-minted-only rule this ADR reuses.
- `internal/adapter/authority/helper/restore_apply.go` — `RestoreApplyScope`, `RestoreApplyAuthorizationIssuer`.
- `docs/adr/0023-reconsider-the-physical-console-ceremony-development-path.md` — the decision this amends, and its audit of why no test double can exist.
- `docs/adr/0016-adopt-a-terminal-outcome-for-an-interrupted-restore.md` — the abandonment ceremony.
- `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md` — fields 16, 21, 24; §5 (E-3, who may and may not issue a verdict); §6.1.
- `docs/operations/slice-c-maintainer-tasks.md` — Task B, and the "legitimate alternative" paragraph that authorises this ADR's existence.
- `docs/internal/tasks/sc-def-23-fs-init-journal-inside-pgdata-breaks-initdb.md` — the model for a unilateral cross-repository fix under D3.
