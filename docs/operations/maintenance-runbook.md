# Maintenance Runbook

Canonical operator procedures for dependency compatibility planning,
patch application, rollback, advisory lifecycle, and troubleshooting.
This runbook documents only the implemented command surface
(`central maintenance plan`, `central maintenance apply`) — the
authority-recorded compatibility matrix introduced by Slice E.

**Boundary.** These commands mutate the *authority matrix* — the signed,
journaled record of which dependency pins the instance authorizes.
The physical rollout (pulling an image, recreating a service, pinning
`central-local-infra` digests) is a separate procedure; see
`ghcr-push-runbook.md` and the pin script `ci/pin-infra-lock.sh`. The
matrix commit is the authority act that permits a transition to be
recorded as applied.

## 1. Compatibility planning

```bash
central maintenance plan
central maintenance plan --check=postgresql=16.15
```

`plan` probes the host for every dependency the matrix tracks, evaluates
each against the matrix, and — for each `--check=name=target` — evaluates
the proposed transition against the entry's allowed range. It mutates
nothing and requires no ceremony.

Output detail fields: per-dependency `current`, `min`, `max`, `gate`,
observed value (`in_range`, `diverged`, or `unprobed`), and per-check
verdict (`allowed` or a refusal reason). On success the command writes
`slice-e-compatibility-matrix.json` into the current directory and exits 0.

Read the matrix as the contract: a transition `X → Y` is admissible only
when `Y` is inside the entry's allowed set. Proposing outside the range
refuses with `MAINTENANCE_TRANSITION_UNLISTED` — extend the matrix
(a code change with review) rather than forcing a pin.

## 2. Patch application

```bash
central maintenance apply --set=postgresql=16.15
```

Sequence:

1. **Pre-check** — run `central maintenance plan --check=postgresql=16.15`
   and confirm the transition is `allowed`.
2. **Stage the target physically first** — the gate verifies the target is
   *already observable* on the host before the matrix commits. For a
   host tool that means the new version installed; for an infra image the
   tag/digest present (`docker image inspect` must succeed). Applying
   before staging fails the gate and journals `patch_failed`.
3. **Ceremony** — the operator is prompted on the physical TTY to type
   `PATCH CENTRAL <instance> <target> <operation>` and authenticate via
   PAM under a `maintenance_apply` grant. Denial or expiry refuses with
   `AUTHORITY_DENIED`; nothing is journaled.
4. **Commit** — on gate pass the matrix entry's `current` moves to the
   target, the sequence increments, and `patch_applied` is journaled
   (HMAC-authenticated, digest-chained). Evidence:
   `slice-e-patch-apply.json` in the current directory.

Verify after: `central maintenance plan` shows the new `current`.

### Resume

```bash
central maintenance apply --resume=<attempt-id>
```

A crash between `patch_pending` (or `rollback_pending`) and its terminal
row leaves a durable pending attempt. `--resume` re-runs the pending
row's own gate and direction — a rollback-pending row resumes as a
rollback. The pending attempt id is returned by the refusal
`MAINTENANCE_PATCH_PENDING`.

### Abandon

```bash
central maintenance apply --abandon=<attempt-id>
```

Closes a pending attempt without completing it — requires the same
ceremony. Journals `patch_abandoned` or `rollback_abandoned` matching the
pending row's direction. The matrix is not touched. Evidence verdict:
`abandoned`.

## 3. Rollback

```bash
central maintenance apply --rollback=<attempt-id>
```

Valid only while the attempt's latest row is `patch_applied` **and** the
matrix's `current` still equals that patch's target (`to`). Rollback
records a `rollback_pending` row with `from`/`to` reversed, runs the same
gate against the *previous* version (the host must already be observed
back on it — stage the downgrade physically first), then commits the
matrix back and journals `rollback_applied` under the same attempt id.

A rollback on a matrix that has since moved refuses
`MAINTENANCE_ROLLBACK_STALE` — apply a forward patch to the desired pin
instead. Physical downgrade of the dependency itself is the infra
procedure, not this command.

## 4. Advisory lifecycle

The B01 advisory evaluator admits operations per the installed release
advisory's stage, computed from the bundle's `issued_at`/`expires_at`
against the host clock:

| Stage | Meaning | Operator action |
|---|---|---|
| `current` | within validity window | none |
| `stale` | expired, within 7-day grace | plan an advisory update; admissions still evaluate |
| `hard_expired` | expired > 7 days | update the advisory bundle; writes deny-safe until then |
| `deny` | emergency deny, tampered signature, or invalid bundle | treat as an incident; install a valid signed bundle via `central local security update` |

Advisory evaluation evidence is journaled per admission as an
`advisory_evaluation` authority transition. The E04 conformance suite
(`TestE04AdvisoryLifecycleConformance`) proves all stages and their
journal receipts; fixture advisories are regenerated per run — operators
do not sign anything.

## 5. Troubleshooting

| Reason token | Exit | Cause | Action |
|---|---|---|---|
| `INVALID_MAINTENANCE_GRAMMAR` | config | bad or mutually exclusive flags | re-check `--set`/`--resume`/`--rollback`/`--abandon` usage |
| `MAINTENANCE_SERVICE_UNAVAILABLE` | unsupported | no apply client wired (helper absent) | install/enable the helper service |
| `MAINTENANCE_UNAVAILABLE` | deferred | store read/write failed | check protected-state filesystem, retry |
| `MAINTENANCE_MATRIX_TAMPERED` | denied | journal/matrix HMAC or digest mismatch | **stop** — inspect protected state, do not retry blindly |
| `MAINTENANCE_TRANSITION_UNLISTED` | denied | target outside matrix range | `plan --check` first; extend matrix via review |
| `MAINTENANCE_PATCH_PENDING` | denied | an attempt is pending | `--resume` it, or `--abandon` it |
| `MAINTENANCE_PATCH_UNKNOWN` | denied | attempt id not journaled | re-check the id from the refusal detail |
| `MAINTENANCE_PATCH_CLOSED` | denied | attempt already terminal | create a new `--set` attempt |
| `MAINTENANCE_ROLLBACK_STALE` | denied | matrix moved past the patch target | forward-patch instead |
| `MAINTENANCE_GATE_UNKNOWN` | denied | entry's gate verb unimplemented | matrix entry needs an implemented gate |
| `MAINTENANCE_GATE_FAILED` | denied | target not observable on host | stage the target physically, then retry |
| `AUTHORITY_DENIED` | denied | ceremony refused/expired | re-run, type the phrase, authenticate |
| `DENY_SAFE_ACTIVE` | denied | deny-safe mode is active | run `central local security rescue` first |

Diagnostics: evidence artifacts (`slice-e-compatibility-matrix.json`,
`slice-e-patch-apply.json`) land in the command's working directory; the
journal lives in the protected matrix store alongside
`maintenance-transitions.jsonl` — never edit it by hand.
