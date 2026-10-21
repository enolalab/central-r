# ADR 0031: Admit a Docker evidence profile for SC-G3

- **Number:** 0031
- **Title:** Admit a Docker evidence profile for SC-G3
- **Status:** Accepted
- **Created:** 2026-09-23
- **Owners:** Central maintainer
- **Decision due:** 2026-09-30
- **Decision due history:** None
- **Implementation blocked at:** None; implementation authorized per
  Follow-ups. Before Acceptance this was: any Docker-profile C06 evidence
  run claimed toward SC-G3; grant-mode rehearsal iteration (no verdict) was
  not blocked.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-09-23)
- **Decision date:** 2026-09-23
- **Decision record:** Maintainer acceptance in session; status recorded by
  agent at maintainer direction
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0023 (widens its formal-acceptance path, does not replace
  the physical-console track); Slice C acceptance governance
  (`docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md`,
  fields 16 and 21)
- **Amended by:** ADR 0033 (extends the Docker evidence profile's scope to Slice D acceptance)
- **Related:** ADR 0015 (restore-engine process identity); ADR 0016
  (interrupted-restore terminal outcome); ADR 0028 (grant ceremony mode and
  unattended-profile verdicts); `docs/operations/slice-c-maintainer-tasks.md`
  Tasks B–D

## Context

SC-G1 through SC-G3 gate every destructive step on a confirmation typed at a
real TTY, and the physical-presence guarantee is the whole point of formal
acceptance (ADR 0023, Accepted). ADR 0028 added a `grant` ceremony mode for
unattended runs, recorded as **Accepted (unattended profile)** rather than
plain Accepted.

A customer now needs proof that the Slice C recovery chain runs, and accepts
Docker-only evidence: the full C06 continuous recovery sequence, executed
against Docker-provided PostgreSQL/MinIO on an ordinary Docker host, driven
unattended via grants. They do not require (and their environment cannot
supply) a physical console, systemd units, a PAM user population, or
device-level capacity measurement.

Two things must not be confused: proving the recovery *mechanism* works end
to end (valuable, and exactly what the prior grant-mode rehearsals did), and
proving it works *in the production topology under human authorization*
(what SC-G3's physical track certifies). This ADR admits the first as a
first-class, honestly labeled evidence profile without letting it masquerade
as the second.

## Decision

1. SC-G3 admits a second evidence profile, the **Docker profile**, alongside
   the still-open physical-console track. A Docker-profile verdict is
   recorded as **Accepted (Docker profile)** and never as plain Accepted.
2. Docker-profile evidence meets every SC-G3 requirement EXCEPT the
   physical-console ceremony: immutable candidate from a clean checkout,
   full C06 scope (continuous scenario, negatives, restart injections,
   measurements, the five plan-named artifacts), the same
   `central.slice-c-acceptance/v1` manifest schema with `ceremony_mode:
   grant` (field 16) and the grant-consumption records (field 21), plus a
   new `evidence_profile: docker` marker.
3. The verdict discloses, at minimum: no human presence at any destructive
   step (grants instead of typed confirmations); no systemd unit, PAM,
   multi-user, or device-fidelity coverage (whatever the Docker host
   provides is mechanism scaffolding, not production topology); and the
   Docker host's exact shape (engine version, image digests, port plan,
   which containers coexisted).
4. The physical-console track stays open and unchanged. A plain
   **Accepted** SC-G3 still requires it. Closing Slice C on Docker-profile
   evidence alone is explicitly out of scope for this ADR.

## Consequences

### Benefits

- The customer gets the runnable proof they asked for, under rules that say
  exactly what it proves.
- Grant-mode C06 iteration becomes repeatable acceptance work instead of
  throwaway rehearsal, so defects found there (the historical norm: P-1–P-5,
  SC-DEF-59–72) keep arriving with evidence attached.
- The physical track keeps its meaning; nothing already Accepted is
  weakened or relabeled.

### Costs and limitations

- A Docker-profile verdict proves mechanism, not production readiness: a
  green Docker run can still hide defects that only systemd/PAM/multi-user
  topology exposes (precedent: SC-DEF-73, the `RuntimeDirectoryMode`
  rehearsal finding).
- The C06 harness assumes a reference host (fixed ports 55432/59000,
  launcherd units, PAM, console fd); a Docker-host port needs harness and
  composition adjustments, each a defect surface of its own (precedent:
  SC-DEF-74).
- The dev workstation currently hosts unrelated containers; a
  Docker-profile run needs a clean, conflict-free port and volume plan, or
  its own evidence is suspect.

## Alternatives considered

### Amend SC-G3 to accept Docker as plain Accepted

Rejected: it spends the physical track's meaning to save a label. Every
downstream claim built on "SC-G3 Accepted" (enterprise readiness, disaster
recovery) would silently rest on weaker evidence.

### Separate customer-only track outside governance

Rejected: a second, parallel acceptance universe doubles the labeling and
verdict machinery for one customer. The profile mechanism (fields 16/21
plus `evidence_profile`) already exists for exactly this; use it.

## Follow-ups

- Governance amendment (fields 16/21 + `evidence_profile: docker`) and
  runbook update (`slice-c-maintainer-tasks.md` Docker-profile section) —
  after this ADR is accepted, before any Docker-profile verdict.
- Docker-profile C06 implementation plan (harness port, composition without
  systemd units, clean-host port plan for the chosen Docker host) — after
  this ADR is accepted.
- SC-G3 Docker-profile verdict template (disclosure checklist from Decision
  §3) — with the first Docker-profile run.

## References

- `docs/operations/slice-c-maintainer-tasks.md` (Tasks B–D, unattended
  alternative)
- `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md`
  (fields 16, 21; independence rule)
- `docs/internal/tasks/sc-g3-release-authority-key-substitution-2026-09-23.md` (current
  candidate trust anchor; any Docker-profile run inherits its disclosure)
