# ADR 0033: Admit a Docker evidence profile for Slice D acceptance

- **Number:** 0033
- **Title:** Admit a Docker evidence profile for Slice D acceptance
- **Status:** Accepted
- **Created:** 2026-09-26
- **Owners:** Central maintainer
- **Decision due:** 2026-09-26
- **Decision due history:** None
- **Implementation blocked at:** Any Slice D (D07) verdict; Slice D
  implementation and rehearsal runs were never blocked.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-09-26)
- **Decision date:** 2026-09-26
- **Decision record:** Maintainer approval in session; status recorded by
  agent at maintainer direction
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0031 (extends the Docker evidence profile's scope from
  SC-G3 to Slice D acceptance; ADR 0031's physical-track Decision 4 is
  unchanged)
- **Amended by:** None
- **Related:** ADR 0028 (grant ceremony); ADR 0032 (grant kinds for Slice D
  verbs, decided the same day);
  `docs/internal/superpowers/specs/2026-09-26-slice-d-destructive-portable-design.md`
  (OQ-2)

## Context

The Slice D dossier demands physical-seat confirmation for every
destructive verb, which no container can supply. The customer accepts
Docker-profile proof (the ADR 0031 precedent for SC-G3): the full D07
acceptance sequence, executed against Docker-provided PostgreSQL/MinIO on
an ordinary Docker host, driven unattended via grants (ADR 0032). The same
two things must not be confused as in ADR 0031: proving the destructive
mechanisms work end to end (valuable), versus proving they work in the
production topology under human authorization (what the physical track
certifies). This ADR admits the first as a first-class, honestly labeled
evidence profile for Slice D without letting it masquerade as the second.

## Decision

1. Slice D acceptance (D07) admits a second evidence profile, the **Docker
   profile**, alongside the still-open physical-console track. A
   Docker-profile verdict is recorded as **Accepted (Docker profile)** and
   never as plain Accepted. Self-issuance, if applicable, is disclosed
   alongside per the governance §5 amendment.
2. Docker-profile evidence meets every D07 requirement EXCEPT the
   physical-seat ceremony: immutable candidate from a clean checkout, full
   D07 scope (the dossier's 8 scenarios), grant-mode ceremonies under
   ADR 0032 kinds with consumption records in the journal, and all seven
   plan-named evidence artifacts, plus an `evidence_profile: docker`
   marker.
3. The verdict discloses, at minimum: no human presence at any destructive
   step (grants instead of typed confirmations); no systemd unit, PAM user
   population, multi-user, or production AppArmor-enforcement coverage
   (whatever the Docker host provides is mechanism scaffolding — D01's
   AppArmor deactivation step in particular is host-shaped and its Docker
   behavior is disclosed, not asserted as production proof); and the Docker
   host's exact shape (engine version, image digests, port plan, which
   containers coexisted).
4. The physical-console track stays open and unchanged. A plain
   **Accepted** Slice D still requires it.

## Consequences

### Benefits

- The customer gets runnable Slice D proof under rules that say exactly
  what it proves, consistent with the SC-G3 precedent.
- Grant-mode D07 iteration becomes repeatable acceptance work instead of
  rehearsal-only effort.

### Risks

- Docker-profile acceptance is blind to seat/PAM/systemd/AppArmor defects
  by construction. Mitigated by mandatory disclosure (Decision 3) and the
  open physical track (Decision 4), same as ADR 0031.

## Follow-ups

- The Slice D implementation plan's D07 task gathers evidence under this
  profile; its verdict follows Decisions 2–3.
- If a later physical-console D07 run happens, it upgrades a Docker-profile
  verdict; nothing downgrades it.
