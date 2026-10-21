# ADR 0032: Extend the pre-authorized grant ceremony to Slice D verbs

- **Number:** 0032
- **Title:** Extend the pre-authorized grant ceremony to Slice D verbs
- **Status:** Accepted
- **Created:** 2026-09-26
- **Owners:** Central maintainer
- **Decision due:** 2026-09-26
- **Decision due history:** None
- **Implementation blocked at:** Grant-mode Slice D evidence runs and any
  D07 verdict; `physical_tty` Slice D implementation was never blocked.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-09-26)
- **Decision date:** 2026-09-26
- **Decision record:** Maintainer approval in session; status recorded by
  agent at maintainer direction
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0028 (extends the D1 grant-kind set; the grant discipline
  itself is unchanged)
- **Amended by:** ADR 0037 (the grant-kind set gains `init`, the one kind issued before an instance exists)
- **Related:** ADR 0031 (Docker evidence profile for SC-G3); ADR 0033
  (Docker evidence profile for Slice D, decided the same day);
  `docs/internal/superpowers/specs/2026-09-26-slice-d-destructive-portable-design.md`
  (OQ-1)

## Context

ADR 0028 D1 closed the grant-kind set at five values
(`restore_apply`, `restore_resume`, `restore_abandon`, `migration_reset`,
`prepare`): "cannot issue a grant for a kind the helper does not know."
Slice D adds six destructive or destructive-adjacent verbs (`local wipe`,
`backup export/import/delete`, `backup prune apply`, `security rescue`),
each gated by the same PAM + physical-seat ceremony. Without grant kinds
for them, no Slice D verb can run unattended or on a Docker host, and the
customer-accepted Docker evidence path (ADR 0031 precedent) cannot extend
to Slice D.

## Decision

1. The helper's grant-kind set gains six values: `wipe`, `backup_export`,
   `backup_import`, `backup_delete`, `backup_prune`, `security_rescue`.
   `central grant issue --kind` accepts exactly these plus the existing
   five; no wildcard, no `--force`, unchanged.
2. Every new kind reuses ADR 0028's discipline byte for byte: root-only
   grant directory, helper-resolved bindings (ceremony kind, `InstanceID`,
   `TargetID`, exact operation/bundle/plan ID where one exists, `BootID`,
   `HelperRelease`, `IssuedAt`, `ExpiresAt` hard-capped at 24 h, random
   nonce, helper-held HMAC), atomic one-use consumption before the
   confirmation token returns.
3. What ADR 0028 did not change, this ADR does not change either: the
   `physical_tty` default, the socket peer policy, the protected journal,
   the fail-closed denial matrix, and the per-mode "no substitute
   confirmer" test assertions (extended to the new kinds, not weakened).
4. The honest property statement carries over: in `grant` mode the control
   degenerates to "root on this host, deliberately, for this exact
   operation, within this window." Slice D evidence from grant-mode runs
   says so, under ADR 0033's disclosure rules.

## Consequences

### Benefits

- Slice D verbs can run unattended and on Docker hosts under the same
  audited one-use discipline as Slice C.
- No new trust mechanism: same files, same HMAC, same consumption path,
  same journal records.

### Risks

- The weaker security property now covers destruction beyond restore
  (wipe, delete, prune). Mitigated exactly as in ADR 0028: one-use,
  short TTL, exact-operation binding, journaled consumption, and an
  honestly labeled verdict (never plain Accepted).

## Follow-ups

- Implement the six kinds in the grant module + `central grant issue`
  (Slice D plan Task 0); extend the per-mode confirmer tests.
- ADR 0033 (same day) admits the Docker evidence profile that consumes
  these grants for Slice D acceptance.
