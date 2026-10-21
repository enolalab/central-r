# ADR 0034: Restore imported data to the data plane (import data-plane mode)

- **Number:** 0034
- **Title:** Restore imported data to the data plane (import data-plane mode)
- **Status:** Accepted
- **Created:** 2026-09-26
- **Owners:** Central maintainer
- **Decision due:** 2026-10-10
- **Decision due history:** None
- **Implementation blocked at:** Nothing (unblocked on acceptance).
- **Decided by:** Central maintainer
- **Decision date:** 2026-09-26
- **Decision record:** Accepted as proposed. The MinIO-write capability
  returns in the narrowest form: a new purpose (`PurposeMinioImport`)
  bound to one import operation + bundle digest, per-operation expiry,
  fresh-target gate, and provisioner byte-for-byte cross-check — the same
  discipline as the existing backup purposes. ADR 0017 option B's
  read-only `PurposeMinioRestore` is unchanged; the import write lives
  beside it, not inside it.
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0017 (option B made PurposeMinioRestore read-only and
  removed PutObject "rather than merely time-boxing" it; the data-plane
  import needs a MinIO-write capability for foreign bodies, which does not
  exist anywhere in the tree)
- **Amended by:** None
- **Related:** ADR 0015/0016 (restore identity/terminal outcome — the
  launch discipline the import mode must reuse, not fork);
  `docs/internal/tasks/d03-import-implementation-notes-2026-09-26.md` (staging design +
  restore-plan.json handoff)

## Context

D03 (`backup import`) is implemented through staging: ceremony,
freshness gate, token verification, decryption, extraction, manifest
verification, protected-state bootstrap, and a verified
`restore-plan.json` staging the database dump and bodies. What remains is
executing the plan: pg_restore of the staged dump and upload of the staged
bodies to the fresh host's MinIO.

No legitimate path exists today:

1. The C04 repository choreography cannot consume foreign data: seal
   verification binds the source repository's binding ID, and writing a
   local companion over foreign bytes would forge a seal (attestation
   means "this worker run produced this data"), not extend one.
2. The helper holds no data-plane credentials by design; all PG/MinIO
   write credentials terminate in broker-launched workers with
   purpose-bound, per-operation bindings.
3. central-restore holds the pg_restore credential but its MinIO
   credential is read-only by Accepted decision (ADR 0017 option B), and
   its launch protocol knows only verify/apply/resume over repository
   identities — no bundle source exists.

## Proposal

1. A new broker credential purpose (`PurposeMinioImport`, scoped to the
   import operation + bundle digest, same per-operation binding discipline
   as the backup purposes) grants PutObject on the runtime ready prefix.
   The external provisioner cross-checks the rendered policy byte-for-byte
   before any broker accepts it, as it does for the existing purposes.
2. A new central-restore launch mode (`import`) consumes the staged
   `restore-plan.json` by opaque import-operation identity: pg_restore
   through the existing `PGRestore` runner with a bundle dump source,
   MinIO upload through the import credential, then the dossier's
   post-import verification (PG checksum + object count vs the plan).
3. The import launch reuses the restore launch's peer pinning, expiry,
   one-use consumption, and journal discipline; it adds a mode, not a
   trust mechanism.
4. On success the engine marks the plan consumed and the import verb's
   `DataPlaneRestored` flips true (a follow-up import status verb, or a
   re-run that detects the consumed plan — decided at implementation).

## Consequences

### Benefits

- D03 completes honestly: foreign data reaches the data plane through the
  same credential discipline as every other restore, with no seal forgery
  and no helper-held data-plane credentials.

### Risks

- A new MinIO-write capability exists where ADR 0017 deliberately removed
  one. Mitigated by purpose binding (import operation + bundle digest),
  per-operation expiry, the fresh-target gate (import refuses initialized
  instances, so the write cannot clobber live data), and provisioner
  cross-checking.

## Follow-ups

- On acceptance: implement the broker purpose, the engine mode, and the
  D07 live data-plane import scenario against Docker PG/MinIO.
- Until acceptance: `backup import` stages and reports
  `data_plane_restored: false`; D07 covers staging, and the Slice D
  verdict records the data-plane import as pending this ADR.
