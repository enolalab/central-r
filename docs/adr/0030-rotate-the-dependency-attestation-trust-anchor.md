# ADR 0030: Rotate the dependency-attestation trust anchor after loss of the dev-local signing key

- **Number:** 0030
- **Title:** Rotate the dependency-attestation trust anchor after loss of the dev-local signing key
- **Status:** Accepted
- **Created:** 2026-09-06
- **Owners:** Central maintainer
- **Decision due:** 2026-09-13
- **Decision due history:** None
- **Implementation blocked at:** None; implementation authorized per Follow-ups.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-09-06)
- **Decision date:** 2026-09-06
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0020 §1 (narrowly: `attestation_trust` is not a mode inventory and is updated by this ADR, not by an external delivery); the sentence in `docs/operations/console-bringup-probe.md` that "editing the lock to match is not permitted"
- **Amended by:** ADR 0038 (release imports)
- **Related:** ADR 0027 (the fetch-phase module acquisition that made `prepare` real); ADR 0028 D3 (why this is an ADR); commit `f767aa8` (the B02 pipeline that introduced the anchor); `docs/internal/tasks/delivery-2026-09-06-central-local-infra-8ef5da6.md`

## Context

`central local prepare` signs the receipt it produces with an ed25519 key and the lock's `attestation_trust` policy names the public keys whose signatures a receipt may carry. The lock ships exactly one: `central-dependency-attestation-dev-local/v1`, public key `b4f6a6e5ddfe47a4d121ba36d8a0ed0f164e456fce673ded68e1a9b8beb4b3f2`. Commit `f767aa8` (2026-08-20) records where its private half lives: "under `$XDG_STATE_HOME/central/dev-trust`, never in the repo". The helper loads it from `$HOME/.local/state/central/dev-trust/dependency-attestation-key.json` (root's home on a production host; override `CENTRAL_DEPENDENCY_ATTESTATION_KEY`) and, per the console runbook, "without it the helper does not merely disable prepare — it refuses to start at all"; in the current tree it starts and marks prepare unavailable.

On 2026-09-06 the maintainer confirmed **the private half is lost**. It is on neither the development host nor the rehearsal VM (the VM carries a different, untrusted `vm-rehearsal/v1` key from an earlier uncommitted rehearsal edit of the lock). The consequences:

1. **No host can run `prepare`.** The lock's `minio` inventory is, by the runbook's own account, a placeholder that "a real prepare replaces by writing the identity of the MinIO image it actually builds", so the version-zero receipt (ADR 0020) can never pass admission's reinspection on a fresh host — `ADMISSION_FAILED: receipt inspector: mode minio is unavailable locally`, observed on the VM after the SC-DEF-23 delivery landed. "Prepare, then up — on every fresh host, once" is therefore impossible everywhere.
2. **The runbook forbids the only fix.** "Editing the lock to match is not permitted — a lock is updated only from an accepted external delivery (ADR 0020 §1)." That rule was written for mode inventories; applied to the trust anchor it makes a lost key permanent.
3. **`revoked: true` cannot record the loss.** `AttestationTrustPolicy.Validate` (`internal/dependencyprepare/lock.go:528`) fails the *whole policy* if any key is marked revoked, so the field that exists for exactly this event cannot be used without breaking every lock load. Revocation has to be expressed by removal.
4. **Nothing generates a key.** No verb or script in either repository produces a key file in the schema `LoadAttestationSigner` requires (`central.local-dependency-attestation-key/v1`, base64 private key, hex public key, mode 0600, regular file). The original was produced by hand once and never reproduced, which is how it came to be lost.

ADR 0028 D3 requires an ADR here: the change alters a trust anchor in a governed lock.

## Decision

**Accepted.** Rotate the anchor, and make the operation repeatable so it is never again a one-off.

1. **New anchor.** A fresh ed25519 key, key ID `central-dependency-attestation-local/v2`, `expires_at` one year from issue, replaces `central-dependency-attestation-dev-local/v1` in `attestation_trust`. The v1 entry is **removed**, not marked revoked, because of point 3 above; its removal is the revocation, and this ADR is the durable record of why. Any receipt signed by v1 is thereby untrusted — the only such receipts are the placeholder-era ones on the rehearsal VM, already set aside.
2. **Custody.** The private half is a deployment secret owned by the maintainer, held outside any repository, and provisioned to each host that runs `prepare` at the path the helper reads. The maintainer keeps a second copy in a place that survives the loss of any one machine; this ADR does not choose the place, only requires that there be one and that its existence is recorded in the runbook.
3. **A key-generation verb.** `central attest keygen --key-id ID [--expires DURATION] --out PATH` (root-only, ModeGrant-style privilege) writes the key file in the loader's exact schema at mode 0600 and prints the `TrustedKey` JSON to add to the lock. It generates; it never edits the lock. Same shape as `central grant issue`: the human act is the lock edit and the copy, both recorded.
4. **Lock edits to `attestation_trust` are authorized by ADR**, not by external delivery. ADR 0020 §1 continues to govern mode inventories unchanged. The runbook sentence is amended to say so.
5. **`Validate` is corrected** so a key marked `revoked: true` is retained and refused by the verifier rather than failing the policy. A future rotation can then keep the retired key in the lock as a visible revocation. This is a one-line behaviour change with a test and is applied under D3 with this ADR as its authority; it does not change how the v1 key is handled now (point 1 stands regardless).

## Consequences

### Benefits

- `prepare` becomes possible again, on the VM and on every future clean host — which SC-G1's own "install a production-shaped instance" step requires.
- The anchor's lifecycle (generate, provision, record, rotate) becomes a documented procedure with a verb behind it rather than tribal knowledge.
- The lock keeps a truthful history: this ADR says why v1 disappeared, and after point 5 future retirements stay visible in the lock itself.

### Costs and limitations

- Every receipt signed by v1 is untrusted from the moment the lock changes. On the rehearsal VM that is the intended effect; no other host has ever run `prepare`.
- The lock's `attestation_trust` becomes maintainer-edited data. That is what it always was (the v1 key was hand-made); it is now admitted rather than implied.
- Custody remains a human discipline. A verb can generate a key; it cannot stop the maintainer from losing the next one. The runbook line is the only guard.
- The compiled-in lock means a key rotation is a Central release. That is acceptable for a local-first product with one maintainer and is unchanged from today.

## Alternatives considered

### Add the VM's existing `vm-rehearsal/v1` key to the lock

Rejected. Its private half lives only on the rehearsal VM, generated ad hoc during an uncommitted experiment, with no custody at all — it repeats the loss, and it binds the production lock to a throwaway host.

### Drop attestation trust and let `prepare` run unsigned

Rejected. The signature is what binds a receipt's dependency set to a builder the maintainer chose; without it any root process on the host can write the receipt the daemon later trusts. The B02 pipeline's review made this the anchor for a reason.

### Keep the placeholder `minio` digest in the lock and pin the VM-built image instead

Rejected as a substitute for rotation, though it may be done in addition: the runbook is explicit that the `minio` inventory is a placeholder that only a real `prepare` may replace, and pinning a VM-built digest would be a lock edit from an unaccepted, unattested build — the exact thing the anchor exists to prevent.

## Follow-ups

- **Decided 2026-09-06.** Owner of implementation: agent, under ADR 0028 D3.
- **Implementation refinement (2026-09-06, does not reopen the decision):** point 3's "root-only, ModeGrant-style privilege" is implemented as **no privilege requirement** instead. `central attest keygen` only ever writes the single `--out` path it is given, which may be a maintainer's own workstation state directory (generation) or a production host's root-owned one (installation as root) -- unlike `central grant`, it never touches a fixed root-owned tree, so gating it to root added no protection the file's own 0600 mode does not already give. The custody obligation in point 2 is unchanged.
- On Acceptance, under D3 in one commit: the `central attest keygen` verb with tests; the `Validate` correction (point 5) with a test; the lock edit (v2 in, v1 out); runbook amendment; a `tasks/` record naming the new key ID and public key (never the private half).
- Then on the VM: generate v2 into `/root/.local/state/central/dev-trust/dependency-attestation-key.json` (0600 root), copy the private half to the maintainer's custody location, rebuild, `central grant issue --kind prepare`, `central local prepare`, `local up`.
- The maintainer records the custody location in `docs/operations/console-bringup-probe.md`.

## References

- `internal/dependencyprepare/lock.go` — `AttestationTrustPolicy`, `TrustedKey`, `Validate` (line 528, the revoked-key rejection).
- `internal/adapter/dependencyprepare/attestation_key_linux.go` — `AttestationKeyPath`, `LoadAttestationSigner`, the key-file schema.
- `internal/adapter/dependencyprepare/attestation.go` — `AttestationVerifier`, the key map built from the policy.
- `docs/operations/console-bringup-probe.md` — "prepare, then up", the key path, and the sentence this ADR amends.
- `docs/adr/0020-populate-the-version-zero-dependency-receipt-at-provisioning.md` §1.
- `docs/adr/0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md` D3.
