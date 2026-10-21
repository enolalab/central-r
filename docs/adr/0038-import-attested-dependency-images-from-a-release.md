# ADR 0038: Import attested dependency images from a release

- **Number:** 0038
- **Title:** Import attested dependency images from a release
- **Status:** Accepted
- **Created:** 2026-10-01
- **Owners:** Central maintainer
- **Decision due:** 2026-10-15
- **Decision due history:** None
- **Implementation blocked at:** Any code path that writes a dependency receipt from artifacts it did not build itself (`central local prepare --from-release`), any change to `attestation_trust` handling for release envelopes, and the installer's end-user path after genesis (one-click install sub-project A1). `local prepare` as it is today is not blocked.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-10-01)
- **Decision date:** 2026-10-01
- **Decision record:** Maintainer approval in session on 2026-10-01 ("chấp nhận ADR 0038 và 0039"); committed by the maintainer in this dedicated status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0020 (a second writer of a live instance's `active` dependency receipt, for release imports); ADR 0030 D2 (hosts that only import never hold the private attestation key)
- **Amended by:** None
- **Related:** `docs/internal/superpowers/specs/2026-09-27-one-click-install-design.md` §A; `docs/internal/tasks/install-c-broker-helper-units-2026-09-27.md` (host prerequisites); ADR 0024; `internal/dependencyprepare` (`AttestationVerifier`, `PreparedManifest`); `internal/adapter/dependencyprepare` (`CandidateStore`)

## Context

`central local prepare` is the only way a live instance gets a dependency receipt whose MinIO image is real: it fetches the MinIO source pinned in the embedded lock, builds it twice with BuildKit, compares the builds, signs DSSE attestations with the dependency-attestation key (`central-dependency-attestation-local/v2`, pinned in the lock's `attestation_trust`), verifies them in process, loads the image, stages a manifest and switches the `active` selector. The version-zero receipt written at genesis (ADR 0020) names a placeholder MinIO digest that corresponds to no image, so `local up` cannot run before a prepare.

ADR 0030 D2 makes the private attestation key a maintainer deployment secret "provisioned to each host that runs `prepare`". An end user's host can never hold it. The install-C VM run confirmed the consequence: without the key, `local prepare` answers `PREPARE_UNAVAILABLE`, and with it the host also needs `buildctl`, network access to the source and base images, and about five minutes of building. A one-command install for users cannot work this way.

The code already has the half that a user host needs: `AttestationVerifier.Verify` checks any DSSE envelope against the lock's trust policy (Ed25519 over the DSSE PAE, every signature naming a policy key, exact predicate/subject/materials equality). What is missing is a path that writes a receipt from images and envelopes produced elsewhere.

## Decision

Accepted:

1. **Release-built, host-verified.** The MinIO image is built, compared and attested by the existing prepare pipeline on the maintainer's release host, the only host that holds the private attestation key (ADR 0030 custody unchanged). A release carries, for each attested image, its OCI image layout and its three DSSE envelopes (the `sbom`, `license-report` and `slsa-provenance` predicates the pipeline produces today), plus the OCI layout of `central-local-infra` at the lock-pinned digest. The public `library/postgres` image is pulled by its lock-pinned digest as today.
2. **Import verb.** `central local prepare --from-release DIR` (same helper verb, same `prepare` grant kind or console ceremony, same lifecycle exclusivity) runs on the user host: capacity, B01 admission, then, instead of fetch/build/compare/sign: verify every envelope with `AttestationVerifier` against the embedded lock's `attestation_trust`; check the statement's trust-relevant materials against the embedded lock exactly (`lock_digest`, `source_archive_digest`, `source_commit`, `base_identities`) and its subject against the shipped OCI layout's index/manifest/config digests; accept the producer-local materials (`operation_id`, builder identities, `invocation_digest`) as recorded facts, not as expectations; `docker load` the layout, `ValidateLoadedImage`, tag under the pinned name; then stage, promote and switch the selector exactly as prepare does. `central-local-infra` is loaded only if its layout's digests equal the lock pin; nothing unpinned is ever tagged under a pinned name.
3. **Durable evidence.** The staged manifest gains the source `release` and keeps the verified envelopes themselves (not only the 4-tuple facts), so a later audit can re-verify the receipt offline.
4. **Admission unchanged.** `local up` keeps checking B01, the active receipt and local image presence; it does not start reading attestations.
5. **Expiry is a release date.** The trust policy fails as a whole once any key expires (`2027-09-06` today), so every shipped binary inherits that hard date; rotating before it is a Central release (ADR 0030).

## Consequences

### Benefits

- An end-user host reaches a running instance with no private key, no `buildctl`, no source fetch and no build.
- The trust anchor is the same: a receipt still binds images whose attestations verify against the key pinned in the lock that ships in the binary.
- The import is auditable offline from the persisted envelopes.

### Costs and limitations

- A release becomes a security artefact: its OCI layouts and envelopes must be produced on the key-holding host and published intact.
- Only MinIO is attested; `central-local-infra` relies on the lock pin (as today) and postgres on its public digest.
- A second receipt writer exists (ADR 0020 amended); its tests must prove it cannot write a receipt the verifier did not accept.
- The trust policy's expiry is a hard date for every shipped binary.

## Alternatives considered

### Ship the private attestation key with the release

Contradicts ADR 0030 D2 and makes the key public in effect. Rejected.

### Pin the release-built MinIO digest in the lock and skip prepare

ADR 0030 rejected pinning an unattested, elsewhere-built digest as "the exact thing the anchor exists to prevent". The import keeps the attestation in the loop instead.

### Let each user host generate its own key

A host key is not in the lock's trust policy, so the in-process verification refuses it; adding per-host keys to the lock is impossible after release.

## Follow-ups

- One-click install sub-project A1: implement the import verb, the release layout and the manifest change (owner: Central maintainer; blocked on this ADR).
- Sub-project A: a release workflow on the key-holding host that produces the layouts and envelopes.

## References

- `docs/adr/0020-populate-the-version-zero-dependency-receipt-at-provisioning.md`
- `docs/adr/0024-settle-the-promoted-minio-identity-and-the-helper-release-digest.md` (lock pins and inventories)
- `docs/adr/0030-rotate-the-dependency-attestation-trust-anchor.md`
- `internal/dependencyprepare/attestation.go`, `internal/dependencyprepare/domain.go`, `internal/adapter/dependencyprepare/store_linux.go`
