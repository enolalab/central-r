# ADR 0012: Extend root credential mount and add minio-provision mode

- **Number:** 0012
- **Title:** Extend root credential mount and add minio-provision mode
- **Status:** Accepted
- **Created:** 2026-08-06
- **Owners:** Central maintainer
- **Decision due:** 2026-08-13
- **Decision due history:** None
- **Implementation blocked at:** SB-G3 plan Task 9 (extending the fixed root-credential mount to `minio-provision` in `internal/adapter/infralifecycle/compose_linux.go`'s `addFixedSecretMount`/`validateCredentialMount`) and Task 13 (registering `minio-provision` as a valid mode in `central-local-infra`'s image and policy metadata), both of which declare themselves explicitly blocked on this ADR's acceptance in their own plan headers. The plan's Global Constraints section gates the same two tasks — "before Task 9 (the mount extension) or Task 13 (the new mode's Dockerfile label) may land" — on this ADR reaching Accepted status.
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-07
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** ADR 0014
- **Related:** [SB-G3 MinIO Runtime Provisioning Design](../internal/superpowers/specs/2026-08-06-sb-g3-minio-runtime-provisioning-design.md), [central-local-infra Design (2026-08-05)](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md), [SB-G3 MinIO Runtime Provisioning Implementation Plan](../internal/superpowers/plans/2026-08-06-sb-g3-minio-runtime-provisioning.md), [Central Local Infra Delivery Requirements](../operations/central-local-infra-delivery-requirements.md), [ADR governance](README.md)

## Context

B10 (Artifact/object-storage lifecycle) has a fully implemented domain, reconciliation algorithm, and outbound broker transport, but `runtimeArtifactObjectStore()` has never had a real MinIO runtime credential to construct a client from — it remains a permanent zero-value stub. The [SB-G3 design](../internal/superpowers/specs/2026-08-06-sb-g3-minio-runtime-provisioning-design.md) closes that gap by having a new `minio-provision` mode in `central-local-infra` mint a scoped MinIO IAM credential and deliver it to Central's broker over a new inbound sealed-descriptor channel, reusing the already-implemented `BindMinioRuntimeSecret` and `handleB10MinioRuntimeTransport`.

Two trust-boundary changes are required to build that mode, and both are currently closed by prior accepted decisions:

1. **The root-credential mount is fixed to one consumer.** `addFixedSecretMount` and `validateCredentialMount` in `internal/adapter/infralifecycle/compose_linux.go` hard-code the only accepted `_FILE`-indirected credential mount as `service.Name == "minio"`, `key == "MINIO_ROOT_PASSWORD_FILE"`, target `/run/secrets/minio-root-password`. Any other service name, environment key, or target fails closed with `ErrInvalidCredentialMount`. To mint a scoped credential, `minio-provision` needs read access to that same root credential file, which today only `minio` can receive.
2. **`central-local-infra`'s accepted mode census excludes `minio-provision`.** The [2026-08-05 central-local-infra design](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md) lists its closed mode census as `fs-init` and `wipe`, and its Non-goals section states plainly: "Implement a `minio-provision` mode." That exclusion was accurate for that design's scope — SB-G2's reproducible build, supply-chain evidence, and denial-proof acceptance of the closed `fs-init`/`wipe` contract — but it never answered how a real runtime credential gets minted, and no other design has answered it since. `docs/operations/central-local-infra-delivery-requirements.md`'s required runtime behavior likewise states the external delivery "must not introduce a `minio-provision` mode ... without an Accepted ADR and topology amendment" — this is that ADR.

Both changes are trust-boundary and privileged-capability-access decisions under ADR governance's "when an ADR is required" list (security or trust boundaries; privileged-capability and secret-access models; deployment topology or operating mode). Neither can proceed without a durable, reviewable decision record.

## Decision

1. **Extend the fixed root-credential mount to also cover `minio-provision`**, using the exact mechanism `minio` already uses and no new mechanism. `addFixedSecretMount` and `validateCredentialMount` are extended so that `service.Name == "minio-provision"` with the same `_FILE`-suffixed environment key pattern, the same `/run/central-infra/<instance>/secrets/minio-root-password` source, and the same read-only, non-interpolated, instance-scoped mount validation as `minio` is accepted. No other service name gains mount eligibility, no new credential-delivery pathway (environment-variable value, writable mount, or otherwise) is introduced, and every existing credential-boundary invariant SB-G2 already proved (unsupported `_FILE` destination, wrong-instance source, writable mount) continues to reject for every service other than `minio` and `minio-provision`.

2. **Authorize `central-local-infra` to add a third mode, `minio-provision`**, whose sole purpose is minting a scoped MinIO IAM credential (matching `secretbootstrap.MinioRuntimePolicy`'s declared scope, never root, never a shared secret) and delivering it to Central's broker through the existing class of sealed, one-use, fenced, SCM_RIGHTS handoff already used for the outbound broker transport. This explicitly amends the [2026-08-05 central-local-infra design](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md)'s Non-goals section to remove the "Implement a `minio-provision` mode" exclusion; every other non-goal in that document (no arbitrary shell, package-manager operations, host paths, mounts, network targets, or caller-controlled entrypoints; no Task/Run/agent/UI/PostgreSQL/MinIO-server logic) remains in force unchanged. `minio-provision` gains exactly three capabilities beyond its existing image baseline: read the root-credential file (via decision 1), reach `minio` on the existing `infra` network, and connect to one new fixed broker socket path. It gains no shell, no package manager, no additional host path, no additional network target, and no caller-controlled entrypoint.

This is a design-document amendment, not an ADR-to-ADR amendment — `docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md` is a technical specification, not a numbered ADR, so the `Amends` metadata field (reserved for ADR-to-ADR relationships) stays `None` and the relationship is recorded in prose here and in the Related section instead.

## Consequences

### Benefits

- Closes the last gap between B10's already-built, already-tested Artifact domain/reconciliation logic and it running against real object storage — `runtimeArtifactObjectStore()` can finally be wired to a real, broker-issued credential.
- Reuses all existing broker infrastructure end to end: the same sealed-descriptor handoff class, the same `BindMinioRuntimeSecret`/`handleB10MinioRuntimeTransport` pair, and the same fixed-mount validation mechanism `minio` already exercises. No new trust mechanism is introduced, only a second authorized consumer of an existing one.
- Keeps the failure mode closed: if provisioning fails for any reason, B10 stays unconfigured (today's default state), and B01–B09 are unaffected.

### Costs and limitations

- Widens the set of components trusted with the root MinIO credential from one (`minio`) to two (`minio`, `minio-provision`). Every root-credential-boundary invariant SB-G2 already proved (`TestRenderIncludesOnlySafeEnvironmentAndPolicyCommandsAndMounts`, `TestValidateModelRejectsWritableOrSubstitutedCredentialMount`, `TestB10RuntimePathNeverReferencesRootCredentialMaterial`, `TestB10HandoffRejectsRootPurposeGeneration`) must be re-verified to still hold, unmodified in intent, after the mount extension lands.
- `central-local-infra` needs a second independent SB-G2-style acceptance cycle (reproducible build, two isolated clean-builder byte-identical records, signed manifest/config/layer digests, SBOM, provenance attestation, vulnerability-admission result, syscall and AppArmor policy digests) for the new image candidate that includes the `minio-provision` mode. This is real, non-trivial delivery-side work, not a rubber stamp.
- Credential rotation on a running instance stays out of scope; rotation happens by re-running provisioning at the next bring-up, same as today's `fs-init`/`wipe` modes.

## Alternatives considered

### Separate short-lived non-root admin account for provisioning only

Mint a dedicated, time-boxed MinIO admin account distinct from the root credential, scoped only to IAM-provisioning operations, instead of extending root-credential access to a second component. Rejected during brainstorming: it adds significant machinery (account creation, rotation, and revocation logic on top of the credential-minting logic it would gate) for only a marginal blast-radius reduction over granting a second trusted, narrowly-scoped, non-network-facing component the same root access `minio` already has. `minio-provision` is not network-facing, runs only during bring-up, and gains no capability beyond reading the root file, reaching `minio`, and one broker socket — the incremental risk this alternative would mitigate does not justify its added complexity.

## Follow-ups

- Tasks 2–14 of the [SB-G3 implementation plan](../internal/superpowers/plans/2026-08-06-sb-g3-minio-runtime-provisioning.md) implement the request/receipt contracts, IAM minting, seal-and-deliver logic, broker inbound handler, the mount and mode extensions this ADR authorizes, and the accompanying tests; Task 9 and Task 13 specifically may not land before this ADR reaches Accepted.
- Task 16 of the same plan owns the second independent SB-G2-style acceptance cycle this decision's Costs section requires for the new `central-local-infra` image candidate.
- Task 17 owns final SB-G3 acceptance evidence and status update once all preceding tasks, including this ADR's acceptance, are durable.

## References

- [SB-G3 MinIO Runtime Provisioning Design](../internal/superpowers/specs/2026-08-06-sb-g3-minio-runtime-provisioning-design.md)
- [SB-G3 MinIO Runtime Provisioning Implementation Plan](../internal/superpowers/plans/2026-08-06-sb-g3-minio-runtime-provisioning.md)
- [central-local-infra Design (2026-08-05)](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md)
- [Central Local Infra Delivery Requirements](../operations/central-local-infra-delivery-requirements.md)
