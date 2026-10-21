# Central Local Infra Delivery Requirements

`central-local-infra` is an external delivery required before B10 can become
Accepted. This document is a requirements record, not an acceptance contract.
The delivery owner must provide a completed immutable contract before G2 starts.

## Required immutable inputs

- Named delivery responsible individual and escalation owner.
- Immutable source repository URI and commit SHA.
- Delivery date.
- Reproducible build recipe and SHA-256 digest.
- Two isolated, cache-independent clean-builder records using the same
  hermetic inputs and producing byte-identical OCI layout, manifest, config,
  and layer digests; any mismatch rejects delivery.
- Signed OCI manifest, config, and layer digests.
- SBOM, provenance attestation, vulnerability-admission result, and syscall and
  AppArmor policy digests.

## Required runtime behavior

- Preserve the accepted `central-local-infra` closed mode census of `fs-init`
  and `wipe`. The external delivery must not introduce a `minio-provision`
  mode or replace the existing MinIO `minio-provision` Compose service without
  an Accepted ADR and topology amendment.
- No mutable tag, shell, package manager, arbitrary host path, arbitrary
  network target, or caller-controlled entrypoint.
- `minio_runtime_v1` is a sealed, descriptor-only handoff bound to the exact
  provisioner identity and operation receipt. It specifies recipient UID,
  instance and bucket scope, one-use consumption, replay denial, expiry,
  revocation, rotation, and opaque receipt fingerprint. It never appears in
  Compose YAML, environment variables, image metadata, logs, or receipts.
- Per-runtime MinIO principal is deny-by-default and cannot list, delete,
  cross Workspace prefixes, access administration or console APIs, use root
  credentials, bypass retention, delete versions, or access anonymous
  endpoints. Ready-key overwrite prevention is enforced by the Artifact
  adapter's create-only conditional write precondition, not IAM alone.

## Required verification

- Clean-host image pull and digest inspection.
- Signed provenance and SBOM verification before deployment.
- Descriptor replay, substitution, expiry, revocation, wrong-UID, wrong-prefix,
  list, delete, cross-Workspace, anonymous, root, and retention-bypass denial
  tests, plus a ready-key create-only precondition conflict test.
- Object Lock mode and UID separation proof.
