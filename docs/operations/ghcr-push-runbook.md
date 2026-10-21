# GHCR Push Runbook (maintainer)

Pushes the delivery-reviewed `central-local-infra` image to GHCR so the
installer pulls it by digest. Run once per delivery; record the digest below.

Prerequisites: `docker login ghcr.io` (a token with `write:packages`), a
delivery-reviewed `central-local-infra` commit (SB-G2-style evidence).

1. Note the commit and the expected digest (from Central's
   `internal/dependencyprepare/assets/dependency-lock.json`, any of the
   `*-fs-init` / `minio-provision` / `postgres-throughput-provision` modes —
   all four share one manifest):
   `git -C ~/Code/central-local-infra rev-parse HEAD`
   Expected manifest: `sha256:3930ac40a034eff98b844a500e61c5c4924cb44bdeb45b2efedc18f048c0063b`
   (If the lock has moved on, use ITS digest, not this one.)
2. Build + policy-check with the qualified ref:
   `cd ~/Code/central-local-infra`
   `make image IMAGE_REF=ghcr.io/enolalab/central-local-infra:review-<shortsha>`
   `make check-image-policy IMAGE_REF=ghcr.io/enolalab/central-local-infra:review-<shortsha>`
3. Push: `docker push ghcr.io/enolalab/central-local-infra:review-<shortsha>`
4. Verify the pushed manifest digest equals the lock digest (fail = STOP, do
   not use; re-run the delivery):
   `docker buildx imagetools inspect --raw ghcr.io/enolalab/central-local-infra:review-<shortsha> | sha256sum`
5. Record: date, commit, tag, digest in `docs/internal/tasks/install-a-distribution-2026-10-02.md`
   (or the then-current distribution record).

Notes: `postgres:*` and `minio` modes are external Docker Hub images — never
pushed here. The installer pulls by digest, so a wrong image fails the pull
instead of installing wrong bytes.
