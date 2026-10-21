# ADR 0039: Rotate the release authority key and record its custody

- **Number:** 0039
- **Title:** Rotate the release authority key and record its custody
- **Status:** Accepted
- **Created:** 2026-10-01
- **Owners:** Central maintainer
- **Decision due:** 2026-10-15
- **Decision due history:** None
- **Implementation blocked at:** Changing the pinned release authority public key in `internal/advisory/release_key.go`, the default key id of `cmd/central-advisory-sign`, and shipping any signed advisory bundle with a release (one-click install sub-project A2). Development admission (`CENTRAL_DEVELOPMENT_LOCAL_ONLY=1`) is not blocked.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-10-01)
- **Decision date:** 2026-10-01
- **Decision record:** Maintainer approval in session on 2026-10-01 ("chấp nhận ADR 0038 và 0039"); committed by the maintainer in this dedicated status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/internal/tasks/sc-g3-release-authority-key-substitution-2026-09-23.md`; `docs/internal/superpowers/specs/2026-09-27-one-click-install-design.md` decisions 4-6 and §A; ADR 0030 (the analogous rotation of the dependency-attestation key); `internal/advisory/release_key.go`, `internal/advisory/verify.go`, `cmd/central-advisory-sign`

## Context

Production B01 admission verifies a signed security advisory bundle against one compiled-in Ed25519 public key, key id `central-release-authority/v1` (`internal/advisory/release_key.go`). The private half of the original key was lost; the key compiled in today is a test key generated on a rehearsal VM for SC-G3 under the same key id, and its disclosure says it proves the mechanism and is **not** the production trust anchor (`docs/internal/tasks/sc-g3-release-authority-key-substitution-2026-09-23.md`). No ADR records who holds this key or how it is backed up.

Without a real key no release can ship a bundle, so production admission refuses every host, and every install today needs `--dev-admission` for anything after genesis (install D1 record). The host-side witness (`time-witness.json`) stores only times, not a key id, so a host that accepted a bundle under one key accepts a correctly dated bundle under another.

## Decision

Accepted:

1. **New key, new id.** The maintainer generates a new Ed25519 key pair offline with `central-advisory-sign genkey`, key id `central-release-authority/v2`. The `v1` id is retired with its test key; no binary trusts both (single-key trust, as today).
2. **Custody.** The private half is a maintainer deployment secret held outside any repository, on the maintainer's workstation at `~/.local/state/central/release-authority/release-authority-v2.json` (mode 0600), with at least one offline backup that survives the loss of that machine (ADR 0030 D2's rule, applied to this key). It never reaches CI, a VM, or a release artifact.
3. **Pin.** `release_key.go` pins the v2 public key and key id; `central-advisory-sign` defaults to the v2 id; the tests that pin the id change with it. This is a Central release.
4. **Release bundles.** Each release ships one advisory bundle signed with the v2 key, with the host-specific compatibility fields (kernel, docker) left empty so it matches any supported host, and an `expires_at` that the installer's `--verify` warns about ahead of time. `install.sh` installs it with `central local security update` after genesis.
5. **Upgrade effect.** A host upgraded to a v2 binary refuses its installed v1 bundle (`SignatureInvalid`, so Denied) until the v2 bundle is installed; the installer does that in the same run.
6. **Separate from the release signature.** The key that signs the release's `SHA256SUMS` (one-click design decision 6) stays a different key.

## Consequences

### Benefits

- Production admission becomes possible for every installed host, and `--dev-admission` returns to being a development-only switch.
- The key's custody is written down, which is what the lost v1 key lacked.

### Costs and limitations

- The maintainer must create, back up and guard a second long-lived secret.
- Upgrading a host requires installing the new bundle in the same run, or the host is Denied until it is.
- Single-key trust means no overlap period: a key compromise is a release.

## Alternatives considered

### Keep the key id `v1` with a new key

Indistinguishable in logs and bundles from the lost and test keys of the same id; a v1 bundle seen anywhere would be ambiguous. Rejected.

### Multi-key trust with an overlap period

Smoother rotations, but a verifier change and a new attack surface for no current need (there is no deployed population to migrate). Deferred.

### Use the release `SHA256SUMS` key for advisories too

One secret fewer, but compromise of the release signing path would also grant admission authority. Rejected (one-click design decision 6).

## Follow-ups

- One-click install sub-project A2: the pin change, the sign tool default, the release bundle and the installer step (owner: Central maintainer; blocked on this ADR and on the maintainer generating the key).
- Record the backup location and its last verification date in the A2 record without the key material.

## References

- `docs/internal/tasks/sc-g3-release-authority-key-substitution-2026-09-23.md`
- `docs/adr/0030-rotate-the-dependency-attestation-trust-anchor.md`
- `internal/advisory/release_key.go`, `internal/advisory/verify.go`, `internal/adapter/advisory/time_witness_linux.go`, `cmd/central-advisory-sign/main.go`
