# Release-authority key custody and offline signing

> **Public-project applicability (2026-10-30):** this document is the
> maintainer custody record for `enolalab/central-workspace`. Custody
> holder: the maintainer alone (`hieuntg81`), single-signer model.
> Sections that already apply verbatim: "Custody model", "Offline
> backup", "Offline signing runbook", "Rotation and emergency
> revocation" — the advisory trust root is compiled at
> `central-infra::advisory` (`central-release-authority/v2`). Sections
> describing artifacts this repository does not yet ship — "Tarball
> signer (`central-release/v1`)", `install.sh` verification,
> `ci/build-release.sh`, `release-signing.pub` — are pending the Phase 3
> release workflow (`docs/internal/tasks/open-source-readiness.md`); the
> `central-release/v1` key has not been generated, and its fingerprint
> slot below stays unfilled until it is.

Two different "release keys" exist — do not confuse them:

- **Advisory key** (this document): Ed25519, `key_id central-release-authority/v2`, signs security-advisory bundles. Trust root = compiled-in pubkey in `internal/advisory/release_key.go`; fingerprint = `sha256(pubkey)`.
- **Release-tarball signer**: an SSH key (`install.sh` `RELEASE_PUBKEY` / `ssh-keygen -Y verify`, `install.sh --show-release-key`) that signs `SHA256SUMS` for release artifacts. Separate custody — see "Tarball signer" below.

## Tarball signer (central-release/v1)

- Identity: SSH Ed25519 keypair `central-release/v1`, principal `central-release`, signature namespace `central-release` (`ssh-keygen -Y sign/verify`).
- The private key is generated **once, offline** by the maintainer (`ssh-keygen -t ed25519 -f central-release-v1 -C central-release/v1`), kept in the same offline-custody manner as the advisory key, never committed, never on CI.
- The public half is committed at `packaging/install/release-signing.pub` and stamped into every released `install.sh` by `ci/build-release.sh`. A placeholder (`…REPLACE_ME…`) blocks tag builds until the real `.pub` is committed.
- `scripts/release-sign.sh` refuses to sign when `ssh-keygen -y` on the private key disagrees with the committed `.pub` — a mismatch means the released installer would verify nothing.
- Fingerprint (publish, verify against — maintainer fills at keygen):
  `central-release/v1` SHA256:`<fill at keygen>`

## Custody model

- The v2 private key lives only in `~/.local/state/central/release-authority/release-authority-v2.json` on the maintainer's dev host (mode `0600`). It is never committed, never on CI, never in release artifacts.
- The public key is committed by design (`release_key.go`) — a public key discloses nothing.
- Fingerprint (publish this, verify against it):
  `central-release-authority/v2` sha256 `bef5edef6abe9a1f437ffa3630508b2d78f420e49142dc752ff8a5664969057d`
  pubkey (base64): `qvXtNCLuEhrZ2x3nwaXICuq4RytGkhRVEU3DZtkZdRA=`

## Offline backup — maintainer-executed checklist

It cannot be performed by automation; record location+date in your private note, not in git.

- [ ] Encrypt to a symmetric container: `gpg --symmetric --cipher-algo AES256 --output release-authority-v2.json.gpg ~/.local/state/central/release-authority/release-authority-v2.json` (gpg is already an install dependency; pick a strong passphrase).
- [ ] **Passphrase custody**: store the passphrase in your password manager AND/OR a separate physical note. A lost passphrase = a lost key.
- [ ] Copy the `.gpg` file to **≥2 offline media** (e.g. two USB sticks), stored in different physical locations.
- [ ] Verify each copy: `sha256sum` matches the original `.gpg`, and `gpg --decrypt` on a copy yields a file whose sha256 matches the source JSON.
- [ ] Optional upgrade path: hardware token or Shamir split — documented as optional; not required at single-maintainer scale.
- [ ] Record media locations + last-verified date in a maintainer-private note. **Locations are sensitive — never commit them.**

## Offline signing runbook

Never sign on CI. To sign a bundle:

1. Restore/copy the key file to a scratch location on a trusted host (or read it in place).
2. Pipe the private key via stdin — do not write a bare-key file:

```bash
python3 -c "import json;d=json.load(open('release-authority-v2.json'));print(d['private_key'],end='')" \
  | central-advisory-sign bundle --private-key-file - --out advisory-bundle.json \
      --expires 2027-01-01T00:00:00Z [--os-release … --kernel … --docker … --compose … --psql …]
```

3. Verify offline before distribution: `central-advisory-sign verify --bundle advisory-bundle.json` → `VALID key_id=central-release-authority/v2 …`.
4. Deliver via `central local security update advisory-bundle.json` (or ship in the release).
5. Shred scratch copies (prefer tmpfs `/dev/shm` — `shred` is unreliable on SSDs).

## Rotation and emergency revocation

Clients learn the trust anchor from the **binary they run** — `productionTrust` in `release_key.go`. Rotation therefore ships as code + release:

- **Compromise** (v2 held): issue a v2-signed `emergency_deny` bundle immediately (`bundle --emergency-deny --deny-reason …`) — hard-stops `serve` and mutations; then on an offline-clean host `genkey` v3, embed `public_key_base64` + `key_id central-release-authority/v3` in `release_key.go`, publish the new fingerprint in README/SECURITY.md/release notes, and ship a release. Users get the new anchor by upgrading.
- **Loss without compromise**: same path minus the emergency-deny step.
- `ReleaseAuthorityDigest` in `productionTrust` stays `""` — it is an unused cross-check field, not part of compiled trust.

## Verification drill (rehearsal)

The custody drill — sign from a backup copy and verify with the production trust root — is exercised in `docs/internal/tasks/key-custody-rehearsal-2026-10-04.md`. Repeat it whenever a backup medium is created or rotated:

1. Copy the key JSON to scratch (simulating restore from backup).
2. Sign a test bundle from the copy via stdin.
3. `central-advisory-sign verify` → VALID.
4. Destroy the scratch copy.
