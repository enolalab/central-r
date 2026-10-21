# Local Security Authority — Operational Runbook

Design-only Gate 8 contract — commands are not currently available; Gate 9 slices return exit 5/UNSUPPORTED_IN_THIS_SLICE without mutation until implemented.

Every ADR-0009-dependent rule in this document (release-security owner roles, advisory bundle compilation, offline signing ceremony, public-key custody, emergency response, and all current/stale/hard-expired/deny behavior) is documentary and becomes effective only when ADR 0009 is Accepted.

## 1. Purpose and ownership

This document is the operational security-authority runbook for the Gate 8 local development environment. It defines the release-security owner's roles, the lifecycle of `central.security-advisory/v1` bundles, the current/stale/hard-expired/deny state machine, emergency response procedures, key custody and recovery, publication outage behavior, offline distribution, and operator recovery actions. It consumes the approved [Gate 8 governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) and the [configuration and protected-state contract](../security/local-configuration-and-protected-state.md), through [ADR 0009](../adr/0009-adopt-local-development-environment-topology.md).

The release-security owner—not Gate 9 runtime code, the Central maintainer, or any development operator—owns:

- The advisory compiler and source-feed ingestion pipeline
- The offline signing ceremony for `central.security-advisory/v1` bundles
- The Ed25519 release-security private key, its offline custody, and its recovery
- Publication of signed advisory bundles to the embedded HTTPS endpoint
- Emergency denylist activation and publication
- The independently downloadable offline bundle channel
- Key-compromise recovery through a reviewed release

The installed production helper and all Gate 9 runtime components are **closed consumers**: they verify, admit, and enforce bundles but never create, sign, extend, or weaken them. Repository state, unsigned caches, caller environment, TLS alone, scanner exit status alone, or a locally edited vulnerability database is never advisory authority.

## 2. Advisory bundle identity and compilation

### 2.1 Bundle schema and identity

A canonical `central.security-advisory/v1` bundle is a root-owned, create-only, signed JSON document. It contains:

| Section | Fields |
| --- | --- |
| Bundle identity | `bundle_id` (UUIDv7), `key_id` (fixed ASCII), `issued_at` (UTC RFC 3339), `expires_at` (UTC RFC 3339, at most 7 days after issue) |
| Source verification | Source-feed snapshots and digests, scanner names/versions/database digests |
| Platform identity | Exact platform, prerequisite-manifest, dependency-lock, build-recipe, helper-authority, and policy digests |
| PostgreSQL evidence | OCI index/platform/config/layer/package identities and SPDX SBOM digest |
| MinIO evidence | Source URL/tag/commit/archive, module graph, build/runtime base, built OCI identities, package inventory, and SPDX SBOM digest |
| Infrastructure evidence | `central-local-infra` OCI/config/layer identities, static-binary provenance, syscall-policy digest, and SPDX SBOM digest |
| Tool identity | Docker, Compose, Go, and PostgreSQL client identities used to resolve, build, scan, or operate the dependencies |
| Findings | For every finding: advisory ID, affected component and exact digest, CVSS vector/score/severity, known-exploited status (CISA KEV or equivalent), fixed-version status, and signed evidence references |
| Exceptions | Signed exceptions (see §2.4) |
| Emergency denylist | Advisory IDs and component/image/source digests that are immediately denied |

### 2.2 Deterministic compilation

The release-security owner builds each bundle from:

1. Fixed-version vulnerability scanners and feed databases with pinned, independently stored snapshot evidence.
2. The exact embedded prerequisite, dependency-lock, helper-authority, and policy digests matching the release artifact.
3. Independently resolved digest evidence for every dependency.
4. Every finding traceable to an advisory ID, component digest, CVSS score, and known-exploited classification.

Compilation produces one RFC 8785 canonical JSON bundle. The owner computes SHA-256 over the canonical bytes, creates an Ed25519 signature over domain-separated `central.security-advisory/v1|bundle|SHA-256:<digest>` with the offline release-security key, and bundles the result as `{bundle, signature}`. The owner verifies the signature under the embedded public key and records the compilation evidence before publication.

### 2.3 Issue and expiry limits

| Rule | Value |
| --- | --- |
| Maximum bundle lifetime | 7 days (issue to expiry) |
| Issue time | Must not be in the future (validated against database time or kernel monotonic clock) |
| Expiry | Strictly in the future at admission time |
| Grace period after expiry (stale) | 30 elapsed days from expiry, allowing unchanged admitted identities only |
| Hard expiry | Immediately after stale grace expires; serve and all mutations blocked |
| Stale admission ceiling | 30 days; after this, `SECURITY_AUTHORITY_HARD_EXPIRED` |

The helper stores each admitted bundle as a create-only generation with an atomically replaced `active.json` selector. Database time is used when safely available; otherwise kernel time must be no earlier than the root-owned last successful activation time, so local clock rollback cannot reactivate old evidence. A bundle is admissible only when:

1. Its Ed25519 signature over RFC 8785 canonical JSON verifies under the embedded key.
2. Its issue time is not in the future.
3. Its expiry is no more than seven days after issue and is still in the future.
4. Every evidence digest resolves.
5. Every identity matches the installed helper and preparation authority.
6. No emergency deny applies.
7. No policy/exception/provenance violation exists.

Successful admission writes a root-owned immutable `central.security-admission/v1` receipt binding the exact already-installed prerequisite, helper, lock, images, policy, bundle, exception, and emergency-deny identities. Expiry never admits a different identity.

### 2.4 Signed exceptions

A signed exception may cover only one exact non-known-exploited High/Critical advisory and component digest. It must state scope, owner, compensating controls, issue time, and expiry. Expiry is at most 30 days after issue and no later than bundle expiry. Unknown/unscored findings, known-exploited findings, emergency-denied identities, provenance mismatches, and expired evidence are non-exemptible.

### 2.5 Fixed acceptance policy

The helper rejects any component with:

- CVSS score ≥ 7.0 (High or Critical)
- CISA KEV or signed equivalent known-exploited finding
- Any emergency-denied advisory or digest
- Any finding with unknown severity/score
- Stale feed evidence
- Any provenance/SBOM/identity mismatch

These categories are non-exemptible. A signed exception may cover only one exact non-known-exploited High/Critical advisory and component digest; all other denials remain.

## 3. Security authority state machine

### 3.1 Four authority states

| State | Definition | Behavior |
| --- | --- | --- |
| `current` | Active signed bundle, not expired, all checks pass | Admit new dependencies and artifacts; `prepare`, dependency-upgrade, and all normal operations permitted |
| `stale` (`SECURITY_AUTHORITY_STALE`) | Bundle expired but ≤ 30 days elapsed; exact prior admission receipt matches current installation | `prepare`, dependency-upgrade, helper/release transition, and changed-identity operations **blocked**; `up` and `serve` **permitted** only with the receipt-bound set of identities; prominent warnings/metrics emitted; exit code is `0` with the stale diagnostic |
| `hard_expired` (`SECURITY_AUTHORITY_HARD_EXPIRED`) | Expiry + 30 elapsed days exceeded, or clock rollback evidence | `up`, `serve`, agent execution, bootstrap/session creation, migration, ordinary backup create, restore apply, and every application mutation **blocked**; exit code is `5`/`SECURITY_AUTHORITY_HARD_EXPIRED` |
| `denied` (`DEPENDENCY_DENIED`) | Signed emergency deny present, or policy/exception/provenance violation, or identity mismatch | All admission and protected-value use **blocked immediately**; exit code is `5`/`DEPENDENCY_DENIED` |

### 3.2 State transition matrix

| From | Trigger | To | Exit code |
| --- | --- | --- | --- |
| `current` | Bundle expiry (no new bundle admitted) | `stale` | `0`/`SECURITY_AUTHORITY_STALE` |
| `stale` | New current bundle admitted | `current` | `0`/`OK` |
| `stale` | 30 days elapsed from expiry | `hard_expired` | `5`/`SECURITY_AUTHORITY_HARD_EXPIRED` |
| `current` | Emergency deny published and admitted | `denied` | `5`/`DEPENDENCY_DENIED` |
| `stale` | Emergency deny published and admitted | `denied` | `5`/`DEPENDENCY_DENIED` |
| `hard_expired` | New current bundle admitted | `current` | `0`/`OK` (after `security update`) |
| `denied` | Deny rescinded and new current bundle admitted | `current` | `0`/`OK` (after `security update`) |
| Any | Clock rollback detected | `hard_expired` or `denied` (whichever is stricter) | `5` |

### 3.3 Permitted operations by state

| Operation | `current` | `stale` (≤30d) | `hard_expired` | `denied` |
| --- | --- | --- | --- | --- |
| `prepare` | ✓ | ✗ | ✗ | ✗ |
| `dependency-upgrade` | ✓ | ✗ | ✗ | ✗ |
| `up` / `serve` | ✓ | ✓ (receipt-bound only) | ✗ | ✗ |
| `local status` / `local security status` | ✓ | ✓ | ✓ | ✓ |
| `local doctor` (read-only, no probes) | ✓ | ✓ | ✓ | ✓ |
| `local doctor --write-probe` | ✓ | ✗ | ✗ | ✗ |
| `local doctor --backup-throughput-probe` | ✓ | ✗ | ✗ | ✗ |
| `bootstrap show` | ✓ | ✓ | ✗ | ✗ |
| `browser open` | ✓ | ✓ | ✗ | ✗ |
| `migrate up` | ✓ | ✗ | ✗ | ✗ |
| `backup create` (ordinary) | ✓ | ✗ | ✗ | ✗ |
| `backup create --security-rescue` | N/A | N/A | ✓ (one seal only) | ✗ (rescue creation blocked; cleanup still permitted) |
| `backup verify` / `backup list` / `backup export` | ✓ | ✓ | ✓ (sealed only) | ✗ |
| `backup import` (fresh host) | ✓ (after `security update`) | ✗ | ✗ | ✗ |
| `restore verify` / `restore apply` | ✓ | ✗ | ✗ | ✗ |
| `security update` | ✓ (refresh) | ✓ (re-admit) | ✓ (re-admit) | ✓ (only if deny rescinded and new bundle signed) |
| `backup security-rescue cleanup` | ✓ (if bound scratch exists) | ✓ (if bound scratch exists) | ✓ (if bound scratch exists) | ✓ (if bound scratch exists; deny cannot block cleanup) |
| `local down` | ✓ | ✓ | ✓ | ✓ |
| `explain` | ✓ | ✓ | ✓ | ✓ |

### 3.4 Clock rollback resistance

The helper records the last successful activation time in root-owned immutable evidence. Every admission check requires kernel time ≥ last activation time. If kernel time is earlier (rollback), the helper:

1. Does not admit the bundle.
2. If a previously current bundle is now in the past relative to the recorded last-activation time, transitions to `hard_expired` or `denied` (whichever is stricter).
3. Records root-owned time-evidence with the UTC discrepancy, boot ID, and recorded activation head.
4. Returns exit `5`/`SECURITY_REVIEW_REQUIRED` or `SECURITY_AUTHORITY_HARD_EXPIRED`.

There is no renewable risk-acceptance override. Database time, when safely available from the existing authorized connection, is compared to kernel time; a persistent discrepancy ≥ 60 seconds blocks admission.

### 3.5 Emergency deny

A signed emergency deny is part of the `central.security-advisory/v1` bundle (not a separate artifact). It contains exact advisory IDs and component/image/source digests to deny. At admission:

- Every denied digest is immediately blocked regardless of CVSS score, exception, or prior admission.
- A deny cannot be overridden by an exception.
- The helper writes immutable emergency-deny evidence and synchronizes it before any existing bundle can be replaced.
- A new current bundle that removes the deny entries, after signature verification, permits re-admission of the previously denied identities.

**A signed deny blocks new rescue creation but cannot block cleanup of an already bound rescue scratch root.** The `abandoned_for_cleanup` transition is explicitly permitted even when the active bundle contains a deny. This ensures that scratch roots from interrupted or completed rescue operations can always be cleaned, preventing indefinite disk consumption from an emergency advisory.

## 4. Advisory update procedure

### 4.1 Online update

`central local security update` is a lifecycle-exclusive explicit operation. It requires:

1. Dependencies stopped (`local down` or proven stopped).
2. No active runtime, backup, restore, migration, wipe, or upgrade operation.
3. Fresh PAM authentication.
4. Lifecycle-exclusive ownership.

The online form permits the helper to fetch only its embedded HTTPS advisory endpoint. The helper:
1. Bounds input size.
2. Verifies the complete bundle (signature, freshness, evidence, policy).
3. Synchronizes a create-only generation.
4. Atomically activates it.
5. Writes correlated safe audit evidence.

### 4.2 Offline update

The offline form has the controller open one operator-selected absolute file with no-follow regular-file checks and pass only a fixed inherited read-only descriptor. The pathname is not sent and the signed bytes receive no authority until validation completes. The helper:
1. Bounds input size from the descriptor.
2. Verifies the complete bundle using the identical signature and freshness rules.
3. Applies the identical admission policy.
4. Cannot extend validity beyond the bundle's embedded expiry.

Neither form accepts a caller URL, public key, digest, scanner database, exception, denylist, policy, or expiry.

### 4.3 Advisory warnings

The helper emits advisory-expiry warnings through the observability pipeline at:

| Threshold | Action |
| --- | ---: |
| 72 hours before expiry | Metric `central_security_authority_seconds_until_expiry` becomes observably decreasing; trusted TTY status shows `STALE_IN_72H` |
| 24 hours before expiry | Trusted TTY status shows `STALE_IN_24H` |
| 6 hours before expiry | Trusted TTY status shows `STALE_IN_6H`; `central serve` logs a warning at severity `WARN` every 30 minutes |
| Expiry reached | Authority transitions to `stale`; metric goes negative; prominent warning on every `local status`/`local doctor`/`serve` startup |
| Stale grace expiry | `serve` refuses startup; running `serve` terminates at the next health interval with `SECURITY_AUTHORITY_HARD_EXPIRED` |

## 5. Key custody and recovery

### 5.1 Release-security key

The installed helper embeds one Ed25519 release-security public key and key ID inside its root-owned authority digest. The corresponding private key is offline and absent from:

- The repository
- The helper executable or its build environment
- The local instance
- Every container, mount, environment variable, and network path
- The advisory endpoint (which serves only signed bundles)

### 5.2 Key rotation

Normal key rotation requires:
1. A transition bundle signed by the **previously trusted** private key containing the new public key and key ID.
2. A new helper release embedding the new public key.
3. The old key remains verification-only until all admitted bundles referencing it have expired or been replaced.

Loss or compromise of the offline private key requires an explicit root trust transition: an independently reviewed new release artifact with a new embedded public key, installed by an administrator. `security update` cannot perform this transition.

### 5.3 Key loss procedure

If the offline signing key is lost:

1. The release-security owner generates a new Ed25519 key pair and records the key-compromise event.
2. A new Central release is cut with the new embedded public key and key ID.
3. The administrator installs the new release helper following the prerequisite runbook.
4. The new helper admits no bundles signed by the old lost key.
5. All existing admitted bundles become stale and eventually hard-expired unless the new release-security owner publishes new bundles signed by the new key before the existing installed bundle's stale grace expires.

If the signing key is compromised:
1. The release-security owner immediately publishes an emergency deny bundle signed by the compromised key (the last authoritative action of that key) denying all currently pinned digests, or if the key is already untrusted, publishes a new bundle signed by a new key distributed through the offline channel.
2. The compromised key is recorded in the repository's key-compromise ledger.
3. All operators are instructed to perform `security update` offline with the new bundle.
4. A new release with the replacement key follows within the stale grace period.

### 5.4 Publication outage

If the HTTPS advisory endpoint is unreachable:

1. `security update` online returns exit `3`/`DEPENDENCY_UNAVAILABLE` with the exact offline-update command template.
2. The operator obtains the current signed bundle through the independently available offline channel.
3. The operator runs `central local security update` with the offline file descriptor.
4. The bundle is verified under the identical rules; offline delivery cannot extend validity.

The offline channel is the release-security owner's responsibility: it may be a separately hosted HTTPS download, a signed Git release artifact, or physical media. The channel identity is not embedded in the helper (it is a human process), but the bundle signature and embedded key provide authenticity regardless of channel.

If both the online endpoint and offline channel are unavailable, an already-admitted installation continues under the [state machine rules](#31-four-authority-states): current → stale (30 days) → hard_expired. The release-security owner must restore at least one channel within the 30-day stale window to prevent hard expiry.

## 6. Operator recovery actions

### 6.1 Normal re-admission (stale → current)

```text
central --config <absolute-config-path> local security update
# If online is unavailable:
central --config <absolute-config-path> local security update
# (select the offline bundle file at the helper prompt)
```

After successful admission, `local security status` reports `authority_state: current`.

### 6.2 Recovery from hard expiry

1. Obtain a current signed advisory bundle (online or offline).
2. Ensure dependencies are stopped.
3. Run `central --config <absolute-config-path> local security update`.
4. Verify: `central --config <absolute-config-path> local security status` reports `current`.
5. If a rescue backup was created during hard-expired state: verify it with `backup verify`, then follow the restore journey when ready.

Note: A hard-expired installation cannot create new backups, serve, or mutate. An existing sealed backup from the current epoch remains verifiable and restorable once authority returns.

### 6.3 Recovery from emergency deny

1. The operator runs `local security status` to confirm the deny state and denied identities.
2. Obtain a new signed bundle that either removes the deny entries (after the vulnerability is remediated or the deny is rescinded) or explicitly re-admits the installation.
3. Ensure dependencies are stopped.
4. Run `central --config <absolute-config-path> local security update`.
5. If a rescue scratch root exists: `backup security-rescue cleanup --operation=<id>` remains permitted regardless of deny state.

### 6.4 Rescue backup cleanup during deny

A signed deny cannot block `backup security-rescue cleanup --operation=<id>`. The operator runs:

```text
central --config <absolute-config-path> backup security-rescue cleanup --operation=<rescue-operation-id>
```

This requires fresh PAM, lifecycle-exclusive ownership, and proves no rescue process/lock is active. It commits `abandoned_for_cleanup`, stops/reaps operation-bound temporary containers, proves mounts released, deletes scratch data in bounded quanta, and records the tombstone. No backup, data mutation, or caller path is permitted.

## 7. Offline distribution

### 7.1 Bundle channel requirements

The release-security owner must provide an independently accessible offline bundle channel. Requirements:

1. The bundle is the same canonical JSON + Ed25519 signature as the online endpoint.
2. The bundle filename convention is `central-security-advisory-v1-<bundle-id>.json` with an accompanying `central-security-advisory-v1-<bundle-id>.sig`.
3. The channel must be accessible without the Central instance (i.e., not hosted on the Central operational or application listener).
4. The channel identity (URL, filesystem path, physical media) is documented in release notes but is not embedded in the helper as authority; the signature alone provides authenticity.

### 7.2 Operator offline update procedure

1. Download or copy the bundle and signature files to operator-owned media.
2. Ensure the files are regular files (not symlinks) on the supported ext4 filesystem.
3. Run `central --config <absolute-config-path> local security update`.
4. At the helper prompt, select the bundle file.
5. The helper opens the file with no-follow semantics, verifies the bundle and signature, and atomically activates it.

The operator never imports a bundle through a flag, environment variable, `--output=json`, or stdin redirection. The helper-owned PAM and TTY ceremony remains mandatory.

## 8. Operator audit evidence

Every security-authority transition produces immutable audit evidence:

1. `central.security-admission/v1` receipt: bundle ID, key ID, issue/expiry, all admitted identity digests, policy result, admission time.
2. Operator-audit record in `central-state`: command, operator UID, PAM authorization class, bundle IDs, transition reason (`current_to_stale`, `stale_to_hard_expired`, `deny_activated`, `new_bundle_admitted`), start/update/end time, and broker HMAC.

Audit records are retained for at minimum 365 days (or the newest 10,000 records, whichever is larger). Security-authority transitions are never eligible for automatic pruning while the referenced bundle is current or stale; hard-expired security transitions may be archived after 365 days plus a new current bundle has been admitted.

## 9. Reference-host security checklist

The release-security owner must validate before every bundle publication:

- [ ] Offline signing key present and verified on air-gapped hardware
- [ ] Scanner feed databases updated within 24 hours of bundle issue
- [ ] No known-exploited (CISA KEV or equivalent) finding for any pinned dependency digest without an emergency deny
- [ ] No High/Critical (CVSS ≥ 7.0) finding for any pinned dependency digest without either an exact signed exception or emergency deny
- [ ] Every evidence digest (OCI indices, manifests, configs, layers, SBOMs, provenance) independently resolved and verified
- [ ] Bundle expiry ≤ 7 days from issue
- [ ] Bundle signature verified under the embedded public key before publication
- [ ] Publication endpoint reachable and serving the exact signed bundle
- [ ] Offline bundle available through the independent channel
- [ ] Emergency denylist reviewed and signed (if any entries)
- [ ] Signed exceptions reviewed, each covering only one exact non-known-exploited advisory/component with expiry ≤ 30 days
- [ ] No unsigned, placeholder, or ambiguous evidence in any section

## 10. Canonical references

- [Gate 8 governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md)
- [ADR 0009](../adr/0009-adopt-local-development-environment-topology.md)
- [Local configuration and protected state contract](../security/local-configuration-and-protected-state.md)
- [Local topology contract](../architecture/local-development-environment.md)
- Gate 8 implementation plan (upstream `central` record: `docs/internal/superpowers/plans/2026-07-16-phase-0-local-development-environment.md`)
