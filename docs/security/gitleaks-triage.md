# Gitleaks full-history triage

Issue: enolalab/central#42. Spec: `docs/internal/superpowers/specs/2026-10-04-gitleaks-triage-design.md`. Plan: `docs/internal/superpowers/plans/2026-10-04-gitleaks-triage.md`.

## Metadata

| field | value |
|-------|-------|
| tool | gitleaks v8.28.0 (`~/go/bin/gitleaks`; build reports "version is set by build process") |
| scan date | 2026-10-04 |
| repo | `central` working copy (`$CENTRAL_SRC`), branch `oss/issue-42-gitleaks-triage` |
| commit range | all refs (`--log-opts='--all'` / `git rev-list --all`), 1630 revs, root `cbd266f1`, HEAD `fa845548`; gitleaks reports 1582 commits scanned |
| baseline report | `/tmp/gitleaks-central.json` — **42 findings**, all classified below |
| config'd reports | `/tmp/gl-central-after.json` (history) = `[]`, `/tmp/gl-central-dir.json` (worktree) = `[]` |

Commands:

```bash
# baseline (no allowlists). NOTE: `gitleaks git` auto-loads a repo-root .gitleaks.toml
# when --config is omitted — a post-Task-1 baseline must pass an explicit config.
printf 'title = "no-allowlist default config"\n[extend]\nuseDefault = true\n' > /tmp/noop-gitleaks.toml
gitleaks git --log-opts='--all' --config /tmp/noop-gitleaks.toml -r /tmp/gitleaks-central.json .
# after allowlist
gitleaks git --log-opts='--all' --config .gitleaks.toml -r /tmp/gl-central-after.json .   # 0 findings
gitleaks dir . --config .gitleaks.toml -r /tmp/gl-central-dir.json                        # 0 findings
# canary proves the ruleset is loaded under the config
printf 'token = "ghp_<36 alnum>"' > /tmp/gl-canary/x.txt   # canary literal redacted; see plan step 4
gitleaks dir /tmp/gl-canary --config .gitleaks.toml                                       # 1 finding: github-pat
```

No secret values appear in this document; findings are identified by `commit:file:rule:line` fingerprints.

## Finding groups and classification

All 42 baseline findings are fixtures, placeholders, detection patterns, or quoted strings. No real credentials.

| group | rule | files | n | classification |
|-------|------|-------|---|----------------|
| 1 | generic-api-key | `.superpowers/sdd/{gate-task-8,gate-task-9B,task-4}-report.md` | 22 | SDD gate/task reports quote fixture UUIDs, ids and hash-like values produced by test runs — not live secrets |
| 2 | generic-api-key | `docs/internal/superpowers/reviews/evidence/2026-09-10-sc-g{1-draft,1-redo}/slice-c-backup-creation.json`, `.../sc-g2-draft/slice-c-restore-verification.json` | 3 | SHA-256 digests of backup artifacts recorded as gate evidence |
| 3 | generic-api-key | `internal/adapter/postgres/migrate/b09_{durable_context_authority,provider_turn}.go` | 4 | fixed constraint-name marker constants (a `b09_…_fkey` identifier) |
| 4 | generic-api-key | `docs/internal/superpowers/specs/2026-08-01-verified-serve-configuration-snapshot-design.md` | 1 | literal placeholder string (a sentinel pair) quoted in prose |
| 5 | generic-api-key | `cmd/central/b12_slice_b_acceptance_test.go` | 1 | idempotency-key fixture constant (a `b12-settle-…` identifier) |
| 6 | curl-auth-header | `cmd/central/harness_permission_e2e_test.go`, `docs/internal/superpowers/plans/2026-09-29-harness-phase-3c.md`, `docs/internal/superpowers/reviews/2026-07-16-…-validator-contract.md` | 3 | the `sk-ant-e2e-…` e2e placeholder and a literal `…-token` doc placeholder |
| 7 | private-key | `internal/artifact/app/{classifier.go,classifier_test.go}` | 3 | PEM detection patterns and a truncated stub (`MIIB…`) used to test the artifact classifier — no key material |
| 8 | private-key | `docs/internal/superpowers/plans/2026-07-16-phase-0-implementation-backlog-and-closure.md` | 2 | doc quotes `BEGIN … PRIVATE KEY` header strings to describe classification boundaries |
| 9 | slack-bot-token | `internal/artifact/app/classifier_test.go`, `.superpowers/sdd/task-6-report.md` | 2 | `xoxb-2222…` dummy token fixture |
| 10 | github-pat | `docs/internal/superpowers/plans/2026-10-04-gitleaks-triage.md` | 1 | the plan's own canary string — a fabricated example PAT used to prove the ruleset loads |

Group totals: 22 + 3 + 4 + 1 + 1 + 3 + 3 + 2 + 2 + 1 = **42**.

Two further finding shapes exist outside the `git`-history baseline and are covered by allowlist entries but produce no baseline fingerprint:

- **`curl-auth-header` in `.superpowers/sdd/review-*.diff`** — `dir`-scan findings on tracked working notes whose on-disk content quotes the e2e placeholder (first `dir` pass reported 2; suppressed by the filename-pattern entry; final `dir` run = 0).
- **secondary `generic-api-key` emissions** on `internal/artifact/app/classifier_test.go` and `docs/internal/superpowers/plans/2026-10-04-gitleaks-triage.md` — appear only in config'd scans once the primary rules (`slack-bot-token`, `github-pat`) are allowlisted, because gitleaks dedupes across rules *after* allowlist filtering. Same fixtures; covered by a `generic-api-key` allowlist entry on the same two paths.

## Fingerprint appendix

`commit:file:rule:startline` for every baseline finding (source: `/tmp/gitleaks-central.json`).

```
75506da00fbf  cmd/central/harness_permission_e2e_test.go                                          curl-auth-header   :27
874bc6b7dd16  docs/superpowers/plans/2026-09-29-harness-phase-3c.md                               curl-auth-header   :7059
1860abddaa11  docs/superpowers/reviews/2026-07-16-phase-0-implementation-backlog-validator-contract.md  curl-auth-header :493
be2287bcca4a  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :887
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :434
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :457
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :504 (x2)
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :527 (x2)
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :552
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :575
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :624
fe5a382ce435  .superpowers/sdd/gate-task-8-report.md                                              generic-api-key    :647
c3fde7cce3f3  .superpowers/sdd/gate-task-9B-report.md                                             generic-api-key    :325,345,365,367,388,408,428,448,469,490
8d9a6a86c6e2  .superpowers/sdd/task-4-report.md                                                   generic-api-key    :71-72
791615b752a3  cmd/central/b12_slice_b_acceptance_test.go                                          generic-api-key    :1837
9b216204f7df  docs/superpowers/reviews/evidence/2026-09-10-sc-g1-draft/slice-c-backup-creation.json  generic-api-key   :10
6321626f525b  docs/superpowers/reviews/evidence/2026-09-10-sc-g1-redo/slice-c-backup-creation.json   generic-api-key   :10
6321626f525b  docs/superpowers/reviews/evidence/2026-09-10-sc-g2-draft/slice-c-restore-verification.json generic-api-key :9
74e30edc5559  docs/superpowers/specs/2026-08-01-verified-serve-configuration-snapshot-design.md   generic-api-key    :183
472cc9f43b6d  internal/adapter/postgres/migrate/b09_durable_context_authority.go                  generic-api-key    :254
1edb05e22712  internal/adapter/postgres/migrate/b09_durable_context_authority.go                  generic-api-key    :254
472cc9f43b6d  internal/adapter/postgres/migrate/b09_provider_turn.go                              generic-api-key    :649
1edb05e22712  internal/adapter/postgres/migrate/b09_provider_turn.go                              generic-api-key    :646
653999e9b87b  docs/superpowers/plans/2026-10-04-gitleaks-triage.md                                github-pat         :33
8a79c530af20  docs/superpowers/plans/2026-07-16-phase-0-implementation-backlog-and-closure.md    private-key        :390
334ab904801f  docs/superpowers/plans/2026-07-16-phase-0-implementation-backlog-and-closure.md    private-key        :385
313139220b02  internal/artifact/app/classifier.go                                                 private-key        :132-134
313139220b02  internal/artifact/app/classifier.go                                                 private-key        :135-137
313139220b02  internal/artifact/app/classifier_test.go                                            private-key        :61-62
eb420edf3636  .superpowers/sdd/task-6-report.md                                                   slack-bot-token    :310
b94b2c98970c  internal/artifact/app/classifier_test.go                                            slack-bot-token    :69
```

## Manual sweep results

Three surfaces, run 2026-10-04 against all refs + worktree. Content grep used `git grep -lE '<pat>' $(git rev-list --all) -- ':!vendor'` (POSIX ERE; `[0-9]` for `\d`) plus `git grep -lE '<pat>' -- ':!vendor'` for the worktree. "rev-hits" counts `rev:path` pairs (a file matching in N commits counts N times); "files" is unique paths.

### Surface 1 — commit messages (`git log --all --format=%B`)

| pattern | hits | classification |
|---------|------|----------------|
| `Claude-Session:` trailer | 694 lines / 694 commits / 12 unique session ids | agent-harness session URLs (`claude.ai/code/session_*`) — reference identifiers, no credential material; documented per plan |
| `AKIA\|ASIA` | 2 lines / 1 commit (`b94b2c98`) | prose describing provider-prefix detection ("an AKIA / ASIA substring … is no longer a finding") — not a key id |
| `^Host ` | 5 lines / 5 commits | lowercase "host …" prose at line start — not SSH `Host` stanzas |
| `\.(internal\|corp\|local)\b` | 2 lines / 2 commits | `settings.local.json` filename (`96720f85`), `com.central.local-infra.modes` docker label (`f6d2f9ef`) — not hostnames |
| all other patterns | 0 | — |

### Surface 2 — history paths (`git log --all --name-only | sort -u`)

Sensitive-filename pattern `(\.env|\.pem$|\.key$|\.p12$|id_rsa|id_ed|credentials|kubeconfig|\.kube)`: **22 hits**, all benign — 2 task docs with `credentials` in the filename (`tasks/sc-def-67-…credentials-never-expire…md`, `tasks/sc-def-69-…minio-credentials.md`) and 20 vendored minio-go SDK sources under `vendor/github.com/minio/minio-go/v7/pkg/credentials/`. No `.env`, `.pem`, `.key`, `.p12`, `id_rsa`, `id_ed`, `kubeconfig`, or `.kube` path exists in history.

Notable non-filename finding: three binary artifacts were accidentally committed and removed — `broker.test` and `dev/null` (added `c4c1f17e`, deleted `d992458d`, same day) and `central` (added `2df8cae9`, removed `bac1bb56`). Their `.internal` string matches are Go reflection type names (`.eq.internal/abi.ITab`, …) — no credentials.

### Surface 3 — content (history 1630 revs + worktree, excluding `vendor/`)

| pattern | files | rev-hits | classification |
|---------|-------|----------|----------------|
| `BEGIN.*PRIVATE KEY` | 19 | 19321 | detection-pattern strings in `classifier.go`/`recovery/evidence.go`, marker lists in `command/*_test.go`, `cli/result_test.go`, `helper/prepare_test.go`, truncated PEM stubs, doc quotes. No key material anywhere |
| `sk-ant-` | 20 | 909 | the `sk-ant-e2e-…` e2e placeholder, redaction/session tests, doc quotes |
| `sk-or-` | 2 | 8 | only the gitleaks plan/spec pattern lists (self-referential) |
| `xox[baprs]-` | 6 | 2426 | classifier detection patterns + `xoxb-2222…` dummy + docs + `.gitleaks.toml` description |
| `ghp_\|gho_\|github_pat_\|glpat-` | 9 | 4331 | canary/example token strings in docs/tests + classifier patterns; no real PAT |
| `AKIA\|ASIA` | 18 | 13011 | `AKIAFAKE`/`AKIAI0NOTAREALKEY`/`AKIAIOSFODNN7EXAMPLE` (canonical AWS example key) fixtures, regex definitions, prose |
| `AGE-SECRET-KEY` | 2 | 7 | gitleaks plan/spec pattern lists only |
| `untrusted comment:` | 2 | 7 | gitleaks plan/spec pattern lists only |
| `eyJ[A-Za-z0-9_-]{10,}` | 1 | 1343 | `attestation_test.go` JWT-shaped fixture (`eyJzdWJqZWN0IjpbXX0=` → `{"subject":[]}`) — test data, not a token |
| `apiVersion:.*kind: Config` | 2 | 8 | gitleaks plan/spec pattern lists only |
| `^Host ` | 3 | 3731 | "Host" sentence-start prose in 3 docs — not SSH config |
| `10.x/192.168/172.16-31` | 1 | 1229 | `10.0.0.5` non-loopback fixture in `middleware_test.go` |
| `\.(internal\|corp\|local)\b` | 150 | 101529 | `db.internal` classifier fixture; `central.local-result`, `central.local-dependency-lock`, `central.local-remediation`, `central.local.infra.{request,receipt}` artifact-name conventions; `com.central.local-infra.*` docker labels; `settings.local.json`; Go binary reflection strings; `...internal/artifact` prose. No real internal hostnames |
| `postgres://[^/]*:[^@]*@` | 31 | 23289 | local-dev/test fixture DSNs only — distinct userinfo across all history: `central_migration:central_migration`, `central_outbox:central_outbox`, `central_runtime:{central_runtime,password,secret}`, `central:s3cr3t` (classifier fixture), `postgres:{postgres,central-reference-host-superuser}`, `user:secret` (doc example), `%s:%s` (format string) |

Every surface-3 hit classifies as fixture / detection pattern / doc quote / naming convention. No hit resembles a real credential.

## vendor/ scope

`vendor/` is inside the scan scope for all three gitleaks runs (baseline, history-after-config, dir) and produced **zero findings**. It was excluded only from the manual `git grep` sweep (upstream code, not ours to triage line-by-line); its filenames are still covered by the surface-2 path sweep above.

## Allowlist rationale

`.gitleaks.toml` extends the default ruleset and adds 12 `[[rules.allowlists]]` entries nested under 5 id-only `[[rules]]` stubs (`generic-api-key`, `curl-auth-header`, `private-key`, `slack-bot-token`, `github-pat`). The id-stub form is required: global `[[allowlists]]` + `targetRules` under `[extend] useDefault` is silently ignored on gitleaks v8.28.x (upstream bug gitleaks#1919, smoke-tested in Task 1).

Each entry maps 1:1 to a finding group above, uses exactly one criterion (anchored `paths` regexes naming specific files — no `commits`, no stopwords, no dir-level patterns), and records the fixture's safety rationale in its `description`. Two entries use filename patterns instead of exact paths:

- `^\.superpowers/sdd/(gate-task-|task-|sb-g4-task-|b06-task-)[0-9A-Za-z]+-report\.md$` — SDD report files are created per task; enumerating paths could not cover the 22 findings' files plus future same-shaped notes.
- `^\.superpowers/sdd/review-[0-9A-Fa-f]+\.\.[0-9A-Fa-f]+\.diff$` — review diffs are generated per review round.

## Residual risks

1. **Filename-pattern allowlists auto-suppress future same-shaped files.** A real secret pasted into a *new* `.superpowers/sdd/{gate,task,sb-g4,b06}-*-report.md` or `review-*.diff` would be silently suppressed. Mitigation: these notes quote run output by convention; any new finding class still trips other rules, and drift is caught by re-running the baseline.
2. **`gitleaks git` auto-loads repo-root `.gitleaks.toml`.** Running the "baseline" command without `--config` post-Task-1 silently reports 0 findings (observed). Always pass an explicit default-only config for a true baseline.
3. **`dir` coverage is filesystem-state-only.** `.superpowers/brainstorm/` is untracked *and* gitignored; `dir` sees whatever is on disk today but nothing guarantees its coverage over time. Conversely, `.superpowers/sdd/` findings that live in deleted/churned notes are history-only — `dir` cannot exercise those allowlist entries; the `git` scan carries them.
4. **Suppression is rule+path-scoped, not content-scoped.** A future *real* secret committed to an allowlisted path (e.g. `classifier_test.go`) would be suppressed. Mitigation: entries are per-file, the sweep above is repeatable, and new findings require the same triage before allowlisting.
5. **Dedup-after-allowlist.** Suppressing a primary rule can surface a secondary `generic-api-key` finding on the same fragment (observed during triage in the SDD-report group and the two non-baseline finding shapes); future allowlist edits should re-scan to catch newly-visible secondary matches.
