# gitleaks triage — central-rust

- **Tool:** `gitleaks git` v8.30.1, full-history scan of
  `enolalab/central-workspace`, run 2026-10-30 on `main` @ `0906a75`.
- **Findings:** 7. All classified below. **No real secrets exist in
  history** — every finding is a secret-detection pattern or a test
  fixture.
- **Baseline:** `.gitleaks.toml` allowlists them path-scoped (no
  `commits` entries), so the ADR 0042 history rewrite does not require
  re-derivation. Re-scan gate in CI (Phase 3 of
  `docs/internal/tasks/open-source-readiness.md`).

## Findings

| # | Rule | File | Line | Classification |
| --- | --- | --- | --- | --- |
| 1 | `private-key` | `crates/adapters/central-adapter-linux/src/broker/xdg.rs` | 440 | Test fixture: a JSON blob containing a PEM *marker string* used to exercise the XDG projection path. Not a parseable key. |
| 2 | `private-key` | `docs/internal/superpowers/plans/2026-10-22-phase-r2-verified-artifact-lifecycle.md` | 189 | Doc quote: the plan lists the PEM header strings the content classifier detects. |
| 3 | `gitlab-pat` | `crates/capabilities/central-artifact/src/classifier.rs` | 507 | Detection-pattern constant: `glpat-abcdefghij0123456789` is the classifier's placeholder, not a valid token. |
| 4 | `slack-bot-token` | `crates/capabilities/central-artifact/src/classifier.rs` | 504 | Detection-pattern constant: `xoxb-123456789012-…-abcdefghijklmnop` placeholder. |
| 5–7 | `private-key` | `crates/capabilities/central-artifact/src/classifier.rs` | 218, 221, 483 | PEM marker constants and a `b3BlbnNzaA==` fixture body in the secret-detection test table. |

## Rule for future findings

Classify each finding as *fixture / placeholder / detection pattern /
doc quote* or *real*. Any real finding must be revoked and rotated
first, then the baseline updated with a `commits` entry — and per the
ADR 0042 amendment that `commits` entry must be re-derived after the
history rewrite.
