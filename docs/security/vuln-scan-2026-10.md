# Vulnerability scan — October 2026 (issue #49)

`govulncheck v1.1.4`, run 2026-10-04 against `main` of both repositories.

## Result

| Repo | Toolchain before | Reachable vulns before | After `go 1.26.6` |
| --- | --- | --- | --- |
| `enolalab/central` | go1.26.5 | 7 (all stdlib) | **0** |
| `enolalab/central-local-infra` | go1.25.0 | 18 (all stdlib) | **0** |

## Reachable findings fixed by the toolchain bump

- central (go1.26.5 → fixed in go1.26.6): GO-2026-6218, GO-2026-6091, GO-2026-6090, GO-2026-6089, GO-2026-6088, GO-2026-5972, GO-2026-5026 — `crypto/tls`, `encoding/asn1`, `encoding/xml`, `html/template`, `net/http`, `net/url`.
- infra (go1.25.0 → fixed ≤ go1.26.6): GO-2026-4599, -4600, -4601, -4602, -4866, -4870, -4918, -4946, -4947, -4971, -5026, -5037, -5039, -5856, -5972, -6088, -6090, -6218 — `crypto/tls`, `crypto/x509`, `encoding/asn1`, `encoding/xml`, `net`, `net/http`, `net/textproto`, `net/url`, `os`.

## Residual (not code-reachable)

govulncheck additionally reports findings in imported packages / required modules that **our code does not call** — central: 1 imported-package + 4 module; infra: 1 imported-package + 18 module. These are dependency-tree facts, not reachable paths; they resolve as dependencies are updated in the normal course and are re-checked by the next scan. Re-run `govulncheck ./...` after any `go.mod`/`vendor` change.

## Caveats — read before trusting "0"

1. **Source-clean ≠ shipped-artifact-clean.** The infra container image still published under the pre-bump base (`golang:1.25.11`) until it is rebuilt and re-pinned under release signing (`dependency-lock.json`, `INFRA_IMAGE`, signed advisory admission). Queued for the release-workflow issue (#51); the base pin in `image/Dockerfile` and build scripts now points at `golang:1.26.6` so the next rebuild produces a fixed artifact.
2. govulncheck covers known Go vulnerabilities only — it is not a substitute for review of the threat-model register or for an independent security review.

## Recommendation carried forward

An independent security review of `docs/security/threat-model.md` and the authority/advisory code paths is **recommended before public beta**. This cannot be self-certified by the current solo maintainer (see `GOVERNANCE.md`).
