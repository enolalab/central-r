# Security Policy

Central runs privileged components on the host: a root helper daemon, a
protected broker with a seccomp-hardened syscall surface, a sandbox
launcher, PAM/TTY physical-console ceremonies, and credential handoff
over `SCM_RIGHTS`. We take reports against these boundaries seriously.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a
security problem.**

Email **34208688+hieuntg81@users.noreply.github.com** with the subject line starting
`[central-workspace security]`. Include:

- the affected component (binary, crate, or verb) and commit/version;
- a description of the issue and its impact;
- reproduction steps or a proof of concept;
- whether the issue is already public or known to others.

You should receive an acknowledgement within **5 business days**. We
will keep you informed while we investigate, agree on a disclosure date
with you, and credit you in the advisory unless you prefer to stay
anonymous.

## Supported versions

Central is pre-1.0. Only the latest commit on `main` (and, once
releases exist, the latest tagged release) receives security fixes.

| Version | Supported |
| --- | --- |
| `main` / latest release | Yes |
| anything older | No |

## Scope

In scope:

- privilege escalation or authority bypass through the helper, broker,
  sandbox launcher, or launcher daemons;
- seccomp, namespace, `openat2` confinement, or peer-credential check
  bypasses;
- grant/PAM/TTY ceremony bypasses;
- credential or secret disclosure (PostgreSQL roles, MinIO credentials,
  TLS keys, export tokens);
- artifact content-policy bypasses or cross-workspace data access;
- authentication, session, or CSRF flaws in `central serve`.

Out of scope:

- attacks that require an already-root attacker on the host;
- denial of service against a local-only, loopback-bound service by a
  local user who can already stop it;
- vulnerabilities in third-party dependencies without a demonstrated
  impact on Central (report those upstream; `cargo deny` advisories are
  tracked in CI).

The threat model behind these boundaries is documented in
[`docs/security/threat-model.md`](docs/security/threat-model.md).
