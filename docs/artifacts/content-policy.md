# Artifact Content Policy

## Authority and status

This is the canonical Gate 4 Artifact content-delivery policy for the Central project. It defines the trust boundary, detected classification, trusted sensitivity, safe display names, Central-mediated delivery authorization, disposition, preview allowlist, inspection and preview hard bounds, restricted content, secret-disclosure handling, observability, and validation for Phase 1 Artifact body delivery and preview.

These contracts were adopted by Accepted ADR 0005 and passed Gate 4 design-contract validation. This document makes no runtime implementation claim. Phase 0 validated it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning.

This policy is a companion contract to the [Artifact lifecycle contract](lifecycle.md) and consumes the same authority: ADR 0001 (durable Task domain and lifecycle), ADR 0003 (security policy and SecretReference model), and ADR 0004 (staged runtime and verified adapter handoffs). It is the implementation-neutral source for how Artifact bytes are classified, delivered, previewed, and bounded. Gate 5 owns API and Event field names, the delivery endpoint, response headers, and the preview renderer boundary; Gate 6 owns PostgreSQL representation; Gate 7 owns Go domain ports and streaming interfaces; Gate 8 owns bucket and MinIO topology. None of those gates may widen this allowlist, relax a hard bound, expose raw or presigned object URLs to the browser, render active content directly, or permit MIME sniffing without a later ADR.

This policy does not select concrete media-type parsers, sanitization libraries, HTTP header implementations, browser renderer internals, serialized API or Event fields, Go types, or storage APIs. Those are Gate 5 through Gate 8 work that must preserve these semantics.

## Trust boundary

Every Artifact body is untrusted data. This rule is unconditional: a producer that is itself a trusted system component does not make its emitted bytes trusted as browser-interpretable content.

Untrusted inputs that may not grant or relax any delivery, preview, sensitivity, or authorization decision include:

- the producer-declared media type;
- the producer-supplied filename or display name;
- Task text, prompt content, model output, tool output, and network response content;
- object-store metadata, user-supplied headers, and side-channel labels;
- prior classification of a parent or derived Artifact.

Declared media type and filename are hints only. They may inform display text and human-facing labels but never control rendering, disposition, preview eligibility, sensitivity, or authorization. Detected content classification derived from bounded verification is the only basis for delivery, preview, and disposition decisions. Where declared and detected types disagree, the detected classification governs and the contradiction is recorded as evidence.

## Detected classification

Classification is derived from bounded bytes and format structure observed during verification, not from producer declarations. Verification reads at most the configured bounded header and leading-body bytes, recomputes size and SHA-256 over the full body, and runs only allowlisted format parsers under bounded work and time budgets.

Detected classification records, at minimum:

- declared media type and producer-supplied name as hints;
- detected media family or type;
- preview eligibility;
- disposition;
- the verification pass, parser identity, and bounds snapshot under which classification was produced.

Classification outcomes:

- a recognized, internally consistent family produces that family's disposition and preview rule;
- unrecognized content is download-only;
- content whose declared type, detected structure, and bounded bytes contradict one another is download-only;
- content that fails a parser bound, times out, or aborts is download-only;
- content whose installed policy forbids storage is rejected at verification rather than finalized.

Detected classification is durable and immutable once an Artifact is ready. A later re-classification requires a new Artifact with explicit lineage; no ready body's classification is mutated in place. Classification evidence excludes body content, secret material, raw filenames, unsafe key fragments, and unbounded labels.

## Trusted sensitivity

Sensitivity is derived only from trusted producer context and policy. Trusted producer context is the trusted system component, Task, Run, Step, StepAttempt, or ToolCallAttempt identity, the Workspace scope, the producer's configured role, and the durable capability, Approval, secret-use, and egress evidence — never Task text, model output, tool output, filename, media type, or any other untrusted input.

Producer-controlled sensitivity downgrade is explicitly prohibited. Untrusted Task, tool, filename, or media-type input cannot lower sensitivity, cannot relax a restriction, cannot grant preview eligibility, and cannot remove a disposition. A producer may declare a hint; only trusted context and policy may set or change sensitivity, and only policy may raise it.

Uncertainty is restricted or download-only. When trusted context is absent, ambiguous, expired, revoked, or fails closed, the Artifact is treated as restricted: it is never inline-previewed, and delivery remains download-only with the full Central-mediated revalidation in force. A sensitivity decision never relaxes delivery authorization, Workspace ownership, ready-state, delete-intent, disposition, or preview-eligibility checks.

## Safe display names

The Artifact display name is a sanitized, human-facing label. Sanitization removes or escapes path separators, control characters, null bytes, executable extensions used as authority, scheme and locator fragments, and any sequence that could be interpreted as a path, URL, command, header, or authorization input.

The display name is never used as:

- a filesystem path or path component;
- an executable URL or request target;
- an authorization, capability, or scope input;
- an object key or key fragment;
- a media type, disposition, or preview-eligibility authority;
- a SQL, log, Event, metric, or error interpolation that bypasses source-boundary redaction.

Object keys contain only version markers and opaque application-generated IDs, as defined by the lifecycle contract. The display name is recorded as sanitized metadata only. Logs, Events, metrics, and errors record the sanitized name or, where safer, an opaque ID; they never record raw filenames.

## Central-mediated delivery authorization

Central mediates every body delivery. Raw bucket access is never exposed to the browser. Presigned object URLs are never exposed to the browser. Delivery is always a Central-streamed response whose authority, ownership, state, sensitivity, disposition, delete-intent, and preview-eligibility are revalidated at use time.

### Prohibition on raw and presigned browser URLs

The delivery boundary must not:

- expose a raw object-store URL, bucket name, or backend locator to the browser;
- issue a presigned object URL for browser fetch, inline preview, or download;
- delegate delivery to an unmediated redirect, cookie, or signed-token path that bypasses use-time revalidation;
- rely on object-store ACLs, bucket policies, or URL expiry as the delivery authority.

Presigned URL generation for browser use is prohibited regardless of expiry, scope, or perceived convenience. The cost of the Central streaming hop and per-request revalidation is intentional.

### Use-time revalidation

Immediately before any byte is streamed, the delivery boundary revalidates, in force at the moment of streaming:

- authenticated session authority for the requesting operator and session;
- Workspace ownership — the Artifact, request, and session belong to the same Workspace, and cross-Workspace delivery is a structured authorization denial;
- `ready` state — only a ready Artifact is downloadable; `reserved`, `staging`, `verifying`, `rejected`, `delete_pending`, and `deleted` are not downloadable;
- absence of delete intent — once delete intent is durable, no body is served, regardless of prior authority or cached consent;
- trusted sensitivity — derived from trusted producer context and policy at the moment of delivery, never from untrusted input, and never downgraded by producer hint;
- disposition — attachment by default unless preview is eligible and all preview conditions hold;
- preview eligibility — only allowlisted detected content, with all format-specific sanitization and bounds satisfied, and only when the Artifact is not restricted or sensitive.

Any check that fails, expires, is ambiguous, or cannot be proven fails closed. Uncertainty is deny for preview and download-only for body delivery; where even download-only delivery cannot be proven safe, the request is denied. A cached, prior, or stale authorization never satisfies use-time revalidation.

Revalidation is performed against durable PostgreSQL-derived state, not object-store listing or in-memory cache. The revalidation result, actor, authority, timestamp, and decision evidence are recorded as safe observations.

## Disposition

The default and baseline disposition is attachment. A body delivered with attachment disposition is downloaded, not rendered, regardless of detected media type.

Every delivery sets an explicit `Content-Type` reflecting the detected classification, not the producer-declared type, and sets `X-Content-Type-Options: nosniff`. MIME sniffing is prohibited: the delivery boundary, response headers, object-store metadata, and any intermediate must not sniff, infer, upgrade, or substitute a content type other than the explicit detected type. Producers, clients, intermediates, and browsers may not override `nosniff` or the explicit type.

Inline disposition is permitted only when all of the following hold:

- the detected content is on the preview allowlist;
- every format-specific sanitization and bound is satisfied;
- the Artifact is not restricted or sensitive;
- use-time revalidation permits preview.

When any condition fails, disposition falls back to attachment with explicit type and `nosniff`. There is no path from attachment to inline rendering through producer declaration, client hint, or filename.

## Preview allowlist

Only the following detected content may be considered for inline preview, and only after the conditions in each row hold:

| Detected content | Preview rule |
| --- | --- |
| Plain text, CSV, JSON | May preview only as bounded escaped text. JSON is never executed or rendered as HTML. CSV and text are never parsed as markup, script, or formula. |
| PNG, JPEG, GIF | May preview only after image parser verification and configured dimension, byte, and frame bounds. |

Everything not on this allowlist is download-only in Phase 1. This includes, without exception:

- HTML — never inline-rendered; never executed;
- SVG — never inline-rendered; never executed;
- PDF — never inline-rendered;
- office documents — never inline-rendered;
- archives — never inline-rendered;
- scripts — never executed;
- executables — never executed;
- unknown, binary, or contradictory content — never inline-rendered.

A restricted or sensitive Artifact is never inline-previewed regardless of detected media type. Preview eligibility is not transferable: a parent Artifact's preview eligibility does not confer eligibility on a derived Artifact, and a derived Artifact is classified independently.

Preview sanitization and renderer implementation are Gate 5 work, but Gate 5 must not widen this allowlist, render HTML or SVG inline, execute scripts, parse active markup, or add a new active format without a material review and a later ADR. The allowlist is deliberately narrow; convenience is not grounds for expansion.

## Inspection and preview hard bounds

Classification, parsing, sanitization, and preview operate under installed-policy hard bounds. A bound is a maximum; installed policy may choose lower values but never higher. Gate 4 owns these hard maxima; changing a hard maximum is a material contract change requiring ADR review.

The bounded dimensions are:

- input and header bytes read for classification;
- parser work and wall-clock time per Artifact;
- decoded body bytes retained for classification or preview;
- image pixels, dimensions, and frames;
- text bytes and text lines considered for escaped preview;
- structured nesting depth for JSON, CSV, and any future structured format;
- aggregate preview work and bytes per request, session, and Workspace.

A bound breach is never silently truncated. Outcomes are:

- the preview is denied and delivery falls back to download-only; or
- where installed policy forbids storage of the offending content, the Artifact is rejected at verification.

A limit breach never produces a partial preview, never relaxes sanitization, never widens a bound, and never causes active content to render. Breach evidence records the dimension, the configured maximum, the observed value, and the decision, and excludes body content, secret material, and raw filenames.

## Restricted content

An Artifact is restricted when trusted producer context and policy mark it so, when it carries material that may not be safely delivered inline, or when sensitivity, classification, authorization, or delete-intent state is uncertain.

Restricted-content rules:

- a restricted Artifact is download-only;
- a restricted Artifact is never inline-previewed, regardless of detected media type;
- delivery still requires the full Central-mediated use-time revalidation;
- restricted state is derived only from trusted context and policy; untrusted input cannot remove a restriction;
- uncertainty is restricted: when trusted context is absent, ambiguous, expired, revoked, or fails closed, the Artifact is treated as restricted until proven otherwise.

Restricted state is durable evidence. It records the trusted basis for the restriction and excludes body content, secret material, raw filenames, and unsafe key fragments. A restricted Artifact that becomes unrestricted requires a new Artifact with explicit lineage and a fresh trusted classification; no ready body's restriction is relaxed in place.

## Secret-disclosure handling

Central-managed and secret-aware paths never write plaintext secrets or credential-bearing requests or responses into Artifact bodies. This prohibition covers API keys, bearer tokens, session cookies, passwords, private keys, credential-bearing request and response bodies, and any material that the security policy classifies as secret under ADR 0003.

Suspected secret disclosure in a producer body blocks readiness and delivery. The contract does not continue merely after redaction: a body believed to contain secret material is not finalized, not promoted, not delivered, and not previewed.

On suspected disclosure, the policy:

- blocks verification, promotion, finalization, and delivery for the affected Artifact;
- preserves only sanitized structured evidence — opaque IDs, classification decision, detection reason, producer identity, Workspace, timestamps, and correlation and causation IDs;
- excludes plaintext secrets, credential-bearing request and response bodies, raw filenames, and unsafe key fragments from every Event, log, metric, error, and observation surface;
- emits the existing safe revoke and rotate guidance defined by the security policy and SecretReference model, so the operator can act through the established protected resolver and revocation flow rather than through Artifact content;
- records the disclosure suspicion and its safe remedy as durable evidence without persisting the disclosed material.

Secret-disclosure handling composes with ADR 0003: SecretReference remains an opaque Workspace-scoped logical identity, secret material remains outside PostgreSQL and S3 behind the protected resolver, and Artifact content policy adds no new secret-reveal capability, generic-process secret injection, name discovery, or fallback reference. Suspected disclosure is fail-closed; the burden of proof that a body is safe rests with verification and policy, not with delivery.

## Observability

Safe observations for content policy include Artifact, Workspace, Task, Run, producer, staging generation, content generation, declared and detected content class, preview decision, disposition, sensitivity decision, restriction basis, sanitization pass, parser identity, bound snapshot, bound-breach dimension and values, secret-disclosure suspicion and remedy, delivery authorization decision, revalidation actor, authority, and timestamp, and correlation and causation IDs.

Required observations include:

- declared and detected classification and the contradiction record when present;
- preview eligibility decision, sanitization pass, and bound snapshot;
- disposition decision and the explicit `Content-Type` and `nosniff` headers applied;
- sensitivity decision and its trusted basis;
- restricted state and its trusted basis;
- bound-breach dimension, configured maximum, observed value, and outcome;
- secret-disclosure suspicion, sanitized evidence, and the emitted revoke and rotate guidance;
- delivery authorization revalidation result, actor, authority, and timestamp;
- denial, download-only fallback, and rejection reasons.

Source-boundary redaction occurs before data enters any Event, log, metric, trace, or error. Evidence excludes body content, secret material, raw filenames, unsafe key fragments, presigned URLs, backend locators, and unbounded labels. Logs, Events, metrics, and errors repeat this prohibition: they record opaque IDs, size buckets, classification decisions, and safe status only.

## Validation scenarios

The following validation scenarios are owned by the Artifact content policy. They are validated in Phase 0 as contract walkthroughs and repository checks. Phase 1 implements them with fake object-store, clock, limits, content-classification, sanitization, and delivery adapters plus failure injection.

| Scenario | Rule |
| --- | --- |
| C01 | Declared media type and filename are hints only; detected classification governs disposition, preview, and sensitivity. |
| C02 | A declared type that contradicts detected structure is download-only and the contradiction is recorded. |
| C03 | Unrecognized, binary, or unknown content is download-only with explicit type and `nosniff`. |
| C04 | HTML, SVG, PDF, office documents, archives, scripts, executables, and unknown content are never inline-previewed and never execute. |
| C05 | Bounded escaped text, CSV, and JSON may preview only within configured byte, line, and nesting bounds; JSON is never rendered as HTML or executed. |
| C06 | PNG, JPEG, and GIF may preview only after image parser verification and configured dimension, byte, and frame bounds; a bound breach is download-only or rejected. |
| C07 | A restricted or sensitive Artifact is never inline-previewed regardless of detected media type. |
| C08 | Sensitivity is derived only from trusted producer context and policy; producer-controlled downgrade through Task text, tool output, filename, or media type is rejected. |
| C09 | Uncertain trusted context, sensitivity, classification, or authorization is restricted or download-only; uncertainty never grants preview. |
| C10 | Central mediates every delivery; raw bucket access and presigned object URLs are never exposed to the browser. |
| C11 | Use-time revalidation checks session authority, Workspace ownership, `ready` state, absence of delete intent, trusted sensitivity, disposition, and preview eligibility immediately before streaming; any failure or ambiguity is deny or download-only. |
| C12 | MIME sniffing is prohibited at the delivery boundary, in response headers, in object-store metadata, and in any intermediate; `nosniff` and the explicit detected type are always set. |
| C13 | The display name is sanitized and is never used as a path, executable URL, authorization input, object key, or unsanitized log interpolation. |
| C14 | A parser, byte, pixel, frame, text, nesting, work, or time bound breach is never silently truncated; it is download-only or rejected with structured evidence. |
| C15 | Suspected secret disclosure blocks readiness and delivery, preserves only sanitized structured evidence, and emits the existing safe revoke and rotate guidance. |
| C16 | Logs, Events, metrics, errors, and observations contain no body content, secret material, raw filenames, presigned URLs, backend locators, or unbounded labels. |
| C17 | Cross-Workspace delivery, post-delete delivery, and delivery of a non-ready Artifact are denied with structured authorization failure and no body bytes streamed. |
| C18 | The preview allowlist is not widened by Gate 5 representation, renderer, or convenience; adding a new active format requires material review and a later ADR. |
