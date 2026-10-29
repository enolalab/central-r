# R5 Task 7 — broker custody: signing, TLS, secret bootstrap, handoff, XDG, export tokens

Status: in progress. Branch `r5-host-authority-broker-compose` from `725ea2f`.

## Goal

Port upstream `internal/adapter/authority/broker` custody machinery into
`crates/adapters/central-adapter-linux/src/broker/`:

| Module | Upstream source | Behavior |
|---|---|---|
| `signing.rs` (extend) | `signing.go` | keep existing HMAC `SigningService`/`Ed25519Signer`; add canonical-JSON Ed25519 sign + verify helpers used by XDG projections and BX1 tokens |
| `tls.rs` | `tls_authority.go`, `tls_persistent.go` | `TlsAuthority`: Ed25519 self-signed CA (CN `Central Local CA`, serial 1, ~365d, KeyCertSign), leaf signing (CN/SAN `127.0.0.1`, serial 2, ServerAuth, DigitalSignature, caller NotAfter), SHA-256-DER fingerprints, `tls-authority.json` durable state (0600, owner/nlink/regular checks, ≤64KiB, atomic publish, corruption refusal, load-time chain validation, atomic rekey) |
| `secret_bootstrap.rs` | `secret_bootstrap.go` | `SecretBootstrap`: durable leases/receipts/operations/proofs under the broker root, `bindings/<id>/` layout, idempotent adopt, one-use receipts, fencing-token discipline, 10-step descriptor-first materialize ladder, lifecycle-proof issue/verify, binding revoke/delete, restart recovery, redacted records |
| `bootstrap_session.rs` | `bootstrap_session.go` | `BootstrapSession` implementing `central_session::port::ProtectedBootstrap` (register/activate/reset), `bootstrap-candidate-state.json` atomic persistence, in-memory rollback on persist failure, strict `decode_candidate_binding`, `BootstrapPresenter`/`BootstrapActivator` socket clients |
| `handoff.rs` | `handoff.go`, `handoff_linux.go`, `secret_bootstrap_transport_linux.go` | sealed-memfd handoff via `sys::memfd`/`sys::scm_rights` (no new unsafe), `receive_descriptor`/`write_value_to_descriptor`/`send_descriptor`, B04/B05 ACK frames, `handle_b04_materialize_transport` descriptor-first state machine |
| `xdg.rs` | XDG projection sites | signed safe projections `central.projected-config/v1` + `central.projected-diagnostic/v1`, recipients `runtime`/`agent`/`operator`, Ed25519 over JCS-canonical view bytes, generation-bound, deny secret markers in views |
| `export_token.rs` | `internal/portable/bundle.go` | `Bx1Token` issue/verify (JCS, Ed25519, exact upstream verify ladder + error codes), HKDF-SHA256 bundle-key derivation, `export-identity.json` mint/load, `scan_protected_subset` trust-material guard |

## Server wiring (minimal, upstream-parity)

- `Service::new` constructs `TlsAuthority::new_persistent`, `SecretBootstrap::new`,
  `BootstrapSession::new_persistent` under the broker root.
- JSON dispatch arms: `sign_leaf`, `register_bootstrap_candidate`,
  `activate_bootstrap_candidate`, `present_bootstrap` (staged value; recovery
  fallback is R6 → `BOOTSTRAP_NOT_STAGED`), `adopt_b03_minio_bootstrap`,
  `issue_b04_lifecycle_proof`.
- `0xb4` framed transport → `handle_b04_materialize_transport`.
- B05/B10 frames keep upstream closed denials (launch-evidence and
  runtime-binding stores are R6); `materialize_postgres_migration` keeps
  "descriptor-only transport required".
- Nothing returns plaintext: B04 resolution happens only inside the descriptor
  transport, `ResolveCredential` runs strictly after descriptor validation.

## Deps

`rcgen = "=0.14.10"` (pem + x509-parser features), `x509-parser = "=0.18.0"` —
workspace-pinned; raw-Ed25519-pubkey → SPKI DER built manually for `signed_by`.

## Tests-first

Each module file ships `#[cfg(test)]` coverage written against the upstream
contract before/with implementation; skeleton run records RED, then bodies are
implemented and run GREEN.

## Verify

`cargo test -p central-adapter-linux`, `cargo fmt --check`, clippy `-D warnings`,
`cargo deny check` (if configured).

## Report

`task-r5-07-report.md` at repo root; commit message exactly
`feat(adapter-linux): add broker signing, TLS authority, secret bootstrap, and signed projections`.
