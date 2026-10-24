//! PostgreSQL store for the B06 session capability — the port of
//! upstream `internal/adapter/postgres/session`.
//!
//! [`PgSessionStore`] keeps every `sqlx` type inside the adapter and
//! implements `central_session::port::SessionStore` and
//! `central_session::port::PresentationStore`:
//!
//! - `discover_bootstrap_candidates` — the durable `delivery_pending`
//!   (plus orphaned `pending_bootstrap` and first-use-overdue
//!   `active`) recovery census;
//! - `exchange` — the atomic generation-consume + throttle +
//!   `pending_bootstrap` insert + replacement registration, all on
//!   PostgreSQL `clock_timestamp()`;
//! - `prepare_delivery` — `pending_bootstrap -> delivery_pending`
//!   gated on the exact consumed-generation candidate evidence;
//! - `activate_delivery` — the precommit `delivery_pending -> active`
//!   transition persisting only token/CSRF hashes;
//! - `validate` — the token-hash + epoch + expiry + first-use-fence +
//!   optional CSRF-hash read with `last_seen`/`first_used` updates;
//! - `revoke` — idempotent terminal transition;
//! - `begin_presentation`/`validate_presentation` — the durable
//!   3-minute bootstrap presentation lease on database time.
//!
//! All SQL lives in `store.rs` as audited constants (the
//! parameterized/database-clock/credential-column tests assert over
//! them, mirroring upstream `store_test.go`'s query inventory tests).
//! Every mutating statement and every throttle/expiry decision uses
//! `clock_timestamp()` — never the process clock.

mod store;

pub use store::PgSessionStore;
