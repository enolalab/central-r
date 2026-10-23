//! The Slice-2D retry application component — the port of
//! `central/internal/retry/app`: the [`sweeper::RetrySweeper`]
//! deadline monitor that periodically drives
//! [`crate::port::Store::sweep_timeouts`] so the session, node and
//! workflow deadline bounds (spec-4 decision 5) fire without a
//! dispatcher on the write path.
//!
//! The package depends only on the retry domain and its ports —
//! durable state lives behind [`crate::port::Store`].
//!
//! Upstream's `Run`/`Shutdown` loop body (the `time.Ticker` loop and
//! the done-channel wait) is a kernel `Component` concern — this
//! crate carries the pass itself ([`sweeper::RetrySweeper::sweep_once`])
//! plus the `tick_interval` cadence contract the supervisor ticks on
//! (the `central-scheduler` `app` precedent).
//!
//! TICK CONTRACT — upstream `Run` calls `sweepOnce` BEFORE creating
//! the ticker (sweeper.go:58): the supervisor runs one
//! [`sweeper::RetrySweeper::sweep_once`] pass at component start,
//! then again on every `tick_interval` tick. A supervisor that only
//! sleeps on `tick_interval` delays the first deadline pass by a full
//! interval.
//!
//! Passes never overlap by construction (one `&self` call), and
//! cancellation is future-drop: a pass abandoned mid-await is the
//! upstream `ctx.Done` case — no durable write beyond what already
//! committed, and the next pass re-verifies every candidate under the
//! run-row lock.
//!
//! OWNING PACKET: P2D03. SLICE: 2D (issue #95).

pub mod sweeper;
