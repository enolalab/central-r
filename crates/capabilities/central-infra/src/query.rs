//! Read-side projections for `central-infra` — a documented stub.
//!
//! No projection ships yet. The A03 genesis domain introduced in this
//! task is read through [`crate::port::GenesisPort`] (an authority
//! boundary, not a query contract), and the read-side surfaces the
//! upstream app layer serves — advisory status (`central local
//! advisory status`), prepared-dependency status, and lifecycle
//! status (`central local status`) — land with their owning R5 tasks
//! (T10–T12), where each projection's fields will be defined beside
//! the query trait that returns it.
//!
//! When the first projection lands it follows the house pattern:
//! a `#[trait_variant::make(Send)]` trait with `Send + Sync + 'static`
//! returning read-only DTOs — never domain mutation types, and never
//! adapter shapes.
