//! `central-runview` — Phase 2E read-only DAG projections, run lineage
//! views, fleet probes; consumes `central-eventjournal` fold types
//! (approved DAG edge).
//!
//! Three layers land here: `domain` (pure read models), `port` (the
//! [`port::Reader`] seam every projection store implements), and
//! `query` (the cursor codec + paging bounds the views share). The
//! capability owns no `app` layer — it is a read projection, not a
//! command service: mutations belong to the workflow/checkpoint stores
//! the run controls invoke.

pub mod domain;
pub mod port;
pub mod query;
