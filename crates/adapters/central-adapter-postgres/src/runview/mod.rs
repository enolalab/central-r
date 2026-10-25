//! `central-adapter-postgres/runview` — the read-projection store
//! backing the operator run/DAG, node, lineage and fleet surfaces
//! (upstream `internal/adapter/postgres/runview`).

pub mod store;

pub use store::Store;
