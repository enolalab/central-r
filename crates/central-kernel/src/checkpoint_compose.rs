//! Slice-2C (issue #94) checkpoint composition — the kernel half of
//! upstream's checkpoint wiring: the supervised `central.checkpoint`
//! janitor component the scheduler capability registers when the gate
//! is on.
//!
//! The CLI half — compose the PostgreSQL checkpoint backend from
//! `CENTRAL_CHECKPOINT_DSN` with the filesystem workspace digester —
//! already lives in `bins/central/src/checkpoint_cli.rs` (upstream
//! `cmd/central/checkpoint_composition.go`, landed with the T8 slice)
//! and is intentionally not duplicated here.
//!
//! The janitor's `Collect` path never invokes the workspace digester —
//! GC deletes checkpoint rows and journals `checkpoint_gc_collected`;
//! digest-bound writes belong to the checkpoint-open path — so the
//! kernel composes the store without one, exactly like the upstream
//! composition that happens to pass a digester the pass never calls.

use std::sync::Arc;

use central_adapter_postgres::checkpoint::Store as PgCheckpointStore;
use central_checkpoint::janitor::Janitor;

use crate::lifecycle::Component;
use crate::scheduler_compose::TickedPassComponent;

/// `ckptapp.Janitor`'s supervised half (upstream
/// `&ckptapp.Janitor{Store: req.CheckpointGC}` as a kernel component):
/// one `collect` pass at component start — a serve boot must not wait
/// a whole interval before expired rows go — then one per
/// `tick_interval` (15 minutes by default). A failed pass leaves the
/// rows for the next tick; the component itself never exits on a
/// transient store error.
pub fn janitor_component(store: PgCheckpointStore) -> impl Component {
    let janitor = Arc::new(Janitor::new(store));
    let interval = janitor.tick_interval();
    TickedPassComponent::new(
        "checkpoint_janitor",
        std::time::Duration::new(
            interval.whole_seconds().max(0) as u64,
            interval.subsec_nanoseconds().max(0) as u32,
        ),
        move || {
            let janitor = janitor.clone();
            Box::pin(async move { janitor.collect_once().await })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// The janitor composes a supervised `Component` over the postgres
    /// checkpoint store (upstream `&ckptapp.Janitor{Store: req.CheckpointGC}`)
    /// — a lazy pool suffices because the pass only runs when the
    /// component does.
    #[tokio::test(flavor = "current_thread")]
    async fn janitor_component_composes() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/central")
            .expect("lazy pool");
        let mut component = janitor_component(PgCheckpointStore::new(pool));
        // `settle` is the shared no-op arm — callable without a DB.
        component.settle().await.expect("settle");
    }
}
