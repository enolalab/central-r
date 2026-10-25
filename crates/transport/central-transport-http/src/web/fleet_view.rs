//! Fleet view handler (issue #96, packet P2E05): `GET /app/runs/fleet`
//! renders registered workers, the live lease set, deferred admission
//! residue grouped under live runs, and the transactional-outbox health
//! card. Read-only — every hard projection failure is a bare 503, a nil
//! reader the same.

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use central_eventjournal::app::publisher as ejapp;
use central_foundation::identity::RunId;
use central_runview::domain::{DeferredRow, LeaseRow, OutboxHealth, RunSummary, WorkerRow};
use central_runview::query::{FLEET_DEFERRED_RUN_SCAN_LIMIT, fleet_run_live};
use central_scheduler::domain as scheduler;

use super::handler::harness_banner;
use super::{WebState, active_session, format_timestamp, html_response, render_bootstrap};
use crate::error;

/// One registered worker row: identity, declared capabilities and
/// concurrency ceiling, live lease count, the recorded
/// `worker_registrations.state`, and the observed ladder verdict
/// derived from the server-measured last-beat age. Recorded and
/// observed render side by side — a disagreement between them is
/// sweeper lag, itself observable.
struct FleetWorkerView {
    id: String,
    harness_kinds: String,
    workspace_kinds: String,
    max_concurrent: i32,
    live_leases: i64,
    /// "Ns" ago, or "never recorded" when no heartbeat exists.
    beat_age: String,
    beat_age_set: bool,
    missed_beats: u32,
    /// `worker_registrations.state` verbatim.
    recorded: String,
    /// Ladder verdict, "deregistered", or "" when no beat exists.
    observed: String,
    /// suspect/lost by either verdict — emphasized row.
    flagged: bool,
}

/// One live lease row: node/attempt coordinates, the holding worker,
/// lease id, issue and expiry marks, and the observed ladder verdict
/// over the heartbeat age.
struct FleetLeaseView {
    id: String,
    run_id: String,
    node_id: String,
    node_key: String,
    attempt_id: String,
    attempt_seq: i32,
    worker_id: String,
    issued_at: String,
    expires_at: String,
    heartbeat_age: i64,
    missed_beats: u32,
    /// Ladder verdict: active|suspect|lost.
    state: String,
    flagged: bool,
}

/// One journaled `admission_deferred` event rendered in the run's
/// claim-FIFO order.
struct FleetDeferredRow {
    seq: i64,
    node_id: String,
    node_key: String,
    /// `reason_code` verbatim, typically `CAPACITY_ADMISSION_DEFERRED`.
    reason: String,
    /// The node's `ready_at` mark, "" when absent.
    ready_at: String,
    recorded_at: String,
}

/// One live run's deferred admissions: the run header plus its
/// journaled deferral rows in claim-FIFO order.
struct FleetDeferredGroup {
    run_id: String,
    status: String,
    run_key: String,
    deferred: Vec<FleetDeferredRow>,
}

/// One flagged worker in the suspect/lost banner: the observed verdict,
/// the missed-beat evidence behind it, and how many live leases the
/// verdict endangers.
struct FleetSilentWorker {
    id: String,
    observed: String,
    recorded: String,
    missed_beats: u32,
    beat_age: i64,
    live_leases: i64,
}

/// The transactional-outbox health card: the same unpublished-depth and
/// oldest-anchor numbers the publisher's stall detector reads, the
/// thresholds it evaluates them against, and the stall verdict.
struct FleetOutboxView {
    depth: i64,
    has_oldest: bool,
    oldest: String,
    oldest_age_seconds: i64,
    depth_limit: u64,
    age_limit_seconds: i64,
    stalled: bool,
    /// Which leg of the publisher predicate fired.
    stall_reason: String,
}

/// The `runs_fleet` view model.
struct FleetViewModel {
    /// `CENTRAL_PHASE2_SCHEDULER` gate: off, no new workers/leases/
    /// deferrals are produced and the page renders a notice over
    /// whatever residual rows the tables still hold.
    scheduler_disabled: bool,
    /// The suspect/lost banner population plus the domain thresholds
    /// the banner names.
    silent: Vec<FleetSilentWorker>,
    suspect_beats: u32,
    lost_beats: u32,

    workers: Vec<FleetWorkerView>,
    leases: Vec<FleetLeaseView>,
    deferred: Vec<FleetDeferredGroup>,
    outbox: FleetOutboxView,
}

/// `buildFleetWorkers` — projects the worker registrations, computing
/// the observed ladder verdict per worker from the server-measured beat
/// age. A deregistered worker is rendered verbatim and never flagged;
/// a worker that never heartbeated has no beat age to ladder.
fn build_fleet_workers(
    workers: &[WorkerRow],
    leases: &[LeaseRow],
) -> (Vec<FleetWorkerView>, Vec<FleetSilentWorker>) {
    let mut lease_counts: BTreeMap<_, i64> = BTreeMap::new();
    for lease in leases {
        *lease_counts.entry(lease.worker_id).or_insert(0) += 1;
    }
    let mut rows = Vec::with_capacity(workers.len());
    let mut silent = Vec::new();
    for worker in workers {
        let mut row = FleetWorkerView {
            id: worker.id.to_string(),
            harness_kinds: worker.harness_kinds.join(", "),
            workspace_kinds: worker.workspace_kinds.join(", "),
            max_concurrent: worker.max_concurrent_attempts,
            live_leases: *lease_counts.get(&worker.id).unwrap_or(&0),
            beat_age: "never recorded".to_string(),
            beat_age_set: false,
            missed_beats: 0,
            recorded: worker.state.clone(),
            observed: String::new(),
            flagged: false,
        };
        if let Some(age) = worker.beat_age_seconds {
            row.beat_age_set = true;
            row.beat_age = format!("{age}s");
            row.missed_beats = (age / scheduler::HEARTBEAT_INTERVAL_SEC).max(0) as u32;
        }
        let deregistered = worker.deregistered_at.is_some()
            || worker.state == scheduler::WorkerState::Deregistered.as_str();
        if deregistered {
            row.observed = scheduler::WorkerState::Deregistered.as_str().to_string();
        } else if worker.beat_age_seconds.is_some() {
            row.observed = scheduler::ladder(row.missed_beats).as_str().to_string();
        }
        // No heartbeat was ever recorded: there is no missed-beat count
        // to ladder, so no observed verdict is fabricated.
        if !deregistered
            && (row.observed == scheduler::WorkerState::Suspect.as_str()
                || row.observed == scheduler::WorkerState::Lost.as_str()
                || worker.state == scheduler::WorkerState::Suspect.as_str()
                || worker.state == scheduler::WorkerState::Lost.as_str())
        {
            row.flagged = true;
            let mut entry = FleetSilentWorker {
                id: row.id.clone(),
                observed: row.observed.clone(),
                recorded: row.recorded.clone(),
                missed_beats: 0,
                beat_age: 0,
                live_leases: row.live_leases,
            };
            if entry.observed.is_empty() {
                // Flagged by the recorded state alone: the banner names
                // the verdict it has.
                entry.observed = row.recorded.clone();
            }
            if row.beat_age_set {
                entry.missed_beats = row.missed_beats;
                entry.beat_age = worker.beat_age_seconds.unwrap_or(0);
            }
            silent.push(entry);
        }
        rows.push(row);
    }
    (rows, silent)
}

/// `buildFleetLeases` — projects the live lease set, evaluating each
/// lease's heartbeat age against the scheduler's suspect/lost ladder.
fn build_fleet_leases(leases: &[LeaseRow]) -> Vec<FleetLeaseView> {
    leases
        .iter()
        .map(|lease| {
            let missed =
                (lease.heartbeat_age_seconds / scheduler::HEARTBEAT_INTERVAL_SEC).max(0) as u32;
            let state = scheduler::ladder(missed);
            FleetLeaseView {
                id: lease.id.to_string(),
                run_id: lease.run_id.to_string(),
                node_id: lease.node_id.to_string(),
                node_key: lease.node_key.clone(),
                attempt_id: lease.attempt_id.to_string(),
                attempt_seq: lease.attempt_seq,
                worker_id: lease.worker_id.to_string(),
                issued_at: format_timestamp(lease.issued_at),
                expires_at: format_timestamp(lease.expires_at),
                heartbeat_age: lease.heartbeat_age_seconds,
                missed_beats: missed,
                state: state.as_str().to_string(),
                flagged: state != scheduler::WorkerState::Active,
            }
        })
        .collect()
}

/// `buildFleetDeferred` — groups each live run's journaled deferral
/// rows under its run header.
fn build_fleet_deferred(
    runs: &[RunSummary],
    deferred_by_run: &BTreeMap<RunId, Vec<DeferredRow>>,
) -> Vec<FleetDeferredGroup> {
    let mut groups = Vec::new();
    for run in runs {
        let Some(rows) = deferred_by_run.get(&run.id) else {
            continue;
        };
        if rows.is_empty() {
            continue;
        }
        let mut group = FleetDeferredGroup {
            run_id: run.id.to_string(),
            status: run.status.clone(),
            run_key: run.run_key.clone().unwrap_or_default(),
            deferred: Vec::with_capacity(rows.len()),
        };
        for row in rows {
            group.deferred.push(FleetDeferredRow {
                seq: row.seq,
                node_id: row.node_id.to_string(),
                node_key: row.node_key.clone(),
                reason: row.reason_code.clone().unwrap_or_default(),
                ready_at: row.ready_at.map_or_else(String::new, format_timestamp),
                recorded_at: format_timestamp(row.recorded_at),
            });
        }
        groups.push(group);
    }
    groups
}

/// `buildFleetOutbox` — projects the outbox probe and evaluates the
/// `OUTBOX_PUBLISH_STALLED` predicate verbatim against the publisher's
/// own thresholds. `now` is the page's evaluation instant, injected so
/// the predicate stays pure — the fleet page is the one view that
/// evaluates a wall-clock threshold, and it takes that clock once per
/// request.
fn build_fleet_outbox(outbox: &OutboxHealth, now: time::OffsetDateTime) -> FleetOutboxView {
    let mut view = FleetOutboxView {
        depth: outbox.unpublished_depth,
        has_oldest: false,
        oldest: String::new(),
        oldest_age_seconds: 0,
        depth_limit: ejapp::DEFAULT_STALLED_DEPTH,
        age_limit_seconds: ejapp::DEFAULT_STALLED_AGE.whole_seconds(),
        stalled: false,
        stall_reason: String::new(),
    };
    if let Some(oldest) = outbox.oldest_unpublished {
        view.has_oldest = true;
        view.oldest = format_timestamp(oldest);
        // A future-stamped row counts as zero age, the same convention
        // `scheduler::missed_beats` applies.
        view.oldest_age_seconds = (now - oldest).whole_seconds().max(0);
    }
    let mut legs: Vec<String> = Vec::new();
    if outbox.unpublished_depth > ejapp::DEFAULT_STALLED_DEPTH as i64 {
        legs.push(format!(
            "unpublished depth {} exceeds {}",
            outbox.unpublished_depth,
            ejapp::DEFAULT_STALLED_DEPTH
        ));
    }
    if outbox.unpublished_depth > 0
        && let Some(oldest) = outbox.oldest_unpublished
        && now - oldest > ejapp::DEFAULT_STALLED_AGE
    {
        legs.push(format!(
            "oldest unpublished row is older than {}",
            ejapp::DEFAULT_STALLED_AGE
        ));
    }
    view.stalled = !legs.is_empty();
    view.stall_reason = legs.join("; ");
    view
}

/// `ServeFleet` — `GET /app/runs/fleet`. The page renders whenever the
/// schema exists; with the scheduler gate off it renders the residual
/// rows under a "scheduler disabled" notice rather than a 503.
pub(crate) async fn serve_fleet(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let Some(reader) = state.fleet.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let workspace_id = sess.workspace_id;
    let Ok(workers) = reader.workers(workspace_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(leases) = reader.live_leases(workspace_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(outbox) = reader.outbox_health().await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(runs) = reader
        .list_runs(workspace_id, None, FLEET_DEFERRED_RUN_SCAN_LIMIT)
        .await
    else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    // Deferred admissions are per-run journaled events: the page scans
    // the newest live runs and keeps the groups that journaled any.
    let mut live_runs: Vec<RunSummary> = Vec::new();
    let mut deferred_by_run: BTreeMap<RunId, Vec<DeferredRow>> = BTreeMap::new();
    for run in runs {
        if !fleet_run_live(&run.status) {
            continue;
        }
        let Ok(rows) = reader.deferred_admissions(run.id).await else {
            return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
        };
        if rows.is_empty() {
            continue;
        }
        deferred_by_run.insert(run.id, rows);
        live_runs.push(run);
    }
    let now = time::OffsetDateTime::now_utc();
    let (workers_v, silent) = build_fleet_workers(&workers, &leases);
    let vm = FleetViewModel {
        scheduler_disabled: !state.scheduler_enabled,
        silent,
        suspect_beats: scheduler::MISSED_BEATS_SUSPECT,
        lost_beats: scheduler::MISSED_BEATS_LOST,
        workers: workers_v,
        leases: build_fleet_leases(&leases),
        deferred: build_fleet_deferred(&live_runs, &deferred_by_run),
        outbox: build_fleet_outbox(&outbox, now),
    };
    let banner = harness_banner(&state, workspace_id).await;
    html_response(StatusCode::OK, &FleetTemplate { vm, banner }.render())
}

/// `fleetViewModel` + banner — the fleet page.
#[derive(Template)]
#[template(path = "runs/fleet.html")]
struct FleetTemplate {
    vm: FleetViewModel,
    banner: super::harness::HarnessBannerView,
}

impl FleetTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Fleet", "Unavailable"))
    }
}
