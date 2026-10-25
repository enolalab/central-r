//! Run lineage view handler (issue #96, packet P2E03):
//! `GET /app/runs/lineage?run=<id>` renders the run's journaled
//! provenance — every produce edge traced to its producing node and
//! attempt, the per-node produce/read tables with undeclared reads
//! flagged (never hidden), the operator-read section, and prompt_ref
//! artifact links. Read-only; artifact bytes are never served from
//! here — artifact cells link by id to the existing scope-checked
//! preview/download routes.

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use central_artifact::domain::State as ArtifactState;
use central_artifact::lineage::{ProduceEdge, ReadEdge};
use central_foundation::identity::{
    ArtifactId, RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId,
};
use central_runview::domain::{AttemptRow, RunGraph};

use super::handler::{harness_banner, query_value};
use super::{
    WebState, active_session, format_timestamp, html_response, render_bootstrap, render_not_found,
};
use crate::error;
use crate::ports::RunLineageReader;

/// One artifact cell in the lineage tables. The artifact id always
/// renders (it is the artifact's public handle); a link to the
/// scope-checked preview route appears only when the artifact is
/// resolved, in the session workspace, and in the ready lifecycle
/// state. Every other case renders an explicit text state instead —
/// the lifecycle state verbatim for non-ready artifacts, "scope
/// denied" for foreign artifacts, "not recorded" for unresolved ids —
/// so a missing link is never ambiguous.
#[derive(Clone)]
struct LineageArtifactView {
    id: String,
    linkable: bool,
    /// Non-linkable reason or lifecycle state.
    state: String,
    /// Foreign workspace → explicit denial, no state detail.
    scope_denied: bool,
}

/// `lineageArtifact` — resolves one artifact id to its rendered cell:
/// a scope-checked link for an in-workspace ready artifact, an explicit
/// text state otherwise. A foreign workspace yields "scope denied" and
/// nothing else — the lifecycle state of another workspace's artifact
/// is not disclosed. An id that resolves to nothing renders "not
/// recorded". A read failure resolves to the same "not recorded" —
/// upstream resolves per-id and a failed resolution is the honest
/// unknown, not a page failure.
async fn lineage_artifact(
    reader: &Arc<dyn RunLineageReader>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
) -> LineageArtifactView {
    let mut view = LineageArtifactView {
        id: artifact_id.to_string(),
        linkable: false,
        state: "not recorded".to_string(),
        scope_denied: false,
    };
    if let Ok(Some(found)) = reader.find_artifact(artifact_id).await {
        if found.workspace_id != workspace_id {
            view.state = "scope denied".to_string();
            view.scope_denied = true;
            return view;
        }
        if found.state == ArtifactState::Ready {
            view.linkable = true;
            view.state = String::new();
            return view;
        }
        view.state = found.state.as_str().to_string();
    }
    view
}

/// One journaled produce edge rendered as "artifact A was produced by
/// node N attempt S".
struct LineageProduceRow {
    artifact: LineageArtifactView,
    node_key: String,
    attempt_seq: Option<i32>,
    attempt_id: String,
    when: String,
}

/// One journaled read edge. `undeclared` flags an attempt-scoped read
/// journaled outside the node's declared input set — the spec's
/// flag-never-hide classification. Operator reads (no reader node) are
/// attributed to the operator section instead and are not undeclared
/// violations: the synthetic operator reader has no declared set to
/// satisfy.
struct LineageReadRow {
    artifact: LineageArtifactView,
    attempt_seq: Option<i32>,
    attempt_id: String,
    undeclared: bool,
    checksum: String,
    when: String,
}

/// The per-node lineage table grouping the node badge, its produced
/// artifacts, its journaled reads, and its prompt_ref artifact link
/// when the spec recorded one.
struct LineageNodeSection {
    node_key: String,
    status: String,
    produced: Vec<LineageProduceRow>,
    reads: Vec<LineageReadRow>,
    prompt_ref: Option<LineageArtifactView>,
}

/// The `run_lineage` view model.
struct RunLineageViewModel {
    run_id: String,
    /// The provenance table: every artifact the run finalized (one
    /// journaled produce edge each) traced to its producing node and
    /// attempt.
    finals: Vec<LineageProduceRow>,
    /// The same edges grouped per producing/reading node, in graph
    /// order; every graph node renders a section even when it produced,
    /// read, and prompted nothing.
    nodes: Vec<LineageNodeSection>,
    /// The journaled reads attributed to no node — the synthetic
    /// operator reader of the lineage spec (OQ-5).
    operator_reads: Vec<LineageReadRow>,
    /// The number of attempt-scoped reads journaled outside their
    /// node's declared input set; the page flags them prominently
    /// rather than hiding them.
    undeclared_count: usize,
    empty: bool,
}

/// `lineageNodeKey` — a node id's key, or the id itself when the graph
/// projection does not name the node (a journaled edge to a node the
/// graph never materialized still renders, keyed by id). An empty key
/// falls back to the id like upstream's `ok && key != ""` check.
fn lineage_node_key(keys: &BTreeMap<WorkflowNodeId, String>, id: WorkflowNodeId) -> String {
    keys.get(&id)
        .filter(|k| !k.is_empty())
        .cloned()
        .unwrap_or_else(|| id.to_string())
}

/// `buildRunLineage` — assembles the view model from the journaled edge
/// sets and the runview projections. `resolve` maps each referenced
/// artifact id to its rendered cell; it is the only I/O-shaped input,
/// so the grouping and flagging logic itself stays pure.
async fn build_run_lineage(
    reader: &Arc<dyn RunLineageReader>,
    workspace_id: WorkspaceId,
    run_id: RunId,
    produced: &[ProduceEdge],
    reads: &[ReadEdge],
    graph: &RunGraph,
    attempts: &[AttemptRow],
) -> RunLineageViewModel {
    let mut vm = RunLineageViewModel {
        run_id: run_id.to_string(),
        finals: Vec::new(),
        nodes: Vec::new(),
        operator_reads: Vec::new(),
        undeclared_count: 0,
        empty: false,
    };

    let mut node_keys: BTreeMap<WorkflowNodeId, String> = BTreeMap::new();
    let mut node_status: BTreeMap<WorkflowNodeId, String> = BTreeMap::new();
    let mut node_order: Vec<WorkflowNodeId> = Vec::new();
    for node in &graph.nodes {
        node_keys.insert(node.id, node.key.clone());
        node_status.insert(node.id, node.status.clone());
        node_order.push(node.id);
    }
    let mut attempt_seqs: BTreeMap<SessionAttemptId, i32> = BTreeMap::new();
    let mut prompt_refs: BTreeMap<WorkflowNodeId, ArtifactId> = BTreeMap::new();
    let mut prompt_order: Vec<WorkflowNodeId> = Vec::new();
    for attempt in attempts {
        attempt_seqs.insert(attempt.id, attempt.seq);
        if let Some(prompt) = attempt.versions.prompt_ref_artifact_id
            && !prompt_refs.contains_key(&attempt.node_id)
        {
            prompt_refs.insert(attempt.node_id, prompt);
            prompt_order.push(attempt.node_id);
        }
    }

    let mut produced_by_node: BTreeMap<WorkflowNodeId, Vec<LineageProduceRow>> = BTreeMap::new();
    for edge in produced {
        let mut row = LineageProduceRow {
            artifact: lineage_artifact(reader, workspace_id, edge.artifact_id).await,
            node_key: lineage_node_key(&node_keys, edge.node_id),
            attempt_seq: None,
            attempt_id: edge.attempt_id.to_string(),
            when: format_timestamp(edge.created_at),
        };
        if let Some(&seq) = attempt_seqs.get(&edge.attempt_id) {
            row.attempt_seq = Some(seq);
        }
        produced_by_node
            .entry(edge.node_id)
            .or_default()
            .push(LineageProduceRow {
                artifact: row.artifact.clone(),
                node_key: row.node_key.clone(),
                attempt_seq: row.attempt_seq,
                attempt_id: row.attempt_id.clone(),
                when: row.when.clone(),
            });
        vm.finals.push(row);
    }

    let mut reads_by_node: BTreeMap<WorkflowNodeId, Vec<LineageReadRow>> = BTreeMap::new();
    for edge in reads {
        let mut row = LineageReadRow {
            artifact: lineage_artifact(reader, workspace_id, edge.artifact_id).await,
            attempt_seq: None,
            attempt_id: String::new(),
            undeclared: false,
            checksum: edge.checksum.clone(),
            when: format_timestamp(edge.created_at),
        };
        if let Some(attempt_id) = edge.attempt_id {
            row.attempt_id = attempt_id.to_string();
            if let Some(&seq) = attempt_seqs.get(&attempt_id) {
                row.attempt_seq = Some(seq);
            }
        }
        let Some(reader_node_id) = edge.reader_node_id else {
            vm.operator_reads.push(row);
            continue;
        };
        // Undeclared flags only attempt-scoped reads outside the node's
        // declared input set; the operator reader has no declared set,
        // so its edges are attributed above and never flagged.
        row.undeclared = !edge.declared;
        if row.undeclared {
            vm.undeclared_count += 1;
        }
        reads_by_node.entry(reader_node_id).or_default().push(row);
    }

    // Per-node sections in graph order, then any node that has lineage
    // but is absent from the graph projection (a node the run list
    // never materialized is still rendered, keyed by its id). Every
    // graph node renders a section — produced/read rows or a prompt_ref
    // are not prerequisites.
    let mut seen: BTreeMap<WorkflowNodeId, ()> = BTreeMap::new();
    let mut ordered: Vec<WorkflowNodeId> = node_order;
    for edge in produced {
        if !ordered.contains(&edge.node_id) {
            ordered.push(edge.node_id);
        }
    }
    for edge in reads {
        if let Some(reader_node_id) = edge.reader_node_id
            && !ordered.contains(&reader_node_id)
        {
            ordered.push(reader_node_id);
        }
    }
    for id in prompt_order {
        if !ordered.contains(&id) {
            ordered.push(id);
        }
    }
    for id in ordered {
        if seen.contains_key(&id) {
            continue;
        }
        seen.insert(id, ());
        vm.nodes.push(LineageNodeSection {
            node_key: lineage_node_key(&node_keys, id),
            status: node_status.get(&id).cloned().unwrap_or_default(),
            produced: produced_by_node.remove(&id).unwrap_or_default(),
            reads: reads_by_node.remove(&id).unwrap_or_default(),
            prompt_ref: match prompt_refs.get(&id) {
                Some(artifact_id) => {
                    Some(lineage_artifact(reader, workspace_id, *artifact_id).await)
                }
                None => None,
            },
        });
    }
    // Upstream `vm.Empty = len(vm.Finals) == 0 && len(reads) == 0`: a
    // run that journaled only a prompt_ref still reads as empty — the
    // notice reports provenance-table emptiness, not section count.
    vm.empty = vm.finals.is_empty() && reads.is_empty();
    vm
}

/// `ServeRunLineage` — `GET /app/runs/lineage?run=<id>`. `RunScope` is
/// the workspace scope check BEFORE any lineage data is read: an
/// absent or cross-workspace run is the same generic 404, so the route
/// never discloses that a foreign run id exists. The port is
/// nil-tolerant — a composition that omits it answers the same bare
/// 503 as a read failure.
pub(crate) async fn serve_run_lineage(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let Some(reader) = state.run_lineage.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let workspace_id = sess.workspace_id;
    let query = req.uri().query().map(str::to_string);
    let Some(run_id) = query
        .as_deref()
        .and_then(|q| query_value(q, "run"))
        .and_then(|v| RunId::parse(&v).ok())
    else {
        return render_not_found();
    };
    let scope = match reader.run_scope(run_id).await {
        Ok(s) => s,
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    if scope != Some(workspace_id) {
        return render_not_found();
    }
    let Ok(produced) = reader.produce_edges_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(reads) = reader.read_edges_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(graph) = reader.graph_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(attempts) = reader.attempts_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let vm = build_run_lineage(
        &reader,
        workspace_id,
        run_id,
        &produced,
        &reads,
        &graph,
        &attempts,
    )
    .await;
    let banner = harness_banner(&state, workspace_id).await;
    html_response(StatusCode::OK, &RunLineageTemplate { vm, banner }.render())
}

/// `runLineageViewModel` + banner — the lineage page.
#[derive(Template)]
#[template(path = "runs/lineage.html")]
struct RunLineageTemplate {
    vm: RunLineageViewModel,
    banner: super::harness::HarnessBannerView,
}

impl RunLineageTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Run lineage", "Unavailable"))
    }
}
