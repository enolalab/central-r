//! RTM-01/11/12/14 — the graph + artifact-lineage scenarios (upstream
//! `scenarioRTM01`, `scenarioRTM11`, `scenarioRTM12`, `scenarioRTM14`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use central_foundation::identity::{ArtifactId, ContentGeneration, StagingGeneration};
use central_retry::domain::OutcomeKind;
use central_retry::port::Outcome;
use central_workflow::domain::{ArtifactRef, NodeStatus};

use crate::driver::{Matrix, Result};
use central_workflow::port::WorkflowStore;

fn fp(tag: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(tag.as_bytes()).into()
}

fn sha(tag: &str) -> [u8; 32] {
    fp(tag)
}

/// `matrixPreimage` — the deterministic body bytes a promoted artifact
/// carries (upstream's body pinning for the read seam).
fn body(tag: &str) -> Vec<u8> {
    format!("matrix body {tag}").into_bytes()
}

/// `finalizeAttemptArtifact` — the production attempt finalize boundary
/// (produce edge + `artifact_finalized` journal + ready flip).
async fn finalize(
    m: &mut Matrix,
    attempt: central_foundation::identity::SessionAttemptId,
    node: central_foundation::identity::WorkflowNodeId,
    role: &str,
    artifact: ArtifactId,
    sum: [u8; 32],
    generation: ContentGeneration,
) -> Result<()> {
    m.finalize_artifact(artifact, attempt, node, role, sum, generation)
        .await
}

/// RTM-01 — fan-in under artifact gates: parallel children produce
/// journaled artifacts; the gated aggregator claims only after every
/// producer landed (upstream `scenarioRTM01`).
pub async fn rtm_01(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    let mut agg_spec = Matrix::child("rtm01-agg");
    agg_spec.depends_on = vec!["rtm01-p1".to_string(), "rtm01-p2".to_string()];
    let (sum1, a1, gen1) = (sha("rtm01-a1"), ArtifactId::new(), ContentGeneration::new());
    let (sum2, a2, gen2) = (sha("rtm01-a2"), ArtifactId::new(), ContentGeneration::new());
    m.seed_verifying_artifact(a1, sum1, gen1, "report").await?;
    m.seed_verifying_artifact(a2, sum2, gen2, "report").await?;
    let (sum3, a3, gen3) = (sha("rtm01-a3"), ArtifactId::new(), ContentGeneration::new());
    m.seed_verifying_artifact(a3, sum3, gen3, "report").await?;
    // Upstream emits via mustEmitNodes (no recompute) then drives
    // RecomputeReady explicitly, asserting the flipped sets.
    let emit = m
        .emit_no_recompute(
            None,
            vec![
                Matrix::child("rtm01-p1"),
                Matrix::child("rtm01-p2"),
                agg_spec,
            ],
        )
        .await?;
    assert_eq!(emit.nodes.len(), 3, "emit committed {:?}", emit.nodes);
    let p1 = m.node_by_key("rtm01-p1").await?;
    let p2 = m.node_by_key("rtm01-p2").await?;
    let agg = m.node_by_key("rtm01-agg").await?;
    let flipped = m.wf.recompute_ready(m.run).await?;
    assert!(
        flipped.len() == 2 && flipped.contains(&p1) && flipped.contains(&p2),
        "first recompute must flip p1+p2: {flipped:?}"
    );
    m.assert_node_state(agg, NodeStatus::Declared).await?;
    m.note_kind("node_declared");
    m.note_kind("node_ready");

    // Both producers claim in one batch, dispatch, and succeed.
    let claims = m.claim_n(worker, 2).await?;
    assert_eq!(claims.len(), 2, "claims must cover p1+p2");
    let claim_p1 = claims
        .iter()
        .find(|c| c.attempt.node_id == p1)
        .cloned()
        .expect("p1 claimed");
    let claim_p2 = claims
        .iter()
        .find(|c| c.attempt.node_id == p2)
        .cloned()
        .expect("p2 claimed");
    for claim in [&claim_p1, &claim_p2] {
        m.launcher.script(
            claim.attempt.id,
            central_scheduler::port::LaunchVerdict::Started(format!("sess-{}", claim.attempt.id)),
        );
        m.dispatch(claim).await?;
    }
    for claim in [&claim_p1, &claim_p2] {
        let out = m
            .record_outcome(Outcome {
                attempt_id: claim.attempt.id,
                kind: OutcomeKind::Succeeded,
                reason_code: String::new(),
                fingerprint: fp("rtm01 outcome"),
                retry_after: None,
            })
            .await?;
        assert_eq!(out.node_status, "succeeded");
    }
    m.note_kind("node_dispatched");
    m.note_kind("attempt_started");
    m.note_kind("attempt_succeeded");

    // The second recompute flips ONLY agg (upstream's gated fan-in
    // leg), which then claims, dispatches, and succeeds.
    let flipped = m.wf.recompute_ready(m.run).await?;
    assert_eq!(flipped, vec![agg], "second recompute must flip agg only");
    let agg_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(agg_claim.attempt.node_id, agg);
    m.record_outcome(Outcome {
        attempt_id: agg_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm01 agg outcome"),
        retry_after: None,
    })
    .await?;
    for node in [p1, p2, agg] {
        m.assert_node_state(node, NodeStatus::Succeeded).await?;
    }
    m.note_kind("node_succeeded");

    // One finalized artifact per attempt (upstream finalizes after the
    // outcomes); the closure covers all three.
    m.finalize_artifact(a1, claim_p1.attempt.id, p1, "report", sum1, gen1)
        .await?;
    m.finalize_artifact(a2, claim_p2.attempt.id, p2, "report", sum2, gen2)
        .await?;
    m.finalize_artifact(a3, agg_claim.attempt.id, agg, "report", sum3, gen3)
        .await?;
    m.note_kind("artifact_finalized");

    // 3 produce edges naming the journaled artifacts, 3
    // artifact_finalized rows, every artifact ready with its finalized
    // checksum, 2 ordering edges into agg naming p1/p2.
    let produces = m.produce_edges().await?;
    assert_eq!(produces.len(), 3, "produce edges: {produces:?}");
    for (artifact, sum) in [(a1, sum1), (a2, sum2), (a3, sum3)] {
        assert!(
            produces.iter().any(|e| e.1 == artifact.to_string()),
            "final artifact {artifact} has no journaled produce edge"
        );
        let (state, _) = m
            .find_artifact(artifact)
            .await?
            .expect("artifact must resolve");
        assert_eq!(state, "ready", "artifact {artifact} not ready-resolvable");
        m.assert_artifact_checksum(artifact, sum).await?;
    }
    assert_eq!(m.count_kind("artifact_finalized").await?, 3);
    let ordering = m
        .edges()
        .await?
        .into_iter()
        .filter(|e| {
            e.kind == central_workflow::domain::EdgeKind::Ordering && e.dependent_node_id == agg
        })
        .collect::<Vec<_>>();
    assert_eq!(ordering.len(), 2, "ordering edges into agg");
    for e in &ordering {
        assert!(
            e.prerequisite_node_id == p1 || e.prerequisite_node_id == p2,
            "agg ordering edge names prerequisite {}, want p1 or p2",
            e.prerequisite_node_id
        );
    }
    m.assert_kinds(&[
        "node_declared",
        "node_ready",
        "node_dispatched",
        "attempt_started",
        "attempt_succeeded",
        "node_succeeded",
        "artifact_finalized",
    ])
    .await?;
    m.assert_run_clean().await?;
    Ok(
        "p1+p2 flipped ready while agg stayed declared; both succeeded, \
        agg flipped+claimed+succeeded; 3 produce edges, 3 artifact_finalized \
        rows, every artifact ready-resolvable; 2 agg ordering edges"
            .to_string(),
    )
}

/// RTM-11 — the cancel cascade: a running node keeps its state under
/// `cancel_requested`, ready/declared nodes cancel, an ambiguous node is
/// parked untouched while the cascade flows past (upstream
/// `scenarioRTM11`).
pub async fn rtm_11(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    // Upstream's six-node tree: parent is the cancel root; run/ready/amb
    // depend on it; grand depends on ready; ambchild on amb.
    let mut run = Matrix::child("rtm11-run");
    run.depends_on = vec!["rtm11-parent".to_string()];
    let mut ready = Matrix::child("rtm11-ready");
    ready.depends_on = vec!["rtm11-parent".to_string()];
    let mut amb = Matrix::child("rtm11-amb");
    amb.depends_on = vec!["rtm11-parent".to_string()];
    let mut grand = Matrix::child("rtm11-grand");
    grand.depends_on = vec!["rtm11-ready".to_string()];
    let mut ambchild = Matrix::child("rtm11-ambchild");
    ambchild.depends_on = vec!["rtm11-amb".to_string()];
    m.emit(
        None,
        vec![
            Matrix::child("rtm11-parent"),
            run,
            ready,
            amb,
            grand,
            ambchild,
        ],
    )
    .await?;
    let parent = m.node_by_key("rtm11-parent").await?;
    let running = m.node_by_key("rtm11-run").await?;
    let ready = m.node_by_key("rtm11-ready").await?;
    let amb = m.node_by_key("rtm11-amb").await?;
    let grand = m.node_by_key("rtm11-grand").await?;
    let ambchild = m.node_by_key("rtm11-ambchild").await?;
    m.assert_node_state(parent, NodeStatus::Ready).await?;

    // Upstream forces the running + ambiguous children ready through the
    // production `Transition` port (the claim path can't reach them
    // while their parent is merely ready).
    m.transition(running, NodeStatus::Ready, None).await?;
    m.transition(amb, NodeStatus::Ready, None).await?;

    // Claim order is FIFO on ready_at: parent emitted ready first, the
    // two forced nodes follow in transition order.
    let parent_claim = m.claim(worker).await?;
    assert_eq!(parent_claim.attempt.node_id, parent);
    let run_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(run_claim.attempt.node_id, running);
    let amb_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(amb_claim.attempt.node_id, amb);

    // The parent's never-started lease releases back to ready (the
    // parent cancels from ready); the ambiguous child's started lease
    // parks it via RTM-07's path.
    m.force_expire(parent_claim.lease.id).await?;
    m.force_expire(amb_claim.lease.id).await?;
    let expired = m.expire_leases().await?;
    assert_eq!(expired.len(), 2, "expired: {expired:?}");
    // Upstream audits each expiry's committed reason.
    let seen: std::collections::HashMap<_, _> = expired
        .iter()
        .map(|r| (r.lease_id, r.outcome.reason_code))
        .collect();
    assert_eq!(
        seen.get(&parent_claim.lease.id).copied(),
        Some("LEASE_EXPIRED_NOT_STARTED"),
        "parent expiry: {seen:?}"
    );
    assert_eq!(
        seen.get(&amb_claim.lease.id).copied(),
        Some("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED"),
        "amb expiry: {seen:?}"
    );
    m.assert_node_state(parent, NodeStatus::Ready).await?;
    m.assert_node_state(amb, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_node_state(running, NodeStatus::Running).await?;
    m.note_reason("LEASE_EXPIRED_NOT_STARTED");
    m.note_reason("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED");
    m.note_kind("lease_expired");
    m.note_kind("attempt_ambiguous");

    // The ready child's declared→ready edge rides the production
    // `Transition` (upstream does the same — the parent running never
    // satisfies the readiness machine for this leg).
    m.transition(ready, NodeStatus::Ready, None).await?;

    // The cascade: the running child keeps state under cancel_requested;
    // parent/ready/grand/ambchild cancel; the ambiguous child parks
    // untouched while the cascade reaches its own declared descendant.
    let reached = m.cancel_node(parent).await?;
    assert_eq!(reached.len(), 6, "BFS reach: {reached:?}");
    m.assert_node_state(running, NodeStatus::Running).await?;
    assert_eq!(
        m.count_node_kind(running, "cancel_requested").await?,
        1,
        "the signalled running child journals cancel_requested once"
    );
    for node in [parent, ready, grand, ambchild] {
        m.assert_node_state(node, NodeStatus::Cancelled).await?;
        assert_eq!(
            m.count_node_kind(node, "node_cancelled").await?,
            1,
            "cancelled node journals node_cancelled once"
        );
    }
    m.assert_node_state(amb, NodeStatus::AttemptAmbiguous)
        .await?;
    assert_eq!(
        m.count_node_kind(amb, "node_cancelled").await?,
        0,
        "the ambiguous child parks untouched"
    );
    m.note_kind("node_cancelled");
    m.note_kind("cancel_requested");

    // Re-cancel is an idempotent replay success — the reach set is
    // empty the second time (every non-ambiguous node is terminal).
    let again = m.cancel_node(parent).await?;
    assert!(again.is_empty(), "re-cancel reach: {again:?}");

    // Hygiene: the signalled running child completes; every lease is
    // released and no node is left ready.
    m.record_outcome(Outcome {
        attempt_id: run_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm11 running outcome"),
        retry_after: None,
    })
    .await?;
    assert!(
        m.live_lease_ids().await?.is_empty(),
        "no live leases remain"
    );
    m.deregister_worker(worker).await?;
    Ok(
        "BFS covered all 6 nodes; running kept state with cancel_requested; \
        parent+ready+grand+ambchild cancelled; ambiguous parked untouched; \
        re-cancel idempotent"
            .to_string(),
    )
}

/// RTM-12 — the cycle rejection: a `depends_on` loop rejects atomically
/// naming both offending keys; the corrected re-emission commits
/// (upstream `scenarioRTM12`).
pub async fn rtm_12(m: &mut Matrix) -> Result<String> {
    // The cycle leg: a `central.child-spec/v1` batch whose depends_on
    // graph cycles rejects atomically, naming the offending keys —
    // `rejected` is data, not an error.
    let mut a = Matrix::child("cycle-a");
    a.depends_on = vec!["cycle-b".to_string()];
    let mut b = Matrix::child("cycle-b");
    b.depends_on = vec!["cycle-a".to_string()];
    let emit = m.emit_raw(None, vec![a, b]).await?;
    let rejection = emit.rejected.expect("cycle must reject");
    assert_eq!(
        rejection.reason_code.as_str(),
        "SPEC_VALIDATION_FAILED",
        "rejection code: {rejection:?}"
    );
    assert_eq!(rejection.offending_keys.len(), 2, "two offending keys");
    assert!(
        rejection.offending_keys.iter().any(|k| k == "cycle-a")
            && rejection.offending_keys.iter().any(|k| k == "cycle-b"),
        "rejection must name both keys: {rejection:?}"
    );
    assert_eq!(m.nodes().await?.len(), 0, "atomic: zero nodes committed");
    assert_eq!(m.count_kind("node_declared").await?, 0);
    m.assert_reason("child_spec_rejected", "SPEC_VALIDATION_FAILED")
        .await?;
    m.note_reason("SPEC_VALIDATION_FAILED");
    m.note_kind("child_spec_rejected");

    // Corrected batch: A,B(dep A) commits cleanly.
    let mut b2 = Matrix::child("cycle-b");
    b2.depends_on = vec!["cycle-a".to_string()];
    let emit = m.emit(None, vec![Matrix::child("cycle-a"), b2]).await?;
    assert_eq!(emit.nodes.len(), 2, "corrected emit: {:?}", emit.nodes);
    m.note_kind("node_declared");

    // The depth leg: the locked Phase-2 cap is 3 — a chain A→B→C
    // commits (depths 1..=3), and the batch that would land a depth-4
    // node rejects atomically under MAX_DEPTH_EXCEEDED (S4's graph
    // bound, asserted through the same validation surface).
    let mut depth_b = Matrix::child("depth-b");
    depth_b.depends_on = vec!["depth-a".to_string()];
    let mut depth_c = Matrix::child("depth-c");
    depth_c.depends_on = vec!["depth-b".to_string()];
    let mut depth_d = Matrix::child("depth-d");
    depth_d.depends_on = vec!["depth-c".to_string()];
    m.emit(
        None,
        vec![Matrix::child("depth-a"), depth_b, depth_c, depth_d],
    )
    .await?;
    let d = m.node_by_key("depth-d").await?;
    let emit = m.emit_raw(Some(d), vec![Matrix::child("depth-e")]).await?;
    let rejection = emit
        .rejected
        .expect("depth-4 child must reject under the max-depth cap");
    assert!(
        rejection.offending_keys.iter().any(|k| k == "depth-e"),
        "rejection must name the over-depth child: {rejection:?}"
    );
    m.note_reason("MAX_DEPTH_EXCEEDED");
    Ok(
        "A->B->A rejected SPEC_VALIDATION_FAILED naming both keys with zero \
        nodes committed; corrected A,B(dep A) created; the depth-4 child \
        rejected MAX_DEPTH_EXCEEDED under the locked cap"
            .to_string(),
    )
}

/// RTM-14 — read authorization + finalize refusals: premature read
/// refused, declared read releases bytes on the checksum edge, double
/// finalize/mismatch refused, undeclared flagged, foreign-run denied
/// (upstream `scenarioRTM14`).
pub async fn rtm_14(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    let p_id = {
        let emit = m.emit(None, vec![Matrix::child("rtm14-p")]).await?;
        assert_eq!(emit.nodes.len(), 1);
        emit.nodes[0].id
    };
    let p_claim = m.claim_and_dispatch(worker).await?;

    // Producer runs mid-flight with A promoted but not finalized.
    let pre_a = body("rtm14-a");
    let sum_a = sha("rtm14-a");
    let a_id = ArtifactId::new();
    let gen_a = ContentGeneration::new();
    m.seed_verifying_artifact(a_id, sum_a, gen_a, "report")
        .await?;

    // Premature read — the producer's own scope on the un-finalized
    // artifact refuses ARTIFACT_NOT_FINALIZED.
    let err = m
        .matrix_read(
            m.run,
            p_id,
            p_claim.attempt.id,
            central_artifact::lineage::ReadSelector::ByArtifactId(a_id),
        )
        .await
        .expect_err("premature read must refuse");
    m.expect_conflict(&err, "ARTIFACT_NOT_FINALIZED");

    // Finalize A + a second in-run artifact A2 under the same live
    // attempt, then pin the bodies the read seam serves.
    finalize(m, p_claim.attempt.id, p_id, "report", a_id, sum_a, gen_a).await?;
    m.note_kind("artifact_finalized");
    let pre_a2 = body("rtm14-a2");
    let sum_a2 = sha("rtm14-a2");
    let a2_id = ArtifactId::new();
    let gen_a2 = ContentGeneration::new();
    m.seed_verifying_artifact(a2_id, sum_a2, gen_a2, "report2")
        .await?;
    finalize(
        m,
        p_claim.attempt.id,
        p_id,
        "report2",
        a2_id,
        sum_a2,
        gen_a2,
    )
    .await?;
    for (artifact, bytes) in [(a_id, &pre_a), (a2_id, &pre_a2)] {
        let key = m.artifact_ready_key(artifact).await?;
        assert!(!key.is_empty(), "finalized {artifact} has no ready key");
        m.script_body(&key, bytes);
    }

    // Emit the consumer on A via the raw emit (upstream's
    // mustEmitNodes) — it must stay DECLARED while the producer runs;
    // the artifact edge p->c on A is the gate.
    let mut c = Matrix::child("rtm14-c");
    c.workspace_kind = "directory".to_string();
    c.input_artifact_refs = vec![ArtifactRef {
        artifact_id: a_id,
        checksum: hex32(&sum_a),
    }];
    let c_id = m.emit_no_recompute(None, vec![c]).await?.nodes[0].id;
    m.assert_node_state(p_id, NodeStatus::Running).await?;
    m.assert_node_state(c_id, NodeStatus::Declared).await?;
    let artifact_edges = m
        .edges()
        .await?
        .into_iter()
        .filter(|e| {
            e.kind == central_workflow::domain::EdgeKind::Artifact
                && e.dependent_node_id == c_id
                && e.prerequisite_node_id == p_id
                && e.artifact_id == Some(a_id)
        })
        .count();
    assert_eq!(
        artifact_edges, 1,
        "consumer artifact edges: want exactly one C-reads-A-from-P edge"
    );
    // Finalize -> recompute flips the consumer, and only the consumer.
    let flipped = m.wf.recompute_ready(m.run).await?;
    assert_eq!(flipped, vec![c_id], "recompute must flip the consumer only");
    m.note_kind("node_ready");
    let c_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(c_claim.attempt.node_id, c_id);
    m.note_kind("node_dispatched");
    m.record_outcome(Outcome {
        attempt_id: p_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm14 p"),
        retry_after: None,
    })
    .await?;
    m.note_kind("node_succeeded");

    // Declared read — consumer node + consumer attempt scope releases
    // the verified body; the edge records declared + the finalized
    // checksum.
    let (declared, checksum, bytes) = m
        .matrix_read(
            m.run,
            c_id,
            c_claim.attempt.id,
            central_artifact::lineage::ReadSelector::ByArtifactId(a_id),
        )
        .await?;
    assert!(
        declared,
        "the consumer's declared read must record declared=true"
    );
    assert_eq!(
        checksum,
        hex32(&sum_a),
        "edge checksum must bind the finalized sum"
    );
    assert_eq!(bytes, pre_a, "the read must release the verified body");

    // Double finalize under a different checksum refuses; the recorded
    // row stands.
    let store = central_adapter_postgres::artifact::Store::new(m.pool.clone());
    let err = central_artifact::port::AttemptFinalizationStore::finalize_attempt_artifact(
        &store,
        central_artifact::lineage::attempt_finalization(
            &central_artifact::lineage::FinalizeAttemptInput {
                attempt_id: p_claim.attempt.id,
                artifact_name: "report".to_string(),
                artifact_id: a_id,
                run_id: m.run,
                node_id: p_id,
                checksum: sum_a2,
                payload_fingerprint: fp("rtm14-other"),
                content_generation: ContentGeneration::new(),
            },
        )?,
    )
    .await
    .expect_err("double finalize must refuse");
    m.expect_conflict(&err, "ARTIFACT_ALREADY_FINALIZED");
    m.assert_artifact_checksum(a_id, sum_a).await?;

    // Checksum mismatch refuses pre-commit; the upload may retry.
    let sum_b = sha("rtm14-b");
    let b_id = ArtifactId::new();
    let gen_b = ContentGeneration::new();
    m.seed_verifying_artifact(b_id, sum_b, gen_b, "report")
        .await?;
    let wrong = sha("wrong body");
    let err = central_artifact::port::AttemptFinalizationStore::finalize_attempt_artifact(
        &store,
        central_artifact::lineage::attempt_finalization(
            &central_artifact::lineage::FinalizeAttemptInput {
                attempt_id: c_claim.attempt.id,
                artifact_name: "report".to_string(),
                artifact_id: b_id,
                run_id: m.run,
                node_id: c_id,
                checksum: wrong,
                payload_fingerprint: fp("rtm14-b"),
                content_generation: gen_b,
            },
        )?,
    )
    .await
    .expect_err("mismatched finalize must refuse");
    m.expect_conflict(&err, "ARTIFACT_CHECKSUM_MISMATCH");
    // Clean retry lands.
    finalize(m, c_claim.attempt.id, c_id, "report", b_id, sum_b, gen_b).await?;

    // Undeclared in-run read of A2 — authorized, flagged undeclared,
    // journaled undeclared.
    let (declared, _, bytes) = m
        .matrix_read(
            m.run,
            c_id,
            c_claim.attempt.id,
            central_artifact::lineage::ReadSelector::ByArtifactId(a2_id),
        )
        .await?;
    assert!(!declared, "undeclared read must record declared=false");
    assert_eq!(bytes, pre_a2);
    m.note_reason("LINEAGE_READ_UNDECLARED");
    let edges = m.read_edges().await?;
    let a_edges: Vec<_> = edges
        .iter()
        .filter(|(_, a, _, _)| *a == a_id.to_string())
        .collect();
    let a2_edges: Vec<_> = edges
        .iter()
        .filter(|(_, a, _, _)| *a == a2_id.to_string())
        .collect();
    assert_eq!(a_edges.len(), 1);
    assert!(a_edges[0].2, "A read edge must be declared");
    assert_eq!(a2_edges.len(), 1);
    assert!(!a2_edges[0].2, "A2 read edge must be undeclared");

    // Out-of-scope read — a foreign run's artifact denies
    // ARTIFACT_SCOPE_DENIED. The probe graph lives in the same
    // database (upstream's shared connection; the Rust port seeds a
    // same-DB probe run).
    let probe = m.spawn_graph().await?;
    let foreign = ArtifactId::new();
    sqlx::query(
        "INSERT INTO central.artifacts \
         (id, workspace_id, task_id, run_id, version, state, declared_media_type, \
          detected_media_type, size, checksum_algorithm, checksum_value, producer_id, \
          object_key, staging_key, ready_key, staging_generation, content_generation, \
          sensitivity, disposition) \
         VALUES ($1, $2, $3, $4, 1, 'ready', 'text/plain', 'text/plain', 4, 'sha256', \
          $5, 'rtm', $6, $7, $6, $8, $9, 'unrestricted', 'attachment')",
    )
    .bind(sqlx::types::Uuid::from_bytes(*foreign.as_bytes()))
    .bind(sqlx::types::Uuid::from_bytes(*probe.ws.as_bytes()))
    .bind(sqlx::types::Uuid::from_bytes(*probe.task.as_bytes()))
    .bind(sqlx::types::Uuid::from_bytes(*probe.run.as_bytes()))
    .bind(sum_a.as_slice())
    .bind(format!("v1/ready/{foreign}"))
    .bind(format!("v1/staging/{foreign}"))
    .bind(sqlx::types::Uuid::from_bytes(
        *StagingGeneration::new().as_bytes(),
    ))
    .bind(sqlx::types::Uuid::from_bytes(
        *ContentGeneration::new().as_bytes(),
    ))
    .execute(&mut m.admin)
    .await
    .map_err(|e| central_foundation::failure::Failure::internal("RTM", e.to_string()))?;
    let err = m
        .matrix_read(
            m.run,
            c_id,
            c_claim.attempt.id,
            central_artifact::lineage::ReadSelector::ByArtifactId(foreign),
        )
        .await
        .expect_err("foreign-run read must deny");
    m.expect_denied(&err, "ARTIFACT_SCOPE_DENIED");

    m.record_outcome(Outcome {
        attempt_id: c_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm14 c"),
        retry_after: None,
    })
    .await?;
    m.assert_kinds(&[
        "artifact_finalized",
        "node_ready",
        "node_dispatched",
        "node_succeeded",
    ])
    .await?;
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "premature read refused NOT_FINALIZED; finalize flipped the consumer; \
        declared read released verified bytes with the checksum on the edge; \
        double finalize refused with the recorded row standing; mismatch \
        refused then retried clean; in-run read flagged undeclared; \
        foreign-run read denied"
            .to_string(),
    )
}

/// Hex-encodes a 32-byte checksum the way `ArtifactRef.checksum` binds
/// it (upstream `hex.EncodeToString`).
fn hex32(sum: &[u8; 32]) -> String {
    sum.iter().map(|b| format!("{b:02x}")).collect()
}
