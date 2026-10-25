//! RTM-09/10/18 — the checkpoint/resume + event-journal scenarios
//! (upstream `scenarioRTM09`, `scenarioRTM10`, `scenarioRTM18`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::BTreeSet;

use central_checkpoint::port::ResumeStore;
use central_eventjournal::port::Writer;
use central_foundation::identity::{ArtifactId, ContentGeneration, RunEventId};
use central_retry::domain::OutcomeKind;
use central_retry::port::Outcome;
use central_workflow::domain::ArtifactRef;
use central_workflow::domain::NodeStatus;

use crate::driver::{Matrix, Result};

fn fp(tag: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(tag.as_bytes()).into()
}

/// Hex-encodes a 32-byte checksum the way `ArtifactRef.checksum` binds
/// it (upstream `hex.EncodeToString`).
fn hex32(sum: &[u8; 32]) -> String {
    sum.iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs the checkpoint write on `node` and returns the durable record
/// (upstream `mustWriteCheckpoint` / `WriteCheckpoint`).
async fn write(
    m: &mut Matrix,
    node: central_foundation::identity::WorkflowNodeId,
    seq: i64,
) -> Result<central_checkpoint::domain::ResumeCheckpoint> {
    let cp =
        m.ck.write_checkpoint(
            m.run,
            node,
            "operator:rtm09",
            central_checkpoint::domain::GcClass::Supersedeable,
            seq,
        )
        .await?;
    m.note_kind("checkpoint_written");
    Ok(cp)
}

/// RTM-09 — the preflight ladder: legal writes resolve; unknown and
/// tampered tokens refuse stale; bumped format version refuses
/// incompatible; a mutated workspace mismatches; a GC'd artifact
/// reports missing; a live anchor refuses the write — every refusal
/// leaves the run untouched (upstream `scenarioRTM09`).
pub async fn rtm_09(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;

    // Anchor A completes; producer P finalizes X; consumer C (a child
    // of A) declares X, so checkpoints on A capture X in their read
    // set.
    m.emit(None, vec![Matrix::child("rtm09-a")]).await?;
    let anchor = m.node_by_key("rtm09-a").await?;
    let a_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(a_claim.attempt.node_id, anchor);
    m.record_outcome(Outcome {
        attempt_id: a_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm09 a"),
        retry_after: None,
    })
    .await?;

    m.emit(None, vec![Matrix::child("rtm09-p")]).await?;
    let producer = m.node_by_key("rtm09-p").await?;
    let p_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(p_claim.attempt.node_id, producer);
    let sum = fp("rtm09-x");
    let artifact = ArtifactId::new();
    let generation = ContentGeneration::new();
    m.seed_verifying_artifact(artifact, sum, generation, "report")
        .await?;
    m.finalize_artifact(
        artifact,
        p_claim.attempt.id,
        producer,
        "report",
        sum,
        generation,
    )
    .await?;
    m.record_outcome(Outcome {
        attempt_id: p_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm09 p"),
        retry_after: None,
    })
    .await?;
    let mut c_spec = Matrix::child("rtm09-c");
    c_spec.workspace_kind = "directory".to_string();
    c_spec.input_artifact_refs = vec![ArtifactRef {
        artifact_id: artifact,
        checksum: hex32(&sum),
    }];
    m.emit_children(anchor, vec![c_spec]).await?;
    let consumer = m.node_by_key("rtm09-c").await?;

    // Happy path: the legal-boundary write commits with X in its read
    // set, and the token resolves to the recorded row.
    let rec1 = write(m, anchor, 1).await?;
    assert!(
        rec1.finalized_artifacts.contains(&artifact),
        "checkpoint read set must capture X: {:?}",
        rec1.finalized_artifacts
    );
    let token1 = rec1.encode_token();
    let resolved = m.ck.resolve_token(&token1).await?;
    assert_eq!(resolved.id, rec1.id, "the seq-1 write resolves via token");

    // Unknown token: stale, with no journal row possible (no run
    // context resolves).
    let mut failed_before = m.count_kind("resume_failed").await?;
    let err = m
        .ck
        .resolve_token("ckpt.00000000-0000-0000-0000-000000000000.00000000000000000000000000000000")
        .await
        .expect_err("unknown token must refuse");
    m.expect_code(&err, "RESUME_TOKEN_STALE");
    assert_eq!(
        m.count_kind("resume_failed").await?,
        failed_before,
        "unresolvable token journals nothing"
    );

    // Tampered token digest: stale, journaled, run untouched.
    let before = m.snapshot_run_states().await?;
    let mut parts: Vec<String> = token1.split('.').map(str::to_string).collect();
    let digest_len = parts[2].len();
    parts[2] = "f".repeat(digest_len);
    let tampered = parts.join(".");
    let err =
        m.ck.resume_preflight(&tampered)
            .await
            .expect_err("tampered token must refuse");
    m.expect_code(&err, "RESUME_TOKEN_STALE");
    assert_eq!(
        m.count_kind("resume_failed").await?,
        failed_before + 1,
        "tampered refusal journals one resume_failed"
    );
    assert_eq!(
        m.snapshot_run_states().await?,
        before,
        "refusal leaves the run untouched"
    );
    m.assert_reason("resume_failed", "RESUME_TOKEN_STALE")
        .await?;
    failed_before += 1;

    // Bumped format_version on a REAL written row: incompatible, via
    // the ResumeSubtree entry (no resume_started on a failed
    // preflight). The digest binds format_version, so the tamper
    // re-binds content_digest to keep check 1 reachable and land on
    // the format gate (the leg under test).
    let rec2 = write(m, anchor, 2).await?;
    sqlx::query(
        "UPDATE central.resume_checkpoints SET format_version = 'central.checkpoint/v999' \
         WHERE checkpoint_id = $1",
    )
    .bind(sqlx::types::Uuid::from_bytes(*rec2.id.as_bytes()))
    .execute(&mut m.admin)
    .await
    .map_err(|e| central_foundation::failure::Failure::internal("RTM", e.to_string()))?;
    let mut loaded = m.ck.load_resume_checkpoint_by_id(rec2.id).await?;
    loaded.format_version = "central.checkpoint/v999".to_string();
    let redigest = loaded.digest();
    sqlx::query(
        "UPDATE central.resume_checkpoints SET content_digest = $2 WHERE checkpoint_id = $1",
    )
    .bind(sqlx::types::Uuid::from_bytes(*rec2.id.as_bytes()))
    .bind(redigest.as_str())
    .execute(&mut m.admin)
    .await
    .map_err(|e| central_foundation::failure::Failure::internal("RTM", e.to_string()))?;
    let loaded = m.ck.load_resume_checkpoint_by_id(rec2.id).await?;
    let before = m.snapshot_run_states().await?;
    let started_before = m.count_kind("resume_started").await?;
    let err =
        m.ck.resume_subtree(&loaded.encode_token(), "operator:rtm09")
            .await
            .expect_err("incompatible checkpoint must refuse");
    m.expect_code(&err, "CHECKPOINT_INCOMPATIBLE");
    assert_eq!(
        m.count_kind("resume_failed").await?,
        failed_before + 1,
        "incompatible refusal journals one resume_failed"
    );
    assert_eq!(
        m.count_kind("resume_started").await?,
        started_before,
        "resume_started must not move on a failed preflight"
    );
    assert_eq!(
        m.snapshot_run_states().await?,
        before,
        "refusal leaves the run untouched"
    );
    m.assert_reason("resume_failed", "CHECKPOINT_INCOMPATIBLE")
        .await?;
    failed_before += 1;

    // Mutated workspace: the re-digest mismatches the recorded value.
    let rec3 = write(m, anchor, 3).await?;
    let ws_path = rec3
        .workspace_path
        .clone()
        .expect("checkpoint carries a workspace path to mismatch");
    let ws_digest = rec3
        .workspace_digest
        .clone()
        .expect("checkpoint carries a workspace digest to mismatch");
    m.digester.set(&ws_path, "sha256:mutated-workspace");
    let before = m.snapshot_run_states().await?;
    let err =
        m.ck.resume_preflight(&rec3.encode_token())
            .await
            .expect_err("drifted workspace must refuse");
    m.expect_code(&err, "WORKSPACE_DIGEST_MISMATCH");
    assert_eq!(
        m.count_kind("resume_failed").await?,
        failed_before + 1,
        "mismatch refusal journals one resume_failed"
    );
    assert_eq!(
        m.snapshot_run_states().await?,
        before,
        "refusal leaves the run untouched"
    );
    m.assert_reason("resume_failed", "WORKSPACE_DIGEST_MISMATCH")
        .await?;
    failed_before += 1;
    m.digester.set(&ws_path, &ws_digest);

    // GC'd artifact ref: C completes first (its readiness needs X),
    // then X is collected and token1's read set no longer resolves.
    let c_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(c_claim.attempt.node_id, consumer);
    m.record_outcome(Outcome {
        attempt_id: c_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm09 c"),
        retry_after: None,
    })
    .await?;
    for stmt in [
        "DELETE FROM central.artifact_finalizations WHERE artifact_id = $1",
        "DELETE FROM central.artifact_produce_edges WHERE artifact_id = $1",
        "DELETE FROM central.artifact_read_edges WHERE artifact_id = $1",
        "DELETE FROM central.workflow_edges WHERE artifact_id = $1",
        "DELETE FROM central.capacity_reservations WHERE artifact_id = $1",
        "DELETE FROM central.artifact_command_receipts WHERE artifact_id = $1",
        "DELETE FROM central.artifact_reconciliation_claims WHERE artifact_id = $1",
        "DELETE FROM central.artifacts WHERE id = $1",
    ] {
        sqlx::query(stmt)
            .bind(sqlx::types::Uuid::from_bytes(*artifact.as_bytes()))
            .execute(&mut m.admin)
            .await
            .map_err(|e| central_foundation::failure::Failure::internal("RTM", e.to_string()))?;
    }
    assert!(
        m.find_artifact(artifact).await?.is_none(),
        "artifact must not resolve after GC"
    );
    let before = m.snapshot_run_states().await?;
    let err =
        m.ck.resume_preflight(&token1)
            .await
            .expect_err("GC'd artifact must refuse");
    m.expect_code(&err, "CHECKPOINT_ARTIFACT_MISSING");
    assert_eq!(
        m.count_kind("resume_failed").await?,
        failed_before + 1,
        "missing-artifact refusal journals one resume_failed"
    );
    assert_eq!(
        m.snapshot_run_states().await?,
        before,
        "refusal leaves the run untouched"
    );
    m.assert_reason("resume_failed", "CHECKPOINT_ARTIFACT_MISSING")
        .await?;
    m.note_kind("resume_failed");

    // Illegal boundary: a write while the anchor runs refuses (the only
    // ready node now).
    m.emit(None, vec![Matrix::child("rtm09-live")]).await?;
    let live = m.node_by_key("rtm09-live").await?;
    let live_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(live_claim.attempt.node_id, live);
    let refused_before = m.count_kind("checkpoint_refused").await?;
    let err =
        m.ck.write_checkpoint(
            m.run,
            live,
            "operator:rtm09",
            central_checkpoint::domain::GcClass::Supersedeable,
            1,
        )
        .await
        .expect_err("live anchor must refuse the write");
    m.expect_code(&err, "CHECKPOINT_BOUNDARY_ILLEGAL");
    assert_eq!(
        m.count_kind("checkpoint_refused").await?,
        refused_before + 1,
        "live-boundary refusal journals one checkpoint_refused"
    );
    m.assert_reason("checkpoint_refused", "CHECKPOINT_BOUNDARY_ILLEGAL")
        .await?;
    m.note_kind("checkpoint_refused");
    m.record_outcome(Outcome {
        attempt_id: live_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm09 live"),
        retry_after: None,
    })
    .await?;

    assert_eq!(
        m.count_kind("checkpoint_written").await?,
        3,
        "three legal writes journal exactly three rows"
    );
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "seq-1 write resolved via token; unknown+tampered tokens stale \
        (tampered journaled); bumped version incompatible via \
        ResumeSubtree; mutated workspace mismatched; GC'd artifact \
        missing; running anchor refused; every refusal left run state \
        untouched"
            .to_string(),
    )
}

/// RTM-10 — resume execution: after reopen the preflight resolves,
/// `resume_subtree` returns unfinished work claimable as seq 2, parks
/// the in-flight node RESUME_REQUIRES_OPERATOR_DECISION, leaves
/// pre-parked ambiguity untouched, and re-exposes the produced set
/// (upstream `scenarioRTM10`).
pub async fn rtm_10(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    // Upstream emits each child alone AFTER the anchor succeeded —
    // every emit's recompute flips exactly one candidate, so every
    // claim below has exactly one ready node (no FIFO dependence).
    m.emit(None, vec![Matrix::child("rtm10-a")]).await?;
    let anchor = m.node_by_key("rtm10-a").await?;

    // Anchor completes with a finalized artifact (the produced set the
    // resume re-exposes).
    let a_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(a_claim.attempt.node_id, anchor);
    let sum = fp("rtm10-x");
    let artifact = ArtifactId::new();
    let generation = ContentGeneration::new();
    m.seed_verifying_artifact(artifact, sum, generation, "report")
        .await?;
    m.finalize_artifact(
        artifact,
        a_claim.attempt.id,
        anchor,
        "report",
        sum,
        generation,
    )
    .await?;
    m.record_outcome(Outcome {
        attempt_id: a_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm10 a"),
        retry_after: None,
    })
    .await?;

    // B parked ambiguous before the checkpoint.
    m.emit_children(anchor, vec![Matrix::child("rtm10-b")])
        .await?;
    let parked = m.node_by_key("rtm10-b").await?;
    let p_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(p_claim.attempt.node_id, parked);
    m.force_expire(p_claim.lease.id).await?;
    m.expire_leases().await?;
    m.assert_node_state(parked, NodeStatus::AttemptAmbiguous)
        .await?;
    m.note_kind("lease_expired");

    // F flying: claimed with a live attempt and lease into the
    // watermark.
    m.emit_children(anchor, vec![Matrix::child("rtm10-f")])
        .await?;
    let flying = m.node_by_key("rtm10-f").await?;
    let f_claim = m.claim(worker).await?;
    assert_eq!(f_claim.attempt.node_id, flying);

    // U unfinished: one transient failure, ready for a fresh attempt.
    m.emit_children(anchor, vec![Matrix::child("rtm10-u")])
        .await?;
    let unfinished = m.node_by_key("rtm10-u").await?;
    let u_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(u_claim.attempt.node_id, unfinished);
    m.record_outcome(Outcome {
        attempt_id: u_claim.attempt.id,
        kind: OutcomeKind::Failed,
        reason_code: "PROCESS_EXIT_NONZERO".to_string(),
        fingerprint: fp("rtm10 u"),
        retry_after: None,
    })
    .await?;
    m.assert_node_state(unfinished, NodeStatus::Ready).await?;

    // The checkpoint anchors on the succeeded node; the in-flight set
    // must capture the flying node.
    let rec = write(m, anchor, 1).await?;
    assert!(
        rec.in_flight_nodes.iter().any(|k| k == "rtm10-f"),
        "checkpoint in-flight must capture the flying node: {:?}",
        rec.in_flight_nodes
    );
    let produced_before: BTreeSet<_> = m.produce_edges().await?.into_iter().collect();
    let resolved_before = m.resolve_produced("rtm10-a", "report").await?;
    assert_eq!(
        resolved_before,
        vec![artifact],
        "pre-resume ResolveProduced must return X"
    );
    let token = rec.encode_token();

    // Restart: reopen the stores, then preflight + resume through the
    // production path.
    m.reopen().await?;
    let resolved = m.ck.resume_preflight(&token).await?;
    assert_eq!(resolved.id, rec.id, "preflight resolves the recorded row");
    m.ck.resume_subtree(&token, "operator:rtm10").await?;
    m.note_kind("resume_started");
    m.note_kind("resume_completed");

    // Unfinished requeues claimable as seq 2 and runs to success.
    m.assert_node_state(unfinished, NodeStatus::Ready).await?;
    m.note_kind("node_ready");
    m.clear_not_before(unfinished).await?;
    let rerun = m.claim(worker).await?;
    assert_eq!(rerun.attempt.node_id, unfinished);
    assert_eq!(rerun.attempt.attempt_seq, 2, "unfinished reclaims as seq 2");
    m.launcher.script(
        rerun.attempt.id,
        central_scheduler::port::LaunchVerdict::Started(format!("sess-{}", rerun.attempt.id)),
    );
    m.dispatch(&rerun).await?;
    m.record_outcome(Outcome {
        attempt_id: rerun.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm10 u2"),
        retry_after: None,
    })
    .await?;

    // The flying node parked for an operator decision.
    m.assert_node_state(flying, NodeStatus::AttemptAmbiguous)
        .await?;
    assert_eq!(
        m.node_attempt_states(flying).await?,
        vec![(1, "ambiguous".to_string())],
        "flying attempt-1 state"
    );
    assert_eq!(
        m.node_attempt_reason(flying, 1).await?,
        Some("RESUME_REQUIRES_OPERATOR_DECISION".to_string()),
        "flying attempt-1 reason row"
    );
    m.assert_reason("attempt_ambiguous", "RESUME_REQUIRES_OPERATOR_DECISION")
        .await?;
    m.note_reason("RESUME_REQUIRES_OPERATOR_DECISION");
    m.note_kind("attempt_ambiguous");

    // The pre-checkpoint ambiguity stays parked with no duplicate park.
    m.assert_node_state(parked, NodeStatus::AttemptAmbiguous)
        .await?;
    assert_eq!(
        m.count_node_kind(parked, "attempt_ambiguous").await?,
        1,
        "no duplicate park row"
    );
    assert_eq!(
        m.node_attempt_reason(parked, 1).await?,
        Some("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED".to_string()),
        "parked attempt keeps the original park code"
    );

    // The readable set re-exposes; the produce set is unchanged and no
    // payload was restored or rewritten.
    let resolved_after = m.resolve_produced("rtm10-a", "report").await?;
    assert_eq!(
        resolved_after,
        vec![artifact],
        "post-resume ResolveProduced must return X"
    );
    let produced_after: BTreeSet<_> = m.produce_edges().await?.into_iter().collect();
    assert_eq!(
        produced_after.len(),
        produced_before.len(),
        "produce edges moved across resume"
    );
    for edge in &produced_before {
        assert!(
            produced_after.contains(edge),
            "produce edge {edge:?} missing"
        );
    }
    let (state, checksum) = m
        .find_artifact(artifact)
        .await?
        .expect("X must still resolve");
    assert_eq!(state, "ready", "X must stay ready");
    assert_eq!(checksum.as_slice(), sum.as_slice(), "X checksum unchanged");

    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "preflight ok after restart; unfinished reclaimed as seq 2 and \
        succeeded; flying parked RESUME_REQUIRES_OPERATOR_DECISION; \
        pre-parked ambiguity untouched; ResolveProduced re-resolved X \
        with an unchanged produce set"
            .to_string(),
    )
}

/// RTM-18 — event integrity: the fold flags a synthesized seq gap, a
/// redelivery dedupes to its recorded seq, an undeclared kind stores
/// verbatim and flags UNKNOWN_EVENT_KIND, and the cross-run catalog
/// check covers every journaled kind (upstream `scenarioRTM18`).
pub async fn rtm_18(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm18")]).await?;
    let node = m.node_by_key("rtm18").await?;
    let claim = m.claim_and_dispatch(worker).await?;
    m.record_outcome(Outcome {
        attempt_id: claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm18"),
        retry_after: None,
    })
    .await?;
    for kind in [
        "node_declared",
        "node_ready",
        "node_dispatched",
        "attempt_started",
        "attempt_succeeded",
        "node_succeeded",
    ] {
        m.note_kind(kind);
    }
    assert_eq!(
        m.count_node_kind(node, "attempt_succeeded").await?,
        1,
        "one committed success"
    );

    // The contiguous fold is clean — the production fold consumes the
    // journaled events verbatim.
    let events = m.run_events().await?;
    let folded = central_eventjournal::fold::fold(&events);
    assert!(
        folded.findings.is_empty(),
        "contiguous fold must be clean: {:?}",
        folded.findings
    );

    // A synthesized gap flags EVENT_SEQUENCE_GAP.
    let gapped: Vec<_> = events.iter().filter(|e| e.seq != 2).cloned().collect();
    let folded = central_eventjournal::fold::fold(&gapped);
    assert!(
        folded
            .findings
            .iter()
            .any(|f| f.reason_code.as_str() == "EVENT_SEQUENCE_GAP"),
        "the synthesized gap must flag EVENT_SEQUENCE_GAP: {:?}",
        folded.findings
    );
    m.note_reason("EVENT_SEQUENCE_GAP");

    // Redelivery dedupes to the recorded seq — the same event id
    // appends no second row (DUPLICATE_EVENT_ID is the vocabulary
    // bound; the dedupe is proven by seq identity + a single row).
    let first = events
        .iter()
        .find(|e| e.kind == "node_succeeded")
        .expect("node_succeeded journaled");
    let replayed = m.journal.append(first.clone()).await?;
    assert_eq!(
        replayed, first.seq,
        "redelivery dedupes to the recorded seq"
    );
    assert_eq!(
        m.journal_row_count().await?,
        events.len() as i64,
        "dedupe stores no second row"
    );
    m.note_reason("DUPLICATE_EVENT_ID");

    // An undeclared kind stores verbatim and folds UNKNOWN_EVENT_KIND;
    // the probe graph (same DB, second run) carries the cross-run leg —
    // upstream checks every recorded run's kinds against the catalog.
    let probe = m.spawn_graph().await?;
    for run in [m.run, probe.run] {
        let event = central_eventjournal::domain::RunEvent {
            id: RunEventId::new(),
            workspace_id: if run == m.run { m.ws } else { probe.ws },
            run_id: run,
            seq: 0,
            node_id: None,
            attempt_id: None,
            kind: "matrix.undeclared/v1".to_string(),
            actor: "rtm".to_string(),
            reason_code: None,
            payload: serde_json::json!({}),
            recorded_at: m.clock.now(),
        };
        m.journal.append(event).await?;
    }
    assert!(
        !central_eventjournal::domain::known("matrix.undeclared/v1"),
        "the probe kind is outside the catalog"
    );
    for run in [m.run, probe.run] {
        let events = m.events_for(run).await?;
        assert!(
            events.iter().any(|e| e.kind == "matrix.undeclared/v1"),
            "the undeclared kind must store verbatim in run {run}"
        );
        let folded = central_eventjournal::fold::fold(&events);
        assert!(
            folded
                .findings
                .iter()
                .any(|f| f.reason_code.as_str() == "UNKNOWN_EVENT_KIND"),
            "run {run} must flag UNKNOWN_EVENT_KIND: {:?}",
            folded.findings
        );
    }
    // The recorded-run catalog check: every kind THIS matrix journaled
    // (across every scenario's run in this database) is cataloged.
    for kind in m.event_kinds().await? {
        assert!(
            central_eventjournal::domain::known(&kind) || kind == "matrix.undeclared/v1",
            "journaled kind {kind} outside the catalog"
        );
    }
    m.note_reason("UNKNOWN_EVENT_KIND");
    m.deregister_worker(worker).await?;
    Ok(
        "contiguous fold clean, gapped fold flagged EVENT_SEQUENCE_GAP; \
        redelivery deduped to its seq (DUPLICATE_EVENT_ID \
        vocabulary-bound, dedupe behaviorally proven via seq identity + \
        single stored row); undeclared kind stored verbatim and flagged \
        UNKNOWN_EVENT_KIND"
            .to_string(),
    )
}
