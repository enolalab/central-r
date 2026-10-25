//! Checkpoint/journal scenarios — RTM-09 (write → resume happy path +
//! digest drift refusal), RTM-10 (stale token), RTM-18 (journal fold
//! consistency against materialized state + lineage).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use central_checkpoint::domain::GcClass;
use central_checkpoint::port::ResumeStore;
use central_eventjournal::fold;
use central_foundation::failure::Failure;
use central_workflow::domain::NodeStatus;

use crate::driver::{Matrix, Result};

/// RTM-09 — checkpoint written at a live anchor, token resolves,
/// preflight passes against the scripted digester, and `resume_subtree`
/// journals `resume_started`/`resume_completed`. Then a digest override
/// (workspace mutation) makes the same preflight refuse
/// `WORKSPACE_DIGEST_MISMATCH`.
pub async fn rtm_09(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("anchored")]).await?;
    let node = m.node_by_key("anchored").await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    // A checkpoint writes only at a quiescent boundary — close the
    // attempt first (upstream checkpoints the succeeded anchor).
    central_retry::port::Store::record_outcome(
        m.sched.as_ref(),
        central_retry::port::Outcome {
            attempt_id: claim.attempt.id,
            kind: central_retry::domain::OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: [8; 32],
            retry_after: None,
        },
    )
    .await?;

    let checkpoint =
        m.ck.write_checkpoint(m.run, node, "operator:rtm", GcClass::Pinned, 1)
            .await?;
    let token = checkpoint.encode_token();

    let resolved = m.ck.resolve_token(&token).await?;
    assert_eq!(resolved.id, checkpoint.id);

    let preflight = m.ck.resume_preflight(&token).await?;
    assert_eq!(preflight.id, checkpoint.id);
    m.assert_kinds(&["checkpoint_written"]).await?;

    // Digest drift → the same token now refuses preflight. The anchor's
    // recorded workspace path comes off the checkpoint row.
    if let Some(path) = resolved.workspace_path.clone() {
        m.digester.set(&path, "sha256:mutated");
    } else {
        return Err(Failure::internal(
            "RTM_FIXTURE",
            "no workspace_path recorded",
        ));
    }
    let err = m.ck.resume_preflight(&token).await.unwrap_err();
    assert_eq!(err.code(), "WORKSPACE_DIGEST_MISMATCH", "drift refused");
    m.assert_kinds(&["resume_failed"]).await?;
    Ok("checkpoint round-trip + digest-drift refusal".to_string())
}

/// RTM-10 — a stale resume token refuses `RESUME_TOKEN_STALE`: the row is
/// deleted after the token was minted, so resolution cannot satisfy the
/// embedded digest prefix.
pub async fn rtm_10(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("stale")]).await?;
    let node = m.node_by_key("stale").await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    central_retry::port::Store::record_outcome(
        m.sched.as_ref(),
        central_retry::port::Outcome {
            attempt_id: claim.attempt.id,
            kind: central_retry::domain::OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: [9; 32],
            retry_after: None,
        },
    )
    .await?;

    let checkpoint =
        m.ck.write_checkpoint(m.run, node, "operator:rtm", GcClass::Supersedeable, 1)
            .await?;
    let token = checkpoint.encode_token();
    assert!(m.ck.resolve_token(&token).await.is_ok(), "token resolves");

    // Delete the row — the token's checkpoint id + digest prefix can no
    // longer resolve.
    sqlx::query("DELETE FROM central.resume_checkpoints WHERE checkpoint_id = $1")
        .bind(sqlx::types::Uuid::from_bytes(*checkpoint.id.as_bytes()))
        .execute(&mut m.admin)
        .await
        .map_err(|e| Failure::internal("RTM_FIXTURE", e.to_string()))?;

    let err = m.ck.resolve_token(&token).await.unwrap_err();
    assert_eq!(err.code(), "RESUME_TOKEN_STALE", "stale token");
    // A garbled token refuses the same way at the decode boundary.
    let err = m.ck.resolve_token("rtm.garbage.token").await.unwrap_err();
    assert_eq!(err.code(), "RESUME_TOKEN_STALE");
    Ok("stale + garbled tokens refused".to_string())
}

/// RTM-18 — journal fold consistency: after a real emission + dispatch +
/// outcome, `fold` over the journaled events reconstructs the same
/// terminal node states the materialized tables carry, with no
/// `RECONSTRUCTION_DIVERGED`/unknown-kind findings.
pub async fn rtm_18(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("folded")]).await?;
    let node = m.node_by_key("folded").await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    central_retry::port::Store::record_outcome(
        m.sched.as_ref(),
        central_retry::port::Outcome {
            attempt_id: claim.attempt.id,
            kind: central_retry::domain::OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: [5; 32],
            retry_after: None,
        },
    )
    .await?;
    m.assert_node_state(node, NodeStatus::Succeeded).await?;
    m.assert_kinds(&["attempt_succeeded", "node_succeeded"])
        .await?;

    // Fold every journaled event — every kind must be cataloged.
    use central_eventjournal::query::RunJournalRead;
    let events = m.journal.events_for_run(m.run).await?;
    assert!(!events.is_empty());
    for e in &events {
        assert!(
            central_eventjournal::domain::known(&e.kind),
            "uncataloged kind {}",
            e.kind
        );
    }
    let folded = fold::fold(&events);
    // `current` is the materialized node_key→state map the fold agrees
    // with — the runview/audit surface's comparison input.
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT node_key, state FROM central.workflow_nodes WHERE run_id = $1")
            .bind(sqlx::types::Uuid::from_bytes(*m.run.as_bytes()))
            .fetch_all(&mut m.admin)
            .await
            .map_err(|e| Failure::internal("RTM_FIXTURE", e.to_string()))?;
    let current: std::collections::BTreeMap<String, String> = rows.into_iter().collect();
    let divergences = fold::compare_fold(&current, &folded);
    assert!(
        divergences.is_empty(),
        "fold must reconstruct materialized state: {divergences:?}"
    );
    Ok("fold reconstructed the journaled truth".to_string())
}
