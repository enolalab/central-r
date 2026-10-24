//! `CompletionReceiptStore` — port of upstream `completion_receipt.go`.
//!
//! One fenced, idempotent write of bounded immutable invocation
//! evidence: the digest replay check makes a retry of the identical
//! receipt a no-op and drift a `COMPLETION_RECEIPT_CONFLICT`. The write
//! is fenced by the persisted lease verifier + generation + expiry and
//! by the attempt's durable selector identities and live state
//! (`invoked`/`settling`), exactly as upstream.

use central_execution::domain::Capability;
use central_execution::harness_run::CompletionReceipt;
use central_execution::port::{CompletionReceiptStore, RecordCompletionReceiptRequest};
use central_foundation::failure::Failure;
use sqlx::{Postgres, Transaction};

use super::queries::{db_now, lock_event_counter, read_persisted_lease_for_update};
use super::store::Store;
use super::{
    begin, conflict, ct_eq, denied, go_json_escapes, sha256, uuid_for_invocation, uuid_for_logical,
    uuid_for_physical,
};
use crate::error::SqlxContext;
use crate::store_support::uuid_of;

impl CompletionReceiptStore for Store {
    /// `RecordCompletionReceipt` — upstream `recordCompletionReceipt`.
    async fn record_completion_receipt(
        &self,
        request: RecordCompletionReceiptRequest,
    ) -> Result<(), Failure> {
        request.receipt.validate()?;
        let receipt = &request.receipt;
        if request.scope.workspace_id != receipt.workspace_id
            || !request.scope.allows(Capability::Executor)
        {
            return Err(denied("COMPLETION_RECEIPT_DENIED"));
        }
        let digest = completion_receipt_digest(receipt);
        let mut tx = begin(&self.pool).await?;
        if let Some(stored) = read_receipt_digest(&mut tx, receipt).await? {
            let result = if ct_eq(&stored, &digest) {
                Ok(())
            } else {
                Err(conflict("COMPLETION_RECEIPT_CONFLICT"))
            };
            tx.commit()
                .await
                .ctx("execution: commit receipt replay read")?;
            return result;
        }
        if !request.lease_credential.valid() || request.lease_generation <= 0 {
            return Err(denied("COMPLETION_RECEIPT_DENIED"));
        }
        lock_event_counter(&mut tx, receipt.workspace_id).await?;
        lock_receipt_hierarchy(&mut tx, receipt).await?;
        let Some(lease) =
            read_persisted_lease_for_update(&mut tx, receipt.workspace_id, receipt.run_id).await?
        else {
            return Err(conflict("STALE_LEASE_FENCE"));
        };
        let now = db_now(&mut tx).await?;
        if lease.generation != request.lease_generation
            || !ct_eq(&lease.verifier, &sha256(&request.lease_credential.0))
            || lease.expires_at <= now
            || lease.step_id != receipt.step_id
            || lease.attempt_id != receipt.attempt_id
        {
            return Err(conflict("STALE_LEASE_FENCE"));
        }
        lock_receipt_step(&mut tx, receipt).await?;
        validate_receipt_attempt(&mut tx, receipt).await?;
        let receipt_id = uuid::Uuid::now_v7();
        let outcome_json: serde_json::Value = serde_json::from_slice(&receipt.outcome)
            .map_err(|_| super::invalid("INVALID_COMPLETION_RECEIPT"))?;
        let context_json = (!receipt.context.is_empty())
            .then(|| serde_json::from_slice::<serde_json::Value>(&receipt.context))
            .transpose()
            .map_err(|_| super::invalid("INVALID_COMPLETION_RECEIPT"))?;
        sqlx::query!(
            "INSERT INTO central.execution_completion_receipts ( \
             id, workspace_id, task_id, run_id, step_id, step_attempt_id, \
             logical_operation_id, physical_attempt_id, invocation_id, \
             invocation_generation, final_state, outcome, context, \
             evidence_digest, producer_id, created_at, eligible_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, \
             $13::jsonb, $14, $15, clock_timestamp(), \
             clock_timestamp() + interval '90 days') \
             ON CONFLICT (workspace_id, step_attempt_id) DO NOTHING",
            receipt_id,
            uuid_of(receipt.workspace_id.as_bytes()),
            uuid_of(receipt.task_id.as_bytes()),
            uuid_of(receipt.run_id.as_bytes()),
            uuid_of(receipt.step_id.as_bytes()),
            uuid_of(receipt.attempt_id.as_bytes()),
            uuid_for_logical(&receipt.logical_operation_id),
            uuid_for_physical(&receipt.physical_attempt_id),
            uuid_for_invocation(&receipt.invocation_id),
            receipt.invocation_generation,
            receipt.final_state.as_str(),
            outcome_json,
            context_json,
            &digest[..],
            receipt.producer_id.trim(),
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert completion receipt")?;
        let mut references = receipt.b09_references.clone();
        references.sort_by(|a, b| {
            (a.kind.as_str(), a.id.as_str()).cmp(&(b.kind.as_str(), b.id.as_str()))
        });
        for reference in references {
            sqlx::query!(
                "INSERT INTO central.provider_completion_references ( \
                 workspace_id, completion_receipt_id, evidence_kind, evidence_id) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (workspace_id, completion_receipt_id, evidence_kind, evidence_id) \
                 DO NOTHING",
                uuid_of(receipt.workspace_id.as_bytes()),
                receipt_id,
                reference.kind,
                reference.id,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: insert provider completion reference")?;
        }
        let Some(stored) = read_receipt_digest(&mut tx, receipt).await? else {
            return Err(conflict("COMPLETION_RECEIPT_MISMATCH"));
        };
        if !ct_eq(&stored, &digest) {
            return Err(conflict("COMPLETION_RECEIPT_CONFLICT"));
        }
        tx.commit()
            .await
            .ctx("execution: commit completion receipt")?;
        Ok(())
    }
}

/// `queryReadCompletionReceiptDigest` — the replay probe.
async fn read_receipt_digest(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &CompletionReceipt,
) -> Result<Option<Vec<u8>>, Failure> {
    let row = sqlx::query!(
        "SELECT evidence_digest FROM central.execution_completion_receipts \
         WHERE workspace_id = $1 AND step_attempt_id = $2",
        uuid_of(receipt.workspace_id.as_bytes()),
        uuid_of(receipt.attempt_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: read completion receipt digest")?;
    Ok(row.map(|r| r.evidence_digest))
}

/// `lockCompletionReceiptHierarchy` — the task→run row locks, in the
/// documented lock order after the workspace event counter.
async fn lock_receipt_hierarchy(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &CompletionReceipt,
) -> Result<(), Failure> {
    let task = sqlx::query!(
        "SELECT 1 AS one FROM central.tasks \
         WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
        uuid_of(receipt.workspace_id.as_bytes()),
        uuid_of(receipt.task_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: lock receipt task")?;
    if task.is_none() {
        return Err(conflict("COMPLETION_RECEIPT_MISMATCH"));
    }
    let run = sqlx::query!(
        "SELECT 1 AS one FROM central.runs \
         WHERE workspace_id = $1 AND task_id = $2 AND id = $3 FOR UPDATE",
        uuid_of(receipt.workspace_id.as_bytes()),
        uuid_of(receipt.task_id.as_bytes()),
        uuid_of(receipt.run_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: lock receipt run")?;
    if run.is_none() {
        return Err(conflict("COMPLETION_RECEIPT_MISMATCH"));
    }
    Ok(())
}

/// `queryLockCompletionReceiptStep`.
async fn lock_receipt_step(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &CompletionReceipt,
) -> Result<(), Failure> {
    let step = sqlx::query!(
        "SELECT 1 AS one FROM central.steps \
         WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND id = $4 \
         FOR UPDATE",
        uuid_of(receipt.workspace_id.as_bytes()),
        uuid_of(receipt.task_id.as_bytes()),
        uuid_of(receipt.run_id.as_bytes()),
        uuid_of(receipt.step_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: lock receipt step")?;
    if step.is_none() {
        return Err(conflict("COMPLETION_RECEIPT_MISMATCH"));
    }
    Ok(())
}

/// `queryValidateCompletionReceiptAttempt` — the attempt row must match
/// the receipt's selector identities and still be invoked or settling.
async fn validate_receipt_attempt(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &CompletionReceipt,
) -> Result<(), Failure> {
    let row = sqlx::query!(
        "SELECT logical_operation_id, physical_attempt_id, invocation_id, \
         invocation_generation, state FROM central.step_attempts \
         WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
         AND step_id = $4 AND id = $5 FOR UPDATE",
        uuid_of(receipt.workspace_id.as_bytes()),
        uuid_of(receipt.task_id.as_bytes()),
        uuid_of(receipt.run_id.as_bytes()),
        uuid_of(receipt.step_id.as_bytes()),
        uuid_of(receipt.attempt_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: lock receipt attempt")?;
    let Some(row) = row else {
        return Err(conflict("COMPLETION_RECEIPT_MISMATCH"));
    };
    if row.logical_operation_id != uuid_for_logical(&receipt.logical_operation_id)
        || row.physical_attempt_id != uuid_for_physical(&receipt.physical_attempt_id)
        || row.invocation_id != uuid_for_invocation(&receipt.invocation_id)
        || row.invocation_generation != Some(receipt.invocation_generation)
        || !matches!(row.state.as_str(), "invoked" | "settling")
    {
        return Err(conflict("COMPLETION_RECEIPT_MISMATCH"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `completionReceiptDigest` — SHA-256 over Go `json.Marshal` of the digest
// map. Go sorts map keys, so the field order below is alphabetical;
// `json.RawMessage` values are compacted and HTML-escaped, and
// `B09EvidenceReference` has no JSON tags (Go field names `Kind`, `ID`).
// ---------------------------------------------------------------------------

fn completion_receipt_digest(receipt: &CompletionReceipt) -> [u8; 32] {
    let references = if receipt.b09_references.is_empty() {
        // Go marshals a nil slice as `null`.
        "null".to_string()
    } else {
        let items = receipt
            .b09_references
            .iter()
            .map(|r| {
                format!(
                    "{{\"Kind\":{},\"ID\":{}}}",
                    go_json_string(&r.kind),
                    go_json_string(&r.id),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("[{items}]")
    };
    let context = if receipt.context.is_empty() {
        "null".to_string()
    } else {
        escaped_compact(&receipt.context)
    };
    let invocation =
        uuid_for_invocation(&receipt.invocation_id).map_or_else(String::new, |u| u.to_string());
    let encoded = format!(
        "{{\"attempt_id\":{},\"b09_references\":{},\"context\":{},\
         \"final_state\":{},\"invocation_generation\":{},\"invocation_id\":{},\
         \"logical_operation_id\":{},\"outcome\":{},\"physical_attempt_id\":{},\
         \"producer_id\":{},\"run_id\":{},\"step_id\":{},\"task_id\":{},\
         \"workspace_id\":{}}}",
        go_json_string(&uuid_of(receipt.attempt_id.as_bytes()).to_string()),
        references,
        context,
        go_json_string(receipt.final_state.as_str()),
        receipt.invocation_generation,
        go_json_string(&invocation),
        go_json_string(&uuid_for_logical(&receipt.logical_operation_id).to_string()),
        escaped_compact(&receipt.outcome),
        go_json_string(&uuid_for_physical(&receipt.physical_attempt_id).to_string()),
        go_json_string(&receipt.producer_id),
        go_json_string(&uuid_of(receipt.run_id.as_bytes()).to_string()),
        go_json_string(&uuid_of(receipt.step_id.as_bytes()).to_string()),
        go_json_string(&uuid_of(receipt.task_id.as_bytes()).to_string()),
        go_json_string(&uuid_of(receipt.workspace_id.as_bytes()).to_string()),
    );
    sha256(encoded.as_bytes())
}

/// A Go-`encoding/json` string literal: serde_json's quoting plus the
/// `<`, `>`, `&`, U+2028/U+2029 escapes Go applies.
fn go_json_string(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string());
    String::from_utf8_lossy(&go_json_escapes(quoted.as_bytes())).into_owned()
}

/// Go `json.Marshal(json.RawMessage)` — `appendCompact` with HTML
/// escapes: insignificant whitespace dropped, strings verbatim.
fn escaped_compact(payload: &[u8]) -> String {
    String::from_utf8_lossy(&go_json_escapes(&compact_json(payload))).into_owned()
}

/// Go `encoding/json` `appendCompact` — drops insignificant whitespace
/// outside strings; escape sequences are copied verbatim.
fn compact_json(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut in_string = false;
    let mut i = 0;
    while i < payload.len() {
        let c = payload[i];
        if in_string {
            out.push(c);
            if c == b'\\' && i + 1 < payload.len() {
                out.push(payload[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
        }
        out.push(c);
        i += 1;
    }
    out
}
